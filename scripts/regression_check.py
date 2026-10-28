#!/usr/bin/env python3
"""Check that every live test still produces its expected alerts.

Run on the Wazuh manager after the regression session:

    sudo python3 scripts/regression_check.py --times regression-times.csv --out regression-result

regression-times.csv comes from scripts/Run-AtomicRegression.ps1 (columns id,start,end, local time).
tests/live/expected.json lists the rules each test must raise. A test passes when every expected
rule has at least one alert between the start of the test and its end plus the grace period.
"""
import argparse
import csv
import glob
import gzip
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

ALERT_DIR = "/var/ossec/logs/alerts"


def alert_files(alert_dir):
    files = sorted(glob.glob(f"{alert_dir}/*/*/ossec-alerts-*.json*"))
    current = Path(alert_dir) / "alerts.json"
    if current.exists():
        files.append(str(current))
    return files


def open_any(path):
    return gzip.open(path, "rt", encoding="utf-8", errors="replace") if path.endswith(".gz") \
        else open(path, encoding="utf-8", errors="replace")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--times", required=True)
    p.add_argument("--expected", default="tests/live/expected.json")
    p.add_argument("--tz", default="America/New_York")
    p.add_argument("--alerts-dir", default=ALERT_DIR)
    p.add_argument("--out", default="regression-result")
    args = p.parse_args()

    tz = ZoneInfo(args.tz)
    spec = json.loads(Path(args.expected).read_text(encoding="utf-8"))
    grace = timedelta(seconds=spec.get("grace_seconds", 300))
    windows = {}
    with open(args.times, encoding="utf-8-sig") as handle:
        for row in csv.DictReader(handle):
            fmt = "%Y-%m-%d %H:%M:%S"
            windows[row["id"]] = (datetime.strptime(row["start"], fmt).replace(tzinfo=tz),
                                  datetime.strptime(row["end"], fmt).replace(tzinfo=tz))
    if not windows:
        print("no test windows found in", args.times)
        return 1
    first = min(s for s, _ in windows.values()) - timedelta(minutes=1)
    last = max(e for _, e in windows.values()) + grace

    hits = {}  # (test id, rule id) -> list of alert times
    seen = set()
    for path in alert_files(args.alerts_dir):
        with open_any(path) as handle:
            for line in handle:
                try:
                    alert = json.loads(line)
                    when = datetime.strptime(alert["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z").astimezone(tz)
                except (ValueError, KeyError):
                    continue
                if not (first <= when <= last):
                    continue
                key = alert.get("id") or (alert["timestamp"], alert["rule"]["id"])
                if key in seen:
                    continue
                seen.add(key)
                rid = str(alert["rule"]["id"])
                for tid, (start, end) in windows.items():
                    if start <= when <= end + grace:
                        hits.setdefault((tid, rid), []).append(when)

    rows, failed = [], 0
    for test in spec["tests"]:
        tid = test["id"]
        if tid not in windows:
            rows.append((tid, test["name"], "not run", "-", "-"))
            failed += 1
            continue
        start, end = windows[tid]
        found, missing = [], []
        for rid in test["expect"]:
            times = hits.get((tid, rid))
            if times:
                found.append(f"{rid} (x{len(times)}, first {int((min(times) - start).total_seconds())} s)")
            else:
                missing.append(rid)
        status = "PASS" if not missing else "FAIL"
        failed += bool(missing)
        rows.append((tid, test["name"], status, ", ".join(found) or "-", ", ".join(missing) or "-"))

    lines = [f"{len(rows) - failed} of {len(rows)} live tests raised every expected alert", "",
             "| Test | Name | Result | Alerts seen | Missing |", "| --- | --- | --- | --- | --- |"]
    lines += [f"| {t} | {n} | {s} | {f} | {m} |" for t, n, s, f, m in rows]
    out = Path(args.out + ".md")
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
