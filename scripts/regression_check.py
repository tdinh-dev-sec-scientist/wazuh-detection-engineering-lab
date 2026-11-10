#!/usr/bin/env python3
"""Check live regression alerts against exact identity, source, severity, and ATT&CK.

Run on the Wazuh manager after scripts/Run-AtomicRegression.ps1 has produced the
CSV of test windows:

    sudo python3 scripts/regression_check.py --times regression-times.csv \\
        --expected tests/live/expected.json --out regression-result

Every expectation is an alert contract. An alert passes only when its rule ID,
agent.name, event-source fields, rule.level, and complete rule.mitre.id array
match the JSON oracle inside that test's time window.
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


def get_path(value, dotted):
    node = value
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def mitre_ids(alert):
    value = get_path(alert, "rule.mitre.id")
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def parse_timestamp(value, timezone):
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone)
    return stamp.astimezone(timezone)


def validate_spec(spec):
    tests = spec.get("tests")
    if not isinstance(tests, list) or not tests:
        raise ValueError("expected.json must contain a nonempty tests array")
    seen_ids = set()
    for test in tests:
        test_id = test.get("id")
        if not test_id or test_id in seen_ids:
            raise ValueError(f"missing or duplicate test id: {test_id!r}")
        seen_ids.add(test_id)
        expectations = test.get("expect")
        if not isinstance(expectations, list) or not expectations:
            raise ValueError(f"{test_id}: expect must be a nonempty array")
        for index, expectation in enumerate(expectations, 1):
            required = ("rule_id", "agent_name", "event_source", "level", "mitre")
            missing = [key for key in required if key not in expectation]
            if missing:
                raise ValueError(f"{test_id} expectation {index}: missing {', '.join(missing)}")
            if not isinstance(expectation["event_source"], dict) or not expectation["event_source"]:
                raise ValueError(f"{test_id} expectation {index}: event_source must be a nonempty object")
            if not isinstance(expectation["mitre"], list):
                raise ValueError(f"{test_id} expectation {index}: mitre must be an array")
            if isinstance(expectation["level"], bool) or not isinstance(expectation["level"], int):
                raise ValueError(f"{test_id} expectation {index}: level must be an integer")


def mismatch_reasons(alert, expectation):
    problems = []
    actual_rule = str(get_path(alert, "rule.id") or "")
    if actual_rule != str(expectation["rule_id"]):
        problems.append(f"rule.id expected {expectation['rule_id']}, got {actual_rule or 'missing'}")
    actual_agent = get_path(alert, "agent.name")
    if actual_agent != expectation["agent_name"]:
        problems.append(f"agent.name expected {expectation['agent_name']}, got {actual_agent!r}")
    for field, expected_value in expectation["event_source"].items():
        actual_value = get_path(alert, field)
        if str(actual_value) != str(expected_value):
            problems.append(f"{field} expected {expected_value!r}, got {actual_value!r}")
    try:
        actual_level = int(get_path(alert, "rule.level"))
    except (TypeError, ValueError):
        actual_level = None
    if actual_level != expectation["level"]:
        problems.append(f"rule.level expected {expectation['level']}, got {actual_level}")
    actual_mitre = sorted(mitre_ids(alert))
    expected_mitre = sorted(str(item) for item in expectation["mitre"])
    if actual_mitre != expected_mitre:
        problems.append(f"rule.mitre.id expected {expected_mitre}, got {actual_mitre}")
    return problems


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--times", required=True)
    parser.add_argument("--expected", default="tests/live/expected.json")
    parser.add_argument("--tz", default="America/New_York")
    parser.add_argument("--alerts-dir", default=ALERT_DIR)
    parser.add_argument("--out", default="regression-result")
    args = parser.parse_args()

    timezone = ZoneInfo(args.tz)
    spec = json.loads(Path(args.expected).read_text(encoding="utf-8"))
    validate_spec(spec)
    grace = timedelta(seconds=int(spec.get("grace_seconds", 300)))
    windows = {}
    with open(args.times, encoding="utf-8-sig") as handle:
        for row in csv.DictReader(handle):
            fmt = "%Y-%m-%d %H:%M:%S"
            windows[row["id"]] = (
                datetime.strptime(row["start"], fmt).replace(tzinfo=timezone),
                datetime.strptime(row["end"], fmt).replace(tzinfo=timezone),
            )
    if not windows:
        print("no test windows found in", args.times)
        return 1

    first = min(start for start, _ in windows.values()) - timedelta(minutes=1)
    last = max(end for _, end in windows.values()) + grace
    alerts = []
    seen = set()
    for path in alert_files(args.alerts_dir):
        with open_any(path) as handle:
            for line in handle:
                try:
                    alert = json.loads(line)
                    when = parse_timestamp(alert["timestamp"], timezone)
                except (ValueError, KeyError, TypeError):
                    continue
                if not (first <= when <= last):
                    continue
                key = alert.get("id") or (alert["timestamp"], get_path(alert, "rule.id"))
                if key in seen:
                    continue
                seen.add(key)
                alerts.append((when, alert))

    rows, failed = [], 0
    for test in spec["tests"]:
        test_id = test["id"]
        if test_id not in windows:
            rows.append((test_id, test["name"], "not run", "-", "window missing in times CSV"))
            failed += 1
            continue
        start, end = windows[test_id]
        test_alerts = [(when, alert) for when, alert in alerts if start <= when <= end + grace]
        results, test_failed = [], False
        for expectation in test["expect"]:
            rule_id = str(expectation["rule_id"])
            candidates = [(when, alert) for when, alert in test_alerts
                          if str(get_path(alert, "rule.id") or "") == rule_id]
            matching = [(when, alert) for when, alert in candidates
                        if not mismatch_reasons(alert, expectation)]
            if matching:
                when = min(stamp for stamp, _ in matching)
                results.append(f"{rule_id} PASS (+{int((when - start).total_seconds())}s)")
                continue
            test_failed = True
            if candidates:
                reasons = mismatch_reasons(candidates[0][1], expectation)
                results.append(f"{rule_id} DEVIATION: " + "; ".join(reasons))
            else:
                results.append(f"{rule_id} MISSING: no matching rule alert in window")
        status = "FAIL" if test_failed else "PASS"
        failed += test_failed
        rows.append((test_id, test["name"], status, "; ".join(results), "-" if not test_failed else "see alert contract"))

    lines = [f"{len(rows) - failed} of {len(rows)} live tests matched all expected alert contracts", "",
             "| Test | Name | Result | Alert contract checks | Failure |",
             "| --- | --- | --- | --- | --- |"]
    lines += [f"| {test_id} | {name} | {status} | {found} | {failure} |"
              for test_id, name, status, found, failure in rows]
    output = Path(args.out + ".md")
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
