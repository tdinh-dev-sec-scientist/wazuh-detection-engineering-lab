#!/usr/bin/env python3
"""Count alerts per rule per day for the baseline week and export the distinct events.

Run on the Wazuh manager (root is needed to read the alert files):

    sudo python3 scripts/baseline_report.py --start "2026-11-02 08:00" --end "2026-11-09 08:00" \
        --rules rules/local_rules.xml --actions actions.csv --out baseline-week1

Writes
  <out>.md           per rule per day table, per rule summary, top event tuples, collector health
  <out>-events.jsonl one line per distinct event shape for each custom rule, with a count, so the
                     tuned rules can be scored against the same week without waiting another week
  <out>.csv          the per rule per day counts

--actions takes the actions.csv written by baseline/Generate-NormalActivity.ps1. An alert that
follows a recorded action within --window seconds is counted as explained by the generator.
"""
import argparse
import csv
import glob
import gzip
import json
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

ALERT_DIR = "/var/ossec/logs/alerts"
HEALTH = {"202": "agent queue 90% full", "203": "agent queue full", "204": "agent queue flooded",
          "205": "agent queue back to normal", "504": "agent disconnected", "506": "agent stopped"}
VOLATILE = {"systemTime", "eventRecordID", "processID", "threadID", "processGuid", "utcTime",
            "logonId", "logonGuid", "subjectLogonId", "targetLogonId", "newProcessId", "parentProcessGuid",
            "parentProcessId", "hashes", "terminalSessionId", "targetSid", "memberSid", "message", "processId"}


def alert_files(alert_dir):
    files = sorted(glob.glob(f"{alert_dir}/*/*/ossec-alerts-*.json*"))
    current = Path(alert_dir) / "alerts.json"
    if current.exists():
        files.append(str(current))
    return files


def open_any(path):
    return gzip.open(path, "rt", encoding="utf-8", errors="replace") if path.endswith(".gz") \
        else open(path, encoding="utf-8", errors="replace")


def rule_ids(path):
    root = ET.fromstring("<root>" + Path(path).read_text(encoding="utf-8") + "</root>")
    return [r.attrib["id"] for r in root.iter("rule")]


def parse_ts(value):
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f%z")


def strip_volatile(node):
    if isinstance(node, dict):
        return {k: strip_volatile(v) for k, v in node.items() if k not in VOLATILE}
    return node


def signature(alert):
    """Stable key for the shape of an event: its content without ids, times and handles."""
    try:
        event = json.loads(alert["full_log"])
    except (ValueError, KeyError, TypeError):
        return alert.get("full_log", "")[:300]
    return json.dumps(strip_volatile(event), sort_keys=True)


def short(text, limit=90):
    text = " ".join(str(text).replace("\\\\", "\\").split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def tuple_label(alert):
    ed = alert.get("data", {}).get("win", {}).get("eventdata", {})
    if ed:
        parent = ed.get("parentImage") or ed.get("parentProcessName") or ""
        who = ed.get("user") or ed.get("subjectUserName") or ed.get("targetUserName") or ""
        what = ed.get("commandLine") or ed.get("image") or ed.get("targetUserName") or ""
        return f"{short(who, 30)} | parent {short(parent.split(chr(92))[-1], 30)} | {short(what)}"
    data = alert.get("data", {})
    if data.get("srcip") or data.get("src_ip"):
        return f"{data.get('srcip') or data.get('src_ip')} -> {data.get('dstip') or data.get('dest_ip')}:{data.get('dstport') or data.get('dest_port', '')}"
    return short(alert.get("full_log", ""))


def load_actions(path, tz):
    rows = []
    with open(path, encoding="utf-8-sig") as handle:
        for row in csv.DictReader(handle):
            try:
                rows.append(datetime.strptime(row["time"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=tz))
            except (ValueError, KeyError):
                continue
    return sorted(rows)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--start", required=True)
    p.add_argument("--end", required=True)
    p.add_argument("--tz", default="America/New_York")
    p.add_argument("--rules", default="rules/local_rules.xml")
    p.add_argument("--also", default="", help="comma separated stock rule ids to count as well")
    p.add_argument("--actions", help="actions.csv from the generator")
    p.add_argument("--window", type=int, default=180)
    p.add_argument("--top", type=int, default=5)
    p.add_argument("--alerts-dir", default=ALERT_DIR)
    p.add_argument("--out", default="baseline")
    args = p.parse_args()

    tz = ZoneInfo(args.tz)
    start = datetime.strptime(args.start, "%Y-%m-%d %H:%M").replace(tzinfo=tz)
    end = datetime.strptime(args.end, "%Y-%m-%d %H:%M").replace(tzinfo=tz)
    wanted = set(rule_ids(args.rules)) | {r for r in args.also.split(",") if r}
    actions = load_actions(args.actions, tz) if args.actions else []

    seen, per_day, tuples, shapes, health = set(), defaultdict(Counter), defaultdict(Counter), {}, defaultdict(Counter)
    hosts, explained = defaultdict(set), Counter()
    total = Counter()
    for path in alert_files(args.alerts_dir):
        with open_any(path) as handle:
            for line in handle:
                try:
                    alert = json.loads(line)
                    when = parse_ts(alert["timestamp"]).astimezone(tz)
                except (ValueError, KeyError):
                    continue
                if not (start <= when < end):
                    continue
                key = alert.get("id") or (alert["timestamp"], alert["rule"]["id"], alert.get("full_log", "")[:80])
                if key in seen:
                    continue
                seen.add(key)
                rid = str(alert["rule"]["id"])
                day = when.strftime("%Y-%m-%d")
                if rid in HEALTH:
                    health[rid][day] += 1
                if rid not in wanted:
                    continue
                per_day[rid][day] += 1
                total[rid] += 1
                hosts[rid].add(alert.get("agent", {}).get("name", ""))
                tuples[rid][tuple_label(alert)] += 1
                if actions and any(timedelta(0) <= when - a <= timedelta(seconds=args.window) for a in actions):
                    explained[rid] += 1
                sig = signature(alert)
                if (rid, sig) not in shapes:
                    shapes[(rid, sig)] = {"rule": rid, "agent": alert.get("agent", {}).get("name", ""),
                                          "captured": alert["timestamp"], "log_format": "syslog",
                                          "event": alert.get("full_log", ""), "level": alert["rule"].get("level"),
                                          "mitre": (alert["rule"].get("mitre") or {}).get("id", []), "count": 0}
                shapes[(rid, sig)]["count"] += 1

    days = []
    d = start.replace(hour=0, minute=0)
    while d < end:
        days.append(d.strftime("%Y-%m-%d"))
        d += timedelta(days=1)
    days = sorted(set(days))

    out = Path(args.out)
    with open(f"{out}.csv", "w", newline="", encoding="utf-8") as handle:
        w = csv.writer(handle)
        w.writerow(["rule"] + days + ["total", "per_day"])
        for rid in sorted(wanted):
            w.writerow([rid] + [per_day[rid][x] for x in days] + [total[rid], round(total[rid] / max(1, len(days)), 2)])
    with open(f"{out}-events.jsonl", "w", encoding="utf-8") as handle:
        for item in sorted(shapes.values(), key=lambda s: (s["rule"], -s["count"])):
            handle.write(json.dumps(item) + "\n")

    lines = [f"# Baseline {args.start} to {args.end} ({args.tz})", "",
             f"{sum(total.values())} alerts from {len([r for r in wanted if total[r]])} of {len(wanted)} counted rules, "
             f"{len(shapes)} distinct event shapes.", "",
             "## Alerts per rule per day", "",
             "| Rule | " + " | ".join(x[5:] for x in days) + " | Total | Per day | Hosts |",
             "| --- |" + " --- |" * (len(days) + 3)]
    for rid in sorted(wanted):
        lines.append(f"| {rid} | " + " | ".join(str(per_day[rid][x]) for x in days) +
                     f" | {total[rid]} | {total[rid] / max(1, len(days)):.1f} | {', '.join(sorted(hosts[rid])) or '-'} |")
    if actions:
        lines += ["", f"## Alerts that follow a generator action within {args.window} s", "",
                  "| Rule | Alerts | Explained | Unexplained |", "| --- | --- | --- | --- |"]
        for rid in sorted(r for r in wanted if total[r]):
            lines.append(f"| {rid} | {total[rid]} | {explained[rid]} | {total[rid] - explained[rid]} |")
    lines += ["", "## Top event tuples per rule", ""]
    for rid in sorted(r for r in wanted if total[r]):
        lines += [f"### {rid} ({total[rid]} alerts)", ""]
        for label, count in tuples[rid].most_common(args.top):
            lines.append(f"- {count} x {label}")
        lines.append("")
    lines += ["## Collector health", "", "| Rule | Meaning | " + " | ".join(x[5:] for x in days) + " |",
              "| --- | --- |" + " --- |" * len(days)]
    for rid, meaning in HEALTH.items():
        lines.append(f"| {rid} | {meaning} | " + " | ".join(str(health[rid][x]) for x in days) + " |")
    Path(f"{out}.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"{sum(total.values())} alerts, {len(shapes)} event shapes -> {out}.md, {out}.csv, {out}-events.jsonl")
    return 0


if __name__ == "__main__":
    sys.exit(main())
