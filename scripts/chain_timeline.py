#!/usr/bin/env python3
"""Build a timeline of Wazuh alerts for a time window.

Run on the Wazuh manager (root is needed to read the alert files):

    sudo python3 scripts/chain_timeline.py --start "2026-10-16 10:00" --end "2026-10-16 10:40" \
        --tz America/New_York --min-level 3 --out chain-alerts

Writes <out>.md (a table you can read) and <out>.json (the raw alerts) with one row per alert
from every agent: Windows endpoints, the firewall syslog stream and Suricata.
"""
import argparse
import glob
import gzip
import json
import sys
from datetime import datetime, timezone
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


def parse_ts(value):
    # Wazuh writes 2026-10-15T16:36:17.123+0000
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f%z")


def short(text, limit=110):
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def key_detail(alert):
    data = alert.get("data", {})
    win = data.get("win", {})
    ed = win.get("eventdata", {})
    parts = []
    if ed.get("commandLine"):
        parts.append("cmd: " + short(ed["commandLine"].replace("\\\\", "\\")))
    elif ed.get("image"):
        parts.append("image: " + ed["image"].replace("\\\\", "\\"))
    for key, label in (("targetUserName", "target user"), ("subjectUserName", "subject"),
                       ("ipAddress", "src ip"), ("workstationName", "workstation"),
                       ("logonType", "logon type"), ("status", "status"), ("subStatus", "sub status"),
                       ("user", "user")):
        if ed.get(key) and ed.get(key) != "-":
            parts.append(f"{label}: {short(ed[key].replace(chr(92) * 2, chr(92)), 40)}")
    if data.get("src_ip"):
        parts.append(f"{data['src_ip']} -> {data.get('dest_ip', '?')}:{data.get('dest_port', '?')}")
    if data.get("srcip") and not data.get("src_ip"):
        parts.append(f"{data['srcip']} -> {data.get('dstip', '?')}")
    return "; ".join(parts)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--start", required=True, help='local time, e.g. "2026-10-16 10:00"')
    parser.add_argument("--end", required=True)
    parser.add_argument("--tz", default="America/New_York")
    parser.add_argument("--min-level", type=int, default=3)
    parser.add_argument("--alerts-dir", default=ALERT_DIR)
    parser.add_argument("--out", default="chain-alerts")
    args = parser.parse_args()

    tz = ZoneInfo(args.tz)
    start = datetime.strptime(args.start, "%Y-%m-%d %H:%M").replace(tzinfo=tz)
    end = datetime.strptime(args.end, "%Y-%m-%d %H:%M").replace(tzinfo=tz)

    rows = []
    seen = set()       # Wazuh writes each alert to alerts.json and to the file of the day
    duplicates = 0
    for path in alert_files(args.alerts_dir):
        with open_any(path) as handle:
            for line in handle:
                try:
                    alert = json.loads(line)
                    when = parse_ts(alert["timestamp"])
                except (ValueError, KeyError):
                    continue
                if not (start <= when <= end):
                    continue
                if int(alert.get("rule", {}).get("level", 0)) < args.min_level:
                    continue
                key = alert.get("id") or (alert["timestamp"], alert.get("rule", {}).get("id"), alert.get("full_log"))
                if key in seen:
                    duplicates += 1
                    continue
                seen.add(key)
                rows.append((when, alert))
    rows.sort(key=lambda item: item[0])

    lines = [f"Alerts from {args.start} to {args.end} ({args.tz}), level {args.min_level} and up: {len(rows)}", "",
             "| Time | Agent | Rule | Level | Description | ATT&CK | Detail |",
             "| --- | --- | --- | --- | --- | --- | --- |"]
    for when, alert in rows:
        rule = alert["rule"]
        mitre = ", ".join((rule.get("mitre") or {}).get("id", []))
        lines.append("| {t} | {agent} | {rid} | {lvl} | {desc} | {mitre} | {detail} |".format(
            t=when.astimezone(tz).strftime("%H:%M:%S"), agent=alert.get("agent", {}).get("name", ""),
            rid=rule.get("id", ""), lvl=rule.get("level", ""), desc=short(rule.get("description", ""), 80),
            mitre=mitre, detail=short(key_detail(alert).replace("|", "/"), 160)))
    Path(args.out + ".md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    Path(args.out + ".json").write_text(json.dumps([a for _, a in rows], indent=1), encoding="utf-8")
    print(f"{len(rows)} alerts written to {args.out}.md and {args.out}.json ({duplicates} duplicate lines skipped)")
    by_rule = {}
    for _, alert in rows:
        rid = alert["rule"]["id"]
        by_rule[rid] = by_rule.get(rid, 0) + 1
    print("per rule:", ", ".join(f"{k}x{v}" for k, v in sorted(by_rule.items())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
