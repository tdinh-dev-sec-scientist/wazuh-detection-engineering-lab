#!/usr/bin/env python3
"""Capture real events from Wazuh alerts and save them as engine test fixtures.

Run on the Wazuh manager (root is needed to read the alert files):

    sudo python3 scripts/extract_fixtures.py --rules rules/local_rules.xml --out tests/engine/fixtures/real

For every custom rule that has alerted, the script picks the earliest alert that still
carries its full_log and writes tests/engine/fixtures/real/<rule>.json with the event text and
what the lab produced for it (rule id, level, ATT&CK techniques). The engine tests then replay
that exact event through a clean Wazuh manager and expect the same result.

Alert files read: /var/ossec/logs/alerts/alerts.json and the rotated daily files under
/var/ossec/logs/alerts/<year>/<month>/ (plain or gzip).
"""
import argparse
import glob
import gzip
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ALERT_DIR = "/var/ossec/logs/alerts"
# Rules that need several events before they fire.
REPEAT = {"100400": 10}


def alert_files():
    files = sorted(glob.glob(f"{ALERT_DIR}/*/*/ossec-alerts-*.json*"))
    current = Path(ALERT_DIR) / "alerts.json"
    if current.exists():
        files.append(str(current))
    return files


def open_any(path):
    return gzip.open(path, "rt", encoding="utf-8", errors="replace") if path.endswith(".gz") \
        else open(path, encoding="utf-8", errors="replace")


def custom_rule_ids(rules_file):
    text = Path(rules_file).read_text(encoding="utf-8")
    root = ET.fromstring("<root>" + text + "</root>")
    return [r.attrib["id"] for r in root.iter("rule")]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rules", default="rules/local_rules.xml")
    parser.add_argument("--out", default="tests/engine/fixtures/real")
    parser.add_argument("--alerts-dir", default=ALERT_DIR)
    args = parser.parse_args()

    wanted = set(custom_rule_ids(args.rules))
    found = {}
    counts = {}
    for path in alert_files():
        with open_any(path) as handle:
            for line in handle:
                if '"rule"' not in line:
                    continue
                try:
                    alert = json.loads(line)
                except ValueError:
                    continue
                rid = str(alert.get("rule", {}).get("id", ""))
                if rid not in wanted:
                    continue
                counts[rid] = counts.get(rid, 0) + 1
                if rid in found or not alert.get("full_log"):
                    continue
                found[rid] = alert

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for rid, alert in sorted(found.items()):
        rule = alert["rule"]
        mitre = (rule.get("mitre") or {}).get("id", [])
        fixture = {
            "rule": rid,
            "agent": alert.get("agent", {}).get("name", ""),
            "captured": alert.get("timestamp", ""),
            "log_format": "syslog",
            "event": alert["full_log"],
            "expect": {"rule_id": rid, "level": rule.get("level"), "mitre": mitre},
        }
        if rid in REPEAT:
            fixture["repeat"] = REPEAT[rid]
        (out / f"{rid}.json").write_text(json.dumps(fixture, indent=2) + "\n", encoding="utf-8")

    print(f"{len(found)} of {len(wanted)} rules have a captured event -> {out}")
    for rid in sorted(wanted):
        state = f"{counts.get(rid, 0)} alerts, fixture written" if rid in found else \
            f"{counts.get(rid, 0)} alerts, nothing to capture"
        print(f"  {rid}: {state}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
