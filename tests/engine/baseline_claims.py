#!/usr/bin/env python3
"""Check the claims the docs make about Wazuh's default rules against the installed ruleset.

Run with the path to the stock rules (default /var/ossec/ruleset/rules):

    python3 tests/engine/baseline_claims.py [rules_dir]

Every row of the coverage table that says what the default ruleset does is backed by an
assertion here, so a wording like "no technique" cannot drift from the real rule definition.
"""
import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def load(rules_dir):
    rules = {}
    for path in sorted(Path(rules_dir).glob("*.xml")):
        text = re.sub(r"<\?xml[^>]*\?>", "", path.read_text(encoding="utf-8"))
        try:
            root = ET.fromstring("<root>" + text + "</root>")
        except ET.ParseError:
            continue
        for rule in root.iter("rule"):
            rules[rule.attrib["id"]] = rule
    return rules


# (rule id, level, techniques that must be present, techniques that must be absent, note)
CLAIMS = [
    ("60109", 8, {"T1098"}, {"T1136.001", "T1136.002"}, "account creation carries T1098, not Create Account"),
    ("60204", 10, {"T1110"}, set(), "multiple logon failures map to T1110"),
    ("63103", 5, {"T1070"}, {"T1070.001"}, "Security 1102 maps to the parent technique only"),
    ("63104", 5, {"T1070"}, {"T1070.001"}, "event 104 maps to the parent technique only"),
    ("67027", 3, set(), set(), "generic process creation has no technique"),
    ("92052", 4, {"T1059.003"}, {"T1021.002"}, "no admin share technique"),
    ("92032", 3, {"T1087"}, {"T1087.001"}, "discovery alert is generic"),
    ("92033", 3, {"T1087"}, {"T1087.001"}, "discovery alert is generic"),
    ("92036", 3, set(), {"T1087.001"}, "generic cmd child alert"),
    ("92057", 12, {"T1059.001"}, set(), "encoded PowerShell is covered at level 12"),
    ("92302", 6, {"T1547.001"}, set(), "Run key persistence is covered"),
    ("61138", 5, {"T1543.003"}, set(), "service creation is covered"),
    ("92307", 3, {"T1543.003"}, set(), "service registry key is covered"),
    ("62123", 12, set(), set(), "Defender detection has no technique"),
    ("92213", 15, {"T1105"}, set(), "executable dropped in a malware folder"),
]


def main():
    rules_dir = sys.argv[1] if len(sys.argv) > 1 else "/var/ossec/ruleset/rules"
    rules = load(rules_dir)
    failures = []
    for rid, level, present, absent, note in CLAIMS:
        rule = rules.get(rid)
        if rule is None:
            failures.append(f"rule {rid} not found in {rules_dir}")
            continue
        techniques = {t.text for t in rule.findall("./mitre/id")}
        if int(rule.attrib["level"]) != level:
            failures.append(f"rule {rid}: level {rule.attrib['level']}, docs say {level}")
        for t in present - techniques:
            failures.append(f"rule {rid}: {t} not present ({note})")
        for t in absent & techniques:
            failures.append(f"rule {rid}: {t} present, docs say it is not ({note})")
    # 87701 is why default firewall blocks never alert.
    options = [o.text for o in rules["87701"].findall("options")] if "87701" in rules else []
    if "no_log" not in options:
        failures.append("rule 87701: expected the no_log option")
    print(f"{len(CLAIMS) + 1} claims about the default ruleset checked in {rules_dir}")
    for message in failures:
        print("  FAIL", message)
        if os.environ.get("GITHUB_ACTIONS"):
            print(f"::error::{message}")
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # make the reason visible as a workflow annotation
        if os.environ.get("GITHUB_ACTIONS"):
            print(f"::error::{type(exc).__name__}: {exc}"[:900])
        raise
