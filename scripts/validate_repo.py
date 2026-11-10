#!/usr/bin/env python3
"""Consistency checks for the rule set and its documentation.

Checks:
  1. rules/local_rules.xml and decoders/local_decoder.xml are well formed.
  2. Rule IDs are unique and every rule has a level and a description.
  3. Every pcre2 pattern compiles, and every MITRE ID has a valid format.
  4. A rule with frequency has a timeframe.
  5. docs/rule-catalog.md lists exactly the rules in the XML.
  6. mitre/attack-navigator-layer.json is valid JSON and covers every technique used by a rule.
  7. Every screenshot referenced in the docs exists and every screenshot file is referenced.
  8. docs/detection-quality.md has a row for every rule.
  9. Every engine fixture under tests/engine/fixtures/real is valid and names an existing rule.
 10. tests/live/expected.json only expects custom rules that exist.

Exit code 0 when all checks pass, 1 otherwise.
"""
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
errors = []


def fail(message):
    errors.append(message)


def load_xml(path):
    text = path.read_text(encoding="utf-8")
    try:
        return ET.fromstring("<root>" + text + "</root>")
    except ET.ParseError as exc:
        fail(f"{path.relative_to(ROOT)}: not well formed XML ({exc})")
        return None


def main():
    rules_root = load_xml(ROOT / "rules" / "local_rules.xml")
    load_xml(ROOT / "decoders" / "local_decoder.xml")
    load_xml(ROOT / "configs" / "wazuh-agent-defender-localfile.xml")
    if rules_root is None:
        return report()

    rule_ids = []
    techniques = set()
    for rule in rules_root.iter("rule"):
        rid = rule.attrib.get("id", "?")
        rule_ids.append(rid)
        if "level" not in rule.attrib:
            fail(f"rule {rid}: missing level")
        if rule.find("description") is None or not (rule.find("description").text or "").strip():
            fail(f"rule {rid}: missing description")
        if "frequency" in rule.attrib and "timeframe" not in rule.attrib:
            fail(f"rule {rid}: frequency without timeframe")
        for field in rule.iter("field"):
            if field.attrib.get("type") == "pcre2":
                try:
                    re.compile(field.text or "")
                except re.error as exc:
                    fail(f"rule {rid}: pattern does not compile ({exc}): {field.text}")
        for tid in rule.findall("./mitre/id"):
            value = (tid.text or "").strip()
            if not re.fullmatch(r"T\d{4}(\.\d{3})?", value):
                fail(f"rule {rid}: bad MITRE ID {value!r}")
            techniques.add(value)

    duplicates = {i for i in rule_ids if rule_ids.count(i) > 1}
    if duplicates:
        fail(f"duplicate rule IDs: {sorted(duplicates)}")

    # Rule catalog must list exactly the rules in the XML.
    catalog = (ROOT / "docs" / "rule-catalog.md").read_text(encoding="utf-8")
    catalog_ids = set(re.findall(r"^\| (\d{6}) \|", catalog, flags=re.M))
    if catalog_ids != set(rule_ids):
        fail(
            "docs/rule-catalog.md and rules/local_rules.xml disagree: "
            f"only in catalog {sorted(catalog_ids - set(rule_ids))}, "
            f"only in XML {sorted(set(rule_ids) - catalog_ids)}"
        )

    # ATT&CK Navigator layer must cover every technique used by a rule.
    layer_path = ROOT / "mitre" / "attack-navigator-layer.json"
    try:
        layer = json.loads(layer_path.read_text(encoding="utf-8"))
        layer_ids = {t["techniqueID"] for t in layer["techniques"]}
        missing = techniques - layer_ids
        if missing:
            fail(f"ATT&CK layer is missing techniques used by rules: {sorted(missing)}")
    except (OSError, ValueError, KeyError) as exc:
        fail(f"mitre/attack-navigator-layer.json: {exc}")

    # Screenshots referenced in the docs must exist, and none may be orphaned.
    shots_dir = ROOT / "screenshots"
    on_disk = {p.name for p in shots_dir.glob("*.png")}
    referenced = set()
    for doc in (ROOT / "docs").rglob("*.md"):
        for name in re.findall(r"\((?:\.\./)+screenshots/([^)]+)\)", doc.read_text(encoding="utf-8")):
            referenced.add(name)
    for name in sorted(referenced - on_disk):
        fail(f"docs reference a missing screenshot: {name}")
    for name in sorted(on_disk - referenced):
        fail(f"screenshot is not referenced by any doc: {name}")

    # The quality page must cover every rule.
    quality = (ROOT / "docs" / "detection-quality.md").read_text(encoding="utf-8")
    quality_ids = set(re.findall(r"^\| (\d{6}) \|", quality, flags=re.M))
    if quality_ids != set(rule_ids):
        fail("docs/detection-quality.md and rules/local_rules.xml disagree: "
             f"only in quality page {sorted(quality_ids - set(rule_ids))}, "
             f"only in XML {sorted(set(rule_ids) - quality_ids)}")

    # Captured engine fixtures may assert either a positive alert contract or
    # an explicit negative target-rule expectation.
    for path in sorted((ROOT / "tests" / "engine" / "fixtures" / "real").glob("*.json")):
        try:
            fixture = json.loads(path.read_text(encoding="utf-8"))
            if fixture["rule"] not in rule_ids:
                fail(f"{path.name}: unknown rule {fixture['rule']}")
            expect = fixture["expect"]
            if not fixture["event"] or not isinstance(expect, dict):
                fail(f"{path.name}: missing event or object expectation")
            if "rule_id" in expect:
                if expect["rule_id"] != fixture["rule"]:
                    fail(f"{path.name}: positive expectation does not match fixture rule")
                if "level" in expect and (isinstance(expect["level"], bool) or not isinstance(expect["level"], int)):
                    fail(f"{path.name}: expectation level must be an integer")
                if "mitre" in expect and not isinstance(expect["mitre"], list):
                    fail(f"{path.name}: expectation MITRE IDs must be an array")
            elif "not_rule_id" in expect:
                if expect["not_rule_id"] != fixture["rule"]:
                    fail(f"{path.name}: negative expectation does not name fixture rule")
            else:
                fail(f"{path.name}: expectation must contain rule_id or not_rule_id")
        except (ValueError, KeyError, TypeError) as exc:
            fail(f"{path.name}: {exc}")

    # Live expectations require a complete alert contract for every expected rule.
    try:
        live = json.loads((ROOT / "tests" / "live" / "expected.json").read_text(encoding="utf-8"))
        for test in live["tests"]:
            if not isinstance(test.get("expect"), list) or not test["expect"]:
                fail(f"tests/live/expected.json: {test.get('id')} has no alert contracts")
                continue
            for expectation in test["expect"]:
                required = ("rule_id", "agent_name", "event_source", "level", "mitre")
                missing = [key for key in required if key not in expectation]
                if missing:
                    fail(f"tests/live/expected.json: {test['id']} missing {', '.join(missing)}")
                    continue
                rid = str(expectation["rule_id"])
                if rid.startswith("100") and rid not in rule_ids:
                    fail(f"tests/live/expected.json: {test['id']} expects unknown rule {rid}")
                if not isinstance(expectation["event_source"], dict) or not expectation["event_source"]:
                    fail(f"tests/live/expected.json: {test['id']} has no event source")
                if isinstance(expectation["level"], bool) or not isinstance(expectation["level"], int):
                    fail(f"tests/live/expected.json: {test['id']} level must be an integer")
                if not isinstance(expectation["mitre"], list):
                    fail(f"tests/live/expected.json: {test['id']} MITRE must be an array")
                for technique in expectation["mitre"]:
                    if not re.fullmatch(r"T\d{4}(\.\d{3})?", str(technique)):
                        fail(f"tests/live/expected.json: {test['id']} has invalid MITRE ID {technique!r}")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        fail(f"tests/live/expected.json: {exc}")

    print(f"{len(rule_ids)} rules, {len(techniques)} techniques, "
          f"{len(on_disk)} screenshots checked")
    return report()


def report():
    if errors:
        print("\nFAILED")
        for message in errors:
            print(f"  - {message}")
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
