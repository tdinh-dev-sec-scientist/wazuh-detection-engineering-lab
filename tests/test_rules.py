"""Regression tests for the field patterns in rules/local_rules.xml.

Run from the repository root:  python3 -m unittest discover -s tests -v

The tests extract each rule's <field> patterns from the XML and check them against the
samples in cases.py. Python's re module stands in for PCRE2, which behaves the same for
the constructs used here (lookahead, \\b, \\W, inline (?i)). Parent conditions such as
if_group and if_sid are not evaluated, so wazuh-logtest remains the final check.
"""
import re
import sys
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cases import CASES  # noqa: E402

RULES_FILE = Path(__file__).resolve().parent.parent / "rules" / "local_rules.xml"


def load_rules():
    root = ET.fromstring("<root>" + RULES_FILE.read_text(encoding="utf-8") + "</root>")
    return {rule.attrib["id"]: rule for rule in root.iter("rule")}


def fields_match(rule, values):
    """True when every <field> of the rule matches the sample values."""
    for field in rule.findall("field"):
        name = field.attrib["name"]
        pattern = field.text or ""
        negate = field.attrib.get("negate") == "yes"
        if name not in values:
            return False
        matched = re.search(pattern, values[name]) is not None
        if matched == negate:
            return False
    return True


class RuleFieldTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = load_rules()

    def test_cases_reference_existing_rules(self):
        for rule_id, _values, _expected in CASES:
            self.assertIn(rule_id, self.rules, f"case refers to unknown rule {rule_id}")

    def test_samples(self):
        for rule_id, values, expected in CASES:
            with self.subTest(rule=rule_id, expected=expected, sample=str(values)[:90]):
                self.assertEqual(fields_match(self.rules[rule_id], values), expected)

    def test_every_pattern_rule_has_a_positive_and_negative_case(self):
        covered = {}
        for rule_id, _values, expected in CASES:
            covered.setdefault(rule_id, set()).add(expected)
        pattern_rules = {
            rid for rid, rule in self.rules.items()
            if any(f.attrib.get("type") == "pcre2" for f in rule.findall("field"))
        }
        # 100701, 100711 and 100721 repeat the pattern of their Sysmon twins, so for them a
        # positive case is enough.
        twins = {"100701", "100711", "100721"}
        for rid in sorted(pattern_rules - twins):
            self.assertEqual(covered.get(rid), {True, False}, f"rule {rid} needs a positive and a negative case")


if __name__ == "__main__":
    unittest.main()
