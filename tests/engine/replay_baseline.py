#!/usr/bin/env python3
"""Replay captured baseline events and fail on any unexpected detection drift.

Run on a Wazuh manager after scripts/prepare_engine_tests.py:

    sudo python3 tests/engine/replay_baseline.py baseline/week1-events.jsonl \\
        --min-level 6 --out replay-results

Input is the *-events.jsonl file written by scripts/baseline_report.py. Each line
contains the captured event, its prior ``rule`` and ``level``, and optionally an
``expect`` object describing the intended current result, for example:

    {"rule":"92032","level":3,"expect":{"rule_id":"100500","level":8}, ...}

Without ``expect``, the captured rule and level are the strict oracle. This makes
rule changes explicit: update the line's ``expect`` only after reviewing the
intended rule and severity. Missing rule hits, unexpected rule IDs, and severity
deviations all fail the command with exit code 1.
"""
import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_engine_tests import Logtest, SOCKET  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("events")
    parser.add_argument("--min-level", type=int, default=6,
                        help="level at which an alert would reach an analyst")
    parser.add_argument("--out", default="replay-results")
    parser.add_argument("--socket", default=SOCKET)
    args = parser.parse_args()

    logtest = Logtest(args.socket)
    before, after = Counter(), Counter()
    rows = []
    failures = 0
    processed = 0
    for line_number, line in enumerate(Path(args.events).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        item = json.loads(line)
        processed += 1
        count = int(item.get("count", 1))
        old_rule = str(item["rule"])
        old_level = int(item.get("level") or 0)
        expect = item.get("expect") or {}
        if not isinstance(expect, dict):
            raise ValueError(f"line {line_number}: expect must be an object")
        expected_rule = str(expect.get("rule_id", old_rule))
        expected_level = int(expect.get("level", old_level) or 0)

        data = logtest.run([item["event"]] * int(item.get("repeat", 1)),
                           item.get("log_format", "syslog"))
        rule = (data.get("output") or {}).get("rule") or {}
        actual_rule = str(rule.get("id", ""))
        actual_level = int(rule.get("level", 0) or 0)
        problems = []
        if not actual_rule:
            problems.append("missing alert hit")
        elif actual_rule != expected_rule:
            problems.append(f"unexpected rule {actual_rule}; expected {expected_rule}")
        if actual_level != expected_level:
            problems.append(f"severity deviation {actual_level}; expected {expected_level}")

        if old_level >= args.min_level:
            before[old_rule] += count
        if actual_level >= args.min_level and actual_rule.startswith("100"):
            after[actual_rule] += count
        if (actual_rule, actual_level) != (old_rule, old_level):
            rows.append((old_rule, old_level, expected_rule, expected_level,
                         actual_rule or "none", actual_level, count, problems))
        elif problems:
            rows.append((old_rule, old_level, expected_rule, expected_level,
                         actual_rule or "none", actual_level, count, problems))
        else:
            rows.append((old_rule, old_level, expected_rule, expected_level,
                         actual_rule or "none", actual_level, count, problems))
        failures += bool(problems)

    if processed == 0:
        failures += 1
        rows.append(("-", 0, "-", 0, "none", 0, 0, ["no input events were processed"]))

    rules = sorted(set(before) | set(after))
    lines = [f"Alerts at level {args.min_level} or higher, same events, before and after tuning", "",
             "| Rule | Before | After | Change |", "| --- | --- | --- | --- |"]
    for rule_id in rules:
        old_count, new_count = before[rule_id], after[rule_id]
        change = f"{(new_count - old_count) / old_count * 100:+.0f}%" if old_count else ("new" if new_count else "-")
        lines.append(f"| {rule_id} | {old_count} | {new_count} | {change} |")
    total_before, total_after = sum(before.values()), sum(after.values())
    lines.append(f"| all | {total_before} | {total_after} | "
                 f"{(total_after - total_before) / max(1, total_before) * 100:+.0f}% |")
    lines += ["", "Replay assertions:", "", "| Line | Prior | Expected current | Actual | Count | Result |",
              "| --- | --- | --- | --- | --- | --- |"]
    for index, (old_rule, old_level, expected_rule, expected_level,
                actual_rule, actual_level, count, problems) in enumerate(rows, 1):
        result = "FAIL: " + "; ".join(problems) if problems else "PASS"
        lines.append(f"| {index} | {old_rule} (L{old_level}) | {expected_rule} (L{expected_level}) | "
                     f"{actual_rule} (L{actual_level}) | {count} | {result} |")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "replay.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    if os.environ.get("GITHUB_ACTIONS"):
        print("::notice::replay " + " ; ".join(
            line for line in lines if line.startswith("| all") or line.startswith("| 100"))[:900])
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
