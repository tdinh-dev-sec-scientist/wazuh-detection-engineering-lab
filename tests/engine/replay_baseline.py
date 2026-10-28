#!/usr/bin/env python3
"""Score captured baseline events against the current rules, inside a real Wazuh manager.

    sudo python3 tests/engine/replay_baseline.py baseline/week1-events.jsonl --min-level 6 --out replay-results

Input is the *-events.jsonl file written by scripts/baseline_report.py: one line per distinct
event shape with the rule that alerted when the week was recorded ("rule", "level") and how many
times it happened ("count"). Each event is sent through wazuh-logtest again. The tuned rules
decide which rule fires now and at what level, and the counts give the alerts per week before
and after tuning on the same traffic.

Limits: a frequency rule such as 100400 needs its own events in one session, so it is measured from
the live weeks, not here. The manager must be prepared with scripts/prepare_engine_tests.py.
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
    p = argparse.ArgumentParser()
    p.add_argument("events")
    p.add_argument("--min-level", type=int, default=6, help="level at which an alert would reach an analyst")
    p.add_argument("--out", default="replay-results")
    p.add_argument("--socket", default=SOCKET)
    args = p.parse_args()

    logtest = Logtest(args.socket)
    before, after, moved = Counter(), Counter(), Counter()
    rows = []
    for line in Path(args.events).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        count = int(item.get("count", 1))
        old_rule, old_level = str(item["rule"]), int(item.get("level") or 0)
        data = logtest.run([item["event"]] * int(item.get("repeat", 1)), item.get("log_format", "syslog"))
        rule = (data.get("output") or {}).get("rule") or {}
        new_rule, new_level = str(rule.get("id", "")), int(rule.get("level", 0) or 0)
        if old_level >= args.min_level:
            before[old_rule] += count
        if new_level >= args.min_level and new_rule.startswith("100"):
            after[new_rule] += count
        if (new_rule, new_level) != (old_rule, old_level):
            moved[(old_rule, old_level, new_rule or "none", new_level)] += count
        rows.append((old_rule, old_level, new_rule or "none", new_level, count))

    rules = sorted(set(before) | set(after))
    lines = [f"Alerts at level {args.min_level} or higher, same events, before and after tuning", "",
             "| Rule | Before | After | Change |", "| --- | --- | --- | --- |"]
    for r in rules:
        b, a = before[r], after[r]
        change = f"{(a - b) / b * 100:+.0f}%" if b else ("new" if a else "-")
        lines.append(f"| {r} | {b} | {a} | {change} |")
    lines.append(f"| all | {sum(before.values())} | {sum(after.values())} | "
                 f"{(sum(after.values()) - sum(before.values())) / max(1, sum(before.values())) * 100:+.0f}% |")
    if moved:
        lines += ["", "Events that changed rule or level:", "", "| Was | Now | Events |", "| --- | --- | --- |"]
        for (orule, olevel, nrule, nlevel), count in sorted(moved.items()):
            lines.append(f"| {orule} (level {olevel}) | {nrule} (level {nlevel}) | {count} |")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "replay.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    if os.environ.get("GITHUB_ACTIONS"):
        print("::notice::replay " + " ; ".join(l for l in lines if l.startswith("| all") or l.startswith("| 100"))[:900])
    return 0


if __name__ == "__main__":
    sys.exit(main())
