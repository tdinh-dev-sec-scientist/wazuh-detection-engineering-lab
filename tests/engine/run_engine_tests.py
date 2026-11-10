#!/usr/bin/env python3
"""Engine tests: send events to the real wazuh-analysisd and check which rule fires.

Run on a host with a running Wazuh manager (root is needed for the logtest socket):

    sudo python3 tests/engine/run_engine_tests.py --out engine-results

Two kinds of cases are used:
  synthetic  built from the samples in tests/cases.py plus a few extra events
  real       events captured from alerts in the lab (tests/engine/fixtures/real/*.json),
             created with scripts/extract_fixtures.py

Windows events are sent in the decoded JSON form. wazuh-logtest does not run the
eventchannel decoder, so the manager must be prepared with scripts/prepare_engine_tests.py,
which applies the same change to rule 60000 that Wazuh's own ruleset tests use.

Exit code 0 when every case passes.
"""
import argparse
import json
import os
import socket
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from synthetic import build_cases  # noqa: E402

SOCKET = "/var/ossec/queue/sockets/logtest"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "real"


class Logtest:
    def __init__(self, path=SOCKET):
        self.path = path

    def _call(self, command, parameters):
        message = json.dumps({
            "version": 1,
            "origin": {"name": "engine-tests", "module": "engine-tests"},
            "command": command,
            "parameters": parameters,
        }).encode("utf-8")
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.settimeout(30)
        conn.connect(self.path)
        conn.sendall(struct.pack("<I", len(message)) + message)
        size = struct.unpack("<I", conn.recv(4, socket.MSG_WAITALL))[0]
        reply = json.loads(conn.recv(size, socket.MSG_WAITALL))
        conn.close()
        if reply.get("error"):
            raise RuntimeError(f"logtest error {reply.get('error')}: {reply.get('message')}")
        return reply["data"]

    def run(self, events, log_format="syslog", location="stdin"):
        """Send events in one session and return the reply for the last one."""
        token = None
        data = None
        for event in events:
            params = {"event": event, "log_format": log_format, "location": location}
            if token:
                params["token"] = token
            data = self._call("log_processing", params)
            token = data["token"]
        self._call("remove_session", {"token": token})
        return data


def load_real_cases():
    cases = []
    for path in sorted(FIXTURES.glob("*.json")):
        fixture = json.loads(path.read_text(encoding="utf-8"))
        cases.append(dict(
            name=f"{fixture['rule']} real event ({fixture.get('agent', '?')}, {fixture.get('captured', '?')})",
            rule=fixture["rule"], kind="real",
            events=[fixture["event"]] * int(fixture.get("repeat", 1)),
            log_format=fixture.get("log_format", "syslog"), expect=fixture["expect"]))
    return cases


def _mitre_ids(rule):
    value = (rule.get("mitre") or {}).get("id", [])
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def evaluate(case, data):
    out = data.get("output", {})
    rule = out.get("rule") or {}
    fired = str(rule.get("id", ""))
    try:
        level = int(rule.get("level")) if rule.get("level") is not None else None
    except (TypeError, ValueError):
        level = None
    mitre = _mitre_ids(rule)
    expect = case["expect"]
    problems = []
    if "rule_id" in expect and fired != str(expect["rule_id"]):
        problems.append(f"expected rule {expect['rule_id']}, got {fired or 'none'}")
    if "not_rule_id" in expect and fired == str(expect["not_rule_id"]):
        problems.append(f"rule {fired} fired but should not have")
    if "level" in expect and level != int(expect["level"]):
        problems.append(f"expected level {expect['level']}, got {level}")
    if "mitre" in expect:
        expected_mitre = [str(item) for item in expect["mitre"]]
        if mitre != expected_mitre:
            problems.append(f"expected exact MITRE IDs {expected_mitre}, got {mitre}")
    if problems:
        brief = {k: v for k, v in out.items() if k in ("predecoder", "decoder", "data", "rule")}
        problems.append("output " + json.dumps(brief, separators=(",", ":"))[:500])
    return fired, level, mitre, problems


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="engine-results")
    parser.add_argument("--socket", default=SOCKET)
    args = parser.parse_args()

    cases = build_cases() + load_real_cases()
    for case in cases:
        expect = case["expect"]
        if case["kind"] == "synthetic" and "rule_id" in expect:
            if "level" not in expect or "mitre" not in expect:
                raise ValueError(f"synthetic positive lacks level/MITRE oracle: {case['name']}")
        if "mitre" in expect and not isinstance(expect["mitre"], list):
            raise ValueError(f"MITRE oracle must be an array: {case['name']}")
    logtest = Logtest(args.socket)
    results = []
    for case in cases:
        try:
            data = logtest.run(case["events"], case["log_format"])
            fired, level, mitre, problems = evaluate(case, data)
        except Exception as exc:  # report and keep going
            fired, level, mitre, problems = "", None, [], [f"error: {exc}"]
        results.append(dict(case=case["name"], rule=case["rule"], kind=case["kind"],
                            expect=case["expect"], fired=fired, level=level, mitre=mitre,
                            passed=not problems, problems=problems))

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")

    lines = ["| Case | Kind | Expected | Fired | Level | Result |", "| --- | --- | --- | --- | --- | --- |"]
    for r in results:
        expected = r["expect"].get("rule_id")
        if expected:
            expected = f"{expected} / level {r['expect'].get('level')} / MITRE {r['expect'].get('mitre', [])}"
        else:
            expected = f"not {r['expect'].get('not_rule_id')}"
        mark = "pass" if r["passed"] else "FAIL: " + "; ".join(r["problems"])
        lines.append(f"| {r['case']} | {r['kind']} | {expected} | {r['fired'] or 'none'} | {r['level'] if r['level'] is not None else ''} | {mark} |")
    passed = sum(1 for r in results if r["passed"])
    real = [r for r in results if r["kind"] == "real"]
    summary = (f"{passed} of {len(results)} engine cases passed "
               f"({len(real)} on real captured events, {len(results) - len(real)} synthetic).")
    (out_dir / "results.md").write_text(summary + "\n\n" + "\n".join(lines) + "\n", encoding="utf-8")
    print(summary)
    annotate = bool(os.environ.get("GITHUB_ACTIONS"))
    shown = 0
    for r in results:
        if not r["passed"]:
            print(f"  FAIL {r['case']}: {'; '.join(r['problems'])}")
            if annotate and shown < 9:
                shown += 1
                print(f"::error::{r['case']}: {'; '.join(r['problems'])}"[:900])
    if annotate:
        print(f"::notice::{summary}")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # make the reason visible as a workflow annotation
        if os.environ.get("GITHUB_ACTIONS"):
            print(f"::error::{type(exc).__name__}: {exc}"[:900])
        raise
