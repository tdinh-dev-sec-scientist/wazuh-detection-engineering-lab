"""Event builders for the engine tests.

The engine tests send events to the real wazuh-analysisd through wazuh-logtest. Windows
events are sent in the JSON form that the manager produces after decoding an eventchannel
message ({"win": {"system": ..., "eventdata": ...}}), which is the same text that appears in
the full_log field of an alert.

Field values are written the way Wazuh stores them: backslashes doubled and quotes escaped
as backslash-quote. json.dumps adds one more level of escaping, and the JSON decoder in the
manager removes it again, so the rules see the stored form.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from cases import CASES  # noqa: E402

COMPUTER = "WS01.corp.lab"


def _set(tree, dotted, value):
    parts = dotted.split(".")
    node = tree
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value


def _merge(base, fields):
    for dotted, value in fields.items():
        _set(base, dotted, value)
    return base


def sysmon_event1(fields):
    event = {"win": {
        "system": {
            "providerName": "Microsoft-Windows-Sysmon",
            "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}",
            "eventID": "1", "version": "5", "level": "4", "task": "1", "opcode": "0",
            "keywords": "0x8000000000000000", "systemTime": "2026-10-15T20:36:17.000000000Z",
            "eventRecordID": "1000", "processID": "2232", "threadID": "3100",
            "channel": "Microsoft-Windows-Sysmon/Operational", "computer": COMPUTER,
            "severityValue": "INFORMATION", "message": "Process Create",
        },
        "eventdata": {
            "ruleName": "-", "utcTime": "2026-10-15 20:36:17.000",
            "processId": "6408", "image": "C:\\\\Windows\\\\System32\\\\cmd.exe",
            "fileVersion": "10.0.26100.1", "description": "Windows Command Processor",
            "product": "Microsoft Windows Operating System", "company": "Microsoft Corporation",
            "originalFileName": "Cmd.Exe", "commandLine": "cmd.exe",
            "currentDirectory": "C:\\\\Windows\\\\System32\\\\", "user": "CORP\\\\adm.truong",
            "logonId": "0x1f4a2b", "terminalSessionId": "1", "integrityLevel": "High",
            "hashes": "SHA256=0000000000000000000000000000000000000000000000000000000000000000",
            "parentProcessId": "5120",
            "parentImage": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",
            "parentCommandLine": "powershell.exe", "parentUser": "CORP\\\\adm.truong",
        },
    }}
    return _merge(event, fields)


def security_4688(fields):
    event = {"win": {
        "system": {
            "providerName": "Microsoft-Windows-Security-Auditing",
            "providerGuid": "{54849625-5478-4994-a5ba-3e3b0328c30d}",
            "eventID": "4688", "version": "2", "level": "0", "task": "13312", "opcode": "0",
            "keywords": "0x8020000000000000", "systemTime": "2026-10-15T20:36:17.000000000Z",
            "eventRecordID": "2000", "processID": "4", "threadID": "100",
            "channel": "Security", "computer": COMPUTER,
            "severityValue": "AUDIT_SUCCESS", "message": "A new process has been created.",
        },
        "eventdata": {
            "subjectUserSid": "S-1-5-21-1-2-3-1104", "subjectUserName": "adm.truong",
            "subjectDomainName": "CORP", "subjectLogonId": "0x1f4a2b",
            "newProcessId": "0x1908", "newProcessName": "C:\\\\Windows\\\\System32\\\\cmd.exe",
            "tokenElevationType": "%%1937", "processId": "0x1400",
            "commandLine": "cmd.exe",
            "targetUserSid": "S-1-0-0", "targetUserName": "-", "targetDomainName": "-",
            "targetLogonId": "0x0",
            "parentProcessName": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",
            "mandatoryLabel": "S-1-16-12288",
        },
    }}
    return _merge(event, fields)


def security_4720(fields):
    event = {"win": {
        "system": {
            "providerName": "Microsoft-Windows-Security-Auditing",
            "providerGuid": "{54849625-5478-4994-a5ba-3e3b0328c30d}",
            "eventID": "4720", "version": "0", "level": "0", "task": "13824", "opcode": "0",
            "keywords": "0x8020000000000000", "systemTime": "2026-10-15T21:11:48.000000000Z",
            "eventRecordID": "3000", "processID": "4", "threadID": "100",
            "channel": "Security", "computer": COMPUTER,
            "severityValue": "AUDIT_SUCCESS", "message": "A user account was created.",
        },
        "eventdata": {
            "targetUserName": "T1136.001_CMD", "targetDomainName": "WS01",
            "targetSid": "S-1-5-21-9-8-7-1001", "subjectUserSid": "S-1-5-21-1-2-3-1104",
            "subjectUserName": "adm.truong", "subjectDomainName": "CORP",
            "subjectLogonId": "0x1f4a2b", "privilegeList": "-",
            "samAccountName": "T1136.001_CMD",
        },
    }}
    return _merge(event, fields)


def eventlog_cleared(event_id):
    """Event 1102 (Security channel) or 104 (System channel) from the Eventlog provider."""
    channel = "Security" if event_id == "1102" else "System"
    return {"win": {
        "system": {
            "providerName": "Microsoft-Windows-Eventlog",
            "providerGuid": "{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}",
            "eventID": event_id, "version": "0", "level": "4", "task": "104", "opcode": "0",
            "keywords": "0x4020000000000000", "systemTime": "2026-10-15T21:23:30.000000000Z",
            "eventRecordID": "4000", "processID": "1100", "threadID": "2200",
            "channel": channel, "computer": COMPUTER, "severityValue": "INFORMATION",
            "message": "The log file was cleared.",
        },
        "eventdata": {"subjectUserName": "adm.truong", "subjectDomainName": "CORP",
                      "subjectLogonId": "0x1f4a2b", "channel": "Application"},
    }}


SYSMON_RULES = {"100100", "100101", "100500", "100501", "100550", "100552", "100600",
                "100601", "100602", "100603", "100700", "100710", "100720"}
SEC4688_RULES = {"100701", "100711", "100721", "100722"}

SURICATA_LINE = (
    '<134>Oct 15 15:40:51 FW01.corp.lab suricata[53242]: {"timestamp":"2026-10-15T15:40:51.123456-0400",'
    '"flow_id":1234567890123,"in_iface":"igb4","event_type":"alert","src_ip":"10.10.50.181","src_port":41352,'
    '"dest_ip":"10.10.30.149","dest_port":1433,"proto":"TCP","alert":{"action":"allowed","gid":1,'
    '"signature_id":2010935,"rev":3,"signature":"ET SCAN Suspicious inbound to MSSQL port 1433",'
    '"category":"Potential Corporate Privacy Violation","severity":2}}'
)
SURICATA_NON_SCAN = SURICATA_LINE.replace(
    "ET SCAN Suspicious inbound to MSSQL port 1433", "ET POLICY Possible Bitcoin Mining Pool Connection")
SURICATA_STATS = SURICATA_LINE.replace('"event_type":"alert"', '"event_type":"stats"')

# Modelled on the filterlog example shipped with the Wazuh pf decoder.
FILTERLOG_BLOCK = ("Oct 15 15:03:08 FW01 filterlog[4412]: 65,,,0,igb3,match,block,in,4,0x0,,64,21011,0,none,1,"
                   "icmp,84,10.10.30.149,10.10.50.254,datalength=64")
FILTERLOG_PASS = FILTERLOG_BLOCK.replace(",block,", ",pass,")
FILTERLOG_EXTERNAL = FILTERLOG_BLOCK.replace("10.10.30.149", "203.0.113.7")


def build_cases():
    """Return the engine cases built from the field samples in cases.py plus extra ones.

    Each case: dict(name, rule, kind, events, log_format, expect) where expect is either
    {"rule_id": "..."} (the last event must fire exactly this rule) or {"not_rule_id": "..."}.
    """
    cases = []
    for index, (rule_id, fields, positive) in enumerate(CASES):
        if rule_id in SYSMON_RULES:
            event = sysmon_event1(fields)
        elif rule_id in SEC4688_RULES:
            event = security_4688(fields)
        elif rule_id == "100450":
            event = security_4720(fields)
        elif rule_id == "100301":
            line = SURICATA_LINE if positive else SURICATA_NON_SCAN
            cases.append(dict(name=f"{rule_id} {'positive' if positive else 'negative'} #{index}",
                              rule=rule_id, kind="synthetic", events=[line], log_format="syslog",
                              expect=({"rule_id": rule_id} if positive else {"not_rule_id": rule_id})))
            continue
        else:
            raise SystemExit(f"no engine template for rule {rule_id}")
        cases.append(dict(
            name=f"{rule_id} {'positive' if positive else 'negative'} #{index}",
            rule=rule_id, kind="synthetic", events=[json.dumps(event, separators=(",", ":"))],
            log_format="syslog",
            expect=({"rule_id": rule_id} if positive else {"not_rule_id": rule_id})))

    def add(name, rule, events, expect, log_format="syslog"):
        cases.append(dict(name=name, rule=rule, kind="synthetic", events=events,
                          log_format=log_format, expect=expect))

    dump = lambda e: json.dumps(e, separators=(",", ":"))  # noqa: E731

    # Rules that the field samples cannot cover: decoders, frequency, parent only rules.
    add("100300 parent alert (any Suricata alert)", "100300", [SURICATA_NON_SCAN], {"rule_id": "100300"})
    add("100300 negative, not an alert event", "100300", [SURICATA_STATS], {"not_rule_id": "100300"})
    add("100200 firewall block between lab segments", "100200", [FILTERLOG_BLOCK], {"rule_id": "100200"})
    add("100200 negative, traffic that was passed", "100200", [FILTERLOG_PASS], {"not_rule_id": "100200"})
    add("100200 negative, source outside the lab range", "100200", [FILTERLOG_EXTERNAL], {"not_rule_id": "100200"})
    add("100551 Security 1102 audit log cleared", "100551", [dump(eventlog_cleared("1102"))], {"rule_id": "100551"})
    add("100551 System 104 log file cleared", "100551", [dump(eventlog_cleared("104"))], {"rule_id": "100551"})

    # Frequency rule 100400: the tenth account creation inside one session fires it, the ninth does not.
    def account(name):
        return dump(security_4720({"win.eventdata.targetUserName": name,
                                   "win.eventdata.targetDomainName": "CORP",
                                   "win.eventdata.samAccountName": name}))
    nine = [account(f"zz.test{i}") for i in range(1, 10)]
    add("100400 boundary, 9 accounts stay below the threshold", "100400", nine, {"not_rule_id": "100400"})
    add("100400 boundary, the 10th account fires", "100400", nine + [account("zz.test10")],
        {"rule_id": "100400"})
    return cases
