# Rule catalog

All custom rules in [`rules/local_rules.xml`](../rules/local_rules.xml). The last column links to the test and screenshots for each rule in the [evidence log](detection-evidence-log.md).

| Rule | Level | ATT&CK | Log source | What it detects | Evidence |
| --- | --- | --- | --- | --- | --- |
| 100100 | 6 | T1082 | Sysmon event 1 | Sysmon: systeminfo.exe executed (System Information Discovery) | [T1082 System Information Discovery](detection-evidence-log.md#t1082-system-information-discovery) |
| 100101 | 8 | T1082, T1036.003 | Sysmon event 1 | Sysmon: systeminfo.exe running under a different file name (masquerading) | [Renamed binaries](detection-evidence-log.md#renamed-binaries) |
| 100200 | 6 | none | OPNsense filterlog over syslog | Firewall blocked traffic between internal lab segments | [OPNsense firewall blocks](detection-evidence-log.md#opnsense-firewall-blocks) |
| 100300 | 3 | none | Suricata EVE JSON over syslog | Suricata: $(alert.signature) | [Suricata network detection](detection-evidence-log.md#suricata-network-detection) |
| 100301 | 7 | T1046 | Suricata EVE JSON over syslog | Suricata: network scan detected ($(alert.signature)) from $(src_ip) to $(dest_ip) | [Suricata network detection](detection-evidence-log.md#suricata-network-detection) |
| 100400 | 10 | T1136.002 | Security 4720 (DC01), frequency rule on 60109 | Mass account creation detected: 10+ accounts created within 60 seconds | [Account creation on DC01](detection-evidence-log.md#account-creation-on-dc01) |
| 100450 | 8 | T1136.001 | Security 4720 (workstation) | Local user account created on a workstation ($(win.eventdata.targetUserName)) | [T1136.001 Local Account Creation](detection-evidence-log.md#t1136001-local-account-creation) |
| 100500 | 8 | T1053.005 | Sysmon event 1 | Sysmon: scheduled task created via schtasks.exe (Persistence) | [T1053.005 Scheduled Task](detection-evidence-log.md#t1053005-scheduled-task) |
| 100501 | 8 | T1053.005, T1036.003 | Sysmon event 1 | Sysmon: scheduled task created via renamed schtasks.exe (Persistence, masquerading) | [Renamed binaries](detection-evidence-log.md#renamed-binaries) |
| 100550 | 8 | T1070.001 | Sysmon event 1 | Sysmon: wevtutil used to clear an event log | [T1070.001 Clear Windows Event Logs](detection-evidence-log.md#t1070001-clear-windows-event-logs) |
| 100551 | 8 | T1070.001 | System 104 / Security 1102 (log cleared) | Windows event log cleared (possible defense evasion) | [T1070.001 Clear Windows Event Logs](detection-evidence-log.md#t1070001-clear-windows-event-logs) |
| 100552 | 8 | T1070.001, T1036.003 | Sysmon event 1 | Sysmon: event log cleared via renamed wevtutil.exe (masquerading) | [Renamed binaries](detection-evidence-log.md#renamed-binaries) |
| 100600 | 6 | T1087.001 | Sysmon event 1 | Sysmon: local account enumeration with net.exe | [T1087.001 Account Discovery](detection-evidence-log.md#t1087001-account-discovery) |
| 100601 | 6 | T1069.001 | Sysmon event 1 | Sysmon: local group enumeration with net.exe | [T1087.001 Account Discovery](detection-evidence-log.md#t1087001-account-discovery) |
| 100602 | 6 | T1555.004 | Sysmon event 1 | Sysmon: stored credentials listed with cmdkey.exe | [T1087.001 Account Discovery](detection-evidence-log.md#t1087001-account-discovery) |
| 100603 | 6 | T1033 | Sysmon event 1 | Sysmon: logged on users enumerated | [T1087.001 Account Discovery](detection-evidence-log.md#t1087001-account-discovery) |
| 100700 | 8 | T1105 | Sysmon event 1 | Sysmon: certutil used to download a file | [T1105 Ingress Tool Transfer](detection-evidence-log.md#t1105-ingress-tool-transfer) |
| 100701 | 8 | T1105 | Security 4688 | Security 4688: certutil used to download a file | [T1105 Ingress Tool Transfer](detection-evidence-log.md#t1105-ingress-tool-transfer) |
| 100710 | 6 | T1021.002 | Sysmon event 1 | Sysmon: command line uses a Windows administrative share | [T1021.002 SMB/Windows Admin Shares](detection-evidence-log.md#t1021002-smbwindows-admin-shares) |
| 100711 | 6 | T1021.002 | Security 4688 | Security 4688: command line uses a Windows administrative share | [T1021.002 SMB/Windows Admin Shares](detection-evidence-log.md#t1021002-smbwindows-admin-shares) |
| 100720 | 8 | T1218 | Sysmon event 1 | Sysmon: wlrmdr.exe used to launch another program | [T1218 System Binary Proxy Execution](detection-evidence-log.md#t1218-system-binary-proxy-execution) |
| 100721 | 8 | T1218 | Security 4688 | Security 4688: wlrmdr.exe used to launch another program | [T1218 System Binary Proxy Execution](detection-evidence-log.md#t1218-system-binary-proxy-execution) |
| 100722 | 8 | T1218 | Security 4688 | Security 4688: process started by wlrmdr.exe | [T1218 System Binary Proxy Execution](detection-evidence-log.md#t1218-system-binary-proxy-execution) |

23 rules. Rules with the same parent are evaluated in file order and the first match wins, which is why the order inside each group matters.
