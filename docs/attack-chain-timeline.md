# Attack chain timeline

One continuous session on 2026-10-16 (local time, ET), run from the [runbook](attack-chain-runbook.md): a scan and an SMB password guess from Kali through FW01 to WS01, then eleven Atomic Red Team and native commands on WS01, ending with an event log clear. This page compares three things for each step: what the endpoint logged, which Wazuh alert fired, and what was missed.

Sources: the Wazuh alert export (`chain_timeline.py`, 304 unique alerts), the WS01 export (`Export-ChainEvents.ps1`, 269 events) and the times I wrote down for each command. The raw exports are not in the repo because the command lines contain the test password.

## Result in one table

Delay is the time between the endpoint event (`systemTime` in the alert) and the Wazuh alert timestamp.

| Step | Command time | Endpoint log | Wazuh alert | Delay | Verdict |
| --- | --- | --- | --- | --- | --- |
| Port scan from Kali | 14:05:30 | FW01 Suricata | 100301, 21 alerts (ET SCAN rules) | n/a | Detected |
| SMB guess, first run | 14:05:33 to 14:06:28 | none, every `smbclient` timed out | none | n/a | Test failed, see below |
| `net user` | 14:06:06 | Sysmon 1, Security 4688 | 100600 | 1 s | Detected |
| `net localgroup administrators` | 14:06:06 | Sysmon 1, 4688 | 100601 | 1 s | Detected |
| `query user` | 14:06:07 | Sysmon 1, 4688 | 100603 | 1 s | Detected |
| `cmdkey /list` | 14:06:07 | Sysmon 1, 4688 | 100602 (T1555.004) | 1 s | Detected |
| `systeminfo` | 14:06:07 | Sysmon 1, 4688 | 100100 (T1082) | 1 s | Detected |
| T1105-7 certutil download | 14:06:11 | 4688 only (Sysmon logged no process, Defender blocked it) | 100701 (T1105), 62123 level 12, 62124 | 21 s, 21 s, 67 s | Detected |
| T1053.005-1 schtasks | 14:06:16 | Sysmon 1, 11, 13 | 100500 twice (OnLogon, OnStartup) | 60 s, 77 s | Detected, late |
| T1547.001-1 Run key | 14:06:21 | Sysmon 1, 13 (`reg.exe` set HKCU Run) | none | n/a | **Missed** |
| T1136.001-4, first run | 14:06:23 | Sysmon 1, 4688 (`net user /add`, failed, password rejected) | none | n/a | **Missed** |
| T1021.002-4 admin share | 14:08:24 | Sysmon 1, 4688 | 100710, 100711 (T1021.002) | 11 s, 5 s | Detected |
| T1218-16 wlrmdr | 14:08:26 | Sysmon 1, 4688 | 100720, 100721, 100722 (T1218) | 14 s | Detected |
| SMB guess, second run | 14:13:11 to 14:13:58 | 12 x 4625 | 60122 x 11 (T1531), 60204 x 1 (T1110, level 10) | 1 s | Detected |
| T1136.001-4, rerun | 14:17:30 | 4720, 4722, 4732, 4688 | 92040 (level 12), 100450, 60109, 60160, 60170 | 6 s, 13 s | Detected |
| `wevtutil cl Application` | 14:19:39 | Sysmon 1, 4688, 1102 | 100550, 100551 (T1070.001) | 0 to 1 s | Detected |

## What went wrong, and what it showed

**The first SMB run produced nothing.** Kali had moved from 10.10.50.181 to 10.10.50.121 (DHCP), and the temporary WS01 firewall rule only allowed .181, so all twelve `smbclient` calls timed out and WS01 never saw a logon attempt. This is an environment fault, not a detection result. I changed the rule and reran; the second run is the one in the table. Lesson for the runbook: check the Kali address before starting.

**The first account creation failed.** The password was not valid for the domain policy, so `net user /add` returned an error and no account existed. I reran it with a compliant password. The failed attempt is still a real command line and is still in the table as a miss, because the endpoint logged it and Wazuh did not alert.

**Two misses sit inside the same 30 seconds.** The WS01 agent raised rule 202 (queue 90% full) at 14:06:21, rule 203 (queue full, events may be lost) at 14:06:22 and rule 205 (back to normal) at 14:06:49. The Run key write (14:06:23) and the failed `net user /add` (14:06:24) both fall inside that window, and neither got an alert, although the evidence log records default rule 92302 firing for the same Run key test when it was run alone. The schtasks alerts, which also fall in the window, arrived 60 and 77 seconds late, and the Defender alerts 21 and 67 seconds late. That fits event loss and delay from a full agent queue during a burst of about 40 commands in 20 seconds. I have not proven it: I did not enable `logall` for this run, so I cannot show the lost events arriving at the manager. It is the leading explanation, not a measured one.

**What it means for a SOC.** A burst of attacker activity is exactly when the queue fills. A detection that works when a test runs alone can stay silent during a fast chain. Rule 203 itself fired, so a real deployment should alert on it and raise the agent `client_buffer` limits.

## Notes on specific alerts

- **T1105 on a blocked download.** Defender stopped the certutil download, so Sysmon logged no process for it, but Security 4688 still recorded the command line and rule 100701 fired from it. Rules 62123 and 62124 carry no technique mapping, so 100701 is the alert that places this in ATT&CK.
- **T1110 versus T1531.** Rule 60122 (each bad password) maps to T1531 Account Access Removal, which is the wrong technique for a guess. Only the frequency rule 60204 maps to T1110. It fired on the eighth failure and replaced the eighth 60122, so the twelve failures became eleven 60122 alerts and one 60204. This corrects the earlier note in the [evidence log](detection-evidence-log.md) that listed T1110 for both.
- **Account creation had two layers.** The default rule 92040 (level 12, T1136.001) fired on the command line at 6 seconds. The custom rule 100450 and the default rules 60109, 60160 and 60170 fired from the 4720, 4722 and 4732 events at 13 seconds. The command line alert was faster than the event log alert.
- **Command lines carry secrets.** The 92040 alert and the exports contain the account password in clear text because Sysmon and 4688 record the full command line. A SOC that forwards these logs needs to treat the alert index as sensitive.
- **Unrelated noise.** Fifteen 100200 alerts (WS01 to WAZUH tcp/1514 blocked) fired between 14:01:13 and 14:01:27, before the session started. I have not found the cause. The Kali clock was about 3 seconds ahead of the manager, which is why the scan alerts appear to start before the `nmap` time I wrote down.

## What I changed because of this run

- `chain_timeline.py` now skips duplicate alerts. Wazuh writes each alert to `alerts.json` and to the file of the day, so the first export counted every alert twice (608 lines, 304 alerts).
- The runbook now checks the Kali address first and uses a prompt for the account password instead of a literal.
