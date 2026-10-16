# Detection quality

What the 23 rules have been shown to do, how each claim was checked, and where they fail. Alert counts in this lab say nothing about accuracy, so this page lists expected against observed results, negative tests, and the misses I know about.

## How a rule is verified

| Level | What it proves | Where it runs | What it cannot prove |
| --- | --- | --- | --- |
| 1. Pattern test | A rule's field patterns match the sample and skip near misses | `validate` workflow, [tests/test_rules.py](../tests/test_rules.py), 47 samples (25 positive, 22 negative) | Parent rules, decoders, frequency and the order of sibling rules |
| 2. Engine test | The full event reaches the intended rule inside a real Wazuh 4.14.8 `wazuh-analysisd`, with parents, decoders and thresholds | `engine` workflow, [tests/engine](../tests/engine), 78 cases (22 real captured events, 56 synthetic) | The Windows eventchannel decoder (see below) and the quality of the sample |
| 3. Live test | The attack ran in the lab and the alert appeared in the dashboard | [Evidence log](detection-evidence-log.md), 54 screenshots | Repeatability. Each live test was run once or a few times |

The engine job installs the Wazuh manager package, copies in `rules/` and `decoders/`, and sends every case through `wazuh-logtest`. It also checks the statements this repository makes about Wazuh's default rules against the stock ruleset in the same package ([baseline_claims.py](../tests/engine/baseline_claims.py)).

One limit shapes level 2. `wazuh-logtest` does not run the Windows eventchannel decoder, which is a separate thread inside `wazuh-analysisd` (I read this in the 4.14 source: `logtest.c` calls only `DecodeEvent`, while `w_decode_winevt_thread` in `analysisd.c` handles `WIN_EVT_MQ`). Wazuh's own ruleset tests work around it by changing base rule 60000 to accept events decoded by the generic `json` decoder. [prepare_engine_tests.py](../scripts/prepare_engine_tests.py) applies the same change on a throwaway manager. Windows events therefore enter at the point where the decoded `{"win": {...}}` JSON would, and level 3 remains the check for the production path.

## Rule by rule

| Rule | Level 1 samples (pos / neg) | Level 2 engine | Level 3 live alert | Note |
| --- | --- | --- | --- | --- |
| 100100 | 1 / 1 | yes | yes | |
| 100101 | 1 / 2 | yes | yes | Renamed copy of systeminfo.exe |
| 100200 | none | yes | yes | Needs the stock rule 87701 as parent |
| 100300 | none | yes | seen as the parent of 100301 | Parent only, level 3 |
| 100301 | 1 / 1 | yes | yes | |
| 100400 | none | yes, 9 accounts stay silent, 10 fire | yes, 15 accounts, then 9 / 10 / 11 | Frequency rule |
| 100450 | 1 / 2 | yes | yes | |
| 100500 | 2 / 2 | yes | yes | |
| 100501 | 1 / 2 | yes | yes | |
| 100550 | 1 / 1 | yes | yes | |
| 100551 | none | yes | yes | Parent rules only, no field pattern |
| 100552 | 1 / 1 | yes | yes | |
| 100600 | 2 / 2 | yes | yes | |
| 100601 | 2 / 1 | yes | yes | |
| 100602 | 1 / 1 | yes | yes | |
| 100603 | 2 / 1 | yes | yes | |
| 100700 | 2 / 1 | yes | **no, only a synthetic echo** | Sysmon never logged the Defender-blocked process |
| 100701 | 1 / 0 | yes | yes | |
| 100710 | 2 / 2 | yes | yes | |
| 100711 | 1 / 0 | yes | yes | |
| 100720 | 1 / 1 | yes | yes | |
| 100721 | 1 / 0 | yes | yes | |
| 100722 | 1 / 1 | yes | yes | |

Rules with 0 negative samples are the Security 4688 twins of a Sysmon rule. They repeat the same pattern, so the negatives of the Sysmon rule apply.

## The 15 attack tests: expected against observed

"Default" is what Wazuh 4.14.8 did before any custom rule. Each row is checked against the evidence log.

| Technique | Expected | Default ruleset | After my rules | Residual miss |
| --- | --- | --- | --- | --- |
| T1082 System Information Discovery | alert | Missed: no alert | 100100 fired; 100101 fired for a renamed copy | Other discovery tools |
| Firewall blocks between segments | alert | Missed: rule 87701 has the `no_log` option and never alerts | 100200 fired 6 times | Allowed traffic is not logged |
| T1046 Network Service Discovery | alert | Missed: Suricata lines not decoded, fell to rule 1002 at level 2 | 100301 fired 16 times | Two alerts per probe, no grouping |
| T1136.002 Domain Account Creation | alert on a burst | Partial: single creations alert at level 8, no burst rule | 100400 fired; silent at 9 accounts, fired at 10 | Fixed threshold, not per creating user |
| T1053.005 Scheduled Task | alert with technique | Partial: generic level 3 only | 100500 and 100501 fired | `/delete` and other task tools |
| T1136.001 Local Account Creation | alert with technique | Partial: 60109 carries T1098, two alerts per creation | 100450 fired with T1136.001 | Local accounts of any machine alert |
| T1070.001 Clear Windows Event Logs | alert on the command | Partial: 63104 at level 5 maps to T1070 only, no process alert | 100550, 100551, 100552 fired | `Clear-EventLog` reaches only 100551 |
| T1087.001 Local Account Discovery (and T1069.001, T1555.004, T1033) | alert with technique | Partial: generic level 3 alerts, no sub-technique | 100600 to 100603 fired, 14 hits | PowerShell cmdlets, `whoami.exe` |
| T1105 Ingress Tool Transfer | alert | Partial: generic level 3; Defender detection never reached Wazuh until the agent collected its channel | 100701 fired; 100700 stayed silent in real runs | Only `certutil -urlcache` and `-verifyctl` |
| T1021.002 SMB/Windows Admin Shares | alert with technique | Partial: levels 3 and 4, no T1021.002 | 100710 and 100711 fired | Share access events 5140 and 5145 raised no alert |
| T1218 System Binary Proxy Execution | alert with technique | Missed: no alert with T1218 | 100720, 100721, 100722 fired | One binary only, `wlrmdr.exe` |
| T1547.001 Registry Run Keys | alert | Covered: 92302, level 6 | none needed | |
| T1110 Brute Force | alert | Covered: 60122 x11 and 60204 x1, T1110 | none needed | Parent technique, one source, one account |
| T1059.001 PowerShell | alert | Covered: 92057, level 12 | none needed | Script block text (4104) not alerted |
| T1543.003 Windows Service | alert | Covered: 61138 and 92307 | none needed | Low levels, only `sc.exe` tested |

Totals: of 15 tests, the defaults fully covered 4, partly covered 7 (an alert, but a missing burst rule, a missing or wrong technique, or a low level) and missed 4. After the custom rules, all 11 gaps produced an alert with the intended technique in a live test. One rule, 100700, has never fired on a real event, and its Security 4688 twin 100701 covers that case.

## Negative tests

- Level 1 and 2: 22 negative samples, plus 4 more at level 2 (a Suricata `stats` event, a passed firewall packet, a source outside the lab range, 9 account creations).
- Level 3: five harmless commands run with the T1218 test: `schtasks /query /fo LIST`, `wevtutil qe Application /c:1 /f:text`, `certutil -hashfile ... SHA256`, `cmd.exe /c echo \\server\share\file.txt` and `cmd.exe /c echo wlrmdr`. None of the rules built for them alerted.
- Not done: a baseline of normal activity over several days. That is why this repository publishes no precision or false positive rate. A fair number needs days of ordinary administration, software updates and logons on WS01 and DC01, with every alert triaged.

## Known misses

- **Sysmon does not see everything.** When Defender blocked `certutil.exe`, Sysmon logged no process event, so rule 100700 stayed silent and only the Security 4688 twin (100701) fired. In the `wlrmdr.exe` test Sysmon logged the PowerShell launcher but not `wlrmdr.exe` or `calc.exe`, and rule 100722 works only because Security 4688 saw them.
- **Command lines only.** The same actions through PowerShell cmdlets or APIs (`Get-LocalUser`, `Clear-EventLog`, `Invoke-WebRequest`) are not matched by the process rules.
- **Fixed thresholds.** Rule 100400 counts alerts across all creators for 10 accounts in 60 seconds.
- **Unreviewed share access.** Events 5140 and 5145 for administrative shares produced no alert.
- **Renamed binaries with edited version resources.** Rules 100101, 100501 and 100552 trust `OriginalFileName`; a copy with a modified resource was not tested.
- **Duplicates.** Each Suricata probe alerts twice because two interfaces are monitored.

## Latency

Two measurements: the Security 4688 event behind rule 100701 was logged at 19:05:30 and the alert was stamped 19:05:57 (27 seconds). The Defender event behind rule 62123 was logged at 19:14:26 and alerted at 19:14:54 (28 seconds). Sysmon alerts appeared in the dashboard minutes later than the Security alerts in the T1218 test, so a query run right after a test can look empty. Two data points are not a latency distribution.

## Corrections found while checking this page

Checking the documentation against the engine caught claims that were too strong. Default rules 63103 and 63104 map to T1070, so "no technique" was wrong; they lack only the sub-technique T1070.001. Rules 92052, 92032 and 92033 carry T1059.003 and T1087, so for T1021.002 and T1087.001 the accurate wording is "no sub-technique", not "no technique". The coverage tables now use the corrected wording, and `baseline_claims.py` fails CI if they drift again.
