# Investigation cases

Three alerts from this lab, worked the way an analyst would triage them: timeline, context, disposition, impact and what I would do next. Every fact below is taken from the alerts and screenshots in the [evidence log](detection-evidence-log.md); nothing here is invented for the writeup. Each case ends with a disposition because that is the actual analyst deliverable, not the rule that fired.

## Case 1: Proxy execution through wlrmdr.exe on WS01

**Alert**: rule 100721 "Security 4688: wlrmdr.exe used to launch another program", level 8, T1218 System Binary Proxy Execution. Source: [T1218 System Binary Proxy Execution](detection-evidence-log.md#t1218-system-binary-proxy-execution).

### Timeline (from the Security log on WS01, local time)

| Time | Event |
| --- | --- |
| 19:48:20 | `powershell.exe` starts under CORP\adm.truong |
| 19:48:21 | The same `powershell.exe` creates `wlrmdr.exe` with command line `wlrmdr.exe -s 3600 -f 0 -t _ -m _ -a 11 -u "C:\Windows\System32\calc.exe"` |
| 19:48:21 | `wlrmdr.exe` creates `calc.exe` |
| 19:48:27 | Wazuh alert rule 100721 (Security 4688) |
| 19:48:28 | Wazuh alert rule 100720 (Sysmon event 1, same command line) |

### Context

- **Process tree**: `powershell.exe` (parent) → `wlrmdr.exe` → `calc.exe`. `wlrmdr.exe` is a built-in Windows binary that the Atomic test abuses to start another program through its `-u` option.
- **User**: CORP\adm.truong, an administrative account, on WS01 (a workstation, not a server).
- **Command line**: carries the full `-u "C:\Windows\System32\calc.exe"` argument, so the launched target is visible without decoding anything.
- **Host role**: WS01 is the domain-joined workstation used for the Atomic Red Team tests in this lab. In a real environment this detail would come from the asset inventory or CMDB, not from the alert.

### Benign or suspicious

In this lab the activity is the Atomic Red Team T1218-16 test, run on purpose. Read only from the alert, the pattern (an interactive PowerShell session invoking a lesser-known LOLBin with an explicit `-u` target) is a textbook proxy-execution test and would be treated as suspicious in a live environment: `calc.exe` is the canary here, but the same chain with a different target binary is a way to launch a payload under a process name analysts do not usually watch. The parent being an interactive PowerShell session on a workstation, not a scheduled task or service, argues against this being routine automation.

### Impact if real

Low on its own (no credential theft or persistence in this single event), but proxy execution like this is normally staging for a later step, such as launching a renamed payload or evading a path-based block rule. The account used is administrative, which raises the ceiling on what a successful foothold could reach.

### Disposition and escalation

I would escalate this for human review rather than close it as benign, for three reasons: the binary and switch combination is unusual, the parent is an interactive admin session, and the only reference I have (a public Sigma rule) treats `winlogon.exe`, not `powershell.exe`, as the normal parent of `wlrmdr.exe`. I have not baselined normal `wlrmdr.exe` use in this environment, so I would ask whether adm.truong's session matches known testing or maintenance before closing it,

### What I would do before it reached a human

- Pull the full process lineage for the PowerShell session (parent of parent) to see what started it, and check whether that session raised other alerts.
- Check whether `calc.exe` (or the real target, in a live case) actually ran past creation, which 100722 confirms here.
- Note for the write-up that Sysmon did not log `wlrmdr.exe` or `calc.exe` process creation in this run; only Security 4688 did. An investigation that only queries Sysmon would miss this chain entirely.

### Remediation if this were a real finding

- Baseline legitimate `wlrmdr.exe` invocations (parent process, frequency) before tuning the rule, since the current pattern has no allowlist for `winlogon.exe`.
- Extend rule 100722 (child-of-`wlrmdr.exe`) to the Sysmon side once the Sysmon visibility gap for this binary is understood, so the chain is not dependent on Security auditing alone.

## Case 2: Command line through a local administrative share on WS01

**Alerts**: rule 100710 (Sysmon event 1) and 100711 (Security 4688), "command line uses a Windows administrative share", level 6, T1021.002 SMB/Windows Admin Shares. Source: [T1021.002 SMB/Windows Admin Shares](detection-evidence-log.md#t1021002-smbwindows-admin-shares).

### Timeline

| Time | Event |
| --- | --- |
| 19:30:48 | Sysmon event 1 on WS01: `cmd.exe` runs `cmd.exe /Q /c hostname 1> \\127.0.0.1\ADMIN$\output.txt 2>&1`, parent PowerShell, user CORP\adm.truong |
| 19:30:52 | Wazuh alert rule 100711 (Security 4688) |
| 19:30:53 | Wazuh alert rule 100710 (Sysmon event 1) |

### Context

- **Command**: `hostname` run and its output redirected through the loopback address's `ADMIN$` share to `output.txt`, which lands at `C:\Windows\output.txt`.
- **Destination**: `127.0.0.1`, the local machine, not a remote host. This single fact changes the read of the alert: there is no lateral movement here, only the mechanism that lateral movement over SMB admin shares would use.
- **User and host**: CORP\adm.truong, an administrative account, on WS01.
- **What I checked and found empty**: a search for `shareName: *ADMIN*` turned up no alert, so Windows share-access auditing (events 5140/5145) either is not enabled or is not forwarded; the only visibility into this activity is the process command line.

### Benign or suspicious

Suspicious in form, benign in this instance. The technique T1021.002 is about using administrative shares to execute commands or move files to another system. Here the target is the originating host itself, so the actual risk (remote code execution via SMB) is not present. This is the Atomic Red Team T1021.002-4 test, which intentionally uses the loopback address because the other tests for this technique need credentials or PsExec that were not set up. An analyst without that context would still be right to flag it, since the command line alone cannot distinguish a loopback test from the first half of a real admin-share pivot; the destination IP is what resolves it.

### Impact if the destination had been remote

If `127.0.0.1` had instead been `10.10.20.10` (DC01) or another workstation, this would be the signature of a successful lateral-movement step: credentials already usable against the target, a share reachable, and a command executed through it. The output file dropped on the target would also be a disposable indicator to hunt for.

### Disposition and escalation

Closed as benign for this instance, with the reasoning written down (loopback destination, known test account): a real investigation should record why an alert was closed, not just that it was. I would still open a hunt for any other 100710/100711 alert in the same time window with a non-loopback destination IP before fully closing the case, since a real actor could run the loopback version first to validate the technique and then repeat it against a real target seconds later. In this capture, no such second alert exists.

### Remediation if this were a real finding

- Enable auditing for events 5140/5145 (share object access) so a real remote use of an admin share is corroborated by a second, independent log source instead of relying on command-line text alone.
- Split the rule's severity by destination: loopback stays at level 6, a non-loopback, non-approved destination should alert at a higher level, since that is the pattern that matters operationally.

## Case 3: Mass account creation on DC01

**Alert**: rule 100400, "Mass account creation detected: 10+ accounts created within 60 seconds", level 10, T1136.002 Create Account: Domain Account. Source: [Account creation on DC01](detection-evidence-log.md#account-creation-on-dc01).

### Timeline

| Time | Event |
| --- | --- |
| earlier | BadBlood populates corp.lab with 495 test users, 110 groups, 41 computers (bulk domain seeding, not part of this alert) |
| 16:22:xx | 15 disabled accounts `zz.test1`-`zz.test15` created in a loop with `New-ADUser` |
| 16:22:51 | Wazuh alert rule 100400, level 10, on DC01 |
| 22:29:24 | Boundary test batch 1: 9 accounts created |
| 22:31:54 | Boundary test batch 2: 10 accounts created |
| 22:31:55 | Wazuh alert rule 100400 fires for batch 2 |
| 22:34:25 | Boundary test batch 3: 11 accounts created |
| 22:34:26 | Wazuh alert rule 100400 fires for batch 3 |

### Context

- **Source**: the alerts come from the DC01 agent, and the test accounts were created in a `New-ADUser` loop. In a live case the first question would be how the session on the domain controller was reached.
- **Account naming**: `zz.test1` through `zz.test15` (and the boundary batches) is an obvious test pattern. A real adversary would not reuse a single prefix; this is a tell that is specific to lab testing, not something to expect in a live case.
- **Volume**: rule 60109 (single account creation) logged 28 hits across the three boundary batches; the frequency rule reported the two batches that crossed the 10-in-60-seconds threshold (28 individual alerts plus 2 frequency alerts accounts for all 30 creations in the boundary test, though I did not open each alert to confirm which specific event carried the 10th position).

### Benign or suspicious

In a live environment, this pattern, many accounts created in rapid succession from one session, is a known staging technique for persistence (creating accounts to blend into a large AD environment, or load-bearing accounts for a later campaign) and for hiding a smaller change in a burst of noise. Here it is confirmed as authored activity: BadBlood seeding and a scripted test. The naming convention and the fact that the accounts stayed disabled (confirmed by cleanup afterward) support that reading.

### Impact if real

High. Domain account creation at this volume, if attacker-driven, usually means AD write access has already been obtained (domain admin or a delegated OU with create-user rights), which is itself the finding that matters more than the new accounts. The accounts created could be leveraged for persistence, lateral movement, or Kerberoasting setups.

### Disposition and escalation

Closed as authorized testing for this specific alert, but I would treat the underlying detection gap as the real lesson: the rule fires on the 10th account within a session, not per creating identity, so two legitimate admins each creating 6 accounts in the same minute would also trigger it (noted in the rule's own limitations), and conversely an attacker who paces creation at 9 accounts per 61-second window would never trigger it at all. Either finding, if it showed up outside a known test window, should go to a human for confirmation of who ran the script and why, before the accounts are touched.

### Remediation if this were a real finding

- Key the frequency window on the creating identity (`subjectUserName`) in addition to the event ID, so the threshold measures one actor's burst rather than the whole domain's.
- Add a lower-level alert for any account creation outside business hours or by an account that has not created accounts before, to catch an attacker who paces around the burst threshold.
- Require second-person approval for any AD account creation outside a change window, which is a process control the detection rule cannot substitute for.

## What these three cases have in common

Each one needed the full event, not just the rule that matched, to reach a disposition: the destination IP in case 2, the parent process and the missing Sysmon event in case 1, and the account-naming pattern plus the creating session in case 3. A rule firing is the start of triage, not the end of it, and all three cases were closed only after checking something the rule itself does not evaluate.
