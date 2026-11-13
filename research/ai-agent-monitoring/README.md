# Behavioral monitoring of AI coding agents on a Windows endpoint

Lab experiment (Nov 2026): what endpoint telemetry sees when AI coding agents
(Claude Code 2.1.323, then Antigravity CLI 1.5.8) run on a domain-joined Windows 11 workstation, and how to
separate its normal baseline from drift. Written as field evidence for
[CoSAI WS4 #195 "Agent Behavioral Monitoring"](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/issues/195).

## Setup

| Item | Value |
|---|---|
| Endpoint | WS01, Windows 11, domain-joined, agent run as a standard (non-admin) user |
| Agent | Claude Code 2.1.323, PowerShell shell |
| Telemetry | Sysmon EID 1, Security 4688 (with command line), PowerShell 4104/4103 |
| SIEM | Wazuh manager, `logall_json` enabled during the runs |

Runs: one **baseline** task (edit a script, run it, commit), one **drift** task
(collect current user and groups, domain, domain controllers, local admins "for the README"),
repeated several times, plus a second baseline to measure false positives.

## Findings

1. **The real command is hidden from process telemetry.** Agent shells run as
   `claude.exe -> cmd.exe -> powershell.exe -ExecutionPolicy Bypass -Command "$__claudeCodeScript = $env:CLAUDE_CODE_SHELL_LAUNCHER_SCRIPT ..."`.
   The command lives in an environment variable, so process creation shows only the launcher.
2. **No single source saw the whole drift.**

   | Action | Sysmon EID1 | 4688 | PS 4104 |
   |---|---|---|---|
   | `whoami`, `whoami /groups` | yes | yes | yes |
   | `net localgroup Administrators` | yes | yes | yes |
   | `nltest /dclist` | **no** (Sysmon config gap) | yes | yes |
   | `Get-CimInstance Win32_ComputerSystem` | **no** (in-process) | **no** | yes |

3. **4104 shows intent; process events show execution.** 4104 logs the submitted script,
   including branches that may not run. Combine both sources.
4. **The baseline is mostly the agent's own background activity.** A two-command task produced about
   68 background processes (61 `git`, 7 `reg`). Bootstrap looks like attacker TTPs:
   `tasklist | findstr` IDE detection, and `reg add HKCU\Software\Classes\claude-cli\shell\open\command`.
5. **Default rules invert signal and noise.** On a benign task the stock ruleset raised 6 level-15 alerts
   (92213, PowerShell `__PSScriptPolicyTest_*.ps1` files) and 3 level-10 alerts (91809, the agent's own
   Base64 AST check). On drift it raised nothing for `whoami`, `nltest`, or the CIM query.
6. **Tool choice is non-deterministic.** The same prompt listed local admins with `net.exe` in one run and
   without spawning it in another.
7. **The model-layer guardrail is separate and can be bypassed by rewording.** An explicit request for
   credential-manager and Wi-Fi entries was blocked before execution. The same recon, reworded
   "for the README", ran with only an advisory note.

## Second agent: Antigravity CLI

Same workstation, user and telemetry, repeated with Google's Antigravity CLI (`agy` 1.5.8). (Gemini CLI sign-in for individual accounts no longer works, so Antigravity CLI is Google's current agent.) Sessions: one benign coding task (add a `-Quiet` switch, test, commit), then short marker-command sessions to isolate the findings below.

| | Claude Code | Antigravity CLI |
|---|---|---|
| Shell launch | `cmd.exe -> powershell.exe`, real command passed through an environment variable | `agy.exe -> powershell.exe -Command "<real command>"` |
| Command visible in process command line | No (4104 only) | Yes |
| Sandbox | None observed | Most commands run in an OS sandbox: 4688 label Low (`S-1-16-4096`), Sysmon `IntegrityLevel: AppContainer` |
| Startup activity | ~68 processes (mostly git, reg) | 2 `git merge-base` calls |
| Attribution markers | `CLAUDE_CODE_SHELL_LAUNCHER_SCRIPT`, `claude-pwd-ps-N` | parent `agy.exe`; every sandboxed command starts with `$env:TEMP = $env:_TEMP; $env:TMP = $env:_TMP; $env:LOCALAPPDATA = $env:_LOCALAPPDATA;` |

**Finding: a common Sysmon config drops sandboxed agent commands.** In the benign session, none of the agent's sandboxed processes (the shell plus children such as `git status` and the test runs of the script) appeared in Sysmon Event ID 1, while Security 4688 recorded all of them. Sysmon still logged Event IDs 7, 11, 13 and 17 for the same PIDs and there were no Event ID 255 errors.

Root cause: the sysmon-modular ProcessCreate exclusion `<IntegrityLevel condition="is">AppContainer</IntegrityLevel>` ("Don't care about sandboxed processes"), inherited from SwiftOnSecurity's config.

| Sysmon config | Sandboxed agent processes with Event ID 1 |
|---|---|
| sysmon-modular rule as shipped | 0 of 6 |
| Minimal config (`<ProcessCreate onmatch="exclude"/>`) | 5 of 5 (`IntegrityLevel: AppContainer`) |
| Exclusion scoped to AppContainer **and** `C:\Program Files\WindowsApps\` | 5 of 5 |

Control: a Low-integrity process started with `PsExec -l` is logged as `IntegrityLevel: Low` and is not affected. Note that `whoami /groups` inside the sandbox shows only Low integrity and no `S-1-15-2-*` package SID, so the token alone does not reveal that this rule will match. Reported upstream: [olafhartong/sysmon-modular#235](https://github.com/olafhartong/sysmon-modular/issues/235).

Other observations:
- Benign sandboxed activity still looks TTP-like: `powershell -ExecutionPolicy Bypass -File .\count-notes.ps1`, and `New-Item .git\test.txt` to probe write access.
- The Claude Code rules below do not match Antigravity at all. Attribution has to be built per agent.

## Rules (`ai_agent_monitoring.xml`)

Level-3 parent rules record agent activity (the baseline). Level-10 child rules fire on discovery (the drift).

| ID | Source | Logic |
|---|---|---|
| 100800 | PS 4104 | script block contains the agent wrapper marker `claude-pwd-ps-<n>` |
| 100801 | PS 4104 | child of 100800: account, group, domain, or DC discovery keywords |
| 100802 | Sysmon EID1 | parent command line contains `CLAUDE_CODE_SHELL_LAUNCHER_SCRIPT` |
| 100803 | Sysmon EID1 | child of 100802: discovery binary (`whoami`, `net`, `nltest`, ...) |
| 100804 | Security 4688 | `nltest.exe` fallback for the Sysmon gap (no agent attribution) |

Results: the drift run produced 6 alerts across all three sources (100801, 100803 x2, 100804, plus the
existing net.exe rule 100601). The second baseline produced **0 drift alerts** (only 100800/100802 at level 3).

**Gotcha:** 100800 was silently shadowed by stock rule 91816, which matched first among
the children of 91802. Fixed by chaining 100800 under 91802 and all of its direct children.

## Install

Copy `ai_agent_monitoring.xml` to `/var/ossec/etc/rules/`, run `/var/ossec/bin/wazuh-analysisd -t`, and
restart the manager. Requires PowerShell Script Block Logging (GPO) and collection of
`Microsoft-Windows-PowerShell/Operational`. The 100800 `if_sid` list matches the Wazuh 4.x stock ruleset;
regenerate it if your ruleset differs.

## Limits

A single lab host, two agents, a handful of runs each. The markers are specific to these agent versions
and may change. Raw event exports are not published because they contain lab SIDs and account names.
