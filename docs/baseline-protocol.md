# Baseline and tuning protocol

The rules were written against attacks. This protocol measures how often they fire when nobody is attacking, tunes the noisy ones, and proves the detections still work afterwards.

## What the numbers will mean

- The "normal" week is scripted by me ([baseline/](../baseline/)). It is a believable mix of user and administrator activity on one workstation and one domain controller, not a real user population. The results are alerts per day on that workload, a lower bound for a lab and not a false positive rate for a company.
- Every alert in an attack-free week is counted as a false positive. Some of them are administrator actions that look exactly like the technique (a scheduled task created by a help desk script, say). Those stay in the count and are handled by tuning, not by excusing them.
- Tuning may not use the generator as a cheat sheet. No exception may name a generator file, folder, task or marker string. An exception has to be something a real environment could also state: an account, a parent process, a signed binary, a rate.

## Before the week starts

1. **Freeze the rules.** The manager and the repository must hold the same file.
   `sha256sum /var/ossec/etc/rules/local_rules.xml` on WAZUH must equal `sha256sum rules/local_rules.xml` in a fresh clone. Tag the commit `baseline-v1`.
2. **Keep the lab awake for 7 days.** On the Mac run `caffeinate -dimsu` in a Terminal that stays open, keep the charger and the HomeLab SSD attached, and turn off VM suspend on sleep in VMware Fusion. On WS01 and DC01 run `powercfg /change standby-timeout-ac 0` and `powercfg /change monitor-timeout-ac 0`, and stay signed in as `CORP\adm.truong` (locking the screen is fine).
3. **Check capacity.** `df -h /var/ossec` on WAZUH has at least 20 GB free. Wazuh keeps rotated alert files on disk, but the dashboard index keeps 14 days, so copy the alert files off the box at the end.
4. **Snapshot** WS01, DC01 and WAZUH as `06-baseline-start`.
5. **Install the generators.** On WS01 run `baseline\Install-BaselineTasks.ps1`. On DC01 run `baseline\Generate-DcActivity.ps1 -Install -OnboardingDay <a date in the middle of the week>`. Installing writes events of its own, so the clock starts when the scripts finish. Write down that time.

## During the week

A two minute check each day:

- `sudo /var/ossec/bin/agent_control -l` shows WS01 and DC01 as Active.
- The baseline report (below) over the last day shows no rule 202, 203 or 504 (agent queue full, agent disconnected). Do not change any rule or agent setting during the week. If the queue fills, note it and decide afterwards.
- Do not run any attack, Atomic test or scan. Do not open the attack tools on Kali.

## After the week

On WAZUH:

```
sudo python3 scripts/baseline_report.py --start "<start>" --end "<start + 7 days>" --rules rules/local_rules.xml --actions actions.csv --out baseline-week1
```

`actions.csv` is `C:\ProgramData\Baseline\actions.csv` from WS01. The report gives alerts per rule per day, the most common event tuples behind each rule, which alerts follow a generator action, and the collector health table. It also writes `baseline-week1-events.jsonl`, one line per distinct event shape with a count. Commit that file under `baseline/` once you have checked it for secrets: command lines in this lab can contain passwords, and the generator uses random throwaway ones.

## Tuning

Work on rules in order of alerts per day. For each one, write down in `docs/tuning-log.md`:

| Field | Content |
| --- | --- |
| Rule and count | Alerts per day in the baseline week |
| What fired | The two or three event tuples that account for most of it |
| Why it is benign here | What a real environment would also know |
| The change | Level, exception, aggregation or threshold |
| What it still catches | The attack behaviour from the evidence log that still alerts, with the real fixture that proves it |
| Cost | What a hunter could now miss |

Preferred changes, in this order: aggregate (one level 8 alert when four discovery commands run within five minutes, instead of one alert per command), lower the level of a single occurrence, add a context condition (parent process, account, destination), and only then silence a shape completely.

## Proving nothing was lost

1. **Engine tests.** The `engine` workflow runs 78 cases on every push, 22 of them real events captured from alerts. A tuned rule must still fire on every real fixture.
2. **Replay on the baseline week.** The same workflow replays `baseline/*-events.jsonl` through the tuned rules, so the before and after counts come from identical traffic.
3. **Live regression.** On WS01 run `scripts\Run-AtomicRegression.ps1`, then on WAZUH run `scripts/regression_check.py`. All 15 live tests must raise their expected alerts. The runner leaves 90 seconds between tests on purpose, because a burst can fill the agent queue and lose detections.

## Second baseline

Run the same week again with the tuned rules and a fresh `06-baseline-start` style snapshot. The final table in the README has three columns for each rule: week 1 live, week 1 replayed with the tuned rules, week 2 live. A rule whose replay and live numbers disagree is a finding, not a rounding error.
