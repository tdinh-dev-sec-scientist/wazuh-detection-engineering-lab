# Baseline generators

Scripts that produce scripted normal activity for the attack-free weeks described in [docs/baseline-protocol.md](../docs/baseline-protocol.md).

| Script | Runs on | What it does |
| --- | --- | --- |
| `Install-BaselineTasks.ps1` | WS01, elevated, as the admin account | Installs two scheduled tasks (every 15 minutes in working hours, hourly otherwise), or removes them with `-Remove` |
| `Generate-NormalActivity.ps1` | WS01, started by those tasks | Picks user actions (browsing, file work, lookups) and capped admin actions (`systeminfo`, `net user`, a short lived scheduled task, an admin share copy, a short lived local account and similar), undoes each change, and logs it to `C:\ProgramData\Baseline\actions.csv` |
| `Generate-DcActivity.ps1` | DC01, elevated | Daily new hire accounts, a password reset and a group change, plus one 12 account onboarding burst on a chosen day |

Nothing here attacks anything. The workload is my guess at ordinary activity, so the alert counts it produces are a lower bound for a lab, not a measured false positive rate.
