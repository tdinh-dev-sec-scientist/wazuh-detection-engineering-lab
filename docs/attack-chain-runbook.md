# Attack chain runbook

One continuous session that strings together tests already documented in the [evidence log](detection-evidence-log.md), so the timeline can be compared across Kali, FW01, WS01 and Wazuh. Run it only in the lab. Every step uses a command that has already been run once on its own.

## Before

1. On WS01, open an elevated PowerShell as `CORP\adm.truong` and note the start time:
   `Get-Date -Format "yyyy-MM-dd HH:mm"`
2. On WS01, allow SMB from Kali only, temporarily:
   `New-NetFirewallRule -DisplayName "TEMP SMB from Kali" -Direction Inbound -Protocol TCP -LocalPort 445 -RemoteAddress 10.10.50.181 -Action Allow`
3. Download the endpoint export script on WS01:
   `Invoke-WebRequest https://raw.githubusercontent.com/tdinh-dev-sec-scientist/wazuh-detection-engineering-lab/main/scripts/Export-ChainEvents.ps1 -OutFile C:\Users\Public\Export-ChainEvents.ps1`

## Phase 1: from Kali (about 3 minutes)

```
nmap -sS -Pn -T4 -p 22,1433,3306,5432,1521,5900 10.10.30.149
for i in $(seq 1 12); do smbclient -L //10.10.30.149 -U 'fakeuser%WrongPass123'; done
```

Write down the time each command starts (`date`).

## Phase 2: on WS01, elevated PowerShell (about 10 minutes)

Run in this order and write down the time of each line.

```
net user
net localgroup administrators
query user
cmdkey /list
systeminfo | Out-Null
Invoke-AtomicTest T1105 -TestNumbers 7
Invoke-AtomicTest T1053.005 -TestNumbers 1
Invoke-AtomicTest T1547.001 -TestNumbers 1
Invoke-AtomicTest T1136.001 -TestNumbers 4     # with the compliant password, as in the earlier test
Invoke-AtomicTest T1021.002 -TestNumbers 4
Invoke-AtomicTest T1218 -TestNumbers 16
```

Export what WS01 logged before clearing anything:

```
powershell -ExecutionPolicy Bypass -File C:\Users\Public\Export-ChainEvents.ps1 -Start "<start time>" -End (Get-Date) -Out C:\Users\Public\chain-endpoint-A.csv
```

Then the last step, the same command as the T1070.001 test:

```
wevtutil cl Application
```

## Cleanup

```
Invoke-AtomicTest T1053.005 -TestNumbers 1 -Cleanup
Invoke-AtomicTest T1547.001 -TestNumbers 1 -Cleanup
Invoke-AtomicTest T1136.001 -TestNumbers 4 -Cleanup
Remove-NetFirewallRule -DisplayName "TEMP SMB from Kali"
```

Confirm with `net user` that the test account is gone, and `Test-Path C:\Windows\output.txt` returns False.

## Collect

On WAZUH, with the start time and the end time of the session:

```
sudo python3 scripts/chain_timeline.py --start "2026-10-16 HH:MM" --end "2026-10-16 HH:MM" --out chain-alerts
```

Keep `chain-alerts.md`, `chain-alerts.json` and `chain-endpoint-A.csv`, plus the times you wrote down for each command.
