<#
.SYNOPSIS
  Runs the 15 live detection tests in order and records when each one ran.

.DESCRIPTION
  Run in an elevated PowerShell on WS01 as CORP\adm.truong, after the baseline weeks and after every
  tuning change. Tests that start on Kali or DC01 pause and wait for you. The script leaves 90 seconds
  between tests: in the first attack chain session a burst of 40 commands in 20 seconds filled the agent
  queue and two detections were lost, so a regression run must not be a burst.
  Writes regression-times.csv (id,start,end in local time). Then run scripts/regression_check.py on the manager.

.EXAMPLE
  .\Run-AtomicRegression.ps1 -Out C:\Users\Public\regression-times.csv
#>
param([string]$Out = 'regression-times.csv', [int]$Gap = 90)

if (-not (Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue)) {
  Import-Module 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1' -Force
}
'id,start,end' | Out-File $Out -Encoding ascii
$fmt = 'yyyy-MM-dd HH:mm:ss'

function Step($id, [scriptblock]$run) {
  $start = (Get-Date).ToString($fmt)
  Write-Host "[$id] start $start"
  & $run
  $end = (Get-Date).ToString($fmt)
  "$id,$start,$end" | Add-Content $Out
  Write-Host "[$id] end   $end"
  Start-Sleep -Seconds $Gap
}
function Manual($id, $where, $what) {
  $prompt = "[$id] on ${where}: $what. Press Enter here when it has finished"
  Step $id { Read-Host $prompt | Out-Null }
}

Step 'T1082'      { Invoke-AtomicTest T1082 -TestNumbers 1 }
Step 'FW-BLOCK'   { ping -n 4 10.10.50.254 | Out-Null }
Manual 'T1046'     'Kali' 'run nmap -sS -Pn -T4 -p 22,1433,3306,5432,1521,5900 10.10.30.149 (check Kali address and the temporary WS01 firewall rule first)'
Manual 'T1136.002' 'DC01' 'create 15 disabled test accounts in one loop with New-ADUser, then delete them'
Step 'T1053.005'  { Invoke-AtomicTest T1053.005 -TestNumbers 1; Invoke-AtomicTest T1053.005 -TestNumbers 1 -Cleanup }
Step 'T1547.001'  { Invoke-AtomicTest T1547.001 -TestNumbers 1; Invoke-AtomicTest T1547.001 -TestNumbers 1 -Cleanup }
Step 'T1136.001'  { Invoke-AtomicTest T1136.001 -TestNumbers 4; Invoke-AtomicTest T1136.001 -TestNumbers 4 -Cleanup }   # type a compliant password when asked
Step 'T1070.001'  { wevtutil cl Application }
Manual 'T1110'     'Kali' 'run 12 smbclient logons with fakeuser against WS01 (see the runbook)'
Step 'T1059.001'  { Invoke-AtomicTest T1059.001 -TestNumbers 17 }
Step 'T1087.001'  { net user | Out-Null; net localgroup administrators | Out-Null; cmdkey /list | Out-Null; query user | Out-Null }
Step 'T1105'      { Invoke-AtomicTest T1105 -TestNumbers 7 }
Step 'T1021.002'  { Invoke-AtomicTest T1021.002 -TestNumbers 4; Invoke-AtomicTest T1021.002 -TestNumbers 4 -Cleanup }
Step 'T1543.003'  { Invoke-AtomicTest T1543.003 -TestNumbers 2; Invoke-AtomicTest T1543.003 -TestNumbers 2 -Cleanup }
Step 'T1218'      { Invoke-AtomicTest T1218 -TestNumbers 16 }

Write-Host "Done. Copy $Out to the manager and run: sudo python3 scripts/regression_check.py --times regression-times.csv"
