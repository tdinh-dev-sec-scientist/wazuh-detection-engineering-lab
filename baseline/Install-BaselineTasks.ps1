<#
.SYNOPSIS
  Installs (or removes) the scheduled tasks that run the baseline generator on WS01.

.DESCRIPTION
  Run in an elevated PowerShell on WS01 as CORP\adm.truong. The tasks run as that user, only while
  the user is logged on, so keep a console session open (locked is fine) and turn off sleep.
    Baseline-Work  every 15 minutes between 08:00 and 18:00
    Baseline-Off   every 60 minutes all day
  Installing writes events itself, so start the 7 day clock after this script finishes.

.EXAMPLE
  .\Install-BaselineTasks.ps1
  .\Install-BaselineTasks.ps1 -Remove
#>
param([switch]$Remove)

$root = 'C:\ProgramData\Baseline'
$user = "$env:USERDOMAIN\$env:USERNAME"

if ($Remove) {
  'Baseline-Work', 'Baseline-Off' | ForEach-Object { Unregister-ScheduledTask -TaskName $_ -Confirm:$false -ErrorAction SilentlyContinue }
  'tasks removed; actions.csv kept in ' + $root
  return
}

New-Item -ItemType Directory -Force -Path $root | Out-Null
Copy-Item (Join-Path $PSScriptRoot 'Generate-NormalActivity.ps1') $root -Force

$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 10)

function New-Action($window) {
  New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File $root\Generate-NormalActivity.ps1 -Window $window"
}

$work = New-ScheduledTaskTrigger -Once -At (Get-Date).Date.AddHours(8) -RepetitionInterval (New-TimeSpan -Minutes 15) -RepetitionDuration (New-TimeSpan -Hours 10)
$work.Repetition.StopAtDurationEnd = $true
# The 08:00 trigger fires daily through a daily trigger with the same repetition.
$workDaily = New-ScheduledTaskTrigger -Daily -At 08:00
$workDaily.Repetition = $work.Repetition
$off = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Minutes 60)

Register-ScheduledTask -TaskName 'Baseline-Work' -Action (New-Action 'Work') -Trigger $workDaily -Principal $principal -Settings $settings -Force | Out-Null
Register-ScheduledTask -TaskName 'Baseline-Off'  -Action (New-Action 'Off')  -Trigger $off       -Principal $principal -Settings $settings -Force | Out-Null

Get-ScheduledTask -TaskName 'Baseline-*' | Select-Object TaskName, State | Format-Table -AutoSize
'Installed at ' + (Get-Date -Format 'yyyy-MM-dd HH:mm') + '. Write this time down: it is the start of the baseline.'
