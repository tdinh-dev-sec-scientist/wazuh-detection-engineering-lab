<#
.SYNOPSIS
  Produces scripted directory administration on DC01 for the baseline week.

.DESCRIPTION
  Run in an elevated PowerShell on DC01 as a domain admin. It registers one daily task (09:30)
  that creates one to three "new hire" accounts, resets a password and changes a group membership,
  and removes the accounts it created the day before. On the day given with -OnboardingDay it also
  creates 12 accounts in one minute, the way a class or a department is onboarded, so the mass
  account creation rule (100400) is measured against a legitimate burst.

.EXAMPLE
  .\Generate-DcActivity.ps1 -Install -OnboardingDay (Get-Date).AddDays(3)
  .\Generate-DcActivity.ps1 -Remove
#>
param(
  [switch]$Install,
  [switch]$Remove,
  [switch]$Run,
  [datetime]$OnboardingDay,
  [string]$Root = 'C:\ProgramData\Baseline',
  [string]$Ou = 'CN=Users,DC=corp,DC=lab'
)

$ErrorActionPreference = 'SilentlyContinue'
New-Item -ItemType Directory -Force -Path $Root | Out-Null
$log = Join-Path $Root 'dc-actions.csv'
$cfg = Join-Path $Root 'dc-config.txt'
if (-not (Test-Path $log)) { 'time,action' | Out-File $log -Encoding ascii }
function Write-Action($name) { ('{0},{1}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $name) | Add-Content $log }
function New-Pass { ConvertTo-SecureString ('Bl!' + ([guid]::NewGuid().ToString('N').Substring(0, 12)) + 'Aa1') -AsPlainText -Force }

if ($Remove) {
  Unregister-ScheduledTask -TaskName 'Baseline-DC' -Confirm:$false
  Get-ADUser -Filter 'SamAccountName -like "hire.*" -or SamAccountName -like "onboard.*"' | Remove-ADUser -Confirm:$false
  'task and baseline accounts removed'; return
}

if ($Install) {
  Copy-Item $PSCommandPath $Root -Force
  if ($OnboardingDay) { $OnboardingDay.ToString('yyyy-MM-dd') | Out-File $cfg -Encoding ascii }
  $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File $Root\Generate-DcActivity.ps1 -Run"
  $trigger = New-ScheduledTaskTrigger -Daily -At 09:30
  $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Highest
  Register-ScheduledTask -TaskName 'Baseline-DC' -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
  'Installed at ' + (Get-Date -Format 'yyyy-MM-dd HH:mm') + '. Keep a console session open on DC01.'
  return
}

if ($Run) {
  Import-Module ActiveDirectory
  # remove yesterday's and older accounts
  Get-ADUser -Filter 'SamAccountName -like "hire.*"' | Remove-ADUser -Confirm:$false
  Get-ADUser -Filter 'SamAccountName -like "onboard.*"' | Remove-ADUser -Confirm:$false

  $count = Get-Random -Minimum 1 -Maximum 4
  for ($i = 1; $i -le $count; $i++) {
    $sam = 'hire.' + (Get-Random -Minimum 1000 -Maximum 9999)
    New-ADUser -Name $sam -SamAccountName $sam -Path $Ou -AccountPassword (New-Pass) -Enabled $true
    Write-Action "new-hire $sam"
    Start-Sleep -Seconds (Get-Random -Minimum 30 -Maximum 300)
  }
  $any = Get-ADUser -Filter 'SamAccountName -like "hire.*"' | Select-Object -First 1
  if ($any) {
    Set-ADAccountPassword -Identity $any -Reset -NewPassword (New-Pass); Write-Action "password-reset $($any.SamAccountName)"
    New-ADGroup -Name BaselineStaff -GroupScope Global -Path $Ou
    Add-ADGroupMember -Identity 'BaselineStaff' -Members $any; Write-Action "group-change $($any.SamAccountName)"
  }

  if ((Test-Path $cfg) -and ((Get-Content $cfg) -eq (Get-Date).ToString('yyyy-MM-dd'))) {
    Start-Sleep -Seconds 600
    Write-Action 'onboarding-burst-start'
    1..12 | ForEach-Object { New-ADUser -Name ('onboard.{0:00}' -f $_) -SamAccountName ('onboard.{0:00}' -f $_) -Path $Ou -AccountPassword (New-Pass) -Enabled $true }
    Write-Action 'onboarding-burst-end'
  }
}
