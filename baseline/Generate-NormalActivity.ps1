<#
.SYNOPSIS
  Produces scripted "normal" activity on WS01 so the custom rules can be measured without any attack.

.DESCRIPTION
  Each run picks a few actions from two sets and records them in C:\ProgramData\Baseline\actions.csv.
    User actions    browsing, file work, name lookups, small PowerShell housekeeping
    Admin actions   the kind of commands a help desk or administrator really runs and that some
                    custom rules watch: systeminfo, net user, schtasks /create, certutil -hashfile,
                    admin share copies, short-lived local accounts, service and Run key changes
  Rare actions have a daily cap. Nothing here attacks anything: every change is undone in the same run.
  The workload is scripted by me, not a real user population, so the numbers it produces are a
  lower bound for a lab, not a measured false positive rate for a company.
#>
param(
  [ValidateSet('Work', 'Off')][string]$Window = 'Work',
  [string]$Root = 'C:\ProgramData\Baseline'
)

$ErrorActionPreference = 'SilentlyContinue'
New-Item -ItemType Directory -Force -Path $Root | Out-Null
$log = Join-Path $Root 'actions.csv'
if (-not (Test-Path $log)) { 'time,kind,action' | Out-File $log -Encoding ascii }
$work = Join-Path $Root 'work'
New-Item -ItemType Directory -Force -Path $work | Out-Null

function Write-Action($kind, $name) {
  ('{0},{1},{2}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $kind, $name) | Add-Content $log
}
function Count-Today($name) {
  $today = (Get-Date).ToString('yyyy-MM-dd')
  @(Import-Csv $log | Where-Object { $_.action -eq $name -and $_.time.StartsWith($today) }).Count
}
function New-Pass { 'Bl!' + ([guid]::NewGuid().ToString('N').Substring(0, 12)) + 'Aa1' }

# ---- user actions -------------------------------------------------------------------
$user = @{
  'browse'      = { foreach ($u in 'https://example.com', 'https://en.wikipedia.org/wiki/Main_Page') { Invoke-WebRequest $u -UseBasicParsing -TimeoutSec 15 | Out-Null } }
  'dns-lookup'  = { nslookup microsoft.com | Out-Null; nslookup dc01.corp.lab | Out-Null }
  'ping-dc'     = { ping -n 2 10.10.20.10 | Out-Null }
  'file-work'   = {
      $f = Join-Path $work ('doc-' + (Get-Random) + '.txt'); 'quarterly notes' | Out-File $f
      Copy-Item $f ($f + '.bak'); Compress-Archive $f ($f + '.zip') -Force
      Remove-Item $f, ($f + '.bak'), ($f + '.zip') -Force }
  'open-calc'   = { $p = Start-Process calc -PassThru; Start-Sleep 5; Stop-Process -Id $p.Id -Force }
  'open-notepad'= { $p = Start-Process notepad -PassThru; Start-Sleep 5; Stop-Process -Id $p.Id -Force }
  'ps-inventory'= { Get-Process | Select-Object -First 20 | Out-Null; Get-Service | Where-Object Status -eq Running | Out-Null; Get-ChildItem C:\Windows\System32 -Filter *.dll | Select-Object -First 50 | Out-Null }
  'net-time'    = { w32tm /query /status | Out-Null }
}

# ---- admin actions (weight, daily cap) ----------------------------------------------
$admin = @(
  @{ n = 'systeminfo';              cap = 3; s = { systeminfo | Out-Null } },
  @{ n = 'whoami-all';              cap = 4; s = { whoami /all | Out-Null } },
  @{ n = 'net-user-list';           cap = 4; s = { net user | Out-Null } },
  @{ n = 'net-localgroup-admins';   cap = 3; s = { net localgroup administrators | Out-Null } },
  @{ n = 'query-user';              cap = 3; s = { query user | Out-Null } },
  @{ n = 'cmdkey-list';             cap = 2; s = { cmdkey /list | Out-Null } },
  @{ n = 'schtasks-query';          cap = 4; s = { schtasks /query /fo LIST | Out-Null } },
  @{ n = 'wevtutil-query';          cap = 3; s = { wevtutil qe System /c:5 /f:text | Out-Null } },
  @{ n = 'certutil-hashfile';       cap = 3; s = { certutil -hashfile C:\Windows\System32\notepad.exe SHA256 | Out-Null } },
  @{ n = 'certutil-store';          cap = 2; s = { certutil -store my | Out-Null } },
  @{ n = 'schtasks-create-delete';  cap = 2; s = {
        schtasks /create /tn 'Baseline-Maint' /tr 'cmd.exe /c echo maint' /sc daily /st 03:00 /f | Out-Null
        Start-Sleep 3; schtasks /delete /tn 'Baseline-Maint' /f | Out-Null } },
  @{ n = 'local-account-add-remove';cap = 2; s = {
        $pw = New-Pass; net user baseline.tmp $pw /add | Out-Null; Start-Sleep 3; net user baseline.tmp /delete | Out-Null } },
  @{ n = 'admin-share-copy';        cap = 3; s = {
        $f = Join-Path $work 'share-test.txt'; 'x' | Out-File $f
        Copy-Item $f '\\localhost\C$\Windows\Temp\share-test.txt' -Force; Remove-Item '\\localhost\C$\Windows\Temp\share-test.txt' -Force; Remove-Item $f -Force } },
  @{ n = 'dc-admin-share-list';     cap = 2; s = { Get-ChildItem '\\dc01.corp.lab\C$' | Select-Object -First 5 | Out-Null } },
  @{ n = 'service-create-delete';   cap = 1; s = {
        sc.exe create BaselineSvc binPath= 'C:\Windows\System32\notepad.exe' start= demand | Out-Null; Start-Sleep 3; sc.exe delete BaselineSvc | Out-Null } },
  @{ n = 'run-key-add-remove';      cap = 1; s = {
        reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run' /v BaselineApp /t REG_SZ /d 'C:\Windows\System32\notepad.exe' /f | Out-Null
        Start-Sleep 3; reg delete 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run' /v BaselineApp /f | Out-Null } },
  @{ n = 'ps-encoded-command';      cap = 1; s = {
        $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Get-Date | Out-Null'))
        powershell.exe -NoProfile -EncodedCommand $enc } },
  @{ n = 'clear-custom-log';        cap = 1; s = {
        New-EventLog -LogName BaselineLog -Source BaselineSrc; Write-EventLog -LogName BaselineLog -Source BaselineSrc -EventId 1 -Message 'baseline'
        Clear-EventLog -LogName BaselineLog; Remove-EventLog -LogName BaselineLog } }
)

# ---- pick what to run ---------------------------------------------------------------
$runs = if ($Window -eq 'Work') { Get-Random -Minimum 1 -Maximum 4 } else { 1 }
for ($i = 0; $i -lt $runs; $i++) {
  $adminChance = if ($Window -eq 'Work') { 0.30 } else { 0.05 }
  if ((Get-Random -Minimum 0.0 -Maximum 1.0) -lt $adminChance) {
    $pick = $admin | Get-Random
    if ((Count-Today $pick.n) -lt $pick.cap) { Write-Action 'admin' $pick.n; & $pick.s }
  } else {
    $name = $user.Keys | Get-Random
    Write-Action 'user' $name; & $user[$name]
  }
  Start-Sleep -Seconds (Get-Random -Minimum 2 -Maximum 20)
}
