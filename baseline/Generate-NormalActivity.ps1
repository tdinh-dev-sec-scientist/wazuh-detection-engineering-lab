<#
.SYNOPSIS
  Produces scripted "normal" activity on WS01 so custom rules can be measured without an attack.

.DESCRIPTION
  Each run picks a few actions from two sets and records successful actions in actions.csv.
  Failures are written to errors.csv and cause a nonzero exit after the run. Success rows are
  written only after the action and its verification complete. Random local-account passwords
  remain in memory and are never written to the activity or error logs.
#>
param(
  [ValidateSet('Work', 'Off')][string]$Window = 'Work',
  [string]$Root = 'C:\ProgramData\Baseline'
)

$ErrorActionPreference = 'Stop'
$log = Join-Path $Root 'actions.csv'
$errorLog = Join-Path $Root 'errors.csv'
$work = Join-Path $Root 'work'
$script:ActivityFailures = 0

function Write-Action([string]$Kind, [string]$Name) {
  ('{0},{1},{2}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $Kind, $Name) | Add-Content -Path $log -ErrorAction Stop
}

function Write-ActivityError([string]$Kind, [string]$Name, [System.Management.Automation.ErrorRecord]$Record) {
  $message = [string]$Record.Exception.Message
  $message = $message -replace '(?i)(password\s*[:=]\s*)\S+', '$1<REDACTED_PASSWORD>'
  $row = [pscustomobject]@{
    time = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    kind = $Kind
    action = $Name
    error = $message
  }
  $row | Export-Csv -Path $errorLog -NoTypeInformation -Append -Encoding UTF8 -ErrorAction Stop
  Write-Host ("FAILED {0}/{1}: {2}" -f $Kind, $Name, $message) -ForegroundColor Red
}

function Invoke-NativeCommand([scriptblock]$Command) {
  & $Command
  $exitCode = $LASTEXITCODE
  if ($null -eq $exitCode -or $exitCode -ne 0) {
    throw "Native command failed with exit code $exitCode."
  }
}

function Invoke-LoggedAction([string]$Kind, [string]$Name, [scriptblock]$Action) {
  try {
    & $Action
    Write-Action $Kind $Name
    Write-Host ("Completed {0}/{1}" -f $Kind, $Name)
    return $true
  } catch {
    Write-ActivityError $Kind $Name $_
    $script:ActivityFailures++
    return $false
  }
}

try {
  New-Item -ItemType Directory -Force -Path $Root -ErrorAction Stop | Out-Null
  New-Item -ItemType Directory -Force -Path $work -ErrorAction Stop | Out-Null
  if (-not (Test-Path -LiteralPath $log)) {
    'time,kind,action' | Out-File -FilePath $log -Encoding ascii -ErrorAction Stop
  }
  if (-not (Test-Path -LiteralPath $errorLog)) {
    'time,kind,action,error' | Out-File -FilePath $errorLog -Encoding ascii -ErrorAction Stop
  }
} catch {
  Write-Host ("Could not initialize activity logging: {0}" -f $_.Exception.Message) -ForegroundColor Red
  exit 1
}

function Count-Today([string]$Name) {
  $today = (Get-Date).ToString('yyyy-MM-dd')
  @(Import-Csv -Path $log -ErrorAction Stop | Where-Object { $_.action -eq $Name -and $_.time.StartsWith($today) }).Count
}

function New-Pass {
  'Bl!' + ([guid]::NewGuid().ToString('N').Substring(0, 12)) + 'Aa1'
}

function Test-ScheduledTaskExists([string]$Name) {
  & schtasks.exe /query /tn $Name *> $null
  return ($LASTEXITCODE -eq 0)
}

function Test-ServiceExists([string]$Name) {
  & sc.exe query $Name *> $null
  return ($LASTEXITCODE -eq 0)
}

function Wait-ServiceAbsent([string]$Name) {
  for ($attempt = 0; $attempt -lt 10; $attempt++) {
    if (-not (Test-ServiceExists $Name)) { return $true }
    Start-Sleep -Seconds 1
  }
  return (-not (Test-ServiceExists $Name))
}

function Test-RegistryValueExists([string]$Key, [string]$Name) {
  & reg.exe query $Key /v $Name *> $null
  return ($LASTEXITCODE -eq 0)
}

# ---- user actions -------------------------------------------------------------------
$user = @{
  'browse' = {
    foreach ($url in 'https://example.com', 'https://en.wikipedia.org/wiki/Main_Page') {
      $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
      if ([int]$response.StatusCode -lt 200 -or [int]$response.StatusCode -ge 400) {
        throw "Web request returned HTTP $($response.StatusCode)."
      }
    }
  }
  'dns-lookup' = {
    Invoke-NativeCommand { nslookup.exe microsoft.com | Out-Null }
    Invoke-NativeCommand { nslookup.exe dc01.corp.lab | Out-Null }
  }
  'ping-dc' = { Invoke-NativeCommand { ping.exe -n 2 10.10.20.10 | Out-Null } }
  'file-work' = {
    $file = Join-Path $work ('doc-' + (Get-Random) + '.txt')
    $temporaryFiles = @($file, ($file + '.bak'), ($file + '.zip'))
    try {
      'quarterly notes' | Out-File -FilePath $file -ErrorAction Stop
      Copy-Item -LiteralPath $file -Destination ($file + '.bak') -ErrorAction Stop
      Compress-Archive -Path $file -DestinationPath ($file + '.zip') -Force -ErrorAction Stop
      if (-not (Test-Path -LiteralPath $file) -or -not (Test-Path -LiteralPath ($file + '.bak')) -or
          -not (Test-Path -LiteralPath ($file + '.zip'))) {
        throw 'File-work output verification failed.'
      }
    } finally {
      foreach ($candidate in $temporaryFiles) {
        if (Test-Path -LiteralPath $candidate) {
          Remove-Item -LiteralPath $candidate -Force -ErrorAction Stop
        }
      }
      if (@($temporaryFiles | Where-Object { Test-Path -LiteralPath $_ }).Count -gt 0) {
        throw 'File-work cleanup did not remove every temporary file.'
      }
    }
  }
  'open-calc' = {
    $process = Start-Process -FilePath 'calc.exe' -PassThru -ErrorAction Stop
    if (-not $process) { throw 'Calculator did not start.' }
    Start-Sleep -Seconds 5
    $running = Get-Process -ErrorAction Stop | Where-Object { $_.Id -eq $process.Id }
    if ($running) { Stop-Process -Id $process.Id -Force -ErrorAction Stop }
  }
  'open-notepad' = {
    $process = Start-Process -FilePath 'notepad.exe' -PassThru -ErrorAction Stop
    if (-not $process) { throw 'Notepad did not start.' }
    Start-Sleep -Seconds 5
    $running = Get-Process -ErrorAction Stop | Where-Object { $_.Id -eq $process.Id }
    if ($running) { Stop-Process -Id $process.Id -Force -ErrorAction Stop }
  }
  'ps-inventory' = {
    Get-Process -ErrorAction Stop | Select-Object -First 20 | Out-Null
    Get-Service -ErrorAction Stop | Where-Object Status -eq Running | Out-Null
    Get-ChildItem -Path 'C:\Windows\System32' -Filter '*.dll' -ErrorAction Stop | Select-Object -First 50 | Out-Null
  }
  'net-time' = { Invoke-NativeCommand { w32tm.exe /query /status | Out-Null } }
}

# ---- admin actions (weight, daily cap) ----------------------------------------------
$admin = @(
  @{ n = 'systeminfo'; cap = 3; s = { Invoke-NativeCommand { systeminfo.exe | Out-Null } } },
  @{ n = 'whoami-all'; cap = 4; s = { Invoke-NativeCommand { whoami.exe /all | Out-Null } } },
  @{ n = 'net-user-list'; cap = 4; s = { Invoke-NativeCommand { net.exe user | Out-Null } } },
  @{ n = 'net-localgroup-admins'; cap = 3; s = { Invoke-NativeCommand { net.exe localgroup administrators | Out-Null } } },
  @{ n = 'query-user'; cap = 3; s = { Invoke-NativeCommand { query.exe user | Out-Null } } },
  @{ n = 'cmdkey-list'; cap = 2; s = { Invoke-NativeCommand { cmdkey.exe /list | Out-Null } } },
  @{ n = 'schtasks-query'; cap = 4; s = { Invoke-NativeCommand { schtasks.exe /query /fo LIST | Out-Null } } },
  @{ n = 'wevtutil-query'; cap = 3; s = { Invoke-NativeCommand { wevtutil.exe qe System /c:5 /f:text | Out-Null } } },
  @{ n = 'certutil-hashfile'; cap = 3; s = { Invoke-NativeCommand { certutil.exe -hashfile C:\Windows\System32\notepad.exe SHA256 | Out-Null } } },
  @{ n = 'certutil-store'; cap = 2; s = { Invoke-NativeCommand { certutil.exe -store my | Out-Null } } },
  @{ n = 'schtasks-create-delete'; cap = 2; s = {
      try {
        Invoke-NativeCommand { schtasks.exe /create /tn 'Baseline-Maint' /tr 'cmd.exe /c echo maint' /sc daily /st 03:00 /f | Out-Null }
        if (-not (Test-ScheduledTaskExists 'Baseline-Maint')) { throw 'Scheduled task creation was not visible.' }
        Invoke-NativeCommand { schtasks.exe /delete /tn 'Baseline-Maint' /f | Out-Null }
        if (Test-ScheduledTaskExists 'Baseline-Maint') { throw 'Scheduled task still exists after deletion.' }
      } finally {
        if (Test-ScheduledTaskExists 'Baseline-Maint') {
          Invoke-NativeCommand { schtasks.exe /delete /tn 'Baseline-Maint' /f | Out-Null }
          if (Test-ScheduledTaskExists 'Baseline-Maint') { throw 'Scheduled task cleanup failed.' }
        }
      }
    }
  },
  @{ n = 'local-account-add-remove'; cap = 2; s = {
      & net.exe user baseline.tmp *> $null
      if ($LASTEXITCODE -eq 0) {
        Invoke-NativeCommand { net.exe user baseline.tmp /delete | Out-Null }
      }
      $password = New-Pass
      try {
        Invoke-NativeCommand { net.exe user baseline.tmp $password /add | Out-Null }
        & net.exe user baseline.tmp *> $null
        if ($LASTEXITCODE -ne 0) { throw 'New local account was not visible after creation.' }
        Start-Sleep -Seconds 3
        Invoke-NativeCommand { net.exe user baseline.tmp /delete | Out-Null }
        & net.exe user baseline.tmp *> $null
        if ($LASTEXITCODE -eq 0) { throw 'Local account still exists after deletion.' }
      } finally {
        & net.exe user baseline.tmp *> $null
        if ($LASTEXITCODE -eq 0) {
          Invoke-NativeCommand { net.exe user baseline.tmp /delete | Out-Null }
          & net.exe user baseline.tmp *> $null
          if ($LASTEXITCODE -eq 0) { throw 'Local account cleanup failed.' }
        }
        $password = $null
      }
    }
  },
  @{ n = 'admin-share-copy'; cap = 3; s = {
      $file = Join-Path $work 'share-test.txt'
      $remote = '\\localhost\C$\Windows\Temp\share-test.txt'
      try {
        'x' | Out-File -FilePath $file -ErrorAction Stop
        Copy-Item -LiteralPath $file -Destination $remote -Force -ErrorAction Stop
        if (-not (Test-Path -LiteralPath $remote)) { throw 'Share copy was not present at the destination.' }
      } finally {
        foreach ($candidate in @($remote, $file)) {
          if (Test-Path -LiteralPath $candidate) {
            Remove-Item -LiteralPath $candidate -Force -ErrorAction Stop
          }
        }
        if ((Test-Path -LiteralPath $remote) -or (Test-Path -LiteralPath $file)) {
          throw 'Share-copy cleanup did not remove its files.'
        }
      }
    }
  },
  @{ n = 'dc-admin-share-list'; cap = 2; s = {
      Get-ChildItem -LiteralPath '\\dc01.corp.lab\C$' -ErrorAction Stop | Select-Object -First 5 | Out-Null
    }
  },
  @{ n = 'service-create-delete'; cap = 1; s = {
      try {
        Invoke-NativeCommand { sc.exe create BaselineSvc binPath= 'C:\Windows\System32\notepad.exe' start= demand | Out-Null }
        if (-not (Test-ServiceExists 'BaselineSvc')) { throw 'Service creation was not visible.' }
        Invoke-NativeCommand { sc.exe delete BaselineSvc | Out-Null }
        if (-not (Wait-ServiceAbsent 'BaselineSvc')) { throw 'Service still exists after deletion.' }
      } finally {
        if (Test-ServiceExists 'BaselineSvc') {
          Invoke-NativeCommand { sc.exe delete BaselineSvc | Out-Null }
          if (-not (Wait-ServiceAbsent 'BaselineSvc')) { throw 'Service cleanup failed.' }
        }
      }
    }
  },
  @{ n = 'run-key-add-remove'; cap = 1; s = {
      $key = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
      try {
        Invoke-NativeCommand { reg.exe add $key /v BaselineApp /t REG_SZ /d 'C:\Windows\System32\notepad.exe' /f | Out-Null }
        if (-not (Test-RegistryValueExists $key 'BaselineApp')) { throw 'Run key was not visible after creation.' }
        Invoke-NativeCommand { reg.exe delete $key /v BaselineApp /f | Out-Null }
        if (Test-RegistryValueExists $key 'BaselineApp') { throw 'Run key still exists after deletion.' }
      } finally {
        if (Test-RegistryValueExists $key 'BaselineApp') {
          Invoke-NativeCommand { reg.exe delete $key /v BaselineApp /f | Out-Null }
          if (Test-RegistryValueExists $key 'BaselineApp') { throw 'Run-key cleanup failed.' }
        }
      }
    }
  },
  @{ n = 'ps-encoded-command'; cap = 1; s = {
      $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Get-Date | Out-Null'))
      Invoke-NativeCommand { powershell.exe -NoProfile -EncodedCommand $encoded | Out-Null }
    }
  },
  @{ n = 'clear-custom-log'; cap = 1; s = {
      try {
        New-EventLog -LogName BaselineLog -Source BaselineSrc -ErrorAction Stop
        Write-EventLog -LogName BaselineLog -Source BaselineSrc -EventId 1 -Message 'baseline' -ErrorAction Stop
        $entry = Get-EventLog -LogName BaselineLog -Newest 1 -ErrorAction Stop
        if (-not $entry -or $entry.Source -ne 'BaselineSrc') { throw 'Test event was not visible in BaselineLog.' }
        Clear-EventLog -LogName BaselineLog -ErrorAction Stop
        if (@(Get-EventLog -LogName BaselineLog -ErrorAction Stop).Count -gt 0) { throw 'BaselineLog was not cleared.' }
      } finally {
        $existingLog = @(Get-EventLog -List -ErrorAction Stop | Where-Object { $_.Log -eq 'BaselineLog' })
        if ($existingLog.Count -gt 0) {
          Remove-EventLog -LogName BaselineLog -ErrorAction Stop
          $existingLog = @(Get-EventLog -List -ErrorAction Stop | Where-Object { $_.Log -eq 'BaselineLog' })
          if ($existingLog.Count -gt 0) { throw 'BaselineLog cleanup failed.' }
        }
      }
    }
  }
)

# ---- pick what to run ---------------------------------------------------------------
$runs = if ($Window -eq 'Work') { Get-Random -Minimum 1 -Maximum 4 } else { 1 }
try {
  for ($i = 0; $i -lt $runs; $i++) {
    $adminChance = if ($Window -eq 'Work') { 0.30 } else { 0.05 }
    if ((Get-Random -Minimum 0.0 -Maximum 1.0) -lt $adminChance) {
      $pick = $admin | Get-Random
      if ((Count-Today $pick.n) -lt $pick.cap) {
        Invoke-LoggedAction -Kind 'admin' -Name $pick.n -Action $pick.s | Out-Null
      }
    } else {
      $name = $user.Keys | Get-Random
      Invoke-LoggedAction -Kind 'user' -Name $name -Action $user[$name] | Out-Null
    }
    Start-Sleep -Seconds (Get-Random -Minimum 2 -Maximum 20)
  }
} catch {
  Write-ActivityError 'runner' 'main-loop' $_
  $script:ActivityFailures++
}

Write-Host ("Activity run finished with {0} failure(s). See {1} for details." -f $script:ActivityFailures, $errorLog)
if ($script:ActivityFailures -gt 0) { exit 1 }
