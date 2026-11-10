<#
.SYNOPSIS
  Produces scripted directory administration on DC01 for the baseline week.

.DESCRIPTION
  Run in elevated PowerShell on DC01 as a domain administrator. All account creation,
  lookup, and cleanup is confined to the fixed OU=LabTesting,DC=corp,DC=lab OU. Create
  that dedicated lab OU before installing this task. No domain-wide account searches run.

  Successful actions are recorded in dc-actions.csv only after the requested operation
  is verified. Failures are recorded in errors.csv and return a nonzero exit code.

.EXAMPLE
  .\Generate-DcActivity.ps1 -Install -OnboardingDay (Get-Date).AddDays(3)
  .\Generate-DcActivity.ps1 -Remove
#>
param(
  [switch]$Install,
  [switch]$Remove,
  [switch]$Run,
  [datetime]$OnboardingDay,
  [string]$Root = 'C:\ProgramData\Baseline'
)

$ErrorActionPreference = 'Stop'
$LabOu = 'OU=LabTesting,DC=corp,DC=lab'
$log = Join-Path $Root 'dc-actions.csv'
$errorLog = Join-Path $Root 'errors.csv'
$configPath = Join-Path $Root 'dc-config.txt'
$script:CreatedThisRun = New-Object 'System.Collections.Generic.List[string]'
$currentAction = 'initialize'

function Write-Action([string]$Name) {
  ('{0},{1}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $Name) | Add-Content -Path $log -ErrorAction Stop
}

function Write-ActivityError([string]$Name, [System.Management.Automation.ErrorRecord]$Record) {
  $message = [string]$Record.Exception.Message
  $message = $message -replace '(?i)(password\s*[:=]\s*)\S+', '$1<REDACTED_PASSWORD>'
  $row = [pscustomobject]@{
    time = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    kind = 'dc'
    action = $Name
    error = $message
  }
  try {
    $row | Export-Csv -Path $errorLog -NoTypeInformation -Append -Encoding UTF8 -ErrorAction Stop
  } catch {
    Write-Host ("Could not append to {0}: {1}" -f $errorLog, $_.Exception.Message) -ForegroundColor Red
  }
  Write-Host ("FAILED dc/{0}: {1}" -f $Name, $message) -ForegroundColor Red
}

function New-Pass {
  ConvertTo-SecureString ('Bl!' + ([guid]::NewGuid().ToString('N').Substring(0, 12)) + 'Aa1') -AsPlainText -Force
}

function Get-LabUsers([string]$Pattern) {
  Get-ADUser -SearchBase $LabOu -SearchScope Subtree `
    -Filter "SamAccountName -like '$Pattern'" -ErrorAction Stop
}

function Get-LabUserExact([string]$SamAccountName, [string[]]$Properties = @()) {
  $propertyArg = @('SamAccountName') + $Properties
  Get-ADUser -SearchBase $LabOu -SearchScope Subtree -Properties $propertyArg `
    -Filter "SamAccountName -eq '$SamAccountName'" -ErrorAction Stop |
    Select-Object -First 1
}

function Assert-InLabOu($User) {
  if (-not $User -or -not $User.DistinguishedName.EndsWith(',' + $LabOu, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Directory object is outside the dedicated lab OU ($LabOu)."
  }
}

function Remove-LabUsers([string]$Pattern) {
  $users = @(Get-LabUsers $Pattern)
  foreach ($user in $users) {
    Assert-InLabOu $user
    $script:CurrentAction = "cleanup $($user.SamAccountName)"
    Remove-ADUser -Identity $user.DistinguishedName -Confirm:$false -ErrorAction Stop
    $remaining = Get-LabUserExact $user.SamAccountName
    if ($remaining) { throw "Account $($user.SamAccountName) still exists after cleanup." }
    Write-Action "removed $($user.SamAccountName)"
  }
}

function Add-LabUser([string]$SamAccountName, [bool]$Enabled = $true) {
  $script:CurrentAction = "create $SamAccountName"
  $created = New-ADUser -Name $SamAccountName -SamAccountName $SamAccountName `
    -Path $LabOu -AccountPassword (New-Pass) -Enabled $Enabled -PassThru -ErrorAction Stop
  $script:CreatedThisRun.Add($SamAccountName)
  $verified = Get-LabUserExact $SamAccountName
  Assert-InLabOu $verified
  Write-Action "new-account $SamAccountName"
  return $verified
}

function Remove-TaskIfPresent {
  $tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskName -eq 'Baseline-DC' })
  foreach ($task in $tasks) {
    $script:CurrentAction = 'unregister Baseline-DC task'
    Unregister-ScheduledTask -TaskName 'Baseline-DC' -Confirm:$false -ErrorAction Stop
  }
  $remaining = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskName -eq 'Baseline-DC' })
  if ($remaining.Count -gt 0) { throw 'Baseline-DC task still exists after removal.' }
  if ($tasks.Count -gt 0) { Write-Action 'task-removed' }
}

function Rollback-CreatedUsers {
  foreach ($sam in @($script:CreatedThisRun.ToArray())) {
    try {
      $user = Get-LabUserExact $sam
      if ($user) {
        Assert-InLabOu $user
        Remove-ADUser -Identity $user.DistinguishedName -Confirm:$false -ErrorAction Stop
        if (Get-LabUserExact $sam) { throw "Rollback did not remove $sam." }
        Write-Action "rollback-removed $sam"
      }
    } catch {
      Write-ActivityError "rollback $sam" $_
    }
  }
}

try {
  New-Item -ItemType Directory -Force -Path $Root -ErrorAction Stop | Out-Null
  if (-not (Test-Path -LiteralPath $log)) {
    'time,action' | Out-File -FilePath $log -Encoding ascii -ErrorAction Stop
  }
  if (-not (Test-Path -LiteralPath $errorLog)) {
    'time,kind,action,error' | Out-File -FilePath $errorLog -Encoding ascii -ErrorAction Stop
  }
  Import-Module ActiveDirectory -ErrorAction Stop
  $null = Get-ADOrganizationalUnit -Identity $LabOu -ErrorAction Stop
} catch {
  Write-ActivityError $currentAction $_
  exit 1
}

$operationCount = 0
if ($Install) { $operationCount++ }
if ($Remove) { $operationCount++ }
if ($Run) { $operationCount++ }
if ($operationCount -ne 1) {
  $record = [System.Management.Automation.ErrorRecord]::new(
    [System.ArgumentException]::new('Specify exactly one of -Install, -Remove, or -Run.'),
    'InvalidOperation', [System.Management.Automation.ErrorCategory]::InvalidArgument, $null)
  Write-ActivityError 'arguments' $record
  exit 2
}

try {
  if ($Remove) {
    Remove-TaskIfPresent
    Remove-LabUsers 'hire.*'
    Remove-LabUsers 'onboard.*'
    Write-Host "Removed Baseline-DC resources from $LabOu."
    exit 0
  }

  if ($Install) {
    $currentAction = 'copy generator script'
    Copy-Item -LiteralPath $PSCommandPath -Destination $Root -Force -ErrorAction Stop
    $installedScript = Join-Path $Root 'Generate-DcActivity.ps1'
    if (-not (Test-Path -LiteralPath $installedScript)) { throw 'Generator script copy verification failed.' }

    if ($OnboardingDay) {
      $configuredDate = $OnboardingDay.ToString('yyyy-MM-dd')
      $configuredDate | Out-File -FilePath $configPath -Encoding ascii -Force -ErrorAction Stop
      if ((Get-Content -LiteralPath $configPath -Raw -ErrorAction Stop).Trim() -ne $configuredDate) {
        throw 'Onboarding-day configuration verification failed.'
      }
    } elseif (Test-Path -LiteralPath $configPath) {
      Remove-Item -LiteralPath $configPath -Force -ErrorAction Stop
      if (Test-Path -LiteralPath $configPath) { throw 'Old onboarding-day configuration remains.' }
    }

    $currentAction = 'register Baseline-DC task'
    $arguments = '-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}" -Run' -f $installedScript
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments -ErrorAction Stop
    $trigger = New-ScheduledTaskTrigger -Daily -At 09:30 -ErrorAction Stop
    $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" `
      -LogonType Interactive -RunLevel Highest -ErrorAction Stop
    Register-ScheduledTask -TaskName 'Baseline-DC' -Action $action -Trigger $trigger `
      -Principal $principal -Force -ErrorAction Stop | Out-Null
    $task = Get-ScheduledTask -TaskName 'Baseline-DC' -ErrorAction Stop
    if (-not $task -or $task.Actions.Arguments -notlike '*Generate-DcActivity.ps1*') {
      throw 'Scheduled task registration verification failed.'
    }
    Write-Action 'task-installed'
    Write-Host 'Installed Baseline-DC. Keep an interactive domain-admin session open on DC01.'
    exit 0
  }

  if ($Run) {
    $currentAction = 'cleanup prior generated accounts'
    Remove-LabUsers 'hire.*'
    Remove-LabUsers 'onboard.*'

    $count = Get-Random -Minimum 1 -Maximum 4
    for ($i = 1; $i -le $count; $i++) {
      $sam = 'hire.' + (Get-Random -Minimum 1000 -Maximum 9999)
      $null = Add-LabUser $sam $true
      if ($i -lt $count) { Start-Sleep -Seconds (Get-Random -Minimum 30 -Maximum 300) }
    }

    $any = Get-LabUsers 'hire.*' | Select-Object -First 1
    if ($any) {
      Assert-InLabOu $any
      $before = Get-LabUserExact -SamAccountName $any.SamAccountName -Properties @('PasswordLastSet')
      $currentAction = "password reset $($any.SamAccountName)"
      Set-ADAccountPassword -Identity $any.DistinguishedName -Reset -NewPassword (New-Pass) -ErrorAction Stop
      $after = Get-LabUserExact -SamAccountName $any.SamAccountName -Properties @('PasswordLastSet')
      if (-not $after -or -not $after.PasswordLastSet -or
          ($before.PasswordLastSet -and $after.PasswordLastSet -lt $before.PasswordLastSet)) {
        throw "Password-reset verification failed for $($any.SamAccountName)."
      }
      Write-Action "password-reset $($any.SamAccountName)"

      $groups = @(Get-ADGroup -SearchBase $LabOu -SearchScope Subtree `
        -Filter "Name -eq 'BaselineStaff'" -ErrorAction Stop)
      $group = $groups | Select-Object -First 1
      if (-not $group) {
        $currentAction = 'create BaselineStaff group'
        New-ADGroup -Name 'BaselineStaff' -GroupScope Global -Path $LabOu -ErrorAction Stop
        $groups = @(Get-ADGroup -SearchBase $LabOu -SearchScope Subtree `
          -Filter "Name -eq 'BaselineStaff'" -ErrorAction Stop)
        $group = $groups | Select-Object -First 1
        if (-not $group) { throw 'BaselineStaff group creation was not visible inside the lab OU.' }
        Write-Action 'group-created BaselineStaff'
      }
      if (-not $group.DistinguishedName.EndsWith(',' + $LabOu, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'BaselineStaff resolved outside the dedicated lab OU.'
      }
      $currentAction = "add $($any.SamAccountName) to BaselineStaff"
      Add-ADGroupMember -Identity $group.DistinguishedName -Members $any.DistinguishedName -ErrorAction Stop
      $members = @(Get-ADGroupMember -Identity $group.DistinguishedName -Recursive -ErrorAction Stop)
      if ($members.ObjectGUID -notcontains $any.ObjectGUID) {
        throw "Group membership verification failed for $($any.SamAccountName)."
      }
      Write-Action "group-change $($any.SamAccountName)"
    }

    if (Test-Path -LiteralPath $configPath) {
      $configuredDate = (Get-Content -LiteralPath $configPath -Raw -ErrorAction Stop).Trim()
      if ($configuredDate -eq (Get-Date).ToString('yyyy-MM-dd')) {
        Start-Sleep -Seconds 600
        $onboardingNames = @(1..12 | ForEach-Object { 'onboard.{0:00}' -f $_ })
        foreach ($sam in $onboardingNames) {
          $currentAction = "onboarding create $sam"
          $null = New-ADUser -Name $sam -SamAccountName $sam -Path $LabOu `
            -AccountPassword (New-Pass) -Enabled $true -PassThru -ErrorAction Stop
          $script:CreatedThisRun.Add($sam)
        }
        $found = @(Get-LabUsers 'onboard.*' | Select-Object -ExpandProperty SamAccountName)
        $missing = @($onboardingNames | Where-Object { $_ -notin $found })
        if ($missing.Count -gt 0) { throw "Onboarding verification is missing: $($missing -join ', ')." }
        foreach ($sam in $onboardingNames) {
          $verified = Get-LabUserExact $sam
          Assert-InLabOu $verified
        }
        foreach ($sam in $onboardingNames) { Write-Action "onboarding-account $sam" }
        Write-Action 'onboarding-burst-verified 12'
      }
    }
    Write-Host "DC activity completed within $LabOu."
  }
} catch {
  Write-ActivityError $currentAction $_
  Rollback-CreatedUsers
  exit 1
}
