<#
.SYNOPSIS
  Export what a Windows endpoint logged during a time window, to compare with what Wazuh alerted on.

.DESCRIPTION
  Run in an elevated PowerShell on WS01 (or DC01). It reads Sysmon, Security, System and
  Microsoft Defender events between -Start and -End (local time) and writes one CSV row per
  event with a short summary. Nothing is changed on the machine.

.EXAMPLE
  .\Export-ChainEvents.ps1 -Start "2026-10-16 10:00" -End "2026-10-16 10:40" -Out C:\Users\Public\chain-endpoint-A.csv
#>
param(
  [Parameter(Mandatory = $true)][datetime]$Start,
  [Parameter(Mandatory = $true)][datetime]$End,
  [string]$Out = "chain-endpoint.csv"
)

$sources = @(
  @{ Log = 'Microsoft-Windows-Sysmon/Operational'; Ids = 1, 3, 11, 13 },
  @{ Log = 'Security'; Ids = 1102, 4624, 4625, 4688, 4720, 4722, 4732 },
  @{ Log = 'System'; Ids = 104, 7045 },
  @{ Log = 'Microsoft-Windows-Windows Defender/Operational'; Ids = 1116, 1117 }
)

function Get-Fields($event) {
  $fields = @{}
  $xml = [xml]$event.ToXml()
  foreach ($d in $xml.Event.EventData.Data) {
    if ($d.Name) { $fields[$d.Name] = [string]$d.'#text' }
  }
  # Events 104 and 1102 keep their fields under UserData instead of EventData.
  if ($xml.Event.UserData -and $xml.Event.UserData.FirstChild) {
    foreach ($n in $xml.Event.UserData.FirstChild.ChildNodes) { $fields[$n.Name] = [string]$n.InnerText }
  }
  return $fields
}

function Get-Summary($log, $id, $f) {
  switch ("$log|$id") {
    'Microsoft-Windows-Sysmon/Operational|1'  { return "$($f['Image']) :: $($f['CommandLine']) (parent $($f['ParentImage']), user $($f['User']))" }
    'Microsoft-Windows-Sysmon/Operational|3'  { return "$($f['Image']) -> $($f['DestinationIp']):$($f['DestinationPort'])" }
    'Microsoft-Windows-Sysmon/Operational|11' { return "$($f['Image']) created $($f['TargetFilename'])" }
    'Microsoft-Windows-Sysmon/Operational|13' { return "$($f['Image']) set $($f['TargetObject'])" }
    'Security|4688' { return "$($f['NewProcessName']) :: $($f['CommandLine']) (parent $($f['ParentProcessName']), user $($f['SubjectUserName']))" }
    'Security|4624' { return "logon type $($f['LogonType']) user $($f['TargetUserName']) from $($f['IpAddress']) workstation $($f['WorkstationName'])" }
    'Security|4625' { return "failed logon type $($f['LogonType']) user $($f['TargetUserName']) from $($f['IpAddress']) status $($f['Status']) sub $($f['SubStatus'])" }
    'Security|4720' { return "account created $($f['TargetUserName']) by $($f['SubjectUserName'])" }
    'Security|4722' { return "account enabled $($f['TargetUserName']) by $($f['SubjectUserName'])" }
    'Security|4732' { return "member $($f['MemberSid']) added to group $($f['TargetUserName']) by $($f['SubjectUserName'])" }
    'Security|1102' { return "audit log cleared by $($f['SubjectUserName'])" }
    'System|104'    { return "log cleared: $($f['Channel']) by $($f['SubjectUserName'])" }
    'System|7045'   { return "service installed $($f['ServiceName']) $($f['ImagePath'])" }
    default         { return ($f.GetEnumerator() | Select-Object -First 6 | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; ' }
  }
}

$rows = foreach ($s in $sources) {
  try {
    $events = Get-WinEvent -FilterHashtable @{ LogName = $s.Log; Id = $s.Ids; StartTime = $Start; EndTime = $End } -ErrorAction Stop
  } catch {
    continue   # no events of this kind in the window
  }
  foreach ($e in $events) {
    $f = Get-Fields $e
    [pscustomobject]@{
      Time    = $e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
      Log     = $s.Log -replace 'Microsoft-Windows-', ''
      EventId = $e.Id
      Summary = Get-Summary $s.Log $e.Id $f
    }
  }
}

$rows | Sort-Object Time | Export-Csv -Path $Out -NoTypeInformation -Encoding UTF8
"{0} events written to {1}" -f @($rows).Count, $Out
$rows | Group-Object Log, EventId | Sort-Object Name | ForEach-Object { "{0,5}  {1}" -f $_.Count, $_.Name }
