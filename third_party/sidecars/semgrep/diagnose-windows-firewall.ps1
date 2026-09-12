param([Parameter(Mandatory = $true)][string]$OutputRoot)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$PSNativeCommandUseErrorActionPreference = $false
function Fail([string]$Message) { throw $Message }
. (Join-Path $PSScriptRoot 'windows-offline-firewall.ps1')

function Convert-WfpBlockedEvent([xml]$EventXml) {
  $Fields = @{}
  foreach ($Entry in $EventXml.Event.EventData.Data) { $Fields[[string]$Entry.Name] = [string]$Entry.InnerText }
  $Result = [ordered]@{ timestamp = [string]$EventXml.Event.System.TimeCreated.SystemTime }
  foreach ($Pair in ([ordered]@{
    applicationPath = 'Application'; pid = 'ProcessID'; destinationIp = 'DestAddress'
    destinationPort = 'DestPort'; protocol = 'Protocol'; filterId = 'FilterRTID'
  }).GetEnumerator()) {
    $Value = [string]$Fields[$Pair.Value]
    $Result[$Pair.Key] = $Value.Substring(0, [Math]::Min(1024, $Value.Length))
  }
  return [pscustomobject]$Result
}

function Read-AuditPolicyCsv([string]$Csv) {
  if ($Csv.Length -eq 0 -or $Csv.Length -gt 1048576 -or $Csv.Contains([char]0)) { throw 'invalid audit CSV size or content' }
  if ($Csv.StartsWith([string][char]0xFEFF, [StringComparison]::Ordinal)) { $Csv = $Csv.Substring(1) }
  # Exact seven-column Microsoft audit CSV header, including option and per-user rows:
  # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/6494a0f2-8a16-40e2-b87d-328be7d732e0
  $Header = 'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value'
  $Parser = [Microsoft.VisualBasic.FileIO.TextFieldParser]::new([IO.StringReader]::new($Csv))
  $Parser.SetDelimiters(',')
  $Parser.HasFieldsEnclosedInQuotes = $true
  $Parser.TrimWhiteSpace = $false
  $Rows = [Collections.Generic.Dictionary[string,string[]]]::new([StringComparer]::Ordinal)
  try {
    $Fields = $Parser.ReadFields()
    if ($null -eq $Fields -or $Fields.Count -ne 7 -or
        -not [string]::Equals(($Fields -join ','), $Header, [StringComparison]::Ordinal)) { throw 'invalid audit CSV header' }
    while (-not $Parser.EndOfData) {
      $Fields = $Parser.ReadFields()
      if ($Fields.Count -ne 7 -or $Rows.Count -ge 4096 -or @($Fields | Where-Object Length -gt 4096).Count) {
        throw 'invalid audit CSV row shape or bound'
      }
      $Key = ConvertTo-Json -InputObject $Fields[0..3] -Compress
      # Reject repeated identities, including identical duplicates; never silently overwrite policy.
      if ($Rows.ContainsKey($Key)) { throw 'duplicate audit CSV identity' }
      $Rows.Add($Key, $Fields)
    }
    if ($Rows.Count -eq 0) { throw 'empty audit CSV policy' }
    return ,$Rows
  } finally {
    $Parser.Dispose()
  }
}

function Compare-AuditPolicyCsv([string]$BeforeCsv, [string]$AfterCsv) {
  $Before = Read-AuditPolicyCsv $BeforeCsv
  $After = Read-AuditPolicyCsv $AfterCsv
  $Missing = @($Before.Keys | Where-Object { -not $After.ContainsKey($_) }).Count
  $Extra = @($After.Keys | Where-Object { -not $Before.ContainsKey($_) }).Count
  $Changed = 0
  $ChangedFields = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  $Names = @('Machine Name', 'Policy Target', 'Subcategory', 'Subcategory GUID', 'Inclusion Setting', 'Exclusion Setting', 'Setting Value')
  foreach ($Key in $Before.Keys) {
    if (-not $After.ContainsKey($Key)) { continue }
    $Different = $false
    for ($Index = 0; $Index -lt 7; $Index++) {
      if (-not [string]::Equals($Before[$Key][$Index], $After[$Key][$Index], [StringComparison]::Ordinal)) {
        $Different = $true
        [void]$ChangedFields.Add($Names[$Index])
      }
    }
    if ($Different) { $Changed++ }
  }
  # Only counts and fixed field names leave this function; never policy targets or row values.
  return [pscustomobject]@{
    equal = ($Missing -eq 0 -and $Extra -eq 0 -and $Changed -eq 0)
    beforeRows = $Before.Count; afterRows = $After.Count
    missingRows = $Missing; extraRows = $Extra; changedRows = $Changed
    changedFields = @($ChangedFields | Sort-Object)
  }
}

function Get-ConnectionAuditFlags([string]$Csv) {
  $Rows = Read-AuditPolicyCsv $Csv
  $Selected = [Collections.Generic.List[string[]]]::new()
  foreach ($Row in $Rows.Values) {
    if ([string]::Equals($Row[1], 'System', [StringComparison]::Ordinal) -and
        [string]::Equals($Row[3], '{0CCE9226-69AE-11D9-BED3-505054503030}', [StringComparison]::OrdinalIgnoreCase)) {
      $Selected.Add($Row)
    }
  }
  if ($Selected.Count -ne 1) { throw 'system connection audit row is missing or ambiguous' }
  $Row = $Selected[0]
  if ($Row[6] -notmatch '\A[0-3]\z' -or $Row[5].Length -ne 0) { throw 'system connection audit flags are unsupported' }
  $Flags = [int]$Row[6]
  $Labels = @('No Auditing', 'Success', 'Failure', 'Success and Failure')
  if (-not [string]::Equals($Row[4], $Labels[$Flags], [StringComparison]::Ordinal)) {
    throw 'system connection audit flags are ambiguous'
  }
  return [pscustomobject]@{
    success = $(if ($Flags -band 1) { 'enable' } else { 'disable' })
    failure = $(if ($Flags -band 2) { 'enable' } else { 'disable' })
  }
}

# This changes host policy: only the disposable GitHub-hosted Windows 2022 job may run it.
if (-not $IsWindows -or $env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows' -or
    $env:ImageOS -ne 'win22' -or $env:CONTEXT_RELAY_RUNNER_IMAGE -ne 'windows-2022') {
  Fail 'firewall diagnostics require an ephemeral windows-2022 GitHub Actions runner'
}
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
$TempRoot = [IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\') + '\'
if (-not $OutputRoot.StartsWith($TempRoot, [StringComparison]::OrdinalIgnoreCase) -or
    (Test-Path -LiteralPath $OutputRoot)) { Fail 'diagnostic output must be a new runner-temp directory' }
New-Item -ItemType Directory -Path $OutputRoot | Out-Null
$Auditpol = Join-Path ([Environment]::SystemDirectory) 'auditpol.exe'
# Capture all policy rows, but restore only the system subcategory this diagnostic changes.
# https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-set
$AuditBackup = Join-Path $env:RUNNER_TEMP "$([Guid]::NewGuid().ToString('N')).audit.csv"
$AuditRestored = "$AuditBackup.restored"
# https://learn.microsoft.com/en-us/windows/win32/fwp/auditing-and-logging
$ConnectionAudit = '{0CCE9226-69AE-11D9-BED3-505054503030}'
$Report = [ordered]@{
  schemaVersion = 1; purpose = 'short-firewall-diagnostic-not-release-qualification'
  observationSeconds = 120; baselineConnected = $false; isolatedShellDenied = $false
  firewallRestored = $false; auditRestored = $false; postRestoreConnected = $false
  failureStage = $null; eventLimit = 256; eventsTruncated = $false; blockedConnections = @()
  auditVerification = [ordered]@{ restoreExitCode = $null; backupExitCode = $null; comparison = $null }
}
$Stage = 'baseline'
$AuditSaved = $false
$FirewallRestored = $false
$Started = [DateTime]::UtcNow
$Ended = $Started
try {
  $Address = [Net.Dns]::GetHostAddresses('github.com') |
    Where-Object AddressFamily -eq ([Net.Sockets.AddressFamily]::InterNetwork) | Select-Object -First 1
  if ($null -eq $Address -or -not (Test-OutboundTcp $Address)) { Fail 'baseline connection failed' }
  $Report.baselineConnected = $true
  $Stage = 'audit-setup'
  & $Auditpol /backup "/file:$AuditBackup" 2>&1 | Out-Null
  if ($LASTEXITCODE -ne 0) { Fail 'audit backup failed' }
  if ((Get-Item -LiteralPath $AuditBackup).Length -gt 1048576) { Fail 'audit CSV file exceeds bound' }
  $OriginalAuditFlags = Get-ConnectionAuditFlags ([IO.File]::ReadAllText($AuditBackup, [Text.UTF8Encoding]::new($false, $true)))
  # Unsupported initial representations fail before any audit policy mutation.
  $AuditSaved = $true
  & $Auditpol /set "/subcategory:$ConnectionAudit" /failure:enable 2>&1 | Out-Null
  if ($LASTEXITCODE -ne 0) { Fail 'audit enable failed' }
  $Stage = 'isolated-window'
  $Started = [DateTime]::UtcNow
  Invoke-WindowsOfflineFirewall {
    # Entry occurs only after the shared policy's hostile shell TCP probe was denied.
    $Report.isolatedShellDenied = $true
    Start-Sleep -Seconds 120
  } -RestorationVerified ([ref]$FirewallRestored)
} catch {
  # Never export exception text (native tools can include unrelated host data).
  $Report.failureStage = $Stage
} finally {
  $Ended = [DateTime]::UtcNow
  $Report.firewallRestored = $FirewallRestored
  if ($AuditSaved) {
    & $Auditpol /set "/subcategory:$ConnectionAudit" "/success:$($OriginalAuditFlags.success)" "/failure:$($OriginalAuditFlags.failure)" 2>&1 | Out-Null
    $Report.auditVerification.restoreExitCode = $LASTEXITCODE
    if ($LASTEXITCODE -ne 0) {
      $Report.failureStage = 'audit-restore-native-exit'
    } else {
      & $Auditpol /backup "/file:$AuditRestored" 2>&1 | Out-Null
      $Report.auditVerification.backupExitCode = $LASTEXITCODE
      if ($LASTEXITCODE -ne 0) {
        $Report.failureStage = 'audit-restored-backup-native-exit'
      } else {
        try {
          foreach ($Path in @($AuditBackup, $AuditRestored)) {
            if ((Get-Item -LiteralPath $Path).Length -gt 1048576) { throw 'audit CSV file exceeds bound' }
          }
          $Utf8 = [Text.UTF8Encoding]::new($false, $true)
          $Report.auditVerification.comparison = Compare-AuditPolicyCsv ([IO.File]::ReadAllText($AuditBackup, $Utf8)) ([IO.File]::ReadAllText($AuditRestored, $Utf8))
          $Report.auditRestored = $Report.auditVerification.comparison.equal
          if (-not $Report.auditRestored) { $Report.failureStage = 'audit-policy-mismatch' }
        } catch {
          $Report.failureStage = 'audit-policy-invalid-csv'
        }
      }
    }
    Remove-Item -LiteralPath $AuditBackup, $AuditRestored -Force -ErrorAction SilentlyContinue
  }
}
if (-not $Report.firewallRestored -or -not $Report.auditRestored) {
  # Retain bounded comparison metadata even on failure; connection events remain uncollected.
  $Report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $OutputRoot 'firewall-diagnostic.v1.json') -Encoding utf8
  Fail 'diagnostic did not verify both restorations; network event export suppressed'
}
$Report.postRestoreConnected = Test-OutboundTcp $Address
try {
  $Events = @(Get-WinEvent -FilterHashtable @{
    LogName = 'Security'; ProviderName = 'Microsoft-Windows-Security-Auditing'
    Id = 5157; StartTime = $Started; EndTime = $Ended
  } -MaxEvents 257 -ErrorAction Stop)
  $Report.eventsTruncated = $Events.Count -gt 256
  $Report.blockedConnections = @($Events | Select-Object -First 256 | ForEach-Object {
    Convert-WfpBlockedEvent ([xml]$_.ToXml())
  })
} catch {
  $Report.failureStage = 'event-collection'
}
if (-not $Report.postRestoreConnected) { $Report.failureStage = 'post-restoration-network' }
if (@($Report.blockedConnections | Where-Object pid -eq ([string]$PID)).Count -eq 0) {
  $Report.failureStage = 'missing-shell-denial-audit'
}
$Report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $OutputRoot 'firewall-diagnostic.v1.json') -Encoding utf8
if ($null -ne $Report.failureStage) { Fail "firewall diagnostic failed at $($Report.failureStage)" }
Write-Output 'Short firewall diagnostic completed and host policies restored; sustained build qualification remains unproven.'
