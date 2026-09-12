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
# Native auditpol backup/restore preserves system, per-user and option settings.
# https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-restore
$AuditBackup = Join-Path $env:RUNNER_TEMP "$([Guid]::NewGuid().ToString('N')).audit.csv"
$AuditRestored = "$AuditBackup.restored"
# https://learn.microsoft.com/en-us/windows/win32/fwp/auditing-and-logging
$ConnectionAudit = '{0CCE9226-69AE-11D9-BED3-505054503030}'
$Report = [ordered]@{
  schemaVersion = 1; purpose = 'short-firewall-diagnostic-not-release-qualification'
  observationSeconds = 120; baselineConnected = $false; isolatedShellDenied = $false
  firewallRestored = $false; auditRestored = $false; postRestoreConnected = $false
  failureStage = $null; eventLimit = 256; eventsTruncated = $false; blockedConnections = @()
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
  & $Auditpol /backup "/file:$AuditBackup" | Out-Null
  if ($LASTEXITCODE -ne 0) { Fail 'audit backup failed' }
  $AuditSaved = $true
  & $Auditpol /set "/subcategory:$ConnectionAudit" /failure:enable | Out-Null
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
    & $Auditpol /restore "/file:$AuditBackup" | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail 'audit restoration failed; diagnostic export suppressed' }
    & $Auditpol /backup "/file:$AuditRestored" | Out-Null
    if ($LASTEXITCODE -ne 0 -or
        (Get-FileHash -LiteralPath $AuditBackup).Hash -ne (Get-FileHash -LiteralPath $AuditRestored).Hash) {
      Fail 'audit restoration verification failed; diagnostic export suppressed'
    }
    $Report.auditRestored = $true
    Remove-Item -LiteralPath $AuditBackup, $AuditRestored -Force
  }
}
if (-not $Report.firewallRestored -or -not $Report.auditRestored) {
  Fail 'diagnostic did not verify both restorations; diagnostic export suppressed'
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
