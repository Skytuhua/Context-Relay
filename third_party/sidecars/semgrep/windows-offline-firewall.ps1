function Test-OutboundTcp([Net.IPAddress]$Address, [ValidateSet(80, 443)][int]$Port = 443) {
  $Client = [Net.Sockets.TcpClient]::new($Address.AddressFamily)
  try {
    $Connect = $Client.ConnectAsync($Address, $Port)
    if (-not $Connect.Wait([TimeSpan]::FromSeconds(8))) { return $false }
    return $Client.Connected
  } catch {
    return $false
  } finally {
    $Client.Dispose()
  }
}

function Get-RunnerControlPlanePrograms {
  # Qualification experiment under the existing hosted-runner ancestor model, not vendor attestation.
  $RequiredNames = @('Runner.Worker.exe', 'Runner.Listener.exe', 'hosted-compute-agent')
  $Found = [Collections.Generic.List[object]]::new()
  $Visited = [Collections.Generic.HashSet[uint32]]::new()
  [uint32]$CurrentProcessId = $PID
  $ChildCreated = $null
  while ($CurrentProcessId -ne 0 -and $Visited.Count -lt 32) {
    if (-not $Visited.Add($CurrentProcessId)) { Fail 'runner ancestor cycle' }
    $Processes = @(Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $CurrentProcessId" -Property ProcessId,ParentProcessId,CreationDate,ExecutablePath -ErrorAction Stop | Select-Object -First 2)
    if ($Processes.Count -ne 1) { Fail 'runner ancestor is missing or ambiguous' }
    $Process = $Processes[0]
    if ([uint32]$Process.ProcessId -ne $CurrentProcessId -or $null -eq $Process.CreationDate) { Fail 'runner ancestor identity is unavailable' }
    $Created = ([DateTime]$Process.CreationDate).ToUniversalTime()
    if ($null -ne $ChildCreated -and $Created -gt $ChildCreated) { Fail 'runner parent identity was reused or creation order is invalid' }
    $Path = [string]$Process.ExecutablePath
    $Name = [IO.Path]::GetFileName($Path)
    if ($RequiredNames -contains $Name) {
      if (-not [string]::Equals($Name, $RequiredNames[$Found.Count], [StringComparison]::OrdinalIgnoreCase)) { Fail 'runner ancestors are duplicated or out of order' }
      if ($Path.Length -gt 1024 -or $Path -notmatch '\A[A-Za-z]:\\' -or $Path.Substring(2).Contains(':') -or ($Path -split '\\') -contains '..') { Fail 'runner executable path is unsafe' }
      $Path = [IO.Path]::GetFullPath($Path)
      $Part = $Path
      while (-not [string]::IsNullOrEmpty($Part)) {
        $Item = Get-Item -LiteralPath $Part -Force -ErrorAction Stop
        if (($Item.Attributes -band ([IO.FileAttributes]::ReparsePoint -bor [IO.FileAttributes]::Device)) -ne 0 -or
            ($Part -eq $Path -and $Item.PSIsContainer) -or ($Part -ne $Path -and -not $Item.PSIsContainer)) { Fail 'runner executable path is not a regular no-link file' }
        $Part = [IO.Path]::GetDirectoryName($Part)
      }
      $Hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path -ErrorAction Stop).Hash
      if ($Hash -notmatch '\A[0-9A-Fa-f]{64}\z') { Fail 'runner executable hash is invalid' }
      $Found.Add([pscustomobject]@{
        Name = $RequiredNames[$Found.Count]; Path = $Path; ProcessId = $CurrentProcessId
        ParentProcessId = [uint32]$Process.ParentProcessId; CreatedAt = $Created.ToString('o'); Sha256 = $Hash
      })
      if ($Found.Count -eq 3) {
        if (-not [string]::Equals([IO.Path]::GetDirectoryName($Found[0].Path), [IO.Path]::GetDirectoryName($Found[1].Path), [StringComparison]::OrdinalIgnoreCase)) { Fail 'runner control-plane executables do not share one trusted directory' }
        return $Found.ToArray()
      }
    }
    $ChildCreated = $Created
    $CurrentProcessId = [uint32]$Process.ParentProcessId
  }
  Fail 'required runner ancestors were not found within 32 processes'
}

function Assert-RunnerControlPlaneIdentity([object[]]$Expected) {
  $Current = @(Get-RunnerControlPlanePrograms)
  if ($Expected.Count -ne 3 -or $Current.Count -ne 3 -or
      -not [string]::Equals(($Expected | ConvertTo-Json -Compress), ($Current | ConvertTo-Json -Compress), [StringComparison]::Ordinal)) {
    Fail 'runner ancestor PID, creation, path or hash changed'
  }
}

function Assert-OfflineFirewallRules([object[]]$ExpectedRules) {
  foreach ($Expected in $ExpectedRules) {
    $Rules = @(Get-NetFirewallRule -Name $Expected.Name -PolicyStore ActiveStore -ErrorAction Stop)
    if ($Rules.Count -ne 1 -or -not [string]::Equals([string]$Rules[0].Name, [string]$Expected.Name, [StringComparison]::Ordinal)) { Fail 'isolation rule is missing or ambiguous' }
    $Rule = $Rules[0]
    $Application = $Rule | Get-NetFirewallApplicationFilter
    $AddressFilter = $Rule | Get-NetFirewallAddressFilter
    $Port = $Rule | Get-NetFirewallPortFilter
    $Service = $Rule | Get-NetFirewallServiceFilter
    $ActualAddresses = [string[]]@($AddressFilter.RemoteAddress)
    $ExpectedAddresses = [string[]]@($Expected.RemoteAddress)
    [Array]::Sort($ActualAddresses, [StringComparer]::Ordinal)
    [Array]::Sort($ExpectedAddresses, [StringComparer]::Ordinal)
    $Protocol = [string]$Port.Protocol
    if ($Protocol -eq '6') { $Protocol = 'TCP' }
    if ($Protocol -eq '17') { $Protocol = 'UDP' }
    $Actual = @([string]$Rule.Enabled, [string]$Rule.Direction, [string]$Rule.Action, [string]$Rule.Profile, [string]$Application.Program, ($ActualAddresses -join ','), [string]$Port.RemotePort, $Protocol, [string]$Service.Service)
    $Wanted = @('True', 'Outbound', 'Allow', 'Any', $Expected.Program, ($ExpectedAddresses -join ','), $Expected.RemotePort, $Expected.Protocol, $Expected.Service)
    if (-not [string]::Equals(($Actual | ConvertTo-Json -Compress), ($Wanted | ConvertTo-Json -Compress), [StringComparison]::Ordinal)) { Fail 'isolation rule program, service, address or port is not exact and active' }
  }
  $Names = [Collections.Generic.HashSet[string]]::new([string[]]@($ExpectedRules | ForEach-Object Name), [StringComparer]::Ordinal)
  $Extra = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Action Allow -Enabled True | Where-Object { -not $Names.Contains([string]$_.Name) })
  if ($Extra.Count -ne 0) { Fail 'outbound allow rules remain outside the control-plane carveout' }
}

function Test-DnsResolverAddress([Net.IPAddress]$Address) {
  if ($Address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -and
      $Address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetworkV6) { return $false }
  return -not [Net.IPAddress]::IsLoopback($Address) -and
    -not $Address.Equals([Net.IPAddress]::Any) -and
    -not $Address.Equals([Net.IPAddress]::IPv6Any) -and
    -not $Address.IsIPv6Multicast
}

function Invoke-WindowsOfflineFirewall([scriptblock]$Action, [ref]$RestorationVerified) {
  if ($null -ne $RestorationVerified) { $RestorationVerified.Value = $false }
  $ProbeAddress = [Net.Dns]::GetHostAddresses('github.com') |
    Where-Object AddressFamily -eq ([Net.Sockets.AddressFamily]::InterNetwork) |
    Select-Object -First 1
  if ($null -eq $ProbeAddress -or -not (Test-OutboundTcp $ProbeAddress)) {
    Fail 'outbound TCP preflight failed before enabling offline firewall policy'
  }
  $ImdsAddress = [Net.IPAddress]::Parse('169.254.169.254')
  if (-not (Test-OutboundTcp $ImdsAddress 80)) { Fail 'IMDS TCP preflight failed before enabling offline firewall policy' }
  $RunnerIdentities = @(Get-RunnerControlPlanePrograms)
  $RunnerPrograms = @($RunnerIdentities | ForEach-Object Path)
  $HcaProgram = $RunnerIdentities[2].Path
  $ResolverSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Resolver in @(Get-DnsClientServerAddress -ErrorAction Stop | ForEach-Object ServerAddresses)) {
    [Net.IPAddress]$Address = $null
    if (-not [Net.IPAddress]::TryParse([string]$Resolver, [ref]$Address) -or
        -not (Test-DnsResolverAddress $Address)) { continue }
    [void]$ResolverSet.Add($Address.ToString())
  }
  $ResolverAddresses = [string[]]@($ResolverSet)
  [Array]::Sort($ResolverAddresses, [StringComparer]::Ordinal)
  if ($ResolverAddresses.Count -eq 0 -or $ResolverAddresses.Count -gt 16) {
    Fail 'configured DNS resolver address set is missing or unbounded'
  }
  $ProfileSnapshots = @(foreach ($ProfileName in @('Domain', 'Private', 'Public')) {
    $Profile = Get-NetFirewallProfile -Profile $ProfileName -ErrorAction Stop
    [pscustomobject]@{
      Name = $Profile.Name
      DefaultOutboundAction = [string]$Profile.DefaultOutboundAction
    }
  })
  $FirewallPrefix = "ContextRelaySemgrepOffline-$PID-$([Guid]::NewGuid().ToString('N'))"
  $RunnerRuleNames = [Collections.Generic.List[string]]::new()
  $DnsRuleNames = [Collections.Generic.List[string]]::new()
  $DisabledOutboundRuleNames = [Collections.Generic.List[string]]::new()
  $ExpectedRules = [Collections.Generic.List[object]]::new()
  try {
    $RuleIndex = 0
    foreach ($Program in $RunnerPrograms) {
      $RuleIndex += 1
      $RuleName = "$FirewallPrefix-Runner-$RuleIndex"
      $RunnerRuleNames.Add($RuleName)
      New-NetFirewallRule -Name $RuleName -DisplayName $RuleName -Direction Outbound -Program $Program -RemoteAddress Any -RemotePort 443 -Protocol TCP -Action Allow -Profile Any -ErrorAction Stop | Out-Null
      $ExpectedRules.Add([pscustomobject]@{ Name = $RuleName; Program = $Program; RemoteAddress = @('Any'); RemotePort = '443'; Protocol = 'TCP'; Service = 'Any' })
    }
    $RuleName = "$FirewallPrefix-Hca-Imds"
    $RunnerRuleNames.Add($RuleName)
    New-NetFirewallRule -Name $RuleName -DisplayName $RuleName -Direction Outbound -Program $HcaProgram -RemoteAddress '169.254.169.254' -RemotePort 80 -Protocol TCP -Action Allow -Profile Any -ErrorAction Stop | Out-Null
    $ExpectedRules.Add([pscustomobject]@{ Name = $RuleName; Program = $HcaProgram; RemoteAddress = @('169.254.169.254'); RemotePort = '80'; Protocol = 'TCP'; Service = 'Any' })

    $DnsProgram = [IO.Path]::GetFullPath((Join-Path ([Environment]::SystemDirectory) 'svchost.exe'))
    foreach ($Protocol in @('UDP', 'TCP')) {
      $RuleName = "$FirewallPrefix-Dns-$Protocol"
      $DnsRuleNames.Add($RuleName)
      New-NetFirewallRule -Name $RuleName -DisplayName $RuleName -Direction Outbound -Program $DnsProgram -Service Dnscache -RemoteAddress $ResolverAddresses -RemotePort 53 -Protocol $Protocol -Action Allow -Profile Any -ErrorAction Stop | Out-Null
      $ExpectedRules.Add([pscustomobject]@{ Name = $RuleName; Program = $DnsProgram; RemoteAddress = $ResolverAddresses; RemotePort = '53'; Protocol = $Protocol; Service = 'Dnscache' })
    }

    $ExistingOutboundAllows = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Action Allow -Enabled True |
      Where-Object { -not $RunnerRuleNames.Contains([string]$_.Name) -and -not $DnsRuleNames.Contains([string]$_.Name) })
    foreach ($ExistingRule in $ExistingOutboundAllows) {
      if ([string]$ExistingRule.PolicyStoreSourceType -ne 'Local' -or [string]::IsNullOrWhiteSpace($ExistingRule.Name)) {
        Fail "non-local outbound allow rule prevents fail-closed isolation: $($ExistingRule.DisplayName)"
      }
      $DisabledOutboundRuleNames.Add($ExistingRule.Name)
      Disable-NetFirewallRule -Name $ExistingRule.Name -ErrorAction Stop | Out-Null
    }
    $RemainingBroadAllows = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Action Allow -Enabled True |
      Where-Object { -not $RunnerRuleNames.Contains([string]$_.Name) -and -not $DnsRuleNames.Contains([string]$_.Name) })
    if ($RemainingBroadAllows.Count -ne 0) { Fail 'outbound allow rules remain outside the runner control-plane carveout' }

    foreach ($ProfileSnapshot in $ProfileSnapshots) {
      Set-NetFirewallProfile -Profile $ProfileSnapshot.Name -DefaultOutboundAction Block -ErrorAction Stop
    }
    foreach ($ProfileSnapshot in $ProfileSnapshots) {
      $Effective = Get-NetFirewallProfile -Profile $ProfileSnapshot.Name -ErrorAction Stop
      if ([string]$Effective.DefaultOutboundAction -ne 'Block' -or [string]$Effective.Enabled -ne 'True') { Fail "offline default outbound policy is not active: $($ProfileSnapshot.Name)" }
    }
    Assert-RunnerControlPlaneIdentity $RunnerIdentities
    Assert-OfflineFirewallRules $ExpectedRules.ToArray()
    if (Test-OutboundTcp $ProbeAddress) { Fail 'hostile outbound TCP probe bypassed the offline firewall policy' }
    if (Test-OutboundTcp $ImdsAddress 80) { Fail 'hostile shell IMDS TCP probe bypassed the offline firewall policy' }
    . $Action
    Assert-RunnerControlPlaneIdentity $RunnerIdentities
    Assert-OfflineFirewallRules $ExpectedRules.ToArray()
    foreach ($ProfileSnapshot in $ProfileSnapshots) {
      $Effective = Get-NetFirewallProfile -Profile $ProfileSnapshot.Name -ErrorAction Stop
      if ([string]$Effective.DefaultOutboundAction -ne 'Block' -or [string]$Effective.Enabled -ne 'True') { Fail "offline firewall policy changed during the isolated action: $($ProfileSnapshot.Name)" }
    }
    if (Test-OutboundTcp $ProbeAddress) { Fail 'offline firewall policy was removed during the isolated action' }
    if (Test-OutboundTcp $ImdsAddress 80) { Fail 'shell IMDS TCP denial was removed during the isolated action' }
  } finally {
    $RestoreFailures = [Collections.Generic.List[string]]::new()
    foreach ($ProfileSnapshot in $ProfileSnapshots) {
      try {
        Set-NetFirewallProfile -Profile $ProfileSnapshot.Name -DefaultOutboundAction $ProfileSnapshot.DefaultOutboundAction -ErrorAction Stop
        $Restored = Get-NetFirewallProfile -Profile $ProfileSnapshot.Name -ErrorAction Stop
        if ([string]$Restored.DefaultOutboundAction -ne $ProfileSnapshot.DefaultOutboundAction) {
          throw "restored value differs: $($Restored.DefaultOutboundAction)"
        }
      } catch {
        $RestoreFailures.Add("profile $($ProfileSnapshot.Name): $($_.Exception.Message)")
      }
    }
    foreach ($RuleName in $DisabledOutboundRuleNames) {
      try {
        Enable-NetFirewallRule -Name $RuleName -ErrorAction Stop | Out-Null
        $RestoredRule = Get-NetFirewallRule -Name $RuleName -PolicyStore ActiveStore -ErrorAction Stop
        if ($RestoredRule.Enabled -ne 'True') { throw 'rule is not enabled' }
      } catch {
        $RestoreFailures.Add("outbound rule ${RuleName}: $($_.Exception.Message)")
      }
    }
    foreach ($RuleName in [string[]]@($RunnerRuleNames + $DnsRuleNames)) {
      try {
        if (Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue) {
          Remove-NetFirewallRule -Name $RuleName -ErrorAction Stop
        }
        if (Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue) { throw 'rule still exists' }
      } catch {
        $RestoreFailures.Add("isolation allow rule ${RuleName}: $($_.Exception.Message)")
      }
    }
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    if ($RestoreFailures.Count -ne 0) { Fail "firewall restoration failed: $($RestoreFailures -join '; ')" }
    if ($null -ne $RestorationVerified) { $RestorationVerified.Value = $true }
  }
}
