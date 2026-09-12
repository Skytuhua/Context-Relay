function Test-OutboundTcp([Net.IPAddress]$Address) {
  $Client = [Net.Sockets.TcpClient]::new($Address.AddressFamily)
  try {
    $Connect = $Client.ConnectAsync($Address, 443)
    if (-not $Connect.Wait([TimeSpan]::FromSeconds(8))) { return $false }
    return $Client.Connected
  } catch {
    return $false
  } finally {
    $Client.Dispose()
  }
}

function Get-RunnerControlPlanePrograms {
  $RequiredNames = @('Runner.Worker.exe', 'Runner.Listener.exe')
  $Found = @{}
  $Visited = [Collections.Generic.HashSet[uint32]]::new()
  [uint32]$CurrentProcessId = $PID
  while ($CurrentProcessId -ne 0 -and $Visited.Add($CurrentProcessId)) {
    $Process = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $CurrentProcessId" -ErrorAction Stop
    if ($null -eq $Process) { break }
    $Name = [IO.Path]::GetFileName([string]$Process.ExecutablePath)
    if ($RequiredNames -contains $Name) {
      if ([string]::IsNullOrWhiteSpace([string]$Process.ExecutablePath)) { Fail "runner executable path is empty: $Name" }
      $Resolved = (Resolve-Path -LiteralPath ([string]$Process.ExecutablePath) -ErrorAction Stop).Path
      $Item = Get-Item -LiteralPath $Resolved -Force
      if (-not $Item.PSIsContainer -and (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0)) {
        $Found[$Name] = $Resolved
      } else {
        Fail "runner executable path is not a regular file: $Name"
      }
    }
    [uint32]$ParentProcessId = $Process.ParentProcessId
    if ($ParentProcessId -eq $CurrentProcessId) { break }
    $CurrentProcessId = $ParentProcessId
  }
  foreach ($Name in $RequiredNames) {
    if (-not $Found.ContainsKey($Name)) { Fail "runner control-plane ancestor not found: $Name" }
  }
  $Directories = @($RequiredNames | ForEach-Object { Split-Path -Parent $Found[$_] } | Select-Object -Unique)
  if ($Directories.Count -ne 1) { Fail 'runner control-plane executables do not share one trusted directory' }
  return [string[]]@($RequiredNames | ForEach-Object { $Found[$_] })
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
  $RunnerPrograms = @(Get-RunnerControlPlanePrograms)
  $RunnerProgramHashes = @{}
  foreach ($Program in $RunnerPrograms) {
    $RunnerProgramHashes[$Program] = (Get-FileHash -Algorithm SHA256 -LiteralPath $Program).Hash
  }
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
  try {
    $RuleIndex = 0
    foreach ($Program in $RunnerPrograms) {
      $RuleIndex += 1
      $RuleName = "$FirewallPrefix-Runner-$RuleIndex"
      $RunnerRuleNames.Add($RuleName)
      New-NetFirewallRule -Name $RuleName -DisplayName $RuleName -Direction Outbound -Program $Program -RemoteAddress Any -RemotePort 443 -Protocol TCP -Action Allow -Profile Any -ErrorAction Stop | Out-Null
      $Rule = Get-NetFirewallRule -Name $RuleName -PolicyStore ActiveStore -ErrorAction Stop
      $Application = $Rule | Get-NetFirewallApplicationFilter
      $AddressFilter = $Rule | Get-NetFirewallAddressFilter
      $Port = $Rule | Get-NetFirewallPortFilter
      if ($Rule.Enabled -ne 'True' -or
          $Rule.Direction -ne 'Outbound' -or
          $Rule.Action -ne 'Allow' -or
          [IO.Path]::GetFullPath($Application.Program) -ne [IO.Path]::GetFullPath($Program) -or
          [string]$AddressFilter.RemoteAddress -cne 'Any' -or
          [string]$Port.RemotePort -cne '443' -or
          @('TCP', '6') -notcontains [string]$Port.Protocol) {
        Fail 'runner control-plane firewall allow rule is not exact and active'
      }
    }
  
    $DnsProgram = [IO.Path]::GetFullPath((Join-Path ([Environment]::SystemDirectory) 'svchost.exe'))
    foreach ($Protocol in @('UDP', 'TCP')) {
      $RuleName = "$FirewallPrefix-Dns-$Protocol"
      $DnsRuleNames.Add($RuleName)
      New-NetFirewallRule -Name $RuleName -DisplayName $RuleName -Direction Outbound -Program $DnsProgram -Service Dnscache -RemoteAddress $ResolverAddresses -RemotePort 53 -Protocol $Protocol -Action Allow -Profile Any -ErrorAction Stop | Out-Null
    }
  
    $ExistingOutboundAllows = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Action Allow -Enabled True |
      Where-Object { $RunnerRuleNames -notcontains $_.Name -and $DnsRuleNames -notcontains $_.Name })
    foreach ($ExistingRule in $ExistingOutboundAllows) {
      if ([string]$ExistingRule.PolicyStoreSourceType -ne 'Local' -or [string]::IsNullOrWhiteSpace($ExistingRule.Name)) {
        Fail "non-local outbound allow rule prevents fail-closed isolation: $($ExistingRule.DisplayName)"
      }
      $DisabledOutboundRuleNames.Add($ExistingRule.Name)
      Disable-NetFirewallRule -Name $ExistingRule.Name -ErrorAction Stop | Out-Null
    }
    $RemainingBroadAllows = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Action Allow -Enabled True |
      Where-Object { $RunnerRuleNames -notcontains $_.Name -and $DnsRuleNames -notcontains $_.Name })
    if ($RemainingBroadAllows.Count -ne 0) { Fail 'outbound allow rules remain outside the runner control-plane carveout' }
  
    foreach ($ProfileSnapshot in $ProfileSnapshots) {
      Set-NetFirewallProfile -Profile $ProfileSnapshot.Name -DefaultOutboundAction Block -ErrorAction Stop
    }
    foreach ($ProfileSnapshot in $ProfileSnapshots) {
      $Effective = Get-NetFirewallProfile -Profile $ProfileSnapshot.Name -ErrorAction Stop
      if ([string]$Effective.DefaultOutboundAction -ne 'Block') { Fail "offline default outbound policy is not active: $($ProfileSnapshot.Name)" }
    }
    if (Test-OutboundTcp $ProbeAddress) { Fail 'hostile outbound TCP probe bypassed the offline firewall policy' }
    . $Action
    foreach ($Program in $RunnerPrograms) {
      if ((Get-FileHash -Algorithm SHA256 -LiteralPath $Program).Hash -ne $RunnerProgramHashes[$Program]) {
        Fail "runner control-plane executable changed during the isolated action: $Program"
      }
    }
    foreach ($ProfileSnapshot in $ProfileSnapshots) {
      $Effective = Get-NetFirewallProfile -Profile $ProfileSnapshot.Name -ErrorAction Stop
      if ([string]$Effective.DefaultOutboundAction -ne 'Block') { Fail "offline firewall policy changed during the isolated action: $($ProfileSnapshot.Name)" }
    }
    if (Test-OutboundTcp $ProbeAddress) { Fail 'offline firewall policy was removed during the isolated action' }
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
