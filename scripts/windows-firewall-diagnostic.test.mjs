import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

test('5157 diagnostics retain only bounded connection metadata', () => {
  const script = fileURLToPath(new URL('../third_party/sidecars/semgrep/diagnose-windows-firewall.ps1', import.meta.url));
  const output = execFileSync('pwsh', ['-NoProfile', '-Command', `
    $ErrorActionPreference = 'Stop'
    $ast = [Management.Automation.Language.Parser]::ParseFile($env:FIREWALL_DIAGNOSTIC_TEST_SCRIPT, [ref]$null, [ref]$null)
    $fn = $ast.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Convert-WfpBlockedEvent' }, $false)
    if ($null -eq $fn) { throw 'missing metadata projection' }
    Invoke-Expression $fn.Extent.Text
    $xml = [xml]'<Event><System><TimeCreated SystemTime="2026-09-12T00:00:00Z"/></System><EventData><Data Name="Application">app.exe</Data><Data Name="ProcessID">123</Data><Data Name="DestAddress">1.2.3.4</Data><Data Name="DestPort">443</Data><Data Name="Protocol">6</Data><Data Name="FilterRTID">42</Data><Data Name="Secret">DO-NOT-EXPORT</Data></EventData></Event>'
    $first = Convert-WfpBlockedEvent $xml
    $xml.Event.EventData.Data[0].InnerText = 'a' * 5000
    $second = Convert-WfpBlockedEvent $xml
    @($first, $second) | ConvertTo-Json -Compress
  `], { encoding: 'utf8', env: { ...process.env, FIREWALL_DIAGNOSTIC_TEST_SCRIPT: script } });
  const [event, oversized] = JSON.parse(output);
  assert.deepEqual(event, { timestamp: '2026-09-12T00:00:00Z', applicationPath: 'app.exe', pid: '123', destinationIp: '1.2.3.4', destinationPort: '443', protocol: '6', filterId: '42' });
  assert.equal(oversized.applicationPath.length, 1024);
  assert.ok(!output.includes('DO-NOT-EXPORT'));
});


test('audit restoration compares every CSV field, rejecting malformed and duplicate rows', () => {
  const script = fileURLToPath(new URL('../third_party/sidecars/semgrep/diagnose-windows-firewall.ps1', import.meta.url));
  const output = execFileSync('pwsh', ['-NoProfile', '-Command', `
    $ErrorActionPreference = 'Stop'
    $ast = [Management.Automation.Language.Parser]::ParseFile($env:FIREWALL_DIAGNOSTIC_TEST_SCRIPT, [ref]$null, [ref]$null)
    $functions = @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in @('Read-AuditPolicyCsv', 'Compare-AuditPolicyCsv', 'Get-ConnectionAuditFlags') }, $false))
    if ($functions.Count -ne 3) { throw 'missing audit policy comparison or target flags' }
    foreach ($fn in $functions) { Invoke-Expression $fn.Extent.Text }
    $header = 'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value'
    $system = 'PRIVATE-HOST,System,Filtering Platform Connection,{0CCE9226-69AE-11D9-BED3-505054503030},Failure,,2'
    $option = 'PRIVATE-HOST,,Option:CrashOnAuditFail,,Disabled,,0'
    $userRow = 'PRIVATE-HOST,S-1-5-21-PRIVATE,File System,{0CCE921D-69AE-11D9-BED3-505054503030},Success,Failure,9'
    $before = ($header, $system, $option, $userRow) -join [char]10
    $after = [char]0xFEFF + (($header, $userRow, $option, $system) -join ([string][char]13 + [char]10)) + [char]13 + [char]10
    $results = @{}
    $results.reordered = Compare-AuditPolicyCsv $before $after
    $results.setting = Compare-AuditPolicyCsv $before ($before.Replace('Failure,,2', 'Failure,,3'))
    $results.option = Compare-AuditPolicyCsv $before ($before.Replace('Disabled,,0', 'Disabled,,1'))
    $results.target = Compare-AuditPolicyCsv $before ($before.Replace('S-1-5-21-PRIVATE', 'S-1-5-21-OTHER'))
    $results.text = Compare-AuditPolicyCsv $before ($before.Replace('Success,Failure,9', 'success,Failure,9'))
    $results.softHyphen = Compare-AuditPolicyCsv $before ($before.Replace('Disabled', ('Dis' + [char]0x00AD + 'abled')))
    $results.flags = @(foreach ($state in @(@('No Auditing', '0'), @('Success', '1'), @('Failure', '2'), @('Success and Failure', '3'))) {
      Get-ConnectionAuditFlags ($before.Replace('Failure,,2', ($state[0] + ',,' + $state[1])))
    })
    $results.ambiguous = @(foreach ($invalid in @('Not Specified,,2', 'Success,,2', 'Failure,,4', 'Failure,Failure,2')) {
      try { $null = Get-ConnectionAuditFlags ($before.Replace('Failure,,2', $invalid)); 'accepted' } catch { 'rejected' }
    })
    foreach ($case in @{
      header = $before.Replace('Setting Value', 'Setting Value,Unknown')
      softHyphenHeader = $before.Replace('Setting Value', ('Setting Val' + [char]0x00AD + 'ue'))
      duplicate = $before + [char]10 + $system
      conflict = $before + [char]10 + $system.Replace('Failure,,2', 'Failure,,3')
      extra = $before + ',EXTRA'
      quote = $header + [char]10 + '"unclosed'
      oversized = 'x' * 1048577
    }.GetEnumerator()) {
      try { $null = Compare-AuditPolicyCsv $before $case.Value; $results[$case.Key] = 'accepted' }
      catch { $results[$case.Key] = 'rejected' }
    }
    $results | ConvertTo-Json -Depth 5 -Compress
  `], { encoding: 'utf8', env: { ...process.env, FIREWALL_DIAGNOSTIC_TEST_SCRIPT: script } });
  const results = JSON.parse(output);
  assert.equal(results.reordered.equal, true);
  assert.equal(results.reordered.beforeRows, 3);
  assert.equal(results.reordered.afterRows, 3);
  assert.deepEqual(results.flags, [
    { success: 'disable', failure: 'disable' }, { success: 'enable', failure: 'disable' },
    { success: 'disable', failure: 'enable' }, { success: 'enable', failure: 'enable' },
  ]);
  assert.deepEqual(results.ambiguous, ['rejected', 'rejected', 'rejected', 'rejected']);
  for (const name of ['setting', 'option', 'target', 'text', 'softHyphen']) assert.equal(results[name].equal, false, name);
  for (const name of ['header', 'softHyphenHeader', 'duplicate', 'conflict', 'extra', 'quote', 'oversized']) assert.equal(results[name], 'rejected', name);
  assert.ok(!output.includes('PRIVATE'));
});

test('candidate snapshots filter names, bound metadata, and reject inaccessible or linked files', () => {
  const script = fileURLToPath(new URL('../third_party/sidecars/semgrep/diagnose-windows-firewall.ps1', import.meta.url));
  const output = execFileSync('pwsh', ['-NoProfile', '-Command', `
    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest
    $ast = [Management.Automation.Language.Parser]::ParseFile($env:FIREWALL_DIAGNOSTIC_TEST_SCRIPT, [ref]$null, [ref]$null)
    $fn = $ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-CandidateProcessSnapshot'}, $false)
    if ($null -eq $fn) { throw 'missing candidate snapshot' }
    Invoke-Expression $fn.Extent.Text
    $script:Processes = @(
      [pscustomobject]@{Name='not-a-candidate.exe'; ProcessId=1; ParentProcessId=0; CreationDate=[datetime]'2026-09-12T00:00:00Z'; ExecutablePath='C:\\hidden.exe'; CommandLine='PRIVATE'},
      [pscustomobject]@{Name='WaAppAgent.exe'; ProcessId=2; ParentProcessId=1; CreationDate=[datetime]'2026-09-12T00:00:00Z'; ExecutablePath='C:\\agents\\WaAppAgent.exe'; CommandLine='PRIVATE'},
      [pscustomobject]@{Name='WindowsAzureGuestAgent.exe'; ProcessId=3; ParentProcessId=1; CreationDate=[datetime]'2026-09-12T00:00:00Z'; ExecutablePath='C:\\denied\\WindowsAzureGuestAgent.exe'; CommandLine='PRIVATE'},
      [pscustomobject]@{Name='provjobd.exe123'; ProcessId=4; ParentProcessId=1; CreationDate=[datetime]'2026-09-12T00:00:00Z'; ExecutablePath='C:\\linked\\provjobd.exe123'; CommandLine='PRIVATE'},
      [pscustomobject]@{Name='hosted-compute-agent.exe'; ProcessId=5; ParentProcessId=1; CreationDate=[datetime]'2026-09-12T00:00:00Z'; ExecutablePath=('C:\\' + ('x' * 1100) + '\\hosted-compute-agent.exe'); CommandLine='PRIVATE'},
      [pscustomobject]@{Name='provjobd.exe-attacker'; ProcessId=6; ParentProcessId=1; CreationDate=[datetime]'2026-09-12T00:00:00Z'; ExecutablePath='C:\\hidden.exe'; CommandLine='PRIVATE'}
    )
    function Get-CimInstance { param($ClassName,$Filter,$Property)
      if (($Property -join ',') -ne 'Name,ProcessId,ParentProcessId,CreationDate,ExecutablePath') { throw 'unexpected CIM fields' }
      $script:Processes
    }
    function Get-Item { param($LiteralPath)
      if ($LiteralPath -like '*denied*') { throw 'PRIVATE ACCESS ERROR' }
      [pscustomobject]@{PSIsContainer=($LiteralPath -notmatch '\\.exe[0-9]*$'); Attributes=$(if ($LiteralPath -eq 'C:\\linked') { [IO.FileAttributes]::ReparsePoint } else { [IO.FileAttributes]::Normal }); Length=32}
    }
    function Get-FileHash { param($LiteralPath,$Algorithm)
      if ($LiteralPath -ne 'C:\\agents\\WaAppAgent.exe' -or $Algorithm -ne 'SHA256') { throw 'unexpected file hashed' }
      [pscustomobject]@{Hash=('A' * 64)}
    }
    function Get-AuthenticodeSignature { param($LiteralPath)
      if ($LiteralPath -ne 'C:\\agents\\WaAppAgent.exe') { throw 'unexpected file signed' }
      [pscustomobject]@{Status='Valid'; SignerCertificate=[pscustomobject]@{Thumbprint=('B' * 40); Subject='PRIVATE'}}
    }
    $first = Get-CandidateProcessSnapshot
    $script:Processes = @()
    $empty = Get-CandidateProcessSnapshot
    $script:Processes = @(1..20 | ForEach-Object { [pscustomobject]@{Name='WaAppAgent.exe'; ProcessId=$_; ParentProcessId=0; CreationDate=$null; ExecutablePath=$null} })
    $many = Get-CandidateProcessSnapshot
    @{first=$first; empty=$empty; many=$many} | ConvertTo-Json -Depth 8 -Compress
  `], { encoding: 'utf8', env: { ...process.env, FIREWALL_DIAGNOSTIC_TEST_SCRIPT: script } });
  const { first, empty, many } = JSON.parse(output);
  assert.equal(first.candidates.length, 4);
  const good = first.candidates[0];
  assert.deepEqual(Object.keys(good).sort(), ['candidateName','pid','parentPid','createdAt','executablePath','sha256','authenticodeStatus','signerThumbprint','error'].sort());
  assert.equal(good.pid, 2);
  assert.equal(good.parentPid, 1);
  assert.match(good.createdAt, /^2026-09-12T/);
  assert.equal(good.sha256, 'A'.repeat(64));
  assert.equal(good.authenticodeStatus, 'Valid');
  assert.equal(good.signerThumbprint, 'B'.repeat(40));
  assert.equal(good.error, null);
  assert.equal(first.candidates[1].error, 'file-unavailable');
  assert.equal(first.candidates[2].error, 'unsafe-file');
  assert.equal(first.candidates[2].sha256, null);
  assert.equal(first.candidates[3].error, 'unsupported-path');
  assert.equal(first.candidates[3].executablePath.length, 1024);
  assert.equal(empty.candidates.length, 0);
  assert.equal(many.candidates.length, 16);
  assert.equal(many.truncated, true);
  assert.ok(!output.includes('PRIVATE'));
});

test('job ancestry joins exact candidate identities and reports broken or reused chains', () => {
  const script = fileURLToPath(new URL('../third_party/sidecars/semgrep/diagnose-windows-firewall.ps1', import.meta.url));
  const output = execFileSync('pwsh', ['-NoProfile', '-Command', `
    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest
    $ast = [Management.Automation.Language.Parser]::ParseFile($env:FIREWALL_DIAGNOSTIC_TEST_SCRIPT, [ref]$null, [ref]$null)
    $fn = $ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-JobAncestrySnapshot'}, $false)
    if ($null -eq $fn) { throw 'missing ancestry snapshot' }
    Invoke-Expression $fn.Extent.Text
    function Get-CimInstance { param($ClassName,$Filter,$Property)
      if (($Property -join ',') -ne 'ProcessId,ParentProcessId,CreationDate,ExecutablePath' -or $Filter -notmatch '^ProcessId = ([0-9]+)$') { throw 'unexpected CIM query' }
      $script:Queries++
      $script:Rows[[uint32]$Matches[1]]
    }
    $baseTime = [datetime]'2026-09-12T00:00:00Z'
    $script:Rows = @{}
    $paths = @('pwsh.exe', 'Runner.Worker.exe', 'Runner.Listener.exe', 'hosted-compute-agent.exe', 'provjobd.exe123')
    for ($i=0; $i -lt 5; $i++) {
      $script:Rows[[uint32]($PID+$i)] = [pscustomobject]@{ProcessId=($PID+$i); ParentProcessId=$(if($i -eq 4){0}else{$PID+$i+1}); CreationDate=$baseTime.AddSeconds(-$i); ExecutablePath=('C:\\agents\\'+$paths[$i]); CommandLine='PRIVATE'}
    }
    $candidates = [pscustomobject]@{ candidates = @(
      [pscustomobject]@{pid=($PID+3); createdAt=$baseTime.AddSeconds(-3).ToUniversalTime().ToString('o')},
      [pscustomobject]@{pid=($PID+4); createdAt=$baseTime.AddSeconds(-4).ToUniversalTime().ToString('o')},
      [pscustomobject]@{pid=999999; createdAt=$baseTime.ToUniversalTime().ToString('o')}
    )}
    $script:Queries=0
    $good = Get-JobAncestrySnapshot $candidates
    $same = Get-JobAncestrySnapshot $candidates $good
    $script:Rows[[uint32]($PID+4)].CreationDate = $baseTime.AddSeconds(-3)
    $reuse = Get-JobAncestrySnapshot $candidates $good
    $script:Rows[[uint32]($PID+4)].CreationDate = $baseTime.AddSeconds(1)
    $newParent = Get-JobAncestrySnapshot $candidates
    $script:Rows[[uint32]($PID+4)].CreationDate = $baseTime.AddSeconds(-4)
    $duplicateCandidates = [pscustomobject]@{candidates=@($candidates.candidates[0],$candidates.candidates[0])}
    $duplicate = Get-JobAncestrySnapshot $duplicateCandidates
    $script:Rows[[uint32]($PID+4)].ParentProcessId = $PID
    $cycle = Get-JobAncestrySnapshot $candidates
    $script:Rows.Remove([uint32]($PID+4))
    $missing = Get-JobAncestrySnapshot $candidates
    $script:Rows = @{}
    for ($i=0; $i -lt 40; $i++) {
      $script:Rows[[uint32]($PID+$i)] = [pscustomobject]@{ProcessId=($PID+$i); ParentProcessId=($PID+$i+1); CreationDate=$baseTime; ExecutablePath=('C:\\'+('x'*1100)); CommandLine='PRIVATE'}
    }
    $script:Queries=0
    $long = Get-JobAncestrySnapshot $candidates
    @{good=$good;same=$same;reuse=$reuse;newParent=$newParent;duplicate=$duplicate;cycle=$cycle;missing=$missing;long=$long;longQueries=$script:Queries} | ConvertTo-Json -Depth 8 -Compress
  `], { encoding: 'utf8', env: { ...process.env, FIREWALL_DIAGNOSTIC_TEST_SCRIPT: script } });
  const result = JSON.parse(output);
  assert.equal(result.good.termination, 'root');
  assert.equal(result.good.nodes.length, 5);
  assert.deepEqual(result.good.nodes.map(x => x.candidateIndex), [null, null, null, 0, 1]);
  assert.ok(result.same.nodes.every(x => x.previousIdentity === 'same-pid-and-creation'));
  assert.equal(result.reuse.nodes.at(-1).previousIdentity, 'pid-reused');
  assert.equal(result.reuse.nodes.at(-1).candidateIndex, null);
  assert.equal(result.newParent.termination, 'parent-created-after-child');
  assert.equal(result.duplicate.nodes[3].candidateMatch, 'duplicate-identity');
  assert.equal(result.duplicate.nodes[3].candidateIndex, null);
  assert.equal(result.cycle.termination, 'cycle');
  assert.equal(result.missing.termination, 'missing-process');
  assert.equal(result.long.termination, 'limit');
  assert.equal(result.long.nodes.length, 32);
  assert.equal(result.longQueries, 32);
  assert.equal(result.long.nodes[0].executablePath.length, 1024);
  assert.deepEqual(Object.keys(result.good.nodes[0]).sort(), ['pid','parentPid','createdAt','executablePath','candidateIndex','candidateMatch','previousIdentity'].sort());
  assert.ok(!output.includes('PRIVATE'));
});

test('firewall control-plane discovery requires bounded ordered live Worker Listener HCA identities', () => {
  const script = fileURLToPath(new URL('../third_party/sidecars/semgrep/windows-offline-firewall.ps1', import.meta.url));
  const output = execFileSync('pwsh', ['-NoProfile','-Command', `
    $ErrorActionPreference='Stop'; Set-StrictMode -Version Latest
    . $env:FIREWALL_DIAGNOSTIC_TEST_SCRIPT
    function Fail($Message) { throw $Message }
    function Get-CimInstance { param($ClassName,$Filter,$Property)
      if($Filter -notmatch '^ProcessId = ([0-9]+)$'){throw 'bad query'}
      $script:Queries++
      $script:Rows[[uint32]$Matches[1]]
    }
    function Resolve-Path { param($LiteralPath) [pscustomobject]@{Path=$LiteralPath} }
    function Get-Item {param($LiteralPath)
      [pscustomobject]@{PSIsContainer=($LiteralPath -notmatch 'exe$|hosted-compute-agent$'); Attributes=$(if($script:Unsafe){[IO.FileAttributes]::ReparsePoint}else{[IO.FileAttributes]::Normal}); Length=32}
    }
    function Get-FileHash {param($LiteralPath,$Algorithm) [pscustomobject]@{Hash=$script:Hash} }
    function Reset-Rows {
      $script:Queries=0; $script:Unsafe=$false; $script:Hash='A'*64; $script:Rows=@{}
      $paths=@('C:\\pwsh.exe','C:\\runner\\Runner.Worker.exe','C:\\runner\\Runner.Listener.exe','C:\\hca\\hosted-compute-agent')
      for($i=0;$i -lt 4;$i++) { $script:Rows[[uint32]($PID+$i)]=[pscustomobject]@{ProcessId=($PID+$i);ParentProcessId=($PID+$i+1);CreationDate=([datetime]'2026-09-12T00:00:00Z').AddSeconds(-$i);ExecutablePath=$paths[$i]} }
    }
    Reset-Rows
    $first=@(Get-RunnerControlPlanePrograms)
    if($first.Count -ne 3){throw 'HCA identity absent'}
    Assert-RunnerControlPlaneIdentity $first
    $result=@{names=@($first | ForEach-Object Name)}
    foreach($case in @('ambiguous','missing','cycle','duplicate','newer','unsafe','different-directory','pid-reused','hash-changed','limit')) {
      Reset-Rows
      switch($case){
        ambiguous { $script:Rows[[uint32]$PID]=@($script:Rows[[uint32]$PID],$script:Rows[[uint32]$PID]) }
        missing { $script:Rows.Remove([uint32]($PID+3)) }
        cycle { $script:Rows[[uint32]($PID+2)].ParentProcessId=$PID }
        duplicate { $script:Rows[[uint32]($PID+2)].ExecutablePath='C:\\runner\\Runner.Worker.exe' }
        newer { $script:Rows[[uint32]($PID+2)].CreationDate=[datetime]'2026-09-12T01:00:00Z' }
        unsafe { $script:Unsafe=$true }
        different-directory { $script:Rows[[uint32]($PID+2)].ExecutablePath='C:\\other\\Runner.Listener.exe' }
        pid-reused { $script:Rows[[uint32]($PID+3)].CreationDate=([datetime]'2026-09-12T00:00:00Z').AddSeconds(-2) }
        hash-changed { $script:Hash='B'*64 }
        limit { for($i=0;$i -lt 40;$i++) { $script:Rows[[uint32]($PID+$i)]=[pscustomobject]@{ProcessId=($PID+$i);ParentProcessId=($PID+$i+1);CreationDate=[datetime]'2026-09-12T00:00:00Z';ExecutablePath='C:\\pwsh.exe'} } }
      }
      try { Assert-RunnerControlPlaneIdentity $first; $result[$case]='accepted' }catch{ $result[$case]='rejected' }
      if($case -eq 'limit'){$result.limitQueries=$script:Queries}
    }
    $result|ConvertTo-Json -Compress
  `], {encoding:'utf8', env:{...process.env,FIREWALL_DIAGNOSTIC_TEST_SCRIPT:script}});
  const result=JSON.parse(output);
  assert.equal(result.limitQueries,32);
  assert.deepEqual(result.names,['Runner.Worker.exe','Runner.Listener.exe','hosted-compute-agent']);
  for(const name of ['ambiguous','missing','cycle','duplicate','newer','unsafe','different-directory','pid-reused','hash-changed','limit']) assert.equal(result[name],'rejected',name);
});

test('effective offline rules reject broader IMDS address, program, port, DNS service, and added allows', () => {
  const script=fileURLToPath(new URL('../third_party/sidecars/semgrep/windows-offline-firewall.ps1',import.meta.url));
  const output=execFileSync('pwsh',['-NoProfile','-Command',`
    $ErrorActionPreference='Stop'; Set-StrictMode -Version Latest
    . $env:FIREWALL_DIAGNOSTIC_TEST_SCRIPT
    function Fail($Message){throw $Message}
    if(-not(Get-Command Assert-OfflineFirewallRules -ErrorAction SilentlyContinue)){throw 'missing rule verification'}
    $expected=@(
      [pscustomobject]@{Name='https';Program='C:\\runner\\Runner.Worker.exe';RemoteAddress=@('Any');RemotePort='443';Protocol='TCP';Service='Any'},
      [pscustomobject]@{Name='imds';Program='C:\\hca\\hosted-compute-agent';RemoteAddress=@('169.254.169.254');RemotePort='80';Protocol='TCP';Service='Any'},
      [pscustomobject]@{Name='dns';Program='C:\\Windows\\System32\\svchost.exe';RemoteAddress=@('1.2.3.4');RemotePort='53';Protocol='UDP';Service='Dnscache'}
    )
    function Reset-Rules {
      $script:Rules=@{}
      foreach($entry in $expected){$script:Rules[$entry.Name]=[pscustomobject]@{Name=$entry.Name;Enabled='True';Direction='Outbound';Action='Allow';Profile='Any';Program=$entry.Program;RemoteAddress=$entry.RemoteAddress;RemotePort=$entry.RemotePort;Protocol=$entry.Protocol;Service=$entry.Service}}
    }
    function Get-NetFirewallRule {param($Name,$PolicyStore,$Direction,$Action,$Enabled) if($Name){$script:Rules[$Name]}else{$script:Rules.Values}}
    function Get-NetFirewallApplicationFilter {param([Parameter(ValueFromPipeline=$true)]$Rule) process{[pscustomobject]@{Program=$Rule.Program}}}
    function Get-NetFirewallAddressFilter {param([Parameter(ValueFromPipeline=$true)]$Rule) process{[pscustomobject]@{RemoteAddress=$Rule.RemoteAddress}}}
    function Get-NetFirewallPortFilter {param([Parameter(ValueFromPipeline=$true)]$Rule) process{[pscustomobject]@{RemotePort=$Rule.RemotePort;Protocol=$Rule.Protocol}}}
    function Get-NetFirewallServiceFilter {param([Parameter(ValueFromPipeline=$true)]$Rule) process{[pscustomobject]@{Service=$Rule.Service}}}
    Reset-Rules; Assert-OfflineFirewallRules $expected
    $result=@{}
    foreach($case in @('address','program','port','protocol','service','extra','softHyphen')){
      Reset-Rules
      switch($case){
        address{$script:Rules.imds.RemoteAddress=@('Any')}
        program{$script:Rules.imds.Program='Any'}
        port{$script:Rules.imds.RemotePort='Any'}
        protocol{$script:Rules.imds.Protocol='UDP'}
        service{$script:Rules.dns.Service='Any'}
        extra{$script:Rules.extra=[pscustomobject]@{Name='extra'}}
        softHyphen{$script:Rules.extra=[pscustomobject]@{Name=('im'+[char]0x00ad+'ds')}}
      }
      try{Assert-OfflineFirewallRules $expected;$result[$case]='accepted'}catch{$result[$case]='rejected'}
    }
    $result|ConvertTo-Json -Compress
  `],{encoding:'utf8',env:{...process.env,FIREWALL_DIAGNOSTIC_TEST_SCRIPT:script}});
  assert.deepEqual(JSON.parse(output),{address:'rejected',program:'rejected',port:'rejected',protocol:'rejected',service:'rejected',extra:'rejected',softHyphen:'rejected'});
});
