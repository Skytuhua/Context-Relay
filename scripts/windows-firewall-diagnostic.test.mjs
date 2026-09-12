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
