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
