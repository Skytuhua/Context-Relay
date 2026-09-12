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

