import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

test('installed smoke consumes this build artifact and retains only bounded evidence', async () => {
  const workflow = await readFile(new URL('../.github/workflows/windows-package.yml', import.meta.url), 'utf8');
  const installed = workflow.match(/^  installed-smoke:\n([\s\S]+)$/m)?.[1];
  assert.ok(installed, 'a separate installed-smoke job is required');
  assert.match(installed, /needs: package\n/);
  assert.match(installed, /runs-on: windows-2025\n/);
  assert.match(installed, /timeout-minutes: 40\n/);
  assert.match(installed, /actions\/download-artifact@[a-f0-9]{40}/);
  assert.match(installed, /name: context-relay-windows-x64-\$\{\{ github\.sha \}\}/);
  assert.match(installed, /shell: powershell\n/);
  assert.match(installed, /EXPECTED_SOURCE_COMMIT: \$\{\{ github\.sha \}\}/);
  assert.match(installed, /if: always\(\)/);
  assert.match(installed, /path: \$\{\{ runner\.temp \}\}\/context-relay-installed-evidence\/installed-smoke\.json\n/);
  assert.doesNotMatch(installed, /continue-on-error|pull_request_target|actions\/setup-|\b(?:pnpm|npm|cargo|rustup)\b|secrets\./);
  assert.doesNotMatch(installed, /\b(?:run-id|repository|github-token):/);
});

// Parse the whole driver, but evaluate ONLY these named helper definitions.
// Add-Type compiles the C# types; no job is constructed, native entry point is
// called, installer is executed, or application/profile is touched by this test.
test('Windows driver parses, its helper types compile, and artifact paths fail closed', {
  skip: process.platform !== 'win32' ? 'requires Windows PowerShell 5.1 and UI Automation reference assemblies' : false,
  timeout: 180_000,
}, () => {
  const command = String.raw`
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$tokens = $null; $parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($env:CONTEXT_RELAY_SMOKE_DRIVER, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw (($parseErrors | ForEach-Object { $_.Message }) -join '; ') }
foreach ($name in @('Assert-RegularPath', 'Get-ContainedPath', 'Assert-FileRecord', 'Initialize-SmokeHelpers')) {
    $definitions = @($ast.FindAll({ param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
    }, $false))
    if ($definitions.Count -ne 1) { throw ('Expected one safe helper definition: ' + $name) }
    . ([scriptblock]::Create($definitions[0].Extent.Text))
}
Initialize-SmokeHelpers
function Assert-Rejected([scriptblock]$Action) {
    $rejected = $false
    try { & $Action | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Expected the invalid fixture to be refused.' }
}
$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('context-relay-smoke-validation-' + [Guid]::NewGuid().ToString('N'))
$junction = Join-Path $fixtureRoot 'link'
try {
    $null = [IO.Directory]::CreateDirectory($fixtureRoot)
    Assert-RegularPath $fixtureRoot
    $actual = Get-ContainedPath $fixtureRoot 'search/runtime/onnxruntime.dll'
    if ($actual -cne [IO.Path]::GetFullPath((Join-Path $fixtureRoot 'search\runtime\onnxruntime.dll'))) { throw 'Valid payload path changed.' }
    foreach ($invalid in @('..\escape', '/outside', 'C:\outside', '\\host\share\file',
        'file:stream', 'search\..\escape', 'search//file', 'search.\file', 'search \file',
        'CON', 'con.txt', 'NUL.json', 'COM1.exe', 'LPT9.txt', '.', '')) {
        Assert-Rejected { Get-ContainedPath $fixtureRoot $invalid }
    }
    $file = Join-Path $fixtureRoot 'payload.exe'
    [IO.File]::WriteAllText($file, 'non-executable fixture', [Text.UTF8Encoding]::new($false))
    $record = [pscustomobject]@{ name = 'payload.exe'; bytes = (Get-Item -LiteralPath $file).Length
        sha256 = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() }
    if ((Assert-FileRecord $fixtureRoot $record) -cne $file) { throw 'Valid payload bytes were refused.' }
    $record.sha256 = '0' * 64
    Assert-Rejected { Assert-FileRecord $fixtureRoot $record }
    $record.sha256 = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
    $record.bytes = '22'
    Assert-Rejected { Assert-FileRecord $fixtureRoot $record }
    $destination = Join-Path $fixtureRoot 'destination'
    $null = [IO.Directory]::CreateDirectory($destination)
    $null = New-Item -ItemType Junction -Path $junction -Target $destination
    Assert-Rejected { Assert-RegularPath $junction }
    [IO.File]::WriteAllText((Join-Path $destination 'nested.txt'), 'fixture')
    Assert-Rejected { Assert-RegularPath (Join-Path $junction 'nested.txt') }
} finally {
    if ([IO.Directory]::Exists($junction)) { [IO.Directory]::Delete($junction) }
    if ([IO.Directory]::Exists($fixtureRoot)) { [IO.Directory]::Delete($fixtureRoot, $true) }
}
Write-Output 'Driver AST, helper compilation, and path/hash refusal checks passed without product execution.'
`;
  const result = spawnSync(join(process.env.SystemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'),
    ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', command], {
      encoding: 'utf8', timeout: 150_000, maxBuffer: 1024 * 1024,
      env: { ...process.env, CONTEXT_RELAY_SMOKE_DRIVER: fileURLToPath(new URL('./windows-installed-smoke.ps1', import.meta.url)) },
    });
  assert.ifError(result.error);
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  assert.match(result.stdout, /without product execution/);
});
