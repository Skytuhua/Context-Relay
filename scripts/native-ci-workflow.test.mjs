import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { acceptsCygwinRelease } from './assert-cygwin-release.mjs';
import { validateIndependentBuilderIdentities } from './verify-native-builder-identities.mjs';

const workflowUrl = new URL('../.github/workflows/ci.yml', import.meta.url);
const publicationWorkflowUrl = new URL('../.github/workflows/publish-semgrep-native.yml', import.meta.url);
const sourceLockUrl = new URL('../third_party/sidecars/semgrep/source-lock.v1.json', import.meta.url);
const provenanceUrl = new URL('../third_party/sidecars/semgrep/native-ci-provenance.v1.json', import.meta.url);

function job(source, name, next) {
  const start = source.indexOf(`  ${name}:`);
  const end = next ? source.indexOf(`  ${next}:`, start + 1) : source.length;
  assert.notEqual(start, -1, `missing ${name}`);
  assert.notEqual(end, -1, `missing boundary after ${name}`);
  return source.slice(start, end);
}

test('native CI independently builds, compares, candidate-smokes, then uploads exact target artifacts', async () => {
  const source = await readFile(workflowUrl, 'utf8');
  const windowsBuilder = job(source, 'native-semgrep-windows-x64-builders', 'native-isolation-windows-x64');
  const windows = job(source, 'native-isolation-windows-x64', 'native-semgrep-macos-arm64-builders');
  const macosBuilder = job(source, 'native-semgrep-macos-arm64-builders', 'native-isolation-macos-arm64');
  const macos = job(source, 'native-isolation-macos-arm64', 'request-native-sidecar-publication');

  for (const builder of [windowsBuilder, macosBuilder]) {
    assert.equal((builder.match(/semgrep-source-bundle\.mjs --build/g) ?? []).length, 1);
    assert.equal((builder.match(/semgrep-source-bundle\.mjs --verify-evidence/g) ?? []).length, 1);
    assert.match(builder, /build-public-source-(?:windows\.ps1|macos\.sh)/);
  }

  for (const [target, body] of [['windows', windows], ['macos', macos]]) {
    assert.match(body, /prepare-semgrep-runtime\.mjs --prepare[^\n]+--source-bundle[^\n]+--bundle-evidence/);
    assert.match(body, /-- --list/);
    assert.match(body, /CONTEXT_RELAY_REAL_SIDECAR_MANIFEST_ROOT/);
    assert.match(body, /CONTEXT_RELAY_CI_CANDIDATE_DOCUMENT/);
    assert.doesNotMatch(body, /Require enabled .*Semgrep/);
    const prepared = body.indexOf('prepare-semgrep-runtime.mjs --prepare');
    const nativeSmoke = body.indexOf('real_semgrep', prepared) >= 0
      ? body.indexOf('real_semgrep', prepared)
      : body.indexOf('real_sidecar_semgrep', prepared);
    const upload = body.indexOf('actions/upload-artifact@');
    const smokeEvidence = body.indexOf('native-smoke-evidence.mjs --write', nativeSmoke);
    assert.ok(
      prepared >= 0 && nativeSmoke > prepared && smokeEvidence > nativeSmoke && upload > smokeEvidence,
      `${target} must smoke and attest before upload`,
    );
    const uploaded = body.slice(upload);
    assert.doesNotMatch(uploaded, /context-relay-semgrep-output/);
    assert.doesNotMatch(uploaded, /candidate-workspace/);
    assert.doesNotMatch(uploaded, /ci-candidate-closure|CONTEXT_RELAY_CI_CANDIDATE_DOCUMENT/);
    assert.match(body, /context-relay-semgrep-candidate-(?:windows|macos)\/artifact/);
    assert.match(body, /source-a\.tar/);
    assert.match(body, /source-b\.tar/);
    assert.match(body, /bundle-evidence\.v1\.json/);
    assert.match(body, /build-a\.identity\.v1\.json/);
    assert.match(body, /build-b\.identity\.v1\.json/);
    assert.match(body, new RegExp(`native-smoke\\.${target === 'windows' ? 'windows-x86_64' : 'macos-aarch64'}\\.v1\\.json`));
  }
  assert.match(
    macos,
    /cargo test -p context-relay-core --test native_filesystem_macos_v1 --test native_recovery_v1 --test native_recovery_crash_v1/,
  );

  assert.match(macosBuilder, /runs-on: macos-15\n/);
  assert.match(macos, /runs-on: macos-15\n/);
  assert.match(macos, /test "\$\(uname -m\)" = arm64/);
  assert.doesNotMatch(`${macosBuilder}${macos}`, /macos-15-xlarge/);

  for (const name of [
    'real_rulesync_generates_only_the_validated_output_inside_appcontainer',
    'real_rulesync_rejects_malformed_frontmatter_and_cleans_up',
    'real_gitleaks_distinguishes_clean_and_findings_and_ignores_attacker_ignore_file',
    'real_semgrep_clean_and_finding_use_the_closed_policy',
    'real_sidecar_rulesync_generates_only_the_validated_output',
    'real_sidecar_rulesync_rejects_malformed_frontmatter_and_cleans_up',
    'real_sidecar_gitleaks_clean_and_finding_ignore_attacker_gitleaksignore',
    'real_sidecar_semgrep_clean_and_finding_use_the_closed_policy',
  ]) assert.match(source, new RegExp(name));
});

test('macOS native CI mounts a debuggable case-sensitive APFS image', async () => {
  const source = await readFile(workflowUrl, 'utf8');
  const macos = job(source, 'native-isolation-macos-arm64', 'request-native-sidecar-publication');
  const start = macos.indexOf('- name: Mount canonical case-sensitive APFS root');
  const end = macos.indexOf('- name: Run macOS native and exact registered real-sidecar gates', start);
  assert.ok(start >= 0 && end > start, 'missing case-sensitive APFS mount step');
  const mount = macos.slice(start, end);

  assert.match(mount, /hdiutil create[^\n]+-fs 'Case-sensitive APFS'/);
  assert.doesNotMatch(mount, /-fs APFSX|hdiutil (?:create|attach) -quiet/);
  assert.match(mount, /printf x > "\$mount\/CaseProbe"/);
  assert.match(mount, /printf y > "\$mount\/caseprobe"/);
  assert.match(mount, /find "\$mount"[^\n]+-iname caseprobe[^\n]+wc -l/);
});

test('the CI-only candidate verifier feature is scoped to the exact ignored Semgrep smokes', async () => {
  const source = await readFile(workflowUrl, 'utf8');
  const windows = job(source, 'native-isolation-windows-x64', 'native-semgrep-macos-arm64-builders');
  const macos = job(source, 'native-isolation-macos-arm64', 'request-native-sidecar-publication');
  const broadCandidateFeatures = source.split('\n').filter((line) =>
    line.includes('--all-features') && /--workspace|native-runner|launcher-harness/.test(line));
  assert.deepEqual(broadCandidateFeatures, []);
  assert.equal((source.match(/--features ci-candidate-sidecar-smoke/g) ?? []).length, 2);
  assert.match(windows, /if \(\$name -eq 'real_semgrep_clean_and_finding_use_the_closed_policy'\)[\s\S]+--features ci-candidate-sidecar-smoke/);
  assert.match(macos, /if test "\$name" = real_sidecar_semgrep_clean_and_finding_use_the_closed_policy[\s\S]+--features ci-candidate-sidecar-smoke/);
  const request = job(source, 'request-native-sidecar-publication');
  assert.doesNotMatch(request, /ci-candidate-closure|CONTEXT_RELAY_CI_CANDIDATE_DOCUMENT|candidate-workspace/);
});

test('independent builders use the same canonical smoke root and relative Semgrep inputs', async () => {
  const [source, macos, windows] = await Promise.all([
    readFile(workflowUrl, 'utf8'),
    readFile(new URL('../third_party/sidecars/semgrep/build-public-source-macos.sh', import.meta.url), 'utf8'),
    readFile(new URL('../third_party/sidecars/semgrep/build-public-source-windows.ps1', import.meta.url), 'utf8'),
  ]);
  const windowsBuilder = job(source, 'native-semgrep-windows-x64-builders', 'native-isolation-windows-x64');
  const macosBuilder = job(source, 'native-semgrep-macos-arm64-builders', 'native-isolation-macos-arm64');
  assert.match(windowsBuilder, /context-relay-semgrep-work-windows'/);
  assert.match(macosBuilder, /context-relay-semgrep-work-macos"/);
  assert.doesNotMatch(`${windowsBuilder}${macosBuilder}`, /semgrep-work-(?:windows|macos)-(?:\$slot|\$\{?CONTEXT_RELAY_BUILD_SLOT)/);
  assert.match(macos, /cd "\$SMOKE_FIXTURES"/);
  assert.match(macos, /run_closed_scan "\$DESTINATION\/osemgrep" rule\.yml clean\.txt/);
  assert.match(windows, /Push-Location -LiteralPath \$SmokeFixtures/);
  assert.match(windows, /Invoke-ClosedScan \$RuntimeExecutable 'rule\.yml' 'clean\.txt'/);
});

test('Windows native CI pins and records its exact AMD64 toolchain', async () => {
  const source = await readFile(workflowUrl, 'utf8');
  const windows = job(source, 'native-semgrep-windows-x64-builders', 'native-isolation-windows-x64');
  assert.match(windows, /PROCESSOR_ARCHITECTURE[^\n]+AMD64/);
  assert.match(windows, /x86_64-pc-windows-msvc/);
  assert.match(windows, /v24\.14\.0/);
  assert.match(windows, /cygcheck\.exe -cd/);
  assert.match(windows, /assert-cygwin-release\.mjs/);
  assert.match(windows, /--windows-evidence/);
  assert.match(windows, /--windows-stable-toolchain/);
  for (const block of windows.split(/(?=      - name:|      - uses:)/)) {
    if (block.includes('shell: pwsh')) assert.match(block, /\$PSNativeCommandUseErrorActionPreference = \$true/);
  }
});

test('native builders provision locked system dependencies before closed builds', async () => {
  const [source, lockText, macosScript] = await Promise.all([
    readFile(workflowUrl, 'utf8'),
    readFile(sourceLockUrl, 'utf8'),
    readFile(new URL('../third_party/sidecars/semgrep/build-public-source-macos.sh', import.meta.url), 'utf8'),
  ]);
  const lock = JSON.parse(lockText);
  const windows = job(source, 'native-semgrep-windows-x64-builders', 'native-isolation-windows-x64');
  const macos = job(source, 'native-semgrep-macos-arm64-builders', 'native-isolation-macos-arm64');
  const cygwinPackages = [
    'mingw64-i686-curl',
    'mingw64-i686-gmp',
    'mingw64-i686-pcre2',
    'mingw64-x86_64-curl',
    'mingw64-x86_64-gmp',
    'mingw64-x86_64-pcre2',
    'pkgconf',
  ];
  const homebrewFormulae = [
    'curl',
    'dwarfutils',
    'gmp',
    'libev',
    'libunwind-headers',
    'pcre2',
    'pkgconf',
    'zstd',
  ];

  const windowsProvision = windows.indexOf('$cygwinSetup');
  const windowsClosedBuild = windows.indexOf('build-public-source-windows.ps1');
  assert.ok(windowsProvision >= 0 && windowsClosedBuild > windowsProvision);
  assert.match(windows, /C:\\cygwin\\setup-x86_64\.exe/);
  for (const name of cygwinPackages) assert.match(windows, new RegExp(`['\"]${name}['\"]`));
  assert.match(
    windows,
    /Start-Process -FilePath \$cygwinSetup -ArgumentList \$arguments -Wait -PassThru -WindowStyle Hidden/,
  );
  assert.match(windows, /\$process\.ExitCode/);
  assert.doesNotMatch(windows, /& \$cygwinSetup @arguments/);
  const lockedWindows = lock.toolchains.find(({ distributionTarget }) => distributionTarget === 'windows-x86_64');
  for (const name of cygwinPackages) assert.ok(lockedWindows.cygwinPackages.includes(name), name);

  const macosProvision = macos.indexOf('brew install');
  const macosClosedBuild = macos.indexOf('build-public-source-macos.sh');
  assert.ok(macosProvision >= 0 && macosClosedBuild > macosProvision);
  assert.match(macos, /HOMEBREW_NO_AUTO_UPDATE=1/);
  for (const name of homebrewFormulae) {
    assert.match(macos, new RegExp(`brew install[^\\n]*\\b${name.replace('-', '\\-')}\\b`));
    assert.match(macosScript, new RegExp(`\\b${name.replace('-', '\\-')}\\b`));
  }
  const lockedMacos = lock.toolchains.find(({ distributionTarget }) => distributionTarget === 'aarch64-apple-darwin');
  const provenance = JSON.parse(await readFile(provenanceUrl, 'utf8'));
  const provenanceMacos = provenance.toolchains.find(({ distributionTarget }) => distributionTarget === 'aarch64-apple-darwin');
  assert.deepEqual(lockedMacos.homebrewPackages, homebrewFormulae);
  assert.deepEqual(provenanceMacos.homebrewPackages, homebrewFormulae);
  assert.match(macosScript, /brew list --versions/);
  assert.doesNotMatch(macosScript, /brew install/);
});

test('the shared Cygwin release policy accepts package-suffixed 3.6.10 builds', () => {
  for (const release of ['3.6.10', '3.6.10-1.x86_64', '3.6.10+patch', '3.6.10.1', '3.6.10(0.341/5/3)']) {
    assert.equal(acceptsCygwinRelease(release, '3.6.10'), true, release);
  }
  for (const release of ['3.6.1', '3.6.100', '3.6.10rc1', '3.7.0']) {
    assert.equal(acceptsCygwinRelease(release, '3.6.10'), false, release);
  }
});

test('macOS artifact transport restores only a proven executable mode', async () => {
  const source = await readFile(workflowUrl, 'utf8');
  const builder = job(source, 'native-semgrep-macos-arm64-builders', 'native-isolation-macos-arm64');
  const comparator = job(source, 'native-isolation-macos-arm64', 'request-native-sidecar-publication');
  const built = builder.indexOf('build-public-source-macos.sh');
  const producerProof = builder.indexOf('macOS producer executable mode mismatch');
  const uploaded = builder.indexOf('actions/upload-artifact@');
  assert.ok(built >= 0 && producerProof > built && uploaded > producerProof, 'producer mode proof must follow the build and precede upload');
  assert.match(builder, /O_NOFOLLOW/);
  assert.match(builder, /fstatSync\(fd\)/);
  assert.match(builder, /s\.nlink !== 1/);
  assert.match(builder, /\(s\.mode & 0o777\) !== 0o755/);

  const firstDownload = comparator.indexOf('actions/download-artifact@');
  const verified = comparator.indexOf('verify-native-builder-identities.mjs');
  const normalized = comparator.indexOf('macOS artifact transport mode mismatch');
  const prepared = comparator.indexOf('prepare-semgrep-runtime.mjs --prepare');
  assert.ok(firstDownload >= 0 && verified > firstDownload && normalized > verified && prepared > normalized);
  assert.match(comparator, /"\$root\/build-a\/osemgrep" "\$root\/build-b\/osemgrep"/);
  assert.match(comparator, /\(before\.mode & 0o777\) !== 0o644/);
  assert.match(comparator, /fchmodSync\(fd, 0o755\)/);
  assert.match(comparator, /\(after\.mode & 0o777\) !== 0o755/);
  assert.match(comparator, /before\.nlink !== 1/);
  assert.match(comparator, /after\.nlink !== 1/);
  assert.doesNotMatch(comparator, /chmod\s+-R|chmod[^\n]*\*/);
  const windows = job(source, 'native-isolation-windows-x64', 'native-semgrep-macos-arm64-builders');
  assert.doesNotMatch(windows, /artifact transport mode|fchmodSync/);
});

test('each target uses two independent native builder jobs and a fail-closed comparator', async () => {
  const source = await readFile(workflowUrl, 'utf8');
  for (const [target, builderName, comparatorName, next] of [
    ['windows', 'native-semgrep-windows-x64-builders', 'native-isolation-windows-x64', 'native-semgrep-macos-arm64-builders'],
    ['macos', 'native-semgrep-macos-arm64-builders', 'native-isolation-macos-arm64', 'request-native-sidecar-publication'],
  ]) {
    const builder = job(source, builderName, comparatorName);
    const comparator = job(source, comparatorName, next);
    assert.match(builder, /matrix:\s*\n\s+build:\s*\[a, b\]/);
    assert.match(builder, /strategy\.job-index/);
    assert.match(builder, /strategy\.job-total/);
    assert.match(builder, /job\.check_run_id/);
    assert.match(builder, /github\.run_id/);
    assert.match(builder, /github\.run_attempt/);
    assert.match(builder, /build-\$\{\{ matrix\.build \}\}/);
    assert.equal((builder.match(/build-public-source-(?:windows\.ps1|macos\.sh)/g) ?? []).length, 1);
    assert.match(comparator, new RegExp(`- ${builderName}`));
    assert.match(comparator, /build-a\.identity\.v1\.json/);
    assert.match(comparator, /build-b\.identity\.v1\.json/);
    assert.match(comparator, /verify-native-builder-identities\.mjs/);
    assert.match(builder, /checkRunId/);
    assert.match(builder, /jobIndex/);
    assert.match(builder, /runId/);
    assert.match(builder, /runAttempt/);
    assert.match(builder, /artifactName/);
    assert.match(builder, /jobDefinition/);
    assert.match(comparator, new RegExp(`target[^\n]+${target}`));
  }
});

test('independent builder identity validation rejects empty, zero, or reused provenance', () => {
  const expected = {
    target: 'windows-x86_64',
    commit: 'a'.repeat(40),
    runId: '123',
    runAttempt: 1,
    workflowRef: 'owner/repo/.github/workflows/ci.yml@refs/heads/main',
    workflowSha: 'b'.repeat(40),
    jobDefinition: 'native-semgrep-windows-x64-builders',
    artifactPrefix: 'task9-semgrep-windows-build',
  };
  const make = (slot, index, checkRunId) => ({
    schemaVersion: 1,
    target: expected.target,
    build: `build-${slot}`,
    artifactName: `${expected.artifactPrefix}-${slot}-${expected.commit}-${expected.runId}-${expected.runAttempt}`,
    commit: expected.commit,
    runId: expected.runId,
    runAttempt: expected.runAttempt,
    checkRunId,
    jobDefinition: expected.jobDefinition,
    jobIndex: index,
    jobTotal: 2,
    runnerName: `runner-${slot}`,
    runnerOs: 'Windows',
    runnerArch: 'X64',
    workflowRef: expected.workflowRef,
    workflowSha: expected.workflowSha,
  });
  const a = make('a', 0, 101);
  const b = make('b', 1, 102);
  assert.equal(validateIndependentBuilderIdentities(a, b, expected), true);
  for (const mutate of [
    (x) => { x.runnerName = ''; },
    (x) => { x.checkRunId = 0; },
    (x) => { x.runId = '0'; },
    (x) => { x.jobIndex = 0; },
    (x) => { x.artifactName = ''; },
  ]) {
    const changed = structuredClone(b);
    mutate(changed);
    assert.throws(() => validateIndependentBuilderIdentities(a, changed, expected));
  }
  const reused = structuredClone(b);
  reused.checkRunId = a.checkRunId;
  assert.throws(() => validateIndependentBuilderIdentities(a, reused, expected));
});

test('native runtime builds prove OS-enforced offline execution', async () => {
  const [macos, windows] = await Promise.all([
    readFile(new URL('../third_party/sidecars/semgrep/build-public-source-macos.sh', import.meta.url), 'utf8'),
    readFile(new URL('../third_party/sidecars/semgrep/build-public-source-windows.ps1', import.meta.url), 'utf8'),
  ]);
  assert.match(macos, /\/usr\/bin\/sandbox-exec/);
  assert.match(macos, /\(deny network\*\)/);
  assert.match(macos, /node:net|require\(["']net["']\)/);
  assert.match(macos, /EPERM/);
  assert.match(macos, /EACCES/);
  assert.match(macos, /offline-egress\.v1\.json/);

  assert.match(windows, /Runner\.Worker\.exe/);
  assert.match(windows, /Runner\.Listener\.exe/);
  assert.match(windows, /Get-CimInstance[^\n]+Win32_Process/);
  assert.match(windows, /New-NetFirewallRule/);
  assert.match(windows, /-Direction\s+Outbound/);
  assert.match(windows, /-Program\s+\$Program/);
  assert.match(windows, /-Action\s+Allow/);
  assert.match(windows, /Set-NetFirewallProfile[^\n]+-DefaultOutboundAction\s+Block/);
  assert.match(windows, /DefaultOutboundAction/);
  assert.match(windows, /Disable-NetFirewallRule/);
  assert.match(windows, /Enable-NetFirewallRule/);
  assert.match(windows, /TcpClient/);
  assert.match(windows, /Get-NetFirewallRule/);
  assert.match(windows, /finally\s*\{[\s\S]*Set-NetFirewallProfile[\s\S]*DefaultOutboundAction[\s\S]*Enable-NetFirewallRule[\s\S]*Remove-NetFirewallRule/);
  assert.doesNotMatch(windows, /New-NetFirewallRule[^\n]+-Action\s+Block/);
  assert.match(windows, /offline-egress\.v1\.json/);
});

test('Windows offline build pins only observed runner control-plane hosts', async () => {
  const windows = await readFile(
    new URL('../third_party/sidecars/semgrep/build-public-source-windows.ps1', import.meta.url),
    'utf8',
  );

  assert.match(
    windows,
    /function Get-RunnerControlPlaneHosts[\s\S]{0,4000}\$RunnerPrograms[\s\S]{0,1000}Split-Path[\s\S]{0,1000}Join-Path[^\n]+['"]_diag['"]/,
  );
  assert.match(windows, /Get-ChildItem[^\n]+-LiteralPath\s+\$RunnerDiag[^\n]+-Filter\s+['"]\*\.log['"]/);
  assert.match(windows, /\[Uri\][^\n]+[\r\n]+[^\n]*\.Host/);
  assert.match(
    windows,
    /\^\(\?:github\\\.com\|api\\\.github\\\.com\|\(\?:\[a-z0-9-\]\+\\\.\)\+actions\\\.githubusercontent\\\.com\)\$/,
  );
  assert.match(
    windows,
    /foreach \(\$Log in \$DiagnosticLogs\)[\s\S]{0,2500}current runner diagnostic log has no Actions control-plane host/,
  );
  assert.match(windows, /['"]\{0\}\s+\{1\}['"]\s+-f\s+\$Address,\s*\$Hostname/);
  assert.doesNotMatch(windows, /WriteAll(?:Text|Lines|Bytes)\([^\n]*(?:Uri|Url|Diag|Log)/i);

  assert.match(windows, /\$HostsSnapshot\s*=\s*\[IO\.File\]::ReadAllBytes\(\$HostsPath\)/);
  assert.match(windows, /\[IO\.File\]::WriteAllBytes\(\$HostsPath,\s*\$HostsOverlayBytes\)/);
  const blockAt = windows.search(/Set-NetFirewallProfile[^\n]+-DefaultOutboundAction\s+Block/);
  const resolutions = [...windows.matchAll(/\[Net\.Dns\]::GetHostAddresses\(\$Hostname\)/g)].map(({ index }) => index);
  assert.ok(resolutions.some((index) => index < blockAt), 'runner hosts must be resolved before outbound blocking');
  assert.ok(resolutions.some((index) => index > blockAt), 'pinned runner hosts must resolve after outbound blocking');
  assert.match(windows.slice(blockAt), /Clear-DnsClientCache\s+-ErrorAction\s+Stop/);
  assert.match(windows.slice(blockAt), /pinned runner control-plane hostname resolution mismatch/);
  assert.match(windows.slice(blockAt), /@\(Compare-Object[\s\S]{0,300}\)\.Count\s+-ne\s+0/);
  assert.match(windows.slice(blockAt), /ReadAllBytes\(\$HostsPath\)[\s\S]{0,500}SequenceEqual\([^,]+,\s*\$HostsOverlayBytes\)/);
  assert.match(
    windows,
    /finally\s*\{[\s\S]*\[IO\.File\]::WriteAllBytes\(\$HostsPath,\s*\$HostsSnapshot\)/,
  );

  assert.doesNotMatch(windows, /New-NetFirewallRule[^\n]*(?:svchost(?:\.exe)?|Dnscache)/i);
});

test('Windows runtime DLL closure never searches ambient PATH', async () => {
  const windows = await readFile(
    new URL('../third_party/sidecars/semgrep/build-public-source-windows.ps1', import.meta.url),
    'utf8',
  );
  assert.doesNotMatch(windows, /\$env:PATH\.Split/);
  assert.match(windows, /TrustedDllRoots/);
  assert.match(windows, /x86_64-w64-mingw32-gcc/);
  assert.match(windows, /untrusted runtime DLL path/);
});

test('native builders consume authoritative CI provenance bound to the sealed source lock', async () => {
  const [source, lockBytes, provenanceText, macosScript, windowsScript] = await Promise.all([
    readFile(workflowUrl, 'utf8'),
    readFile(sourceLockUrl),
    readFile(provenanceUrl, 'utf8'),
    readFile(new URL('../third_party/sidecars/semgrep/build-public-source-macos.sh', import.meta.url), 'utf8'),
    readFile(new URL('../third_party/sidecars/semgrep/build-public-source-windows.ps1', import.meta.url), 'utf8'),
  ]);
  const provenance = JSON.parse(provenanceText);
  const sourceLock = JSON.parse(lockBytes);
  const workflowBytes = Buffer.from(source);
  const workflowGitBlob = createHash('sha1')
    .update(`blob ${workflowBytes.length}\0`)
    .update(workflowBytes)
    .digest('hex');
  for (const toolchain of sourceLock.toolchains) {
    assert.equal(toolchain.workflowGitBlob, workflowGitBlob, `${toolchain.distributionTarget} workflow blob`);
  }
  assert.equal(provenance.schemaVersion, 1);
  assert.equal(provenance.sourceLock.path, 'third_party/sidecars/semgrep/source-lock.v1.json');
  assert.equal(
    createHash('sha256').update(lockBytes).digest('hex'),
    provenance.sourceLock.sha256,
    'native CI provenance must stay bound to the sealed source lock',
  );
  assert.equal(
    provenance.sourceLock.embeddedActionToolchainStatus,
    'sealed-historical-metadata-non-authoritative-for-native-ci',
  );
  const native = source.slice(source.indexOf('  native-semgrep-windows-x64-builders:'));
  const common = new Map(provenance.actions
    .filter(({ distributionTarget }) => distributionTarget === undefined)
    .map(({ action, revision }) => [action, revision]));
  for (const action of ['actions/checkout', 'actions/setup-node', 'actions/upload-artifact', 'actions/download-artifact']) {
    const revision = common.get(action);
    assert.match(revision ?? '', /^[0-9a-f]{40}$/, `${action} is not authoritatively locked`);
    const uses = [...native.matchAll(new RegExp(`uses: ${action.replace('/', '\\/')}@([0-9a-f]{40})`, 'g'))];
    assert.ok(uses.length > 0, `native workflow does not consume ${action}`);
    for (const match of uses) assert.equal(match[1], revision, `${action} drifted from source lock`);
  }
  for (const toolchain of provenance.toolchains) {
    const builderName = toolchain.distributionTarget === 'windows-x86_64'
      ? 'native-semgrep-windows-x64-builders'
      : 'native-semgrep-macos-arm64-builders';
    const next = toolchain.distributionTarget === 'windows-x86_64'
      ? 'native-isolation-windows-x64'
      : 'native-isolation-macos-arm64';
    const builder = job(source, builderName, next);
    assert.match(builder, new RegExp(`runs-on: ${toolchain.runner}\\n`));
    assert.match(builder, new RegExp(`ocaml-compiler: ${toolchain.ocamlCompiler.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`));
    assert.match(builder, new RegExp(`semgrep/setup-ocaml@${toolchain.setupAction.split('@')[1]}`));
    assert.match(builder, new RegExp(`actions/setup-node@${toolchain.setupNodeAction.split('@')[1]}`));
  }
  for (const script of [macosScript, windowsScript]) {
    assert.match(script, /native CI source lock identity mismatch/i);
    assert.match(script, /native CI action provenance mismatch/i);
    assert.match(script, /native CI toolchain provenance mismatch/i);
    assert.match(script, /native-ci-provenance\.v1\.json/);
  }
});

test('protected native success dispatches a separately reviewed final publication', async () => {
  const [source, publication] = await Promise.all([
    readFile(workflowUrl, 'utf8'),
    readFile(publicationWorkflowUrl, 'utf8'),
  ]);
  const request = job(source, 'request-native-sidecar-publication');
  assert.match(request, /native-isolation-windows-x64/);
  assert.match(request, /native-isolation-macos-arm64/);
  assert.match(request, /github\.event_name == 'push'/);
  assert.match(request, /github\.ref == 'refs\/heads\/main'/);
  assert.match(request, /github\.ref_protected == true/);
  assert.equal((request.match(/outputs\.hydration_mode == 'candidate'/g) ?? []).length, 2);
  assert.match(request, /contents: write/);
  assert.match(request, /GH_REPO:\s*\$\{\{ github\.repository \}\}/);
  assert.match(request, /repos\/\$GITHUB_REPOSITORY\/dispatches/);
  assert.match(request, /semgrep-native-publication/);
  for (const field of ['commit', 'runId', 'runAttempt', 'workflowRef', 'workflowSha']) {
    assert.match(request, new RegExp(field));
  }

  assert.match(publication, /repository_dispatch:/);
  assert.match(publication, /semgrep-native-publication/);
  assert.match(publication, /group: semgrep-native-publication/);
  assert.match(publication, /cancel-in-progress: false/);
  assert.doesNotMatch(publication, /workflow_dispatch:/);
  assert.match(publication, /github\.actor == 'github-actions\[bot\]'/);
  assert.match(publication, /environment: semgrep-sidecar-publication/);
  assert.match(publication, /actions: read/);
  assert.match(publication, /contents: write/);
  assert.match(publication, /ref:\s*\$\{\{ github\.event\.client_payload\.commit \}\}/);
  assert.match(publication, /actions\/runs\/\$SOURCE_RUN_ID/);
  assert.match(publication, /branches\/main/);
  assert.match(publication, /native-isolation-windows-x64/);
  assert.match(publication, /native-isolation-macos-arm64/);
  assert.equal((publication.match(/gh run download "\$SOURCE_RUN_ID"/g) ?? []).length, 2);
  assert.match(publication, /finalize-semgrep-native-release\.mjs/);
  assert.match(publication, /--bootstrap-source/);
  assert.match(publication, /FINAL_OUTPUT:\s*\$\{\{ runner\.temp \}\}\/context-relay-semgrep-final/);
  assert.match(publication, /--output "\$FINAL_OUTPUT"/);
  assert.doesNotMatch(publication, /--output "\$GITHUB_WORKSPACE\/final"/);
  assert.match(publication, /runtime-closure\.\$target\.v1\.json/);
  assert.match(publication, /native-smoke\.\$target\.v1\.json/);
  assert.match(publication, /build-a\.identity\.v1\.json/);
  assert.match(publication, /build-b\.offline-egress\.v1\.json/);
  assert.match(publication, /builder-evidence\.windows-x86_64\.v1\.json/);
  assert.match(publication, /builder-toolchain\.windows-x86_64\.v1\.json/);
  assert.match(publication, /builder-evidence\.windows-x86_64\.v1\.schema\.json/);
  assert.match(publication, /sidecars-semgrep-1\.170\.0-source\.1/);
  assert.match(publication, /--draft/);
  assert.match(publication, /gh release upload/);
  assert.match(publication, /gh release download/);
  assert.match(publication, /comm -13 expected-assets existing-assets/);
  assert.match(publication, /comm -23 expected-assets existing-assets/);
  assert.match(publication, /isDraft/);
  assert.match(publication, /cmp expected-assets published-assets/);
  assert.match(publication, /cmp expected-assets completed-assets/);
  assert.match(publication, /git\/ref\/tags\/\$tag/);
  assert.match(publication, /object\?\.type!=="commit"/);
  assert.match(publication, /object\?\.sha!==process\.argv\[3\]/);
  assert.equal((publication.match(/verify_tag_ref/g) ?? []).length, 3);
  assert.match(publication, /verify_tag_ref\s+gh release edit/);
  assert.match(publication, /! -name SHA256SUMS/);
  assert.match(publication, /RUNNER_TEMP\/SHA256SUMS/);
  assert.match(publication, /--draft=false/);
  assert.match(publication, /\.immutable/);
  assert.match(publication, /IMMUTABLE_RELEASES_READ_TOKEN/);
  assert.match(publication, /environments\/semgrep-sidecar-publication/);
  assert.match(publication, /protected_branches/);
  assert.match(publication, /required_reviewers/);
  assert.match(publication, /prevent_self_review/);
  assert.match(publication, /final-semgrep-native-patch/);
});

test('every workflow action remains pinned to a full commit SHA', async () => {
  const source = (await Promise.all([
    readFile(workflowUrl, 'utf8'),
    readFile(publicationWorkflowUrl, 'utf8'),
  ])).join('\n');
  const uses = [...source.matchAll(/^\s*- uses:\s*(\S+?)(?:\s+#.*)?\s*$/gm)].map((match) => match[1]);
  assert.ok(uses.length > 0);
  for (const action of uses) assert.match(action, /^[^@]+@[0-9a-f]{40}$/);
  assert.doesNotMatch(source, /continue-on-error:\s*true/);
});
