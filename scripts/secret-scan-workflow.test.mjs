import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const workflowUrl = new URL('../.github/workflows/secret-scan.yml', import.meta.url);
const securityPolicyUrl = new URL('../SECURITY.md', import.meta.url);
const ignoreUrl = new URL(
  '../third_party/sidecars/policies/repository.gitleaksignore',
  import.meta.url,
);

const reviewedSyntheticFixtures = [
  '7e5089dd4e433ddd552e91a9abb184225618079d:crates/native-runner/tests/real_sidecars_windows_v1.rs:aws-access-token:123',
  '7e5089dd4e433ddd552e91a9abb184225618079d:crates/native-runner/tests/macos-launcher-harness/tests/adapter_native.rs:aws-access-token:452',
  'd7855f58669beb6f6814d6450253761448edd5b5:apps/desktop/src/schema-parity.test.ts:private-key:77',
  'd7855f58669beb6f6814d6450253761448edd5b5:apps/desktop/src/schema-parity.test.ts:private-key:79',
  'd7855f58669beb6f6814d6450253761448edd5b5:crates/protocol/tests/packages_v1.rs:private-key:85',
  'd7855f58669beb6f6814d6450253761448edd5b5:crates/protocol/tests/packages_v1.rs:private-key:87',
].join('\n') + '\n';

test('repository secret scan verifies pinned Gitleaks and scans every Git ref', async () => {
  const source = await readFile(workflowUrl, 'utf8');

  assert.match(source, /^name:\s*Secret Scan$/m);
  assert.match(source, /^\s+pull_request:\s*$/m);
  assert.match(source, /^\s+push:\s*$/m);
  assert.match(source, /branches:\s*\[main\]/);
  assert.match(source, /permissions:\s*\n\s+contents:\s*read/);
  assert.match(source, /actions\/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10/);
  assert.match(source, /fetch-depth:\s*0/);
  assert.match(source, /persist-credentials:\s*false/);
  assert.match(source, /gitleaks_8\.30\.1_windows_x64\.zip/);
  assert.match(source, /d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e/);
  assert.match(source, /17157e2ee8b76fc8b1d8bee607a250e34b8a8023c8bc81822d4b5ee4d78fcb7c/);
  assert.match(source, /repository\.gitleaksignore/);
  assert.match(source, /d5d44a8d107c0e407ba99ce0e7400b66e6b538de6e3b0c9b4ddbb9f6ab9bccd8/);
  assert.match(source, /--gitleaks-ignore-path/);
  assert.match(source, /--ignore-gitleaks-allow/);
  assert.match(source, /'git'/);
  assert.match(source, /--log-opts=--all/);
  assert.doesNotMatch(source, /continue-on-error:\s*true/);

  const uses = [...source.matchAll(/^\s+- uses:\s*(\S+?)(?:\s+#.*)?\s*$/gm)]
    .map((match) => match[1]);
  assert.deepEqual(uses, [
    'actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10',
  ]);

  assert.equal(await readFile(ignoreUrl, 'utf8'), reviewedSyntheticFixtures);
});

test('credential response policy treats every finding as active', async () => {
  const source = await readFile(securityPolicyUrl, 'utf8');
  assert.match(source, /Treat every secret-scanning finding as active/);
  assert.match(source, /revoke and rotate/i);
});
