import assert from 'node:assert/strict';
import test from 'node:test';

import {
  createNativeSmokeEvidence,
  parseNativeSmokeEvidence,
} from './native-smoke-evidence.mjs';

const COMMON = {
  commit: 'a'.repeat(40),
  runId: '123456789',
  runAttempt: '2',
  checkRunId: '987654321',
};

const CASES = [
  {
    target: 'windows-x86_64',
    jobDefinition: 'native-isolation-windows-x64',
    sandboxMechanism: 'windows-appcontainer',
    tests: [
      'real_rulesync_generates_only_the_validated_output_inside_appcontainer',
      'real_rulesync_rejects_malformed_frontmatter_and_cleans_up',
      'real_gitleaks_distinguishes_clean_and_findings_and_ignores_attacker_ignore_file',
      'real_semgrep_clean_and_finding_use_the_closed_policy',
    ],
  },
  {
    target: 'macos-aarch64',
    jobDefinition: 'native-isolation-macos-arm64',
    sandboxMechanism: 'macos-sandbox-exec-inherited',
    tests: [
      'real_sidecar_rulesync_generates_only_the_validated_output',
      'real_sidecar_rulesync_rejects_malformed_frontmatter_and_cleans_up',
      'real_sidecar_gitleaks_clean_and_finding_ignore_attacker_gitleaksignore',
      'real_sidecar_semgrep_clean_and_finding_use_the_closed_policy',
    ],
  },
];

test('native smoke evidence is bounded, canonical, and fixes each platform gate set', () => {
  for (const expected of CASES) {
    const bytes = createNativeSmokeEvidence({ ...COMMON, ...expected });
    assert.ok(Buffer.isBuffer(bytes));
    assert.ok(bytes.length < 4096);
    assert.equal(bytes.at(-1), 0x0a);
    const evidence = parseNativeSmokeEvidence(bytes);
    assert.deepEqual(evidence, {
      schemaVersion: 1,
      target: expected.target,
      commit: COMMON.commit,
      runId: COMMON.runId,
      runAttempt: 2,
      checkRunId: 987654321,
      jobDefinition: expected.jobDefinition,
      sandboxMechanism: expected.sandboxMechanism,
      tests: expected.tests,
    });
    assert.deepEqual(bytes, Buffer.from(`${JSON.stringify(evidence, null, 2)}\n`));
  }
});

test('native smoke evidence rejects caller-selected gates and invalid CI identity', () => {
  for (const changed of [
    { commit: 'A'.repeat(40) },
    { runId: '0' },
    { runAttempt: '0' },
    { checkRunId: '0' },
    { jobDefinition: 'native-isolation-macos-arm64' },
    { sandboxMechanism: 'none' },
    { tests: [] },
  ]) {
    assert.throws(() => createNativeSmokeEvidence({ ...COMMON, ...CASES[0], ...changed }));
  }
  assert.throws(() => parseNativeSmokeEvidence(Buffer.from('{}\n')));
  assert.throws(() => parseNativeSmokeEvidence(Buffer.alloc(4097, 0x20)));
});
