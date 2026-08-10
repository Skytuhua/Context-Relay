import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const workflowUrl = new URL('../.github/workflows/secret-scan.yml', import.meta.url);
const securityPolicyUrl = new URL('../SECURITY.md', import.meta.url);
const exceptionRationaleUrl = new URL(
  '../docs/security/secret-scan-exceptions.md',
  import.meta.url,
);
const masterPlanAuditUrl = new URL(
  '../docs/verification/v1-master-plan-audit.md',
  import.meta.url,
);
const ignoreUrl = new URL(
  '../.github/repository.gitleaksignore',
  import.meta.url,
);

const reviewedExceptionFingerprints = [
  '7e5089dd4e433ddd552e91a9abb184225618079d:crates/native-runner/tests/real_sidecars_windows_v1.rs:aws-access-token:123',
  '7e5089dd4e433ddd552e91a9abb184225618079d:crates/native-runner/tests/macos-launcher-harness/tests/adapter_native.rs:aws-access-token:452',
  'd7855f58669beb6f6814d6450253761448edd5b5:apps/desktop/src/schema-parity.test.ts:private-key:77',
  'd7855f58669beb6f6814d6450253761448edd5b5:apps/desktop/src/schema-parity.test.ts:private-key:79',
  'd7855f58669beb6f6814d6450253761448edd5b5:crates/protocol/tests/packages_v1.rs:private-key:85',
  'd7855f58669beb6f6814d6450253761448edd5b5:crates/protocol/tests/packages_v1.rs:private-key:87',
  '3c2a371aef74f4962af64d0fe71545557244f21a:crates/core/src/hermes/yaml.rs:private-key:456',
  '6b144104d8a315038785dfdeaccdb13cdbca730d:crates/core/tests/hermes_adapter_v1.rs:private-key:406',
  '6b144104d8a315038785dfdeaccdb13cdbca730d:crates/core/tests/hermes_adapter_v1.rs:curl-auth-header:399',
  'f98444a51754f5deaba2da9aa86f4463129a3380:crates/core/src/hermes/yaml.rs:private-key:94',
  '3c2a371aef74f4962af64d0fe71545557244f21a:crates/core/tests/hermes_adapter_v1.rs:curl-auth-header:2480',
].join('\n') + '\n';
const reviewedIgnoreByteLength = 1103;
const reviewedIgnoreSha256 = '651da29e101f61580d789284520431ca8aaf944f933394b86130149b865d6032';
const allowedExceptionClassifications = new Set([
  'detector-literal',
  'synthetic-negative-test',
]);

function parseExceptionEntries(source) {
  return source
    .split(/^### /m)
    .slice(1)
    .map((section) => {
      const [heading, ...bodyLines] = section.split('\n');
      const fingerprint = heading.match(/^`([^`]+)`\s*$/)?.[1];
      const body = bodyLines.join('\n');
      const field = (name, code = false) => {
        const value = body.match(new RegExp(`^- ${name}: (.+)$`, 'm'))?.[1]?.trim();
        if (!value) return undefined;
        if (!code) return value;
        return value.match(/^`([^`]+)`$/)?.[1];
      };

      return {
        fingerprint,
        commit: field('Historical commit', true),
        path: field('Historical path', true),
        rule: field('Rule', true),
        line: field('Line', true),
        classification: field('Classification', true),
        nonCredentialBasis: field('Non-credential basis'),
        securityPurpose: field('Security purpose'),
      };
    });
}

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
  assert.match(source, /\.github\/repository\.gitleaksignore/);
  assert.doesNotMatch(source, /third_party\/sidecars\/policies\/repository\.gitleaksignore/);
  assert.match(source, /\(Get-Item -LiteralPath \$ignore\)\.Length -ne 1103/);
  assert.match(source, new RegExp(reviewedIgnoreSha256));
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
});

test('repository secret scan ignore file is the exact reviewed fingerprint set', async () => {
  const ignore = await readFile(ignoreUrl);

  assert.equal(ignore.byteLength, reviewedIgnoreByteLength);
  assert.equal(
    createHash('sha256').update(ignore).digest('hex'),
    reviewedIgnoreSha256,
  );
  assert.equal(ignore.toString('utf8'), reviewedExceptionFingerprints);
});

test('every exact ignored fingerprint has one complete tracked rationale and no extras', async () => {
  const fingerprints = (await readFile(ignoreUrl, 'utf8')).trimEnd().split('\n');
  let rationale;
  try {
    rationale = await readFile(exceptionRationaleUrl, 'utf8');
  } catch (error) {
    if (error?.code === 'ENOENT') {
      assert.fail('the tracked secret-scan exception rationale document is missing');
    }
    throw error;
  }

  const entries = parseExceptionEntries(rationale);
  const documentedFingerprints = entries.map((entry) => entry.fingerprint);
  assert.equal(new Set(fingerprints).size, fingerprints.length, 'ignore fingerprints must be unique');
  assert.equal(new Set(documentedFingerprints).size, documentedFingerprints.length, 'rationale fingerprints must be unique');
  assert.deepEqual(documentedFingerprints, fingerprints, 'rationales must be a 1:1 ordered copy of the exact ignore fingerprints');

  for (const entry of entries) {
    const fingerprintParts = entry.fingerprint?.match(
      /^([0-9a-f]{40}):(.+):([^:]+):(\d+)$/,
    );
    assert.ok(fingerprintParts, 'each rationale heading must be an exact Gitleaks fingerprint');
    assert.equal(entry.commit, fingerprintParts[1]);
    assert.equal(entry.path, fingerprintParts[2]);
    assert.equal(entry.rule, fingerprintParts[3]);
    assert.equal(entry.line, fingerprintParts[4]);
    assert.ok(
      allowedExceptionClassifications.has(entry.classification),
      `unsupported classification for ${entry.fingerprint}`,
    );
    assert.ok(entry.nonCredentialBasis?.length >= 24, `missing non-credential basis for ${entry.fingerprint}`);
    assert.ok(entry.securityPurpose?.length >= 24, `missing security purpose for ${entry.fingerprint}`);
  }

  const forbiddenRawPayloadShapes = [
    /\bAKIA[0-9A-Z]{16}\b/,
    /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
    /authorization\s*:\s*bearer\s+[^\s`]+/i,
  ];
  for (const pattern of forbiddenRawPayloadShapes) {
    if (pattern.test(rationale)) {
      assert.fail('the rationale document must not copy a raw historical matched payload');
    }
  }
});

test('credential response policy treats every finding as active', async () => {
  const source = await readFile(securityPolicyUrl, 'utf8');
  assert.match(source, /Treat every secret-scanning finding as active/);
  assert.match(source, /revoke and rotate/i);
  assert.match(source, /remove it from the repository and Git history/i);
  assert.match(source, /changed fingerprint.*new active finding/i);
  assert.match(source, /broad\s+(?:regular-expression|regex), path, or rule exclusions\s+are forbidden/i);
  assert.match(source, /docs\/security\/secret-scan-exceptions\.md/);
});

test('the audit links stabilization evidence without promoting pending CI', async () => {
  const source = await readFile(masterPlanAuditUrl, 'utf8');
  assert.match(source, /\[PR #12 stabilization ledger\]\(pr-12-stabilization\.md\)/);
  assert.match(source, /\[secret-scan exception rationale\]\(\.\.\/security\/secret-scan-exceptions\.md\)/);

  const taskThreeRow = source
    .split('\n')
    .find((line) => line.startsWith('| T03 |'));
  assert.ok(taskThreeRow, 'T03 audit row must remain present');
  assert.equal(taskThreeRow.split('|').map((cell) => cell.trim())[4], 'partial');
});
