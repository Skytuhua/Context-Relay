import { basename, dirname, resolve } from 'node:path';
import { lstat, readFile, writeFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

const MAX_BYTES = 4096;
const COMMIT = /^[0-9a-f]{40}$/u;
const POSITIVE_INTEGER = /^[1-9][0-9]*$/u;
const TARGETS = new Map([
  ['windows-x86_64', {
    jobDefinition: 'native-isolation-windows-x64',
    sandboxMechanism: 'windows-appcontainer',
    tests: [
      'real_rulesync_generates_only_the_validated_output_inside_appcontainer',
      'real_rulesync_rejects_malformed_frontmatter_and_cleans_up',
      'real_gitleaks_distinguishes_clean_and_findings_and_ignores_attacker_ignore_file',
      'real_semgrep_clean_and_finding_use_the_closed_policy',
    ],
  }],
  ['macos-aarch64', {
    jobDefinition: 'native-isolation-macos-arm64',
    sandboxMechanism: 'macos-sandbox-exec-inherited',
    tests: [
      'real_sidecar_rulesync_generates_only_the_validated_output',
      'real_sidecar_rulesync_rejects_malformed_frontmatter_and_cleans_up',
      'real_sidecar_gitleaks_clean_and_finding_ignore_attacker_gitleaksignore',
      'real_sidecar_semgrep_clean_and_finding_use_the_closed_policy',
    ],
  }],
]);

function fail(message) {
  throw new Error(message);
}

function positiveInteger(value, label) {
  const text = String(value);
  if (!POSITIVE_INTEGER.test(text)) fail(`${label} is invalid`);
  const number = Number(text);
  if (!Number.isSafeInteger(number)) fail(`${label} exceeds the safe integer range`);
  return number;
}

function exactArray(left, right) {
  return Array.isArray(left)
    && left.length === right.length
    && left.every((value, index) => value === right[index]);
}

export function createNativeSmokeEvidence({
  target,
  commit,
  runId,
  runAttempt,
  checkRunId,
  jobDefinition,
  sandboxMechanism,
  tests,
}) {
  const policy = TARGETS.get(target);
  if (!policy) fail('native smoke target is unsupported');
  if (!COMMIT.test(commit)) fail('native smoke commit is invalid');
  if (!POSITIVE_INTEGER.test(String(runId))) fail('native smoke run ID is invalid');
  if (String(runId).length > 32) fail('native smoke run ID is too long');
  if (jobDefinition !== policy.jobDefinition) fail('native smoke job definition is invalid');
  if (sandboxMechanism !== undefined && sandboxMechanism !== policy.sandboxMechanism) {
    fail('native smoke sandbox mechanism is not fixed');
  }
  if (tests !== undefined && !exactArray(tests, policy.tests)) {
    fail('native smoke test inventory is not fixed');
  }
  const evidence = {
    schemaVersion: 1,
    target,
    commit,
    runId: String(runId),
    runAttempt: positiveInteger(runAttempt, 'native smoke run attempt'),
    checkRunId: positiveInteger(checkRunId, 'native smoke check-run ID'),
    jobDefinition: policy.jobDefinition,
    sandboxMechanism: policy.sandboxMechanism,
    tests: [...policy.tests],
  };
  const bytes = Buffer.from(`${JSON.stringify(evidence, null, 2)}\n`);
  if (bytes.length > MAX_BYTES) fail('native smoke evidence exceeds its size bound');
  return bytes;
}

export function parseNativeSmokeEvidence(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > MAX_BYTES) {
    fail('native smoke evidence has an invalid size');
  }
  let evidence;
  try {
    evidence = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    fail('native smoke evidence is not UTF-8 JSON');
  }
  if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence)) {
    fail('native smoke evidence must be an object');
  }
  const canonical = createNativeSmokeEvidence(evidence);
  if (!bytes.equals(canonical)) fail('native smoke evidence is not canonical');
  return evidence;
}

async function main(argv) {
  if (argv.length !== 8 || argv[0] !== '--write') {
    fail('usage: native-smoke-evidence.mjs --write OUTPUT TARGET COMMIT RUN_ID RUN_ATTEMPT CHECK_RUN_ID JOB_DEFINITION');
  }
  const [, outputArgument, target, commit, runId, runAttempt, checkRunId, jobDefinition] = argv;
  const output = resolve(outputArgument);
  if (basename(output) !== `native-smoke.${target}.v1.json`) {
    fail('native smoke output filename does not match its target');
  }
  const parent = await lstat(dirname(output));
  if (!parent.isDirectory() || parent.isSymbolicLink()) fail('native smoke output parent is unsafe');
  await writeFile(output, createNativeSmokeEvidence({
    target,
    commit,
    runId,
    runAttempt,
    checkRunId,
    jobDefinition,
  }), { flag: 'wx', mode: 0o600 });
  parseNativeSmokeEvidence(await readFile(output));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
