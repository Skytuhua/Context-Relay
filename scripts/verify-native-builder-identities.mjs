import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const keys = [
  'artifactName',
  'build',
  'checkRunId',
  'commit',
  'jobDefinition',
  'jobIndex',
  'jobTotal',
  'runAttempt',
  'runId',
  'runnerArch',
  'runnerName',
  'runnerOs',
  'schemaVersion',
  'target',
  'workflowRef',
  'workflowSha',
].sort();

const targetRunners = new Map([
  ['windows-x86_64', { runnerOs: 'Windows', runnerArch: 'X64' }],
  ['macos-aarch64', { runnerOs: 'macOS', runnerArch: 'ARM64' }],
]);

function nonEmpty(value) {
  return typeof value === 'string' && value.trim() === value && value.length > 0;
}

function fail(message) {
  throw new Error(`invalid independent native builder identity: ${message}`);
}

export function validateIndependentBuilderIdentities(a, b, expected) {
  const runner = targetRunners.get(expected.target);
  if (!runner) fail('unknown target');
  if (!/^[0-9a-f]{40}$/.test(expected.commit)) fail('expected commit');
  if (!/^[1-9][0-9]*$/.test(expected.runId)) fail('expected run id');
  if (!Number.isSafeInteger(expected.runAttempt) || expected.runAttempt <= 0) fail('expected run attempt');
  if (!nonEmpty(expected.workflowRef) || !/^[0-9a-f]{40}$/.test(expected.workflowSha)) fail('expected workflow identity');
  if (!nonEmpty(expected.jobDefinition) || !nonEmpty(expected.artifactPrefix)) fail('expected job/artifact identity');

  for (const [value, slot, index] of [[a, 'build-a', 0], [b, 'build-b', 1]]) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${slot} shape`);
    if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(keys)) fail(`${slot} keys`);
    const artifactName = `${expected.artifactPrefix}-${slot.slice(-1)}-${expected.commit}-${expected.runId}-${expected.runAttempt}`;
    if (value.schemaVersion !== 1
        || value.target !== expected.target
        || value.build !== slot
        || value.commit !== expected.commit
        || value.runId !== expected.runId
        || value.runAttempt !== expected.runAttempt
        || !Number.isSafeInteger(value.checkRunId)
        || value.checkRunId <= 0
        || value.jobDefinition !== expected.jobDefinition
        || value.jobIndex !== index
        || value.jobTotal !== 2
        || value.artifactName !== artifactName
        || value.runnerOs !== runner.runnerOs
        || value.runnerArch !== runner.runnerArch
        || !nonEmpty(value.runnerName)
        || value.workflowRef !== expected.workflowRef
        || value.workflowSha !== expected.workflowSha) {
      fail(slot);
    }
  }
  if (a.checkRunId === b.checkRunId) fail('duplicate check run id');
  return true;
}

function main(argv) {
  if (argv.length !== 10) fail('usage');
  const [aPath, bPath, target, commit, runId, runAttemptText, workflowRef, workflowSha, jobDefinition, artifactPrefix] = argv;
  const expected = {
    target,
    commit,
    runId,
    runAttempt: Number(runAttemptText),
    workflowRef,
    workflowSha,
    jobDefinition,
    artifactPrefix,
  };
  validateIndependentBuilderIdentities(
    JSON.parse(readFileSync(aPath, 'utf8')),
    JSON.parse(readFileSync(bPath, 'utf8')),
    expected,
  );
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
