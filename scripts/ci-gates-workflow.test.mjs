import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import test from 'node:test';

const workflowDirectoryUrl = new URL('../.github/workflows/', import.meta.url);
const ciWorkflowUrl = new URL('../.github/workflows/ci.yml', import.meta.url);

const ordinaryFeatures = [
  'context-relay-core/test-support',
  'context-relay-local-ipc/test-support',
  'context-relay-contextd/test-support',
  'context-relay-context-mcp/test-support',
].join(',');

function job(source, name) {
  const jobsStart = source.indexOf('\njobs:\n');
  assert.notEqual(jobsStart, -1, 'missing jobs map');
  const start = source.indexOf(`\n  ${name}:\n`, jobsStart);
  assert.notEqual(start, -1, `missing independently visible job: ${name}`);
  const remainder = source.slice(start + 1);
  const next = remainder.slice(1).search(/^  [a-zA-Z0-9][a-zA-Z0-9_-]*:\s*$/m);
  return next === -1 ? remainder : remainder.slice(0, next + 1);
}

function assertIndependent(source, names) {
  for (const name of names) {
    const body = job(source, name);
    assert.doesNotMatch(body, /^    needs:/m, `${name} must not wait for another gate`);
  }
}

function assertSupportedHostMatrix(body) {
  assert.match(body, /fail-fast:\s*false/);
  assert.match(body, /include:\s*\n\s+- host:\s*windows-x64\s*\n\s+os:\s*windows-2025/);
  assert.match(body, /- host:\s*macos-arm64\s*\n\s+os:\s*macos-15/);
  assert.equal((body.match(/^\s+- host:/gm) ?? []).length, 2);
  assert.match(body, /RUNNER_ARCH[^\n]+X64/);
  assert.match(body, /uname -m[^\n]+arm64/);
}

test('required CI gates are independently visible and cannot be masked by Rust lint', async () => {
  const source = await readFile(ciWorkflowUrl, 'utf8');
  const required = [
    'rust',
    'rust-lint',
    'rust-tests',
    'daemon-boundary',
    'bindings',
    'schemas',
    'licenses',
    'dependency-policy',
    'whitespace',
    'frontend',
    'native',
  ];
  assertIndependent(source, required);
  for (const name of required) {
    assert.match(
      job(source, name),
      /^    permissions:\s*\n      contents:\s*read$/m,
      `${name} must not inherit actions: read from the native transport boundary`,
    );
  }

  assert.match(job(source, 'rust'), /cargo fmt --all -- --check/);
  assert.match(job(source, 'daemon-boundary'), /node --test scripts\/check-daemon-boundary\.test\.mjs/);
  assert.match(job(source, 'daemon-boundary'), /node scripts\/check-daemon-boundary\.mjs/);
  assert.match(job(source, 'bindings'), /pnpm check:bindings/);
  assert.match(job(source, 'schemas'), /pnpm check:schemas/);
  assert.match(job(source, 'licenses'), /pnpm license:check/);
  assert.match(job(source, 'dependency-policy'), /cargo install cargo-deny --version 0\.20\.2 --locked/);
  assert.match(job(source, 'dependency-policy'), /cargo deny check/);
  assert.match(job(source, 'whitespace'), /git diff --check/);
});

test('strict lint and complete ordinary-feature tests run on both supported hosts', async () => {
  const source = await readFile(ciWorkflowUrl, 'utf8');
  assert.match(
    source,
    new RegExp(`^  ORDINARY_RUST_FEATURES: ${ordinaryFeatures.replaceAll('/', '\\/')}$`, 'm'),
  );

  const lint = job(source, 'rust-lint');
  const tests = job(source, 'rust-tests');
  assertSupportedHostMatrix(lint);
  assertSupportedHostMatrix(tests);
  assert.match(
    lint,
    /cargo clippy --workspace --all-targets --features "\$\{\{ env\.ORDINARY_RUST_FEATURES \}\}" -- -D warnings/,
  );
  assert.match(
    tests,
    /cargo test --workspace --all-targets --features "\$\{\{ env\.ORDINARY_RUST_FEATURES \}\}"/,
  );
  assert.match(
    tests,
    /crates\/native-runner\/tests\/macos-launcher-harness\/Cargo\.toml --test guardian_native -- --nocapture/,
  );
  const apfsMount = tests.indexOf('- name: Mount canonical case-sensitive APFS root');
  const workspaceTests = tests.indexOf('cargo test --workspace --all-targets');
  assert.ok(apfsMount >= 0 && workspaceTests > apfsMount);
  assert.match(tests, /hdiutil create[^\n]+-fs 'Case-sensitive APFS'/);
  assert.match(tests, /CONTEXT_RELAY_CASE_SENSITIVE_APFS_ROOT/);
});

test('the release-candidate verifier stays confined to two exact ignored Semgrep tests', async () => {
  const source = await readFile(ciWorkflowUrl, 'utf8');
  assert.doesNotMatch(source, /--all-features/);
  assert.equal((source.match(/--features ci-candidate-sidecar-smoke/g) ?? []).length, 2);
  assert.match(
    source,
    /real_semgrep_clean_and_finding_use_the_closed_policy[\s\S]+--features ci-candidate-sidecar-smoke \$name -- --ignored --exact/,
  );
  assert.match(
    source,
    /real_sidecar_semgrep_clean_and_finding_use_the_closed_policy[\s\S]+--features ci-candidate-sidecar-smoke --test adapter_native "\$name" -- --ignored --exact/,
  );
});

test('frontend commands are four visible, non-fail-fast matrix gates', async () => {
  const source = await readFile(ciWorkflowUrl, 'utf8');
  const frontend = job(source, 'frontend');
  assert.match(frontend, /fail-fast:\s*false/);
  const gates = [...frontend.matchAll(/- gate:\s*(lint|typecheck|tests|build)\s*\n\s+command:\s*(pnpm [^\n]+)/g)]
    .map(([, gate, command]) => ({ gate, command }));
  assert.deepEqual(gates, [
    { gate: 'lint', command: 'pnpm lint' },
    { gate: 'typecheck', command: 'pnpm typecheck' },
    { gate: 'tests', command: 'pnpm test --run' },
    { gate: 'build', command: 'pnpm build' },
  ]);
  assert.match(frontend, /run:\s*\$\{\{ matrix\.command \}\}/);
});

test('supported native builds are build-only and independent from host tests', async () => {
  const source = await readFile(ciWorkflowUrl, 'utf8');
  const native = job(source, 'native');
  assertSupportedHostMatrix(native);
  assert.match(native, /target:\s*x86_64-pc-windows-msvc/);
  assert.match(native, /target:\s*aarch64-apple-darwin/);
  assert.equal((native.match(/^\s+target:/gm) ?? []).length, 2);
  assert.match(native, /pnpm --filter @context-relay\/desktop tauri build --target \$\{\{ matrix\.target \}\}/);
  assert.doesNotMatch(native, /cargo test|cargo clippy/);
});

test('workflow actions and checkout credentials are immutable and least-privilege', async () => {
  const names = (await readdir(workflowDirectoryUrl))
    .filter((name) => /\.ya?ml$/u.test(name))
    .sort();
  assert.ok(names.length > 0);
  const workflows = await Promise.all(names.map(async (name) => ({
    name,
    source: await readFile(new URL(name, workflowDirectoryUrl), 'utf8'),
  })));

  for (const { name, source } of workflows) {
    const uses = [...source.matchAll(/^\s+(?:-\s+)?uses:\s*(\S+?)(?:\s+#.*)?\s*$/gm)]
      .map((match) => match[1]);
    for (const action of uses) {
      if (action.startsWith('./')) {
        assert.equal(action, './.github/workflows/ci.yml', `${name}: unexpected local workflow`);
      } else {
        assert.match(action, /^[^@\s]+@[0-9a-f]{40}$/, `${name}: mutable action ${action}`);
      }
    }

    const lines = source.split('\n');
    for (let index = 0; index < lines.length; index += 1) {
      const checkout = lines[index].match(/^(\s*)- uses:\s*actions\/checkout@[0-9a-f]{40}/);
      if (!checkout) continue;
      const indent = checkout[1].length;
      let end = index + 1;
      while (end < lines.length && !new RegExp(`^\\s{${indent}}- `).test(lines[end])) end += 1;
      assert.match(
        lines.slice(index, end).join('\n'),
        /persist-credentials:\s*false/,
        `${name}:${index + 1}: checkout credentials must not persist`,
      );
    }
  }

  const ci = workflows.find(({ name }) => name === 'ci.yml')?.source ?? '';
  assert.match(ci, /^permissions:\s*\n  actions:\s*read\s*\n  contents:\s*read$/m);
  assert.equal((ci.match(/contents:\s*write/g) ?? []).length, 1);
  const publication = job(ci, 'request-native-sidecar-publication');
  assert.match(publication, /inputs\.semgrep_release_qualification/);
  assert.match(publication, /github\.ref == 'refs\/heads\/main'/);
  assert.match(publication, /permissions:\s*\n      contents:\s*write/);
  assert.doesNotMatch(ci, /continue-on-error:\s*true/);
});
