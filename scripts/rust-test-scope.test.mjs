import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const workflowUrl = new URL('../.github/workflows/ci.yml', import.meta.url);
const scopeUrl = new URL('./rust-test-scope.mjs', import.meta.url);

function rustSteps(source) {
  const body = source.split('\n  rust-tests:\n')[1]?.split(/\n  [a-z][a-z0-9-]*:\n/u)[0];
  assert.ok(body, 'the required rust-tests job must exist');
  assert.doesNotMatch(body, /^    (?:if|needs):/mu, 'the required job must always report its own result');
  assert.doesNotMatch(body, /continue-on-error:\s*true/u);
  return [...body.matchAll(/^      - [\s\S]*?(?=^      - |(?![\s\S]))/gmu)]
    .map(([step]) => step);
}

function shouldRun(step, runnerOs, output) {
  const expression = step.match(/^(?:      - |        )if: (\$\{\{.+\}\})$/mu)?.[1];
  assert.ok(expression, 'each cargo test step needs an explicit scope condition');
  return Function('runner', 'steps', `return (${expression.slice(3, -2)})`)(
    { os: runnerOs }, { rust_scope: { outputs: { run_tests: output } } },
  );
}

function git(workspace, ...args) {
  return execFileSync('git', args, { cwd: workspace, encoding: 'utf8' }).trim();
}

async function commitFile(workspace, path, content) {
  await mkdir(dirname(join(workspace, path)), { recursive: true });
  await writeFile(join(workspace, path), content);
  git(workspace, 'add', '--', path);
  git(workspace, 'commit', '--quiet', '-m', 'scope fixture');
  return git(workspace, 'rev-parse', 'HEAD');
}

test('workflow connects the scope output to both unchanged cargo test commands', async () => {
  const steps = rustSteps(await readFile(workflowUrl, 'utf8'));
  const scope = steps.find((step) => /run: node scripts\/rust-test-scope\.mjs\s*$/mu.test(step));
  assert.ok(scope, 'the workflow must execute the scope detector');
  assert.match(scope, /^        id: rust_scope$/mu);
  assert.match(scope, /^          EVENT_NAME: \$\{\{ github\.event_name \}\}$/mu);
  assert.match(scope, /^          PR_BASE_SHA: \$\{\{ github\.event\.pull_request\.base\.sha \}\}$/mu);
  assert.match(scope, /^          CURRENT_SHA: \$\{\{ github\.sha \}\}$/mu);
  assert.match(scope, /^          FORCE_RUST_TESTS: \$\{\{ inputs\.semgrep_release_qualification \}\}$/mu);
  assert.match(steps[0], /fetch-depth: 0/u);
  assert.ok(steps.slice(0, steps.indexOf(scope)).some((step) => /run: node --test scripts\/rust-test-scope\.test\.mjs/u.test(step)), 'scope regressions must run in this required job');

  const cargo = steps.filter((step) => /run: cargo test /u.test(step));
  assert.equal(cargo.length, 2);
  const workspace = cargo.find((step) => /cargo test --workspace/u.test(step));
  const guardian = cargo.find((step) => /--test guardian_native/u.test(step));
  assert.ok(workspace && guardian);
  assert.match(workspace, /run: cargo test --workspace --all-targets --features "\$\{\{ env\.ORDINARY_RUST_FEATURES \}\}"\s*$/mu);
  assert.match(guardian, /run: cargo test --manifest-path crates\/native-runner\/tests\/macos-launcher-harness\/Cargo\.toml --test guardian_native -- --nocapture\s*$/mu);
  for (const step of cargo) assert.ok(steps.indexOf(step) > steps.indexOf(scope));
  for (const os of ['Windows', 'macOS', 'Linux']) {
    assert.equal(shouldRun(workspace, os, 'false'), false);
    assert.equal(shouldRun(guardian, os, 'false'), false);
    for (const output of ['true', '', undefined]) {
      assert.equal(shouldRun(workspace, os, output), true);
      assert.equal(shouldRun(guardian, os, output), os === 'macOS');
    }
  }
});

test('only an explicit frontend or documentation path can avoid Rust tests', async () => {
  const { requiresRustTests } = await import(scopeUrl);
  for (const path of [
    'README.md', 'CONTRIBUTING.md', 'docs/verification/example.md',
    'apps/desktop/src/App.tsx', 'apps/desktop/src/styles.css',
    'apps/desktop/src/nested/helper.ts', 'apps/desktop/vite.config.ts',
  ]) assert.equal(requiresRustTests([path]), false, path);
  for (const path of [
    'crates/core/src/lib.rs', 'crates/core/migrations/0001_vault.sql',
    'apps/desktop/src-tauri/tauri.conf.json', 'Cargo.toml', 'Cargo.lock',
    '.cargo/config.toml', 'rust-toolchain.toml', '.github/workflows/ci.yml',
    'third_party/sidecars/manifest.v1.json', 'scripts/package-windows.mjs',
    'schemas/context-relay-package-v1.json', 'supabase/functions/sync/core.mjs',
    'package.json', 'pnpm-lock.yaml', 'apps/desktop/package.json', '.node-version',
    'docs/fixture.json', 'apps/desktop/src/native.rs', 'unknown-input',
    'docs/looks-safe.md\ncrates/core/src/lib.rs',
  ]) assert.equal(requiresRustTests(['README.md', path]), true, path);
});

test('the detector uses real Git changes and defaults to running on uncertain events or history', async () => {
  const { determineRustTestScope } = await import(scopeUrl);
  const workspace = await mkdtemp(join(tmpdir(), 'context-relay-rust-scope-'));
  try {
    git(workspace, 'init', '--quiet');
    git(workspace, 'config', 'user.name', 'CI Contract');
    git(workspace, 'config', 'user.email', 'ci-contract@example.invalid');
    const base = await commitFile(workspace, 'README.md', 'base\n');
    const frontend = await commitFile(workspace, 'apps/desktop/src/App.tsx', 'frontend\n');
    const event = { cwd: workspace, eventName: 'pull_request', baseSha: base, headSha: frontend };
    assert.equal(determineRustTestScope(event).runTests, false);
    assert.equal(determineRustTestScope({ ...event, force: true }).runTests, true);
    for (const eventName of ['push', 'workflow_dispatch', 'workflow_call', '']) {
      assert.equal(determineRustTestScope({ ...event, eventName }).runTests, true, eventName);
    }
    for (const baseSha of ['', '0'.repeat(40), 'f'.repeat(40), 'HEAD', '--all', '$(echo unsafe)']) {
      assert.equal(determineRustTestScope({ ...event, baseSha }).runTests, true, baseSha);
    }
    assert.equal(determineRustTestScope({ ...event, headSha: 'f'.repeat(40) }).runTests, true);
    assert.equal(determineRustTestScope({ ...event, cwd: tmpdir() }).runTests, true);

    const native = await commitFile(workspace, 'crates/core/native-fixture.md', 'native input\n');
    assert.equal(determineRustTestScope({ ...event, headSha: native }).runTests, true);
    await mkdir(join(workspace, 'docs'), { recursive: true });
    await rename(join(workspace, 'crates/core/native-fixture.md'), join(workspace, 'docs/native-fixture.md'));
    git(workspace, 'add', '--all');
    git(workspace, 'commit', '--quiet', '-m', 'move native material to docs');
    const renamed = git(workspace, 'rev-parse', 'HEAD');
    assert.equal(determineRustTestScope({ ...event, baseSha: native, headSha: renamed }).runTests, true, 'the old native path of a rename must remain visible');
    const unknown = await commitFile(workspace, 'unknown-input', 'input\n');
    await rm(join(workspace, 'unknown-input'));
    git(workspace, 'add', '--all');
    git(workspace, 'commit', '--quiet', '-m', 'delete unknown material');
    assert.equal(determineRustTestScope({ ...event, baseSha: unknown, headSha: git(workspace, 'rev-parse', 'HEAD') }).runTests, true, 'native or unknown deletions must run');

    const output = join(workspace, 'step-output');
    const summary = join(workspace, 'step-summary');
    const result = spawnSync(process.execPath, [fileURLToPath(scopeUrl)], {
      cwd: workspace,
      encoding: 'utf8',
      env: { ...process.env, EVENT_NAME: 'pull_request', PR_BASE_SHA: base, CURRENT_SHA: frontend, FORCE_RUST_TESTS: '', GITHUB_OUTPUT: output, GITHUB_STEP_SUMMARY: summary },
    });
    assert.equal(result.error, undefined);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(await readFile(output, 'utf8'), 'run_tests=false\n');
    assert.match(await readFile(summary, 'utf8'), /only frontend or documentation files changed/u);
    const steps = rustSteps(await readFile(workflowUrl, 'utf8'));
    for (const step of steps.filter((step) => /run: cargo test /u.test(step))) {
      assert.equal(shouldRun(step, 'Windows', (await readFile(output, 'utf8')).trim().split('=')[1]), false);
    }
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});
