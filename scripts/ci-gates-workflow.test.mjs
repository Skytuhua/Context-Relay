import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { access, mkdir, mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import test from 'node:test';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRequire } from 'node:module';

const desktopRequire = createRequire(new URL('../apps/desktop/package.json', import.meta.url));
const { load: parseYaml } = createRequire(desktopRequire.resolve('eslint'))('js-yaml');

const workflowDirectoryUrl = new URL('../.github/workflows/', import.meta.url);
const ciWorkflowUrl = new URL('../.github/workflows/ci.yml', import.meta.url);

const ordinaryFeatures = [
  'context-relay-core/test-support',
  'context-relay-local-ipc/test-support',
  'context-relay-contextd/test-support',
  'context-relay-context-mcp/test-support',
].join(',');
const checkoutNode24 = 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1';
const setupNode24 = 'actions/setup-node@820762786026740c76f36085b0efc47a31fe5020';

// These checked-in conditions use the common JS/Actions boolean and JSON subset.
function evaluate(expression, { inputs = {}, needs = {}, github = {}, cancelled = false } = {}) {
  if (typeof expression !== 'string') return expression;
  assert.match(expression, /^\$\{\{[\s\S]+\}\}$/);
  const body = expression.slice(3, -2).replace(/needs\.([a-z][a-z0-9-]*)/g, 'needs["$1"]');
  return Function('inputs', 'needs', 'github', 'fromJSON', 'always', 'cancelled', `return (${body})`)(
    inputs, needs, github, JSON.parse, () => true, () => cancelled,
  );
}

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
  const rows = evaluate(Object.values(parseYaml(body))[0].strategy.matrix.include);
  assert.deepEqual(rows.map(({ host, os }) => ({ host, os })), [
    { host: 'windows-x64', os: 'windows-2025' },
  ]);
  assert.match(body, /RUNNER_ARCH[^\n]+X64/);
  assert.match(body, /uname -m[^\n]+arm64/);
}

function namedStep(body, name) {
  const marker = `      - name: ${name}\n`;
  const start = body.indexOf(marker);
  assert.notEqual(start, -1, `missing workflow step: ${name}`);
  const remainder = body.slice(start);
  const next = remainder.slice(1).search(/^      - /m);
  return next === -1 ? remainder : remainder.slice(0, next + 1);
}

function literalRun(step) {
  const marker = '        run: |\n';
  const start = step.indexOf(marker);
  assert.notEqual(start, -1, 'workflow step must use a literal run block');
  return step
    .slice(start + marker.length)
    .split('\n')
    .map((line) => line.startsWith('          ') ? line.slice(10) : line)
    .join('\n');
}

function git(workspace, ...args) {
  return execFileSync('git', args, { cwd: workspace, encoding: 'utf8' }).trim();
}

function runWhitespaceCheck(script, workspace, event) {
  return spawnSync('/bin/bash', ['--noprofile', '--norc', '-c', script], {
    cwd: workspace,
    encoding: 'utf8',
    env: {
      ...process.env,
      CURRENT_SHA: '',
      EVENT_NAME: '',
      PR_BASE_SHA: '',
      PR_HEAD_SHA: '',
      PUSH_BEFORE_SHA: '',
      ...event,
    },
  });
}

async function initializedRepository(prefix) {
  const workspace = await mkdtemp(join(tmpdir(), prefix));
  git(workspace, 'init', '--quiet');
  git(workspace, 'config', 'user.email', 'ci-contract@example.invalid');
  git(workspace, 'config', 'user.name', 'CI Contract');
  return workspace;
}

test('Windows/shared qualification defers Apple hosts and retains strict dependency gates', async () => {
  const ci = parseYaml(await readFile(ciWorkflowUrl, 'utf8'));
  const caller = parseYaml(await readFile(new URL('semgrep-release-qualification.yml', workflowDirectoryUrl), 'utf8'));
  assert.equal(caller.on.workflow_dispatch.inputs.windows_only.type, 'boolean');
  assert.equal(caller.on.workflow_dispatch.inputs.windows_only.default, false);
  assert.equal(ci.on.workflow_call.inputs.semgrep_windows_only.type, 'boolean');
  assert.equal(ci.on.workflow_call.inputs.semgrep_windows_only.default, false);
  assert.equal(caller.jobs.qualification.with.semgrep_release_qualification, true);
  for (const windowsOnly of [false, true]) {
    assert.equal(evaluate(caller.jobs.qualification.with.semgrep_windows_only, { inputs: { windows_only: windowsOnly } }), windowsOnly);
  }
  const windowsHost = { host: 'windows-x64', os: 'windows-2025' };
  const windowsBuilder = ci.jobs['native-semgrep-windows-x64-builders'];
  const windowsIsolation = ci.jobs['native-isolation-windows-x64'];
  assert.equal(windowsBuilder.needs, 'semgrep-materials');
  assert.deepEqual(windowsIsolation.needs, ['semgrep-materials', 'native-semgrep-windows-x64-builders']);
  assert.deepEqual(ci.jobs['request-native-sidecar-publication'].needs, ['native-isolation-windows-x64', 'native-isolation-macos-arm64']);
  for (const qualification of [false, true]) {
    for (const windowsOnly of [false, true]) {
      const inputs = { semgrep_release_qualification: qualification, semgrep_windows_only: windowsOnly, semgrep_artifact_run_id: '' };
      for (const name of ['rust-lint', 'rust-tests', 'native']) {
        const rows = evaluate(ci.jobs[name].strategy.matrix.include, { inputs });
        const expected = [windowsHost];
        assert.deepEqual(rows, name === 'native'
          ? expected.map((row) => ({ ...row, target: row.host === 'windows-x64' ? 'x86_64-pc-windows-msvc' : 'aarch64-apple-darwin' }))
          : expected, `${name}: qualification=${qualification}, windowsOnly=${windowsOnly}`);
        assert.equal(ci.jobs[name]['runs-on'], '${{ matrix.os }}');
      }
      const needs = Object.fromEntries(Object.keys(ci.jobs).map((name) => [name, { result: 'success', outputs: { changed: 'true', hydration_mode: 'candidate' } }]));
      const context = { inputs, needs, github: { event_name: 'workflow_dispatch', ref: 'refs/heads/main', ref_protected: true } };
      assert.equal(evaluate(windowsBuilder.if, context), true);
      assert.deepEqual(evaluate(windowsBuilder.strategy.matrix.build, context), qualification ? ['a', 'b'] : ['a']);
      assert.equal(evaluate(windowsIsolation.if, context), true);
      for (const name of ['native-semgrep-macos-arm64-builders', 'native-isolation-macos-arm64']) {
        assert.equal(evaluate(ci.jobs[name].if, context), false, `${name} remains deferred`);
      }
      const publication = ci.jobs['request-native-sidecar-publication'].if;
      assert.equal(evaluate(publication, context), false, 'manual dispatch cannot publish');
      assert.equal(evaluate(publication, { ...context, github: { ...context.github, event_name: 'push' } }), qualification && !windowsOnly, 'policy predicate with artificial successful Apple outputs; unreachable while deferred');
      needs['native-semgrep-macos-arm64-builders'].result = 'skipped';
      needs['native-isolation-macos-arm64'] = { result: 'skipped', outputs: {} };
      assert.equal(evaluate(publication, { ...context, github: { ...context.github, event_name: 'push' } }), false, 'deferred Apple jobs cannot qualify public publication');
      assert.equal(evaluate(windowsIsolation.if, context), true, 'Apple skip cannot suppress Windows isolation');
      needs['native-semgrep-windows-x64-builders'].result = 'failure';
      assert.equal(evaluate(windowsIsolation.if, context), false, 'failed Windows builds cannot qualify');
      assert.equal(evaluate(windowsIsolation.if, { ...context, cancelled: true }), false);
      needs['semgrep-materials'].outputs.changed = 'false';
      assert.equal(evaluate(windowsBuilder.if, context), false);
    }
  }
});

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
    'node-dependency-policy',
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
  assert.match(job(source, 'node-dependency-policy'), /node --test scripts\/dependency-policy\.test\.mjs/);
  assert.match(job(source, 'node-dependency-policy'), /pnpm audit --audit-level low/);

  const whitespace = job(source, 'whitespace');
  assert.match(whitespace, /actions\/checkout@[0-9a-f]{40}[\s\S]+fetch-depth:\s*0/);
  assert.doesNotMatch(whitespace, /^\s+- run:\s*git diff --check\s*$/m);
  for (const [name, expression] of [
    ['EVENT_NAME', 'github.event_name'],
    ['PR_BASE_SHA', 'github.event.pull_request.base.sha'],
    ['PR_HEAD_SHA', 'github.event.pull_request.head.sha'],
    ['PUSH_BEFORE_SHA', 'github.event.before'],
    ['CURRENT_SHA', 'github.sha'],
  ]) {
    assert.match(whitespace, new RegExp(`${name}: \\$\\{\\{ ${expression.replaceAll('.', '\\.')} \\}\\}`));
  }
  const check = literalRun(namedStep(whitespace, 'Check committed whitespace'));
  assert.doesNotMatch(check, /\$\{\{/);
  assert.match(check, /\^\[0-9a-f\]\{40\}\$/);
  assert.match(check, /git cat-file -e/);
  assert.match(check, /git diff --check "\$PR_BASE_SHA" "\$PR_HEAD_SHA"/);
  assert.match(check, /git diff --check "\$PUSH_BEFORE_SHA" "\$CURRENT_SHA"/);
  assert.match(check, /git diff-tree -r --check --root/);
});

test('ordinary CI gates use the reviewed Node 24 action revisions', async () => {
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
    'node-dependency-policy',
    'whitespace',
    'frontend',
    'native',
  ];
  for (const name of required) {
    const body = job(source, name);
    assert.match(body, new RegExp(checkoutNode24.replace('/', '\\/')));
    if (body.includes('actions/setup-node@')) {
      assert.match(body, new RegExp(setupNode24.replace('/', '\\/')));
    }
  }
});

test('whitespace gate checks committed event ranges and fails on a real defect', async () => {
  const source = await readFile(ciWorkflowUrl, 'utf8');
  const script = literalRun(namedStep(job(source, 'whitespace'), 'Check committed whitespace'));
  const workspace = await initializedRepository('context-relay-whitespace-range-');
  const rootWorkspace = await initializedRepository('context-relay-whitespace-root-');
  try {
    await writeFile(join(workspace, 'fixture.txt'), 'clean\n');
    git(workspace, 'add', 'fixture.txt');
    git(workspace, 'commit', '--quiet', '-m', 'clean base');
    const base = git(workspace, 'rev-parse', 'HEAD');
    await writeFile(join(workspace, 'fixture.txt'), 'still clean\n');
    git(workspace, 'add', 'fixture.txt');
    git(workspace, 'commit', '--quiet', '-m', 'clean change');
    const cleanHead = git(workspace, 'rev-parse', 'HEAD');
    await writeFile(join(workspace, 'fixture.txt'), 'committed defect  \n');
    git(workspace, 'add', 'fixture.txt');
    git(workspace, 'commit', '--quiet', '-m', 'add trailing whitespace');
    const head = git(workspace, 'rev-parse', 'HEAD');

    const clean = runWhitespaceCheck(script, workspace, {
      EVENT_NAME: 'pull_request',
      PR_BASE_SHA: base,
      PR_HEAD_SHA: cleanHead,
      CURRENT_SHA: head,
    });
    assert.equal(clean.error, undefined, 'clean range check failed to start');
    assert.equal(clean.status, 0, `${clean.stdout}${clean.stderr}`);

    const cases = [
      {
        name: 'pull request',
        event: { EVENT_NAME: 'pull_request', PR_BASE_SHA: base, PR_HEAD_SHA: head, CURRENT_SHA: base },
      },
      {
        name: 'push',
        event: { EVENT_NAME: 'push', PUSH_BEFORE_SHA: base, CURRENT_SHA: head },
      },
      {
        name: 'workflow dispatch',
        event: { EVENT_NAME: 'workflow_dispatch', CURRENT_SHA: head },
      },
    ];
    for (const { name, event } of cases) {
      const result = runWhitespaceCheck(script, workspace, event);
      assert.equal(result.error, undefined, `${name} check failed to start`);
      assert.notEqual(result.status, 0, `${name} check accepted committed trailing whitespace`);
      assert.match(`${result.stdout}${result.stderr}`, /trailing whitespace/, name);
    }

    const invalidCurrent = runWhitespaceCheck(script, workspace, {
      EVENT_NAME: 'pull_request',
      PR_BASE_SHA: base,
      PR_HEAD_SHA: cleanHead,
      CURRENT_SHA: 'A'.repeat(40),
    });
    assert.notEqual(invalidCurrent.status, 0);
    assert.match(`${invalidCurrent.stdout}${invalidCurrent.stderr}`, /CURRENT_SHA.*lowercase 40-hex/i);

    const missing = runWhitespaceCheck(script, workspace, {
      EVENT_NAME: 'pull_request',
      PR_BASE_SHA: 'f'.repeat(40),
      PR_HEAD_SHA: head,
      CURRENT_SHA: head,
    });
    assert.notEqual(missing.status, 0);
    assert.match(`${missing.stdout}${missing.stderr}`, /PR_BASE_SHA.*commit/i);

    const injected = join(workspace, 'injected');
    const invalid = runWhitespaceCheck(script, workspace, {
      EVENT_NAME: 'pull_request',
      PR_BASE_SHA: `$(touch ${injected})`,
      PR_HEAD_SHA: head,
      CURRENT_SHA: head,
    });
    assert.notEqual(invalid.status, 0);
    await assert.rejects(access(injected), { code: 'ENOENT' });

    await mkdir(join(rootWorkspace, 'nested'));
    await writeFile(join(rootWorkspace, 'nested/root.txt'), 'root defect  \n');
    git(rootWorkspace, 'add', 'nested/root.txt');
    git(rootWorkspace, 'commit', '--quiet', '-m', 'root with trailing whitespace');
    const root = git(rootWorkspace, 'rev-parse', 'HEAD');
    const rootResult = runWhitespaceCheck(script, rootWorkspace, {
      EVENT_NAME: 'push',
      PUSH_BEFORE_SHA: '0'.repeat(40),
      CURRENT_SHA: root,
    });
    assert.notEqual(rootResult.status, 0);
    assert.match(`${rootResult.stdout}${rootResult.stderr}`, /trailing whitespace/);
  } finally {
    await Promise.all([
      rm(workspace, { recursive: true, force: true }),
      rm(rootWorkspace, { recursive: true, force: true }),
    ]);
  }
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
  assert.match(tests, /image="\$RUNNER_TEMP\/cr-ws-cs\.sparseimage"/);
  assert.match(tests, /mount="\$RUNNER_TEMP\/cr-ws-cs"/);
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
  assert.deepEqual(evaluate(parseYaml(native).native.strategy.matrix.include).map(({ target }) => target), [
    'x86_64-pc-windows-msvc',
  ]);
  assert.match(native, /pnpm --filter @context-relay\/desktop tauri build --target \$\{\{ matrix\.target \}\}/);
  assert.match(native, /run: pnpm package:macos/);
  assert.match(native, /CONTEXT_RELAY_SEARCH_ASSETS: \$\{\{ runner\.temp \}\}\/macos-search-resources/);
  assert.match(native, /node --test scripts\/package-macos\.test\.mjs/);
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
