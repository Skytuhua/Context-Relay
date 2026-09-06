import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  copyFileSync,
  mkdtempSync,
  mkdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

import {
  checkMetadata,
  checkWorkspace,
  findForbiddenPath,
  findInstallationTokenWriterViolations,
} from './check-daemon-boundary.mjs';

test('keeps the real workspace dependency graph behind the daemon boundary', () => {
  assert.deepEqual(checkWorkspace(), []);
});

test('exports daemon authority adapters only with test-support', () => {
  const workspace = resolve(import.meta.dirname, '..');
  const fixture = mkdtempSync(join(tmpdir(), 'context-relay-daemon-api-'));
  try {
    mkdirSync(join(fixture, 'src'));
    writeFileSync(
      join(fixture, 'Cargo.toml'),
      `[package]
name = "context-relay-daemon-api-contract"
version = "0.0.0"
edition = "2024"

[workspace]

[features]
daemon-test-support = ["context-relay-contextd/test-support"]

[dependencies]
context-relay-contextd = { path = ${JSON.stringify(join(workspace, 'crates/contextd'))} }
`,
    );
    copyFileSync(join(workspace, 'Cargo.lock'), join(fixture, 'Cargo.lock'));
    writeFileSync(
      join(fixture, 'src/main.rs'),
      `use context_relay_contextd::test_support::{
    TestCodexBridgeInstallEngine,
    TestCodexBridgeInstallFixture,
    TestCodexBridgeInstallRequest,
    TestDaemonConfig,
    TestNativeMemoryRegistration,
    TestNativeMemorySource,
    TestSetupPlanSummary,
    test_primary_memory_instruction_component,
};

fn main() {
    let _ = std::mem::size_of::<TestCodexBridgeInstallFixture>();
    let _ = std::mem::size_of::<TestCodexBridgeInstallRequest>();
    let _ = std::mem::size_of::<TestNativeMemoryRegistration>();
    let _ = std::mem::size_of::<TestNativeMemorySource>();
    let _ = std::mem::size_of::<TestSetupPlanSummary>();
    let _ = test_primary_memory_instruction_component;
    let _ = TestDaemonConfig::native_memory_preview_complete;
    let _ = TestDaemonConfig::setup_plan_summary;
    let _ = TestDaemonConfig::setup_plan_applied;
    let _ = TestDaemonConfig::native_transaction_committed;
    let _ = TestCodexBridgeInstallEngine::from_request;
}
`,
    );
    const cargoOptions = {
      cwd: fixture,
      encoding: 'utf8',
      env: {
        ...process.env,
        CARGO_TARGET_DIR: join(workspace, 'target/daemon-api-contract'),
      },
      maxBuffer: 16 * 1024 * 1024,
    };
    // Update the copied lock for the fixture package only. `cargo
    // generate-lockfile` would re-resolve every dependency to its latest
    // compatible version, discarding the workspace's pins — tinyvec 1.13.0
    // (published with a no_std `vec!` scoping break) then breaks the build
    // on the runner. `--workspace` adds the fixture while preserving the
    // locked dependency versions.
    const preparedLock = spawnSync('cargo', ['update', '--workspace'], cargoOptions);
    assert.equal(preparedLock.status, 0, preparedLock.stderr);

    const cargo = (features = []) =>
      spawnSync(
        'cargo',
        ['check', '--locked', '--quiet', ...features],
        cargoOptions,
      );

    const production = cargo();
    assert.notEqual(production.status, 0, 'production build exposed test authority');
    for (const symbol of [
      'TestCodexBridgeInstallFixture',
      'TestCodexBridgeInstallRequest',
      'TestNativeMemoryRegistration',
      'TestNativeMemorySource',
      'TestSetupPlanSummary',
      'test_primary_memory_instruction_component',
      'native_memory_preview_complete',
      'setup_plan_summary',
      'setup_plan_applied',
      'native_transaction_committed',
      'from_request',
    ]) {
      assert.match(production.stderr, new RegExp(symbol));
    }

    const testSupport = cargo(['--features', 'daemon-test-support']);
    assert.equal(testSupport.status, 0, testSupport.stderr);

    // Probe this helper alone so another missing authority symbol cannot hide
    // an accidental production export in the combined contract above.
    writeFileSync(
      join(fixture, 'src/main.rs'),
      `use context_relay_contextd::test_support::test_managed_memory_hooks;

fn main() { let _ = test_managed_memory_hooks; }
`,
    );
    const productionHooks = cargo();
    assert.notEqual(productionHooks.status, 0, 'production build exposed managed memory hooks');
    assert.match(
      productionHooks.stderr,
      /error\[E0432\]: unresolved import `context_relay_contextd::test_support::test_managed_memory_hooks`/,
    );
    const testSupportHooks = cargo(['--features', 'daemon-test-support']);
    assert.equal(testSupportHooks.status, 0, testSupportHooks.stderr);
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
});

test('reports the complete forbidden dependency path', () => {
  const metadata = {
    packages: [
      ['desktop', 'context-relay-desktop'],
      ['ipc', 'context-relay-local-ipc'],
      ['core', 'context-relay-core'],
      ['sql', 'rusqlite'],
    ].map(([id, name]) => ({ id, name })),
    resolve: {
      nodes: [
        { id: 'desktop', deps: [{ pkg: 'ipc' }] },
        { id: 'ipc', deps: [{ pkg: 'core' }] },
        { id: 'core', deps: [{ pkg: 'sql' }] },
        { id: 'sql', deps: [] },
      ],
    },
  };

  assert.deepEqual(
    findForbiddenPath(
      metadata,
      'context-relay-desktop',
      new Set(['context-relay-core', 'rusqlite']),
    ),
    ['context-relay-desktop', 'context-relay-local-ipc', 'context-relay-core'],
  );
});

test('accepts a protocol-only client graph', () => {
  const metadata = {
    packages: [
      { id: 'mcp', name: 'context-relay-context-mcp' },
      { id: 'ipc', name: 'context-relay-local-ipc' },
    ],
    resolve: {
      nodes: [
        { id: 'mcp', deps: [{ pkg: 'ipc' }] },
        { id: 'ipc', deps: [] },
      ],
    },
  };

  assert.equal(
    findForbiddenPath(
      metadata,
      'context-relay-context-mcp',
      new Set(['context-relay-core', 'rusqlite']),
    ),
    null,
  );
});

test('enforces forbidden paths and direct client dependencies', () => {
  const metadata = {
    packages: [
      { id: 'ipc', name: 'context-relay-local-ipc' },
      { id: 'mcp', name: 'context-relay-context-mcp' },
      { id: 'desktop', name: 'context-relay-desktop' },
      { id: 'embed', name: 'fastembed' },
      { id: 'keyring', name: 'keyring' },
    ],
    resolve: {
      nodes: [
        { id: 'ipc', deps: [{ pkg: 'embed' }] },
        { id: 'mcp', deps: [] },
        { id: 'desktop', deps: [{ pkg: 'ipc' }, { pkg: 'keyring' }] },
        { id: 'embed', deps: [] },
        { id: 'keyring', deps: [] },
      ],
    },
  };

  assert.deepEqual(checkMetadata(metadata), [
    'forbidden dependency path: context-relay-local-ipc -> fastembed',
    'forbidden dependency path: context-relay-desktop -> context-relay-local-ipc -> fastembed',
    'context-relay-context-mcp must directly depend on context-relay-local-ipc',
    'context-relay-desktop must not directly depend on keyring',
  ]);
});

test('allows client keyring only through the direct local-ipc dependency', () => {
  const metadata = {
    packages: [
      { id: 'ipc', name: 'context-relay-local-ipc' },
      { id: 'mcp', name: 'context-relay-context-mcp' },
      { id: 'desktop', name: 'context-relay-desktop' },
      { id: 'keyring', name: 'keyring' },
    ],
    resolve: {
      nodes: [
        { id: 'ipc', deps: [{ pkg: 'keyring' }] },
        { id: 'mcp', deps: [{ pkg: 'ipc' }] },
        { id: 'desktop', deps: [{ pkg: 'ipc' }] },
        { id: 'keyring', deps: [] },
      ],
    },
  };

  assert.deepEqual(checkMetadata(metadata), []);
});

test('allows only contextd to write the installation-token credential', () => {
  assert.deepEqual(
    findInstallationTokenWriterViolations({
      'crates/contextd/src/lib.rs':
        'INSTALLATION_TOKEN_CREDENTIAL_ACCOUNT).set_secret(token)',
      'crates/core/src/vault.rs': 'entry.set_secret(vault_key)',
    }),
    [],
  );
  assert.deepEqual(
    findInstallationTokenWriterViolations({
      'crates/contextd/src/lib.rs':
        'INSTALLATION_TOKEN_CREDENTIAL_ACCOUNT).set_secret(token)',
      'crates/local-ipc/src/auth.rs':
        'INSTALLATION_TOKEN_CREDENTIAL_ACCOUNT).set_secret(token)',
    }),
    [
      'installation-token credential writer outside contextd: crates/local-ipc/src/auth.rs',
    ],
  );
  assert.deepEqual(
    findInstallationTokenWriterViolations({
      'crates/local-ipc/src/auth.rs':
        'pub const INSTALLATION_TOKEN_CREDENTIAL_ACCOUNT: &str = "installation-token-v1";',
    }),
    ['missing contextd installation-token credential writer'],
  );
});
