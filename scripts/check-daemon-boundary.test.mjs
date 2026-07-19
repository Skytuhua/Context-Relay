import assert from 'node:assert/strict';
import test from 'node:test';

import {
  checkMetadata,
  findForbiddenPath,
  findInstallationTokenWriterViolations,
} from './check-daemon-boundary.mjs';

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
