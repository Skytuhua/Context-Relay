import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const workflowUrl = new URL(
  '../.github/workflows/supabase.yml',
  import.meta.url,
);

const expectedPaths = [
  'supabase/**',
  'scripts/check-supabase-contract.mjs',
  'scripts/tests/check-supabase-contract.test.mjs',
  'scripts/verify-supabase-realtime.mjs',
  'scripts/tests/verify-supabase-realtime.test.mjs',
  'package.json',
  'pnpm-lock.yaml',
  '.github/workflows/supabase.yml',
];

const databaseOnlyExcludes = [
  'gotrue',
  'realtime',
  'storage-api',
  'imgproxy',
  'kong',
  'mailpit',
  'postgrest',
  'postgres-meta',
  'studio',
  'edge-runtime',
  'logflare',
  'vector',
  'supavisor',
].join(',');

test('Supabase workflow uses least-privilege immutable actions', async () => {
  const source = await readFile(workflowUrl, 'utf8');

  assert.match(source, /^permissions:\s*\n  contents:\s*read$/m);

  const uses = [...source.matchAll(/^\s+- uses:\s*(\S+?)(?:\s+#.*)?\s*$/gm)]
    .map((match) => match[1]);
  assert.deepEqual(uses, [
    'actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683',
    'actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020',
  ]);
  assert.match(
    source,
    /actions\/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n\s+with:\n\s+persist-credentials:\s*false/,
  );
});

test('Supabase workflow uses the repository Node and pnpm toolchain', async () => {
  const source = await readFile(workflowUrl, 'utf8');

  assert.match(
    source,
    /actions\/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020\n\s+with:\n\s+node-version-file:\s*\.node-version/,
  );
  assert.doesNotMatch(source, /pnpm\/action-setup/);
  assert.doesNotMatch(source, /^\s+cache:\s*pnpm\s*$/m);
  assert.equal(
    source.match(/^\s+- run: npm install --global pnpm@11\.9\.0\s*$/gm)?.length ?? 0,
    1,
  );
});

test('Supabase workflow preserves triggers and the local contract lifecycle', async () => {
  const source = await readFile(workflowUrl, 'utf8');
  const packageJson = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));

  const paths = [...source.matchAll(/^\s{6}- '([^']+)'\s*$/gm)]
    .map((match) => match[1]);
  assert.deepEqual(paths, [...expectedPaths, ...expectedPaths]);
  assert.match(source, /SUPABASE_AUTH_GITHUB_CLIENT_ID:\s*local-ci-client-id/);
  assert.match(source, /SUPABASE_AUTH_GITHUB_SECRET:\s*local-ci-secret/);

  const commands = [...source.matchAll(/^\s+- run:\s*(.+)\s*$/gm)]
    .map((match) => match[1]);
  assert.deepEqual(commands.filter(
    (command) => command !== 'npm install --global pnpm@11.9.0',
  ), [
    'pnpm install --frozen-lockfile',
    'pnpm check:supabase',
    'node --test scripts/tests/check-supabase-contract.test.mjs',
    'node --test scripts/tests/verify-supabase-realtime.test.mjs',
    'pnpm supabase:start:ci',
    'pnpm supabase:reset',
    'pnpm supabase:test',
    'pnpm supabase:lint',
  ]);
  assert.match(
    source,
    /^\s+- if:\s*always\(\)\s*\n\s+run:\s*pnpm supabase:stop\s*$/m,
  );
  assert.equal(
    packageJson.scripts['supabase:start:ci'],
    `supabase start --exclude ${databaseOnlyExcludes}`,
  );
  assert.doesNotMatch(packageJson.scripts['supabase:start:ci'], /ignore-health-check|--debug/);
});
