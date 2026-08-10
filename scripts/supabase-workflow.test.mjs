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

function sqlCallArgumentCounts(source, callName) {
  const counts = [];
  const callPattern = new RegExp(`\\b${callName}\\s*\\(`, 'g');
  for (const match of source.matchAll(callPattern)) {
    let depth = 1;
    let commas = 0;
    let index = match.index + match[0].length;
    while (index < source.length && depth > 0) {
      if (source[index] === "'") {
        for (index += 1; index < source.length; index += 1) {
          if (source[index] !== "'") continue;
          if (source[index + 1] === "'") index += 1;
          else { index += 1; break; }
        }
        continue;
      }
      const dollar = source.slice(index).match(/^\$[A-Za-z0-9_]*\$/)?.[0];
      if (dollar) {
        const close = source.indexOf(dollar, index + dollar.length);
        assert.notEqual(close, -1, `unterminated SQL dollar quote at byte ${index}`);
        index = close + dollar.length;
        continue;
      }
      if (source[index] === '(') depth += 1;
      else if (source[index] === ')') depth -= 1;
      else if (source[index] === ',' && depth === 1) commas += 1;
      index += 1;
    }
    assert.equal(depth, 0, `unterminated ${callName} call at byte ${match.index}`);
    counts.push({
      count: commas + 1,
      line: source.slice(0, match.index).split('\n').length,
    });
  }
  return counts;
}

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

test('Supabase CLI excludes the known current_user role-grant crash', async () => {
  const packageJson = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
  const lockfile = await readFile(new URL('../pnpm-lock.yaml', import.meta.url), 'utf8');

  assert.equal(packageJson.devDependencies.supabase, '2.113.0');
  assert.match(lockfile, /^\s+supabase:\n\s+specifier: 2\.113\.0\n\s+version: 2\.113\.0$/m);
  assert.doesNotMatch(lockfile, /(?:supabase|@supabase\/cli-[^@\s]+)@2\.110\.0/);
});

test('pgTAP runs only the planned suite and compares catalog text with one collation', async () => {
  const packageJson = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
  const suite = await readFile(
    new URL('../supabase/tests/0001_context_relay_ciphertext_boundary_test.sql', import.meta.url),
    'utf8',
  );

  assert.equal(
    packageJson.scripts['supabase:test'],
    'supabase test db supabase/tests/0001_context_relay_ciphertext_boundary_test.sql',
  );
  assert.match(
    suite,
    /select policy\.polname::text collate "C", policy\.polcmd::text collate "C", role_name\.rolname::text collate "C"/,
  );
  assert.match(
    suite,
    /'ciphertext_objects_authenticated_insert'::text collate "C", 'a'::text collate "C", 'authenticated'::text collate "C"/,
  );
  for (const [block] of suite.matchAll(/select results_eq\([\s\S]*?\n\);/g)) {
    assert.doesNotMatch(
      block,
      /::text(?! collate "C")/,
      'every text cast compared by pgTAP must pin the same deterministic collation',
    );
  }
  assert.ok(sqlCallArgumentCounts(suite, 'throws_ok').length > 0);
  assert.ok(
    sqlCallArgumentCounts(suite, 'throws_ok').every(({ count }) => count >= 3),
    `throws_ok descriptions must not occupy the expected-error-message slot: ${JSON.stringify(
      sqlCallArgumentCounts(suite, 'throws_ok').filter(({ count }) => count < 3),
    )}`,
  );

  const membershipAssertion = suite.indexOf(
    "'Context Relay owner has no runtime-capability role memberships'",
  );
  const harnessGrant = suite.indexOf(
    'grant context_relay_rls_owner to current_user with inherit true, set true;',
  );
  const fixtureSeed = suite.indexOf('insert into public.accounts');
  const harnessRevoke = suite.lastIndexOf(
    'revoke context_relay_rls_owner from current_user granted by current_user;',
  );
  const finish = suite.indexOf('select * from finish();');
  assert.ok(membershipAssertion < harnessGrant && harnessGrant < fixtureSeed);
  assert.ok(fixtureSeed < harnessRevoke && harnessRevoke < finish);
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
