import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { validateSupabaseContract } from '../check-supabase-contract.mjs';

const safeConfig = `project_id = "context-relay"

[api]
schemas = ["public", "graphql_public"]

[db]
major_version = 17

[auth]
jwt_expiry = 900

[auth.external.github]
enabled = true
client_id = "env(SUPABASE_AUTH_GITHUB_CLIENT_ID)"
secret = "env(SUPABASE_AUTH_GITHUB_SECRET)"

[storage.buckets.ciphertext]
public = false
file_size_limit = "33554432"
`;

const canonicalMigration = 'supabase/migrations/20260804000000_context_relay_ciphertext_boundary.sql';
const internalExecuteMigration = 'supabase/migrations/20260805170000_revoke_context_relay_internal_execute.sql';
const realtimeVerifier = 'scripts/verify-supabase-realtime.mjs';
const realtimePolicyPattern = /\ncreate policy context_relay_authenticated_sync_hint_read\s+on realtime\.messages\s+for select\s+to authenticated\s+using\s*\([\s\S]*?\n\);\n/i;
const exactRealtimePolicySql = `create policy context_relay_authenticated_sync_hint_read
on realtime.messages
for select
to authenticated
using (
  extension = 'broadcast'
  and (select realtime.topic()) = 'account:'
    || (select context_relay_private.current_read_account_id())::text
    || ':sync'
);`;
const mutateRealtimePolicy = (migration, mutate) => migration.replace(
  realtimePolicyPattern,
  (policy) => mutate(policy),
);

async function fixture(files) {
  const root = await mkdtemp(path.join(tmpdir(), 'context-relay-supabase-contract-'));
  for (const [relativePath, contents] of Object.entries(files)) {
    const target = path.join(root, relativePath);
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, contents);
  }
  return root;
}

const unsafeCases = [
  ['project-id', { 'supabase/config.toml': safeConfig.replace('project_id = "context-relay"', 'project_id = "other-project"') }],
  ['db-major-version', { 'supabase/config.toml': safeConfig.replace('major_version = 17', 'major_version = 16') }],
  ['api-schemas', { 'supabase/config.toml': safeConfig.replace('["public", "graphql_public"]', '["graphql_public", "public"]') }],
  ['private-schema-exposed', { 'supabase/config.toml': safeConfig.replace('"graphql_public"]', '"graphql_public", "context_relay_private"]') }],
  ['jwt-expiry', { 'supabase/config.toml': safeConfig.replace('jwt_expiry = 900', 'jwt_expiry = 901') }],
  ['github-oauth-secret', { 'supabase/config.toml': safeConfig.replace('env(SUPABASE_AUTH_GITHUB_SECRET)', 'not-a-secret') }],
  ['ciphertext-bucket', { 'supabase/config.toml': safeConfig.replace('public = false', 'public = true') }],
  ['ciphertext-bucket', { 'supabase/config.toml': safeConfig.replace('33554432', '33554433') }],
  ['migration-rls', { 'supabase/config.toml': safeConfig, 'supabase/migrations/0001.sql': 'create table public.accounts (id uuid);' }],
  ['migration-grants', { 'supabase/config.toml': safeConfig, 'supabase/migrations/0001.sql': 'alter table public.accounts enable row level security;' }],
  ['migration-session-helpers', { 'supabase/config.toml': safeConfig, 'supabase/migrations/0001.sql': 'alter table public.accounts enable row level security; revoke all on table public.accounts from public;' }],
  ['migration-relations', { 'supabase/config.toml': safeConfig, [canonicalMigration]: 'create schema context_relay_private;' }],
  ['migration-owner', { 'supabase/config.toml': safeConfig, [canonicalMigration]: 'create table public.accounts (id uuid primary key);' }],
  ['migration-private-schema', { 'supabase/config.toml': safeConfig, [canonicalMigration]: 'create role context_relay_rls_owner nologin noinherit;' }],
  ['migration-enums', { 'supabase/config.toml': safeConfig, [canonicalMigration]: 'create schema context_relay_private;' }],
  ['migration-account-scoping', { 'supabase/config.toml': safeConfig, [canonicalMigration]: 'create table public.sync_operations (account_id uuid, workspace_id uuid, device_id uuid, device_certificate_id uuid);' }],
  ['migration-constants', { 'supabase/config.toml': safeConfig, [canonicalMigration]: 'create table public.accounts (quota_limit_bytes bigint);' }],
  ['migration-rls-relations', { 'supabase/config.toml': safeConfig, [canonicalMigration]: 'create table public.accounts (id uuid);' }],
  ['migration-indexes', { 'supabase/config.toml': safeConfig, [canonicalMigration]: 'create table public.device_bindings (account_id uuid, auth_user_id uuid, session_id uuid, device_id uuid);' }],
  ['migration-privilege-reset', { 'supabase/config.toml': safeConfig, [canonicalMigration]: 'create table public.accounts (id uuid);' }],
  ['migration-helper-hardening', { 'supabase/config.toml': safeConfig, [canonicalMigration]: 'create function context_relay_private.current_session_id() returns uuid language sql as $$ select null::uuid $$;' }],
  ['migration-helper-grants', { 'supabase/config.toml': safeConfig, [canonicalMigration]: 'revoke execute on all functions in schema context_relay_private from public;' }],
  ['migration-part-size-validator', { 'supabase/config.toml': safeConfig, [canonicalMigration]: `
    create function context_relay_private.valid_ciphertext_part_sizes(part_sizes jsonb) returns boolean
    language sql immutable as $$ select pg_catalog.jsonb_typeof(part_sizes) = 'array' $$;
    create table public.blob_manifests (ciphertext_part_sizes jsonb check (context_relay_private.valid_ciphertext_part_sizes(ciphertext_part_sizes)));
    create table context_relay_private.blob_upload_reservations (expected_part_sizes jsonb check (context_relay_private.valid_ciphertext_part_sizes(expected_part_sizes)));
  ` }],
  ['migration-read-grants', { 'supabase/config.toml': safeConfig, [canonicalMigration]: 'revoke all on table public.accounts from public, anon, authenticated, service_role;' }],
  ['migration-read-policies', { 'supabase/config.toml': safeConfig, [canonicalMigration]: 'grant select on table public.accounts to authenticated;' }],
  ['migration-service-wrappers', { 'supabase/config.toml': safeConfig, [canonicalMigration]: 'create function public.service_begin_account_deletion(uuid) returns uuid language sql as $$ select null::uuid $$;' }],
  ['identity-helper-arguments', { 'supabase/config.toml': safeConfig, 'supabase/migrations/0001.sql': 'create function context_relay_private.current_read_account_id(user_id uuid) returns uuid language sql as $$ select user_id $$;' }],
  ['storage-predicate-identity-arguments', { 'supabase/config.toml': safeConfig, 'supabase/migrations/0001.sql': 'create function context_relay_private.can_read_ciphertext_object(user_id uuid, bucket_id text) returns boolean language sql as $$ select true $$;' }],
  ['immutable-authenticated-mutation-grant', { 'supabase/config.toml': safeConfig, 'supabase/migrations/0001.sql': 'grant insert on table public.sync_operations to authenticated;' }],
  ['service-role-context-relation-grant', { 'supabase/config.toml': safeConfig, 'supabase/migrations/0001.sql': 'grant select on table public.accounts to service_role;' }],
  ['realtime-context-relation', { 'supabase/config.toml': safeConfig, 'supabase/migrations/0001.sql': 'alter publication supabase_realtime add table public.sync_operations;' }],
  ['signed-url-contract', { 'supabase/config.toml': safeConfig, 'supabase/migrations/0001.sql': 'create function public.make_signed_url() returns text language sql as $$ select \'x\' $$;' }],
  ['signed-url-contract', { 'supabase/config.toml': safeConfig, 'supabase/functions/create-link/index.ts': 'const url = await storage.createSignedUrl(path, 60);' }],
  ['ci-supabase-commands', { 'supabase/config.toml': safeConfig, '.github/workflows/supabase.yml': 'name: Supabase\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: pnpm check:supabase\n' }],
];

test('accepts the minimal safe configuration without a migration', async (t) => {
  const root = await fixture({ 'supabase/config.toml': safeConfig });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.deepEqual(validateSupabaseContract(root), []);
});

test('requires the canonical migration for repository validation', async (t) => {
  const root = await fixture({ 'supabase/config.toml': safeConfig });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root, { requireMigration: true }).some((violation) => violation.ruleId === 'migration-required'));
});

test('repository migration satisfies the complete static contract', () => {
  const root = path.resolve(import.meta.dirname, '../..');
  assert.deepEqual(validateSupabaseContract(root, { requireMigration: true }), []);
});

test('Supabase CI runs both contract suites when the live verifier changes', async (t) => {
  const workflow = await readFile(path.resolve(import.meta.dirname, '../../.github/workflows/supabase.yml'), 'utf8');
  const required = [
    "'scripts/verify-supabase-realtime.mjs'",
    "'scripts/tests/verify-supabase-realtime.test.mjs'",
    'node --test scripts/tests/check-supabase-contract.test.mjs',
    'node --test scripts/tests/verify-supabase-realtime.test.mjs',
  ];

  for (const contract of required) {
    assert.ok(workflow.includes(contract), `workflow is missing ${contract}`);
    const root = await fixture({
      'supabase/config.toml': safeConfig,
      '.github/workflows/supabase.yml': workflow.replace(contract, ''),
    });
    t.after(() => rm(root, { recursive: true, force: true }));
    assert.ok(
      validateSupabaseContract(root).some((violation) => violation.ruleId === 'ci-supabase-commands'),
      `checker accepted a workflow without ${contract}`,
    );
  }
});

test('Task 7 checker requires owner-scoped revocation for every internal helper', async (t) => {
  const repositoryRoot = path.resolve(import.meta.dirname, '../..');
  const foundation = await readFile(path.join(repositoryRoot, canonicalMigration), 'utf8');
  const repair = await readFile(path.join(repositoryRoot, internalExecuteMigration), 'utf8');
  const weakened = repair.replace(
    '  context_relay_private.charge_sync_operation_bytes()\n',
    '',
  );
  assert.notEqual(weakened, repair);

  const root = await fixture({
    'supabase/config.toml': safeConfig,
    [canonicalMigration]: foundation,
    [internalExecuteMigration]: weakened,
  });
  t.after(() => rm(root, { recursive: true, force: true }));

  assert.ok(
    validateSupabaseContract(root, { requireMigration: true })
      .some((violation) => violation.ruleId === 'migration-internal-function-execute'),
  );

  const temporaryGrant = 'grant context_relay_rls_owner to current_user with inherit false, set true;';
  const finalRevoke = 'revoke context_relay_rls_owner from current_user;';
  const reordered = repair
    .replace(temporaryGrant, '__CONTEXT_RELAY_FINAL_REVOKE__')
    .replace(finalRevoke, temporaryGrant)
    .replace('__CONTEXT_RELAY_FINAL_REVOKE__', finalRevoke);
  assert.notEqual(reordered, repair);

  const reorderedRoot = await fixture({
    'supabase/config.toml': safeConfig,
    [canonicalMigration]: foundation,
    [internalExecuteMigration]: reordered,
  });
  t.after(() => rm(reorderedRoot, { recursive: true, force: true }));

  assert.ok(
    validateSupabaseContract(reorderedRoot, { requireMigration: true })
      .some((violation) => violation.ruleId === 'migration-internal-function-execute'),
  );
});

test('Task 7 owner-role bootstrap is hosted-safe and fails closed', async () => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');

  assert.match(migration, /create role context_relay_rls_owner nologin noinherit/i);
  assert.doesNotMatch(migration, /\balter\s+role\s+context_relay_rls_owner\b/i);
  assert.match(migration, /context_relay_rls_owner has unsafe attributes/i);
  for (const attribute of [
    'rolcanlogin',
    'rolinherit',
    'rolsuper',
    'rolbypassrls',
    'rolcreatedb',
    'rolcreaterole',
    'rolreplication',
  ]) {
    assert.match(migration, new RegExp(`\\b${attribute}\\b`));
  }
  assert.match(
    migration,
    /set local role context_relay_rls_owner;[\s\S]*revoke all on schema context_relay_private from public, anon, authenticated, service_role;[\s\S]*grant usage, create on schema context_relay_private to session_user;[\s\S]*reset role;/i,
  );
  assert.match(
    migration,
    /set local role context_relay_rls_owner;[\s\S]*revoke all on schema context_relay_private from session_user;[\s\S]*reset role;[\s\S]*revoke context_relay_rls_owner from current_user granted by current_user;/i,
  );
  assert.match(
    migration,
    /grant create on schema public to context_relay_rls_owner;[\s\S]*alter table public\.accounts owner to context_relay_rls_owner;[\s\S]*revoke create on schema public from context_relay_rls_owner;[\s\S]*revoke context_relay_rls_owner from current_user granted by current_user;/i,
  );
  assert.match(
    migration,
    /alter table public\.deletion_requests owner to context_relay_rls_owner;[\s\S]*alter table context_relay_private\.blob_upload_reservations owner to context_relay_rls_owner;\s*set local role context_relay_rls_owner;[\s\S]*alter table public\.accounts enable row level security;[\s\S]*reset role;\s*insert into storage\.buckets/i,
  );
});

test('Task 7 uses a least-privilege hosted Auth context bridge', async () => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const bridge = migration.match(
    /create function context_relay_private\.request_auth_context\(\)[\s\S]*?\$auth_context\$\s*;/i,
  )?.[0] ?? '';

  assert.match(bridge, /returns table\s*\(\s*auth_user_id uuid,\s*session_id text\s*\)/i);
  assert.match(bridge, /language sql[\s\S]*stable[\s\S]*security definer[\s\S]*set search_path = ''/i);
  assert.match(bridge, /select auth\.uid\(\), auth\.jwt\(\) ->> 'session_id'/i);
  assert.doesNotMatch(migration, /alter function context_relay_private\.request_auth_context\(\) owner to context_relay_rls_owner/i);
  assert.match(
    migration,
    /revoke all on function context_relay_private\.request_auth_context\(\)\s*from public, anon, authenticated, service_role, context_relay_rls_owner;/i,
  );
  assert.match(
    migration,
    /grant execute on function context_relay_private\.request_auth_context\(\)\s*to context_relay_rls_owner;/i,
  );

  const identityDefinitions = [...migration.matchAll(
    /create function context_relay_private\.(current_(?:session|read_account|write_account|read_device|write_device)_id)\(\)[\s\S]*?\$\$\s*;/gi,
  )];
  assert.equal(identityDefinitions.length, 5);
  for (const [, name] of identityDefinitions) {
    const definition = identityDefinitions.find((match) => match[1] === name)?.[0] ?? '';
    assert.match(definition, /context_relay_private\.request_auth_context\(\)/i);
    assert.doesNotMatch(definition, /auth\.(?:uid|jwt)\(\)/i);
  }
});

test('Task 7 checker rejects an invoker-rights hosted Auth context bridge', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const weakened = migration.replace(
    "create function context_relay_private.request_auth_context()\nreturns table (\n  auth_user_id uuid,\n  session_id text\n)\nlanguage sql\nstable\nsecurity definer",
    "create function context_relay_private.request_auth_context()\nreturns table (\n  auth_user_id uuid,\n  session_id text\n)\nlanguage sql\nstable\nsecurity invoker",
  );
  assert.notEqual(weakened, migration);
  const root = await fixture({ 'supabase/config.toml': safeConfig, [canonicalMigration]: weakened });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-auth-context-bridge'));
});

test('Task 2 foundation omits the premature 16384 part-count ceiling', async () => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  assert.equal(/\b16384\b/.test(migration), false);
});

test('Task 4 freezes the exact immutable sync envelope and quota contract', async () => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  assert.match(migration, /project_id uuid/);
  assert.doesNotMatch(migration, /\bmutation_id\b/);
  assert.match(migration, /device_sequence numeric not null/);
  assert.match(migration, /sync_operations_schema_version_check check \(schema_version = 1\)/);
  assert.match(migration, /sync_operations_device_sequence_check check \(/);
  assert.match(migration, /device_sequence between 0 and 18446744073709551615/);
  assert.match(migration, /sync_operations_control_epoch_check check \(control_epoch between 0 and 4294967295\)/);
  assert.match(migration, /previous_device_hash bytea not null/);
  assert.match(migration, /previous_checkpoint_hash bytea not null/);
  assert.match(migration, /valid_sync_causal_frontier\(causal_frontier\)/);
  assert.match(migration, /valid_sync_blob_refs\(blob_refs\)/);
  assert.match(migration, /valid_hybrid_logical_clock\(created_hlc\)/);
  assert.match(migration, /create trigger sync_operations_charge_quota_before_insert[\s\S]*before insert on public\.sync_operations[\s\S]*charge_sync_operation_bytes\(\)/i);
  for (const index of [
    'sync_operations_account_workspace_received_idx',
    'sync_checkpoints_account_workspace_received_idx',
    'sync_checkpoints_creator_received_idx',
    'sync_checkpoints_causal_frontier_idx',
    'blob_manifests_account_storage_idx',
  ]) {
    assert.match(migration, new RegExp(`create index ${index}\\b`));
  }
});

test('Task 4 preserves canonical sync values without lossy database coercion', async () => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  assert.match(migration, /device_sequence = pg_catalog\.trunc\(device_sequence\)/);
  assert.match(migration, /previous_device_id is not null[\s\S]*device_id_text::pg_catalog\.uuid <= previous_device_id::pg_catalog\.uuid/);
  assert.match(migration, /logical_text !~ '\^\(0\|\[1-9\]\[0-9\]\*\)\$'/);
  assert.match(migration, /U&'\\0009\\000A\\000B\\000C\\000D\\0020/);
});

test('Task 5 freezes quota-safe chunked ciphertext Storage', async () => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');

  assert.match(migration, /create function public\.service_reserve_blob_upload\(\s*p_account_id uuid,\s*p_device_id uuid,\s*p_storage_id uuid,\s*p_ciphertext_sha256 bytea,\s*p_part_sizes bigint\[\],\s*p_expires_at timestamptz\s*\)/i);
  assert.match(migration, /create function public\.service_finalize_blob_upload\(p_storage_id uuid\)/i);
  assert.match(migration, /create function public\.service_release_blob_upload\(\s*p_storage_id uuid,\s*p_terminal_state context_relay_private\.upload_reservation_state\s*\)/i);
  assert.match(migration, /ciphertext_digest bytea not null/);
  assert.match(migration, /blob_upload_reservations_storage_id_key unique \(storage_id\)/);
  assert.match(migration, /blob_manifests_storage_id_key unique \(storage_id\)/);
  assert.match(migration, /jsonb_array_length\(part_sizes\) > 16/);
  assert.match(migration, /part_count between 1 and 16/);
  assert.match(migration, /ambiguous device certificate/i);
  assert.match(migration, /account row first, then the upload reservation/i);
  assert.match(migration, /pg_catalog\.lpad\([^,]+, 8, '0'\) \|\| '\.bin'/);
  assert.match(migration, /jsonb_typeof\(p_metadata -> 'size'\) = 'number'/);
  assert.match(migration, /insert into storage\.buckets[\s\S]*?'ciphertext'[\s\S]*?33554432/i);
  assert.match(migration, /create policy ciphertext_objects_authenticated_insert[\s\S]*?for insert[\s\S]*?to authenticated[\s\S]*?can_upload_ciphertext_object/i);
  assert.match(migration, /create policy ciphertext_objects_authenticated_select[\s\S]*?for select[\s\S]*?to authenticated[\s\S]*?can_read_ciphertext_object[\s\S]*?storage\.allow_only_operation\('storage\.object\.upload'\)[\s\S]*?can_upload_ciphertext_object/i);
  assert.match(migration, /account_row\.deletion_state\s*<>\s*'active'[\s\S]*?binding\.account_id\s*=\s*reservation_row\.account_id[\s\S]*?binding\.device_id\s*=\s*reservation_row\.creator_device_id[\s\S]*?binding\.state\s*=\s*'active'[\s\S]*?binding\.revoked_at\s+is\s+null[\s\S]*?binding\.expires_at/i);
  assert.doesNotMatch(migration, /create policy ciphertext_objects_authenticated_(?:update|delete)/i);
  assert.doesNotMatch(migration, /signed[ _-]?url/i);
});

test('Task 6 freezes the exact receive-only private Realtime hint policy', async () => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  assert.match(migration, /create policy context_relay_authenticated_sync_hint_read\s+on realtime\.messages\s+for select\s+to authenticated\s+using\s*\(\s*extension\s*=\s*'broadcast'\s+and\s+\(select realtime\.topic\(\)\)\s*=\s*'account:'\s*\|\|\s*\(select context_relay_private\.current_read_account_id\(\)\)::text\s*\|\|\s*':sync'\s*\)/i);
  assert.doesNotMatch(migration, /create policy[\s\S]*?on realtime\.messages[\s\S]*?for insert/i);
  assert.doesNotMatch(migration, /(?:grant|revoke)[^;]*on (?:table )?realtime\.messages/i);
});

test('Task 6 checker rejects a missing private Realtime hint policy', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const weakened = migration.replace(realtimePolicyPattern, '\n');
  assert.notEqual(weakened, migration);
  const root = await fixture({ 'supabase/config.toml': safeConfig, [canonicalMigration]: weakened });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-realtime-hint-policy'));
});

for (const [description, mutate] of [
  ['a non-Broadcast extension', (policy) => policy.replace("extension = 'broadcast'", "extension = 'presence'")],
  ['a non-scalar topic lookup', (policy) => policy.replace('(select realtime.topic())', 'realtime.topic()')],
  ['a write-account helper', (policy) => policy.replace('(select context_relay_private.current_read_account_id())', '(select context_relay_private.current_write_account_id())')],
  ['a prefix-match topic predicate', (policy) => policy.replace(/= 'account:'\s*\|\|/, "like 'account:%' ||")],
]) {
  test(`Task 6 checker rejects ${description} in the Realtime policy`, async (t) => {
    const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
    const unsafe = mutateRealtimePolicy(migration, mutate);
    assert.notEqual(unsafe, migration);
    const root = await fixture({ 'supabase/config.toml': safeConfig, [canonicalMigration]: unsafe });
    t.after(() => rm(root, { recursive: true, force: true }));
    assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-realtime-hint-policy'));
  });
}

test('Task 6 checker rejects an authenticated Realtime send policy', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const unsafe = `${migration}\ncreate policy context_relay_authenticated_sync_hint_send on realtime.messages for insert to authenticated with check (extension = 'broadcast');\n`;
  const root = await fixture({ 'supabase/config.toml': safeConfig, [canonicalMigration]: unsafe });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-realtime-hint-policy'));
});

for (const [description, mutate] of [
  ['ALTER POLICY weakening', (migration) => `${migration}\nalter policy context_relay_authenticated_sync_hint_read on realtime.messages using (true);\n`],
  ['DROP POLICY removal', (migration) => `${migration}\ndrop policy context_relay_authenticated_sync_hint_read on realtime.messages;\n`],
  ['uppercase Broadcast literal', (migration) => mutateRealtimePolicy(migration, (policy) => policy.replace("'broadcast'", "'BROADCAST'"))],
]) {
  test(`Task 6 checker rejects ${description}`, async (t) => {
    const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
    const unsafe = mutate(migration);
    assert.notEqual(unsafe, migration);
    const root = await fixture({ 'supabase/config.toml': safeConfig, [canonicalMigration]: unsafe });
    t.after(() => rm(root, { recursive: true, force: true }));
    assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-realtime-hint-policy'));
  });
}

test('Task 6 checker rejects a restrictive real policy hidden by a fake exact policy literal', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const restrictive = mutateRealtimePolicy(
    migration,
    (policy) => policy.replace('\non realtime.messages', '\nas restrictive\non realtime.messages'),
  );
  assert.notEqual(restrictive, migration);
  const unsafe = `${restrictive}\nselect $fake_policy$\n${exactRealtimePolicySql}\n$fake_policy$;\n`;
  const root = await fixture({ 'supabase/config.toml': safeConfig, [canonicalMigration]: unsafe });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-realtime-hint-policy'));
});

test('Task 6 checker rejects a fake exact policy inside a dollar-quoted SQL literal', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const withoutPolicy = migration.replace(realtimePolicyPattern, '\n');
  assert.notEqual(withoutPolicy, migration);
  const unsafe = `${withoutPolicy}\nselect $fake_policy$\n${exactRealtimePolicySql}\n$fake_policy$;\n`;
  const root = await fixture({ 'supabase/config.toml': safeConfig, [canonicalMigration]: unsafe });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-realtime-hint-policy'));
});

test('Task 6 checker rejects an exact policy hidden inside a nested PostgreSQL block comment', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const withoutPolicy = migration.replace(realtimePolicyPattern, '\n');
  assert.notEqual(withoutPolicy, migration);
  const unsafe = `${withoutPolicy}\n/* outer comment\n/* nested comment */\n${exactRealtimePolicySql}\n*/\n`;
  const root = await fixture({ 'supabase/config.toml': safeConfig, [canonicalMigration]: unsafe });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-realtime-hint-policy'));
});

test('Task 6 checker rejects disabling RLS on the Realtime provider table', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const unsafe = `${migration}\nalter table realtime.messages disable row level security;\n`;
  const root = await fixture({ 'supabase/config.toml': safeConfig, [canonicalMigration]: unsafe });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-realtime-hint-policy'));
});

for (const providerMutation of [
  'drop table realtime.messages;',
  'truncate table realtime.messages;',
  "insert into realtime.messages (topic) values ('account:unsafe:sync');",
  "update realtime.messages set topic = 'account:unsafe:sync';",
  'delete from realtime.messages;',
]) {
  test(`Task 6 checker rejects provider-table mutation: ${providerMutation}`, async (t) => {
    const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
    const root = await fixture({
      'supabase/config.toml': safeConfig,
      [canonicalMigration]: `${migration}\n${providerMutation}\n`,
    });
    t.after(() => rm(root, { recursive: true, force: true }));
    assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-realtime-hint-policy'));
  });
}

test('Task 6 checker rejects dynamic Realtime policy DDL inside a PL/pgSQL DO body', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const unsafe = `${migration}\ndo $body$\nbegin\n  execute 'alter policy context_relay_authenticated_sync_hint_read on realtime.messages using (true)';\nend\n$body$;\n`;
  const root = await fixture({ 'supabase/config.toml': safeConfig, [canonicalMigration]: unsafe });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-realtime-hint-policy'));
});

test('Task 6 checker rejects formatted dynamic Realtime policy DDL inside a DO body', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const unsafe = `${migration}\ndo $body$\nbegin\n  execute format('alter policy %I on %I.%I using (true)', 'context_relay_authenticated_sync_hint_read', 'realtime', 'messages');\nend\n$body$;\n`;
  const root = await fixture({ 'supabase/config.toml': safeConfig, [canonicalMigration]: unsafe });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-realtime-hint-policy'));
});

test('Task 6 checker rejects formatted dynamic Realtime table DDL inside a DO body', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const unsafe = `${migration}\ndo $body$\nbegin\n  execute format('alter table %I.%I disable row level security', 'realtime', 'messages');\nend\n$body$;\n`;
  const root = await fixture({ 'supabase/config.toml': safeConfig, [canonicalMigration]: unsafe });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-realtime-hint-policy'));
});

test('Task 6 checker ignores Realtime DDL text inside a nested comment in a DO body', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const safe = `${migration}\ndo $body$\nbegin\n  /* inert outer /* execute 'alter policy context_relay_authenticated_sync_hint_read on realtime.messages using (true)'; */ comment */\n  null;\nend\n$body$;\n`;
  const root = await fixture({ 'supabase/config.toml': safeConfig, [canonicalMigration]: safe });
  t.after(() => rm(root, { recursive: true, force: true }));
  const realtimeRules = validateSupabaseContract(root)
    .filter((violation) => violation.ruleId.startsWith('migration-realtime-hint'));
  assert.deepEqual(realtimeRules, []);
});

for (const privilegeStatement of [
  'grant select on table realtime.messages to authenticated;',
  'revoke insert on realtime.messages from authenticated;',
  'grant select on all tables in schema realtime to authenticated;',
  'revoke insert on all tables in schema "realtime" from authenticated;',
  'grant select on all tables in schema public, realtime to authenticated;',
]) {
  test(`Task 6 checker rejects provider privilege change: ${privilegeStatement}`, async (t) => {
    const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
    const root = await fixture({
      'supabase/config.toml': safeConfig,
      [canonicalMigration]: `${migration}\n${privilegeStatement}\n`,
    });
    t.after(() => rm(root, { recursive: true, force: true }));
    assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-realtime-hint-grants'));
  });
}

test('Task 6 checker ignores provider DDL text stored only as SQL data', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const safe = `${migration}\nselect 'grant select on realtime.messages to authenticated;';\nselect $fake_ddl$drop policy context_relay_authenticated_sync_hint_read on realtime.messages; revoke insert on all tables in schema realtime from authenticated;$fake_ddl$;\n`;
  const root = await fixture({ 'supabase/config.toml': safeConfig, [canonicalMigration]: safe });
  t.after(() => rm(root, { recursive: true, force: true }));
  const realtimeRules = validateSupabaseContract(root)
    .filter((violation) => violation.ruleId.startsWith('migration-realtime-hint'));
  assert.deepEqual(realtimeRules, []);
});

for (const [description, mutate] of [
  ['event', (source) => source.replace("event: 'sync_hint'", "event: 'record_changed'")],
  ['uppercase event', (source) => source.replace("event: 'sync_hint'", "event: 'SYNC_HINT'")],
  ['version', (source) => source.replace('version: 1', 'version: 2')],
  ['kind', (source) => source.replace("kind: 'pull_now'", "kind: 'push_now'")],
  ['uppercase kind', (source) => source.replace("kind: 'pull_now'", "kind: 'PULL_NOW'")],
  ['private flag', (source) => source.replace('private: true', 'private: false')],
  ['arbitrary payload field', (source) => source.replace("kind: 'pull_now'", "kind: 'pull_now', extra: true")],
  ['operation ID', (source) => source.replace("kind: 'pull_now'", "kind: 'pull_now', operationId: 'opaque'")],
  ['device ID', (source) => source.replace("kind: 'pull_now'", "kind: 'pull_now', deviceId: 'opaque'")],
  ['record ID', (source) => source.replace("kind: 'pull_now'", "kind: 'pull_now', recordId: 'opaque'")],
  ['project ID', (source) => source.replace("kind: 'pull_now'", "kind: 'pull_now', projectId: 'opaque'")],
  ['ciphertext', (source) => source.replace("kind: 'pull_now'", "kind: 'pull_now', ciphertext: 'opaque'")],
  ['title', (source) => source.replace("kind: 'pull_now'", "kind: 'pull_now', title: 'opaque'")],
  ['deletion state', (source) => source.replace("kind: 'pull_now'", "kind: 'pull_now', deletionState: 'active'")],
  ['topic construction', (source) => source.replace('return `account:${accountId}:sync`;', 'return `account:${accountId}:sync:extra`;')],
]) {
  test(`Task 6 checker rejects a changed Realtime hint ${description}`, async (t) => {
    const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
    const verifier = await readFile(path.resolve(import.meta.dirname, '../../', realtimeVerifier), 'utf8');
    const unsafe = mutate(verifier);
    assert.notEqual(unsafe, verifier);
    const root = await fixture({
      'supabase/config.toml': safeConfig,
      [canonicalMigration]: migration,
      [realtimeVerifier]: unsafe,
    });
    t.after(() => rm(root, { recursive: true, force: true }));
    assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'realtime-hint-contract'));
  });
}

test('Task 6 checker ignores a fake exact contract in a template and rejects the unsafe real export', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const verifier = await readFile(path.resolve(import.meta.dirname, '../../', realtimeVerifier), 'utf8');
  const unsafeReal = verifier.replace("kind: 'pull_now'", "kind: 'pull_now', operationId: 'opaque'");
  assert.notEqual(unsafeReal, verifier);
  const fake = "export const REALTIME_HINT = Object.freeze({ event: 'sync_hint', payload: Object.freeze({ version: 1, kind: 'pull_now' }), private: true });";
  const unsafe = `${unsafeReal}\nconst fakeRealtimeContract = \`${fake}\`;\n`;
  const root = await fixture({
    'supabase/config.toml': safeConfig,
    [canonicalMigration]: migration,
    [realtimeVerifier]: unsafe,
  });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'realtime-hint-contract'));
});

test('Task 6 checker rejects an unsafe real send hidden by a dead exact send', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const verifier = await readFile(path.resolve(import.meta.dirname, '../../', realtimeVerifier), 'utf8');
  const unsafeReal = verifier.replace(
    "event: REALTIME_HINT.event,\n        payload: REALTIME_HINT.payload,",
    "event: 'record_changed',\n        payload: { version: 1, kind: 'pull_now', operationId: 'opaque' },",
  );
  assert.notEqual(unsafeReal, verifier);
  const unsafe = `${unsafeReal}\nfunction deadExactSend() { return serviceChannels[label].send({ type: 'broadcast', event: REALTIME_HINT.event, payload: REALTIME_HINT.payload }); }\n`;
  const root = await fixture({
    'supabase/config.toml': safeConfig,
    [canonicalMigration]: migration,
    [realtimeVerifier]: unsafe,
  });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'realtime-hint-contract'));
});

test('Task 6 checker rejects unsafe real topics hidden by dead exact topicFor calls', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const verifier = await readFile(path.resolve(import.meta.dirname, '../../', realtimeVerifier), 'utf8');
  const unsafeReal = verifier.replace(
    "a: topicFor(state.users.a.accountId),\n      b: topicFor(state.users.b.accountId),",
    "a: `account:${state.users.a.accountId}:sync:extra`,\n      b: `account:${state.users.b.accountId}:sync:extra`,",
  );
  assert.notEqual(unsafeReal, verifier);
  const unsafe = `${unsafeReal}\nfunction deadExactTopics() { return [topicFor(state.users.a.accountId), topicFor(state.users.b.accountId)]; }\n`;
  const root = await fixture({
    'supabase/config.toml': safeConfig,
    [canonicalMigration]: migration,
    [realtimeVerifier]: unsafe,
  });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'realtime-hint-contract'));
});

for (const [channelKind, exactCall] of [
  ['own', 'privateChannel(userClients[label], topics[label])'],
  ['cross-account', 'privateChannel(userClients.a, topics.b)'],
  ['service', 'privateChannel(serviceClient, topics.a)'],
  ['fresh post-revocation', 'privateChannel(freshAClient, topics.a)'],
]) {
  test(`Task 6 checker rejects suffix expansion at an actual ${channelKind} privateChannel call`, async (t) => {
    const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
    const verifier = await readFile(path.resolve(import.meta.dirname, '../../', realtimeVerifier), 'utf8');
    const unsafe = verifier.replace(exactCall, `${exactCall.slice(0, -1)} + ':extra')`);
    assert.notEqual(unsafe, verifier);
    const root = await fixture({
      'supabase/config.toml': safeConfig,
      [canonicalMigration]: migration,
      [realtimeVerifier]: unsafe,
    });
    t.after(() => rm(root, { recursive: true, force: true }));
    assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'realtime-hint-contract'));
  });
}

test('Task 6 checker ignores forbidden field words outside the exported hint contract', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const verifier = await readFile(path.resolve(import.meta.dirname, '../../', realtimeVerifier), 'utf8');
  const unrelated = `${verifier}\n// operationId deviceId recordId projectId ciphertext title deletionState\nfunction describeRecord(recordId, projectId) { return { recordId, projectId }; }\n`;
  const root = await fixture({
    'supabase/config.toml': safeConfig,
    [canonicalMigration]: migration,
    [realtimeVerifier]: unrelated,
  });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.equal(validateSupabaseContract(root).some((violation) => violation.ruleId === 'realtime-hint-contract'), false);
});

test('Task 5 checker rejects a migration without the blob Storage boundary', async (t) => {
  const root = await fixture({
    'supabase/config.toml': safeConfig,
    [canonicalMigration]: 'create schema context_relay_private;',
  });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-blob-storage'));
});

test('Task 5 checker rejects caller execution on Storage service wrappers and predicates', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const unsafe = `${migration}\n
grant execute on function public.service_finalize_blob_upload(uuid) to authenticated;\n
grant execute on function context_relay_private.can_read_ciphertext_object(text,text) to anon;\n`;
  const root = await fixture({ 'supabase/config.toml': safeConfig, [canonicalMigration]: unsafe });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-blob-storage-grants'));
});

test('Task 5 checker rejects authenticated Storage update or delete policies', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const unsafe = `${migration}\n
create policy ciphertext_objects_authenticated_update on storage.objects for update to authenticated using (true) with check (true);\n`;
  const root = await fixture({ 'supabase/config.toml': safeConfig, [canonicalMigration]: unsafe });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-blob-storage-policies'));
});

test('Task 5 checker rejects reserved-object SELECT without the upload operation guard', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const weakened = migration.replace(
    /storage\.allow_only_operation\('storage\.object\.upload'\)\s+and/i,
    'true and',
  );
  assert.notEqual(weakened, migration);
  const root = await fixture({ 'supabase/config.toml': safeConfig, [canonicalMigration]: weakened });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-blob-storage-policies'));
});

test('Task 5 checker rejects finalization without an active account lifecycle check', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const weakened = migration.replace(
    "if account_row.deletion_state <> 'active'::context_relay_private.account_deletion_state then\n    raise exception using errcode = '55000', message = 'account state does not permit blob finalization';\n  end if;",
    "if false then\n    raise exception using errcode = '55000', message = 'account state does not permit blob finalization';\n  end if;",
  );
  assert.notEqual(weakened, migration);
  const root = await fixture({ 'supabase/config.toml': safeConfig, [canonicalMigration]: weakened });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-blob-storage'));
});

test('Task 5 checker rejects finalization without active creator-device revalidation', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const weakened = migration.replace(
    'binding.device_id = reservation_row.creator_device_id',
    'binding.device_id = binding.device_id',
  );
  assert.notEqual(weakened, migration);
  const root = await fixture({ 'supabase/config.toml': safeConfig, [canonicalMigration]: weakened });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-blob-storage'));
});

test('Task 5 checker preserves finalized replay before reserved-upload lifecycle revalidation', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const accountLifecycleCheck = "  if account_row.deletion_state <> 'active'::context_relay_private.account_deletion_state then\n    raise exception using errcode = '55000', message = 'account state does not permit blob finalization';\n  end if;\n";
  let weakened = migration.replace(accountLifecycleCheck, '');
  weakened = weakened.replace(
    "  if reservation_row.state = 'finalized'::context_relay_private.upload_reservation_state then",
    `${accountLifecycleCheck}\n  if reservation_row.state = 'finalized'::context_relay_private.upload_reservation_state then`,
  );
  assert.notEqual(weakened, migration);
  const root = await fixture({ 'supabase/config.toml': safeConfig, [canonicalMigration]: weakened });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-blob-storage'));
});

test('Task 5 public service wrappers coexist with the exact lifecycle wrapper set', () => {
  const root = path.resolve(import.meta.dirname, '../..');
  assert.equal(
    validateSupabaseContract(root, { requireMigration: true })
      .some((violation) => violation.ruleId === 'migration-service-wrappers'),
    false,
  );
});

test('Task 5 checker recognizes account-first locking after a preliminary reservation lookup', () => {
  const root = path.resolve(import.meta.dirname, '../..');
  assert.equal(
    validateSupabaseContract(root, { requireMigration: true })
      .some((violation) => violation.ruleId === 'migration-blob-storage'),
    false,
  );
});

test('rejects an approximate SyncOperationV1 storage shape', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const weakened = migration.replace('  project_id uuid,', '  mutation_id uuid not null,');
  assert.notEqual(weakened, migration);
  const root = await fixture({ 'supabase/config.toml': safeConfig, [canonicalMigration]: weakened });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-sync-envelopes'));
});

test('rejects a fixed-scale device sequence that rounds fractional input', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const weakened = migration.replace(
    /device_sequence numeric(?:\(\s*20\s*,\s*0\s*\))? not null/,
    'device_sequence numeric(20, 0) not null',
  );
  const root = await fixture({ 'supabase/config.toml': safeConfig, [canonicalMigration]: weakened });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-sync-envelopes'));
});

test('rejects an operation quota trigger without an account row lock', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const weakened = migration.replace(
    'where account.id = new.account_id\n  for update;',
    'where account.id = new.account_id;',
  );
  assert.notEqual(weakened, migration);
  const root = await fixture({ 'supabase/config.toml': safeConfig, [canonicalMigration]: weakened });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-operation-quota-trigger'));
});

for (const statement of [
  'alter publication "supabase_realtime" add table "public"."sync_checkpoints";',
  'alter publication supabase_realtime add table only public.sync_operations;',
  'alter publication supabase_realtime add table public.unrelated, only "public"."sync_checkpoints";',
  'alter publication supabase_realtime add table sync_operations;',
]) {
  test(`rejects Context Relay Realtime publication form: ${statement}`, async (t) => {
    const root = await fixture({
      'supabase/config.toml': safeConfig,
      'supabase/migrations/0001.sql': statement,
    });
    t.after(() => rm(root, { recursive: true, force: true }));
    assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'realtime-context-relation'));
  });
}

for (const statement of [
  'alter publication supabase_realtime add tables in schema public;',
  'alter publication "supabase_realtime" set tables in schema unrelated, "context_relay_private";',
  'alter publication supabase_realtime add table public.unrelated, tables in schema "public", unrelated;',
  'ALTER PUBLICATION "supabase_realtime" ADD TABLES IN SCHEMA CURRENT_SCHEMA;',
  'alter publication supabase_realtime SeT TaBlEs In ScHeMa current_schema;',
]) {
  test(`rejects Context Relay Realtime schema publication form: ${statement}`, async (t) => {
    const root = await fixture({
      'supabase/config.toml': safeConfig,
      'supabase/migrations/0001.sql': statement,
    });
    t.after(() => rm(root, { recursive: true, force: true }));
    assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'realtime-context-relation'));
  });
}

test('rejects an extra relation in the canonical migration', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const root = await fixture({
    'supabase/config.toml': safeConfig,
    [canonicalMigration]: `${migration}\ncreate table public.unexpected_context_relay_relation (id uuid);\n`,
  });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-relations'));
});

test('rejects an extra current identity helper', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const root = await fixture({
    'supabase/config.toml': safeConfig,
    [canonicalMigration]: `${migration}\ncreate function context_relay_private.current_untrusted_id() returns uuid language sql stable security definer set search_path = '' as $$ select null::uuid $$;\n`,
  });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-helper-hardening'));
});

test('rejects duplicate constraint names inside a table declaration', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const constraint = 'constraint sync_operations_control_epoch_check check (control_epoch between 0 and 4294967295),';
  const duplicated = migration.replace(constraint, `${constraint}\n  ${constraint}`);
  assert.notEqual(duplicated, migration);
  const root = await fixture({ 'supabase/config.toml': safeConfig, [canonicalMigration]: duplicated });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-duplicate-constraint'));
});

test('rejects duplicate RLS enablement declarations', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const root = await fixture({
    'supabase/config.toml': safeConfig,
    [canonicalMigration]: `${migration}\nalter table public.github_installations enable row level security;\n`,
  });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-rls-relations'));
});

test('accepts supporting unique indexes without redundant prefix indexes', async (t) => {
  let migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  for (const indexName of [
    'device_bindings_account_device_idx',
    'device_certificates_account_idx',
    'pairing_requests_account_idx',
    'recovery_roots_account_idx',
    'github_installations_account_idx',
    'deletion_requests_account_idx',
  ]) {
    migration = migration.replace(new RegExp(`^create index ${indexName}[^\\n]*\\n`, 'm'), '');
  }
  const root = await fixture({ 'supabase/config.toml': safeConfig, [canonicalMigration]: migration });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.equal(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-indexes'), false);
});

test('rejects a supporting unique index with the foreign-key prefix out of order', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const reordered = migration.replace(
    'constraint device_certificates_account_workspace_device_key unique (account_id, workspace_id, device_id),',
    'constraint device_certificates_account_workspace_device_key unique (workspace_id, account_id, device_id),',
  );
  assert.notEqual(reordered, migration);
  const root = await fixture({ 'supabase/config.toml': safeConfig, [canonicalMigration]: reordered });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-indexes'));
});

test('rejects caller execution on a service lifecycle wrapper', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const root = await fixture({
    'supabase/config.toml': safeConfig,
    [canonicalMigration]: `${migration}\ngrant execute on function public.service_begin_account_deletion(uuid) to authenticated;\n`,
  });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-service-wrapper-grants'));
});

test('rejects authenticated access to all public tables', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const root = await fixture({
    'supabase/config.toml': safeConfig,
    [canonicalMigration]: `${migration}\ngrant select on all tables in schema public to authenticated;\n`,
  });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-read-grants'));
});

test('rejects service access to all tables in a quoted private schema', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const root = await fixture({
    'supabase/config.toml': safeConfig,
    [canonicalMigration]: `${migration}\ngrant all privileges on all tables in schema "context_relay_private" to service_role;\n`,
  });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-read-grants'));
});

test('rejects authenticated execution on all public functions', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const root = await fixture({
    'supabase/config.toml': safeConfig,
    [canonicalMigration]: `${migration}\ngrant execute on all functions in schema public to authenticated;\n`,
  });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-service-wrapper-grants'));
});

test('rejects mixed protected roles on all functions in a quoted public schema', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const root = await fixture({
    'supabase/config.toml': safeConfig,
    [canonicalMigration]: `${migration}\ngrant execute on all functions in schema "public" to PUBLIC, anon;\n`,
  });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-service-wrapper-grants'));
});

test('rejects a forbidden relation grant to a quoted client role', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const root = await fixture({
    'supabase/config.toml': safeConfig,
    [canonicalMigration]: `${migration}\ngrant select on table public.pairing_requests to "authenticated";\n`,
  });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-read-grants'));
});

test('rejects a forbidden grant on quoted relation identifiers', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const root = await fixture({
    'supabase/config.toml': safeConfig,
    [canonicalMigration]: `${migration}\ngrant select on table "public"."pairing_requests" to authenticated;\n`,
  });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-read-grants'));
});

test('rejects authenticated relation privileges with grant option', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const root = await fixture({
    'supabase/config.toml': safeConfig,
    [canonicalMigration]: `${migration}\ngrant select on table public.accounts to authenticated with grant option;\n`,
  });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-read-grants'));
});

test('rejects quoted authenticated execution on a service wrapper', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const root = await fixture({
    'supabase/config.toml': safeConfig,
    [canonicalMigration]: `${migration}\ngrant execute on function public.service_begin_account_deletion(uuid) to "authenticated";\n`,
  });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-service-wrapper-grants'));
});

test('rejects mixed service and client execution grantees on a service wrapper', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const root = await fixture({
    'supabase/config.toml': safeConfig,
    [canonicalMigration]: `${migration}\ngrant execute on function public.service_begin_account_deletion(uuid) to service_role, authenticated;\n`,
  });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-service-wrapper-grants'));
});

test('rejects service wrapper execution with grant option', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const root = await fixture({
    'supabase/config.toml': safeConfig,
    [canonicalMigration]: `${migration}\ngrant execute on function public.service_begin_account_deletion(uuid) to service_role with grant option;\n`,
  });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-service-wrapper-grants'));
});

test('rejects an extra authenticated read policy', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const root = await fixture({
    'supabase/config.toml': safeConfig,
    [canonicalMigration]: `${migration}\ncreate policy unexpected_read on public.pairing_requests for select to authenticated using (true);\n`,
  });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-read-policies'));
});

test('rejects a revocation wrapper that does not lock the account first', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const unsafe = migration.replace(
    'from public.accounts as account\n  where account.id = p_account_id\n  for update;',
    'from public.accounts as account\n  where account.id = p_account_id;',
  );
  assert.notEqual(unsafe, migration);
  const root = await fixture({ 'supabase/config.toml': safeConfig, [canonicalMigration]: unsafe });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-service-wrappers'));
});

test('rejects a revocation wrapper that advances an epoch more than once', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const unsafe = migration.replace('control_epoch = account.control_epoch + 1,', 'control_epoch = account.control_epoch + 2,');
  assert.notEqual(unsafe, migration);
  const root = await fixture({ 'supabase/config.toml': safeConfig, [canonicalMigration]: unsafe });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-service-wrappers'));
});

test('rejects a deletion wrapper with a non-seven-day deadline', async (t) => {
  const migration = await readFile(path.resolve(import.meta.dirname, '../../', canonicalMigration), 'utf8');
  const unsafe = migration.replace("transition_time + interval '7 days'", "transition_time + interval '8 days'");
  assert.notEqual(unsafe, migration);
  const root = await fixture({ 'supabase/config.toml': safeConfig, [canonicalMigration]: unsafe });
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === 'migration-service-wrappers'));
});

for (const [ruleId, files] of unsafeCases) {
  test(`rejects ${ruleId}`, async (t) => {
    const root = await fixture(files);
    t.after(() => rm(root, { recursive: true, force: true }));
    assert.ok(validateSupabaseContract(root).some((violation) => violation.ruleId === ruleId));
  });
}
