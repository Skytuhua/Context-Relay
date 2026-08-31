import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import test from "node:test";

const migrationDirectory = new URL("../../supabase/migrations/", import.meta.url);

async function admissionMigration() {
  const names = (await readdir(migrationDirectory)).filter((name) =>
    name.endsWith("_signed_sync_cloud_admission.sql"),
  );
  assert.equal(names.length, 1, "one forward signed-sync admission migration is required");
  return readFile(new URL(names[0], migrationDirectory), "utf8");
}

test("cloud admission acquires and releases the existing table-owner role", async () => {
  const sql = await admissionMigration();

  const ownerGrant = sql.search(
    /grant context_relay_rls_owner to current_user with inherit false, set true;/i,
  );
  const publicCreateGrant = sql.search(
    /grant create on schema public to context_relay_rls_owner;/i,
  );
  const ownerRole = sql.search(/set local role context_relay_rls_owner;/i);
  const firstTableAlter = sql.search(/alter table public\.sync_operations/i);

  assert.ok(ownerGrant >= 0, "the migration runner must reacquire SET authority");
  assert.ok(publicCreateGrant > ownerGrant, "function creation authority must be explicit");
  assert.ok(ownerRole > publicCreateGrant && ownerRole < firstTableAlter);
  assert.match(
    sql,
    /reset role;\s*revoke create on schema public from context_relay_rls_owner;\s*revoke context_relay_rls_owner from current_user;\s*$/i,
    "temporary migration authority must be removed at the transaction boundary",
  );
});

test("cloud admission has one service-only identity and append boundary", async () => {
  const sql = await admissionMigration();

  assert.match(sql, /create function public\.service_sync_identity_context\s*\(/i);
  assert.match(sql, /create function public\.service_append_sync_operations\s*\(/i);
  assert.match(sql, /security definer/gi);
  assert.match(sql, /set search_path = ''/gi);
  assert.match(
    sql,
    /revoke all on function public\.service_sync_identity_context\([\s\S]*?from public, anon, authenticated, service_role;/i,
  );
  assert.match(
    sql,
    /revoke all on function public\.service_append_sync_operations\([\s\S]*?from public, anon, authenticated, service_role;/i,
  );
  assert.match(
    sql,
    /grant execute on function public\.service_sync_identity_context\([\s\S]*?to service_role;/i,
  );
  assert.match(
    sql,
    /grant execute on function public\.service_append_sync_operations\([\s\S]*?to service_role;/i,
  );
  assert.doesNotMatch(sql, /grant\s+(?:select|insert|update|delete)[\s\S]*?to service_role/i);
});

test("append revalidates JWT identity, binding, certificate, epochs, chain, replay, and quota", async () => {
  const sql = await admissionMigration();

  for (const required of [
    "p_auth_user_id",
    "p_session_id",
    "device_bindings",
    "device_certificates",
    "control_epoch",
    "key_epoch",
    "device_sequence",
    "previous_device_hash",
    "canonical_sha256",
    "quota_limit_bytes",
  ]) {
    assert.match(sql, new RegExp(required, "i"), `missing ${required} admission check`);
  }
  assert.match(sql, /jsonb_array_length\(p_operations\)\s+between\s+1\s+and\s+256/i);
  assert.match(sql, /for update/i);
  assert.match(sql, /on conflict \(id\) do nothing/i);
  assert.match(sql, /duplicate_operation_mismatch/i);
  assert.match(sql, /device_sequence_gap/i);
  assert.match(sql, /device_hash_mismatch/i);
  assert.match(sql, /quota_blocked/i);
});

test("every mutating sync boundary locks the account and then revalidates session authority", async () => {
  const sql = await admissionMigration();

  const helper = sql.match(
    /create function context_relay_private\.locked_sync_identity_context\s*\([\s\S]*?\n\$\$;/i,
  )?.[0];
  assert.ok(helper, "a private locked identity helper is required");
  const firstIdentity = helper.search(/public\.service_sync_identity_context\s*\(/i);
  const accountLock = helper.search(/from public\.accounts[\s\S]*?for update;/i);
  const secondIdentity = helper.lastIndexOf("public.service_sync_identity_context(");
  assert.ok(firstIdentity >= 0 && accountLock > firstIdentity, "identity must resolve before locking");
  assert.ok(secondIdentity > accountLock, "authority must be revalidated after the account lock");
  assert.match(
    sql,
    /revoke all on function context_relay_private\.locked_sync_identity_context\([\s\S]*?from public, anon, authenticated, service_role;/i,
  );

  for (const name of [
    "service_reserve_blob_upload_for_session",
    "service_finalize_blob_upload_for_session",
    "service_release_blob_upload_for_session",
    "service_append_sync_operations",
    "service_append_sync_checkpoint",
  ]) {
    const body = sql.match(
      new RegExp(`create function public\\.${name}\\s*\\([\\s\\S]*?\\n\\$\\$;`, "i"),
    )?.[0];
    assert.ok(body, `missing ${name}`);
    assert.match(
      body,
      /context_relay_private\.locked_sync_identity_context\s*\(/i,
      `${name} can write after stale one-time authorization`,
    );
  }
});

test("post-lock identity revalidation uses fresh PostgreSQL snapshots", async () => {
  const sql = await admissionMigration();

  for (const name of ["service_sync_identity_context", "service_sync_session_context"]) {
    const body = sql.match(
      new RegExp(`create function public\\.${name}\\s*\\([\\s\\S]*?\\n\\$\\$;`, "i"),
    )?.[0];
    assert.ok(body, `missing ${name}`);
    assert.match(
      body,
      /language plpgsql\s+volatile\s+security definer/i,
      `${name} must not reuse the calling query's pre-lock STABLE snapshot`,
    );
  }
});

test("every mutating session boundary revalidates identity after the account serialization lock", async () => {
  const sql = await admissionMigration();

  assert.match(
    sql,
    /create function context_relay_private\.locked_sync_identity_context\s*\([\s\S]*?identity_context\s*:=\s*public\.service_sync_identity_context\([\s\S]*?from public\.accounts[\s\S]*?for update;[\s\S]*?identity_context\s*:=\s*public\.service_sync_identity_context\(/i,
    "the identity snapshot must be refreshed after the same account lock used by revocation",
  );
  for (const functionName of [
    "service_reserve_blob_upload_for_session",
    "service_finalize_blob_upload_for_session",
    "service_release_blob_upload_for_session",
    "service_append_sync_operations",
    "service_append_sync_checkpoint",
  ]) {
    const body = sql.match(
      new RegExp(
        `create function public\\.${functionName}\\s*\\([\\s\\S]*?\\n\\$\\$;`,
        "i",
      ),
    )?.[0];
    assert.ok(body, `missing ${functionName}`);
    assert.match(
      body,
      /context_relay_private\.locked_sync_identity_context\s*\(/i,
      `${functionName} can use a stale pre-revocation identity snapshot`,
    );
  }
  assert.match(
    sql,
    /revoke all on function context_relay_private\.locked_sync_identity_context\([\s\S]*?from public, anon, authenticated, service_role;/i,
  );
});

test("operation and checkpoint rows gain exact canonical hashes and checkpoint v2", async () => {
  const sql = await admissionMigration();

  assert.match(
    sql,
    /alter table public\.sync_operations\s+add column canonical_sha256 bytea/i,
  );
  assert.match(
    sql,
    /alter table public\.sync_checkpoints\s+add column canonical_sha256 bytea/i,
  );
  assert.match(sql, /octet_length\(canonical_sha256\)\s*=\s*32/i);
  assert.match(sql, /sync_checkpoints_schema_version_check[\s\S]*schema_version\s*=\s*2/i);
  assert.match(
    sql,
    /create index sync_checkpoints_account_workspace_received_hash_idx\s+on public\.sync_checkpoints\s*\(account_id, workspace_id, schema_version, received_at, canonical_sha256\)/i,
    "checkpoint cursor pagination requires an exact composite access path",
  );
});

test("serialized appends stamp insertion time so committed rows cannot fall behind a pull cursor", async () => {
  const sql = await admissionMigration();

  assert.match(
    sql,
    /insert into public\.sync_operations\s*\([\s\S]*?canonical_sha256,\s*received_at\s*\)[\s\S]*?operation_canonical_sha256,\s*pg_catalog\.clock_timestamp\(\)/i,
  );
  assert.match(
    sql,
    /insert into public\.sync_checkpoints\s*\([\s\S]*?canonical_sha256,\s*received_at\s*\)[\s\S]*?checkpoint_canonical_sha256,\s*pg_catalog\.clock_timestamp\(\)/i,
  );
});

test("the post-commit hint is a separate service-only private Realtime call", async () => {
  const sql = await admissionMigration();

  assert.match(sql, /create function public\.service_send_sync_hint\s*\(/i);
  assert.match(
    sql,
    /realtime\.send\([\s\S]*jsonb_build_object\('v',\s*1,\s*'kind',\s*'pull_now'\)[\s\S]*'pull_now'[\s\S]*'account:'[\s\S]*':sync'[\s\S]*true/i,
  );
  assert.match(
    sql,
    /revoke all on function public\.service_send_sync_hint\(uuid\)[\s\S]*from public, anon, authenticated, service_role;/i,
  );
  assert.match(
    sql,
    /grant execute on function public\.service_send_sync_hint\(uuid\)[\s\S]*to service_role;/i,
  );
});

test("checkpoint admission is service-only and revalidates identity, epochs, and continuity", async () => {
  const sql = await admissionMigration();

  assert.match(sql, /create function public\.service_append_sync_checkpoint\s*\(/i);
  assert.match(sql, /public\.service_sync_identity_context\s*\(/i);
  for (const required of [
    "p_auth_user_id",
    "p_session_id",
    "schemaVersion",
    "previousCheckpointHash",
    "canonicalSha256",
    "creatorDeviceId",
    "keyEpoch",
    "checkpoint_chain_mismatch",
  ]) {
    assert.match(sql, new RegExp(required, "i"), `missing ${required} checkpoint admission check`);
  }
  assert.match(
    sql,
    /revoke all on function public\.service_append_sync_checkpoint\(uuid, uuid, jsonb\)[\s\S]*from public, anon, authenticated, service_role;/i,
  );
  assert.match(
    sql,
    /grant execute on function public\.service_append_sync_checkpoint\(uuid, uuid, jsonb\)[\s\S]*to service_role;/i,
  );
  assert.match(
    sql,
    /create index sync_checkpoints_account_workspace_previous_hash_idx\s+on public\.sync_checkpoints\s*\(account_id, workspace_id, previous_checkpoint_hash\)/i,
    "checkpoint tip discovery requires a predecessor lookup index",
  );
  assert.match(
    sql,
    /not exists\s*\([\s\S]*child\.previous_checkpoint_hash\s*=\s*candidate\.canonical_sha256[\s\S]*\)/i,
    "checkpoint continuity must select the unreferenced chain tip instead of timestamp order",
  );
  assert.match(
    sql,
    /checkpoint_count\s*>\s*0[\s\S]*coalesce\(pg_catalog\.cardinality\(head_canonical_hashes\),\s*0\)\s*<>\s*1[\s\S]*checkpoint_chain_mismatch/i,
    "missing or branched checkpoint tips must fail closed",
  );
});

test("blob tickets derive ownership from the verified session and expose only exact paths", async () => {
  const sql = await admissionMigration();

  for (const name of [
    "service_sync_session_context",
    "service_reserve_blob_upload_for_session",
    "service_finalize_blob_upload_for_session",
    "service_release_blob_upload_for_session",
  ]) {
    assert.match(sql, new RegExp(`create function public\\.${name}\\s*\\(`, "i"));
    assert.match(
      sql,
      new RegExp(`revoke all on function public\\.${name}\\([\\s\\S]*?from public, anon, authenticated, service_role;`, "i"),
    );
    assert.match(
      sql,
      new RegExp(`grant execute on function public\\.${name}\\([\\s\\S]*?to service_role;`, "i"),
    );
  }
  assert.match(sql, /device_bindings[\s\S]*session_id\s*=\s*p_session_id/i);
  assert.match(sql, /blob_upload_reservations[\s\S]*expected_part_sizes/i);
  assert.match(sql, /00000000\.bin|lpad\([^;]*8[^;]*'0'\)/i);
  assert.match(
    sql,
    /insert into context_relay_private\.blob_upload_reservations[\s\S]*on conflict \(storage_id\) do nothing[\s\S]*returning storage_id into inserted_storage_id/i,
    "a cross-account storage-id race must resolve to a stable conflict without overwriting",
  );
  assert.match(
    sql,
    /if inserted_storage_id is null then[\s\S]*message = 'blob_storage_conflict'/i,
  );
  assert.doesNotMatch(
    sql,
    /create function public\.service_reserve_blob_upload_for_session\([^)]*p_account_id/i,
    "the blob Edge boundary must not accept client account ownership",
  );
});
