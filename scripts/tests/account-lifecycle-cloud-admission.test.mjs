import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import test from "node:test";

const migrationDirectory = new URL("../../supabase/migrations/", import.meta.url);

async function lifecycleMigration() {
  const names = (await readdir(migrationDirectory)).filter((name) =>
    name.endsWith("_account_lifecycle.sql"),
  );
  assert.equal(names.length, 1, "one forward account-lifecycle migration is required");
  return readFile(new URL(names[0], migrationDirectory), "utf8");
}

function functionBody(sql, name) {
  return sql.match(
    new RegExp(`create function (?:public|context_relay_private)\\.${name}\\s*\\([\\s\\S]*?\\n\\$\\$;`, "i"),
  )?.[0];
}

test("account lifecycle temporarily reacquires and then removes table-owner authority", async () => {
  const sql = await lifecycleMigration();

  assert.match(sql, /grant context_relay_rls_owner to current_user with inherit false, set true;/i);
  assert.match(sql, /grant create on schema public to context_relay_rls_owner;/i);
  assert.match(sql, /set local role context_relay_rls_owner;/i);
  assert.match(
    sql,
    /reset role;\s*revoke create on schema public from context_relay_rls_owner;\s*revoke context_relay_rls_owner from current_user;\s*$/i,
  );
});

test("lifecycle RPCs are service-only hardened definers with no client account authority", async () => {
  const sql = await lifecycleMigration();
  for (const name of [
    "service_account_deletion_status_for_session",
    "service_begin_account_deletion_for_session",
    "service_cancel_account_deletion_for_session",
  ]) {
    const body = functionBody(sql, name);
    assert.ok(body, `missing ${name}`);
    assert.match(body, /language plpgsql\s+volatile\s+security definer\s+set search_path = ''/i);
    assert.doesNotMatch(body, /p_account_id/i);
    assert.match(
      sql,
      new RegExp(`revoke all on function public\\.${name}\\([\\s\\S]*?from public, anon, authenticated, service_role;`, "i"),
    );
    assert.match(
      sql,
      new RegExp(`grant execute on function public\\.${name}\\([\\s\\S]*?to service_role;`, "i"),
    );
  }
  assert.doesNotMatch(sql, /grant\s+(?:select|insert|update|delete)[\s\S]*?to service_role/i);
  assert.match(
    sql,
    /revoke all on function public\.service_begin_account_deletion\(uuid\)[\s\S]*?from public, anon, authenticated, service_role;/i,
  );
  assert.match(
    sql,
    /revoke all on function public\.service_cancel_account_deletion\(uuid\)[\s\S]*?from public, anon, authenticated, service_role;/i,
  );
});

test("every lifecycle transition serializes the account and revalidates session authority", async () => {
  const sql = await lifecycleMigration();
  const helper = functionBody(sql, "locked_account_lifecycle_context");
  assert.ok(helper, "a private locked lifecycle context is required");
  const firstBinding = helper.search(/from public\.device_bindings/i);
  const accountLock = helper.search(/from public\.accounts[\s\S]*?for update;/i);
  const secondBinding = helper.lastIndexOf("from public.device_bindings");
  assert.ok(firstBinding >= 0 && accountLock > firstBinding);
  assert.ok(secondBinding > accountLock, "session authority must be refreshed after serialization");
  assert.match(helper, /device_certificates/i);
  assert.match(helper, /control_epoch/i);
  assert.match(helper, /workspace_id\s*=\s*p_workspace_id/i);

  for (const name of [
    "service_account_deletion_status_for_session",
    "service_begin_account_deletion_for_session",
    "service_cancel_account_deletion_for_session",
  ]) {
    assert.match(functionBody(sql, name), /locked_account_lifecycle_context\s*\(/i);
  }
});

test("the exact seven-day projection is assembled only from locked server timestamps", async () => {
  const sql = await lifecycleMigration();

  assert.match(sql, /deletion_requested_at/i);
  assert.match(sql, /deletion_scheduled_for/i);
  assert.match(sql, /interval '7 days'/i);
  assert.match(sql, /requestedAtMs/i);
  assert.match(sql, /purgeDeadlineMs/i);
  assert.match(sql, /extract\s*\(\s*epoch from/i);
  assert.doesNotMatch(sql, /p_requested_at|p_purge_deadline/i);
});

test("the live Auth session is locked without giving the runtime role access to Auth tables", async () => {
  const sql = await lifecycleMigration();
  const bridge = functionBody(sql, "lock_live_account_lifecycle_auth_session");
  assert.ok(bridge, "an exact private Auth-session bridge is required");
  assert.match(bridge, /from auth\.sessions/i);
  assert.match(bridge, /session\.id\s*=\s*p_session_id/i);
  assert.match(bridge, /session\.user_id\s*=\s*p_auth_user_id/i);
  assert.match(bridge, /not_after[\s\S]*clock_timestamp\(\)/i);
  assert.match(bridge, /for share;/i);
  assert.match(functionBody(sql, "locked_account_lifecycle_context"), /lock_live_account_lifecycle_auth_session\(/i);
  assert.doesNotMatch(sql, /grant (?:usage|select)[\s\S]*?on (?:schema auth|(?:table )?auth\.sessions)/i);
  assert.match(sql, /grant execute on function context_relay_private\.lock_live_account_lifecycle_auth_session\(uuid, uuid\)\s*to context_relay_rls_owner;/i);
});

test("lifecycle calls have a durable account-wide budget and post-lock fresh-auth checks", async () => {
  const sql = await lifecycleMigration();
  assert.match(sql, /create table context_relay_private\.account_lifecycle_rate_limits/i);
  assert.match(sql, /account_lifecycle_rate_limits enable row level security/i);
  assert.match(sql, /interval '60 seconds'/i);
  assert.match(sql, /request_count\s*>\s*30/i);
  assert.match(sql, /message = 'rate_limited'/i);
  for (const name of ["service_begin_account_deletion_for_session", "service_cancel_account_deletion_for_session"]) {
    const body = functionBody(sql, name);
    assert.match(body, /p_credential_authenticated_at_seconds bigint/i);
    const lock = body.indexOf("locked_account_lifecycle_context(");
    const fresh = body.indexOf("require_fresh_account_lifecycle_auth(");
    const mutation = body.search(/perform public\.service_(?:begin|cancel)_account_deletion\(/);
    assert.ok(lock >= 0 && fresh > lock && mutation > fresh);
  }
});

test("deletion retries are durable receipts and cannot repeat a transition after an intervening action", async () => {
  const sql = await lifecycleMigration();
  assert.ok(sql.includes("create table context_relay_private.account_lifecycle_receipts"));
  assert.ok(sql.includes("primary key (account_id, request_id)"));
  assert.ok(sql.includes("octet_length(request_id) = 32"));
  for (const name of ["service_begin_account_deletion_for_session", "service_cancel_account_deletion_for_session"]) {
    const body = functionBody(sql, name);
    assert.match(body, /p_request_id bytea/i);
    const lookup = body.indexOf("find_account_lifecycle_receipt(");
    const mutation = body.search(/perform public\.service_(?:begin|cancel)_account_deletion\(/);
    const receipt = body.indexOf("store_account_lifecycle_receipt(");
    assert.ok(lookup >= 0 && mutation > lookup && receipt > mutation);
    assert.match(body, /if receipt is not null then\s*return receipt;/i);
  }
});
