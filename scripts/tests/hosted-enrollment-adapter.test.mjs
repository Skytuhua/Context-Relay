import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createSupabaseEnrollmentDependencies } from "../../supabase/functions/enrollment/adapter.mjs";
import { decodeEnrollmentRecord } from "../../supabase/functions/enrollment/record.mjs";
const fixtures = new URL("../../crates/core/tests/fixtures/", import.meta.url);
const vector = JSON.parse(readFileSync(new URL("hosted-enrollment-proof-v1.json", fixtures)));
const record = decodeEnrollmentRecord(Buffer.from(readFileSync(new URL("recovery-enrollment-record-v1.hex", fixtures), "utf8").trim(), "hex"));
function setup() {
  const calls = [], clients = [];
  let claims = { sub: vector.authUserId, session_id: vector.sessionId }, error = null;
  const dependencies = createSupabaseEnrollmentDependencies({
    env: { SUPABASE_URL: "https://example.supabase.co", SUPABASE_PUBLISHABLE_KEY: "public-test", CONTEXT_RELAY_SUPABASE_SECRET_KEY: "server-test" },
    createClient(url, key, options) {
      clients.push({ url, key, options });
      return key === "public-test" ? { auth: { async getClaims(token) {
        calls.push({ token }); return { data: { claims }, error };
      } } } : { async rpc(name, args) { calls.push({ name, args }); return { data: {}, error }; } };
    },
  });
  return { calls, clients, dependencies, setClaims: value => { claims = value; }, setError: value => { error = value; } };
}
test("enrollment derives identity from verified claims and uses isolated clients", async () => {
  const f = setup();
  assert.equal(f.clients.length, 2);
  for (const client of f.clients) assert.deepEqual(client.options.auth, { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false });
  assert.deepEqual(await f.dependencies.authenticate("token"), { userId: vector.authUserId, sessionId: vector.sessionId });
  f.setClaims({ sub: vector.authUserId, user_metadata: { session_id: vector.sessionId } });
  await assert.rejects(f.dependencies.authenticate("token"), /auth_required/);
  f.setError({ message: "private detail" });
  await assert.rejects(f.dependencies.authenticate("token"), /auth_required/);
});
test("enrollment generates server scope and passes canonical fields to the sealed RPCs", async () => {
  const f = setup(), identity = { userId: vector.authUserId, sessionId: vector.sessionId };
  const started = Date.now();
  await f.dependencies.reserve(identity, vector.reservationId);
  const args = f.calls.at(-1).args;
  assert.equal(f.calls.at(-1).name, "service_reserve_enrollment_for_session");
  for (const field of ["p_account_id", "p_workspace_id"]) {
    assert.match(args[field], /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    const timestamp = Number.parseInt(args[field].replaceAll("-", "").slice(0, 12), 16);
    assert.ok(timestamp >= started && timestamp <= Date.now());
  }
  assert.notEqual(args.p_account_id, args.p_workspace_id);
  assert.match(args.p_nonce, /^\\x[0-9a-f]{64}$/);
  await f.dependencies.status(identity, vector.reservationId);
  assert.equal(f.calls.at(-1).name, "service_enrollment_status_for_session");
  await f.dependencies.commit(identity, vector.reservationId, Buffer.from(vector.nonce, "hex"), record);
  const commit = f.calls.at(-1);
  assert.equal(commit.name, "service_commit_enrollment_for_session");
  assert.equal(Object.keys(commit.args).length, 18);
  assert.equal(commit.args.p_auth_user_id, vector.authUserId);
  assert.equal(commit.args.p_session_id, vector.sessionId);
  assert.equal(commit.args.p_encrypted_metadata, "\\x" + Buffer.from(record.encryptedMetadata).toString("hex"));
  assert.equal(commit.args.p_canonical_record, "\\x" + Buffer.from(record.canonicalRecord).toString("hex"));
  f.setError({ message: "private SQL detail" });
  await assert.rejects(f.dependencies.status(identity, vector.reservationId), /^Error: transient$/);
});
