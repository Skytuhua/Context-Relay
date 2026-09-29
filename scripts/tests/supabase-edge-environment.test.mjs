import assert from "node:assert/strict";
import test from "node:test";
import { readEdgeEnvironment } from "../../supabase/functions/_shared/environment.mjs";

test("Edge Functions read platform key maps and preserve explicit overrides without leaking malformed secrets", () => {
  const values = {
    SUPABASE_URL: "https://example.supabase.co",
    SUPABASE_PUBLISHABLE_KEYS: JSON.stringify({default: "sb_publishable_test"}),
    SUPABASE_SECRET_KEYS: JSON.stringify({default: "sb_secret_test"}),
    CONTEXT_RELAY_PAIRING_PEPPER: "42".repeat(32),
  };
  const read = (extra = {}) => readEdgeEnvironment(name => ({...values, ...extra})[name]);
  assert.deepEqual(read(), {
    SUPABASE_URL: values.SUPABASE_URL,
    SUPABASE_PUBLISHABLE_KEY: "sb_publishable_test",
    CONTEXT_RELAY_SUPABASE_SECRET_KEY: "sb_secret_test",
    CONTEXT_RELAY_PAIRING_PEPPER: values.CONTEXT_RELAY_PAIRING_PEPPER,
  });
  assert.equal(read({CONTEXT_RELAY_SUPABASE_SECRET_KEY: "dedicated-key", SUPABASE_SECRET_KEYS: "invalid"}).CONTEXT_RELAY_SUPABASE_SECRET_KEY, "dedicated-key");
  assert.equal(read({SUPABASE_PUBLISHABLE_KEY: "local-key"}).SUPABASE_PUBLISHABLE_KEY, "local-key");
  assert.equal(read({CONTEXT_RELAY_SUPABASE_SECRET_KEY: ""}).CONTEXT_RELAY_SUPABASE_SECRET_KEY, "");
  for (const invalid of [undefined, "secret-canary", "null", "[]", "{}", '{"default":42}', '{"default":""}']) {
    for (const name of ["SUPABASE_PUBLISHABLE_KEYS", "SUPABASE_SECRET_KEYS"]) {
      assert.throws(() => read({[name]: invalid}), {message: "configuration_error"});
    }
  }
});
