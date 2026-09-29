import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const indexUrl = new URL("../../supabase/functions/sync/index.ts", import.meta.url);
const configUrl = new URL("../../supabase/config.toml", import.meta.url);

test("the sync Edge entrypoint pins supabase-js and delegates to the tested core", async () => {
  const source = await readFile(indexUrl, "utf8");

  assert.match(source, /npm:@supabase\/supabase-js@2\.112\.0/);
  assert.match(source, /createSupabaseSyncDependencies/);
  assert.match(source, /createSyncEdgeHandler/);
  assert.match(source, /Deno\.serve\(handler\)/);
  assert.doesNotMatch(source, /console\.(?:log|debug|info|warn|error)/);
  assert.doesNotMatch(source, /SUPABASE_SERVICE_ROLE_KEY/);
});

test("platform JWT verification is disabled only because verified getClaims runs in code", async () => {
  const config = await readFile(configUrl, "utf8");

  assert.match(config, /\[functions\.sync\][\s\S]*?verify_jwt\s*=\s*false/);
});
