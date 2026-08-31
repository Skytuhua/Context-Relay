import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const moduleSource = await readFile(new URL("../../crates/core/src/sync/mod.rs", import.meta.url), "utf8");
const transportSource = await readFile(
  new URL("../../crates/core/src/sync/supabase.rs", import.meta.url),
  "utf8",
);

test("the credential-observing HTTP seam exists only behind test-support", () => {
  assert.match(
    moduleSource,
    /#\[cfg\(feature = "test-support"\)\]\s*pub use supabase::\{[\s\S]*SupabaseHttpClient[\s\S]*SupabaseHttpRequest[\s\S]*\};/,
  );
  assert.match(
    transportSource,
    /#\[cfg\(feature = "test-support"\)\]\s*pub fn with_http_client\(/,
  );
  assert.match(
    transportSource,
    /impl Drop for SupabaseHttpRequest[\s\S]*value\.zeroize\(\)/,
  );
});
