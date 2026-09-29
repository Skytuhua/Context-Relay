import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const workspace = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("the desktop packaging icon is a 512px square PNG", async () => {
  const icon = await readFile(
    path.join(workspace, "apps", "desktop", "src-tauri", "icons", "icon.png"),
  );

  assert.deepEqual(icon.subarray(0, 8), Buffer.from("89504e470d0a1a0a", "hex"));
  assert.equal(icon.readUInt32BE(16), 512);
  assert.equal(icon.readUInt32BE(20), 512);
  assert.equal(icon[24], 8);
  assert.equal(icon[25], 6);
});
