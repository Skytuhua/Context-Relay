import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { stageMacCompanions } from './package-macos.mjs';

const names = ['context-relay-contextd', 'context-relay-context-mcp', 'context-relay-native-helper', 'context-relay-sidecar-installer'];
function executable() {
  // A thin arm64 executable header with one load command; not executable code.
  const bytes = Buffer.alloc(40);
  bytes.writeUInt32LE(0xfeedfacf, 0);
  bytes.writeUInt32LE(0x0100000c, 4);
  bytes.writeUInt32LE(2, 12);
  bytes.writeUInt32LE(1, 16);
  bytes.writeUInt32LE(8, 20);
  bytes.writeUInt32LE(8, 36);
  return bytes;
}

test('macOS staging validates all companions before replacing output and preserves executable mode', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'context-relay-mac-package-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const sourceDirectory = join(root, 'source');
  const stagingDirectory = join(root, 'staged');
  await mkdir(sourceDirectory);
  await mkdir(stagingDirectory);
  const prior = join(stagingDirectory, `${names[0]}-aarch64-apple-darwin`);
  await writeFile(prior, 'prior');
  for (const name of names.slice(0, -1)) await writeFile(join(sourceDirectory, name), executable());
  await assert.rejects(stageMacCompanions({ sourceDirectory, stagingDirectory }), /sidecar-installer/);
  const last = join(sourceDirectory, names.at(-1));
  for (const mutate of [
    () => Buffer.from('not Mach-O'),
    b => { b.writeUInt32LE(0x01000007, 4); return b; },
    b => { b.writeUInt32LE(6, 12); return b; },
    b => { b.writeUInt32LE(16, 36); return b; },
    b => { b.writeUInt32LE(2, 16); return b; },
    b => b.subarray(0, 39),
  ]) {
    await writeFile(last, mutate(executable()));
    await assert.rejects(stageMacCompanions({ sourceDirectory, stagingDirectory }), /sidecar-installer.*Mach-O/);
    assert.equal(await readFile(prior, 'utf8'), 'prior');
    assert.equal((await readdir(stagingDirectory)).length, 1);
  }
  await writeFile(last, executable());
  await stageMacCompanions({ sourceDirectory, stagingDirectory });
  assert.deepEqual((await readdir(stagingDirectory)).sort(), names.map(n => `${n}-aarch64-apple-darwin`).sort());
  for (const name of names) {
    const path = join(stagingDirectory, `${name}-aarch64-apple-darwin`);
    assert.deepEqual(await readFile(path), executable());
    if (process.platform !== 'win32') assert.equal((await stat(path)).mode & 0o777, 0o755);
  }
});

test('macOS bundle maps the exact pinned search inputs and all companions', async () => {
  const config = JSON.parse(await readFile(new URL('../apps/desktop/src-tauri/tauri.macos-release.conf.json', import.meta.url)));
  assert.deepEqual(config.bundle.targets, ['app']);
  assert.deepEqual(config.bundle.externalBin, names.map(n => `binaries/${n}`));
  const expected = { '../../../LICENSE': 'LICENSE', '../../../THIRD_PARTY_NOTICES.md': 'THIRD_PARTY_NOTICES.md' };
  for (const [folder, manifest] of [['model', 'bge-small-en-v1.5'], ['runtime', 'onnxruntime-osx-arm64-1.24.2']]) {
    const pins = JSON.parse(await readFile(new URL(`../crates/core/models/${manifest}/manifest.json`, import.meta.url)));
    for (const { file } of pins.artifacts) expected[`resources/search/${folder}/${file}`] = `search/${folder}/${file}`;
  }
  assert.deepEqual(config.bundle.resources, expected);
});
