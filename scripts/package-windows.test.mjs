import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { stageWindowsCompanions, windowsReleaseEnvironment } from './package-windows.mjs';

test('release builds statically link the CRT for companions and desktop', () => {
  const env = windowsReleaseEnvironment({ PATH: 'build-tools' }, 'C:/target');
  assert.equal(env.CARGO_ENCODED_RUSTFLAGS, '-Ctarget-feature=+crt-static');
  assert.equal(env.CARGO_TARGET_DIR, 'C:/target');
  assert.equal(env.PATH, 'build-tools');
});

test('release flags preserve plain rustflags before enforcing static CRT', () => {
  const env = windowsReleaseEnvironment({ RUSTFLAGS: '-D warnings -Ctarget-feature=-crt-static' }, 'C:/target');
  assert.deepEqual(env.CARGO_ENCODED_RUSTFLAGS.split('\x1f'), [
    '-D', 'warnings', '-Ctarget-feature=-crt-static', '-Ctarget-feature=+crt-static',
  ]);
});

test('encoded rustflags retain argument boundaries and precedence over plain flags', () => {
  const env = windowsReleaseEnvironment({
    CARGO_ENCODED_RUSTFLAGS: '-L\x1fC:/path with spaces',
    RUSTFLAGS: 'ignored',
  }, 'C:/target');
  assert.deepEqual(env.CARGO_ENCODED_RUSTFLAGS.split('\x1f'), [
    '-L', 'C:/path with spaces', '-Ctarget-feature=+crt-static',
  ]);
});

const names = [
  'context-relay-contextd',
  'context-relay-context-mcp',
  'context-relay-native-helper',
  'context-relay-sidecar-installer',
];
const expectedFiles = [
  'context-relay-context-mcp-x86_64-pc-windows-msvc.exe',
  'context-relay-contextd-x86_64-pc-windows-msvc.exe',
  'context-relay-native-helper-x86_64-pc-windows-msvc.exe',
  'context-relay-sidecar-installer-x86_64-pc-windows-msvc.exe',
];

// Minimal PE headers exercise the assembly gate, not Windows loader acceptance.
function peFixture(machine = 0x8664) {
  const bytes = Buffer.alloc(256);
  bytes.write('MZ');
  bytes.writeUInt32LE(128, 0x3c);
  bytes.write('PE\0\0', 128);
  bytes.writeUInt16LE(machine, 132);
  return bytes;
}

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'context-relay-package-windows-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const sourceDirectory = join(root, 'release');
  const stagingDirectory = join(root, 'staging');
  await mkdir(sourceDirectory);
  for (const name of names) {
    await writeFile(join(sourceDirectory, `${name}.exe`), peFixture());
  }
  return { sourceDirectory, stagingDirectory };
}

test('missing companion fails before staging any binaries', async (t) => {
  const paths = await fixture(t);
  await rm(join(paths.sourceDirectory, 'context-relay-sidecar-installer.exe'));
  await assert.rejects(stageWindowsCompanions(paths), /context-relay-sidecar-installer.*ENOENT/);
  await assert.rejects(readdir(paths.stagingDirectory), { code: 'ENOENT' });
});

for (const [label, bytes] of [
  ['non-PE', Buffer.from('not a Windows executable')],
  ['missing DOS signature', (() => { const b = peFixture(); b.write('XX'); return b; })()],
  ['missing PE signature', (() => { const b = peFixture(); b.write('XX', 128); return b; })()],
  ['out-of-bounds PE offset', (() => { const b = peFixture(); b.writeUInt32LE(0xffffffff, 0x3c); return b; })()],
  ['truncated COFF header', peFixture().subarray(0, 140)],
  ['x86 architecture', peFixture(0x14c)],
  ['ARM64 architecture', peFixture(0xaa64)],
]) {
  test(`${label} companion fails without replacing prior staged output`, async (t) => {
    const paths = await fixture(t);
    await mkdir(paths.stagingDirectory);
    const priorPath = join(paths.stagingDirectory, expectedFiles[0]);
    await writeFile(priorPath, 'prior output');
    await writeFile(join(paths.sourceDirectory, 'context-relay-sidecar-installer.exe'), bytes);
    await assert.rejects(stageWindowsCompanions(paths), /context-relay-sidecar-installer.*(PE|AMD64)/);
    assert.equal(await readFile(priorPath, 'utf8'), 'prior output');
    assert.deepEqual(await readdir(paths.stagingDirectory), [expectedFiles[0]]);
  });
}

test('valid companions stage exactly the four target-suffixed files, ignoring unrelated Cargo output', async (t) => {
  const paths = await fixture(t);
  await writeFile(join(paths.sourceDirectory, 'unrelated.exe'), 'unrelated');
  await stageWindowsCompanions(paths);
  assert.deepEqual((await readdir(paths.stagingDirectory)).sort(), expectedFiles);
  for (const name of names) {
    assert.deepEqual(
      await readFile(join(paths.stagingDirectory, `${name}-x86_64-pc-windows-msvc.exe`)),
      await readFile(join(paths.sourceDirectory, `${name}.exe`)),
    );
  }
});
