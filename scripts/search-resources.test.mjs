import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { cp, mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { stageSearchResources } from './search-resources.mjs';

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'context-relay-search-resources-專案-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const stagingDirectory = join(root, 'staging');
  await mkdir(stagingDirectory);
  await writeFile(join(stagingDirectory, 'prior.txt'), 'prior verified output');
  return { root, stagingDirectory };
}

test('missing search input fails before replacing existing staged resources', async (t) => {
  const { root, stagingDirectory } = await fixture(t);
  await assert.rejects(stageSearchResources({
    target: 'x86_64-pc-windows-msvc',
    modelDirectory: join(root, 'missing-model'), runtimeDirectory: join(root, 'missing-runtime'), stagingDirectory,
  }), /model_optimized\.onnx/);
  assert.deepEqual(await readdir(stagingDirectory), ['prior.txt']);
  assert.equal(await readFile(join(stagingDirectory, 'prior.txt'), 'utf8'), 'prior verified output');
});

const assets = process.env.CONTEXT_RELAY_SEARCH_ASSETS;
test('all real pinned model/runtime files stage byte-for-byte, including the C++ dependencies', { skip: !assets }, async (t) => {
  const { root } = await fixture(t);
  const stagingDirectory = join(root, 'complete');
  await stageSearchResources({
    target: 'x86_64-pc-windows-msvc',
    modelDirectory: join(resolve(assets), 'bge-small-en-v1.5'), runtimeDirectory: join(resolve(assets), 'runtime'), stagingDirectory,
  });
  const modelNames = ['model_optimized.onnx', 'config.json', 'special_tokens_map.json', 'tokenizer.json', 'tokenizer_config.json'];
  const runtimeNames = ['onnxruntime.dll', 'onnxruntime_providers_shared.dll', 'LICENSE', 'ThirdPartyNotices.txt',
    'vcruntime140.dll', 'vcruntime140_1.dll', 'msvcp140.dll', 'msvcp140_1.dll'];
  for (const [directory, source, names] of [['model', 'bge-small-en-v1.5', modelNames], ['runtime', 'runtime', runtimeNames]]) {
    assert.deepEqual((await readdir(join(stagingDirectory, directory))).sort(), names.sort());
    for (const name of names) {
      const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
      assert.equal(hash(await readFile(join(stagingDirectory, directory, name))), hash(await readFile(join(assets, source, name))));
    }
  }
});

test('a same-size damaged C++ dependency cannot partially replace staged resources', { skip: !assets }, async (t) => {
  const { root, stagingDirectory } = await fixture(t);
  const runtimeDirectory = join(root, 'runtime');
  await cp(join(resolve(assets), 'runtime'), runtimeDirectory, { recursive: true });
  const damaged = join(runtimeDirectory, 'msvcp140_1.dll');
  const bytes = await readFile(damaged);
  bytes[bytes.length - 1] ^= 1;
  await writeFile(damaged, bytes);
  await assert.rejects(stageSearchResources({
    target: 'x86_64-pc-windows-msvc',
    modelDirectory: join(resolve(assets), 'bge-small-en-v1.5'), runtimeDirectory, stagingDirectory,
  }), /msvcp140_1\.dll.*hash/i);
  assert.deepEqual(await readdir(stagingDirectory), ['prior.txt']);
  assert.equal(await readFile(join(stagingDirectory, 'prior.txt'), 'utf8'), 'prior verified output');
});

test('unsupported search targets fail without staging any resources', async (t) => {
  const { root, stagingDirectory } = await fixture(t);
  await assert.rejects(stageSearchResources({
    target: 'x86_64-apple-darwin', modelDirectory: root, runtimeDirectory: root, stagingDirectory,
  }), /Unsupported search target/);
  assert.deepEqual(await readdir(stagingDirectory), ['prior.txt']);
});

const macAssets = process.env.CONTEXT_RELAY_MACOS_SEARCH_ASSETS;
test('macOS arm64 stages its pinned runtime and rejects tampering before changing output', { skip: !assets || !macAssets }, async (t) => {
  const { root, stagingDirectory } = await fixture(t);
  const runtimeDirectory = join(root, 'runtime');
  await cp(join(resolve(macAssets), 'runtime'), runtimeDirectory, { recursive: true });
  const options = {
    target: 'aarch64-apple-darwin', modelDirectory: join(resolve(assets), 'bge-small-en-v1.5'), runtimeDirectory, stagingDirectory,
  };
  await stageSearchResources(options);
  const runtimeNames = ['LICENSE', 'ThirdPartyNotices.txt', 'libonnxruntime.1.24.2.dylib'];
  assert.deepEqual((await readdir(join(stagingDirectory, 'runtime'))).sort(), runtimeNames);
  for (const name of runtimeNames) {
    assert.deepEqual(await readFile(join(stagingDirectory, 'runtime', name)), await readFile(join(runtimeDirectory, name)));
  }
  const damaged = join(runtimeDirectory, 'libonnxruntime.1.24.2.dylib');
  const bytes = await readFile(damaged);
  bytes[bytes.length - 1] ^= 1;
  await writeFile(damaged, bytes);
  await writeFile(join(stagingDirectory, 'model', 'config.json'), 'prior staged model');
  await assert.rejects(stageSearchResources(options), /hash mismatch/);
  assert.equal(await readFile(join(stagingDirectory, 'model', 'config.json'), 'utf8'), 'prior staged model');
  // Selecting macOS cannot accept the Windows runtime directory.
  await assert.rejects(stageSearchResources({ ...options, runtimeDirectory: join(resolve(assets), 'runtime') }), /libonnxruntime/);
});
