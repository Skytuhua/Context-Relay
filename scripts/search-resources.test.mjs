import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { cp, mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { stageWindowsSearchResources } from './search-resources.mjs';

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
  await assert.rejects(stageWindowsSearchResources({
    modelDirectory: join(root, 'missing-model'), runtimeDirectory: join(root, 'missing-runtime'), stagingDirectory,
  }), /model_optimized\.onnx/);
  assert.deepEqual(await readdir(stagingDirectory), ['prior.txt']);
  assert.equal(await readFile(join(stagingDirectory, 'prior.txt'), 'utf8'), 'prior verified output');
});

const assets = process.env.CONTEXT_RELAY_SEARCH_ASSETS;
test('all real pinned model/runtime files stage byte-for-byte, including the C++ dependencies', { skip: !assets }, async (t) => {
  const { root } = await fixture(t);
  const stagingDirectory = join(root, 'complete');
  await stageWindowsSearchResources({
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
  await assert.rejects(stageWindowsSearchResources({
    modelDirectory: join(resolve(assets), 'bge-small-en-v1.5'), runtimeDirectory, stagingDirectory,
  }), /msvcp140_1\.dll.*hash/i);
  assert.deepEqual(await readdir(stagingDirectory), ['prior.txt']);
  assert.equal(await readFile(join(stagingDirectory, 'prior.txt'), 'utf8'), 'prior verified output');
});
