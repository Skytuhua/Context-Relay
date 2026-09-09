import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { fetchMacSearchResources } from './fetch-macos-search-resources.mjs';

test('a bad download leaves existing search resources untouched', async (t) => {
  const stagingDirectory = await mkdtemp(join(tmpdir(), 'mac-search-download-'));
  t.after(() => rm(stagingDirectory, { recursive: true, force: true }));
  await writeFile(join(stagingDirectory, 'prior'), 'verified');
  let calls = 0;
  await assert.rejects(fetchMacSearchResources({
    stagingDirectory,
    run: async (command, args, options) => {
      calls += 1;
      assert.match(command, /^curl(?:\.exe)?$/);
      assert.equal(args[0], '--disable');
      assert.equal(args[args.indexOf('--proto') + 1], '=https');
      assert.equal(args[args.indexOf('--proto-redir') + 1], '=https');
      assert.equal(options.maxBuffer, 66465125);
      return { stdout: Buffer.from('invalid model') };
    },
  }), /model_optimized\.onnx: pinned bytes mismatch/);
  assert.equal(calls, 1);
  assert.deepEqual(await readdir(stagingDirectory), ['prior']);
  assert.equal(await readFile(join(stagingDirectory, 'prior'), 'utf8'), 'verified');
});
