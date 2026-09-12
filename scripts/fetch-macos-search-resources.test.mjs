import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

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
      assert.equal(args[args.indexOf('--retry') + 1], '4');
      assert.equal(args[args.indexOf('--retry-delay') + 1], '15');
      assert.equal(args[args.indexOf('--retry-max-time') + 1], '120');
      assert.equal(options.timeout, 310000);
      return { stdout: Buffer.from('invalid model') };
    },
  }), /model_optimized\.onnx: pinned bytes mismatch/);
  assert.equal(calls, 1);
  assert.deepEqual(await readdir(stagingDirectory), ['prior']);
  assert.equal(await readFile(join(stagingDirectory, 'prior'), 'utf8'), 'verified');
});

test('Windows pinned downloads recover from 429 and reject wrong hashes and permanent errors',
  { skip: process.platform !== 'win32', timeout: 45000 }, async (t) => {
    const root = await mkdtemp(join(tmpdir(), 'windows-search-download-'));
    t.after(() => rm(root, { recursive: true, force: true }));
    const body = Buffer.from('verified');
    const counts = { '/retry': 0, '/bad': 0, '/missing': 0 };
    const server = createServer((request, response) => {
      counts[request.url] += 1;
      if (request.url === '/retry' && counts['/retry'] === 1) {
        response.writeHead(429); response.end();
      } else if (request.url === '/missing') {
        response.writeHead(404); response.end();
      } else {
        response.end(request.url === '/bad' ? 'tampered' : body);
      }
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise((resolve) => server.close(resolve)));
    const path = join(root, 'model');
    const env = { ...process.env, NO_PROXY: '127.0.0.1',
      SEARCH_FETCH_SCRIPT: fileURLToPath(new URL('./fetch-search-resources.ps1', import.meta.url)),
      SEARCH_FETCH_URI: `http://127.0.0.1:${server.address().port}`,
      SEARCH_FETCH_PATH: path, SEARCH_FETCH_SHA: createHash('sha256').update(body).digest('hex') };
    await promisify(execFile)('pwsh', ['-NoProfile', '-Command', `
      $ErrorActionPreference = 'Stop'
      $ast = [Management.Automation.Language.Parser]::ParseFile($env:SEARCH_FETCH_SCRIPT, [ref]$null, [ref]$null)
      foreach ($name in @('Test-PinnedFile', 'Get-PinnedFile')) {
        $fn = $ast.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $false)
        if ($null -eq $fn) { throw 'missing pinned download helper' }
        Invoke-Expression $fn.Extent.Text
      }
      Get-PinnedFile ($env:SEARCH_FETCH_URI + '/retry') $env:SEARCH_FETCH_PATH 8 $env:SEARCH_FETCH_SHA
      Get-PinnedFile ($env:SEARCH_FETCH_URI + '/retry') $env:SEARCH_FETCH_PATH 8 $env:SEARCH_FETCH_SHA
      foreach ($route in @('/bad', '/missing')) {
        [IO.File]::WriteAllText($env:SEARCH_FETCH_PATH, 'original')
        $rejected = $false
        try { Get-PinnedFile ($env:SEARCH_FETCH_URI + $route) $env:SEARCH_FETCH_PATH 8 $env:SEARCH_FETCH_SHA }
        catch { $rejected = $true }
        if (!$rejected -or [IO.File]::ReadAllText($env:SEARCH_FETCH_PATH) -cne 'original') { throw 'invalid download replaced prior bytes' }
      }
    `], { env, windowsHide: true, timeout: 40000 });
    assert.deepEqual(counts, { '/retry': 2, '/bad': 1, '/missing': 1 });
    assert.equal(await readFile(path, 'utf8'), 'original');
  });
