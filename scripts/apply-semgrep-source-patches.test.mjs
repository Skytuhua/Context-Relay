import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { applySourcePatches } from './apply-semgrep-source-patches.mjs';

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

const ORIGINAL = `module Httpc = struct
  let authenticator =
    match Ca_certs.authenticator () with
    | Ok x -> x
    | Error (\`Msg m) ->
      Fmt.failwith "Failed to create system store X509 authenticator: %s" m

  let create net = Httpc.make ~https:(Some (https ~authenticator)) net
end
`;

const PATCHED = `module Httpc = struct
  let authenticator () =
    match Ca_certs.authenticator () with
    | Ok x -> x
    | Error (\`Msg m) ->
      Fmt.failwith "Failed to create system store X509 authenticator: %s" m

  let create net =
    Httpc.make ~https:(Some (https ~authenticator:(authenticator ()))) net
end
`;

function manifest() {
  return {
    schemaVersion: 1,
    sourceModified: true,
    patches: [{
      id: 'opentelemetry-client-cohttp-eio-lazy-authenticator',
      package: 'opentelemetry-client-cohttp-eio',
      revision: '6cfa5f16d85ac65b602f732469b667bac4aca5ac',
      root: 'pin',
      path: 'src/client-cohttp-eio/opentelemetry_client_cohttp_eio.ml',
      baseSha256: sha256(ORIGINAL),
      patchedSha256: sha256(PATCHED),
      replacements: [
        { before: '  let authenticator =\n', after: '  let authenticator () =\n' },
        {
          before: '  let create net = Httpc.make ~https:(Some (https ~authenticator)) net\n',
          after: '  let create net =\n    Httpc.make ~https:(Some (https ~authenticator:(authenticator ()))) net\n',
        },
      ],
      rationale: 'Defer system CA discovery until an OpenTelemetry HTTP client is created.',
    }],
  };
}

async function fixture(t, source = ORIGINAL) {
  const root = await mkdtemp(join(tmpdir(), 'context-relay-semgrep-patches-'));
  t.after(() => rm(root, { force: true, recursive: true }));
  const revision = manifest().patches[0].revision;
  const target = join(root, 'pins', revision, 'src', 'client-cohttp-eio');
  await mkdir(target, { recursive: true });
  await writeFile(join(target, 'opentelemetry_client_cohttp_eio.ml'), source);
  const manifestPath = join(root, 'patches.v1.json');
  await writeFile(manifestPath, `${JSON.stringify(manifest(), null, 2)}\n`);
  return { bundleRoot: root, manifestPath, target: join(target, 'opentelemetry_client_cohttp_eio.ml') };
}

test('applies the declared Semgrep source patch exactly once and verifies both hashes', async (t) => {
  const paths = await fixture(t);
  const result = await applySourcePatches(paths);
  assert.deepEqual(result, [{
    id: 'opentelemetry-client-cohttp-eio-lazy-authenticator',
    path: 'src/client-cohttp-eio/opentelemetry_client_cohttp_eio.ml',
    revision: '6cfa5f16d85ac65b602f732469b667bac4aca5ac',
    root: 'pin',
    sha256: sha256(PATCHED),
  }]);
  assert.equal(await readFile(paths.target, 'utf8'), PATCHED);
});

test('rejects source drift, duplicate replacement matches, and already-patched input', async (t) => {
  const drift = await fixture(t, ORIGINAL.replace('module Httpc', 'module Drifted'));
  await assert.rejects(() => applySourcePatches(drift), /base sha256/i);

  const duplicate = await fixture(t, ORIGINAL.replace('end\n', '  let authenticator =\nend\n'));
  const duplicateManifest = manifest();
  duplicateManifest.patches[0].baseSha256 = sha256(await readFile(duplicate.target));
  await writeFile(duplicate.manifestPath, `${JSON.stringify(duplicateManifest, null, 2)}\n`);
  await assert.rejects(() => applySourcePatches(duplicate), /exactly once/i);

  const applied = await fixture(t);
  await applySourcePatches(applied);
  await assert.rejects(() => applySourcePatches(applied), /base sha256/i);
});

test('rejects unsafe or dishonest patch manifests', async (t) => {
  const paths = await fixture(t);
  for (const mutate of [
    (value) => { value.sourceModified = false; },
    (value) => { value.patches[0].path = '../escape'; },
    (value) => { value.patches[0].revision = 'not-a-commit'; },
    (value) => { value.patches[0].root = 'ambient'; },
    (value) => { value.patches[0].replacements[0].after = value.patches[0].replacements[0].before; },
  ]) {
    const value = manifest();
    mutate(value);
    await writeFile(paths.manifestPath, `${JSON.stringify(value, null, 2)}\n`);
    await assert.rejects(() => applySourcePatches(paths), /patch|manifest|unsafe|revision|replacement/i);
  }
});

test('applies the exact pinned Semgrep project patch and verifies its production hash', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'context-relay-semgrep-project-patch-'));
  t.after(() => rm(root, { force: true, recursive: true }));
  const target = join(root, 'sources', 'semgrep', 'libs', 'parallelism', 'Concurrent.ml');
  await mkdir(join(root, 'sources', 'semgrep', 'libs', 'parallelism'), { recursive: true });
  const original = await readFile(
    new URL('./fixtures/semgrep-1.170.0/Concurrent.ml', import.meta.url),
  );
  await writeFile(target, original);
  const production = JSON.parse(
    await readFile(new URL('../third_party/sidecars/semgrep/patches.v1.json', import.meta.url)),
  );
  const projectPatch = production.patches.find(({ id }) => id === 'semgrep-single-job-current-domain');
  assert.ok(projectPatch);
  const value = { ...production, patches: [projectPatch] };
  const manifestPath = join(root, 'patches.v1.json');
  await writeFile(manifestPath, `${JSON.stringify(value, null, 2)}\n`);
  const result = await applySourcePatches({ bundleRoot: root, manifestPath });
  assert.equal(result[0].root, 'semgrep');
  assert.equal(sha256(await readFile(target)), projectPatch.patchedSha256);
});

test('applies the exact pinned Semgrep empty-proxy patch and verifies its production hash', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'context-relay-semgrep-proxy-patch-'));
  t.after(() => rm(root, { force: true, recursive: true }));
  const target = join(root, 'sources', 'semgrep', 'libs', 'networking', 'proxy', 'proxy.ml');
  await mkdir(join(root, 'sources', 'semgrep', 'libs', 'networking', 'proxy'), {
    recursive: true,
  });
  const original = await readFile(
    new URL('./fixtures/semgrep-1.170.0/proxy.ml', import.meta.url),
  );
  await writeFile(target, original);
  const production = JSON.parse(
    await readFile(new URL('../third_party/sidecars/semgrep/patches.v1.json', import.meta.url)),
  );
  const proxyPatch = production.patches.find(
    ({ id }) => id === 'semgrep-skip-empty-proxy-initialization',
  );
  assert.ok(proxyPatch);
  const value = { ...production, patches: [proxyPatch] };
  const manifestPath = join(root, 'patches.v1.json');
  await writeFile(manifestPath, `${JSON.stringify(value, null, 2)}\n`);
  const result = await applySourcePatches({ bundleRoot: root, manifestPath });
  assert.equal(result[0].root, 'semgrep');
  assert.equal(sha256(await readFile(target)), proxyPatch.patchedSha256);
});

test('applies exact archive-identified Windows dependency patches', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'context-relay-semgrep-windows-patches-'));
  t.after(() => rm(root, { force: true, recursive: true }));
  const original = 'long len;\n';
  const patched = 'intnat len;\n';
  const revision = 'a'.repeat(64);
  const path = 'package-1.0/src/stubs.c';
  const target = join(root, 'sources', 'opam', revision, ...path.split('/'));
  await mkdir(join(target, '..'), { recursive: true });
  await writeFile(target, original);
  const inventory = {
    schemaVersion: 1,
    sourceModified: true,
    patches: [{
      id: 'package-intnat',
      package: 'package',
      revision,
      root: 'opam',
      path,
      baseSha256: sha256(original),
      patchedSha256: sha256(patched),
      replacements: [{ before: original, after: patched }],
      rationale: 'Match the pinned compiler C API.',
    }],
  };
  const manifestPath = join(root, 'patches.windows.v1.json');
  await writeFile(manifestPath, `${JSON.stringify(inventory, null, 2)}\n`);
  const result = await applySourcePatches({ bundleRoot: root, manifestPath });
  assert.equal(result.length, 1);
  assert.equal(result[0].root, 'opam');
  assert.equal(await readFile(target, 'utf8'), patched);
});

test('Windows dependency inventory binds diagnosed upstream files and the MinGW configure host', async () => {
  const inventory = JSON.parse(
    await readFile(new URL('../third_party/sidecars/semgrep/patches.windows.v1.json', import.meta.url)),
  );
  assert.equal(inventory.patches.length, 3);
  const ansi = inventory.patches.find(({ package: packageName }) => packageName === 'ANSITerminal');
  const parmap = inventory.patches.find(({ package: packageName }) => packageName === 'parmap');
  const ocurl = inventory.patches.find(({ package: packageName }) => packageName === 'ocurl');
  assert.equal(ansi.baseSha256, '45c428bfb1f1a5ea17351b1aebe253e23b4065967680c7de992735874fca58e6');
  assert.equal(ansi.patchedSha256, '6367b47b7781587e27e7ed71111d4b5b137e01836d14ddaeca89035b71623887');
  assert.match(ansi.replacements[0].after, /caml\/fail\.h/);
  assert.equal(ansi.replacements[1].after, '  DWORD NumberOfCharsWritten;\n');
  assert.equal(parmap.baseSha256, 'c6abd87cb802467948f63ecb2711088e5a576f49056e02151af6cbc67521a06b');
  assert.equal(parmap.patchedSha256, '88da5335c0966ca8962cb9d4e0cc1a4360f0346a659f752fe6525f6c4ec5c9b3');
  assert.deepEqual(parmap.replacements, [{
    before: '  long len;\n',
    after: '  intnat len;\n',
  }]);
  assert.equal(ocurl.revision, 'c65f01913270b674a0ca0f278f91bc1e368d7110e8308084bc2280b43a0bc258');
  assert.equal(ocurl.path, 'ocurl-0.9.1/opam');
  assert.equal(ocurl.baseSha256, '17a98b1b80740fb18aed1354260991eb14acccc38afbf04d30b1630b6c9b185c');
  assert.equal(ocurl.patchedSha256, 'd28b855937aa8b06860b30ae9010cb1cd0aae026f5c8fd6772742b3567c01dbe');
  assert.deepEqual(ocurl.replacements, [{
    before: '  ["./configure"]',
    after: '  ["./configure" "--host=x86_64-w64-mingw32"]',
  }]);
});

test('the single-job Semgrep patch keeps Eio scheduling without a worker domain', async () => {
  const inventory = JSON.parse(
    await readFile(new URL('../third_party/sidecars/semgrep/patches.v1.json', import.meta.url)),
  );
  const patch = inventory.patches.find(({ id }) => id === 'semgrep-single-job-current-domain');
  assert.ok(patch);
  const replacement = patch.replacements[0].after;
  const singleJobBranch = replacement.slice(
    replacement.indexOf('if domain_count = 1 then'),
    replacement.indexOf('\n  else\n'),
  );
  assert.match(singleJobBranch, /Eio\.Fiber\.List\.map ~max_fibers:1/);
  assert.doesNotMatch(singleJobBranch, /Executor_pool|domain_mgr|Domain/);
});

test('the closed-runtime Semgrep patch skips only empty proxy initialization', async () => {
  const inventory = JSON.parse(
    await readFile(new URL('../third_party/sidecars/semgrep/patches.v1.json', import.meta.url)),
  );
  const patch = inventory.patches.find(
    ({ id }) => id === 'semgrep-skip-empty-proxy-initialization',
  );
  assert.ok(patch);
  assert.equal(patch.path, 'libs/networking/proxy/proxy.ml');
  const replacement = patch.replacements[0].after;
  assert.match(replacement, /scheme_proxy <> \[\]/);
  assert.match(replacement, /Option\.is_some all_proxy/);
  assert.match(replacement, /Option\.is_some settings\.no_proxy/);
  assert.match(replacement, /Option\.is_some proxy_headers/);
  assert.ok(
    replacement.indexOf('then (') < replacement.indexOf('Cohttp_lwt_unix.Client.set_cache'),
  );
});

test('both public-source builders apply the bundle-carried patch inventory', async () => {
  const [generator, macos, windows] = await Promise.all([
    readFile(new URL('./semgrep-source-bundle.mjs', import.meta.url), 'utf8'),
    readFile(new URL('../third_party/sidecars/semgrep/build-public-source-macos.sh', import.meta.url), 'utf8'),
    readFile(new URL('../third_party/sidecars/semgrep/build-public-source-windows.ps1', import.meta.url), 'utf8'),
  ]);
  assert.match(generator, /scripts\/apply-semgrep-source-patches\.mjs/);
  assert.match(generator, /third_party\/sidecars\/semgrep\/patches\.windows\.v1\.json/);
  for (const builder of [macos, windows]) {
    assert.match(builder, /support[\\/]scripts[\\/]apply-semgrep-source-patches\.mjs/);
    assert.match(builder, /support[\\/]third_party[\\/]sidecars[\\/]semgrep[\\/]patches\.v1\.json/);
  }
  assert.match(windows, /support[\\/]third_party[\\/]sidecars[\\/]semgrep[\\/]patches\.windows\.v1\.json/);
});
