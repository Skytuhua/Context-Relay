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

test('applies a declared Semgrep project patch without creating a worker-domain dependency', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'context-relay-semgrep-project-patch-'));
  t.after(() => rm(root, { force: true, recursive: true }));
  const target = join(root, 'sources', 'semgrep', 'libs', 'parallelism', 'Concurrent.ml');
  await mkdir(join(root, 'sources', 'semgrep', 'libs', 'parallelism'), { recursive: true });
  const original = 'let map ~domain_count f l =\n  spawn_domains domain_count f l\n';
  const patched = 'let map ~domain_count f l =\n  if domain_count = 1 then List.map f l else spawn_domains domain_count f l\n';
  await writeFile(target, original);
  const value = {
    schemaVersion: 1,
    sourceModified: true,
    patches: [{
      id: 'semgrep-single-job-current-domain',
      package: 'semgrep',
      revision: 'bd614accba811b407ae5c9ec6f1eecd3bdc29911',
      root: 'semgrep',
      path: 'libs/parallelism/Concurrent.ml',
      baseSha256: sha256(original),
      patchedSha256: sha256(patched),
      replacements: [{
        before: '  spawn_domains domain_count f l\n',
        after: '  if domain_count = 1 then List.map f l else spawn_domains domain_count f l\n',
      }],
      rationale: 'Run an explicitly single-job scan in the current domain.',
    }],
  };
  const manifestPath = join(root, 'patches.v1.json');
  await writeFile(manifestPath, `${JSON.stringify(value, null, 2)}\n`);
  const result = await applySourcePatches({ bundleRoot: root, manifestPath });
  assert.equal(result[0].root, 'semgrep');
  assert.equal(await readFile(target, 'utf8'), patched);
});

test('both public-source builders apply the bundle-carried patch inventory', async () => {
  const [generator, macos, windows] = await Promise.all([
    readFile(new URL('./semgrep-source-bundle.mjs', import.meta.url), 'utf8'),
    readFile(new URL('../third_party/sidecars/semgrep/build-public-source-macos.sh', import.meta.url), 'utf8'),
    readFile(new URL('../third_party/sidecars/semgrep/build-public-source-windows.ps1', import.meta.url), 'utf8'),
  ]);
  assert.match(generator, /scripts\/apply-semgrep-source-patches\.mjs/);
  for (const builder of [macos, windows]) {
    assert.match(builder, /support[\\/]scripts[\\/]apply-semgrep-source-patches\.mjs/);
    assert.match(builder, /support[\\/]third_party[\\/]sidecars[\\/]semgrep[\\/]patches\.v1\.json/);
  }
});
