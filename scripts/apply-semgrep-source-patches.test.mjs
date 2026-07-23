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
