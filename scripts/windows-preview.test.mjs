import assert from 'node:assert/strict';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import test from 'node:test';
import {
  validateVersions, hostedIdentity, createSbom, verifyPublication, recordInstallerPayload,
} from './windows-preview.mjs';

const sha = 'a'.repeat(40);
const digest = 'b'.repeat(64);
const candidate = {
  version: '0.1.1', tag: 'v0.1.1-alpha.1', source_commit: sha,
  target: 'x86_64-pc-windows-msvc', unsigned: true,
  hosted: { url: 'https://example.supabase.co', publishable_key_sha256: digest },
  workflow: { run_id: '123', run_attempt: '1' },
  installer: { name: 'Context Relay_0.1.1_x64-setup.exe', sha256: digest },
};
const run = {
  id: 123, run_attempt: 1, head_sha: sha, head_branch: 'main',
  event: 'workflow_dispatch', conclusion: 'success',
  path: '.github/workflows/windows-package.yml',
  repository: { full_name: 'Skytuhua/Context-Relay' },
};

test('version gate rejects mixed Cargo/Tauri/package versions', () => {
  assert.doesNotThrow(() => validateVersions(['0.1.1', '0.1.1']));
  assert.throws(() => validateVersions(['0.1.1', '0.1.0']), /version/i);
  assert.throws(() => validateVersions([]), /version/i);
});

test('hosted release identity rejects missing/secret keys and unsafe URLs', () => {
  for (const key of ['', 'sb_secret_secret', 'eyJ.legacy.jwt', 'sb_publishable_']) {
    assert.throws(() => hostedIdentity('https://example.supabase.co', key), /publishable/i);
  }
  for (const url of ['http://example.supabase.co', 'https://user:pass@example.supabase.co', 'https://example.supabase.co/path', 'https://example.supabase.co?key=x']) {
    assert.throws(() => hostedIdentity(url, 'sb_publishable_fixture'), /URL/i);
  }
  const identity = hostedIdentity('https://example.supabase.co', 'sb_publishable_fixture');
  assert.match(identity.publishable_key_sha256, /^[a-f0-9]{64}$/);
  assert.equal(JSON.stringify(identity).includes('sb_publishable_fixture'), false);
});

test('SBOM rejects unknown licenses and includes exact Rust and Node identities', () => {
  const cargo = { packages: [{ name: 'example', version: '1.2.3', license: 'MIT' }] };
  const npm = { MIT: [{ name: '@scope/example', versions: ['2.0.0'], license: 'MIT' }] };
  const bom = createSbom(cargo, npm);
  assert.equal(bom.bomFormat, 'CycloneDX');
  assert.deepEqual(bom.components.map(c => c.version), ['1.2.3', '2.0.0']);
  assert.throws(() => createSbom({ packages: [{ name: 'unknown', version: '1' }] }, {}), /license/i);
  assert.throws(() => createSbom(cargo, { UNKNOWN: [{ name: 'bad', versions: ['1'], license: 'UNKNOWN' }] }), /license/i);
});

test('publication verifies source, successful trusted workflow, and installer digest', () => {
  assert.doesNotThrow(() => verifyPublication(candidate, run, sha, digest));
  for (const change of [
    { head_sha: 'c'.repeat(40) }, { conclusion: 'failure' }, { head_branch: 'feature' },
    { event: 'pull_request' }, { path: '.github/workflows/other.yml' },
    { id: 124 }, { run_attempt: 2 }, { repository: { full_name: 'other/repo' } },
  ]) assert.throws(() => verifyPublication(candidate, { ...run, ...change }, sha, digest));
  assert.throws(() => verifyPublication(candidate, run, sha, 'd'.repeat(64)), /digest/i);
  assert.throws(() => verifyPublication({ ...candidate, version: '0.1.0' }, run, sha, digest));
  assert.throws(() => verifyPublication({ ...candidate, hosted: null }, run, sha, digest));
  assert.throws(() => verifyPublication({ ...candidate, installer: { ...candidate.installer, name: '../escape.exe' } }, run, sha, digest));
});

test('publication requires main, explicit environment approval and an existing protected tag', async () => {
  const workflow = await readFile(new URL('../.github/workflows/windows-preview-release.yml', import.meta.url), 'utf8');
  assert.match(workflow, /github\.ref == 'refs\/heads\/main'/);
  assert.match(workflow, /environment: windows-preview-publication/);
  assert.match(workflow, /contents: write/);
  assert.match(workflow, /--verify-tag/);
  assert.match(workflow, /--prerelease/);
  assert.doesNotMatch(workflow, /git push|git tag|--clobber|pull_request_target/);
});

test('SBOM preserves legacy Cargo license declarations without invalid SPDX expressions', () => {
  const bom=createSbom({packages:[{name:'legacy',version:'1.0.0',license:'MIT/Apache-2.0'}]},{});
  assert.deepEqual(bom.components[0].licenses,[{license:{name:'MIT/Apache-2.0'}}]);
});

// Tauri patches the desktop bundle type for NSIS and restores the build output.
// Provenance must describe extracted payload bytes, not the restored executable.
test('installer provenance hashes packaged desktop bytes and all auxiliary payloads', async () => {
  const packaged = Buffer.from('desktop with NSIS bundle marker');
  const result = await recordInstallerPayload('candidate.exe', ['LICENSE'], async (_installer, directory) => {
    for (const name of ['context-relay-desktop', 'context-relay-contextd', 'context-relay-context-mcp', 'context-relay-native-helper', 'context-relay-sidecar-installer']) {
      await writeFile(join(directory, `${name}.exe`), packaged);
    }
    await writeFile(join(directory, 'LICENSE'), 'license');
    await mkdir(join(directory, '$PLUGINSDIR'));
    await writeFile(join(directory, '$PLUGINSDIR', 'context-relay-service-control.exe'), 'helper');
  });
  assert.equal(result.binaries[0].sha256, createHash('sha256').update(packaged).digest('hex'));
  assert.equal(result.resources[0].name, 'LICENSE');
  assert.ok(result.payload_files.some(file => file.name === '$PLUGINSDIR/context-relay-service-control.exe'));
  assert.equal(result.payload_files.length, 7);
});

test('installer provenance fails closed when a declared payload is missing', async () => {
  await assert.rejects(recordInstallerPayload('candidate.exe', ['LICENSE'], async () => {}), /ENOENT/);
});
