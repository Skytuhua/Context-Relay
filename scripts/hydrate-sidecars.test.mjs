import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  link,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  stat,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { gunzipSync, gzipSync } from 'node:zlib';

import {
  digestArgv,
  extractExpectedFile,
  guardedInstallerInvocation,
  hydrateSidecars,
  loadSidecarManifest,
  parseSidecarManifest,
  validateSemgrepNativeBuildEvidence,
  validateManifestMaterials,
} from './hydrate-sidecars.mjs';
import { verifyResolvedSourceInventory } from './semgrep-source-inventory.mjs';

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const fullHex = (value) => value.repeat(64).slice(0, 64);
const digestForFixture = (argv) => sha256(Buffer.from(argv.join(String.fromCharCode(0))));
const gunzipForTest = (bytes) => gunzipSync(bytes);

function canonicalSemgrepLicenseMaterials() {
  const sources = [
    'memtrace',
    'obackward',
    'ocaml-compiler',
    'ocaml-opentelemetry',
    'ocaml-tree-sitter-core',
    'pcre2-ocaml',
    'pyro-caml',
    'semgrep',
    'semgrep-interfaces',
    'testo',
    'tree-sitter-runtime',
  ];
  const materials = sources.map((source) => ({
    source,
    kind: 'license',
    spdx: 'MIT',
    path: source === 'semgrep'
      ? 'sources/semgrep/LICENSE'
      : source === 'tree-sitter-runtime'
        ? 'support/tree-sitter-LICENSE'
        : `pins/${source}/LICENSE`,
    sha256: fullHex('f'),
  }));
  materials.splice(9, 0, {
    source: 'semgrep-interfaces',
    kind: 'notice',
    spdx: 'MIT',
    path: 'pins/semgrep-interfaces/NOTICE',
    sha256: fullHex('e'),
  });
  return materials;
}

function nativeEvidenceFixture(lock, target, support) {
  const ci = {
    commit: fullHex('1').slice(0, 40),
    runId: '42',
    runAttempt: 1,
    workflowRef: 'example/project/.github/workflows/ci.yml@refs/heads/main',
    workflowSha: fullHex('1').slice(0, 40),
  };
  const policy = target.target === 'windows-x86_64'
    ? {
        artifact: 'task9-semgrep-windows-build',
        job: 'native-semgrep-windows-x64-builders',
        smokeJob: 'native-isolation-windows-x64',
        sandbox: 'windows-appcontainer',
      }
    : {
        artifact: 'task9-semgrep-macos-build',
        job: 'native-semgrep-macos-arm64-builders',
        smokeJob: 'native-isolation-macos-arm64',
        sandbox: 'macos-sandbox-exec-inherited',
      };
  const archiveName = new URL(target.download.url).pathname.split('/').at(-1);
  return {
    schemaVersion: 1,
    status: 'native_builds_and_sandbox_smokes_verified',
    bootstrapSource: {
      sourceLockSha256: fullHex('2'),
      sourceRevision: lock.sourceRevision,
      sourceTree: lock.sourceTree,
      bundleEvidenceSha256: fullHex('3'),
      bundle: { sha256: fullHex('4'), size: 1024, payloadEntries: 2, recordedLinks: 0 },
    },
    ci,
    provenanceSha256: support[0].sha256,
    builders: ['a', 'b'].map((slot, index) => ({
      target: target.target,
      build: `build-${slot}`,
      artifactName: `${policy.artifact}-${slot}-${ci.commit}-${ci.runId}-${ci.runAttempt}`,
      identitySha256: fullHex(index === 0 ? '5' : '6'),
      identitySize: 256,
      checkRunId: 100 + index,
      jobDefinition: policy.job,
      jobIndex: index,
      jobTotal: 2,
      runnerName: `runner-${slot}`,
      runnerOs: target.target === 'windows-x86_64' ? 'Windows' : 'macOS',
      runnerArch: target.target === 'windows-x86_64' ? 'X64' : 'ARM64',
    })),
    smokes: [{
      target: target.target,
      checkRunId: 102,
      jobDefinition: policy.smokeJob,
      sandboxMechanism: policy.sandbox,
      sha256: fullHex('7'),
      size: 256,
    }],
    targets: [{
      target: target.target,
      runtimeArchive: { name: archiveName, size: target.download.size, sha256: target.download.sha256 },
      evidenceArchive: { name: `${archiveName}.evidence.tar.gz`, size: 512, sha256: fullHex('8') },
      runtimeClosure: { sha256: fullHex('9'), size: 256 },
      manifests: Object.fromEntries([
        'build-a.MANIFEST.sha256',
        'build-b.MANIFEST.sha256',
        'build-a-evidence.MANIFEST.sha256',
        'build-b-evidence.MANIFEST.sha256',
      ].map((name, index) => [name, { sha256: fullHex(index < 2 ? '1' : '2'), size: 128 }])),
      offlineEvidence: ['a', 'b'].map((slot, index) => ({
        build: `build-${slot}`,
        sha256: fullHex(index === 0 ? 'a' : 'b'),
        size: 128,
      })),
    }],
    windowsBuilder: target.target === 'windows-x86_64' ? {
      evidence: { sha256: fullHex('c'), size: 256 },
      schema: { sha256: fullHex('d'), size: 256 },
      toolchain: { sha256: fullHex('e'), size: 256 },
    } : null,
    support: support.map(({ path, sha256: digest }) => ({ path, sha256: digest })),
  };
}

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function zip(entries) {
  const localParts = [];
  const centralParts = [];
  let offset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name);
    const body = Buffer.from(entry.body ?? '');
    const flags = entry.dataDescriptor ? 0x8 : 0;
    const checksum = crc32(body);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(flags, 6);
    if (!entry.dataDescriptor) {
      local.writeUInt32LE(checksum, 14);
      local.writeUInt32LE(body.length, 18);
      local.writeUInt32LE(body.length, 22);
    }
    local.writeUInt16LE(name.length, 26);
    const descriptor = entry.dataDescriptor ? Buffer.alloc(16) : Buffer.alloc(0);
    if (entry.dataDescriptor) {
      descriptor.writeUInt32LE(0x08074b50, 0);
      descriptor.writeUInt32LE(checksum, 4);
      descriptor.writeUInt32LE(body.length, 8);
      descriptor.writeUInt32LE(body.length, 12);
    }
    localParts.push(local, name, body, descriptor);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(0x0314, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(flags, 8);
    central.writeUInt32LE(checksum, 16);
    central.writeUInt32LE(body.length, 20);
    central.writeUInt32LE(body.length, 24);
    central.writeUInt16LE(name.length, 28);
    const mode = entry.type === 'directory' ? 0o040755 : entry.type === 'symlink' ? 0o120777 : 0o100755;
    central.writeUInt32LE((mode << 16) >>> 0, 38);
    central.writeUInt32LE(offset, 42);
    centralParts.push(central, name);
    offset += local.length + name.length + body.length + descriptor.length;
  }
  const centralBytes = Buffer.concat(centralParts);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralBytes.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...localParts, centralBytes, end]);
}

function writeOctal(header, offset, length, value) {
  header.write(value.toString(8).padStart(length - 1, '0'), offset, length - 1, 'ascii');
  header[offset + length - 1] = 0;
}

function tarGz(entries) {
  const chunks = [];
  for (const entry of entries) {
    const body = Buffer.from(entry.body ?? '');
    const header = Buffer.alloc(512);
    header.write(entry.name, 0, 100, 'utf8');
    writeOctal(header, 100, 8, entry.type === 'directory' ? 0o755 : 0o644);
    writeOctal(header, 108, 8, 0);
    writeOctal(header, 116, 8, 0);
    writeOctal(header, 124, 12, body.length);
    writeOctal(header, 136, 12, 0);
    header.fill(0x20, 148, 156);
    const typeFlag = { directory: '5', symlink: '2', hardlink: '1', device: '3' }[entry.type] ?? '0';
    header[156] = typeFlag.charCodeAt(0);
    header.write('ustar\0', 257, 6, 'ascii');
    writeOctal(header, 148, 8, [...header].reduce((sum, byte) => sum + byte, 0));
    chunks.push(header, body, Buffer.alloc((512 - (body.length % 512)) % 512));
  }
  return gzipSync(Buffer.concat([...chunks, Buffer.alloc(1024)]), { mtime: 0 });
}

async function fixture() {
  const workspace = await mkdtemp(join(tmpdir(), 'context-relay-sidecars-'));
  const payload = Buffer.from('not an executable');
  const archive = zip([
    { name: 'LICENSE', body: 'MIT' },
    { name: 'fixture.exe', body: payload },
  ]);
  const licensePath = 'third_party/sidecars/licenses/fixture-MIT.txt';
  const sourcePath = 'third_party/sidecars/fixture/source-lock.v1.json';
  const sourceBytes = Buffer.from('{"locked":true}\n');
  await mkdir(join(workspace, dirname(licensePath)), { recursive: true });
  await mkdir(join(workspace, dirname(sourcePath)), { recursive: true });
  await writeFile(join(workspace, licensePath), 'MIT\n');
  await writeFile(join(workspace, sourcePath), sourceBytes);
  const manifest = {
    schemaVersion: 1,
    digestFormat: 'sha256-nul-argv-v1',
    allowedReleaseHosts: ['github.com', 'release-assets.githubusercontent.com'],
    tools: [{
      id: 'fixture',
      version: '1.0.0',
      source: {
        repository: 'https://github.com/example/fixture',
        revision: 'a'.repeat(40),
        tree: 'b'.repeat(40),
        materialPath: sourcePath,
        materialSha256: sha256(sourceBytes),
      },
      license: { spdx: 'MIT', path: licensePath, sha256: sha256(Buffer.from('MIT\n')) },
      relinking: null,
      materials: [],
      commandTemplate: {
        id: 'fixture-v1',
        argv: ['fixture', '--scan'],
        sha256: digestForFixture(['fixture', '--scan']),
      },
      targets: [{
        target: 'windows-x86_64',
        enabled: true,
        disabledReason: null,
        reproducibleBuilds: 2,
        correspondingSourceComplete: true,
        download: {
          url: 'https://github.com/example/fixture/releases/download/v1/fixture.zip',
          format: 'zip',
          size: archive.length,
          sha256: sha256(archive),
          entries: [
            { path: 'LICENSE', type: 'file', size: 3 },
            { path: 'fixture.exe', type: 'file', size: payload.length },
          ],
          extractPath: 'fixture.exe',
        },
        executable: { path: 'fixture.exe', size: payload.length, sha256: sha256(payload) },
        closure: [{ path: 'fixture.exe', size: payload.length, sha256: sha256(payload), executable: true }],
      }],
    }],
  };
  const manifestPath = join(workspace, 'third_party/sidecars/manifest.v1.json');
  await mkdir(dirname(manifestPath), { recursive: true });
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  return { archive, manifest, manifestPath, payload, sourcePath, workspace };
}

test('sha256-nul-argv-v1 is mechanically reproducible for every source lock', async () => {
  assert.equal(
    digestArgv(['rulesync', 'generate']),
    '845298eda9096a496436d5a6b47d8ad17b20313f7296b8128c21a96a38ee64b0',
  );
  for (const name of ['rulesync', 'gitleaks', 'semgrep']) {
    const lock = JSON.parse(
      await readFile(new URL(`../third_party/sidecars/${name}/source-lock.v1.json`, import.meta.url)),
    );
    assert.equal(digestArgv(lock.commandTemplate.argv), lock.commandTemplate.sha256, name);
  }
});

function response(body, { status = 200, location = null, onRead = null } = {}) {
  return {
    status,
    headers: {
      get: (name) => {
        if (name.toLowerCase() === 'location') return location;
        if (name.toLowerCase() === 'content-length') return String(body.length);
        return null;
      },
    },
    async arrayBuffer() {
      onRead?.();
      return body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength);
    },
  };
}

test('manifest rejects unknown keys, duplicate IDs and duplicate targets', async (t) => {
  const { manifest, workspace } = await fixture();
  t.after(() => rm(workspace, { recursive: true, force: true }));
  assert.throws(() => parseSidecarManifest(JSON.stringify({ ...manifest, surprise: true })), /unknown/i);
  const nestedUnknown = structuredClone(manifest);
  nestedUnknown.tools[0].source.surprise = true;
  assert.throws(() => parseSidecarManifest(JSON.stringify(nestedUnknown)), /unknown.*surprise/i);
  assert.throws(
    () => parseSidecarManifest(JSON.stringify({ ...manifest, tools: [...manifest.tools, manifest.tools[0]] })),
    /duplicate.*fixture/i,
  );
  const changed = structuredClone(manifest);
  changed.tools[0].targets.push(changed.tools[0].targets[0]);
  assert.throws(() => parseSidecarManifest(JSON.stringify(changed)), /duplicate.*target/i);
});

test('manifest rejects abbreviated and malformed hashes', async (t) => {
  const { manifest, workspace } = await fixture();
  t.after(() => rm(workspace, { recursive: true, force: true }));
  for (const bad of ['abc123', 'G'.repeat(64), 'A'.repeat(64)]) {
    const changed = structuredClone(manifest);
    changed.tools[0].targets[0].download.sha256 = bad;
    assert.throws(() => parseSidecarManifest(JSON.stringify(changed)), /sha-?256/i);
  }
});

test('material verification catches one-byte source changes and missing license/source/relink files', async (t) => {
  const item = await fixture();
  t.after(() => rm(item.workspace, { recursive: true, force: true }));
  const parsed = parseSidecarManifest(JSON.stringify(item.manifest));
  await validateManifestMaterials(parsed, item.workspace);
  await writeFile(join(item.workspace, item.sourcePath), '{"locked":false}\n');
  await assert.rejects(() => validateManifestMaterials(parsed, item.workspace), /source.*sha-?256/i);
  await writeFile(join(item.workspace, item.sourcePath), '{"locked":true}\n');
  await rm(join(item.workspace, item.manifest.tools[0].license.path));
  await assert.rejects(() => validateManifestMaterials(parsed, item.workspace), /license/i);

  const semgrep = structuredClone(item.manifest);
  semgrep.tools[0].id = 'semgrep';
  semgrep.tools[0].license.spdx = 'LGPL-2.1-or-later';
  semgrep.tools[0].relinking = null;
  assert.throws(() => parseSidecarManifest(JSON.stringify(semgrep)), /relink/i);
});

test('material verification also pins policy and build-support bytes', async (t) => {
  const item = await fixture();
  t.after(() => rm(item.workspace, { recursive: true, force: true }));
  const policyPath = 'third_party/sidecars/policies/fixture.toml';
  const policy = Buffer.from('trusted = true\n');
  await mkdir(join(item.workspace, dirname(policyPath)), { recursive: true });
  await writeFile(join(item.workspace, policyPath), policy);
  item.manifest.tools[0].materials = [
    { role: 'policy', path: policyPath, sha256: sha256(policy) },
  ];
  const parsed = parseSidecarManifest(JSON.stringify(item.manifest));
  await validateManifestMaterials(parsed, item.workspace);
  await writeFile(join(item.workspace, policyPath), 'trusted = false\n');
  await assert.rejects(() => validateManifestMaterials(parsed, item.workspace), /policy.*sha-?256/i);
});

test('enabled Semgrep requires complete corresponding source and two matching builds on every target', async (t) => {
  const { manifest, workspace } = await fixture();
  t.after(() => rm(workspace, { recursive: true, force: true }));
  manifest.tools[0].id = 'semgrep';
  const relinkingPath = 'third_party/sidecars/semgrep/RELINKING.md';
  const relinkingBytes = Buffer.from('replace the executable\n');
  await mkdir(join(workspace, dirname(relinkingPath)), { recursive: true });
  await writeFile(join(workspace, relinkingPath), relinkingBytes);
  manifest.tools[0].relinking = { path: relinkingPath, sha256: sha256(relinkingBytes) };
  for (const target of ['windows-x86_64', 'macos-aarch64']) {
    const changed = structuredClone(manifest);
    changed.tools[0].targets[0].target = target;
    changed.tools[0].targets[0].reproducibleBuilds = 1;
    changed.tools[0].targets[0].correspondingSourceComplete = false;
    assert.throws(() => parseSidecarManifest(JSON.stringify(changed)), /semgrep.*reproducible/i);
  }
});

test('enabled Semgrep requires complete internal evidence in the hashed source lock', async (t) => {
  const item = await fixture();
  t.after(() => rm(item.workspace, { recursive: true, force: true }));
  const tool = item.manifest.tools[0];
  tool.id = 'semgrep';
  tool.license.spdx = 'LGPL-2.1-or-later';
  const relinkingPath = 'third_party/sidecars/semgrep/RELINKING.md';
  const relinking = Buffer.from('relinking instructions\n');
  await mkdir(join(item.workspace, dirname(relinkingPath)), { recursive: true });
  await writeFile(join(item.workspace, relinkingPath), relinking);
  tool.relinking = { path: relinkingPath, sha256: sha256(relinking) };
  const generatorPath = 'scripts/semgrep-source-bundle.mjs';
  const generator = Buffer.from('export const fixture = true;\n');
  await mkdir(join(item.workspace, dirname(generatorPath)), { recursive: true });
  await writeFile(join(item.workspace, generatorPath), generator);
  const evidencePath = 'third_party/sidecars/semgrep/bundle-evidence.v1.json';
  const nativeEvidencePath = 'third_party/sidecars/semgrep/native-build-evidence.v1.json';
  const support = [
    ['native-ci-provenance', 'third_party/sidecars/semgrep/native-ci-provenance.v1.json', 'provenance\n'],
    ['native-release-finalizer', 'scripts/finalize-semgrep-native-release.mjs', 'finalizer\n'],
    ['source-bundle-reseal', 'scripts/reseal-semgrep-source-bundle.mjs', 'reseal\n'],
  ].map(([role, path, body]) => ({ role, path, bytes: Buffer.from(body), sha256: sha256(Buffer.from(body)) }));
  for (const material of support) {
    await mkdir(dirname(join(item.workspace, material.path)), { recursive: true });
    await writeFile(join(item.workspace, material.path), material.bytes);
  }

  const complete = {
    sourceRevision: tool.source.revision,
    sourceTree: tool.source.tree,
    toolchains: [{
      distributionTarget: 'windows-x86_64',
      status: 'native_builds_verified',
      builderEvidence: {
        status: 'verified_native_capture',
        sha256: fullHex('c'),
        schemaSha256: fullHex('d'),
      },
    }],
    completeCorrespondingSource: true,
    recursiveInventoryComplete: true,
    licenseMaterials: canonicalSemgrepLicenseMaterials(),
    opam: {
      resolvedSourceArchivesComplete: true,
      resolvedSourceArchives: [{
        package: 'dependency',
        version: '1.0',
        targets: ['windows-x86_64'],
        opamPath: 'packages/dependency/dependency.1.0/opam',
        opamSha256: fullHex('a'),
        licenses: ['MIT'],
        source: {
          checksums: [{ algorithm: 'sha256', digest: fullHex('b') }],
          mirrors: [],
          supplementalChecksums: [],
          url: 'https://example.invalid/dependency.tbz',
        },
        extraSources: [],
      }],
    },
    missingMaterial: [],
    targetStatus: [{ distributionTarget: 'windows-x86_64', enabled: true }],
  };
  const validateLock = async (lock, evidenceChanges = {}) => {
    lock = structuredClone(lock);
    const nativeEvidence = nativeEvidenceFixture(lock, tool.targets[0], support);
    evidenceChanges.mutateNativeEvidence?.(nativeEvidence);
    const nativeEvidenceBytes = Buffer.from(`${JSON.stringify(nativeEvidence)}\n`);
    await writeFile(join(item.workspace, nativeEvidencePath), nativeEvidenceBytes);
    if (!evidenceChanges.omitNativeEvidence) {
      lock.nativeBuildEvidence = {
        path: nativeEvidencePath,
        sha256: sha256(nativeEvidenceBytes),
        support: support.map(({ path, sha256: digest }) => ({ path, sha256: digest })),
      };
    }
    const bytes = Buffer.from(`${JSON.stringify(lock)}\n`);
    await writeFile(join(item.workspace, item.sourcePath), bytes);
    tool.source.materialSha256 = sha256(bytes);
    const evidence = {
      schemaVersion: 1,
      format: 'context-relay-semgrep-source-v1',
      sourceLockSha256: evidenceChanges.sourceLockSha256 ?? sha256(bytes),
      bundleGeneratorSha256: evidenceChanges.bundleGeneratorSha256 ?? sha256(generator),
      independentBuilds: 2,
      byteIdentical: true,
      status: evidenceChanges.status ?? 'complete_corresponding_source',
      sourceAssetUrl: 'https://github.com/Skytuhua/Context-Relay/releases/download/sidecars-semgrep-1.170.0-source.1/semgrep-1.170.0-corresponding-source.tar',
      bundle: {
        sha256: fullHex('c'),
        size: 1_149_545_984,
        payloadEntries: 39_539,
        recordedLinks: 85,
      },
    };
    const evidenceBytes = Buffer.from(`${JSON.stringify(evidence)}\n`);
    await writeFile(join(item.workspace, evidencePath), evidenceBytes);
    tool.materials = [
      { role: 'source-bundle-generator', path: generatorPath, sha256: sha256(generator) },
      { role: 'source-bundle-evidence', path: evidencePath, sha256: sha256(evidenceBytes) },
      { role: 'native-build-evidence', path: nativeEvidencePath, sha256: sha256(nativeEvidenceBytes) },
      ...support.map(({ role, path, sha256: digest }) => ({ role, path, sha256: digest })),
    ];
    const parsed = parseSidecarManifest(JSON.stringify(item.manifest));
    await validateManifestMaterials(parsed, item.workspace);
  };
  await validateLock(complete);
  const directEvidence = nativeEvidenceFixture(complete, tool.targets[0], support);
  assert.doesNotThrow(() => validateSemgrepNativeBuildEvidence(
    directEvidence,
    { ...complete, nativeBuildEvidence: {
      path: nativeEvidencePath,
      sha256: fullHex('f'),
      support: support.map(({ path, sha256: digest }) => ({ path, sha256: digest })),
    } },
    { role: 'native-build-evidence', path: nativeEvidencePath, sha256: fullHex('f') },
    support,
    [tool.targets[0]],
  ));
  await assert.rejects(
    () => validateLock(complete, { omitNativeEvidence: true }),
    /semgrep.*native build evidence/i,
  );
  await assert.rejects(
    () => validateLock(complete, {
      mutateNativeEvidence: (value) => { value.status = 'pending'; },
    }),
    /semgrep.*native build evidence/i,
  );
  await assert.rejects(
    () => validateLock(complete, {
      mutateNativeEvidence: (value) => { value.targets[0].runtimeArchive.sha256 = fullHex('0'); },
    }),
    /semgrep.*native build evidence/i,
  );
  const licenseMutations = [
    { ...complete, licenseMaterials: undefined },
    { ...complete, licenseMaterials: complete.licenseMaterials.slice(0, -1) },
    {
      ...complete,
      licenseMaterials: [complete.licenseMaterials[1], complete.licenseMaterials[0], ...complete.licenseMaterials.slice(2)],
    },
    {
      ...complete,
      licenseMaterials: complete.licenseMaterials.map((material, index) => (
        index === 1 ? { ...material, path: complete.licenseMaterials[0].path } : material
      )),
    },
    {
      ...complete,
      licenseMaterials: complete.licenseMaterials.map((material) => (
        material.source === 'semgrep' ? { ...material, path: 'pins/semgrep/LICENSE' } : material
      )),
    },
    {
      ...complete,
      licenseMaterials: complete.licenseMaterials.map((material, index) => (
        index === 0 ? { ...material, sha256: '0'.repeat(64) } : material
      )),
    },
    {
      ...complete,
      licenseMaterials: [
        ...complete.licenseMaterials,
        {
          source: 'testo',
          kind: 'notice',
          spdx: 'MIT',
          path: 'pins/testo/NOTICE',
          sha256: fullHex('d'),
        },
      ],
    },
  ];
  for (const lock of licenseMutations) {
    await assert.rejects(() => validateLock(lock), /semgrep.*license material/i);
  }
  await assert.rejects(
    () => validateLock(complete, { status: 'source_bundle_reproducible_native_builds_pending' }),
    /semgrep.*bundle.*status/i,
  );
  await assert.rejects(
    () => validateLock(complete, { sourceLockSha256: fullHex('d') }),
    /semgrep.*bundle.*source lock/i,
  );
  await assert.rejects(
    () => validateLock(complete, { bundleGeneratorSha256: fullHex('e') }),
    /semgrep.*bundle.*generator/i,
  );

  const incomplete = [
    { ...complete, completeCorrespondingSource: false },
    { ...complete, recursiveInventoryComplete: false },
    { ...complete, opam: { ...complete.opam, resolvedSourceArchivesComplete: false } },
    { ...complete, opam: { ...complete.opam, resolvedSourceArchives: [] } },
    { ...complete, missingMaterial: ['missing source'] },
    { ...complete, targetStatus: [{ distributionTarget: 'windows-x86_64', enabled: false }] },
    { ...complete, targetStatus: [] },
    {
      ...complete,
      opam: {
        ...complete.opam,
        resolvedSourceArchives: [{
          ...complete.opam.resolvedSourceArchives[0],
          opamSha256: '0'.repeat(64),
        }],
      },
    },
    {
      ...complete,
      opam: {
        ...complete.opam,
        resolvedSourceArchives: [{
          ...complete.opam.resolvedSourceArchives[0],
          unexpected: true,
        }],
      },
    },
  ];
  for (const lock of incomplete) {
    await assert.rejects(() => validateLock(lock), /semgrep.*(?:source|inventory|archive|material|status)/i);
  }

  const malformedUtf8 = Buffer.from(`${JSON.stringify(complete)}\n`);
  malformedUtf8[malformedUtf8.indexOf('dependency')] = 0xff;
  await writeFile(join(item.workspace, item.sourcePath), malformedUtf8);
  tool.source.materialSha256 = sha256(malformedUtf8);
  const parsed = parseSidecarManifest(JSON.stringify(item.manifest));
  await assert.rejects(
    () => validateManifestMaterials(parsed, item.workspace),
    /semgrep.*(?:utf-?8|source lock)/i,
  );
});

test('manifest rejects unsafe archive names, Windows compatibility aliases, normalized duplicates, and excessive sizes', async (t) => {
  const { manifest, workspace } = await fixture();
  t.after(() => rm(workspace, { recursive: true, force: true }));
  for (const bad of [
    '../tool.exe',
    '/tool.exe',
    'C:/tool.exe',
    'dir\\tool.exe',
    'CON',
    'COM¹',
    'LPT²',
    'LPT³',
    'ＣＯＮ',
    'CLOCK$',
    'CONIN$',
    'CONOUT$',
    'tool.',
  ]) {
    const changed = structuredClone(manifest);
    changed.tools[0].targets[0].download.entries[1].path = bad;
    changed.tools[0].targets[0].download.extractPath = bad;
    assert.throws(() => parseSidecarManifest(JSON.stringify(changed)), /relative path/i);
  }
  const duplicate = structuredClone(manifest);
  duplicate.tools[0].targets[0].download.entries[0].path = 'FIXTURE.EXE';
  assert.throws(() => parseSidecarManifest(JSON.stringify(duplicate)), /duplicate.*normalized/i);
  for (const field of ['download', 'executable']) {
    const changed = structuredClone(manifest);
    changed.tools[0].targets[0][field].size = 268435457;
    if (field === 'executable') changed.tools[0].targets[0].closure[0].size = 268435457;
    assert.throws(() => parseSidecarManifest(JSON.stringify(changed)), /size.*maximum/i);
  }
});

test('material verification rejects a linked path component', async (t) => {
  const item = await fixture();
  t.after(() => rm(item.workspace, { recursive: true, force: true }));
  const sourceDirectory = join(item.workspace, dirname(item.sourcePath));
  const external = await mkdtemp(join(tmpdir(), 'context-relay-linked-material-'));
  t.after(() => rm(external, { recursive: true, force: true }));
  await writeFile(join(external, 'source-lock.v1.json'), '{"locked":true}\n');
  await rm(sourceDirectory, { recursive: true });
  await symlink(external, sourceDirectory, process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(
    () => validateManifestMaterials(parseSidecarManifest(JSON.stringify(item.manifest)), item.workspace),
    /no-link/i,
  );
});

test('archive pins entry count, name, type and size while extracting only the expected file', () => {
  const payload = Buffer.from('payload');
  const expected = {
    entries: [
      { path: 'LICENSE', type: 'file', size: 3 },
      { path: 'tool.exe', type: 'file', size: payload.length },
    ],
    extractPath: 'tool.exe',
  };
  for (const archive of [
    ['zip', zip([{ name: 'LICENSE', body: 'MIT' }, { name: 'tool.exe', body: payload }])],
    ['tar.gz', tarGz([{ name: 'LICENSE', body: 'MIT' }, { name: 'tool.exe', body: payload }])],
  ]) assert.deepEqual(extractExpectedFile(archive[1], archive[0], expected), payload);
  assert.throws(() => extractExpectedFile(zip([{ name: 'tool.exe', body: payload }]), 'zip', expected), /entry count/i);
  assert.throws(
    () => extractExpectedFile(tarGz([{ name: 'renamed.exe', body: payload }]), 'tar.gz', { ...expected, entries: [expected.entries[1]] }),
    /entry.*path/i,
  );
  assert.throws(
    () => extractExpectedFile(zip([{ name: 'tool.exe', type: 'directory' }]), 'zip', { ...expected, entries: [expected.entries[1]] }),
    /entry.*type/i,
  );
  assert.throws(
    () => extractExpectedFile(zip([{ name: 'tool.exe', body: payload }]), 'zip', { ...expected, entries: [{ ...expected.entries[1], size: 1 }] }),
    /entry.*size/i,
  );
  for (const [format, archive, pattern] of [
    ['zip', zip([{ name: 'tool.exe', type: 'symlink', body: 'target' }]), /special|symlink/i],
    ['tar.gz', tarGz([{ name: 'tool.exe', type: 'symlink', body: 'target' }]), /special/i],
    ['tar.gz', tarGz([{ name: 'tool.exe', type: 'hardlink' }]), /special/i],
    ['tar.gz', tarGz([{ name: 'tool.exe', type: 'device' }]), /special/i],
  ]) {
    assert.throws(
      () => extractExpectedFile(archive, format, { ...expected, entries: [expected.entries[1]] }),
      pattern,
    );
  }
});

test('ZIP accepts only canonical signed data descriptors and exact local-record layout', () => {
  const expected = { entries: [{ path: 'tool', type: 'file', size: 7 }], extractPath: 'tool' };
  const canonical = zip([{ name: 'tool', body: 'payload', dataDescriptor: true }]);
  assert.deepEqual(extractExpectedFile(canonical, 'zip', expected), Buffer.from('payload'));

  const descriptorOffset = 30 + Buffer.byteLength('tool') + Buffer.byteLength('payload');
  for (const [fieldOffset, pattern] of [
    [0, /descriptor.*signature/i],
    [4, /descriptor.*CRC/i],
    [8, /descriptor.*compressed/i],
    [12, /descriptor.*uncompressed/i],
  ]) {
    const damaged = Buffer.from(canonical);
    damaged.writeUInt32LE(1, descriptorOffset + fieldOffset);
    assert.throws(() => extractExpectedFile(damaged, 'zip', expected), pattern);
  }

  for (const fieldOffset of [14, 18, 22]) {
    const damaged = Buffer.from(canonical);
    damaged.writeUInt32LE(1, fieldOffset);
    assert.throws(() => extractExpectedFile(damaged, 'zip', expected), /local.*zero|local\/central/i);
  }

  const centralOffset = canonical.readUInt32LE(canonical.length - 22 + 16);
  const truncated = Buffer.concat([canonical.subarray(0, centralOffset - 4), canonical.subarray(centralOffset)]);
  truncated.writeUInt32LE(centralOffset - 4, truncated.length - 22 + 16);
  assert.throws(() => extractExpectedFile(truncated, 'zip', expected), /descriptor.*truncated/i);

  const gap = Buffer.concat([canonical.subarray(0, centralOffset), Buffer.from([0]), canonical.subarray(centralOffset)]);
  gap.writeUInt32LE(centralOffset + 1, gap.length - 22 + 16);
  assert.throws(() => extractExpectedFile(gap, 'zip', expected), /local.*layout|gap/i);

  const overlapping = zip([
    { name: 'tool', body: 'payload', dataDescriptor: true },
    { name: 'tool', body: 'payload', dataDescriptor: true },
  ]);
  const overlappingCentralOffset = overlapping.readUInt32LE(overlapping.length - 22 + 16);
  const secondCentralOffset = overlappingCentralOffset + 46 + Buffer.byteLength('tool');
  overlapping.writeUInt32LE(0, secondCentralOffset + 42);
  assert.throws(
    () => extractExpectedFile(overlapping, 'zip', { ...expected, entries: [expected.entries[0], expected.entries[0]] }),
    /local.*overlap|local.*layout/i,
  );

  for (const forbiddenFlag of [0x1, 0x40]) {
    const damaged = Buffer.from(canonical);
    damaged.writeUInt16LE(0x8 | forbiddenFlag, 6);
    damaged.writeUInt16LE(0x8 | forbiddenFlag, centralOffset + 8);
    assert.throws(() => extractExpectedFile(damaged, 'zip', expected), /ZIP.*flags|encrypted/i);
  }

  assert.throws(
    () => extractExpectedFile(Buffer.concat([canonical, Buffer.from('junk')]), 'zip', expected),
    /trailing/i,
  );
});

test('archive extraction rejects CRC, TAR checksum, and trailing-data corruption', () => {
  const expected = { entries: [{ path: 'tool', type: 'file', size: 7 }], extractPath: 'tool' };
  const damagedZip = zip([{ name: 'tool', body: 'payload' }]);
  damagedZip[30 + Buffer.byteLength('tool')] ^= 1;
  assert.throws(() => extractExpectedFile(damagedZip, 'zip', expected), /content|crc/i);
  const damagedTar = gunzipForTest(tarGz([{ name: 'tool', body: 'payload' }]));
  damagedTar[0] ^= 1;
  assert.throws(() => extractExpectedFile(gzipSync(damagedTar, { mtime: 0 }), 'tar.gz', expected), /checksum/i);
  assert.throws(
    () => extractExpectedFile(Buffer.concat([tarGz([{ name: 'tool', body: 'payload' }]), Buffer.from('junk')]), 'tar.gz', expected),
    /trailing|gzip/i,
  );

  const malformedName = gunzipForTest(tarGz([{ name: 'tool', body: 'payload' }]));
  malformedName[0] = 0xff;
  malformedName.fill(0x20, 148, 156);
  writeOctal(
    malformedName,
    148,
    8,
    [...malformedName.subarray(0, 512)].reduce((sum, byte) => sum + byte, 0),
  );
  assert.throws(
    () => extractExpectedFile(gzipSync(malformedName, { mtime: 0 }), 'tar.gz', expected),
    /utf-?8|encoding|name/i,
  );
});

test('hydration rejects archive and executable byte drift', async (t) => {
  const item = await fixture();
  t.after(() => rm(item.workspace, { recursive: true, force: true }));
  const mutated = Buffer.from(item.archive);
  mutated[0] ^= 1;
  await assert.rejects(
    () => hydrateSidecars({ workspace: item.workspace, target: 'windows-x86_64', fetchImpl: async () => response(mutated) }),
    /archive.*sha-?256/i,
  );
  item.manifest.tools[0].targets[0].executable.sha256 = fullHex('d');
  item.manifest.tools[0].targets[0].closure[0].sha256 = fullHex('d');
  await writeFile(item.manifestPath, `${JSON.stringify(item.manifest)}\n`);
  await assert.rejects(
    () => hydrateSidecars({ workspace: item.workspace, target: 'windows-x86_64', fetchImpl: async () => response(item.archive) }),
    /executable.*sha-?256/i,
  );
});

test('hydration never substitutes a target or follows a redirect outside the release allowlist', async (t) => {
  const item = await fixture();
  t.after(() => rm(item.workspace, { recursive: true, force: true }));
  await assert.rejects(
    () => hydrateSidecars({ workspace: item.workspace, target: 'macos-aarch64', fetchImpl: async () => response(item.archive) }),
    /no enabled.*macos-aarch64/i,
  );
  await assert.rejects(
    () => hydrateSidecars({
      workspace: item.workspace,
      target: 'windows-x86_64',
      fetchImpl: async () => response(Buffer.alloc(0), { status: 302, location: 'https://evil.example/tool.zip' }),
    }),
    /redirect.*host/i,
  );
});

test('hydration publishes atomically, executes nothing, and verify-only is offline', async (t) => {
  const item = await fixture();
  t.after(() => rm(item.workspace, { recursive: true, force: true }));
  const calls = [];
  const result = await hydrateSidecars({
    workspace: item.workspace,
    target: 'windows-x86_64',
    fetchImpl: async (url, options) => {
      calls.push([url, options]);
      return response(item.archive);
    },
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0][1].redirect, 'manual');
  assert.equal(result.directories.fixture, join(result.directory, 'fixture'));
  assert.deepEqual(await readFile(join(result.directories.fixture, 'fixture.exe')), item.payload);
  assert.equal((await stat(join(result.directories.fixture, 'fixture.exe'))).isFile(), true);
  assert.deepEqual((await readdir(dirname(result.directory))).sort(), [result.manifestDigest]);
  const source = await readFile(new URL('./hydrate-sidecars.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /\b(?:mkdir|rename|rmdir|unlink)\s*\(/);
  assert.doesNotMatch(source, /\b(?:exec|fork)Sync?\s*\(/);
  const repository = resolve(import.meta.dirname, '..');
  assert.deepEqual(guardedInstallerInvocation(), {
    command: 'cargo',
    args: [
      'run',
      '--locked',
      '--manifest-path',
      join(repository, 'Cargo.toml'),
      '-p',
      'context-relay-native-runner',
      '--bin',
      'context-relay-sidecar-installer',
      '--',
    ],
    options: {
      cwd: repository,
      shell: false,
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    },
  });
  const verified = await hydrateSidecars({
    workspace: item.workspace,
    target: 'windows-x86_64',
    verifyOnly: true,
    fetchImpl: async () => { throw new Error('network used in verify-only'); },
  });
  assert.equal(verified.directory, result.directory);
});

test('hydration publishes and verifies an exact isolated closure directory per enabled tool', async (t) => {
  const item = await fixture();
  t.after(() => rm(item.workspace, { recursive: true, force: true }));
  const second = structuredClone(item.manifest.tools[0]);
  second.id = 'second';
  second.version = '2.0.0';
  second.commandTemplate.id = 'second-v1';
  item.manifest.tools.push(second);
  await writeFile(item.manifestPath, `${JSON.stringify(item.manifest)}\n`);

  let downloads = 0;
  const result = await hydrateSidecars({
    workspace: item.workspace,
    target: 'windows-x86_64',
    fetchImpl: async () => {
      downloads += 1;
      return response(item.archive);
    },
  });
  assert.equal(downloads, 2);
  assert.deepEqual((await readdir(result.directory)).sort(), ['fixture', 'second']);
  assert.deepEqual(await readFile(join(result.directory, 'fixture', 'fixture.exe')), item.payload);
  assert.deepEqual(await readFile(join(result.directory, 'second', 'fixture.exe')), item.payload);

  const verified = await hydrateSidecars({
    workspace: item.workspace,
    target: 'windows-x86_64',
    verifyOnly: true,
    fetchImpl: async () => { throw new Error('verify-only used the network'); },
  });
  assert.equal(verified.directory, result.directory);
});

test('hydration materializes every verified runtime-closure file from one archive', async (t) => {
  const item = await fixture();
  t.after(() => rm(item.workspace, { recursive: true, force: true }));
  const runtime = Buffer.from('pinned runtime library');
  item.archive = zip([
    { name: 'LICENSE', body: 'MIT' },
    { name: 'fixture.exe', body: item.payload },
    { name: 'runtime.dll', body: runtime },
  ]);
  const target = item.manifest.tools[0].targets[0];
  target.download.size = item.archive.length;
  target.download.sha256 = sha256(item.archive);
  target.download.entries.push({ path: 'runtime.dll', type: 'file', size: runtime.length });
  target.closure.push({
    path: 'runtime.dll',
    size: runtime.length,
    sha256: sha256(runtime),
    executable: false,
  });
  await writeFile(item.manifestPath, `${JSON.stringify(item.manifest)}\n`);

  const result = await hydrateSidecars({
    workspace: item.workspace,
    target: 'windows-x86_64',
    fetchImpl: async () => response(item.archive),
  });

  assert.deepEqual(
    (await readdir(result.directories.fixture)).sort(),
    ['fixture.exe', 'runtime.dll'],
  );
  assert.deepEqual(await readFile(join(result.directories.fixture, 'fixture.exe')), item.payload);
  assert.deepEqual(await readFile(join(result.directories.fixture, 'runtime.dll')), runtime);
  await hydrateSidecars({
    workspace: item.workspace,
    target: 'windows-x86_64',
    verifyOnly: true,
    fetchImpl: async () => { throw new Error('verify-only used the network'); },
  });
});

test('hydration rejects redirected cache ancestors before writing outside the workspace', async (t) => {
  const item = await fixture();
  const external = await mkdtemp(join(tmpdir(), 'context-relay-sidecar-redirect-'));
  t.after(() => rm(item.workspace, { recursive: true, force: true }));
  t.after(() => rm(external, { recursive: true, force: true }));
  await symlink(external, join(item.workspace, 'target'), process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(
    () => hydrateSidecars({
      workspace: item.workspace,
      target: 'windows-x86_64',
      fetchImpl: async () => response(item.archive),
    }),
    /link|redirect|topology/i,
  );
  assert.deepEqual(await readdir(external), []);
});

test('offline verification rejects a linked cache root and a hardlinked closure file', async (t) => {
  const item = await fixture();
  t.after(() => rm(item.workspace, { recursive: true, force: true }));
  const result = await hydrateSidecars({
    workspace: item.workspace,
    target: 'windows-x86_64',
    fetchImpl: async () => response(item.archive),
  });

  const perToolFile = join(result.directory, 'fixture', 'fixture.exe');
  const legacyFile = join(result.directory, 'fixture.exe');
  const cachedFile = await stat(perToolFile).then(() => perToolFile, () => legacyFile);
  try {
    await link(cachedFile, join(item.workspace, 'same-inode-copy'));
  } catch (error) {
    if (['ENOTSUP', 'EPERM', 'EACCES'].includes(error.code)) {
      t.skip(`hard links unavailable: ${error.code}`);
      return;
    }
    throw error;
  }
  await assert.rejects(
    () => hydrateSidecars({ workspace: item.workspace, target: 'windows-x86_64', verifyOnly: true }),
    /hardlink|link count|topology/i,
  );
  await rm(join(item.workspace, 'same-inode-copy'));

  const realCache = join(item.workspace, 'real-cache');
  await rename(result.directory, realCache);
  await symlink(realCache, result.directory, process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(
    () => hydrateSidecars({ workspace: item.workspace, target: 'windows-x86_64', verifyOnly: true }),
    /link|redirect|topology/i,
  );
});

test('interrupted hydration leaves no partial or enabled directory', async (t) => {
  const item = await fixture();
  t.after(() => rm(item.workspace, { recursive: true, force: true }));
  const controller = new AbortController();
  await assert.rejects(
    () => hydrateSidecars({
      workspace: item.workspace,
      target: 'windows-x86_64',
      signal: controller.signal,
      fetchImpl: async () => response(item.archive, { onRead: () => controller.abort() }),
    }),
    /abort/i,
  );
  const root = join(item.workspace, 'target/sidecars/windows-x86_64');
  assert.deepEqual(await readdir(root).catch(() => []), []);
});

test('streaming hydration stops at the manifest byte bound before buffering', async (t) => {
  const item = await fixture();
  t.after(() => rm(item.workspace, { recursive: true, force: true }));
  let reads = 0;
  await assert.rejects(
    () => hydrateSidecars({
      workspace: item.workspace,
      target: 'windows-x86_64',
      fetchImpl: async () => ({
        status: 200,
        headers: { get: () => null },
        body: {
          getReader: () => ({
            async read() {
              reads += 1;
              return { done: false, value: Buffer.alloc(item.archive.length + 1) };
            },
            async cancel() {},
            releaseLock() {},
          }),
        },
      }),
    }),
    /exceeds expected size/i,
  );
  assert.equal(reads, 1);
});

test('the committed manifest and all referenced material validate', async () => {
  const workspace = new URL('..', import.meta.url);
  const manifest = await loadSidecarManifest(new URL('../third_party/sidecars/manifest.v1.json', import.meta.url));
  await validateManifestMaterials(manifest, workspace);
});

test('Semgrep records the V1 source bundle but remains disabled pending release qualification', async () => {
  const lockBytes = await readFile(new URL('../third_party/sidecars/semgrep/source-lock.v1.json', import.meta.url));
  const lock = JSON.parse(lockBytes);
  const bundleEvidence = JSON.parse(
    await readFile(new URL('../third_party/sidecars/semgrep/bundle-evidence.v1.json', import.meta.url)),
  );
  assert.equal(lock.completeCorrespondingSource, false);
  assert.equal(lock.recursiveInventoryComplete, true);
  assert.equal(sha256(lockBytes), 'd5c29931ef5e68a5f6840c9bb27557cbbc8b22ccbb9ae13592c97b928d65dd26');
  assert.equal(lock.licenseMaterials.length, 12);
  assert.equal(lock.rootGitlinks.length, 36);
  assert.equal(lock.opam.resolvedSourceArchivesComplete, true);
  assert.equal(lock.opam.resolvedSourceArchives.length, 244);
  assert.doesNotThrow(() => verifyResolvedSourceInventory(lock.opam.resolvedSourceArchives));
  assert.equal(lock.opam.resolvedSourceArchives.filter((entry) => entry.source !== null).length, 208);
  assert.equal(lock.opam.resolvedSourceArchives.reduce((count, entry) => count + entry.extraSources.length, 0), 10);
  assert.equal(lock.missingMaterial.includes('byte-identical complete corresponding-source bundle built twice'), false);
  assert.equal(lock.missingMaterial.some((entry) => /source-archive inventory|resolved opam source/i.test(entry)), false);
  assert.equal(bundleEvidence.byteIdentical, false);
  assert.equal(bundleEvidence.independentBuilds, 1);
  assert.equal(bundleEvidence.status, 'source_bundle_v1_native_builds_pending');
  assert.equal(
    bundleEvidence.sourceAssetUrl,
    'https://github.com/Skytuhua/Context-Relay/releases/download/sidecars-semgrep-1.170.0-source.1/semgrep-1.170.0-corresponding-source.tar',
  );
  assert.equal('sourceAssetUrl' in lock, false);
  assert.equal('sourceBundleSha256' in lock, false);
  assert.equal(bundleEvidence.bundle.sha256, '45e885a2315387240d4af8a1e6576613c4dbdb564a694af1edff06c35e7910d9');
  assert.equal(bundleEvidence.bundle.size, 1149640192);
  assert.equal(bundleEvidence.bundle.payloadEntries, 39542);
  assert.equal(bundleEvidence.bundle.recordedLinks, 222);
  assert.equal(bundleEvidence.sourceLockSha256, 'd5c29931ef5e68a5f6840c9bb27557cbbc8b22ccbb9ae13592c97b928d65dd26');
  assert.equal(bundleEvidence.bundleGeneratorSha256, '092fe2855df51267ca3c8525c0b404c3ca0587470cedfc63bf1818df60e72007');
  assert.equal(
    sha256(await readFile(new URL('./semgrep-source-bundle.mjs', import.meta.url))),
    '092fe2855df51267ca3c8525c0b404c3ca0587470cedfc63bf1818df60e72007',
  );
  assert.equal(lock.researchEvidence.usableForHydration, false);
  assert.equal(lock.researchEvidence.usableForPackaging, false);
  assert.deepEqual(
    lock.targetStatus.map(({ distributionTarget, enabled, reason }) => ({ distributionTarget, enabled, reason })),
    [
      {
        distributionTarget: 'windows-x86_64',
        enabled: false,
        reason: 'pending_two_matching_public_source_builds_and_no_python_smoke',
      },
      {
        distributionTarget: 'aarch64-apple-darwin',
        enabled: false,
        reason: 'pending_two_matching_public_source_builds_post_sign_inventory_and_sandbox_smoke',
      },
    ],
  );
});

test('Semgrep pins Node and an exact pending Windows builder-evidence contract', async () => {
  const [nodeVersionBytes, lockBytes, schemaBytes, bundleGenerator] = await Promise.all([
    readFile(new URL('../.node-version', import.meta.url)),
    readFile(new URL('../third_party/sidecars/semgrep/source-lock.v1.json', import.meta.url)),
    readFile(
      new URL(
        '../third_party/sidecars/semgrep/builder-evidence.windows-x86_64.v1.schema.json',
        import.meta.url,
      ),
    ),
    readFile(new URL('./semgrep-source-bundle.mjs', import.meta.url), 'utf8'),
  ]);
  const lock = JSON.parse(lockBytes);
  const schema = JSON.parse(schemaBytes);
  const setupNodeRevision = '49933ea5288caeca8642d1e84afbd3f7d6820020';
  const schemaPath =
    'third_party/sidecars/semgrep/builder-evidence.windows-x86_64.v1.schema.json';

  assert.equal(nodeVersionBytes.toString('utf8').trim(), '24.14.0');
  assert.deepEqual(
    lock.actions.find(({ action }) => action === 'actions/setup-node'),
    { action: 'actions/setup-node', revision: setupNodeRevision },
  );
  for (const toolchain of lock.toolchains) {
    assert.equal(toolchain.nodeVersion, '24.14.0');
    assert.equal(
      toolchain.setupNodeAction,
      'actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020',
    );
  }

  const windows = lock.toolchains.find(
    ({ distributionTarget }) => distributionTarget === 'windows-x86_64',
  );
  const macos = lock.toolchains.find(
    ({ distributionTarget }) => distributionTarget === 'aarch64-apple-darwin',
  );
  assert.equal(macos.runner, 'macos-15');
  assert.equal('cygwinPackageVersionsPinned' in windows, false);
  assert.deepEqual(windows.builderEvidence, {
    artifactPath: 'builder-evidence.windows-x86_64.v1.json',
    hashAlgorithm: 'sha256',
    schemaPath,
    schemaSha256: sha256(schemaBytes),
    sha256: null,
    status: 'pending_native_capture',
  });
  assert.equal(schema['$schema'], 'https://json-schema.org/draft/2020-12/schema');
  assert.deepEqual(schema.required, [
    'schemaVersion',
    'target',
    'commit',
    'run',
    'hostedImage',
    'toolchain',
    'cygwinPackages',
  ]);
  assert.equal(schema.properties.schemaVersion.const, 1);
  assert.equal(schema.properties.target.const, 'windows-x86_64');
  assert.equal(schema.properties.toolchain.properties.setupNodeActionSha.const, setupNodeRevision);
  assert.equal(
    schema.properties.toolchain.properties.setupOcamlActionSha.const,
    '3e4c6ff8c9a04c9ec8f6f87701cd4b661b0f1f18',
  );
  assert.equal(schema.properties.toolchain.properties.nodeVersion.const, '24.14.0');
  assert.equal(schema.properties.toolchain.properties.opamVersion.const, '2.5.2');
  assert.equal(schema.properties.toolchain.properties.rustHost.const, 'x86_64-pc-windows-msvc');
  assert.deepEqual(schema['x-context-relay-normalization'].toolchainKeyOrder, [
    'setupNodeActionSha',
    'setupOcamlActionSha',
    'nodeVersion',
    'opamVersion',
    'cygwinRelease',
    'rustHost',
    'rustRelease',
  ]);
  assert.match(bundleGenerator, /builder-evidence\.windows-x86_64\.v1\.schema\.json/);
});
