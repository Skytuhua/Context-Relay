import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  chmod,
  copyFile,
  link,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { gzipSync } from 'node:zlib';

import {
  digestArgv,
  validateSemgrepNativeBuildEvidence,
} from './hydrate-sidecars.mjs';
import { createNativeSmokeEvidence } from './native-smoke-evidence.mjs';
import {
  createWindowsStableToolchainEvidence,
  createWindowsToolchainEvidence,
  prepareRuntimeArtifact,
} from './prepare-semgrep-runtime.mjs';
import {
  buildDeterministicTar,
  verifyDeterministicTar,
} from './semgrep-source-bundle.mjs';
import { finalizeSemgrepNativeRelease } from './finalize-semgrep-native-release.mjs';

const COMMIT = '1'.repeat(40);
const SEMGREP_REVISION = 'bd614accba811b407ae5c9ec6f1eecd3bdc29911';
const TREE = 'ad8e607874820dc7253d58997736463ed258ea34';
const RUN_ID = '1234';
const WORKFLOW_REF = 'Skytuhua/Context-Relay/.github/workflows/ci.yml@refs/heads/main';
const SOURCE_URL = 'https://github.com/Skytuhua/Context-Relay/releases/download/sidecars-semgrep-1.170.0-source.1/semgrep-1.170.0-corresponding-source.tar';
const MISSING = [
  'two byte-identical executable and runtime-closure inventories per target',
  'schema-valid Windows builder evidence with the exact Cygwin package-version snapshot',
  'Windows no-Python AppContainer smoke evidence',
  'macOS post-sign entitlement and inherited-sandbox smoke evidence',
];

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function json(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
}

async function put(root, relative, bytes, mode = 0o644) {
  const path = join(root, ...relative.split('/'));
  await mkdir(join(path, '..'), { recursive: true });
  await writeFile(path, bytes);
  await chmod(path, mode);
  return path;
}

function identity(target, build, checkRunId) {
  const windows = target === 'windows-x86_64';
  const letter = build.slice(-1);
  return {
    schemaVersion: 1,
    target,
    build,
    artifactName: `task9-semgrep-${windows ? 'windows' : 'macos'}-build-${letter}-${COMMIT}-${RUN_ID}-1`,
    commit: COMMIT,
    runId: RUN_ID,
    runAttempt: 1,
    checkRunId,
    jobDefinition: `native-semgrep-${windows ? 'windows-x64' : 'macos-arm64'}-builders`,
    jobIndex: letter === 'a' ? 0 : 1,
    jobTotal: 2,
    runnerName: `hosted-${target}-${letter}`,
    runnerOs: windows ? 'Windows' : 'macOS',
    runnerArch: windows ? 'X64' : 'ARM64',
    workflowRef: WORKFLOW_REF,
    workflowSha: COMMIT,
  };
}

async function makeBuildRoot(root, target) {
  const executable = target === 'windows-x86_64' ? 'osemgrep.exe' : 'osemgrep';
  const runtime = new Map([[executable, Buffer.from(`native-${target}`)]]);
  if (target === 'windows-x86_64') runtime.set('runtime.dll', Buffer.from('runtime'));
  const manifest = [...runtime]
    .sort(([left], [right]) => Buffer.compare(Buffer.from(left), Buffer.from(right)))
    .map(([path, bytes]) => `${sha256(bytes)}  ${path}\n`).join('');
  const evidence = new Map([
    ['MANIFEST.sha256', Buffer.from(manifest)],
    ['clean.json', Buffer.from('{}\n')],
    ['clean.stderr', Buffer.alloc(0)],
    ['finding.json', Buffer.from('{"results":[{}]}\n')],
    ['finding.stderr', Buffer.alloc(0)],
    ['invalid.json', Buffer.from('{}\n')],
    ['invalid.stderr', Buffer.from('invalid\n')],
    ['runtime-dependencies.txt', Buffer.from(target === 'windows-x86_64' ? 'runtime.dll\n' : '')],
    ['version.txt', Buffer.from('1.170.0\n')],
  ]);
  for (const slot of ['a', 'b']) {
    const release = join(root, `build-${slot}`);
    const proof = join(root, `build-${slot}-evidence`);
    await mkdir(release, { recursive: true });
    await mkdir(proof, { recursive: true });
    for (const [path, bytes] of runtime) {
      await writeFile(join(release, path), bytes);
      await chmod(join(release, path), path === executable ? 0o755 : 0o644);
    }
    for (const [path, bytes] of evidence) await writeFile(join(proof, path), bytes);
  }
}

function writeOctal(header, offset, length, value) {
  header.write(value.toString(8).padStart(length - 1, '0'), offset, length - 1, 'ascii');
  header[offset + length - 1] = 0;
}

function tar(entries) {
  const chunks = [];
  for (const entry of entries) {
    const header = Buffer.alloc(512);
    header.write(entry.path, 0, 100, 'utf8');
    writeOctal(header, 100, 8, entry.executable ? 0o755 : 0o644);
    writeOctal(header, 108, 8, 0);
    writeOctal(header, 116, 8, 0);
    writeOctal(header, 124, 12, entry.bytes.length);
    writeOctal(header, 136, 12, 0);
    header.fill(0x20, 148, 156);
    header[156] = 0x30;
    header.write('ustar\0', 257, 6, 'ascii');
    header.write('00', 263, 2, 'ascii');
    writeOctal(header, 148, 8, [...header].reduce((sum, byte) => sum + byte, 0));
    chunks.push(header, entry.bytes, Buffer.alloc((512 - (entry.bytes.length % 512)) % 512));
  }
  chunks.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(chunks), { level: 9, mtime: 0 });
}

async function makeMacArtifact(root) {
  const artifact = join(root, 'artifact');
  const release = join(artifact, 'release');
  const proof = join(artifact, 'release-evidence');
  await mkdir(release, { recursive: true });
  await mkdir(proof);
  const executable = Buffer.from('native-macos-aarch64');
  const runtimeManifest = Buffer.from(`${sha256(executable)}  osemgrep\n`);
  const evidence = new Map([
    ['MANIFEST.sha256', runtimeManifest],
    ['clean.json', Buffer.from('{}\n')],
    ['clean.stderr', Buffer.alloc(0)],
    ['finding.json', Buffer.from('{"results":[{}]}\n')],
    ['finding.stderr', Buffer.alloc(0)],
    ['invalid.json', Buffer.from('{}\n')],
    ['invalid.stderr', Buffer.from('invalid\n')],
    ['runtime-dependencies.txt', Buffer.alloc(0)],
    ['version.txt', Buffer.from('1.170.0\n')],
  ]);
  await writeFile(join(release, 'osemgrep'), executable);
  for (const [path, bytes] of evidence) await writeFile(join(proof, path), bytes);
  const evidenceEntries = [...evidence]
    .sort(([left], [right]) => Buffer.compare(Buffer.from(left), Buffer.from(right)))
    .map(([path, bytes]) => ({ path, bytes, executable: false }));
  const evidenceManifest = Buffer.from(evidenceEntries.map(({ path, bytes }) => `${sha256(bytes)}  ${path}\n`).join(''));
  for (const slot of ['a', 'b']) {
    await writeFile(join(artifact, `build-${slot}.MANIFEST.sha256`), runtimeManifest);
    await writeFile(join(artifact, `build-${slot}-evidence.MANIFEST.sha256`), evidenceManifest);
  }
  const archiveName = 'semgrep-1.170.0-macos-aarch64.tar.gz';
  const evidenceArchiveName = 'semgrep-1.170.0-macos-aarch64-release-evidence.tar.gz';
  const archive = tar([{ path: 'osemgrep', bytes: executable, executable: true }]);
  const evidenceArchive = tar(evidenceEntries);
  await writeFile(join(artifact, archiveName), archive);
  await writeFile(join(artifact, evidenceArchiveName), evidenceArchive);
  await writeFile(join(artifact, 'runtime-closure.macos-aarch64.v1.json'), json({
    schemaVersion: 1,
    target: 'macos-aarch64',
    archive: { name: archiveName, size: archive.length, sha256: sha256(archive) },
    evidenceArchive: { name: evidenceArchiveName, size: evidenceArchive.length, sha256: sha256(evidenceArchive) },
    closure: [{ executable: true, path: 'osemgrep', sha256: sha256(executable), size: executable.length }],
  }));
  return artifact;
}

async function addNativeEvidence(artifact, target, bootstrap, bundleEvidence) {
  for (const slot of ['a', 'b']) {
    await copyFile(bootstrap, join(artifact, `source-${slot}.tar`));
    await writeFile(
      join(artifact, `build-${slot}.identity.v1.json`),
      `${JSON.stringify(identity(
        target,
        `build-${slot}`,
        (target === 'windows-x86_64' ? 11 : 13) + (slot === 'b' ? 1 : 0),
      ))}\n`,
    );
    await writeFile(
      join(artifact, `build-${slot}.offline-egress.v1.json`),
      target === 'windows-x86_64'
        ? '{"mechanism":"windows-firewall-default-outbound-block-runner-control-plane-allow","probe":"hostile-outbound-tcp-denied","schemaVersion":1}\n'
        : '{"mechanism":"macos-sandbox-exec-network-deny","probe":"hostile-outbound-tcp-denied-with-eperm-or-eacces","schemaVersion":1}\n',
    );
  }
  await writeFile(join(artifact, 'bundle-evidence.v1.json'), bundleEvidence);
  const windows = target === 'windows-x86_64';
  await writeFile(
    join(artifact, `native-smoke.${target}.v1.json`),
    createNativeSmokeEvidence({
      target,
      commit: COMMIT,
      runId: RUN_ID,
      runAttempt: 1,
      checkRunId: windows ? 21 : 22,
      jobDefinition: windows ? 'native-isolation-windows-x64' : 'native-isolation-macos-arm64',
    }),
  );
}

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'context-relay-finalize-'));
  const workspace = join(root, 'workspace');
  await mkdir(workspace);
  const schema = Buffer.from('{"schemaVersion":1}\n');
  const generator = await readFile(new URL('./semgrep-source-bundle.mjs', import.meta.url));
  const compilerRevision = '5'.repeat(40);
  const compilerLicense = Buffer.from('compiler license\n');
  const semgrepLicense = Buffer.from('semgrep source license\n');
  const sourceLock = {
    schemaVersion: 1,
    project: 'Semgrep',
    version: '1.170.0',
    tag: 'v1.170.0',
    tagObject: '3'.repeat(40),
    repository: 'https://github.com/semgrep/semgrep',
    sourceRevision: SEMGREP_REVISION,
    sourceTree: TREE,
    license: 'LGPL-2.1-or-later',
    licenseMaterials: [
      {
        source: 'compiler', kind: 'license', spdx: 'LGPL-2.1-or-later',
        path: `pins/${compilerRevision}/LICENSE`, sha256: sha256(compilerLicense),
      },
      {
        source: 'semgrep', kind: 'license', spdx: 'LGPL-2.1-or-later',
        path: 'sources/semgrep/LICENSE', sha256: sha256(semgrepLicense),
      },
    ],
    additionalArchives: [],
    completeCorrespondingSource: false,
    recursiveInventoryComplete: true,
    rootGitlinks: [],
    opam: {
      repository: { revision: '6'.repeat(40) },
      compiler: {
        url: 'https://github.com/ocaml/ocaml',
        revision: compilerRevision,
        licenseSource: 'compiler',
      },
      pinDepends: [],
      resolvedSourceArchivesComplete: true,
      resolvedSourceArchives: [{
        package: 'fixture', version: '1', targets: ['aarch64-apple-darwin', 'windows-x86_64'],
        opamPath: 'packages/fixture/fixture.1/opam', opamSha256: '7'.repeat(64),
        licenses: ['MIT'], source: null, extraSources: [],
      }],
    },
    sourceFiles: [],
    actions: [],
    toolchains: [
      {
        distributionTarget: 'aarch64-apple-darwin',
        runner: 'macos-15',
        ocamlCompiler: 'ocaml-variants.5.3.0+options,ocaml-option-flambda',
        opamVersion: '2.5.0',
        nodeVersion: '24.14.0',
        setupNodeAction: 'actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020',
        setupAction: 'semgrep/setup-ocaml@a739c5405d73c42ef15a9dc995efc0f87396cc36',
        workflowGitBlob: '4'.repeat(40),
      },
      {
        distributionTarget: 'windows-x86_64',
        runner: 'windows-2022',
        status: 'closed_public_cygwin_mingw_route_scripted_pending_two_build_evidence',
        opamVersion: '2.5.2',
        nodeVersion: '24.14.0',
        setupNodeAction: 'actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020',
        setupAction: 'semgrep/setup-ocaml@3e4c6ff8c9a04c9ec8f6f87701cd4b661b0f1f18',
        cygwinVersion: '3.6.10',
        cygwinPackages: ['curl'],
        builderEvidence: {
          artifactPath: 'builder-evidence.windows-x86_64.v1.json',
          hashAlgorithm: 'sha256',
          schemaPath: 'third_party/sidecars/semgrep/builder-evidence.windows-x86_64.v1.schema.json',
          schemaSha256: sha256(schema),
          sha256: null,
          status: 'pending_native_capture',
        },
        workflowGitBlob: null,
        note: 'pending native evidence',
      },
    ],
    buildCommands: [],
    patchInventory: { path: 'third_party/sidecars/semgrep/patches.v1.json', sourceModified: false },
    manifestRule: 'third_party/sidecars/semgrep/MANIFEST.sha256.md',
    targetStatus: [
      { distributionTarget: 'windows-x86_64', enabled: false, reason: 'pending_two_matching_public_source_builds_and_no_python_smoke' },
      { distributionTarget: 'aarch64-apple-darwin', enabled: false, reason: 'pending_two_matching_public_source_builds_post_sign_inventory_and_sandbox_smoke' },
    ],
    researchEvidence: {},
    missingMaterial: [...MISSING],
    commandTemplate: { format: 'sha256-nul-argv-v1', argv: ['osemgrep'], sha256: digestArgv(['osemgrep']) },
  };
  const sourceLockBytes = json(sourceLock);
  const sourceLockPath = await put(workspace, 'third_party/sidecars/semgrep/source-lock.v1.json', sourceLockBytes);
  await put(workspace, 'scripts/semgrep-source-bundle.mjs', generator);
  await put(workspace, 'scripts/reseal-semgrep-source-bundle.mjs', Buffer.from('// reseal\n'));
  await put(workspace, 'scripts/finalize-semgrep-native-release.mjs', Buffer.from('// finalizer\n'));
  await put(workspace, 'third_party/sidecars/semgrep/builder-evidence.windows-x86_64.v1.schema.json', schema);
  await put(workspace, 'third_party/sidecars/licenses/semgrep-LGPL-2.1-or-later.txt', Buffer.from('license\n'));
  await put(workspace, 'third_party/sidecars/semgrep/RELINKING.md', Buffer.from('relink\n'));

  const provenance = {
    schemaVersion: 1,
    sourceLock: {
      path: 'third_party/sidecars/semgrep/source-lock.v1.json',
      sha256: sha256(sourceLockBytes),
      embeddedActionToolchainStatus: 'sealed-historical-metadata-non-authoritative-for-native-ci',
    },
    actions: [
      { action: 'actions/checkout', revision: 'df4cb1c069e1874edd31b4311f1884172cec0e10' },
      { action: 'actions/setup-node', revision: '49933ea5288caeca8642d1e84afbd3f7d6820020' },
      { action: 'semgrep/setup-ocaml', distributionTarget: 'aarch64-apple-darwin', revision: 'a739c5405d73c42ef15a9dc995efc0f87396cc36' },
      { action: 'semgrep/setup-ocaml', distributionTarget: 'windows-x86_64', revision: '3e4c6ff8c9a04c9ec8f6f87701cd4b661b0f1f18' },
      { action: 'actions/upload-artifact', revision: '043fb46d1a93c77aae656e7c1c64a875d1fc6a0a' },
      { action: 'actions/download-artifact', revision: '37930b1c2abaa49bbe596cd826c3c89aef350131' },
    ],
    toolchains: [
      {
        distributionTarget: 'aarch64-apple-darwin', runner: 'macos-15',
        ocamlCompiler: 'ocaml-variants.5.3.0+options,ocaml-option-flambda', opamVersion: '2.5.0', nodeVersion: '24.14.0',
        setupNodeAction: 'actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020',
        setupAction: 'semgrep/setup-ocaml@a739c5405d73c42ef15a9dc995efc0f87396cc36',
      },
      {
        distributionTarget: 'windows-x86_64', runner: 'windows-2022', ocamlCompiler: '5.3.0', opamVersion: '2.5.2', nodeVersion: '24.14.0', cygwinVersion: '3.6.10',
        setupNodeAction: 'actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020',
        setupAction: 'semgrep/setup-ocaml@3e4c6ff8c9a04c9ec8f6f87701cd4b661b0f1f18',
      },
    ],
  };
  const provenanceBytes = json(provenance);
  await put(workspace, 'third_party/sidecars/semgrep/native-ci-provenance.v1.json', provenanceBytes);

  const bootstrap = join(root, 'bootstrap.tar');
  await buildDeterministicTar({
    entries: [
      { bytes: sourceLockBytes, executable: false, path: 'metadata/source-lock.v1.json' },
      { bytes: Buffer.from('source\n'), executable: false, path: 'sources/semgrep/main.ml' },
    ],
    outputPath: bootstrap,
  });
  const verifiedBootstrap = await verifyDeterministicTar(bootstrap);
  const bundleEvidence = json({
    bundle: {
      payloadEntries: verifiedBootstrap.payloadEntries,
      recordedLinks: verifiedBootstrap.links,
      sha256: verifiedBootstrap.sha256,
      size: verifiedBootstrap.size,
    },
    bundleGeneratorSha256: sha256(generator),
    byteIdentical: true,
    format: 'context-relay-semgrep-source-v1',
    independentBuilds: 2,
    schemaVersion: 1,
    sourceAssetUrl: SOURCE_URL,
    sourceLockSha256: sha256(sourceLockBytes),
    status: 'source_bundle_reproducible_native_builds_pending',
  });
  await put(workspace, 'third_party/sidecars/semgrep/bundle-evidence.v1.json', bundleEvidence);

  const materials = [
    ['source-bundle-generator', 'scripts/semgrep-source-bundle.mjs', generator],
    ['source-bundle-evidence', 'third_party/sidecars/semgrep/bundle-evidence.v1.json', bundleEvidence],
    ['windows-builder-evidence-schema', 'third_party/sidecars/semgrep/builder-evidence.windows-x86_64.v1.schema.json', schema],
    ['native-ci-provenance', 'third_party/sidecars/semgrep/native-ci-provenance.v1.json', provenanceBytes],
  ].map(([role, path, bytes]) => ({ role, path, sha256: sha256(bytes) }));
  const disabled = (target, reason) => ({
    target, enabled: false, disabledReason: reason, reproducibleBuilds: 0,
    correspondingSourceComplete: false, download: null, executable: null, closure: [],
  });
  const manifest = {
    schemaVersion: 1,
    digestFormat: 'sha256-nul-argv-v1',
    allowedReleaseHosts: ['github.com', 'release-assets.githubusercontent.com'],
    tools: [{
      id: 'semgrep',
      version: '1.170.0',
      source: {
        repository: 'https://github.com/semgrep/semgrep', revision: SEMGREP_REVISION, tree: TREE,
        materialPath: 'third_party/sidecars/semgrep/source-lock.v1.json', materialSha256: sha256(sourceLockBytes),
      },
      license: {
        spdx: 'LGPL-2.1-or-later', path: 'third_party/sidecars/licenses/semgrep-LGPL-2.1-or-later.txt',
        sha256: sha256(Buffer.from('license\n')),
      },
      relinking: { path: 'third_party/sidecars/semgrep/RELINKING.md', sha256: sha256(Buffer.from('relink\n')) },
      materials,
      commandTemplate: { id: 'osemgrep-scan-v1', argv: ['osemgrep'], sha256: digestArgv(['osemgrep']) },
      targets: [
        disabled('windows-x86_64', 'pending_two_matching_public_source_builds_and_no_python_smoke'),
        disabled('macos-aarch64', 'pending_two_matching_public_source_builds_post_sign_inventory_and_sandbox_smoke'),
        disabled('macos-x86_64', 'unsupported_v1_distribution_target'),
      ],
    }],
  };
  await put(workspace, 'third_party/sidecars/manifest.v1.json', Buffer.from(`${JSON.stringify(manifest)}\n`));

  const artifacts = {};
  for (const target of ['windows-x86_64']) {
    const buildRoot = join(root, `build-${target}`);
    await makeBuildRoot(buildRoot, target);
    const prepared = await prepareRuntimeArtifact({
      buildRoot,
      outputRoot: join(root, `prepared-${target}`),
      targetName: target,
      version: '1.170.0',
    });
    artifacts[target] = prepared.artifactRoot;
    await addNativeEvidence(prepared.artifactRoot, target, bootstrap, bundleEvidence);
  }
  artifacts['macos-aarch64'] = await makeMacArtifact(join(root, 'prepared-macos-aarch64'));
  await addNativeEvidence(artifacts['macos-aarch64'], 'macos-aarch64', bootstrap, bundleEvidence);
  const facts = {
    commit: COMMIT,
    cygwinRelease: '3.6.10(0.349/5/3)',
    imageOs: 'win22',
    imageVersion: '20260719.1',
    nodeVersion: 'v24.14.0',
    opamVersion: '2.5.2',
    runAttempt: '1',
    runId: RUN_ID,
    runnerArch: 'X64',
    runnerOs: 'Windows',
    rustHost: 'x86_64-pc-windows-msvc',
    rustRelease: '1.88.0',
    setupNodeActionSha: '49933ea5288caeca8642d1e84afbd3f7d6820020',
    setupOcamlActionSha: '3e4c6ff8c9a04c9ec8f6f87701cd4b661b0f1f18',
    windowsVersion: 'Microsoft Windows NT 10.0.20348',
  };
  const builder = createWindowsToolchainEvidence({ cygcheck: 'Package Version\ncurl 8.0\n', facts });
  await writeFile(join(artifacts['windows-x86_64'], 'builder-evidence.windows-x86_64.v1.json'), builder);
  await writeFile(
    join(artifacts['windows-x86_64'], 'builder-toolchain.windows-x86_64.v1.json'),
    createWindowsStableToolchainEvidence(builder),
  );
  await writeFile(join(artifacts['windows-x86_64'], 'builder-evidence.windows-x86_64.v1.schema.json'), schema);

  return {
    args: {
      workspace,
      windowsArtifactRoot: artifacts['windows-x86_64'],
      macosArtifactRoot: artifacts['macos-aarch64'],
      bootstrapSourcePath: bootstrap,
      outputRoot: join(root, 'final'),
      expected: {
        commit: COMMIT,
        runId: RUN_ID,
        runAttempt: 1,
        workflowRef: WORKFLOW_REF,
        workflowSha: COMMIT,
      },
    },
    root,
    sourceLockPath,
  };
}

test('finalizer verifies native evidence and emits only a complete reviewable patch and deterministic source asset', async () => {
  const value = await fixture();
  try {
    const result = await finalizeSemgrepNativeRelease(value.args);
    const patchRoot = join(value.args.outputRoot, 'patch');
    const sourceLock = JSON.parse(await readFile(join(patchRoot, 'third_party/sidecars/semgrep/source-lock.v1.json')));
    const manifest = JSON.parse(await readFile(join(patchRoot, 'third_party/sidecars/manifest.v1.json')));
    const evidence = JSON.parse(await readFile(join(patchRoot, 'third_party/sidecars/semgrep/native-build-evidence.v1.json')));
    const bundle = JSON.parse(await readFile(join(patchRoot, 'third_party/sidecars/semgrep/bundle-evidence.v1.json')));
    const semgrep = manifest.tools.find(({ id }) => id === 'semgrep');
    assert.equal(sourceLock.completeCorrespondingSource, true);
    assert.deepEqual(sourceLock.missingMaterial, []);
    assert.deepEqual(sourceLock.targetStatus.map(({ enabled }) => enabled), [true, true]);
    assert.equal(sourceLock.nativeBuildEvidence.sha256, sha256(json(evidence)));
    assert.deepEqual(semgrep.targets.map(({ enabled }) => enabled), [true, true, false]);
    for (const role of ['native-ci-provenance', 'native-release-finalizer', 'source-bundle-reseal']) {
      assert.equal(semgrep.materials.filter((material) => material.role === role).length, 1);
    }
    assert.match(semgrep.targets[0].download.url, /sidecars-semgrep-1\.170\.0-source\.1/);
    assert.match(semgrep.targets[1].download.url, /sidecars-semgrep-1\.170\.0-source\.1/);
    assert.equal(evidence.ci.commit, COMMIT);
    assert.equal(evidence.builders.length, 4);
    assert.equal(new Set(evidence.builders.map(({ checkRunId }) => checkRunId)).size, 4);
    const nativeMaterial = semgrep.materials.find(({ role }) => role === 'native-build-evidence');
    assert.doesNotThrow(() => validateSemgrepNativeBuildEvidence(
      evidence,
      sourceLock,
      nativeMaterial,
      semgrep.materials,
      semgrep.targets.filter(({ enabled }) => enabled),
    ));
    assert.equal(bundle.status, 'complete_corresponding_source');
    assert.equal(bundle.bundle.sha256, result.sourceBundle.sha256);
    assert.equal(
      sha256(await readFile(join(value.args.outputRoot, 'release', 'semgrep-1.170.0-corresponding-source.tar'))),
      bundle.bundle.sha256,
    );
  } finally {
    await rm(value.root, { force: true, recursive: true });
  }
});

test('finalizer refuses drift, topology tricks, and a pre-existing output without deleting it', async (t) => {
  await t.test('unknown pending source-lock key', async () => {
    const value = await fixture();
    try {
      const lock = JSON.parse(await readFile(value.sourceLockPath));
      lock.unreviewed = true;
      await writeFile(value.sourceLockPath, json(lock));
      await assert.rejects(finalizeSemgrepNativeRelease(value.args), /source lock.*keys/i);
    } finally {
      await rm(value.root, { force: true, recursive: true });
    }
  });

  await t.test('mismatched native-smoke run', async () => {
    const value = await fixture();
    try {
      await writeFile(
        join(value.args.macosArtifactRoot, 'native-smoke.macos-aarch64.v1.json'),
        createNativeSmokeEvidence({
          target: 'macos-aarch64', commit: COMMIT, runId: '9999', runAttempt: 1,
          checkRunId: 22, jobDefinition: 'native-isolation-macos-arm64',
        }),
      );
      await assert.rejects(finalizeSemgrepNativeRelease(value.args), /native smoke.*run/i);
    } finally {
      await rm(value.root, { force: true, recursive: true });
    }
  });

  await t.test('A/B runtime manifest drift', async () => {
    const value = await fixture();
    try {
      await writeFile(
        join(value.args.windowsArtifactRoot, 'build-b.MANIFEST.sha256'),
        `${'0'.repeat(64)}  osemgrep.exe\n`,
      );
      await assert.rejects(finalizeSemgrepNativeRelease(value.args), /A\/B manifests differ/i);
    } finally {
      await rm(value.root, { force: true, recursive: true });
    }
  });

  await t.test('prematurely completed source lock', async () => {
    const value = await fixture();
    try {
      const lock = JSON.parse(await readFile(value.sourceLockPath));
      lock.completeCorrespondingSource = true;
      lock.missingMaterial = [];
      lock.targetStatus = lock.targetStatus.map((status) => ({ ...status, enabled: true, reason: null }));
      await writeFile(value.sourceLockPath, json(lock));
      await assert.rejects(finalizeSemgrepNativeRelease(value.args), /honest pending state/i);
    } finally {
      await rm(value.root, { force: true, recursive: true });
    }
  });

  await t.test('drifted source copy', async () => {
    const value = await fixture();
    try {
      await writeFile(join(value.args.windowsArtifactRoot, 'source-b.tar'), 'drift');
      await assert.rejects(finalizeSemgrepNativeRelease(value.args), /source bundle.*differ|source.*mismatch/i);
    } finally {
      await rm(value.root, { force: true, recursive: true });
    }
  });

  await t.test('hardlinked artifact input', async () => {
    const value = await fixture();
    try {
      await link(
        join(value.args.macosArtifactRoot, 'build-a.identity.v1.json'),
        join(value.args.macosArtifactRoot, 'trap.identity.v1.json'),
      );
      await assert.rejects(finalizeSemgrepNativeRelease(value.args), /hardlink|topology/i);
    } finally {
      await rm(value.root, { force: true, recursive: true });
    }
  });

  await t.test('pre-existing output', async () => {
    const value = await fixture();
    try {
      await mkdir(value.args.outputRoot);
      await writeFile(join(value.args.outputRoot, 'keep'), 'keep');
      await assert.rejects(finalizeSemgrepNativeRelease(value.args), /output.*exists/i);
      assert.equal(await readFile(join(value.args.outputRoot, 'keep'), 'utf8'), 'keep');
    } finally {
      await rm(value.root, { force: true, recursive: true });
    }
  });
});
