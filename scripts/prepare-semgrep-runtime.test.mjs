import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  assertExactRuntimeInventory,
  createCandidateDocuments,
  createWindowsStableToolchainEvidence,
  createWindowsToolchainEvidence,
  prepareRuntimeArtifact,
  writeCandidateWorkspace,
} from './prepare-semgrep-runtime.mjs';
import {
  extractExpectedFile,
  hydrateCiCandidateSidecar,
  hydrateSidecars,
  parseSidecarManifest,
} from './hydrate-sidecars.mjs';

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

async function buildFixture({ includeRelease = true } = {}) {
  const root = await mkdtemp(join(tmpdir(), 'context-relay-semgrep-runtime-'));
  const buildRoot = join(root, 'build');
  const runtime = new Map([
    ['osemgrep.exe', Buffer.from('native osemgrep')],
    ['runtime.dll', Buffer.from('native runtime')],
  ]);
  const manifest = [...runtime]
    .sort(([left], [right]) => Buffer.compare(Buffer.from(left), Buffer.from(right)))
    .map(([path, bytes]) => `${sha256(bytes)}  ${path}\n`)
    .join('');
  const evidence = new Map([
    ['MANIFEST.sha256', Buffer.from(manifest)],
    ['clean.json', Buffer.from('{"results":[]}\n')],
    ['clean.stderr', Buffer.alloc(0)],
    ['finding.json', Buffer.from('{"results":[{}]}\n')],
    ['finding.stderr', Buffer.alloc(0)],
    ['invalid.json', Buffer.from('{"errors":[{}]}\n')],
    ['invalid.stderr', Buffer.alloc(0)],
    ['runtime-dependencies.txt', Buffer.from('kernel32.dll\nruntime.dll\n')],
    ['version.txt', Buffer.from('1.170.0\n')],
  ]);
  const labels = includeRelease ? ['build-a', 'build-b', 'release'] : ['build-a', 'build-b'];
  for (const label of labels) {
    const directory = join(buildRoot, label);
    await mkdir(directory, { recursive: true });
    for (const [path, bytes] of runtime) {
      const destination = join(directory, path);
      await writeFile(destination, bytes);
      await chmod(destination, path === 'osemgrep.exe' ? 0o755 : 0o644);
    }
    const evidenceDirectory = join(buildRoot, `${label}-evidence`);
    await mkdir(evidenceDirectory);
    for (const [path, bytes] of evidence) await writeFile(join(evidenceDirectory, path), bytes);
  }
  return { buildRoot, root };
}

test('runtime artifact is deterministic and contains the exact twice-built release', async () => {
  const fixture = await buildFixture();
  const first = await prepareRuntimeArtifact({
    buildRoot: fixture.buildRoot,
    outputRoot: join(fixture.root, 'candidate-a'),
    targetName: 'windows-x86_64',
    version: '1.170.0',
  });
  const second = await prepareRuntimeArtifact({
    buildRoot: fixture.buildRoot,
    outputRoot: join(fixture.root, 'candidate-b'),
    targetName: 'windows-x86_64',
    version: '1.170.0',
  });

  assert.deepEqual(
    first.closure.map(({ path, executable }) => [path, executable]),
    [
      ['osemgrep.exe', true],
      ['runtime.dll', false],
    ],
  );
  assert.deepEqual(await readFile(first.archivePath), await readFile(second.archivePath));
  assert.equal(first.archiveSha256, sha256(await readFile(first.archivePath)));
  assert.deepEqual(
    await readFile(join(first.artifactRoot, 'build-a.MANIFEST.sha256')),
    await readFile(join(first.artifactRoot, 'build-b.MANIFEST.sha256')),
  );
  assert.deepEqual(
    await readFile(join(first.artifactRoot, 'release', 'osemgrep.exe')),
    Buffer.from('native osemgrep'),
  );
  assert.deepEqual(
    await readFile(join(first.artifactRoot, 'release', 'runtime.dll')),
    Buffer.from('native runtime'),
  );
  assert.deepEqual(
    await readFile(join(first.artifactRoot, 'release-evidence', 'version.txt')),
    Buffer.from('1.170.0\n'),
  );
  assert.deepEqual(
    await readFile(join(first.artifactRoot, 'build-a-evidence.MANIFEST.sha256')),
    await readFile(join(first.artifactRoot, 'build-b-evidence.MANIFEST.sha256')),
  );
  assert.deepEqual(
    extractExpectedFile(await readFile(first.archivePath), 'tar.gz', {
      entries: first.closure.map(({ path, size }) => ({ path, type: 'file', size })),
      extractPath: 'osemgrep.exe',
    }),
    Buffer.from('native osemgrep'),
  );
  const closureEvidence = JSON.parse(await readFile(
    join(first.artifactRoot, 'runtime-closure.windows-x86_64.v1.json'),
  ));
  assert.equal(closureEvidence.archive.sha256, first.archiveSha256);
  assert.equal(
    closureEvidence.evidenceArchive.sha256,
    sha256(await readFile(first.evidenceArchivePath)),
  );
  assert.deepEqual(closureEvidence.closure, first.closure);
});

test('runtime artifact derives its canonical release from exact A/B builds without a third build', async () => {
  const fixture = await buildFixture({ includeRelease: false });
  const runtime = await prepareRuntimeArtifact({
    buildRoot: fixture.buildRoot,
    outputRoot: join(fixture.root, 'candidate'),
    targetName: 'windows-x86_64',
    version: '1.170.0',
  });

  assert.deepEqual(
    await readFile(join(runtime.artifactRoot, 'release', 'osemgrep.exe')),
    await readFile(join(fixture.buildRoot, 'build-a', 'osemgrep.exe')),
  );
  assert.deepEqual(
    await readFile(join(runtime.artifactRoot, 'release-evidence', 'MANIFEST.sha256')),
    await readFile(join(fixture.buildRoot, 'build-a-evidence', 'MANIFEST.sha256')),
  );
});

test('runtime artifact rejects an unlisted build-a file before selecting the release', async () => {
  const fixture = await buildFixture();
  await writeFile(join(fixture.buildRoot, 'build-a', 'unexpected.dll'), 'extra');

  await assert.rejects(
    prepareRuntimeArtifact({
      buildRoot: fixture.buildRoot,
      outputRoot: join(fixture.root, 'candidate'),
      targetName: 'windows-x86_64',
      version: '1.170.0',
    }),
    /build-a path inventory mismatch/i,
  );
});

test('runtime artifact rejects a manifest-listed non-runtime file', async () => {
  const fixture = await buildFixture();
  const bytes = Buffer.from('not runtime');
  for (const label of ['build-a', 'build-b', 'release']) {
    await writeFile(join(fixture.buildRoot, label, 'notes.txt'), bytes);
    const manifestPath = join(fixture.buildRoot, `${label}-evidence`, 'MANIFEST.sha256');
    const lines = (await readFile(manifestPath, 'utf8')).trimEnd().split('\n');
    lines.push(`${sha256(bytes)}  notes.txt`);
    lines.sort((left, right) => Buffer.compare(Buffer.from(left.slice(66)), Buffer.from(right.slice(66))));
    await writeFile(manifestPath, `${lines.join('\n')}\n`);
  }

  await assert.rejects(
    prepareRuntimeArtifact({
      buildRoot: fixture.buildRoot,
      outputRoot: join(fixture.root, 'candidate'),
      targetName: 'windows-x86_64',
      version: '1.170.0',
    }),
    /unexpected runtime file/i,
  );
});

test('runtime artifact rejects disagreement between the two build manifests', async () => {
  const fixture = await buildFixture();
  await writeFile(join(fixture.buildRoot, 'build-b-evidence', 'MANIFEST.sha256'), `${'0'.repeat(64)}  osemgrep.exe\n`);

  await assert.rejects(
    prepareRuntimeArtifact({
      buildRoot: fixture.buildRoot,
      outputRoot: join(fixture.root, 'candidate'),
      targetName: 'windows-x86_64',
      version: '1.170.0',
    }),
    /build-b.*(?:sha-256|path inventory)|twice-built.*mismatch/i,
  );
});

test('runtime artifact preserves a pre-existing output root when refusing it', async () => {
  const fixture = await buildFixture();
  const outputRoot = join(fixture.root, 'candidate');
  await mkdir(outputRoot);
  await writeFile(join(outputRoot, 'sentinel'), 'keep');

  await assert.rejects(
    prepareRuntimeArtifact({
      buildRoot: fixture.buildRoot,
      outputRoot,
      targetName: 'windows-x86_64',
      version: '1.170.0',
    }),
    /already exists/i,
  );
  assert.equal(await readFile(join(outputRoot, 'sentinel'), 'utf8'), 'keep');
});

test('exact inventory comparison includes executable metadata', () => {
  const expected = [{ path: 'osemgrep', size: 3, sha256: sha256('bin'), executable: true }];
  const changed = [{ ...expected[0], executable: false }];
  assert.throws(() => assertExactRuntimeInventory(expected, changed), /executable/i);
});

test('candidate smoke document binds runtime while production manifest and source gates stay pending', () => {
  const manifest = {
    allowedReleaseHosts: ['github.com'],
    tools: [{
      id: 'semgrep',
      version: '1.170.0',
      source: { materialPath: 'third_party/sidecars/semgrep/source-lock.v1.json', materialSha256: '0'.repeat(64) },
      targets: [
        { target: 'windows-x86_64', enabled: false, disabledReason: 'pending', reproducibleBuilds: 0, correspondingSourceComplete: false, download: null, executable: null, closure: [] },
        { target: 'macos-aarch64', enabled: false, disabledReason: 'pending', reproducibleBuilds: 0, correspondingSourceComplete: false, download: null, executable: null, closure: [] },
      ],
    }],
  };
  const sourceLock = {
    completeCorrespondingSource: false,
    recursiveInventoryComplete: true,
    opam: { resolvedSourceArchives: [{ package: 'fixture' }], resolvedSourceArchivesComplete: true },
    missingMaterial: [
      'two byte-identical executable and runtime-closure inventories per target',
      'schema-valid Windows builder evidence with the exact Cygwin package-version snapshot',
      'Windows no-Python AppContainer smoke evidence',
      'macOS post-sign entitlement and inherited-sandbox smoke evidence',
    ],
    targetStatus: [
      { distributionTarget: 'windows-x86_64', enabled: false, reason: 'pending' },
      { distributionTarget: 'aarch64-apple-darwin', enabled: false, reason: 'pending' },
    ],
  };
  const runtime = {
    archiveSha256: 'a'.repeat(64),
    archiveSize: 42,
    closure: [{ path: 'osemgrep.exe', size: 7, sha256: 'b'.repeat(64), executable: true }],
  };
  const manifestBefore = structuredClone(manifest);
  const sourceLockBefore = structuredClone(sourceLock);
  const sourceLockSha256 = 'd'.repeat(64);
  const bundleEvidence = {
    schemaVersion: 1,
    sourceLockSha256,
    independentBuilds: 2,
    byteIdentical: true,
    status: 'source_bundle_reproducible_native_builds_pending',
  };
  const result = createCandidateDocuments({
    bundleEvidence,
    bundleEvidenceSha256: 'e'.repeat(64),
    manifest,
    manifestSha256: 'c'.repeat(64),
    runtime,
    sourceLock,
    sourceLockSha256,
    targetName: 'windows-x86_64',
  });
  const document = JSON.parse(result.candidateDocumentBytes);

  assert.deepEqual(manifest, manifestBefore, 'input manifest was mutated');
  assert.deepEqual(sourceLock, sourceLockBefore, 'input source lock was mutated');
  assert.equal(manifest.tools[0].targets[0].enabled, false);
  assert.equal(manifest.tools[0].targets[0].correspondingSourceComplete, false);
  assert.equal(sourceLock.completeCorrespondingSource, false);
  assert.notDeepEqual(sourceLock.missingMaterial, []);
  assert.equal(sourceLock.targetStatus[0].enabled, false);
  assert.equal(document.enabled, false);
  assert.equal(document.publishable, false);
  assert.equal(document.purpose, 'ci-native-sidecar-smoke-only');
  assert.equal(document.archive.sha256, runtime.archiveSha256);
  assert.deepEqual(document.closure, runtime.closure);
  assert.match(result.candidateDigest, /^[0-9a-f]{64}$/);
});

test('candidate documents reject an unexpected missing source or evidence item', () => {
  const manifest = {
    allowedReleaseHosts: ['github.com'],
    tools: [{
      id: 'semgrep',
      source: { materialPath: 'third_party/sidecars/semgrep/source-lock.v1.json', materialSha256: '0'.repeat(64) },
      targets: [{ target: 'windows-x86_64', enabled: false }],
    }],
  };
  const sourceLock = {
    completeCorrespondingSource: false,
    recursiveInventoryComplete: true,
    opam: { resolvedSourceArchives: [{ package: 'fixture' }], resolvedSourceArchivesComplete: true },
    missingMaterial: [
      'two byte-identical executable and runtime-closure inventories per target',
      'schema-valid Windows builder evidence with the exact Cygwin package-version snapshot',
      'Windows no-Python AppContainer smoke evidence',
      'macOS post-sign entitlement and inherited-sandbox smoke evidence',
      'an unrelated source archive is missing',
    ],
    targetStatus: [{ distributionTarget: 'windows-x86_64', enabled: false, reason: 'pending' }],
  };
  const runtime = {
    archiveSha256: 'a'.repeat(64),
    archiveSize: 42,
    closure: [{ path: 'osemgrep.exe', size: 7, sha256: 'b'.repeat(64), executable: true }],
  };

  assert.throws(
    () => createCandidateDocuments({
      bundleEvidence: {
        independentBuilds: 2,
        byteIdentical: true,
        sourceLockSha256: 'd'.repeat(64),
        status: 'source_bundle_reproducible_native_builds_pending',
      },
      bundleEvidenceSha256: 'e'.repeat(64),
      manifest,
      manifestSha256: 'c'.repeat(64),
      runtime,
      sourceLock,
      sourceLockSha256: 'd'.repeat(64),
      targetName: 'windows-x86_64',
    }),
    /unexpected missing material/i,
  );
});

test('pending candidate uses only the programmatic CI cache and production hydration rejects it', async () => {
  const fixture = await buildFixture();
  const runtime = await prepareRuntimeArtifact({
    buildRoot: fixture.buildRoot,
    outputRoot: join(fixture.root, 'candidate-artifact'),
    targetName: 'windows-x86_64',
    version: '1.170.0',
  });
  const workspace = fileURLToPath(new URL('..', import.meta.url));
  const manifest = JSON.parse(await readFile(join(workspace, 'third_party/sidecars/manifest.v1.json')));
  for (const tool of manifest.tools) {
    tool.source.materialSha256 = sha256(await readFile(join(workspace, tool.source.materialPath)));
    tool.license.sha256 = sha256(await readFile(join(workspace, tool.license.path)));
    if (tool.relinking) tool.relinking.sha256 = sha256(await readFile(join(workspace, tool.relinking.path)));
    for (const material of tool.materials) {
      material.sha256 = sha256(await readFile(join(workspace, material.path)));
    }
  }
  for (const tool of manifest.tools.filter(({ id }) => id !== 'semgrep')) {
    const target = tool.targets.find(({ target }) => target === 'windows-x86_64');
    Object.assign(target, {
      closure: [],
      correspondingSourceComplete: false,
      disabledReason: 'test-only candidate isolation',
      download: null,
      enabled: false,
      executable: null,
      reproducibleBuilds: 0,
    });
  }
  const semgrep = manifest.tools.find(({ id }) => id === 'semgrep');
  const sourceLockBytes = await readFile(join(workspace, semgrep.source.materialPath));
  const sourceLock = JSON.parse(sourceLockBytes);
  const bundleEvidencePath = join(workspace, 'third_party/sidecars/semgrep/bundle-evidence.v1.json');
  const bundleEvidenceBytes = await readFile(bundleEvidencePath);
  const bundleEvidence = JSON.parse(bundleEvidenceBytes);
  const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`);
  const documents = createCandidateDocuments({
    bundleEvidence,
    bundleEvidenceSha256: sha256(bundleEvidenceBytes),
    manifest,
    manifestSha256: sha256(manifestBytes),
    runtime,
    sourceLock,
    sourceLockSha256: sha256(sourceLockBytes),
    targetName: 'windows-x86_64',
  });
  const candidateWorkspace = join(fixture.root, 'candidate-workspace');
  await writeCandidateWorkspace(workspace, candidateWorkspace, manifest, documents, manifestBytes);
  const archive = await readFile(runtime.archivePath);
  await assert.rejects(
    hydrateSidecars({ target: 'windows-x86_64', workspace: candidateWorkspace }),
    /no enabled sidecars/i,
  );
  assert.throws(
    () => parseSidecarManifest(documents.candidateDocumentBytes.toString('utf8')),
    /manifest/i,
  );

  const hydrated = await hydrateCiCandidateSidecar({
    archiveBytes: archive,
    candidateDocumentBytes: documents.candidateDocumentBytes,
    target: 'windows-x86_64',
    workspace: candidateWorkspace,
  });
  assert.equal(hydrated.manifestDigest, documents.candidateDigest);
  assert.deepEqual(
    await readFile(join(hydrated.directories.semgrep, 'osemgrep.exe')),
    Buffer.from('native osemgrep'),
  );
  await assert.rejects(
    hydrateCiCandidateSidecar({
      archiveBytes: Buffer.concat([archive, Buffer.from('tampered')]),
      candidateDocumentBytes: documents.candidateDocumentBytes,
      target: 'windows-x86_64',
      workspace: candidateWorkspace,
    }),
    /archive (?:size|sha-256) mismatch/i,
  );
});

test('Windows toolchain evidence normalizes and sorts the exact Cygwin package snapshot', () => {
  const bytes = createWindowsToolchainEvidence({
    cygcheck: 'Cygwin Package Information\r\nPackage              Version\r\nzlib 1.3.1-1\r\nbash 5.2.21-1\r\n',
    facts: {
      commit: 'c'.repeat(40),
      cygwinRelease: '3.6.10(0.341/5/3)',
      imageOs: 'win22',
      imageVersion: '20260713.1.0',
      nodeVersion: 'v24.14.0',
      opamVersion: '2.5.2',
      runAttempt: '2',
      runId: '123',
      runnerArch: 'X64',
      runnerOs: 'Windows',
      rustHost: 'x86_64-pc-windows-msvc',
      rustRelease: '1.97.0',
      setupNodeActionSha: '49933ea5288caeca8642d1e84afbd3f7d6820020',
      setupOcamlActionSha: '3e4c6ff8c9a04c9ec8f6f87701cd4b661b0f1f18',
      windowsVersion: 'Microsoft Windows NT 10.0.20348.0',
    },
  });

  assert.equal(
    bytes.toString(),
    `${JSON.stringify({
      schemaVersion: 1,
      target: 'windows-x86_64',
      commit: 'c'.repeat(40),
      run: { id: 123, attempt: 2 },
      hostedImage: {
        runnerOs: 'Windows',
        runnerArch: 'X64',
        imageOs: 'win22',
        imageVersion: '20260713.1.0',
        windowsVersion: 'Microsoft Windows NT 10.0.20348.0',
      },
      toolchain: {
        setupNodeActionSha: '49933ea5288caeca8642d1e84afbd3f7d6820020',
        setupOcamlActionSha: '3e4c6ff8c9a04c9ec8f6f87701cd4b661b0f1f18',
        nodeVersion: '24.14.0',
        opamVersion: '2.5.2',
        cygwinRelease: '3.6.10(0.341/5/3)',
        rustHost: 'x86_64-pc-windows-msvc',
        rustRelease: '1.97.0',
      },
      cygwinPackages: [
        { name: 'bash', version: '5.2.21-1' },
        { name: 'zlib', version: '1.3.1-1' },
      ],
    }, null, 2)}\n`,
  );
  const stable = createWindowsStableToolchainEvidence(bytes);
  const rerun = JSON.parse(bytes);
  rerun.run = { id: 999, attempt: 7 };
  assert.deepEqual(
    stable,
    createWindowsStableToolchainEvidence(Buffer.from(`${JSON.stringify(rerun, null, 2)}\n`)),
  );
  assert.equal(Object.hasOwn(JSON.parse(stable), 'run'), false);
  assert.throws(
    () => createWindowsToolchainEvidence({
      cygcheck: 'Package Version\nbash 1\nbash 2\n',
      facts: JSON.parse(JSON.stringify({
        commit: 'c'.repeat(40), cygwinRelease: '3.6.10', imageOs: 'win22', imageVersion: '1', nodeVersion: 'v24.14.0', opamVersion: '2.5.2', runAttempt: '1', runId: '1', runnerArch: 'X64', runnerOs: 'Windows', rustHost: 'x86_64-pc-windows-msvc', rustRelease: '1.97.0', setupNodeActionSha: '49933ea5288caeca8642d1e84afbd3f7d6820020', setupOcamlActionSha: '3e4c6ff8c9a04c9ec8f6f87701cd4b661b0f1f18', windowsVersion: 'Windows',
      })),
    }),
    /duplicate cygwin package/i,
  );
});
