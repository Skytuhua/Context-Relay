import { createHash } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  readFile,
  realpath,
  readdir,
  rm,
  writeFile,
} from 'node:fs/promises';
import { basename, dirname, join, parse, resolve } from 'node:path';
import { finished } from 'node:stream/promises';
import { fileURLToPath } from 'node:url';
import { createGzip } from 'node:zlib';

import {
  hydrateCiCandidateSidecar,
  hydrateSidecars,
  parseSidecarManifest,
} from './hydrate-sidecars.mjs';
import { verifyBundleEvidence } from './semgrep-source-bundle.mjs';

const TARGETS = new Map([
  ['windows-x86_64', { executable: 'osemgrep.exe', sourceTarget: 'windows-x86_64' }],
  ['macos-aarch64', { executable: 'osemgrep', sourceTarget: 'aarch64-apple-darwin' }],
]);
const EVIDENCE_FILES = [
  'MANIFEST.sha256',
  'clean.json',
  'clean.stderr',
  'finding.json',
  'finding.stderr',
  'invalid.json',
  'invalid.stderr',
  'runtime-dependencies.txt',
  'version.txt',
];
const BOOTSTRAP_MISSING = [
  'two byte-identical executable and runtime-closure inventories per target',
  'schema-valid Windows builder evidence with the exact Cygwin package-version snapshot',
  'Windows no-Python AppContainer smoke evidence',
  'macOS post-sign entitlement and inherited-sandbox smoke evidence',
];
const MAX_FILES = 128;
const MAX_FILE_BYTES = 512 * 1024 * 1024;
const MAX_TOTAL_BYTES = 1024 * 1024 * 1024;
const SHA256 = /^[0-9a-f]{64}$/;
const COMMIT = /^[0-9a-f]{40}$/;
const SETUP_NODE_SHA = '49933ea5288caeca8642d1e84afbd3f7d6820020';
const SETUP_OCAML_WINDOWS_SHA = '3e4c6ff8c9a04c9ec8f6f87701cd4b661b0f1f18';

function fail(message) {
  throw new Error(`Semgrep runtime candidate: ${message}`);
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function safePath(path, label = 'path') {
  if (typeof path !== 'string' || path.length === 0 || path.normalize('NFC') !== path
      || path.startsWith('/') || path.includes('\\') || /^[A-Za-z]:/.test(path)
      || /[\u0000-\u001f\u007f]/.test(path)) fail(`${label} is unsafe`);
  const parts = path.split('/');
  if (parts.some((part) => part.length === 0 || part === '.' || part === '..')) {
    fail(`${label} is unsafe`);
  }
  return path;
}

function targetPolicy(targetName) {
  const policy = TARGETS.get(targetName);
  if (!policy) fail(`unsupported target: ${targetName}`);
  return policy;
}

async function hashFile(path) {
  const hash = createHash('sha256');
  let size = 0;
  for await (const chunk of createReadStream(path)) {
    size += chunk.length;
    if (size > MAX_FILE_BYTES) fail(`file exceeds size limit: ${basename(path)}`);
    hash.update(chunk);
  }
  return { sha256: hash.digest('hex'), size };
}

function parseManifest(bytes, label) {
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    fail(`${label} is not UTF-8`);
  }
  if (!text.endsWith('\n')) fail(`${label} must end with LF`);
  const entries = [];
  const seen = new Set();
  for (const line of text.replace(/\r\n/g, '\n').split('\n').slice(0, -1)) {
    const match = /^([0-9a-f]{64})  (.+)$/.exec(line);
    if (!match) fail(`${label} contains a malformed line`);
    const path = safePath(match[2].startsWith('./') ? match[2].slice(2) : match[2], `${label} path`);
    if (path.includes('/')) fail(`${label} must describe a flat runtime directory`);
    if (seen.has(path)) fail(`${label} contains a duplicate path`);
    seen.add(path);
    entries.push({ path, sha256: match[1] });
  }
  const sorted = [...entries].sort((left, right) => compareUtf8(left.path, right.path));
  if (JSON.stringify(entries) !== JSON.stringify(sorted)) fail(`${label} paths are not canonical`);
  if (entries.length === 0 || entries.length > MAX_FILES) fail(`${label} file count is invalid`);
  return entries;
}

async function flatFiles(root, label) {
  const rootInfo = await lstat(root);
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) fail(`${label} is not a no-link directory`);
  const entries = await readdir(root, { withFileTypes: true });
  if (entries.length > MAX_FILES + 1) fail(`${label} contains too many files`);
  const names = [];
  for (const entry of entries) {
    if (!entry.isFile() || entry.isSymbolicLink()) fail(`${label} contains non-regular content: ${entry.name}`);
    safePath(entry.name, `${label} file`);
    names.push(entry.name);
  }
  return names.sort(compareUtf8);
}

function executableBit(targetName, path, mode) {
  if (targetName === 'windows-x86_64') return path === 'osemgrep.exe';
  return (mode & 0o111) !== 0;
}

async function readBuildDirectory(root, evidenceRoot, targetName, label) {
  const manifestBytes = await readFile(join(evidenceRoot, 'MANIFEST.sha256'));
  const declared = parseManifest(manifestBytes, `${label} MANIFEST.sha256`);
  const actual = await flatFiles(root, label);
  const expected = declared.map(({ path }) => path);
  if (JSON.stringify(actual) !== JSON.stringify(expected)) fail(`${label} path inventory mismatch`);
  const inventory = [];
  let total = 0;
  for (const entry of declared) {
    const path = join(root, entry.path);
    const info = await lstat(path);
    if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1) fail(`${label} contains unsafe topology: ${entry.path}`);
    const digest = await hashFile(path);
    total += digest.size;
    if (total > MAX_TOTAL_BYTES) fail(`${label} exceeds aggregate size limit`);
    if (digest.sha256 !== entry.sha256) fail(`${label} SHA-256 mismatch: ${entry.path}`);
    inventory.push({
      executable: executableBit(targetName, entry.path, info.mode),
      path: entry.path,
      sha256: digest.sha256,
      size: digest.size,
    });
  }
  const policy = targetPolicy(targetName);
  const executable = inventory.find((entry) => entry.path === policy.executable);
  if (!executable?.executable) fail(`${label} has no exact executable`);
  for (const entry of inventory) {
    if (entry.path !== policy.executable && entry.executable) fail(`${label} has an unexpected executable: ${entry.path}`);
    if (targetName === 'windows-x86_64'
        && entry.path !== policy.executable
        && !entry.path.toLowerCase().endsWith('.dll')) fail(`${label} has an unexpected runtime file: ${entry.path}`);
  }
  if (targetName === 'macos-aarch64' && inventory.length !== 1) fail(`${label} has an unexpected runtime file`);
  return { inventory, manifestBytes, root };
}

async function readEvidenceDirectory(root, label, version) {
  const names = await flatFiles(root, label);
  if (JSON.stringify(names) !== JSON.stringify(EVIDENCE_FILES)) fail(`${label} path inventory mismatch`);
  const inventory = [];
  for (const path of names) {
    const info = await lstat(join(root, path));
    if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1) fail(`${label} contains unsafe topology: ${path}`);
    inventory.push({ executable: false, path, ...await hashFile(join(root, path)) });
  }
  const actualVersion = new TextDecoder('utf-8', { fatal: true })
    .decode(await readFile(join(root, 'version.txt')))
    .trim();
  if (actualVersion !== version) fail(`${label} version mismatch`);
  return { inventory, root };
}

export function assertExactRuntimeInventory(expected, actual) {
  if (!Array.isArray(expected) || !Array.isArray(actual)) fail('runtime inventories must be arrays');
  if (expected.length !== actual.length) fail('runtime path inventory mismatch');
  for (let index = 0; index < expected.length; index += 1) {
    const left = expected[index];
    const right = actual[index];
    if (left.path !== right.path) fail('runtime path inventory mismatch');
    for (const field of ['size', 'sha256', 'executable']) {
      if (left[field] !== right[field]) fail(`runtime ${field} mismatch: ${left.path}`);
    }
  }
}

function inventoryManifest(inventory) {
  return Buffer.from(inventory.map(({ path, sha256 }) => `${sha256}  ${path}\n`).join(''));
}

function writeOctal(header, offset, length, value) {
  const encoded = value.toString(8).padStart(length - 1, '0');
  if (encoded.length !== length - 1) fail('tar numeric field overflow');
  header.write(encoded, offset, length - 1, 'ascii');
  header[offset + length - 1] = 0;
}

function tarHeader(entry) {
  const name = Buffer.from(entry.path, 'utf8');
  if (name.length > 100) fail(`tar path is too long: ${entry.path}`);
  const header = Buffer.alloc(512);
  name.copy(header, 0);
  writeOctal(header, 100, 8, entry.executable ? 0o755 : 0o644);
  writeOctal(header, 108, 8, 0);
  writeOctal(header, 116, 8, 0);
  writeOctal(header, 124, 12, entry.size);
  writeOctal(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  header[156] = '0'.charCodeAt(0);
  header.write('ustar\0', 257, 6, 'ascii');
  header.write('00', 263, 2, 'ascii');
  writeOctal(header, 148, 8, [...header].reduce((sum, byte) => sum + byte, 0));
  return header;
}

async function writeChunk(stream, bytes) {
  if (stream.write(bytes)) return;
  await new Promise((accept, reject) => {
    stream.once('drain', accept);
    stream.once('error', reject);
  });
}

async function writeArchive(path, sourceRoot, inventory) {
  const output = createWriteStream(path, { flags: 'wx', mode: 0o600 });
  const gzip = createGzip({ level: 9, mtime: 0 });
  gzip.pipe(output);
  for (const entry of inventory) {
    await writeChunk(gzip, tarHeader(entry));
    let read = 0;
    for await (const chunk of createReadStream(join(sourceRoot, entry.path))) {
      read += chunk.length;
      await writeChunk(gzip, chunk);
    }
    if (read !== entry.size) fail(`file changed while archiving: ${entry.path}`);
    const padding = (512 - (entry.size % 512)) % 512;
    if (padding) await writeChunk(gzip, Buffer.alloc(padding));
  }
  await writeChunk(gzip, Buffer.alloc(1024));
  gzip.end();
  await Promise.all([finished(gzip), finished(output)]);
  return hashFile(path);
}

async function copyRuntimeFiles(source, destination, inventory) {
  await mkdir(destination);
  for (const entry of inventory) {
    const target = join(destination, entry.path);
    await copyFile(join(source, entry.path), target);
    await chmod(target, entry.executable ? 0o755 : 0o644);
  }
}

export async function prepareRuntimeArtifact({ buildRoot, outputRoot, targetName, version }) {
  targetPolicy(targetName);
  if (typeof version !== 'string' || !/^\d+\.\d+\.\d+$/.test(version)) fail('version is invalid');
  buildRoot = resolve(buildRoot);
  outputRoot = resolve(outputRoot);
  if (outputRoot === parse(outputRoot).root || outputRoot === buildRoot || outputRoot.startsWith(`${buildRoot}\\`) || outputRoot.startsWith(`${buildRoot}/`)) {
    fail('output root is unsafe');
  }
  try {
    await lstat(outputRoot);
    fail('output root already exists');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  let created = false;
  try {
    await mkdir(outputRoot);
    created = true;
    const aEvidence = await readEvidenceDirectory(join(buildRoot, 'build-a-evidence'), 'build-a evidence', version);
    const bEvidence = await readEvidenceDirectory(join(buildRoot, 'build-b-evidence'), 'build-b evidence', version);
    const a = await readBuildDirectory(join(buildRoot, 'build-a'), aEvidence.root, targetName, 'build-a');
    const b = await readBuildDirectory(join(buildRoot, 'build-b'), bEvidence.root, targetName, 'build-b');
    if (!a.manifestBytes.equals(b.manifestBytes)) {
      fail('twice-built MANIFEST.sha256 mismatch');
    }
    assertExactRuntimeInventory(a.inventory, b.inventory);
    assertExactRuntimeInventory(aEvidence.inventory, bEvidence.inventory);
    const closure = a.inventory;
    const artifactRoot = join(outputRoot, 'artifact');
    await mkdir(artifactRoot);
    await copyRuntimeFiles(a.root, join(artifactRoot, 'release'), closure);
    await writeFile(join(artifactRoot, 'build-a.MANIFEST.sha256'), a.manifestBytes, { flag: 'wx' });
    await writeFile(join(artifactRoot, 'build-b.MANIFEST.sha256'), b.manifestBytes, { flag: 'wx' });
    await writeFile(join(artifactRoot, 'build-a-evidence.MANIFEST.sha256'), inventoryManifest(aEvidence.inventory), { flag: 'wx' });
    await writeFile(join(artifactRoot, 'build-b-evidence.MANIFEST.sha256'), inventoryManifest(bEvidence.inventory), { flag: 'wx' });
    await copyRuntimeFiles(aEvidence.root, join(artifactRoot, 'release-evidence'), aEvidence.inventory);
    const archiveName = `semgrep-${version}-${targetName}.tar.gz`;
    const archivePath = join(artifactRoot, archiveName);
    const comparisonPath = join(outputRoot, 'runtime-build-b.tar.gz');
    const archiveA = await writeArchive(archivePath, a.root, a.inventory);
    const archiveB = await writeArchive(comparisonPath, b.root, b.inventory);
    if (archiveA.size !== archiveB.size || archiveA.sha256 !== archiveB.sha256) {
      fail('twice-built runtime archives differ');
    }
    await rm(comparisonPath);
    const evidenceArchiveName = `semgrep-${version}-${targetName}-release-evidence.tar.gz`;
    const evidenceArchivePath = join(artifactRoot, evidenceArchiveName);
    const evidenceComparisonPath = join(outputRoot, 'evidence-build-b.tar.gz');
    const evidenceArchiveA = await writeArchive(evidenceArchivePath, aEvidence.root, aEvidence.inventory);
    const evidenceArchiveB = await writeArchive(evidenceComparisonPath, bEvidence.root, bEvidence.inventory);
    if (evidenceArchiveA.size !== evidenceArchiveB.size || evidenceArchiveA.sha256 !== evidenceArchiveB.sha256) {
      fail('twice-built evidence archives differ');
    }
    await rm(evidenceComparisonPath);
    await writeFile(
      join(artifactRoot, `runtime-closure.${targetName}.v1.json`),
      jsonBytes({
        schemaVersion: 1,
        target: targetName,
        archive: { name: archiveName, size: archiveA.size, sha256: archiveA.sha256 },
        evidenceArchive: {
          name: evidenceArchiveName,
          size: evidenceArchiveA.size,
          sha256: evidenceArchiveA.sha256,
        },
        closure,
      }),
      { flag: 'wx' },
    );
    return {
      archiveName,
      archivePath,
      archiveSha256: archiveA.sha256,
      archiveSize: archiveA.size,
      artifactRoot,
      closure,
      evidenceArchiveName,
      evidenceArchivePath,
    };
  } catch (error) {
    if (created) await rm(outputRoot, { force: true, recursive: true });
    throw error;
  }
}

function jsonBytes(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
}

export function createCandidateDocuments({
  bundleEvidence,
  bundleEvidenceSha256,
  manifest,
  manifestSha256,
  runtime,
  sourceLock,
  sourceLockSha256,
  targetName,
}) {
  const policy = targetPolicy(targetName);
  for (const [value, label] of [
    [manifestSha256, 'manifest'],
    [sourceLockSha256, 'source lock'],
    [bundleEvidenceSha256, 'bundle evidence'],
  ]) {
    if (!SHA256.test(value)) fail(`${label} identity is invalid`);
  }
  if (!SHA256.test(runtime.archiveSha256)
      || !Number.isSafeInteger(runtime.archiveSize)
      || runtime.archiveSize <= 0) {
    fail('runtime archive identity is invalid');
  }
  if (sourceLock.completeCorrespondingSource !== false
      || sourceLock.recursiveInventoryComplete !== true
      || sourceLock.opam?.resolvedSourceArchivesComplete !== true
      || !Array.isArray(sourceLock.opam?.resolvedSourceArchives)
      || sourceLock.opam.resolvedSourceArchives.length === 0) {
    fail('candidate source lock is not an incomplete but fully resolved bootstrap lock');
  }
  const missing = sourceLock.missingMaterial;
  if (!Array.isArray(missing)
      || missing.length !== BOOTSTRAP_MISSING.length
      || new Set(missing).size !== missing.length
      || missing.some((item) => !BOOTSTRAP_MISSING.includes(item))) {
    fail('candidate source lock contains unexpected missing material');
  }
  const statuses = sourceLock.targetStatus?.filter(({ distributionTarget }) => distributionTarget === policy.sourceTarget) ?? [];
  if (statuses.length !== 1 || statuses[0].enabled !== false) {
    fail('candidate source target status is missing, ambiguous, or already enabled');
  }
  if (!bundleEvidence || typeof bundleEvidence !== 'object' || Array.isArray(bundleEvidence)
      || bundleEvidence.sourceLockSha256 !== sourceLockSha256
      || bundleEvidence.independentBuilds !== 2
      || bundleEvidence.byteIdentical !== true
      || bundleEvidence.status !== 'source_bundle_reproducible_native_builds_pending') {
    fail('candidate bundle evidence is not honestly pending and reproducible');
  }

  const semgrep = manifest.tools?.find(({ id }) => id === 'semgrep');
  if (!semgrep) fail('Semgrep manifest entry is missing');
  const targets = semgrep.targets?.filter(({ target }) => target === targetName) ?? [];
  if (targets.length !== 1
      || targets[0].enabled !== false
      || targets[0].correspondingSourceComplete !== false
      || targets[0].download !== null
      || targets[0].executable !== null
      || !Array.isArray(targets[0].closure)
      || targets[0].closure.length !== 0) {
    fail('candidate target must remain uniquely disabled and non-runnable');
  }
  const target = targets[0];
  const archive = {
    format: 'tar.gz',
    size: runtime.archiveSize,
    sha256: runtime.archiveSha256,
    entries: runtime.closure.map(({ path, size }) => ({ path, type: 'file', size })),
    extractPath: policy.executable,
  };
  const executable = runtime.closure.find(({ path }) => path === policy.executable);
  if (!executable?.executable) fail('runtime executable is missing');
  const candidateDocumentBytes = jsonBytes({
    schemaVersion: 1,
    purpose: 'ci-native-sidecar-smoke-only',
    publishable: false,
    enabled: false,
    target: targetName,
    sidecar: 'semgrep',
    version: semgrep.version,
    productionManifestSha256: manifestSha256,
    sourceLockSha256,
    bundleEvidenceSha256,
    bundleEvidenceStatus: bundleEvidence.status,
    archive,
    executable: { path: executable.path, size: executable.size, sha256: executable.sha256 },
    closure: structuredClone(runtime.closure),
  });
  const candidateDigest = sha256(Buffer.concat([
    Buffer.from('context-relay/ci-candidate-sidecar-smoke/v1\0'),
    candidateDocumentBytes,
  ]));
  return {
    candidateDigest,
    candidateDocumentBytes,
    documentRelativePath: `third_party/sidecars/semgrep/ci-candidate-closure.${targetName}.v1.json`,
    target,
  };
}

async function readNoLink(workspace, relative) {
  safePath(relative, 'material path');
  let current = resolve(workspace);
  for (const part of relative.split('/')) {
    current = join(current, part);
    const info = await lstat(current);
    if (info.isSymbolicLink()) fail(`material contains a link: ${relative}`);
  }
  const info = await lstat(current);
  if (!info.isFile() || info.size > 16 * 1024 * 1024) fail(`material is not a bounded regular file: ${relative}`);
  return readFile(current);
}

export async function writeCandidateWorkspace(workspace, candidateRoot, manifest, documents, manifestBytes) {
  if (!Buffer.isBuffer(manifestBytes) || sha256(manifestBytes) !== JSON.parse(documents.candidateDocumentBytes).productionManifestSha256) {
    fail('candidate production manifest bytes do not match the smoke document');
  }
  await mkdir(candidateRoot);
  const paths = new Set();
  for (const tool of manifest.tools) {
    paths.add(tool.source.materialPath);
    paths.add(tool.license.path);
    if (tool.relinking) paths.add(tool.relinking.path);
    for (const material of tool.materials) paths.add(material.path);
  }
  for (const relative of [...paths].sort(compareUtf8)) {
    const destination = join(candidateRoot, ...relative.split('/'));
    await mkdir(dirname(destination), { recursive: true });
    await writeFile(destination, await readNoLink(workspace, relative), { flag: 'wx' });
  }
  const manifestPath = join(candidateRoot, 'third_party', 'sidecars', 'manifest.v1.json');
  await mkdir(dirname(manifestPath), { recursive: true });
  await writeFile(manifestPath, manifestBytes, { flag: 'wx' });
  const documentPath = join(candidateRoot, ...documents.documentRelativePath.split('/'));
  await mkdir(dirname(documentPath), { recursive: true });
  await writeFile(documentPath, documents.candidateDocumentBytes, { flag: 'wx' });
}

function enabledTargetMatchesRuntime(target, runtime, targetName) {
  const policy = targetPolicy(targetName);
  let url;
  try {
    url = new URL(target.download?.url);
  } catch {
    fail('enabled target URL is invalid');
  }
  if (url.protocol !== 'https:' || url.hostname === 'candidate.contextrelay.invalid') {
    fail('enabled target must use its stable HTTPS production URL');
  }
  if (target.download?.format !== 'tar.gz'
      || target.download.size !== runtime.archiveSize
      || target.download.sha256 !== runtime.archiveSha256
      || target.download.extractPath !== policy.executable) fail('enabled target archive does not match the current build');
  const entries = runtime.closure.map(({ path, size }) => ({ path, type: 'file', size }));
  if (JSON.stringify(target.download.entries) !== JSON.stringify(entries)) fail('enabled target archive inventory mismatch');
  assertExactRuntimeInventory(runtime.closure, target.closure);
  const executable = runtime.closure.find(({ path }) => path === policy.executable);
  if (JSON.stringify(target.executable) !== JSON.stringify({ path: executable.path, size: executable.size, sha256: executable.sha256 })) {
    fail('enabled target executable mismatch');
  }
}

async function hydratedInventory(root, targetName) {
  const names = await flatFiles(root, 'hydrated Semgrep closure');
  const inventory = [];
  for (const path of names) {
    const info = await lstat(join(root, path));
    const digest = await hashFile(join(root, path));
    inventory.push({ executable: executableBit(targetName, path, info.mode), path, ...digest });
  }
  return inventory;
}

export async function prepareAndHydrate({
  buildRoot,
  bundleEvidencePath,
  outputRoot,
  sourceBundlePath,
  targetName,
  workspace,
}) {
  workspace = resolve(workspace);
  const manifestBytes = await readFile(join(workspace, 'third_party', 'sidecars', 'manifest.v1.json'));
  const manifest = parseSidecarManifest(new TextDecoder('utf-8', { fatal: true }).decode(manifestBytes));
  const semgrep = manifest.tools.find(({ id }) => id === 'semgrep');
  const target = semgrep.targets.find((entry) => entry.target === targetName);
  const sourceLockPath = join(workspace, ...semgrep.source.materialPath.split('/'));
  const committedEvidencePath = join(workspace, 'third_party', 'sidecars', 'semgrep', 'bundle-evidence.v1.json');
  if (resolve(bundleEvidencePath) !== resolve(committedEvidencePath)) fail('bundle evidence must be the committed evidence document');
  await verifyBundleEvidence({
    bundlePath: resolve(sourceBundlePath),
    evidencePath: committedEvidencePath,
    sourceLockPath,
  });
  const runtime = await prepareRuntimeArtifact({ buildRoot, outputRoot, targetName, version: semgrep.version });
  let hydrationWorkspace = workspace;
  let result;
  let mode;
  let candidateDigest = null;
  let candidateDocumentPath = null;
  if (target.enabled) {
    enabledTargetMatchesRuntime(target, runtime, targetName);
    result = await hydrateSidecars({ target: targetName, workspace });
    mode = 'enabled';
  } else {
    const sourceLockBytes = await readFile(sourceLockPath);
    const sourceLock = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(sourceLockBytes));
    const bundleEvidenceBytes = await readFile(committedEvidencePath);
    const bundleEvidence = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bundleEvidenceBytes));
    const rawManifest = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(manifestBytes));
    const documents = createCandidateDocuments({
      bundleEvidence,
      bundleEvidenceSha256: sha256(bundleEvidenceBytes),
      manifest: rawManifest,
      manifestSha256: sha256(manifestBytes),
      runtime,
      sourceLock,
      sourceLockSha256: sha256(sourceLockBytes),
      targetName,
    });
    hydrationWorkspace = join(resolve(outputRoot), 'candidate-workspace');
    await writeCandidateWorkspace(workspace, hydrationWorkspace, rawManifest, documents, manifestBytes);
    result = await hydrateCiCandidateSidecar({
      archiveBytes: await readFile(runtime.archivePath),
      candidateDocumentBytes: documents.candidateDocumentBytes,
      target: targetName,
      workspace: hydrationWorkspace,
    });
    candidateDigest = documents.candidateDigest;
    candidateDocumentPath = await realpath(join(hydrationWorkspace, ...documents.documentRelativePath.split('/')));
    mode = 'candidate';
  }
  if (mode === 'enabled') {
    await hydrateSidecars({ target: targetName, verifyOnly: true, workspace: hydrationWorkspace });
  }
  for (const id of ['rulesync', 'gitleaks', 'semgrep']) {
    if (resolve(result.directories[id] ?? '') !== resolve(result.directory, id)) {
      fail(`hydrated ${id} root is missing or noncanonical`);
    }
    const info = await lstat(result.directories[id]);
    if (!info.isDirectory() || info.isSymbolicLink()) fail(`hydrated ${id} root is unsafe`);
  }
  const hydratedRoot = resolve(result.directories.semgrep);
  assertExactRuntimeInventory(runtime.closure, await hydratedInventory(hydratedRoot, targetName));
  return {
    ...runtime,
    candidateDigest,
    candidateDocumentPath,
    candidateWorkspace: mode === 'candidate' ? await realpath(hydrationWorkspace) : null,
    hydrationRoot: await realpath(result.directory),
    mode,
  };
}

function exactObject(value, keys, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) fail(`${label} keys are invalid`);
}

function requiredText(value, label) {
  if (typeof value !== 'string' || value.length === 0 || /[\r\n\u0000]/.test(value)) fail(`${label} is invalid`);
  return value;
}

export function createWindowsToolchainEvidence({ cygcheck, facts }) {
  exactObject(facts, [
    'commit', 'cygwinRelease', 'imageOs', 'imageVersion', 'nodeVersion', 'opamVersion',
    'runAttempt', 'runId', 'runnerArch', 'runnerOs', 'rustHost', 'rustRelease',
    'setupNodeActionSha', 'setupOcamlActionSha', 'windowsVersion',
  ], 'Windows evidence facts');
  if (!COMMIT.test(facts.commit)) fail('commit is invalid');
  if (facts.runnerOs !== 'Windows' || facts.runnerArch !== 'X64') fail('hosted runner identity mismatch');
  if (facts.setupNodeActionSha !== SETUP_NODE_SHA || facts.setupOcamlActionSha !== SETUP_OCAML_WINDOWS_SHA) fail('setup action identity mismatch');
  if (facts.nodeVersion !== 'v24.14.0' || facts.opamVersion !== '2.5.2') fail('tool version mismatch');
  if (!facts.cygwinRelease.startsWith('3.6.10') || facts.rustHost !== 'x86_64-pc-windows-msvc') fail('Windows toolchain host mismatch');
  const id = Number(facts.runId);
  const attempt = Number(facts.runAttempt);
  if (!Number.isSafeInteger(id) || id <= 0 || !Number.isSafeInteger(attempt) || attempt <= 0) fail('run identity is invalid');
  for (const key of ['imageOs', 'imageVersion', 'windowsVersion', 'rustRelease']) requiredText(facts[key], key);
  if (typeof cygcheck !== 'string') fail('cygcheck output is invalid');
  const packages = [];
  const names = new Set();
  for (const raw of cygcheck.replace(/\r\n/g, '\n').split('\n')) {
    const line = raw.replace(/^[ \t]+|[ \t]+$/g, '');
    if (!line || line === 'Cygwin Package Information' || /^Package[ \t]+Version$/.test(line)) continue;
    const match = /^([^ \t]+)[ \t]+([^ \t]+)$/.exec(line);
    if (!match) fail('cygcheck output contains a malformed line');
    const [, name, version] = match;
    requiredText(name, 'Cygwin package name');
    requiredText(version, 'Cygwin package version');
    if (names.has(name)) fail(`duplicate Cygwin package: ${name}`);
    names.add(name);
    packages.push({ name, version });
  }
  if (packages.length === 0) fail('Cygwin package snapshot is empty');
  packages.sort((left, right) => compareUtf8(left.name, right.name) || compareUtf8(left.version, right.version));
  const evidence = {
    schemaVersion: 1,
    target: 'windows-x86_64',
    commit: facts.commit,
    run: { id, attempt },
    hostedImage: {
      runnerOs: facts.runnerOs,
      runnerArch: facts.runnerArch,
      imageOs: facts.imageOs,
      imageVersion: facts.imageVersion,
      windowsVersion: facts.windowsVersion,
    },
    toolchain: {
      setupNodeActionSha: facts.setupNodeActionSha,
      setupOcamlActionSha: facts.setupOcamlActionSha,
      nodeVersion: facts.nodeVersion.slice(1),
      opamVersion: facts.opamVersion,
      cygwinRelease: facts.cygwinRelease,
      rustHost: facts.rustHost,
      rustRelease: facts.rustRelease,
    },
    cygwinPackages: packages,
  };
  assertWindowsEvidenceValue(evidence);
  return jsonBytes(evidence);
}

function assertWindowsEvidenceValue(value) {
  exactObject(value, [
    'schemaVersion', 'target', 'commit', 'run', 'hostedImage', 'toolchain', 'cygwinPackages',
  ], 'Windows builder evidence');
  if (value.schemaVersion !== 1 || value.target !== 'windows-x86_64' || !COMMIT.test(value.commit)) fail('Windows builder evidence identity is invalid');
  exactObject(value.run, ['id', 'attempt'], 'Windows builder run evidence');
  if (!Number.isSafeInteger(value.run.id) || value.run.id <= 0
      || !Number.isSafeInteger(value.run.attempt) || value.run.attempt <= 0) fail('Windows builder run evidence is invalid');
  exactObject(value.hostedImage, [
    'runnerOs', 'runnerArch', 'imageOs', 'imageVersion', 'windowsVersion',
  ], 'Windows hosted image evidence');
  if (value.hostedImage.runnerOs !== 'Windows' || value.hostedImage.runnerArch !== 'X64') fail('Windows hosted image identity is invalid');
  for (const key of ['imageOs', 'imageVersion', 'windowsVersion']) requiredText(value.hostedImage[key], key);
  exactObject(value.toolchain, [
    'setupNodeActionSha', 'setupOcamlActionSha', 'nodeVersion', 'opamVersion',
    'cygwinRelease', 'rustHost', 'rustRelease',
  ], 'Windows toolchain evidence');
  if (value.toolchain.setupNodeActionSha !== SETUP_NODE_SHA
      || value.toolchain.setupOcamlActionSha !== SETUP_OCAML_WINDOWS_SHA
      || value.toolchain.nodeVersion !== '24.14.0'
      || value.toolchain.opamVersion !== '2.5.2'
      || !value.toolchain.cygwinRelease.startsWith('3.6.10')
      || value.toolchain.rustHost !== 'x86_64-pc-windows-msvc') fail('Windows toolchain evidence identity is invalid');
  requiredText(value.toolchain.rustRelease, 'rustRelease');
  if (!Array.isArray(value.cygwinPackages) || value.cygwinPackages.length === 0) fail('Windows Cygwin package evidence is invalid');
  const packages = new Set();
  let previous = null;
  for (const entry of value.cygwinPackages) {
    exactObject(entry, ['name', 'version'], 'Windows Cygwin package evidence');
    if (!/^\S+$/.test(entry.name) || !/^\S+$/.test(entry.version) || packages.has(entry.name)) fail('Windows Cygwin package evidence is invalid');
    if (previous && (compareUtf8(previous.name, entry.name) || compareUtf8(previous.version, entry.version)) > 0) fail('Windows Cygwin package evidence is not canonical');
    packages.add(entry.name);
    previous = entry;
  }
}

export function createWindowsStableToolchainEvidence(bytes) {
  let evidence;
  try {
    evidence = JSON.parse(Buffer.isBuffer(bytes) ? bytes.toString('utf8') : bytes);
  } catch {
    fail('Windows builder evidence JSON is invalid');
  }
  assertWindowsEvidenceValue(evidence);
  return jsonBytes({
    schemaVersion: evidence.schemaVersion,
    target: evidence.target,
    commit: evidence.commit,
    hostedImage: evidence.hostedImage,
    toolchain: evidence.toolchain,
    cygwinPackages: evidence.cygwinPackages,
  });
}

async function command() {
  const [mode, ...args] = process.argv.slice(2);
  if (mode === '--prepare' && args.length === 12) {
    const values = Object.fromEntries(Array.from({ length: 6 }, (_, index) => [args[index * 2], args[index * 2 + 1]]));
    if (JSON.stringify(Object.keys(values).sort()) !== JSON.stringify([
      '--build-root', '--bundle-evidence', '--output-root', '--source-bundle', '--target', '--workspace',
    ])) fail('prepare arguments are invalid');
    const result = await prepareAndHydrate({
      buildRoot: values['--build-root'],
      bundleEvidencePath: values['--bundle-evidence'],
      outputRoot: values['--output-root'],
      sourceBundlePath: values['--source-bundle'],
      targetName: values['--target'],
      workspace: values['--workspace'],
    });
    process.stdout.write(`${JSON.stringify(result)}\n`);
    return;
  }
  if (mode === '--windows-evidence' && args.length === 3) {
    const facts = JSON.parse(await readFile(args[0], 'utf8'));
    const cygcheck = await readFile(args[1], 'utf8');
    await writeFile(args[2], createWindowsToolchainEvidence({ cygcheck, facts }), { flag: 'wx' });
    return;
  }
  if (mode === '--windows-stable-toolchain' && args.length === 2) {
    await writeFile(args[1], createWindowsStableToolchainEvidence(await readFile(args[0])), { flag: 'wx' });
    return;
  }
  fail('usage: --prepare --workspace ROOT --target TARGET --build-root ROOT --output-root ROOT --source-bundle TAR --bundle-evidence JSON | --windows-evidence FACTS.json CYGCHECK.txt OUTPUT.json | --windows-stable-toolchain BUILDER.json OUTPUT.json');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  command().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
