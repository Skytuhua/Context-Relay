import { createHash } from 'node:crypto';
import {
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  rm,
  writeFile,
} from 'node:fs/promises';
import { dirname, join, parse, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { gunzipSync } from 'node:zlib';

import {
  parseSidecarManifest,
  validateManifestMaterials,
  validateSemgrepNativeBuildEvidence,
} from './hydrate-sidecars.mjs';
import { parseNativeSmokeEvidence } from './native-smoke-evidence.mjs';
import { createWindowsStableToolchainEvidence } from './prepare-semgrep-runtime.mjs';
import { resealSemgrepSourceBundle } from './reseal-semgrep-source-bundle.mjs';
import { verifyBundleEvidence } from './semgrep-source-bundle.mjs';
import { validateIndependentBuilderIdentities } from './verify-native-builder-identities.mjs';

const VERSION = '1.170.0';
const SEMGREP_REVISION = 'bd614accba811b407ae5c9ec6f1eecd3bdc29911';
const SEMGREP_TREE = 'ad8e607874820dc7253d58997736463ed258ea34';
const RELEASE_TAG = 'sidecars-semgrep-1.170.0-source.1';
const RELEASE_BASE = `https://github.com/Skytuhua/Context-Relay/releases/download/${RELEASE_TAG}`;
const SOURCE_ASSET = `semgrep-${VERSION}-corresponding-source.tar`;
const SOURCE_URL = `${RELEASE_BASE}/${SOURCE_ASSET}`;
const SHA256 = /^[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;
const MAX_DOCUMENT = 16 * 1024 * 1024;
const MAX_ARCHIVE = 512 * 1024 * 1024;
const MAX_TAR = 1280 * 1024 * 1024;
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
const MACOS_HOMEBREW_PACKAGES = [
  'curl', 'dwarfutils', 'gmp', 'libev', 'libunwind-headers', 'pcre2', 'pkgconf', 'zstd',
];
const MISSING = [
  'two byte-identical executable and runtime-closure inventories per target',
  'schema-valid Windows builder evidence with the exact Cygwin package-version snapshot',
  'Windows no-Python AppContainer smoke evidence',
  'macOS post-sign entitlement and inherited-sandbox smoke evidence',
];
const SOURCE_LOCK_KEYS = [
  'schemaVersion', 'project', 'version', 'tag', 'tagObject', 'repository',
  'sourceRevision', 'sourceTree', 'license', 'licenseMaterials', 'additionalArchives',
  'completeCorrespondingSource', 'recursiveInventoryComplete', 'rootGitlinks', 'opam',
  'sourceFiles', 'actions', 'toolchains', 'buildCommands', 'patchInventory',
  'manifestRule', 'targetStatus', 'researchEvidence', 'missingMaterial', 'commandTemplate',
];
const TARGETS = new Map([
  ['windows-x86_64', {
    executable: 'osemgrep.exe',
    jobDefinition: 'native-semgrep-windows-x64-builders',
    artifactPrefix: 'task9-semgrep-windows-build',
    smokeJob: 'native-isolation-windows-x64',
    sourceTarget: 'windows-x86_64',
    pendingReason: 'pending_two_matching_public_source_builds_and_no_python_smoke',
    offline: '{"mechanism":"windows-firewall-default-outbound-block-hash-pinned-runner-tcp443-allow","probe":"hostile-outbound-tcp-denied","schemaVersion":1}\n',
  }],
  ['macos-aarch64', {
    executable: 'osemgrep',
    jobDefinition: 'native-semgrep-macos-arm64-builders',
    artifactPrefix: 'task9-semgrep-macos-build',
    smokeJob: 'native-isolation-macos-arm64',
    sourceTarget: 'aarch64-apple-darwin',
    pendingReason: 'pending_two_matching_public_source_builds_post_sign_inventory_and_sandbox_smoke',
    offline: '{"mechanism":"macos-sandbox-exec-network-deny","probe":"hostile-outbound-tcp-denied-with-eperm-or-eacces","schemaVersion":1}\n',
  }],
]);
const SUPPORT = [
  ['native-ci-provenance', 'third_party/sidecars/semgrep/native-ci-provenance.v1.json'],
  ['native-release-finalizer', 'scripts/finalize-semgrep-native-release.mjs'],
  ['source-bundle-reseal', 'scripts/reseal-semgrep-source-bundle.mjs'],
];

function fail(message) {
  throw new Error(`Semgrep native release finalizer: ${message}`);
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function jsonBytes(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
}

function exact(value, keys, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || JSON.stringify(Object.keys(value).sort(compareUtf8)) !== JSON.stringify([...keys].sort(compareUtf8))) {
    fail(`${label} keys are invalid`);
  }
}

function safeName(value, label) {
  if (typeof value !== 'string' || value.length === 0 || value.includes('/') || value.includes('\\')
      || value === '.' || value === '..' || value.normalize('NFC') !== value
      || /[\u0000-\u001f\u007f]/u.test(value)) fail(`${label} is unsafe`);
  return value;
}

function positive(value, label) {
  if (!Number.isSafeInteger(value) || value <= 0) fail(`${label} is invalid`);
  return value;
}

function targetPolicy(target) {
  const policy = TARGETS.get(target);
  if (!policy) fail(`unsupported target: ${target}`);
  return policy;
}

async function readNoLink(root, relative, limit = MAX_DOCUMENT) {
  const parts = relative.split('/');
  if (parts.some((part) => safeName(part, relative) !== part)) fail(`unsafe workspace path: ${relative}`);
  let path = resolve(root);
  const rootInfo = await lstat(path);
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) fail(`workspace root is unsafe: ${root}`);
  for (let index = 0; index < parts.length; index += 1) {
    path = join(path, parts[index]);
    const info = await lstat(path);
    if (info.isSymbolicLink() || (index < parts.length - 1 ? !info.isDirectory() : !info.isFile())) {
      fail(`workspace material has unsafe topology: ${relative}`);
    }
    if (index === parts.length - 1 && (info.nlink !== 1 || info.size > limit)) {
      fail(`workspace material is hardlinked or exceeds its bound: ${relative}`);
    }
  }
  return readFile(path);
}

function parseJson(bytes, label, style = 'pretty') {
  let value;
  try {
    value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    fail(`${label} is not UTF-8 JSON`);
  }
  if (style !== null) {
    const canonical = style === 'compact' ? Buffer.from(`${JSON.stringify(value)}\n`) : jsonBytes(value);
    if (!bytes.equals(canonical)) fail(`${label} is not canonical`);
  }
  return value;
}

async function hashRegularFile(path, limit, label) {
  const named = await lstat(path);
  if (!named.isFile() || named.isSymbolicLink() || named.nlink !== 1 || named.size > limit) {
    fail(`${label} is not a bounded no-link, no-hardlink regular file`);
  }
  const handle = await open(path, 'r');
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || opened.dev !== named.dev || opened.ino !== named.ino || opened.size !== named.size) {
      fail(`${label} changed while being opened`);
    }
    const hash = createHash('sha256');
    const buffer = Buffer.alloc(1024 * 1024);
    let position = 0;
    while (position < opened.size) {
      const { bytesRead } = await handle.read(buffer, 0, Math.min(buffer.length, opened.size - position), position);
      if (bytesRead <= 0) fail(`${label} became truncated`);
      hash.update(buffer.subarray(0, bytesRead));
      position += bytesRead;
    }
    const final = await handle.stat();
    const current = await lstat(path);
    if (final.dev !== opened.dev || final.ino !== opened.ino || final.size !== opened.size
        || current.dev !== opened.dev || current.ino !== opened.ino || current.size !== opened.size
        || current.nlink !== 1) fail(`${label} changed while being hashed`);
    return { path, sha256: hash.digest('hex'), size: opened.size };
  } finally {
    await handle.close();
  }
}

async function filesEqual(leftPath, rightPath) {
  const [left, right] = await Promise.all([open(leftPath, 'r'), open(rightPath, 'r')]);
  try {
    const [a, b] = await Promise.all([left.stat(), right.stat()]);
    if (a.size !== b.size) return false;
    const leftBuffer = Buffer.alloc(1024 * 1024);
    const rightBuffer = Buffer.alloc(1024 * 1024);
    for (let position = 0; position < a.size; position += leftBuffer.length) {
      const length = Math.min(leftBuffer.length, a.size - position);
      const [one, two] = await Promise.all([
        left.read(leftBuffer, 0, length, position),
        right.read(rightBuffer, 0, length, position),
      ]);
      if (one.bytesRead !== length || two.bytesRead !== length
          || !leftBuffer.subarray(0, length).equals(rightBuffer.subarray(0, length))) return false;
    }
    return true;
  } finally {
    await Promise.all([left.close(), right.close()]);
  }
}

async function scanTree(root, label) {
  root = resolve(root);
  const info = await lstat(root);
  if (!info.isDirectory() || info.isSymbolicLink()) fail(`${label} root is unsafe`);
  const files = [];
  const directories = [];
  async function walk(path, prefix) {
    const entries = await readdir(path, { withFileTypes: true });
    for (const entry of entries) {
      safeName(entry.name, `${label} entry`);
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      const child = join(path, entry.name);
      const childInfo = await lstat(child);
      if (entry.isSymbolicLink() || childInfo.isSymbolicLink()) fail(`${label} contains a link: ${relative}`);
      if (entry.isDirectory() && childInfo.isDirectory()) {
        directories.push(relative);
        await walk(child, relative);
      } else if (entry.isFile() && childInfo.isFile()) {
        if (childInfo.nlink !== 1) fail(`${label} contains hardlinked topology: ${relative}`);
        files.push(relative);
      } else fail(`${label} contains unsupported topology: ${relative}`);
    }
  }
  await walk(root, '');
  return { directories: directories.sort(compareUtf8), files: files.sort(compareUtf8), root };
}

function requireInventory(actual, expected, label) {
  const wanted = [...expected].sort(compareUtf8);
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) fail(`${label} inventory mismatch`);
}

function parseManifest(bytes, label) {
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    fail(`${label} is not UTF-8`);
  }
  if (!text.endsWith('\n')) fail(`${label} has no final LF`);
  const records = [];
  const seen = new Set();
  for (const line of text.slice(0, -1).split('\n')) {
    const match = /^([0-9a-f]{64})  ([^/\\\r\n]+)$/u.exec(line);
    if (!match) fail(`${label} has a malformed line`);
    safeName(match[2], `${label} path`);
    if (seen.has(match[2])) fail(`${label} has a duplicate path`);
    seen.add(match[2]);
    records.push({ path: match[2], sha256: match[1] });
  }
  if (records.length === 0 || JSON.stringify(records) !== JSON.stringify([...records].sort((a, b) => compareUtf8(a.path, b.path)))) {
    fail(`${label} is empty or noncanonical`);
  }
  return records;
}

function octal(bytes, label) {
  const text = bytes.toString('ascii').replace(/[\0 ]+$/gu, '');
  if (!/^[0-7]+$/u.test(text)) fail(`runtime archive ${label} is invalid`);
  const value = Number.parseInt(text, 8);
  if (!Number.isSafeInteger(value)) fail(`runtime archive ${label} is invalid`);
  return value;
}

function verifyRuntimeArchive(bytes, inventory, label) {
  let tar;
  try {
    tar = gunzipSync(bytes, { maxOutputLength: MAX_TAR });
  } catch {
    fail(`${label} is not a bounded gzip archive`);
  }
  let position = 0;
  for (const entry of inventory) {
    if (position + 512 > tar.length) fail(`${label} is truncated`);
    const header = tar.subarray(position, position + 512);
    const checksum = octal(header.subarray(148, 156), 'checksum');
    const checked = Buffer.from(header);
    checked.fill(0x20, 148, 156);
    if ([...checked].reduce((sum, byte) => sum + byte, 0) !== checksum
        || header.subarray(257, 263).toString('ascii') !== 'ustar\0'
        || header.subarray(263, 265).toString('ascii') !== '00'
        || header[156] !== 0x30
        || octal(header.subarray(108, 116), 'uid') !== 0
        || octal(header.subarray(116, 124), 'gid') !== 0
        || octal(header.subarray(136, 148), 'mtime') !== 0
        || header.subarray(345, 500).some((byte) => byte !== 0)) fail(`${label} has noncanonical metadata`);
    const end = header.indexOf(0, 0);
    const name = header.subarray(0, end === -1 || end > 100 ? 100 : end).toString('utf8');
    const size = octal(header.subarray(124, 136), 'size');
    const mode = octal(header.subarray(100, 108), 'mode');
    if (name !== entry.path || size !== entry.size || mode !== (entry.executable ? 0o755 : 0o644)) {
      fail(`${label} entry does not match its inventory: ${entry.path}`);
    }
    const body = tar.subarray(position + 512, position + 512 + size);
    if (body.length !== size || sha256(body) !== entry.sha256) fail(`${label} payload mismatch: ${entry.path}`);
    const padding = (512 - (size % 512)) % 512;
    if (tar.subarray(position + 512 + size, position + 512 + size + padding).some((byte) => byte !== 0)) {
      fail(`${label} has nonzero padding`);
    }
    position += 512 + size + padding;
  }
  if (tar.length !== position + 1024 || tar.subarray(position).some((byte) => byte !== 0)) {
    fail(`${label} has an unexpected member or trailer`);
  }
}

function validateExpected(expected) {
  exact(expected, ['commit', 'runId', 'runAttempt', 'workflowRef', 'workflowSha'], 'expected CI identity');
  if (!COMMIT.test(expected.commit) || !COMMIT.test(expected.workflowSha)
      || expected.workflowSha !== expected.commit || !/^[1-9][0-9]*$/u.test(expected.runId)
      || expected.runId.length > 32 || positive(expected.runAttempt, 'run attempt') !== expected.runAttempt
      || typeof expected.workflowRef !== 'string'
      || !/^[^\r\n\0]+\/\.github\/workflows\/ci\.yml@[^\r\n\0]+$/u.test(expected.workflowRef)) {
    fail('expected CI identity is invalid');
  }
}

function validatePendingSource(lock, manifestSemgrep, sourceLockSha256, schemaSha256) {
  exact(lock, SOURCE_LOCK_KEYS, 'pending source lock');
  if (lock.schemaVersion !== 1 || lock.project !== 'Semgrep' || lock.version !== VERSION
      || lock.repository !== 'https://github.com/semgrep/semgrep'
      || lock.sourceRevision !== SEMGREP_REVISION || lock.sourceTree !== SEMGREP_TREE
      || lock.completeCorrespondingSource !== false || lock.recursiveInventoryComplete !== true
      || lock.opam?.resolvedSourceArchivesComplete !== true
      || !Array.isArray(lock.opam?.resolvedSourceArchives) || lock.opam.resolvedSourceArchives.length === 0
      || JSON.stringify(lock.missingMaterial) !== JSON.stringify(MISSING)) {
    fail('source lock is not the exact honest pending state');
  }
  if (manifestSemgrep.version !== VERSION
      || manifestSemgrep.source.repository !== 'https://github.com/semgrep/semgrep'
      || manifestSemgrep.source.materialPath !== 'third_party/sidecars/semgrep/source-lock.v1.json'
      || manifestSemgrep.source.revision !== lock.sourceRevision
      || manifestSemgrep.source.tree !== lock.sourceTree
      || manifestSemgrep.source.materialSha256 !== sourceLockSha256) fail('manifest/source-lock identity mismatch');
  const statuses = new Map(lock.targetStatus?.map((entry) => [entry?.distributionTarget, entry]));
  if (!Array.isArray(lock.targetStatus) || lock.targetStatus.length !== 2) {
    fail('pending source target status is invalid');
  }
  for (const status of lock.targetStatus) {
    exact(status, ['distributionTarget', 'enabled', 'reason'], 'pending source target status');
  }
  if (statuses.size !== 2
      || [...TARGETS.values()].some(({ sourceTarget, pendingReason }) => {
    const status = statuses.get(sourceTarget);
    return !status || status.enabled !== false || status.reason !== pendingReason;
  })) fail('pending source target status is invalid');
  const targets = new Map(manifestSemgrep.targets.map((entry) => [entry.target, entry]));
  if (targets.size !== 3 || [...TARGETS].some(([target, policy]) => {
    const entry = targets.get(target);
    return !entry || entry.enabled !== false || entry.reproducibleBuilds !== 0
      || entry.correspondingSourceComplete !== false || entry.download !== null
      || entry.executable !== null || entry.closure.length !== 0 || entry.disabledReason !== policy.pendingReason;
  }) || targets.get('macos-x86_64')?.enabled !== false
      || targets.get('macos-x86_64')?.disabledReason !== 'unsupported_v1_distribution_target') {
    fail('Semgrep manifest is not honestly pending');
  }
  if (manifestSemgrep.materials.some(({ role }) => role === 'native-build-evidence')) {
    fail('pending manifest contains prematurely completed native evidence');
  }
  const windows = lock.toolchains?.filter(({ distributionTarget }) => distributionTarget === 'windows-x86_64') ?? [];
  const macos = lock.toolchains?.filter(({ distributionTarget }) => distributionTarget === 'aarch64-apple-darwin') ?? [];
  if (!Array.isArray(lock.toolchains) || lock.toolchains.length !== 2
      || windows.length !== 1 || macos.length !== 1
      || windows[0].status !== 'closed_public_cygwin_mingw_route_scripted_pending_two_build_evidence'
      || windows[0].builderEvidence?.schemaSha256 !== schemaSha256
      || windows[0].builderEvidence?.sha256 !== null
      || windows[0].builderEvidence?.status !== 'pending_native_capture') {
    fail('pending source toolchain state is invalid');
  }
  exact(macos[0], [
    'distributionTarget', 'runner', 'ocamlCompiler', 'opamVersion', 'nodeVersion',
    'setupNodeAction', 'setupAction', 'homebrewPackages', 'workflowGitBlob',
  ], 'pending macOS toolchain');
  if (JSON.stringify(macos[0].homebrewPackages) !== JSON.stringify(MACOS_HOMEBREW_PACKAGES)) {
    fail('pending macOS Homebrew package provenance is invalid');
  }
  exact(windows[0], [
    'distributionTarget', 'runner', 'status', 'opamVersion', 'nodeVersion',
    'setupNodeAction', 'setupAction', 'cygwinVersion', 'cygwinPackages',
    'builderEvidence', 'workflowGitBlob', 'note',
  ], 'pending Windows toolchain');
  exact(windows[0].builderEvidence, [
    'artifactPath', 'hashAlgorithm', 'schemaPath', 'schemaSha256', 'sha256', 'status',
  ], 'pending Windows builder evidence');
  exact(lock.commandTemplate, ['format', 'argv', 'sha256'], 'pending source command template');
  if (lock.commandTemplate.format !== 'sha256-nul-argv-v1'
      || JSON.stringify(lock.commandTemplate.argv) !== JSON.stringify(manifestSemgrep.commandTemplate.argv)
      || lock.commandTemplate.sha256 !== manifestSemgrep.commandTemplate.sha256) {
    fail('source-lock command template drifted from the manifest');
  }
  return { macos: macos[0], windows: windows[0] };
}

function validateProvenance(value, bytes, sourceLockSha256, toolchains) {
  exact(value, ['schemaVersion', 'sourceLock', 'actions', 'toolchains'], 'native CI provenance');
  exact(value.sourceLock, ['path', 'sha256', 'embeddedActionToolchainStatus'], 'native CI provenance source lock');
  if (value.schemaVersion !== 1
      || value.sourceLock.path !== 'third_party/sidecars/semgrep/source-lock.v1.json'
      || value.sourceLock.sha256 !== sourceLockSha256
      || value.sourceLock.embeddedActionToolchainStatus !== 'sealed-historical-metadata-non-authoritative-for-native-ci') {
    fail('native CI provenance source lock is invalid');
  }
  const expectedActions = [
    ['actions/checkout', 'df4cb1c069e1874edd31b4311f1884172cec0e10', null],
    ['actions/setup-node', '49933ea5288caeca8642d1e84afbd3f7d6820020', null],
    ['semgrep/setup-ocaml', 'a739c5405d73c42ef15a9dc995efc0f87396cc36', 'aarch64-apple-darwin'],
    ['semgrep/setup-ocaml', '3e4c6ff8c9a04c9ec8f6f87701cd4b661b0f1f18', 'windows-x86_64'],
    ['actions/upload-artifact', '043fb46d1a93c77aae656e7c1c64a875d1fc6a0a', null],
    ['actions/download-artifact', '37930b1c2abaa49bbe596cd826c3c89aef350131', null],
  ];
  if (!Array.isArray(value.actions) || value.actions.length !== expectedActions.length) fail('native CI action provenance is incomplete');
  for (let index = 0; index < expectedActions.length; index += 1) {
    const [action, revision, distributionTarget] = expectedActions[index];
    exact(value.actions[index], distributionTarget ? ['action', 'distributionTarget', 'revision'] : ['action', 'revision'], 'native CI action');
    if (value.actions[index].action !== action || value.actions[index].revision !== revision
        || (distributionTarget && value.actions[index].distributionTarget !== distributionTarget)) fail('native CI action provenance drifted');
  }
  const byTarget = new Map(value.toolchains?.map((entry) => [entry.distributionTarget, entry]));
  if (!Array.isArray(value.toolchains) || value.toolchains.length !== 2 || byTarget.size !== 2) {
    fail('native CI toolchain provenance is incomplete');
  }
  const mac = byTarget.get('aarch64-apple-darwin');
  const win = byTarget.get('windows-x86_64');
  exact(mac, ['distributionTarget', 'runner', 'ocamlCompiler', 'opamVersion', 'nodeVersion', 'setupNodeAction', 'setupAction', 'homebrewPackages'], 'macOS native CI toolchain');
  exact(win, ['distributionTarget', 'runner', 'ocamlCompiler', 'opamVersion', 'nodeVersion', 'cygwinVersion', 'setupNodeAction', 'setupAction'], 'Windows native CI toolchain');
  if (mac.runner !== 'macos-15' || mac.ocamlCompiler !== 'ocaml-variants.5.3.0+options,ocaml-option-flambda'
      || mac.opamVersion !== '2.5.0' || mac.nodeVersion !== '24.14.0'
      || JSON.stringify(mac.homebrewPackages) !== JSON.stringify(MACOS_HOMEBREW_PACKAGES)
      || JSON.stringify(mac.homebrewPackages) !== JSON.stringify(toolchains.macos.homebrewPackages)
      || mac.setupNodeAction !== toolchains.macos.setupNodeAction || mac.setupAction !== toolchains.macos.setupAction
      || win.runner !== 'windows-2022' || win.ocamlCompiler !== '5.3.0'
      || win.opamVersion !== '2.5.2' || win.nodeVersion !== '24.14.0' || win.cygwinVersion !== '3.6.10'
      || win.setupNodeAction !== toolchains.windows.setupNodeAction || win.setupAction !== toolchains.windows.setupAction) {
    fail('native CI toolchain provenance drifted');
  }
  return { bytes, sha256: sha256(bytes) };
}

async function readArtifact(root, target, expected, pendingBundleBytes, sourceLock) {
  const policy = targetPolicy(target);
  const tree = await scanTree(root, `${target} artifact`);
  const closureName = `runtime-closure.${target}.v1.json`;
  const closureBytes = await readFile(join(tree.root, closureName));
  const closureDocument = parseJson(closureBytes, `${target} runtime closure`);
  exact(closureDocument, ['schemaVersion', 'target', 'archive', 'evidenceArchive', 'closure'], `${target} runtime closure`);
  exact(closureDocument.archive, ['name', 'size', 'sha256'], `${target} runtime archive identity`);
  exact(closureDocument.evidenceArchive, ['name', 'size', 'sha256'], `${target} evidence archive identity`);
  if (closureDocument.schemaVersion !== 1 || closureDocument.target !== target
      || closureDocument.archive.name !== `semgrep-${VERSION}-${target}.tar.gz`
      || closureDocument.evidenceArchive.name !== `semgrep-${VERSION}-${target}-release-evidence.tar.gz`
      || !Array.isArray(closureDocument.closure) || closureDocument.closure.length === 0) {
    fail(`${target} runtime closure identity is invalid`);
  }
  const seen = new Set();
  for (const entry of closureDocument.closure) {
    exact(entry, ['executable', 'path', 'sha256', 'size'], `${target} closure entry`);
    safeName(entry.path, `${target} closure path`);
    if (seen.has(entry.path) || !SHA256.test(entry.sha256) || !Number.isSafeInteger(entry.size)
        || entry.size <= 0 || typeof entry.executable !== 'boolean') fail(`${target} closure entry is invalid`);
    seen.add(entry.path);
  }
  const sortedClosure = [...closureDocument.closure].sort((a, b) => compareUtf8(a.path, b.path));
  if (JSON.stringify(sortedClosure) !== JSON.stringify(closureDocument.closure)
      || closureDocument.closure.filter(({ executable }) => executable).length !== 1
      || !closureDocument.closure.find(({ path }) => path === policy.executable)?.executable
      || (target === 'macos-aarch64' && closureDocument.closure.length !== 1)
      || (target === 'windows-x86_64' && closureDocument.closure.some(({ path }) => path !== policy.executable && !path.toLowerCase().endsWith('.dll')))) {
    fail(`${target} closure policy is invalid`);
  }

  const manifests = {};
  for (const name of [
    'build-a.MANIFEST.sha256', 'build-b.MANIFEST.sha256',
    'build-a-evidence.MANIFEST.sha256', 'build-b-evidence.MANIFEST.sha256',
  ]) manifests[name] = await readFile(join(tree.root, name));
  if (!manifests['build-a.MANIFEST.sha256'].equals(manifests['build-b.MANIFEST.sha256'])
      || !manifests['build-a-evidence.MANIFEST.sha256'].equals(manifests['build-b-evidence.MANIFEST.sha256'])) {
    fail(`${target} A/B manifests differ`);
  }
  const runtimeManifest = parseManifest(manifests['build-a.MANIFEST.sha256'], `${target} runtime manifest`);
  const evidenceManifest = parseManifest(manifests['build-a-evidence.MANIFEST.sha256'], `${target} evidence manifest`);
  if (JSON.stringify(runtimeManifest.map(({ path, sha256: digest }) => ({ path, sha256: digest })))
      !== JSON.stringify(closureDocument.closure.map(({ path, sha256: digest }) => ({ path, sha256: digest })))) {
    fail(`${target} runtime manifest does not match its closure`);
  }
  requireInventory(evidenceManifest.map(({ path }) => path).sort(compareUtf8), [...EVIDENCE_FILES].sort(compareUtf8), `${target} evidence manifest`);

  const releaseInventory = [];
  for (const entry of closureDocument.closure) {
    const file = await hashRegularFile(join(tree.root, 'release', entry.path), MAX_ARCHIVE, `${target} release ${entry.path}`);
    if (file.sha256 !== entry.sha256 || file.size !== entry.size) fail(`${target} release does not match its closure: ${entry.path}`);
    releaseInventory.push(`release/${entry.path}`);
  }
  const evidenceInventory = [];
  const evidenceEntries = [];
  for (const entry of evidenceManifest) {
    const file = await hashRegularFile(join(tree.root, 'release-evidence', entry.path), MAX_DOCUMENT, `${target} evidence ${entry.path}`);
    if (file.sha256 !== entry.sha256) fail(`${target} release evidence hash mismatch: ${entry.path}`);
    evidenceInventory.push(`release-evidence/${entry.path}`);
    evidenceEntries.push({ executable: false, path: entry.path, sha256: file.sha256, size: file.size });
  }
  if (!(await readFile(join(tree.root, 'release-evidence', 'MANIFEST.sha256'))).equals(manifests['build-a.MANIFEST.sha256'])) {
    fail(`${target} release evidence does not bind the runtime manifest`);
  }

  const archive = await hashRegularFile(join(tree.root, closureDocument.archive.name), MAX_ARCHIVE, `${target} runtime archive`);
  const evidenceArchive = await hashRegularFile(join(tree.root, closureDocument.evidenceArchive.name), MAX_ARCHIVE, `${target} evidence archive`);
  if (archive.sha256 !== closureDocument.archive.sha256 || archive.size !== closureDocument.archive.size
      || evidenceArchive.sha256 !== closureDocument.evidenceArchive.sha256 || evidenceArchive.size !== closureDocument.evidenceArchive.size) {
    fail(`${target} archive hash or size mismatch`);
  }
  verifyRuntimeArchive(await readFile(archive.path), closureDocument.closure, `${target} runtime archive`);
  verifyRuntimeArchive(await readFile(evidenceArchive.path), evidenceEntries, `${target} evidence archive`);

  const identities = [];
  for (const slot of ['a', 'b']) {
    const bytes = await readFile(join(tree.root, `build-${slot}.identity.v1.json`));
    identities.push({
      bytes,
      sha256: sha256(bytes),
      size: bytes.length,
      value: parseJson(bytes, `${target} build-${slot} identity`, 'compact'),
    });
  }
  validateIndependentBuilderIdentities(identities[0].value, identities[1].value, {
    target,
    ...expected,
    jobDefinition: policy.jobDefinition,
    artifactPrefix: policy.artifactPrefix,
  });
  const smokeBytes = await readFile(join(tree.root, `native-smoke.${target}.v1.json`));
  const smoke = parseNativeSmokeEvidence(smokeBytes);
  if (smoke.target !== target || smoke.commit !== expected.commit || smoke.runId !== expected.runId
      || smoke.runAttempt !== expected.runAttempt || smoke.jobDefinition !== policy.smokeJob) {
    fail(`${target} native smoke does not match the expected commit/run`);
  }
  const offline = [];
  for (const slot of ['a', 'b']) {
    const bytes = await readFile(join(tree.root, `build-${slot}.offline-egress.v1.json`));
    if (!bytes.equals(Buffer.from(policy.offline))) fail(`${target} build-${slot} offline evidence is invalid`);
    offline.push({ build: `build-${slot}`, sha256: sha256(bytes), size: bytes.length });
  }
  const artifactBundleBytes = await readFile(join(tree.root, 'bundle-evidence.v1.json'));
  if (!artifactBundleBytes.equals(pendingBundleBytes)) fail(`${target} pending bundle evidence drifted`);

  const common = [
    closureName,
    closureDocument.archive.name,
    closureDocument.evidenceArchive.name,
    'build-a.MANIFEST.sha256', 'build-b.MANIFEST.sha256',
    'build-a-evidence.MANIFEST.sha256', 'build-b-evidence.MANIFEST.sha256',
    'build-a.identity.v1.json', 'build-b.identity.v1.json',
    'build-a.offline-egress.v1.json', 'build-b.offline-egress.v1.json',
    'source-a.tar', 'source-b.tar', 'bundle-evidence.v1.json', `native-smoke.${target}.v1.json`,
    ...releaseInventory, ...evidenceInventory,
  ];
  if (target === 'windows-x86_64') common.push(
    'builder-evidence.windows-x86_64.v1.json',
    'builder-toolchain.windows-x86_64.v1.json',
    'builder-evidence.windows-x86_64.v1.schema.json',
  );
  requireInventory(tree.directories, ['release', 'release-evidence'], `${target} artifact directories`);
  requireInventory(tree.files, common, `${target} artifact files`);

  let windowsBuilder = null;
  if (target === 'windows-x86_64') {
    const builderBytes = await readFile(join(tree.root, 'builder-evidence.windows-x86_64.v1.json'));
    const builder = parseJson(builderBytes, 'Windows builder evidence');
    const stableBytes = createWindowsStableToolchainEvidence(builderBytes);
    const recordedStable = await readFile(join(tree.root, 'builder-toolchain.windows-x86_64.v1.json'));
    if (!recordedStable.equals(stableBytes) || builder.commit !== expected.commit
        || String(builder.run.id) !== expected.runId || builder.run.attempt !== expected.runAttempt) {
      fail('Windows builder evidence/toolchain identity mismatch');
    }
    const schemaBytes = await readFile(join(tree.root, 'builder-evidence.windows-x86_64.v1.schema.json'));
    if (sha256(schemaBytes) !== sourceLock.builderEvidence.schemaSha256) fail('Windows builder evidence schema mismatch');
    const packages = new Set(builder.cygwinPackages.map(({ name }) => name));
    if (sourceLock.cygwinPackages.some((name) => !packages.has(name))) fail('Windows builder package snapshot is incomplete');
    windowsBuilder = {
      evidence: { sha256: sha256(builderBytes), size: builderBytes.length },
      schema: { sha256: sha256(schemaBytes), size: schemaBytes.length },
      toolchain: { sha256: sha256(stableBytes), size: stableBytes.length },
    };
  }
  const sources = await Promise.all(['a', 'b'].map((slot) => hashRegularFile(
    join(tree.root, `source-${slot}.tar`),
    MAX_TAR,
    `${target} source-${slot} bundle`,
  )));
  return {
    archive: closureDocument.archive,
    closure: closureDocument.closure,
    closureDocument: { sha256: sha256(closureBytes), size: closureBytes.length },
    evidenceArchive: closureDocument.evidenceArchive,
    identities,
    manifests: Object.fromEntries(Object.entries(manifests).map(([name, bytes]) => [name, { sha256: sha256(bytes), size: bytes.length }])),
    offline,
    smoke: {
      checkRunId: smoke.checkRunId,
      jobDefinition: smoke.jobDefinition,
      sandboxMechanism: smoke.sandboxMechanism,
      sha256: sha256(smokeBytes),
      size: smokeBytes.length,
    },
    sources,
    target,
    windowsBuilder,
  };
}

function finalSourceLock(pending, nativeEvidenceSha256, support, windowsBuilderSha256) {
  const lock = structuredClone(pending);
  lock.completeCorrespondingSource = true;
  lock.missingMaterial = [];
  lock.targetStatus = lock.targetStatus.map((status) => ({ ...status, enabled: true, reason: null }));
  const windows = lock.toolchains.find(({ distributionTarget }) => distributionTarget === 'windows-x86_64');
  windows.status = 'native_builds_verified';
  windows.builderEvidence.sha256 = windowsBuilderSha256;
  windows.builderEvidence.status = 'verified_native_capture';
  windows.note = 'Native builder capture and stable toolchain are bound by native-build-evidence.v1.json.';
  lock.nativeBuildEvidence = {
    path: 'third_party/sidecars/semgrep/native-build-evidence.v1.json',
    sha256: nativeEvidenceSha256,
    support: support.map(({ path, sha256: digest }) => ({ path, sha256: digest })),
  };
  return lock;
}

function finalManifest(pending, sourceLockSha256, bundleEvidenceSha256, nativeEvidenceSha256, support, artifacts) {
  const manifest = structuredClone(pending);
  const semgrep = manifest.tools.find(({ id }) => id === 'semgrep');
  semgrep.source.materialSha256 = sourceLockSha256;
  const evidence = semgrep.materials.filter(({ role }) => role === 'source-bundle-evidence');
  if (evidence.length !== 1) fail('pending manifest must have one source-bundle-evidence material');
  evidence[0].sha256 = bundleEvidenceSha256;
  semgrep.materials.push({
    role: 'native-build-evidence',
    path: 'third_party/sidecars/semgrep/native-build-evidence.v1.json',
    sha256: nativeEvidenceSha256,
  });
  for (const { path, role, sha256: digest } of support) {
    const existing = semgrep.materials.filter((material) => material.role === role || material.path === path);
    if (existing.length === 0) semgrep.materials.push({ role, path, sha256: digest });
    else if (existing.length !== 1 || existing[0].role !== role
        || existing[0].path !== path || existing[0].sha256 !== digest) {
      fail(`pending support material drifted: ${role}`);
    }
  }
  for (const artifact of artifacts) {
    const policy = targetPolicy(artifact.target);
    const target = semgrep.targets.find((entry) => entry.target === artifact.target);
    const executable = artifact.closure.find(({ path }) => path === policy.executable);
    Object.assign(target, {
      enabled: true,
      disabledReason: null,
      reproducibleBuilds: 2,
      correspondingSourceComplete: true,
      download: {
        url: `${RELEASE_BASE}/${artifact.archive.name}`,
        format: 'tar.gz',
        size: artifact.archive.size,
        sha256: artifact.archive.sha256,
        entries: artifact.closure.map(({ path, size }) => ({ path, type: 'file', size })),
        extractPath: policy.executable,
      },
      executable: { path: executable.path, size: executable.size, sha256: executable.sha256 },
      closure: structuredClone(artifact.closure),
    });
  }
  return manifest;
}

export async function finalizeSemgrepNativeRelease({
  bootstrapSourcePath,
  expected,
  macosArtifactRoot,
  outputRoot,
  windowsArtifactRoot,
  workspace,
}) {
  validateExpected(expected);
  for (const [value, label] of [
    [workspace, 'workspace'], [windowsArtifactRoot, 'Windows artifact root'],
    [macosArtifactRoot, 'macOS artifact root'], [bootstrapSourcePath, 'bootstrap source'],
    [outputRoot, 'output root'],
  ]) if (typeof value !== 'string' || value.length === 0) fail(`${label} path is invalid`);
  workspace = resolve(workspace);
  windowsArtifactRoot = resolve(windowsArtifactRoot);
  macosArtifactRoot = resolve(macosArtifactRoot);
  bootstrapSourcePath = resolve(bootstrapSourcePath);
  outputRoot = resolve(outputRoot);
  if (outputRoot === parse(outputRoot).root || [workspace, windowsArtifactRoot, macosArtifactRoot]
    .some((root) => outputRoot === root || outputRoot.startsWith(`${root}${process.platform === 'win32' ? '\\' : '/'}`))) {
    fail('output root is unsafe');
  }
  try {
    await lstat(outputRoot);
    fail('output root already exists');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  const manifestBytes = await readNoLink(workspace, 'third_party/sidecars/manifest.v1.json');
  const manifestValue = parseJson(manifestBytes, 'pending sidecar manifest', null);
  const manifest = parseSidecarManifest(manifestBytes.toString('utf8'));
  const semgrep = manifest.tools.filter(({ id }) => id === 'semgrep');
  if (semgrep.length !== 1) fail('pending manifest must contain exactly one Semgrep tool');
  const sourceLockBytes = await readNoLink(workspace, semgrep[0].source.materialPath);
  const sourceLock = parseJson(sourceLockBytes, 'pending source lock');
  const bundleEvidenceBytes = await readNoLink(workspace, 'third_party/sidecars/semgrep/bundle-evidence.v1.json');
  const bundleEvidence = parseJson(bundleEvidenceBytes, 'pending bundle evidence');
  exact(bundleEvidence, [
    'bundle', 'bundleGeneratorSha256', 'byteIdentical', 'format', 'independentBuilds',
    'schemaVersion', 'sourceAssetUrl', 'sourceLockSha256', 'status',
  ], 'pending bundle evidence');
  exact(bundleEvidence.bundle, ['payloadEntries', 'recordedLinks', 'sha256', 'size'], 'pending bundle evidence bundle');
  const schemaBytes = await readNoLink(workspace, 'third_party/sidecars/semgrep/builder-evidence.windows-x86_64.v1.schema.json');
  const pendingToolchains = validatePendingSource(sourceLock, semgrep[0], sha256(sourceLockBytes), sha256(schemaBytes));
  if (bundleEvidence.status !== 'source_bundle_reproducible_native_builds_pending'
      || bundleEvidence.sourceAssetUrl !== SOURCE_URL || bundleEvidence.sourceLockSha256 !== sha256(sourceLockBytes)
      || bundleEvidence.independentBuilds !== 2 || bundleEvidence.byteIdentical !== true) {
    fail('bundle evidence is not the exact honest pending state');
  }
  await validateManifestMaterials(manifest, workspace);
  for (const tool of manifest.tools) {
    for (const path of [
      tool.source.materialPath,
      tool.license.path,
      ...(tool.relinking ? [tool.relinking.path] : []),
      ...tool.materials.map((material) => material.path),
    ]) await readNoLink(workspace, path);
  }
  const provenanceBytes = await readNoLink(workspace, 'third_party/sidecars/semgrep/native-ci-provenance.v1.json');
  const provenance = validateProvenance(
    parseJson(provenanceBytes, 'native CI provenance'),
    provenanceBytes,
    sha256(sourceLockBytes),
    pendingToolchains,
  );
  const support = [];
  for (const [role, path] of SUPPORT) {
    const bytes = role === 'native-ci-provenance'
      ? provenanceBytes
      : await readNoLink(workspace, path);
    support.push({ bytes, path, role, sha256: sha256(bytes) });
  }
  for (const { path, role, sha256: digest } of support) {
    const existing = semgrep[0].materials.filter((material) => material.role === role || material.path === path);
    if (existing.length > 1 || (existing.length === 1
        && (existing[0].role !== role || existing[0].path !== path || existing[0].sha256 !== digest))) {
      fail(`pending support material drifted: ${role}`);
    }
  }
  if (semgrep[0].materials.filter(({ role }) => role === 'native-ci-provenance').length !== 1) {
    fail('pending manifest must bind the native CI provenance');
  }

  const verify = verifyBundleEvidence;
  const reseal = resealSemgrepSourceBundle;
  const bootstrapIdentity = await hashRegularFile(bootstrapSourcePath, MAX_TAR, 'bootstrap source bundle');
  const verifiedBootstrap = await verify({
    bundlePath: bootstrapSourcePath,
    evidencePath: join(workspace, 'third_party', 'sidecars', 'semgrep', 'bundle-evidence.v1.json'),
    sourceLockPath: join(workspace, ...semgrep[0].source.materialPath.split('/')),
  });
  if (bootstrapIdentity.sha256 !== bundleEvidence.bundle.sha256
      || bootstrapIdentity.size !== bundleEvidence.bundle.size
      || verifiedBootstrap.sha256 !== bootstrapIdentity.sha256
      || verifiedBootstrap.size !== bootstrapIdentity.size
      || verifiedBootstrap.payloadEntries !== bundleEvidence.bundle.payloadEntries
      || verifiedBootstrap.links !== bundleEvidence.bundle.recordedLinks) fail('verified bootstrap source identity mismatch');

  const artifacts = await Promise.all([
    readArtifact(windowsArtifactRoot, 'windows-x86_64', expected, bundleEvidenceBytes, pendingToolchains.windows),
    readArtifact(macosArtifactRoot, 'macos-aarch64', expected, bundleEvidenceBytes, pendingToolchains.macos),
  ]);
  const sourceCopies = artifacts.flatMap(({ sources }) => sources);
  if (sourceCopies.length !== 4 || sourceCopies.some(({ sha256: digest, size }) => (
    digest !== bootstrapIdentity.sha256 || size !== bootstrapIdentity.size
  ))) fail('four pending source bundles differ from the verified bootstrap source');
  const checkRunIds = [
    ...artifacts.flatMap(({ identities }) => identities.map(({ value }) => value.checkRunId)),
    ...artifacts.map(({ smoke }) => smoke.checkRunId),
  ];
  if (new Set(checkRunIds).size !== 6) fail('native builder/smoke check-run identities are not distinct');

  const builders = artifacts.flatMap(({ identities, target }) => identities.map(({ sha256: digest, size, value }) => ({
    target,
    build: value.build,
    artifactName: value.artifactName,
    identitySha256: digest,
    identitySize: size,
    checkRunId: value.checkRunId,
    jobDefinition: value.jobDefinition,
    jobIndex: value.jobIndex,
    jobTotal: value.jobTotal,
    runnerName: value.runnerName,
    runnerOs: value.runnerOs,
    runnerArch: value.runnerArch,
  })));
  const nativeEvidenceValue = {
    schemaVersion: 1,
    status: 'native_builds_and_sandbox_smokes_verified',
    bootstrapSource: {
      sourceLockSha256: sha256(sourceLockBytes),
      sourceRevision: sourceLock.sourceRevision,
      sourceTree: sourceLock.sourceTree,
      bundleEvidenceSha256: sha256(bundleEvidenceBytes),
      bundle: {
        sha256: bootstrapIdentity.sha256,
        size: bootstrapIdentity.size,
        payloadEntries: verifiedBootstrap.payloadEntries,
        recordedLinks: verifiedBootstrap.links,
      },
    },
    ci: { ...expected },
    provenanceSha256: provenance.sha256,
    builders,
    smokes: artifacts.map(({ smoke, target }) => ({ target, ...smoke })),
    targets: artifacts.map((artifact) => ({
      target: artifact.target,
      runtimeArchive: artifact.archive,
      evidenceArchive: artifact.evidenceArchive,
      runtimeClosure: artifact.closureDocument,
      manifests: artifact.manifests,
      offlineEvidence: artifact.offline,
    })),
    windowsBuilder: artifacts[0].windowsBuilder,
    support: support.map(({ path, sha256: digest }) => ({ path, sha256: digest })),
  };
  const nativeEvidenceBytes = jsonBytes(nativeEvidenceValue);
  const nativeEvidenceSha256 = sha256(nativeEvidenceBytes);
  const finalLockValue = finalSourceLock(
    sourceLock,
    nativeEvidenceSha256,
    support,
    artifacts[0].windowsBuilder.evidence.sha256,
  );
  const finalLockBytes = jsonBytes(finalLockValue);
  const finalLockSha256 = sha256(finalLockBytes);

  let created = false;
  try {
    await mkdir(outputRoot);
    created = true;
    const patchRoot = join(outputRoot, 'patch');
    const semgrepPatch = join(patchRoot, 'third_party', 'sidecars', 'semgrep');
    const releaseRoot = join(outputRoot, 'release');
    await mkdir(semgrepPatch, { recursive: true });
    await mkdir(releaseRoot);
    const finalSourcePath = join(releaseRoot, SOURCE_ASSET);
    const comparisonPath = join(releaseRoot, '.comparison-source.tar');
    const additions = [
      {
        bytes: nativeEvidenceBytes,
        executable: false,
        path: 'support/third_party/sidecars/semgrep/native-build-evidence.v1.json',
      },
      ...support.map(({ bytes, path }) => ({ bytes, executable: false, path: `support/${path}` })),
    ];
    const replacements = [{ bytes: finalLockBytes, executable: false, path: 'metadata/source-lock.v1.json' }];
    const [first, second] = await Promise.all([
      reseal({ additions, inputPath: bootstrapSourcePath, outputPath: finalSourcePath, replacements }),
      reseal({ additions, inputPath: bootstrapSourcePath, outputPath: comparisonPath, replacements }),
    ]);
    if (first.sha256 !== second.sha256 || first.size !== second.size
        || first.payloadEntries !== second.payloadEntries || first.links !== second.links
        || !(await filesEqual(finalSourcePath, comparisonPath))) fail('two final source reseals are not byte-identical');
    const expectedDigests = new Map([
      ['metadata/source-lock.v1.json', finalLockSha256],
      ['support/third_party/sidecars/semgrep/native-build-evidence.v1.json', nativeEvidenceSha256],
      ...support.map(({ path, sha256: digest }) => [`support/${path}`, digest]),
    ]);
    if ([...expectedDigests].some(([path, digest]) => first.digests?.[path] !== digest)) {
      fail('final source bundle does not bind its release metadata');
    }
    await rm(comparisonPath);
    const finalBundleEvidenceValue = {
      bundle: {
        payloadEntries: first.payloadEntries,
        recordedLinks: first.links,
        sha256: first.sha256,
        size: first.size,
      },
      bundleGeneratorSha256: bundleEvidence.bundleGeneratorSha256,
      byteIdentical: true,
      format: 'context-relay-semgrep-source-v1',
      independentBuilds: 2,
      schemaVersion: 1,
      sourceAssetUrl: SOURCE_URL,
      sourceLockSha256: finalLockSha256,
      status: 'complete_corresponding_source',
    };
    const finalBundleEvidenceBytes = jsonBytes(finalBundleEvidenceValue);
    const finalManifestValue = finalManifest(
      manifestValue,
      finalLockSha256,
      sha256(finalBundleEvidenceBytes),
      nativeEvidenceSha256,
      support,
      artifacts,
    );
    const finalManifestBytes = jsonBytes(finalManifestValue);
    parseSidecarManifest(finalManifestBytes.toString('utf8'));
    const finalSemgrep = finalManifestValue.tools.find(({ id }) => id === 'semgrep');
    const nativeMaterial = finalSemgrep.materials.find(({ role }) => role === 'native-build-evidence');
    validateSemgrepNativeBuildEvidence(
      nativeEvidenceValue,
      finalLockValue,
      nativeMaterial,
      finalSemgrep.materials,
      finalSemgrep.targets.filter(({ enabled }) => enabled),
    );
    await writeFile(join(semgrepPatch, 'native-build-evidence.v1.json'), nativeEvidenceBytes, { flag: 'wx' });
    await writeFile(join(semgrepPatch, 'source-lock.v1.json'), finalLockBytes, { flag: 'wx' });
    await writeFile(join(semgrepPatch, 'bundle-evidence.v1.json'), finalBundleEvidenceBytes, { flag: 'wx' });
    const manifestPath = join(patchRoot, 'third_party', 'sidecars', 'manifest.v1.json');
    await mkdir(dirname(manifestPath), { recursive: true });
    await writeFile(manifestPath, finalManifestBytes, { flag: 'wx' });
    await verify({
      bundlePath: finalSourcePath,
      evidencePath: join(semgrepPatch, 'bundle-evidence.v1.json'),
      sourceLockPath: join(semgrepPatch, 'source-lock.v1.json'),
    });
    return {
      outputRoot,
      patchRoot,
      releaseRoot,
      nativeBuildEvidenceSha256: nativeEvidenceSha256,
      sourceLockSha256: finalLockSha256,
      sourceBundle: {
        path: finalSourcePath,
        sha256: first.sha256,
        size: first.size,
        payloadEntries: first.payloadEntries,
        recordedLinks: first.links,
      },
    };
  } catch (error) {
    if (created) await rm(outputRoot, { force: true, recursive: true });
    throw error;
  }
}

async function main(argv) {
  if (argv.length !== 20) fail('usage: --workspace PATH --windows-artifact PATH --macos-artifact PATH --bootstrap-source PATH --output PATH --commit SHA --run-id ID --run-attempt N --workflow-ref REF --workflow-sha SHA');
  const values = Object.fromEntries(Array.from({ length: 10 }, (_, index) => [argv[index * 2], argv[index * 2 + 1]]));
  if (JSON.stringify(Object.keys(values).sort()) !== JSON.stringify([
    '--bootstrap-source', '--commit', '--macos-artifact', '--output', '--run-attempt',
    '--run-id', '--windows-artifact', '--workflow-ref', '--workflow-sha', '--workspace',
  ])) fail('arguments are invalid');
  const result = await finalizeSemgrepNativeRelease({
    workspace: values['--workspace'],
    windowsArtifactRoot: values['--windows-artifact'],
    macosArtifactRoot: values['--macos-artifact'],
    bootstrapSourcePath: values['--bootstrap-source'],
    outputRoot: values['--output'],
    expected: {
      commit: values['--commit'],
      runId: values['--run-id'],
      runAttempt: Number(values['--run-attempt']),
      workflowRef: values['--workflow-ref'],
      workflowSha: values['--workflow-sha'],
    },
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
