import { createHash, randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { constants as fsConstants } from 'node:fs';
import {
  lstat,
  open,
  readFile,
  readdir,
} from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { gunzipSync, inflateRawSync } from 'node:zlib';

import { verifyResolvedSourceInventory } from './semgrep-source-inventory.mjs';

const HASH = /^[0-9a-f]{64}$/;
const GIT_ID = /^[0-9a-f]{40}$/;
const ID = /^[a-z][a-z0-9-]*$/;
const TARGETS = new Set(['windows-x86_64', 'macos-aarch64', 'macos-x86_64']);
const FORMATS = new Set(['raw', 'zip', 'tar.gz']);
const MAX_REDIRECTS = 5;
const MAX_ARTIFACT_BYTES = 268435456;
const MAX_TOOLS = 16;
const MAX_TARGETS = 3;
const MAX_ARCHIVE_ENTRIES = 64;
const MAX_CLOSURE_ENTRIES = 64;
const ALLOWED_LICENSES = new Set(['MIT', 'LGPL-2.1-or-later']);
const MAX_MANIFEST_BYTES = 1048576;
const MAX_SOURCE_BUNDLE_BYTES = 2_147_483_648;
const SEMGREP_SOURCE_ASSET_URL = 'https://github.com/Skytuhua/Context-Relay/releases/download/sidecars-semgrep-1.170.0-source.1/semgrep-1.170.0-corresponding-source.tar';
const CI_CANDIDATE_SOURCE_CLAIMS = new Map([
  ['source_bundle_v1_native_builds_pending', [1, false]],
  ['source_bundle_reproducible_native_builds_pending', [2, true]],
]);
const SEMGREP_LICENSE_SOURCES = [
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
const WINDOWS_DEVICE = new Set(['CON', 'PRN', 'AUX', 'NUL', 'CLOCK$', 'CONIN$', 'CONOUT$']);
const UTF8 = new TextDecoder('utf-8', { fatal: true });

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

export function digestArgv(argv) {
  return sha256(Buffer.from(argv.join(String.fromCharCode(0)), 'utf8'));
}

function object(value, path) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${path} must be an object`);
  return value;
}

function exactKeys(value, allowed, required, path) {
  object(value, path);
  for (const key of Object.keys(value)) if (!allowed.includes(key)) throw new Error(`${path} has unknown key ${key}`);
  for (const key of required) if (!Object.hasOwn(value, key)) throw new Error(`${path} is missing ${key}`);
}

function text(value, path) {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`${path} must be a non-empty string`);
  return value;
}

function integer(value, path, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${path} must be an integer between ${minimum} and maximum ${maximum}`);
  }
  return value;
}

function hash(value, path) {
  if (typeof value !== 'string' || !HASH.test(value)) throw new Error(`${path} must be a lowercase 64-character SHA-256`);
  return value;
}

function safeRelativePath(value, path) {
  text(value, path);
  const parts = value.split('/');
  if (
    value.length > 1024
    || isAbsolute(value)
    || value.includes('\\')
    || /[\u0000-\u001f\u007f]/u.test(value)
    || parts.some((part) => part === '' || part === '.' || part === '..' || part.length > 255)
    || parts.length > 64
    || parts.some((part) => /[. ]$/u.test(part) || windowsReservedName(part))
    || value.includes(':')
    || value !== value.normalize('NFC')
  ) throw new Error(`${path} must be a canonical relative path`);
  return value;
}

function windowsReservedName(component) {
  const stem = component.split('.')[0].normalize('NFKC').toUpperCase();
  return WINDOWS_DEVICE.has(stem) || /^(?:COM|LPT)[1-9]$/u.test(stem);
}

function httpsUrl(value, hosts, path) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${path} must be a valid URL`);
  }
  if (url.protocol !== 'https:' || url.username || url.password || !hosts.has(url.hostname)) {
    throw new Error(`${path} must use HTTPS on an allowlisted release host`);
  }
  return value;
}

function unique(items, key, path) {
  const seen = new Set();
  for (const item of items) {
    const value = item[key];
    if (seen.has(value)) throw new Error(`${path} has duplicate ${key} ${value}`);
    seen.add(value);
  }
}

function uniquePaths(items, path) {
  const seen = new Set();
  for (const item of items) {
    const normalized = item.path.normalize('NFKC').toLowerCase();
    if (seen.has(normalized)) throw new Error(`${path} has duplicate normalized path ${item.path}`);
    seen.add(normalized);
  }
}

function decodeUtf8(bytes, label) {
  try {
    return UTF8.decode(bytes);
  } catch {
    throw new Error(`${label} is not valid UTF-8`);
  }
}

function validateEntry(entry, path) {
  exactKeys(entry, ['path', 'type', 'size'], ['path', 'type', 'size'], path);
  safeRelativePath(entry.path, `${path}.path`);
  if (!['file', 'directory'].includes(entry.type)) throw new Error(`${path}.type must be file or directory`);
  integer(entry.size, `${path}.size`, 0, MAX_ARTIFACT_BYTES);
  if (entry.type === 'directory' && entry.size !== 0) throw new Error(`${path}.size must be zero for a directory`);
}

function validateClosure(entry, path) {
  exactKeys(entry, ['path', 'size', 'sha256', 'executable'], ['path', 'size', 'sha256', 'executable'], path);
  safeRelativePath(entry.path, `${path}.path`);
  integer(entry.size, `${path}.size`, 0, MAX_ARTIFACT_BYTES);
  hash(entry.sha256, `${path}.sha256`);
  if (typeof entry.executable !== 'boolean') throw new Error(`${path}.executable must be boolean`);
}

export function parseSidecarManifest(json) {
  if (typeof json !== 'string' || Buffer.byteLength(json) > MAX_MANIFEST_BYTES) {
    throw new Error(`sidecar manifest exceeds maximum ${MAX_MANIFEST_BYTES} bytes`);
  }
  let manifest;
  try {
    manifest = JSON.parse(json);
  } catch (error) {
    throw new Error(`sidecar manifest is not valid JSON: ${error.message}`);
  }
  exactKeys(
    manifest,
    ['schemaVersion', 'digestFormat', 'allowedReleaseHosts', 'tools'],
    ['schemaVersion', 'digestFormat', 'allowedReleaseHosts', 'tools'],
    'manifest',
  );
  if (manifest.schemaVersion !== 1) throw new Error('manifest.schemaVersion must be 1');
  if (manifest.digestFormat !== 'sha256-nul-argv-v1') throw new Error('manifest.digestFormat is unsupported');
  if (!Array.isArray(manifest.allowedReleaseHosts) || manifest.allowedReleaseHosts.length === 0) {
    throw new Error('manifest.allowedReleaseHosts must be a non-empty array');
  }
  if (manifest.allowedReleaseHosts.length > 8) throw new Error('manifest.allowedReleaseHosts exceeds maximum 8');
  unique(manifest.allowedReleaseHosts.map((host) => ({ host })), 'host', 'manifest.allowedReleaseHosts');
  const hosts = new Set();
  for (const [index, host] of manifest.allowedReleaseHosts.entries()) {
    if (typeof host !== 'string' || host !== host.toLowerCase() || !/^[a-z0-9.-]+$/.test(host)) {
      throw new Error(`manifest.allowedReleaseHosts[${index}] is invalid`);
    }
    hosts.add(host);
  }
  if (!Array.isArray(manifest.tools) || manifest.tools.length === 0) throw new Error('manifest.tools must be a non-empty array');
  if (manifest.tools.length > MAX_TOOLS) throw new Error(`manifest.tools exceeds maximum ${MAX_TOOLS}`);
  unique(manifest.tools, 'id', 'manifest.tools');

  for (const [toolIndex, tool] of manifest.tools.entries()) {
    const path = `manifest.tools[${toolIndex}]`;
    exactKeys(
      tool,
      ['id', 'version', 'source', 'license', 'relinking', 'materials', 'commandTemplate', 'targets'],
      ['id', 'version', 'source', 'license', 'relinking', 'materials', 'commandTemplate', 'targets'],
      path,
    );
    if (typeof tool.id !== 'string' || !ID.test(tool.id)) throw new Error(`${path}.id is invalid`);
    text(tool.version, `${path}.version`);

    exactKeys(
      tool.source,
      ['repository', 'revision', 'tree', 'materialPath', 'materialSha256'],
      ['repository', 'revision', 'tree', 'materialPath', 'materialSha256'],
      `${path}.source`,
    );
    httpsUrl(tool.source.repository, new Set(['github.com']), `${path}.source.repository`);
    if (!GIT_ID.test(tool.source.revision)) throw new Error(`${path}.source.revision must be a full lowercase Git object ID`);
    if (!GIT_ID.test(tool.source.tree)) throw new Error(`${path}.source.tree must be a full lowercase Git object ID`);
    safeRelativePath(tool.source.materialPath, `${path}.source.materialPath`);
    hash(tool.source.materialSha256, `${path}.source.materialSha256`);

    exactKeys(tool.license, ['spdx', 'path', 'sha256'], ['spdx', 'path', 'sha256'], `${path}.license`);
    if (!ALLOWED_LICENSES.has(tool.license.spdx)) throw new Error(`${path}.license.spdx is not allowlisted`);
    safeRelativePath(tool.license.path, `${path}.license.path`);
    hash(tool.license.sha256, `${path}.license.sha256`);
    if (tool.relinking !== null) {
      exactKeys(tool.relinking, ['path', 'sha256'], ['path', 'sha256'], `${path}.relinking`);
      safeRelativePath(tool.relinking.path, `${path}.relinking.path`);
      hash(tool.relinking.sha256, `${path}.relinking.sha256`);
    }
    if (tool.id === 'semgrep' && tool.relinking === null) throw new Error('semgrep requires hashed relinking material');
    if (!Array.isArray(tool.materials) || tool.materials.length > 32) {
      throw new Error(`${path}.materials must be an array with at most 32 entries`);
    }
    for (const [index, material] of tool.materials.entries()) {
      const materialPath = `${path}.materials[${index}]`;
      exactKeys(material, ['role', 'path', 'sha256'], ['role', 'path', 'sha256'], materialPath);
      if (!ID.test(material.role)) throw new Error(`${materialPath}.role is invalid`);
      safeRelativePath(material.path, `${materialPath}.path`);
      hash(material.sha256, `${materialPath}.sha256`);
    }
    uniquePaths(tool.materials, `${path}.materials`);

    exactKeys(tool.commandTemplate, ['id', 'argv', 'sha256'], ['id', 'argv', 'sha256'], `${path}.commandTemplate`);
    if (!ID.test(tool.commandTemplate.id)) throw new Error(`${path}.commandTemplate.id is invalid`);
    if (!Array.isArray(tool.commandTemplate.argv)
      || tool.commandTemplate.argv.length === 0
      || tool.commandTemplate.argv.length > 64
      || tool.commandTemplate.argv.some((argument) => (
        typeof argument !== 'string'
        || argument.length === 0
        || Buffer.byteLength(argument) > 256
        || argument.includes(String.fromCharCode(0))
      ))) {
      throw new Error(`${path}.commandTemplate.argv is invalid`);
    }
    hash(tool.commandTemplate.sha256, `${path}.commandTemplate.sha256`);
    if (digestArgv(tool.commandTemplate.argv) !== tool.commandTemplate.sha256) {
      throw new Error(`${path}.commandTemplate SHA-256 does not match sha256-nul-argv-v1`);
    }

    if (!Array.isArray(tool.targets) || tool.targets.length === 0) throw new Error(`${path}.targets must be non-empty`);
    if (tool.targets.length > MAX_TARGETS) throw new Error(`${path}.targets exceeds maximum ${MAX_TARGETS}`);
    unique(tool.targets, 'target', `${path}.targets`);
    for (const [targetIndex, target] of tool.targets.entries()) {
      const targetPath = `${path}.targets[${targetIndex}]`;
      exactKeys(
        target,
        [
          'target',
          'enabled',
          'disabledReason',
          'reproducibleBuilds',
          'correspondingSourceComplete',
          'download',
          'executable',
          'closure',
        ],
        [
          'target',
          'enabled',
          'disabledReason',
          'reproducibleBuilds',
          'correspondingSourceComplete',
          'download',
          'executable',
          'closure',
        ],
        targetPath,
      );
      if (!TARGETS.has(target.target)) throw new Error(`${targetPath}.target is unsupported`);
      if (typeof target.enabled !== 'boolean') throw new Error(`${targetPath}.enabled must be boolean`);
      integer(target.reproducibleBuilds, `${targetPath}.reproducibleBuilds`);
      if (typeof target.correspondingSourceComplete !== 'boolean') {
        throw new Error(`${targetPath}.correspondingSourceComplete must be boolean`);
      }
      if (!Array.isArray(target.closure)) throw new Error(`${targetPath}.closure must be an array`);
      if (target.closure.length > MAX_CLOSURE_ENTRIES) throw new Error(`${targetPath}.closure exceeds maximum ${MAX_CLOSURE_ENTRIES}`);
      target.closure.forEach((entry, index) => validateClosure(entry, `${targetPath}.closure[${index}]`));
      uniquePaths(target.closure, `${targetPath}.closure`);

      if (!target.enabled) {
        text(target.disabledReason, `${targetPath}.disabledReason`);
        if (target.download !== null || target.executable !== null || target.closure.length !== 0) {
          throw new Error(`${targetPath} disabled targets cannot contain runnable material`);
        }
        continue;
      }
      if (target.disabledReason !== null) throw new Error(`${targetPath}.disabledReason must be null when enabled`);
      if (tool.id === 'semgrep' && (target.reproducibleBuilds < 2 || !target.correspondingSourceComplete)) {
        throw new Error('semgrep target requires two reproducible builds and complete corresponding source');
      }
      object(target.download, `${targetPath}.download`);
      exactKeys(
        target.download,
        ['url', 'format', 'size', 'sha256', 'entries', 'extractPath'],
        ['url', 'format', 'size', 'sha256', 'entries', 'extractPath'],
        `${targetPath}.download`,
      );
      httpsUrl(target.download.url, hosts, `${targetPath}.download.url`);
      if (!FORMATS.has(target.download.format)) throw new Error(`${targetPath}.download.format is unsupported`);
      integer(target.download.size, `${targetPath}.download.size`, 1, MAX_ARTIFACT_BYTES);
      hash(target.download.sha256, `${targetPath}.download.sha256`);
      if (!Array.isArray(target.download.entries) || target.download.entries.length === 0) {
        throw new Error(`${targetPath}.download.entries must be non-empty`);
      }
      if (target.download.entries.length > MAX_ARCHIVE_ENTRIES) {
        throw new Error(`${targetPath}.download.entries exceeds maximum ${MAX_ARCHIVE_ENTRIES}`);
      }
      target.download.entries.forEach((entry, index) => validateEntry(entry, `${targetPath}.download.entries[${index}]`));
      uniquePaths(target.download.entries, `${targetPath}.download.entries`);
      safeRelativePath(target.download.extractPath, `${targetPath}.download.extractPath`);
      if (!target.download.entries.some((entry) => entry.path === target.download.extractPath && entry.type === 'file')) {
        throw new Error(`${targetPath}.download.extractPath must name a regular archive entry`);
      }
      exactKeys(target.executable, ['path', 'size', 'sha256'], ['path', 'size', 'sha256'], `${targetPath}.executable`);
      safeRelativePath(target.executable.path, `${targetPath}.executable.path`);
      integer(target.executable.size, `${targetPath}.executable.size`, 1, MAX_ARTIFACT_BYTES);
      hash(target.executable.sha256, `${targetPath}.executable.sha256`);
      const closure = target.closure.find((entry) => entry.path === target.executable.path);
      if (!closure || !closure.executable || closure.size !== target.executable.size || closure.sha256 !== target.executable.sha256) {
        throw new Error(`${targetPath}.executable must match its executable closure entry`);
      }
      const archivePaths = new Set();
      for (const entry of target.closure) {
        const archivePath = entry.path === target.executable.path
          ? target.download.extractPath
          : entry.path;
        if (archivePaths.has(archivePath)) {
          throw new Error(`${targetPath}.closure maps more than once to ${archivePath}`);
        }
        archivePaths.add(archivePath);
        const archived = target.download.entries.find((candidate) => candidate.path === archivePath);
        if (!archived || archived.type !== 'file' || archived.size !== entry.size) {
          throw new Error(`${targetPath}.closure entry is missing from the archive: ${entry.path}`);
        }
      }
    }
  }
  return manifest;
}

function asPath(value) {
  return value instanceof URL ? fileURLToPath(value) : value;
}

export async function loadSidecarManifest(path) {
  return parseSidecarManifest(await readFile(asPath(path), 'utf8'));
}

async function verifyMaterial(workspace, material, label) {
  const root = resolve(workspace);
  const parts = material.path.split('/');
  const path = resolve(root, ...parts);
  if (path === root || !path.startsWith(`${root}${process.platform === 'win32' ? '\\' : '/'}`)) {
    throw new Error(`${label} material escapes the workspace`);
  }
  let bytes;
  try {
    let current = root;
    for (let index = 0; index < parts.length; index += 1) {
      current = join(current, parts[index]);
      const info = await lstat(current);
      if (info.isSymbolicLink()) throw new Error('link component');
      if (index < parts.length - 1 ? !info.isDirectory() : !info.isFile()) throw new Error('wrong material type');
    }
    bytes = await readFile(path);
  } catch {
    throw new Error(`${label} material is missing or not a regular no-link file: ${material.path}`);
  }
  if (sha256(bytes) !== material.sha256) throw new Error(`${label} SHA-256 mismatch: ${material.path}`);
  return bytes;
}

function validateSemgrepLicenseMaterials(materials) {
  if (!Array.isArray(materials) || materials.length !== 12) {
    throw new Error('semgrep license material inventory must contain the canonical 12 records');
  }
  const paths = new Set();
  const licensedSources = new Set();
  const noticedSources = new Set();
  let previous;
  for (const [index, material] of materials.entries()) {
    const label = `semgrep license material ${index}`;
    exactKeys(material, ['source', 'kind', 'spdx', 'path', 'sha256'], ['source', 'kind', 'spdx', 'path', 'sha256'], label);
    if (typeof material.source !== 'string' || Buffer.byteLength(material.source) > 128 || !ID.test(material.source)) {
      throw new Error(`${label} source is invalid`);
    }
    if (!['license', 'notice'].includes(material.kind)) throw new Error(`${label} kind is invalid`);
    if (
      typeof material.spdx !== 'string'
      || material.spdx.length === 0
      || Buffer.byteLength(material.spdx) > 256
      || material.spdx !== material.spdx.normalize('NFC')
      || /[\u0000-\u001f\u007f]/u.test(material.spdx)
    ) throw new Error(`${label} SPDX expression is invalid`);
    try {
      safeRelativePath(material.path, `${label} path`);
    } catch {
      throw new Error(`${label} path is invalid`);
    }
    if (!HASH.test(material.sha256) || /^0{64}$/u.test(material.sha256)) {
      throw new Error(`${label} SHA-256 is invalid`);
    }
    const key = `${material.source}\0${material.kind}\0${material.path}`;
    if (previous !== undefined && Buffer.compare(Buffer.from(previous), Buffer.from(key)) >= 0) {
      throw new Error('semgrep license material inventory is not strictly sorted');
    }
    previous = key;
    if (paths.has(material.path)) throw new Error(`${label} path is duplicated`);
    paths.add(material.path);
    if (material.kind === 'license') {
      if (licensedSources.has(material.source)) throw new Error(`${label} source has multiple licenses`);
      licensedSources.add(material.source);
    } else {
      noticedSources.add(material.source);
    }
    const expectedPrefix = material.source === 'semgrep'
      ? 'sources/semgrep/'
      : material.source === 'tree-sitter-runtime'
        ? 'support/'
        : 'pins/';
    if (!material.path.startsWith(expectedPrefix)) throw new Error(`${label} path has the wrong source prefix`);
  }
  if (
    JSON.stringify([...licensedSources].sort()) !== JSON.stringify(SEMGREP_LICENSE_SOURCES)
    || noticedSources.size !== 1
    || !noticedSources.has('semgrep-interfaces')
  ) throw new Error('semgrep license material inventory does not match the canonical source set');
}

function validateSemgrepSourceLock(bytes, enabledTargets) {
  let json;
  try {
    json = decodeUtf8(bytes, 'semgrep source lock');
  } catch {
    throw new Error('semgrep source lock is not valid UTF-8');
  }
  let lock;
  try {
    lock = JSON.parse(json);
  } catch {
    throw new Error('semgrep source lock is not valid JSON');
  }
  if (!lock || typeof lock !== 'object' || Array.isArray(lock)) {
    throw new Error('semgrep source lock must be an object');
  }
  validateSemgrepLicenseMaterials(lock.licenseMaterials);
  if (lock.completeCorrespondingSource !== true) {
    throw new Error('semgrep source lock has incomplete corresponding source');
  }
  if (lock.recursiveInventoryComplete !== true) {
    throw new Error('semgrep source lock recursive inventory is incomplete');
  }
  if (
    !lock.opam
    || typeof lock.opam !== 'object'
    || lock.opam.resolvedSourceArchivesComplete !== true
    || !Array.isArray(lock.opam.resolvedSourceArchives)
    || lock.opam.resolvedSourceArchives.length === 0
  ) throw new Error('semgrep source lock resolved archive inventory is incomplete');
  try {
    verifyResolvedSourceInventory(lock.opam.resolvedSourceArchives);
  } catch {
    throw new Error('semgrep source lock resolved archive inventory is invalid');
  }
  if (!Array.isArray(lock.missingMaterial) || lock.missingMaterial.length !== 0) {
    throw new Error('semgrep source lock still records missing material');
  }
  if (!Array.isArray(lock.targetStatus)) {
    throw new Error('semgrep source lock target status inventory is missing');
  }
  const sourceTarget = {
    'windows-x86_64': 'windows-x86_64',
    'macos-aarch64': 'aarch64-apple-darwin',
    'macos-x86_64': 'x86_64-apple-darwin',
  };
  for (const target of enabledTargets) {
    const matches = lock.targetStatus.filter(
      (status) => status?.distributionTarget === sourceTarget[target.target],
    );
    if (matches.length !== 1 || matches[0].enabled !== true) {
      throw new Error(`semgrep source lock target status is not enabled: ${target.target}`);
    }
  }
  return lock;
}

const NATIVE_EVIDENCE_SUPPORT = [
  ['native-ci-provenance', 'third_party/sidecars/semgrep/native-ci-provenance.v1.json'],
  ['native-release-finalizer', 'scripts/finalize-semgrep-native-release.mjs'],
  ['source-bundle-reseal', 'scripts/reseal-semgrep-source-bundle.mjs'],
];

const NATIVE_EVIDENCE_TARGETS = new Map([
  ['windows-x86_64', {
    artifactPrefix: 'task9-semgrep-windows-build',
    builderJob: 'native-semgrep-windows-x64-builders',
    smokeJob: 'native-isolation-windows-x64',
    sandboxMechanism: 'windows-appcontainer',
  }],
  ['macos-aarch64', {
    artifactPrefix: 'task9-semgrep-macos-build',
    builderJob: 'native-semgrep-macos-arm64-builders',
    smokeJob: 'native-isolation-macos-arm64',
    sandboxMechanism: 'macos-sandbox-exec-inherited',
  }],
]);

function evidenceHash(value, path) {
  hash(value, path);
  if (value === '0'.repeat(64)) throw new Error(`${path} cannot be empty`);
}

function evidenceIdentity(value, path, maximum = MAX_ARTIFACT_BYTES) {
  exactKeys(value, ['sha256', 'size'], ['sha256', 'size'], path);
  evidenceHash(value.sha256, `${path}.sha256`);
  integer(value.size, `${path}.size`, 1, maximum);
}

export function validateSemgrepNativeBuildEvidence(
  evidence,
  sourceLock,
  nativeMaterial,
  manifestSupport,
  enabledTargets,
) {
  const fail = (message) => { throw new Error(`semgrep native build evidence ${message}`); };
  try {
    exactKeys(evidence, [
      'schemaVersion', 'status', 'bootstrapSource', 'ci', 'provenanceSha256',
      'builders', 'smokes', 'targets', 'windowsBuilder', 'support',
    ], [
      'schemaVersion', 'status', 'bootstrapSource', 'ci', 'provenanceSha256',
      'builders', 'smokes', 'targets', 'windowsBuilder', 'support',
    ], 'evidence');
    if (evidence.schemaVersion !== 1 || evidence.status !== 'native_builds_and_sandbox_smokes_verified') {
      fail('status is not complete');
    }

    exactKeys(sourceLock.nativeBuildEvidence, ['path', 'sha256', 'support'], ['path', 'sha256', 'support'], 'source lock nativeBuildEvidence');
    if (nativeMaterial.role !== 'native-build-evidence'
        || nativeMaterial.path !== 'third_party/sidecars/semgrep/native-build-evidence.v1.json'
        || sourceLock.nativeBuildEvidence.path !== nativeMaterial.path
        || sourceLock.nativeBuildEvidence.sha256 !== nativeMaterial.sha256) fail('material binding is invalid');
    evidenceHash(nativeMaterial.sha256, 'native build material sha256');

    if (!Array.isArray(sourceLock.nativeBuildEvidence.support)
        || !Array.isArray(evidence.support)
        || sourceLock.nativeBuildEvidence.support.length !== NATIVE_EVIDENCE_SUPPORT.length
        || evidence.support.length !== NATIVE_EVIDENCE_SUPPORT.length) fail('support inventory is invalid');
    const expectedSupport = [];
    for (const [role, path] of NATIVE_EVIDENCE_SUPPORT) {
      const matches = manifestSupport.filter((material) => material.role === role && material.path === path);
      if (matches.length !== 1) fail(`support material is missing: ${role}`);
      evidenceHash(matches[0].sha256, `${role} sha256`);
      expectedSupport.push({ path, sha256: matches[0].sha256 });
    }
    if (JSON.stringify(sourceLock.nativeBuildEvidence.support) !== JSON.stringify(expectedSupport)
        || JSON.stringify(evidence.support) !== JSON.stringify(expectedSupport)) fail('support hashes drifted');
    evidenceHash(evidence.provenanceSha256, 'provenanceSha256');
    if (evidence.provenanceSha256 !== expectedSupport[0].sha256) fail('provenance hash drifted');

    exactKeys(evidence.bootstrapSource, [
      'sourceLockSha256', 'sourceRevision', 'sourceTree', 'bundleEvidenceSha256', 'bundle',
    ], [
      'sourceLockSha256', 'sourceRevision', 'sourceTree', 'bundleEvidenceSha256', 'bundle',
    ], 'bootstrapSource');
    for (const [key, label] of [
      ['sourceLockSha256', 'bootstrap source lock'],
      ['bundleEvidenceSha256', 'bootstrap bundle evidence'],
    ]) evidenceHash(evidence.bootstrapSource[key], `${label} sha256`);
    if (!GIT_ID.test(evidence.bootstrapSource.sourceRevision)
        || !GIT_ID.test(evidence.bootstrapSource.sourceTree)
        || evidence.bootstrapSource.sourceRevision !== sourceLock.sourceRevision
        || evidence.bootstrapSource.sourceTree !== sourceLock.sourceTree) fail('bootstrap source revision drifted');
    exactKeys(evidence.bootstrapSource.bundle, [
      'sha256', 'size', 'payloadEntries', 'recordedLinks',
    ], [
      'sha256', 'size', 'payloadEntries', 'recordedLinks',
    ], 'bootstrapSource.bundle');
    evidenceHash(evidence.bootstrapSource.bundle.sha256, 'bootstrap bundle sha256');
    integer(evidence.bootstrapSource.bundle.size, 'bootstrap bundle size', 1, MAX_SOURCE_BUNDLE_BYTES);
    integer(evidence.bootstrapSource.bundle.payloadEntries, 'bootstrap bundle payload entries', 1, 1_000_000);
    integer(evidence.bootstrapSource.bundle.recordedLinks, 'bootstrap bundle recorded links', 0, 1_000_000);

    exactKeys(evidence.ci, [
      'commit', 'runId', 'runAttempt', 'workflowRef', 'workflowSha',
    ], [
      'commit', 'runId', 'runAttempt', 'workflowRef', 'workflowSha',
    ], 'ci');
    if (!GIT_ID.test(evidence.ci.commit) || !GIT_ID.test(evidence.ci.workflowSha)
        || evidence.ci.commit !== evidence.ci.workflowSha
        || !/^[1-9][0-9]{0,31}$/u.test(evidence.ci.runId)
        || typeof evidence.ci.workflowRef !== 'string'
        || !evidence.ci.workflowRef.endsWith('/.github/workflows/ci.yml@refs/heads/main')) fail('CI identity is invalid');
    integer(evidence.ci.runAttempt, 'ci.runAttempt', 1);

    const targets = enabledTargets.map((target) => target.target).sort();
    if (targets.length === 0 || targets.some((target) => !NATIVE_EVIDENCE_TARGETS.has(target))) {
      fail('enabled target inventory is invalid');
    }
    const uniqueEvidenceTargets = (items, label) => {
      if (!Array.isArray(items)) fail(`${label} must be an array`);
      const values = items.map((entry) => entry?.target).sort();
      if (JSON.stringify(values) !== JSON.stringify(targets)) fail(`${label} target inventory drifted`);
    };
    uniqueEvidenceTargets(evidence.smokes, 'smoke');
    uniqueEvidenceTargets(evidence.targets, 'runtime');

    if (!Array.isArray(evidence.builders) || evidence.builders.length !== targets.length * 2) {
      fail('builder inventory is invalid');
    }
    const checkRunIds = new Set();
    for (const target of targets) {
      const policy = NATIVE_EVIDENCE_TARGETS.get(target);
      const builders = evidence.builders.filter((builder) => builder?.target === target);
      if (builders.length !== 2) fail(`${target} builder inventory is invalid`);
      builders.sort((left, right) => left.build.localeCompare(right.build));
      for (const [index, builder] of builders.entries()) {
        exactKeys(builder, [
          'target', 'build', 'artifactName', 'identitySha256', 'identitySize', 'checkRunId',
          'jobDefinition', 'jobIndex', 'jobTotal', 'runnerName', 'runnerOs', 'runnerArch',
        ], [
          'target', 'build', 'artifactName', 'identitySha256', 'identitySize', 'checkRunId',
          'jobDefinition', 'jobIndex', 'jobTotal', 'runnerName', 'runnerOs', 'runnerArch',
        ], `${target} builder`);
        const slot = index === 0 ? 'a' : 'b';
        if (builder.build !== `build-${slot}`
            || builder.artifactName !== `${policy.artifactPrefix}-${slot}-${evidence.ci.commit}-${evidence.ci.runId}-${evidence.ci.runAttempt}`
            || builder.jobDefinition !== policy.builderJob || builder.jobIndex !== index || builder.jobTotal !== 2) {
          fail(`${target} builder identity drifted`);
        }
        evidenceHash(builder.identitySha256, `${target} builder identity sha256`);
        integer(builder.identitySize, `${target} builder identity size`, 1, 1_048_576);
        integer(builder.checkRunId, `${target} builder check-run ID`, 1);
        for (const key of ['runnerName', 'runnerOs', 'runnerArch']) text(builder[key], `${target} builder ${key}`);
        if (checkRunIds.has(builder.checkRunId)) fail('check-run identity is reused');
        checkRunIds.add(builder.checkRunId);
      }
      const smoke = evidence.smokes.find((entry) => entry.target === target);
      exactKeys(smoke, [
        'target', 'checkRunId', 'jobDefinition', 'sandboxMechanism', 'sha256', 'size',
      ], [
        'target', 'checkRunId', 'jobDefinition', 'sandboxMechanism', 'sha256', 'size',
      ], `${target} smoke`);
      if (smoke.jobDefinition !== policy.smokeJob || smoke.sandboxMechanism !== policy.sandboxMechanism) {
        fail(`${target} smoke policy drifted`);
      }
      evidenceHash(smoke.sha256, `${target} smoke sha256`);
      integer(smoke.size, `${target} smoke size`, 1, 1_048_576);
      integer(smoke.checkRunId, `${target} smoke check-run ID`, 1);
      if (checkRunIds.has(smoke.checkRunId)) fail('check-run identity is reused');
      checkRunIds.add(smoke.checkRunId);

      const targetEvidence = evidence.targets.find((entry) => entry.target === target);
      exactKeys(targetEvidence, [
        'target', 'runtimeArchive', 'evidenceArchive', 'runtimeClosure', 'manifests', 'offlineEvidence',
      ], [
        'target', 'runtimeArchive', 'evidenceArchive', 'runtimeClosure', 'manifests', 'offlineEvidence',
      ], `${target} runtime evidence`);
      const manifestTarget = enabledTargets.find((entry) => entry.target === target);
      exactKeys(targetEvidence.runtimeArchive, ['name', 'size', 'sha256'], ['name', 'size', 'sha256'], `${target} runtime archive`);
      const archiveName = new URL(manifestTarget.download.url).pathname.split('/').at(-1);
      if (targetEvidence.runtimeArchive.name !== archiveName
          || targetEvidence.runtimeArchive.size !== manifestTarget.download.size
          || targetEvidence.runtimeArchive.sha256 !== manifestTarget.download.sha256) fail(`${target} runtime archive drifted`);
      exactKeys(targetEvidence.evidenceArchive, ['name', 'sha256', 'size'], ['name', 'sha256', 'size'], `${target} evidence archive`);
      text(targetEvidence.evidenceArchive.name, `${target} evidence archive name`);
      evidenceHash(targetEvidence.evidenceArchive.sha256, `${target} evidence archive sha256`);
      integer(targetEvidence.evidenceArchive.size, `${target} evidence archive size`, 1, MAX_ARTIFACT_BYTES);
      evidenceIdentity(targetEvidence.runtimeClosure, `${target} runtime closure`, 1_048_576);
      const manifestNames = [
        'build-a.MANIFEST.sha256', 'build-b.MANIFEST.sha256',
        'build-a-evidence.MANIFEST.sha256', 'build-b-evidence.MANIFEST.sha256',
      ];
      exactKeys(targetEvidence.manifests, manifestNames, manifestNames, `${target} manifests`);
      for (const name of manifestNames) evidenceIdentity(targetEvidence.manifests[name], `${target} ${name}`, 1_048_576);
      if (targetEvidence.manifests[manifestNames[0]].sha256 !== targetEvidence.manifests[manifestNames[1]].sha256
          || targetEvidence.manifests[manifestNames[2]].sha256 !== targetEvidence.manifests[manifestNames[3]].sha256) {
        fail(`${target} A/B manifests differ`);
      }
      if (!Array.isArray(targetEvidence.offlineEvidence) || targetEvidence.offlineEvidence.length !== 2) {
        fail(`${target} offline evidence is invalid`);
      }
      for (const [index, offline] of targetEvidence.offlineEvidence.entries()) {
        exactKeys(offline, ['build', 'sha256', 'size'], ['build', 'sha256', 'size'], `${target} offline evidence`);
        if (offline.build !== `build-${index === 0 ? 'a' : 'b'}`) fail(`${target} offline build drifted`);
        evidenceHash(offline.sha256, `${target} offline sha256`);
        integer(offline.size, `${target} offline size`, 1, 1_048_576);
      }
    }

    if (targets.includes('windows-x86_64')) {
      exactKeys(evidence.windowsBuilder, ['evidence', 'schema', 'toolchain'], ['evidence', 'schema', 'toolchain'], 'windowsBuilder');
      for (const key of ['evidence', 'schema', 'toolchain']) {
        evidenceIdentity(evidence.windowsBuilder[key], `windowsBuilder.${key}`, 16_777_216);
      }
      const sourceWindows = sourceLock.toolchains?.filter(
        (toolchain) => toolchain?.distributionTarget === 'windows-x86_64',
      );
      if (sourceWindows?.length !== 1
          || sourceWindows[0].status !== 'native_builds_verified'
          || sourceWindows[0].builderEvidence?.status !== 'verified_native_capture'
          || sourceWindows[0].builderEvidence?.sha256 !== evidence.windowsBuilder.evidence.sha256
          || sourceWindows[0].builderEvidence?.schemaSha256 !== evidence.windowsBuilder.schema.sha256) {
        fail('Windows builder source-lock binding drifted');
      }
    } else if (evidence.windowsBuilder !== null) fail('unexpected Windows builder evidence');
  } catch (error) {
    if (error.message.startsWith('semgrep native build evidence ')) throw error;
    fail(`is invalid: ${error.message}`);
  }
}

function validateSemgrepBundleEvidence(bytes, sourceLockSha256, generatorSha256) {
  let evidence;
  try {
    evidence = JSON.parse(decodeUtf8(bytes, 'semgrep bundle evidence'));
  } catch {
    throw new Error('semgrep bundle evidence is not valid UTF-8 JSON');
  }
  exactKeys(
    evidence,
    [
      'schemaVersion',
      'format',
      'sourceLockSha256',
      'bundleGeneratorSha256',
      'independentBuilds',
      'byteIdentical',
      'status',
      'sourceAssetUrl',
      'bundle',
    ],
    [
      'schemaVersion',
      'format',
      'sourceLockSha256',
      'bundleGeneratorSha256',
      'independentBuilds',
      'byteIdentical',
      'status',
      'sourceAssetUrl',
      'bundle',
    ],
    'semgrep bundle evidence',
  );
  exactKeys(
    evidence.bundle,
    ['sha256', 'size', 'payloadEntries', 'recordedLinks'],
    ['sha256', 'size', 'payloadEntries', 'recordedLinks'],
    'semgrep bundle evidence.bundle',
  );
  hash(evidence.sourceLockSha256, 'semgrep bundle evidence.sourceLockSha256');
  hash(evidence.bundleGeneratorSha256, 'semgrep bundle evidence.bundleGeneratorSha256');
  hash(evidence.bundle.sha256, 'semgrep bundle evidence.bundle.sha256');
  integer(evidence.bundle.size, 'semgrep bundle evidence.bundle.size', 1, MAX_SOURCE_BUNDLE_BYTES);
  integer(evidence.bundle.payloadEntries, 'semgrep bundle evidence.bundle.payloadEntries', 1, 1_000_000);
  integer(evidence.bundle.recordedLinks, 'semgrep bundle evidence.bundle.recordedLinks', 0, 1_000_000);
  if (evidence.schemaVersion !== 1) throw new Error('semgrep bundle evidence schemaVersion must be 1');
  if (evidence.format !== 'context-relay-semgrep-source-v1') throw new Error('semgrep bundle evidence format is unsupported');
  if (evidence.independentBuilds !== 2) throw new Error('semgrep bundle evidence must record exactly two independent builds');
  if (evidence.byteIdentical !== true) throw new Error('semgrep bundle evidence builds are not byte-identical');
  if (evidence.status !== 'complete_corresponding_source') throw new Error('semgrep bundle evidence status is not complete');
  if (evidence.sourceAssetUrl !== SEMGREP_SOURCE_ASSET_URL) throw new Error('semgrep bundle evidence source asset URL is not fixed');
  if (evidence.sourceLockSha256 !== sourceLockSha256) throw new Error('semgrep bundle evidence source lock SHA-256 mismatch');
  if (evidence.bundleGeneratorSha256 !== generatorSha256) throw new Error('semgrep bundle evidence generator SHA-256 mismatch');
  if (evidence.bundle.sha256 === '0'.repeat(64)) throw new Error('semgrep bundle evidence bundle SHA-256 is empty');
}

export async function validateManifestMaterials(manifest, workspace) {
  workspace = asPath(workspace);
  for (const tool of manifest.tools) {
    const sourceLock = await verifyMaterial(
      workspace,
      { path: tool.source.materialPath, sha256: tool.source.materialSha256 },
      `${tool.id} source`,
    );
    await verifyMaterial(workspace, tool.license, `${tool.id} license`);
    if (tool.relinking) await verifyMaterial(workspace, tool.relinking, `${tool.id} relinking`);
    const verifiedMaterials = [];
    for (const material of tool.materials) verifiedMaterials.push({
      ...material,
      bytes: await verifyMaterial(workspace, material, `${tool.id} ${material.role}`),
    });
    const enabledTargets = tool.targets.filter((target) => target.enabled);
    if (tool.id === 'semgrep' && enabledTargets.length !== 0) {
      const sourceGate = validateSemgrepSourceLock(sourceLock, enabledTargets);
      const evidence = verifiedMaterials.filter((material) => material.role === 'source-bundle-evidence');
      const generator = verifiedMaterials.filter((material) => material.role === 'source-bundle-generator');
      if (evidence.length !== 1 || generator.length !== 1) {
        throw new Error('semgrep bundle evidence requires exactly one evidence and generator material');
      }
      validateSemgrepBundleEvidence(
        evidence[0].bytes,
        tool.source.materialSha256,
        generator[0].sha256,
      );
      const nativeEvidence = verifiedMaterials.filter((material) => material.role === 'native-build-evidence');
      if (nativeEvidence.length !== 1) throw new Error('semgrep native build evidence requires exactly one material');
      let nativeEvidenceValue;
      try {
        nativeEvidenceValue = JSON.parse(decodeUtf8(nativeEvidence[0].bytes, 'semgrep native build evidence'));
      } catch {
        throw new Error('semgrep native build evidence is not valid UTF-8 JSON');
      }
      validateSemgrepNativeBuildEvidence(
        nativeEvidenceValue,
        sourceGate,
        nativeEvidence[0],
        verifiedMaterials,
        enabledTargets,
      );
    }
  }
}

function archivePath(name) {
  safeRelativePath(name, 'archive entry path');
  return name;
}

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function zipEntries(bytes) {
  const DATA_DESCRIPTOR_FLAG = 0x0008;
  const UTF8_FLAG = 0x0800;
  let end = -1;
  const minimum = Math.max(0, bytes.length - 65557);
  for (let offset = bytes.length - 22; offset >= minimum; offset -= 1) {
    if (bytes.readUInt32LE(offset) === 0x06054b50) {
      end = offset;
      break;
    }
  }
  if (end < 0) throw new Error('ZIP end record is missing');
  if (bytes.readUInt16LE(end + 4) !== 0 || bytes.readUInt16LE(end + 6) !== 0) throw new Error('multi-disk ZIP is forbidden');
  const count = bytes.readUInt16LE(end + 10);
  if (count !== bytes.readUInt16LE(end + 8)) throw new Error('ZIP entry counts disagree');
  const centralSize = bytes.readUInt32LE(end + 12);
  const centralOffset = bytes.readUInt32LE(end + 16);
  const commentLength = bytes.readUInt16LE(end + 20);
  if (end + 22 + commentLength !== bytes.length) throw new Error('ZIP trailing data is forbidden');
  if (centralOffset > end || centralSize > end - centralOffset || centralOffset + centralSize !== end) {
    throw new Error('ZIP central directory bounds are invalid');
  }
  const entries = [];
  const localRanges = [];
  let offset = centralOffset;
  for (let index = 0; index < count; index += 1) {
    if (offset + 46 > end || bytes.readUInt32LE(offset) !== 0x02014b50) throw new Error('ZIP central entry is invalid');
    const madeBy = bytes.readUInt16LE(offset + 4) >> 8;
    const flags = bytes.readUInt16LE(offset + 8);
    const method = bytes.readUInt16LE(offset + 10);
    if ((flags & ~(DATA_DESCRIPTOR_FLAG | UTF8_FLAG)) !== 0) throw new Error('unsupported or encrypted ZIP flags are forbidden');
    if (method !== 0 && method !== 8) throw new Error('unsupported ZIP compression');
    const expectedCrc = bytes.readUInt32LE(offset + 16);
    const compressedSize = bytes.readUInt32LE(offset + 20);
    const size = bytes.readUInt32LE(offset + 24);
    const nameLength = bytes.readUInt16LE(offset + 28);
    const extraLength = bytes.readUInt16LE(offset + 30);
    const commentLength = bytes.readUInt16LE(offset + 32);
    const centralEntryLength = 46 + nameLength + extraLength + commentLength;
    if (centralEntryLength > end - offset) throw new Error('ZIP central entry is truncated');
    if (bytes.readUInt16LE(offset + 34) !== 0) throw new Error('multi-disk ZIP entries are forbidden');
    const name = archivePath(decodeUtf8(
      bytes.subarray(offset + 46, offset + 46 + nameLength),
      'ZIP central name',
    ));
    const external = bytes.readUInt32LE(offset + 38);
    const unixType = madeBy === 3 ? ((external >>> 16) & 0o170000) : 0;
    const type = name.endsWith('/') || unixType === 0o040000 ? 'directory' : 'file';
    if (unixType !== 0 && unixType !== 0o040000 && unixType !== 0o100000) throw new Error('ZIP special entries are forbidden');
    const localOffset = bytes.readUInt32LE(offset + 42);
    if (localOffset > centralOffset || 30 > centralOffset - localOffset || bytes.readUInt32LE(localOffset) !== 0x04034b50) {
      throw new Error('ZIP local entry is invalid');
    }
    const localNameLength = bytes.readUInt16LE(localOffset + 26);
    const localExtraLength = bytes.readUInt16LE(localOffset + 28);
    const localVariableLength = localNameLength + localExtraLength;
    if (localVariableLength > centralOffset - (localOffset + 30)) throw new Error('ZIP local entry is truncated');
    const localName = decodeUtf8(
      bytes.subarray(localOffset + 30, localOffset + 30 + localNameLength),
      'ZIP local name',
    );
    if (
      localName !== name
      || bytes.readUInt16LE(localOffset + 6) !== flags
      || bytes.readUInt16LE(localOffset + 8) !== method
    ) throw new Error('ZIP local/central entries disagree');
    const localCrc = bytes.readUInt32LE(localOffset + 14);
    const localCompressedSize = bytes.readUInt32LE(localOffset + 18);
    const localSize = bytes.readUInt32LE(localOffset + 22);
    const usesDataDescriptor = (flags & DATA_DESCRIPTOR_FLAG) !== 0;
    if (usesDataDescriptor) {
      if (localCrc !== 0 || localCompressedSize !== 0 || localSize !== 0) {
        throw new Error('ZIP data descriptor local fields must be zero');
      }
    } else if (localCrc !== expectedCrc || localCompressedSize !== compressedSize || localSize !== size) {
      throw new Error('ZIP local/central entries disagree');
    }
    const start = localOffset + 30 + localNameLength + localExtraLength;
    if (compressedSize > centralOffset - start) throw new Error('ZIP entry is truncated');
    const compressedEnd = start + compressedSize;
    const compressed = bytes.subarray(start, compressedEnd);
    let localEnd = compressedEnd;
    if (usesDataDescriptor) {
      if (16 > centralOffset - compressedEnd) throw new Error('ZIP data descriptor is truncated');
      if (bytes.readUInt32LE(compressedEnd) !== 0x08074b50) throw new Error('ZIP data descriptor signature is invalid');
      if (bytes.readUInt32LE(compressedEnd + 4) !== expectedCrc) throw new Error('ZIP data descriptor CRC disagrees');
      if (bytes.readUInt32LE(compressedEnd + 8) !== compressedSize) throw new Error('ZIP data descriptor compressed size disagrees');
      if (bytes.readUInt32LE(compressedEnd + 12) !== size) throw new Error('ZIP data descriptor uncompressed size disagrees');
      localEnd += 16;
    }
    const body = method === 0 ? Buffer.from(compressed) : inflateRawSync(compressed, { maxOutputLength: size });
    if (body.length !== size || crc32(body) !== expectedCrc) throw new Error('ZIP entry content is invalid');
    entries.push({ path: name, type, size, body });
    localRanges.push({ start: localOffset, end: localEnd });
    offset += centralEntryLength;
  }
  if (offset !== end) throw new Error('ZIP central directory has trailing data');
  localRanges.sort((left, right) => left.start - right.start || left.end - right.end);
  let localOffset = 0;
  for (const range of localRanges) {
    if (range.start < localOffset) throw new Error('ZIP local record layout overlaps');
    if (range.start > localOffset) throw new Error('ZIP local record layout has a gap');
    localOffset = range.end;
  }
  if (localOffset !== centralOffset) throw new Error('ZIP local record layout has a gap');
  return entries;
}

function octal(bytes, offset, length, label) {
  const value = bytes.subarray(offset, offset + length).toString('ascii').replace(/\0.*$/, '').trim();
  if (!/^[0-7]+$/.test(value || '0')) throw new Error(`TAR ${label} is invalid`);
  return Number.parseInt(value || '0', 8);
}

function tarEntries(archive) {
  let bytes;
  try {
    bytes = gunzipSync(archive, { maxOutputLength: MAX_ARTIFACT_BYTES });
  } catch (error) {
    throw new Error(`TAR gzip is invalid: ${error.message}`);
  }
  const entries = [];
  let offset = 0;
  let terminated = false;
  while (offset + 512 <= bytes.length) {
    const header = bytes.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {
      if (offset + 1024 > bytes.length || !bytes.subarray(offset).every((byte) => byte === 0)) {
        throw new Error('TAR trailing data is forbidden');
      }
      terminated = true;
      break;
    }
    const storedChecksum = octal(header, 148, 8, 'checksum');
    const checksumHeader = Buffer.from(header);
    checksumHeader.fill(0x20, 148, 156);
    if ([...checksumHeader].reduce((sum, byte) => sum + byte, 0) !== storedChecksum) throw new Error('TAR checksum mismatch');
    const rawName = decodeUtf8(header.subarray(0, 100), 'TAR name').replace(/\0.*$/, '');
    const prefix = decodeUtf8(header.subarray(345, 500), 'TAR prefix').replace(/\0.*$/, '');
    const path = archivePath(prefix ? `${prefix}/${rawName}` : rawName);
    const size = octal(header, 124, 12, 'size');
    const flag = header[156];
    const type = flag === 53 ? 'directory' : (flag === 0 || flag === 48) ? 'file' : null;
    if (!type) throw new Error('TAR special entries are forbidden');
    const start = offset + 512;
    const body = bytes.subarray(start, start + size);
    if (body.length !== size) throw new Error('TAR entry is truncated');
    entries.push({ path, type, size, body: Buffer.from(body) });
    offset = start + Math.ceil(size / 512) * 512;
  }
  if (!terminated) throw new Error('TAR zero terminator is missing');
  return entries;
}

function extractExpectedEntries(bytes, format, expected) {
  let actual;
  if (format === 'raw') {
    actual = [{ path: expected.extractPath, type: 'file', size: bytes.length, body: Buffer.from(bytes) }];
  } else if (format === 'zip') {
    actual = zipEntries(bytes);
  } else if (format === 'tar.gz') {
    actual = tarEntries(bytes);
  } else {
    throw new Error('unsupported archive format');
  }
  if (actual.length !== expected.entries.length) throw new Error('archive entry count mismatch');
  for (let index = 0; index < actual.length; index += 1) {
    const got = actual[index];
    const want = expected.entries[index];
    if (got.path !== want.path) throw new Error(`archive entry path mismatch at ${index}`);
    if (got.type !== want.type) throw new Error(`archive entry type mismatch for ${got.path}`);
    if (got.size !== want.size) throw new Error(`archive entry size mismatch for ${got.path}`);
  }
  return actual;
}

export function extractExpectedFile(bytes, format, expected) {
  const actual = extractExpectedEntries(bytes, format, expected);
  const selected = actual.find((entry) => entry.path === expected.extractPath);
  if (!selected || selected.type !== 'file') throw new Error('archive extract path is missing');
  return selected.body;
}

function extractRuntimeClosure(bytes, format, target) {
  const actual = extractExpectedEntries(bytes, format, target.download);
  const byPath = new Map(actual.map((entry) => [entry.path, entry]));
  return target.closure.map((entry) => {
    const label = entry.path === target.executable.path ? 'executable' : 'runtime closure';
    const archivePath = entry.path === target.executable.path
      ? target.download.extractPath
      : entry.path;
    const selected = byPath.get(archivePath);
    if (!selected || selected.type !== 'file') {
      throw new Error(`runtime closure archive entry is missing: ${archivePath}`);
    }
    if (selected.body.length !== entry.size) {
      throw new Error(`${label} size mismatch: ${entry.path}`);
    }
    if (sha256(selected.body) !== entry.sha256) {
      throw new Error(`${label} SHA-256 mismatch: ${entry.path}`);
    }
    return { entry, bytes: selected.body };
  });
}

async function readBoundedResponse(response, expectedSize, signal) {
  const contentLength = response.headers.get('content-length');
  if (contentLength !== null && (!/^\d+$/.test(contentLength) || Number(contentLength) !== expectedSize)) {
    throw new Error('download Content-Length mismatch');
  }
  if (!response.body?.getReader) {
    if (contentLength === null) throw new Error('non-streaming download is missing Content-Length');
    const bytes = Buffer.from(await response.arrayBuffer());
    if (bytes.length > expectedSize) throw new Error('download exceeds expected size');
    return bytes;
  }
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      ensureNotAborted(signal);
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > expectedSize) {
        await reader.cancel();
        throw new Error('download exceeds expected size');
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks, total);
}

async function fetchPinned(url, hosts, fetchImpl, signal, expectedSize) {
  let current = new URL(url);
  for (let redirects = 0; redirects <= MAX_REDIRECTS; redirects += 1) {
    if (current.protocol !== 'https:' || !hosts.has(current.hostname) || current.username || current.password) {
      throw new Error(`redirect host is not allowlisted: ${current.hostname}`);
    }
    const response = await fetchImpl(current, { redirect: 'manual', signal });
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get('location');
      if (!location) throw new Error('redirect is missing Location');
      current = new URL(location, current);
      continue;
    }
    if (response.status !== 200) throw new Error(`download failed with HTTP ${response.status}`);
    return readBoundedResponse(response, expectedSize, signal);
  }
  throw new Error('too many redirects');
}

function ensureNotAborted(signal) {
  if (signal?.aborted) throw signal.reason instanceof Error ? signal.reason : new Error('hydration aborted');
}

function topologyError(path, detail) {
  return new Error(`sidecar cache contains unsafe topology (${detail}): ${path}`);
}

function sameIdentity(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.birthtimeMs === right.birthtimeMs;
}

function childParts(root, target) {
  const value = relative(resolve(root), resolve(target));
  if (
    value === '..'
    || value.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`)
    || isAbsolute(value)
  ) throw topologyError(target, 'path escapes trusted root');
  return value === '' ? [] : value.split(/[\\/]/u);
}

async function safeDirectoryChain(root, target) {
  const trustedRoot = resolve(root);
  const parts = childParts(trustedRoot, target);
  const snapshots = [];
  let current = trustedRoot;
  for (let index = -1; index < parts.length; index += 1) {
    if (index >= 0) current = join(current, parts[index]);
    let info;
    try {
      info = await lstat(current, { bigint: true });
    } catch {
      throw topologyError(current, 'directory is missing');
    }
    if (info.isSymbolicLink() || !info.isDirectory()) {
      throw topologyError(current, 'linked or non-directory ancestor');
    }
    snapshots.push({ path: current, info });
  }
  return snapshots;
}

async function recheckDirectoryChain(snapshots) {
  for (const snapshot of snapshots) {
    const current = await lstat(snapshot.path, { bigint: true }).catch(() => null);
    if (
      !current
      || current.isSymbolicLink()
      || !current.isDirectory()
      || !sameIdentity(current, snapshot.info)
    ) throw topologyError(snapshot.path, 'ancestor identity changed');
  }
}

async function safeDirectoryEntries(workspace, directory) {
  const snapshots = await safeDirectoryChain(workspace, directory);
  const before = (await readdir(directory)).sort();
  const entries = [];
  for (const name of before) {
    const path = join(directory, name);
    const info = await lstat(path, { bigint: true });
    if (info.isSymbolicLink() || (!info.isDirectory() && !info.isFile())) {
      throw topologyError(path, 'link or special entry');
    }
    if (info.isFile() && info.nlink !== 1n) {
      throw topologyError(path, 'hardlink link count is not one');
    }
    entries.push({ name, info });
  }
  const after = (await readdir(directory)).sort();
  if (JSON.stringify(before) !== JSON.stringify(after)) {
    throw topologyError(directory, 'directory inventory changed');
  }
  await recheckDirectoryChain(snapshots);
  return entries;
}

async function listFiles(workspace, root, prefix = '') {
  const directory = prefix ? join(root, ...prefix.split('/')) : root;
  const files = [];
  for (const entry of await safeDirectoryEntries(workspace, directory)) {
    const path = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.info.isDirectory()) files.push(...await listFiles(workspace, root, path));
    else files.push(path);
  }
  return files;
}

async function readSafeClosureFile(workspace, path, entry) {
  const snapshots = await safeDirectoryChain(workspace, dirname(path));
  const before = await lstat(path, { bigint: true }).catch(() => null);
  if (!before || before.isSymbolicLink() || !before.isFile()) {
    throw topologyError(path, 'closure entry is not a regular no-link file');
  }
  if (before.nlink !== 1n) throw topologyError(path, 'hardlink link count is not one');
  if (before.size !== BigInt(entry.size)) throw new Error(`sidecar closure size mismatch: ${entry.path}`);

  const noFollow = process.platform === 'win32' ? 0 : (fsConstants.O_NOFOLLOW ?? 0);
  let handle;
  try {
    handle = await open(path, fsConstants.O_RDONLY | noFollow);
  } catch {
    throw topologyError(path, 'closure entry could not be opened without following links');
  }
  let opened;
  let bytes;
  try {
    opened = await handle.stat({ bigint: true });
    if (
      !opened.isFile()
      || opened.nlink !== 1n
      || !sameIdentity(before, opened)
      || opened.size !== BigInt(entry.size)
    ) throw topologyError(path, 'closure entry identity changed while opening');
    bytes = await handle.readFile();
    const afterRead = await handle.stat({ bigint: true });
    if (!sameIdentity(opened, afterRead) || afterRead.size !== opened.size || afterRead.nlink !== 1n) {
      throw topologyError(path, 'closure entry changed while reading');
    }
  } finally {
    await handle.close();
  }
  const after = await lstat(path, { bigint: true }).catch(() => null);
  if (!after || after.isSymbolicLink() || !after.isFile() || !sameIdentity(opened, after)) {
    throw topologyError(path, 'closure entry changed after reading');
  }
  await recheckDirectoryChain(snapshots);
  return { bytes, info: opened };
}

async function verifyClosure(workspace, directory, artifact) {
  const expected = artifact.target.closure;
  uniquePaths(expected, `${artifact.tool.id} enabled closure`);
  const actual = (await listFiles(workspace, directory)).sort();
  const paths = expected.map((entry) => entry.path).sort();
  if (JSON.stringify(actual) !== JSON.stringify(paths)) {
    throw new Error(`${artifact.tool.id} sidecar closure path inventory mismatch`);
  }
  for (const entry of expected) {
    const path = join(directory, ...entry.path.split('/'));
    const { bytes, info } = await readSafeClosureFile(workspace, path, entry);
    if (sha256(bytes) !== entry.sha256) throw new Error(`sidecar closure SHA-256 mismatch: ${entry.path}`);
    if (process.platform !== 'win32' && entry.executable !== ((Number(info.mode) & 0o111) !== 0)) {
      throw new Error(`sidecar closure executable mode mismatch: ${entry.path}`);
    }
  }
}

async function verifyCache(workspace, directory, artifacts) {
  const expectedTools = artifacts.map(({ tool }) => tool.id).sort();
  const entries = await safeDirectoryEntries(workspace, directory);
  const actualTools = entries.map(({ name }) => name).sort();
  if (
    JSON.stringify(actualTools) !== JSON.stringify(expectedTools)
    || entries.some(({ info }) => !info.isDirectory())
  ) throw new Error('sidecar cache per-tool inventory mismatch');
  for (const artifact of artifacts) {
    await verifyClosure(workspace, join(directory, artifact.tool.id), artifact);
  }
  const after = (await safeDirectoryEntries(workspace, directory)).map(({ name }) => name).sort();
  if (JSON.stringify(after) !== JSON.stringify(expectedTools)) {
    throw topologyError(directory, 'per-tool inventory changed during verification');
  }
}

function integerBuffer(bytes, value) {
  const buffer = Buffer.alloc(bytes);
  if (bytes === 2) buffer.writeUInt16LE(value);
  else if (bytes === 4) buffer.writeUInt32LE(value);
  else buffer.writeBigUInt64LE(BigInt(value));
  return buffer;
}

async function writeToChild(stream, bytes) {
  await new Promise((resolveWrite, rejectWrite) => {
    stream.write(bytes, (error) => (error ? rejectWrite(error) : resolveWrite()));
  });
}

export function guardedInstallerInvocation() {
  const repository = resolve(import.meta.dirname, '..');
  return {
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
  };
}

async function runGuardedInstaller({ workspace, target, manifestDigest, nonce, files, signal }) {
  ensureNotAborted(signal);
  // Hydration is a developer/CI build-time command; a trusted Cargo installation on PATH is a prerequisite.
  const invocation = guardedInstallerInvocation();
  const child = spawn(invocation.command, invocation.args, invocation.options);
  const output = { stdout: [], stderr: [], stdoutBytes: 0, stderrBytes: 0, exceeded: false };
  for (const [name, stream] of [['stdout', child.stdout], ['stderr', child.stderr]]) {
    stream.on('data', (chunk) => {
      const count = `${name}Bytes`;
      output[count] += chunk.length;
      if (output[count] > 65536) {
        output.exceeded = true;
        child.kill();
      } else {
        output[name].push(Buffer.from(chunk));
      }
    });
  }
  const closed = new Promise((resolveClose, rejectClose) => {
    child.once('error', rejectClose);
    child.once('close', (code) => resolveClose(code));
  });
  const abort = () => child.kill();
  signal?.addEventListener('abort', abort, { once: true });
  try {
    const workspaceBytes = Buffer.from(workspace, 'utf8');
    const targetBytes = Buffer.from(target, 'utf8');
    const chunks = [
      Buffer.from('CRHYDR1\0', 'ascii'),
      integerBuffer(4, workspaceBytes.length),
      workspaceBytes,
      integerBuffer(2, targetBytes.length),
      targetBytes,
      Buffer.from(manifestDigest, 'hex'),
      Buffer.from(nonce, 'hex'),
      integerBuffer(2, files.length),
    ];
    for (const chunk of chunks) await writeToChild(child.stdin, chunk);
    for (const file of files) {
      const path = Buffer.from(file.path, 'utf8');
      await writeToChild(child.stdin, integerBuffer(2, path.length));
      await writeToChild(child.stdin, path);
      await writeToChild(child.stdin, Buffer.from([Number(file.executable)]));
      await writeToChild(child.stdin, integerBuffer(8, file.bytes.length));
      await writeToChild(child.stdin, Buffer.from(file.sha256, 'hex'));
      await writeToChild(child.stdin, file.bytes);
    }
    child.stdin.end();
    const code = await closed;
    ensureNotAborted(signal);
    if (output.exceeded) throw new Error('native guarded hydration output exceeded its bound');
    const stdout = Buffer.concat(output.stdout).toString('utf8');
    const stderr = Buffer.concat(output.stderr).toString('utf8').trim();
    if (code !== 0) throw new Error(stderr || 'native guarded hydration failed');
    if (stdout !== 'installed\n' && stdout !== 'exists\n') {
      throw new Error('native guarded hydration returned an invalid response');
    }
    return stdout === 'installed\n' ? 'installed' : 'exists';
  } catch (error) {
    child.stdin.destroy();
    child.kill();
    await closed.catch(() => {});
    throw error;
  } finally {
    signal?.removeEventListener('abort', abort);
  }
}

function defaultTarget() {
  if (process.platform === 'win32' && process.arch === 'x64') return 'windows-x86_64';
  if (process.platform === 'darwin' && process.arch === 'arm64') return 'macos-aarch64';
  if (process.platform === 'darwin' && process.arch === 'x64') return 'macos-x86_64';
  throw new Error(`unsupported hydration target: ${process.platform}-${process.arch}`);
}

function parseCiCandidateDocument(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > MAX_MANIFEST_BYTES) {
    throw new Error('CI candidate document is missing or too large');
  }
  let candidate;
  try {
    candidate = JSON.parse(decodeUtf8(bytes, 'CI candidate document'));
  } catch {
    throw new Error('CI candidate document is not valid UTF-8 JSON');
  }
  exactKeys(
    candidate,
    [
      'schemaVersion',
      'purpose',
      'publishable',
      'enabled',
      'target',
      'sidecar',
      'version',
      'productionManifestSha256',
      'sourceLockSha256',
      'bundleEvidenceSha256',
      'bundleEvidenceStatus',
      'archive',
      'executable',
      'closure',
    ],
    [
      'schemaVersion',
      'purpose',
      'publishable',
      'enabled',
      'target',
      'sidecar',
      'version',
      'productionManifestSha256',
      'sourceLockSha256',
      'bundleEvidenceSha256',
      'bundleEvidenceStatus',
      'archive',
      'executable',
      'closure',
    ],
    'CI candidate document',
  );
  if (candidate.schemaVersion !== 1
      || candidate.purpose !== 'ci-native-sidecar-smoke-only'
      || candidate.publishable !== false
      || candidate.enabled !== false
      || candidate.sidecar !== 'semgrep'
      || !TARGETS.has(candidate.target)
      || !CI_CANDIDATE_SOURCE_CLAIMS.has(candidate.bundleEvidenceStatus)) {
    throw new Error('CI candidate document is not an explicitly pending smoke document');
  }
  text(candidate.version, 'CI candidate document.version');
  hash(candidate.productionManifestSha256, 'CI candidate document.productionManifestSha256');
  hash(candidate.sourceLockSha256, 'CI candidate document.sourceLockSha256');
  hash(candidate.bundleEvidenceSha256, 'CI candidate document.bundleEvidenceSha256');
  exactKeys(
    candidate.archive,
    ['format', 'size', 'sha256', 'entries', 'extractPath'],
    ['format', 'size', 'sha256', 'entries', 'extractPath'],
    'CI candidate document.archive',
  );
  if (candidate.archive.format !== 'tar.gz') throw new Error('CI candidate archive format is unsupported');
  integer(candidate.archive.size, 'CI candidate document.archive.size', 1, MAX_ARTIFACT_BYTES);
  hash(candidate.archive.sha256, 'CI candidate document.archive.sha256');
  if (!Array.isArray(candidate.archive.entries) || candidate.archive.entries.length === 0
      || candidate.archive.entries.length > MAX_ARCHIVE_ENTRIES) {
    throw new Error('CI candidate archive entries are invalid');
  }
  candidate.archive.entries.forEach((entry, index) => validateEntry(entry, `CI candidate document.archive.entries[${index}]`));
  uniquePaths(candidate.archive.entries, 'CI candidate document.archive.entries');
  safeRelativePath(candidate.archive.extractPath, 'CI candidate document.archive.extractPath');
  exactKeys(
    candidate.executable,
    ['path', 'size', 'sha256'],
    ['path', 'size', 'sha256'],
    'CI candidate document.executable',
  );
  safeRelativePath(candidate.executable.path, 'CI candidate document.executable.path');
  integer(candidate.executable.size, 'CI candidate document.executable.size', 1, MAX_ARTIFACT_BYTES);
  hash(candidate.executable.sha256, 'CI candidate document.executable.sha256');
  if (!Array.isArray(candidate.closure) || candidate.closure.length === 0
      || candidate.closure.length > MAX_CLOSURE_ENTRIES) {
    throw new Error('CI candidate closure is invalid');
  }
  candidate.closure.forEach((entry, index) => validateClosure(entry, `CI candidate document.closure[${index}]`));
  uniquePaths(candidate.closure, 'CI candidate document.closure');
  const executable = candidate.closure.find((entry) => entry.path === candidate.executable.path);
  if (!executable || !executable.executable
      || executable.size !== candidate.executable.size
      || executable.sha256 !== candidate.executable.sha256
      || candidate.archive.extractPath !== candidate.executable.path) {
    throw new Error('CI candidate executable does not match its closure');
  }
  const expectedEntries = candidate.closure.map(({ path, size }) => ({ path, type: 'file', size }));
  if (JSON.stringify(candidate.archive.entries) !== JSON.stringify(expectedEntries)) {
    throw new Error('CI candidate archive inventory does not match its closure');
  }
  return candidate;
}

function ciCandidateDigest(bytes) {
  return sha256(Buffer.concat([
    Buffer.from('context-relay/ci-candidate-sidecar-smoke/v1\0'),
    bytes,
  ]));
}

function assertPendingCiCandidateMaterials(manifest, workspace, candidate) {
  const semgrep = manifest.tools.find(({ id }) => id === 'semgrep');
  const target = semgrep?.targets.find(({ target: name }) => name === candidate.target);
  if (!semgrep || !target
      || target.enabled !== false
      || target.correspondingSourceComplete !== false
      || target.download !== null
      || target.executable !== null
      || target.closure.length !== 0
      || semgrep.version !== candidate.version
      || semgrep.source.materialSha256 !== candidate.sourceLockSha256) {
    throw new Error('CI candidate production target is not strictly pending');
  }
  const sourceTarget = candidate.target === 'windows-x86_64'
    ? 'windows-x86_64'
    : candidate.target === 'macos-aarch64'
      ? 'aarch64-apple-darwin'
      : 'x86_64-apple-darwin';
  return Promise.all([
    readFile(join(workspace, ...semgrep.source.materialPath.split('/'))),
    (async () => {
      const evidence = semgrep.materials.filter(({ role }) => role === 'source-bundle-evidence');
      if (evidence.length !== 1 || evidence[0].sha256 !== candidate.bundleEvidenceSha256) {
        throw new Error('CI candidate bundle evidence identity mismatch');
      }
      return readFile(join(workspace, ...evidence[0].path.split('/')));
    })(),
  ]).then(([sourceBytes, evidenceBytes]) => {
    if (sha256(sourceBytes) !== candidate.sourceLockSha256
        || sha256(evidenceBytes) !== candidate.bundleEvidenceSha256) {
      throw new Error('CI candidate pending material SHA-256 mismatch');
    }
    let source;
    let evidence;
    try {
      source = JSON.parse(decodeUtf8(sourceBytes, 'CI candidate source lock'));
      evidence = JSON.parse(decodeUtf8(evidenceBytes, 'CI candidate bundle evidence'));
    } catch {
      throw new Error('CI candidate pending materials are not valid JSON');
    }
    const statuses = source.targetStatus?.filter(({ distributionTarget }) => distributionTarget === sourceTarget) ?? [];
    const [independentBuilds, byteIdentical] = CI_CANDIDATE_SOURCE_CLAIMS.get(
      candidate.bundleEvidenceStatus,
    );
    if (source.completeCorrespondingSource !== false
        || source.recursiveInventoryComplete !== true
        || source.opam?.resolvedSourceArchivesComplete !== true
        || !Array.isArray(source.missingMaterial)
        || source.missingMaterial.length === 0
        || statuses.length !== 1
        || statuses[0].enabled !== false
        || evidence.sourceLockSha256 !== candidate.sourceLockSha256
        || evidence.independentBuilds !== independentBuilds
        || evidence.byteIdentical !== byteIdentical
        || evidence.status !== candidate.bundleEvidenceStatus) {
      throw new Error('CI candidate source or bundle evidence was prematurely completed');
    }
  });
}

// Programmatic CI-only bridge. It is intentionally absent from parseCli and never mutates the
// production manifest or source evidence into an enabled state.
export async function hydrateCiCandidateSidecar({
  archiveBytes,
  candidateDocumentBytes,
  workspace = resolve(import.meta.dirname, '..'),
  target,
  fetchImpl = globalThis.fetch,
  signal,
}) {
  workspace = resolve(asPath(workspace));
  if (!TARGETS.has(target)) throw new Error(`unsupported hydration target: ${target}`);
  const candidate = parseCiCandidateDocument(candidateDocumentBytes);
  if (candidate.target !== target) throw new Error('CI candidate target mismatch');
  const manifestPath = join(workspace, 'third_party/sidecars/manifest.v1.json');
  const manifestBytes = await readFile(manifestPath);
  const manifest = parseSidecarManifest(manifestBytes.toString('utf8'));
  await validateManifestMaterials(manifest, workspace);
  if (sha256(manifestBytes) !== candidate.productionManifestSha256) {
    throw new Error('CI candidate production manifest SHA-256 mismatch');
  }
  await assertPendingCiCandidateMaterials(manifest, workspace, candidate);
  if (!Buffer.isBuffer(archiveBytes) || archiveBytes.length !== candidate.archive.size) {
    throw new Error('CI candidate archive size mismatch');
  }
  if (sha256(archiveBytes) !== candidate.archive.sha256) {
    throw new Error('CI candidate archive SHA-256 mismatch');
  }

  const productionArtifacts = manifest.tools
    .map((tool) => ({ tool, target: tool.targets.find((entry) => entry.target === target) }))
    .filter(({ target: entry }) => entry?.enabled);
  let production;
  if (productionArtifacts.length !== 0) {
    production = await hydrateSidecars({ fetchImpl, signal, target, workspace });
  }
  const semgrep = manifest.tools.find(({ id }) => id === 'semgrep');
  const candidateTarget = {
    download: candidate.archive,
    executable: candidate.executable,
    closure: candidate.closure,
  };
  const artifacts = [...productionArtifacts, { tool: semgrep, target: candidateTarget }];
  const files = [];
  for (const artifact of productionArtifacts) {
    for (const entry of artifact.target.closure) {
      const material = await readSafeClosureFile(
        workspace,
        join(production.directory, artifact.tool.id, ...entry.path.split('/')),
        entry,
      );
      files.push({
        path: `${artifact.tool.id}/${entry.path}`,
        bytes: material.bytes,
        sha256: entry.sha256,
        executable: entry.executable,
      });
    }
  }
  for (const material of extractRuntimeClosure(archiveBytes, candidate.archive.format, candidateTarget)) {
    files.push({
      path: `semgrep/${material.entry.path}`,
      bytes: material.bytes,
      sha256: material.entry.sha256,
      executable: material.entry.executable,
    });
  }
  const manifestDigest = ciCandidateDigest(candidateDocumentBytes);
  const directory = join(workspace, 'target', 'sidecars', target, manifestDigest);
  const result = {
    directory,
    directories: Object.fromEntries(artifacts.map(({ tool }) => [tool.id, join(directory, tool.id)])),
    manifestDigest,
    target,
  };
  try {
    await lstat(directory);
    await verifyCache(workspace, directory, artifacts);
    return result;
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  await runGuardedInstaller({
    workspace,
    target,
    manifestDigest,
    nonce: randomUUID().replaceAll('-', ''),
    files,
    signal,
  });
  await verifyCache(workspace, directory, artifacts);
  return result;
}

export async function hydrateSidecars({
  workspace = resolve(import.meta.dirname, '..'),
  target = defaultTarget(),
  verifyOnly = false,
  fetchImpl = globalThis.fetch,
  signal,
} = {}) {
  workspace = resolve(asPath(workspace));
  if (!TARGETS.has(target)) throw new Error(`unsupported hydration target: ${target}`);
  const manifestPath = join(workspace, 'third_party/sidecars/manifest.v1.json');
  const manifestBytes = await readFile(manifestPath);
  const manifest = parseSidecarManifest(manifestBytes.toString('utf8'));
  await validateManifestMaterials(manifest, workspace);
  const artifacts = manifest.tools
    .map((tool) => ({ tool, target: tool.targets.find((entry) => entry.target === target) }))
    .filter(({ target: entry }) => entry?.enabled);
  if (artifacts.length === 0) throw new Error(`no enabled sidecars for target ${target}`);
  const manifestDigest = sha256(manifestBytes);
  const parent = join(workspace, 'target', 'sidecars', target);
  const directory = join(parent, manifestDigest);
  const result = {
    directory,
    directories: Object.fromEntries(
      artifacts.map(({ tool }) => [tool.id, join(directory, tool.id)]),
    ),
    manifestDigest,
    target,
  };
  if (verifyOnly) {
    await verifyCache(workspace, directory, artifacts);
    return result;
  }

  try {
    await lstat(directory);
    await verifyCache(workspace, directory, artifacts);
    return result;
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  const files = [];
  ensureNotAborted(signal);
  for (const artifact of artifacts) {
    const bytes = await fetchPinned(
      artifact.target.download.url,
      new Set(manifest.allowedReleaseHosts),
      fetchImpl,
      signal,
      artifact.target.download.size,
    );
    ensureNotAborted(signal);
    if (bytes.length !== artifact.target.download.size) throw new Error(`${artifact.tool.id} archive size mismatch`);
    if (sha256(bytes) !== artifact.target.download.sha256) throw new Error(`${artifact.tool.id} archive SHA-256 mismatch`);
    const closure = extractRuntimeClosure(bytes, artifact.target.download.format, artifact.target);
    for (const material of closure) {
      files.push({
        path: `${artifact.tool.id}/${material.entry.path}`,
        bytes: material.bytes,
        sha256: material.entry.sha256,
        executable: material.entry.executable,
      });
    }
  }
  await runGuardedInstaller({
    workspace,
    target,
    manifestDigest,
    nonce: randomUUID().replaceAll('-', ''),
    files,
    signal,
  });
  await verifyCache(workspace, directory, artifacts);
  return result;
}

function parseCli(args) {
  let target;
  let verifyOnly = false;
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === '--verify-only') verifyOnly = true;
    else if (argument === '--target' && args[index + 1]) target = args[++index];
    else throw new Error(`unknown argument: ${argument}`);
  }
  return { target, verifyOnly };
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(import.meta.filename)) {
  try {
    const options = parseCli(process.argv.slice(2));
    const result = await hydrateSidecars({ ...options, target: options.target ?? defaultTarget() });
    process.stdout.write(`${result.directory}\n`);
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
