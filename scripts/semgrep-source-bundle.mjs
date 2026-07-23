import { createHash } from 'node:crypto';
import { execFile, spawnSync } from 'node:child_process';
import http from 'node:http';
import https from 'node:https';
import {
  link,
  lstat,
  mkdir,
  open,
  readFile,
  rename,
  rm,
  symlink,
  unlink,
} from 'node:fs/promises';
import { dirname, basename, join, posix, resolve } from 'node:path';
import { isIP } from 'node:net';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

import { verifyResolvedSourceInventory } from './semgrep-source-inventory.mjs';

const execute = promisify(execFile);
const TAR_BLOCK = 512;
const MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024;
const MAX_ARCHIVE_CACHE_BYTES = 2 * 1024 * 1024 * 1024;
const MAX_BUNDLE_BYTES = 1280 * 1024 * 1024;
const BUNDLE_METADATA = Buffer.from('{"format":"context-relay-semgrep-source-v1","schemaVersion":1}\n');
const SOURCE_ASSET_URL = 'https://github.com/Skytuhua/Context-Relay/releases/download/sidecars-semgrep-1.170.0-source.1/semgrep-1.170.0-corresponding-source.tar';
const BUNDLE_EVIDENCE_STATUSES = new Set([
  'source_bundle_v1_native_builds_pending',
  'source_bundle_reproducible_native_builds_pending',
  'complete_corresponding_source',
]);
const LEGACY_HTTP_ARCHIVE = new Map([[
  'http://erratique.ch/software/hmap/releases/hmap-0.8.1.tbz',
  '6a00db1b12b6f55e1b2419f206fdfbaa669e14b51c78f8ac3cffa0a58897be83',
]]);
const DEFAULT_SUPPORT_PATHS = [
  'scripts/apply-semgrep-source-patches.mjs',
  'scripts/semgrep-source-bundle.mjs',
  'scripts/semgrep-source-inventory.mjs',
  'third_party/sidecars/licenses/semgrep-LGPL-2.1-or-later.txt',
  'third_party/sidecars/licenses/tree-sitter-MIT.txt',
  'third_party/sidecars/semgrep/MANIFEST.sha256.md',
  'third_party/sidecars/semgrep/RELINKING.md',
  'third_party/sidecars/semgrep/builder-evidence.windows-x86_64.v1.schema.json',
  'third_party/sidecars/semgrep/build-public-source-macos.sh',
  'third_party/sidecars/semgrep/build-public-source-windows.ps1',
  'third_party/sidecars/semgrep/patches.v1.json',
];

function fail(message) {
  throw new Error(`Semgrep source bundle: ${message}`);
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function hash(algorithm, bytes) {
  return createHash(algorithm).update(bytes).digest('hex');
}

export async function writeAll(handle, bytes) {
  let offset = 0;
  while (offset < bytes.length) {
    const { bytesWritten } = await handle.write(bytes, offset, bytes.length - offset, null);
    if (!Number.isInteger(bytesWritten) || bytesWritten <= 0 || bytesWritten > bytes.length - offset) {
      fail('file write made no valid progress');
    }
    offset += bytesWritten;
  }
}

function safePath(path, label = 'path') {
  if (typeof path !== 'string' || path.length === 0 || path.normalize('NFC') !== path
      || path.startsWith('/') || path.includes('\\') || /[\u0000-\u001f\u007f]/.test(path)
      || /^[A-Za-z]:/.test(path)) {
    fail(`${label} is unsafe`);
  }
  const segments = path.split('/');
  if (segments.some((segment) => segment === '' || segment === '.' || segment === '..')) {
    fail(`${label} is unsafe`);
  }
  return path;
}

export function verifyLicenseMaterials(materials, entries = null, expectedSources = null) {
  if (!Array.isArray(materials) || materials.length === 0 || materials.length > 64) {
    fail('license material inventory is empty or excessive');
  }
  const paths = new Set();
  const licensedSources = new Set();
  let previous = null;
  for (const material of materials) {
    if (!material || typeof material !== 'object' || Array.isArray(material)
        || Object.keys(material).sort().join(',') !== 'kind,path,sha256,source,spdx'
        || typeof material.source !== 'string' || !/^[a-z][a-z0-9-]*$/.test(material.source)
        || !['license', 'notice'].includes(material.kind)
        || typeof material.spdx !== 'string' || material.spdx.length === 0 || material.spdx.length > 256
        || material.spdx.normalize('NFC') !== material.spdx || /[\u0000-\u001f\u007f]/.test(material.spdx)
        || typeof material.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(material.sha256)
        || /^0+$/.test(material.sha256)) {
      fail('license material path/SPDX/SHA-256 record is invalid');
    }
    safePath(material.path, 'license material path');
    const key = `${material.source}\0${material.kind}\0${material.path}`;
    if (previous !== null && compareUtf8(previous, key) >= 0) {
      fail('license material inventory is not canonical');
    }
    if (paths.has(material.path)) fail('license material path is duplicated');
    paths.add(material.path);
    previous = key;
    if (material.kind === 'license') {
      if (licensedSources.has(material.source)) fail('license material source has more than one license');
      licensedSources.add(material.source);
    }
  }
  if (expectedSources !== null) {
    const expected = [...expectedSources].sort(compareUtf8);
    const actual = [...licensedSources].sort(compareUtf8);
    if (JSON.stringify(actual) !== JSON.stringify(expected)) fail('license material source coverage is incomplete');
  }
  if (entries !== null) {
    const bundled = new Map(entries.map((entry) => [entry.path, entry]));
    for (const material of materials) {
      const entry = bundled.get(material.path);
      if (!entry || hash('sha256', entry.bytes) !== material.sha256) {
        fail(`license material is missing from the bundle or has drifted: ${material.path}`);
      }
    }
  }
}

function safeLink(link) {
  if (!link || typeof link !== 'object' || Array.isArray(link)
      || Object.keys(link).sort().join(',') !== 'path,target') {
    fail('link record is invalid');
  }
  safePath(link.path, 'link path');
  if (typeof link.target !== 'string' || link.target.length === 0
      || link.target.normalize('NFC') !== link.target || link.target.startsWith('/')
      || link.target.includes('\\') || /[\u0000-\u001f\u007f]/.test(link.target)
      || /^[A-Za-z]:/.test(link.target)) {
    fail('link target is unsafe');
  }
  const resolved = posix.normalize(posix.join(posix.dirname(link.path), link.target));
  if (resolved === '..' || resolved.startsWith('../') || resolved.startsWith('/')) {
    fail('link target escapes the source bundle');
  }
  safePath(resolved, 'resolved link target');
  return { path: link.path, target: link.target };
}

function canonicalize(entries, links) {
  const files = [];
  const folded = new Set();
  for (const entry of entries) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)
        || Object.keys(entry).sort().join(',') !== 'bytes,executable,path'
        || typeof entry.executable !== 'boolean'
        || !(Buffer.isBuffer(entry.bytes) || entry.bytes instanceof Uint8Array)) {
      fail('file entry is invalid');
    }
    const path = safePath(entry.path);
    const key = path.normalize('NFC').toLowerCase();
    if (folded.has(key)) fail('bundle path duplicate or case collision');
    folded.add(key);
    files.push({ bytes: Buffer.from(entry.bytes), executable: entry.executable, path });
  }
  const canonicalLinks = links.map(safeLink);
  for (const item of canonicalLinks) {
    const key = item.path.normalize('NFC').toLowerCase();
    if (folded.has(key)) fail('bundle path duplicate or case collision');
    folded.add(key);
  }
  files.sort((left, right) => compareUtf8(left.path, right.path));
  canonicalLinks.sort((left, right) => compareUtf8(left.path, right.path));
  return { files, links: canonicalLinks };
}

function octal(value, width, label) {
  if (!Number.isSafeInteger(value) || value < 0) fail(`${label} is out of range`);
  const text = value.toString(8);
  if (text.length > width - 1) fail(`${label} is too large for USTAR`);
  return `${text.padStart(width - 1, '0')}\0`;
}

function trySplitTarPath(path) {
  const bytes = Buffer.byteLength(path);
  if (bytes <= 100) return { name: path, prefix: '' };
  for (let index = path.lastIndexOf('/'); index > 0; index = path.lastIndexOf('/', index - 1)) {
    const prefix = path.slice(0, index);
    const name = path.slice(index + 1);
    if (Buffer.byteLength(prefix) <= 155 && Buffer.byteLength(name) <= 100) return { name, prefix };
  }
  return null;
}

function splitTarPath(path) {
  const split = trySplitTarPath(path);
  if (split === null) fail(`path does not fit deterministic USTAR fields: ${path}`);
  return split;
}

function longStoredPath(path) {
  return `LONG_PATHS/${hash('sha256', Buffer.from(path, 'utf8'))}`;
}

function parseLongPaths(bytes) {
  let document;
  try {
    document = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    fail('long-path metadata is invalid');
  }
  if (!document || Object.keys(document).sort().join(',') !== 'paths,schemaVersion'
      || document.schemaVersion !== 1 || !Array.isArray(document.paths)) {
    fail('long-path metadata is invalid');
  }
  let previous = null;
  const folded = new Set();
  return document.paths.map((item) => {
    if (!item || Object.keys(item).sort().join(',') !== 'path,stored') fail('long-path record is invalid');
    const path = safePath(item.path, 'long path');
    const stored = safePath(item.stored, 'stored long path');
    if (trySplitTarPath(path) !== null || stored !== longStoredPath(path)
        || (previous !== null && compareUtf8(previous, path) >= 0)
        || folded.has(path.toLowerCase()) || folded.has(stored.toLowerCase())) {
      fail('long-path metadata is not canonical');
    }
    previous = path;
    folded.add(path.toLowerCase());
    folded.add(stored.toLowerCase());
    return { path, stored };
  });
}

function tarHeader(entry) {
  const header = Buffer.alloc(TAR_BLOCK);
  const { name, prefix } = splitTarPath(entry.path);
  header.write(name, 0, 100, 'utf8');
  header.write(octal(entry.executable ? 0o755 : 0o644, 8, 'mode'), 100, 8, 'ascii');
  header.write(octal(0, 8, 'uid'), 108, 8, 'ascii');
  header.write(octal(0, 8, 'gid'), 116, 8, 'ascii');
  header.write(octal(entry.bytes.length, 12, 'size'), 124, 12, 'ascii');
  header.write(octal(0, 12, 'mtime'), 136, 12, 'ascii');
  header.fill(0x20, 148, 156);
  header[156] = 0x30;
  header.write('ustar\0', 257, 6, 'ascii');
  header.write('00', 263, 2, 'ascii');
  if (prefix) header.write(prefix, 345, 155, 'utf8');
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  header.write(`${checksum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii');
  return header;
}

function metadataEntries(files, links) {
  const symlinks = Buffer.from(`${JSON.stringify({ links, schemaVersion: 1 })}\n`);
  const occupied = new Set(links.map((item) => item.path.toLowerCase()));
  const longPaths = [];
  const storedFiles = files.map((entry) => {
    if (entry.path === 'LONG_PATHS' || entry.path.startsWith('LONG_PATHS/')) {
      fail('source path uses the reserved long-path namespace');
    }
    const stored = trySplitTarPath(entry.path) === null ? longStoredPath(entry.path) : entry.path;
    const folded = stored.toLowerCase();
    if (occupied.has(folded)) fail('stored bundle path duplicate or case collision');
    occupied.add(folded);
    if (stored !== entry.path) longPaths.push({ path: entry.path, stored });
    return { ...entry, path: stored };
  });
  const metadata = [
    { bytes: BUNDLE_METADATA, executable: false, path: 'BUNDLE.v1.json' },
    { bytes: symlinks, executable: false, path: 'SYMLINKS.v1.json' },
  ];
  if (longPaths.length !== 0) {
    metadata.push({
      bytes: Buffer.from(`${JSON.stringify({ paths: longPaths, schemaVersion: 1 })}\n`),
      executable: false,
      path: 'LONG_PATHS.v1.json',
    });
  }
  for (const entry of metadata) {
    const folded = entry.path.toLowerCase();
    if (occupied.has(folded)) fail('bundle metadata path collision');
    occupied.add(folded);
  }
  const payload = [
    ...storedFiles,
    ...metadata,
  ].sort((left, right) => compareUtf8(left.path, right.path));
  const manifest = Buffer.from(payload.map((entry) => `${hash('sha256', entry.bytes)}  ${entry.path}\n`).join(''));
  const modes = Buffer.from(payload.map((entry) => `${entry.path}\t${entry.executable ? 1 : 0}\n`).join(''));
  return [
    ...payload,
    { bytes: manifest, executable: false, path: 'MANIFEST.sha256' },
    { bytes: modes, executable: false, path: 'MODES.v1' },
  ].sort((left, right) => compareUtf8(left.path, right.path));
}

export async function buildDeterministicTar({ entries, links = [], maxBytes = MAX_BUNDLE_BYTES, outputPath }) {
  if (!Array.isArray(entries) || !Array.isArray(links) || typeof outputPath !== 'string') {
    fail('bundle arguments are invalid');
  }
  if (!Number.isSafeInteger(maxBytes) || maxBytes < TAR_BLOCK * 2 || maxBytes > MAX_BUNDLE_BYTES) {
    fail('bundle aggregate size limit is invalid');
  }
  const canonical = canonicalize(entries, links);
  const allEntries = metadataEntries(canonical.files, canonical.links);
  const aggregateSize = allEntries.reduce(
    (total, entry) => total + TAR_BLOCK + Math.ceil(entry.bytes.length / TAR_BLOCK) * TAR_BLOCK,
    TAR_BLOCK * 2,
  );
  if (aggregateSize > maxBytes) {
    fail(`bundle aggregate size ${aggregateSize} exceeds the limit ${maxBytes}`);
  }
  await mkdir(dirname(resolve(outputPath)), { recursive: true });
  const temporary = join(dirname(resolve(outputPath)), `.${basename(outputPath)}.${process.pid}.${Date.now()}.tmp`);
  let handle;
  try {
    handle = await open(temporary, 'wx', 0o600);
    for (const entry of allEntries) {
      await writeAll(handle, tarHeader(entry));
      await writeAll(handle, entry.bytes);
      const padding = (TAR_BLOCK - (entry.bytes.length % TAR_BLOCK)) % TAR_BLOCK;
      if (padding) await writeAll(handle, Buffer.alloc(padding));
    }
    await writeAll(handle, Buffer.alloc(TAR_BLOCK * 2));
    await handle.sync();
    await handle.close();
    handle = null;
    await link(temporary, resolve(outputPath));
    await unlink(temporary);
  } catch (error) {
    if (handle) await handle.close().catch(() => {});
    await rm(temporary, { force: true }).catch(() => {});
    throw error;
  }
  return verifyDeterministicTar(outputPath);
}

function tarText(header, start, length) {
  const end = header.indexOf(0, start);
  return header.subarray(start, end === -1 || end > start + length ? start + length : end).toString('utf8');
}

function tarOctal(header, start, length, label) {
  const text = header.subarray(start, start + length).toString('ascii').replace(/[\0 ]+$/g, '');
  if (!/^[0-7]+$/.test(text)) fail(`tar ${label} is invalid`);
  const value = Number.parseInt(text, 8);
  if (!Number.isSafeInteger(value)) fail(`tar ${label} is invalid`);
  return value;
}

function parseLineMap(bytes, expression, label, pathIndex, valueIndexes) {
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  if (!text.endsWith('\n')) fail(`${label} lacks final LF`);
  const map = new Map();
  let previous = null;
  for (const line of text.slice(0, -1).split('\n')) {
    const match = expression.exec(line);
    if (!match) fail(`${label} contains an invalid line`);
    const path = safePath(match[pathIndex], `${label} path`);
    if (previous !== null && compareUtf8(previous, path) >= 0) fail(`${label} is not canonical`);
    previous = path;
    map.set(path, valueIndexes.map((index) => match[index]));
  }
  return map;
}

async function readTarBytes(handle, position, length, bundleHasher) {
  const bytes = Buffer.alloc(length);
  let offset = 0;
  while (offset < length) {
    const { bytesRead } = await handle.read(bytes, offset, length - offset, position + offset);
    if (!Number.isInteger(bytesRead) || bytesRead <= 0 || bytesRead > length - offset) {
      fail('tar member is truncated');
    }
    offset += bytesRead;
  }
  bundleHasher.update(bytes);
  return bytes;
}

async function readTarMember(handle, position, size, bundleHasher, memberPath) {
  const sha256 = createHash('sha256');
  const archive = parseBundledArchivePath(memberPath);
  const addressed = archive?.algorithm === 'sha512' ? createHash('sha512') : null;
  const keep = ['BUNDLE.v1.json', 'LONG_PATHS.v1.json', 'MANIFEST.sha256', 'MODES.v1', 'SYMLINKS.v1.json'].includes(memberPath);
  if (keep && size > 64 * 1024 * 1024) fail('bundle metadata member exceeds the size limit');
  const chunks = keep ? [] : null;
  let read = 0;
  while (read < size) {
    const chunk = await readTarBytes(handle, position + read, Math.min(1024 * 1024, size - read), bundleHasher);
    sha256.update(chunk);
    addressed?.update(chunk);
    chunks?.push(chunk);
    read += chunk.length;
  }
  const digest = sha256.digest('hex');
  if (archive && (archive.algorithm === 'sha256' ? digest : addressed.digest('hex')) !== archive.digest) {
    fail('bundle archive address mismatch');
  }
  return { bytes: chunks === null ? null : Buffer.concat(chunks), digest };
}

export async function verifyDeterministicTar(path, maxBytes = MAX_BUNDLE_BYTES) {
  if (typeof path !== 'string' || !Number.isSafeInteger(maxBytes)
      || maxBytes < TAR_BLOCK * 2 || maxBytes > MAX_BUNDLE_BYTES) {
    fail('bundle verification size limit is invalid');
  }
  const absolute = resolve(path);
  const input = await lstat(absolute);
  if (!input.isFile() || input.isSymbolicLink() || input.size < TAR_BLOCK * 2 || input.size > maxBytes) {
    fail('bundle is not a bounded no-link regular file or exceeds the size limit');
  }
  const handle = await open(absolute, 'r');
  const entries = new Map();
  const bundleHasher = createHash('sha256');
  let position = 0;
  let previous = null;
  let ended = false;
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || opened.size !== input.size || opened.dev !== input.dev || opened.ino !== input.ino) {
      fail('bundle changed while being opened');
    }
    while (position + TAR_BLOCK <= input.size) {
      const header = await readTarBytes(handle, position, TAR_BLOCK, bundleHasher);
      position += TAR_BLOCK;
      if (header.every((byte) => byte === 0)) {
        const end = await readTarBytes(handle, position, TAR_BLOCK, bundleHasher);
        position += TAR_BLOCK;
        if (end.some((byte) => byte !== 0) || position !== input.size) {
          fail('tar end markers or trailing bytes are invalid');
        }
        ended = true;
        break;
      }
      const expectedChecksum = tarOctal(header, 148, 8, 'checksum');
      const check = Buffer.from(header);
      check.fill(0x20, 148, 156);
      if (check.reduce((sum, byte) => sum + byte, 0) !== expectedChecksum) fail('tar header checksum mismatch');
      if (tarText(header, 257, 6) !== 'ustar' || tarText(header, 263, 2) !== '00'
          || tarOctal(header, 108, 8, 'uid') !== 0 || tarOctal(header, 116, 8, 'gid') !== 0
          || tarOctal(header, 136, 12, 'mtime') !== 0 || header[156] !== 0x30
          || header.subarray(157, 257).some((byte) => byte !== 0)
          || header.subarray(265, 345).some((byte) => byte !== 0)
          || header.subarray(500, 512).some((byte) => byte !== 0)) {
        fail('tar member metadata is not deterministic regular-file metadata');
      }
      const name = tarText(header, 0, 100);
      const prefix = tarText(header, 345, 155);
      const memberPath = safePath(prefix ? `${prefix}/${name}` : name, 'tar member path');
      if (previous !== null && compareUtf8(previous, memberPath) >= 0) fail('tar members are not canonical');
      previous = memberPath;
      const mode = tarOctal(header, 100, 8, 'mode');
      if (mode !== 0o644 && mode !== 0o755) fail('tar mode is not normalized');
      const size = tarOctal(header, 124, 12, 'size');
      if (position + size > input.size) fail('tar member is truncated');
      const member = await readTarMember(handle, position, size, bundleHasher, memberPath);
      position += size;
      const paddingLength = (TAR_BLOCK - (size % TAR_BLOCK)) % TAR_BLOCK;
      if (paddingLength) {
        const padding = await readTarBytes(handle, position, paddingLength, bundleHasher);
        if (padding.some((byte) => byte !== 0)) fail('tar member padding is not zero');
        position += paddingLength;
      }
      entries.set(memberPath, { ...member, executable: mode === 0o755 });
    }
    if (!ended || position !== input.size) fail('tar end markers or trailing bytes are invalid');
  } finally {
    await handle.close();
  }
  const manifestEntry = entries.get('MANIFEST.sha256');
  const modesEntry = entries.get('MODES.v1');
  const linksEntry = entries.get('SYMLINKS.v1.json');
  const bundleEntry = entries.get('BUNDLE.v1.json');
  if (!manifestEntry || !modesEntry || !linksEntry || !bundleEntry) fail('bundle metadata is incomplete');
  if (!bundleEntry.bytes.equals(BUNDLE_METADATA)) fail('bundle metadata is invalid');
  const longEntry = entries.get('LONG_PATHS.v1.json');
  const longPaths = longEntry ? parseLongPaths(longEntry.bytes) : [];
  const storedLongPaths = [...entries.keys()].filter((name) => name.startsWith('LONG_PATHS/'));
  if (storedLongPaths.length !== longPaths.length
      || longPaths.some((item) => !entries.has(item.stored))) {
    fail('bundle long-path membership mismatch');
  }
  const manifest = parseLineMap(manifestEntry.bytes, /^([0-9a-f]{64})  (.+)$/, 'manifest', 2, [1]);
  const modes = parseLineMap(modesEntry.bytes, /^(.+)\t([01])$/, 'mode manifest', 1, [2]);
  const payload = [...entries.entries()].filter(([name]) => name !== 'MANIFEST.sha256' && name !== 'MODES.v1');
  if (manifest.size !== payload.length || modes.size !== payload.length) fail('bundle manifest membership mismatch');
  for (const [name, entry] of payload) {
    if (manifest.get(name)?.[0] !== entry.digest
        || modes.get(name)?.[0] !== (entry.executable ? '1' : '0')) {
      fail('bundle manifest checksum or mode mismatch');
    }
  }
  let symlinks;
  try {
    symlinks = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(linksEntry.bytes));
  } catch {
    fail('symlink metadata is invalid');
  }
  if (!symlinks || Object.keys(symlinks).sort().join(',') !== 'links,schemaVersion'
      || symlinks.schemaVersion !== 1 || !Array.isArray(symlinks.links)) fail('symlink metadata is invalid');
  const canonicalLinks = symlinks.links.map(safeLink).sort((left, right) => compareUtf8(left.path, right.path));
  if (JSON.stringify(canonicalLinks) !== JSON.stringify(symlinks.links)) fail('symlink metadata is not canonical');
  return {
    digests: Object.fromEntries(payload.map(([name, entry]) => [name, entry.digest])),
    links: canonicalLinks.length,
    paths: payload.map(([name]) => name),
    payloadEntries: payload.length,
    sha256: bundleHasher.digest('hex'),
    size: input.size,
  };
}

export function flattenArchiveSources(lock) {
  verifyResolvedSourceInventory(lock?.opam?.resolvedSourceArchives);
  const archives = [];
  const sourceGroups = lock.opam.resolvedSourceArchives
    .map((record) => [record.source, ...record.extraSources].filter(Boolean));
  const additional = lock.additionalArchives ?? [];
  if (!Array.isArray(additional)) fail('additional archive inventory is invalid');
  let previousAdditional = null;
  for (const item of additional) {
    if (!item || Object.keys(item).sort().join(',') !== 'id,licenseSource,purpose,source'
        || typeof item.id !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(item.id)
        || typeof item.licenseSource !== 'string' || !/^[a-z][a-z0-9-]*$/.test(item.licenseSource)
        || typeof item.purpose !== 'string' || item.purpose.length === 0 || item.purpose.normalize('NFC') !== item.purpose
        || (previousAdditional !== null && compareUtf8(previousAdditional, item.id) >= 0)) {
      fail('additional archive inventory is invalid or not canonical');
    }
    verifyResolvedSourceInventory([{
      extraSources: [],
      licenses: ['MIT'],
      opamPath: `packages/${item.id}/${item.id}.1/opam`,
      opamSha256: '1'.repeat(64),
      package: item.id,
      source: item.source,
      targets: ['aarch64-apple-darwin', 'windows-x86_64'],
      version: '1',
    }]);
    previousAdditional = item.id;
    sourceGroups.push([item.source]);
  }
  for (const sources of sourceGroups) {
    for (const source of sources) {
      const tokens = new Set([...source.checksums, ...source.supplementalChecksums]
        .filter((checksum) => checksum.algorithm === 'sha256' || checksum.algorithm === 'sha512')
        .map((checksum) => `${checksum.algorithm}:${checksum.digest}`));
      const matches = archives.filter((archive) => [...tokens].some((token) => archive.tokens.has(token)));
      const current = matches.shift() ?? { sources: [], tokens: new Set() };
      for (const duplicate of matches) {
        current.sources.push(...duplicate.sources);
        for (const token of duplicate.tokens) current.tokens.add(token);
        archives.splice(archives.indexOf(duplicate), 1);
      }
      current.sources.push(source);
      for (const token of tokens) current.tokens.add(token);
      if (!archives.includes(current)) archives.push(current);
    }
  }
  const resolved = archives.map((archive) => {
    const sha256 = [...archive.tokens].filter((token) => token.startsWith('sha256:'));
    const sha512 = [...archive.tokens].filter((token) => token.startsWith('sha512:'));
    if (sha256.length > 1 || sha512.length > 1) fail('deduplicated archive has conflicting strong checksums');
    const token = sha256[0] ?? sha512[0] ?? fail('archive has no strong checksum');
    const [algorithm, digest] = token.split(':');
    return { algorithm, digest, sha256: sha256[0]?.slice(7) ?? null, sources: archive.sources };
  });
  return resolved.sort((left, right) => compareUtf8(left.algorithm, right.algorithm) || compareUtf8(left.digest, right.digest));
}

function bundledArchivePath({ algorithm, digest }) {
  const base = `opam-repository/cache/${algorithm}/${digest.slice(0, 2)}`;
  return algorithm === 'sha512'
    ? `${base}/${digest.slice(0, 64)}/${digest.slice(64)}`
    : `${base}/${digest}`;
}

function officialArchivePath({ algorithm, digest }) {
  return `opam-repository/cache/${algorithm}/${digest.slice(0, 2)}/${digest}`;
}

export function archiveCacheLinks(lock) {
  const aliases = new Map();
  for (const archive of flattenArchiveSources(lock)) {
    const stored = bundledArchivePath(archive);
    for (const [algorithm, digest] of requiredArchiveChecksums(archive)) {
      if (algorithm === archive.algorithm && digest === archive.digest) continue;
      const path = officialArchivePath({ algorithm, digest });
      const target = posix.relative(posix.dirname(path), stored);
      const previous = aliases.get(path);
      if (previous !== undefined && previous !== target) fail('archive checksum alias is ambiguous');
      aliases.set(path, target);
    }
  }
  return [...aliases]
    .map(([path, target]) => safeLink({ path, target }))
    .sort((left, right) => compareUtf8(left.path, right.path));
}

function parseBundledArchivePath(path) {
  if (!path.startsWith('opam-repository/cache/')) return null;
  const sha256 = /^opam-repository\/cache\/sha256\/([0-9a-f]{2})\/([0-9a-f]{64})$/.exec(path);
  const sha512 = /^opam-repository\/cache\/sha512\/([0-9a-f]{2})\/([0-9a-f]{64})\/([0-9a-f]{64})$/.exec(path);
  const algorithm = sha256 ? 'sha256' : sha512 ? 'sha512' : null;
  const prefix = (sha256 ?? sha512)?.[1];
  const digest = sha256?.[2] ?? (sha512 ? sha512[2] + sha512[3] : null);
  if (algorithm === null || digest.slice(0, 2) !== prefix) fail('bundle archive path is not canonical');
  return { algorithm, digest };
}

async function readNoLink(root, relative, maxBytes) {
  const absoluteRoot = resolve(root);
  let current = absoluteRoot;
  const rootInfo = await lstat(current);
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) fail('cache root is not a no-link directory');
  for (const segment of relative.split('/')) {
    current = join(current, segment);
    const info = await lstat(current);
    if (info.isSymbolicLink()) fail('cache contains a link component');
    if (current === join(absoluteRoot, ...relative.split('/'))) {
      if (!info.isFile() || info.size === 0 || info.size > maxBytes) fail('cache archive is not a bounded regular file');
    } else if (!info.isDirectory()) fail('cache parent is not a directory');
  }
  return readFile(current);
}

export async function verifyArchiveCache(lock, cacheRoot) {
  const entries = [];
  for (const archive of flattenArchiveSources(lock)) {
    const relative = `${archive.algorithm}/${archive.digest}`;
    let bytes;
    try {
      bytes = await readNoLink(cacheRoot, relative, MAX_ARCHIVE_BYTES);
    } catch (error) {
      fail(`${relative}: ${error.message}`);
    }
    const required = new Map();
    for (const source of archive.sources) {
      for (const checksum of [...source.checksums, ...source.supplementalChecksums]) {
        const previous = required.get(checksum.algorithm);
        if (previous && previous !== checksum.digest) fail('deduplicated archive has conflicting checksums');
        required.set(checksum.algorithm, checksum.digest);
      }
    }
    for (const [algorithm, expected] of required) {
      if (hash(algorithm, bytes) !== expected) fail(`${relative} ${algorithm} checksum mismatch`);
    }
    entries.push({
      bytes,
      executable: false,
      path: bundledArchivePath(archive),
    });
  }
  return entries;
}

function requiredArchiveChecksums(archive) {
  const required = new Map();
  for (const source of archive.sources) {
    for (const checksum of [...source.checksums, ...source.supplementalChecksums]) {
      const previous = required.get(checksum.algorithm);
      if (previous && previous !== checksum.digest) fail('deduplicated archive has conflicting checksums');
      required.set(checksum.algorithm, checksum.digest);
    }
  }
  return required;
}

function safeFetchUrl(value, sha256, previous = null) {
  let url;
  try {
    url = new URL(value, previous ?? undefined);
  } catch {
    fail('archive URL or redirect is invalid');
  }
  if (url.username || url.password || url.hash || /[\u0000-\u0020\u007f]/.test(url.href)
      || isIP(url.hostname) !== 0 || url.hostname === 'localhost' || url.hostname.endsWith('.local')) {
    fail('archive URL or redirect is unsafe');
  }
  if (url.protocol === 'http:') {
    if (LEGACY_HTTP_ARCHIVE.get(url.href) !== sha256
        || (previous !== null && new URL(previous).hostname !== url.hostname)) {
      fail('plain HTTP archive URL or redirect is not allowlisted');
    }
  } else if (url.protocol !== 'https:') {
    fail('archive URL or redirect protocol is unsafe');
  }
  if (previous !== null && new URL(previous).protocol === 'https:' && url.protocol !== 'https:') {
    fail('archive redirect cannot downgrade HTTPS');
  }
  return url.href;
}

async function fetchWithRedirects(start, sha256, fetchImpl, requestTimeoutMs) {
  let current = safeFetchUrl(start, sha256);
  const signal = AbortSignal.timeout(requestTimeoutMs);
  for (let redirects = 0; redirects <= 5; redirects += 1) {
    const response = await fetchImpl(current, {
      headers: { 'accept-encoding': 'identity', 'user-agent': 'Context-Relay-Semgrep-Source/1' },
      redirect: 'manual',
      signal,
    });
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get('location');
      if (location === null || redirects === 5) fail('archive redirect chain is invalid or too long');
      current = safeFetchUrl(new URL(location, current).href, sha256, current);
      continue;
    }
    if (response.status !== 200 || response.body === null) fail(`archive server returned HTTP ${response.status}`);
    const encoding = response.headers.get('content-encoding');
    if (encoding !== null && encoding !== 'identity') fail('archive response content encoding is unsafe');
    const length = response.headers.get('content-length');
    if (length !== null && (!/^[0-9]+$/.test(length) || Number(length) <= 0 || Number(length) > MAX_ARCHIVE_BYTES)) {
      fail('archive response length is invalid');
    }
    return response;
  }
  fail('archive redirect chain is too long');
}

function nodeRequest(url, { headers, signal }) {
  return new Promise((resolveRequest, rejectRequest) => {
    const parsed = new URL(url);
    const request = (parsed.protocol === 'https:' ? https : http).get(parsed, { headers, signal }, (response) => {
      resolveRequest({
        body: response,
        headers: {
          get(name) {
            const value = response.headers[name.toLowerCase()];
            return Array.isArray(value) ? value.join(', ') : value ?? null;
          },
        },
        status: response.statusCode ?? 0,
      });
    });
    request.on('error', rejectRequest);
  });
}

async function verifyCachedArchive(cacheRoot, archive) {
  const relative = `${archive.algorithm}/${archive.digest}`;
  const bytes = await readNoLink(cacheRoot, relative, MAX_ARCHIVE_BYTES);
  for (const [algorithm, expected] of requiredArchiveChecksums(archive)) {
    if (hash(algorithm, bytes) !== expected) fail(`${relative} ${algorithm} checksum mismatch`);
  }
  return bytes;
}

async function fetchOneArchive(cacheRoot, archive, fetchImpl, budget, requestTimeoutMs) {
  try {
    const bytes = await verifyCachedArchive(cacheRoot, archive);
    budget.add(bytes.length);
    return;
  } catch (error) {
    if (!String(error.message).match(/ENOENT|no such file/i)) throw error;
  }
  const directory = join(resolve(cacheRoot), archive.algorithm);
  await mkdir(directory, { recursive: true });
  const destination = join(directory, archive.digest);
  const temporary = join(directory, `.${archive.digest}.${process.pid}.${Date.now()}.tmp`);
  const candidates = [...new Set(archive.sources.flatMap((source) => [source.url, ...source.mirrors]))];
  let lastError;
  for (const candidate of candidates) {
    let handle;
    let downloaded = 0;
    try {
      const response = await fetchWithRedirects(candidate, archive.sha256, fetchImpl, requestTimeoutMs);
      handle = await open(temporary, 'wx', 0o600);
      const digests = new Map([...requiredArchiveChecksums(archive)].map(([algorithm]) => [algorithm, createHash(algorithm)]));
      let size = 0;
      for await (const chunk of response.body) {
        const bytes = Buffer.from(chunk);
        size += bytes.length;
        if (size > MAX_ARCHIVE_BYTES) fail('archive response exceeds the size limit');
        budget.add(bytes.length);
        downloaded += bytes.length;
        for (const digest of digests.values()) digest.update(bytes);
        await writeAll(handle, bytes);
      }
      if (size === 0) fail('archive response is empty');
      for (const [algorithm, expected] of requiredArchiveChecksums(archive)) {
        if (digests.get(algorithm).digest('hex') !== expected) fail(`${algorithm} checksum mismatch`);
      }
      await handle.sync();
      await handle.close();
      handle = null;
      try {
        await link(temporary, destination);
      } catch (error) {
        if (error.code !== 'EEXIST') throw error;
        await verifyCachedArchive(cacheRoot, archive);
      }
      await unlink(temporary);
      return;
    } catch (error) {
      lastError = error;
      budget.add(-downloaded);
      if (handle) await handle.close().catch(() => {});
      await rm(temporary, { force: true }).catch(() => {});
    }
  }
  fail(`all archive URLs failed for ${archive.algorithm}:${archive.digest}: ${lastError?.message ?? 'no candidate URL'}`);
}

export async function fetchArchiveCache(lock, cacheRoot, {
  fetchImpl = nodeRequest,
  maxAggregateBytes = MAX_ARCHIVE_CACHE_BYTES,
  parallel = 4,
  requestTimeoutMs = 120_000,
} = {}) {
  if (typeof fetchImpl !== 'function' || !Number.isInteger(parallel) || parallel < 1 || parallel > 8
      || !Number.isSafeInteger(maxAggregateBytes) || maxAggregateBytes < 1 || maxAggregateBytes > MAX_ARCHIVE_CACHE_BYTES
      || !Number.isSafeInteger(requestTimeoutMs) || requestTimeoutMs < 1000 || requestTimeoutMs > 300_000) {
    fail('archive fetch options are invalid');
  }
  const archives = flattenArchiveSources(lock);
  const budget = {
    size: 0,
    add(bytes) {
      if (!Number.isSafeInteger(bytes) || this.size + bytes < 0 || this.size + bytes > maxAggregateBytes) {
        fail('archive cache aggregate size exceeds the limit');
      }
      this.size += bytes;
    },
  };
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(parallel, archives.length) }, async () => {
    while (next < archives.length) {
      const archive = archives[next];
      next += 1;
      await fetchOneArchive(cacheRoot, archive, fetchImpl, budget, requestTimeoutMs);
    }
  }));
  return { archives: archives.length, bytes: budget.size };
}

async function git(root, args, options = {}) {
  try {
    return await execute('git', ['-C', root, ...args], { encoding: options.encoding ?? 'buffer', maxBuffer: 64 * 1024 * 1024 });
  } catch (error) {
    fail(`git ${args.join(' ')} failed: ${error.stderr?.toString().trim() || error.message}`);
  }
}

function parseGitTree(bytes) {
  const entries = [];
  for (const record of bytes.toString('utf8').split('\0')) {
    if (!record) continue;
    const match = /^(100644|100755|120000|160000) (blob|commit) ([0-9a-f]{40})\t(.+)$/.exec(record);
    if (!match) fail('git tree contains an unsupported entry');
    safePath(match[4], 'git path');
    entries.push({ mode: match[1], type: match[2], oid: match[3], path: match[4] });
  }
  entries.sort((left, right) => compareUtf8(left.path, right.path));
  return entries;
}

function readGitBlobs(root, objectIds) {
  const ids = [...new Set(objectIds)];
  const result = spawnSync('git', ['-C', root, 'cat-file', '--batch'], {
    input: `${ids.join('\n')}\n`,
    maxBuffer: 1024 * 1024 * 1024,
    windowsHide: true,
  });
  if (result.status !== 0) fail(`git cat-file --batch failed: ${result.stderr?.toString().trim()}`);
  const blobs = new Map();
  let offset = 0;
  for (const expected of ids) {
    const lineEnd = result.stdout.indexOf(0x0a, offset);
    if (lineEnd === -1) fail('git batch output is truncated');
    const match = /^([0-9a-f]{40}) blob ([0-9]+)$/.exec(result.stdout.subarray(offset, lineEnd).toString('ascii'));
    if (!match || match[1] !== expected) fail('git batch output identity mismatch');
    const size = Number(match[2]);
    const start = lineEnd + 1;
    const end = start + size;
    if (!Number.isSafeInteger(size) || end >= result.stdout.length || result.stdout[end] !== 0x0a) {
      fail('git batch blob is truncated');
    }
    blobs.set(expected, Buffer.from(result.stdout.subarray(start, end)));
    offset = end + 1;
  }
  if (offset !== result.stdout.length) fail('git batch output has trailing bytes');
  return blobs;
}

export async function collectGitRepository({ expectedRevision, expectedTree = null, includePaths = null, prefix, root }) {
  if (!/^[0-9a-f]{40}$/.test(expectedRevision) || (expectedTree !== null && !/^[0-9a-f]{40}$/.test(expectedTree))) {
    fail('expected git identity is invalid');
  }
  safePath(prefix, 'git prefix');
  const rootInfo = await lstat(resolve(root));
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) fail('git root is not a no-link directory');
  if (includePaths !== null && (!Array.isArray(includePaths) || includePaths.length === 0)) {
    fail('git include path inventory is invalid');
  }
  const includes = includePaths?.map((path) => safePath(path, 'git include path')) ?? null;
  const revision = (await git(root, ['rev-parse', 'HEAD'], { encoding: 'utf8' })).stdout.trim();
  const tree = (await git(root, ['rev-parse', 'HEAD^{tree}'], { encoding: 'utf8' })).stdout.trim();
  if (revision !== expectedRevision || (expectedTree !== null && tree !== expectedTree)) fail('git revision or tree mismatch');
  const listed = parseGitTree((await git(root, ['ls-tree', '-rz', '--full-tree', 'HEAD'])).stdout)
    .filter((item) => includes === null || includes.some((path) => item.path === path || item.path.startsWith(`${path}/`)));
  const blobs = readGitBlobs(root, listed.filter((item) => item.type === 'blob').map((item) => item.oid));
  const entries = [];
  const links = [];
  const gitlinks = [];
  for (const item of listed) {
    const bundlePath = `${prefix}/${item.path}`;
    if (item.mode === '160000') {
      gitlinks.push({ path: item.path, revision: item.oid });
      continue;
    }
    if (item.mode === '120000') {
      const bytes = blobs.get(item.oid);
      let target;
      try {
        target = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      } catch {
        fail(`git link target is not UTF-8: ${item.path}`);
      }
      links.push(safeLink({ path: bundlePath, target }));
      continue;
    }
    const bytes = blobs.get(item.oid);
    entries.push({ bytes, executable: item.mode === '100755', path: bundlePath });
  }
  return { entries, gitlinks, links, revision, tree };
}

function gitIdentity(value, label) {
  if (typeof value !== 'string' || !/^[0-9a-f]{40}$/.test(value) || /^0+$/.test(value)) {
    fail(`${label} is invalid`);
  }
  return value;
}

function validateBundleLock(lock) {
  if (!lock || typeof lock !== 'object' || Array.isArray(lock) || lock.schemaVersion !== 1
      || lock.recursiveInventoryComplete !== true) fail('source lock is invalid or recursively incomplete');
  gitIdentity(lock.sourceRevision, 'Semgrep revision');
  gitIdentity(lock.sourceTree, 'Semgrep tree');
  if (!Array.isArray(lock.rootGitlinks)) fail('root gitlink inventory is invalid');
  let previous = null;
  for (const link of lock.rootGitlinks) {
    if (!link || Object.keys(link).sort().join(',') !== 'path,revision') fail('root gitlink record is invalid');
    safePath(link.path, 'root gitlink path');
    gitIdentity(link.revision, 'root gitlink revision');
    if (previous !== null && compareUtf8(previous, link.path) >= 0) fail('root gitlink inventory is not canonical');
    previous = link.path;
  }
  if (!lock.opam || typeof lock.opam !== 'object' || !lock.opam.repository) fail('opam source lock is invalid');
  gitIdentity(lock.opam.repository.revision, 'opam repository revision');
  verifyResolvedSourceInventory(lock.opam.resolvedSourceArchives);
  const expectedLicenseSources = new Set(['semgrep']);
  const additional = lock.additionalArchives ?? [];
  if (!Array.isArray(additional)) fail('additional archive inventory is invalid');
  for (const archive of additional) {
    if (!archive || typeof archive.licenseSource !== 'string'
        || !/^[a-z][a-z0-9-]*$/.test(archive.licenseSource)
        || expectedLicenseSources.has(archive.licenseSource)) {
      fail('additional archive license source is invalid or duplicated');
    }
    expectedLicenseSources.add(archive.licenseSource);
  }
  const pins = [lock.opam.compiler, ...(lock.opam.pinDepends ?? [])];
  for (const pin of pins) {
    if (!pin || typeof pin.url !== 'string' || typeof pin.licenseSource !== 'string'
        || !/^[a-z][a-z0-9-]*$/.test(pin.licenseSource)
        || expectedLicenseSources.has(pin.licenseSource)) fail('pin source record is invalid');
    gitIdentity(pin.revision, 'pin revision');
    const url = new URL(pin.url);
    if (url.protocol !== 'https:' || url.username || url.password || url.hash) fail('pin source URL is unsafe');
    expectedLicenseSources.add(pin.licenseSource);
  }
  verifyLicenseMaterials(lock.licenseMaterials, null, expectedLicenseSources);
  const licenses = new Map(lock.licenseMaterials
    .filter((material) => material.kind === 'license')
    .map((material) => [material.source, material]));
  if (!licenses.get('semgrep')?.path.startsWith('sources/semgrep/')) {
    fail('Semgrep license material path is outside its source');
  }
  for (const pin of pins) {
    if (!licenses.get(pin.licenseSource)?.path.startsWith(`pins/${pin.revision}/`)) {
      fail(`pin license material path is outside its source: ${pin.licenseSource}`);
    }
  }
  for (const archive of additional) {
    if (!licenses.get(archive.licenseSource)?.path.startsWith('support/')) {
      fail(`additional archive license material is not explicit support: ${archive.licenseSource}`);
    }
  }
  return lock;
}

async function readJsonFile(path, label) {
  const info = await lstat(resolve(path));
  if (!info.isFile() || info.isSymbolicLink() || info.size === 0 || info.size > 16 * 1024 * 1024) {
    fail(`${label} is not a bounded no-link regular file`);
  }
  const bytes = await readFile(path);
  let value;
  try {
    value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    fail(`${label} is not canonical UTF-8 JSON`);
  }
  return { bytes, value };
}

async function collectRecursiveGit({ expectedRevision, expectedTree = null, prefix, root }, state) {
  if (state.depth >= 64) fail('recursive git depth exceeds the limit');
  const absolute = resolve(root);
  if (state.roots.has(absolute.toLowerCase())) fail('recursive git repository cycle detected');
  state.roots.add(absolute.toLowerCase());
  state.depth += 1;
  const repository = await collectGitRepository({ expectedRevision, expectedTree, prefix, root });
  state.entries.push(...repository.entries);
  state.links.push(...repository.links);
  state.repositories.push({ gitlinks: repository.gitlinks, prefix, revision: repository.revision, tree: repository.tree });
  for (const gitlink of repository.gitlinks) {
    await collectRecursiveGit({
      expectedRevision: gitlink.revision,
      prefix: `${prefix}/${gitlink.path}`,
      root: join(root, ...gitlink.path.split('/')),
    }, state);
  }
  state.depth -= 1;
  state.roots.delete(absolute.toLowerCase());
  return repository;
}

export async function buildSemgrepSourceBundle({
  archiveCacheRoot,
  opamRoot,
  outputPath,
  pinRoot,
  semgrepRoot,
  sourceLockPath,
  supportPaths = [],
  supportRoot = process.cwd(),
}) {
  if (![archiveCacheRoot, opamRoot, outputPath, pinRoot, semgrepRoot, sourceLockPath, supportRoot]
    .every((value) => typeof value === 'string') || !Array.isArray(supportPaths)) fail('bundle assembly arguments are invalid');
  const loaded = await readJsonFile(sourceLockPath, 'source lock');
  const lock = validateBundleLock(loaded.value);
  const state = { depth: 0, entries: [], links: [], repositories: [], roots: new Set() };
  const semgrep = await collectRecursiveGit({
    expectedRevision: lock.sourceRevision,
    expectedTree: lock.sourceTree,
    prefix: 'sources/semgrep',
    root: semgrepRoot,
  }, state);
  if (JSON.stringify(semgrep.gitlinks) !== JSON.stringify(lock.rootGitlinks)) {
    fail('root gitlink inventory does not match the source lock');
  }

  const recordPaths = [...new Set(lock.opam.resolvedSourceArchives.map((record) => posix.dirname(record.opamPath)))];
  const opam = await collectGitRepository({
    expectedRevision: lock.opam.repository.revision,
    includePaths: ['repo', ...recordPaths],
    prefix: 'opam-repository',
    root: opamRoot,
  });
  if (opam.gitlinks.length !== 0) fail('opam repository records contain an unexpected gitlink');
  state.entries.push(...opam.entries);
  state.links.push(...opam.links);
  state.repositories.push({ gitlinks: [], prefix: 'opam-repository', revision: opam.revision, tree: opam.tree });
  const opamEntries = new Map(opam.entries.map((entry) => [entry.path.slice('opam-repository/'.length), entry]));
  for (const record of lock.opam.resolvedSourceArchives) {
    const entry = opamEntries.get(record.opamPath);
    if (!entry || hash('sha256', entry.bytes) !== record.opamSha256) fail(`opam record mismatch: ${record.opamPath}`);
  }

  const pins = [lock.opam.compiler, ...(lock.opam.pinDepends ?? [])];
  const seenPins = new Set();
  for (const pin of pins.sort((left, right) => compareUtf8(left.revision, right.revision))) {
    if (seenPins.has(pin.revision)) continue;
    seenPins.add(pin.revision);
    await collectRecursiveGit({
      expectedRevision: pin.revision,
      prefix: `pins/${pin.revision}`,
      root: join(pinRoot, pin.revision),
    }, state);
  }

  state.entries.push(...await verifyArchiveCache(lock, archiveCacheRoot));
  state.links.push(...archiveCacheLinks(lock));
  state.entries.push({ bytes: loaded.bytes, executable: false, path: 'metadata/source-lock.v1.json' });
  for (const path of [...supportPaths].sort(compareUtf8)) {
    safePath(path, 'support path');
    const bytes = await readNoLink(supportRoot, path, 16 * 1024 * 1024);
    state.entries.push({ bytes, executable: false, path: `support/${path}` });
  }
  verifyLicenseMaterials(lock.licenseMaterials, state.entries);
  state.repositories.sort((left, right) => compareUtf8(left.prefix, right.prefix));
  state.entries.push({
    bytes: Buffer.from(`${JSON.stringify({ repositories: state.repositories, schemaVersion: 1 })}\n`),
    executable: false,
    path: 'metadata/git-repositories.v1.json',
  });
  return buildDeterministicTar({ entries: state.entries, links: state.links, outputPath });
}

export async function verifySemgrepSourceBundle({ bundlePath, sourceLockPath }) {
  const loaded = await readJsonFile(sourceLockPath, 'source lock');
  const lock = validateBundleLock(loaded.value);
  const verified = await verifyDeterministicTar(bundlePath);
  if (verified.digests['metadata/source-lock.v1.json'] !== hash('sha256', loaded.bytes)) {
    fail('bundle source lock does not match the expected lock');
  }
  const actualArchives = verified.paths.filter((path) => path.startsWith('opam-repository/cache/')).sort(compareUtf8);
  const expectedArchives = flattenArchiveSources(lock)
    .map(bundledArchivePath).sort(compareUtf8);
  if (JSON.stringify(actualArchives) !== JSON.stringify(expectedArchives)) fail('bundle archive inventory does not match the source lock');
  return verified;
}

function exactEvidenceKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail(`${label} has unexpected or missing fields`);
  }
  const actual = Object.keys(value).sort(compareUtf8);
  const wanted = [...expected].sort(compareUtf8);
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    fail(`${label} has unexpected or missing fields`);
  }
}

export async function verifyBundleEvidence({ bundlePath, evidencePath, sourceLockPath }) {
  if (![bundlePath, evidencePath, sourceLockPath].every((value) => typeof value === 'string')) {
    fail('bundle evidence arguments are invalid');
  }
  const [evidenceFile, sourceLockFile] = await Promise.all([
    readJsonFile(evidencePath, 'bundle evidence'),
    readJsonFile(sourceLockPath, 'source lock'),
  ]);
  const evidence = evidenceFile.value;
  exactEvidenceKeys(evidence, [
    'bundle',
    'bundleGeneratorSha256',
    'byteIdentical',
    'format',
    'independentBuilds',
    'schemaVersion',
    'sourceAssetUrl',
    'sourceLockSha256',
    'status',
  ], 'bundle evidence');
  exactEvidenceKeys(evidence.bundle, [
    'payloadEntries',
    'recordedLinks',
    'sha256',
    'size',
  ], 'bundle evidence bundle');
  const sha256Pattern = /^[0-9a-f]{64}$/;
  if (evidence.sourceAssetUrl !== SOURCE_ASSET_URL) {
    fail('bundle evidence source asset URL is invalid');
  }
  if (evidence.schemaVersion !== 1
      || evidence.format !== 'context-relay-semgrep-source-v1'
      || !Number.isSafeInteger(evidence.independentBuilds)
      || typeof evidence.byteIdentical !== 'boolean'
      || !BUNDLE_EVIDENCE_STATUSES.has(evidence.status)
      || !sha256Pattern.test(evidence.sourceLockSha256)
      || !sha256Pattern.test(evidence.bundleGeneratorSha256)
      || !sha256Pattern.test(evidence.bundle.sha256)
      || !Number.isSafeInteger(evidence.bundle.size) || evidence.bundle.size < TAR_BLOCK * 2
      || !Number.isSafeInteger(evidence.bundle.payloadEntries) || evidence.bundle.payloadEntries < 1
      || !Number.isSafeInteger(evidence.bundle.recordedLinks) || evidence.bundle.recordedLinks < 0) {
    fail('bundle evidence is invalid');
  }
  const v1 = evidence.status === 'source_bundle_v1_native_builds_pending';
  if (evidence.independentBuilds !== (v1 ? 1 : 2)
      || evidence.byteIdentical !== !v1) fail('bundle evidence qualification claim is invalid');
  if (evidence.sourceLockSha256 !== hash('sha256', sourceLockFile.bytes)) {
    fail('bundle evidence source lock hash mismatch');
  }
  const generatorPath = fileURLToPath(import.meta.url);
  const generatorInfo = await lstat(generatorPath);
  if (!generatorInfo.isFile() || generatorInfo.isSymbolicLink() || generatorInfo.size === 0
      || generatorInfo.size > 16 * 1024 * 1024) {
    fail('bundle generator is not a bounded no-link regular file');
  }
  if (evidence.bundleGeneratorSha256 !== hash('sha256', await readFile(generatorPath))) {
    fail('bundle evidence generator hash mismatch');
  }
  const verified = await verifySemgrepSourceBundle({ bundlePath, sourceLockPath });
  if (evidence.bundle.sha256 !== verified.sha256
      || evidence.bundle.size !== verified.size
      || evidence.bundle.payloadEntries !== verified.payloadEntries
      || evidence.bundle.recordedLinks !== verified.links) {
    fail('bundle evidence does not match the verified bundle');
  }
  return verified;
}

async function noLinkParent(root, relative) {
  let current = resolve(root);
  const rootInfo = await lstat(current);
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) fail('bundle root is not a no-link directory');
  for (const segment of relative.split('/').slice(0, -1)) {
    current = join(current, segment);
    const info = await lstat(current);
    if (!info.isDirectory() || info.isSymbolicLink()) fail('bundle link parent is unsafe');
  }
}

async function ensureNoLinkParent(root, relative) {
  let current = resolve(root);
  const rootInfo = await lstat(current);
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) fail('bundle root is not a no-link directory');
  for (const segment of relative.split('/').slice(0, -1)) {
    current = join(current, segment);
    let info;
    try {
      info = await lstat(current);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      await mkdir(current, { mode: 0o755 });
      info = await lstat(current);
    }
    if (!info.isDirectory() || info.isSymbolicLink()) fail('bundle materialization parent is unsafe');
  }
}

export async function materializeBundleLinks(root) {
  const metadata = await readNoLink(root, 'SYMLINKS.v1.json', 16 * 1024 * 1024);
  let document;
  try {
    document = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(metadata));
  } catch {
    fail('symlink metadata is invalid');
  }
  if (!document || Object.keys(document).sort().join(',') !== 'links,schemaVersion'
      || document.schemaVersion !== 1 || !Array.isArray(document.links)) fail('symlink metadata is invalid');
  const links = document.links.map(safeLink).sort((left, right) => compareUtf8(left.path, right.path));
  if (JSON.stringify(links) !== JSON.stringify(document.links)) fail('symlink metadata is not canonical');
  let longPaths = [];
  try {
    longPaths = parseLongPaths(await readNoLink(root, 'LONG_PATHS.v1.json', 64 * 1024 * 1024));
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  for (const item of longPaths) {
    await noLinkParent(root, item.stored);
    await ensureNoLinkParent(root, item.path);
    const source = join(resolve(root), ...item.stored.split('/'));
    const sourceInfo = await lstat(source);
    if (!sourceInfo.isFile() || sourceInfo.isSymbolicLink()) fail('stored long-path source is unsafe');
    const destination = join(resolve(root), ...item.path.split('/'));
    try {
      await lstat(destination);
      fail(`long-path destination already exists: ${item.path}`);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    await link(source, destination);
  }
  for (const item of links) {
    await ensureNoLinkParent(root, item.path);
    const destination = join(resolve(root), ...item.path.split('/'));
    try {
      await lstat(destination);
      fail(`bundle link path already exists: ${item.path}`);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    const target = posix.normalize(posix.join(posix.dirname(item.path), item.target));
    if (item.path.startsWith('opam-repository/cache/')) {
      if (!target.startsWith('opam-repository/cache/')) fail('archive checksum alias target is unsafe');
      await noLinkParent(root, target);
      const source = join(resolve(root), ...target.split('/'));
      const sourceInfo = await lstat(source);
      if (!sourceInfo.isFile() || sourceInfo.isSymbolicLink()) {
        fail('archive checksum alias source is unsafe');
      }
      await link(source, destination);
      continue;
    }
    let type = 'file';
    try {
      if ((await lstat(join(resolve(root), ...target.split('/')))).isDirectory()) type = 'dir';
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    await symlink(item.target, destination, type);
  }
  const manifest = parseLineMap(
    await readNoLink(root, 'MANIFEST.sha256', 64 * 1024 * 1024),
    /^([0-9a-f]{64})  (.+)$/,
    'manifest',
    2,
    [1],
  );
  for (const stored of manifest.keys()) {
    if (!stored.startsWith('opam-repository/cache/')) continue;
    const archive = parseBundledArchivePath(stored);
    if (archive.algorithm !== 'sha512') continue;
    const official = officialArchivePath(archive);
    await noLinkParent(root, stored);
    await noLinkParent(root, official);
    const source = join(resolve(root), ...stored.split('/'));
    const sourceInfo = await lstat(source);
    if (!sourceInfo.isFile() || sourceInfo.isSymbolicLink()) fail('bundled SHA-512 archive is unsafe');
    const destination = join(resolve(root), ...official.split('/'));
    try {
      const destinationInfo = await lstat(destination);
      if (!destinationInfo.isFile() || destinationInfo.isSymbolicLink()
          || destinationInfo.dev !== sourceInfo.dev || destinationInfo.ino !== sourceInfo.ino) {
        fail(`official SHA-512 cache path already exists: ${official}`);
      }
      continue;
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    await link(source, destination);
  }
  return links.length;
}

async function command() {
  const [mode, ...args] = process.argv.slice(2);
  if (mode === '--fetch' && args.length === 2) {
    const loaded = await readJsonFile(args[0], 'source lock');
    process.stdout.write(`${JSON.stringify(await fetchArchiveCache(validateBundleLock(loaded.value), args[1]))}\n`);
    return;
  }
  if (mode === '--build' && args.length === 7) {
    const result = await buildSemgrepSourceBundle({
      archiveCacheRoot: args[4],
      opamRoot: args[2],
      outputPath: args[5],
      pinRoot: args[3],
      semgrepRoot: args[1],
      sourceLockPath: args[0],
      supportPaths: DEFAULT_SUPPORT_PATHS,
      supportRoot: args[6],
    });
    const { digests: _digests, paths: _paths, ...summary } = result;
    process.stdout.write(`${JSON.stringify(summary)}\n`);
    return;
  }
  if (mode === '--verify' && args.length === 2) {
    const result = await verifySemgrepSourceBundle({ bundlePath: args[1], sourceLockPath: args[0] });
    const { digests: _digests, paths: _paths, ...summary } = result;
    process.stdout.write(`${JSON.stringify(summary)}\n`);
    return;
  }
  if (mode === '--verify-evidence' && args.length === 3) {
    const result = await verifyBundleEvidence({
      bundlePath: args[1],
      evidencePath: args[2],
      sourceLockPath: args[0],
    });
    const { digests: _digests, paths: _paths, ...summary } = result;
    process.stdout.write(`${JSON.stringify(summary)}\n`);
    return;
  }
  if (mode === '--materialize-links' && args.length === 1) {
    process.stdout.write(`${JSON.stringify({ links: await materializeBundleLinks(args[0]) })}\n`);
    return;
  }
  fail('usage: --fetch LOCK CACHE | --build LOCK SEMGREP OPAM PINS CACHE OUTPUT SUPPORT_ROOT | --verify LOCK BUNDLE | --verify-evidence LOCK BUNDLE EVIDENCE | --materialize-links ROOT');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  command().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
