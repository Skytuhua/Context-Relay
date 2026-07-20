import { createHash, randomBytes } from 'node:crypto';
import {
  link,
  lstat,
  mkdir,
  open,
  rm,
  unlink,
} from 'node:fs/promises';
import { basename, dirname, resolve } from 'node:path';

import { verifyDeterministicTar } from './semgrep-source-bundle.mjs';

const TAR_BLOCK = 512;
const MAX_BUNDLE_BYTES = 1280 * 1024 * 1024;
const MAX_PATCH_ENTRIES = 64;
const MAX_PATCH_ENTRY_BYTES = 16 * 1024 * 1024;
const RESERVED = new Set([
  'BUNDLE.v1.json',
  'LONG_PATHS.v1.json',
  'MANIFEST.sha256',
  'MODES.v1',
  'SYMLINKS.v1.json',
]);
const RESERVED_FOLDED = new Set([...RESERVED].map((path) => path.toLowerCase()));

function fail(message) {
  throw new Error(`Semgrep source reseal: ${message}`);
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function digest(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export function assertResealMetadataDigest(bytes, expected, path) {
  if (!Buffer.isBuffer(bytes) || typeof expected !== 'string' || digest(bytes) !== expected) {
    fail(`verified ${path} changed while being read`);
  }
}

export async function publishResealedBundle(
  temporary,
  output,
  sealedIdentity,
  operations = { link, lstat, unlink },
) {
  let published = false;
  try {
    await operations.link(temporary, output);
    published = true;
    await operations.unlink(temporary);
  } catch (error) {
    if (published) {
      const current = await operations.lstat(output).catch(() => null);
      if (current && current.dev === sealedIdentity.dev && current.ino === sealedIdentity.ino) {
        await operations.unlink(output).catch(() => {});
      }
    }
    throw error;
  }
}

function safePath(path, label) {
  if (typeof path !== 'string' || path.length === 0 || path.normalize('NFC') !== path
      || path.startsWith('/') || path.includes('\\') || /^[A-Za-z]:/.test(path)
      || /[\u0000-\u001f\u007f]/.test(path)) fail(`${label} is unsafe`);
  const parts = path.split('/');
  if (parts.some((part) => part.length === 0 || part === '.' || part === '..')) {
    fail(`${label} is unsafe`);
  }
  splitUstarPath(path, label);
  return path;
}

function splitUstarPath(path, label) {
  if (Buffer.byteLength(path) <= 100) return { name: path, prefix: '' };
  for (let index = path.lastIndexOf('/'); index > 0; index = path.lastIndexOf('/', index - 1)) {
    const prefix = path.slice(0, index);
    const name = path.slice(index + 1);
    if (Buffer.byteLength(prefix) <= 155 && Buffer.byteLength(name) <= 100) {
      return { name, prefix };
    }
  }
  fail(`${label} is not representable in deterministic USTAR`);
}

function octal(header, offset, length, value) {
  const text = value.toString(8).padStart(length - 1, '0');
  if (text.length !== length - 1) fail('tar numeric field overflow');
  header.write(text, offset, length - 1, 'ascii');
  header[offset + length - 1] = 0;
}

function tarHeader({ executable, path, size }) {
  const { name, prefix } = splitUstarPath(path, 'tar member path');
  const header = Buffer.alloc(TAR_BLOCK);
  header.write(name, 0, 100, 'utf8');
  octal(header, 100, 8, executable ? 0o755 : 0o644);
  octal(header, 108, 8, 0);
  octal(header, 116, 8, 0);
  octal(header, 124, 12, size);
  octal(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  header[156] = 0x30;
  header.write('ustar\0', 257, 6, 'ascii');
  header.write('00', 263, 2, 'ascii');
  header.write(prefix, 345, 155, 'utf8');
  const checksum = [...header].reduce((sum, byte) => sum + byte, 0);
  header.write(`${checksum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii');
  return header;
}

function tarText(header, offset, length) {
  const end = header.indexOf(0, offset);
  return header.subarray(offset, end === -1 || end > offset + length ? offset + length : end).toString('utf8');
}

function tarNumber(header, offset, length) {
  const text = header.subarray(offset, offset + length).toString('ascii').replace(/[\0 ]+$/g, '');
  if (!/^[0-7]+$/.test(text)) fail('verified input tar changed while being indexed');
  const value = Number.parseInt(text, 8);
  if (!Number.isSafeInteger(value)) fail('verified input tar changed while being indexed');
  return value;
}

async function readExact(handle, position, length) {
  const bytes = Buffer.alloc(length);
  let offset = 0;
  while (offset < length) {
    const { bytesRead } = await handle.read(bytes, offset, length - offset, position + offset);
    if (!Number.isInteger(bytesRead) || bytesRead <= 0) fail('verified input tar changed or became truncated');
    offset += bytesRead;
  }
  return bytes;
}

async function writeAll(handle, bytes) {
  let offset = 0;
  while (offset < bytes.length) {
    const { bytesWritten } = await handle.write(bytes, offset, bytes.length - offset, null);
    if (!Number.isInteger(bytesWritten) || bytesWritten <= 0) fail('output write made no progress');
    offset += bytesWritten;
  }
}

async function indexInput(handle, inputSize, verified) {
  const members = [];
  let position = 0;
  while (position + TAR_BLOCK * 2 <= inputSize) {
    const header = await readExact(handle, position, TAR_BLOCK);
    if (header.every((byte) => byte === 0)) break;
    const name = tarText(header, 0, 100);
    const prefix = tarText(header, 345, 155);
    const path = prefix ? `${prefix}/${name}` : name;
    const size = tarNumber(header, 124, 12);
    const mode = tarNumber(header, 100, 8);
    const padding = (TAR_BLOCK - (size % TAR_BLOCK)) % TAR_BLOCK;
    members.push({
      blockLength: TAR_BLOCK + size + padding,
      dataOffset: position + TAR_BLOCK,
      executable: mode === 0o755,
      header,
      path,
      size,
    });
    position += TAR_BLOCK + size + padding;
  }
  if (position + TAR_BLOCK * 2 !== inputSize) fail('verified input tar size changed while being indexed');
  const expected = [...verified.paths, 'MANIFEST.sha256', 'MODES.v1'].sort(compareUtf8);
  if (JSON.stringify(members.map(({ path }) => path)) !== JSON.stringify(expected)) {
    fail('verified input tar membership changed while being indexed');
  }
  return members;
}

function patches(values, label) {
  if (values === undefined) return [];
  if (!Array.isArray(values) || values.length > MAX_PATCH_ENTRIES) fail(`${label} inventory is invalid`);
  return values.map((entry, index) => {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)
        || Object.keys(entry).sort().join(',') !== 'bytes,executable,path'
        || !Buffer.isBuffer(entry.bytes) || entry.bytes.length > MAX_PATCH_ENTRY_BYTES
        || typeof entry.executable !== 'boolean') fail(`${label}[${index}] is invalid`);
    const path = safePath(entry.path, `${label}[${index}].path`);
    const folded = path.toLowerCase();
    const reservedMetadata = [...RESERVED_FOLDED]
      .some((reserved) => folded === reserved || folded.startsWith(`${reserved}/`));
    if (reservedMetadata || folded === 'long_paths' || folded.startsWith('long_paths/')) {
      fail(`${label}[${index}] targets generated metadata`);
    }
    return { bytes: entry.bytes, executable: entry.executable, path };
  });
}

async function logicalPaths(handle, indexed, verified) {
  const paths = indexed.map(({ path }) => path);
  const byPath = new Map(indexed.map((entry) => [entry.path, entry]));
  for (const [metadataPath, collection] of [
    ['SYMLINKS.v1.json', 'links'],
    ['LONG_PATHS.v1.json', 'paths'],
  ]) {
    const member = byPath.get(metadataPath);
    if (!member) continue;
    if (member.size > MAX_PATCH_ENTRY_BYTES) fail(`${metadataPath} exceeds the reseal metadata limit`);
    let document;
    try {
      const bytes = await readExact(handle, member.dataOffset, member.size);
      assertResealMetadataDigest(bytes, verified.digests[metadataPath], metadataPath);
      document = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    } catch {
      fail(`verified ${metadataPath} changed while being read`);
    }
    if (!Array.isArray(document?.[collection])) fail(`verified ${metadataPath} is invalid`);
    for (const entry of document[collection]) {
      if (typeof entry?.path !== 'string') fail(`verified ${metadataPath} is invalid`);
      paths.push(entry.path);
    }
  }
  return paths;
}

function pathConflict(candidate, occupied) {
  const folded = candidate.normalize('NFC').toLowerCase();
  return occupied.find((path) => {
    const other = path.normalize('NFC').toLowerCase();
    return folded === other || folded.startsWith(`${other}/`) || other.startsWith(`${folded}/`);
  });
}

function outputMembers(indexed, verified, additions, replacements, logicalOccupied) {
  const existing = new Map(indexed.map((entry) => [entry.path, entry]));
  const replacementMap = new Map();
  for (const entry of replacements) {
    if (!existing.has(entry.path)) fail(`replacement does not exist: ${entry.path}`);
    if (replacementMap.has(entry.path)) fail(`replacement is duplicated: ${entry.path}`);
    replacementMap.set(entry.path, entry);
  }
  for (const entry of additions) {
    const conflict = pathConflict(entry.path, logicalOccupied);
    if (conflict) fail(`addition collision or ancestor/descendant conflict with ${conflict}`);
    logicalOccupied.push(entry.path);
    existing.set(entry.path, { ...entry, added: true, size: entry.bytes.length });
  }
  const payload = [...existing.values()]
    .filter(({ path }) => path !== 'MANIFEST.sha256' && path !== 'MODES.v1')
    .map((entry) => {
      const patch = replacementMap.get(entry.path);
      if (patch) return { ...entry, ...patch, size: patch.bytes.length };
      return entry;
    });
  const manifest = Buffer.from(payload
    .sort((left, right) => compareUtf8(left.path, right.path))
    .map((entry) => `${entry.bytes ? digest(entry.bytes) : verified.digests[entry.path]}  ${entry.path}\n`)
    .join(''));
  const modes = Buffer.from(payload
    .map((entry) => `${entry.path}\t${entry.executable ? 1 : 0}\n`)
    .join(''));
  return [
    ...payload,
    { bytes: manifest, executable: false, generated: true, path: 'MANIFEST.sha256', size: manifest.length },
    { bytes: modes, executable: false, generated: true, path: 'MODES.v1', size: modes.length },
  ].sort((left, right) => compareUtf8(left.path, right.path));
}

async function consumeOriginal(handle, member, inputHash, output, copyPayload, buffer) {
  inputHash.update(member.header);
  let read = 0;
  while (read < member.size) {
    const length = Math.min(buffer.length, member.size - read);
    const { bytesRead } = await handle.read(buffer, 0, length, member.dataOffset + read);
    if (bytesRead !== length) fail('verified input tar changed or became truncated');
    const chunk = buffer.subarray(0, bytesRead);
    inputHash.update(chunk);
    if (copyPayload) await writeAll(output, chunk);
    read += bytesRead;
  }
  const paddingLength = member.blockLength - TAR_BLOCK - member.size;
  if (paddingLength) {
    const padding = await readExact(handle, member.dataOffset + member.size, paddingLength);
    inputHash.update(padding);
  }
}

export async function resealSemgrepSourceBundle({
  additions,
  inputPath,
  outputPath,
  replacements,
}) {
  if (typeof inputPath !== 'string' || typeof outputPath !== 'string'
      || resolve(inputPath) === resolve(outputPath)) fail('input and output paths are invalid');
  const verified = await verifyDeterministicTar(inputPath);
  const added = patches(additions, 'addition');
  const replaced = patches(replacements, 'replacement');
  if (added.length + replaced.length > MAX_PATCH_ENTRIES) fail('patch inventory is too large');
  const input = await open(resolve(inputPath), 'r');
  let initial;
  try {
    initial = await input.stat();
    const namedInput = await lstat(resolve(inputPath));
    if (!initial.isFile() || !namedInput.isFile() || namedInput.isSymbolicLink()
        || initial.size !== verified.size || namedInput.size !== verified.size
        || initial.dev !== namedInput.dev || initial.ino !== namedInput.ino) {
      fail('verified input identity changed before resealing');
    }
  } catch (error) {
    await input.close();
    throw error;
  }
  let output = null;
  let temporaryCreated = false;
  let sealedIdentity = null;
  const absoluteOutput = resolve(outputPath);
  const temporary = resolve(
    dirname(absoluteOutput),
    `.${basename(absoluteOutput)}.${process.pid}.${randomBytes(16).toString('hex')}.tmp`,
  );
  try {
    const indexed = await indexInput(input, initial.size, verified);
    const byPath = new Map(indexed.map((entry) => [entry.path, entry]));
    const finalMembers = outputMembers(
      indexed,
      verified,
      added,
      replaced,
      await logicalPaths(input, indexed, verified),
    );
    const finalSize = finalMembers.reduce(
      (total, member) => total + TAR_BLOCK + member.size
        + ((TAR_BLOCK - (member.size % TAR_BLOCK)) % TAR_BLOCK),
      TAR_BLOCK * 2,
    );
    if (finalSize > MAX_BUNDLE_BYTES) fail('final bundle exceeds the aggregate size limit');
    try {
      await lstat(absoluteOutput);
      fail('output already exists');
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    await mkdir(dirname(absoluteOutput), { recursive: true });
    output = await open(temporary, 'wx', 0o600);
    temporaryCreated = true;
    const inputHash = createHash('sha256');
    const copyBuffer = Buffer.alloc(1024 * 1024);
    for (const member of finalMembers) {
      await writeAll(output, tarHeader(member));
      const original = byPath.get(member.path);
      if (original) {
        await consumeOriginal(input, original, inputHash, output, !member.bytes, copyBuffer);
      }
      if (member.bytes) await writeAll(output, member.bytes);
      const padding = (TAR_BLOCK - (member.size % TAR_BLOCK)) % TAR_BLOCK;
      if (padding) await writeAll(output, Buffer.alloc(padding));
    }
    const originalEnd = await readExact(input, initial.size - TAR_BLOCK * 2, TAR_BLOCK * 2);
    inputHash.update(originalEnd);
    await writeAll(output, Buffer.alloc(TAR_BLOCK * 2));
    const finalInput = await input.stat();
    if (finalInput.size !== initial.size || finalInput.dev !== initial.dev || finalInput.ino !== initial.ino
        || inputHash.digest('hex') !== verified.sha256) {
      fail('verified input tar changed while being resealed');
    }
    await output.sync();
    sealedIdentity = await output.stat();
    await output.close();
    output = null;
    await publishResealedBundle(temporary, absoluteOutput, sealedIdentity);
    temporaryCreated = false;
  } catch (error) {
    if (output) await output.close().catch(() => {});
    if (temporaryCreated) await rm(temporary, { force: true }).catch(() => {});
    throw error;
  } finally {
    await input.close();
  }
  try {
    const result = await verifyDeterministicTar(absoluteOutput);
    const outputInfo = await lstat(absoluteOutput);
    if (!outputInfo.isFile() || outputInfo.isSymbolicLink()
        || outputInfo.dev !== sealedIdentity.dev || outputInfo.ino !== sealedIdentity.ino) {
      fail('final bundle identity changed after publication');
    }
    return result;
  } catch (error) {
    const current = await lstat(absoluteOutput).catch(() => null);
    if (current && current.dev === sealedIdentity.dev && current.ino === sealedIdentity.ino) {
      await unlink(absoluteOutput).catch(() => {});
    }
    throw error;
  }
}
