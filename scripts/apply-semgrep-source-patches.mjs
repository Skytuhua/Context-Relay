import { createHash } from 'node:crypto';
import { lstat, open, readFile, rename, rm } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const MAX_MANIFEST_BYTES = 256 * 1024;
const MAX_SOURCE_BYTES = 2 * 1024 * 1024;
const MAX_PATCHES = 32;
const MAX_REPLACEMENTS = 32;

function fail(message) {
  throw new Error(`Semgrep source patch: ${message}`);
}

function exactKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...expected].sort())) {
    fail(`${label} fields are invalid`);
  }
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function safeRelativePath(value, label) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 512
      || value.includes('\\') || value.startsWith('/') || value.includes('\0')
      || value.split('/').some((part) => part === '' || part === '.' || part === '..')
      || value.normalize('NFC') !== value) {
    fail(`${label} is unsafe`);
  }
  return value;
}

function boundedString(value, label) {
  if (typeof value !== 'string' || value.length === 0
      || Buffer.byteLength(value) > MAX_SOURCE_BYTES || value.includes('\0')) {
    fail(`${label} is invalid`);
  }
  return value;
}

async function boundedRegularFile(path, limit, label) {
  const info = await lstat(path).catch(() => fail(`${label} is missing`));
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.size === 0 || info.size > limit) {
    fail(`${label} must be a bounded single-link regular file`);
  }
  return readFile(path);
}

function countOccurrences(source, needle) {
  let count = 0;
  let offset = 0;
  while ((offset = source.indexOf(needle, offset)) !== -1) {
    count += 1;
    offset += needle.length;
  }
  return count;
}

function validateManifest(value) {
  exactKeys(value, ['schemaVersion', 'sourceModified', 'patches'], 'manifest');
  if (value.schemaVersion !== 1 || value.sourceModified !== true
      || !Array.isArray(value.patches) || value.patches.length === 0
      || value.patches.length > MAX_PATCHES) {
    fail('manifest does not declare a bounded modified-source inventory');
  }
  const identities = new Set();
  return value.patches.map((patch, patchIndex) => {
    const label = `patch[${patchIndex}]`;
    exactKeys(patch, [
      'id', 'package', 'revision', 'path', 'baseSha256', 'patchedSha256',
      'replacements', 'rationale',
    ], label);
    if (typeof patch.id !== 'string' || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(patch.id)
        || typeof patch.package !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._+-]*$/.test(patch.package)
        || typeof patch.revision !== 'string' || !/^[0-9a-f]{40}$/.test(patch.revision)
        || typeof patch.baseSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(patch.baseSha256)
        || typeof patch.patchedSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(patch.patchedSha256)
        || patch.baseSha256 === patch.patchedSha256
        || typeof patch.rationale !== 'string' || patch.rationale.length === 0 || patch.rationale.length > 512
        || /[\r\n\0]/.test(patch.rationale)
        || !Array.isArray(patch.replacements) || patch.replacements.length === 0
        || patch.replacements.length > MAX_REPLACEMENTS) {
      fail(`${label} metadata is invalid`);
    }
    const path = safeRelativePath(patch.path, `${label}.path`);
    const identity = `${patch.revision}\0${path}`;
    if (identities.has(identity)) fail(`${label} duplicates a source target`);
    identities.add(identity);
    const replacements = patch.replacements.map((replacement, replacementIndex) => {
      const replacementLabel = `${label}.replacements[${replacementIndex}]`;
      exactKeys(replacement, ['before', 'after'], replacementLabel);
      const before = boundedString(replacement.before, `${replacementLabel}.before`);
      const after = boundedString(replacement.after, `${replacementLabel}.after`);
      if (before === after) fail(`${replacementLabel} does not modify source`);
      return { after, before };
    });
    return { ...patch, path, replacements };
  });
}

export async function applySourcePatches({ manifestPath, pinsRoot }) {
  if (typeof manifestPath !== 'string' || typeof pinsRoot !== 'string') fail('paths are required');
  const root = resolve(pinsRoot);
  const rootInfo = await lstat(root).catch(() => fail('pins root is missing'));
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) fail('pins root is invalid');
  const manifestBytes = await boundedRegularFile(resolve(manifestPath), MAX_MANIFEST_BYTES, 'manifest');
  let manifest;
  try {
    manifest = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(manifestBytes));
  } catch {
    fail('manifest is not valid UTF-8 JSON');
  }
  const patches = validateManifest(manifest);
  const results = [];
  for (const patch of patches) {
    const target = resolve(join(root, patch.revision, ...patch.path.split('/')));
    const inside = relative(root, target);
    if (inside === '' || inside.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`) || isAbsolute(inside)) {
      fail(`patch ${patch.id} target escapes the pins root`);
    }
    const original = await boundedRegularFile(target, MAX_SOURCE_BYTES, `patch ${patch.id} source`);
    if (sha256(original) !== patch.baseSha256) fail(`patch ${patch.id} base sha256 mismatch`);
    let source;
    try {
      source = new TextDecoder('utf-8', { fatal: true }).decode(original);
    } catch {
      fail(`patch ${patch.id} source is not UTF-8`);
    }
    for (const [index, replacement] of patch.replacements.entries()) {
      if (countOccurrences(source, replacement.before) !== 1) {
        fail(`patch ${patch.id} replacement[${index}] must match exactly once`);
      }
      source = source.replace(replacement.before, replacement.after);
    }
    const patched = Buffer.from(source, 'utf8');
    if (patched.length === 0 || patched.length > MAX_SOURCE_BYTES
        || sha256(patched) !== patch.patchedSha256) {
      fail(`patch ${patch.id} patched sha256 mismatch`);
    }
    const temporary = join(dirname(target), `.${patch.id}.${process.pid}.tmp`);
    let handle;
    try {
      handle = await open(temporary, 'wx', 0o600);
      await handle.writeFile(patched);
      await handle.sync();
      await handle.close();
      handle = undefined;
      await rename(temporary, target);
    } finally {
      await handle?.close().catch(() => {});
      await rm(temporary, { force: true }).catch(() => {});
    }
    results.push({ id: patch.id, path: patch.path, revision: patch.revision, sha256: patch.patchedSha256 });
  }
  return results;
}

async function command() {
  const [manifestPath, pinsRoot] = process.argv.slice(2);
  if (!manifestPath || !pinsRoot || process.argv.length !== 4) {
    fail('usage: apply-semgrep-source-patches.mjs PATCHES.v1.json PINS_ROOT');
  }
  const result = await applySourcePatches({ manifestPath, pinsRoot });
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  command().catch((error) => {
    process.stderr.write(`${String(error?.message ?? error)}\n`);
    process.exitCode = 1;
  });
}
