import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { lstat, readFile, rename, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { promisify } from 'node:util';

const execute = promisify(execFile);

const TARGETS = ['aarch64-apple-darwin', 'windows-x86_64'];
const CHECKSUM_ORDER = new Map([['md5', 0], ['sha256', 1], ['sha512', 2]]);
const CHECKSUM_LENGTH = new Map([['md5', 32], ['sha256', 64], ['sha512', 128]]);
const LEGACY_SOURCE_CHECKSUMS = new Map([[
  'https://github.com/inhabitedtype/bigstringaf/archive/0.10.0.tar.gz',
  {
    requiredMd5: 'be0a44416840852777651150757a0a3b',
    supplemental: [{
      algorithm: 'sha256',
      digest: 'ed92f5b05fbc11b9defcec734d59b1068f3717a9ae4f9705c16c7f7ac3729f28',
    }],
  },
]]);
const PINNED_PACKAGES = new Set([
  'memtrace@dev',
  'obackward@dev',
  'ocaml-variants@5.3.0',
  'opentelemetry@dev',
  'opentelemetry-client-cohttp-eio@dev',
  'opentelemetry-client-ocurl@dev',
  'opentelemetry-logs@dev',
  'pcre2@dev',
  'pyro-caml-instruments@dev',
  'pyro-caml-ppx@dev',
  'semgrep-interfaces@dev',
  'testo@dev',
  'testo-diff@dev',
  'testo-lwt@dev',
  'testo-util@dev',
  'tree-sitter@dev',
]);
const COMPILER_VIRTUAL_PACKAGES = new Set([
  'atomic@base',
  'base-bigarray@base',
  'base-bytes@base',
  'base-domains@base',
  'base-effects@base',
  'base-nnp@base',
  'base-threads@base',
  'base-unix@base',
  'seq@base',
]);
const OCAML_COMPILER_LICENSE = 'LGPL-2.1-or-later WITH OCaml-LGPL-linking-exception';
const MAX_LOCK_BYTES = 1024 * 1024;
const MAX_OPAM_BYTES = 1024 * 1024;

function fail(message) {
  throw new Error('Semgrep source inventory: ' + message);
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function exactKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(label + ' must be an object');
  const actual = Object.keys(value).sort(compareUtf8);
  const wanted = [...expected].sort(compareUtf8);
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    fail(label + ' has unexpected or missing fields');
  }
}

function decodeQuoted(token, label) {
  try {
    const value = JSON.parse(token);
    if (typeof value !== 'string') fail(label + ' must be a string');
    return value;
  } catch {
    fail(label + ' is not a valid quoted string');
  }
}

function quotedStrings(text, label) {
  const tokens = text.match(/"(?:\\.|[^"\\])*"/g) ?? [];
  return tokens.map((token) => decodeQuoted(token, label));
}

function matchingDelimiter(text, start, open, close, label) {
  let depth = 0;
  let inString = false;
  let escaped = false;
  let inComment = false;
  for (let index = start; index < text.length; index += 1) {
    const character = text[index];
    if (inComment) {
      if (character === '\n') inComment = false;
      continue;
    }
    if (inString) {
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === '"') inString = false;
      continue;
    }
    if (character === '#') {
      inComment = true;
      continue;
    }
    if (character === '"') {
      inString = true;
      continue;
    }
    if (character === open) depth += 1;
    else if (character === close) {
      depth -= 1;
      if (depth === 0) return index;
      if (depth < 0) break;
    }
  }
  fail(label + ' has an unterminated delimiter');
}

function safeAtom(value, label) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9+_.~-]*$/.test(value)) {
    fail(label + ' is invalid');
  }
  if (value.normalize('NFC') !== value) fail(label + ' is not NFC');
  return value;
}

export function parseLockedDependencies(text, target) {
  if (typeof text !== 'string' || Buffer.byteLength(text) === 0 || Buffer.byteLength(text) > MAX_LOCK_BYTES) {
    fail('opam lock is empty or too large');
  }
  if (!TARGETS.includes(target)) fail('opam lock target is invalid');
  const starts = [...text.matchAll(/^depends[ \t]*:[ \t]*\[/gm)];
  if (starts.length !== 1) fail('opam lock must contain exactly one depends list');
  const open = text.indexOf('[', starts[0].index);
  const close = matchingDelimiter(text, open, '[', ']', 'opam lock depends list');
  const body = text.slice(open + 1, close);
  const seen = new Set();
  const dependencies = [];
  for (const rawLine of body.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line === '') continue;
    const match = /^"([^"\\]+)"[ \t]+\{=[ \t]+"([^"\\]+)"\}$/.exec(line);
    if (!match) fail('opam lock contains an unrecognized dependency entry');
    const packageName = safeAtom(match[1], 'locked package');
    const version = safeAtom(match[2], 'locked version');
    const key = packageName + '@' + version;
    if (seen.has(key)) fail('opam lock contains duplicate package ' + packageName);
    seen.add(key);
    dependencies.push({ package: packageName, target, version });
  }
  if (dependencies.length === 0) fail('opam lock has no dependencies');
  dependencies.sort((left, right) => compareUtf8(left.package, right.package) || compareUtf8(left.version, right.version));
  return dependencies;
}

function topLevelField(text, name) {
  const expression = new RegExp('^' + name + '[ \\t]*:[ \\t]*', 'gm');
  const matches = [...text.matchAll(expression)];
  if (matches.length === 0) return null;
  if (matches.length !== 1) fail('opam metadata has duplicate ' + name + ' fields');
  const start = matches[0].index + matches[0][0].length;
  const next = /^[A-Za-z][A-Za-z0-9_-]*(?:[ \t]*:|[ \t]*\{)/gm;
  next.lastIndex = start;
  const match = next.exec(text);
  return text.slice(start, match?.index ?? text.length);
}

function parseLicenses(text) {
  const field = topLevelField(text, 'license');
  if (field === null) return [];
  const licenses = quotedStrings(field, 'opam license');
  if (licenses.length === 0) fail('opam license field has no string value');
  for (const license of licenses) {
    if (license.length === 0 || /[\u0000-\u001f\u007f]/.test(license) || license.normalize('NFC') !== license) {
      fail('opam license value is invalid');
    }
  }
  const residue = field.replace(/"(?:\\.|[^"\\])*"/g, '').replace(/[\s\[\]]/g, '');
  if (residue !== '') fail('opam license field contains unparsed data');
  return licenses;
}

function sourceBlocks(text) {
  const expression = /^(url)[ \t]*\{|^extra-source[ \t]+"([^"\r\n]+)"[ \t]*\{/gm;
  const blocks = [];
  for (let match = expression.exec(text); match; match = expression.exec(text)) {
    const open = text.indexOf('{', match.index);
    const close = matchingDelimiter(text, open, '{', '}', 'opam source block');
    blocks.push({ body: text.slice(open + 1, close), kind: match[1] === 'url' ? 'primary' : 'extra', name: match[2] ?? null });
    expression.lastIndex = close + 1;
  }
  const declaredPrimary = [...text.matchAll(/^url\b/gm)].length;
  const declaredExtra = [...text.matchAll(/^extra-source\b/gm)].length;
  if (declaredPrimary !== blocks.filter((block) => block.kind === 'primary').length
      || declaredExtra !== blocks.filter((block) => block.kind === 'extra').length) {
    fail('opam metadata contains an unparsed source declaration');
  }
  return blocks;
}

function sourceFieldValue(body, name) {
  const expression = new RegExp('^[ \\t]*' + name + '[ \\t]*:[ \\t]*', 'gm');
  const fields = [...body.matchAll(expression)];
  if (fields.length === 0) return null;
  if (fields.length !== 1) fail('opam source must contain at most one ' + name + ' field');
  const start = fields[0].index + fields[0][0].length;
  const next = /^[ \t]*[A-Za-z][A-Za-z0-9_-]*[ \t]*:/gm;
  next.lastIndex = start;
  return body.slice(start, next.exec(body)?.index ?? body.length);
}

function safeSourceUrl(url, label) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    fail(label + ' URL is invalid');
  }
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username !== '' || parsed.password !== ''
      || parsed.hash !== '' || /[\u0000-\u0020\u007f]/.test(url)) {
    fail(label + ' URL is unsafe');
  }
}

function parseChecksums(body, url) {
  const field = sourceFieldValue(body, 'checksum');
  if (field === null) fail('opam source must contain exactly one checksum field');
  const values = quotedStrings(field, 'opam checksum');
  if (values.length === 0) fail('opam source has no checksum');
  const checksums = [];
  const seen = new Set();
  for (const value of values) {
    const match = /^(md5|sha256|sha512)=([0-9a-f]+)$/.exec(value);
    if (!match) fail('opam source contains an unsupported or malformed checksum');
    const [algorithm, digest] = [match[1], match[2]];
    if (digest.length !== CHECKSUM_LENGTH.get(algorithm) || /^0+$/.test(digest)) {
      fail('opam source checksum has an invalid digest');
    }
    if (seen.has(algorithm)) fail('opam source contains a duplicate checksum algorithm');
    seen.add(algorithm);
    checksums.push({ algorithm, digest });
  }
  checksums.sort((left, right) => CHECKSUM_ORDER.get(left.algorithm) - CHECKSUM_ORDER.get(right.algorithm));
  let supplementalChecksums = [];
  if (!seen.has('sha256') && !seen.has('sha512')) {
    const legacy = LEGACY_SOURCE_CHECKSUMS.get(url);
    const md5 = checksums.find((checksum) => checksum.algorithm === 'md5')?.digest;
    if (!legacy || md5 !== legacy.requiredMd5) fail('opam source requires a strong checksum');
    supplementalChecksums = structuredClone(legacy.supplemental);
  }
  return { checksums, supplementalChecksums };
}

function parseSourceBlock(block) {
  const fields = [...block.body.matchAll(/^[ \t]*([A-Za-z][A-Za-z0-9_-]*)[ \t]*:/gm)].map((match) => match[1]);
  if (fields.filter((field) => field === 'src').length !== 1
      || fields.filter((field) => field === 'checksum').length !== 1
      || fields.filter((field) => field === 'mirrors').length > 1
      || fields.some((field) => !['src', 'checksum', 'mirrors'].includes(field))) {
    fail('opam source/src block has unexpected, duplicate, or missing fields');
  }
  const sources = [...block.body.matchAll(/^[ \t]*src[ \t]*:[ \t]*(?:\r?\n[ \t]*)?"([^"\r\n]+)"[ \t]*$/gm)];
  if (sources.length !== 1) fail('opam source block must contain exactly one src');
  const url = sources[0][1];
  safeSourceUrl(url, 'opam source');
  const mirrorField = sourceFieldValue(block.body, 'mirrors');
  const mirrors = mirrorField === null ? [] : quotedStrings(mirrorField, 'opam mirror');
  const mirrorResidue = mirrorField === null ? '' : mirrorField.replace(/"(?:\\.|[^"\\])*"/g, '').replace(/[\s\[\]]/g, '');
  if (mirrorResidue !== '') fail('opam mirror field contains unparsed data');
  const seenMirrors = new Set();
  for (const mirror of mirrors) {
    safeSourceUrl(mirror, 'opam mirror');
    if (seenMirrors.has(mirror)) fail('opam source contains a duplicate mirror URL');
    seenMirrors.add(mirror);
  }
  return { ...parseChecksums(block.body, url), mirrors, url };
}

export function parseOpamMetadata(text) {
  if (typeof text !== 'string' || Buffer.byteLength(text) === 0 || Buffer.byteLength(text) > MAX_OPAM_BYTES) {
    fail('opam metadata is empty or too large');
  }
  const blocks = sourceBlocks(text);
  const primary = blocks.filter((block) => block.kind === 'primary');
  if (primary.length > 1) fail('opam metadata has duplicate primary sources');
  const seenExtras = new Set();
  const extraSources = blocks.filter((block) => block.kind === 'extra').map((block) => {
    if (!/^[A-Za-z0-9][A-Za-z0-9._+-]*$/.test(block.name)
        || block.name === '.' || block.name === '..' || block.name.normalize('NFC') !== block.name) {
      fail('opam extra-source name is unsafe');
    }
    const folded = block.name.toLowerCase();
    if (seenExtras.has(folded)) fail('opam metadata has duplicate extra-source name');
    seenExtras.add(folded);
    return { ...parseSourceBlock(block), name: block.name };
  });
  extraSources.sort((left, right) => compareUtf8(left.name, right.name));
  return {
    extraSources,
    licenses: parseLicenses(text),
    source: primary.length === 0 ? null : parseSourceBlock(primary[0]),
  };
}

async function readRegular(path, limit, label) {
  let info;
  try {
    info = await lstat(path);
  } catch {
    fail(label + ' is missing');
  }
  if (!info.isFile() || info.isSymbolicLink() || info.size === 0 || info.size > limit) {
    fail(label + ' is not a bounded regular file');
  }
  return readFile(path);
}

async function gitCommit(root, label) {
  let stdout;
  try {
    ({ stdout } = await execute('git', ['-C', root, 'rev-parse', '--verify', 'HEAD^{commit}'], {
      encoding: 'utf8',
      maxBuffer: 1024,
      windowsHide: true,
    }));
  } catch {
    fail(label + ' is not a readable Git repository');
  }
  const revision = stdout.trim();
  if (!/^[0-9a-f]{40}$/.test(revision)) fail(label + ' Git revision is invalid');
  return revision;
}

async function readGitBlob(root, revision, relative, limit) {
  if (typeof relative !== 'string' || relative.startsWith('/') || relative.includes('\\')
      || relative.split('/').some((part) => part === '' || part === '.' || part === '..')) {
    fail('Git blob path is unsafe');
  }
  let stdout;
  try {
    ({ stdout } = await execute('git', ['-C', root, 'cat-file', 'blob', revision + ':' + relative], {
      encoding: 'buffer',
      maxBuffer: limit + 1,
      windowsHide: true,
    }));
  } catch {
    fail(relative + ' is missing from locked Git source');
  }
  if (!Buffer.isBuffer(stdout) || stdout.length === 0 || stdout.length > limit) {
    fail(relative + ' is not a bounded Git blob');
  }
  return stdout;
}

function packageKey(entry) {
  return entry.package + '@' + entry.version;
}

export async function buildResolvedSourceInventory({ opamRoot, semgrepRoot, requireSemgrepPins = false }) {
  opamRoot = resolve(opamRoot);
  semgrepRoot = resolve(semgrepRoot);
  const [opamRevision, semgrepRevision] = await Promise.all([
    gitCommit(opamRoot, 'opam source'),
    gitCommit(semgrepRoot, 'Semgrep source'),
  ]);
  const lockDefinitions = [
    ['opam-lockfiles/semgrep.opam.mac-arm64.locked', 'aarch64-apple-darwin'],
    ['opam-lockfiles/semgrep.opam.windows-x86.locked', 'windows-x86_64'],
  ];
  const merged = new Map();
  const foundPins = new Set();
  for (const [relative, target] of lockDefinitions) {
    const bytes = await readGitBlob(semgrepRoot, semgrepRevision, relative, MAX_LOCK_BYTES);
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    for (const dependency of parseLockedDependencies(text, target)) {
      const key = packageKey(dependency);
      if (PINNED_PACKAGES.has(key)) {
        foundPins.add(key);
        continue;
      }
      const current = merged.get(key) ?? { package: dependency.package, targets: new Set(), version: dependency.version };
      current.targets.add(target);
      merged.set(key, current);
    }
  }
  if (requireSemgrepPins && (foundPins.size !== PINNED_PACKAGES.size
      || [...PINNED_PACKAGES].some((entry) => !foundPins.has(entry)))) {
    fail('pinned package inventory does not match Semgrep lockfiles');
  }

  const inventory = [];
  const packages = [...merged.values()].sort((left, right) => compareUtf8(left.package, right.package) || compareUtf8(left.version, right.version));
  for (const entry of packages) {
    const relative = 'packages/' + entry.package + '/' + entry.package + '.' + entry.version + '/opam';
    const bytes = await readGitBlob(opamRoot, opamRevision, relative, MAX_OPAM_BYTES);
    let metadata;
    try {
      metadata = parseOpamMetadata(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    } catch (error) {
      fail(relative + ': ' + String(error?.message ?? error));
    }
    const licenses = metadata.licenses.length === 0 && COMPILER_VIRTUAL_PACKAGES.has(packageKey(entry))
      ? [OCAML_COMPILER_LICENSE]
      : metadata.licenses;
    inventory.push({
      package: entry.package,
      version: entry.version,
      targets: TARGETS.filter((target) => entry.targets.has(target)),
      opamPath: relative,
      opamSha256: sha256(bytes),
      licenses,
      source: metadata.source,
      extraSources: metadata.extraSources,
    });
  }
  verifyResolvedSourceInventory(inventory);
  return inventory;
}

function verifyChecksums(checksums, label, requireStrong = true) {
  if (!Array.isArray(checksums) || checksums.length === 0) fail(label + ' checksum inventory is empty');
  let last = -1;
  let strong = false;
  const seen = new Set();
  for (const checksum of checksums) {
    exactKeys(checksum, ['algorithm', 'digest'], label + ' checksum');
    const order = CHECKSUM_ORDER.get(checksum.algorithm);
    if (order === undefined || order <= last || seen.has(checksum.algorithm)) fail(label + ' checksums are not canonical');
    if (typeof checksum.digest !== 'string' || checksum.digest.length !== CHECKSUM_LENGTH.get(checksum.algorithm)
        || !/^[0-9a-f]+$/.test(checksum.digest) || /^0+$/.test(checksum.digest)) {
      fail(label + ' checksum digest is invalid');
    }
    if (checksum.algorithm === 'sha256' || checksum.algorithm === 'sha512') strong = true;
    seen.add(checksum.algorithm);
    last = order;
  }
  if (requireStrong && !strong) fail(label + ' requires a strong checksum');
  return strong;
}

function verifySource(source, label) {
  exactKeys(source, ['checksums', 'mirrors', 'supplementalChecksums', 'url'], label);
  if (typeof source.url !== 'string') fail(label + ' URL is invalid');
  safeSourceUrl(source.url, label);
  if (!Array.isArray(source.mirrors)) fail(label + ' mirror inventory is invalid');
  const seenMirrors = new Set();
  for (const mirror of source.mirrors) {
    if (typeof mirror !== 'string') fail(label + ' mirror inventory is invalid');
    safeSourceUrl(mirror, label + ' mirror');
    if (seenMirrors.has(mirror)) fail(label + ' mirror inventory contains duplicates');
    seenMirrors.add(mirror);
  }
  const declaredStrong = verifyChecksums(source.checksums, label, false);
  if (!Array.isArray(source.supplementalChecksums)) fail(label + ' supplemental checksum inventory is invalid');
  if (source.supplementalChecksums.length === 0) {
    if (!declaredStrong) fail(label + ' requires a strong checksum');
    return;
  }
  const legacy = LEGACY_SOURCE_CHECKSUMS.get(source.url);
  const md5 = source.checksums.find((checksum) => checksum.algorithm === 'md5')?.digest;
  if (!legacy || md5 !== legacy.requiredMd5
      || JSON.stringify(source.supplementalChecksums) !== JSON.stringify(legacy.supplemental)) {
    fail(label + ' supplemental legacy checksum inventory is invalid');
  }
  verifyChecksums(source.supplementalChecksums, label + ' supplemental');
}

export function verifyResolvedSourceInventory(inventory, expected = null) {
  if (!Array.isArray(inventory) || inventory.length === 0) fail('resolved inventory is empty');
  let previous = null;
  const seen = new Set();
  for (const entry of inventory) {
    exactKeys(entry, ['package', 'version', 'targets', 'opamPath', 'opamSha256', 'licenses', 'source', 'extraSources'], 'resolved package');
    safeAtom(entry.package, 'resolved package name');
    safeAtom(entry.version, 'resolved package version');
    const key = packageKey(entry);
    if (seen.has(key)) fail('resolved inventory contains a duplicate package');
    if (previous !== null
        && (compareUtf8(previous.package, entry.package) > 0
          || (previous.package === entry.package && compareUtf8(previous.version, entry.version) >= 0))) {
      fail('resolved inventory is not in canonical sort order');
    }
    seen.add(key);
    previous = entry;
    if (!Array.isArray(entry.targets) || entry.targets.length === 0
        || entry.targets.some((target, index) => !TARGETS.includes(target) || TARGETS.indexOf(target) <= TARGETS.indexOf(entry.targets[index - 1]))) {
      fail('resolved package targets are not canonical');
    }
    const expectedPath = 'packages/' + entry.package + '/' + entry.package + '.' + entry.version + '/opam';
    if (entry.opamPath !== expectedPath || typeof entry.opamSha256 !== 'string'
        || !/^[0-9a-f]{64}$/.test(entry.opamSha256) || /^0+$/.test(entry.opamSha256)) {
      fail('resolved package opam material is invalid');
    }
    if (!Array.isArray(entry.licenses) || entry.licenses.length === 0
        || entry.licenses.some((license) => typeof license !== 'string' || license.length === 0)) {
      fail('resolved package license inventory is invalid');
    }
    if (entry.source !== null) verifySource(entry.source, 'resolved package source');
    if (!Array.isArray(entry.extraSources)) fail('resolved package extra-source inventory is invalid');
    let previousExtra = null;
    for (const extra of entry.extraSources) {
      exactKeys(extra, ['checksums', 'mirrors', 'name', 'supplementalChecksums', 'url'], 'resolved package extra-source');
      if (typeof extra.name !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._+-]*$/.test(extra.name)
          || (previousExtra !== null && compareUtf8(previousExtra, extra.name) >= 0)) {
        fail('resolved package extra-source names are not canonical');
      }
      previousExtra = extra.name;
      verifySource({
        checksums: extra.checksums,
        mirrors: extra.mirrors,
        supplementalChecksums: extra.supplementalChecksums,
        url: extra.url,
      }, 'resolved package extra-source');
    }
  }
  if (expected !== null && JSON.stringify(inventory) !== JSON.stringify(expected)) {
    fail('resolved inventory does not match regenerated material');
  }
}

async function command() {
  const [mode, semgrepRoot, opamRoot, lockPath] = process.argv.slice(2);
  if (!['--print', '--check', '--update-lock'].includes(mode) || !semgrepRoot || !opamRoot
      || ((mode === '--check' || mode === '--update-lock') && !lockPath)) {
    fail('usage: --print SEMGREP_ROOT OPAM_ROOT | --check SEMGREP_ROOT OPAM_ROOT SOURCE_LOCK | --update-lock SEMGREP_ROOT OPAM_ROOT SOURCE_LOCK');
  }
  const inventory = await buildResolvedSourceInventory({ opamRoot, requireSemgrepPins: true, semgrepRoot });
  if (mode === '--print') {
    process.stdout.write(JSON.stringify(inventory, null, 2) + '\n');
    return;
  }
  const absoluteLock = resolve(lockPath);
  const bytes = await readRegular(absoluteLock, 16 * 1024 * 1024, 'Semgrep source lock');
  let lock;
  try {
    lock = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    fail('Semgrep source lock is not valid UTF-8 JSON');
  }
  if (!lock?.opam || !Array.isArray(lock.opam.resolvedSourceArchives)) fail('Semgrep source lock has no resolved inventory');
  if (mode === '--check') {
    verifyResolvedSourceInventory(lock.opam.resolvedSourceArchives, inventory);
    if (lock.opam.resolvedSourceArchivesComplete !== true) fail('Semgrep source inventory is not marked complete');
    return;
  }
  lock.opam.resolvedSourceArchives = inventory;
  lock.opam.resolvedSourceArchivesComplete = true;
  const temporary = join(dirname(absoluteLock), '.source-lock.v1.json.inventory-' + process.pid);
  await writeFile(temporary, JSON.stringify(lock, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  await rename(temporary, absoluteLock);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  command().catch((error) => {
    process.stderr.write(String(error?.message ?? error) + '\n');
    process.exitCode = 1;
  });
}
