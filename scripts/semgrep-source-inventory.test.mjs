import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';

import {
  buildResolvedSourceInventory,
  parseLockedDependencies,
  parseOpamMetadata,
  verifyResolvedSourceInventory,
} from './semgrep-source-inventory.mjs';

const sha256 = 'a'.repeat(64);
const sha512 = 'b'.repeat(128);

test('locked dependencies preserve exact target membership and reject malformed duplicates', () => {
  const mac = [
    'depends: [',
    '  "alpha" {= "1.0"}',
    '  "shared" {= "base"}',
    ']',
  ].join('\n');
  assert.deepEqual(parseLockedDependencies(mac, 'aarch64-apple-darwin'), [
    { package: 'alpha', target: 'aarch64-apple-darwin', version: '1.0' },
    { package: 'shared', target: 'aarch64-apple-darwin', version: 'base' },
  ]);
  assert.throws(
    () => parseLockedDependencies(mac.replace(']', '  "alpha" {= "1.0"}\n]'), 'aarch64-apple-darwin'),
    /duplicate.*alpha/i,
  );
  assert.throws(() => parseLockedDependencies('depends: [\n  "alpha"\n]\n', 'windows-x86_64'), /lock/i);
});

test('opam metadata records primary and extra sources, strong hashes, and licenses exactly', () => {
  const opam = [
    'opam-version: "2.0"',
    'license: ["ISC" "MIT"]',
    'url {',
    '  src:',
    '    "https://example.invalid/alpha.tbz"',
    '  checksum: [',
    '    "sha256=' + sha256 + '"',
    '    "sha512=' + sha512 + '"',
    '  ]',
    '  mirrors: "https://mirror.example.invalid/alpha.tbz"',
    '}',
    'extra-source "build.sh" {',
    '  src: "https://example.invalid/build.sh"',
    '  checksum:',
    '    "sha512=' + sha512 + '"',
    '}',
  ].join('\n');
  assert.deepEqual(parseOpamMetadata(opam), {
    extraSources: [{
      checksums: [{ algorithm: 'sha512', digest: sha512 }],
      mirrors: [],
      name: 'build.sh',
      supplementalChecksums: [],
      url: 'https://example.invalid/build.sh',
    }],
    licenses: ['ISC', 'MIT'],
    source: {
      checksums: [
        { algorithm: 'sha256', digest: sha256 },
        { algorithm: 'sha512', digest: sha512 },
      ],
      mirrors: ['https://mirror.example.invalid/alpha.tbz'],
      supplementalChecksums: [],
      url: 'https://example.invalid/alpha.tbz',
    },
  });
});

test('opam metadata represents source-free virtual packages without inventing source', () => {
  assert.deepEqual(parseOpamMetadata([
    'opam-version: "2.0"',
    'flags: conf',
    'license: "BSD-2-Clause"',
  ].join('\n')), {
    extraSources: [],
    licenses: ['BSD-2-Clause'],
    source: null,
  });
});

test('the sole legacy opam archive has an explicit independently verified strong checksum', () => {
  const metadata = parseOpamMetadata([
    'opam-version: "2.0"',
    'url {',
    '  src: "https://github.com/inhabitedtype/bigstringaf/archive/0.10.0.tar.gz"',
    '  checksum: "md5=be0a44416840852777651150757a0a3b"',
    '}',
  ].join('\n'));
  assert.deepEqual(metadata.source.supplementalChecksums, [{
    algorithm: 'sha256',
    digest: 'ed92f5b05fbc11b9defcec734d59b1068f3717a9ae4f9705c16c7f7ac3729f28',
  }]);
  assert.throws(
    () => parseOpamMetadata([
      'opam-version: "2.0"',
      'url {',
      '  src: "https://github.com/inhabitedtype/bigstringaf/archive/0.10.0.tar.gz"',
      '  checksum: "md5=' + 'c'.repeat(32) + '"',
      '}',
    ].join('\n')),
    /legacy|checksum/i,
  );
});

test('opam metadata rejects weak-only, duplicate, unsafe, or unparsed source material', () => {
  const block = (body) => ['opam-version: "2.0"', 'url {', body, '}'].join('\n');
  assert.throws(
    () => parseOpamMetadata(block('  src: "https://example.invalid/a"\n  checksum: "md5=' + 'c'.repeat(32) + '"')),
    /strong checksum/i,
  );
  assert.throws(
    () => parseOpamMetadata(block('  src: "https://example.invalid/a"\n  src: "https://example.invalid/b"\n  checksum: "sha256=' + sha256 + '"')),
    /src/i,
  );
  assert.throws(
    () => parseOpamMetadata([
      'opam-version: "2.0"',
      'extra-source "../escape" {',
      '  src: "https://example.invalid/a"',
      '  checksum: "sha256=' + sha256 + '"',
      '}',
    ].join('\n')),
    /extra-source.*name/i,
  );
  assert.throws(
    () => parseOpamMetadata(block('  src: "https://example.invalid/a"\n  checksum: "sha999=' + sha256 + '"')),
    /checksum/i,
  );
  assert.throws(
    () => parseOpamMetadata(block('  src: "https://example.invalid/a"\n  checksum: "sha256=' + sha256 + '"\n  mirrors: "file:///escape"')),
    /mirror|url/i,
  );
});

test('resolved inventory is deterministic, exact across targets, and self-verifying', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'context-relay-semgrep-inventory-'));
  t.after(() => rm(root, { force: true, recursive: true }));
  const semgrepRoot = join(root, 'semgrep');
  const opamRoot = join(root, 'opam');
  const macLock = join(semgrepRoot, 'opam-lockfiles', 'semgrep.opam.mac-arm64.locked');
  const windowsLock = join(semgrepRoot, 'opam-lockfiles', 'semgrep.opam.windows-x86.locked');
  const alphaOpam = join(opamRoot, 'packages', 'alpha', 'alpha.1.0', 'opam');
  const virtualOpam = join(opamRoot, 'packages', 'virtual', 'virtual.1', 'opam');
  await Promise.all([
    mkdir(dirname(macLock), { recursive: true }),
    mkdir(dirname(alphaOpam), { recursive: true }),
    mkdir(dirname(virtualOpam), { recursive: true }),
  ]);
  await writeFile(macLock, 'depends: [\n  "alpha" {= "1.0"}\n]\n');
  await writeFile(windowsLock, 'depends: [\n  "virtual" {= "1"}\n  "alpha" {= "1.0"}\n]\n');
  const alphaBytes = Buffer.from([
    'opam-version: "2.0"',
    'license: "ISC"',
    'url {',
    '  src: "https://example.invalid/alpha.tbz"',
    '  checksum: "sha256=' + sha256 + '"',
    '}',
  ].join('\n'));
  await writeFile(alphaOpam, alphaBytes);
  await writeFile(virtualOpam, 'opam-version: "2.0"\nflags: conf\nlicense: "MIT"\n');

  for (const repository of [semgrepRoot, opamRoot]) {
    execFileSync('git', ['init', '--quiet'], { cwd: repository });
    execFileSync('git', ['config', 'core.autocrlf', 'false'], { cwd: repository });
    execFileSync('git', ['config', 'user.email', 'source-inventory@example.invalid'], { cwd: repository });
    execFileSync('git', ['config', 'user.name', 'Source Inventory Test'], { cwd: repository });
    execFileSync('git', ['add', '.'], { cwd: repository });
    execFileSync('git', ['commit', '--quiet', '-m', 'fixture'], { cwd: repository });
  }
  await writeFile(alphaOpam, Buffer.from(alphaBytes.toString().replaceAll('\n', '\r\n')));

  const inventory = await buildResolvedSourceInventory({ opamRoot, semgrepRoot });
  assert.deepEqual(inventory.map((entry) => [entry.package, entry.version, entry.targets]), [
    ['alpha', '1.0', ['aarch64-apple-darwin', 'windows-x86_64']],
    ['virtual', '1', ['windows-x86_64']],
  ]);
  assert.equal(inventory[0].opamPath, 'packages/alpha/alpha.1.0/opam');
  assert.equal(inventory[0].opamSha256, createHash('sha256').update(alphaBytes).digest('hex'));
  assert.equal(inventory[1].source, null);
  assert.doesNotThrow(() => verifyResolvedSourceInventory(inventory));

  const drift = structuredClone(inventory);
  drift[0].source.checksums[0].digest = '0'.repeat(64);
  assert.throws(() => verifyResolvedSourceInventory(drift), /inventory|checksum/i);
  const missingLicense = structuredClone(inventory);
  missingLicense[0].licenses = [];
  assert.throws(() => verifyResolvedSourceInventory(missingLicense), /license/i);
  assert.throws(() => verifyResolvedSourceInventory([inventory[1], inventory[0]]), /sort/i);
});
