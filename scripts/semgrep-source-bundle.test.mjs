import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, rename, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  archiveCacheLinks,
  buildDeterministicTar,
  buildSemgrepSourceBundle,
  collectGitRepository,
  fetchArchiveCache,
  flattenArchiveSources,
  materializeBundleLinks,
  verifyArchiveCache,
  verifyBundleEvidence,
  verifyDeterministicTar,
  verifyLicenseMaterials,
  verifySemgrepSourceBundle,
  writeAll,
} from './semgrep-source-bundle.mjs';

const digest = (algorithm, bytes) => createHash(algorithm).update(bytes).digest('hex');

test('license inventory is complete, canonical, and bound to bundled bytes', () => {
  const bytes = Buffer.from('MIT license\n');
  const materials = [{
    source: 'fixture',
    kind: 'license',
    spdx: 'MIT',
    path: 'sources/fixture/LICENSE',
    sha256: digest('sha256', bytes),
  }];
  assert.doesNotThrow(() => verifyLicenseMaterials(materials, [
    { bytes, executable: false, path: 'sources/fixture/LICENSE' },
  ], new Set(['fixture'])));
  assert.throws(() => verifyLicenseMaterials([], [], new Set(['fixture'])), /license/i);
  assert.throws(
    () => verifyLicenseMaterials(materials, [], new Set(['fixture'])),
    /license.*(?:missing|bundle)/i,
  );
  assert.throws(
    () => verifyLicenseMaterials([{ ...materials[0], sha256: '0'.repeat(64) }]),
    /license.*sha/i,
  );
});

test('writeAll retries partial FileHandle writes without dropping bytes', async () => {
  const written = [];
  const handle = {
    write: async (bytes, offset, length) => {
      const count = Math.min(3, length);
      written.push(Buffer.from(bytes.subarray(offset, offset + count)));
      return { bytesWritten: count };
    },
  };
  const expected = Buffer.from('partial writes must be retried');
  await writeAll(handle, expected);
  assert.deepEqual(Buffer.concat(written), expected);
});

test('locked compiler identity can be supplied without modifying source', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'context-relay-compiler-identity-'));
  t.after(() => rm(root, { force: true, recursive: true }));
  const gitDir = join(root, 'compiler-git');
  const source = join(root, 'source');
  const revision = '3499e5708b0637c12d24d973dd103406a32b8fe8';
  await mkdir(source);
  execFileSync('git', ['init', '--bare', gitDir], { stdio: 'ignore' });
  await writeFile(join(gitDir, 'HEAD'), `${revision}\n`);
  const actual = execFileSync('git', ['rev-parse', 'HEAD'], {
    cwd: source,
    encoding: 'utf8',
    env: { ...process.env, GIT_DIR: gitDir },
  });
  assert.equal(actual.trim(), revision);
  assert.deepEqual(await readdir(source), []);
});

test('deterministic source tar is byte-identical and contains no link members', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'context-relay-semgrep-bundle-'));
  t.after(() => rm(root, { force: true, recursive: true }));
  const first = join(root, 'first.tar');
  const second = join(root, 'second.tar');
  const entries = [
    { bytes: Buffer.from('#!/bin/sh\nexit 0\n'), executable: true, path: 'sources/semgrep/tool.sh' },
    { bytes: Buffer.from('source\n'), executable: false, path: 'sources/semgrep/lib/source.ml' },
    {
      bytes: Buffer.from('long path\n'),
      executable: false,
      path: `sources/${'a'.repeat(70)}/${'b'.repeat(101)}/file`,
    },
  ];
  const links = [{ path: 'sources/semgrep/tool', target: 'tool.sh' }];

  await buildDeterministicTar({ entries: [...entries].reverse(), links, outputPath: first });
  await buildDeterministicTar({ entries, links, outputPath: second });

  assert.deepEqual(await readFile(first), await readFile(second));
  const verified = await verifyDeterministicTar(first);
  assert.equal(verified.payloadEntries, 6);
  assert.equal(verified.links, 1);
  assert.match(verified.sha256, /^[0-9a-f]{64}$/);
  assert.ok(verified.size > 0);
  await assert.rejects(
    () => verifyDeterministicTar(first, verified.size - 1),
    /size|limit/i,
  );
});

test('source tar enforces aggregate size and leaves an existing output untouched', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'context-relay-semgrep-bundle-cap-'));
  t.after(() => rm(root, { force: true, recursive: true }));
  const outputPath = join(root, 'bundle.tar');
  const entries = [{ bytes: Buffer.from('source'), executable: false, path: 'source/file' }];
  await assert.rejects(
    () => buildDeterministicTar({ entries, links: [], maxBytes: 1024, outputPath }),
    /aggregate|size|limit/i,
  );
  await writeFile(outputPath, 'sentinel');
  await assert.rejects(() => buildDeterministicTar({ entries, links: [], outputPath }), /exist|EEXIST/i);
  assert.equal(await readFile(outputPath, 'utf8'), 'sentinel');
  assert.equal((await readdir(root)).some((name) => name.endsWith('.tmp')), false);
});

test('source tar verifier rejects nonzero reserved USTAR header fields', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'context-relay-semgrep-bundle-header-'));
  t.after(() => rm(root, { force: true, recursive: true }));
  const outputPath = join(root, 'bundle.tar');
  await buildDeterministicTar({ entries: [{ bytes: Buffer.from('x'), executable: false, path: 'source/file' }], links: [], outputPath });
  const bytes = await readFile(outputPath);
  bytes[265] = 0x78;
  bytes.fill(0x20, 148, 156);
  const checksum = bytes.subarray(0, 512).reduce((sum, byte) => sum + byte, 0);
  bytes.write(`${checksum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii');
  await writeFile(join(root, 'changed.tar'), bytes);
  await assert.rejects(() => verifyDeterministicTar(join(root, 'changed.tar')), /metadata|reserved|header/i);
});

test('source tar verifier rejects nonzero member padding', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'context-relay-semgrep-bundle-padding-'));
  t.after(() => rm(root, { force: true, recursive: true }));
  const outputPath = join(root, 'bundle.tar');
  await buildDeterministicTar({ entries: [{ bytes: Buffer.from('x'), executable: false, path: 'source/file' }], links: [], outputPath });
  const bytes = await readFile(outputPath);
  const firstSize = Number.parseInt(bytes.subarray(124, 136).toString('ascii').replace(/[\0 ]+$/g, ''), 8);
  bytes[512 + firstSize] = 1;
  const changed = join(root, 'changed.tar');
  await writeFile(changed, bytes);
  await assert.rejects(() => verifyDeterministicTar(changed), /padding|canonical|zero/i);
});

test('source tar verifier requires exactly two trailing zero blocks', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'context-relay-semgrep-bundle-end-'));
  t.after(() => rm(root, { force: true, recursive: true }));
  const outputPath = join(root, 'bundle.tar');
  await buildDeterministicTar({ entries: [{ bytes: Buffer.from('x'), executable: false, path: 'source/file' }], links: [], outputPath });
  const bytes = await readFile(outputPath);
  const changed = join(root, 'changed.tar');
  await writeFile(changed, bytes.subarray(0, bytes.length - 1024));
  await assert.rejects(() => verifyDeterministicTar(changed), /end marker|trailing|truncated/i);
});

test('source tar rejects traversal, aliases, duplicates, and unsafe links', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'context-relay-semgrep-bundle-invalid-'));
  t.after(() => rm(root, { force: true, recursive: true }));
  const outputPath = join(root, 'bundle.tar');
  const entry = (path) => ({ bytes: Buffer.from('x'), executable: false, path });

  for (const path of ['../escape', '/absolute', 'C:/drive', 'a\\b', 'a/./b', 'a//b']) {
    await assert.rejects(() => buildDeterministicTar({ entries: [entry(path)], links: [], outputPath }), /path|safe/i);
  }
  for (const paths of [['a/File', 'a/file'], ['a/Σ', 'a/σ']]) {
    await assert.rejects(
      () => buildDeterministicTar({ entries: paths.map(entry), links: [], outputPath }),
      /duplicate|collision/i,
    );
  }
  await assert.rejects(
    () => buildDeterministicTar({ entries: [entry('a/target')], links: [{ path: 'a/link', target: '../../escape' }], outputPath }),
    /link|target/i,
  );
});

test('verified link metadata materializes only in-tree source links', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'context-relay-semgrep-links-'));
  t.after(() => rm(root, { force: true, recursive: true }));
  await mkdir(join(root, 'source'), { recursive: true });
  await writeFile(join(root, 'source', 'target'), 'target\n');
  await writeFile(join(root, 'SYMLINKS.v1.json'), `${JSON.stringify({ links: [{ path: 'source/link', target: 'target' }], schemaVersion: 1 })}\n`);
  await writeFile(join(root, 'MANIFEST.sha256'), `${digest('sha256', Buffer.from('target\n'))}  source/target\n`);
  try {
    await materializeBundleLinks(root);
  } catch (error) {
    if (error.code === 'EPERM') {
      t.skip('symlink creation is unavailable');
      return;
    }
    throw error;
  }
  assert.equal(await readFile(join(root, 'source', 'link'), 'utf8'), 'target\n');
  await assert.rejects(() => materializeBundleLinks(root), /exist|link/i);
});

test('verified link materialization creates Git-untracked parent directories safely', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'context-relay-semgrep-link-parents-'));
  t.after(() => rm(root, { force: true, recursive: true }));
  await writeFile(join(root, 'target'), 'target\n');
  await writeFile(join(root, 'SYMLINKS.v1.json'), `${JSON.stringify({ links: [{ path: 'empty/bin/tool', target: '../../target' }], schemaVersion: 1 })}\n`);
  await writeFile(join(root, 'MANIFEST.sha256'), `${digest('sha256', Buffer.from('target\n'))}  target\n`);

  try {
    assert.equal(await materializeBundleLinks(root), 1);
  } catch (error) {
    if (error.code === 'EPERM') {
      t.skip('symlink creation is unavailable');
      return;
    }
    throw error;
  }
  assert.equal(await readFile(join(root, 'empty', 'bin', 'tool'), 'utf8'), 'target\n');
});

test('verified materialization restores official long SHA-512 opam cache names', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'context-relay-semgrep-sha512-link-'));
  t.after(() => rm(root, { force: true, recursive: true }));
  const bytes = Buffer.from('sha512-only archive\n');
  const sha512 = digest('sha512', bytes);
  const stored = `opam-repository/cache/sha512/${sha512.slice(0, 2)}/${sha512.slice(0, 64)}/${sha512.slice(64)}`;
  const official = `opam-repository/cache/sha512/${sha512.slice(0, 2)}/${sha512}`;
  await mkdir(join(root, ...stored.split('/').slice(0, -1)), { recursive: true });
  await writeFile(join(root, ...stored.split('/')), bytes);
  await writeFile(join(root, 'SYMLINKS.v1.json'), '{"links":[],"schemaVersion":1}\n');
  await writeFile(join(root, 'MANIFEST.sha256'), `${digest('sha256', bytes)}  ${stored}\n`);

  assert.equal(await materializeBundleLinks(root), 0);
  assert.deepEqual(await readFile(join(root, ...official.split('/'))), bytes);
});

test('verified materialization restores every declared opam checksum alias as a hard link', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'context-relay-semgrep-checksum-links-'));
  t.after(() => rm(root, { force: true, recursive: true }));
  const bytes = Buffer.from('mixed-checksum archive\n');
  const md5 = digest('md5', bytes);
  const sha256 = digest('sha256', bytes);
  const links = archiveCacheLinks({
    opam: {
      resolvedSourceArchives: [{
        package: 'fixture',
        version: '1',
        targets: ['aarch64-apple-darwin'],
        opamPath: 'packages/fixture/fixture.1/opam',
        opamSha256: '1'.repeat(64),
        licenses: ['MIT'],
        source: {
          checksums: [
            { algorithm: 'md5', digest: md5 },
            { algorithm: 'sha256', digest: sha256 },
          ],
          supplementalChecksums: [],
          mirrors: [],
          url: 'https://example.invalid/fixture.tar.gz',
        },
        extraSources: [],
      }],
    },
  });
  const stored = `opam-repository/cache/sha256/${sha256.slice(0, 2)}/${sha256}`;
  const alias = `opam-repository/cache/md5/${md5.slice(0, 2)}/${md5}`;
  assert.deepEqual(links, [{
    path: alias,
    target: `../../sha256/${sha256.slice(0, 2)}/${sha256}`,
  }]);
  await mkdir(join(root, ...stored.split('/').slice(0, -1)), { recursive: true });
  await writeFile(join(root, ...stored.split('/')), bytes);
  await writeFile(join(root, 'SYMLINKS.v1.json'), `${JSON.stringify({ links, schemaVersion: 1 })}\n`);
  await writeFile(join(root, 'MANIFEST.sha256'), `${sha256}  ${stored}\n`);

  assert.equal(await materializeBundleLinks(root), 1);
  assert.deepEqual(await readFile(join(root, ...alias.split('/'))), bytes);
  const [storedInfo, aliasInfo] = await Promise.all([
    lstat(join(root, ...stored.split('/'))),
    lstat(join(root, ...alias.split('/'))),
  ]);
  assert.equal(aliasInfo.isSymbolicLink(), false);
  assert.equal(aliasInfo.dev, storedInfo.dev);
  assert.equal(aliasInfo.ino, storedInfo.ino);
});

test('verified materialization restores USTAR-unrepresentable source paths', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'context-relay-semgrep-long-path-'));
  t.after(() => rm(root, { force: true, recursive: true }));
  const original = `sources/${'a'.repeat(70)}/${'b'.repeat(101)}/file`;
  const stored = `LONG_PATHS/${digest('sha256', Buffer.from(original))}`;
  const bytes = Buffer.from('long source path\n');
  await mkdir(join(root, 'LONG_PATHS'), { recursive: true });
  await writeFile(join(root, ...stored.split('/')), bytes);
  await writeFile(join(root, 'LONG_PATHS.v1.json'), `${JSON.stringify({ paths: [{ path: original, stored }], schemaVersion: 1 })}\n`);
  await writeFile(join(root, 'SYMLINKS.v1.json'), '{"links":[],"schemaVersion":1}\n');
  await writeFile(join(root, 'MANIFEST.sha256'), `${digest('sha256', bytes)}  ${stored}\n`);

  assert.equal(await materializeBundleLinks(root), 0);
  assert.deepEqual(await readFile(join(root, ...original.split('/'))), bytes);
});

test('public-source build scripts consume the verified bundle through closed native routes', async () => {
  const [mac, windows] = await Promise.all([
    readFile(new URL('../third_party/sidecars/semgrep/build-public-source-macos.sh', import.meta.url), 'utf8'),
    readFile(new URL('../third_party/sidecars/semgrep/build-public-source-windows.ps1', import.meta.url), 'utf8'),
  ]);
  for (const script of [mac, windows]) {
    assert.match(script, /bd614accba811b407ae5c9ec6f1eecd3bdc29911/);
    assert.match(script, /49933ea5288caeca8642d1e84afbd3f7d6820020/);
    assert.match(script, /v24\.14\.0/);
    assert.match(script, /--verify/);
    assert.match(script, /--materialize-links/);
    assert.match(script, /MANIFEST\.sha256/);
    assert.match(script, /build-a/);
    assert.match(script, /build-b/);
    assert.match(script, /python/i);
    assert.match(script, /3499e5708b0637c12d24d973dd103406a32b8fe8/);
    assert.match(script, /5\.3\.0\+semgrep-fork@/);
    assert.match(script, /ocamlc -version/);
    assert.match(script, /sourceLock\.opam\?\.compiler/);
    assert.doesNotMatch(script, /scripts[\\/]validate-compiler-sha\.sh/);
    assert.doesNotMatch(script, /(?:sed|patch)[^\r\n]*(?:configure|VERSION)/i);
    assert.doesNotMatch(script, /--inplace-build/);
    assert.doesNotMatch(script, /dev[\\/]required\.opam/);
    assert.doesNotMatch(script, /pypi|pysemgrep|dumpbin|cl\.exe|visual studio/i);
  }
  assert.match(mac, /Darwin/);
  assert.match(mac, /arm64/);
  assert.match(mac, /macos-15/);
  assert.doesNotMatch(mac, /macos-15-xlarge/);
  assert.match(mac, /a739c5405d73c42ef15a9dc995efc0f87396cc36/);
  assert.match(mac, /2\.5\.0/);
  assert.match(mac, /archive-mirrors=\[\\"\$ARCHIVE_MIRROR\\"\]/);
  assert.doesNotMatch(mac, /archive-mirrors=\$ARCHIVE_MIRROR/);
  assert.match(mac, /cp -RL "\$CURRENT\/bundle\/pins" "\$CURRENT\/pins"/);
  assert.match(mac, /test -z "\$\(find "\$CURRENT\/pins" -type l -print -quit\)"/);
  assert.match(mac, /HOMEBREW_NO_AUTO_UPDATE=1/);
  assert.match(mac, /brew list --versions/);
  assert.match(mac, /test -x \/usr\/bin\/curl-config/);
  assert.match(mac, /\/usr\/bin\/curl-config --libs/);
  for (const archive of ['libgmp.a', 'libpcre2-8.a', 'libdwarf.a', 'libzstd.a', 'libev.a']) {
    assert.match(mac, new RegExp(archive.replace('.', '\\.')));
  }
  assert.match(mac, /opam pin add --no-action "\$1" "\$CURRENT\/pins\/\$2"/);
  assert.match(mac, /git init --bare "\$compiler_git_dir"/);
  assert.match(mac, /prepare_compiler_identity "\$COMPILER_GIT_DIR" "\$COMPILER_REVISION"/);
  assert.match(mac, /GIT_DIR="\$COMPILER_GIT_DIR" opam install --update-invariant/);
  assert.equal((mac.match(/(?:^|\s)GIT_DIR=/g) ?? []).length, 1);
  assert.match(mac, /rsync file:\/\/\$CURRENT\/pins\/\$revision/);
  assert.doesNotMatch(mac, /opam pin add --no-action[^\n]+bundle\/pins/);
  assert.match(
    mac,
    /LWT_DISCOVER_ARGUMENTS='--use-libev true'/,
  );
  assert.match(mac, /LIBRARY_PATH="\$\(brew --prefix\)\/lib:\$\{LIBRARY_PATH:-\}"/);
  assert.match(
    mac,
    /opam install --locked --update-invariant --assume-depexts --deps-only \.\/semgrep\.opam/,
  );
  assert.match(
    mac,
    /opam install --locked --update-invariant --assume-depexts --deps-only \.\/semgrep\.opam[\s\S]+validate_compiler_identity "\$COMPILER_REVISION"/,
  );
  assert.match(mac, /otool/);
  assert.match(mac, /if ! otool -L[^\n]+>[^\n]+; then/);
  assert.doesNotMatch(mac, /otool -L[^\n]*\|/);
  assert.doesNotMatch(mac, /\$DESTINATION\/otool-L\.txt/);
  assert.match(mac, /rm "\$OTOOL_OUTPUT"/);
  assert.match(windows, /Cygwin/);
  assert.match(windows, /3e4c6ff8c9a04c9ec8f6f87701cd4b661b0f1f18/);
  assert.match(windows, /2\.5\.2/);
  assert.match(windows, /archive-mirrors=\["\{0\}"\]/);
  assert.doesNotMatch(windows, /archive-mirrors=\$CacheUri/);
  assert.match(
    windows,
    /\$CachePath = \(Join-Path \$Repository 'cache'\)\.Replace\('\\', '\/'\)/,
  );
  assert.match(windows, /\$CacheUri = "file:\/\/\$CachePath"/);
  assert.doesNotMatch(windows, /\$CacheUri = \(\[Uri\]/);
  assert.match(windows, /git init --bare "\$1"/);
  assert.match(windows, /\$GitDirForward = \[IO\.Path\]::GetFullPath\(\$GitDir\)\.Replace\('\\', '\/'\)/);
  assert.match(windows, /\$env:GIT_DIR = \$CompilerGitDirForward/);
  assert.doesNotMatch(windows, /\$GitDirPosix = \(& \$Cygpath -u/);
  assert.match(windows, /Remove-Item Env:GIT_DIR -ErrorAction SilentlyContinue/);
  assert.match(windows, /StartsWith\('file:\/\/'/);
  assert.match(windows, /\$ExpectedPinUrl = "file:\/\/\$ExpectedPinPath"/);
  assert.match(
    windows,
    /& \$Opam init --bare --no-setup --no-cygwin-setup default \$Repository/,
  );
  assert.match(
    windows,
    /& \$Opam switch create \$Switch --empty[^\r\n]*\r?\n\s*\$env:OPAMSWITCH = \$Switch/,
  );
  assert.match(
    windows,
    /& \$Opam install --locked --update-invariant --deps-only '\.\\semgrep\.opam' \} 'dependency installation'/,
  );
  assert.match(
    windows,
    /'dependency installation'\r?\n\s+Assert-CompilerIdentity \$CompilerRevision/,
  );
  assert.match(windows, /\[Environment\]::SystemDirectory/);
  assert.equal((windows.match(/& \$Tar /g) ?? []).length, 2);
  assert.doesNotMatch(windows, /& tar\.exe\b/i);
  assert.match(windows, /3\.6\.10/);
  assert.match(windows, /x86_64-w64-mingw32-(?:gcc|objdump)/);
});

test('native public-source builds smoke the literal closed scan template outside the runtime closure', async () => {
  const [mac, windows] = await Promise.all([
    readFile(new URL('../third_party/sidecars/semgrep/build-public-source-macos.sh', import.meta.url), 'utf8'),
    readFile(new URL('../third_party/sidecars/semgrep/build-public-source-windows.ps1', import.meta.url), 'utf8'),
  ]);
  const literalTemplate = [
    'scan',
    '--experimental',
    '--oss-only',
    '--metrics=off',
    '--disable-version-check',
    '--strict',
    '--error',
    '--json',
    '--quiet',
    '--no-git-ignore',
    '--x-ignore-semgrepignore-files',
    '--jobs=1',
    '--timeout=30',
    '--timeout-threshold=1',
    '--max-target-bytes=8388608',
    '--config',
  ];
  for (const [label, script, marker] of [
    ['macOS', mac, 'run_closed_scan()'],
    ['Windows', windows, '$ClosedScanArguments = @('],
  ]) {
    const route = script.slice(script.indexOf(marker));
    assert.notEqual(route, script.slice(-1), `${label} closed scan marker`);
    let offset = 0;
    for (const token of literalTemplate) {
      const next = route.indexOf(token, offset);
      assert.ok(next >= offset, `${label} closed scan token ${token}`);
      offset = next + token.length;
    }
    assert.match(route, /clean/i);
    assert.match(route, /finding/i);
    assert.match(route, /invalid/i);
    assert.match(route, /results[^\n]+(?:0|zero)/i);
    assert.match(route, /results[^\n]+(?:1|one)/i);
  }
  assert.match(mac, /EVIDENCE="\$OUTPUT_ROOT\/\$label-evidence"/);
  assert.match(windows, /\$Evidence = Join-Path \$OutputRoot "\$Label-evidence"/);
  assert.doesNotMatch(mac, /cp -R "\$OUTPUT_ROOT\/build-a" "\$OUTPUT_ROOT\/release"/);
  assert.doesNotMatch(windows, /Copy-Item[^\n]+build-a[^\n]+release[^\n]+-Recurse/);
  assert.match(mac, /sed 's#\^\\\.\/#\#'/);
  assert.match(windows, /\[Array\]::Sort\(\$RuntimeNames, \[StringComparer\]::Ordinal\)/);
  assert.match(mac, /INVALID_STATUS/);
  assert.match(mac, /INVALID_STATUS" -eq 1/);
  assert.match(windows, /\$InvalidStatus -eq 1/);
  for (const script of [mac, windows]) {
    assert.match(script, /invalid[^\n]+(?:parse|config|yaml)|(?:parse|config|yaml)[^\n]+invalid/i);
  }
  assert.match(windows, /\$ClosedEnvironment = \[ordered\]@\{/);
  assert.match(
    windows,
    /Get-ChildItem Env:[\s\S]+SetEnvironmentVariable\(\$Name, \$null, 'Process'\)/,
  );
  const closedEnvironment = windows.slice(
    windows.indexOf('$ClosedEnvironment = [ordered]@{'),
    windows.indexOf('try {', windows.indexOf('$ClosedEnvironment = [ordered]@{')),
  );
  for (const inheritedSecret of [
    'SEMGREP_APP_TOKEN',
    'PYTHONHOME',
    'PYTHONPATH',
    'GITHUB_TOKEN',
    'ACTIONS_ID_TOKEN_REQUEST_TOKEN',
    'AWS_SECRET_ACCESS_KEY',
  ]) {
    assert.doesNotMatch(closedEnvironment, new RegExp(inheritedSecret, 'i'));
  }
  for (const script of [mac, windows]) {
    assert.doesNotMatch(script, /(?:DESTINATION|Destination)[^\n]+smoke-fixtures/i);
  }
});

test('archive inventory deduplicates by strong digest and verifies every declared checksum', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'context-relay-semgrep-cache-'));
  t.after(() => rm(root, { force: true, recursive: true }));
  const bytes = Buffer.from('locked archive\n');
  const sha256 = digest('sha256', bytes);
  const sha512 = digest('sha512', bytes);
  const lock = {
    opam: {
      resolvedSourceArchives: [
        {
          package: 'one', version: '1', targets: ['windows-x86_64'], opamPath: 'packages/one/one.1/opam',
          opamSha256: 'a'.repeat(64), licenses: ['MIT'], extraSources: [],
          source: { url: 'https://example.invalid/source.tar', mirrors: [], supplementalChecksums: [], checksums: [
            { algorithm: 'sha256', digest: sha256 }, { algorithm: 'sha512', digest: sha512 },
          ] },
        },
        {
          package: 'two', version: '1', targets: ['aarch64-apple-darwin'], opamPath: 'packages/two/two.1/opam',
          opamSha256: 'b'.repeat(64), licenses: ['MIT'], source: null,
          extraSources: [{ name: 'source.tar', url: 'https://mirror.invalid/source.tar', mirrors: [], supplementalChecksums: [], checksums: [
            { algorithm: 'sha256', digest: sha256 }, { algorithm: 'sha512', digest: sha512 },
          ] }],
        },
      ],
    },
  };
  await mkdir(join(root, 'sha256'));
  await writeFile(join(root, 'sha256', sha256), bytes);

  assert.equal(flattenArchiveSources(lock).length, 1);
  const verified = await verifyArchiveCache(lock, root);
  assert.deepEqual(verified.map((entry) => entry.path), [`opam-repository/cache/sha256/${sha256.slice(0, 2)}/${sha256}`]);

  await writeFile(join(root, 'sha256', sha256), Buffer.from('drift'));
  await assert.rejects(() => verifyArchiveCache(lock, root), /checksum|sha/i);
});

test('sha512-only opam archives use their strongest declared digest as the cache key', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'context-relay-semgrep-cache-sha512-'));
  t.after(() => rm(root, { force: true, recursive: true }));
  const bytes = Buffer.from('sha512 archive\n');
  const sha512 = digest('sha512', bytes);
  const source = { url: 'https://example.invalid/a', mirrors: [], supplementalChecksums: [], checksums: [{ algorithm: 'sha512', digest: sha512 }] };
  const lock = { opam: { resolvedSourceArchives: [{ package: 'a', version: '1', targets: ['windows-x86_64'], opamPath: 'packages/a/a.1/opam', opamSha256: 'a'.repeat(64), licenses: ['MIT'], source, extraSources: [] }] } };
  await mkdir(join(root, 'sha512'));
  await writeFile(join(root, 'sha512', sha512), bytes);

  assert.deepEqual(flattenArchiveSources(lock).map(({ algorithm, digest }) => ({ algorithm, digest })), [{ algorithm: 'sha512', digest: sha512 }]);
  const verified = await verifyArchiveCache(lock, root);
  assert.equal(
    verified[0].path,
    `opam-repository/cache/sha512/${sha512.slice(0, 2)}/${sha512.slice(0, 64)}/${sha512.slice(64)}`,
  );
});

test('non-opam build archives are checksum-locked and bundled in the same offline cache', () => {
  const first = 'a'.repeat(64);
  const second = 'b'.repeat(64);
  const source = (digest) => ({ url: `https://example.invalid/${digest}`, mirrors: [], supplementalChecksums: [], checksums: [{ algorithm: 'sha256', digest }] });
  const lock = {
    additionalArchives: [{ id: 'tree-sitter-runtime-0.22.6', licenseSource: 'tree-sitter-runtime', purpose: 'native parser runtime', source: source(second) }],
    opam: { resolvedSourceArchives: [{
      package: 'a', version: '1', targets: ['windows-x86_64'], opamPath: 'packages/a/a.1/opam', opamSha256: 'c'.repeat(64), licenses: ['MIT'],
      source: source(first), extraSources: [],
    }] },
  };
  assert.deepEqual(flattenArchiveSources(lock).map(({ algorithm, digest }) => `${algorithm}:${digest}`), [
    `sha256:${first}`,
    `sha256:${second}`,
  ]);
});

test('archive cache rejects linked files or linked parent components', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'context-relay-semgrep-cache-link-'));
  const outside = await mkdtemp(join(tmpdir(), 'context-relay-semgrep-cache-outside-'));
  t.after(() => Promise.all([rm(root, { force: true, recursive: true }), rm(outside, { force: true, recursive: true })]));
  const bytes = Buffer.from('archive');
  const sha256 = digest('sha256', bytes);
  const source = { url: 'https://example.invalid/a', mirrors: [], supplementalChecksums: [], checksums: [{ algorithm: 'sha256', digest: sha256 }] };
  const lock = { opam: { resolvedSourceArchives: [{ package: 'a', version: '1', targets: ['windows-x86_64'], opamPath: 'packages/a/a.1/opam', opamSha256: 'a'.repeat(64), licenses: ['MIT'], source, extraSources: [] }] } };
  await writeFile(join(outside, sha256), bytes);
  try {
    await symlink(outside, join(root, 'sha256'), 'junction');
  } catch (error) {
    t.skip(`links unavailable: ${error.code}`);
    return;
  }
  await assert.rejects(() => verifyArchiveCache(lock, root), /link|regular/i);
});

test('archive fetch verifies before atomic persistence and reuses a valid cache', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'context-relay-semgrep-fetch-'));
  t.after(() => rm(root, { force: true, recursive: true }));
  const bytes = Buffer.from('downloaded archive\n');
  const sha256 = digest('sha256', bytes);
  const source = { url: 'https://example.invalid/archive.tar', mirrors: [], supplementalChecksums: [], checksums: [{ algorithm: 'sha256', digest: sha256 }] };
  const lock = { opam: { resolvedSourceArchives: [{ package: 'a', version: '1', targets: ['windows-x86_64'], opamPath: 'packages/a/a.1/opam', opamSha256: 'a'.repeat(64), licenses: ['MIT'], source, extraSources: [] }] } };
  let calls = 0;
  const fetchImpl = async (_url, options) => {
    calls += 1;
    assert.ok(options.signal instanceof AbortSignal);
    return new Response(bytes, { status: 200, headers: { 'content-length': String(bytes.length) } });
  };

  await fetchArchiveCache(lock, root, { fetchImpl });
  assert.deepEqual(await readFile(join(root, 'sha256', sha256)), bytes);
  await fetchArchiveCache(lock, root, { fetchImpl });
  assert.equal(calls, 1);

  await rm(join(root, 'sha256', sha256));
  await assert.rejects(
    () => fetchArchiveCache(lock, root, { fetchImpl: async () => new Response('drift', { status: 200 }) }),
    /checksum/i,
  );
  await assert.rejects(() => readFile(join(root, 'sha256', sha256)), /ENOENT/i);
});

test('archive fetch enforces one aggregate cache budget across downloads', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'context-relay-semgrep-fetch-cap-'));
  t.after(() => rm(root, { force: true, recursive: true }));
  const bytes = Buffer.from('aggregate budget');
  const sha256 = digest('sha256', bytes);
  const source = { url: 'https://example.invalid/archive', mirrors: [], supplementalChecksums: [], checksums: [{ algorithm: 'sha256', digest: sha256 }] };
  const lock = { opam: { resolvedSourceArchives: [{ package: 'a', version: '1', targets: ['windows-x86_64'], opamPath: 'packages/a/a.1/opam', opamSha256: 'a'.repeat(64), licenses: ['MIT'], source, extraSources: [] }] } };
  await assert.rejects(
    () => fetchArchiveCache(lock, root, {
      fetchImpl: async () => new Response(bytes, { status: 200 }),
      maxAggregateBytes: bytes.length - 1,
    }),
    /aggregate|budget|limit/i,
  );
  await assert.rejects(() => readFile(join(root, 'sha256', sha256)), /ENOENT/i);
});

test('archive fetch rejects an unsafe downgrade redirect', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'context-relay-semgrep-fetch-redirect-'));
  t.after(() => rm(root, { force: true, recursive: true }));
  const bytes = Buffer.from('archive');
  const sha256 = digest('sha256', bytes);
  const source = { url: 'https://example.invalid/archive', mirrors: [], supplementalChecksums: [], checksums: [{ algorithm: 'sha256', digest: sha256 }] };
  const lock = { opam: { resolvedSourceArchives: [{ package: 'a', version: '1', targets: ['windows-x86_64'], opamPath: 'packages/a/a.1/opam', opamSha256: 'a'.repeat(64), licenses: ['MIT'], source, extraSources: [] }] } };
  await assert.rejects(
    () => fetchArchiveCache(lock, root, { fetchImpl: async () => new Response(null, { status: 302, headers: { location: 'http://evil.invalid/archive' } }) }),
    /redirect|http|unsafe/i,
  );
});

test('git collector reads pinned blobs, ignores worktree drift, and records executable mode', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'context-relay-semgrep-git-'));
  t.after(() => rm(root, { force: true, recursive: true }));
  execFileSync('git', ['init', '-q', root]);
  execFileSync('git', ['-C', root, 'config', 'user.name', 'Context Relay']);
  execFileSync('git', ['-C', root, 'config', 'user.email', 'context-relay@example.invalid']);
  await writeFile(join(root, 'source.ml'), 'let answer = 42\n');
  await writeFile(join(root, 'build.sh'), '#!/bin/sh\n');
  await chmod(join(root, 'build.sh'), 0o755);
  execFileSync('git', ['-C', root, 'add', 'source.ml', 'build.sh']);
  execFileSync('git', ['-C', root, 'update-index', '--chmod=+x', 'build.sh']);
  execFileSync('git', ['-C', root, 'commit', '-qm', 'fixture']);
  await writeFile(join(root, 'untracked'), 'ignored\n');
  const revision = execFileSync('git', ['-C', root, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  const tree = execFileSync('git', ['-C', root, 'rev-parse', 'HEAD^{tree}'], { encoding: 'utf8' }).trim();

  const collected = await collectGitRepository({ expectedRevision: revision, expectedTree: tree, prefix: 'sources/fixture', root });
  assert.deepEqual(collected.entries.map((entry) => [entry.path, entry.executable]), [
    ['sources/fixture/build.sh', true],
    ['sources/fixture/source.ml', false],
  ]);
  assert.equal(collected.links.length, 0);
  await writeFile(join(root, 'source.ml'), 'dirty\n');
  const pinned = await collectGitRepository({ expectedRevision: revision, expectedTree: tree, prefix: 'sources/fixture', root });
  assert.equal(pinned.entries.find((entry) => entry.path.endsWith('/source.ml')).bytes.toString(), 'let answer = 42\n');
});

test('complete bundle includes recursive git, opam records, pins, archives, and exact lock deterministically', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'context-relay-semgrep-complete-'));
  t.after(() => rm(root, { force: true, recursive: true }));
  const gitIdentity = (path) => ({
    revision: execFileSync('git', ['-C', path, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(),
    tree: execFileSync('git', ['-C', path, 'rev-parse', 'HEAD^{tree}'], { encoding: 'utf8' }).trim(),
  });
  const init = async (path, files) => {
    await mkdir(path, { recursive: true });
    execFileSync('git', ['init', '-q', path]);
    execFileSync('git', ['-C', path, 'config', 'user.name', 'Context Relay']);
    execFileSync('git', ['-C', path, 'config', 'user.email', 'context-relay@example.invalid']);
    for (const [name, bytes] of Object.entries(files)) {
      await mkdir(join(path, ...name.split('/').slice(0, -1)), { recursive: true });
      await writeFile(join(path, ...name.split('/')), bytes);
    }
    execFileSync('git', ['-C', path, 'add', '.']);
    execFileSync('git', ['-C', path, 'commit', '-qm', 'fixture']);
    return gitIdentity(path);
  };
  const subRoot = join(root, 'sub');
  const sub = await init(subRoot, { 'sub.ml': 'let sub = true\n' });
  const semgrepRoot = join(root, 'semgrep');
  const license = Buffer.from('MIT license\n');
  await init(semgrepRoot, { LICENSE: license, 'main.ml': 'let main = true\n' });
  execFileSync('git', ['-C', semgrepRoot, '-c', 'protocol.file.allow=always', 'submodule', 'add', '-q', subRoot, 'deps/sub']);
  execFileSync('git', ['-C', semgrepRoot, 'commit', '-qam', 'submodule']);
  const semgrep = gitIdentity(semgrepRoot);
  const opamRoot = join(root, 'opam');
  const opam = await init(opamRoot, {
    repo: 'opam-version: "2.0"\n',
    'packages/a/a.1/files/fix.patch': 'patch\n',
    'packages/a/a.1/opam': 'opam-version: "2.0"\n',
  });
  const pinRoot = join(root, 'pins');
  const pinWork = join(root, 'pin-work');
  const pin = await init(pinWork, { LICENSE: license, 'pin.ml': 'let pin = true\n' });
  await mkdir(pinRoot);
  await rename(pinWork, join(pinRoot, pin.revision));
  const archive = Buffer.from('locked archive\n');
  const archiveSha256 = digest('sha256', archive);
  const cacheRoot = join(root, 'cache');
  await mkdir(join(cacheRoot, 'sha256'), { recursive: true });
  await writeFile(join(cacheRoot, 'sha256', archiveSha256), archive);
  const sourceLockPath = join(root, 'source-lock.v1.json');
  const lock = {
    schemaVersion: 1,
    sourceRevision: semgrep.revision,
    sourceTree: semgrep.tree,
    recursiveInventoryComplete: true,
    rootGitlinks: [{ path: 'deps/sub', revision: sub.revision }],
    licenseMaterials: [{
      source: 'fixture-pin', kind: 'license', spdx: 'MIT',
      path: `pins/${pin.revision}/LICENSE`, sha256: digest('sha256', license),
    }, {
      source: 'semgrep', kind: 'license', spdx: 'MIT',
      path: 'sources/semgrep/LICENSE', sha256: digest('sha256', license),
    }],
    opam: {
      repository: { url: 'https://example.invalid/opam', revision: opam.revision },
      compiler: { package: 'ocaml-variants.5.3.0', licenseSource: 'fixture-pin', url: 'https://example.invalid/compiler', revision: pin.revision },
      pinDepends: [],
      resolvedSourceArchives: [{
        package: 'a', version: '1', targets: ['windows-x86_64'], opamPath: 'packages/a/a.1/opam',
        opamSha256: digest('sha256', Buffer.from('opam-version: "2.0"\n')), licenses: ['MIT'], extraSources: [],
        source: { url: 'https://example.invalid/archive', mirrors: [], supplementalChecksums: [], checksums: [{ algorithm: 'sha256', digest: archiveSha256 }] },
      }],
    },
  };
  await writeFile(sourceLockPath, `${JSON.stringify(lock, null, 2)}\n`);
  const first = join(root, 'first.tar');
  const second = join(root, 'second.tar');
  const options = { archiveCacheRoot: cacheRoot, opamRoot, pinRoot, semgrepRoot, sourceLockPath, supportPaths: [], supportRoot: root };

  await buildSemgrepSourceBundle({ ...options, outputPath: first });
  await buildSemgrepSourceBundle({ ...options, outputPath: second });
  assert.deepEqual(await readFile(first), await readFile(second));
  const verified = await verifySemgrepSourceBundle({ bundlePath: first, sourceLockPath });
  for (const path of [
    'sources/semgrep/main.ml',
    'sources/semgrep/deps/sub/sub.ml',
    'opam-repository/packages/a/a.1/files/fix.patch',
    `pins/${pin.revision}/pin.ml`,
    `opam-repository/cache/sha256/${archiveSha256.slice(0, 2)}/${archiveSha256}`,
    'metadata/source-lock.v1.json',
  ]) assert.ok(verified.paths.includes(path), path);

  const evidencePath = join(root, 'bundle-evidence.v1.json');
  const evidence = {
    bundle: {
      payloadEntries: verified.payloadEntries,
      recordedLinks: verified.links,
      sha256: verified.sha256,
      size: verified.size,
    },
    bundleGeneratorSha256: digest('sha256', await readFile(new URL('./semgrep-source-bundle.mjs', import.meta.url))),
    byteIdentical: true,
    format: 'context-relay-semgrep-source-v1',
    independentBuilds: 2,
    schemaVersion: 1,
    sourceAssetUrl: 'https://github.com/Skytuhua/Context-Relay/releases/download/sidecars-semgrep-1.170.0-source.1/semgrep-1.170.0-corresponding-source.tar',
    sourceLockSha256: digest('sha256', await readFile(sourceLockPath)),
    status: 'source_bundle_reproducible_native_builds_pending',
  };
  await writeFile(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`);
  assert.equal(
    (await verifyBundleEvidence({ bundlePath: first, evidencePath, sourceLockPath })).sha256,
    verified.sha256,
  );
  evidence.status = 'complete_corresponding_source';
  await writeFile(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`);
  assert.equal(
    (await verifyBundleEvidence({ bundlePath: first, evidencePath, sourceLockPath })).sha256,
    verified.sha256,
  );
  evidence.sourceAssetUrl = 'http://example.invalid/source.tar';
  await writeFile(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`);
  await assert.rejects(
    () => verifyBundleEvidence({ bundlePath: first, evidencePath, sourceLockPath }),
    /source asset|https|url/i,
  );
  evidence.sourceAssetUrl = 'https://github.com/Skytuhua/Context-Relay/releases/download/sidecars-semgrep-1.170.0-source.1/semgrep-1.170.0-corresponding-source.tar';
  evidence.status = 'source_bundle_reproducible_native_builds_pending';
  evidence.bundle.size += 512;
  await writeFile(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`);
  await assert.rejects(
    () => verifyBundleEvidence({ bundlePath: first, evidencePath, sourceLockPath }),
    /evidence.*bundle|bundle.*evidence|size/i,
  );
});
