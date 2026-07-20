import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { link, lstat, mkdtemp, readFile, rm, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  buildDeterministicTar,
  verifyDeterministicTar,
} from './semgrep-source-bundle.mjs';
import {
  assertResealMetadataDigest,
  publishResealedBundle,
  resealSemgrepSourceBundle,
} from './reseal-semgrep-source-bundle.mjs';

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'context-relay-reseal-'));
  const input = join(root, 'input.tar');
  await buildDeterministicTar({
    entries: [
      {
        bytes: Buffer.from('{"completeCorrespondingSource":false}\n'),
        executable: false,
        path: 'metadata/source-lock.v1.json',
      },
      {
        bytes: Buffer.from('#!/bin/sh\nexit 0\n'),
        executable: true,
        path: 'support/build.sh',
      },
      {
        bytes: Buffer.from('source\n'),
        executable: false,
        path: 'sources/semgrep/main.ml',
      },
    ],
    outputPath: input,
  });
  return { input, root };
}

test('reseal streams one verified bundle into a deterministic final bundle', async () => {
  const { input, root } = await fixture();
  try {
    const sourceLock = Buffer.from('{"completeCorrespondingSource":true}\n');
    const nativeEvidence = Buffer.from('{"schemaVersion":1,"status":"native_builds_verified"}\n');
    const first = join(root, 'first.tar');
    const second = join(root, 'second.tar');
    const arguments_ = {
      additions: [
        {
          bytes: nativeEvidence,
          executable: false,
          path: 'support/third_party/sidecars/semgrep/native-build-evidence.v1.json',
        },
      ],
      inputPath: input,
      replacements: [
        {
          bytes: sourceLock,
          executable: false,
          path: 'metadata/source-lock.v1.json',
        },
      ],
    };

    const a = await resealSemgrepSourceBundle({ ...arguments_, outputPath: first });
    const b = await resealSemgrepSourceBundle({ ...arguments_, outputPath: second });
    assert.deepEqual(a, b);
    assert.deepEqual(await readFile(first), await readFile(second));

    const verified = await verifyDeterministicTar(first);
    assert.equal(verified.digests['metadata/source-lock.v1.json'], sha256(sourceLock));
    assert.equal(
      verified.digests['support/third_party/sidecars/semgrep/native-build-evidence.v1.json'],
      sha256(nativeEvidence),
    );
    assert.equal(verified.digests['sources/semgrep/main.ml'], sha256(Buffer.from('source\n')));
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});

test('a no-op reseal is byte-identical to the bound deterministic generator', async () => {
  const { input, root } = await fixture();
  try {
    const output = join(root, 'output.tar');
    await resealSemgrepSourceBundle({ inputPath: input, outputPath: output });
    assert.deepEqual(await readFile(output), await readFile(input));
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});

test('reseal rejects generated metadata, aliases, and an existing output', async () => {
  const { input, root } = await fixture();
  try {
    const output = join(root, 'output.tar');
    await assert.rejects(
      resealSemgrepSourceBundle({
        additions: [{ bytes: Buffer.from('bad'), executable: false, path: 'MANIFEST.sha256' }],
        inputPath: input,
        outputPath: output,
      }),
      /generated metadata/i,
    );
    await assert.rejects(
      resealSemgrepSourceBundle({
        additions: [{ bytes: Buffer.from('bad'), executable: false, path: 'manifest.sha256' }],
        inputPath: input,
        outputPath: output,
      }),
      /generated metadata|collision/i,
    );
    await assert.rejects(
      resealSemgrepSourceBundle({
        additions: [{ bytes: Buffer.from('bad'), executable: false, path: 'LONG_PATHS.v1.json/child' }],
        inputPath: input,
        outputPath: output,
      }),
      /generated metadata|collision/i,
    );
    await assert.rejects(
      resealSemgrepSourceBundle({
        additions: [{ bytes: Buffer.from('bad'), executable: false, path: 'SOURCES\/SEMGREP\/MAIN.ML' }],
        inputPath: input,
        outputPath: output,
      }),
      /collision/i,
    );
    await writeFile(output, 'keep');
    await assert.rejects(
      resealSemgrepSourceBundle({ inputPath: input, outputPath: output }),
      /exist/i,
    );
    assert.equal(await readFile(output, 'utf8'), 'keep');
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});

test('reseal rejects additions that shadow files, links, or long logical paths', async () => {
  const root = await mkdtemp(join(tmpdir(), 'context-relay-reseal-topology-'));
  const input = join(root, 'input.tar');
  const longPath = `sources/${'long-segment/'.repeat(20)}source.ml`;
  try {
    await buildDeterministicTar({
      entries: [
        { bytes: Buffer.from('target\n'), executable: false, path: 'sources/target.txt' },
        { bytes: Buffer.from('long\n'), executable: false, path: longPath },
      ],
      links: [{ path: 'sources/current', target: 'target.txt' }],
      outputPath: input,
    });
    for (const path of [
      'sources',
      'sources/current/child',
      longPath.slice(0, longPath.indexOf('/', 'sources/'.length + 1)),
    ]) {
      await assert.rejects(
        resealSemgrepSourceBundle({
          additions: [{ bytes: Buffer.from('bad'), executable: false, path }],
          inputPath: input,
          outputPath: join(root, `${sha256(Buffer.from(path))}.tar`),
        }),
        /collision|ancestor|descendant/i,
        path,
      );
    }
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});

test('reseal never removes a pre-existing predictable temporary-path file', async () => {
  const { input, root } = await fixture();
  const originalNow = Date.now;
  try {
    Date.now = () => 123456789;
    const output = join(root, 'output.tar');
    const trap = join(root, `.output.tar.${process.pid}.${Date.now()}.tmp`);
    await writeFile(trap, 'keep');
    await resealSemgrepSourceBundle({ inputPath: input, outputPath: output });
    assert.equal(await readFile(trap, 'utf8'), 'keep');
  } finally {
    Date.now = originalNow;
    await rm(root, { force: true, recursive: true });
  }
});

test('logical collision metadata is bound to the verified input digest', () => {
  const original = Buffer.from('{"links":[],"schemaVersion":1}\n');
  assert.doesNotThrow(() => assertResealMetadataDigest(original, sha256(original), 'SYMLINKS.v1.json'));
  assert.throws(
    () => assertResealMetadataDigest(
      Buffer.from('{"links":[{"path":"alias","target":"target"}],"schemaVersion":1}\n'),
      sha256(original),
      'SYMLINKS.v1.json',
    ),
    /changed/i,
  );
});

test('a temporary-link cleanup failure removes the owned unpublished output', async () => {
  const root = await mkdtemp(join(tmpdir(), 'context-relay-reseal-publish-'));
  const temporary = join(root, 'temporary.tar');
  const output = join(root, 'output.tar');
  try {
    await writeFile(temporary, 'sealed');
    const identity = await lstat(temporary);
    await assert.rejects(
      publishResealedBundle(temporary, output, identity, {
        link,
        lstat,
        unlink: async (path) => {
          if (path === temporary) throw new Error('injected temporary unlink failure');
          return unlink(path);
        },
      }),
      /injected temporary unlink failure/,
    );
    await assert.rejects(lstat(output), /ENOENT/);
    assert.equal(await readFile(temporary, 'utf8'), 'sealed');
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});

test('reseal fails closed before copying a corrupted source bundle', async () => {
  const { input, root } = await fixture();
  try {
    const bytes = await readFile(input);
    bytes[700] ^= 1;
    await writeFile(input, bytes);
    const output = join(root, 'output.tar');
    await assert.rejects(
      resealSemgrepSourceBundle({ inputPath: input, outputPath: output }),
      /bundle|manifest|checksum|padding/i,
    );
    await assert.rejects(readFile(output), /ENOENT/);
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}
