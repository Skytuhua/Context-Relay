import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  collectBundledFiles,
  LICENSE,
  REPOSITORY,
  validateBundledFileInventory,
  validateMetadata,
} from './check-license-metadata.mjs';

test('accepts canonical first-party metadata', () => {
  assert.doesNotThrow(() =>
    validateMetadata([{ name: 'context-relay', license: LICENSE, repository: REPOSITORY }]),
  );
});

test('rejects missing or unknown first-party license metadata', () => {
  assert.throws(() => validateMetadata([{ name: 'missing' }]));
  assert.throws(() =>
    validateMetadata([{ name: 'unknown', license: 'Proprietary', repository: REPOSITORY }]),
  );
});

test('bundled third-party inventory rejects unaccounted executables and license files', () => {
  const accounted = new Set([
    'third_party/sidecars/licenses/rulesync-MIT.txt',
    'target/sidecars/windows/rulesync.exe',
  ]);
  assert.doesNotThrow(() => validateBundledFileInventory([...accounted], accounted));
  assert.throws(
    () => validateBundledFileInventory(['target/sidecars/windows/stray.exe'], new Set()),
    /unaccounted.*stray\.exe/i,
  );
  assert.throws(
    () => validateBundledFileInventory(['third_party/sidecars/licenses/stray.txt'], new Set()),
    /unaccounted.*stray\.txt/i,
  );
});

test('bundled inventory scans extensionless and executable files everywhere under sidecars', async (t) => {
  const workspace = await mkdtemp(join(tmpdir(), 'context-relay-license-inventory-'));
  t.after(() => rm(workspace, { recursive: true, force: true }));
  await mkdir(join(workspace, 'third_party/sidecars/unexpected'), { recursive: true });
  await mkdir(join(workspace, 'target/sidecars/windows/digest/tool'), { recursive: true });
  await writeFile(join(workspace, 'third_party/sidecars/unexpected/binary'), 'binary');
  await writeFile(join(workspace, 'third_party/sidecars/unexpected/tool.exe'), 'binary');
  await writeFile(join(workspace, 'target/sidecars/windows/digest/tool/tool.exe'), 'binary');

  const files = collectBundledFiles(workspace);
  assert.deepEqual(files, [
    'target/sidecars/windows/digest/tool/tool.exe',
    'third_party/sidecars/unexpected/binary',
    'third_party/sidecars/unexpected/tool.exe',
  ]);
  assert.throws(() => validateBundledFileInventory(files, new Set()), /unaccounted/i);
});
