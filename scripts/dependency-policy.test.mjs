import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const desktopPackageUrl = new URL('../apps/desktop/package.json', import.meta.url);
const lockfileUrl = new URL('../pnpm-lock.yaml', import.meta.url);
const workspaceUrl = new URL('../pnpm-workspace.yaml', import.meta.url);

test('Node dependency floor excludes every open patched advisory', async () => {
  const desktop = JSON.parse(await readFile(desktopPackageUrl, 'utf8'));
  const lockfile = await readFile(lockfileUrl, 'utf8');
  const workspace = await readFile(workspaceUrl, 'utf8');
  const resolvedLockfile = lockfile.slice(lockfile.indexOf('\npackages:\n'));

  assert.equal(desktop.devDependencies.ajv, '8.18.0');
  assert.equal(desktop.devDependencies.vite, '7.3.5');
  assert.equal(desktop.devDependencies.vitest, '3.2.6');
  assert.match(
    workspace,
    /overrides:\n  'brace-expansion@1\.1\.16': '1\.1\.18'\n  'brace-expansion@2\.1\.2': '2\.1\.4'\n  'esbuild@0\.27\.7': '0\.28\.1'\n  'fast-uri@3\.1\.3': '3\.1\.5'\n  'js-yaml@4\.3\.0': '4\.3\.1'\n  'nanoid@3\.3\.16': '3\.3\.18'\n  'postcss@8\.5\.19': '8\.5\.23'/,
  );

  for (const fixed of [
    'ajv@8.18.0',
    'brace-expansion@1.1.18',
    'brace-expansion@2.1.4',
    'esbuild@0.28.1',
    'fast-uri@3.1.5',
    'js-yaml@4.3.1',
    'nanoid@3.3.18',
    'postcss@8.5.23',
    'vite@7.3.5',
    'vitest@3.2.6',
  ]) {
    assert.ok(
      lockfile.includes(`\n  ${fixed}:`) || lockfile.includes(`\n  '${fixed}':`),
      `lockfile is missing ${fixed}`,
    );
  }

  assert.doesNotMatch(
    resolvedLockfile,
    /(?:ajv@8\.17\.1|brace-expansion@1\.1\.1[0-7]|brace-expansion@2\.1\.[0-3]|esbuild@0\.27\.|fast-uri@3\.1\.[0-4]|js-yaml@4\.[0-2]\.|js-yaml@4\.3\.0|nanoid@3\.3\.(?:[0-9]|1[0-7])|postcss@8\.5\.(?:[0-9]|1[0-9]|2[0-2])|vite@7\.[0-2]\.|vite@7\.3\.[0-4]|vitest@3\.2\.[0-5])(?=:|\()/,
  );
});
