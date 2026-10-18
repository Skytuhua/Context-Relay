import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const desktopPackageUrl = new URL('../apps/desktop/package.json', import.meta.url);
const lockfileUrl = new URL('../pnpm-lock.yaml', import.meta.url);
const workspaceUrl = new URL('../pnpm-workspace.yaml', import.meta.url);

// The overrides block is pinned line for line on purpose: it is the record of
// which advisory forced each floor. Add a comment to pnpm-workspace.yaml and
// this regex stops matching, so document a new floor here instead.
test('Node dependency floor excludes every open patched advisory', async () => {
  const desktop = JSON.parse(await readFile(desktopPackageUrl, 'utf8'));
  const lockfile = await readFile(lockfileUrl, 'utf8');
  const workspace = await readFile(workspaceUrl, 'utf8');
  const resolvedLockfile = lockfile.slice(lockfile.indexOf('\npackages:\n'));

  assert.equal(desktop.devDependencies.ajv, '8.18.0');
  assert.equal(desktop.devDependencies.vite, '7.3.5');
  assert.equal(desktop.devDependencies.vitest, '4.1.11');
  // This release removes fast-glob -> micromatch -> unpatched braces.
  assert.equal(desktop.devDependencies['typescript-eslint'], '8.71.2');
  assert.match(
    workspace,
    /overrides:\n  'brace-expansion@>=1\.0\.0 <1\.1\.21': '1\.1\.21'\n  'brace-expansion@>=2\.0\.0 <2\.1\.7': '2\.1\.7'\n  'esbuild@0\.27\.7': '0\.28\.1'\n  'browserslist@4\.28\.6': '4\.28\.7'\n  'fast-uri@3\.1\.3': '3\.1\.8'\n  'js-yaml@4\.3\.0': '4\.3\.2'\n  'nanoid@3\.3\.16': '3\.3\.18'\n  'postcss@8\.5\.19': '8\.5\.23'\n  'source-map-js@<1\.2\.2': '1\.2\.2'/,
  );

  for (const fixed of [
    'ajv@8.18.0',
    'browserslist@4.28.7',
    'brace-expansion@1.1.21',
    'esbuild@0.28.1',
    'fast-uri@3.1.8',
    'js-yaml@4.3.2',
    'nanoid@3.3.18',
    'postcss@8.5.23',
    'source-map-js@1.2.2',
    'vite@7.3.5',
    'vitest@4.1.11',
    '@vitest/mocker@4.1.11',
  ]) {
    assert.ok(
      lockfile.includes(`\n  ${fixed}:`) || lockfile.includes(`\n  '${fixed}':`),
      `lockfile is missing ${fixed}`,
    );
  }

  assert.doesNotMatch(
    resolvedLockfile,
    /(?:ajv@8\.17\.1|brace-expansion@1\.(?:0\.\d+|1\.(?:[0-9]|1[0-9]|20))|brace-expansion@2\.(?:0\.\d+|1\.[0-6])|braces@(?:[0-2]\.\d+\.\d+|3\.0\.[0-3])|esbuild@0\.27\.\d+|fast-uri@3\.1\.[0-7]|js-yaml@4\.[0-2]\.\d+|js-yaml@4\.3\.[01]|nanoid@3\.3\.(?:[0-9]|1[0-7])|postcss@8\.5\.(?:[0-9]|1[0-9]|2[0-2])|source-map-js@(?:0\.\d+\.\d+|1\.[01]\.\d+|1\.2\.[01])|vite@7\.[0-2]\.\d+|vite@7\.3\.[0-4]|vitest@3\.2\.[0-5])(?=:|\()/,
  );
});
