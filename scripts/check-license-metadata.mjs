import { globSync, lstatSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { relative } from 'node:path';

import {
  loadSidecarManifest,
  validateManifestMaterials,
} from './hydrate-sidecars.mjs';

export const LICENSE = 'Apache-2.0';
export const REPOSITORY = 'https://github.com/Skytuhua/Context-Relay';

export function validateMetadata(packages) {
  for (const packageMetadata of packages) {
    if (packageMetadata.license !== LICENSE || packageMetadata.repository !== REPOSITORY) {
      throw new Error(`${packageMetadata.name ?? 'unknown package'} must declare ${LICENSE} and ${REPOSITORY}`);
    }
  }
}

export function validateBundledFileInventory(files, accounted) {
  for (const file of files) {
    const normalized = file.replaceAll('\\', '/');
    if (!accounted.has(normalized)) throw new Error(`unaccounted bundled binary/license: ${normalized}`);
  }
}

export function collectBundledFiles(workspace) {
  return globSync('{third_party/sidecars/**/*,target/sidecars/**/*}', {
    cwd: workspace,
    dot: true,
  })
    .filter((file) => !lstatSync(resolve(workspace, file)).isDirectory())
    .map((file) => relative(workspace, resolve(workspace, file)).replaceAll('\\', '/'))
    .sort();
}

function accountedBundledFiles(manifest, manifestDigest) {
  const accounted = new Set(['third_party/sidecars/manifest.v1.json']);
  for (const tool of manifest.tools) {
    accounted.add(tool.source.materialPath);
    accounted.add(tool.license.path);
    if (tool.relinking) accounted.add(tool.relinking.path);
    for (const material of tool.materials) accounted.add(material.path);
    for (const target of tool.targets.filter((entry) => entry.enabled)) {
      for (const entry of target.closure) {
        accounted.add(
          `target/sidecars/${target.target}/${manifestDigest}/${tool.id}/${entry.path}`,
        );
      }
    }
  }
  return accounted;
}

export async function checkWorkspace(workspace = resolve(import.meta.dirname, '..')) {
  const packageFiles = globSync('**/package.json', {
    cwd: workspace,
    exclude: ['**/node_modules/**', '**/target/**', '**/.pnpm-store/**'],
  });
  validateMetadata(packageFiles.map((file) => JSON.parse(readFileSync(resolve(workspace, file), 'utf8'))));

  const cargo = spawnSync('cargo', ['metadata', '--format-version', '1', '--no-deps'], {
    cwd: workspace,
    encoding: 'utf8',
  });
  if (cargo.status !== 0) throw new Error(cargo.stderr);
  validateMetadata(JSON.parse(cargo.stdout).packages);

  const manifestPath = resolve(workspace, 'third_party/sidecars/manifest.v1.json');
  const manifest = await loadSidecarManifest(manifestPath);
  await validateManifestMaterials(manifest, workspace);
  const manifestDigest = createHash('sha256').update(readFileSync(manifestPath)).digest('hex');
  validateBundledFileInventory(
    collectBundledFiles(workspace),
    accountedBundledFiles(manifest, manifestDigest),
  );
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(import.meta.filename)) {
  await checkWorkspace();
}
