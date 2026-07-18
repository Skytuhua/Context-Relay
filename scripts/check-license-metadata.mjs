import { globSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

export const LICENSE = 'Apache-2.0';
export const REPOSITORY = 'https://github.com/Skytuhua/Context-Relay';

export function validateMetadata(packages) {
  for (const packageMetadata of packages) {
    if (packageMetadata.license !== LICENSE || packageMetadata.repository !== REPOSITORY) {
      throw new Error(`${packageMetadata.name ?? 'unknown package'} must declare ${LICENSE} and ${REPOSITORY}`);
    }
  }
}

export function checkWorkspace(workspace = resolve(import.meta.dirname, '..')) {
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
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(import.meta.filename)) {
  checkWorkspace();
}
