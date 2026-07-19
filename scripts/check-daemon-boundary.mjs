import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { relative, resolve } from 'node:path';

const PROTECTED_ROOTS = [
  'context-relay-local-ipc',
  'context-relay-context-mcp',
  'context-relay-desktop',
];
const CLIENT_ROOTS = [
  'context-relay-context-mcp',
  'context-relay-desktop',
];
const FORBIDDEN_PACKAGES = new Set([
  'context-relay-core',
  'rusqlite',
  'libsqlite3-sys',
  'fastembed',
]);

export function findForbiddenPath(metadata, rootPackage, forbiddenNames) {
  const packages = new Map(metadata.packages.map(({ id, name }) => [id, name]));
  const root = metadata.packages.find(({ name }) => name === rootPackage);
  if (!root) throw new Error('missing Cargo package: ' + rootPackage);

  const dependencies = new Map(
    metadata.resolve.nodes.map(({ id, deps }) => [
      id,
      deps.map(({ pkg }) => pkg),
    ]),
  );
  const queue = [[root.id, [rootPackage]]];
  const visited = new Set([root.id]);

  for (let index = 0; index < queue.length; index += 1) {
    const [id, path] = queue[index];
    for (const dependency of dependencies.get(id) ?? []) {
      const name = packages.get(dependency);
      const nextPath = [...path, name];
      if (forbiddenNames.has(name)) return nextPath;
      if (!visited.has(dependency)) {
        visited.add(dependency);
        queue.push([dependency, nextPath]);
      }
    }
  }

  return null;
}

function directDependencies(metadata, rootPackage) {
  const packages = new Map(metadata.packages.map(({ id, name }) => [id, name]));
  const root = metadata.packages.find(({ name }) => name === rootPackage);
  if (!root) throw new Error('missing Cargo package: ' + rootPackage);
  const node = metadata.resolve.nodes.find(({ id }) => id === root.id);
  if (!node) throw new Error('missing Cargo resolve node: ' + rootPackage);
  return new Set(node.deps.map(({ pkg }) => packages.get(pkg)));
}

export function checkMetadata(metadata) {
  const violations = PROTECTED_ROOTS
    .map((root) => findForbiddenPath(metadata, root, FORBIDDEN_PACKAGES))
    .filter((path) => path !== null)
    .map((path) => 'forbidden dependency path: ' + path.join(' -> '));

  for (const root of CLIENT_ROOTS) {
    const direct = directDependencies(metadata, root);
    if (!direct.has('context-relay-local-ipc')) {
      violations.push(root + ' must directly depend on context-relay-local-ipc');
    }
    if (direct.has('keyring')) {
      violations.push(root + ' must not directly depend on keyring');
    }
  }
  return violations;
}

export function findInstallationTokenWriterViolations(sources) {
  let contextdWriter = false;
  const violations = [];
  for (const [path, source] of Object.entries(sources)) {
    const writesToken =
      source.includes('.set_secret(') &&
      (source.includes('INSTALLATION_TOKEN_CREDENTIAL_ACCOUNT') ||
        source.includes('installation-token-v1'));
    if (!writesToken) continue;
    const normalized = path.split(String.fromCharCode(92)).join('/');
    if (normalized.startsWith('crates/contextd/')) {
      contextdWriter = true;
    } else {
      violations.push(
        'installation-token credential writer outside contextd: ' + normalized,
      );
    }
  }
  if (!contextdWriter) {
    violations.push('missing contextd installation-token credential writer');
  }
  return violations;
}

function rustSources(workspace) {
  const sources = {};
  const visit = (directory) => {
    if (!existsSync(directory)) return;
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = resolve(directory, entry.name);
      if (entry.isDirectory()) visit(path);
      else if (entry.isFile() && path.endsWith('.rs')) {
        const normalized = relative(workspace, path)
          .split(String.fromCharCode(92))
          .join('/');
        sources[normalized] = readFileSync(path, 'utf8');
      }
    }
  };
  visit(resolve(workspace, 'crates'));
  visit(resolve(workspace, 'apps', 'desktop', 'src-tauri', 'src'));
  return sources;
}

export function checkWorkspace(workspace = resolve(import.meta.dirname, '..')) {
  const cargo = spawnSync('cargo', ['metadata', '--format-version', '1'], {
    cwd: workspace,
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
  });
  if (cargo.status !== 0) throw new Error(cargo.stderr);

  return [
    ...checkMetadata(JSON.parse(cargo.stdout)),
    ...findInstallationTokenWriterViolations(rustSources(workspace)),
  ];
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(import.meta.filename)) {
  const violations = checkWorkspace();
  for (const violation of violations) console.error(violation);
  if (violations.length > 0) process.exitCode = 1;
}
