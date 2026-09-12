import { execFileSync } from 'node:child_process';
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { stageSearchResources } from './search-resources.mjs';

const target = 'aarch64-apple-darwin';
const workspace = fileURLToPath(new URL('../', import.meta.url));
const companions = ['context-relay-contextd', 'context-relay-context-mcp', 'context-relay-native-helper', 'context-relay-sidecar-installer'];

function validateExecutable(bytes, name) {
  const invalid = () => { throw new Error(`${name}: invalid thin arm64 Mach-O executable`); };
  if (bytes.length < 32 || bytes.readUInt32LE(0) !== 0xfeedfacf
      || bytes.readUInt32LE(4) !== 0x0100000c || bytes.readUInt32LE(12) !== 2) invalid();
  const count = bytes.readUInt32LE(16);
  const end = 32 + bytes.readUInt32LE(20);
  if (!count || end > bytes.length || count > (end - 32) / 8) invalid();
  let offset = 32;
  for (let i = 0; i < count; i++) {
    if (offset + 8 > end) invalid();
    const size = bytes.readUInt32LE(offset + 4);
    if (size < 8 || size % 8 !== 0 || offset + size > end) invalid();
    offset += size;
  }
  if (offset !== end) invalid();
}

export async function stageMacCompanions({ sourceDirectory, stagingDirectory }) {
  // Validate the complete set before changing output; write the verified bytes.
  const files = [];
  for (const name of companions) {
    const bytes = await readFile(join(sourceDirectory, name));
    validateExecutable(bytes, name);
    files.push({ name, bytes });
  }
  await mkdir(stagingDirectory, { recursive: true });
  for (const { name, bytes } of files) {
    const path = join(stagingDirectory, `${name}-${target}`);
    await writeFile(path, bytes, { mode: 0o755 });
    await chmod(path, 0o755);
  }
}

async function main() {
  if (process.argv.length !== 2) throw new Error('package:macos takes no arguments');
  if (process.platform !== 'darwin' || process.arch !== 'arm64') {
    throw new Error('package:macos requires an arm64 macOS host and its native toolchain');
  }
  const identity = process.env.CONTEXT_RELAY_MACOS_SIGNING_IDENTITY;
  if (!identity || (identity !== '-' && !identity.startsWith('Developer ID Application:'))) {
    throw new Error('Set CONTEXT_RELAY_MACOS_SIGNING_IDENTITY to a Developer ID Application identity or explicit internal candidate -');
  }
  const desktop = join(workspace, 'apps', 'desktop');
  const require = createRequire(join(desktop, 'package.json'));
  const tauriCli = require.resolve('@tauri-apps/cli/tauri.js');
  const metadata = JSON.parse(execFileSync('cargo', [
    'metadata', '--locked', '--no-deps', '--format-version', '1',
  ], { cwd: workspace, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 }));
  const targetDirectory = metadata.target_directory;
  if (typeof targetDirectory !== 'string' || !isAbsolute(targetDirectory)) {
    throw new Error('Cargo metadata did not provide an absolute target_directory');
  }
  const env = { ...process.env, CARGO_TARGET_DIR: targetDirectory };
  const assets = resolve(process.env.CONTEXT_RELAY_SEARCH_ASSETS ?? join(targetDirectory, 'macos-search-resources'));
  await stageSearchResources({
    target, modelDirectory: join(assets, 'model'), runtimeDirectory: join(assets, 'runtime'),
    stagingDirectory: join(desktop, 'src-tauri', 'resources', 'search'),
  });
  const signingScript = join(workspace, 'scripts', 'macos_signing.py');
  const signingMetadata = join(targetDirectory, 'macos-signing', 'runtime.json');
  execFileSync('python3', [signingScript, 'prepare',
    join(desktop, 'src-tauri', 'resources', 'search', 'runtime'), signingMetadata, identity,
  ], { cwd: workspace, stdio: 'inherit' });
  const signing = JSON.parse(await readFile(signingMetadata, 'utf8'));
  env.CONTEXT_RELAY_MACOS_RUNTIME = JSON.stringify(signing.buildTrust);
  execFileSync('cargo', [
    'build', '--locked', '--release', '--target', target, '--target-dir', targetDirectory,
    '-p', 'context-relay-contextd', '-p', 'context-relay-context-mcp',
    '-p', 'context-relay-native-runner', '--bins',
  ], { cwd: workspace, env, stdio: 'inherit' });
  await stageMacCompanions({
    sourceDirectory: join(targetDirectory, target, 'release'),
    stagingDirectory: join(desktop, 'src-tauri', 'binaries'),
  });
  execFileSync(process.execPath, [
    tauriCli, 'build', '--target', target, '--no-sign',
    '--config', 'src-tauri/tauri.macos-release.conf.json', '--', '--locked',
  ], { cwd: desktop, env, stdio: 'inherit' });
  execFileSync('python3', [signingScript, 'finish',
    join(targetDirectory, target, 'release', 'bundle', 'macos', 'Context Relay.app'), signingMetadata, identity,
  ], { cwd: workspace, stdio: 'inherit' });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => {
    console.error(`macOS packaging failed: ${error.message}`);
    process.exitCode = Number.isInteger(error.status) && error.status > 0 ? error.status : 1;
  });
}
