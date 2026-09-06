import { execFileSync } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const target = 'x86_64-pc-windows-msvc';
const workspace = fileURLToPath(new URL('../', import.meta.url));

export const REQUIRED_WINDOWS_BINARIES = Object.freeze([
  'context-relay-contextd',
  'context-relay-context-mcp',
  'context-relay-native-helper',
  'context-relay-sidecar-installer',
]);

export function windowsReleaseEnvironment(environment, targetDirectory) {
  // Cargo gives encoded flags precedence over whitespace-delimited RUSTFLAGS.
  // Enforce static CRT for every target crate, including non-Tauri companions.
  // This release policy intentionally replaces Cargo-config rustflags while
  // preserving explicit environment flags and their argument boundaries.
  const flags = environment.CARGO_ENCODED_RUSTFLAGS !== undefined
    ? environment.CARGO_ENCODED_RUSTFLAGS.split('\x1f').filter(Boolean)
    : (environment.RUSTFLAGS ?? '').split(/\s+/).filter(Boolean);
  return {
    ...environment,
    CARGO_TARGET_DIR: targetDirectory,
    CARGO_ENCODED_RUSTFLAGS: [...flags, '-Ctarget-feature=+crt-static'].join('\x1f'),
  };
}

function validatePe(bytes, name) {
  if (bytes.length < 64 || bytes.toString('ascii', 0, 2) !== 'MZ') {
    throw new Error(`${name}: invalid PE DOS header`);
  }
  const offset = bytes.readUInt32LE(0x3c);
  if (offset < 64 || offset + 24 > bytes.length || bytes.readUInt32LE(offset) !== 0x00004550) {
    throw new Error(`${name}: invalid PE signature or truncated COFF header`);
  }
  if (bytes.readUInt16LE(offset + 4) !== 0x8664) {
    throw new Error(`${name}: PE machine must be AMD64 for ${target}`);
  }
}

export async function stageWindowsCompanions({ sourceDirectory, stagingDirectory }) {
  // Validate the complete set before touching prior staged output. Keep the
  // validated bytes so the copied files are exactly the bytes that passed.
  const companions = [];
  for (const name of REQUIRED_WINDOWS_BINARIES) {
    let bytes;
    try {
      bytes = await readFile(join(sourceDirectory, `${name}.exe`));
    } catch (error) {
      throw new Error(`${name}: cannot read companion (${error.code ?? error.message})`, { cause: error });
    }
    validatePe(bytes, name);
    companions.push({ name, bytes });
  }
  await mkdir(stagingDirectory, { recursive: true });
  for (const { name, bytes } of companions) {
    await writeFile(join(stagingDirectory, `${name}-${target}.exe`), bytes);
  }
}

async function main() {
  if (process.argv.length > 2) {
    throw new Error('package:windows takes no arguments; configure Cargo through its environment or config');
  }
  if (process.platform !== 'win32') {
    throw new Error('package:windows requires the Windows MSVC toolchain on Windows');
  }
  const desktop = join(workspace, 'apps', 'desktop');
  const require = createRequire(join(desktop, 'package.json'));
  const tauriCli = require.resolve('@tauri-apps/cli/tauri.js');

  // Cargo resolves target-dir from both its config and environment. Pin the
  // resolved absolute directory for both builds, even though Tauri changes cwd.
  const metadata = JSON.parse(execFileSync('cargo.exe', [
    'metadata', '--locked', '--no-deps', '--format-version', '1',
  ], { cwd: workspace, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 }));
  const targetDirectory = metadata.target_directory;
  if (typeof targetDirectory !== 'string' || !isAbsolute(targetDirectory)) {
    throw new Error('Cargo metadata did not provide an absolute target_directory');
  }
  const env = windowsReleaseEnvironment(process.env, targetDirectory);
  execFileSync('cargo.exe', [
    'build', '--locked', '--release', '--target', target,
    '--target-dir', targetDirectory,
    '-p', 'context-relay-contextd',
    '-p', 'context-relay-context-mcp',
    '-p', 'context-relay-native-runner', '--bins',
  ], { cwd: workspace, env, stdio: 'inherit' });
  await stageWindowsCompanions({
    sourceDirectory: join(targetDirectory, target, 'release'),
    stagingDirectory: join(desktop, 'src-tauri', 'binaries'),
  });
  // Run the pinned JS entry point directly: Windows .cmd wrappers require a
  // shell and would lose the structured argument boundary for workspace paths.
  execFileSync(process.execPath, [
    tauriCli, 'build', '--target', target,
    '--config', 'src-tauri/tauri.windows-release.conf.json',
    '--', '--locked',
  ], { cwd: desktop, env, stdio: 'inherit' });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(`Windows packaging failed: ${error.message}`);
    process.exitCode = Number.isInteger(error.status) && error.status > 0 ? error.status : 1;
  });
}
