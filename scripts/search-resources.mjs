import { createHash } from 'node:crypto';
import { mkdir, open, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const modelManifest = new URL('../crates/core/models/bge-small-en-v1.5/manifest.json', import.meta.url);
const runtimeManifests = new Map([
  ['x86_64-pc-windows-msvc', new URL('../crates/core/models/onnxruntime-win-x64-1.24.2/manifest.json', import.meta.url)],
  ['aarch64-apple-darwin', new URL('../crates/core/models/onnxruntime-osx-arm64-1.24.2/manifest.json', import.meta.url)],
]);

async function readPinned(directory, artifact) {
  const { file, bytes, sha256 } = artifact;
  if (!/^[a-zA-Z0-9_.-]+$/.test(file) || !Number.isSafeInteger(bytes) || bytes <= 0 || bytes > 80 * 1024 * 1024 ||
    !/^[a-f0-9]{64}$/.test(sha256)) throw new Error('Invalid pinned search artifact');
  const handle = await open(join(directory, file), 'r');
  try {
    const metadata = await handle.stat();
    if (!metadata.isFile() || metadata.size !== bytes) throw new Error(`${file}: size mismatch`);
    // Bound the read even if a source file grows after stat. Retain the exact
    // bytes that passed validation instead of reopening a possibly changed path.
    const buffer = Buffer.alloc(bytes + 1);
    let count = 0;
    while (count < buffer.length) {
      const result = await handle.read(buffer, count, buffer.length - count, null);
      if (!result.bytesRead) break;
      count += result.bytesRead;
    }
    if (count !== bytes) throw new Error(`${file}: size mismatch`);
    const content = buffer.subarray(0, bytes);
    if (createHash('sha256').update(content).digest('hex') !== sha256) throw new Error(`${file}: hash mismatch`);
    return content;
  } finally { await handle.close(); }
}

export async function stageSearchResources({ target, modelDirectory, runtimeDirectory, stagingDirectory }) {
  const runtimeManifest = runtimeManifests.get(target);
  if (!runtimeManifest) throw new Error(`Unsupported search target: ${target}`);
  const pending = [];
  for (const [manifestPath, source, destination] of [
    [modelManifest, modelDirectory, 'model'], [runtimeManifest, runtimeDirectory, 'runtime'],
  ]) {
    const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
    for (const artifact of manifest.artifacts) {
      pending.push({ destination, file: artifact.file, bytes: await readPinned(source, artifact) });
    }
  }
  // Validate the full set before replacing any previously staged resource.
  // Tauri includes an explicit file list, so unrelated/stale files are excluded.
  for (const { destination, file, bytes } of pending) {
    const directory = join(stagingDirectory, destination);
    await mkdir(directory, { recursive: true });
    await writeFile(join(directory, file), bytes);
  }
}
