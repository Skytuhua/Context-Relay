import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

import { stageSearchResources } from './search-resources.mjs';

const execute = promisify(execFile);
const archive = {
  file: 'onnxruntime-osx-arm64-1.24.2.tgz',
  bytes: 31604221,
  sha256: '0af4fa503e8ea285245b47ee42d0a7461b8156a81270857da0c1d4ecf858abde',
};

function verify(bytes, artifact) {
  if (!Buffer.isBuffer(bytes) || bytes.length !== artifact.bytes
      || createHash('sha256').update(bytes).digest('hex') !== artifact.sha256) {
    throw new Error(`${artifact.file}: pinned bytes mismatch`);
  }
  return bytes;
}

export async function fetchMacSearchResources({ stagingDirectory, run = execute }) {
  if (typeof stagingDirectory !== 'string' || !stagingDirectory) {
    throw new Error('A staging directory is required');
  }
  const root = await mkdtemp(join(tmpdir(), 'context-relay-mac-search-'));
  const modelDirectory = join(root, 'model');
  const runtimeDirectory = join(root, 'runtime');
  const options = (bytes) => ({ encoding: 'buffer', maxBuffer: bytes + 1, timeout: 180000, windowsHide: true });
  async function download(url, artifact) {
    const result = await run(process.platform === 'win32' ? 'curl.exe' : 'curl', [
      '--disable', '--fail', '--silent', '--show-error', '--location', '--max-redirs', '5',
      '--proto', '=https', '--proto-redir', '=https', '--max-time', '180',
      '--retry', '4', '--retry-delay', '15', '--retry-max-time', '120',
      '--max-filesize', String(artifact.bytes), url,
    // A final attempt may outlive the retry window by its 180-second transfer cap.
    ], { ...options(artifact.bytes), timeout: 310000 });
    return verify(result.stdout, artifact);
  }
  try {
    await mkdir(modelDirectory);
    await mkdir(runtimeDirectory);
    const model = JSON.parse(await readFile(new URL('../crates/core/models/bge-small-en-v1.5/manifest.json', import.meta.url), 'utf8'));
    for (const artifact of model.artifacts) {
      const bytes = await download(`https://huggingface.co/${model.model}/resolve/${model.revision}/${artifact.file}`, artifact);
      await writeFile(join(modelDirectory, artifact.file), bytes);
    }
    const archivePath = join(root, archive.file);
    await writeFile(archivePath, await download(`https://github.com/microsoft/onnxruntime/releases/download/v1.24.2/${archive.file}`, archive));
    const runtime = JSON.parse(await readFile(new URL('../crates/core/models/onnxruntime-osx-arm64-1.24.2/manifest.json', import.meta.url), 'utf8'));
    for (const artifact of runtime.artifacts) {
      const member = `onnxruntime-osx-arm64-1.24.2/${artifact.file.endsWith('.dylib') ? 'lib/' : ''}${artifact.file}`;
      // Extract only to bounded stdout; archive paths never become filesystem writes.
      const result = await run('tar', ['-xzOf', archivePath, member], options(artifact.bytes));
      await writeFile(join(runtimeDirectory, artifact.file), verify(result.stdout, artifact));
    }
    await stageSearchResources({ target: 'aarch64-apple-darwin', modelDirectory, runtimeDirectory, stagingDirectory });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (process.argv.length !== 3) {
    console.error('Usage: node scripts/fetch-macos-search-resources.mjs STAGING_DIRECTORY');
    process.exitCode = 1;
  } else {
    await fetchMacSearchResources({ stagingDirectory: resolve(process.argv[2]) });
    console.log('Verified macOS search inputs staged.');
  }
}
