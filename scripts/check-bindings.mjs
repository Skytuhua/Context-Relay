import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const workspace = resolve(import.meta.dirname, '..');
const cargo = process.env.CONTEXT_RELAY_CARGO ?? 'cargo';
const temporaryDirectory = mkdtempSync(join(tmpdir(), 'context-relay-bindings-'));
const generated = join(temporaryDirectory, 'bindings.ts');

try {
  execFileSync(
    cargo,
    ['run', '-p', 'context-relay-protocol', '--bin', 'export-bindings', '--', generated],
    { cwd: workspace, stdio: 'inherit' },
  );

  const committed = readFileSync(join(workspace, 'apps/desktop/src/bindings.ts'), 'utf8');
  if (readFileSync(generated, 'utf8') !== committed) {
    throw new Error('TypeScript bindings are stale; run pnpm generate:bindings');
  }
} finally {
  rmSync(temporaryDirectory, { recursive: true, force: true });
}
