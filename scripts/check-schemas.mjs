import { execFileSync } from 'node:child_process';
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const workspace = resolve(import.meta.dirname, '..');
const cargo = process.env.CONTEXT_RELAY_CARGO ?? 'cargo';
const temporary = mkdtempSync(join(tmpdir(), 'context-relay-schemas-'));
try {
  execFileSync(cargo, ['run', '-p', 'context-relay-protocol', '--bin', 'export-schemas', '--', temporary], { cwd: workspace, stdio: 'inherit' });
  const expected = readdirSync(temporary).sort();
  const committed = readdirSync(join(workspace, 'schemas')).sort();
  if (JSON.stringify(expected) !== JSON.stringify(committed)) throw new Error('Schema file list is stale');
  for (const file of expected) {
    if (readFileSync(join(temporary, file), 'utf8') !== readFileSync(join(workspace, 'schemas', file), 'utf8')) throw new Error(`Schema is stale: ${file}`);
  }
} finally { rmSync(temporary, { recursive: true, force: true }); }
