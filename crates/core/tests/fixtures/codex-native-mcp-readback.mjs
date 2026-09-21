import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

// The Rust parent assigns this process to a kill-on-close job before opening
// the gate. No child may start until then.
assert.equal(fs.readFileSync(0, 'utf8'), 'run');
const manifest = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const hash = file => createHash('sha256').update(fs.readFileSync(file)).digest('hex');
assert.equal(hash(manifest.executable), manifest.sha256);
const results = [];
for (const entry of manifest.cases) {
  const environment = { SystemRoot: process.env.SystemRoot, WINDIR: process.env.WINDIR };
  for (const name of ['HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'PROGRAMDATA', 'TEMP', 'TMP', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_DATA_HOME']) {
    environment[name] = entry.home;
  }
  const run = (home, args) => execFileSync(manifest.executable, args, {
    env: { ...environment, CODEX_HOME: home }, cwd: entry.home, windowsHide: true,
    encoding: 'utf8', timeout: 15000, maxBuffer: 64 * 1024,
  });
  assert.equal(run(entry.home, ['--version']).trim(), 'codex-cli 0.144.6');
  const before = fs.readFileSync(join(entry.home, 'config.toml'));
  const direct = JSON.parse(run(entry.home, ['mcp', 'get', 'context-relay', '--json']));
  assert.equal(direct.transport.command, entry.command);
  assert.deepEqual(direct.transport.args, ['--harness', 'codex']);
  assert.equal(direct.enabled, true);
  assert.deepEqual(fs.readFileSync(join(entry.home, 'config.toml')), before);
  const parity = join(entry.home, 'empty-parity');
  fs.mkdirSync(parity);
  run(parity, ['mcp', 'add', 'context-relay', '--', entry.command, '--harness', 'codex']);
  const official = JSON.parse(run(parity, ['mcp', 'get', 'context-relay', '--json']));
  assert.deepEqual(direct, official);
  const listed = JSON.parse(run(entry.home, ['mcp', 'list', '--json']));
  assert.deepEqual(listed.map(server => server.name).sort(), ['context-relay', 'unrelated']);
  assert.deepEqual(fs.readFileSync(join(entry.home, 'config.toml')), before);
  results.push({ name: entry.name, nativeReadbackMatchesOfficialCli: true, configUnchanged: true });
}
assert.equal(hash(manifest.executable), manifest.sha256);
console.log(JSON.stringify({ version: '0.144.6', results }));
