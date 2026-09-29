import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import { join } from 'node:path';
import { createInterface } from 'node:readline';

assert.equal(fs.readFileSync(0, 'utf8'), 'run');
const fixture = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const hash = () => createHash('sha256').update(fs.readFileSync(fixture.executable)).digest('hex');
assert.equal(hash(), fixture.sha256);
const results = [];
for (const entry of fixture.cases) {
  const env = { SystemRoot: process.env.SystemRoot, WINDIR: process.env.WINDIR,
    CODEX_HOME: entry.home, PATH: join(process.env.SystemRoot, 'System32'),
    COMSPEC: join(process.env.SystemRoot, 'System32', 'cmd.exe'), PATHEXT: '.COM;.EXE;.BAT;.CMD' };
  for (const key of ['HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'PROGRAMDATA', 'TEMP', 'TMP', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_DATA_HOME']) env[key] = entry.home;
  const child = spawn(fixture.executable, ['app-server', '--listen', 'stdio://'],
    { cwd: entry.cwd, env, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
  const pending = new Map();
  let outputBytes = 0, errorBytes = 0, deadline;
  const exited = new Promise((resolve, reject) => {
    const fail = error => { child.kill(); reject(error); };
    deadline = setTimeout(() => fail(new Error('Native trust readback timed out')), 15000);
    child.once('error', fail);
    child.once('close', resolve);
    child.stdout.on('data', value => { outputBytes += value.length; if (outputBytes > 256 * 1024) fail(new Error('Native readback output exceeded limit')); });
    child.stderr.on('data', value => { errorBytes += value.length; if (errorBytes > 65536) fail(new Error('Native readback errors exceeded limit')); });
  });
  exited.catch(() => {});
  const lines = createInterface({ input: child.stdout });
  lines.on('line', line => {
    const value = JSON.parse(line);
    const resolve = pending.get(value.id);
    if (resolve) { pending.delete(value.id); resolve(value); }
  });
  let nextId = 0;
  const rpc = async (method, params) => {
    const id = ++nextId;
    const reply = new Promise(resolve => pending.set(id, resolve));
    child.stdin.write(JSON.stringify({ id, method, params }) + '\n');
    const value = await Promise.race([reply, exited.then(() => { throw new Error('Native readback ended before replying'); })]);
    assert.equal(value.error, undefined, JSON.stringify(value.error));
    return value.result;
  };
  const config = fs.readFileSync(join(entry.home, 'config.toml'));
  const hooks = fs.readFileSync(join(entry.cwd, '.codex', 'hooks.json'));
  try {
    const initialized = await rpc('initialize', { clientInfo: { name: 'context-relay-trust-fixture', version: '0.1.0' }, capabilities: { experimentalApi: true } });
    assert.ok(initialized.userAgent.includes('0.144.6'));
    child.stdin.write(JSON.stringify({ method: 'initialized', params: {} }) + '\n');
    const { data } = await rpc('hooks/list', { cwds: [entry.cwd] });
    assert.equal(data.length, 1);
    assert.deepEqual(data[0].errors, []);
    assert.deepEqual(data[0].warnings, []);
    assert.equal(fs.realpathSync.native(data[0].cwd), fs.realpathSync.native(entry.cwd));
    assert.ok(data[0].hooks.length === 0 || data[0].hooks.length === 1);
    assert.ok(data[0].hooks.every(hook => hook.source === 'project' && hook.command === 'context-relay-inert-fixture-command' && hook.trustStatus === 'untrusted'));
    results.push({ name: entry.name, trusted: data[0].hooks.length === 1 });
    child.stdin.end();
    assert.equal(await exited, 0);
    assert.deepEqual(fs.readFileSync(join(entry.home, 'config.toml')), config);
    assert.deepEqual(fs.readFileSync(join(entry.cwd, '.codex', 'hooks.json')), hooks);
  } finally { lines.close(); clearTimeout(deadline); child.kill(); }
}
assert.equal(hash(), fixture.sha256);
fs.writeFileSync(fixture.results, JSON.stringify(results));
console.log(JSON.stringify(results));
