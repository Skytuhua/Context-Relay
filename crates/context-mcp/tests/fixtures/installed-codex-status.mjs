// Opt-in read-only installed-service qualification; launched by the Rust job owner.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { createInterface } from 'node:readline';

assert.equal(fs.readFileSync(0, 'utf8'), 'run');
const fixture = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const hash = file => createHash('sha256').update(fs.readFileSync(file)).digest('hex');
assert.equal(hash(fixture.executable), fixture.sha256);
assert.equal(hash(fixture.bridge), fixture.bridgeSha256);
assert.equal(fs.existsSync(join(fixture.root, 'context-relay-contextd.exe')), false);
const env = { SystemRoot: process.env.SystemRoot, WINDIR: process.env.WINDIR,
  CODEX_HOME: fixture.home, CONTEXT_RELAY_FIXTURE_KEY: 'synthetic-local-fixture',
  COMSPEC: join(process.env.SystemRoot, 'System32', 'cmd.exe'),
  PATH: join(process.env.SystemRoot, 'System32'), PATHEXT: '.COM;.EXE;.BAT;.CMD',
};
for (const name of Object.keys(fixture.bridgeEnv)) {
  env[name] = fixture.home;
  assert.notEqual(fixture.bridgeEnv[name].toLowerCase(), fixture.home.toLowerCase());
}

async function run(args, action) {
  const child = spawn(fixture.executable, args, { env, cwd: fixture.project, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
  let stdout = '', stderr = '', timer;
  const exit = new Promise((resolve, reject) => {
    const fail = error => { child.kill(); reject(error); };
    timer = setTimeout(() => fail(new Error('Codex session timeout')), 60000);
    child.once('error', fail); child.once('close', resolve);
    child.stdout.on('data', chunk => { stdout += chunk; if (stdout.length > 512 * 1024) fail(new Error('Codex stdout exceeded limit')); });
    child.stderr.on('data', chunk => { stderr += chunk; if (stderr.length > 65536) fail(new Error('Codex stderr exceeded limit')); });
  });
  exit.catch(() => {});
  try {
    if (action) await Promise.race([action(child), exit.then(() => { throw new Error('Codex exited during RPC'); })]);
    child.stdin.end();
    assert.equal(await exit, 0, `${stderr}\n${JSON.stringify(failures)}`);
    return stdout;
  } finally { clearTimeout(timer); child.kill(); }
}

async function appServer() {
  await run(['app-server', '--listen', 'stdio://'], async child => {
    let nextId = 0, complete;
    const pending = new Map(), timers = new Set();
    const finished = new Promise(resolve => { complete = resolve; });
    const lines = createInterface({ input: child.stdout });
    lines.on('line', line => {
      const value = JSON.parse(line);
      if (value.method === 'turn/completed') complete(value.params);
      const handler = pending.get(value.id);
      if (handler) { pending.delete(value.id); handler(value); }
    });
    const rpc = (method, params) => new Promise((resolve, reject) => {
      const id = ++nextId;
      const timeout = setTimeout(() => { pending.delete(id); reject(new Error(`${method} timed out`)); }, 30000);
      timers.add(timeout);
      pending.set(id, value => { clearTimeout(timeout); timers.delete(timeout); value.error ? reject(new Error(`${method} failed`)) : resolve(value.result); });
      child.stdin.write(JSON.stringify({ id, method, params }) + '\n');
    });
    try {
      const initialized = await rpc('initialize', { clientInfo: { name: 'context-relay-installed-status-fixture', version: '0.1.0' }, capabilities: { experimentalApi: true } });
      assert.ok(initialized.userAgent.includes('0.144.6'));
      child.stdin.write(JSON.stringify({ method: 'initialized', params: {} }) + '\n');
      const thread = await rpc('thread/start', { cwd: fixture.project, ephemeral: true });
      await rpc('turn/start', { threadId: thread.thread.id, input: [{ type: 'text', text: 'Read Context Relay status once.', text_elements: [] }] });
      const turn = await finished;
      assert.equal(turn.turn.status, 'completed');
      await rpc('thread/unsubscribe', { threadId: thread.thread.id });
    } finally { lines.close(); for (const timer of timers) clearTimeout(timer); }
  });
}

function toolNames(tools, prefix = '') {
  return tools.flatMap(tool => tool.type === 'namespace' ? toolNames(tool.tools, `${tool.name}.`) : tool.name ? [prefix + tool.name] : []);
}

let round = 0, step = 0;
const failures = [];
const server = createServer(async (req, res) => {
  try {
    assert.equal(req.method, 'POST'); assert.equal(req.url, '/v1/responses');
    assert.equal(req.headers.authorization, 'Bearer synthetic-local-fixture');
    let bytes = 0; const chunks = [];
    for await (const chunk of req) { bytes += chunk.length; assert.ok(bytes <= 2 * 1024 * 1024); chunks.push(chunk); }
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    assert.equal(body.model, 'synthetic-context-relay');
    assert.deepEqual(toolNames(body.tools).filter(name => name.startsWith('mcp__context_relay.')), ['mcp__context_relay.context_relay_status']);
    let item;
    if (step === 0) {
      item = { type: 'function_call', id: `fc_${round}`, call_id: `call_${round}`, namespace: 'mcp__context_relay', name: 'context_relay_status', arguments: '{}', status: 'completed' };
    } else {
      assert.equal(step, 1);
      const reply = body.input.find(item => item.type === 'function_call_output' && item.call_id === `call_${round}`);
      assert.ok(reply, 'Status tool output missing');
      const match = /^Wall time: [0-9]+(?:\.[0-9]+)? seconds\nOutput:\n([\s\S]+)$/.exec(reply.output);
      assert.ok(match, 'Unexpected status result format');
      const result = JSON.parse(match[1]);
      assert.deepEqual(result.protocol, { min: fixture.protocol, max: fixture.protocol });
      assert.equal(result.vault, 'unlocked');
      assert.equal(result.resolvedProject, null);
      item = { type: 'message', id: `msg_${round}`, role: 'assistant', status: 'completed', content: [{ type: 'output_text', text: 'Installed service status verified.', annotations: [] }] };
    }
    step++;
    const events = [
      { type: 'response.created', response: { id: `resp_${round}_${step}`, status: 'in_progress', output: [] } },
      { type: 'response.output_item.done', output_index: 0, item },
      { type: 'response.completed', response: { id: `resp_${round}_${step}`, status: 'completed', output: [item], usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2 } } },
    ];
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.end(events.map(event => `event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`).join(''));
  } catch (error) { failures.push(error.message); res.writeHead(400); res.end('Invalid local status exchange'); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
try {
  const config = `model = "synthetic-context-relay"\nmodel_provider = "fixture"\napproval_policy = "never"\nsandbox_mode = "danger-full-access"\n` +
    `[model_providers.fixture]\nname = "Local fixture"\nbase_url = "http://127.0.0.1:${server.address().port}/v1"\nwire_api = "responses"\nenv_key = "CONTEXT_RELAY_FIXTURE_KEY"\nrequest_max_retries = 0\nstream_max_retries = 0\n` +
    `[memories]\ngenerate_memories = false\nuse_memories = false\n[features]\nshell_snapshot = false\n` +
    `[mcp_servers.context-relay]\ncommand = ${JSON.stringify(fixture.bridge)}\nargs = ["--harness", "codex"]\nenabled_tools = ["context_relay_status"]\n` +
    // Parent Codex is isolated; the production bridge explicitly retains normal
    // profile locations for the installed service and OS credential store.
    `[mcp_servers.context-relay.env]\n` + Object.entries(fixture.bridgeEnv).map(([name, value]) => `${name} = ${JSON.stringify(value)}\n`).join('') +
    `[projects.${JSON.stringify(fixture.project.toLowerCase())}]\ntrust_level = "trusted"\n`;
  const configPath = join(fixture.home, 'config.toml');
  fs.writeFileSync(configPath, config);
  for (const surface of ['exec', 'app-server']) {
    step = 0;
    if (surface === 'exec') {
      const stdout = await run(['exec', '--json', '--ephemeral', '--skip-git-repo-check', 'Read Context Relay status once.']);
      const events = stdout.trim().split(/\r?\n/).map(line => JSON.parse(line));
      assert.ok(events.some(event => event.type === 'turn.completed'), JSON.stringify(failures));
    } else await appServer();
    assert.deepEqual(failures, []); assert.equal(step, 2);
    assert.equal(fs.readFileSync(configPath, 'utf8'), config);
    console.log(JSON.stringify({ surface, statusCalls: 1, protocol: fixture.protocol, vault: 'unlocked', configurationUnchanged: true }));
    round++;
  }
} finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
