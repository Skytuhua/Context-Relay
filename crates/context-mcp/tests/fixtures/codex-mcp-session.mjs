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
const env = { SystemRoot: process.env.SystemRoot, WINDIR: process.env.WINDIR,
  CODEX_HOME: fixture.home, CONTEXT_RELAY_FIXTURE_KEY: 'synthetic-local-fixture',
  COMSPEC: join(process.env.SystemRoot, 'System32', 'cmd.exe'),
  PATH: join(process.env.SystemRoot, 'System32'), PATHEXT: '.COM;.EXE;.BAT;.CMD',
};
for (const name of ['HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'PROGRAMDATA', 'TEMP', 'TMP', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_DATA_HOME']) env[name] = fixture.home;

async function run(args, action, executable = fixture.executable) {
  const child = spawn(executable, args, { env, cwd: fixture.project, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
  let stdout = '', stderr = '', timer;
  const exit = new Promise((resolve, reject) => {
    const fail = error => { child.kill(); reject(error); };
    timer = setTimeout(() => fail(new Error(`Codex timeout: ${stderr}`)), 60000);
    child.once('error', fail); child.once('close', resolve);
    child.stdout.on('data', chunk => { stdout += chunk; if (stdout.length > 512 * 1024) fail(new Error('Codex stdout exceeded limit')); });
    child.stderr.on('data', chunk => { stderr += chunk; if (stderr.length > 65536) fail(new Error('Codex stderr exceeded limit')); });
  });
  exit.catch(() => {});
  try {
    const value = action ? await Promise.race([action(child), exit.then(() => { throw new Error(`Codex exited during RPC: ${stderr}`); })]) : undefined;
    child.stdin.end(); assert.equal(await exit, 0, `${stderr}\n${JSON.stringify(failures)}`);
    return { stdout, stderr, value };
  } finally { clearTimeout(timer); child.kill(); }
}

async function appServer(session = false) {
  return (await run(['app-server', '--listen', 'stdio://'], async child => {
    let nextId = 0, completed;
    const pending = new Map(), timers = new Set(), notifications = [];
    const finished = new Promise(resolve => { completed = resolve; });
    const lines = createInterface({ input: child.stdout });
    lines.on('line', line => {
      const value = JSON.parse(line);
      if (value.method) { notifications.push(value); if (value.method === 'turn/completed') completed(value.params); }
      const handler = pending.get(value.id);
      if (handler) { pending.delete(value.id); handler(value); }
    });
    const rpc = (method, params) => new Promise((resolve, reject) => {
      const id = ++nextId;
      const timeout = setTimeout(() => { pending.delete(id); reject(new Error(`${method} timed out`)); }, 30000);
      timers.add(timeout);
      pending.set(id, value => { clearTimeout(timeout); timers.delete(timeout); value.error ? reject(new Error(JSON.stringify(value.error))) : resolve(value.result); });
      child.stdin.write(JSON.stringify({ id, method, params }) + '\n');
    });
    try {
      const initialized = await rpc('initialize', { clientInfo: { name: 'context-relay-native-fixture', version: '0.1.0' }, capabilities: { experimentalApi: true } });
      assert.ok(initialized.userAgent.includes('0.144.6'));
      child.stdin.write(JSON.stringify({ method: 'initialized', params: {} }) + '\n');
      const listed = await rpc('hooks/list', { cwds: [fixture.project] });
      assert.equal(listed.data.length, 1); assert.deepEqual(listed.data[0].errors, []);
      const hooks = listed.data[0].hooks;
      assert.equal(hooks.length, 2);
      if (!session) return { hooks };
      const thread = await rpc('thread/start', { cwd: fixture.project, ephemeral: true });
      await rpc('turn/start', { threadId: thread.thread.id, input: [{ type: 'text', text: 'Perform the fixed local fixture tool sequence.', text_elements: [] }] });
      const turn = await finished;
      assert.equal(turn.turn.status, 'completed', JSON.stringify(turn));
      await rpc('thread/unsubscribe', { threadId: thread.thread.id });
      return { hooks, notifications };
    } finally { lines.close(); for (const timer of timers) clearTimeout(timer); }
  })).value;
}

function decodedOutput(output) {
  assert.equal(typeof output, 'string');
  // The pinned Codex client adds timing text around the MCP structured result.
  const match = /^Wall time: [0-9]+(?:\.[0-9]+)? seconds\nOutput:\n([\s\S]+)$/.exec(output);
  assert.ok(match, `Unexpected native tool output: ${output.slice(0, 4096)}`);
  return JSON.parse(match[1]);
}
function toolNames(tools, prefix = '') {
  return tools.flatMap(tool => tool.type === 'namespace' ? toolNames(tool.tools, `${tool.name}.`) : tool.name ? [prefix + tool.name] : []);
}

let round = 0, step = 0, memory, task;
const failures = [];
const server = createServer(async (req, res) => {
  try {
    assert.equal(req.method, 'POST'); assert.equal(req.url, '/v1/responses');
    assert.equal(req.headers.authorization, 'Bearer synthetic-local-fixture');
    let bytes = 0; const chunks = [];
    for await (const chunk of req) { bytes += chunk.length; assert.ok(bytes <= 2 * 1024 * 1024); chunks.push(chunk); }
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    assert.equal(body.model, 'synthetic-context-relay');
    if (step === 0) {
      assert.ok(JSON.stringify(body).includes('Query Context Relay for the active project'), 'SessionStart reminder did not reach the model');
      const advertised = toolNames(body.tools).filter(name => name.startsWith('mcp__context_relay.')).sort();
      assert.deepEqual(advertised, fixture.toolNames.map(name => `mcp__context_relay.${name}`).sort());
    }
    if (step > 0) {
      const reply = body.input.find(item => item.type === 'function_call_output' && item.call_id === `call_${round}_${step - 1}`);
      assert.ok(reply, JSON.stringify(body.input));
      const result = decodedOutput(reply.output);
      if (step === 1) { assert.equal(result.vault, 'unlocked'); assert.equal(result.resolvedProject, fixture.projectId); }
      if (step === 2) { memory = result.memory; assert.equal(memory.title, `Native Codex round trip ${round}`); assert.equal(memory.scope.projectId, fixture.projectId); }
      if (step === 3) assert.equal(result.record.record.id, memory.id);
      if (step === 4) assert.ok(result.memories.some(item => item.id === memory.id), JSON.stringify(result));
      if (step === 5) { task = result.task; assert.equal(task.status, 'open'); }
      if (step === 6) { task = result.task; assert.equal(task.status, 'done'); assert.equal(task.evidence[0].summary, 'Completed by actual Codex MCP client.'); }
      if (step === 7) assert.ok(result.tasks.some(item => item.id === task.id && item.status === 'done'));
    }
    const calls = [
      ['context_relay_status', {}],
      ['context_relay_remember', { operationId: fixture.operations[round * 4], kind: 'note', title: `Native Codex round trip ${round}`, markdown: 'Saved through the actual Codex MCP client.', tags: ['native-fixture'], scope: { scope: 'active_project' } }],
      ['context_relay_get', { recordId: memory?.id }],
      ['context_relay_search', { query: `Native Codex round trip ${round}`, scope: { scope: 'active_project' }, limit: 10 }],
      ['context_relay_upsert_task', { operationId: fixture.operations[round * 4 + 1], taskId: null, expectedRevision: null, title: `Native task ${round}`, bodyMarkdown: 'Complete the native fixture.', status: 'open' }],
      ['context_relay_complete_task', { operationId: fixture.operations[round * 4 + 2], taskId: task?.id, expectedRevision: task?.revision, evidence: [{ kind: 'result', summary: 'Completed by actual Codex MCP client.' }] }],
      ['context_relay_list_tasks', { status: 'done' }],
    ];
    let item;
    if (step < calls.length) {
      const [name, arguments_] = calls[step];
      const available = toolNames(body.tools);
      const actual = available.find(candidate => candidate === `mcp__context_relay.${name}`);
      assert.ok(actual, `Missing ${name}; available ${JSON.stringify(available)}`);
      item = { type: 'function_call', id: `fc_${round}_${step}`, call_id: `call_${round}_${step}`, namespace: 'mcp__context_relay', name, arguments: JSON.stringify(arguments_), status: 'completed' };
    } else {
      assert.equal(step, calls.length);
      item = { type: 'message', id: `msg_${round}`, role: 'assistant', status: 'completed', content: [{ type: 'output_text', text: 'Native bridge fixture complete.', annotations: [] }] };
    }
    step++;
    const events = [
      { type: 'response.created', response: { id: `resp_${round}_${step}`, status: 'in_progress', output: [] } },
      { type: 'response.output_item.done', output_index: 0, item },
      { type: 'response.completed', response: { id: `resp_${round}_${step}`, status: 'completed', output: [item], usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2 } } },
    ];
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.end(events.map(event => `event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`).join(''));
  } catch (error) { failures.push(error.message); res.writeHead(400); res.end('Invalid local fixture exchange'); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
try {
  // Reject an accidentally selected production bridge before Codex can invoke it.
  // The production CLI rejects this unknown flag before connecting to any daemon.
  const identity = await run(['--fixture-info'], undefined, fixture.bridge);
  assert.equal(identity.stdout.trim(), 'context-relay-isolated-codex-bridge-fixture-v1');
  const configPath = join(fixture.home, 'config.toml');
  const config = `model = "synthetic-context-relay"\nmodel_provider = "fixture"\napproval_policy = "never"\nsandbox_mode = "danger-full-access"\n` +
    `[model_providers.fixture]\nname = "Local fixture"\nbase_url = "http://127.0.0.1:${server.address().port}/v1"\nwire_api = "responses"\nenv_key = "CONTEXT_RELAY_FIXTURE_KEY"\nrequest_max_retries = 0\nstream_max_retries = 0\n` +
    `[memories]\ngenerate_memories = false\nuse_memories = false\n[features]\nshell_snapshot = false\n` +
    `[mcp_servers.context-relay]\ncommand = ${JSON.stringify(fixture.bridge)}\nargs = ["--harness", "codex"]\n` +
    `[projects.${JSON.stringify(fixture.project.toLowerCase())}]\ntrust_level = "trusted"\n`;
  fs.writeFileSync(configPath, config);
  const hookPath = join(fixture.home, 'hooks.json');
  fs.writeFileSync(hookPath, JSON.stringify({ hooks: fixture.hooks }));
  const initial = await appServer();
  assert.ok(initial.hooks.every(hook => hook.trustStatus === 'untrusted' && hook.enabled && !hook.isManaged));
  const trust = initial.hooks.map(hook => `\n[hooks.state.${JSON.stringify(hook.key)}]\ntrusted_hash = ${JSON.stringify(hook.currentHash)}\n`).join('');
  // Only fixture-owned, production-generated commands in this disposable home.
  fs.writeFileSync(configPath, config + trust);
  const before = fs.readFileSync(configPath, 'utf8');
  for (const surface of ['exec', 'app-server']) {
    step = 0; memory = undefined; task = undefined;
    if (surface === 'exec') {
      const result = await run(['exec', '--json', '--ephemeral', '--skip-git-repo-check', 'Perform the fixed local fixture tool sequence.']);
      const events = result.stdout.trim().split(/\r?\n/).map(line => JSON.parse(line));
      assert.ok(events.some(event => event.type === 'turn.completed'), `${result.stdout}\n${result.stderr}\n${JSON.stringify(failures)}`);
    } else {
      const result = await appServer(true);
      const hooks = result.notifications.filter(value => value.method === 'hook/completed').map(value => value.params.run);
      assert.equal(hooks.length, 2); assert.ok(hooks.every(hook => hook.status === 'completed'), JSON.stringify(hooks));
    }
    assert.deepEqual(failures, []); assert.equal(step, 8);
    assert.equal(fs.readFileSync(configPath, 'utf8'), before);
    console.log(JSON.stringify({ surface, memoryId: memory.id, taskId: task.id, taskStatus: task.status, modelRequests: step }));
    round++;
  }
  assert.equal(hash(fixture.executable), fixture.sha256);
  assert.equal(hash(fixture.bridge), fixture.bridgeSha256);
} finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
