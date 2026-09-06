import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { createInterface } from 'node:readline';

// The Rust parent contains this process and every descendant before opening the gate.
assert.equal(fs.readFileSync(0, 'utf8'), 'run');
const manifest = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const hash = file => createHash('sha256').update(fs.readFileSync(file)).digest('hex');
assert.equal(hash(manifest.executable), manifest.sha256);
let requests = 0;
const failures = [];
const server = createServer(async (req, res) => {
  try {
    assert.equal(req.method, 'POST');
    assert.equal(req.url, '/v1/responses');
    assert.equal(req.headers.authorization, 'Bearer synthetic-local-fixture');
    let body = '';
    for await (const chunk of req) {
      body += chunk;
      assert.ok(body.length < 512 * 1024);
    }
    assert.equal(JSON.parse(body).model, 'synthetic-context-relay');
    requests++;
    const message = { id: 'msg_fixture', type: 'message', role: 'assistant', status: 'completed',
      content: [{ type: 'output_text', text: 'Synthetic session complete.', annotations: [] }] };
    const events = [
      { type: 'response.created', response: { id: 'resp_fixture', status: 'in_progress', output: [] } },
      { type: 'response.output_item.done', output_index: 0, item: message },
      { type: 'response.completed', response: { id: 'resp_fixture', status: 'completed', output: [message],
        usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2 } } },
    ];
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.end(events.map(event => `event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`).join(''));
  } catch (error) {
    failures.push(error.message);
    res.writeHead(400); res.end('Invalid synthetic request');
  }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));

function environment(entry) {
  const env = { SystemRoot: process.env.SystemRoot, WINDIR: process.env.WINDIR,
    CODEX_HOME: entry.home, CONTEXT_RELAY_FIXTURE_KEY: 'synthetic-local-fixture',
    COMSPEC: join(process.env.SystemRoot, 'System32', 'cmd.exe'),
    PATH: join(process.env.SystemRoot, 'System32'),
    PATHEXT: '.COM;.EXE;.BAT;.CMD',
  };
  for (const name of ['HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'PROGRAMDATA', 'TEMP', 'TMP', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_DATA_HOME']) env[name] = entry.home;
  return env;
}

async function run(entry, args, action) {
  const child = spawn(manifest.executable, args, {
    env: environment(entry), cwd: entry.project, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'],
  });
  let stdout = '', stderr = '';
  let timer;
  const exit = new Promise((resolve, reject) => {
    const fail = error => { child.kill(); reject(error); };
    timer = setTimeout(() => fail(new Error(`Codex fixture timeout: ${stderr}`)), 20000);
    child.once('error', fail);
    child.once('close', code => resolve(code));
    child.stdout.on('data', chunk => {
      stdout += chunk;
      if (stdout.length > 65536) fail(new Error('Codex fixture stdout exceeded limit'));
    });
    child.stderr.on('data', chunk => {
      stderr += chunk;
      if (stderr.length > 65536) fail(new Error('Codex fixture stderr exceeded limit'));
    });
  });
  // Avoid an unhandled rejection while an RPC is pending.
  exit.catch(() => {});
  try {
    const value = action ? await Promise.race([action(child), exit.then(() => { throw new Error('Codex exited during RPC'); })]) : undefined;
    child.stdin.end();
    assert.equal(await exit, 0, stderr);
    return { stdout, stderr, value };
  } finally { clearTimeout(timer); child.kill(); }
}

async function listedHooks(entry, session = false) {
  return (await run(entry, ['app-server', '--listen', 'stdio://'], async child => {
    let nextId = 0;
    const pending = new Map();
    const timers = new Set();
    const notifications = [];
    let completed;
    const turnFinished = new Promise(resolve => { completed = resolve; });
    const lines = createInterface({ input: child.stdout });
    lines.on('line', line => {
      const value = JSON.parse(line);
      if (value.method) {
        notifications.push(value);
        if (value.method === 'turn/completed') completed(value.params);
      }
      const handler = pending.get(value.id);
      if (handler) { pending.delete(value.id); handler(value); }
    });
    const request = (method, params) => new Promise((resolve, reject) => {
      const id = ++nextId;
      const timeout = setTimeout(() => { pending.delete(id); reject(new Error(`${method} timed out`)); }, 10000);
      timers.add(timeout);
      pending.set(id, value => {
        clearTimeout(timeout);
        timers.delete(timeout);
        value.error ? reject(new Error(JSON.stringify(value.error))) : resolve(value.result);
      });
      child.stdin.write(JSON.stringify({ id, method, params }) + '\n');
    });
    try {
      const initialized = await request('initialize', {
        clientInfo: { name: 'context-relay-fixture', version: '0.1.0' }, capabilities: { experimentalApi: true },
      });
      assert.ok(initialized.userAgent.includes('0.144.6'));
      child.stdin.write(JSON.stringify({ method: 'initialized', params: {} }) + '\n');
      const listed = await request('hooks/list', { cwds: [entry.project] });
      assert.equal(listed.data.length, 1);
      assert.deepEqual(listed.data[0].errors, []);
      assert.equal(listed.data[0].hooks.length, 2);
      let sessionResult;
      if (session) {
        const started = await request('thread/start', { cwd: entry.project, ephemeral: true });
        await request('turn/start', { threadId: started.thread.id,
          input: [{ type: 'text', text: 'Reply with the fixed synthetic completion.', text_elements: [] }] });
        const finished = await turnFinished;
        assert.equal(finished.turn.status, 'completed');
        sessionResult = { threadId: started.thread.id, hooks: notifications.filter(value => value.method === 'hook/completed').map(value => value.params.run) };
        await request('thread/unsubscribe', { threadId: started.thread.id });
      }
      return { hooks: listed.data[0].hooks, session: sessionResult };
    } finally { lines.close(); for (const timer of timers) clearTimeout(timer); }
  })).value;
}

try {
  for (const entry of manifest.cases) {
    const configPath = join(entry.home, 'config.toml');
    const config = `model = "synthetic-context-relay"\nmodel_provider = "fixture"\n` +
      `approval_policy = "never"\nsandbox_mode = "danger-full-access"\n` +
      `[model_providers.fixture]\nname = "Local fixture"\nbase_url = "http://127.0.0.1:${server.address().port}/v1"\n` +
      `wire_api = "responses"\nenv_key = "CONTEXT_RELAY_FIXTURE_KEY"\nrequest_max_retries = 0\nstream_max_retries = 0\n` +
      `[memories]\ngenerate_memories = false\nuse_memories = false\n[features]\nhooks = true\nshell_snapshot = false\n` +
      `[projects.${JSON.stringify(entry.project.toLowerCase())}]\ntrust_level = "trusted"\n`;
    fs.writeFileSync(configPath, config);
    const hookFile = join(entry.home, 'hooks.json');
    fs.writeFileSync(hookFile, JSON.stringify({ hooks: entry.hooks }));
    const { hooks: initial } = await listedHooks(entry);
    assert.ok(initial.every(hook => hook.trustStatus === 'untrusted' && !hook.isManaged && hook.enabled));
    // Only the two inert, fixture-owned definitions are trusted in this disposable
    // home. This matches upstream 0.144.6's trust_discovered_hooks test fixture.
    const trust = initial.map(hook => `\n[hooks.state.${JSON.stringify(hook.key)}]\ntrusted_hash = ${JSON.stringify(hook.currentHash)}\n`).join('');
    for (const phase of ['untrusted', 'trusted', 'modified']) {
      if (phase === 'trusted') fs.writeFileSync(configPath, config + trust);
      if (phase === 'modified') {
        const hooks = structuredClone(entry.hooks);
        for (const event of ['SessionStart', 'Stop']) hooks[event][0].hooks[0].statusMessage = 'Changed synthetic definition';
        fs.writeFileSync(hookFile, JSON.stringify({ hooks }));
      }
      const { hooks: listed } = await listedHooks(entry);
      assert.ok(listed.every(hook => hook.trustStatus === phase));
      const before = fs.readFileSync(configPath);
      for (const surface of ['exec', 'app-server']) {
        const beforeRequests = requests;
        let threadId;
        let detail = '';
        if (surface === 'exec') {
          const session = await run(entry, ['exec', '--json', '--ephemeral', '--skip-git-repo-check', 'Reply with the fixed synthetic completion.']);
          const events = session.stdout.trim().split(/\r?\n/).map(line => JSON.parse(line));
          assert.ok(events.some(event => event.type === 'turn.completed'), session.stdout);
          threadId = events.find(event => event.type === 'thread.started').thread_id;
          detail = session.stderr;
        } else {
          const { session } = await listedHooks(entry, true);
          threadId = session.threadId;
          assert.equal(session.hooks.length, phase === 'trusted' ? 2 : 0);
          assert.ok(session.hooks.every(hook => hook.status === 'completed'), JSON.stringify(session.hooks));
        }
        assert.equal(requests - beforeRequests, 1, detail);
        for (const [file, eventName] of [['hook-input.json', 'SessionStart'], ['hook-stop-input.json', 'Stop']]) {
          const output = join(entry.root, file);
          assert.equal(fs.existsSync(output), phase === 'trusted', `${entry.name}/${phase}/${surface}/${eventName}: ${detail}`);
          if (phase === 'trusted') {
            const input = JSON.parse(fs.readFileSync(output, 'utf8'));
            assert.equal(input.session_id, threadId);
            assert.equal(input.hook_event_name, eventName);
            assert.equal(fs.realpathSync(input.cwd), fs.realpathSync(entry.project));
            fs.unlinkSync(output);
          }
        }
        console.log(JSON.stringify({ case: entry.name, phase, surface, sessionCompleted: true, hooksDelivered: phase === 'trusted' }));
      }
      assert.equal(fs.readFileSync(configPath, 'utf8'), before.toString('utf8'));
    }
  }
  assert.deepEqual(failures, []);
  assert.equal(hash(manifest.executable), manifest.sha256);
} finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
