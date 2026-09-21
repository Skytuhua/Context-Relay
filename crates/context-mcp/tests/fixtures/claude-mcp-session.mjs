// Actual pinned Claude client; synthetic credentials, profiles and loopback model.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';

assert.equal(fs.readFileSync(0, 'utf8'), 'run');
const fixture = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const hash = path => createHash('sha256').update(fs.readFileSync(path)).digest('hex');
assert.equal(hash(fixture.executable), fixture.sha256);
assert.equal(hash(fixture.bridge), fixture.bridgeSha256);
const key = 'context-relay-synthetic-claude-key';
const confirmation = 'CONTEXT_RELAY_NATIVE_CLAUDE_OK';
const env = { SystemRoot: process.env.SystemRoot, WINDIR: process.env.WINDIR,
  COMSPEC: join(process.env.SystemRoot, 'System32/cmd.exe'), PATH: join(process.env.SystemRoot, 'System32'),
  PATHEXT: '.COM;.EXE;.BAT;.CMD', CLAUDE_CONFIG_DIR: fixture.config,
  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: '1', DISABLE_AUTOUPDATER: '1', ENABLE_TOOL_SEARCH: 'false',
};
for (const name of ['HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'PROGRAMDATA', 'ProgramFiles', 'TEMP', 'TMP', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_DATA_HOME']) env[name] = fixture.home;

async function run(args, executable = fixture.executable) {
  const child = spawn(executable, args, { env, cwd: fixture.project, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '', timer;
  try {
    const code = await new Promise((resolve, reject) => {
      const fail = error => { child.kill(); reject(error); };
      timer = setTimeout(() => fail(new Error(`Claude deadline: ${stderr.slice(0, 4096)}`)), 90000);
      child.once('error', fail); child.once('close', resolve);
      child.stdout.on('data', chunk => { stdout += chunk; if (stdout.length > 1024 * 1024) fail(new Error('Claude stdout limit')); });
      child.stderr.on('data', chunk => { stderr += chunk; if (stderr.length > 65536) fail(new Error('Claude stderr limit')); });
    });
    assert.equal(code, 0, `${stderr.slice(0, 4096)}\n${stdout.slice(0, 4096)}`);
    return stdout;
  } finally { clearTimeout(timer); child.kill(); }
}

assert.equal((await run(['--version'])).trim(), '2.1.202 (Claude Code)');
assert.equal((await run(['--fixture-info'], fixture.bridge)).trim(), 'context-relay-isolated-codex-bridge-fixture-v1');
const declaration = { type: 'stdio', command: fixture.bridge, args: ['--harness', 'claude-code'] };
await run(['mcp', 'add-json', 'context-relay', JSON.stringify(declaration), '--scope', 'user']);
const statePath = join(fixture.config, '.claude.json');
const savedDeclaration = JSON.parse(fs.readFileSync(statePath, 'utf8')).mcpServers['context-relay'];
assert.deepEqual(savedDeclaration, declaration);
const settingsPath = join(fixture.config, 'settings.json');
const settings = JSON.stringify({ hooks: fixture.hooks, autoMemoryEnabled: false, fixtureCanary: true });
fs.writeFileSync(settingsPath, settings);

let step = 0, requests = 0, memory, task;
const failures = [];
function resultFrom(body) {
  const results = body.messages.flatMap(message => Array.isArray(message.content) ? message.content : [])
    .filter(item => item.type === 'tool_result' && item.tool_use_id === `tool_${step - 1}`);
  assert.equal(results.length, 1, `missing result for step ${step}`);
  const result = results[0];
  assert.notEqual(result.is_error, true, JSON.stringify(result).slice(0, 4096));
  const text = typeof result.content === 'string' ? result.content
    : result.content.filter(item => item.type === 'text').map(item => item.text).join('\n');
  return JSON.parse(text);
}
const server = createServer(async (req, res) => {
  try {
    assert.ok(++requests <= 32, 'request limit');
    let length = 0; const chunks = [];
    for await (const chunk of req) { length += chunk.length; assert.ok(length <= 2 * 1024 * 1024, 'request size limit'); chunks.push(chunk); }
    if (req.method === 'HEAD' && req.url === '/' && length === 0) {
      assert.equal(req.headers['x-api-key'], undefined); assert.equal(req.headers.authorization, undefined);
      res.writeHead(200).end(); return;
    }
    assert.equal(req.method, 'POST');
    assert.equal(req.headers['x-api-key'], key); assert.equal(req.headers.authorization, undefined);
    const path = new URL(req.url, 'http://127.0.0.1').pathname;
    assert.ok(['/v1/messages', '/v1/messages/count_tokens'].includes(path));
    const body = JSON.parse(Buffer.concat(chunks));
    if (path.endsWith('/count_tokens')) { res.writeHead(200, { 'content-type': 'application/json' }).end('{"input_tokens":100}'); return; }
    assert.ok(step <= 8, 'unexpected model request');
    const names = body.tools.map(tool => tool.name);
    const prefix = 'mcp__context-relay__';
    assert.deepEqual(names.filter(name => name.startsWith(prefix)).sort(), fixture.toolNames.map(name => prefix + name).sort());
    if (step === 0) assert.ok(JSON.stringify(body).includes('Query Context Relay for the active project'), 'SessionStart reminder missing');
    if (step > 0) {
      const result = resultFrom(body);
      if (step === 1) { assert.equal(result.vault, 'unlocked'); assert.equal(result.resolvedProject, fixture.projectId); }
      if (step === 2) { memory = result.memory; assert.equal(memory.title, 'Native Claude round trip'); assert.equal(memory.scope.projectId, fixture.projectId); }
      if (step === 3) assert.equal(result.record.record.id, memory.id);
      if (step === 4) assert.ok(result.memories.some(item => item.id === memory.id));
      if (step === 5) { task = result.task; assert.equal(task.status, 'open'); }
      if (step === 6) { task = result.task; assert.equal(task.status, 'done'); assert.equal(task.evidence[0].summary, 'Completed by actual Claude MCP client.'); }
      if (step === 7) assert.ok(result.tasks.some(item => item.id === task.id && item.status === 'done'));
      if (step === 8) { assert.equal(typeof result.handoffId, 'string'); assert.ok(result.payload.tasks.some(item => item.id === task.id)); }
    }
    const calls = [
      ['context_relay_status', {}],
      ['context_relay_remember', { operationId: fixture.operations[0], kind: 'note', title: 'Native Claude round trip', markdown: 'Saved through the actual Claude MCP client. 專案', tags: ['native-fixture'], scope: { scope: 'active_project' } }],
      ['context_relay_get', { recordId: memory?.id }],
      ['context_relay_search', { query: 'Native Claude round trip', scope: { scope: 'active_project' }, limit: 10 }],
      ['context_relay_upsert_task', { operationId: fixture.operations[1], taskId: null, expectedRevision: null, title: 'Native Claude task', bodyMarkdown: 'Complete the native fixture.', status: 'open' }],
      ['context_relay_complete_task', { operationId: fixture.operations[2], taskId: task?.id, expectedRevision: task?.revision, evidence: [{ kind: 'result', summary: 'Completed by actual Claude MCP client.' }] }],
      ['context_relay_list_tasks', { status: 'done' }],
      ['context_relay_create_handoff', { operationId: fixture.operations[3], memoryIds: [memory?.id], decisionIds: [], taskIds: [task?.id], summary: 'Continue with the context saved by actual Claude.' }],
    ];
    const call = calls[step];
    const content = call ? { type: 'tool_use', id: `tool_${step}`, name: prefix + call[0], input: call[1] } : { type: 'text', text: confirmation };
    const reason = call ? 'tool_use' : 'end_turn';
    const message = { id: `msg_${step}`, type: 'message', role: 'assistant', content: [], model: body.model, stop_reason: null, stop_sequence: null, usage: { input_tokens: 100, output_tokens: 1 } };
    step++;
    if (!body.stream) { res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ ...message, content: [content], stop_reason: reason })); return; }
    const events = [
      { type: 'message_start', message },
      { type: 'content_block_start', index: 0, content_block: call ? { ...content, input: {} } : { type: 'text', text: '' } },
      { type: 'content_block_delta', index: 0, delta: call ? { type: 'input_json_delta', partial_json: JSON.stringify(content.input) } : { type: 'text_delta', text: confirmation } },
      { type: 'content_block_stop', index: 0 },
      { type: 'message_delta', delta: { stop_reason: reason, stop_sequence: null }, usage: { output_tokens: 8 } },
      { type: 'message_stop' },
    ];
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.end(events.map(event => `event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`).join(''));
  } catch (error) { failures.push(error.message); res.writeHead(400).end('Invalid local fixture exchange'); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
env.ANTHROPIC_BASE_URL = `http://127.0.0.1:${server.address().port}`;
env.ANTHROPIC_API_KEY = key;
try {
  const output = await run(['--print', '--output-format', 'json', '--model', 'claude-sonnet-4-6', '--max-turns', '10', '--tools', '', '--allowedTools', 'mcp__context-relay__*', '--', 'Perform the fixed local fixture tool sequence.']);
  assert.deepEqual(failures, []);
  const result = JSON.parse(output);
  assert.equal(result.subtype, 'success', output.slice(0, 4096));
  assert.equal(result.is_error, false);
  assert.equal(result.result, confirmation);
  assert.equal(step, 9);
  assert.equal(fs.readFileSync(settingsPath, 'utf8'), settings);
  assert.deepEqual(JSON.parse(fs.readFileSync(statePath, 'utf8')).mcpServers['context-relay'], savedDeclaration);
  await run(['mcp', 'remove', 'context-relay', '--scope', 'user']);
  assert.equal(JSON.parse(fs.readFileSync(statePath, 'utf8')).mcpServers?.['context-relay'], undefined);
  assert.equal(hash(fixture.executable), fixture.sha256); assert.equal(hash(fixture.bridge), fixture.bridgeSha256);
  console.log(JSON.stringify({ surface: 'Claude --print', memoryId: memory.id, taskId: task.id, taskStatus: task.status, modelRequests: step }));
} catch (error) { throw new Error(`${error.message}\nModel failures: ${JSON.stringify(failures).slice(0, 8192)}`, { cause: error }); }
finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
