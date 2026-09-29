// Actual Claude client, disposable settings, status-only installed-service access.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';

assert.equal(fs.readFileSync(0, 'utf8'), 'run');
const fixture = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const hash = file => createHash('sha256').update(fs.readFileSync(file)).digest('hex');
assert.equal(hash(fixture.executable), fixture.sha256);
assert.equal(hash(fixture.bridge), fixture.bridgeSha256);
assert.equal(fs.existsSync(join(fixture.root, 'context-relay-contextd.exe')), false);
const config = join(fixture.home, 'selected-claude');
fs.mkdirSync(config);
const key = 'context-relay-synthetic-claude-key';
const confirmation = 'CONTEXT_RELAY_INSTALLED_CLAUDE_OK';
const env = { SystemRoot: process.env.SystemRoot, WINDIR: process.env.WINDIR,
  COMSPEC: join(process.env.SystemRoot, 'System32/cmd.exe'), PATH: join(process.env.SystemRoot, 'System32'),
  PATHEXT: '.COM;.EXE;.BAT;.CMD', CLAUDE_CONFIG_DIR: config,
  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: '1', DISABLE_AUTOUPDATER: '1', ENABLE_TOOL_SEARCH: 'false',
};
for (const name of Object.keys(fixture.bridgeEnv)) {
  env[name] = fixture.home;
  assert.notEqual(fixture.bridgeEnv[name].toLowerCase(), fixture.home.toLowerCase());
}

async function run(args) {
  const child = spawn(fixture.executable, args, { env, cwd: fixture.project, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '', timer;
  try {
    const code = await new Promise((resolve, reject) => {
      const fail = error => { child.kill(); reject(error); };
      timer = setTimeout(() => fail(new Error('Claude deadline exceeded')), 60000);
      child.once('error', fail); child.once('close', resolve);
      child.stdout.on('data', chunk => { stdout += chunk; if (stdout.length > 1024 * 1024) fail(new Error('Claude stdout limit')); });
      child.stderr.on('data', chunk => { stderr += chunk; if (stderr.length > 65536) fail(new Error('Claude stderr limit')); });
    });
    assert.equal(code, 0, `${stderr.slice(0, 4096)}\n${stdout.slice(0, 4096)}`);
    return stdout;
  } finally { clearTimeout(timer); child.kill(); }
}

assert.equal((await run(['--version'])).trim(), '2.1.202 (Claude Code)');
// The production bridge restores normal Windows profile directories explicitly;
// none of the fake HOME values above apply to that MCP child.
const declaration = { type: 'stdio', command: fixture.bridge, args: ['--harness', 'claude-code'], env: fixture.bridgeEnv };
await run(['mcp', 'add-json', 'context-relay', JSON.stringify(declaration), '--scope', 'user']);
const statePath = join(config, '.claude.json');
assert.deepEqual(JSON.parse(fs.readFileSync(statePath, 'utf8')).mcpServers['context-relay'], declaration);
const settingsPath = join(config, 'settings.json');
const settings = JSON.stringify({ autoMemoryEnabled: false, fixtureCanary: true });
fs.writeFileSync(settingsPath, settings);

let step = 0, requests = 0;
const failures = [];
const prefix = 'mcp__context-relay__';
const statusTool = prefix + 'context_relay_status';
const server = createServer(async (req, res) => {
  try {
    assert.ok(++requests <= 12, 'request limit');
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
    assert.ok(step <= 1, 'unexpected model request');
    assert.deepEqual(body.tools.map(tool => tool.name), [statusTool]);
    if (step === 1) {
      const results = body.messages.flatMap(message => Array.isArray(message.content) ? message.content : [])
        .filter(item => item.type === 'tool_result' && item.tool_use_id === 'installed_status');
      assert.equal(results.length, 1, 'Status result missing');
      assert.notEqual(results[0].is_error, true, 'Status tool failed');
      const content = results[0].content;
      const text = typeof content === 'string' ? content : content.filter(item => item.type === 'text').map(item => item.text).join('\n');
      const result = JSON.parse(text);
      assert.deepEqual(result.protocol, { min: fixture.protocol, max: fixture.protocol });
      assert.equal(result.vault, 'unlocked'); assert.equal(result.resolvedProject, null);
    }
    const call = step === 0;
    const content = call ? { type: 'tool_use', id: 'installed_status', name: statusTool, input: {} } : { type: 'text', text: confirmation };
    const reason = call ? 'tool_use' : 'end_turn';
    const message = { id: `msg_${step}`, type: 'message', role: 'assistant', content: [], model: body.model, stop_reason: null, stop_sequence: null, usage: { input_tokens: 100, output_tokens: 1 } };
    step++;
    if (!body.stream) { res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ ...message, content: [content], stop_reason: reason })); return; }
    const events = [
      { type: 'message_start', message },
      { type: 'content_block_start', index: 0, content_block: call ? { ...content, input: {} } : { type: 'text', text: '' } },
      { type: 'content_block_delta', index: 0, delta: call ? { type: 'input_json_delta', partial_json: '{}' } : { type: 'text_delta', text: confirmation } },
      { type: 'content_block_stop', index: 0 },
      { type: 'message_delta', delta: { stop_reason: reason, stop_sequence: null }, usage: { output_tokens: 8 } },
      { type: 'message_stop' },
    ];
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.end(events.map(event => `event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`).join(''));
  } catch (error) { failures.push(error.message); res.writeHead(400).end('Invalid local status exchange'); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
env.ANTHROPIC_BASE_URL = `http://127.0.0.1:${server.address().port}`;
env.ANTHROPIC_API_KEY = key;
try {
  const disallowed = fixture.toolNames.filter(name => prefix + name !== statusTool).map(name => prefix + name);
  const output = await run(['--print', '--output-format', 'json', '--model', 'claude-sonnet-4-6', '--max-turns', '3', '--tools', '', '--allowedTools', statusTool, '--disallowedTools', ...disallowed, '--', 'Read Context Relay status once.']);
  assert.deepEqual(failures, []);
  const result = JSON.parse(output);
  assert.equal(result.subtype, 'success'); assert.equal(result.is_error, false);
  assert.equal(result.result, confirmation); assert.equal(step, 2);
  assert.equal(fs.readFileSync(settingsPath, 'utf8'), settings);
  assert.deepEqual(JSON.parse(fs.readFileSync(statePath, 'utf8')).mcpServers['context-relay'], declaration);
  console.log(JSON.stringify({ surface: 'Claude --print', statusCalls: 1, protocol: fixture.protocol, vault: 'unlocked', configurationUnchanged: true }));
} catch (error) { throw new Error(`${error.message}\nModel failures: ${JSON.stringify(failures).slice(0, 8192)}`, { cause: error }); }
finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
