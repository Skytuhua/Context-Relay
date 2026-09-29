// Opt-in real-CLI fixture. Model requests use a dummy key and a loopback server.
// Only synthetic marker matches are retained, never complete model prompts.
import { createServer } from 'node:http';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

// Rust releases this gate only after assigning Node to its owned Windows job.
if (readFileSync(0, 'utf8') !== 'run') throw Error('Missing process containment gate');
const manifest = JSON.parse(readFileSync(process.argv[2], 'utf8'));
if (createHash('sha256').update(readFileSync(manifest.executable)).digest('hex') !== manifest.sha256) {
  throw Error('Unexpected executable');
}
const version = spawnSync(manifest.executable, ['--version'], {
  cwd: manifest.cases[0].project, env: manifest.cases[0].environment,
  windowsHide: true, timeout: 30000, encoding: 'utf8', maxBuffer: 65536,
});
if (version.error || version.status !== 0 || version.stdout.trim() !== manifest.version + ' (Claude Code)') {
  throw Error('Unexpected CLI version');
}
const dummyKey = 'context-relay-local-fixture-key';
const confirmation = 'CONTEXT_RELAY_TEST_OK';
const results = [];

async function run(args, test, env) {
  let stdout = '', stderr = '', limit;
  let rejectRun;
  const failed = new Promise((_, reject) => { rejectRun = reject; });
  const child = spawn(manifest.executable, args, {
    cwd: test.project, env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', data => { stdout += data; boundOutput(); });
  child.stderr.on('data', data => { stderr += data; boundOutput(); });
  function boundOutput() {
    if (stdout.length + stderr.length > 2 * 1024 * 1024) {
      limit = 'Output limit';
      child.kill();
      rejectRun(Error(limit));
    }
  }
  const timer = setTimeout(() => { limit = 'Session timeout'; child.kill(); rejectRun(Error(limit)); }, 30000);
  try {
    const status = await Promise.race([failed, new Promise((resolve, reject) => {
      child.on('error', reject);
      child.on('close', (code, signal) => resolve({ code, signal }));
    })]);
    return { status, stdout, stderr, limit };
  } finally {
    clearTimeout(timer);
  }
}

for (const test of manifest.cases) {
  const requests = [], failures = [];
  let connectivityChecks = 0, requestCount = 0;
  const server = createServer(async (req, res) => {
    try {
      if (++requestCount > 8) throw Error('Request count limit');
      const buffers = [];
      let size = 0;
      for await (const chunk of req) {
        size += chunk.length;
        if (size > 2 * 1024 * 1024) throw Error('Request size limit');
        buffers.push(chunk);
      }
      // The pinned CLI probes the base URL without sending credentials.
      if (req.method === 'HEAD' && req.url === '/' && size === 0
          && req.headers['x-api-key'] === undefined && req.headers.authorization === undefined
          && ++connectivityChecks <= 4) {
        res.writeHead(200).end();
        return;
      }
      if (req.headers['x-api-key'] !== dummyKey || req.headers.authorization !== undefined) {
        throw Error('Unexpected authentication');
      }
      const path = new URL(req.url, 'http://localhost').pathname;
      if (req.method !== 'POST' || !['/v1/messages', '/v1/messages/count_tokens'].includes(path)) {
        throw Error('Unexpected request');
      }
      const json = JSON.parse(Buffer.concat(buffers));
      if (path === '/v1/messages/count_tokens') {
        res.writeHead(200, { 'content-type': 'application/json' }).end('{"input_tokens":100}');
        return;
      }
      if (requests.length >= 4) throw Error('Model request limit');
      const body = JSON.stringify(json);
      requests.push({ markers: Object.fromEntries(
        Object.keys(test.markers).map(marker => [marker, body.includes(marker)]),
      ) });
      const message = {
        id: 'msg_context_relay_fixture', type: 'message', role: 'assistant', content: [],
        model: json.model, stop_reason: null, stop_sequence: null,
        usage: { input_tokens: 100, output_tokens: 1 },
      };
      if (!json.stream) {
        res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({
          ...message, content: [{ type: 'text', text: confirmation }], stop_reason: 'end_turn',
        }));
        return;
      }
      const events = [
        { type: 'message_start', message },
        { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } },
        { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: confirmation } },
        { type: 'content_block_stop', index: 0 },
        { type: 'message_delta', delta: { stop_reason: 'end_turn', stop_sequence: null }, usage: { output_tokens: 8 } },
        { type: 'message_stop' },
      ];
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      for (const event of events) res.write('event: ' + event.type + '\ndata: ' + JSON.stringify(event) + '\n\n');
      res.end();
    } catch (error) {
      failures.push({
        error: error.message, method: req.method,
        path: new URL(req.url, 'http://localhost').pathname,
        hasApiKey: req.headers['x-api-key'] !== undefined,
        hasAuthorization: req.headers.authorization !== undefined,
      });
      res.writeHead(400).end();
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const env = {
    ...test.environment, ANTHROPIC_API_KEY: dummyKey,
    ANTHROPIC_BASE_URL: 'http://127.0.0.1:' + server.address().port,
  };
  let output;
  try {
    output = await run([
      '--print', '--output-format', 'json', '--model', 'claude-sonnet-4-6', '--max-turns', '1',
      ...(test.arguments ?? []), '--tools', 'Read,Write', '--', 'Say the test confirmation.',
    ], test, env);
  } finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
  function readHook(filename) {
    try { return JSON.parse(readFileSync(join(test.root, filename), 'utf8')); }
    catch { failures.push({ error: 'Missing or invalid ' + filename }); return {}; }
  }
  const start = readHook('hook-input.json'), stop = readHook('hook-stop-input.json');
  let result;
  try { result = JSON.parse(output.stdout); } catch { /* Report failure below. */ }
  const passed = output.status.code === 0 && !output.limit
    && result?.result === confirmation && result?.subtype === 'success'
    && failures.length === 0 && requests.length === 1
    && Object.entries(test.markers).every(([marker, expected]) => requests[0].markers[marker] === expected)
    && start.hook_event_name === 'SessionStart' && stop.hook_event_name === 'Stop'
    && start.session_id === stop.session_id && start.session_id === result.session_id;
  const summary = {
    name: test.name, passed, status: output.status, markers: requests[0]?.markers,
    requestCount: requests.length, connectivityChecks, failures, stderr: output.stderr, limit: output.limit,
  };
  results.push({ ...summary, start, stop });
  console.log(JSON.stringify(summary));
}
writeFileSync(manifest.result, JSON.stringify({
  version: manifest.version, sha256: manifest.sha256, results,
}, null, 2));
if (results.some(result => !result.passed)) process.exitCode = 1;
