import assert from 'node:assert/strict';
import { appendFile, chmod, link, mkdtemp, readFile, rm, stat, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import {
  REALTIME_HINT,
  cleanupRealtimeVerifier,
  loadRealtimeVerifierConfig,
  prepareRealtimeVerifier,
  runRealtimeVerifierMode,
  verifyRealtimeVerifier,
} from '../verify-supabase-realtime.mjs';

const UUIDS = [
  '10000000-0000-4000-8000-000000000001',
  '10000000-0000-4000-8000-000000000002',
  '10000000-0000-4000-8000-000000000003',
  '10000000-0000-4000-8000-000000000004',
  '10000000-0000-4000-8000-000000000005',
  '10000000-0000-4000-8000-000000000006',
];
let stateFileSequence = 0;

function directStateFile(t, label = 'state') {
  stateFileSequence += 1;
  const target = `/private/tmp/context-relay-realtime-${process.pid}-${stateFileSequence}-${label}.json`;
  t.after(() => rm(target, { force: true }));
  return target;
}

async function stateRecords(stateFile) {
  return (await readFile(stateFile, 'utf8')).trim().split('\n').map((line) => JSON.parse(line));
}

function jwt(payload) {
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `test-header.${encoded}.test-signature`;
}

class BehavioralRealtimeBackend {
  constructor(config) {
    this.config = config;
    this.users = new Map();
    this.tokens = new Map();
    this.bindings = new Map();
    this.channels = [];
    this.authorizationAttempts = [];
    this.broadcasts = [];
    this.revocations = [];
    this.clients = [];
    this.nextUuid = 0;
    this.failBroadcast = false;
    this.failSignInWithSecrets = false;
    this.failDeleteUsers = false;
    this.interruptAfterCreateNumber = null;
    this.createCount = 0;
    this.deleteAttempts = [];
    this.createdAttributes = [];
    this.journalSnapshots = [];
    this.rpcResponse = undefined;
    this.ambiguousCreateCommitsAfterDeletes = false;
    this.pendingAmbiguousUser = null;
  }

  uuid() {
    return UUIDS[this.nextUuid++];
  }

  makeClient({ role, accessToken, label }) {
    const client = new BehavioralClient(this, { role, accessToken, label, clientId: this.clients.length + 1 });
    this.clients.push(client);
    return client;
  }

  seedBindings(state) {
    for (const label of ['a', 'b']) {
      const user = state.users[label];
      this.bindings.set(user.accountId, {
        accountId: user.accountId,
        deviceId: user.deviceId,
        sessionId: user.sessionId,
        userId: user.userId,
        revoked: false,
      });
    }
  }

  authorize(channel) {
    if (!channel.private) return true;
    if (channel.client.role === 'service') return true;
    const session = this.tokens.get(channel.client.accessToken);
    const topicMatch = /^account:([0-9a-f-]{36}):sync$/.exec(channel.topic);
    const binding = topicMatch && this.bindings.get(topicMatch[1]);
    const allowed = Boolean(
      session && binding && !binding.revoked && binding.sessionId === session.sessionId && binding.userId === session.userId,
    );
    this.authorizationAttempts.push({
      label: channel.client.label,
      topic: channel.topic,
      allowed,
      sessionId: session?.sessionId ?? null,
      clientId: channel.client.clientId,
    });
    return allowed;
  }

  deliver(sender, message) {
    if (this.failBroadcast) return 'error';
    this.broadcasts.push({ topic: sender.topic, event: message.event, payload: message.payload });
    for (const channel of this.channels) {
      if (channel === sender || !channel.subscribed || channel.closed || channel.topic !== sender.topic) continue;
      channel.emitBroadcast(message.event, message.payload);
    }
    return 'ok';
  }
}

class BehavioralClient {
  constructor(backend, { role, accessToken, label, clientId }) {
    this.backend = backend;
    this.role = role;
    this.accessToken = accessToken ?? null;
    this.label = label ?? role;
    this.clientId = clientId;
    this.auth = role === 'service'
      ? {
          admin: {
            createUser: async ({ id, email, password, email_confirm: emailConfirm }) => {
              if (backend.stateFile) {
                const journalStat = await stat(backend.stateFile);
                backend.journalSnapshots.push({
                  inode: journalStat.ino,
                  mode: journalStat.mode & 0o777,
                  state: JSON.parse(await readFile(backend.stateFile, 'utf8')),
                });
              }
              backend.createCount += 1;
              backend.createdAttributes.push({ id, email, emailConfirm });
              const user = { id, email, password, emailConfirm, sessionId: backend.uuid() };
              if (backend.ambiguousCreateCommitsAfterDeletes) {
                backend.pendingAmbiguousUser = user;
                throw new Error('create response lost in transport');
              }
              backend.users.set(user.id, user);
              if (backend.interruptAfterCreateNumber === backend.createCount) {
                throw new Error('simulated interruption after remote user creation');
              }
              return { data: { user: { id: user.id } }, error: null };
            },
            deleteUser: async (id) => {
              backend.deleteAttempts.push(id);
              if (backend.failDeleteUsers) {
                return { data: { user: null }, error: { status: 503, code: 'temporarily_unavailable', message: 'cleanup unavailable' } };
              }
              if (!backend.users.has(id)) {
                if (backend.pendingAmbiguousUser && backend.deleteAttempts.length >= 2) {
                  backend.users.set(backend.pendingAmbiguousUser.id, backend.pendingAmbiguousUser);
                  backend.pendingAmbiguousUser = null;
                }
                return { data: { user: null }, error: { status: 404, code: 'user_not_found', message: 'not found' } };
              }
              backend.users.delete(id);
              return { data: { user: { id } }, error: null };
            },
          },
        }
      : {
          signInWithPassword: async ({ email, password }) => {
            if (backend.failSignInWithSecrets) {
              return {
                data: { user: null, session: null },
                error: new Error(`rejected ${password} ${backend.config.anonKey} ${backend.config.serviceRoleKey} ${backend.config.oauthSecret}`),
              };
            }
            const user = [...backend.users.values()].find((candidate) => candidate.email === email && candidate.password === password);
            if (!user) return { data: { user: null, session: null }, error: new Error('invalid credentials') };
            const accessToken = jwt({ sub: user.id, opaque_test_token: true });
            backend.tokens.set(accessToken, { userId: user.id, sessionId: user.sessionId });
            return {
              data: {
                user: { id: user.id },
                session: {
                  access_token: accessToken,
                  refresh_token: `refresh-${user.id}`,
                  token_type: 'bearer',
                  expires_in: 900,
                  expires_at: 1_800_000_900,
                  user: { id: user.id },
                },
              },
              error: null,
            };
          },
          getClaims: async (accessToken) => {
            const session = backend.tokens.get(accessToken);
            if (!session) return { data: null, error: new Error('invalid access token') };
            return { data: { claims: { sub: session.userId, session_id: session.sessionId } }, error: null };
          },
        };
    this.realtime = {
      setAuth: async (token = null) => {
        this.accessToken = token;
      },
    };
  }

  channel(topic, options = { config: {} }) {
    const existing = this.backend.channels.find((channel) => channel.client === this && channel.topic === topic && !channel.closed);
    if (existing) return existing;
    const channel = new BehavioralChannel(this, topic, options);
    this.backend.channels.push(channel);
    return channel;
  }

  async removeChannel(channel) {
    return channel.unsubscribe();
  }

  async removeAllChannels() {
    const channels = this.backend.channels.filter((channel) => channel.client === this && !channel.closed);
    return Promise.all(channels.map((channel) => channel.unsubscribe()));
  }

  async rpc(name, args) {
    if (this.role !== 'service' || name !== 'service_revoke_device_binding') {
      return { data: null, error: new Error('rpc not permitted') };
    }
    assert.match(args.p_cutoff_hash, /^\\x[0-9a-f]{64}$/);
    assert.match(args.p_cutoff_signature, /^\\x[0-9a-f]{128}$/);
    const binding = this.backend.bindings.get(args.p_account_id);
    if (!binding || binding.deviceId !== args.p_device_id) return { data: null, error: new Error('binding not found') };
    binding.revoked = true;
    this.backend.revocations.push({ ...args, sessionId: binding.sessionId });
    return this.backend.rpcResponse === undefined
      ? { data: null, error: null }
      : this.backend.rpcResponse;
  }
}

class BehavioralChannel {
  constructor(client, topic, options) {
    this.client = client;
    this.topic = topic;
    this.private = options.config?.private === true;
    this.options = options;
    this.listeners = [];
    this.subscribed = false;
    this.closed = false;
  }

  on(type, filter, callback) {
    this.listeners.push({ type, filter, callback });
    return this;
  }

  subscribe(callback, _timeout) {
    queueMicrotask(() => {
      if (this.client.backend.authorize(this)) {
        this.subscribed = true;
        callback?.('SUBSCRIBED');
      } else {
        callback?.('CHANNEL_ERROR', new Error('private channel authorization denied'));
      }
    });
    return this;
  }

  async send(message) {
    if (!this.subscribed || this.closed) return 'error';
    return this.client.backend.deliver(this, message);
  }

  emitBroadcast(event, payload) {
    for (const listener of this.listeners) {
      if (listener.type === 'broadcast' && listener.filter.event === event) {
        listener.callback({ type: 'broadcast', event, payload });
      }
    }
  }

  async unsubscribe() {
    this.subscribed = false;
    this.closed = true;
    return 'ok';
  }
}

function config() {
  const value = {
    url: 'http://127.0.0.1:54321',
    anonKey: 'anon-secret-value',
    serviceRoleKey: 'service-secret-value',
    emailDomain: 'example.test',
    password: 'password-secret-value',
    oauthSecret: 'oauth-secret-value',
  };
  value.secrets = [value.anonKey, value.serviceRoleKey, value.password, value.oauthSecret];
  return value;
}

function dependencies(backend, messages) {
  let randomCall = 0;
  return {
    createClient: (options) => backend.makeClient(options),
    logger: {
      info: (message) => messages.push(String(message)),
      error: (message) => messages.push(String(message)),
    },
    clock: {
      now: () => 1_800_000_000_000,
      setTimeout,
      clearTimeout,
    },
    randomBytes: (size) => {
      randomCall += 1;
      return Buffer.alloc(size, randomCall + 17);
    },
  };
}

async function preparedFixture(t) {
  const stateFile = directStateFile(t);
  const messages = [];
  const verifierConfig = config();
  const backend = new BehavioralRealtimeBackend(verifierConfig);
  backend.stateFile = stateFile;
  const deps = dependencies(backend, messages);
  const result = await prepareRealtimeVerifier({ stateFile, config: verifierConfig, ...deps });
  const records = await stateRecords(stateFile);
  const state = records.at(-1);
  backend.seedBindings(state);
  return { backend, deps, messages, records, result, state, stateFile, verifierConfig };
}

test('requires every hosted credential and has no credential defaults', () => {
  assert.throws(() => loadRealtimeVerifierConfig({}), /SUPABASE_URL.*SUPABASE_ANON_KEY.*SUPABASE_SERVICE_ROLE_KEY.*SUPABASE_REALTIME_TEST_EMAIL_DOMAIN.*SUPABASE_REALTIME_TEST_PASSWORD/);
  const loaded = loadRealtimeVerifierConfig({
    SUPABASE_URL: 'https://project.supabase.co',
    SUPABASE_ANON_KEY: 'anon',
    SUPABASE_SERVICE_ROLE_KEY: 'service',
    SUPABASE_REALTIME_TEST_EMAIL_DOMAIN: 'example.test',
    SUPABASE_REALTIME_TEST_PASSWORD: 'password',
  });
  assert.equal(loaded.url, 'https://project.supabase.co');
  assert.equal(loaded.anonKey, 'anon');
  assert.equal(loaded.serviceRoleKey, 'service');
  assert.equal(loaded.emailDomain, 'example.test');
  assert.equal(loaded.password, 'password');
});

test('prepare creates two unique confirmed users and writes only required IDs and access tokens to a 0600 /private/tmp file', async (t) => {
  const fixture = await preparedFixture(t);
  const fileStat = await stat(fixture.stateFile);
  assert.equal(fileStat.mode & 0o777, 0o600);
  assert.equal(fixture.backend.users.size, 2);
  assert.equal(new Set([...fixture.backend.users.values()].map((user) => user.email)).size, 2);
  assert.ok([...fixture.backend.users.values()].every((user) => user.emailConfirm === true));
  assert.deepEqual(Object.keys(fixture.state).sort(), ['status', 'users', 'version']);
  assert.equal(fixture.state.status, 'ready');
  assert.deepEqual(fixture.records.map((record) => record.status), ['preparing', 'ready']);
  for (const label of ['a', 'b']) {
    assert.deepEqual(Object.keys(fixture.state.users[label]).sort(), [
      'accessToken', 'accountId', 'deviceId', 'sessionId', 'userId',
    ]);
  }
  const serialized = await readFile(fixture.stateFile, 'utf8');
  assert.doesNotMatch(serialized, /refresh-|password-secret|anon-secret|service-secret|oauth-secret/);
  assert.ok(fixture.messages.every((message) => !/test-header|refresh-|password-secret|anon-secret|service-secret|oauth-secret|@example\.test/.test(message)));
  assert.deepEqual(fixture.backend.createdAttributes.map(({ id, emailConfirm }) => ({ id, emailConfirm })), [
    { id: fixture.state.users.a.userId, emailConfirm: true },
    { id: fixture.state.users.b.userId, emailConfirm: true },
  ]);
  assert.equal(fixture.backend.journalSnapshots.length, 2);
  for (const snapshot of fixture.backend.journalSnapshots) {
    assert.equal(snapshot.mode, 0o600);
    assert.equal(snapshot.state.status, 'preparing');
    assert.deepEqual(snapshot.state, {
      version: 1,
      status: 'preparing',
      users: {
        a: { userId: fixture.state.users.a.userId },
        b: { userId: fixture.state.users.b.userId },
      },
    });
  }
  assert.ok(fixture.backend.journalSnapshots.every((snapshot) => snapshot.inode === fileStat.ino));
  assert.deepEqual(fixture.result.users, {
    a: {
      userId: fixture.state.users.a.userId,
      sessionId: fixture.state.users.a.sessionId,
      accountId: fixture.state.users.a.accountId,
      deviceId: fixture.state.users.a.deviceId,
    },
    b: {
      userId: fixture.state.users.b.userId,
      sessionId: fixture.state.users.b.sessionId,
      accountId: fixture.state.users.b.accountId,
      deviceId: fixture.state.users.b.deviceId,
    },
  });
});

test('prepare rejects unsafe paths and refuses to overwrite an existing private file', async (t) => {
  const verifierConfig = config();
  const backend = new BehavioralRealtimeBackend(verifierConfig);
  const deps = dependencies(backend, []);
  await assert.rejects(
    prepareRealtimeVerifier({ stateFile: '/tmp/not-explicitly-private.json', config: verifierConfig, ...deps }),
    /\/private\/tmp/,
  );
  const directory = await mkdtemp('/private/tmp/context-relay-realtime-test-');
  t.after(() => rm(directory, { recursive: true, force: true }));
  const nestedStateFile = path.join(directory, 'nested.json');
  await assert.rejects(
    prepareRealtimeVerifier({ stateFile: nestedStateFile, config: verifierConfig, ...deps }),
    /direct child/,
  );
  const swappableParent = `/private/tmp/context-relay-parent-link-${process.pid}-${stateFileSequence}`;
  t.after(() => rm(swappableParent, { force: true }));
  await symlink(directory, swappableParent);
  await assert.rejects(
    prepareRealtimeVerifier({ stateFile: path.join(swappableParent, 'state.json'), config: verifierConfig, ...deps }),
    /direct child/,
  );

  const stateFile = directStateFile(t, 'existing');
  await writeFile(stateFile, 'keep-me', { mode: 0o600 });
  await assert.rejects(prepareRealtimeVerifier({ stateFile, config: verifierConfig, ...deps }), /already exists/);
  assert.equal(await readFile(stateFile, 'utf8'), 'keep-me');
  assert.equal(backend.users.size, 0);
});

test('a durable preparing journal recovers predetermined users after interruption and failed inline cleanup', async (t) => {
  const stateFile = directStateFile(t, 'recovery');
  const verifierConfig = config();
  const backend = new BehavioralRealtimeBackend(verifierConfig);
  backend.stateFile = stateFile;
  backend.interruptAfterCreateNumber = 1;
  backend.failDeleteUsers = true;
  const deps = dependencies(backend, []);

  await assert.rejects(
    prepareRealtimeVerifier({ stateFile, config: verifierConfig, ...deps }),
    /cleanup unavailable/,
  );
  const journalStat = await stat(stateFile);
  const journal = JSON.parse(await readFile(stateFile, 'utf8'));
  assert.equal(journalStat.mode & 0o777, 0o600);
  assert.equal(journal.status, 'preparing');
  assert.deepEqual(Object.keys(journal.users.a), ['userId']);
  assert.deepEqual(Object.keys(journal.users.b), ['userId']);
  assert.equal(backend.users.size, 1);
  await appendFile(stateFile, '{"version":1');
  await assert.rejects(
    verifyRealtimeVerifier({ stateFile, config: verifierConfig, ...deps }),
    /not ready/,
  );
  assert.equal(backend.users.size, 1);

  backend.failDeleteUsers = false;
  const cleanup = await cleanupRealtimeVerifier({ stateFile, config: verifierConfig, ...deps });
  assert.deepEqual(cleanup.deletedUserIds, [journal.users.a.userId]);
  assert.deepEqual(backend.deleteAttempts.slice(-2), [journal.users.a.userId, journal.users.b.userId]);
  assert.equal(backend.users.size, 0);
});

test('an ambiguous create keeps the journal when the user commits after immediate 404 cleanup', async (t) => {
  const stateFile = directStateFile(t, 'ambiguous-create');
  const verifierConfig = config();
  const backend = new BehavioralRealtimeBackend(verifierConfig);
  backend.stateFile = stateFile;
  backend.ambiguousCreateCommitsAfterDeletes = true;
  const deps = dependencies(backend, []);

  await assert.rejects(
    prepareRealtimeVerifier({ stateFile, config: verifierConfig, ...deps }),
    /create response lost in transport/,
  );
  const journal = (await stateRecords(stateFile))[0];
  assert.equal(journal.status, 'preparing');
  assert.deepEqual(backend.deleteAttempts, [journal.users.a.userId, journal.users.b.userId]);
  assert.equal(backend.users.has(journal.users.a.userId), true);

  const cleanup = await cleanupRealtimeVerifier({ stateFile, config: verifierConfig, ...deps });
  assert.deepEqual(cleanup.deletedUserIds, [journal.users.a.userId]);
  assert.equal(backend.users.size, 0);
});

test('verify exercises own and cross-topic authorization, intended-only delivery, and same-session revocation', async (t) => {
  const fixture = await preparedFixture(t);
  const result = await verifyRealtimeVerifier({
    stateFile: fixture.stateFile,
    config: fixture.verifierConfig,
    ...fixture.deps,
  });

  const topicA = `account:${fixture.state.users.a.accountId}:sync`;
  const topicB = `account:${fixture.state.users.b.accountId}:sync`;
  assert.deepEqual(result.ownTopics, [topicA, topicB]);
  assert.deepEqual(result.crossTopicRejections, [
    { label: 'a', topic: topicB },
    { label: 'b', topic: topicA },
  ]);
  assert.deepEqual(result.deliveries, {
    [topicA]: { a: 1, b: 0 },
    [topicB]: { a: 0, b: 1 },
  });
  assert.deepEqual(fixture.backend.broadcasts, [
    { topic: topicA, event: 'sync_hint', payload: REALTIME_HINT.payload },
    { topic: topicB, event: 'sync_hint', payload: REALTIME_HINT.payload },
  ]);
  assert.equal(fixture.backend.revocations.length, 1);
  assert.equal(fixture.backend.revocations[0].sessionId, fixture.state.users.a.sessionId);
  assert.equal(result.revocation.existingChannelClosed, true);
  assert.equal(result.revocation.freshSameSessionRejected, true);
  const aOwnAttempts = fixture.backend.authorizationAttempts.filter((attempt) => attempt.label === 'a' && attempt.topic === topicA);
  assert.deepEqual(aOwnAttempts.map((attempt) => attempt.allowed), [true, false]);
  assert.notEqual(aOwnAttempts[0].clientId, aOwnAttempts[1].clientId);
});

test('verify rejects incomplete, failed, or non-void service revocation RPC responses', async (t) => {
  for (const response of [
    null,
    { data: null },
    { error: null },
    { data: { unexpected: true }, error: null },
    { data: null, error: new Error('revocation failed') },
  ]) {
    const fixture = await preparedFixture(t);
    fixture.backend.rpcResponse = response;
    await assert.rejects(
      verifyRealtimeVerifier({ stateFile: fixture.stateFile, config: fixture.verifierConfig, ...fixture.deps }),
      /unexpected service revocation RPC response/,
    );
    assert.equal(fixture.backend.users.size, 0);
  }
});

test('verify cleans every channel and both ephemeral users after success and failure', async (t) => {
  const successful = await preparedFixture(t);
  await verifyRealtimeVerifier({ stateFile: successful.stateFile, config: successful.verifierConfig, ...successful.deps });
  assert.equal(successful.backend.channels.filter((channel) => !channel.closed).length, 0);
  assert.equal(successful.backend.users.size, 0);

  const failing = await preparedFixture(t);
  failing.backend.failBroadcast = true;
  await assert.rejects(
    verifyRealtimeVerifier({ stateFile: failing.stateFile, config: failing.verifierConfig, ...failing.deps }),
    /broadcast failed/,
  );
  assert.equal(failing.backend.channels.filter((channel) => !channel.closed).length, 0);
  assert.equal(failing.backend.users.size, 0);
});

test('verify still deletes both users if a user client cannot be constructed', async (t) => {
  const fixture = await preparedFixture(t);
  const originalCreateClient = fixture.deps.createClient;
  await assert.rejects(
    verifyRealtimeVerifier({
      stateFile: fixture.stateFile,
      config: fixture.verifierConfig,
      ...fixture.deps,
      createClient: (options) => {
        if (options.role === 'user' && options.label === 'b') throw new Error('client construction failed');
        return originalCreateClient(options);
      },
    }),
    /client construction failed/,
  );
  assert.equal(fixture.backend.users.size, 0);
});

test('cleanup is idempotent for interrupted runs', async (t) => {
  const fixture = await preparedFixture(t);
  const first = await cleanupRealtimeVerifier({ stateFile: fixture.stateFile, config: fixture.verifierConfig, ...fixture.deps });
  const second = await runRealtimeVerifierMode({ mode: 'cleanup', stateFile: fixture.stateFile, config: fixture.verifierConfig, ...fixture.deps });
  assert.deepEqual(first.deletedUserIds.sort(), [fixture.state.users.a.userId, fixture.state.users.b.userId].sort());
  assert.deepEqual(second.deletedUserIds, []);
  assert.equal(fixture.backend.users.size, 0);
  await assert.rejects(runRealtimeVerifierMode({ mode: 'unknown' }), /unknown Realtime verifier mode/);
});

test('errors and logger output redact access, refresh, service, anon, OAuth, and password values', async (t) => {
  const stateFile = directStateFile(t);
  const verifierConfig = config();
  const backend = new BehavioralRealtimeBackend(verifierConfig);
  backend.stateFile = stateFile;
  backend.failSignInWithSecrets = true;
  const messages = [];
  const deps = dependencies(backend, messages);
  let error;
  try {
    await prepareRealtimeVerifier({ stateFile, config: verifierConfig, ...deps });
  } catch (caught) {
    error = caught;
  }
  assert.ok(error instanceof Error);
  const output = `${error.message}\n${messages.join('\n')}`;
  for (const secret of verifierConfig.secrets) assert.equal(output.includes(secret), false);
  assert.equal(backend.users.size, 0);
  await assert.rejects(stat(stateFile), (statError) => statError.code === 'ENOENT');
});

test('state-file parse and permission errors never include secret file contents', async (t) => {
  const stateFile = directStateFile(t);
  const secretContents = 'refresh-secret-in-file service-secret-in-file';
  await writeFile(stateFile, secretContents, { mode: 0o600 });
  const verifierConfig = config();
  const backend = new BehavioralRealtimeBackend(verifierConfig);
  await assert.rejects(
    cleanupRealtimeVerifier({ stateFile, config: verifierConfig, ...dependencies(backend, []) }),
    (error) => !error.message.includes(secretContents) && /invalid verifier state file/.test(error.message),
  );
  await writeFile(stateFile, JSON.stringify({ version: 1, users: {} }), { mode: 0o644 });
  await chmod(stateFile, 0o644);
  await assert.rejects(
    cleanupRealtimeVerifier({ stateFile, config: verifierConfig, ...dependencies(backend, []) }),
    /mode 0600/,
  );
});

test('verify and cleanup reject symbolic-link state files under /private/tmp', async (t) => {
  const target = directStateFile(t, 'target');
  const stateFile = directStateFile(t, 'symlink');
  await writeFile(target, '{}', { mode: 0o600 });
  await symlink(target, stateFile);
  const verifierConfig = config();
  const backend = new BehavioralRealtimeBackend(verifierConfig);
  await assert.rejects(
    cleanupRealtimeVerifier({ stateFile, config: verifierConfig, ...dependencies(backend, []) }),
    /symbolic link/,
  );
});

test('state files reject unknown secret-bearing fields and hard links', async (t) => {
  const fixture = await preparedFixture(t);
  fixture.state.users.a.refreshToken = 'must-not-be-accepted';
  await writeFile(fixture.stateFile, JSON.stringify(fixture.state));
  await chmod(fixture.stateFile, 0o600);
  await assert.rejects(
    cleanupRealtimeVerifier({ stateFile: fixture.stateFile, config: fixture.verifierConfig, ...fixture.deps }),
    (error) => /unknown fields/.test(error.message) && !error.message.includes('must-not-be-accepted'),
  );

  delete fixture.state.users.a.refreshToken;
  await writeFile(fixture.stateFile, JSON.stringify(fixture.state));
  const hardLink = directStateFile(t, 'hard-link');
  await link(fixture.stateFile, hardLink);
  await assert.rejects(
    cleanupRealtimeVerifier({ stateFile: hardLink, config: fixture.verifierConfig, ...fixture.deps }),
    /hard link/,
  );
});
