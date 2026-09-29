import { randomBytes as nodeRandomBytes } from 'node:crypto';
import { constants as filesystemConstants } from 'node:fs';
import * as nodeFilesystem from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { createClient as createSupabaseClient } from '@supabase/supabase-js';

export const REALTIME_HINT = Object.freeze({
  event: 'sync_hint',
  payload: Object.freeze({ version: 1, kind: 'pull_now' }),
  private: true,
});

const STATE_VERSION = 1;
const LABELS = ['a', 'b'];
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const REQUIRED_ENVIRONMENT = [
  'SUPABASE_URL',
  'SUPABASE_ANON_KEY',
  'SUPABASE_SERVICE_ROLE_KEY',
  'SUPABASE_REALTIME_TEST_EMAIL_DOMAIN',
  'SUPABASE_REALTIME_TEST_PASSWORD',
];

const defaultClock = {
  now: () => Date.now(),
  setTimeout: (...arguments_) => setTimeout(...arguments_),
  clearTimeout: (...arguments_) => clearTimeout(...arguments_),
};

function requiredString(value, name) {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`${name} is required`);
  return value;
}

export function verifierTempRoot(platform = process.platform) {
  if (platform === 'darwin') return '/private/tmp';
  if (platform === 'linux') return '/tmp';
  throw new Error(`unsupported verifier platform: ${String(platform)}`);
}

export function loadRealtimeVerifierConfig(environment = process.env) {
  const missing = REQUIRED_ENVIRONMENT.filter((name) => !environment[name]);
  if (missing.length > 0) throw new Error(`missing required environment: ${missing.join(', ')}`);

  let url;
  try {
    url = new URL(environment.SUPABASE_URL);
  } catch {
    throw new Error('SUPABASE_URL must be a valid http(s) URL');
  }
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('SUPABASE_URL must be a valid http(s) URL');

  const emailDomain = environment.SUPABASE_REALTIME_TEST_EMAIL_DOMAIN;
  if (!/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/i.test(emailDomain) || emailDomain.includes('..')) {
    throw new Error('SUPABASE_REALTIME_TEST_EMAIL_DOMAIN must be a bare email domain');
  }

  const sensitiveValues = Object.entries(environment)
    .filter(([name, value]) => value && /(?:access|refresh|service|anon|oauth|password|secret|token|key)/i.test(name))
    .map(([, value]) => String(value));

  return {
    url: url.href.replace(/\/$/, ''),
    anonKey: environment.SUPABASE_ANON_KEY,
    serviceRoleKey: environment.SUPABASE_SERVICE_ROLE_KEY,
    emailDomain,
    password: environment.SUPABASE_REALTIME_TEST_PASSWORD,
    subscribeTimeoutMs: 10_000,
    deliveryTimeoutMs: 5_000,
    deliverySettleMs: 100,
    secrets: [...new Set(sensitiveValues)],
  };
}

function makeRedactor(config) {
  const secrets = new Set([
    config?.anonKey,
    config?.serviceRoleKey,
    config?.password,
    config?.oauthSecret,
    ...(config?.secrets ?? []),
  ].filter((value) => typeof value === 'string' && value.length > 0));

  return {
    add(value) {
      if (typeof value === 'string' && value.length > 0) secrets.add(value);
    },
    text(value) {
      let result = value instanceof Error || (value && typeof value === 'object' && typeof value.message === 'string')
        ? value.message
        : String(value);
      for (const secret of [...secrets].sort((left, right) => right.length - left.length)) {
        result = result.split(secret).join('[REDACTED]');
      }
      result = result.replace(/\beyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b/g, '[REDACTED_JWT]');
      return result;
    },
  };
}

function safeError(label, error, redactor) {
  return new Error(`${label}: ${redactor.text(error ?? 'unknown error')}`);
}

function verifierStatePath(stateFile) {
  requiredString(stateFile, 'state file');
  const tempRoot = verifierTempRoot();
  if (!path.isAbsolute(stateFile)) throw new Error(`state file must be an absolute path under ${tempRoot}`);
  const normalized = path.normalize(stateFile);
  if (path.dirname(normalized) !== tempRoot || path.basename(normalized) === '') {
    throw new Error(`state file must be a direct child of ${tempRoot}`);
  }
  return normalized;
}

function assertUuid(value, field) {
  if (typeof value !== 'string' || !UUID_PATTERN.test(value)) throw new Error(`invalid verifier state file: ${field} must be a UUID`);
}

function assertExactKeys(value, expected, field) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new Error(`invalid verifier state file: ${field} has unknown fields`);
  }
}

function validateState(parsed, { allowPreparing }) {
  if (!parsed || typeof parsed !== 'object' || parsed.version !== STATE_VERSION || !parsed.users || typeof parsed.users !== 'object') {
    throw new Error('invalid verifier state file: unsupported shape');
  }
  assertExactKeys(parsed, ['version', 'status', 'users'], 'root');
  assertExactKeys(parsed.users, LABELS, 'users');
  if (!['preparing', 'ready'].includes(parsed.status)) throw new Error('invalid verifier state file: unsupported status');
  if (parsed.status === 'preparing' && !allowPreparing) throw new Error('verifier state file is not ready');
  for (const label of LABELS) {
    const user = parsed.users[label];
    if (!user || typeof user !== 'object') throw new Error(`invalid verifier state file: user ${label} is missing`);
    if (parsed.status === 'preparing') {
      assertExactKeys(user, ['userId'], `users.${label}`);
      assertUuid(user.userId, `users.${label}.userId`);
    } else {
      assertExactKeys(user, ['userId', 'sessionId', 'accountId', 'deviceId', 'accessToken'], `users.${label}`);
      for (const field of ['userId', 'sessionId', 'accountId', 'deviceId']) assertUuid(user[field], `users.${label}.${field}`);
      if (typeof user.accessToken !== 'string' || user.accessToken.length === 0) {
        throw new Error(`invalid verifier state file: users.${label}.accessToken is missing`);
      }
    }
  }
  return parsed;
}

function parseStateLog(text, { allowPreparing }) {
  const lines = text.endsWith('\n') ? text.slice(0, -1).split('\n') : text.split('\n');
  if (lines.length === 0 || lines[0] === '') throw new Error('invalid verifier state file: malformed JSON');
  if (lines.length === 1) return validateState(JSON.parse(lines[0]), { allowPreparing });
  if (lines.length !== 2) throw new Error('invalid verifier state file: unexpected journal records');

  const preparing = validateState(JSON.parse(lines[0]), { allowPreparing: true });
  if (preparing.status !== 'preparing') throw new Error('invalid verifier state file: journal must begin in preparing state');
  try {
    const ready = validateState(JSON.parse(lines[1]), { allowPreparing: false });
    if (ready.status !== 'ready') throw new Error('invalid verifier state file: journal did not reach ready state');
    return ready;
  } catch (error) {
    if (allowPreparing && (error instanceof SyntaxError || error?.message === 'verifier state file is not ready')) return preparing;
    if (!allowPreparing && error instanceof SyntaxError) throw new Error('verifier state file is not ready');
    throw error;
  }
}

async function readState(stateFile, filesystem, redactor, { allowPreparing = false } = {}) {
  const target = verifierStatePath(stateFile);
  let fileStat;
  try {
    fileStat = await filesystem.lstat(target);
  } catch (error) {
    throw safeError('unable to inspect verifier state file', error, redactor);
  }
  if (typeof fileStat.isSymbolicLink === 'function' && fileStat.isSymbolicLink()) {
    throw new Error('verifier state file must not be a symbolic link');
  }
  if (typeof fileStat.isFile === 'function' && !fileStat.isFile()) throw new Error('verifier state file must be a regular file');
  if (fileStat.nlink !== 1) throw new Error('verifier state file must not be a hard link');
  if (typeof process.getuid === 'function' && fileStat.uid !== process.getuid()) {
    throw new Error('verifier state file must be owned by the current user');
  }
  if ((fileStat.mode & 0o777) !== 0o600) throw new Error('verifier state file must have mode 0600');
  if (fileStat.size > 65_536) throw new Error('verifier state file is too large');

  let text;
  let handle;
  try {
    handle = await filesystem.open(target, filesystemConstants.O_RDONLY | filesystemConstants.O_NOFOLLOW);
    const openedStat = await handle.stat();
    if (openedStat.dev !== fileStat.dev || openedStat.ino !== fileStat.ino) {
      throw new Error('verifier state file changed while opening');
    }
    text = await handle.readFile('utf8');
  } catch (error) {
    if (error?.code === 'ELOOP') throw new Error('verifier state file must not be a symbolic link');
    throw safeError('unable to read verifier state file', error, redactor);
  } finally {
    await handle?.close();
  }
  try {
    return parseStateLog(text, { allowPreparing });
  } catch (error) {
    if (error?.message?.startsWith('invalid verifier state file:') || error?.message === 'verifier state file is not ready') throw error;
    throw new Error('invalid verifier state file: malformed JSON');
  }
}

async function openRecoveryJournal(stateFile, filesystem, redactor) {
  let handle;
  try {
    handle = await filesystem.open(
      stateFile,
      filesystemConstants.O_RDWR
        | filesystemConstants.O_CREAT
        | filesystemConstants.O_EXCL
        | filesystemConstants.O_NOFOLLOW
        | (filesystemConstants.O_CLOEXEC ?? 0),
      0o600,
    );
    await handle.chmod(0o600);
    const fileStat = await handle.stat();
    if (!fileStat.isFile() || fileStat.nlink !== 1 || (fileStat.mode & 0o777) !== 0o600) {
      throw new Error('new verifier state file is not a strict 0600 regular file');
    }
    if (typeof process.getuid === 'function' && fileStat.uid !== process.getuid()) {
      throw new Error('new verifier state file is not owned by the current user');
    }
    return handle;
  } catch (error) {
    let cleanupError = null;
    if (handle) {
      try {
        await unlinkOpenedState(stateFile, handle, filesystem, redactor);
      } catch (caught) {
        cleanupError = caught;
      }
    }
    await handle?.close().catch(() => {});
    if (error?.code === 'EEXIST') throw new Error('state file already exists');
    const primary = safeError('failed to create verifier recovery journal', error, redactor);
    throw cleanupError ? new Error(`${primary.message}; ${redactor.text(cleanupError)}`) : primary;
  }
}

async function writeOpenedState(handle, state, redactor, { append = false } = {}) {
  const bytes = Buffer.from(`${JSON.stringify(state)}\n`, 'utf8');
  if (bytes.length > 65_536) throw new Error('verifier state file is too large');
  let offset = 0;
  try {
    const position = append ? (await handle.stat()).size : 0;
    if (position + bytes.length > 65_536) throw new Error('verifier state file is too large');
    while (offset < bytes.length) {
      const { bytesWritten } = await handle.write(bytes, offset, bytes.length - offset, position + offset);
      if (bytesWritten <= 0) throw new Error('zero-byte state write');
      offset += bytesWritten;
    }
    if (!append) await handle.truncate(bytes.length);
    await handle.sync();
  } catch (error) {
    throw safeError('failed to persist verifier recovery journal', error, redactor);
  }
}

async function unlinkOpenedState(stateFile, handle, filesystem, redactor) {
  let currentStat;
  try {
    currentStat = await filesystem.lstat(stateFile);
  } catch (error) {
    if (error?.code === 'ENOENT') return;
    throw safeError('failed to inspect verifier recovery journal for removal', error, redactor);
  }
  const openedStat = await handle.stat();
  if (currentStat.isSymbolicLink() || currentStat.dev !== openedStat.dev || currentStat.ino !== openedStat.ino) {
    throw new Error('verifier recovery journal path changed before removal');
  }
  try {
    await filesystem.unlink(stateFile);
  } catch (error) {
    throw safeError('failed to remove verifier recovery journal', error, redactor);
  }
}

function randomUuid(randomBytes) {
  const bytes = Buffer.from(randomBytes(16));
  if (bytes.length !== 16) throw new Error('randomBytes must return the requested byte count');
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function publicUserState(user) {
  return {
    userId: user.userId,
    sessionId: user.sessionId,
    accountId: user.accountId,
    deviceId: user.deviceId,
  };
}

function isMissingUserError(error) {
  return error?.status === 404 || error?.code === 'user_not_found' || /user.*not found/i.test(error?.message ?? '');
}

async function deleteUsers(serviceClient, userIds, redactor) {
  const deletedUserIds = [];
  const failures = [];
  for (const userId of [...new Set(userIds.filter(Boolean))]) {
    try {
      const { error } = await serviceClient.auth.admin.deleteUser(userId);
      if (error && !isMissingUserError(error)) throw error;
      if (!error) deletedUserIds.push(userId);
    } catch (error) {
      if (!isMissingUserError(error)) failures.push(safeError(`failed to delete ephemeral user ${userId}`, error, redactor));
    }
  }
  if (failures.length > 0) throw new Error(failures.map((error) => error.message).join('; '));
  return deletedUserIds;
}

async function cleanupChannels(clients, redactor) {
  const failures = [];
  for (const client of clients.filter(Boolean)) {
    try {
      const results = await client.removeAllChannels();
      for (const result of results ?? []) {
        if (result !== 'ok' && result !== 'timed out') throw new Error(`channel removal returned ${String(result)}`);
      }
    } catch (error) {
      failures.push(safeError('failed to remove Realtime channels', error, redactor));
    }
  }
  if (failures.length > 0) throw new Error(failures.map((error) => error.message).join('; '));
}

function privateChannel(client, topic) {
  return client.channel(topic, {
    config: {
      private: true,
      broadcast: { ack: true, self: false },
    },
  });
}

function topicFor(accountId) {
  return `account:${accountId}:sync`;
}

function waitForSubscription(channel, expectation, timeoutMs, clock, redactor) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      clock.clearTimeout(timer);
      callback(value);
    };
    const timer = clock.setTimeout(
      () => finish(reject, new Error(`Realtime subscription did not ${expectation === 'accept' ? 'succeed' : 'reject'} before timeout`)),
      timeoutMs + 50,
    );

    try {
      channel.subscribe((status, error) => {
        if (expectation === 'accept' && status === 'SUBSCRIBED') return finish(resolve, status);
        if (expectation === 'reject' && status === 'CHANNEL_ERROR') return finish(resolve, status);
        if (status === 'TIMED_OUT') return finish(reject, new Error('Realtime subscription timed out'));
        if (status === 'CLOSED') return finish(reject, new Error('Realtime subscription closed before authorization completed'));
        if (status === 'CHANNEL_ERROR') return finish(reject, safeError('Realtime subscription failed', error, redactor));
        if (status === 'SUBSCRIBED') return finish(reject, new Error('cross-account Realtime subscription was authorized'));
        return undefined;
      }, timeoutMs);
    } catch (error) {
      finish(reject, safeError('Realtime subscription threw', error, redactor));
    }
  });
}

function delay(milliseconds, clock) {
  return new Promise((resolve) => clock.setTimeout(resolve, milliseconds));
}

async function waitForDelivery(predicate, timeoutMs, clock) {
  let elapsedMs = 0;
  while (!predicate()) {
    if (elapsedMs >= timeoutMs) throw new Error('timed out waiting for intended Realtime delivery');
    const intervalMs = Math.min(20, timeoutMs - elapsedMs);
    await delay(intervalMs, clock);
    elapsedMs += intervalMs;
  }
}

function assertFrozenPayload(message) {
  const keys = Object.keys(message ?? {}).sort();
  if (keys.length !== 2 || keys[0] !== 'kind' || keys[1] !== 'version' || message.version !== 1 || message.kind !== 'pull_now') {
    throw new Error('received an invalid Realtime hint payload');
  }
}

function operationDependencies(options) {
  return {
    filesystem: options.filesystem ?? nodeFilesystem,
    logger: options.logger ?? console,
    clock: options.clock ?? defaultClock,
    randomBytes: options.randomBytes ?? nodeRandomBytes,
    createClient: options.createClient,
  };
}

export async function prepareRealtimeVerifier(options) {
  const config = options.config;
  const redactor = makeRedactor(config);
  const { filesystem, logger, clock, randomBytes, createClient } = operationDependencies(options);
  const stateFile = verifierStatePath(options.stateFile);
  if (typeof createClient !== 'function') throw new Error('createClient dependency is required');

  const predeterminedUsers = {
    a: { userId: randomUuid(randomBytes) },
    b: { userId: randomUuid(randomBytes) },
  };
  let journalHandle = await openRecoveryJournal(stateFile, filesystem, redactor);
  let serviceClient = null;
  let remoteCreateAttempted = false;
  let ambiguousCreateOutcome = false;
  try {
    await writeOpenedState(journalHandle, {
      version: STATE_VERSION,
      status: 'preparing',
      users: predeterminedUsers,
    }, redactor);
    serviceClient = createClient({ role: 'service' });
    const users = {};
    for (const label of LABELS) {
      const unique = `${clock.now()}-${Buffer.from(randomBytes(12)).toString('hex')}`;
      const email = `context-relay-realtime-${label}-${unique}@${config.emailDomain}`;
      remoteCreateAttempted = true;
      let userId;
      try {
        const createResult = await serviceClient.auth.admin.createUser({
          id: predeterminedUsers[label].userId,
          email,
          password: config.password,
          email_confirm: true,
        });
        if (createResult.error) throw safeError(`failed to create ephemeral user ${label}`, createResult.error, redactor);
        userId = createResult.data?.user?.id;
        assertUuid(userId, `created user ${label}`);
        if (userId !== predeterminedUsers[label].userId) throw new Error(`created user ${label} did not retain its predetermined ID`);
      } catch (error) {
        ambiguousCreateOutcome = true;
        throw error;
      }

      const userClient = createClient({ role: 'user', label });
      const signInResult = await userClient.auth.signInWithPassword({ email, password: config.password });
      if (signInResult.error) throw safeError(`failed to sign in ephemeral user ${label}`, signInResult.error, redactor);
      const accessToken = signInResult.data?.session?.access_token;
      requiredString(accessToken, `ephemeral user ${label} access token`);
      redactor.add(accessToken);
      redactor.add(signInResult.data?.session?.refresh_token);
      const claimsResult = await userClient.auth.getClaims(accessToken);
      if (claimsResult.error) throw safeError(`failed to validate ephemeral user ${label} claims`, claimsResult.error, redactor);
      const claims = claimsResult.data?.claims;
      if (!claims || typeof claims !== 'object') throw new Error(`ephemeral user ${label} claims are missing`);
      const sessionId = claims.session_id;
      assertUuid(sessionId, `ephemeral user ${label} session`);
      if (claims.sub !== userId || signInResult.data?.user?.id !== userId) throw new Error(`ephemeral user ${label} identity mismatch`);

      users[label] = {
        userId,
        sessionId,
        accountId: randomUuid(randomBytes),
        deviceId: randomUuid(randomBytes),
        accessToken,
      };
    }

    const state = { version: STATE_VERSION, status: 'ready', users };
    await writeOpenedState(journalHandle, state, redactor, { append: true });

    const result = {
      mode: 'prepare',
      users: {
        a: publicUserState(users.a),
        b: publicUserState(users.b),
      },
    };
    logger.info(JSON.stringify(result));
    await journalHandle.close();
    journalHandle = null;
    return result;
  } catch (error) {
    const failures = [error];
    let usersConfirmedAbsent = !remoteCreateAttempted;
    if (serviceClient && remoteCreateAttempted) {
      try {
        await deleteUsers(serviceClient, LABELS.map((label) => predeterminedUsers[label].userId), redactor);
        usersConfirmedAbsent = !ambiguousCreateOutcome;
      } catch (cleanupError) {
        failures.push(cleanupError);
      }
    }
    if (usersConfirmedAbsent) {
      try {
        await unlinkOpenedState(stateFile, journalHandle, filesystem, redactor);
      } catch (removeError) {
        failures.push(removeError);
      }
    }
    try {
      await journalHandle?.close();
      journalHandle = null;
    } catch (closeError) {
      failures.push(safeError('failed to close verifier recovery journal', closeError, redactor));
    }
    throw new Error(failures.map((failure) => redactor.text(failure)).join('; '));
  }
}

export async function verifyRealtimeVerifier(options) {
  const config = options.config;
  const redactor = makeRedactor(config);
  const { filesystem, logger, clock, randomBytes, createClient } = operationDependencies(options);
  if (typeof createClient !== 'function') throw new Error('createClient dependency is required');
  const state = await readState(options.stateFile, filesystem, redactor);
  for (const label of LABELS) redactor.add(state.users[label].accessToken);

  let serviceClient = null;
  const userClients = {};
  const clients = [];
  let primaryError = null;
  let result;
  try {
    serviceClient = createClient({ role: 'service' });
    clients.push(serviceClient);
    userClients.a = createClient({ role: 'user', label: 'a' });
    clients.push(userClients.a);
    userClients.b = createClient({ role: 'user', label: 'b' });
    clients.push(userClients.b);
    await serviceClient.realtime.setAuth(config.serviceRoleKey);
    await Promise.all(LABELS.map((label) => userClients[label].realtime.setAuth(state.users[label].accessToken)));

    const topics = {
      a: topicFor(state.users.a.accountId),
      b: topicFor(state.users.b.accountId),
    };
    const deliveryCounts = {
      [topics.a]: { a: 0, b: 0 },
      [topics.b]: { a: 0, b: 0 },
    };
    const deliveryErrors = [];
    const ownChannels = {};
    for (const label of LABELS) {
      ownChannels[label] = privateChannel(userClients[label], topics[label]);
      ownChannels[label].on('broadcast', { event: REALTIME_HINT.event }, ({ payload }) => {
        try {
          assertFrozenPayload(payload);
          deliveryCounts[topics[label]][label] += 1;
        } catch (error) {
          deliveryErrors.push(error);
        }
      });
    }

    await Promise.all(LABELS.map((label) => waitForSubscription(
      ownChannels[label],
      'accept',
      config.subscribeTimeoutMs ?? 10_000,
      clock,
      redactor,
    )));

    const crossChannels = {
      a: privateChannel(userClients.a, topics.b),
      b: privateChannel(userClients.b, topics.a),
    };
    await Promise.all(LABELS.map((label) => waitForSubscription(
      crossChannels[label],
      'reject',
      config.subscribeTimeoutMs ?? 10_000,
      clock,
      redactor,
    )));

    const serviceChannels = {
      a: privateChannel(serviceClient, topics.a),
      b: privateChannel(serviceClient, topics.b),
    };
    await Promise.all(LABELS.map((label) => waitForSubscription(
      serviceChannels[label],
      'accept',
      config.subscribeTimeoutMs ?? 10_000,
      clock,
      redactor,
    )));

    for (const label of LABELS) {
      const sendResult = await serviceChannels[label].send({
        type: 'broadcast',
        event: REALTIME_HINT.event,
        payload: REALTIME_HINT.payload,
      });
      if (sendResult !== 'ok') throw new Error(`Realtime broadcast failed for account ${label}`);
      await waitForDelivery(
        () => deliveryCounts[topics[label]][label] === 1 || deliveryErrors.length > 0,
        config.deliveryTimeoutMs ?? 5_000,
        clock,
      );
      if (deliveryErrors.length > 0) throw deliveryErrors[0];
      await delay(config.deliverySettleMs ?? 100, clock);
      const otherLabel = label === 'a' ? 'b' : 'a';
      if (deliveryCounts[topics[label]][otherLabel] !== 0) throw new Error(`Realtime hint leaked to account ${otherLabel}`);
      if (deliveryCounts[topics[label]][label] !== 1) throw new Error(`Realtime hint delivered more than once to account ${label}`);
    }

    const rpcResult = await serviceClient.rpc('service_revoke_device_binding', {
      p_account_id: state.users.a.accountId,
      p_device_id: state.users.a.deviceId,
      p_cutoff_sequence: 0,
      p_cutoff_hash: `\\x${Buffer.from(randomBytes(32)).toString('hex')}`,
      p_cutoff_signature: `\\x${Buffer.from(randomBytes(64)).toString('hex')}`,
    });
    if (!rpcResult || typeof rpcResult !== 'object' || rpcResult.error !== null || rpcResult.data !== null) {
      const detail = rpcResult?.error ? `: ${redactor.text(rpcResult.error)}` : '';
      throw new Error(`unexpected service revocation RPC response${detail}`);
    }

    const closeResult = await userClients.a.removeChannel(ownChannels.a);
    if (closeResult !== 'ok') throw new Error(`existing account A channel did not close cleanly: ${String(closeResult)}`);
    const freshAClient = createClient({ role: 'user', label: 'a' });
    if (freshAClient === userClients.a) throw new Error('fresh authorization requires a new Supabase client');
    clients.push(freshAClient);
    await freshAClient.realtime.setAuth(state.users.a.accessToken);
    const freshAChannel = privateChannel(freshAClient, topics.a);
    await waitForSubscription(
      freshAChannel,
      'reject',
      config.subscribeTimeoutMs ?? 10_000,
      clock,
      redactor,
    );

    result = {
      mode: 'verify',
      ownTopics: [topics.a, topics.b],
      crossTopicRejections: [
        { label: 'a', topic: topics.b },
        { label: 'b', topic: topics.a },
      ],
      deliveries: deliveryCounts,
      revocation: {
        existingChannelClosed: true,
        freshSameSessionRejected: true,
      },
    };
  } catch (error) {
    primaryError = error instanceof Error ? new Error(redactor.text(error)) : safeError('verification failed', error, redactor);
  } finally {
    const cleanupFailures = [];
    try {
      await cleanupChannels(clients, redactor);
    } catch (error) {
      cleanupFailures.push(error);
    }
    if (serviceClient) {
      try {
        await deleteUsers(serviceClient, LABELS.map((label) => state.users[label].userId), redactor);
      } catch (error) {
        cleanupFailures.push(error);
      }
    } else {
      cleanupFailures.push(new Error('unable to clean ephemeral users because the service client was not constructed'));
    }
    if (cleanupFailures.length > 0) {
      const cleanupMessage = cleanupFailures.map((error) => redactor.text(error)).join('; ');
      primaryError = new Error(primaryError ? `${primaryError.message}; ${cleanupMessage}` : cleanupMessage);
    }
  }

  if (primaryError) throw primaryError;
  logger.info(JSON.stringify(result));
  return result;
}

export async function cleanupRealtimeVerifier(options) {
  const config = options.config;
  const redactor = makeRedactor(config);
  const { filesystem, logger, createClient } = operationDependencies(options);
  if (typeof createClient !== 'function') throw new Error('createClient dependency is required');
  const state = await readState(options.stateFile, filesystem, redactor, { allowPreparing: true });
  if (state.status === 'ready') {
    for (const label of LABELS) redactor.add(state.users[label].accessToken);
  }
  const serviceClient = createClient({ role: 'service' });
  const deletedUserIds = await deleteUsers(serviceClient, LABELS.map((label) => state.users[label].userId), redactor);
  const result = { mode: 'cleanup', deletedUserIds };
  logger.info(JSON.stringify(result));
  return result;
}

export async function runRealtimeVerifierMode(options) {
  if (options?.mode === 'prepare') return prepareRealtimeVerifier(options);
  if (options?.mode === 'verify') return verifyRealtimeVerifier(options);
  if (options?.mode === 'cleanup') return cleanupRealtimeVerifier(options);
  throw new Error(`unknown Realtime verifier mode: ${String(options?.mode ?? '')}`);
}

function parseCommandLine(arguments_) {
  const [mode, flag, stateFile, ...extra] = arguments_;
  if (!['prepare', 'verify', 'cleanup'].includes(mode) || flag !== '--state-file' || !stateFile || extra.length > 0) {
    const tempRoot = verifierTempRoot();
    throw new Error(`usage: verify-supabase-realtime.mjs <prepare|verify|cleanup> --state-file ${tempRoot}${path.sep}<file>`);
  }
  return { mode, stateFile };
}

function supabaseClientFactory(config) {
  return ({ role }) => createSupabaseClient(
    config.url,
    role === 'service' ? config.serviceRoleKey : config.anonKey,
    {
      auth: {
        autoRefreshToken: false,
        persistSession: false,
        detectSessionInUrl: false,
      },
      realtime: { timeout: config.subscribeTimeoutMs },
    },
  );
}

export async function runRealtimeVerifierCli({ argv = process.argv.slice(2), environment = process.env, logger = console } = {}) {
  const { mode, stateFile } = parseCommandLine(argv);
  const config = loadRealtimeVerifierConfig(environment);
  const createClient = supabaseClientFactory(config);
  return runRealtimeVerifierMode({ mode, stateFile, config, createClient, logger });
}

function isMainModule() {
  return Boolean(process.argv[1]) && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
}

if (isMainModule()) {
  runRealtimeVerifierCli().catch((error) => {
    console.error(error instanceof Error ? error.message : 'Realtime verifier failed');
    process.exitCode = 1;
  });
}
