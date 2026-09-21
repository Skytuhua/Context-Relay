import assert from 'node:assert/strict';
import { setImmediate as nextTurn } from 'node:timers/promises';
import { it } from 'vitest';
import type { HarnessExecutionParams, HarnessExecutionStatus, HarnessSetupRecord } from './bindings';
import { observeHarnessExecution, type HarnessOutcome } from './harness-execution-observer';

const key = { planId: '018f22e2-79b0-7cc8-98c4-dc0c0c073983', action: 'apply' } as HarnessExecutionParams;
const other = { ...key, planId: '018f22e2-79b0-7cc8-98c4-dc0c0c073984' as HarnessExecutionParams['planId'] };
const running: HarnessExecutionStatus = { ...key, phase: 'running', error: null };
const finished: HarnessExecutionStatus = { ...key, phase: 'finished', error: null };
const setup = { plan: { planId: key.planId }, state: 'applied', createdAt: '1' } as unknown as HarnessSetupRecord;
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function fixture() {
  const calls = { current: 0, status: [] as HarnessExecutionParams[], setup: [] as string[] };
  const gateway = {
    harnessExecutionCurrent: async (): Promise<HarnessExecutionStatus | null> => { calls.current++; return null; },
    harnessExecutionStatus: async (target: HarnessExecutionParams): Promise<HarnessExecutionStatus> => { calls.status.push(target); return finished; },
    harnessSetupGet: async (id: typeof key.planId): Promise<HarnessSetupRecord> => { calls.setup.push(id); return setup; },
  };
  const state = { checking: false, pending: null as HarnessExecutionStatus | null, outcome: null as HarnessOutcome | null, error: null as string | null };
  const timers: { callback: () => void; delay: number; canceled: boolean }[] = [];
  const start = (target: HarnessExecutionParams | null = null) => observeHarnessExecution(gateway, target, {
    onChecking: value => { state.checking = value; }, onPending: value => { state.pending = value; },
    onOutcome: value => { state.outcome = value; }, onError: value => { state.error = value; },
  }, (callback, delay) => {
    const timer = { callback, delay, canceled: false }; timers.push(timer);
    return () => { timer.canceled = true; };
  });
  const retry = async () => {
    const timer = timers.shift(); assert.ok(timer); assert.equal(timer.canceled, false);
    timer.callback(); await nextTurn();
  };
  return { gateway, calls, state, timers, start, retry };
}

it('unlocks only after a successful idle response', async () => {
  const f = fixture(); f.start();
  assert.equal(f.state.checking, true);
  await nextTurn();
  assert.equal(f.state.checking, false);
  assert.equal(f.state.pending, null);
  assert.equal(f.timers.length, 0);
});

it('keeps mutations blocked through failed initial discovery and retries read-only', async () => {
  const f = fixture(); let attempts = 0;
  f.gateway.harnessExecutionCurrent = async () => { if (++attempts < 3) throw new Error('PRIVATE TRANSPORT DETAILS'); return null; };
  f.start(); await nextTurn();
  assert.equal(f.state.checking, true); assert.equal(f.state.pending, null);
  assert.equal(f.state.outcome, null); assert.doesNotMatch(f.state.error!, /PRIVATE/);
  assert.equal(f.timers[0].delay, 2000);
  await f.retry(); assert.equal(f.state.checking, true);
  await f.retry(); assert.equal(f.state.checking, false); assert.equal(f.state.error, null);
  assert.deepEqual(f.calls.status, []); assert.deepEqual(f.calls.setup, []);
});

it('retains a discovered running operation and uses the normal polling interval', async () => {
  const f = fixture(); f.gateway.harnessExecutionCurrent = async () => running;
  f.start(); await nextTurn();
  assert.equal(f.state.pending, running); assert.equal(f.state.checking, false);
  assert.equal(f.timers[0].delay, 1000);
  await f.retry();
  assert.deepEqual(f.calls.status, [key]); assert.deepEqual(f.calls.setup, [key.planId]);
  assert.deepEqual(f.state.outcome, { status: finished, setup });
});

it('does not publish Finished until its persisted plan has been read', async () => {
  const f = fixture(); const read = deferred<HarnessSetupRecord>();
  f.gateway.harnessExecutionCurrent = async () => finished;
  f.gateway.harnessSetupGet = () => read.promise;
  f.start(); await nextTurn();
  assert.equal(f.state.checking, true); assert.equal(f.state.outcome, null);
  read.resolve(setup); await nextTurn();
  assert.equal(f.state.checking, false); assert.deepEqual(f.state.outcome, { status: finished, setup });
});

it('keeps the same plan locked while its persisted result is unavailable', async () => {
  const f = fixture(); let attempts = 0;
  f.gateway.harnessExecutionCurrent = async () => finished;
  f.gateway.harnessSetupGet = async id => { f.calls.setup.push(id); if (++attempts === 1) throw new Error('Unavailable'); return setup; };
  f.start(); await nextTurn();
  assert.equal(f.state.checking, true); assert.equal(f.state.outcome, null);
  assert.equal(f.timers[0].delay, 2000);
  await f.retry();
  assert.deepEqual(f.calls.status, [key]); assert.deepEqual(f.calls.setup, [key.planId, key.planId]);
  assert.equal(f.state.checking, false); assert.deepEqual(f.state.outcome, { status: finished, setup });
});

it('rejects a persisted result belonging to a different plan', async () => {
  const f = fixture(); f.gateway.harnessExecutionCurrent = async () => finished;
  f.gateway.harnessSetupGet = async () => ({ ...setup, plan: { ...setup.plan, planId: other.planId } });
  f.start(); await nextTurn();
  assert.equal(f.state.checking, true); assert.equal(f.state.outcome, null);
  assert.equal(f.timers[0].delay, 2000);
});

it('retains a pending operation while its progress read fails', async () => {
  const f = fixture(); f.gateway.harnessExecutionCurrent = async () => running;
  f.gateway.harnessExecutionStatus = async () => { throw new Error('Unavailable'); };
  f.start(); await nextTurn(); await f.retry();
  assert.equal(f.state.pending, running); assert.equal(f.state.checking, true);
  assert.equal(f.state.outcome, null); assert.equal(f.timers[0].delay, 2000);
});

it('reconciles an Unknown attempt after restart instead of replaying its mutation', async () => {
  const f = fixture(); const unknown: HarnessExecutionStatus = { ...key, phase: 'unknown', error: null };
  f.gateway.harnessExecutionStatus = async target => { f.calls.status.push(target); return unknown; };
  f.start(key); await nextTurn();
  assert.deepEqual(f.calls.status, [key]); assert.deepEqual(f.calls.setup, [key.planId]);
  assert.deepEqual(f.state.outcome, { status: unknown, setup });
});

it('queries the requested attempt rather than reusing an unrelated finished one', async () => {
  const f = fixture(); f.gateway.harnessExecutionCurrent = async () => ({ ...finished, ...other });
  f.start(key); await nextTurn();
  assert.deepEqual(f.calls.status, [key]); assert.deepEqual(f.calls.setup, [key.planId]);
});

it('does not update callbacks after an in-flight discovery has been canceled', async () => {
  const f = fixture(); const read = deferred<HarnessExecutionStatus | null>();
  f.gateway.harnessExecutionCurrent = () => read.promise;
  const stop = f.start(); stop(); read.resolve(running); await nextTurn();
  assert.equal(f.state.pending, null); assert.equal(f.state.outcome, null); assert.equal(f.timers.length, 0);
});

it('ignores a late persisted-read failure after cleanup', async () => {
  const f = fixture(); const read = deferred<HarnessSetupRecord>();
  f.gateway.harnessExecutionCurrent = async () => finished; f.gateway.harnessSetupGet = () => read.promise;
  const stop = f.start(); await nextTurn(); stop(); read.reject(new Error('Obsolete')); await nextTurn();
  assert.equal(f.state.error, null); assert.equal(f.state.outcome, null); assert.equal(f.timers.length, 0);
});

it('clears a scheduled reconnect when its observer is disposed', async () => {
  const f = fixture(); f.gateway.harnessExecutionCurrent = async () => { throw new Error('Unavailable'); };
  const stop = f.start(); await nextTurn();
  assert.equal(f.timers[0].canceled, false); stop(); assert.equal(f.timers[0].canceled, true);
});

it.each(['planId', 'action'] as const)('rejects a status response with a different %s without following it', async field => {
  const f = fixture();
  const mismatch: HarnessExecutionStatus = field === 'planId'
    ? { ...finished, planId: other.planId }
    : { ...finished, action: 'rollback' };
  f.gateway.harnessExecutionStatus = async requested => { f.calls.status.push(requested); return mismatch; };
  f.gateway.harnessSetupGet = async id => { f.calls.setup.push(id); return { ...setup, plan: { ...setup.plan, planId: id } }; };
  f.start(key); await nextTurn();
  assert.equal(f.state.checking, true);
  assert.equal(f.state.outcome, null);
  assert.deepEqual(f.calls.setup, []);
  assert.equal(f.timers[0].delay, 2000);
  f.gateway.harnessExecutionStatus = async requested => { f.calls.status.push(requested); return finished; };
  await f.retry();
  assert.deepEqual(f.calls.status, [key, key]);
  assert.deepEqual(f.state.outcome, { status: finished, setup });
});

it('does not interpret a missing requested status as an idle service', async () => {
  const f = fixture();
  f.gateway.harnessExecutionStatus = async () => null as unknown as HarnessExecutionStatus;
  f.start(key); await nextTurn();
  assert.equal(f.state.checking, true);
  assert.equal(f.state.outcome, null);
  assert.equal(f.timers[0].delay, 2000);
});

it('requires an explicit null discovery response before unlocking an idle service', async () => {
  const f = fixture();
  f.gateway.harnessExecutionCurrent = async () => undefined as unknown as HarnessExecutionStatus | null;
  f.start(); await nextTurn();
  assert.equal(f.state.checking, true);
  assert.equal(f.state.outcome, null);
  assert.equal(f.timers[0].delay, 2000);
});

it('snapshots the requested identity before asynchronous discovery starts', async () => {
  const f = fixture();
  const target = { ...key };
  const discovery = deferred<HarnessExecutionStatus | null>();
  f.gateway.harnessExecutionCurrent = () => discovery.promise;
  f.start(target);
  target.planId = other.planId;
  target.action = 'rollback';
  discovery.resolve(null); await nextTurn();
  assert.deepEqual(f.calls.status, [key]);
  assert.deepEqual(f.state.outcome, { status: finished, setup });
});

it('does not expose the retained identity for mutation by a status reader', async () => {
  const f = fixture();
  const target = { ...key };
  f.gateway.harnessExecutionStatus = async requested => {
    requested.planId = other.planId;
    return finished;
  };
  f.start(target); await nextTurn();
  assert.deepEqual(target, key);
  assert.deepEqual(f.state.outcome, { status: finished, setup });
});
