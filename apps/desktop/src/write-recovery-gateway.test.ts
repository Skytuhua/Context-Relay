import { expect, it, vi } from 'vitest';
import type { DesktopWrite, LocalRequest, LocalResult, MemoryCandidate, OperationId } from './bindings';
import { LocalClient } from './local-client';
import { LocalWorkspaceGateway, RecoveryStorageFullError } from './workspace';

it('reports preparation quota without sending the record mutation', async () => {
  const call = vi.fn().mockRejectedValue({ code: 'quota_exceeded' });
  const gateway = new LocalWorkspaceGateway({ call } as unknown as LocalClient);
  await expect(gateway.createMemory(null, 'Title', 'Body')).rejects.toBeInstanceOf(RecoveryStorageFullError);
  expect(call).toHaveBeenCalledTimes(1);
  expect(call.mock.calls[0][0].method).toBe('desktop_write_prepare');
});

it('requires an acknowledgment of the requested suggestion decision before clearing its copy', async () => {
  const candidate = { id: '018f22e2-79b0-7cc8-98c4-dc0c0c075001' } as MemoryCandidate;
  let state = 'pending';
  const call = vi.fn(async (request: LocalRequest) => request.method === 'candidate_review'
    ? { kind: 'candidates', data: { candidates: [{ ...candidate, state }] } } : { kind: 'empty' });
  const gateway = new LocalWorkspaceGateway({ call } as unknown as LocalClient);
  await expect(gateway.reviewCandidate(candidate, true)).rejects.toThrow();
  expect(call.mock.calls.some(([request]) => request.method === 'desktop_write_forget')).toBe(false);
  state = 'accepted';
  await expect(gateway.reviewCandidate(candidate, true)).resolves.toMatchObject({ state: 'accepted' });
  expect(call.mock.calls.filter(([request]) => request.method === 'candidate_review')[1])
    .toEqual(call.mock.calls.filter(([request]) => request.method === 'candidate_review')[0]);
});

function fixture() {
  const journal = new Map<OperationId, DesktopWrite>();
  const records = new Map<OperationId, object>();
  let losePrepare = false;
  let loseSave = true;
  let loseCleanup = false;
  let wrongSave = false;
  let staleRevision = false;
  const call = vi.fn(async (request: LocalRequest): Promise<LocalResult> => {
    switch (request.method) {
      case 'desktop_write_prepare':
        journal.set(request.params.write.params.operationId, structuredClone(request.params.write));
        if (losePrepare) throw new Error('prepare reply lost');
        return { kind: 'empty' };
      case 'desktop_writes_list':
        return { kind: 'desktop_writes', data: { page: { writes: [...journal.values()].map((write) => ({
          operationId: write.params.operationId, action: 'Save context', title: 'A decision', scope: { scope: 'global' },
        })), nextCursor: null } } };
      case 'desktop_write_get':
        return { kind: 'desktop_write', data: { write: journal.get(request.params.operationId) ?? null } };
      case 'desktop_write_forget':
        if (loseCleanup) throw new Error('cleanup reply lost');
        journal.delete(request.params.operationId);
        return { kind: 'empty' };
      case 'memory_create': {
        const id = request.params.operationId;
        if (!records.has(id)) records.set(id, { id, revision: id, title: request.params.title });
        if (loseSave) { loseSave = false; throw new Error('save reply lost'); }
        if (wrongSave) return { kind: 'memory', data: { memory: { id: 'another-record' } } } as LocalResult;
        if (staleRevision) return { kind: 'memory', data: { memory: { id, revision: 'older-operation' } } } as unknown as LocalResult;
        return { kind: 'memory', data: { memory: records.get(id) } } as LocalResult;
      }
      default: throw new Error('unexpected request');
    }
  });
  const gateway = () => new LocalWorkspaceGateway({ call } as unknown as LocalClient);
  return { journal, records, call, gateway, losePrepare: () => { losePrepare = true; }, loseCleanup: () => { loseCleanup = true; }, wrongSave: () => { wrongSave = true; }, staleRevision: () => { staleRevision = true; } };
}

it.each(['form', 'recovery'])('does not clear a %s retry on an acknowledgment of an older revision', async (path) => {
  const f = fixture(); const gateway = f.gateway();
  await expect(gateway.createMemory(null, 'A decision', 'Use TypeScript')).rejects.toThrow();
  f.staleRevision();
  const retry = path === 'form' ? gateway.createMemory(null, 'A decision', 'Use TypeScript') : gateway.retryWrite([...f.journal.values()][0]);
  await expect(retry).rejects.toThrow();
  expect(f.journal.size).toBe(1);
});

it('retains the recovery copy when a normal retry acknowledges a different record', async () => {
  const f = fixture();
  const gateway = f.gateway();
  await expect(gateway.createMemory(null, 'A decision', 'Use TypeScript')).rejects.toThrow();
  f.wrongSave();
  await expect(gateway.createMemory(null, 'A decision', 'Use TypeScript')).rejects.toThrow();
  expect(f.journal.size).toBe(1);
});

it('recovers a committed save with its original identity after a new gateway starts', async () => {
  const f = fixture();
  await expect(f.gateway().createMemory(null, 'A decision', 'Use TypeScript')).rejects.toThrow('save reply lost');
  const original = [...f.journal.values()][0];
  const restarted = f.gateway();
  const page = await restarted.pendingWrites(null);
  expect(f.records.size).toBe(1);
  expect(f.call.mock.calls.filter(([r]) => r.method === 'memory_create')).toHaveLength(1);
  const recovered = await restarted.pendingWrite(page.writes[0].operationId);
  expect(recovered).toEqual(original);
  await restarted.retryWrite(recovered!);
  expect(f.records.size).toBe(1);
  expect(f.journal.size).toBe(0);
  expect(f.call.mock.calls.filter(([r]) => r.method === 'memory_create').map(([r]) => r)).toEqual([original, original]);
});

it('does not send a mutation if preparation acknowledgment is lost', async () => {
  const f = fixture(); f.losePrepare();
  const gateway = f.gateway();
  await expect(gateway.createMemory(null, 'A decision', 'Use TypeScript')).rejects.toThrow();
  await expect(gateway.createMemory(null, 'A decision', 'Use TypeScript')).rejects.toThrow();
  expect(f.records.size).toBe(0);
  expect(f.journal.size).toBe(1);
});

it('keeps known save success separate from cleanup failure and dismiss never undoes it', async () => {
  const f = fixture();
  const gateway = f.gateway();
  await expect(gateway.createMemory(null, 'A decision', 'Use TypeScript')).rejects.toThrow();
  f.loseCleanup();
  await expect(gateway.createMemory(null, 'A decision', 'Use TypeScript')).resolves.toMatchObject({ title: 'A decision' });
  expect(f.journal.size).toBe(1);
  expect(f.records.size).toBe(1);
});

it('explicit dismissal only removes the recovery copy', async () => {
  const f = fixture();
  await expect(f.gateway().createMemory(null, 'A decision', 'Use TypeScript')).rejects.toThrow();
  await f.gateway().forgetWrite([...f.journal.keys()][0]);
  expect(f.records.size).toBe(1);
  expect(f.journal.size).toBe(0);
});
