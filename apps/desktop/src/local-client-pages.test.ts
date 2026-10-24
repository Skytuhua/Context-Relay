import { beforeEach, expect, it, vi } from 'vitest';
import type { LocalRequest } from './bindings';
import { fixtureCandidate, fixtureMemory, fixtureProject, fixtureTask } from './test-fixtures';

const invoke = vi.hoisted(() => vi.fn());
vi.mock('@tauri-apps/api/core', () => ({ invoke }));
import { LocalClient } from './local-client';

beforeEach(() => invoke.mockReset());

for (const [method, kind, field, makeRecord, params] of [
  ['projects_list', 'projects', 'projects', fixtureProject, {}],
  ['memory_list', 'memories', 'memories', fixtureMemory, { projectId: null, includeArchived: false }],
  ['candidates_list', 'candidates', 'candidates', fixtureCandidate, { projectId: null }],
  ['tasks_list', 'tasks', 'tasks', fixtureTask, { projectId: fixtureProject().projectId }],
] as const) {
  it(`collects every ${field} page through bounded IPC requests`, async () => {
    const first = makeRecord();
    const second = makeRecord();
    const cursor = 'v1:fixture:next';
    invoke.mockResolvedValueOnce({ kind: `${kind}_page`, data: { page: { [field]: [first], nextCursor: cursor } } })
      .mockResolvedValueOnce({ kind: `${kind}_page`, data: { page: { [field]: [second], nextCursor: null } } });
    await expect(new LocalClient().call({ method, params } as LocalRequest)).resolves.toEqual({
      kind, data: { [field]: [first, second] },
    });
    expect(invoke.mock.calls).toEqual([
      ['local_request', { request: { method: `${method}_page`, params: { ...params, cursor: null } } }],
      ['local_request', { request: { method: `${method}_page`, params: { ...params, cursor } } }],
    ]);
  });
}

it('reads a history larger than one IPC frame without dropping notes', async () => {
  const memories = Array.from({ length: 128 }, () => fixtureMemory({ bodyMarkdown: 'x'.repeat(64 * 1024) }));
  expect(JSON.stringify(memories).length).toBeGreaterThan(8 * 1024 * 1024);
  invoke.mockResolvedValueOnce({ kind: 'memories_page', data: { page: { memories: memories.slice(0, 64), nextCursor: 'v1:notes:next' } } })
    .mockResolvedValueOnce({ kind: 'memories_page', data: { page: { memories: memories.slice(64), nextCursor: null } } });
  await expect(new LocalClient().call({ method: 'memory_list', params: { projectId: null, includeArchived: false } }))
    .resolves.toEqual({ kind: 'memories', data: { memories } });
});

it('rejects a repeating continuation rather than looping or duplicating records', async () => {
  const first = fixtureMemory();
  const second = fixtureMemory();
  invoke.mockResolvedValueOnce({ kind: 'memories_page', data: { page: { memories: [first], nextCursor: 'repeat' } } })
    .mockResolvedValueOnce({ kind: 'memories_page', data: { page: { memories: [second], nextCursor: 'repeat' } } });
  await expect(new LocalClient().call({ method: 'memory_list', params: { projectId: null, includeArchived: false } }))
    .rejects.toThrow('list page');
  expect(invoke).toHaveBeenCalledTimes(2);
});

it('rejects duplicate or out-of-order records between pages', async () => {
  const memory = fixtureMemory();
  invoke.mockResolvedValueOnce({ kind: 'memories_page', data: { page: { memories: [memory], nextCursor: 'next' } } })
    .mockResolvedValueOnce({ kind: 'memories_page', data: { page: { memories: [memory], nextCursor: null } } });
  await expect(new LocalClient().call({ method: 'memory_list', params: { projectId: null, includeArchived: false } }))
    .rejects.toThrow('list page');
});

for (const page of [
  { memories: [], nextCursor: 'next' },
  { memories: [], nextCursor: 3 },
  { memories: [] },
  { memories: [], nextCursor: '' },
  { memories: [], nextCursor: null, unexpected: true },
  { memories: [{ id: 'malformed' }], nextCursor: null },
]) {
  it(`rejects an invalid list page ${JSON.stringify(page)}`, async () => {
    invoke.mockResolvedValue({ kind: 'memories_page', data: { page } });
    await expect(new LocalClient().call({ method: 'memory_list', params: { projectId: null, includeArchived: false } }))
      .rejects.toThrow();
  });
}
