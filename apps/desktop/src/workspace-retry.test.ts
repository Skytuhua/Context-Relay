import { beforeEach, expect, it, vi } from 'vitest';
import type { MemoryCandidate, MemoryRecord, TaskRecord } from './bindings';

const invoke = vi.hoisted(() => vi.fn());
vi.mock('@tauri-apps/api/core', () => ({ invoke }));
import { LocalWorkspaceGateway } from './workspace';

const memory = { id: 'memory', revision: 'revision' } as MemoryRecord;
const task = { id: 'task', projectId: 'project', revision: 'revision', status: 'open' } as TaskRecord;
const candidate = { id: 'candidate' } as MemoryCandidate;
const cases = [
  { name: 'create context', run: (g: LocalWorkspaceGateway) => g.createMemory('project', 'Title', 'Text'), result: { kind: 'memory', data: { memory } } },
  { name: 'edit context', run: (g: LocalWorkspaceGateway) => g.updateMemory(memory, 'Title', 'Text'), result: { kind: 'memory', data: { memory } } },
  { name: 'archive context', run: (g: LocalWorkspaceGateway) => g.archiveMemory(memory), result: { kind: 'memory', data: { memory } } },
  { name: 'create task', run: (g: LocalWorkspaceGateway) => g.createTask('project', 'Title', 'Text'), result: { kind: 'tasks', data: { tasks: [task] } } },
  { name: 'edit task', run: (g: LocalWorkspaceGateway) => g.updateTask(task, 'Title', 'Text'), result: { kind: 'tasks', data: { tasks: [task] } } },
  { name: 'start task', run: (g: LocalWorkspaceGateway) => g.transitionTask(task, 'in_progress'), result: { kind: 'tasks', data: { tasks: [task] } } },
  { name: 'complete task', run: (g: LocalWorkspaceGateway) => g.completeTask(task, 'Verified'), result: { kind: 'tasks', data: { tasks: [task] } } },
  { name: 'review suggestion', run: (g: LocalWorkspaceGateway) => g.reviewCandidate(candidate, true), result: { kind: 'candidates', data: { candidates: [candidate] } } },
];
beforeEach(() => { invoke.mockReset(); });

it.each(['context', 'task'] as const)('binds uncertain %s creation to its form draft', async (kind) => {
  invoke.mockRejectedValue(new Error('reply lost'));
  const gateway = new LocalWorkspaceGateway();
  const draft = {};
  const create = (attempt: object) => kind === 'context'
    ? gateway.createMemory('project', 'Title', 'Text', attempt)
    : gateway.createTask('project', 'Title', 'Text', attempt);
  await expect(create(draft)).rejects.toThrow();
  await expect(create(draft)).rejects.toThrow();
  await expect(create({})).rejects.toThrow();
  expect(invoke.mock.calls[1]).toEqual(invoke.mock.calls[0]);
  expect(invoke.mock.calls[2][1].request.params.operationId).not.toEqual(invoke.mock.calls[0][1].request.params.operationId);
});

it.each(cases)('$name reuses an unconfirmed operation only on explicit retry', async ({ run, result }) => {
  invoke.mockRejectedValueOnce(new Error('reply lost')).mockResolvedValue(result);
  const gateway = new LocalWorkspaceGateway();
  await expect(run(gateway)).rejects.toThrow('reply lost');
  expect(invoke).toHaveBeenCalledTimes(1);
  await run(gateway);
  expect(invoke.mock.calls[1]).toEqual(invoke.mock.calls[0]);
  await run(gateway);
  expect(invoke.mock.calls[2][1].request.params.operationId)
    .not.toEqual(invoke.mock.calls[0][1].request.params.operationId);
});

it.each(cases)('$name retains the operation when the reply has the wrong shape', async ({ run, result }) => {
  invoke.mockResolvedValueOnce({ kind: 'empty' }).mockResolvedValue(result);
  const gateway = new LocalWorkspaceGateway();
  await expect(run(gateway)).rejects.toThrow();
  await run(gateway);
  expect(invoke.mock.calls[1]).toEqual(invoke.mock.calls[0]);
});

it('keeps separate uncertain saves across changed text, project and intervening actions', async () => {
  invoke.mockRejectedValue(new Error('reply lost'));
  const gateway = new LocalWorkspaceGateway();
  for (const args of [
    ['project', 'Title', 'Text'],
    ['project', 'Title', 'Changed text'],
    ['another-project', 'Title', 'Text'],
    ['project', 'Title', 'Text'],
  ]) {
    await expect(gateway.createMemory(...args as [string, string, string])).rejects.toThrow();
  }
  const ids = invoke.mock.calls.map((call) => call[1].request.params.operationId);
  expect(new Set(ids.slice(0, 3)).size).toBe(3);
  expect(ids[3]).toBe(ids[0]);
});

it('an identical retry after a lost committed reply returns the original record', async () => {
  const records = new Map<string, object>();
  invoke.mockImplementation(async (_command, { request }) => {
    const id = request.params.operationId;
    if (!records.has(id)) {
      records.set(id, { id, title: request.params.title });
      throw new Error('committed, reply lost');
    }
    return { kind: 'memory', data: { memory: records.get(id) } };
  });
  const gateway = new LocalWorkspaceGateway();
  await expect(gateway.createMemory('project', 'Title', 'Text')).rejects.toThrow();
  const saved = await gateway.createMemory('project', 'Title', 'Text');
  expect(records.size).toBe(1);
  expect(saved.id).toBe([...records.keys()][0]);
});

it.each(['context', 'task'] as const)('allows a new identical %s after a later acknowledged action resolves its uncertain creation', async (kind) => {
  const gateway = new LocalWorkspaceGateway();
  let createdId = '';
  let first = true;
  invoke.mockImplementation(async (_command, { request }) => {
    const creation = request.method === 'memory_create' || (request.method === 'task_upsert' && request.params.taskId === null);
    if (creation && first) {
      first = false;
      createdId = request.params.operationId;
      throw new Error('committed, reply lost');
    }
    const record = { id: creation ? request.params.operationId : createdId };
    return kind === 'context' ? { kind: 'memory', data: { memory: record } } : { kind: 'tasks', data: { tasks: [record] } };
  });
  const create = () => kind === 'context' ? gateway.createMemory('project', 'Title', 'Text') : gateway.createTask('project', 'Title', 'Text');
  await expect(create()).rejects.toThrow();
  if (kind === 'context') await gateway.archiveMemory({ ...memory, id: createdId } as MemoryRecord);
  else await gateway.completeTask({ ...task, id: createdId } as TaskRecord, 'Verified');
  const created = await create();
  expect(created.id).not.toBe(createdId);
});
