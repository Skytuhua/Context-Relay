import { beforeEach, expect, it, vi } from 'vitest';

const invoke = vi.hoisted(() => vi.fn());
vi.mock('@tauri-apps/api/core', () => ({ invoke }));

import { LocalWorkspaceGateway } from './workspace';

const hlc = (physicalMs: string) => ({
  physicalMs,
  logical: 0,
  node: '018f22e2-79b0-7cc8-98c4-dc0c0c075602',
});

const memory = {
  id: '018f22e2-79b0-7cc8-98c4-dc0c0c075603',
  scope: { scope: 'global' },
  kind: 'note',
  title: 'Use TypeScript',
  bodyMarkdown: 'Prefer strict mode.',
  tags: [],
  origin: 'explicit',
  provenance: { originDevice: '018f22e2-79b0-7cc8-98c4-dc0c0c075604', harness: null, source: null, createdHlc: hlc('1758000000000') },
  revision: '018f22e2-79b0-7cc8-98c4-dc0c0c075605',
  createdHlc: hlc('1758000000000'),
  updatedHlc: hlc('1758000000000'),
  archived: false,
};

const task = {
  id: '018f22e2-79b0-7cc8-98c4-dc0c0c075606',
  projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c075607',
  title: 'Fix the sign-in page',
  bodyMarkdown: 'Check the error message.',
  status: 'open',
  evidence: [],
  revision: '018f22e2-79b0-7cc8-98c4-dc0c0c075608',
};

beforeEach(() => {
  invoke.mockReset();
});

it('accepts a well formed memory list', async () => {
  invoke.mockResolvedValueOnce({ kind: 'memories', data: { memories: [memory] } });
  await expect(new LocalWorkspaceGateway().memories(null)).resolves.toEqual([memory]);
});

it('rejects a memory whose hybrid logical clock cannot be read as a u64', async () => {
  // dashboard.tsx calls BigInt(record.updatedHlc.physicalMs) while sorting, so a
  // non-decimal clock crashes the screen instead of surfacing a retryable error.
  invoke.mockResolvedValueOnce({
    kind: 'memories',
    data: { memories: [{ ...memory, updatedHlc: hlc('0x6af0c0') }] },
  });
  await expect(new LocalWorkspaceGateway().memories(null)).rejects.toThrow(/invalid memory\.updatedHlc/);
});

it('rejects a memory with an unknown field instead of rendering it', async () => {
  invoke.mockResolvedValueOnce({
    kind: 'memories',
    data: { memories: [{ ...memory, unexpected: 'value' }] },
  });
  await expect(new LocalWorkspaceGateway().memories(null)).rejects.toThrow(/invalid memory/);
});

it('rejects a search result that is not a memory record', async () => {
  invoke.mockResolvedValueOnce({ kind: 'memories', data: { memories: [{ id: memory.id }] } });
  await expect(new LocalWorkspaceGateway().searchMemories('sign', null)).rejects.toThrow(/invalid memory/);
});

it('validates a done task that carries no evidence', async () => {
  invoke.mockResolvedValueOnce({ kind: 'tasks', data: { tasks: [{ ...task, status: 'done', evidence: [] }] } });
  await expect(new LocalWorkspaceGateway().tasks(task.projectId)).rejects.toThrow(/invalid task\.evidence/);
});

it('accepts a well formed task list', async () => {
  invoke.mockResolvedValueOnce({ kind: 'tasks', data: { tasks: [task] } });
  await expect(new LocalWorkspaceGateway().tasks(task.projectId)).resolves.toEqual([task]);
});

it('validates the proposed memory nested inside a candidate', async () => {
  const candidate = {
    id: '018f22e2-79b0-7cc8-98c4-dc0c0c075609',
    proposedMemory: memory,
    evidenceSummary: 'The user asked to prefer strict mode.',
    sourceHarness: 'codex',
    state: 'pending',
  };
  invoke.mockResolvedValueOnce({ kind: 'candidates', data: { candidates: [candidate] } });
  await expect(new LocalWorkspaceGateway().candidates(null)).resolves.toEqual([candidate]);

  invoke.mockResolvedValueOnce({
    kind: 'candidates',
    data: { candidates: [{ ...candidate, proposedMemory: { ...memory, title: '' } }] },
  });
  await expect(new LocalWorkspaceGateway().candidates(null)).rejects.toThrow(/invalid memory\.title/);
});

it('validates a project identity before it drives the project switcher', async () => {
  invoke.mockResolvedValueOnce({
    kind: 'projects',
    data: { projects: [{ projectId: 'not-a-uuid', githubRepositoryId: null, gitRemoteFingerprint: null, monorepoSubdirectory: null, name: 'Website' }] },
  });
  await expect(new LocalWorkspaceGateway().projects()).rejects.toThrow(/invalid project\.projectId/);
});
