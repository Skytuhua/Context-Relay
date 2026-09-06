import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it } from 'vitest';

import App from './App';
import type {
  MemoryCandidate,
  MemoryRecord,
  ProjectIdentity,
  StatusOutput,
  TaskRecord,
} from './bindings';
import { PROTOCOL_VERSION } from './bindings';
import type { WorkspaceGateway } from './workspace';

const id = (suffix: string) => `018f22e2-79b0-7cc8-98c4-dc0c0c0739${suffix}`;

class FakeWorkspaceGateway implements WorkspaceGateway {
  async chooseProjectFolder() { return null; }
  networkCalls = 0;
  private projectsValue: ProjectIdentity[] = [];
  private memoriesValue: MemoryRecord[] = [];
  private tasksValue: TaskRecord[] = [];
  private candidatesValue: MemoryCandidate[] = [];

  constructor() {
    const proposed = this.memory(id('81'), 'Candidate memory', 'Review me');
    const rejected = this.memory(id('91'), 'Noisy candidate', 'Reject me');
    this.candidatesValue = [
      {
        id: id('82'),
        proposedMemory: proposed,
        evidenceSummary: 'Imported from Claude',
        sourceHarness: 'claude_code',
        state: 'pending',
      } as MemoryCandidate,
      {
        id: id('92'),
        proposedMemory: rejected,
        evidenceSummary: 'Low confidence',
        sourceHarness: 'claude_code',
        state: 'pending',
      } as MemoryCandidate,
    ];
  }

  async status(): Promise<StatusOutput> {
    return {
      protocol: { min: { major: 1, minor: 6 }, max: { major: 1, minor: 6 } },
      vault: 'unlocked',
      resolvedProject: null,
      sync: 'offline',
      access: { mode: 'default' },
    };
  }

  async devices() {
    return [];
  }

  async harnessProbe(): Promise<never> { throw new Error('Harness discovery unavailable in offline fixture'); }
  async harnessPreview(): Promise<never> {
    throw new Error('not used in this workflow');
  }

  async harnessApply(): Promise<never> {
    throw new Error('not used in this workflow');
  }

  async harnessRollback(): Promise<never> {
    throw new Error('not used in this workflow');
  }

  async createPairingInvite(): Promise<never> {
    throw new Error('not used in this workflow');
  }

  async joinPairing(): Promise<never> {
    throw new Error('not used in this workflow');
  }

  async pairingStatus(): Promise<never> {
    throw new Error('not used in this workflow');
  }

  async decidePairing(): Promise<never> {
    throw new Error('not used in this workflow');
  }

  async confirmPairing(): Promise<never> {
    throw new Error('not used in this workflow');
  }

  async cancelPairing() {}

  async recoveryEnrollmentBegin(): Promise<never> {
    throw new Error('not used in this workflow');
  }

  async recoveryEnrollmentOverview() {
    return {
      enrollmentId: null,
      state: 'idle' as const,
      createdAtMs: null,
      transitionedAtMs: null,
    };
  }

  async recoveryEnrollmentConfirm(): Promise<never> {
    throw new Error('not used in this workflow');
  }

  async recoveryEnrollmentStatus(): Promise<never> {
    throw new Error('not used in this workflow');
  }

  async recoveryEnrollmentCancel() {}

  async projects() {
    return this.projectsValue;
  }

  async createProject(name: string) {
    const project = {
      projectId: id('80'),
      githubRepositoryId: null,
      gitRemoteFingerprint: null,
      monorepoSubdirectory: null,
      name,
    } as ProjectIdentity;
    this.projectsValue = [project];
    return project;
  }

  async memories() {
    return this.memoriesValue;
  }

  async createMemory(_projectId: string | null, title: string, bodyMarkdown: string) {
    const memory = this.memory(id('83'), title, bodyMarkdown);
    this.memoriesValue = [memory];
    return memory;
  }

  async updateMemory(memory: MemoryRecord, title: string, bodyMarkdown: string) {
    const updated = { ...memory, title, bodyMarkdown, revision: id('84') } as MemoryRecord;
    this.memoriesValue = [updated];
    return updated;
  }

  async archiveMemory(memory: MemoryRecord) {
    this.memoriesValue = [];
    return { ...memory, archived: true } as MemoryRecord;
  }

  async searchMemories(query: string) {
    return this.memoriesValue.filter((memory) =>
      `${memory.title} ${memory.bodyMarkdown}`.toLowerCase().includes(query.toLowerCase()),
    );
  }

  async candidates() {
    return this.candidatesValue;
  }

  async reviewCandidate(candidate: MemoryCandidate, accepted: boolean) {
    const reviewed = { ...candidate, state: accepted ? 'accepted' : 'rejected' } as MemoryCandidate;
    this.candidatesValue = this.candidatesValue.filter((item) => item.id !== candidate.id);
    return reviewed;
  }

  async tasks() {
    return this.tasksValue;
  }

  async createTask(projectId: string, title: string, bodyMarkdown: string) {
    const task = {
      id: id('85'),
      projectId,
      title,
      bodyMarkdown,
      status: 'open',
      evidence: [],
      revision: id('85'),
    } as unknown as TaskRecord;
    this.tasksValue = [task];
    return task;
  }

  async updateTask(task: TaskRecord, title: string, bodyMarkdown: string) {
    const updated = { ...task, title, bodyMarkdown, revision: id('86') } as TaskRecord;
    this.tasksValue = [updated];
    return updated;
  }

  async transitionTask(task: TaskRecord, status: TaskRecord['status']) {
    const updated = { ...task, status, revision: id('87') } as TaskRecord;
    this.tasksValue = [updated];
    return updated;
  }

  async completeTask(task: TaskRecord, summary: string) {
    const updated = {
      ...task,
      status: 'done',
      revision: id('88'),
      evidence: [
        {
          summary,
          evidenceKind: 'manual',
          reference: null,
          recordedHlc: { physicalMs: '1', logical: 0, node: id('89') },
        },
      ],
    } as TaskRecord;
    this.tasksValue = [updated];
    return updated;
  }

  private memory(memoryId: string, title: string, bodyMarkdown: string) {
    return {
      id: memoryId,
      scope: { scope: 'global' },
      kind: 'note',
      title,
      bodyMarkdown,
      tags: [],
      origin: 'explicit',
      provenance: {
        originDevice: id('90'),
        harness: null,
        source: null,
        createdHlc: { physicalMs: '1', logical: 0, node: id('90') },
      },
      revision: memoryId,
      createdHlc: { physicalMs: '1', logical: 0, node: id('90') },
      updatedHlc: { physicalMs: '1', logical: 0, node: id('90') },
      archived: false,
    } as unknown as MemoryRecord;
  }
}

afterEach(cleanup);

it('uses the current protocol range in the offline status fixture', async () => {
  const status = await new FakeWorkspaceGateway().status();
  expect(status.protocol).toEqual({ min: PROTOCOL_VERSION, max: PROTOCOL_VERSION });
});

it('keeps daemon-owned project, review, and task state after the offline desktop closes', async () => {
  HTMLDialogElement.prototype.showModal = function showModal() {
    this.setAttribute('open', '');
  };
  HTMLDialogElement.prototype.close = function close() {
    this.removeAttribute('open');
    this.dispatchEvent(new Event('close'));
  };
  const gateway = new FakeWorkspaceGateway();
  render(<App gateway={gateway} />);
  expect(await screen.findByText('Ready on this computer')).toBeVisible();

  fireEvent.click(screen.getByRole('button', { name: 'Projects' }));
  fireEvent.change(screen.getByRole('textbox', { name: 'Project name' }), {
    target: { value: 'Context Relay' },
  });
  fireEvent.change(screen.getByRole('textbox', { name: 'Project folder' }), {
    target: { value: 'C:\\work\\context-relay' },
  });
  fireEvent.submit(screen.getByRole('form', { name: 'Add project' }));
  expect(await screen.findByText('Context Relay')).toBeVisible();

  fireEvent.click(screen.getByRole('button', { name: 'Saved context' }));
  fireEvent.change(screen.getByRole('textbox', { name: 'Title' }), {
    target: { value: 'Portable validator' },
  });
  fireEvent.change(screen.getByRole('textbox', { name: 'What should your harness remember?' }), {
    target: { value: 'Keep platform output strict' },
  });
  fireEvent.submit(screen.getByRole('form', { name: 'New context' }));
  expect(await screen.findByText('Portable validator')).toBeVisible();

  fireEvent.click(screen.getByRole('button', { name: 'Edit Portable validator' }));
  fireEvent.change(screen.getByRole('textbox', { name: 'Edit title' }), {
    target: { value: 'Portable report validator' },
  });
  fireEvent.submit(screen.getByRole('form', { name: 'Edit context' }));
  expect(await screen.findByText('Portable report validator')).toBeVisible();

  fireEvent.change(screen.getByRole('searchbox', { name: 'Search saved context' }), {
    target: { value: 'strict' },
  });
  fireEvent.submit(screen.getByRole('search', { name: 'Context search' }));
  expect(await screen.findByText('Portable report validator')).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Archive Portable report validator' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Confirm archive' }));
  expect(await screen.findByText('Memory archived')).toBeVisible();

  fireEvent.click(screen.getByRole('button', { name: 'Suggestions' }));
  expect(await screen.findByText('Candidate memory')).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Accept Candidate memory' }));
  expect(await screen.findByText('Candidate accepted')).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Reject Noisy candidate' }));
  expect(await screen.findByText('Candidate rejected')).toBeVisible();

  fireEvent.click(screen.getByRole('button', { name: 'Tasks' }));
  fireEvent.change(screen.getByRole('textbox', { name: 'Task title' }), {
    target: { value: 'Verify offline flow' },
  });
  fireEvent.change(screen.getByRole('textbox', { name: 'Task details' }), {
    target: { value: 'Run the local checks' },
  });
  fireEvent.submit(screen.getByRole('form', { name: 'New task' }));
  expect(await screen.findByText('Verify offline flow')).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Edit Verify offline flow' }));
  fireEvent.change(screen.getByRole('textbox', { name: 'Edit task title' }), {
    target: { value: 'Verify offline workflow' },
  });
  fireEvent.submit(screen.getByRole('form', { name: 'Edit task' }));
  expect(await screen.findByText('Verify offline workflow')).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Start Verify offline workflow' }));
  expect(await screen.findByText('in progress')).toBeVisible();
  fireEvent.change(screen.getByRole('textbox', { name: 'Evidence for Verify offline workflow' }), {
    target: { value: 'All checks passed' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Complete Verify offline workflow' }));
  expect(await screen.findByText('Done')).toBeVisible();
  expect(await screen.findByText('All checks passed')).toBeVisible();
  expect(gateway.networkCalls).toBe(0);

  cleanup();
  expect((await gateway.projects()).map((project) => project.name)).toEqual(['Context Relay']);
  expect(await gateway.candidates()).toEqual([]);
  expect((await gateway.tasks())[0]).toMatchObject({
    title: 'Verify offline workflow',
    status: 'done',
  });
  expect(gateway.networkCalls).toBe(0);
});
