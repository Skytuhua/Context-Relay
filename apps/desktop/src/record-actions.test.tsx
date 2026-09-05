import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';

import App from './App';
import type { MemoryCandidate, MemoryRecord, ProjectIdentity, TaskRecord } from './bindings';
import type { WorkspaceGateway } from './workspace';

const project = { projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c073980', name: 'Research' } as ProjectIdentity;
const memory = { id: 'note', title: 'Project decision', bodyMarkdown: 'Use TypeScript' } as MemoryRecord;
const task = { id: 'task', projectId: project.projectId, title: 'Verify changes', bodyMarkdown: 'Run checks', status: 'open', evidence: [] } as unknown as TaskRecord;
const candidate = { id: 'suggestion', proposedMemory: memory, evidenceSummary: 'A useful decision', state: 'pending' } as MemoryCandidate;
const gateway = {
  status: async () => ({ vault: 'unlocked', sync: 'offline' }),
  projects: async () => [project],
  memories: async () => [memory],
  tasks: async () => [task],
  candidates: async () => [candidate],
} as unknown as WorkspaceGateway;

const actions = [
  { action: 'start', page: 'Tasks', button: 'Start Verify changes', method: 'transitionTask', pending: 'Starting task…', notice: 'Task started', result: { ...task, status: 'in_progress' } },
  { action: 'complete', page: 'Tasks', button: 'Complete Verify changes', method: 'completeTask', pending: 'Completing task…', notice: 'Task completed', result: { ...task, status: 'done' } },
  { action: 'archive', page: 'Saved context', button: 'Archive Project decision', method: 'archiveMemory', pending: 'Archiving context…', notice: 'Memory archived', result: memory },
  { action: 'accept', page: 'Suggestions', button: 'Accept Project decision', method: 'reviewCandidate', pending: 'Saving your review…', notice: 'Candidate accepted', result: candidate },
  { action: 'reject', page: 'Suggestions', button: 'Reject Project decision', method: 'reviewCandidate', pending: 'Saving your review…', notice: 'Candidate rejected', result: candidate },
] as const;

afterEach(cleanup);

async function clickAction(action: typeof actions[number]) {
  fireEvent.click(screen.getByRole('button', { name: action.button }));
  if (action.action === 'archive') {
    await act(async () => {});
    fireEvent.click(screen.getByRole('button', { name: 'Confirm archive' }));
  }
}

function prepareArchiveDialog() {
  const dialog = screen.getByRole('dialog', { hidden: true }) as HTMLDialogElement;
  dialog.showModal = () => { dialog.setAttribute('open', ''); };
  dialog.close = () => { dialog.removeAttribute('open'); };
}

it.each(actions)('$action waits for acknowledgment, rejects overlapping clicks and keeps failures honest', async (action) => {
  let reject!: (error: Error) => void;
  const save = vi.fn().mockImplementationOnce(() => new Promise((_, fail) => { reject = fail; })).mockResolvedValue(action.result);
  render(<App gateway={{ ...gateway, [action.method]: save }} />);
  await screen.findByText('Ready on this computer');
  fireEvent.click(screen.getByRole('button', { name: action.page }));
  await screen.findByRole('button', { name: action.button });
  if (action.action === 'archive') prepareArchiveDialog();
  if (action.action === 'complete') fireEvent.change(screen.getByLabelText('Evidence for Verify changes'), { target: { value: 'All checks passed' } });
  await clickAction(action);
  fireEvent.click(screen.getByRole('button', { name: action.button }));
  expect(save).toHaveBeenCalledTimes(1);
  expect(screen.getByRole('button', { name: 'Home' })).toBeDisabled();
  expect(screen.getByRole('combobox', { name: 'Current project' })).toBeDisabled();
  expect(screen.getByRole('button', { name: action.button })).toBeDisabled();
  expect(screen.getByText(action.pending)).toHaveAttribute('role', 'status');
  expect(screen.queryByText(action.notice)).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Home' }));
  expect(screen.getByRole('heading', { level: 1, name: action.page })).toBeVisible();
  if (action.page === 'Tasks') {
    expect(screen.getByRole('button', { name: 'Save task' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Edit Verify changes' })).toBeDisabled();
    expect(screen.getByLabelText('Evidence for Verify changes')).toBeDisabled();
  } else if (action.page === 'Suggestions') {
    expect(screen.getByRole('button', { name: action.action === 'accept' ? 'Reject Project decision' : 'Accept Project decision' })).toBeDisabled();
  }
  await act(async () => { reject(new Error('private transport failure')); });
  expect(screen.getByRole('alert')).toHaveTextContent('could not confirm');
  expect(screen.getByRole('alert')).not.toHaveTextContent('private transport failure');
  expect(screen.getByRole('button', { name: action.button })).toBeEnabled();
  expect(screen.getByRole('button', { name: 'Home' })).toBeEnabled();
  if (action.action === 'complete') expect(screen.getByLabelText('Evidence for Verify changes')).toHaveValue('All checks passed');
  await clickAction(action);
  await screen.findByText(action.notice);
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  expect(save).toHaveBeenCalledTimes(2);
  if (action.action === 'start') expect(screen.getByText('in progress')).toBeVisible();
  else if (action.action === 'complete') expect(screen.getByText('Done')).toBeVisible();
  else expect(screen.queryByRole('button', { name: action.button })).not.toBeInTheDocument();
});

it('clears the editor only after archiving that context is acknowledged', async () => {
  let finish!: (value: MemoryRecord) => void;
  render(<App gateway={{ ...gateway, archiveMemory: () => new Promise((resolve) => { finish = resolve; }) }} />);
  await screen.findByText('Ready on this computer');
  fireEvent.click(screen.getByRole('button', { name: 'Saved context' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Edit Project decision' }));
  prepareArchiveDialog();
  await clickAction(actions[2]);
  expect(screen.getByRole('form', { name: 'Edit context' })).toBeVisible();
  await act(async () => { finish(memory); });
  expect(screen.queryByRole('form', { name: 'Edit context' })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Edit Project decision' })).not.toBeInTheDocument();
});

it('does not lock the task screen when completion evidence is missing', async () => {
  const completeTask = vi.fn();
  render(<App gateway={{ ...gateway, completeTask }} />);
  await screen.findByText('Ready on this computer');
  fireEvent.click(screen.getByRole('button', { name: 'Tasks' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Complete Verify changes' }));
  expect(completeTask).not.toHaveBeenCalled();
  expect(screen.getByRole('alert')).toHaveTextContent('Enter completion evidence');
  expect(screen.getByRole('button', { name: 'Home' })).toBeEnabled();
  expect(screen.getByLabelText('Evidence for Verify changes')).toBeEnabled();
});
