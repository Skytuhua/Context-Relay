import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';

import App from './App';
import type { MemoryRecord, ProjectIdentity, TaskRecord } from './bindings';
import type { WorkspaceGateway } from './workspace';

const project = { projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c073980', name: 'Research' } as ProjectIdentity;
const first = { id: 'first', title: 'First record', bodyMarkdown: 'First text', status: 'todo', evidence: [] } as unknown as TaskRecord & MemoryRecord;
const second = { ...first, id: 'second', title: 'Second record', bodyMarkdown: 'Second text' };
const gateway = {
  pendingWrites: async () => ({ writes: [], nextCursor: null }),
  status: async () => ({ vault: 'unlocked', sync: 'offline' }),
  projects: async () => [project],
  memories: async () => [first, second],
  tasks: async () => [first, second],
} as unknown as WorkspaceGateway;
const screens = [
  { page: 'Saved context', form: 'Edit context', title: 'Edit title', body: 'Edit context', update: 'updateMemory', create: 'Save context' },
  { page: 'Tasks', form: 'Edit task', title: 'Edit task title', body: 'Edit task details', update: 'updateTask', create: 'Save task' },
] as const;

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it.each(screens)('$page loads the selected record instead of submitting another record’s draft', async ({ page, form, title, body, update }) => {
  const save = vi.fn().mockResolvedValue(second);
  render(<App gateway={{ ...gateway, [update]: save }} />);
  await screen.findByText('Ready on this computer');
  fireEvent.click(screen.getByRole('button', { name: page }));
  fireEvent.click(await screen.findByRole('button', { name: 'Edit First record' }));
  fireEvent.change(screen.getByLabelText(title), { target: { value: 'Unsubmitted first title' } });
  fireEvent.change(screen.getByRole('textbox', { name: body }), { target: { value: 'Unsubmitted first text' } });
  fireEvent.click(screen.getByRole('button', { name: 'Edit Second record' }));
  expect(screen.getByLabelText(title)).toHaveValue(second.title);
  expect(screen.getByRole('textbox', { name: body })).toHaveValue(second.bodyMarkdown);
  fireEvent.submit(screen.getByRole('form', { name: form }));
  await act(async () => {});
  expect(save).toHaveBeenCalledWith(second, second.title, second.bodyMarkdown);
});

it.each(screens)('$page keeps a pending edit attached to its record and preserves an unconfirmed draft', async ({ page, form, title, body, update, create }) => {
  let reject!: (error: Error) => void;
  const save = vi.fn(() => new Promise<never>((_, fail) => { reject = fail; }));
  render(<App gateway={{ ...gateway, [update]: save }} />);
  await screen.findByText('Ready on this computer');
  fireEvent.click(screen.getByRole('button', { name: page }));
  fireEvent.click(await screen.findByRole('button', { name: 'Edit First record' }));
  fireEvent.change(screen.getByLabelText(title), { target: { value: 'Updated title' } });
  fireEvent.change(screen.getByRole('textbox', { name: body }), { target: { value: 'Updated text' } });
  const edit = screen.getByRole('form', { name: form });
  fireEvent.submit(edit);
  fireEvent.submit(edit);
  expect(save).toHaveBeenCalledTimes(1);
  expect(within(edit).getByRole('button', { name: 'Saving changes…' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Home' })).toBeDisabled();
  expect(screen.getByRole('combobox', { name: 'Current project' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Edit Second record' })).toBeDisabled();
  expect(screen.getByRole('button', { name: create })).toBeDisabled();
  expect(screen.getByRole('textbox', { name: body })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Home' }));
  expect(edit).toBeVisible();
  await act(async () => { reject(new Error('private native details')); });
  expect(screen.getByRole('alert')).toHaveTextContent('Your draft is still here.');
  expect(screen.getByRole('alert')).not.toHaveTextContent('private native details');
  expect(screen.getByLabelText(title)).toHaveValue('Updated title');
  expect(screen.getByRole('textbox', { name: body })).toHaveValue('Updated text');
  expect(screen.getByRole('textbox', { name: body })).toBeEnabled();
  expect(screen.getByRole('button', { name: 'Home' })).toBeEnabled();
});

it('keeps an acknowledged edit visible when an older search finishes later', async () => {
  let finishSearch!: (records: MemoryRecord[]) => void;
  const updated = { ...first, title: 'Saved new title', bodyMarkdown: 'Saved new text' };
  const memories = vi.fn().mockResolvedValueOnce([first, second]).mockResolvedValue([updated, second]);
  render(<App gateway={{ ...gateway, memories, updateMemory: async () => updated, searchMemories: () => new Promise((resolve) => { finishSearch = resolve; }) }} />);
  await screen.findByText('Ready on this computer');
  fireEvent.click(screen.getByRole('button', { name: 'Saved context' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Edit First record' }));
  fireEvent.change(screen.getByLabelText('Search saved context'), { target: { value: 'First' } });
  fireEvent.submit(screen.getByRole('search', { name: 'Context search' }));
  fireEvent.change(screen.getByLabelText('Edit title'), { target: { value: updated.title } });
  fireEvent.change(screen.getByRole('textbox', { name: 'Edit context' }), { target: { value: updated.bodyMarkdown } });
  fireEvent.submit(screen.getByRole('form', { name: 'Edit context' }));
  await screen.findByText('Memory updated');
  await act(async () => { finishSearch([first]); });
  expect(screen.getByText(updated.title)).toBeVisible();
  expect(screen.getByText(updated.bodyMarkdown)).toBeVisible();
  expect(screen.queryByText(first.title)).not.toBeInTheDocument();
  expect(screen.queryByRole('form', { name: 'Edit context' })).not.toBeInTheDocument();
  expect(screen.queryByText('Loading your saved records…')).not.toBeInTheDocument();
});

it('keeps a newer visible revision when an older uncertain edit is replayed and refresh fails', async () => {
  const original = { ...first, revision: 'original' as MemoryRecord['revision'] };
  const oldSave = { ...original, revision: 'old-save' as MemoryRecord['revision'], bodyMarkdown: 'Earlier saved edit' };
  const current = { ...original, revision: 'latest' as MemoryRecord['revision'], bodyMarkdown: 'Newer saved text' };
  const updateMemory = vi.fn().mockRejectedValueOnce(new Error('reply lost')).mockResolvedValue(oldSave);
  const memories = vi.fn().mockResolvedValueOnce([original]).mockRejectedValue(new Error('refresh failed'));
  render(<App gateway={{ ...gateway, memories, updateMemory, searchMemories: async () => [current] }} />);
  await screen.findByText('Ready on this computer');
  fireEvent.click(screen.getByRole('button', { name: 'Saved context' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Edit First record' }));
  fireEvent.change(screen.getByRole('textbox', { name: 'Edit context' }), { target: { value: oldSave.bodyMarkdown } });
  fireEvent.submit(screen.getByRole('form', { name: 'Edit context' }));
  await screen.findByRole('alert');
  fireEvent.change(screen.getByLabelText('Search saved context'), { target: { value: 'First' } });
  fireEvent.submit(screen.getByRole('search', { name: 'Context search' }));
  await screen.findByText(current.bodyMarkdown);
  fireEvent.submit(screen.getByRole('form', { name: 'Edit context' }));
  await screen.findByText('Memory updated');
  expect(screen.getByText(current.bodyMarkdown)).toBeVisible();
  expect(screen.queryByText(oldSave.bodyMarkdown)).not.toBeInTheDocument();
});

it.each(['start', 'complete', 'archive'] as const)('does not let an edit refresh undo a later %s acknowledgment', async (action) => {
  let finishRefresh!: (records: (TaskRecord & MemoryRecord)[]) => void;
  const edited = { ...first, title: 'Edited record' };
  const read = vi.fn().mockResolvedValueOnce([first]).mockImplementationOnce(() => new Promise((resolve) => { finishRefresh = resolve; }));
  const transitionTask = vi.fn().mockResolvedValue({ ...edited, status: 'in_progress' });
  const completeTask = vi.fn().mockResolvedValue({ ...edited, status: 'done', evidence: [{ summary: 'Verified work' }] });
  const archiveMemory = vi.fn().mockResolvedValue(undefined);
  render(<App gateway={{ ...gateway, memories: read, tasks: read, updateMemory: async () => edited, updateTask: async () => edited, transitionTask, completeTask, archiveMemory }} />);
  await screen.findByText('Ready on this computer');
  fireEvent.click(screen.getByRole('button', { name: action === 'archive' ? 'Saved context' : 'Tasks' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Edit First record' }));
  fireEvent.change(screen.getByLabelText(action === 'archive' ? 'Edit title' : 'Edit task title'), { target: { value: edited.title } });
  fireEvent.submit(screen.getByRole('form', { name: action === 'archive' ? 'Edit context' : 'Edit task' }));
  await screen.findByText(action === 'archive' ? 'Memory updated' : 'Task updated');
  if (action === 'archive') {
    const dialog = screen.getByRole('dialog', { hidden: true }) as HTMLDialogElement;
    dialog.showModal = () => { dialog.setAttribute('open', ''); };
    dialog.close = () => { dialog.removeAttribute('open'); };
    fireEvent.click(screen.getByRole('button', { name: 'Archive Edited record' }));
    await act(async () => {});
    fireEvent.click(screen.getByRole('button', { name: 'Confirm archive' }));
    await screen.findByText('Memory archived');
  } else if (action === 'complete') {
    fireEvent.change(screen.getByLabelText('Evidence for Edited record'), { target: { value: 'Verified work' } });
    fireEvent.click(screen.getByRole('button', { name: 'Complete Edited record' }));
    await screen.findByText('Task completed');
  } else {
    fireEvent.click(screen.getByRole('button', { name: 'Start Edited record' }));
    await screen.findByText('in progress');
  }
  await act(async () => { finishRefresh([edited]); });
  if (action === 'archive') expect(screen.queryByRole('button', { name: 'Edit Edited record' })).not.toBeInTheDocument();
  else expect(screen.getByText(action === 'complete' ? 'Done' : 'in progress')).toBeVisible();
});
