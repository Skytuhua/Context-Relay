import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import App from './App';
import type { MemoryRecord, ProjectIdentity, TaskRecord } from './bindings';
import type { WorkspaceGateway } from './workspace';

const projectA: ProjectIdentity = { projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c073980' as ProjectIdentity['projectId'], name: 'Project A', githubRepositoryId: null, gitRemoteFingerprint: null, monorepoSubdirectory: null };
const projectB: ProjectIdentity = { ...projectA, projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c073981' as ProjectIdentity['projectId'], name: 'Project B' };
const projectC: ProjectIdentity = { ...projectA, projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c073982' as ProjectIdentity['projectId'], name: 'Project C' };
const clock: MemoryRecord['createdHlc'] = { physicalMs: '1' as MemoryRecord['createdHlc']['physicalMs'], logical: 0, node: '018f22e2-79b0-7cc8-98c4-dc0c0c073987' as MemoryRecord['createdHlc']['node'] };
const note: MemoryRecord = {
  id: '018f22e2-79b0-7cc8-98c4-dc0c0c073983' as MemoryRecord['id'],
  revision: '018f22e2-79b0-7cc8-98c4-dc0c0c073984' as MemoryRecord['revision'],
  scope: { scope: 'project', projectId: projectA.projectId }, kind: 'note', title: 'A note',
  bodyMarkdown: 'Saved text for A', tags: [], archived: false, origin: 'explicit',
  provenance: { originDevice: clock.node, harness: null, source: null, createdHlc: clock },
  createdHlc: clock, updatedHlc: clock,
};
const task: TaskRecord = {
  id: '018f22e2-79b0-7cc8-98c4-dc0c0c073985' as TaskRecord['id'],
  revision: '018f22e2-79b0-7cc8-98c4-dc0c0c073986' as TaskRecord['revision'],
  projectId: projectA.projectId, title: 'A task', bodyMarkdown: 'Saved task for A', status: 'open', evidence: [],
};
const cases = [
  { page: 'Context', form: 'Edit context', record: note, title: 'Edit title', body: 'Edit context', update: 'updateMemory' },
  { page: 'Tasks', form: 'Edit task', record: task, title: 'Edit task title', body: 'Edit task details', update: 'updateTask' },
] as const;

function fixture() {
  const api = {
    status: vi.fn(async () => ({ vault: 'unlocked', sync: 'offline' })),
    projects: vi.fn(async () => [projectA, projectB]),
    pendingWrites: vi.fn(async () => ({ writes: [], nextCursor: null })),
    memories: vi.fn(async (id: string | null) => id === projectA.projectId ? [note] : []),
    tasks: vi.fn(async (id: string) => id === projectA.projectId ? [task] : []),
    candidates: vi.fn(async () => []),
    harnessExecutionCurrent: vi.fn(async () => null),
    harnessSetupsList: vi.fn(async () => ({ setups: [], nextAfter: null })),
    searchIndexStatus: vi.fn(async () => ({ phase: 'disabled', revision: 0 })),
    createProject: vi.fn(async () => projectC),
    updateMemory: vi.fn(async () => note),
    updateTask: vi.fn(async () => task),
  };
  return { api, gateway: api as unknown as WorkspaceGateway };
}

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it.each(cases)('$page isolates and restores an edit when Harnesses changes the project', async ({ page, form, record, title, body, update }) => {
  const { api, gateway } = fixture();
  render(<App gateway={gateway} />);
  await screen.findByText('Ready on this computer');
  fireEvent.click(screen.getByRole('button', { name: page }));
  fireEvent.click(await screen.findByRole('button', { name: `Edit ${record.title}` }));
  fireEvent.change(screen.getByLabelText(title), { target: { value: 'Unsubmitted A title' } });
  fireEvent.change(screen.getByRole('textbox', { name: body }), { target: { value: 'Unsubmitted A body' } });

  fireEvent.click(screen.getByRole('button', { name: 'Harnesses' }));
  fireEvent.change(screen.getByRole('combobox', { name: 'Project' }), { target: { value: projectB.projectId } });
  expect(screen.getByRole('combobox', { name: 'Current project' })).toHaveValue(projectB.projectId);
  fireEvent.click(screen.getByRole('button', { name: page }));
  await waitFor(() => expect(screen.queryByText('Loading your saved records…')).not.toBeInTheDocument());
  expect(screen.queryByRole('form', { name: form })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: `Edit ${record.title}` })).not.toBeInTheDocument();
  expect(api[update]).not.toHaveBeenCalled();

  fireEvent.change(screen.getByRole('combobox', { name: 'Current project' }), { target: { value: projectA.projectId } });
  const editor = await screen.findByRole('form', { name: form });
  expect(screen.getByLabelText(title)).toHaveValue('Unsubmitted A title');
  expect(screen.getByRole('textbox', { name: body })).toHaveValue('Unsubmitted A body');
  fireEvent.submit(editor);
  await waitFor(() => expect(api[update]).toHaveBeenCalledTimes(1));
  expect(api[update]).toHaveBeenCalledWith(record, 'Unsubmitted A title', 'Unsubmitted A body');
});

it.each(cases)('$page clears the old editor after a new project is registered while the form is busy', async ({ page, form, record, title, update }) => {
  const { api, gateway } = fixture();
  render(<App gateway={gateway} />);
  await screen.findByText('Ready on this computer');
  fireEvent.click(screen.getByRole('button', { name: page }));
  fireEvent.click(await screen.findByRole('button', { name: `Edit ${record.title}` }));
  fireEvent.change(screen.getByLabelText(title), { target: { value: 'Keep A draft' } });
  fireEvent.click(screen.getByRole('button', { name: 'Projects' }));
  fireEvent.change(screen.getByLabelText('Project folder'), { target: { value: '/projects/c' } });
  fireEvent.change(screen.getByLabelText('Project name'), { target: { value: projectC.name } });
  fireEvent.submit(screen.getByRole('form', { name: 'Add project' }));
  await screen.findByText('Project added');
  expect(api.createProject).toHaveBeenCalledWith(projectC.name, '/projects/c');
  expect(screen.getByRole('combobox', { name: 'Current project' })).toHaveValue(projectC.projectId);
  fireEvent.click(screen.getByRole('button', { name: page }));
  expect(screen.queryByRole('form', { name: form })).not.toBeInTheDocument();
  expect(api[update]).not.toHaveBeenCalled();
  fireEvent.change(screen.getByRole('combobox', { name: 'Current project' }), { target: { value: projectA.projectId } });
  await screen.findByRole('form', { name: form });
  expect(screen.getByLabelText(title)).toHaveValue('Keep A draft');
});

it('ignores an old search response after Harnesses selects another project', async () => {
  const { gateway } = fixture();
  let resolveSearch!: (records: MemoryRecord[]) => void;
  const searchMemories = vi.fn(() => new Promise<MemoryRecord[]>(resolve => { resolveSearch = resolve; }));
  render(<App gateway={{ ...gateway, searchMemories }} />);
  await screen.findByText('Ready on this computer');
  fireEvent.click(screen.getByRole('button', { name: 'Context' }));
  await screen.findByRole('button', { name: 'Edit A note' });
  fireEvent.change(screen.getByLabelText('Search saved context'), { target: { value: 'A note' } });
  fireEvent.submit(screen.getByRole('search', { name: 'Context search' }));
  await waitFor(() => expect(searchMemories).toHaveBeenCalledTimes(1));
  fireEvent.click(screen.getByRole('button', { name: 'Harnesses' }));
  fireEvent.change(screen.getByRole('combobox', { name: 'Project' }), { target: { value: projectB.projectId } });
  fireEvent.click(screen.getByRole('button', { name: 'Context' }));
  await act(async () => { resolveSearch([note]); });
  expect(screen.getByRole('combobox', { name: 'Current project' })).toHaveValue(projectB.projectId);
  expect(screen.queryByRole('button', { name: 'Edit A note' })).not.toBeInTheDocument();
});
