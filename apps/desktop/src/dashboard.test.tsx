import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import type { MemoryRecord, ProjectIdentity } from './bindings';
import type { WorkspaceGateway } from './workspace';
import { Dashboard } from './dashboard';

afterEach(cleanup);
const project = { projectId: 'p1', name: 'Garden' } as ProjectIdentity;
const note = (title: string) => ({ id: title, title, archived: false, updatedHlc: { physicalMs: '10', logical: 0 } }) as MemoryRecord;
const gateway = (extra = {}) => ({ memories: async () => [], tasks: async () => [], candidates: async () => [], harnessSetupsList: async () => ({ setups: [], nextAfter: null }), ...extra }) as unknown as WorkspaceGateway;
const callbacks = () => ({ onNavigate: vi.fn(), onResumeSetup: vi.fn(), setupDeferred: false });

it('shows actionable empty sections and lets users resume setup', async () => {
  const props = callbacks();
  render(<Dashboard gateway={gateway()} project={project} {...props} setupDeferred />);
  expect(await screen.findByText('No saved context yet.')).toBeVisible();
  expect(screen.getByText('No tasks to continue.')).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Add context' }));
  expect(props.onNavigate).toHaveBeenCalledWith('memory');
  fireEvent.click(screen.getByRole('button', { name: 'Resume setup' }));
  expect(props.onResumeSetup).toHaveBeenCalledOnce();
});

it('shows real active records and never calls saved settings a verified connection', async () => {
  render(<Dashboard project={project} {...callbacks()} gateway={gateway({
    memories: async () => [note('Plain language'), { ...note('Archived'), archived: true }],
    tasks: async () => [{ id: 't', title: 'Continue planting', status: 'in_progress', revision: '1' }, { id: 'd', title: 'Finished', status: 'done' }],
    candidates: async () => [{ id: 'c', state: 'pending', proposedMemory: note('Use native plants') }],
    harnessSetupsList: async () => ({ setups: [{ planId: 's', harness: 'codex', state: 'applied', createdAt: '20', targetScopes: [{ scope: 'project', projectId: 'p1' }] }], nextAfter: null }),
  })} />);
  expect(await screen.findByText('Plain language')).toBeVisible();
  expect(screen.getByText('Continue planting')).toBeVisible();
  expect(screen.getByText('Use native plants')).toBeVisible();
  expect(screen.getByText('Settings saved')).toBeVisible();
  expect(screen.queryByText('Archived')).not.toBeInTheDocument();
  expect(screen.queryByText('Finished')).not.toBeInTheDocument();
  expect(screen.queryByText(/^Connected$|^Connection verified$/)).not.toBeInTheDocument();
});

it('ignores pending data from the previous project', async () => {
  let finish!: (notes: MemoryRecord[]) => void;
  const api = gateway({ memories: (id: string) => id === 'p1' ? new Promise<MemoryRecord[]>(resolve => { finish = resolve; }) : Promise.resolve([note('New project note')]) });
  const props = callbacks();
  const view = render(<Dashboard gateway={api} project={project} {...props} />);
  view.rerender(<Dashboard gateway={api} project={{ ...project, projectId: 'p2' as ProjectIdentity['projectId'] }} {...props} />);
  expect(await screen.findByText('New project note')).toBeVisible();
  await act(async () => { finish([note('Old project note')]); });
  expect(screen.queryByText('Old project note')).not.toBeInTheDocument();
});

it('isolates a failed section and offers a working retry', async () => {
  const memories = vi.fn().mockRejectedValueOnce(new Error('offline')).mockResolvedValue([note('Recovered note')]);
  render(<Dashboard gateway={gateway({ memories })} project={project} {...callbacks()} />);
  expect(await screen.findByText(/Saved context could not be loaded/)).toBeVisible();
  expect(screen.getByText('No tasks to continue.')).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Retry saved context' }));
  expect(await screen.findByText('Recovered note')).toBeVisible();
});

it('asks for a project without fetching project records when none is selected', async () => {
  const memories = vi.fn();
  const props = callbacks();
  render(<Dashboard gateway={gateway({ memories })} project={null} {...props} />);
  fireEvent.click(screen.getByRole('button', { name: 'Choose a project' }));
  expect(props.onNavigate).toHaveBeenCalledWith('projects');
  expect(memories).not.toHaveBeenCalled();
});
