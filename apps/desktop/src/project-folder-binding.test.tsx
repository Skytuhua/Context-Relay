import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import App from './App';
import type { ProjectIdentity } from './bindings';
import { defaultPreferences } from './desktop-preferences';
import { SetupWizard } from './setup-wizard';
import type { WorkspaceGateway } from './workspace';

const project = { projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c073980', name: 'Synced research' } as ProjectIdentity;

function fixture() {
  const api = {
    status: vi.fn(async () => ({ vault: 'unlocked', sync: 'offline' })),
    projects: vi.fn(async () => [project]),
    pendingWrites: vi.fn(async () => ({ writes: [], nextCursor: null })),
    memories: vi.fn(async () => []), tasks: vi.fn(async () => []), candidates: vi.fn(async () => []),
    harnessExecutionCurrent: vi.fn(async () => null),
    harnessSetupsList: vi.fn(async () => ({ setups: [], nextAfter: null })),
    chooseProjectFolder: vi.fn(async (): Promise<string | null> => 'C:\\Work\\research'),
    bindProjectFolder: vi.fn(async () => {}),
    createProject: vi.fn(),
  };
  return { api, gateway: api as unknown as WorkspaceGateway };
}

afterEach(cleanup);

it('connects an existing synced project to a local folder without creating another identity', async () => {
  const { api, gateway } = fixture();
  render(<App gateway={gateway} />);
  await screen.findByText('Ready on this computer');
  fireEvent.click(screen.getByRole('button', { name: 'Projects' }));
  fireEvent.click(screen.getByRole('button', { name: `Choose local folder for ${project.name}` }));
  expect(await screen.findByText('Local folder saved. Review harness setup for this folder.')).toBeVisible();
  expect(api.bindProjectFolder).toHaveBeenCalledExactlyOnceWith(project.projectId, 'C:\\Work\\research');
  expect(api.createProject).not.toHaveBeenCalled();
  expect(screen.getByRole('combobox', { name: 'Current project' })).toHaveValue(project.projectId);
  expect(screen.getByRole('button', { name: project.name })).toBeVisible();
  expect(screen.getByText('C:\\Work\\research')).toBeVisible();
});

it('keeps navigation and other project writes blocked until the binding is acknowledged', async () => {
  const { api, gateway } = fixture();
  let finish!: () => void;
  api.bindProjectFolder.mockImplementation(() => new Promise<void>(resolve => { finish = resolve; }));
  render(<App gateway={gateway} />);
  await screen.findByText('Ready on this computer');
  fireEvent.click(screen.getByRole('button', { name: 'Projects' }));
  const choose = screen.getByRole('button', { name: `Choose local folder for ${project.name}` });
  fireEvent.click(choose);
  await act(async () => {});
  fireEvent.click(choose);
  expect(api.bindProjectFolder).toHaveBeenCalledTimes(1);
  expect(screen.getByRole('button', { name: 'Dashboard' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Add project' })).toBeDisabled();
  await act(async () => { finish(); });
  expect(screen.getByRole('button', { name: 'Dashboard' })).toBeEnabled();
});

it('preserves the binding when the folder picker is canceled and permits retry after rejection', async () => {
  const { api, gateway } = fixture();
  api.chooseProjectFolder.mockResolvedValueOnce(null);
  api.bindProjectFolder.mockRejectedValueOnce(new Error('Folder belongs to another project'));
  render(<App gateway={gateway} />);
  await screen.findByText('Ready on this computer');
  fireEvent.click(screen.getByRole('button', { name: 'Projects' }));
  const choose = screen.getByRole('button', { name: `Choose local folder for ${project.name}` });
  fireEvent.click(choose);
  await act(async () => {});
  expect(api.bindProjectFolder).not.toHaveBeenCalled();
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  fireEvent.click(choose);
  expect(await screen.findByRole('alert')).toHaveTextContent('The local folder could not be saved. Choose an accessible folder that is not assigned to another project, then retry.');
  expect(choose).toBeEnabled();
  expect(api.createProject).not.toHaveBeenCalled();
});

it('offers the same local-folder action for an existing project during onboarding', async () => {
  const { api, gateway } = fixture();
  render(<SetupWizard gateway={gateway} projects={[project]}
    progress={{ ...defaultPreferences().setup, status: 'in_progress', step: 'project', projectId: project.projectId, harnesses: ['codex'] }}
    onChange={vi.fn()} onProjectSaved={vi.fn()} onFinishLater={vi.fn()} onTour={vi.fn()} onOpenGuide={vi.fn()}
    renderConnection={() => null} renderTest={() => null} />);
  const existing = screen.getByRole('group', { name: 'Use an existing project' });
  fireEvent.click(within(existing).getByRole('button', { name: `Choose local folder for ${project.name}` }));
  expect(await screen.findByText('Local folder saved. Review harness setup for this folder.')).toBeVisible();
  expect(api.bindProjectFolder).toHaveBeenCalledExactlyOnceWith(project.projectId, 'C:\\Work\\research');
  expect(screen.getByRole('radio', { name: project.name })).toBeChecked();
  expect(api.createProject).not.toHaveBeenCalled();
});
