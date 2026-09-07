import { readFileSync } from 'node:fs';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import App from './App';
import type { ProjectIdentity, SetupPlan } from './bindings';
import type { WorkspaceGateway } from './workspace';

const project = { projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c075001', name: 'My website' } as ProjectIdentity;
const gateway = {
  harnessExecutionCurrent: async () => null,
  harnessSetupsList: async () => ({ setups: [], nextAfter: null }),
  pendingWrites: async () => ({ writes: [], nextCursor: null }),
  status: async () => ({ vault: 'unlocked', sync: 'offline' }), projects: async () => [],
  memories: async () => [], tasks: async () => [], candidates: async () => [],
} as unknown as WorkspaceGateway;
afterEach(cleanup);

it('explains the ordered first-use journey before presenting a project form', async () => {
  localStorage.clear();
  render(<App gateway={{ ...gateway, harnessProbe: async () => ({ capability: 'missing', harnessVersion: null }) as never }} />);
  await screen.findByRole('heading', { name: 'Choose harnesses' });
  const steps = screen.getByRole('list', { name: 'Setup progress' });
  expect(within(steps).getAllByRole('listitem').map(item => item.textContent?.replace(/^\d/, '')))
    .toEqual(['Choose harnesses', 'Choose a project', 'Connect harnesses', 'Try saved context', 'Explore your dashboard']);
  expect(screen.queryByRole('form', { name: 'Add project' })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('checkbox', { name: 'Codex' }));
  fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
  expect(screen.getByRole('form', { name: 'Add project' })).toBeVisible();
});

it('returns a newly added project to Dashboard with useful context and harness actions', async () => {
  render(<App gateway={{ ...gateway, createProject: async () => project }} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Choose a project' }));
  fireEvent.change(screen.getByLabelText('Project folder'), { target: { value: 'C:\\Work\\website' } });
  fireEvent.change(screen.getByLabelText('Project name'), { target: { value: project.name } });
  fireEvent.submit(screen.getByRole('form', { name: 'Add project' }));
  await screen.findByText('Project added');
  expect(screen.getByRole('heading', { name: 'Dashboard', level: 1 })).toBeVisible();
  expect(screen.getByRole('combobox', { name: 'Current project' })).toHaveValue(project.projectId);
  expect(screen.getByRole('button', { name: 'Open Harnesses' })).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Add context' }));
  expect(screen.getByRole('form', { name: 'New context' })).toBeVisible();
});

it('offers a direct route from an empty Harnesses screen to adding a folder', async () => {
  render(<App gateway={gateway} />);
  await screen.findByText('Ready on this computer');
  fireEvent.click(screen.getByRole('button', { name: 'Harnesses' }));
  expect(screen.getByRole('heading', { name: 'Add a project first' })).toBeVisible();
  expect(screen.queryByRole('button', { name: 'Review setup' })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Add a project' }));
  expect(screen.getByRole('form', { name: 'Add project' })).toBeVisible();
});

it('keeps an unavailable harness actionable without exposing technical paths by default', async () => {
  const fixture = JSON.parse(readFileSync('../../crates/protocol/tests/fixtures/runtime-contracts-v1.json', 'utf8')).setupPlan as SetupPlan;
  const harnessPreview = vi.fn();
  const memories = vi.fn().mockResolvedValue([]);
  render(<App gateway={{ ...gateway, projects: async () => [project], memories, harnessPreview,
    harnessProbe: async () => ({ executable: fixture.executablePath, executableSha256: fixture.executableHash,
      harnessVersion: '0.144.6', installationMethod: 'manual', configRoots: [], activeProfile: null,
      codexSavedHookApproval: null, policyConflicts: [], capability: 'import_only' }),
  }} />);
  await screen.findByText('Ready on this computer');
  fireEvent.click(screen.getByRole('button', { name: 'Harnesses' }));
  await waitFor(() => expect(screen.getByRole('button', { name: 'Review setup' })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: 'Review setup' }));
  const availability = await screen.findByRole('region', { name: 'Harness availability' });
  expect(within(availability).getByText(/Executable:/)).not.toBeVisible();
  expect(within(availability).getByText(/not connected/i)).toBeVisible();
  expect(harnessPreview).not.toHaveBeenCalled();
  fireEvent.click(within(availability).getByRole('button', { name: 'Save context' }));
  expect(screen.getByRole('form', { name: 'New context' })).toBeVisible();
  expect(memories).toHaveBeenCalledWith(project.projectId);
});
