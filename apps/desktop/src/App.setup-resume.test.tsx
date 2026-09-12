import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import App from './App';
import type { ProjectIdentity } from './bindings';
import { defaultPreferences, readPreferences, savePreferences } from './desktop-preferences';
import type { WorkspaceGateway } from './workspace';

const projectA = { projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c073980', name: 'Setup project A' } as ProjectIdentity;
const projectB = { projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c073981', name: 'Work project B' } as ProjectIdentity;
function fixture() {
  const preferences = defaultPreferences();
  preferences.setup = { ...preferences.setup, status: 'deferred', step: 'project', projectId: projectA.projectId, harnesses: ['codex'] };
  savePreferences(preferences);
  const api = {
    status: vi.fn(async () => ({ vault: 'unlocked', sync: 'offline' })),
    projects: vi.fn(async () => [projectA, projectB]),
    memories: vi.fn(async () => []), tasks: vi.fn(async () => []), candidates: vi.fn(async () => []),
    pendingWrites: vi.fn(async () => ({ writes: [], nextCursor: null })),
    harnessExecutionCurrent: vi.fn(async () => null),
    harnessSetupsList: vi.fn(async () => ({ setups: [], nextAfter: null })),
    harnessProbe: vi.fn(async () => ({ capability: 'missing', harnessVersion: null })),
    createMemory: vi.fn(), createProject: vi.fn(), harnessApply: vi.fn(),
  };
  return { api, gateway: api as unknown as WorkspaceGateway };
}
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it('resumes the saved setup project after another project was selected in the workspace', async () => {
  const { api, gateway } = fixture();
  render(<App gateway={gateway} />);
  await screen.findByText('Ready on this computer');
  fireEvent.change(screen.getByRole('combobox', { name: 'Current project' }), { target: { value: projectB.projectId } });
  await act(async () => {});
  fireEvent.click(screen.getByRole('button', { name: 'Resume setup' }));
  expect(screen.getByRole('radio', { name: projectA.name })).toBeChecked();
  fireEvent.click(screen.getByRole('button', { name: 'Finish later' }));
  expect(screen.getByRole('combobox', { name: 'Current project' })).toHaveValue(projectA.projectId);
  expect(readPreferences().setup.projectId).toBe(projectA.projectId);
  expect(api.createMemory).not.toHaveBeenCalled();
  expect(api.createProject).not.toHaveBeenCalled();
  expect(api.harnessApply).not.toHaveBeenCalled();
});

it('does not keep a different workspace project active when the resumed project was removed', async () => {
  const { api, gateway } = fixture();
  api.projects.mockResolvedValue([projectB]);
  render(<App gateway={gateway} />);
  await screen.findByText('Ready on this computer');
  fireEvent.change(screen.getByRole('combobox', { name: 'Current project' }), { target: { value: projectB.projectId } });
  await act(async () => {});
  fireEvent.click(screen.getByRole('button', { name: 'Resume setup' }));
  expect(screen.getByRole('button', { name: 'Continue' })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Finish later' }));
  expect(screen.getByRole('combobox', { name: 'Current project' })).toHaveValue('');
  expect(api.createProject).not.toHaveBeenCalled();
});
