import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import App from './App';
import { PROTOCOL_VERSION, type ProjectIdentity } from './bindings';
import { readPreferences } from './desktop-preferences';
import type { WorkspaceGateway } from './workspace';

const installer = { projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c073980', name: 'Installer verification' } as ProjectIdentity;
const project = { projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c073981', name: 'My website' } as ProjectIdentity;
function fixture() {
  return {
    status: vi.fn(async () => ({ protocol: { min: PROTOCOL_VERSION, max: PROTOCOL_VERSION }, vault: 'unlocked', sync: 'offline', resolvedProject: null, access: { mode: 'default' } })),
    projects: vi.fn(async () => [installer, project]),
    harnessProbe: vi.fn(async () => ({ capability: 'missing', harnessVersion: null })),
    harnessExecutionCurrent: vi.fn(async () => null),
    harnessSetupsList: vi.fn(async () => ({ setups: [], nextAfter: null })),
    pendingWrites: vi.fn(async () => ({ writes: [], nextCursor: null })),
    memories: vi.fn(async () => []), tasks: vi.fn(async () => []), candidates: vi.fn(async () => []),
    createProject: vi.fn(), createMemory: vi.fn(), harnessApply: vi.fn(), connectionCheckStart: vi.fn(),
  };
}
beforeEach(() => { localStorage.clear(); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

it('starts fresh in the five-step guide with no preselected harness or hidden writes', async () => {
  const api = fixture();
  render(<App gateway={api as unknown as WorkspaceGateway} />);
  const heading = await screen.findByRole('heading', { name: 'Choose harnesses', level: 1 });
  expect(heading).toHaveFocus();
  expect(within(screen.getByRole('list', { name: 'Setup progress' })).getAllByRole('listitem')).toHaveLength(5);
  expect(screen.getByRole('button', { name: 'Continue' })).toBeDisabled();
  for (const checkbox of screen.getAllByRole('checkbox')) expect(checkbox).not.toBeChecked();
  expect(document.documentElement.dataset.theme).toBe('dark');
  expect(api.createProject).not.toHaveBeenCalled();
  expect(api.createMemory).not.toHaveBeenCalled();
  expect(api.harnessApply).not.toHaveBeenCalled();
  expect(api.connectionCheckStart).not.toHaveBeenCalled();
});

it('requires a deliberate project choice even when an old installer project exists', async () => {
  const api = fixture();
  render(<App gateway={api as unknown as WorkspaceGateway} />);
  fireEvent.click(await screen.findByRole('checkbox', { name: 'Codex' }));
  fireEvent.click(screen.getByRole('checkbox', { name: 'Claude Code' }));
  fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
  expect(screen.getByRole('heading', { name: 'Choose a project' })).toHaveFocus();
  expect(screen.getByRole('radio', { name: installer.name })).not.toBeChecked();
  expect(screen.getByRole('radio', { name: project.name })).not.toBeChecked();
  expect(screen.getByRole('button', { name: 'Continue' })).toBeDisabled();
  fireEvent.click(screen.getByRole('radio', { name: project.name }));
  expect(readPreferences().setup).toMatchObject({ projectId: project.projectId, harnesses: ['codex', 'claude_code'], step: 'project' });
  expect(screen.getByRole('button', { name: 'Continue' })).toBeEnabled();
  expect(api.createProject).not.toHaveBeenCalled();
  expect(api.harnessApply).not.toHaveBeenCalled();
});

it('defers, restarts and resumes the same selected project and step without replaying writes', async () => {
  const api = fixture();
  const gateway = api as unknown as WorkspaceGateway;
  const first = render(<App gateway={gateway} />);
  fireEvent.click(await screen.findByRole('checkbox', { name: 'Codex' }));
  fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
  fireEvent.click(screen.getByRole('radio', { name: project.name }));
  fireEvent.click(screen.getByRole('button', { name: 'Finish later' }));
  expect(screen.getByRole('heading', { name: 'Dashboard', level: 1 })).toBeVisible();
  expect(readPreferences().setup.status).toBe('deferred');
  expect(screen.getByRole('combobox', { name: 'Current project' })).toHaveValue(project.projectId);
  first.unmount();
  render(<App gateway={gateway} />);
  await screen.findByText('Ready on this computer');
  expect(screen.getByRole('combobox', { name: 'Current project' })).toHaveValue(project.projectId);
  fireEvent.click(screen.getByRole('button', { name: 'Resume setup' }));
  expect(screen.getByRole('heading', { name: 'Choose a project' })).toBeVisible();
  expect(screen.getByRole('radio', { name: project.name })).toBeChecked();
  expect(screen.getByRole('radio', { name: installer.name })).not.toBeChecked();
  expect(api.createProject).not.toHaveBeenCalled();
  expect(api.createMemory).not.toHaveBeenCalled();
  expect(api.harnessApply).not.toHaveBeenCalled();
  expect(api.connectionCheckStart).not.toHaveBeenCalled();
});

it('persists appearance choices and responds to System appearance changes', async () => {
  let listener: (() => void) | undefined;
  const media = { matches: false, addEventListener: vi.fn((_event: string, callback: () => void) => { listener = callback; }), removeEventListener: vi.fn() };
  vi.stubGlobal('matchMedia', vi.fn(() => media));
  const gateway = fixture() as unknown as WorkspaceGateway;
  const first = render(<App gateway={gateway} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Finish later' }));
  fireEvent.click(screen.getByRole('button', { name: 'Settings' }));
  fireEvent.change(screen.getByRole('combobox', { name: 'Theme' }), { target: { value: 'light' } });
  expect(document.documentElement.dataset.theme).toBe('light');
  first.unmount();
  render(<App gateway={gateway} />);
  await screen.findByText('Ready on this computer');
  expect(document.documentElement.dataset.theme).toBe('light');
  fireEvent.click(screen.getByRole('button', { name: 'Settings' }));
  expect(screen.getByRole('combobox', { name: 'Theme' })).toHaveValue('light');
  fireEvent.change(screen.getByRole('combobox', { name: 'Theme' }), { target: { value: 'system' } });
  expect(document.documentElement.dataset.theme).toBe('light');
  act(() => { media.matches = true; listener?.(); });
  expect(document.documentElement.dataset.theme).toBe('dark');
  expect(readPreferences().theme).toBe('system');
  vi.unstubAllGlobals();
});

it('replays the nonblocking tour from Help after skipping it', async () => {
  const api = fixture();
  render(<App gateway={api as unknown as WorkspaceGateway} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Finish later' }));
  fireEvent.click(screen.getByRole('button', { name: 'Help' }));
  fireEvent.click(screen.getByRole('button', { name: 'Start tour' }));
  expect(screen.getByRole('complementary', { name: 'Choose your project' })).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Next' }));
  fireEvent.click(screen.getByRole('button', { name: 'Show saved context' }));
  expect(screen.getByRole('heading', { level: 1, name: 'Context' })).toBeVisible();
  expect(screen.getByRole('button', { name: 'Add context' })).toBeEnabled();
  fireEvent.click(screen.getByRole('button', { name: 'Skip tour' }));
  expect(screen.queryByRole('button', { name: 'Skip tour' })).not.toBeInTheDocument();
  expect(readPreferences().tourCompleted).toBe(true);
  fireEvent.click(screen.getByRole('button', { name: 'Help' }));
  fireEvent.click(screen.getByRole('button', { name: 'Start tour' }));
  expect(screen.getByRole('complementary', { name: 'Choose your project' })).toBeVisible();
  expect(api.harnessApply).not.toHaveBeenCalled();
  expect(api.createMemory).not.toHaveBeenCalled();
});

it('keeps deferred setup resumable after replaying and skipping the Help tour', async () => {
  render(<App gateway={fixture() as unknown as WorkspaceGateway} />);
  fireEvent.click(await screen.findByRole('checkbox', { name: 'Codex' }));
  fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
  fireEvent.click(screen.getByRole('radio', { name: project.name }));
  fireEvent.click(screen.getByRole('button', { name: 'Finish later' }));
  fireEvent.click(screen.getByRole('button', { name: 'Help' }));
  fireEvent.click(screen.getByRole('button', { name: 'Start tour' }));
  fireEvent.click(screen.getByRole('button', { name: 'Skip tour' }));
  expect(readPreferences().setup).toMatchObject({ status: 'deferred', step: 'project', projectId: project.projectId });
  fireEvent.click(screen.getByRole('button', { name: 'Resume setup' }));
  expect(screen.getByRole('heading', { name: 'Choose a project' })).toBeVisible();
  expect(screen.getByRole('radio', { name: project.name })).toBeChecked();
});
