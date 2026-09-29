import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';

import App from './App';
import type { WorkspaceGateway } from './workspace';
import { PROTOCOL_VERSION } from './bindings';
import { defaultPreferences } from './desktop-preferences';
import { fixtureProject } from './test-fixtures';

beforeEach(() => {
  HTMLDialogElement.prototype.showModal = function showModal() { this.setAttribute('open', ''); };
  HTMLDialogElement.prototype.close = function close() { this.removeAttribute('open'); };
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  localStorage.setItem('context-relay.desktop-preferences.v1', JSON.stringify({
    ...defaultPreferences(),
    setup: { ...defaultPreferences().setup, status: 'complete' },
  }));
});

const projects = [fixtureProject({ projectId: 'p-1' as never, name: 'Alpha' }), fixtureProject({ projectId: 'p-2' as never, name: 'Beta' })];

function renderApp() {
  const gateway = {
    harnessExecutionCurrent: async () => null,
    harnessSetupsList: async () => ({ setups: [], nextAfter: null }),
    pendingWrites: async () => ({ writes: [], nextCursor: null }),
    status: async () => ({
      protocol: { min: PROTOCOL_VERSION, max: PROTOCOL_VERSION },
      vault: 'unlocked',
      resolvedProject: null,
      sync: 'offline',
      access: { mode: 'default' },
    }),
    projects: async () => projects,
    searchMemories: async () => [],
    devices: async () => [],
    recoveryRestoreOverview: async () => ({ state: 'idle' }),
    recoveryEnrollmentOverview: async () => ({
      enrollmentId: null, state: 'idle', createdAtMs: null, transitionedAtMs: null,
    }),
    memories: async () => [],
    candidates: async () => [],
    tasks: async () => [],
  } as unknown as WorkspaceGateway;
  render(<App gateway={gateway} />);
  return gateway;
}

const ctrl = (key: string, init: KeyboardEventInit = {}) =>
  fireEvent.keyDown(window, { key, ctrlKey: true, ...init });

it('navigates between screens with number shortcuts', async () => {
  renderApp();
  await screen.findByLabelText('Current project');

  ctrl('3');
  await waitFor(() => expect(screen.getByRole('button', { name: 'Tasks' })).toHaveAttribute('aria-current', 'page'));

  ctrl('2');
  await waitFor(() => expect(screen.getByRole('button', { name: 'Context' })).toHaveAttribute('aria-current', 'page'));
});

it('opens the shortcut reference and lists every group', async () => {
  renderApp();
  await screen.findByLabelText('Current project');
  ctrl('/');
  const dialog = await screen.findByRole('dialog', { name: 'Keyboard shortcuts' });
  expect(dialog).toHaveTextContent('Go to');
  expect(dialog).toHaveTextContent('Switch project');
  expect(dialog).toHaveTextContent('Search context');
});

it('closes the shortcut reference with Escape', async () => {
  renderApp();
  await screen.findByLabelText('Current project');
  ctrl('/');
  await screen.findByRole('dialog', { name: 'Keyboard shortcuts' });
  fireEvent.keyDown(window, { key: 'Escape' });
  await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Keyboard shortcuts' })).toBeNull());
});

it('does not create a note while the user is typing', async () => {
  renderApp();
  await screen.findByLabelText('Current project');
  ctrl('2');
  await waitFor(() => expect(screen.getByLabelText('Search saved context')).toBeInTheDocument());

  // With the new-note form already open, Ctrl+N inside the title field must
  // not be intercepted: it types, it does not reset the editor.
  const title = screen.getByLabelText('Title');
  const before = title.getAttribute('value');
  fireEvent.keyDown(title, { key: 'n', ctrlKey: true });
  expect(screen.getByLabelText('Title')).toBe(title);
  expect(title.getAttribute('value')).toBe(before);

  // And a bare letter inside the search field is typing, not a shortcut.
  const field = screen.getByLabelText('Search saved context');
  fireEvent.keyDown(field, { key: 'n' });
  expect(screen.getByLabelText('Search saved context')).toBe(field);
});

it('cycles projects with the alt-arrow shortcuts, wrapping at the end', async () => {
  renderApp();
  const select = (await screen.findByLabelText('Current project')) as HTMLSelectElement;
  // The app selects the first project on load.
  await waitFor(() => expect(select.value).toBe('p-1'));

  const right = () => fireEvent.keyDown(window, { key: 'ArrowRight', ctrlKey: true, altKey: true });
  const left = () => fireEvent.keyDown(window, { key: 'ArrowLeft', ctrlKey: true, altKey: true });

  right();
  await waitFor(() => expect((screen.getByLabelText('Current project') as HTMLSelectElement).value).toBe('p-2'));
  // Forward from the last project wraps to the first.
  right();
  await waitFor(() => expect((screen.getByLabelText('Current project') as HTMLSelectElement).value).toBe('p-1'));
  // Backwards from the first wraps to the last.
  left();
  await waitFor(() => expect((screen.getByLabelText('Current project') as HTMLSelectElement).value).toBe('p-2'));
});
