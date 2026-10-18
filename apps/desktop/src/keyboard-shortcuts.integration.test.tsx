import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';

import App from './App';
import type { WorkspaceGateway } from './workspace';
import { PROTOCOL_VERSION, type MemoryRecord } from './bindings';
import { defaultPreferences } from './desktop-preferences';
import { fixtureMemory, fixtureProject } from './test-fixtures';

beforeEach(() => {
  HTMLDialogElement.prototype.showModal = function showModal() { this.setAttribute('open', ''); };
  HTMLDialogElement.prototype.close = function close() {
    this.removeAttribute('open');
    this.dispatchEvent(new Event('close'));
  };
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  localStorage.setItem('context-relay.desktop-preferences.v1', JSON.stringify({
    ...defaultPreferences(),
    setup: { ...defaultPreferences().setup, status: 'complete' },
  }));
});

const projects = [fixtureProject({ name: 'Alpha' }), fixtureProject({ name: 'Beta' })];

function renderApp(overrides: Partial<WorkspaceGateway> = {}) {
  const gateway = {
    harnessExecutionCurrent: async () => null,
    harnessSetupsList: async () => ({ setups: [], nextAfter: null }),
    harnessProbe: async () => ({ capability: 'missing', configRoots: [], policyConflicts: [], harnessVersion: null }),
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
    ...overrides,
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

it('uses the native modal cancel event and restores keyboard focus', async () => {
  renderApp();
  await screen.findByLabelText('Current project');
  const trigger = screen.getByRole('button', { name: 'Projects' });
  trigger.focus();
  ctrl('/');
  const dialog = await screen.findByRole('dialog', { name: 'Keyboard shortcuts' });
  expect(dialog).toBeInstanceOf(HTMLDialogElement);
  expect(dialog).toHaveAttribute('open');
  expect(within(dialog).getByRole('button', { name: 'Close' })).toHaveFocus();

  ctrl('3');
  ctrl('ArrowRight', { altKey: true });
  expect(screen.getByRole('button', { name: 'Dashboard' })).toHaveAttribute('aria-current', 'page');
  expect(screen.getByLabelText('Current project')).toHaveValue(projects[0].projectId);

  // Browsers dispatch cancel when Escape is pressed in a modal dialog.
  fireEvent(dialog, new Event('cancel', { cancelable: true }));
  await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Keyboard shortcuts' })).toBeNull());
  expect(trigger).toHaveFocus();
});

it('does not create a note while the user is typing', async () => {
  renderApp();
  await screen.findByLabelText('Current project');
  ctrl('n');
  await screen.findByRole('form', { name: 'New context' });

  // With the new-note form already open, Ctrl+N inside the title field must
  // not be intercepted: it types, it does not reset the editor.
  const title = screen.getByLabelText('Title');
  fireEvent.change(title, { target: { value: 'Unfinished context' } });
  fireEvent.keyDown(title, { key: 'n', ctrlKey: true });
  expect(screen.getByLabelText('Title')).toBe(title);
  expect(title).toHaveValue('Unfinished context');

  // And a bare letter inside the search field is typing, not a shortcut.
  const field = screen.getByLabelText('Search saved context');
  fireEvent.keyDown(field, { key: 'n' });
  expect(screen.getByLabelText('Search saved context')).toBe(field);
});

it('cycles projects with the alt-arrow shortcuts, wrapping at the end', async () => {
  renderApp();
  const select = (await screen.findByLabelText('Current project')) as HTMLSelectElement;
  // The app selects the first project on load.
  await waitFor(() => expect(select.value).toBe(projects[0].projectId));

  const right = () => fireEvent.keyDown(window, { key: 'ArrowRight', ctrlKey: true, altKey: true });
  const left = () => fireEvent.keyDown(window, { key: 'ArrowLeft', ctrlKey: true, altKey: true });

  right();
  await waitFor(() => expect((screen.getByLabelText('Current project') as HTMLSelectElement).value).toBe(projects[1].projectId));
  // Forward from the last project wraps to the first.
  right();
  await waitFor(() => expect((screen.getByLabelText('Current project') as HTMLSelectElement).value).toBe(projects[0].projectId));
  // Backwards from the first wraps to the last.
  left();
  await waitFor(() => expect((screen.getByLabelText('Current project') as HTMLSelectElement).value).toBe(projects[1].projectId));
});

it('reloads the current list for the project selected by a shortcut', async () => {
  const alphaNote = fixtureMemory({ title: 'Alpha context' });
  const betaNote = fixtureMemory({ title: 'Beta context' });
  const memories = vi.fn(async (projectId: string | null) => projectId === projects[0].projectId ? [alphaNote] : [betaNote]);
  renderApp({ memories });
  await screen.findByRole('button', { name: alphaNote.title });
  ctrl('2');
  await screen.findByRole('heading', { name: alphaNote.title });

  ctrl('ArrowRight', { altKey: true });

  expect(screen.queryByRole('heading', { name: alphaNote.title })).not.toBeInTheDocument();
  await screen.findByRole('heading', { name: betaNote.title });
  expect(memories).toHaveBeenLastCalledWith(projects[1].projectId);
});

it('ignores a previous project read that completes after a keyboard project switch', async () => {
  const alphaNote = fixtureMemory({ title: 'Late Alpha context' });
  const betaNote = fixtureMemory({ title: 'Current Beta context' });
  let delayAlpha = false;
  let finishAlpha!: (records: MemoryRecord[]) => void;
  const memories = vi.fn((projectId: string | null) => {
    if (projectId === projects[0].projectId && delayAlpha) {
      delayAlpha = false;
      return new Promise<MemoryRecord[]>(resolve => { finishAlpha = resolve; });
    }
    return Promise.resolve(projectId === projects[0].projectId ? [alphaNote] : [betaNote]);
  });
  renderApp({ memories });
  await screen.findByRole('button', { name: alphaNote.title });
  delayAlpha = true;
  ctrl('2');
  ctrl('ArrowRight', { altKey: true });
  await screen.findByRole('heading', { name: betaNote.title });

  await act(async () => { finishAlpha([alphaNote]); });

  expect(screen.queryByRole('heading', { name: alphaNote.title })).not.toBeInTheDocument();
  expect(screen.getByRole('heading', { name: betaNote.title })).toBeInTheDocument();
});

it('preserves each project draft while cycling with the keyboard', async () => {
  renderApp();
  await screen.findByLabelText('Current project');
  ctrl('n');
  fireEvent.change(screen.getByLabelText('Title'), { target: { value: 'Alpha draft' } });
  fireEvent.change(screen.getByLabelText('What should your harness remember?'), { target: { value: 'Alpha details' } });
  screen.getByRole('heading', { level: 1, name: 'Context' }).focus();
  ctrl('ArrowRight', { altKey: true });
  expect(screen.getByLabelText('Title')).toHaveValue('');
  fireEvent.change(screen.getByLabelText('Title'), { target: { value: 'Beta draft' } });

  screen.getByRole('heading', { level: 1, name: 'Context' }).focus();
  ctrl('ArrowLeft', { altKey: true });

  expect(screen.getByLabelText('Title')).toHaveValue('Alpha draft');
  expect(screen.getByLabelText('What should your harness remember?')).toHaveValue('Alpha details');
  ctrl('ArrowRight', { altKey: true });
  expect(screen.getByLabelText('Title')).toHaveValue('Beta draft');
});

it('does not switch projects or open another editor while a record is saving', async () => {
  let finishSave!: (record: MemoryRecord) => void;
  const createMemory = vi.fn(() => new Promise<MemoryRecord>(resolve => { finishSave = resolve; }));
  renderApp({ createMemory });
  await screen.findByLabelText('Current project');
  ctrl('n');
  fireEvent.change(screen.getByLabelText('Title'), { target: { value: 'Saving draft' } });
  fireEvent.change(screen.getByLabelText('What should your harness remember?'), { target: { value: 'Keep this scope' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save context' }));

  ctrl('ArrowRight', { altKey: true });
  ctrl('t', { shiftKey: true });
  ctrl('1');
  ctrl('/');

  expect(screen.getByLabelText('Current project')).toHaveValue(projects[0].projectId);
  expect(screen.getByRole('button', { name: 'Context' })).toHaveAttribute('aria-current', 'page');
  expect(screen.queryByRole('dialog', { name: 'Keyboard shortcuts' })).not.toBeInTheDocument();
  await act(async () => { finishSave(fixtureMemory({ title: 'Saving draft' })); });
  ctrl('3');
  expect(screen.queryByRole('form', { name: 'New task' })).not.toBeInTheDocument();
});

it('does not queue workspace shortcuts while first-time setup is active', async () => {
  localStorage.clear();
  renderApp();
  await screen.findByRole('heading', { name: 'Choose harnesses' });
  ctrl('n');
  ctrl('/');

  fireEvent.click(screen.getByRole('button', { name: 'Finish later' }));

  expect(screen.queryByRole('dialog', { name: 'Keyboard shortcuts' })).not.toBeInTheDocument();
  ctrl('2');
  expect(screen.queryByRole('form', { name: 'New context' })).not.toBeInTheDocument();
});

it('does not queue a new editor while a project is being added', async () => {
  let finishProject!: (project: typeof projects[number]) => void;
  const createProject = vi.fn(() => new Promise<typeof projects[number]>(resolve => { finishProject = resolve; }));
  renderApp({ createProject });
  await screen.findByLabelText('Current project');
  ctrl('5');
  fireEvent.change(screen.getByLabelText('Project name'), { target: { value: 'Gamma' } });
  fireEvent.change(screen.getByLabelText('Project folder'), { target: { value: 'C:\\Projects\\Gamma' } });
  fireEvent.click(screen.getByRole('button', { name: 'Add project' }));

  ctrl('n');
  ctrl('ArrowRight', { altKey: true });

  expect(screen.getByLabelText('Current project')).toHaveValue(projects[0].projectId);
  await act(async () => { finishProject(fixtureProject({ name: 'Gamma' })); });
  ctrl('2');
  expect(screen.queryByRole('form', { name: 'New context' })).not.toBeInTheDocument();
});

it('pauses workspace shortcuts while another native dialog is open', async () => {
  renderApp();
  await screen.findByLabelText('Current project');
  ctrl('7');
  fireEvent.click(screen.getByRole('button', { name: 'Security details' }));
  await screen.findByRole('dialog', { name: 'Local security details' });

  ctrl('3');
  ctrl('/');

  expect(screen.getByRole('button', { name: 'Settings' })).toHaveAttribute('aria-current', 'page');
  expect(screen.queryByRole('dialog', { name: 'Keyboard shortcuts' })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Close security details' }));
  ctrl('3');
  expect(screen.getByRole('button', { name: 'Tasks' })).toHaveAttribute('aria-current', 'page');
});
