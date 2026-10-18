import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';

import App from './App';
import { ErrorBoundary } from './error-boundary';
import type { WorkspaceGateway } from './workspace';
import { fixtureMemory, fixtureProject, fixtureTask } from './test-fixtures';

beforeEach(() => {
  vi.spyOn(console, 'error').mockImplementation(() => undefined);
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

const project = fixtureProject();
const otherProject = fixtureProject({ name: 'Healthy project' });
const memory = fixtureMemory({ title: 'Use plain language' });
const brokenMemory = fixtureMemory({
  updatedHlc: { ...memory.updatedHlc, physicalMs: 'not-a-number' as typeof memory.updatedHlc.physicalMs },
});
// Two records are necessary to run the dashboard's sort comparator and throw.
const crashingMemories = [memory, brokenMemory];

function gateway(overrides: Partial<WorkspaceGateway> = {}): WorkspaceGateway {
  return {
    status: vi.fn().mockResolvedValue({ vault: 'unlocked' }),
    projects: vi.fn().mockResolvedValue([project, otherProject]),
    pendingWrites: vi.fn().mockResolvedValue({ writes: [], nextCursor: null }),
    memories: vi.fn().mockResolvedValue([memory]),
    searchMemories: vi.fn().mockResolvedValue([memory]),
    tasks: vi.fn().mockResolvedValue([]),
    candidates: vi.fn().mockResolvedValue([]),
    harnessSetupsList: vi.fn().mockResolvedValue({ setups: [], nextAfter: null }),
    ...overrides,
  } as unknown as WorkspaceGateway;
}

it('opens a healthy page after the dashboard fails to render', async () => {
  render(<App gateway={gateway({ memories: vi.fn().mockResolvedValue(crashingMemories) })} />);

  await screen.findByRole('heading', { name: 'Dashboard could not be displayed' });
  expect(screen.getByRole('navigation', { name: 'Workspace' })).toBeInTheDocument();
  expect(screen.getByLabelText('Current project')).toBeInTheDocument();

  fireEvent.click(screen.getByRole('button', { name: 'Projects' }));

  expect(await screen.findByLabelText('Project name')).toBeInTheDocument();
  expect(screen.queryByText(/could not be displayed/)).not.toBeInTheDocument();
});

it('reopens the failed page for a different project', async () => {
  const memories = vi.fn(async (projectId: string | null) => projectId === project.projectId ? crashingMemories : [memory]);
  render(<App gateway={gateway({ memories })} />);
  await screen.findByRole('heading', { name: 'Dashboard could not be displayed' });

  fireEvent.change(screen.getByLabelText('Current project'), { target: { value: otherProject.projectId } });

  expect(await screen.findByRole('button', { name: memory.title })).toBeInTheDocument();
  expect(memories).toHaveBeenCalledWith(otherProject.projectId);
  expect(screen.queryByText(/could not be displayed/)).not.toBeInTheDocument();
});

it('retries the failed screen and displays data that can now render', async () => {
  const memories = vi.fn().mockResolvedValue(crashingMemories);
  render(<App gateway={gateway({ memories })} />);
  await screen.findByRole('heading', { name: 'Dashboard could not be displayed' });

  memories.mockResolvedValue([memory]);
  fireEvent.click(screen.getByRole('button', { name: 'Try again' }));

  expect(await screen.findByRole('button', { name: memory.title })).toBeInTheDocument();
  expect(memories).toHaveBeenCalledTimes(2);
  expect(screen.queryByText(/could not be displayed/)).not.toBeInTheDocument();
});

it('contains a retry that fails again and still allows navigation', async () => {
  const memories = vi.fn().mockResolvedValue(crashingMemories);
  render(<App gateway={gateway({ memories })} />);
  await screen.findByRole('heading', { name: 'Dashboard could not be displayed' });

  fireEvent.click(screen.getByRole('button', { name: 'Try again' }));

  await waitFor(() => expect(memories).toHaveBeenCalledTimes(2));
  await screen.findByRole('heading', { name: 'Dashboard could not be displayed' });
  fireEvent.click(screen.getByRole('button', { name: 'Projects' }));
  expect(await screen.findByLabelText('Project name')).toBeInTheDocument();
});

it('contains an inline screen-render failure and names the failing screen', async () => {
  // The task list is rendered by App's renderScreen function, rather than a
  // separate screen component. It must still execute below the boundary.
  const task = fixtureTask({ evidence: undefined as never });
  render(<App gateway={gateway({ tasks: vi.fn().mockResolvedValue([task]) })} />);
  await screen.findByRole('button', { name: memory.title });

  fireEvent.click(screen.getByRole('button', { name: 'Tasks' }));

  await screen.findByRole('heading', { name: 'Tasks could not be displayed' });
  expect(screen.getByRole('navigation', { name: 'Workspace' })).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Projects' }));
  expect(await screen.findByLabelText('Project name')).toBeInTheDocument();
});

it('preserves a healthy child when the navigation reset key changes', () => {
  const { rerender } = render(<ErrorBoundary label="Harnesses" resetKey="harnesses:project-a">
    <input aria-label="Harness draft" defaultValue="" />
  </ErrorBoundary>);
  fireEvent.change(screen.getByLabelText('Harness draft'), { target: { value: 'Unsaved text' } });

  rerender(<ErrorBoundary label="Harnesses" resetKey="home:project-a">
    <input aria-label="Harness draft" defaultValue="" />
  </ErrorBoundary>);

  expect(screen.getByLabelText('Harness draft')).toHaveValue('Unsaved text');
});

it('does not expose a component stack or file path to the user', async () => {
  render(<App gateway={gateway({ memories: vi.fn().mockResolvedValue(crashingMemories) })} />);
  await screen.findByRole('heading', { name: 'Dashboard could not be displayed' });

  const alert = screen.getByRole('alert');
  expect(alert.textContent).not.toMatch(/at \w+ \(|src\/|\.tsx?:/);
  expect(alert).toHaveTextContent('Your saved context and tasks are unchanged.');
});
