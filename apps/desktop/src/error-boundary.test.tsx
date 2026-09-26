import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';

import App from './App';
import type { WorkspaceGateway } from './workspace';
import { fixtureMemory, fixtureProject, fixtureTask } from './test-fixtures';
import { defaultPreferences } from './desktop-preferences';

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  localStorage.setItem('context-relay.desktop-preferences.v1', JSON.stringify({
    ...defaultPreferences(),
    setup: { ...defaultPreferences().setup, status: 'complete' },
  }));
});

const project = fixtureProject();
const memory = fixtureMemory({ title: 'Use plain language' });

/** A record whose clock is not a decimal u64, which crashes the dashboard sort. */
const broken = { ...memory, updatedHlc: { ...memory.updatedHlc, physicalMs: 'not-a-number' } };

function gateway(overrides: Partial<Record<keyof WorkspaceGateway, unknown>> = {}) {
  return {
    status: vi.fn().mockResolvedValue({ vault: 'unlocked' }),
    projects: vi.fn().mockResolvedValue([project]),
    memories: vi.fn().mockResolvedValue([broken]),
    searchMemories: vi.fn().mockResolvedValue([broken]),
    tasks: vi.fn().mockResolvedValue([fixtureTask()]),
    candidates: vi.fn().mockResolvedValue([]),
    ...overrides,
  } as unknown as WorkspaceGateway;
}

it('keeps navigation alive when a screen fails to render', async () => {
  const consoleError = vi.spyOn(console, 'error').mockImplementation(() => undefined);
  // A record with no physicalMs makes the dashboard's BigInt sort throw while
  // rendering, which is the failure mode the boundary has to contain.
  const failing = gateway({
    memories: vi.fn().mockResolvedValue([{ ...memory, updatedHlc: { physicalMs: undefined } } as never]),
  });
  render(<App gateway={failing} />);

  const alert = await screen.findByRole('alert');
  expect(alert).toHaveTextContent('could not be displayed');
  // The sidebar and project switcher must survive so the user can navigate away.
  expect(screen.getByRole('navigation', { name: 'Workspace' })).toBeInTheDocument();
  expect(screen.getByLabelText('Current project')).toBeInTheDocument();
  consoleError.mockRestore();
});

it('reports the failing screen by name rather than a blank window', async () => {
  const consoleError = vi.spyOn(console, 'error').mockImplementation(() => undefined);
  const failing = gateway({ tasks: vi.fn().mockRejectedValue(new Error('boom')) });
  render(<App gateway={failing} />);
  await screen.findByRole('button', { name: 'Tasks' });
  consoleError.mockRestore();
});

it('does not expose a component stack or file path to the user', async () => {
  const consoleError = vi.spyOn(console, 'error').mockImplementation(() => undefined);
  const failing = gateway({ memories: vi.fn().mockResolvedValue([{ ...memory, updatedHlc: { physicalMs: undefined } } as never]) });
  render(<App gateway={failing} />);
  const alert = await screen.findByRole('alert');
  expect(alert.textContent).not.toMatch(/at \w+ \(|src\/|\.tsx?:/);
  expect(alert).toHaveTextContent('Your saved context and tasks are unchanged.');
  consoleError.mockRestore();
});
