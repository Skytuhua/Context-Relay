import { readFileSync } from 'node:fs';

import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import App from './App';
import { PROTOCOL_VERSION } from './bindings';
import type { WorkspaceGateway } from './workspace';

const destinations = [
  'Home',
  'Projects',
  'Memory',
  'Review queue',
  'Tasks',
  'Harnesses',
  'Packages',
  'Activity',
  'Devices',
  'Settings',
] as const;

const gateway = {
  status: async () => ({
    protocol: { min: { major: 1, minor: 4 }, max: { major: 1, minor: 4 } },
    vault: 'unlocked',
    resolvedProject: null,
    sync: 'offline',
    access: { mode: 'default' },
  }),
  projects: async () => [],
  devices: async () => [],
  recoveryEnrollmentOverview: async () => ({
    enrollmentId: null,
    state: 'idle',
    createdAtMs: null,
    transitionedAtMs: null,
  }),
  memories: async () => [],
  candidates: async () => [],
  tasks: async () => [],
} as unknown as WorkspaceGateway;

describe('App', () => {
  beforeEach(() => {
    HTMLDialogElement.prototype.showModal = function showModal() {
      this.setAttribute('open', '');
    };
    HTMLDialogElement.prototype.close = function close() {
      this.removeAttribute('open');
      this.dispatchEvent(new Event('close'));
    };
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it('uses the current protocol range in its status fixture', async () => {
    const status = await gateway.status();
    expect(status.protocol).toEqual({ min: PROTOCOL_VERSION, max: PROTOCOL_VERSION });
  });

  it('exposes every keyboard-reachable workspace destination and focuses selected headings', async () => {
    render(<App gateway={gateway} />);
    expect(await screen.findByText('Offline')).toBeVisible();
    const navigation = screen.getByRole('navigation', { name: 'Workspace' });
    expect(within(navigation).getAllByRole('button').map((button) => button.textContent)).toEqual(
      destinations,
    );
    expect(screen.getByRole('link', { name: 'Skip to workspace' })).toHaveAttribute(
      'href',
      '#workspace-main',
    );

    for (const destination of destinations.slice(1)) {
      fireEvent.click(screen.getByRole('button', { name: destination }));
      const heading = screen.getByRole('heading', { level: 1, name: destination });
      expect(heading).toHaveFocus();
      expect(screen.getByRole('button', { name: destination })).toHaveAttribute(
        'aria-current',
        'page',
      );
    }
  });

  it('reports associated validation errors without echoing submitted plaintext', async () => {
    render(<App gateway={gateway} />);
    await screen.findByText('Offline');
    fireEvent.click(screen.getByRole('button', { name: 'Memory' }));
    const form = await screen.findByRole('form', { name: 'New memory' });
    fireEvent.submit(form);
    expect(form).toHaveAttribute('aria-describedby', 'workspace-error');
    expect(screen.getByRole('alert')).toHaveTextContent('Enter a title.');
    expect(screen.getByRole('alert')).not.toHaveTextContent('Memory');
  });

  it('keeps all workspace persistence behind the typed client', () => {
    for (const file of ['App.tsx', 'devices.tsx', 'workspace.ts', 'local-client.ts']) {
      const source = readFileSync(new URL(file, import.meta.url), 'utf8');
      expect(source).not.toMatch(
        /localStorage|sessionStorage|indexedDB|navigator\.clipboard|createObjectURL|\bdownload\b/,
      );
    }
  });

  it('restores the security dialog trigger focus after close', async () => {
    render(<App gateway={gateway} />);
    await screen.findByText('Offline');
    fireEvent.click(screen.getByRole('button', { name: 'Settings' }));
    const trigger = screen.getByRole('button', { name: 'Security details' });
    fireEvent.click(trigger);
    fireEvent.click(screen.getByRole('button', { name: 'Close security details' }));
    expect(trigger).toHaveFocus();
  });
});
