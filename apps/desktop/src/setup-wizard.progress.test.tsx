import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';

import { SetupWizard } from './setup-wizard';
import { defaultPreferences } from './desktop-preferences';
import type { WorkspaceGateway } from './workspace';
import { fixtureProject } from './test-fixtures';

const project = fixtureProject();

const gateway = {
  harnessSetups: vi.fn().mockResolvedValue([]),
  harnessProbe: vi.fn().mockResolvedValue({ capability: 'full', installationMethod: 'bundled', configRoots: [], policyConflicts: [] }),
  status: vi.fn().mockResolvedValue({ vault: 'unlocked' }),
} as unknown as WorkspaceGateway;

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

function renderWizard(step: 'harnesses' | 'project' | 'connect' | 'test' | 'tour', overrides: Partial<ReturnType<typeof defaultPreferences>['setup']> = {}) {
  const preferences = defaultPreferences();
  const progress = { ...preferences.setup, status: 'in_progress' as const, step, ...overrides };
  return render(<SetupWizard
    gateway={gateway}
    projects={[project]}
    progress={progress}
    onChange={() => undefined}
    onProjectSaved={() => undefined}
    onFinishLater={() => undefined}
    onOpenGuide={() => undefined}
    onTour={() => undefined}
    renderConnection={() => <div>connection</div>}
    renderTest={() => <div>test</div>}
  />);
}

it('states why Continue is unavailable instead of showing a dead button', async () => {
  renderWizard('harnesses');
  expect(screen.getByRole('button', { name: 'Continue' })).toBeDisabled();
  expect(screen.getByText('Choose at least one harness to continue.')).toBeInTheDocument();
});

it('gives the test step an explanation the user can act on', () => {
  renderWizard('test');
  expect(screen.getByText(/Open the harness, send the test prompt, then return here\./)).toBeInTheDocument();
});

it('shows no reason once Continue is available', () => {
  renderWizard('harnesses', { harnesses: ['codex'] });
  expect(screen.getByRole('button', { name: 'Continue' })).toBeEnabled();
  expect(screen.queryByText('Choose at least one harness to continue.')).not.toBeInTheDocument();
});

it('marks finished steps in the setup rail so a returning user can see their progress', () => {
  renderWizard('connect', { harnesses: ['codex'], projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c075001' });
  const rail = screen.getByRole('list', { name: 'Setup progress' });
  const items = rail.querySelectorAll('li');
  expect(items).toHaveLength(5);
  // The first two steps precede the current one, so they are complete.
  expect(items[0]).toHaveAttribute('data-complete', 'true');
  expect(items[1]).toHaveAttribute('data-complete', 'true');
  expect(items[2]).toHaveAttribute('aria-current', 'step');
  expect(items[2]).toHaveAttribute('data-complete', 'false');
  expect(items[4]).toHaveAttribute('data-complete', 'false');
});

it('announces the completed state to assistive technology, not by colour alone', () => {
  renderWizard('connect', { harnesses: ['codex'] });
  const rail = screen.getByRole('list', { name: 'Setup progress' });
  expect(rail.querySelectorAll('li')[0]).toHaveTextContent('(done)');
});

it('does not mark a not-yet-connected harness with the primary action wording', () => {
  renderWizard('connect', { harnesses: ['codex'], projectId: project.projectId });
  expect(screen.getByText('Not connected yet')).toBeInTheDocument();
  expect(screen.queryByText('Review setup')).not.toBeInTheDocument();
});
