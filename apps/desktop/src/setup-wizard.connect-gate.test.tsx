import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';

import { SetupWizard } from './setup-wizard';
import { defaultPreferences } from './desktop-preferences';
import type { HarnessSetupSummary } from './bindings';
import type { WorkspaceGateway } from './workspace';
import { fixtureProject } from './test-fixtures';

const project = fixtureProject();
const planId = '018f22e2-79b0-7cc8-98c4-dc0c0c075010';

// The history read returns summaries, not full records.
function setupRecord(state: HarnessSetupSummary['state']): HarnessSetupSummary {
  return {
    planId,
    harness: 'codex',
    harnessProfile: null,
    targetScopes: [{ scope: 'project', projectId: project.projectId }],
    state,
    createdAt: '1758000000000',
    expiresAt: '1758003600000',
  } as unknown as HarnessSetupSummary;
}

function renderWizard(states: HarnessSetupSummary['state'][], step: 'project' | 'connect' = 'connect') {
  // projectHarnessSetups pages through harnessSetupsList.
  const harnessSetupsList = vi.fn().mockResolvedValue({ setups: states.map(setupRecord), nextAfter: null });
  const gateway = {
    harnessSetupsList,
    harnessProbe: vi.fn().mockResolvedValue({ capability: 'full', installationMethod: 'bundled', configRoots: [], policyConflicts: [] }),
    status: vi.fn().mockResolvedValue({ vault: 'unlocked' }),
  } as unknown as WorkspaceGateway;
  const preferences = defaultPreferences();
  const progress = {
    ...preferences.setup,
    status: 'in_progress' as const,
    step,
    harnesses: ['codex' as const],
    projectId: project.projectId,
  };
  const onChange = vi.fn();
  render(<SetupWizard
    gateway={gateway}
    projects={[project]}
    progress={progress}
    onChange={onChange}
    onProjectSaved={() => undefined}
    onFinishLater={() => undefined}
    onOpenGuide={() => undefined}
    onTour={() => undefined}
    renderConnection={() => <div>connection</div>}
    renderTest={() => <div>test</div>}
  />);
  return { onChange };
}

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

it('holds Continue on the connect step until a harness has saved settings', async () => {
  renderWizard([]);
  // The gate must not open just because a harness was selected.
  await waitFor(() => expect(screen.getByRole('button', { name: 'Continue' })).toBeDisabled());
});

it('allows the connect step to advance once a selected harness is saved', async () => {
  renderWizard(['applied']);
  await waitFor(() => expect(screen.getByRole('button', { name: 'Continue' })).toBeEnabled());
});

it('does not treat an unrelated saved harness as progress for this selection', async () => {
  // A record for a harness the user did not select must not unlock the step.
  const record = setupRecord('applied');
  const other = { ...record, harness: 'hermes' as const, harnessProfile: 'default' } as HarnessSetupSummary;
  const harnessSetupsList = vi.fn().mockResolvedValue({ setups: [other], nextAfter: null });
  const gateway = {
    harnessSetupsList,
    harnessProbe: vi.fn().mockResolvedValue({ capability: 'full', installationMethod: 'bundled', configRoots: [], policyConflicts: [] }),
  } as unknown as WorkspaceGateway;
  const preferences = defaultPreferences();
  render(<SetupWizard
    gateway={gateway}
    projects={[project]}
    progress={{ ...preferences.setup, status: 'in_progress', step: 'connect', harnesses: ['codex'], projectId: project.projectId }}
    onChange={() => undefined}
    onProjectSaved={() => undefined}
    onFinishLater={() => undefined}
    onOpenGuide={() => undefined}
    onTour={() => undefined}
    renderConnection={() => <div>connection</div>}
    renderTest={() => <div>test</div>}
  />);
  await waitFor(() => expect(screen.getByRole('button', { name: 'Continue' })).toBeDisabled());
});

it('treats a rolled back setup as not connected', async () => {
  renderWizard(['rolled_back']);
  await waitFor(() => expect(screen.getByRole('button', { name: 'Continue' })).toBeDisabled());
});

it('still allows the project step to advance on a chosen folder alone', async () => {
  renderWizard([], 'project');
  await waitFor(() => expect(screen.getByRole('button', { name: 'Continue' })).toBeEnabled());
});
