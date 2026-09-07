import { act, cleanup, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { SetupWizard } from './setup-wizard';
import { defaultPreferences, type SetupProgress } from './desktop-preferences';
import type { HarnessSetupSummary, HarnessSetupsPage, PlanId, ProjectIdentity } from './bindings';
import type { WorkspaceGateway } from './workspace';

const projectA = { projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c073980', name: 'Project A' } as ProjectIdentity;
const projectB = { ...projectA, projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c073981', name: 'Project B' } as ProjectIdentity;
const cursor = '018f22e2-79b0-7cc8-98c4-dc0c0c073982' as PlanId;
const saved = { planId: '018f22e2-79b0-7cc8-98c4-dc0c0c073983', harness: 'codex', harnessProfile: null, targetScopes: [{ scope: 'project', projectId: projectA.projectId }], state: 'applied', createdAt: '1', expiresAt: '2' } as HarnessSetupSummary;
const progress: SetupProgress = { ...defaultPreferences().setup, status: 'in_progress', step: 'connect', projectId: projectA.projectId, harnesses: ['codex'] };
const props = { projects: [projectA, projectB], progress, onChange: vi.fn(), onProjectSaved: vi.fn(), onFinishLater: vi.fn(), onTour: vi.fn(), onOpenGuide: vi.fn(), renderConnection: () => <p>Connection controls</p>, renderTest: () => <p>Read test</p> };

afterEach(cleanup);

it('shows settings saved when the matching setup follows an empty history page', async () => {
  const harnessSetupsList = vi.fn<() => Promise<HarnessSetupsPage>>()
    .mockResolvedValueOnce({ setups: [], nextAfter: cursor })
    .mockResolvedValueOnce({ setups: [saved], nextAfter: null });
  render(<SetupWizard {...props} gateway={{ harnessSetupsList } as unknown as WorkspaceGateway} />);
  expect(await screen.findByRole('button', { name: 'Codex Settings saved · test next' })).toBeVisible();
  expect(harnessSetupsList.mock.calls).toEqual([[null], [cursor]]);
});

it.each(['rolled_back', 'conflict'] as const)('does not hide a later %s behind an older applied setup', async state => {
  const harnessSetupsList = vi.fn<() => Promise<HarnessSetupsPage>>()
    .mockResolvedValueOnce({ setups: [{ ...saved, planId: cursor }], nextAfter: cursor })
    .mockResolvedValueOnce({ setups: [{ ...saved, state }], nextAfter: null });
  render(<SetupWizard {...props} gateway={{ harnessSetupsList } as unknown as WorkspaceGateway} />);
  const label = state === 'rolled_back' ? 'Setup undone' : 'Needs review';
  expect(await screen.findByRole('button', { name: `Codex ${label}` })).toBeVisible();
  expect(screen.queryByText('Settings saved · test next')).not.toBeInTheDocument();
});

it('cancels old pagination and cannot overwrite the state of a newly selected project', async () => {
  let finishA!: (page: HarnessSetupsPage) => void;
  const harnessSetupsList = vi.fn<() => Promise<HarnessSetupsPage>>()
    .mockImplementationOnce(() => new Promise(resolve => { finishA = resolve; }))
    .mockResolvedValueOnce({ setups: [{ ...saved, state: 'rolled_back', targetScopes: [{ scope: 'project', projectId: projectB.projectId }] }], nextAfter: null });
  const gateway = { harnessSetupsList } as unknown as WorkspaceGateway;
  const view = render(<SetupWizard {...props} gateway={gateway} />);
  await waitFor(() => expect(harnessSetupsList).toHaveBeenCalledTimes(1));
  view.rerender(<SetupWizard {...props} gateway={gateway} progress={{ ...progress, projectId: projectB.projectId }} />);
  await screen.findByRole('button', { name: 'Codex Setup undone' });
  await act(async () => { finishA({ setups: [saved], nextAfter: cursor }); });
  expect(screen.getByRole('button', { name: 'Codex Setup undone' })).toBeVisible();
  expect(harnessSetupsList).toHaveBeenCalledTimes(2);
});
