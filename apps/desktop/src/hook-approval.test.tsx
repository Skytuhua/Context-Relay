import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { HarnessesScreen } from './harnesses';
import type { HarnessGateway } from './harness-gateway';
import type { ProbeReport, ProjectIdentity } from './bindings';
import { validateHarnessProbe } from './harness-gateway';

afterEach(cleanup);

const project = { projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c075001', name: 'Research',
  githubRepositoryId: null, gitRemoteFingerprint: null, monorepoSubdirectory: null } as ProjectIdentity;

it.each([
  ['missing', 'Not saved'], ['needs_approval', 'Needs your approval'], ['approved', 'Approval saved'],
  ['changed', 'Changed — review again'], ['disabled', 'Disabled in saved settings'],
])('shows %s as saved settings evidence, without claiming connection', async (state, label) => {
  const report = { executable: null, executableSha256: null, harnessVersion: '0.144.6',
    installationMethod: 'manual', configRoots: [], activeProfile: null, policyConflicts: [], capability: 'import_only',
    codexSavedHookApproval: { sessionStart: state, stop: state } } as ProbeReport;
  const gateway: HarnessGateway = { harnessProbe: vi.fn().mockResolvedValue(report),
    harnessPrepare: vi.fn(), harnessPreparationStatus: vi.fn(), harnessPreparationCancel: vi.fn(), harnessPreparedPreview: vi.fn(),
    harnessExecutionStart: vi.fn(), harnessExecutionStatus: vi.fn(), harnessExecutionCurrent: vi.fn().mockResolvedValue(null),
    harnessSetupGet: vi.fn(), harnessSetupsList: vi.fn().mockResolvedValue({ setups: [], nextAfter: null }),
    harnessPreview: vi.fn(), harnessApply: vi.fn(), harnessRollback: vi.fn() };
  render(<HarnessesScreen gateway={gateway} projects={[project]} />);
  await waitFor(() => expect(screen.getByRole('button', { name: 'Review setup' })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: 'Review setup' }));
  const status = await screen.findByRole('region', { name: 'Saved Codex hook approvals' });
  expect(within(status).getAllByText(label)).toHaveLength(2);
  expect(within(status).getByText(/do not confirm that hooks are enabled or that context is being shared/)).toBeVisible();
  expect(gateway.harnessPreview).not.toHaveBeenCalled();
  expect(gateway.harnessApply).not.toHaveBeenCalled();
  expect(screen.queryByText('Connected')).not.toBeInTheDocument();
});

it('rejects malformed approval evidence and evidence for another harness or version', () => {
  const report = { executable: null, executableSha256: null, harnessVersion: '0.144.6',
    installationMethod: 'manual', configRoots: [], activeProfile: null, policyConflicts: [], capability: 'import_only',
    codexSavedHookApproval: { sessionStart: 'approved', stop: 'approved' } };
  const params = { harness: 'codex' as const, projectId: project.projectId, hermesProfile: null };
  expect(() => validateHarnessProbe(report, params)).not.toThrow();
  for (const approval of [
    { sessionStart: 'connected', stop: 'approved' },
    { sessionStart: 'approved' },
    { sessionStart: 'approved', stop: 'approved', connected: true },
  ]) expect(() => validateHarnessProbe({ ...report, codexSavedHookApproval: approval }, params)).toThrow();
  expect(() => validateHarnessProbe(report, { ...params, harness: 'claude_code' })).toThrow();
  expect(() => validateHarnessProbe({ ...report, harnessVersion: '0.144.7' }, params)).toThrow();
  expect(() => validateHarnessProbe({ ...report, codexSavedHookApproval: null }, params)).not.toThrow();
});
