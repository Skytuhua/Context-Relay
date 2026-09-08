import { readFileSync } from 'node:fs';
import { useState } from 'react';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { DecimalU64, HarnessExecutionParams, HarnessExecutionStatus, HarnessSetupRecord, ProbeReport, ProjectIdentity, SetupPlan } from './bindings';
import { defaultPreferences, type SetupProgress } from './desktop-preferences';
import { HarnessesScreen } from './harnesses';
import { SetupWizard } from './setup-wizard';
import type { WorkspaceGateway } from './workspace';

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn(async () => undefined) }));
const project = { projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c075001', name: 'Onboarding project', githubRepositoryId: null, gitRemoteFingerprint: null, monorepoSubdirectory: null } as ProjectIdentity;

beforeEach(() => {
  vi.spyOn(navigator, 'userAgent', 'get').mockReturnValue('Mozilla/5.0 (Windows NT 10.0; Win64; x64)');
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

function fixture() {
  const source = JSON.parse(readFileSync('../../crates/protocol/tests/fixtures/runtime-contracts-v1.json', 'utf8')).setupPlan as SetupPlan;
  const plan: SetupPlan = { ...source, harness: 'codex', harnessProfile: null,
    expiresAt: String(Date.now() + 60_000) as DecimalU64,
    targetScopes: [{ scope: 'project', projectId: project.projectId, root: source.executablePath }],
  };
  const report: ProbeReport = { executable: plan.executablePath, executableSha256: plan.executableHash,
    harnessVersion: plan.harnessVersion, installationMethod: 'manual', configRoots: [],
    activeProfile: null, codexSavedHookApproval: null, policyConflicts: [], capability: 'full',
  };
  let current: HarnessExecutionStatus | null = null;
  const record: HarnessSetupRecord = { plan, state: 'previewed', createdAt: '1900000000000' };
  const api = {
    harnessExecutionCurrent: vi.fn<() => Promise<HarnessExecutionStatus | null>>(async () => current),
    harnessExecutionStatus: vi.fn(async (key: HarnessExecutionParams): Promise<HarnessExecutionStatus> => current ?? { ...key, phase: 'unknown', error: null }),
    harnessExecutionStart: vi.fn(async (key: HarnessExecutionParams): Promise<HarnessExecutionStatus> => {
      current = { ...key, phase: 'finished', error: null };
      record.state = key.action === 'apply' ? 'applied' : 'rolled_back';
      return current;
    }),
    harnessSetupGet: vi.fn(async () => record),
    harnessSetupsList: vi.fn(async () => ({ setups: [], nextAfter: null })),
    harnessProbe: vi.fn(async () => report),
    harnessPreview: vi.fn(async () => plan),
    createMemory: vi.fn(), createProject: vi.fn(), harnessApply: vi.fn(),
  };
  const onFinishLater = vi.fn();
  const gateway = api as unknown as WorkspaceGateway;
  function Host() {
    const [progress, setProgress] = useState<SetupProgress>({ ...defaultPreferences().setup,
      status: 'in_progress', step: 'connect', projectId: project.projectId, harnesses: ['codex', 'claude_code'],
    });
    const [operationBusy, setBusy] = useState(false);
    return <SetupWizard gateway={gateway} projects={[project]} progress={progress} onChange={setProgress}
      onProjectSaved={vi.fn()} onFinishLater={onFinishLater} onTour={vi.fn()} onOpenGuide={vi.fn()}
      operationBusy={operationBusy}
      renderConnection={(selected, harness) => <HarnessesScreen gateway={gateway} projects={[project]}
        preferredProjectId={selected.projectId} preferredHarness={harness} embedded onBusy={setBusy} />}
      renderTest={() => <section aria-label="Read-note step">Save a note and verify its read.</section>} />;
  }
  return { api, gateway, plan, report, record, Host, onFinishLater,
    setCurrent: (value: HarnessExecutionStatus | null) => { current = value; } };
}

async function reviewAndApprove() {
  const review = screen.getByRole('button', { name: 'Review setup' });
  await waitFor(() => expect(review).toBeEnabled());
  fireEvent.click(review);
  await screen.findByRole('heading', { name: 'Review setup changes' });
  expect(review).toHaveClass('secondary-action');
  expect(screen.getByRole('button', { name: 'Save settings' })).toHaveClass('primary-action');
  expect(screen.getByRole('button', { name: 'Save settings' })).toBeDisabled();
  expect(screen.queryByRole('region', { name: 'Open harness for project' })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('checkbox', { name: /I reviewed and approve/ }));
  fireEvent.click(screen.getByRole('button', { name: 'Save settings' }));
}

it('allows Finish later during an unresolved read but keeps settings changes blocked', async () => {
  const f = fixture();
  f.api.harnessExecutionCurrent.mockImplementation(() => new Promise<HarnessExecutionStatus | null>(() => {}));
  render(<f.Host />);
  expect(screen.getByRole('button', { name: 'Review setup' })).toBeDisabled();
  expect(screen.queryByRole('region', { name: 'Open harness for project' })).not.toBeInTheDocument();
  await waitFor(() => expect(screen.getByRole('button', { name: 'Finish later' })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: 'Finish later' }));
  expect(f.onFinishLater).toHaveBeenCalledTimes(1);
  expect(f.api.harnessExecutionStart).not.toHaveBeenCalled();
  expect(f.api.harnessPreview).not.toHaveBeenCalled();
});

it('does not trap the user after failed initial discovery', async () => {
  const f = fixture();
  f.api.harnessExecutionCurrent.mockRejectedValue(new Error('PRIVATE service detail'));
  render(<f.Host />);
  await screen.findByText(/Could not load setup progress/);
  expect(screen.getByRole('button', { name: 'Review setup' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Finish later' })).toBeEnabled();
  expect(screen.queryByText(/PRIVATE/)).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Finish later' }));
  expect(f.onFinishLater).toHaveBeenCalledTimes(1);
  expect(f.api.harnessExecutionStart).not.toHaveBeenCalled();
});

it('keeps navigation locked for an accepted running save without showing launch instructions', async () => {
  const f = fixture();
  f.api.harnessExecutionStart.mockImplementation(async key => {
    const status: HarnessExecutionStatus = { ...key, phase: 'running', error: null };
    f.setCurrent(status);
    return status;
  });
  render(<f.Host />);
  await reviewAndApprove();
  await screen.findByText('Saving harness settings…');
  expect(screen.getByRole('button', { name: 'Finish later' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Continue' })).toBeDisabled();
  expect(screen.queryByRole('region', { name: 'Open harness for project' })).not.toBeInTheDocument();
  expect(f.api.harnessExecutionStart).toHaveBeenCalledTimes(1);
});

it('separates review, acknowledged save, and the note test without claiming a verified read', async () => {
  const f = fixture();
  render(<f.Host />);
  await reviewAndApprove();
  await screen.findByRole('heading', { name: 'Test saved context next' });
  expect(screen.getByRole('button', { name: 'Review setup' })).toHaveClass('secondary-action');
  expect(screen.queryByRole('region', { name: 'Open harness for project' })).not.toBeInTheDocument();
  expect(screen.getByText('Settings are saved, but the connection has not been verified yet.')).toBeVisible();
  const approvals = screen.getByText('Automatic context and harness approvals').closest('details');
  expect(approvals).not.toHaveAttribute('open');
  fireEvent.click(screen.getByText('Automatic context and harness approvals'));
  // The separate approval instructions remain available, including exact commands.
  expect(within(approvals!).getByText('/hooks')).toBeInTheDocument();
  expect(f.api.createMemory).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
  expect(screen.getByRole('region', { name: 'Read-note step' })).toBeVisible();
  expect(f.api.harnessExecutionStart).toHaveBeenCalledTimes(1);
});

it('offers a project-trust launch only after discovery confirms that it is needed', async () => {
  const f = fixture();
  f.api.harnessProbe.mockResolvedValue({ ...f.report, capability: 'blocked', policyConflicts: ['project_untrusted'] });
  render(<f.Host />);
  expect(screen.queryByRole('button', { name: 'Open Codex for this project' })).not.toBeInTheDocument();
  const review = screen.getByRole('button', { name: 'Review setup' });
  await waitFor(() => expect(review).toBeEnabled());
  fireEvent.click(review);
  expect(await screen.findByRole('button', { name: 'Open Codex for this project' })).toBeEnabled();
  expect(screen.getByText(/Codex needs your approval for this project folder/)).toBeVisible();
  expect(f.api.harnessPreview).not.toHaveBeenCalled();
  expect(f.api.harnessExecutionStart).not.toHaveBeenCalled();
});

it.each(['missing', 'import_only'] as const)('does not offer a launch as the next action for an unavailable %s connection', async capability => {
  const f = fixture();
  f.api.harnessProbe.mockResolvedValue({ ...f.report, capability });
  render(<f.Host />);
  const review = screen.getByRole('button', { name: 'Review setup' });
  await waitFor(() => expect(review).toBeEnabled());
  fireEvent.click(review);
  await screen.findByRole('region', { name: 'Harness availability' });
  expect(screen.queryByRole('region', { name: 'Open harness for project' })).not.toBeInTheDocument();
  expect(f.api.harnessExecutionStart).not.toHaveBeenCalled();
});

it('does not present an old harness result as the next step for a newly selected harness', async () => {
  const f = fixture();
  render(<f.Host />);
  await reviewAndApprove();
  await screen.findByRole('heading', { name: 'Test saved context next' });
  fireEvent.click(screen.getByRole('button', { name: /Claude Code/ }));
  await screen.findByRole('heading', { name: 'Connect Claude Code' });
  expect(screen.queryByRole('region', { name: 'Setup result' })).not.toBeInTheDocument();
  expect(screen.queryByRole('heading', { name: 'Test saved context next' })).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Review setup' })).toHaveClass('primary-action');
});
