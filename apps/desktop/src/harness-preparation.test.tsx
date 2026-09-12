import { readFileSync } from 'node:fs';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { HarnessesScreen } from './harnesses';
import type { HarnessGateway } from './harness-gateway';
import type { HarnessPreparationStatus, HarnessPrepareParams, ProbeReport, ProjectIdentity, SetupPlan } from './bindings';

const project = { projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c075001', name: 'Research', githubRepositoryId: null, gitRemoteFingerprint: null, monorepoSubdirectory: null } as ProjectIdentity;
let gateway: HarnessGateway;
let progress: HarnessPreparationStatus;
let plan: SetupPlan;
beforeEach(() => {
  localStorage.clear();
  plan = JSON.parse(readFileSync('../../crates/protocol/tests/fixtures/runtime-contracts-v1.json', 'utf8')).setupPlan;
  plan = { ...plan, harness: 'hermes', harnessProfile: 'default', rulesyncVersion: 'bridge-preview-v1', expiresAt: String(Date.now() + 60000) as SetupPlan['expiresAt'], targetScopes: [{ scope: 'project', projectId: project.projectId, root: plan.executablePath }] };
  gateway = {
    harnessExecutionCurrent: vi.fn().mockResolvedValue(null), harnessSetupsList: vi.fn().mockResolvedValue({ setups: [], nextAfter: null }),
    harnessExecutionStart: vi.fn(), harnessExecutionStatus: vi.fn(), harnessSetupGet: vi.fn(), harnessApply: vi.fn(), harnessRollback: vi.fn(),
    harnessProbe: vi.fn().mockResolvedValue({ executable: plan.executablePath, executableSha256: plan.executableHash, harnessVersion: '0.17.0', installationMethod: 'manual', activeProfile: 'default', codexSavedHookApproval: null, configRoots: [], capability: 'import_only', policyConflicts: ['python_runtime_preparation_required'] } satisfies ProbeReport),
    harnessPreview: vi.fn(),
    harnessPrepare: vi.fn(async (params: HarnessPrepareParams) => { progress = { ...params, phase: 'copying', completedFiles: 42, completedBytes: 4096, error: null }; return progress; }),
    harnessPreparationStatus: vi.fn(async () => progress),
    harnessPreparationCancel: vi.fn(async () => { progress = { ...progress, phase: 'cancelling' }; return progress; }),
    harnessPreparedPreview: vi.fn().mockResolvedValue(plan),
  };
});
afterEach(() => { cleanup(); localStorage.clear(); vi.useRealTimers(); vi.restoreAllMocks(); });
async function open() {
  const view = render(<HarnessesScreen gateway={gateway} projects={[project]} />);
  await waitFor(() => expect(screen.getByRole('button', { name: 'Review setup' })).toBeEnabled());
  fireEvent.change(screen.getByRole('combobox', { name: 'Harness' }), { target: { value: 'hermes' } });
  fireEvent.click(screen.getByRole('button', { name: 'Review setup' }));
  await screen.findByRole('button', { name: 'Prepare setup' });
  return view;
}
async function start() {
  vi.useFakeTimers();
  await act(async () => fireEvent.click(screen.getByRole('button', { name: 'Prepare setup' })));
}
async function advance(phase: HarnessPreparationStatus['phase']) {
  progress = { ...progress, phase };
  await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
}

it('shows preparation progress and requires a separate review before settings approval', async () => {
  await open(); await start();
  expect(screen.getByText('Copying the Hermes runtime…')).toBeVisible();
  expect(screen.getByText(/42 files/)).toBeVisible();
  expect(screen.getByRole('button', { name: 'Cancel preparation' })).toBeEnabled();
  expect(gateway.harnessPreview).not.toHaveBeenCalled();
  await advance('checking_copy');
  expect(screen.getByText('Checking the prepared copy…')).toBeVisible();
  await advance('ready');
  expect(gateway.harnessPreparedPreview).not.toHaveBeenCalled();
  await act(async () => fireEvent.click(screen.getByRole('button', { name: 'Review prepared setup' })));
  expect(screen.getByRole('heading', { name: 'Review setup changes' })).toBeVisible();
  expect(screen.getByRole('button', { name: 'Save settings' })).toBeDisabled();
  expect(gateway.harnessPreparedPreview).toHaveBeenCalledExactlyOnceWith({ operationId: progress.operationId, selection: progress.selection });
  expect(gateway.harnessExecutionStart).not.toHaveBeenCalled();
});

it('keeps cancellation pending until confirmed and does not mistake a Ready race for canceled', async () => {
  await open(); await start();
  await act(async () => fireEvent.click(screen.getByRole('button', { name: 'Cancel preparation' })));
  expect(screen.getByText('Canceling preparation…')).toBeVisible();
  expect(screen.queryByText('Preparation canceled.')).not.toBeInTheDocument();
  await advance('ready');
  expect(screen.getByRole('button', { name: 'Review prepared setup' })).toBeEnabled();
  expect(screen.queryByText('Preparation canceled.')).not.toBeInTheDocument();
  expect(gateway.harnessPreparedPreview).not.toHaveBeenCalled();
});

it('keeps progress and cancellation available while the start acknowledgement is delayed', async () => {
  let acknowledge!: (value: HarnessPreparationStatus) => void;
  vi.mocked(gateway.harnessPrepare).mockImplementation(async params => {
    progress = { ...params, phase: 'copying', completedFiles: 10, completedBytes: 4096, error: null };
    return new Promise(resolve => { acknowledge = resolve; });
  });
  await open(); await start();
  await advance('copying');
  expect(screen.getByText('Copying the Hermes runtime…')).toBeVisible();
  expect(screen.getByRole('button', { name: 'Cancel preparation' })).toBeEnabled();
  await act(async () => fireEvent.click(screen.getByRole('button', { name: 'Cancel preparation' })));
  expect(gateway.harnessPreparationCancel).toHaveBeenCalledTimes(1);
  await advance('canceled');
  await act(async () => acknowledge(progress));
  expect(screen.getByText('Preparation canceled.')).toBeVisible();
  expect(gateway.harnessPrepare).toHaveBeenCalledTimes(1);
});

it('recovers the same preparation identity after remount without copying again', async () => {
  const view = await open(); await start();
  const original = { operationId: progress.operationId, selection: progress.selection };
  view.unmount();
  render(<HarnessesScreen gateway={gateway} projects={[project]} />);
  await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
  expect(screen.getByText('Copying the Hermes runtime…')).toBeVisible();
  expect(gateway.harnessPrepare).toHaveBeenCalledTimes(1);
  expect(gateway.harnessPreparationStatus).toHaveBeenLastCalledWith(original);
  await advance('canceled');
  expect(screen.getByText('Preparation canceled.')).toBeVisible();
  expect(gateway.harnessPreparedPreview).not.toHaveBeenCalled();
});

it('retains a missing operation after service restart for explicit same-ID retry', async () => {
  const view = await open(); await start(); view.unmount();
  vi.mocked(gateway.harnessPreparationStatus).mockRejectedValue({ code: 'not_found', message: 'PRIVATE PATH' });
  render(<HarnessesScreen gateway={gateway} projects={[project]} />);
  await act(async () => { await vi.advanceTimersByTimeAsync(40_000); });
  expect(screen.getByText(/Preparation is unconfirmed/)).toBeVisible();
  expect(screen.queryByText(/PRIVATE PATH/)).not.toBeInTheDocument();
  expect(gateway.harnessPrepare).toHaveBeenCalledTimes(1);
  expect(screen.queryByRole('button', { name: 'Dismiss preparation' })).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Retry same preparation' })).toBeEnabled();
});

it('retains admission identity beyond 35 seconds after remount and retries only that identity', async () => {
  let acknowledge!: (value: HarnessPreparationStatus) => void;
  vi.mocked(gateway.harnessPrepare).mockImplementationOnce(async params => {
    progress = { ...params, phase: 'inspecting', completedFiles: 0, completedBytes: 0, error: null };
    return new Promise(resolve => { acknowledge = resolve; });
  });
  vi.mocked(gateway.harnessPreparationStatus).mockRejectedValue({ code: 'not_found' });
  const view = await open(); await start(); view.unmount();
  render(<HarnessesScreen gateway={gateway} projects={[project]} />);
  await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
  expect(gateway.harnessPrepare).toHaveBeenCalledTimes(1);
  expect(screen.queryByRole('button', { name: 'Dismiss preparation' })).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Review setup' })).toBeDisabled();
  vi.mocked(gateway.harnessPreparationStatus).mockImplementation(async () => progress);
  await act(async () => fireEvent.click(screen.getByRole('button', { name: 'Retry same preparation' })));
  const calls = vi.mocked(gateway.harnessPrepare).mock.calls;
  expect(calls).toHaveLength(2);
  expect(calls[1]).toEqual(calls[0]);
  await act(async () => acknowledge(progress));
  expect(screen.getByText('Copying the Hermes runtime…')).toBeVisible();
});

it('refreshes a permanently failed prepared review instead of leaving it Ready', async () => {
  vi.mocked(gateway.harnessPreparedPreview).mockImplementation(async () => {
    progress = { ...progress, phase: 'failed', error: { code: 'internal', message: 'PRIVATE FAILURE', fieldPath: null, retryable: false } };
    throw new Error('PRIVATE FAILURE');
  });
  await open(); await start(); await advance('ready');
  await act(async () => fireEvent.click(screen.getByRole('button', { name: 'Review prepared setup' })));
  expect(screen.getByText(/Preparation could not finish/)).toBeVisible();
  expect(screen.queryByRole('button', { name: 'Review prepared setup' })).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Dismiss preparation' })).toBeEnabled();
  expect(screen.queryByText(/PRIVATE FAILURE/)).not.toBeInTheDocument();
});

it('allows dismissal after the daemon records a definite rejected preparation', async () => {
  vi.mocked(gateway.harnessPrepare).mockImplementation(async params => {
    progress = { ...params, phase: 'failed', completedFiles: 0, completedBytes: 0, error: { code: 'internal', message: 'PRIVATE PROJECT PATH', fieldPath: null, retryable: false } };
    return progress;
  });
  await open(); await start();
  expect(screen.getByText(/Preparation could not finish/)).toBeVisible();
  await act(async () => fireEvent.click(screen.getByRole('button', { name: 'Dismiss preparation' })));
  expect(screen.queryByRole('region', { name: 'Harness preparation' })).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Review setup' })).toBeEnabled();
  expect(screen.queryByText(/PRIVATE PROJECT PATH/)).not.toBeInTheDocument();
  expect(gateway.harnessPrepare).toHaveBeenCalledTimes(1);
});

it('recovers a lost preparation acknowledgement and an uncertain prepared review without new work', async () => {
  vi.mocked(gateway.harnessPrepare).mockImplementation(async params => {
    progress = { ...params, phase: 'ready', completedFiles: 12, completedBytes: 4096, error: null };
    throw new Error('PRIVATE ACK');
  });
  vi.mocked(gateway.harnessPreparedPreview).mockRejectedValueOnce(new Error('Lost review acknowledgement'));
  await open(); await start();
  await act(async () => fireEvent.click(screen.getByRole('button', { name: 'Review prepared setup' })));
  expect(screen.getByRole('alert')).toHaveTextContent('Checking preparation before offering the next action');
  await act(async () => fireEvent.click(screen.getByRole('button', { name: 'Review prepared setup' })));
  expect(screen.getByRole('heading', { name: 'Review setup changes' })).toBeVisible();
  expect(gateway.harnessPrepare).toHaveBeenCalledTimes(1);
  expect(vi.mocked(gateway.harnessPreparedPreview).mock.calls[0]).toEqual(vi.mocked(gateway.harnessPreparedPreview).mock.calls[1]);
  expect(screen.queryByText(/PRIVATE ACK/)).not.toBeInTheDocument();
});

it('does not let a late prepared review restore approval after navigating away', async () => {
  let resolve!: (value: SetupPlan) => void;
  vi.mocked(gateway.harnessPreparedPreview).mockImplementation(() => new Promise(done => { resolve = done; }));
  const view = await open(); await start(); await advance('ready');
  fireEvent.click(screen.getByRole('button', { name: 'Review prepared setup' }));
  view.rerender(<HarnessesScreen gateway={gateway} projects={[project]} active={false} />);
  await act(async () => resolve(plan));
  view.rerender(<HarnessesScreen gateway={gateway} projects={[project]} />);
  await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
  expect(screen.queryByRole('button', { name: 'Save settings' })).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Review prepared setup' })).toBeEnabled();
  expect(gateway.harnessExecutionStart).not.toHaveBeenCalled();
});

it('does not start preparation when its recovery identity cannot be saved', async () => {
  await open();
  vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('Storage full'); });
  fireEvent.click(screen.getByRole('button', { name: 'Prepare setup' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Could not remember this preparation');
  expect(gateway.harnessPrepare).not.toHaveBeenCalled();
});

it('does not offer preparation for an unqualified Hermes version', async () => {
  const report = await gateway.harnessProbe({ harness: 'hermes', projectId: project.projectId, hermesProfile: 'default' });
  vi.mocked(gateway.harnessProbe).mockResolvedValue({ ...report, harnessVersion: '0.18.0' });
  render(<HarnessesScreen gateway={gateway} projects={[project]} />);
  await waitFor(() => expect(screen.getByRole('button', { name: 'Review setup' })).toBeEnabled());
  fireEvent.change(screen.getByRole('combobox', { name: 'Harness' }), { target: { value: 'hermes' } });
  fireEvent.click(screen.getByRole('button', { name: 'Review setup' }));
  await screen.findByText(/This version cannot connect automatically yet/);
  expect(screen.queryByRole('button', { name: 'Prepare setup' })).not.toBeInTheDocument();
  expect(gateway.harnessPrepare).not.toHaveBeenCalled();
});
