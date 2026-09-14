import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { StrictMode } from 'react';
import { RecoveryRestorePanel } from './recovery-restore';
import type { RecoveryRestoreStatus, RecoveryHistoryCandidatesPage } from './bindings';
import { validateRecoveryRestoreStatus, validateRecoveryHistoryCandidates } from './protocol-validation';
import { LocalWorkspaceGateway } from './workspace';
import type { LocalClient } from './local-client';

const idle: RecoveryRestoreStatus = { state: 'idle' };
const restoreId = '018f22e2-79b0-7cc8-98c4-dc0c0c075602' as never;
const endpoint = { stateSha256: '11'.repeat(32) as never, controlEpoch: 2, keyEpoch: 2 };
afterEach(cleanup);
it('requires an explicit history choice after admission and exposes a keyboard reachable list action', async () => {
  const api = gateway();
  api.recoveryRestoreOverview.mockResolvedValue({ state: 'restoring_history', restoreId,
    acceptedEndpoint: { stateSha256: '11'.repeat(32), controlEpoch: 2, keyEpoch: 2 }, history: { state: 'unselected' } } as unknown as RecoveryRestoreStatus);
  const onComplete = vi.fn();
  render(<RecoveryRestorePanel gateway={api} onComplete={onComplete} />);
  const list = await screen.findByRole('button', { name: 'Find recovery histories' });
  list.focus();
  expect(list).toHaveFocus();
  expect(screen.queryByRole('button', { name: 'Resume recovery' })).toBeNull();
  expect(screen.getByRole('status')).toHaveTextContent('Choose a history');
  expect(api.recoveryRestoreResume).not.toHaveBeenCalled();
  expect(onComplete).not.toHaveBeenCalled();
});
it('resumes admitted recovery history without treating admission as completion', async () => {
  const history = validateRecoveryRestoreStatus({ state: 'restoring_history', restoreId, acceptedEndpoint: endpoint, history: { state: 'incomplete', selectedEndpoint: endpoint, checkpointSha256: '22'.repeat(32) } });
  const call = vi.fn(async () => ({ kind: 'recovery_restore_status', data: { status: history } }));
  const api = new LocalWorkspaceGateway({ call } as unknown as LocalClient);
  const onComplete = vi.fn();
  render(<RecoveryRestorePanel gateway={api} onComplete={onComplete} />);
  expect(await screen.findByText('Your recovery is saved. Your history is still being restored.')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Resume recovery' }));
  await waitFor(() => expect(call).toHaveBeenLastCalledWith({ method: 'recovery_restore_resume', params: {} }));
  expect(onComplete).not.toHaveBeenCalled();
  expect(screen.queryByRole('button', { name: 'Enter recovery phrase' })).toBeNull();
  expect(() => validateRecoveryRestoreStatus({ state: 'restoring_history' })).toThrow();
  expect(() => validateRecoveryRestoreStatus({ ...history, device: {} })).toThrow();
});
const pending: RecoveryRestoreStatus = { state: 'submitting', restoreId: '018f22e2-79b0-7cc8-98c4-dc0c0c075602' as never };
const gateway = () => ({
  recoveryHistoryCandidates: vi.fn(async (): Promise<RecoveryHistoryCandidatesPage> => ({ restoreId, acceptedEndpoint: endpoint, candidates: [], nextCursor: null })),
  recoveryHistorySelect: vi.fn(async (): Promise<RecoveryRestoreStatus> => pending),
  recoveryHistoryUnlock: vi.fn(async (): Promise<RecoveryRestoreStatus | null> => null),
  recoveryRestoreOverview: vi.fn(async (): Promise<RecoveryRestoreStatus> => idle),
  recoveryRestoreBegin: vi.fn(async (): Promise<RecoveryRestoreStatus | null> => null),
  recoveryRestoreResume: vi.fn(async (): Promise<RecoveryRestoreStatus> => pending),
  recoveryRestoreCancel: vi.fn(async (): Promise<RecoveryRestoreStatus> => idle),
});

it('lists eight bounded candidates without selecting and selects only the explicit exact hash', async () => {
  const api = gateway();
  const status: RecoveryRestoreStatus = { state: 'restoring_history', restoreId, acceptedEndpoint: endpoint, history: { state: 'unselected' } };
  const hash = '22'.repeat(32) as never;
  const candidate = { checkpointSha256: hash, authorDeviceId: restoreId, createdHlc: { node: restoreId, physicalMs: '1' as never, logical: 0 }, keyEpoch: 1, frontierDeviceCount: 0, extent: { state: 'supported' as const, operationCount: 0 } };
  const cursor = { restoreId, acceptedEndpointSha256: endpoint.stateSha256, receivedAt: '2026-09-14T00:00:00Z', canonicalHash: hash };
  const page: RecoveryHistoryCandidatesPage = { restoreId, acceptedEndpoint: endpoint, candidates: [candidate], nextCursor: cursor };
  api.recoveryRestoreOverview.mockResolvedValue(status);
  api.recoveryHistoryCandidates.mockResolvedValueOnce(page).mockResolvedValue({ ...page, candidates: [], nextCursor: null });
  api.recoveryHistorySelect.mockResolvedValue({ ...status, history: { state: 'incomplete', selectedEndpoint: endpoint, checkpointSha256: hash } });
  const onComplete = vi.fn();
  render(<RecoveryRestorePanel gateway={api} onComplete={onComplete} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Find recovery histories' }));
  const restore = await screen.findByRole('button', { name: 'Restore this history' });
  restore.focus(); expect(restore).toHaveFocus();
  expect(api.recoveryHistorySelect).not.toHaveBeenCalled();
  expect(api.recoveryRestoreResume).not.toHaveBeenCalled();
  fireEvent.click(restore);
  expect(await screen.findByRole('button', { name: 'Resume recovery' })).toBeEnabled();
  expect(api.recoveryHistorySelect).toHaveBeenCalledExactlyOnceWith({ restoreId, acceptedEndpointSha256: endpoint.stateSha256, checkpointSha256: hash });
  expect(onComplete).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'More recovery histories' }));
  expect(await screen.findByText('No more recovery histories are available.')).toBeInTheDocument();
  expect(api.recoveryHistoryCandidates).toHaveBeenLastCalledWith({ restoreId, acceptedEndpointSha256: endpoint.stateSha256, cursor });
  expect(() => validateRecoveryHistoryCandidates({ ...page, candidates: Array(9).fill(candidate) })).toThrow();
  expect(() => validateRecoveryHistoryCandidates({ ...page, nextCursor: null })).toThrow();
  expect(() => validateRecoveryHistoryCandidates({ ...page, candidates: [{ ...candidate, extent: { state: 'supported', operationCount: 100001 } }] })).toThrow();
});

it('enables native historical-key reentry only for positively identified missing historical keys', async () => {
  const api = gateway();
  const hash = '22'.repeat(32) as never;
  api.recoveryRestoreOverview.mockResolvedValue({ state: 'restoring_history', restoreId, acceptedEndpoint: endpoint, history: { state: 'historical_keys_needed', selectedEndpoint: endpoint, checkpointSha256: hash } });
  const onComplete = vi.fn();
  render(<RecoveryRestorePanel gateway={api} onComplete={onComplete} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Unlock historical keys' }));
  await waitFor(() => expect(api.recoveryHistoryUnlock).toHaveBeenCalledExactlyOnceWith({ restoreId, acceptedEndpointSha256: endpoint.stateSha256, checkpointSha256: hash }));
  expect(screen.queryByRole('textbox')).toBeNull();
  expect(api.recoveryHistorySelect).not.toHaveBeenCalled();
  expect(onComplete).not.toHaveBeenCalled();
});

it('opens native input without a phrase field and reconciles a lost begin response', async () => {
  const api = gateway();
  api.recoveryRestoreOverview.mockResolvedValueOnce(idle).mockResolvedValue(pending);
  api.recoveryRestoreBegin.mockRejectedValueOnce(new Error('lost response'));
  render(<RecoveryRestorePanel gateway={api} onComplete={vi.fn()} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Enter recovery phrase' }));
  expect(screen.queryByRole('textbox')).toBeNull();
  expect(await screen.findByRole('button', { name: 'Resume recovery' })).toBeEnabled();
  expect(screen.queryByRole('button', { name: 'Enter recovery phrase' })).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Resume recovery' }));
  await waitFor(() => expect(api.recoveryRestoreResume).toHaveBeenCalledOnce());
  expect(api.recoveryRestoreBegin).toHaveBeenCalledOnce();
});

it('keeps begin unavailable when reconciliation fails, then allows a status retry', async () => {
  const api = gateway();
  api.recoveryRestoreOverview.mockRejectedValueOnce(new Error('offline'));
  render(<RecoveryRestorePanel gateway={api} onComplete={vi.fn()} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Check recovery status' }));
  expect(await screen.findByRole('button', { name: 'Enter recovery phrase' })).toBeEnabled();
  expect(api.recoveryRestoreBegin).not.toHaveBeenCalled();
});

it('treats native cancellation as a status refresh without submitting another request', async () => {
  const api = gateway();
  render(<RecoveryRestorePanel gateway={api} onComplete={vi.fn()} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Enter recovery phrase' }));
  await waitFor(() => expect(api.recoveryRestoreOverview).toHaveBeenCalledTimes(2));
  expect(api.recoveryRestoreCancel).not.toHaveBeenCalled();
});

it('reconciles confirmed completion and does not keep a stale error', async () => {
  const api = gateway();
  const complete: RecoveryRestoreStatus = { state: 'complete', restoreId: pending.restoreId,
    device: { deviceId: '018f22e2-79b0-7cc8-98c4-dc0c0c075603' as never, name: 'Restored device', platform: 'windows', state: 'active', isCurrent: true } };
  api.recoveryRestoreOverview.mockResolvedValueOnce(pending).mockResolvedValue(complete);
  api.recoveryRestoreResume.mockRejectedValueOnce(new Error('lost response'));
  const onComplete = vi.fn();
  render(<RecoveryRestorePanel gateway={api} onComplete={onComplete} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Resume recovery' }));
  expect(await screen.findByText('This device has been recovered.')).toBeInTheDocument();
  expect(screen.getByRole('heading', { name: 'Recover this device' })).toHaveFocus();
  expect(screen.queryByRole('alert')).toBeNull();
  expect(onComplete).toHaveBeenCalledOnce();
});

it('loads under StrictMode without leaving the busy guard stuck', async () => {
  const api = gateway();
  render(<StrictMode><RecoveryRestorePanel gateway={api} onComplete={vi.fn()} /></StrictMode>);
  expect(await screen.findByRole('button', { name: 'Enter recovery phrase' })).toBeEnabled();
});

it('can discard an unprepared attempt after reopening the screen', async () => {
  const api = gateway();
  api.recoveryRestoreBegin.mockRejectedValueOnce(new Error('wrong phrase'));
  const first = render(<RecoveryRestorePanel gateway={api} onComplete={vi.fn()} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Enter recovery phrase' }));
  await screen.findByRole('alert');
  first.unmount();
  render(<RecoveryRestorePanel gateway={api} onComplete={vi.fn()} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Stop recovery attempt' }));
  await waitFor(() => expect(api.recoveryRestoreCancel).toHaveBeenCalledOnce());
});

it('rejects selected progress whose endpoint contradicts the accepted endpoint', () => {
  for (const state of ['incomplete', 'historical_keys_needed', 'current_material_unavailable']) {
    expect(() => validateRecoveryRestoreStatus({ state: 'restoring_history', restoreId, acceptedEndpoint: endpoint,
      history: { state, selectedEndpoint: { ...endpoint, stateSha256: '33'.repeat(32) }, checkpointSha256: '22'.repeat(32) } })).toThrow();
  }
  expect(() => validateRecoveryRestoreStatus({ state: 'restoring_history', restoreId, acceptedEndpoint: endpoint,
    history: { state: 'stale_endpoint', selectedEndpoint: endpoint, checkpointSha256: '22'.repeat(32) } })).toThrow();
});

it('rejects candidate frontier summaries beyond the existing checkpoint collection bound', () => {
  const page: RecoveryHistoryCandidatesPage = {
    restoreId, acceptedEndpoint: endpoint, candidates: [{ checkpointSha256: '22'.repeat(32) as never,
      authorDeviceId: restoreId as never, createdHlc: { physicalMs: '1' as never, logical: 0, node: restoreId as never },
      keyEpoch: 1, frontierDeviceCount: 10001, extent: { state: 'supported', operationCount: 10001 } }],
    nextCursor: { restoreId, acceptedEndpointSha256: endpoint.stateSha256, canonicalHash: '22'.repeat(32) as never, receivedAt: '2026-09-14T00:00:00Z' },
  };
  expect(() => validateRecoveryHistoryCandidates(page)).toThrow();
});
