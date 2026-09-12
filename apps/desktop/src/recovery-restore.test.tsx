import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { StrictMode } from 'react';
import { RecoveryRestorePanel } from './recovery-restore';
import type { RecoveryRestoreStatus } from './bindings';

const idle: RecoveryRestoreStatus = { state: 'idle' };
afterEach(cleanup);
const pending: RecoveryRestoreStatus = { state: 'submitting', restoreId: '018f22e2-79b0-7cc8-98c4-dc0c0c075602' as never };
const gateway = () => ({
  recoveryRestoreOverview: vi.fn(async (): Promise<RecoveryRestoreStatus> => idle),
  recoveryRestoreBegin: vi.fn(async (): Promise<RecoveryRestoreStatus | null> => null),
  recoveryRestoreResume: vi.fn(async (): Promise<RecoveryRestoreStatus> => pending),
  recoveryRestoreCancel: vi.fn(async (): Promise<RecoveryRestoreStatus> => idle),
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
