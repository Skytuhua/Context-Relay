import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { StrictMode } from 'react';
import { afterEach, expect, it, vi } from 'vitest';
import type { AccountDeletionIntentSummary, DecimalTimestamp, LocalResult, OperationId } from './bindings';
import { AccountLifecyclePanel } from './account-lifecycle';

const id = '019924bb-5300-7000-8000-000000000001' as OperationId;
const active: Extract<LocalResult, { kind: 'account_deletion' }>['data'] = { state: 'active', purgeDeadline: null, exportAvailable: false };
const pending = { state: 'pending_delete', purgeDeadline: '1789516800000' as DecimalTimestamp, exportAvailable: true } as const;
afterEach(cleanup);
const gateway = () => ({
  accountDeletionStatus: vi.fn(async () => active),
  accountDeletionIntents: vi.fn(async (): Promise<AccountDeletionIntentSummary[]> => []),
  accountDeletionBegin: vi.fn<(operationId: OperationId, confirmation: string) => Promise<typeof active>>(async () => pending),
  accountDeletionCancel: vi.fn<(operationId: OperationId) => Promise<typeof active>>(async () => active),
});

it('requires confirmation and retains the same ID after a lost response without auto replay', async () => {
  const api = gateway();
  api.accountDeletionBegin.mockRejectedValueOnce(new Error('private provider failure'));
  render(<StrictMode><AccountLifecyclePanel gateway={api} /></StrictMode>);
  fireEvent.click(await screen.findByRole('button', { name: 'Request account deletion' }));
  expect(screen.getByLabelText('Type delete to confirm')).toHaveFocus();
  const confirm = screen.getByRole('button', { name: 'Confirm deletion request' });
  expect(confirm).toBeDisabled();
  fireEvent.change(screen.getByLabelText('Type delete to confirm'), { target: { value: 'delete' } });
  fireEvent.click(confirm);
  await screen.findByRole('alert');
  expect(api.accountDeletionBegin).toHaveBeenCalledOnce();
  const original = api.accountDeletionBegin.mock.calls[0];
  expect(original).toEqual([expect.stringMatching(/^[0-9a-f-]{36}$/), 'delete']);
  expect(screen.queryByText('private provider failure')).toBeNull();
  expect(screen.getByLabelText('Type delete to confirm')).toHaveValue('');
  fireEvent.click(screen.getByRole('button', { name: 'Refresh account status and requests' }));
  await waitFor(() => expect(screen.getByRole('button', { name: 'Refresh account status and requests' })).toBeEnabled());
  expect(api.accountDeletionBegin).toHaveBeenCalledOnce();
  fireEvent.change(screen.getByLabelText('Type delete to confirm'), { target: { value: 'delete' } });
  fireEvent.click(screen.getByRole('button', { name: 'Confirm deletion request' }));
  await waitFor(() => expect(api.accountDeletionBegin).toHaveBeenCalledTimes(2));
  expect(api.accountDeletionBegin.mock.calls[1]).toEqual(original);
});

it('discovers previous cancel requests after remount and retries only the selected original ID', async () => {
  const api = gateway();
  api.accountDeletionIntents.mockResolvedValue([{ operationId: id, action: 'cancelDeletion' }]);
  const first = render(<AccountLifecyclePanel gateway={api} />);
  await screen.findByRole('button', { name: `Review cancel request ${id}` });
  first.unmount();
  render(<AccountLifecyclePanel gateway={api} />);
  fireEvent.click(await screen.findByRole('button', { name: `Review cancel request ${id}` }));
  expect(api.accountDeletionCancel).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Confirm cancellation request' }));
  await waitFor(() => expect(api.accountDeletionCancel).toHaveBeenCalledWith(id));
  expect(api.accountDeletionBegin).not.toHaveBeenCalled();
});

it('keeps mutations unavailable when account state cannot be confirmed', async () => {
  const api = gateway();
  api.accountDeletionStatus.mockRejectedValue({ code: 'harness_unsupported' });
  render(<AccountLifecyclePanel gateway={api} />);
  expect(await screen.findByText('Account deletion is not available in this build.')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Request account deletion' })).toBeNull();
  expect(api.accountDeletionBegin).not.toHaveBeenCalled();
});

it('suppresses duplicate submissions and ignores an old gateway response', async () => {
  const old = gateway();
  let finish!: (value: typeof active) => void;
  old.accountDeletionBegin.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  const view = render(<AccountLifecyclePanel gateway={old} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Request account deletion' }));
  fireEvent.change(screen.getByLabelText('Type delete to confirm'), { target: { value: 'delete' } });
  const confirm = screen.getByRole('button', { name: 'Confirm deletion request' });
  fireEvent.click(confirm); fireEvent.click(confirm);
  expect(old.accountDeletionBegin).toHaveBeenCalledOnce();
  const current = gateway();
  view.rerender(<AccountLifecyclePanel gateway={current} />);
  await screen.findByRole('button', { name: 'Request account deletion' });
  finish(pending);
  await waitFor(() => expect(screen.getByRole('button', { name: 'Refresh account status and requests' })).toBeEnabled());
  expect(screen.getByText('Your account is active.')).toBeInTheDocument();
  expect(screen.queryByText(/Deletion is scheduled/)).toBeNull();
});

it('pages history explicitly without sending any mutation', async () => {
  const api = gateway();
  const page = Array.from({ length: 50 }, (_, n) => ({ operationId: `019924bb-5300-7000-8000-${n.toString(16).padStart(12, '0')}` as OperationId, action: 'beginDeletion' as const }));
  api.accountDeletionIntents.mockResolvedValueOnce(page).mockResolvedValue([]);
  render(<AccountLifecyclePanel gateway={api} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Next requests' }));
  await screen.findByText('No previous requests on this page.');
  expect(api.accountDeletionIntents).toHaveBeenLastCalledWith(page[49].operationId);
  expect(api.accountDeletionBegin).not.toHaveBeenCalled();
  expect(api.accountDeletionCancel).not.toHaveBeenCalled();
});

it('recovers the controls if a new request ID cannot be generated', async () => {
  const api = gateway();
  render(<AccountLifecyclePanel gateway={api} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Request account deletion' }));
  fireEvent.change(screen.getByLabelText('Type delete to confirm'), { target: { value: 'delete' } });
  vi.spyOn(crypto, 'getRandomValues').mockImplementationOnce(() => { throw new Error('random unavailable'); });
  fireEvent.click(screen.getByRole('button', { name: 'Confirm deletion request' }));
  await screen.findByRole('alert');
  expect(screen.getByRole('button', { name: 'Refresh account status and requests' })).toBeEnabled();
  expect(api.accountDeletionBegin).not.toHaveBeenCalled();
  vi.restoreAllMocks();
});

it('restores focus when closing a request review', async () => {
  render(<AccountLifecyclePanel gateway={gateway()} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Request account deletion' }));
  expect(screen.getByLabelText('Type delete to confirm')).toHaveFocus();
  fireEvent.click(screen.getByRole('button', { name: 'Close request review' }));
  expect(screen.getByRole('heading', { name: 'Account deletion' })).toHaveFocus();
});
