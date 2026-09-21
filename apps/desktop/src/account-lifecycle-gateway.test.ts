import { expect, it, vi } from 'vitest';
import type { OperationId } from './bindings';
import type { LocalClient } from './local-client';
import { LocalWorkspaceGateway } from './workspace';

const id = '019924bb-5300-7000-8000-000000000001' as OperationId;
it('keeps explicit lifecycle request identities and validates projections', async () => {
  const active = { state: 'active', purgeDeadline: null, exportAvailable: false };
  const call = vi.fn(async () => ({ kind: 'account_deletion', data: active }));
  const api = new LocalWorkspaceGateway({ call } as unknown as LocalClient);
  expect(await api.accountDeletionStatus()).toEqual(active);
  await api.accountDeletionBegin(id, 'delete');
  expect(call).toHaveBeenLastCalledWith({ method: 'account_deletion_begin', params: { operationId: id, confirmation: 'delete' } });
  await api.accountDeletionCancel(id);
  expect(call).toHaveBeenLastCalledWith({ method: 'account_deletion_cancel', params: { operationId: id } });
  for (const data of [{ ...active, exportAvailable: true }, { ...active, purgeDeadline: '0' }, { state: 'pending_delete', purgeDeadline: null, exportAvailable: true }, { ...active, accessToken: 'private' }]) {
    call.mockResolvedValueOnce({ kind: 'account_deletion', data } as never);
    await expect(api.accountDeletionStatus()).rejects.toThrow();
  }
});

it('rejects malformed, excessive and non-advancing history without sending a mutation', async () => {
  const item = { operationId: id, action: 'beginDeletion' };
  const call = vi.fn(async () => ({ kind: 'account_deletion_intents', data: { intents: [item] } }));
  const api = new LocalWorkspaceGateway({ call } as unknown as LocalClient);
  expect(await api.accountDeletionIntents(null)).toEqual([item]);
  await expect(api.accountDeletionIntents(id)).rejects.toThrow();
  for (const intents of [[{ ...item, operationId: 'invalid' }], [item, item], Array(51).fill(item), [{ ...item, action: 'delete' }], [{ ...item, sessionId: 'private' }]]) {
    call.mockResolvedValueOnce({ kind: 'account_deletion_intents', data: { intents } });
    await expect(api.accountDeletionIntents(null)).rejects.toThrow();
  }
  expect(call).toHaveBeenLastCalledWith({ method: 'account_deletion_intents', params: { after: null } });
});
