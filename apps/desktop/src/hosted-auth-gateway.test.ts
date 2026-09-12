import { expect, it, vi } from 'vitest';
import type { OperationId } from './bindings';
import type { LocalClient } from './local-client';
import { LocalWorkspaceGateway } from './workspace';

it('keeps hosted controls generation-bound and rejects unconfirmed responses', async () => {
  const generation = '019924bb-5300-7000-8000-000000000001' as OperationId;
  const operationId = '019924bb-5300-7000-8000-000000000002' as OperationId;
  const status = { generation, state: { phase: 'signed_out', remoteRevoked: null } };
  const call = vi.fn(async () => ({ kind: 'hosted_auth', data: { status } }));
  const gateway = new LocalWorkspaceGateway({ call } as unknown as LocalClient);
  expect(await gateway.hostedAuthStatus()).toEqual(status);
  await expect(gateway.hostedAuthStart({ operationId, expectedGeneration: generation })).rejects.toThrow();
  await gateway.hostedAuthCancel(generation);
  expect(call).toHaveBeenLastCalledWith({ method: 'hosted_auth_cancel', params: { generation } });
  await gateway.hostedAuthLogout(generation);
  expect(call).toHaveBeenLastCalledWith({ method: 'hosted_auth_logout', params: { generation } });
  call.mockResolvedValueOnce({ kind: 'hosted_auth', data: { status: { ...status, state: { ...status.state, accessToken: 'forbidden' } } } } as never);
  await expect(gateway.hostedAuthStatus()).rejects.toThrow();
  call.mockResolvedValueOnce({ kind: 'hosted_auth', data: { status }, accessToken: 'forbidden' } as never);
  await expect(gateway.hostedAuthStatus()).rejects.toThrow();
  call.mockResolvedValueOnce({ kind: 'hosted_auth', data: { status: { generation: operationId, state: { phase: 'signing_in' } } } } as never);
  expect((await gateway.hostedAuthStart({ operationId, expectedGeneration: generation })).generation).toBe(operationId);
});
