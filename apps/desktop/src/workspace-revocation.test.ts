import { beforeEach, expect, it, vi } from 'vitest';

import type { DeviceId, DeviceRevocationStatus, OperationId, Sha256Digest } from './bindings';
import { validateDeviceRevocationIntents, validateDeviceRevocationStatus } from './protocol-validation';

const invoke = vi.hoisted(() => vi.fn());
vi.mock('@tauri-apps/api/core', () => ({ invoke }));
import { LocalWorkspaceGateway } from './workspace';

const operationId = '018f22e2-79b0-7cc8-98c4-dc0c0c077001' as OperationId;
const nextOperationId = '018f22e2-79b0-7cc8-98c4-dc0c0c077002' as OperationId;
const deviceId = '018f22e2-79b0-7cc8-98c4-dc0c0c075002' as DeviceId;

const status: DeviceRevocationStatus = {
  operationId,
  deviceId,
  sendCanceled: false,
  access: 'ready',
  outcome: { state: 'prepared' },
};

beforeEach(() => { invoke.mockReset(); });

it('binds revocation requests and strict responses to the same operation and target', async () => {
  invoke.mockImplementation(async (command, args) => {
    if (!args) throw new Error(`missing request arguments for ${command}`);
    const { request } = args;
    if (request.method === 'device_revocation_intents') {
      return { kind: 'device_revocation_intents', data: { intents: [status] } };
    }
    return { kind: 'device_revocation', data: { status } };
  });
  const gateway = new LocalWorkspaceGateway();

  expect(await gateway.revokeDevice(operationId, deviceId)).toEqual(status);
  expect(await gateway.deviceRevocationStatus(operationId)).toEqual(status);
  expect(await gateway.cancelDeviceRevocation(operationId)).toEqual(status);
  expect(await gateway.deviceRevocationIntents(null)).toEqual([status]);
  expect(invoke.mock.calls.map((call) => call[1].request)).toEqual([
    { method: 'device_revoke', params: { operationId, deviceId } },
    { method: 'device_revocation_status', params: { operationId } },
    { method: 'device_revocation_cancel', params: { operationId } },
    { method: 'device_revocation_intents', params: { after: null } },
  ]);
});

it('rejects substituted identities and noncanonical status shapes', async () => {
  const gateway = new LocalWorkspaceGateway();
  invoke.mockResolvedValueOnce({
    kind: 'device_revocation',
    data: { status: { ...status, operationId: nextOperationId } },
  });
  await expect(gateway.revokeDevice(operationId, deviceId)).rejects.toThrow('identity changed');

  for (const invalid of [
    { ...status, providerMessage: 'untrusted' },
    { ...status, outcome: { state: 'accepted', acceptedEndpoint: {
      stateSha256: '0'.repeat(64) as Sha256Digest,
      controlEpoch: 1,
      keyEpoch: 1,
    } } },
    { ...status, outcome: { state: 'unknown' } },
  ]) {
    expect(() => validateDeviceRevocationStatus(invalid)).toThrow();
  }
});

it('requires bounded revocation summaries in strict operation order', () => {
  expect(validateDeviceRevocationIntents([status, { ...status, operationId: nextOperationId }], null))
    .toHaveLength(2);
  expect(() => validateDeviceRevocationIntents([{ ...status, operationId: nextOperationId }, status], null))
    .toThrow('cursor');
  expect(() => validateDeviceRevocationIntents(Array.from({ length: 51 }, () => status), null))
    .toThrow();
  expect(() => validateDeviceRevocationIntents([status], operationId)).toThrow('cursor');
});
