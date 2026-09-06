import { beforeEach, expect, it, vi } from 'vitest';

import type {
  RecoveryEnrollmentConfirmParams,
  RecoveryEnrollmentHostBeginResult,
  RecoveryEnrollmentHostConfirmResult,
  RecoveryEnrollmentId,
} from './bindings';

const invoke = vi.hoisted(() => vi.fn());
vi.mock('@tauri-apps/api/core', () => ({ invoke }));

import { LocalClient } from './local-client';
import { LocalWorkspaceGateway } from './workspace';

beforeEach(() => {
  invoke.mockReset();
});

it('opens the native folder picker without sending workspace mutations, including cancellation', async () => {
  invoke.mockResolvedValueOnce('C:\\Work\\專案 🚀').mockResolvedValueOnce(null);
  const gateway = new LocalWorkspaceGateway();
  await expect(gateway.chooseProjectFolder()).resolves.toBe('C:\\Work\\專案 🚀');
  await expect(gateway.chooseProjectFolder()).resolves.toBeNull();
  expect(invoke.mock.calls).toEqual([['choose_project_folder'], ['choose_project_folder']]);
});

it('forwards only the typed request through the local_request command', async () => {
  const response = { kind: 'projects', data: { projects: [] } } as const;
  invoke.mockResolvedValue(response);
  const request = { method: 'projects_list', params: {} } as const;

  await expect(new LocalClient().call(request)).resolves.toEqual(response);
  expect(invoke).toHaveBeenCalledWith('local_request', { request });
});

it('uses dedicated native recovery commands and never generic local_request', async () => {
  const beginResult = { kind: 'status', data: recoveryStatus('idle') } satisfies RecoveryEnrollmentHostBeginResult;
  const confirmResult = { kind: 'canceled' } satisfies RecoveryEnrollmentHostConfirmResult;
  const params = {
    enrollmentId: '018f22e2-79b0-7cc8-98c4-dc0c0c076001',
    confirmations: [
      { position: 1, word: 'first' },
      { position: 7, word: 'seventh' },
      { position: 13, word: 'thirteenth' },
      { position: 24, word: 'last' },
    ],
  } as RecoveryEnrollmentConfirmParams;
  invoke.mockResolvedValueOnce(beginResult).mockResolvedValueOnce(confirmResult);

  const client = new LocalClient();
  await expect(client.recoveryEnrollmentBegin()).resolves.toEqual(beginResult);
  await expect(client.recoveryEnrollmentConfirm(params)).resolves.toEqual(confirmResult);

  expect(invoke).toHaveBeenNthCalledWith(1, 'recovery_enrollment_begin');
  expect(invoke).toHaveBeenNthCalledWith(2, 'recovery_enrollment_confirm', { params });
  expect(invoke).not.toHaveBeenCalledWith('local_request', expect.anything());
});

it('rejects phrase-bearing recovery methods on the generic renderer bridge', async () => {
  const client = new LocalClient();
  const params = {
    enrollmentId:
      '018f22e2-79b0-7cc8-98c4-dc0c0c076001' as RecoveryEnrollmentConfirmParams['enrollmentId'],
    confirmations: [],
  };

  await expect(
    client.call({ method: 'recovery_enrollment_begin', params: {} }),
  ).rejects.toThrow('dedicated native recovery command');
  await expect(
    client.call({ method: 'recovery_enrollment_confirm', params }),
  ).rejects.toThrow('dedicated native recovery command');
  expect(invoke).not.toHaveBeenCalled();
});

it('routes only overview, status, and cancel through authenticated local_request', async () => {
  const enrollmentId =
    '018f22e2-79b0-7cc8-98c4-dc0c0c076001' as RecoveryEnrollmentId;
  const idle = recoveryStatus('idle');
  const challenge = {
    kind: 'challenge',
    data: {
      enrollmentId,
      confirmationPositions: [1, 7, 13, 24],
      createdAtMs: '1000',
      expiresAtMs: '601000',
    },
  } as RecoveryEnrollmentHostBeginResult;
  const params = { enrollmentId, confirmations: [] };
  invoke
    .mockResolvedValueOnce({ kind: 'recovery_enrollment_status', data: { status: idle } })
    .mockResolvedValueOnce(challenge)
    .mockResolvedValueOnce({ kind: 'recovery_enrollment_status', data: { status: idle } })
    .mockResolvedValueOnce({ kind: 'canceled' })
    .mockResolvedValueOnce({ kind: 'recovery_enrollment_status', data: { status: idle } });

  const gateway = new LocalWorkspaceGateway();
  await expect(gateway.recoveryEnrollmentOverview()).resolves.toEqual(idle);
  await expect(gateway.recoveryEnrollmentBegin()).resolves.toEqual(challenge);
  await expect(gateway.recoveryEnrollmentStatus(enrollmentId)).resolves.toEqual(idle);
  await expect(gateway.recoveryEnrollmentConfirm(params)).resolves.toEqual({ kind: 'canceled' });
  await expect(gateway.recoveryEnrollmentCancel(enrollmentId)).resolves.toBeUndefined();

  expect(invoke.mock.calls).toEqual([
    ['local_request', { request: { method: 'recovery_enrollment_overview', params: {} } }],
    ['recovery_enrollment_begin'],
    [
      'local_request',
      { request: { method: 'recovery_enrollment_status', params: { enrollmentId } } },
    ],
    ['recovery_enrollment_confirm', { params }],
    [
      'local_request',
      { request: { method: 'recovery_enrollment_cancel', params: { enrollmentId } } },
    ],
  ]);
});

function recoveryStatus(state: 'idle') {
  return {
    enrollmentId: null,
    state,
    createdAtMs: null,
    transitionedAtMs: null,
  } as const;
}
