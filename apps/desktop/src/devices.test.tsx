import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { DevicesScreen } from './devices';
import type {
  ClientError,
  DecimalTimestamp,
  DeviceId,
  DeviceSummary,
  PairingCode,
  PairingId,
  PairingSafetyNumber,
  RecoveryEnrollmentConfirmParams,
  RecoveryEnrollmentHostBeginResult,
  RecoveryEnrollmentHostConfirmResult,
  RecoveryEnrollmentId,
  RecoveryEnrollmentStatus,
  Sha256Digest,
} from './bindings';
import type {
  DeviceGateway,
  PairingCompletionResult,
  PairingDecisionResult,
  PairingInviteResult,
  PairingRequestResult,
  PairingStatusResult,
} from './workspace';

const pairingId = '018f22e2-79b0-7cc8-98c4-dc0c0c075001' as PairingId;
const joinerId = '018f22e2-79b0-7cc8-98c4-dc0c0c075002' as DeviceId;
const currentId = '018f22e2-79b0-7cc8-98c4-dc0c0c075003' as DeviceId;
const requestDigest = '11'.repeat(32) as Sha256Digest;
const changedDigest = '22'.repeat(32) as Sha256Digest;
const fingerprint = '33'.repeat(32) as Sha256Digest;
const code = '01234-ABCDE' as PairingCode;
const safety = '0123-4567-89AB-CDEF-0123' as PairingSafetyNumber;
const createdAt = '1000' as DecimalTimestamp;
const expiresAt = '601000' as DecimalTimestamp;
const enrollmentId = '018f22e2-79b0-7cc8-98c4-dc0c0c076001' as RecoveryEnrollmentId;
const recoveryCreatedAt = '1000' as DecimalTimestamp;
const recoveryExpiresAt = '601000' as DecimalTimestamp;
const recoveryCanaries = ['abandon', 'ability', 'able', 'about'];

const currentDevice: DeviceSummary = {
  deviceId: currentId,
  name: 'Current Mac',
  platform: 'macos',
  state: 'active',
  isCurrent: true,
};

const joiningDevice: DeviceSummary = {
  deviceId: joinerId,
  name: 'Travel Mac',
  platform: 'macos',
  state: 'active',
  isCurrent: true,
};

function recoveryStatus(
  state: RecoveryEnrollmentStatus['state'],
  currentEnrollmentId: RecoveryEnrollmentId | null = null,
): RecoveryEnrollmentStatus {
  return {
    enrollmentId: currentEnrollmentId,
    state,
    createdAtMs: currentEnrollmentId ? recoveryCreatedAt : null,
    transitionedAtMs: currentEnrollmentId ? recoveryCreatedAt : null,
  };
}

const request = (digest = requestDigest): PairingRequestResult => ({
  kind: 'pairing_request',
  data: {
    request: {
      pairingId,
      deviceName: digest === requestDigest ? 'Travel Mac' : 'Changed device',
      platform: 'macos',
      requestedAt: '1001' as DecimalTimestamp,
      keyFingerprint: fingerprint,
      requestDigest: digest,
    },
    status: 'pending',
  },
});

class FakeDeviceGateway implements DeviceGateway {
  devicesValue: DeviceSummary[] = [currentDevice];
  createError: unknown = null;
  confirmError: unknown = null;
  statusQueue: PairingStatusResult[] = [];
  statusCalls = 0;
  decideCalls: Array<{ approve: boolean; digest: Sha256Digest }> = [];
  joinArgs: { code: PairingCode; deviceName: string } | null = null;
  confirmCalls = 0;
  cancelCalls = 0;
  devicesCalls = 0;
  recoveryOverviewValue = recoveryStatus('idle');
  recoveryOverviewQueue: RecoveryEnrollmentStatus[] = [];
  recoveryStatusQueue: RecoveryEnrollmentStatus[] = [];
  recoveryBeginResult: RecoveryEnrollmentHostBeginResult = {
    kind: 'challenge',
    data: {
      enrollmentId,
      confirmationPositions: [1, 7, 13, 24],
      createdAtMs: recoveryCreatedAt,
      expiresAtMs: recoveryExpiresAt,
    },
  };
  recoveryConfirmResult: RecoveryEnrollmentHostConfirmResult = {
    kind: 'complete',
    data: { enrollmentId, device: currentDevice },
  };
  recoveryConfirmError: unknown = null;
  recoveryBeginCalls = 0;
  recoveryConfirmCalls: RecoveryEnrollmentConfirmParams[] = [];
  recoveryStatusCalls: RecoveryEnrollmentId[] = [];
  recoveryCancelCalls: RecoveryEnrollmentId[] = [];
  recoveryCancelError: unknown = null;
  recoveryOverviewCalls = 0;

  async devices() {
    this.devicesCalls += 1;
    return this.devicesValue;
  }

  async recoveryEnrollmentOverview() {
    this.recoveryOverviewCalls += 1;
    return this.recoveryOverviewQueue.shift() ?? this.recoveryOverviewValue;
  }

  async recoveryEnrollmentBegin() {
    this.recoveryBeginCalls += 1;
    return this.recoveryBeginResult;
  }

  async recoveryEnrollmentConfirm(params: RecoveryEnrollmentConfirmParams) {
    this.recoveryConfirmCalls.push(params);
    if (this.recoveryConfirmError) throw this.recoveryConfirmError;
    return this.recoveryConfirmResult;
  }

  async recoveryEnrollmentStatus(nextEnrollmentId: RecoveryEnrollmentId) {
    this.recoveryStatusCalls.push(nextEnrollmentId);
    return this.recoveryStatusQueue.shift() ?? this.recoveryOverviewValue;
  }

  async recoveryEnrollmentCancel(nextEnrollmentId: RecoveryEnrollmentId) {
    this.recoveryCancelCalls.push(nextEnrollmentId);
    if (this.recoveryCancelError) throw this.recoveryCancelError;
  }

  async createPairingInvite(): Promise<PairingInviteResult> {
    if (this.createError) throw this.createError;
    return {
      kind: 'pairing_invite',
      data: {
        invite: { pairingId, code, createdAt, expiresAt },
        status: 'pending',
      },
    };
  }

  async joinPairing(nextCode: PairingCode, deviceName: string): Promise<PairingRequestResult> {
    this.joinArgs = { code: nextCode, deviceName };
    return request();
  }

  async pairingStatus(): Promise<PairingStatusResult> {
    this.statusCalls += 1;
    return this.statusQueue.shift() ?? request();
  }

  async decidePairing(
    _pairingId: PairingId,
    digest: Sha256Digest,
    approve: boolean,
  ): Promise<PairingDecisionResult> {
    this.decideCalls.push({ approve, digest });
    return approve
      ? {
          kind: 'pairing_approval',
          data: {
            approval: {
              request: request().data.request,
              safetyNumber: safety,
            },
          },
        }
      : {
          ...request(),
          data: { ...request().data, status: 'rejected' },
        };
  }

  async confirmPairing(): Promise<PairingCompletionResult> {
    this.confirmCalls += 1;
    if (this.confirmError) throw this.confirmError;
    this.devicesValue = [joiningDevice];
    return {
      kind: 'pairing_completion',
      data: { completion: { pairingId, device: joiningDevice } },
    };
  }

  async cancelPairing() {
    this.cancelCalls += 1;
  }
}

beforeEach(() => {
  vi.spyOn(Date, 'now').mockReturnValue(1_000);
  HTMLDialogElement.prototype.showModal = function showModal() {
    this.setAttribute('open', '');
  };
  HTMLDialogElement.prototype.close = function close() {
    this.removeAttribute('open');
    this.dispatchEvent(new Event('close'));
  };
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.useRealTimers();
  localStorage.clear();
  sessionStorage.clear();
});

describe('DevicesScreen', () => {
  it('shows only the four challenged recovery words and confirms the exact projection', async () => {
    const gateway = new FakeDeviceGateway();
    render(<DevicesScreen gateway={gateway} pollIntervalMs={60_000} />);
    await screen.findByText('Current Mac');

    fireEvent.click(await screen.findByRole('button', { name: 'Set up recovery' }));
    const form = await screen.findByRole('form', { name: 'Confirm recovery phrase' });
    expect(within(form).getAllByRole('textbox')).toHaveLength(4);
    expect(form).toHaveTextContent('10 minutes remaining');
    for (const [index, position] of [1, 7, 13, 24].entries()) {
      const input = within(form).getByRole('textbox', { name: `Word ${position}` });
      expect(input).toHaveAttribute('autocomplete', 'off');
      expect(input).toHaveAttribute('spellcheck', 'false');
      fireEvent.change(input, { target: { value: recoveryCanaries[index] } });
    }

    fireEvent.submit(form);
    await waitFor(() => expect(gateway.recoveryConfirmCalls).toHaveLength(1));
    expect(gateway.recoveryConfirmCalls).toEqual([
      {
        enrollmentId,
        confirmations: [
          { position: 1, word: 'abandon' },
          { position: 7, word: 'ability' },
          { position: 13, word: 'able' },
          { position: 24, word: 'about' },
        ],
      },
    ]);
    expect(gateway.recoveryBeginCalls).toBe(1);
    expect(await screen.findByRole('status')).toHaveTextContent('Recovery is ready.');
    expect(screen.getByRole('heading', { name: 'Recovery' })).toHaveFocus();
    expect(gateway.devicesCalls).toBe(2);
    for (const canary of recoveryCanaries) {
      expect(document.documentElement.outerHTML).not.toContain(canary);
    }
  });

  it('resumes submitting recovery by durable ID and never offers a replacement setup', async () => {
    const gateway = new FakeDeviceGateway();
    gateway.recoveryOverviewValue = recoveryStatus('submitting', enrollmentId);
    gateway.recoveryStatusQueue = [recoveryStatus('complete', enrollmentId)];
    render(<DevicesScreen gateway={gateway} pollIntervalMs={5} />);

    expect(await screen.findByRole('status')).toHaveTextContent('Recovery setup is being secured.');
    await waitFor(() => expect(gateway.recoveryStatusCalls).toEqual([enrollmentId]));
    expect(await screen.findByRole('status')).toHaveTextContent('Recovery is ready.');
    expect(screen.queryByRole('button', { name: 'Set up recovery' })).not.toBeInTheDocument();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it('cancels a lost memory-only challenge after remount without redisplaying words', async () => {
    const gateway = new FakeDeviceGateway();
    gateway.recoveryOverviewValue = recoveryStatus('awaiting_confirmation', enrollmentId);
    render(<DevicesScreen gateway={gateway} />);

    expect(await screen.findByRole('status')).toHaveTextContent(
      'The previous recovery phrase is no longer valid. Start setup again.',
    );
    expect(gateway.recoveryCancelCalls).toEqual([enrollmentId]);
    expect(screen.getByRole('button', { name: 'Set up recovery' })).toBeEnabled();
    expect(document.documentElement.outerHTML).not.toContain('recoveryPhraseWords');
  });

  it('recovers from an already-consumed remount cancellation only after verifying Idle', async () => {
    const gateway = new FakeDeviceGateway();
    gateway.recoveryOverviewQueue = [
      recoveryStatus('awaiting_confirmation', enrollmentId),
      recoveryStatus('idle'),
    ];
    gateway.recoveryCancelError = {
      code: 'invalid_request',
      message: 'session already gone',
      fieldPath: null,
      retryable: false,
    } satisfies ClientError;
    render(<DevicesScreen gateway={gateway} />);

    expect(await screen.findByRole('status')).toHaveTextContent(
      'The previous recovery phrase is no longer valid. Start setup again.',
    );
    expect(gateway.recoveryCancelCalls).toEqual([enrollmentId]);
    expect(gateway.recoveryOverviewCalls).toBe(2);
    expect(screen.getByRole('button', { name: 'Set up recovery' })).toBeEnabled();
  });

  it('keeps an explicit cleanup retry when the daemon is still awaiting confirmation', async () => {
    const gateway = new FakeDeviceGateway();
    gateway.recoveryOverviewQueue = [
      recoveryStatus('awaiting_confirmation', enrollmentId),
      recoveryStatus('awaiting_confirmation', enrollmentId),
    ];
    let attempts = 0;
    gateway.recoveryEnrollmentCancel = async (nextEnrollmentId) => {
      gateway.recoveryCancelCalls.push(nextEnrollmentId);
      attempts += 1;
      if (attempts === 1) throw new Error('transient cleanup race');
    };
    render(<DevicesScreen gateway={gateway} />);

    const retry = await screen.findByRole('button', { name: 'Retry recovery cleanup' });
    expect(screen.getByRole('alert')).toHaveTextContent(
      'The previous recovery setup could not be canceled. Try again.',
    );
    fireEvent.click(retry);
    expect(await screen.findByRole('status')).toHaveTextContent(
      'The previous recovery phrase is no longer valid. Start setup again.',
    );
    expect(gateway.recoveryCancelCalls).toEqual([enrollmentId, enrollmentId]);
    expect(screen.getByRole('button', { name: 'Set up recovery' })).toBeEnabled();
  });

  it('keeps recovery idle when the native phrase display is declined', async () => {
    const gateway = new FakeDeviceGateway();
    gateway.recoveryBeginResult = { kind: 'status', data: recoveryStatus('idle') };
    render(<DevicesScreen gateway={gateway} />);
    await screen.findByText('Current Mac');

    fireEvent.click(await screen.findByRole('button', { name: 'Set up recovery' }));
    await waitFor(() => expect(gateway.recoveryBeginCalls).toBe(1));
    expect(screen.getByRole('button', { name: 'Set up recovery' })).toBeEnabled();
    expect(screen.queryByRole('form', { name: 'Confirm recovery phrase' })).not.toBeInTheDocument();
    expect(gateway.recoveryConfirmCalls).toHaveLength(0);
  });

  it('keeps four entries after native approval is declined, then clears them on explicit cancel', async () => {
    const gateway = new FakeDeviceGateway();
    gateway.recoveryConfirmResult = { kind: 'canceled' };
    render(<DevicesScreen gateway={gateway} />);
    await screen.findByText('Current Mac');
    fireEvent.click(await screen.findByRole('button', { name: 'Set up recovery' }));
    const form = await screen.findByRole('form', { name: 'Confirm recovery phrase' });
    fillRecoveryWords(form);
    fireEvent.submit(form);

    expect(await screen.findByRole('status')).toHaveTextContent(
      'Recovery confirmation was canceled. Your four entries are still here.',
    );
    expect(within(form).getByRole('textbox', { name: 'Word 1' })).toHaveValue('abandon');
    fireEvent.click(within(form).getByRole('button', { name: 'Cancel recovery setup' }));
    expect(await screen.findByRole('status')).toHaveTextContent(
      'Recovery setup canceled. The previous phrase is no longer valid.',
    );
    expect(gateway.recoveryCancelCalls).toEqual([enrollmentId]);
    for (const canary of recoveryCanaries) {
      expect(document.documentElement.outerHTML).not.toContain(canary);
    }
  });

  it('clears every entered word on mismatch and on unmount', async () => {
    const gateway = new FakeDeviceGateway();
    gateway.recoveryConfirmError = {
      code: 'conflict',
      message: 'abandon ability able about must not escape',
      fieldPath: null,
      retryable: false,
    } satisfies ClientError;
    const first = render(<DevicesScreen gateway={gateway} />);
    await screen.findByText('Current Mac');
    fireEvent.click(await screen.findByRole('button', { name: 'Set up recovery' }));
    const form = await screen.findByRole('form', { name: 'Confirm recovery phrase' });
    fillRecoveryWords(form);
    fireEvent.submit(form);
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'The recovery words did not match. Start setup again with a new phrase.',
    );
    expect(screen.getByRole('alert')).not.toHaveTextContent('must not escape');
    for (const canary of recoveryCanaries) {
      expect(document.documentElement.outerHTML).not.toContain(canary);
    }
    first.unmount();

    const secondGateway = new FakeDeviceGateway();
    const second = render(<DevicesScreen gateway={secondGateway} />);
    await screen.findByText('Current Mac');
    fireEvent.click(await screen.findByRole('button', { name: 'Set up recovery' }));
    fillRecoveryWords(await screen.findByRole('form', { name: 'Confirm recovery phrase' }));
    second.unmount();
    expect(secondGateway.recoveryCancelCalls).toEqual([enrollmentId]);
    for (const canary of recoveryCanaries) {
      expect(document.documentElement.outerHTML).not.toContain(canary);
    }
  });

  it('cancels a challenge that returns after the screen unmounts', async () => {
    const gateway = new FakeDeviceGateway();
    const challengeResult = gateway.recoveryBeginResult;
    let resolveBegin: (result: RecoveryEnrollmentHostBeginResult) => void = () => undefined;
    gateway.recoveryEnrollmentBegin = () =>
      new Promise((resolve) => {
        resolveBegin = resolve;
      });
    const view = render(<DevicesScreen gateway={gateway} />);
    await screen.findByText('Current Mac');
    fireEvent.click(await screen.findByRole('button', { name: 'Set up recovery' }));

    view.unmount();
    resolveBegin(challengeResult);
    await waitFor(() => expect(gateway.recoveryCancelCalls).toEqual([enrollmentId]));
    expect(document.documentElement.outerHTML).not.toContain('recoveryPhraseWords');
  });

  it('expires a memory-only challenge at the exact deadline and clears its words', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(1_000);
    const gateway = new FakeDeviceGateway();
    render(<DevicesScreen gateway={gateway} />);
    await act(async () => undefined);
    fireEvent.click(screen.getByRole('button', { name: 'Set up recovery' }));
    await act(async () => undefined);
    const form = screen.getByRole('form', { name: 'Confirm recovery phrase' });
    fillRecoveryWords(form);

    vi.setSystemTime(601_000);
    act(() => vi.advanceTimersByTime(1_000));
    expect(screen.getByRole('alert')).toHaveTextContent(
      'Recovery setup expired. Start again with a new phrase.',
    );
    expect(gateway.recoveryCancelCalls).toEqual([enrollmentId]);
    for (const canary of recoveryCanaries) {
      expect(document.documentElement.outerHTML).not.toContain(canary);
    }
  });

  it('fails closed for conflict and hosted-unavailable recovery states', async () => {
    const conflictGateway = new FakeDeviceGateway();
    conflictGateway.recoveryOverviewValue = recoveryStatus('conflict', enrollmentId);
    const first = render(<DevicesScreen gateway={conflictGateway} />);
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Recovery setup conflicts with the hosted workspace. Contact support before trying again.',
    );
    expect(screen.queryByRole('button', { name: 'Set up recovery' })).not.toBeInTheDocument();
    first.unmount();

    const unavailableGateway = new FakeDeviceGateway();
    unavailableGateway.recoveryEnrollmentOverview = async () => {
      throw {
        code: 'harness_unsupported',
        message: 'must not be shown',
        fieldPath: null,
        retryable: false,
      } satisfies ClientError;
    };
    render(<DevicesScreen gateway={unavailableGateway} />);
    expect(await screen.findByText(
      'Recovery setup needs the hosted workspace service and is not available in this build.',
    )).toBeVisible();
    expect(screen.queryByRole('button', { name: 'Set up recovery' })).not.toBeInTheDocument();
  });

  it('keeps trusted devices visible when hosted pairing is unavailable', async () => {
    const gateway = new FakeDeviceGateway();
    gateway.createError = {
      code: 'harness_unsupported',
      message: 'redacted daemon message',
      fieldPath: null,
      retryable: false,
    } satisfies ClientError;
    render(<DevicesScreen gateway={gateway} />);

    expect(await screen.findByText('Current Mac')).toBeVisible();
    expect(screen.getByText('Current device')).toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: 'Create pairing code' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Pairing needs the hosted device service and is not available in this build.',
    );
    expect(screen.getByText('Current Mac')).toBeVisible();
  });

  it('shows the one-time code and expiry, then cancels without hiding devices', async () => {
    const gateway = new FakeDeviceGateway();
    gateway.statusQueue = [
      {
        kind: 'pairing_invite_status',
        data: { invite: { pairingId, createdAt, expiresAt }, status: 'pending' },
      },
    ];
    render(<DevicesScreen gateway={gateway} pollIntervalMs={60_000} />);
    await screen.findByText('Current Mac');

    fireEvent.click(screen.getByRole('button', { name: 'Create pairing code' }));
    expect(await screen.findByText('01234-ABCDE')).toBeVisible();
    expect(screen.getByText(/Expires/)).toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: 'Cancel pairing' }));
    expect(await screen.findByRole('status')).toHaveTextContent('Pairing canceled.');
    expect(gateway.cancelCalls).toBe(1);
    expect(screen.getByText('Current Mac')).toBeVisible();
  });

  it('returns to a new pairing after provider-delivered cancellation', async () => {
    const gateway = new FakeDeviceGateway();
    gateway.statusQueue = [
      {
        kind: 'pairing_invite_status',
        data: { invite: { pairingId, createdAt, expiresAt }, status: 'canceled' },
      },
    ];
    render(<DevicesScreen gateway={gateway} pollIntervalMs={5} />);
    await screen.findByText('Current Mac');

    fireEvent.click(screen.getByRole('button', { name: 'Create pairing code' }));
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('Pairing canceled.'));
    expect(screen.queryByText(code)).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Create pairing code' })).toBeEnabled();
    expect(screen.getByRole('form', { name: 'Join a device' })).toBeVisible();
  });

  it('submits only the user code and device name and renders no key-shaped fields', async () => {
    const gateway = new FakeDeviceGateway();
    render(<DevicesScreen gateway={gateway} pollIntervalMs={60_000} />);
    await screen.findByText('Current Mac');

    fireEvent.change(screen.getByRole('textbox', { name: 'Pairing code' }), {
      target: { value: '01234-ABCDE' },
    });
    fireEvent.change(screen.getByRole('textbox', { name: 'Device name' }), {
      target: { value: 'Travel Mac' },
    });
    fireEvent.submit(screen.getByRole('form', { name: 'Join a device' }));
    await screen.findByText('Waiting for approval on the trusted device.');
    expect(gateway.joinArgs).toEqual({ code, deviceName: 'Travel Mac' });
    expect(document.body.textContent).not.toMatch(
      /signingPublicKey|wrappingPublicKey|requestNonce|privateKey|workspaceKey/,
    );
    fireEvent.click(screen.getByRole('button', { name: 'Stop checking' }));
    expect(screen.getByRole('status')).toHaveTextContent(
      'Stopped checking this pairing. It can still be approved before expiry, but this device will not trust it without confirmation.',
    );
    expect(gateway.cancelCalls).toBe(0);
    expect(screen.getByRole('form', { name: 'Join a device' })).toBeVisible();
  });

  it('rejects a changed request digest before a dialog decision and restores focus', async () => {
    const gateway = new FakeDeviceGateway();
    gateway.statusQueue = [request(), request(changedDigest)];
    render(<DevicesScreen gateway={gateway} pollIntervalMs={5} />);
    await screen.findByText('Current Mac');
    fireEvent.click(screen.getByRole('button', { name: 'Create pairing code' }));
    const trigger = await screen.findByRole('button', { name: 'Review pairing request' });
    fireEvent.click(trigger);

    const dialog = screen.getByRole('dialog', { name: 'Approve new device' });
    expect(dialog).toHaveTextContent('Travel Mac');
    expect(dialog).toHaveTextContent('Key fingerprint');
    expect(dialog).toHaveTextContent(fingerprint);
    expect(dialog).toHaveTextContent(requestDigest);
    fireEvent.click(within(dialog).getByRole('button', { name: 'Approve device' }));

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'The pairing request changed. Review it again.',
    );
    expect(gateway.decideCalls).toHaveLength(0);
    expect(trigger).toHaveFocus();
  });

  it('shows the approver-only full safety number after an exact approval', async () => {
    const gateway = new FakeDeviceGateway();
    gateway.statusQueue = [request(), request()];
    render(<DevicesScreen gateway={gateway} pollIntervalMs={5} />);
    await screen.findByText('Current Mac');
    fireEvent.click(screen.getByRole('button', { name: 'Create pairing code' }));
    const trigger = await screen.findByRole('button', { name: 'Review pairing request' });
    fireEvent.click(trigger);
    fireEvent.click(screen.getByRole('button', { name: 'Approve device' }));

    expect(await screen.findByText('0123-4567-89AB-CDEF-0123')).toBeVisible();
    expect(screen.getByRole('status')).toHaveTextContent(
      'Compare all five groups on the joining device.',
    );
    expect(gateway.decideCalls).toEqual([{ approve: true, digest: requestDigest }]);
    expect(trigger).toHaveFocus();
    fireEvent.click(screen.getByRole('button', { name: 'Done comparing' }));
    expect(screen.getByRole('button', { name: 'Create pairing code' })).toBeEnabled();
  });

  it('keeps rejection terminal after the exact yes-or-no review', async () => {
    const gateway = new FakeDeviceGateway();
    gateway.statusQueue = [request(), request()];
    render(<DevicesScreen gateway={gateway} pollIntervalMs={5} />);
    await screen.findByText('Current Mac');
    fireEvent.click(screen.getByRole('button', { name: 'Create pairing code' }));
    const trigger = await screen.findByRole('button', { name: 'Review pairing request' });
    fireEvent.click(trigger);
    fireEvent.click(screen.getByRole('button', { name: 'Reject device' }));

    expect(await screen.findByRole('status')).toHaveTextContent('Pairing request rejected.');
    expect(gateway.decideCalls).toEqual([{ approve: false, digest: requestDigest }]);
    expect(screen.queryByText(safety)).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
  });

  it('requires all five safety groups, reports a mismatch safely, and completes trust', async () => {
    const gateway = new FakeDeviceGateway();
    gateway.statusQueue = [
      {
        ...request(),
        data: { ...request().data, status: 'approved' },
      },
    ];
    render(<DevicesScreen gateway={gateway} pollIntervalMs={5} />);
    await screen.findByText('Current Mac');
    fireEvent.change(screen.getByRole('textbox', { name: 'Pairing code' }), {
      target: { value: '01234-ABCDE' },
    });
    fireEvent.change(screen.getByRole('textbox', { name: 'Device name' }), {
      target: { value: 'Travel Mac' },
    });
    fireEvent.submit(screen.getByRole('form', { name: 'Join a device' }));
    const input = await screen.findByRole('textbox', { name: 'Safety number' });
    await waitFor(() => expect(gateway.statusCalls).toBe(1));

    fireEvent.change(input, { target: { value: '0123' } });
    fireEvent.submit(screen.getByRole('form', { name: 'Confirm safety number' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Enter all five safety-number groups.',
    );
    expect(gateway.confirmCalls).toBe(0);

    gateway.confirmError = {
      code: 'conflict',
      message: 'must not be shown',
      fieldPath: null,
      retryable: false,
    } satisfies ClientError;
    fireEvent.change(input, { target: { value: safety } });
    fireEvent.submit(screen.getByRole('form', { name: 'Confirm safety number' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'The safety number did not match. Check all five groups.',
    );
    expect(screen.getByRole('alert')).not.toHaveTextContent('must not be shown');

    gateway.confirmError = null;
    fireEvent.submit(screen.getByRole('form', { name: 'Confirm safety number' }));
    expect(await screen.findByText('This device is now trusted.')).toBeVisible();
    expect(await screen.findByText('Travel Mac')).toBeVisible();
    expect(screen.getByText('Current device')).toBeVisible();
  });

  it('fails closed when a joining flow receives approver-only safety output', async () => {
    const gateway = new FakeDeviceGateway();
    gateway.statusQueue = [
      {
        kind: 'pairing_approval',
        data: { approval: { request: request().data.request, safetyNumber: safety } },
      },
    ];
    render(<DevicesScreen gateway={gateway} pollIntervalMs={5} />);
    await screen.findByText('Current Mac');
    fireEvent.change(screen.getByRole('textbox', { name: 'Pairing code' }), {
      target: { value: code },
    });
    fireEvent.change(screen.getByRole('textbox', { name: 'Device name' }), {
      target: { value: 'Travel Mac' },
    });
    fireEvent.submit(screen.getByRole('form', { name: 'Join a device' }));

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Pairing status was not valid for this device.',
    );
    expect(screen.queryByText(safety)).not.toBeInTheDocument();
  });
});

function fillRecoveryWords(form: HTMLElement) {
  for (const [index, position] of [1, 7, 13, 24].entries()) {
    fireEvent.change(within(form).getByRole('textbox', { name: `Word ${position}` }), {
      target: { value: recoveryCanaries[index] },
    });
  }
}
