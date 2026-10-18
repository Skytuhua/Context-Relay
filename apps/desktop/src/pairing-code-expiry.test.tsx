import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';

import { DevicesScreen } from './devices';
import type { WorkspaceGateway } from './workspace';

beforeEach(() => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  HTMLDialogElement.prototype.showModal = function () { this.open = true; };
  HTMLDialogElement.prototype.close = function () { this.open = false; };
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.restoreAllMocks();
});

const MINUTE = 60_000;

function renderPairing(expiresInMs: number) {
  const gateway = {
    devices: vi.fn().mockResolvedValue([]),
    deviceRevocationIntents: vi.fn().mockResolvedValue([]),
    pendingWrites: vi.fn().mockResolvedValue([]),
    forgetWrite: vi.fn(),
    // The invite is produced by createPairingInvite; pairingStatus only reports
    // the resulting state.
    createPairingInvite: vi.fn().mockResolvedValue({
      kind: 'pairing_invite',
      data: {
        invite: {
          pairingId: '018f22e2-79b0-7cc8-98c4-dc0c0c075030',
          code: 'WXYZ-1234',
          createdAt: String(Date.now()),
          expiresAt: String(Date.now() + expiresInMs),
        },
        status: 'pending',
      },
    }),
    pairingStatus: vi.fn().mockResolvedValue({ kind: 'empty' }),
    cancelPairing: vi.fn().mockResolvedValue(undefined),
  } as unknown as WorkspaceGateway;
  render(<DevicesScreen gateway={gateway} />);
  return gateway;
}

/** Generate a pairing code, which is what surfaces the countdown. */
async function createCode() {
  fireEvent.click(await screen.findByRole('button', { name: /create.*code|generate.*code|new code/i }));
  return screen.findByText('WXYZ-1234');
}

it('tells the user a code expired instead of showing 0 seconds remaining', async () => {
  renderPairing(MINUTE);
  await createCode();
  expect(await screen.findByText(/remaining$/)).toBeTruthy();

  // Cross the expiry.
  await vi.advanceTimersByTimeAsync(2 * MINUTE);
  await waitFor(() => expect(screen.getByText('This code expired. Close this pairing, then create a new code.')).toBeTruthy());
  expect(screen.queryByText(/0 seconds remaining/)).toBeNull();
});

it('closes the expired pairing before offering a separate new code action', async () => {
  const gateway = renderPairing(MINUTE);
  await createCode();
  await screen.findByText(/remaining$/);
  await vi.advanceTimersByTimeAsync(2 * MINUTE);
  fireEvent.click(await screen.findByRole('button', { name: 'Close expired pairing' }));
  await screen.findByRole('button', { name: 'Create pairing code' });
  expect(gateway.cancelPairing).toHaveBeenCalledExactlyOnceWith('018f22e2-79b0-7cc8-98c4-dc0c0c075030');
  expect(gateway.createPairingInvite).toHaveBeenCalledTimes(1);
  expect(screen.queryByText('WXYZ-1234')).not.toBeInTheDocument();
  expect(screen.getByText('Expired pairing closed. Select Create pairing code to try again.')).toBeInTheDocument();
});

it('keeps the ordinary label while the code is still valid', async () => {
  renderPairing(10 * MINUTE);
  await createCode();
  await screen.findByText(/remaining$/);
  expect(screen.getByRole('button', { name: 'Cancel pairing' })).toBeTruthy();
  expect(screen.queryByText(/expired/)).toBeNull();
});
