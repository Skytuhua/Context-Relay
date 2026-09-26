import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';

import { DevicesScreen } from './devices';
import type { WorkspaceGateway } from './workspace';

// jsdom implements neither showModal nor close, so the dialog API must be
// stubbed for the open/close paths to run at all.
beforeEach(() => {
  HTMLDialogElement.prototype.showModal = function () { this.open = true; };
  HTMLDialogElement.prototype.close = function () { this.open = false; };
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

const device = {
  deviceId: '018f22e2-79b0-7cc8-98c4-dc0c0c075020',
  name: 'Work laptop',
  platform: 'windows',
  state: 'active',
  isCurrent: false,
};

function renderDevices(revoke: () => Promise<never>) {
  const gateway = {
    devices: vi.fn().mockResolvedValue([device]),
    deviceRevocationIntents: vi.fn().mockResolvedValue([]),
    pairingStatus: vi.fn().mockResolvedValue({ kind: 'empty' }),
    pairingCode: vi.fn().mockResolvedValue(null),
    revokeDevice: vi.fn(revoke),
    deviceRevocationStatus: vi.fn(),
    cancelDeviceRevocation: vi.fn(),
    pendingWrites: vi.fn().mockResolvedValue([]),
    forgetWrite: vi.fn(),
  } as unknown as WorkspaceGateway;
  render(<DevicesScreen gateway={gateway} />);
  return gateway;
}

it('shows a rejected revocation inside the dialog that is still open', async () => {
  renderDevices(() => Promise.reject(new Error('daemon refused')));
  const revoke = await screen.findByRole('button', { name: 'Revoke Work laptop' });
  fireEvent.click(revoke);
  // Several dialogs are mounted; select the revocation one by its labelled title.
  const dialog = document.querySelector('#device-revocation-title')?.closest('dialog') as HTMLDialogElement;
  expect(dialog).toBeTruthy();
  fireEvent.click(within(dialog).getByRole('button', { name: 'Revoke device', hidden: true }));

  // The failure must be visible in the dialog the user is looking at.
  await waitFor(() => expect(dialog).toHaveTextContent('The revocation request could not be confirmed.'));
  expect(dialog.querySelector('[role="alert"]')).toBeTruthy();
});

it('does not leave a stale revocation error when the dialog is reopened', async () => {
  renderDevices(() => Promise.reject(new Error('daemon refused')));
  const revoke = await screen.findByRole('button', { name: 'Revoke Work laptop' });
  fireEvent.click(revoke);
  const dialog = document.querySelector('#device-revocation-title')?.closest('dialog') as HTMLDialogElement;
  fireEvent.click(within(dialog).getByRole('button', { name: 'Revoke device', hidden: true }));
  await waitFor(() => expect(dialog).toHaveTextContent('could not be confirmed'));

  dialog.close(); // the dialog has no explicit close button before a revocation exists
  const again = await screen.findByRole('button', { name: 'Revoke Work laptop' });
  fireEvent.click(again);
  const reopened = document.querySelector('#device-revocation-title')?.closest('dialog') as HTMLDialogElement;
  expect(reopened.textContent).not.toContain('could not be confirmed');
});
