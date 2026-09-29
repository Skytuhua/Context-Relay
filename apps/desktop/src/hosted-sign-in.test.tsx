import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import type { HostedAuthStartParams, HostedAuthStatus, OperationId } from './bindings';
import { HostedSignIn } from './hosted-sign-in';

const generation = '019924bb-5300-7000-8000-000000000001' as OperationId;
const state = (phase: HostedAuthStatus['state']): HostedAuthStatus => ({ generation, state: phase });
const signedOut = state({ phase: 'signed_out', remoteRevoked: null });
function fixture() {
  return {
    hostedAuthStatus: vi.fn(async () => signedOut),
    hostedAuthStart: vi.fn(async (params: HostedAuthStartParams): Promise<HostedAuthStatus> => ({ generation: params.operationId, state: { phase: 'signing_in' } })),
    hostedAuthCancel: vi.fn(async () => signedOut),
    hostedAuthLogout: vi.fn(async () => signedOut),
  };
}
async function mount(api: ReturnType<typeof fixture>) {
  vi.useFakeTimers();
  const view = render(<HostedSignIn gateway={api} />);
  await act(async () => {});
  return view;
}
afterEach(() => { cleanup(); vi.useRealTimers(); });

it('opens one attempt and cancels only its acknowledged generation', async () => {
  const api = fixture();
  let finish!: (value: HostedAuthStatus) => void;
  api.hostedAuthStart.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  await mount(api);
  fireEvent.click(screen.getByRole('button', { name: 'Sign in with GitHub' }));
  fireEvent.click(screen.getByRole('button', { name: 'Sign in with GitHub' }));
  expect(api.hostedAuthStart).toHaveBeenCalledTimes(1);
  const params = api.hostedAuthStart.mock.calls[0][0];
  expect(params.expectedGeneration).toBe(generation);
  await act(async () => { finish({ generation: params.operationId, state: { phase: 'signing_in' } }); });
  fireEvent.click(screen.getByRole('button', { name: 'Cancel sign-in' }));
  await act(async () => {});
  expect(api.hostedAuthCancel).toHaveBeenCalledWith(params.operationId);
});

it('reuses an uncertain start without displaying native error details', async () => {
  const api = fixture();
  api.hostedAuthStart.mockRejectedValueOnce(new Error('PRIVATE TOKEN'));
  await mount(api);
  fireEvent.click(screen.getByRole('button', { name: 'Sign in with GitHub' }));
  await act(async () => {});
  expect(screen.queryByText(/PRIVATE TOKEN/)).not.toBeInTheDocument();
  await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
  fireEvent.click(screen.getByRole('button', { name: 'Sign in with GitHub' }));
  await act(async () => {});
  expect(api.hostedAuthStart.mock.calls[1][0]).toEqual(api.hostedAuthStart.mock.calls[0][0]);
});

it('ignores a poll started before an acknowledged sign-in action', async () => {
  const api = fixture();
  await mount(api);
  let finishPoll!: (value: HostedAuthStatus) => void;
  api.hostedAuthStatus.mockImplementationOnce(() => new Promise(resolve => { finishPoll = resolve; }));
  await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
  fireEvent.click(screen.getByRole('button', { name: 'Sign in with GitHub' }));
  await act(async () => {});
  await act(async () => { finishPoll(signedOut); });
  expect(screen.getByRole('button', { name: 'Cancel sign-in' })).toBeVisible();
});

it('distinguishes local sign-out from unconfirmed online revocation', async () => {
  const api = fixture();
  api.hostedAuthStatus.mockResolvedValue(state({ phase: 'connected' }));
  api.hostedAuthLogout.mockResolvedValue(state({ phase: 'signed_out', remoteRevoked: false }));
  await mount(api);
  fireEvent.click(screen.getByRole('button', { name: 'Sign out' }));
  await act(async () => {});
  expect(api.hostedAuthLogout).toHaveBeenCalledWith(generation);
  expect(screen.getByText(/Ending the online session could not be confirmed/)).toBeVisible();
});

it('ignores obsolete actions after the gateway changes and keeps disabled sign-in unavailable', async () => {
  const api = fixture();
  let finish!: (value: HostedAuthStatus) => void;
  api.hostedAuthStart.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  const view = await mount(api);
  fireEvent.click(screen.getByRole('button', { name: 'Sign in with GitHub' }));
  const replacement = fixture();
  replacement.hostedAuthStatus.mockResolvedValue(state({ phase: 'disabled' }));
  view.rerender(<HostedSignIn gateway={replacement} />);
  await act(async () => {});
  await act(async () => { finish(state({ phase: 'connected' })); });
  expect(screen.getByText('Cloud sign-in is not available in this build.')).toBeVisible();
  expect(screen.queryByRole('button', { name: 'Sign out' })).not.toBeInTheDocument();
});
