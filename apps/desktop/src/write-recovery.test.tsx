import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import type { DesktopWrite, DesktopWriteSummary, OperationId } from './bindings';
import { WriteRecovery } from './write-recovery';
import App from './App';
import { RecoveryStorageFullError, type WorkspaceGateway } from './workspace';

const operationId = '018f22e2-79b0-7cc8-98c4-dc0c0c075001' as OperationId;
const write: DesktopWrite = { method: 'memory_create', params: { operationId, scope: { scope: 'global' },
  kind: 'note', title: 'Use TypeScript', bodyMarkdown: 'Keep the compiler strict.', tags: [] } };
const summary: DesktopWriteSummary = { operationId, action: 'Save context', title: 'Use TypeScript', scope: { scope: 'global' } };
function fixture() {
  return {
    pendingWrites: vi.fn().mockResolvedValue({ writes: [summary], nextCursor: null }),
    pendingWrite: vi.fn().mockResolvedValue(write),
    retryWrite: vi.fn().mockResolvedValue({ cleanupPending: false }),
    forgetWrite: vi.fn().mockResolvedValue(undefined),
  };
}
afterEach(cleanup);

it('refreshes suggestions after an inline recovered review clears a quota failure', async () => {
  const gateway = fixture();
  let pending = true;
  gateway.pendingWrite.mockResolvedValue({ method: 'candidate_review', params: { operationId, candidateId: operationId, accepted: true } });
  gateway.retryWrite.mockImplementation(async () => { pending = false; return { cleanupPending: false }; });
  const workspace = { ...gateway, status: async () => ({ vault: 'unlocked' }), projects: async () => [],
    candidates: async () => pending ? [{ id: operationId, proposedMemory: { title: 'Use TypeScript', bodyMarkdown: 'Keep the compiler strict.' }, evidenceSummary: 'From a session', state: 'pending' }] : [],
    reviewCandidate: vi.fn().mockRejectedValue(new RecoveryStorageFullError()),
  } as unknown as WorkspaceGateway;
  render(<App gateway={workspace} />);
  await screen.findByText('Ready on this computer');
  fireEvent.click(screen.getByRole('button', { name: 'Suggestions' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Accept Use TypeScript' }));
  await screen.findByText(/Recovery storage is full/);
  fireEvent.click(await screen.findByRole('button', { name: 'Review change: Use TypeScript' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Retry change' }));
  await screen.findByText('No suggestions to review. Suggestions from a connected harness will appear here.');
  expect(screen.queryByRole('button', { name: 'Accept Use TypeScript' })).not.toBeInTheDocument();
});

it('lets a user clear full recovery storage without leaving or losing the current draft', async () => {
  const gateway = fixture();
  const workspace = { ...gateway, status: async () => ({ vault: 'unlocked' }), projects: async () => [],
    memories: async () => [], createMemory: vi.fn().mockRejectedValue(new RecoveryStorageFullError()),
  } as unknown as WorkspaceGateway;
  render(<App gateway={workspace} />);
  await screen.findByText('Ready on this computer');
  fireEvent.click(screen.getByRole('button', { name: 'Saved context' }));
  fireEvent.change(screen.getByRole('textbox', { name: 'Title' }), { target: { value: 'Unsaved decision' } });
  fireEvent.change(screen.getByRole('textbox', { name: 'What should your harness remember?' }), { target: { value: 'Do not lose this draft.' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save context' }));
  await screen.findByText(/Recovery storage is full/);
  fireEvent.click(await screen.findByRole('button', { name: 'Review change: Use TypeScript' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Dismiss recovery copy' }));
  await screen.findByText('Recovery copy dismissed. Any saved change is still there.');
  expect(screen.getByRole('textbox', { name: 'Title' })).toHaveValue('Unsaved decision');
  expect(screen.getByRole('textbox', { name: 'What should your harness remember?' })).toHaveValue('Do not lose this draft.');
});

it('keeps App navigation locked until an explicit recovery retry finishes', async () => {
  const gateway = fixture();
  let resolve!: (value: { cleanupPending: boolean }) => void;
  gateway.retryWrite.mockImplementation(() => new Promise((done) => { resolve = done; }));
  const workspace = { ...gateway, status: async () => ({ vault: 'unlocked' }), projects: async () => [] } as unknown as WorkspaceGateway;
  render(<App gateway={workspace} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Review change: Use TypeScript' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Retry change' }));
  expect(screen.getByRole('button', { name: 'Saved context' })).toBeDisabled();
  await act(async () => resolve({ cleanupPending: false }));
  expect(screen.getByRole('button', { name: 'Saved context' })).toBeEnabled();
});

it('reads on startup and review, then retries only after an explicit click', async () => {
  const gateway = fixture();
  render(<WriteRecovery gateway={gateway} projects={[]} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Review change: Use TypeScript' }));
  await screen.findByText('Keep the compiler strict.');
  expect(gateway.retryWrite).not.toHaveBeenCalled();
  expect(gateway.forgetWrite).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Retry change' }));
  await screen.findByText(/The change is confirmed saved/);
  expect(gateway.retryWrite).toHaveBeenCalledExactlyOnceWith(write);
  expect(screen.queryByRole('button', { name: 'Retry change' })).not.toBeInTheDocument();
});

it('keeps a failed retry available and explains dismissal without undoing', async () => {
  const gateway = fixture();
  gateway.retryWrite.mockRejectedValue(new Error('reply lost'));
  render(<WriteRecovery gateway={gateway} projects={[]} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Review change: Use TypeScript' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Retry change' }));
  await screen.findByRole('alert');
  expect(screen.getByText('Keep the compiler strict.')).toBeVisible();
  expect(screen.getByText(/It does not delete or undo a saved change/)).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Dismiss recovery copy' }));
  await screen.findByText('Recovery copy dismissed. Any saved change is still there.');
  expect(gateway.forgetWrite).toHaveBeenCalledExactlyOnceWith(operationId);
});

it('reports known success when cleanup fails and prevents overlapping retries', async () => {
  const gateway = fixture();
  let resolve!: (value: { cleanupPending: boolean }) => void;
  gateway.retryWrite.mockImplementation(() => new Promise((done) => { resolve = done; }));
  render(<WriteRecovery gateway={gateway} projects={[]} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Review change: Use TypeScript' }));
  const retry = await screen.findByRole('button', { name: 'Retry change' });
  fireEvent.click(retry); fireEvent.click(retry);
  expect(gateway.retryWrite).toHaveBeenCalledTimes(1);
  resolve({ cleanupPending: true });
  await screen.findByText(/The change is confirmed saved. Its recovery copy could not be cleared/);
  expect(screen.getByRole('button', { name: 'Dismiss recovery copy' })).toBeEnabled();
});

it('retains the next-page cursor after dismissing an earlier copy', async () => {
  const gateway = fixture();
  gateway.pendingWrites.mockResolvedValueOnce({ writes: [summary], nextCursor: operationId })
    .mockResolvedValue({ writes: [], nextCursor: null });
  render(<WriteRecovery gateway={gateway} projects={[]} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Review change: Use TypeScript' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Dismiss recovery copy' }));
  await screen.findByText('Recovery copy dismissed. Any saved change is still there.');
  fireEvent.click(screen.getByRole('button', { name: 'Show more changes' }));
  await waitFor(() => expect(gateway.pendingWrites).toHaveBeenLastCalledWith(operationId));
});
