import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';

import { AccountLifecyclePanel } from './account-lifecycle';
import type { WorkspaceGateway } from './workspace';

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

const id = (n: number) => `018f22e2-79b0-7cc8-98c4-dc0c0c0750${String(n).padStart(2, '0')}` as never;

const firstPage = Array.from({ length: 50 }, (_, i) => ({
  operationId: id(i + 10),
  action: 'beginDeletion' as const,
  state: 'rejected' as const,
  createdAt: String(1758000000000 + i),
}));
const secondPage = Array.from({ length: 3 }, (_, i) => ({
  operationId: id(i + 80),
  action: 'beginDeletion' as const,
  state: 'rejected' as const,
  createdAt: String(1758000000000 + i),
}));

function renderHistory() {
  const seen: (string | null)[] = [];
  const gateway = {
    accountDeletionStatus: vi.fn().mockResolvedValue({ state: 'active' }),
    accountDeletionIntents: vi.fn(async (after: string | null) => {
      seen.push(after);
      return after === null ? firstPage : secondPage;
    }),
  } as unknown as WorkspaceGateway;
  render(<AccountLifecyclePanel gateway={gateway} />);
  return { gateway, seen };
}

it('can return to the first page after paging forward', async () => {
  const { seen } = renderHistory();
  expect(await screen.findByRole('button', { name: 'Next requests' })).toBeTruthy();

  fireEvent.click(screen.getByRole('button', { name: 'Next requests' }));
  expect(await screen.findByRole('button', { name: 'Previous requests' })).toBeTruthy();
  // The original request must be reachable again — it is the one a retry needs.
  expect(seen).toEqual([null, firstPage[49].operationId]);

  fireEvent.click(screen.getByRole('button', { name: 'Previous requests' }));
  await waitFor(() => expect(seen).toEqual([null, firstPage[49].operationId, null]));
  // Back on page 1, so the very first request is listed again.
  expect(await screen.findByRole('button', { name: new RegExp(firstPage[0].operationId) })).toBeTruthy();
});

it('hides Previous on the first page', async () => {
  renderHistory();
  await screen.findByRole('button', { name: 'Next requests' });
  expect(screen.queryByRole('button', { name: 'Previous requests' })).toBeNull();
});

it('keeps the original request reviewable after paging forward and back', async () => {
  const { seen } = renderHistory();
  await screen.findByRole('button', { name: 'Next requests' });
  const original = firstPage[0].operationId;

  fireEvent.click(screen.getByRole('button', { name: 'Next requests' }));
  await screen.findByRole('button', { name: 'Previous requests' });
  fireEvent.click(screen.getByRole('button', { name: 'Previous requests' }));
  await waitFor(() => expect(seen.length).toBe(3));

  expect(await screen.findByRole('button', { name: new RegExp(original) })).toBeTruthy();
});

it('offers Next on a short page only while results remain', async () => {
  renderHistory();
  await screen.findByRole('button', { name: 'Next requests' });
  fireEvent.click(screen.getByRole('button', { name: 'Next requests' }));

  // A partial page means the history is exhausted, so no further Next.
  await waitFor(() => expect(screen.getByText(/Showing page 2/)).toBeTruthy());
  expect(screen.queryByRole('button', { name: 'Next requests' })).toBeNull();
});
