import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';

import { AccountLifecyclePanel } from './account-lifecycle';
import type { WorkspaceGateway } from './workspace';

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

const id = (n: number) => `018f22e2-79b0-7cc8-98c4-${String(n).padStart(12, '0')}` as never;

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

function renderHistory(pages = [firstPage, secondPage]) {
  const seen: (string | null)[] = [];
  const gateway = {
    accountDeletionStatus: vi.fn().mockResolvedValue({ state: 'active' }),
    accountDeletionIntents: vi.fn(async (after: string | null) => {
      seen.push(after);
      if (after === null) return pages[0];
      const previousPage = pages.findIndex(page => page.at(-1)?.operationId === after);
      if (previousPage < 0) throw new Error('Unexpected history cursor');
      return pages[previousPage + 1] ?? [];
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

it('moves backward and forward through three pages without losing earlier requests', async () => {
  const middlePage = firstPage.map((request, index) => ({ ...request, operationId: id(80 + index) }));
  const lastPage = secondPage.map((request, index) => ({ ...request, operationId: id(160 + index) }));
  const { seen } = renderHistory([firstPage, middlePage, lastPage]);
  await screen.findByRole('button', { name: 'Next requests' });

  fireEvent.click(screen.getByRole('button', { name: 'Next requests' }));
  await screen.findByText('Showing page 2');
  fireEvent.click(screen.getByRole('button', { name: 'Next requests' }));
  await screen.findByText('Showing page 3');
  expect(screen.getByRole('button', { name: new RegExp(lastPage[0].operationId) })).toBeInTheDocument();

  fireEvent.click(screen.getByRole('button', { name: 'Previous requests' }));
  await screen.findByText('Showing page 2');
  expect(screen.getByRole('button', { name: new RegExp(middlePage[0].operationId) })).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Previous requests' }));
  await screen.findByRole('button', { name: new RegExp(firstPage[0].operationId) });
  expect(screen.queryByRole('button', { name: 'Previous requests' })).not.toBeInTheDocument();
  expect(screen.queryByText(/Showing page/)).not.toBeInTheDocument();

  fireEvent.click(screen.getByRole('button', { name: 'Next requests' }));
  await screen.findByText('Showing page 2');
  fireEvent.click(screen.getByRole('button', { name: 'Next requests' }));
  await screen.findByText('Showing page 3');
  fireEvent.click(screen.getByRole('button', { name: 'Previous requests' }));
  await screen.findByText('Showing page 2');
  fireEvent.click(screen.getByRole('button', { name: 'Next requests' }));
  await screen.findByText('Showing page 3');
  expect(screen.queryByRole('button', { name: 'Next requests' })).not.toBeInTheDocument();
  expect(seen).toEqual([
    null, firstPage[49].operationId, middlePage[49].operationId,
    firstPage[49].operationId, null,
    firstPage[49].operationId, middlePage[49].operationId,
    firstPage[49].operationId, middlePage[49].operationId,
  ]);
});
