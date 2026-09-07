import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import App from './App';
import type { MemoryRecord, SearchIndexStatus } from './bindings';
import type { WorkspaceGateway } from './workspace';

const record = (title: string) => ({ id: title, title, bodyMarkdown: 'Saved text', revision: '1' }) as unknown as MemoryRecord;
const state = (phase: SearchIndexStatus['phase'], revision: string) => ({ phase, revision }) as SearchIndexStatus;
const base = {
  status: async () => ({ vault: 'unlocked', sync: 'offline' }), projects: async () => [],
  pendingWrites: async () => ({ writes: [], nextCursor: null }),
  memories: async () => [record('Keyword match')],
} as unknown as WorkspaceGateway;

afterEach(() => { cleanup(); vi.useRealTimers(); });

async function open(gateway: WorkspaceGateway) {
  vi.useFakeTimers();
  render(<App gateway={gateway} />);
  await act(async () => {});
  fireEvent.click(screen.getByRole('button', { name: 'Context' }));
  await act(async () => {});
}

it('keeps keyword results while preparing and refreshes the submitted search when indexing advances', async () => {
  let progress = state('preparing', '0');
  const searchMemories = vi.fn(async () => [record(progress.phase === 'ready' ? 'Meaning match' : 'Keyword match')]);
  await open({ ...base, searchMemories, searchIndexStatus: async () => progress });
  expect(screen.getByText(/Preparing search across your saved context/)).toBeVisible();
  fireEvent.change(screen.getByLabelText('Search saved context'), { target: { value: 'automobile' } });
  fireEvent.submit(screen.getByRole('search'));
  await act(async () => {});
  expect(screen.getByRole('heading', { name: 'Keyword match' })).toBeVisible();
  progress = state('ready', '2');
  await act(async () => { await vi.advanceTimersByTimeAsync(1500); });
  expect(screen.getByRole('heading', { name: 'Meaning match' })).toBeVisible();
  expect(screen.getByText('Search is ready.')).toBeVisible();
});

it('offers a single retry after an indexing failure without clearing saved results', async () => {
  let resolve!: (status: SearchIndexStatus) => void;
  const searchIndexRetry = vi.fn(() => new Promise<SearchIndexStatus>((done) => { resolve = done; }));
  await open({ ...base, searchIndexStatus: async () => state('failed', '3'), searchIndexRetry });
  expect(screen.getByRole('heading', { name: 'Keyword match' })).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Retry search preparation' }));
  expect(screen.getByRole('button', { name: 'Retrying…' })).toBeDisabled();
  expect(searchIndexRetry).toHaveBeenCalledTimes(1);
  await act(async () => { resolve(state('preparing', '4')); });
  expect(screen.getByText(/Preparing search across your saved context/)).toBeVisible();
});

it('ignores an old query result after a newer query and after leaving Saved context', async () => {
  let finishOld!: (records: MemoryRecord[]) => void;
  const searchMemories = vi.fn((query: string) => query === 'old'
    ? new Promise<MemoryRecord[]>((done) => { finishOld = done; }) : Promise.resolve([record('New match')]));
  await open({ ...base, searchIndexStatus: async () => state('ready', '1'), searchMemories });
  const input = screen.getByLabelText('Search saved context');
  fireEvent.change(input, { target: { value: 'old' } }); fireEvent.submit(screen.getByRole('search'));
  await act(async () => {});
  fireEvent.change(input, { target: { value: 'new' } }); fireEvent.submit(screen.getByRole('search'));
  await act(async () => {});
  await act(async () => { finishOld([record('Old match')]); });
  expect(screen.getByRole('heading', { name: 'New match' })).toBeVisible();
  expect(screen.queryByRole('heading', { name: 'Old match' })).not.toBeInTheDocument();
  fireEvent.change(input, { target: { value: 'old' } }); fireEvent.submit(screen.getByRole('search'));
  await act(async () => {});
  fireEvent.click(screen.getByRole('button', { name: 'Dashboard' }));
  await act(async () => { finishOld([record('Old match')]); });
  fireEvent.click(screen.getByRole('button', { name: 'Context' }));
  await act(async () => {});
  expect(screen.getByRole('heading', { name: 'Keyword match' })).toBeVisible();
  expect(screen.queryByRole('heading', { name: 'Old match' })).not.toBeInTheDocument();
});
