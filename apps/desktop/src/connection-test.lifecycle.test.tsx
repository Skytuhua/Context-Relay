import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { ConnectionTest } from './connection-test';
import type { ConnectionCheckStatus, MemoryRecord, ProjectIdentity } from './bindings';
import type { WorkspaceGateway } from './workspace';

const project = { projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c073980', name: 'Read-check project' } as ProjectIdentity;
const note = { id: '018f22e2-79b0-7cc8-98c4-dc0c0c073981', revision: '018f22e2-79b0-7cc8-98c4-dc0c0c073982', title: 'Test preference', bodyMarkdown: 'Use plain language.', archived: false } as MemoryRecord;
const waiting: ConnectionCheckStatus = { checkId: '018f22e2-79b0-7cc8-98c4-dc0c0c073983' as ConnectionCheckStatus['checkId'], selection: { harness: 'codex', projectId: project.projectId, hermesProfile: null }, memoryId: note.id, expectedRevision: note.revision, phase: 'waiting', expiresInSeconds: 300, verifiedAt: null };
const verified: ConnectionCheckStatus = { ...waiting, phase: 'verified', expiresInSeconds: 0, verifiedAt: '1788780000000' as ConnectionCheckStatus['verifiedAt'] };

function fixture(status = waiting) {
  const api = {
    memories: vi.fn(async () => [note]),
    connectionCheckStatus: vi.fn<(checkId: ConnectionCheckStatus['checkId']) => Promise<ConnectionCheckStatus>>(async () => status),
    connectionCheckStart: vi.fn(async () => waiting),
    connectionCheckCancel: vi.fn(async () => ({ ...waiting, phase: 'canceled' as const, expiresInSeconds: 0 })),
    createMemory: vi.fn(async () => note),
    archiveMemory: vi.fn(async () => ({ ...note, archived: true })),
  };
  const props = { gateway: api as unknown as WorkspaceGateway, project, harnesses: ['codex'] as ConnectionCheckStatus['selection']['harness'][], noteId: note.id, checkId: waiting.checkId, onProgress: vi.fn(), onVerified: vi.fn(), onReceipt: vi.fn(), onOpenHarness: vi.fn(), onCopyPrompt: vi.fn() };
  return { api, props };
}

afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });

it.each(['invalidated', 'canceled'] as const)('withdraws verification when the current check becomes %s', async phase => {
  vi.useFakeTimers();
  const { api, props } = fixture(verified);
  await act(async () => { render(<ConnectionTest {...props} />); });
  expect(screen.getByText(/Connection verified/)).toBeVisible();
  api.connectionCheckStatus.mockResolvedValue({ ...waiting, phase, expiresInSeconds: 0 });
  await act(async () => { await vi.advanceTimersByTimeAsync(1600); });
  expect(screen.queryByText(/Connection verified/)).not.toBeInTheDocument();
  expect(props.onVerified).toHaveBeenLastCalledWith(false);
  expect(screen.getByRole('button', { name: 'Start a new check' })).toBeEnabled();
  expect(api.connectionCheckStart).not.toHaveBeenCalled();
});

it('detects a daemon restart after verification instead of retaining the old success', async () => {
  vi.useFakeTimers();
  const { api, props } = fixture(verified);
  await act(async () => { render(<ConnectionTest {...props} />); });
  api.connectionCheckStatus.mockRejectedValue({ code: 'not_found' });
  await act(async () => { await vi.advanceTimersByTimeAsync(1600); });
  expect(props.onVerified).toHaveBeenLastCalledWith(false);
  expect(screen.queryByText(/Connection verified/)).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Start a new check' })).toBeEnabled();
  expect(api.connectionCheckStart).not.toHaveBeenCalled();
});

it('reconnects to the same check after a transient poll failure without replacing it', async () => {
  vi.useFakeTimers();
  const { api, props } = fixture();
  await act(async () => { render(<ConnectionTest {...props} />); });
  api.connectionCheckStatus.mockRejectedValueOnce({ code: 'busy' }).mockResolvedValue(verified);
  await act(async () => { await vi.advanceTimersByTimeAsync(1600); });
  expect(screen.queryByRole('button', { name: 'Start a new check' })).not.toBeInTheDocument();
  expect(props.onVerified).toHaveBeenLastCalledWith(false);
  await act(async () => { await vi.advanceTimersByTimeAsync(2100); });
  expect(screen.getByText(/Connection verified/)).toBeVisible();
  expect(api.connectionCheckStatus.mock.calls.every(([id]) => id === waiting.checkId)).toBe(true);
  expect(api.connectionCheckStart).not.toHaveBeenCalled();
  expect(props.onReceipt).toHaveBeenCalledTimes(1);
});

it('keeps observing a verified receipt without repeatedly persisting the same receipt', async () => {
  vi.useFakeTimers();
  const { api, props } = fixture(verified);
  await act(async () => { render(<ConnectionTest {...props} />); });
  await act(async () => { await vi.advanceTimersByTimeAsync(4600); });
  expect(api.connectionCheckStatus.mock.calls.length).toBeGreaterThanOrEqual(3);
  expect(props.onReceipt).toHaveBeenCalledTimes(1);
});

it('retries a failed note restoration without offering a duplicate Save test note action', async () => {
  const { api, props } = fixture();
  api.memories.mockRejectedValueOnce({ code: 'timeout', message: 'PRIVATE transport details' });
  await act(async () => { render(<ConnectionTest {...props} />); });
  expect(screen.queryByRole('button', { name: 'Save test note' })).not.toBeInTheDocument();
  expect(screen.getByRole('alert')).not.toHaveTextContent('PRIVATE');
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Retry restoring test' })); });
  expect(screen.getByText(/Waiting for Codex to read/)).toBeVisible();
  expect(api.memories).toHaveBeenCalledTimes(2);
  expect(api.createMemory).not.toHaveBeenCalled();
  expect(api.connectionCheckStart).not.toHaveBeenCalled();
});

it('retries a failed status restoration without offering to replace a potentially live check', async () => {
  const { api, props } = fixture();
  api.connectionCheckStatus.mockRejectedValueOnce({ code: 'timeout' });
  await act(async () => { render(<ConnectionTest {...props} />); });
  expect(screen.queryByRole('button', { name: 'Start a new check' })).not.toBeInTheDocument();
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Retry restoring test' })); });
  expect(screen.getByText(/Waiting for Codex to read/)).toBeVisible();
  expect(api.connectionCheckStart).not.toHaveBeenCalled();
});

it('clears the parent verification while a persisted test is being restored', async () => {
  const { api, props } = fixture(verified);
  let resolve!: (records: MemoryRecord[]) => void;
  api.memories.mockImplementation(() => new Promise(done => { resolve = done; }));
  await act(async () => { render(<ConnectionTest {...props} />); });
  expect(props.onVerified).toHaveBeenLastCalledWith(false);
  await act(async () => { resolve([note]); });
  expect(props.onVerified).toHaveBeenLastCalledWith(true);
});

it('invalidates an already-rendered Hermes receipt when the selected profile changes', async () => {
  const status = { ...verified, selection: { ...verified.selection, harness: 'hermes' as const, hermesProfile: 'default' } };
  const { props } = fixture(status);
  const view = render(<ConnectionTest {...props} harnesses={['hermes']} hermesProfile="default" />);
  await act(async () => {});
  expect(screen.getByText(/Connection verified/)).toBeVisible();
  await act(async () => { view.rerender(<ConnectionTest {...props} harnesses={['hermes']} hermesProfile="coder" />); });
  expect(screen.queryByText(/Connection verified/)).not.toBeInTheDocument();
  expect(props.onVerified).toHaveBeenLastCalledWith(false);
});

it('admits only one save and one check when two submissions arrive in the same render', async () => {
  const { api, props } = fixture();
  let resolve!: (record: MemoryRecord) => void;
  api.createMemory.mockImplementation(() => new Promise(done => { resolve = done; }));
  render(<ConnectionTest {...props} noteId={null} checkId={null} />);
  const form = screen.getByRole('button', { name: 'Save test note' }).closest('form')!;
  act(() => { fireEvent.submit(form); fireEvent.submit(form); });
  expect(api.createMemory).toHaveBeenCalledTimes(1);
  await act(async () => { resolve(note); });
  expect(api.connectionCheckStart).toHaveBeenCalledTimes(1);
});

it('offers a replacement note only after a successful read confirms the old note is absent', async () => {
  const { api, props } = fixture();
  api.memories.mockResolvedValue([]);
  await act(async () => { render(<ConnectionTest {...props} />); });
  expect(screen.getByRole('button', { name: 'Save test note' })).toBeEnabled();
  expect(api.createMemory).not.toHaveBeenCalled();
});
