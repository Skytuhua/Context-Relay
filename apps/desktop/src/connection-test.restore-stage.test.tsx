import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import type { ConnectionCheckStatus, MemoryRecord, ProjectIdentity } from './bindings';
import { ConnectionTest } from './connection-test';
import type { WorkspaceGateway } from './workspace';

const project = { projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c073980', name: 'Restore project' } as ProjectIdentity;
const note = { id: '018f22e2-79b0-7cc8-98c4-dc0c0c073981', revision: '018f22e2-79b0-7cc8-98c4-dc0c0c073982',
  title: 'Setup test note', bodyMarkdown: 'Keep the original note.', archived: false } as MemoryRecord;
const waiting = { checkId: '018f22e2-79b0-7cc8-98c4-dc0c0c073983',
  selection: { harness: 'codex', projectId: project.projectId, hermesProfile: null },
  memoryId: note.id, expectedRevision: note.revision, phase: 'waiting', expiresInSeconds: 300, verifiedAt: null } as ConnectionCheckStatus;

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

function fixture() {
  const replacement = { ...waiting, checkId: '018f22e2-79b0-7cc8-98c4-dc0c0c073984' as ConnectionCheckStatus['checkId'] };
  const api = {
    memories: vi.fn(async (): Promise<MemoryRecord[]> => [note]),
    connectionCheckStatus: vi.fn(async (): Promise<ConnectionCheckStatus> => waiting),
    connectionCheckStart: vi.fn(async () => replacement),
    createMemory: vi.fn(async () => note), connectionCheckCancel: vi.fn(), archiveMemory: vi.fn(),
  };
  const props = { gateway: api as unknown as WorkspaceGateway, project, harnesses: ['codex'] as const,
    noteId: note.id, checkId: waiting.checkId, onProgress: vi.fn(), onVerified: vi.fn(),
    onOpenHarness: vi.fn(), onCopyPrompt: vi.fn() };
  return { api, props, replacement };
}

it.each(['not_found', 'busy', 'timeout'])('retains the original test after a %s note-list failure', async code => {
  const { api, props } = fixture();
  api.memories.mockRejectedValueOnce({ code, message: 'PRIVATE service details' });
  render(<ConnectionTest {...props} harnesses={[...props.harnesses]} />);
  const retry = await screen.findByRole('button', { name: 'Retry restoring test' });
  expect(screen.queryByRole('button', { name: 'Save test note' })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Start a new check' })).not.toBeInTheDocument();
  expect(screen.getByRole('alert')).not.toHaveTextContent('PRIVATE');
  expect(api.connectionCheckStatus).not.toHaveBeenCalled();
  expect(props.onProgress).not.toHaveBeenCalled();
  await waitFor(() => expect(retry).toBeEnabled());
  fireEvent.click(retry);
  await screen.findByText(/Waiting for Codex to read this note/);
  expect(api.memories).toHaveBeenCalledTimes(2);
  expect(api.connectionCheckStatus).toHaveBeenLastCalledWith(waiting.checkId);
  expect(api.createMemory).not.toHaveBeenCalled();
  expect(api.connectionCheckStart).not.toHaveBeenCalled();
  expect(props.onVerified).not.toHaveBeenCalledWith(true);
});

it('offers an explicit new check only when the status read confirms the old check is absent', async () => {
  const { api, props, replacement } = fixture();
  api.connectionCheckStatus.mockRejectedValueOnce({ code: 'not_found' });
  render(<ConnectionTest {...props} harnesses={[...props.harnesses]} />);
  const start = await screen.findByRole('button', { name: 'Start a new check' });
  await waitFor(() => expect(start).toBeEnabled());
  expect(screen.getByText(note.bodyMarkdown)).toBeVisible();
  expect(screen.queryByRole('button', { name: 'Save test note' })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Retry restoring test' })).not.toBeInTheDocument();
  expect(api.connectionCheckStart).not.toHaveBeenCalled();
  fireEvent.click(start);
  await screen.findByText(/Waiting for Codex to read this note/);
  expect(api.connectionCheckStart).toHaveBeenCalledTimes(1);
  expect(api.connectionCheckStart).toHaveBeenCalledWith({ selection: waiting.selection,
    memoryId: note.id, expectedRevision: note.revision });
  expect(props.onProgress).toHaveBeenLastCalledWith(note.id, replacement.checkId, 'codex');
  expect(api.createMemory).not.toHaveBeenCalled();
});

it('offers a replacement note only after a successful list confirms absence', async () => {
  const { api, props } = fixture();
  api.memories.mockResolvedValue([]);
  render(<ConnectionTest {...props} harnesses={[...props.harnesses]} />);
  const save = await screen.findByRole('button', { name: 'Save test note' });
  await waitFor(() => expect(save).toBeEnabled());
  expect(screen.queryByRole('button', { name: 'Retry restoring test' })).not.toBeInTheDocument();
  expect(api.connectionCheckStatus).not.toHaveBeenCalled();
  expect(api.createMemory).not.toHaveBeenCalled();
  expect(api.connectionCheckStart).not.toHaveBeenCalled();
});
