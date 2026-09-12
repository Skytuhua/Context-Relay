import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { useState } from 'react';
import { afterEach, expect, it, vi } from 'vitest';
import { ConnectionTest } from './connection-test';
import type { WorkspaceGateway } from './workspace';
import type { ConnectionCheckStatus, MemoryRecord, ProjectIdentity } from './bindings';

afterEach(cleanup);
const project = { projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c073980', name: 'My project' } as ProjectIdentity;
const note = { id: '018f22e2-79b0-7cc8-98c4-dc0c0c073981', revision: '018f22e2-79b0-7cc8-98c4-dc0c0c073982', title: 'Setup test note', bodyMarkdown: 'Use plain language.', archived: false } as MemoryRecord;
const check = { checkId: '018f22e2-79b0-7cc8-98c4-dc0c0c073983', selection: { harness: 'codex', projectId: project.projectId, hermesProfile: null }, memoryId: note.id, expectedRevision: note.revision, phase: 'waiting', expiresInSeconds: 300, verifiedAt: null } as ConnectionCheckStatus;
const props = { project, harnesses: ['codex'] as const, noteId: null, checkId: null, onProgress: vi.fn(), onVerified: vi.fn(), onOpenHarness: vi.fn(), onCopyPrompt: vi.fn() };

it('creates no note until the explicit Save test note action, then starts a bound check', async () => {
  const gateway = { memories: vi.fn(async () => []), createMemory: vi.fn(async () => note), connectionCheckStart: vi.fn(async () => check) } as unknown as WorkspaceGateway;
  render(<ConnectionTest {...props} harnesses={[...props.harnesses]} gateway={gateway} />);
  expect(gateway.createMemory).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Save test note' }));
  await screen.findByText(/Waiting for Codex to read/);
  expect(gateway.connectionCheckStart).toHaveBeenCalledWith({ selection: check.selection, memoryId: note.id, expectedRevision: note.revision });
  expect(props.onVerified).not.toHaveBeenCalledWith(true);
});

it('resuming a check queries current service state without replaying any write', async () => {
  const verified = { ...check, phase: 'verified', verifiedAt: '1788780000000' };
  const gateway = { memories: vi.fn(async () => [note]), connectionCheckStatus: vi.fn(async () => verified), createMemory: vi.fn(), connectionCheckStart: vi.fn() } as unknown as WorkspaceGateway;
  render(<ConnectionTest {...props} harnesses={[...props.harnesses]} gateway={gateway} noteId={note.id} checkId={check.checkId} />);
  await screen.findByText(/Connection verified/);
  expect(gateway.createMemory).not.toHaveBeenCalled();
  expect(gateway.connectionCheckStart).not.toHaveBeenCalled();
});

it('rejects a receipt for a different harness rather than reporting success', async () => {
  const onVerified = vi.fn();
  const gateway = { memories: vi.fn(async () => [note]), connectionCheckStatus: vi.fn(async () => ({ ...check, selection: { ...check.selection, harness: 'claude_code' }, phase: 'verified', verifiedAt: '1788780000000' })) } as unknown as WorkspaceGateway;
  render(<ConnectionTest {...props} onVerified={onVerified} harnesses={[...props.harnesses]} gateway={gateway} noteId={note.id} checkId={check.checkId} />);
  await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(/does not match/));
  expect(onVerified).not.toHaveBeenCalledWith(true);
});

it('restores the selected second harness without starting a new check', async () => {
  const value = { ...check, selection: { ...check.selection, harness: 'claude_code' }, phase: 'verified', verifiedAt: '1788780000000' };
  const gateway = { memories: vi.fn(async () => [note]), connectionCheckStatus: vi.fn(async () => value), connectionCheckStart: vi.fn() } as unknown as WorkspaceGateway;
  render(<ConnectionTest {...props} harnesses={['codex', 'claude_code']} initialHarness="claude_code" gateway={gateway} noteId={note.id} checkId={check.checkId} />);
  await screen.findByText(/Connection verified — Claude Code/);
  expect(gateway.connectionCheckStart).not.toHaveBeenCalled();
});

it('does not reuse a check after the selected Hermes profile changes', async () => {
  const onVerified = vi.fn();
  const value = { ...check, selection: { ...check.selection, harness: 'hermes', hermesProfile: 'default' }, phase: 'verified', verifiedAt: '1788780000000' };
  const gateway = { memories: vi.fn(async () => [note]), connectionCheckStatus: vi.fn(async () => value) } as unknown as WorkspaceGateway;
  render(<ConnectionTest {...props} onVerified={onVerified} harnesses={['hermes']} hermesProfile="coder" gateway={gateway} noteId={note.id} checkId={check.checkId} />);
  await screen.findByRole('alert');
  expect(onVerified).not.toHaveBeenCalledWith(true);
});

it('keeps controls busy while check creation is pending even if note restoration finishes', async () => {
  let finish!: (status: ConnectionCheckStatus) => void;
  const onBusy = vi.fn();
  const gateway = { memories: vi.fn(async () => [note]), createMemory: vi.fn(async () => note), connectionCheckStart: vi.fn(() => new Promise<ConnectionCheckStatus>(resolve => { finish = resolve; })), connectionCheckStatus: vi.fn(async () => check) } as unknown as WorkspaceGateway;
  function Host() {
    const [ids, setIds] = useState<{ noteId: string | null; checkId: string | null }>({ noteId: null, checkId: null });
    return <ConnectionTest {...props} {...ids} onBusy={onBusy} harnesses={['codex', 'claude_code']} gateway={gateway} onProgress={(noteId, checkId) => setIds({ noteId, checkId })} />;
  }
  render(<Host />);
  fireEvent.click(screen.getByRole('button', { name: 'Save test note' }));
  await waitFor(() => expect(gateway.memories).toHaveBeenCalled());
  expect(screen.getByRole('button', { name: 'Start a new check' })).toBeDisabled();
  expect(screen.getByLabelText('Harness to test')).toBeDisabled();
  expect(onBusy).toHaveBeenLastCalledWith(true);
  finish(check);
  await screen.findByText(/Waiting for Codex/);
});

it('refreshes an invalidated note before starting another check', async () => {
  const updated = { ...note, revision: '018f22e2-79b0-7cc8-98c4-dc0c0c073984' as MemoryRecord['revision'], bodyMarkdown: 'Updated preference.' };
  let changed = false;
  const gateway = { memories: vi.fn(async () => [changed ? updated : note]), connectionCheckStatus: vi.fn(async () => ({ ...check, phase: 'invalidated' })), connectionCheckStart: vi.fn(async () => ({ ...check, expectedRevision: updated.revision })) } as unknown as WorkspaceGateway;
  render(<ConnectionTest {...props} harnesses={['codex']} gateway={gateway} noteId={note.id} checkId={check.checkId} />);
  await screen.findByText(/The note changed after/);
  changed = true;
  fireEvent.click(screen.getByRole('button', { name: 'Start a new check' }));
  await waitFor(() => expect(gateway.connectionCheckStart).toHaveBeenCalledWith(expect.objectContaining({ expectedRevision: updated.revision })));
  expect(screen.getByText('Updated preference.')).toBeVisible();
});
