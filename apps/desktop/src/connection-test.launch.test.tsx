import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { invoke } from '@tauri-apps/api/core';
import { ConnectionTest } from './connection-test';
import type { ConnectionCheckStatus, MemoryRecord, ProjectIdentity } from './bindings';
import type { WorkspaceGateway } from './workspace';

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn() }));
const project = { projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c073980', name: 'Launch project' } as ProjectIdentity;
const note = { id: '018f22e2-79b0-7cc8-98c4-dc0c0c073981', revision: '018f22e2-79b0-7cc8-98c4-dc0c0c073982', bodyMarkdown: 'Read this note.', archived: false } as MemoryRecord;
const check = { checkId: '018f22e2-79b0-7cc8-98c4-dc0c0c073983', selection: { harness: 'codex', projectId: project.projectId, hermesProfile: null }, memoryId: note.id, expectedRevision: note.revision, phase: 'waiting', expiresInSeconds: 300, verifiedAt: null } as ConnectionCheckStatus;
const launchCommand = "cd -- '/projects/launch' && '/tools/codex'";
let originalClipboard: PropertyDescriptor | undefined;
const writeText = vi.fn<(text: string) => Promise<void>>();

beforeEach(() => {
  vi.clearAllMocks();
  vi.spyOn(navigator, 'userAgent', 'get').mockReturnValue('Mozilla/5.0 (Macintosh; Intel Mac OS X)');
  originalClipboard = Object.getOwnPropertyDescriptor(navigator, 'clipboard');
  Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } });
  writeText.mockReset().mockResolvedValue(undefined);
  vi.mocked(invoke).mockReset().mockResolvedValue(launchCommand);
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  if (originalClipboard) Object.defineProperty(navigator, 'clipboard', originalClipboard);
  else Reflect.deleteProperty(navigator, 'clipboard');
});

function fixture() {
  const api = {
    memories: vi.fn(async () => [note]),
    connectionCheckStatus: vi.fn(async () => check),
    createMemory: vi.fn(), connectionCheckStart: vi.fn(), connectionCheckCancel: vi.fn(),
  };
  const props = {
    gateway: api as unknown as WorkspaceGateway, project, harnesses: ['codex' as const],
    noteId: note.id, checkId: check.checkId,
    onProgress: vi.fn(), onVerified: vi.fn(), onOpenHarness: vi.fn(), onCopyPrompt: vi.fn(),
  };
  return { api, props };
}

it('uses the native copy helper on macOS and keeps the launch command separate from the test prompt', async () => {
  const { api, props } = fixture();
  render(<ConnectionTest {...props} />);
  const copy = await screen.findByRole('button', { name: 'Copy launch command' });
  await waitFor(() => expect(copy).toBeEnabled());
  expect(copy).toHaveClass('primary-action');
  expect(screen.queryByRole('button', { name: 'Open Codex' })).not.toBeInTheDocument();
  fireEvent.click(copy);
  await screen.findByText('Launch command copied. Run it in Terminal, then send the test prompt in your harness.');
  expect(invoke).toHaveBeenCalledWith('harness_copy_command', { selection: check.selection });
  expect(writeText).toHaveBeenCalledWith(launchCommand);
  expect(props.onOpenHarness).not.toHaveBeenCalled();
  expect(props.onVerified).not.toHaveBeenCalledWith(true);
  expect(api.createMemory).not.toHaveBeenCalled();
  expect(api.connectionCheckStart).not.toHaveBeenCalled();
  expect(api.connectionCheckCancel).not.toHaveBeenCalled();
  await waitFor(() => expect(screen.getByRole('button', { name: 'Copy test prompt' })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: 'Copy test prompt' }));
  expect(props.onCopyPrompt).toHaveBeenCalledWith(expect.stringContaining(`note ${note.id} in project ${project.projectId}`));
  expect(props.onCopyPrompt).not.toHaveBeenCalledWith(launchCommand);
});

it('allows retry after clipboard failure and verifies only the existing polled receipt', async () => {
  const { api, props } = fixture();
  writeText.mockRejectedValueOnce(new Error('Clipboard unavailable'));
  render(<ConnectionTest {...props} />);
  const copy = await screen.findByRole('button', { name: 'Copy launch command' });
  await waitFor(() => expect(copy).toBeEnabled());
  fireEvent.click(copy);
  expect(await screen.findByRole('alert')).toHaveTextContent('Clipboard unavailable');
  expect(screen.getByText(/Waiting for Codex to read/)).toBeVisible();
  expect(props.onVerified).not.toHaveBeenCalledWith(true);
  fireEvent.click(copy);
  await screen.findByText(/Launch command copied/);
  expect(writeText).toHaveBeenCalledTimes(2);
  api.connectionCheckStatus.mockResolvedValue({ ...check, phase: 'verified', verifiedAt: '1788780000000' as ConnectionCheckStatus['verifiedAt'], expiresInSeconds: 0 });
  await screen.findByText(/Connection verified/, {}, { timeout: 4000 });
  expect(props.onVerified).toHaveBeenCalledWith(true);
  expect(api.connectionCheckStatus).toHaveBeenLastCalledWith(check.checkId);
  expect(api.connectionCheckStart).not.toHaveBeenCalled();
  expect(api.connectionCheckCancel).not.toHaveBeenCalled();
});

it('retains Windows Open and offers a PowerShell fallback when opening fails', async () => {
  vi.spyOn(navigator, 'userAgent', 'get').mockReturnValue('Mozilla/5.0 (Windows NT 10.0; Win64; x64)');
  const { props } = fixture();
  props.onOpenHarness.mockRejectedValueOnce(new Error('Launch failed'));
  render(<ConnectionTest {...props} />);
  const open = await screen.findByRole('button', { name: 'Open Codex' });
  await waitFor(() => expect(open).toBeEnabled());
  fireEvent.click(open);
  expect(await screen.findByRole('alert')).toHaveTextContent('Launch failed');
  fireEvent.click(screen.getByRole('button', { name: 'Copy launch command' }));
  await screen.findByText('Launch command copied. Run it in PowerShell, then send the test prompt in your harness.');
  expect(props.onVerified).not.toHaveBeenCalledWith(true);
});
