import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import App from './App';
import { PROTOCOL_VERSION, type Base64Url, type ConnectionCheckStatus, type MemoryRecord, type OpenCodeMcpExport, type ProjectIdentity, type WireNativeValue } from './bindings';
import type { WorkspaceGateway } from './workspace';

const project = { projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c073980', name: 'OpenCode project' } as ProjectIdentity;
const other = { ...project, projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c073984', name: 'Another project' } as ProjectIdentity;
const note = { id: '018f22e2-79b0-7cc8-98c4-dc0c0c073981', revision: '018f22e2-79b0-7cc8-98c4-dc0c0c073982', title: 'Setup test note', bodyMarkdown: 'Use plain language.', archived: false } as MemoryRecord;
const check = { checkId: '018f22e2-79b0-7cc8-98c4-dc0c0c073983', selection: { harness: 'opencode', projectId: project.projectId, hermesProfile: null }, memoryId: note.id, expectedRevision: note.revision, phase: 'waiting', expiresInSeconds: 300, verifiedAt: null } as ConnectionCheckStatus;
const root = 'C:\\Projects\\OpenCode project';

function path(value: string): WireNativeValue {
  const bytes = new Uint8Array(value.length * 2);
  const view = new DataView(bytes.buffer);
  for (let index = 0; index < value.length; index += 1) view.setUint16(index * 2, value.charCodeAt(index), true);
  return { platform: 'windows', bytes: btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') as Base64Url, display: value };
}

function exported(): OpenCodeMcpExport {
  return {
    projectId: project.projectId, projectRoot: path(root), configPath: path(`${root}\\opencode.json`), instructionPath: path(`${root}\\.context-relay-opencode.md`),
    configFragment: JSON.stringify({ mcp: { 'context-relay': { type: 'local', command: ['C:\\Context Relay\\context-relay-context-mcp.exe', '--harness', 'opencode'], enabled: true, cwd: root, timeout: 60_000 } }, instructions: ['.context-relay-opencode.md'] }),
    instructionMarkdown: '## Context Relay\n\nUse context_relay_search for the active project.\n',
  };
}

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it('protects pending OpenCode note/check mutations from App navigation and retains progress while hidden', async () => {
  let saveNote!: (value: MemoryRecord) => void;
  let startCheck!: (value: ConnectionCheckStatus) => void;
  const api = {
    status: vi.fn(async () => ({ protocol: { min: PROTOCOL_VERSION, max: PROTOCOL_VERSION }, vault: 'unlocked', sync: 'offline', resolvedProject: null, access: { mode: 'default' } })),
    projects: vi.fn(async () => [project, other]),
    pendingWrites: vi.fn(async () => ({ writes: [], nextCursor: null })),
    memories: vi.fn(async () => [note]), tasks: vi.fn(async () => []), candidates: vi.fn(async () => []),
    harnessExecutionCurrent: vi.fn(async () => null),
    harnessSetupsList: vi.fn(async () => ({ setups: [], nextAfter: null })),
    opencodeMcpExport: vi.fn(async () => exported()),
    createMemory: vi.fn(() => new Promise<MemoryRecord>(resolve => { saveNote = resolve; })),
    connectionCheckStart: vi.fn(() => new Promise<ConnectionCheckStatus>(resolve => { startCheck = resolve; })),
    connectionCheckStatus: vi.fn(async () => check),
    connectionCheckCancel: vi.fn(async () => ({ ...check, phase: 'canceled' as const })),
    archiveMemory: vi.fn(async () => {}),
  };
  render(<App gateway={api as unknown as WorkspaceGateway} />);
  await screen.findByText('Ready on this computer');
  fireEvent.click(screen.getByRole('button', { name: 'Harnesses' }));
  await waitFor(() => expect(screen.getByRole('button', { name: 'Prepare OpenCode configuration' })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: 'Prepare OpenCode configuration' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Test OpenCode with saved context' }));
  fireEvent.click(screen.getByRole('button', { name: 'Save test note' }));

  const assertNavigationGuard = () => {
    expect(screen.getByRole('combobox', { name: 'Current project' })).toBeDisabled();
    expect(screen.getByRole('combobox', { name: 'Project' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Projects' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Projects' }));
    fireEvent.change(screen.getByRole('combobox', { name: 'Current project' }), { target: { value: other.projectId } });
    expect(screen.getByRole('heading', { name: 'Harnesses', level: 1 })).toBeVisible();
    expect(screen.getByRole('combobox', { name: 'Current project' })).toHaveValue(project.projectId);
  };
  await waitFor(() => expect(api.createMemory).toHaveBeenCalledTimes(1));
  assertNavigationGuard();
  expect(api.connectionCheckStart).not.toHaveBeenCalled();
  await act(async () => { saveNote(note); });
  expect(api.connectionCheckStart).toHaveBeenCalledWith({ selection: check.selection, memoryId: note.id, expectedRevision: note.revision });
  assertNavigationGuard();

  await act(async () => { startCheck(check); });
  await screen.findByText(/Waiting for OpenCode to read/);
  await waitFor(() => expect(screen.getByRole('button', { name: 'Projects' })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: 'Projects' }));
  expect(screen.getByRole('heading', { name: 'Projects', level: 1 })).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Harnesses' }));
  expect(screen.getByText(/Waiting for OpenCode to read/)).toBeVisible();
  expect(screen.getByText(note.bodyMarkdown)).toBeVisible();
  expect(screen.queryByRole('button', { name: 'Save test note' })).not.toBeInTheDocument();
  expect(api.createMemory).toHaveBeenCalledTimes(1);
  expect(api.connectionCheckStart).toHaveBeenCalledTimes(1);
  expect(api.opencodeMcpExport).toHaveBeenCalledTimes(1);
});
