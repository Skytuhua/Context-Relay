import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { Base64Url, ConnectionCheckStatus, MemoryRecord, OpenCodeMcpExport, ProjectIdentity, WireNativeValue } from './bindings';
import { OpenCodeMcpSetup, type OpenCodeMcpGateway } from './opencode-mcp-setup';
import { validateOpenCodeMcpExport } from './protocol-validation';
import { LocalWorkspaceGateway } from './workspace';

const invoke = vi.hoisted(() => vi.fn());
vi.mock('@tauri-apps/api/core', () => ({ invoke }));

const project = { projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c073980', name: 'OpenCode project' } as ProjectIdentity;
const other = { ...project, projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c073984', name: 'Another project' } as ProjectIdentity;
const root = 'C:\\Projects\\Project & notes 專案 🚀';
const executable = 'C:\\Program Files\\Context Relay\\context-relay-context-mcp.exe';
const note = { id: '018f22e2-79b0-7cc8-98c4-dc0c0c073981', revision: '018f22e2-79b0-7cc8-98c4-dc0c0c073982', title: 'Setup test note', bodyMarkdown: 'Use plain language.', archived: false } as MemoryRecord;
const check = { checkId: '018f22e2-79b0-7cc8-98c4-dc0c0c073983', selection: { harness: 'opencode', projectId: project.projectId, hermesProfile: null }, memoryId: note.id, expectedRevision: note.revision, phase: 'waiting', expiresInSeconds: 300, verifiedAt: null } as ConnectionCheckStatus;

function path(value: string): WireNativeValue {
  const bytes = new Uint8Array(value.length * 2);
  const view = new DataView(bytes.buffer);
  for (let index = 0; index < value.length; index += 1) view.setUint16(index * 2, value.charCodeAt(index), true);
  return { platform: 'windows', bytes: btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') as Base64Url, display: value };
}

function exported(): OpenCodeMcpExport {
  return {
    projectId: project.projectId, projectRoot: path(root), configPath: path(`${root}\\opencode.jsonc`), instructionPath: path(`${root}\\.context-relay-opencode.md`),
    configFragment: JSON.stringify({ mcp: { 'context-relay': { type: 'local', command: [executable, '--harness', 'opencode'], enabled: true, cwd: root, timeout: 60_000 } }, instructions: ['.context-relay-opencode.md'] }, null, 2),
    instructionMarkdown: '## Context Relay\n\nUse context_relay_search for the active project.\n',
  };
}

function api() {
  return {
    opencodeMcpExport: vi.fn(async () => exported()), memories: vi.fn(async () => [note]), createMemory: vi.fn(async () => note), archiveMemory: vi.fn(async () => ({ ...note, archived: true })),
    connectionCheckStart: vi.fn(async () => check), connectionCheckStatus: vi.fn(async () => check), connectionCheckCancel: vi.fn(async () => ({ ...check, phase: 'canceled' as const })),
  } satisfies OpenCodeMcpGateway;
}

const clipboard = vi.fn<(value: string) => Promise<void>>().mockResolvedValue(undefined);
const originalClipboard = Object.getOwnPropertyDescriptor(navigator, 'clipboard');
beforeEach(() => {
  invoke.mockReset(); clipboard.mockClear();
  Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: clipboard } });
});
afterEach(() => {
  cleanup();
  if (originalClipboard) Object.defineProperty(navigator, 'clipboard', originalClipboard);
  else Reflect.deleteProperty(navigator, 'clipboard');
});

it('prepares only after an explicit action and copying never starts a check or managed setup', async () => {
  const gateway = api(); render(<OpenCodeMcpSetup gateway={gateway} project={project} />);
  expect(gateway.opencodeMcpExport).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Prepare OpenCode configuration' }));
  await screen.findByLabelText('Project MCP fragment');
  expect(gateway.opencodeMcpExport).toHaveBeenCalledWith(project.projectId);
  fireEvent.click(screen.getByRole('button', { name: 'Copy MCP fragment' }));
  await screen.findByText(/Copying does not verify a connection/);
  expect(clipboard).toHaveBeenCalledWith(exported().configFragment);
  expect(gateway.createMemory).not.toHaveBeenCalled();
  expect(gateway.connectionCheckStart).not.toHaveBeenCalled();
  expect(screen.queryByText(/Connection verified/)).not.toBeInTheDocument();
  expect(invoke).not.toHaveBeenCalled();
});

it('uses the real project-bound note read check with manual OpenCode launch', async () => {
  const gateway = api(); render(<OpenCodeMcpSetup gateway={gateway} project={project} />);
  fireEvent.click(screen.getByRole('button', { name: 'Prepare OpenCode configuration' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Test OpenCode with saved context' }));
  expect(gateway.createMemory).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Save test note' }));
  await screen.findByText(/Waiting for OpenCode to read/);
  expect(gateway.connectionCheckStart).toHaveBeenCalledWith({ selection: check.selection, memoryId: note.id, expectedRevision: note.revision });
  expect(screen.queryByRole('button', { name: 'Copy launch command' })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Open OpenCode' })).not.toBeInTheDocument();
  expect(screen.queryByText(/Connection verified/)).not.toBeInTheDocument();
  expect(invoke).not.toHaveBeenCalled();
});

it('shows configuration conflicts without offering a copy or a successful connection', async () => {
  const gateway = api();
  gateway.opencodeMcpExport.mockRejectedValueOnce({ code: 'invalid_request', message: 'Both opencode.json and opencode.jsonc exist; resolve the ambiguous project configuration first' });
  render(<OpenCodeMcpSetup gateway={gateway} project={project} />);
  fireEvent.click(screen.getByRole('button', { name: 'Prepare OpenCode configuration' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('ambiguous project configuration');
  expect(screen.queryByRole('button', { name: 'Copy MCP fragment' })).not.toBeInTheDocument();
});

it('discards an export after the selected project changes and leaves retry available', async () => {
  let finish!: (value: OpenCodeMcpExport) => void;
  const gateway = api();
  gateway.opencodeMcpExport.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  const view = render(<OpenCodeMcpSetup gateway={gateway} project={project} />);
  fireEvent.click(screen.getByRole('button', { name: 'Prepare OpenCode configuration' }));
  view.rerender(<OpenCodeMcpSetup gateway={gateway} project={other} />);
  await act(async () => { finish(exported()); });
  expect(screen.queryByLabelText('Project MCP fragment')).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Prepare OpenCode configuration' })).toBeEnabled();
});

it('rejects a valid export returned for another project', async () => {
  const gateway = api(); gateway.opencodeMcpExport.mockResolvedValueOnce({ ...exported(), projectId: other.projectId });
  render(<OpenCodeMcpSetup gateway={gateway} project={project} />);
  fireEvent.click(screen.getByRole('button', { name: 'Prepare OpenCode configuration' }));
  await screen.findByRole('alert');
  expect(screen.queryByRole('button', { name: 'Copy MCP fragment' })).not.toBeInTheDocument();
});

it('validates command shape, timeout and canonical project paths independently of display text', () => {
  expect(validateOpenCodeMcpExport(exported())).toEqual(exported());
  for (const patch of [
    { cwd: 'C:\\another-project' }, { timeout: 5_000 }, { command: ['cmd.exe', '/c', executable] },
    { command: [executable, '--harness', 'codex'] }, { enabled: false }, { type: 'remote' }, { environment: { EXTRA: 'value' } },
  ]) {
    const value = exported(); const config = JSON.parse(value.configFragment);
    Object.assign(config.mcp['context-relay'], patch); value.configFragment = JSON.stringify(config);
    expect(() => validateOpenCodeMcpExport(value)).toThrow();
  }
  expect(() => validateOpenCodeMcpExport({ ...exported(), configPath: path('C:\\another-project\\opencode.json') })).toThrow();
  expect(() => validateOpenCodeMcpExport({ ...exported(), verified: true })).toThrow();
  expect(validateOpenCodeMcpExport({ ...exported(), projectRoot: { ...path(root), display: 'Display is not path authority' } }).projectId).toBe(project.projectId);
});

it('sends only the project ID through the owner-only export request and validates its envelope', async () => {
  const gateway = new LocalWorkspaceGateway();
  invoke.mockResolvedValue({ kind: 'opencode_mcp_export', data: { export: exported() } });
  expect(await gateway.opencodeMcpExport(project.projectId)).toEqual(exported());
  expect(invoke).toHaveBeenLastCalledWith('local_request', { request: { method: 'opencode_mcp_export', params: { projectId: project.projectId } } });
  for (const response of [
    { kind: 'empty' }, { kind: 'opencode_mcp_export', data: { export: exported(), verified: true } },
    { kind: 'opencode_mcp_export', data: { export: { ...exported(), projectId: other.projectId } } },
  ]) {
    invoke.mockResolvedValue(response);
    await expect(gateway.opencodeMcpExport(project.projectId)).rejects.toThrow();
  }
  await waitFor(() => expect(invoke).toHaveBeenCalledTimes(4));
});
