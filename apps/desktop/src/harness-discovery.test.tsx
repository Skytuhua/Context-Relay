import { readFileSync } from 'node:fs';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { HarnessParams, LocalRequest, ProbeReport, ProjectId, SetupPlan } from './bindings';

const invoke = vi.hoisted(() => vi.fn());
vi.mock('@tauri-apps/api/core', () => ({ invoke }));
import { HarnessesScreen } from './harnesses';
import { LocalWorkspaceGateway } from './workspace';

const projectId = '018f22e2-79b0-7cc8-98c4-dc0c0c075001' as ProjectId;
const project = { projectId, name: 'Research', githubRepositoryId: null, gitRemoteFingerprint: null, monorepoSubdirectory: null };
const params: HarnessParams = { harness: 'codex', projectId, hermesProfile: null };
const fixture = JSON.parse(readFileSync('../../crates/protocol/tests/fixtures/runtime-contracts-v1.json', 'utf8')).setupPlan as SetupPlan;
const report: ProbeReport = { executable: fixture.executablePath, executableSha256: fixture.executableHash,
  harnessVersion: '0.144.6', installationMethod: 'manual', configRoots: [], activeProfile: null,
  codexSavedHookApproval: null, policyConflicts: [], capability: 'import_only' };
const response = (value: unknown) => ({ kind: 'probe', data: { report: value } });
let requests: LocalRequest[];

beforeEach(() => {
  requests = [];
  invoke.mockReset().mockImplementation(async (_command, { request }: { request: LocalRequest }) => {
    requests.push(request);
    return response(report);
  });
});
afterEach(cleanup);
function open() { return render(<HarnessesScreen gateway={new LocalWorkspaceGateway()} projects={[project]} />); }
function preview() { fireEvent.click(screen.getByRole('button', { name: 'Review setup' })); }

it.each([
  ['import_only', /This version cannot connect automatically yet/i],
  ['blocked', /Local policy prevents automatic setup/i],
  ['missing', /was not found/i],
] as const)('shows %s discovery without requesting a setup plan or allowing approval', async (capability, message) => {
  invoke.mockImplementation(async (_command, { request }: { request: LocalRequest }) => {
    requests.push(request);
    return response({ ...report, capability, ...(capability === 'missing' ? { executable: null, executableSha256: null, harnessVersion: null } : {}) });
  });
  open(); preview();
  expect(await screen.findByText(message)).toBeVisible();
  if (capability !== 'missing') expect(screen.getByText(/0\.144\.6/)).toBeVisible();
  expect(requests).toEqual([{ method: 'harness_probe', params }]);
  expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Review setup' })).toBeEnabled();
});

it('requests a fresh exact plan only after Full discovery and still requires approval', async () => {
  invoke.mockImplementation(async (_command, { request }: { request: LocalRequest }) => {
    requests.push(request);
    if (request.method === 'harness_probe') return response({ ...report, capability: 'full' });
    return { kind: 'plan', data: { plan: { ...fixture, expiresAt: String(Date.now() + 60_000), targetScopes: [{ scope: 'project', projectId, root: fixture.executablePath }] } } };
  });
  open(); preview();
  expect(await screen.findByRole('heading', { name: 'Review setup changes' })).toBeVisible();
  expect(requests).toEqual([{ method: 'harness_probe', params }, { method: 'harness_preview', params }]);
  expect(screen.getByRole('button', { name: 'Save settings' })).toBeDisabled();
});

it('discards discovery after selection changes without requesting the obsolete plan', async () => {
  let resolve!: (value: unknown) => void;
  invoke.mockImplementation(async (_command, { request }: { request: LocalRequest }) => {
    requests.push(request);
    return new Promise(done => { resolve = done; });
  });
  open(); preview();
  await waitFor(() => expect(requests).toHaveLength(1));
  fireEvent.change(screen.getByRole('combobox', { name: 'Harness' }), { target: { value: 'claude_code' } });
  await act(async () => resolve(response({ ...report, capability: 'full' })));
  expect(requests).toEqual([{ method: 'harness_probe', params }]);
  expect(screen.queryByRole('heading', { name: 'Review setup changes' })).not.toBeInTheDocument();
  expect(screen.queryByText(/0\.144\.6/)).not.toBeInTheDocument();
});

it('binds Hermes discovery and approval to its canonical profile name', async () => {
  invoke.mockImplementation(async (_command, { request }: { request: LocalRequest }) => {
    requests.push(request);
    if (request.method === 'harness_probe') return response({ ...report, capability: 'full', activeProfile: 'coder' });
    return { kind: 'plan', data: { plan: { ...fixture, harness: 'hermes', harnessProfile: 'coder', expiresAt: String(Date.now() + 60_000), targetScopes: [{ scope: 'project', projectId, root: fixture.executablePath }] } } };
  });
  open();
  fireEvent.change(screen.getByRole('combobox', { name: 'Harness' }), { target: { value: 'hermes' } });
  fireEvent.change(screen.getByRole('textbox', { name: 'Hermes profile' }), { target: { value: ' Coder ' } });
  preview();
  expect(await screen.findByRole('heading', { name: 'Review setup changes' })).toBeVisible();
  expect(requests).toEqual(['harness_probe', 'harness_preview'].map(method => ({ method, params: { harness: 'hermes', projectId, hermesProfile: 'coder' } })));
  expect(screen.getByRole('checkbox', { name: /I reviewed/ })).toBeEnabled();
});

it('offers the default Hermes profile and explains that a folder path is invalid', async () => {
  open();
  fireEvent.change(screen.getByRole('combobox', { name: 'Harness' }), { target: { value: 'hermes' } });
  expect(screen.getByRole('textbox', { name: 'Hermes profile' })).toHaveValue('default');
  expect(screen.getByText(/Use a profile name, such as default or coder/)).toBeVisible();
  fireEvent.change(screen.getByRole('textbox', { name: 'Hermes profile' }), { target: { value: 'C:\\Users\\User\\AppData\\Local\\hermes' } });
  expect(screen.getByRole('button', { name: 'Review setup' })).toBeDisabled();
  expect(screen.getByRole('textbox', { name: 'Hermes profile' })).toHaveAttribute('aria-invalid', 'true');
  fireEvent.submit(screen.getByRole('form', { name: 'Review harness setup' }));
  expect(requests).toEqual([]);
});

it('explains a confirmed missing Claude Code executable instead of blaming setup preview', async () => {
  invoke.mockRejectedValue({ code: 'not_found', message: 'Claude Code executable was not found', fieldPath: null, retryable: false });
  open();
  fireEvent.change(screen.getByRole('combobox', { name: 'Harness' }), { target: { value: 'claude_code' } });
  preview();
  expect(await screen.findByRole('alert')).toHaveTextContent('Claude Code command-line executable was not found');
  expect(screen.getByRole('alert')).toHaveTextContent('Install the native Claude Code CLI');
  expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
});

it('explains an unqualified Hermes launcher without calling it a supported version', async () => {
  invoke.mockResolvedValue(response({ ...report, activeProfile: 'default', harnessVersion: 'unknown' }));
  open();
  fireEvent.change(screen.getByRole('combobox', { name: 'Harness' }), { target: { value: 'hermes' } });
  fireEvent.change(screen.getByRole('textbox', { name: 'Hermes profile' }), { target: { value: 'default' } });
  preview();
  expect(await screen.findByText(/Hermes was found, but this launcher cannot connect automatically yet/)).toBeVisible();
  expect(screen.queryByText('Hermes unknown')).not.toBeInTheDocument();
  expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
});

it('explains an unavailable Hermes home separately from a missing executable', async () => {
  invoke.mockRejectedValue({ code: 'not_found', message: 'Hermes default profile was not found', fieldPath: null, retryable: false });
  open();
  fireEvent.change(screen.getByRole('combobox', { name: 'Harness' }), { target: { value: 'hermes' } });
  fireEvent.change(screen.getByRole('textbox', { name: 'Hermes profile' }), { target: { value: 'default' } });
  preview();
  expect(await screen.findByRole('alert')).toHaveTextContent('Hermes home folder is unavailable');
  expect(screen.getByRole('alert')).not.toHaveTextContent('executable was not found');
});

it.each([
  { ...report, capability: 'PRIVATE-INVALID' },
  { ...report, activeProfile: 'another-profile' },
  { ...report, executableSha256: 'PRIVATE-HASH' },
  { ...report, unexpected: true },
  { ...report, capability: 'full', executable: null },
])('rejects invalid discovery %# without exposing raw payloads or requesting a plan', async value => {
  invoke.mockImplementation(async (_command, { request }: { request: LocalRequest }) => { requests.push(request); return response(value); });
  open(); preview();
  expect(await screen.findByRole('alert')).toHaveTextContent(/Could not review this setup/i);
  expect(requests).toEqual([{ method: 'harness_probe', params }]);
  expect(screen.queryByText(/PRIVATE-/)).not.toBeInTheDocument();
  expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
});
