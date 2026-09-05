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
  policyConflicts: [], capability: 'import_only' };
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
function preview() { fireEvent.click(screen.getByRole('button', { name: 'Check connection' })); }

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
  expect(screen.getByRole('button', { name: 'Check connection' })).toBeEnabled();
});

it('requests a fresh exact plan only after Full discovery and still requires approval', async () => {
  invoke.mockImplementation(async (_command, { request }: { request: LocalRequest }) => {
    requests.push(request);
    if (request.method === 'harness_probe') return response({ ...report, capability: 'full' });
    return { kind: 'plan', data: { plan: { ...fixture, expiresAt: String(Date.now() + 60_000), targetScopes: [{ scope: 'project', projectId, root: fixture.executablePath }] } } };
  });
  open(); preview();
  expect(await screen.findByRole('heading', { name: 'Review connection changes' })).toBeVisible();
  expect(requests).toEqual([{ method: 'harness_probe', params }, { method: 'harness_preview', params }]);
  expect(screen.getByRole('button', { name: 'Apply reviewed plan' })).toBeDisabled();
});

it('discards discovery after selection changes without requesting the obsolete plan', async () => {
  let resolve!: (value: unknown) => void;
  invoke.mockImplementation(async (_command, { request }: { request: LocalRequest }) => {
    requests.push(request);
    return new Promise(done => { resolve = done; });
  });
  open(); preview();
  await waitFor(() => expect(requests).toHaveLength(1));
  fireEvent.change(screen.getByRole('combobox', { name: 'AI app' }), { target: { value: 'claude_code' } });
  await act(async () => resolve(response({ ...report, capability: 'full' })));
  expect(requests).toEqual([{ method: 'harness_probe', params }]);
  expect(screen.queryByRole('heading', { name: 'Review connection changes' })).not.toBeInTheDocument();
  expect(screen.queryByText(/0\.144\.6/)).not.toBeInTheDocument();
});

it('binds Hermes discovery and approval to its canonical profile name', async () => {
  invoke.mockImplementation(async (_command, { request }: { request: LocalRequest }) => {
    requests.push(request);
    if (request.method === 'harness_probe') return response({ ...report, capability: 'full', activeProfile: 'coder' });
    return { kind: 'plan', data: { plan: { ...fixture, harness: 'hermes', harnessProfile: 'coder', expiresAt: String(Date.now() + 60_000), targetScopes: [{ scope: 'project', projectId, root: fixture.executablePath }] } } };
  });
  open();
  fireEvent.change(screen.getByRole('combobox', { name: 'AI app' }), { target: { value: 'hermes' } });
  fireEvent.change(screen.getByRole('textbox', { name: 'Hermes profile' }), { target: { value: ' Coder ' } });
  preview();
  expect(await screen.findByRole('heading', { name: 'Review connection changes' })).toBeVisible();
  expect(requests).toEqual(['harness_probe', 'harness_preview'].map(method => ({ method, params: { harness: 'hermes', projectId, hermesProfile: 'coder' } })));
  expect(screen.getByRole('checkbox', { name: /I reviewed/ })).toBeEnabled();
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
  expect(await screen.findByRole('alert')).toHaveTextContent(/preview could not be loaded/i);
  expect(requests).toEqual([{ method: 'harness_probe', params }]);
  expect(screen.queryByText(/PRIVATE-/)).not.toBeInTheDocument();
  expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
});
