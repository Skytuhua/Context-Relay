import { readFileSync } from 'node:fs';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { DecimalU64, LocalRequest, ProjectId, ProjectIdentity, SetupPlan } from './bindings';

const invoke = vi.hoisted(() => vi.fn());
vi.mock('@tauri-apps/api/core', () => ({ invoke }));
import App from './App';
import { LocalWorkspaceGateway } from './workspace';

const projectId = '018f22e2-79b0-7cc8-98c4-dc0c0c075001' as ProjectId;
const secondProject = '018f22e2-79b0-7cc8-98c4-dc0c0c075002' as ProjectId;
const projects: ProjectIdentity[] = [projectId, secondProject].map((id, index) => ({
  projectId: id, name: index ? 'Second project' : 'Research', githubRepositoryId: null,
  gitRemoteFingerprint: null, monorepoSubdirectory: null,
}));
let preview: SetupPlan;
let operation: (request: LocalRequest) => Promise<unknown>;
let requests: LocalRequest[];

beforeEach(() => {
  requests = [];
  const fixture = JSON.parse(readFileSync('../../crates/protocol/tests/fixtures/runtime-contracts-v1.json', 'utf8')).setupPlan as SetupPlan;
  preview = { ...fixture, expiresAt: String(Date.now() + 60_000) as DecimalU64,
    targetScopes: [{ scope: 'project', projectId, root: fixture.executablePath }],
    semanticChanges: [{ class: 'create', target: '.codex/config.toml', summary: 'Register Context Relay' }],
  };
  operation = async (request) => request.method === 'harness_preview'
    ? { kind: 'plan', data: { plan: preview } } : { kind: 'empty' };
  invoke.mockReset().mockImplementation(async (_command, { request }: { request: LocalRequest }) => {
    if (request.method === 'sync_status') return { kind: 'status', data: { status: {
      protocol: { min: { major: 1, minor: 5 }, max: { major: 1, minor: 5 } }, vault: 'unlocked',
      resolvedProject: null, sync: 'offline', access: { mode: 'default' },
    } } };
    if (request.method === 'projects_list') return { kind: 'projects', data: { projects } };
    // Discovery ordering and capabilities are exercised by harness-discovery.test.tsx.
    // This suite records the subsequent preview/apply/rollback lifecycle.
    if (request.method === 'harness_probe') return { kind: 'probe', data: { report: {
      executable: fixture.executablePath, executableSha256: fixture.executableHash,
      harnessVersion: fixture.harnessVersion, installationMethod: 'manual', configRoots: [],
      activeProfile: request.params.hermesProfile, policyConflicts: [], capability: 'full',
    } } };
    requests.push(request);
    return operation(request);
  });
});
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });

async function open() {
  const result = render(<App gateway={new LocalWorkspaceGateway()} />);
  await screen.findByText('Ready on this computer');
  fireEvent.click(screen.getByRole('button', { name: 'AI apps' }));
  return result;
}
async function review() {
  fireEvent.click(screen.getByRole('button', { name: 'Check connection' }));
  await screen.findByRole('heading', { name: 'Review connection changes' });
}
function approve() {
  fireEvent.click(screen.getByRole('checkbox', { name: /I reviewed/ }));
  fireEvent.click(screen.getByRole('button', { name: 'Apply reviewed plan' }));
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

it('requires explicit review, applies only the exact stored ID, and awaits acknowledgment', async () => {
  const pending = deferred<unknown>();
  operation = async (request) => request.method === 'harness_preview'
    ? { kind: 'plan', data: { plan: preview } } : pending.promise;
  await open();
  await review();
  expect(screen.getByRole('button', { name: 'Apply reviewed plan' })).toBeDisabled();
  expect(requests).toEqual([{ method: 'harness_preview', params: { harness: 'codex', projectId, hermesProfile: null } }]);
  approve();
  fireEvent.click(screen.getByRole('button', { name: /Applying/ }));
  expect(requests).toHaveLength(2);
  expect(requests[1]).toEqual({ method: 'harness_apply', params: { planId: '018f22e2-79b0-7cc8-98c4-dc0c0c07398f' } });
  expect(screen.queryByText(/Setup applied/)).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Check connection' })).toBeDisabled();
  await act(async () => pending.resolve({ kind: 'empty' }));
  expect(await screen.findByText(/Setup applied/)).toBeVisible();
});

it('shows safe apply failure, clears approval and never creates a rollback success record', async () => {
  operation = async (request) => {
    if (request.method === 'harness_preview') return { kind: 'plan', data: { plan: preview } };
    throw new Error('PRIVATE-SECRET-PATH');
  };
  await open(); await review(); approve();
  expect(await screen.findByRole('alert')).toHaveTextContent(/could not be confirmed/i);
  expect(screen.queryByText(/PRIVATE-SECRET/)).not.toBeInTheDocument();
  expect(screen.queryByText(/Setup applied/)).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: /Roll back/ })).not.toBeInTheDocument();
  expect(screen.queryByRole('checkbox', { name: /I reviewed/ })).not.toBeInTheDocument();
  expect(requests.filter((r) => r.method === 'harness_apply')).toHaveLength(1);
});

it.each(['Project', 'AI app'])('clears approval when %s selection changes', async (label) => {
  await open(); await review();
  fireEvent.click(screen.getByRole('checkbox', { name: /I reviewed/ }));
  fireEvent.change(screen.getByRole('combobox', { name: label }), { target: { value: label === 'Project' ? secondProject : 'claude_code' } });
  expect(screen.queryByRole('button', { name: 'Apply reviewed plan' })).not.toBeInTheDocument();
  expect(requests).toHaveLength(1);
});

it('ignores a late preview after selection changes and prevents overlapping previews', async () => {
  const pending = deferred<unknown>(); operation = async () => pending.promise;
  await open();
  fireEvent.click(screen.getByRole('button', { name: 'Check connection' }));
  await waitFor(() => expect(requests).toHaveLength(1));
  fireEvent.change(screen.getByRole('combobox', { name: 'Project' }), { target: { value: secondProject } });
  fireEvent.click(screen.getByRole('button', { name: /Checking app/ }));
  expect(requests).toHaveLength(1);
  await act(async () => pending.resolve({ kind: 'plan', data: { plan: preview } }));
  expect(screen.queryByRole('heading', { name: 'Review connection changes' })).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Check connection' })).toBeEnabled();
});

it('ignores preview responses after leaving the screen', async () => {
  const pending = deferred<unknown>(); operation = async () => pending.promise;
  await open();
  fireEvent.click(screen.getByRole('button', { name: 'Check connection' }));
  await waitFor(() => expect(requests).toHaveLength(1));
  fireEvent.click(screen.getByRole('button', { name: 'Home' }));
  await act(async () => pending.resolve({ kind: 'plan', data: { plan: preview } }));
  fireEvent.click(screen.getByRole('button', { name: 'AI apps' }));
  expect(screen.queryByRole('heading', { name: 'Review connection changes' })).not.toBeInTheDocument();
});

it('requires an explicit Hermes profile and clears reviewed approval when it changes', async () => {
  await open();
  fireEvent.change(screen.getByRole('combobox', { name: 'AI app' }), { target: { value: 'hermes' } });
  expect(screen.getByRole('button', { name: 'Check connection' })).toBeDisabled();
  fireEvent.change(screen.getByRole('textbox', { name: 'Hermes profile' }), { target: { value: 'coder' } });
  preview.harness = 'hermes'; preview.harnessProfile = 'coder';
  await review();
  expect(requests[0]).toEqual({ method: 'harness_preview', params: { harness: 'hermes', projectId, hermesProfile: 'coder' } });
  fireEvent.click(screen.getByRole('checkbox', { name: /I reviewed/ }));
  fireEvent.change(screen.getByRole('textbox', { name: 'Hermes profile' }), { target: { value: 'other' } });
  expect(screen.queryByRole('button', { name: 'Apply reviewed plan' })).not.toBeInTheDocument();
});

it.each(['conflict', 'expiry'])('blocks approval because of %s independently', async (reason) => {
  if (reason === 'conflict') preview.semanticChanges = [{ class: 'conflict', target: 'config', summary: 'Existing managed block conflicts' }];
  else preview.expiresAt = '1' as DecimalU64;
  await open(); await review();
  expect(screen.getByText(reason === 'conflict' ? /Resolve conflicts/i : /plan has expired/i)).toBeVisible();
  expect(screen.getByRole('checkbox', { name: /I reviewed/ })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Apply reviewed plan' })).toBeDisabled();
});

it('expires an approved plan while the screen is open', async () => {
  await open(); await review();
  fireEvent.click(screen.getByRole('checkbox', { name: /I reviewed/ }));
  vi.spyOn(Date, 'now').mockReturnValue(Number(preview.expiresAt) + 1);
  await waitFor(() => expect(screen.getByRole('button', { name: 'Apply reviewed plan' })).toBeDisabled(), { timeout: 2000 });
  expect(requests).toHaveLength(1);
});

it('clears old review when refreshing a preview', async () => {
  await open(); await review();
  fireEvent.click(screen.getByRole('checkbox', { name: /I reviewed/ }));
  await review();
  expect(screen.getByRole('checkbox', { name: /I reviewed/ })).not.toBeChecked();
  expect(screen.getByRole('button', { name: 'Apply reviewed plan' })).toBeDisabled();
});

it('retains rollback for the acknowledged plan after selection changes and requires confirmation', async () => {
  await open(); await review(); approve();
  await screen.findByText(/Setup applied/);
  fireEvent.change(screen.getByRole('combobox', { name: 'Project' }), { target: { value: secondProject } });
  fireEvent.change(screen.getByRole('combobox', { name: 'AI app' }), { target: { value: 'claude_code' } });
  fireEvent.click(screen.getByRole('button', { name: 'Roll back Codex for Research' }));
  expect(requests).toHaveLength(2);
  fireEvent.click(screen.getByRole('button', { name: 'Confirm rollback' }));
  await screen.findByText(/Rollback completed/);
  expect(requests[2]).toEqual({ method: 'harness_rollback', params: { planId: '018f22e2-79b0-7cc8-98c4-dc0c0c07398f' } });
});

it('keeps a pending apply exclusive across navigation and retains its acknowledged rollback', async () => {
  const pending = deferred<unknown>();
  operation = async (request) => request.method === 'harness_preview'
    ? { kind: 'plan', data: { plan: preview } } : pending.promise;
  await open(); await review(); approve();
  fireEvent.click(screen.getByRole('button', { name: 'Home' }));
  fireEvent.click(screen.getByRole('button', { name: 'AI apps' }));
  expect(screen.getByRole('button', { name: 'Check connection' })).toBeDisabled();
  await act(async () => pending.resolve({ kind: 'empty' }));
  expect(await screen.findByRole('button', { name: 'Roll back Codex for Research' })).toBeEnabled();
});

it('requires fresh approval after navigating away from a reviewed preview', async () => {
  await open(); await review();
  fireEvent.click(screen.getByRole('checkbox', { name: /I reviewed/ }));
  fireEvent.click(screen.getByRole('button', { name: 'Home' }));
  fireEvent.click(screen.getByRole('button', { name: 'AI apps' }));
  expect(screen.queryByRole('button', { name: 'Apply reviewed plan' })).not.toBeInTheDocument();
});

it('keeps rollback available after failure and requires new confirmation for retry', async () => {
  await open(); await review(); approve(); await screen.findByText(/Setup applied/);
  operation = async () => { throw new Error('PRIVATE-ROLLBACK'); };
  fireEvent.click(screen.getByRole('button', { name: 'Roll back Codex for Research' }));
  fireEvent.click(screen.getByRole('button', { name: 'Confirm rollback' }));
  expect(await screen.findByRole('alert')).toHaveTextContent(/Rollback could not be confirmed/);
  expect(screen.queryByText(/PRIVATE-ROLLBACK|Rollback completed/)).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Confirm rollback' })).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Roll back Codex for Research' })).toBeEnabled();
});

it('can cancel rollback and awaits acknowledgment without duplicate or overlapping actions', async () => {
  await open(); await review(); approve(); await screen.findByText(/Setup applied/);
  fireEvent.click(screen.getByRole('button', { name: 'Roll back Codex for Research' }));
  fireEvent.click(screen.getByRole('button', { name: 'Cancel rollback' }));
  expect(requests).toHaveLength(2);
  const pending = deferred<unknown>(); operation = async () => pending.promise;
  fireEvent.click(screen.getByRole('button', { name: 'Roll back Codex for Research' }));
  fireEvent.click(screen.getByRole('button', { name: 'Confirm rollback' }));
  fireEvent.click(screen.getByRole('button', { name: 'Roll back Codex for Research' }));
  expect(requests).toHaveLength(3);
  expect(screen.getByRole('button', { name: 'Check connection' })).toBeDisabled();
  expect(screen.queryByText(/Rollback completed/)).not.toBeInTheDocument();
  await act(async () => pending.resolve({ kind: 'empty' }));
  expect(await screen.findByText(/Rollback completed/)).toBeVisible();
});

it('shows bytes when the native display string is empty', async () => {
  preview.executablePath = { ...preview.executablePath, display: '' };
  await open(); await review();
  expect(screen.getByText(/Executable: windows bytes \(base64url\): YwA/)).toBeVisible();
});

it('rejects malformed previews without rendering plaintext errors or unsafe HTML', async () => {
  operation = async () => ({ kind: 'plan', data: { plan: { ...preview, batchHash: 'PRIVATE-MALFORMED' } } });
  await open(); fireEvent.click(screen.getByRole('button', { name: 'Check connection' }));
  expect(await screen.findByRole('alert')).toHaveTextContent(/preview could not be loaded/i);
  expect(screen.queryByText(/PRIVATE-MALFORMED/)).not.toBeInTheDocument();
  expect(screen.queryByRole('checkbox', { name: /I reviewed/ })).not.toBeInTheDocument();
});

it('shows review changes, permissions, network, CLI, artifacts and honest native byte fallback', async () => {
  preview.executablePath.display = null;
  preview.semanticChanges[0].summary = '<img src=x onerror=alert(1)>';
  preview.permissionDelta.added = ['Read project'];
  preview.networkDelta.added = [{ scheme: 'https', host: 'example.com', port: 443 }];
  preview.cliOperations = [{ executable: preview.executablePath, arguments: [{ ...preview.executablePath, display: '--register' }], timeoutMs: 2000 }];
  preview.packageArtifacts = [{ packageId: preview.planId as unknown as SetupPlan['packageArtifacts'][number]['packageId'],
    immutableSourceRef: 'git:example@commit', resolvedCommit: 'a'.repeat(40), archiveDigest: preview.batchHash,
    artifactPath: { ...preview.executablePath, display: 'bridge.zip' }, artifactDigest: preview.batchHash, dependencies: [],
  }];
  await open(); await review();
  expect(screen.getAllByText(/windows bytes \(base64url\): YwA/).length).toBeGreaterThan(0);
  expect(screen.getByText('<img src=x onerror=alert(1)>')).toBeVisible();
  expect(document.querySelector('img')).toBeNull();
  expect(screen.getByText('Read project')).toBeVisible();
  expect(screen.getByText('https://example.com:443')).toBeVisible();
  expect(screen.getByText('--register')).toBeVisible();
  expect(screen.getByText('bridge.zip')).toBeVisible();
  expect(screen.getByText('Technical verification details')).toBeVisible();
});
