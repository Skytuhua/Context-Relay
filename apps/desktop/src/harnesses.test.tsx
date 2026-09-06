import { readFileSync } from 'node:fs';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { DecimalU64, HarnessExecutionParams, HarnessExecutionStatus, HarnessSetupRecord, LocalRequest, ProjectId, ProjectIdentity, SetupPlan } from './bindings';

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
let saved: Map<string, HarnessSetupRecord>;
let current: HarnessExecutionStatus | null;
function finished(params: HarnessExecutionParams = { planId: preview.planId, action: 'apply' }) {
  return { kind: 'harness_execution', data: { status: { ...params, phase: 'finished', error: null } } };
}

beforeEach(() => {
  requests = [];
  saved = new Map(); current = null;
  const fixture = JSON.parse(readFileSync('../../crates/protocol/tests/fixtures/runtime-contracts-v1.json', 'utf8')).setupPlan as SetupPlan;
  preview = { ...fixture, rulesyncVersion: 'bridge-preview-v1', expiresAt: String(Date.now() + 60_000) as DecimalU64,
    targetScopes: [{ scope: 'project', projectId, root: fixture.executablePath }],
    semanticChanges: [{ class: 'create', target: '.codex/config.toml', summary: 'Register Context Relay' }],
  };
  operation = async (request) => request.method === 'harness_preview'
    ? { kind: 'plan', data: { plan: preview } } : request.method === 'harness_execution_start' ? finished(request.params) : { kind: 'empty' };
  invoke.mockReset().mockImplementation(async (_command, { request }: { request: LocalRequest }) => {
    if (request.method === 'sync_status') return { kind: 'status', data: { status: {
      protocol: { min: { major: 1, minor: 10 }, max: { major: 1, minor: 10 } }, vault: 'unlocked',
      resolvedProject: null, sync: 'offline', access: { mode: 'default' },
    } } };
    if (request.method === 'projects_list') return { kind: 'projects', data: { projects } };
    // Discovery ordering and capabilities are exercised by harness-discovery.test.tsx.
    // This suite records the subsequent preview/apply/rollback lifecycle.
    if (request.method === 'harness_probe') return { kind: 'probe', data: { report: {
      executable: fixture.executablePath, executableSha256: fixture.executableHash,
      harnessVersion: fixture.harnessVersion, installationMethod: 'manual', configRoots: [],
      activeProfile: request.params.hermesProfile, codexSavedHookApproval: null, policyConflicts: [], capability: 'full',
    } } };
    if (request.method === 'desktop_writes_list') return { kind: 'desktop_writes', data: { page: { writes: [], nextCursor: null } } };
    if (request.method === 'harness_execution_current') return { kind: 'harness_execution_current', data: { status: current } };
    if (request.method === 'harness_execution_status') return { kind: 'harness_execution', data: { status: current ?? { ...request.params, phase: 'unknown', error: null } } };
    if (request.method === 'harness_setup_get') return { kind: 'harness_setup', data: { setup: saved.get(request.params.planId) } };
    if (request.method === 'harness_setups_list') return { kind: 'harness_setups', data: { page: { nextAfter: null, setups: [...saved.values()].sort((a, b) => b.plan.planId.localeCompare(a.plan.planId)).map(({ plan, state, createdAt }) => ({ planId: plan.planId, harness: plan.harness, harnessProfile: plan.harnessProfile,
      targetScopes: plan.targetScopes.map(scope => scope.scope === 'project' ? { scope: 'project', projectId: scope.projectId } : scope), state, createdAt, expiresAt: plan.expiresAt })) } } };
    requests.push(request);
    if (request.method === 'harness_execution_start') {
      current = { ...request.params, phase: 'queued', error: null };
      try {
        const result = await operation(request) as ReturnType<typeof finished>;
        if (result.kind === 'harness_execution') {
          current = result.data.status as HarnessExecutionStatus;
          const record = saved.get(request.params.planId);
          if (record && current.phase === 'finished' && current.error === null) record.state = request.params.action === 'apply' ? 'applied' : 'rolled_back';
        }
        return result;
      } catch (error) {
        current = { ...request.params, phase: 'finished', error: { code: 'internal', message: 'PRIVATE NATIVE ERROR', fieldPath: null, retryable: false } };
        throw error;
      }
    }
    const result = await operation(request);
    if (request.method === 'harness_preview' && result && typeof result === 'object' && 'data' in result) {
      const plan = (result.data as { plan: SetupPlan }).plan;
      if (plan) saved.set(plan.planId, { plan: structuredClone(plan), state: 'previewed', createdAt: '1900000000000' });
    }
    return result;
  });
});
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });

async function open(waitUntilReady = true) {
  const result = render(<App gateway={new LocalWorkspaceGateway()} />);
  await screen.findByText('Ready on this computer');
  fireEvent.click(screen.getByRole('button', { name: 'Harnesses' }));
  if (waitUntilReady) await waitFor(() => expect(screen.getByRole('button', { name: 'Review setup' })).toBeEnabled());
  return result;
}
async function review() {
  fireEvent.click(screen.getByRole('button', { name: 'Review setup' }));
  await screen.findByRole('heading', { name: 'Review setup changes' });
}
function approve() {
  fireEvent.click(screen.getByRole('checkbox', { name: /I reviewed/ }));
  fireEvent.click(screen.getByRole('button', { name: 'Save settings' }));
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

it('keeps an accepted save pending beyond 30 seconds without resending or claiming success', async () => {
  operation = async request => request.method === 'harness_preview' ? { kind: 'plan', data: { plan: preview } }
    : request.method === 'harness_execution_start' ? { kind: 'harness_execution', data: { status: { ...request.params, phase: 'running', error: null } } } : { kind: 'empty' };
  await open(); await review();
  vi.useFakeTimers();
  await act(async () => approve());
  await act(async () => { await vi.advanceTimersByTimeAsync(31_000); });
  expect(screen.getByText('Saving harness settings…')).toBeVisible();
  expect(screen.queryByText(/Settings saved:/)).not.toBeInTheDocument();
  expect(requests.filter(request => request.method === 'harness_execution_start')).toHaveLength(1);
  expect(invoke.mock.calls.filter(call => call[1]?.request?.method === 'harness_execution_status').length).toBeGreaterThan(20);
  current = { planId: preview.planId, action: 'apply', phase: 'finished', error: null };
  saved.get(preview.planId)!.state = 'applied';
  await act(async () => { await vi.advanceTimersByTimeAsync(2_000); });
  vi.useRealTimers();
  expect(await screen.findByText(/Settings saved:/)).toBeVisible();
});

it('recovers a lost save acknowledgement by reading the original result without resending', async () => {
  const originalStart = LocalWorkspaceGateway.prototype.harnessExecutionStart;
  vi.spyOn(LocalWorkspaceGateway.prototype, 'harnessExecutionStart').mockImplementation(async function(this: LocalWorkspaceGateway, params) {
    await originalStart.call(this, params);
    throw new Error('Lost acknowledgement');
  });
  await open(); await review(); approve();
  expect(await screen.findByText(/Settings saved:/)).toBeVisible();
  expect(requests.filter(request => request.method === 'harness_execution_start')).toEqual([
    { method: 'harness_execution_start', params: { planId: preview.planId, action: 'apply' } },
  ]);
});

it('keeps the same pending save across a failed progress read', async () => {
  saved.set(preview.planId, { plan: preview, state: 'applying', createdAt: '1900000000000' });
  current = { planId: preview.planId, action: 'apply', phase: 'running', error: null };
  vi.spyOn(LocalWorkspaceGateway.prototype, 'harnessExecutionStatus').mockRejectedValueOnce(new Error('PRIVATE STATUS ERROR'));
  await open(false);
  await screen.findByText('Saving harness settings…');
  vi.useFakeTimers();
  // Restart the observer so its retry timer is owned by this test clock.
  fireEvent.click(screen.getByRole('button', { name: 'Home' }));
  await act(async () => fireEvent.click(screen.getByRole('button', { name: 'Harnesses' })));
  await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
  expect(screen.getByRole('alert')).toHaveTextContent('Reconnecting to check the same setup');
  expect(screen.getByRole('button', { name: 'Review setup' })).toBeDisabled();
  expect(screen.queryByText(/PRIVATE STATUS ERROR|Settings saved:/)).not.toBeInTheDocument();
  saved.get(preview.planId)!.state = 'applied';
  current = { ...current!, phase: 'finished' };
  await act(async () => { await vi.advanceTimersByTimeAsync(2000); });
  vi.useRealTimers();
  expect(await screen.findByText(/Settings saved:/)).toBeVisible();
  expect(requests).toEqual([]);
});

it('discovers a running save after remount and postpones ordinary history reads', async () => {
  saved.set(preview.planId, { plan: preview, state: 'applying', createdAt: '1900000000000' });
  current = { planId: preview.planId, action: 'apply', phase: 'running', error: null };
  const view = await open(false);
  await screen.findByText('Saving harness settings…');
  view.unmount();
  invoke.mockClear();
  await open(false);
  await screen.findByText('Saving harness settings…');
  const observed = invoke.mock.calls.map(call => call[1]?.request?.method);
  expect(observed).toContain('harness_execution_current');
  expect(observed).not.toContain('harness_setups_list');
  expect(observed).not.toContain('harness_execution_start');
  expect(screen.queryByText(/Settings saved:/)).not.toBeInTheDocument();
});

it('reloads saved setup history after a complete desktop and daemon restart and undoes the original', async () => {
  const original = structuredClone(preview);
  saved.set(original.planId, { plan: original, state: 'applied', createdAt: '1900000000000' });
  current = null; // No in-memory attempt exists after daemon restart.
  await open();
  fireEvent.change(screen.getByRole('combobox', { name: 'Project' }), { target: { value: secondProject } });
  fireEvent.click(await screen.findByRole('button', { name: 'Undo setup 0C07398F for Codex for Research' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Undo setup changes' }));
  expect(await screen.findByText(/Setup changes undone:/)).toBeVisible();
  expect(requests).toEqual([{ method: 'harness_execution_start', params: { planId: original.planId, action: 'rollback' } }]);
});

it('shows an ownerless claim as interrupted and resumes only after reviewing the exact original', async () => {
  saved.set(preview.planId, { plan: preview, state: 'applying', createdAt: '1900000000000' });
  await open();
  expect(await screen.findByText('Save interrupted — review before resuming.')).toBeVisible();
  expect(screen.queryByText('Saving harness settings…')).not.toBeInTheDocument();
  expect(requests).toEqual([]);
  fireEvent.click(screen.getByRole('button', { name: 'Review saved setup for Codex for Research' }));
  await screen.findByRole('heading', { name: 'Review setup changes' });
  expect(screen.getByRole('button', { name: 'Resume save' })).toBeDisabled();
  fireEvent.click(screen.getByRole('checkbox', { name: /I reviewed/ }));
  fireEvent.click(screen.getByRole('button', { name: 'Resume save' }));
  expect(await screen.findByText(/Settings saved:/)).toBeVisible();
  expect(requests).toEqual([{ method: 'harness_execution_start', params: { planId: preview.planId, action: 'apply' } }]);
});

it('requires a fresh review when an interrupted save has expired', async () => {
  preview.expiresAt = '1' as DecimalU64;
  saved.set(preview.planId, { plan: preview, state: 'applying', createdAt: '1900000000000' });
  await open();
  fireEvent.click(await screen.findByRole('button', { name: 'Review saved setup for Codex for Research' }));
  await screen.findByRole('heading', { name: 'Review setup changes' });
  expect(screen.getByText('This setup review has expired. Select Review setup again.')).toBeVisible();
  expect(screen.getByRole('checkbox', { name: /I reviewed/ })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Resume save' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Review setup' })).toBeEnabled();
  expect(screen.queryByText(/Settings saved:/)).not.toBeInTheDocument();
  expect(requests).toEqual([]);
});

it('does not treat a failed Undo on an Applied plan as a successful Undo', async () => {
  saved.set(preview.planId, { plan: preview, state: 'applied', createdAt: '1900000000000' });
  current = { planId: preview.planId, action: 'rollback', phase: 'finished', error: { code: 'conflict', message: 'PRIVATE-PATH', fieldPath: null, retryable: false } };
  await open();
  expect(screen.getByRole('alert')).toHaveTextContent('Undo reported a problem. Settings saved');
  expect(screen.queryByText(/PRIVATE-PATH|Setup changes undone/)).not.toBeInTheDocument();
  expect(requests).toEqual([]);
});

it('keeps pagination available when the first history page contains only excluded plans', async () => {
  const cursor = 'ffffffff-ffff-7cc8-98c4-dc0c0c073990' as SetupPlan['planId'];
  saved.set(preview.planId, { plan: preview, state: 'applied', createdAt: '1900000000000' });
  const originalList = LocalWorkspaceGateway.prototype.harnessSetupsList;
  const list = vi.spyOn(LocalWorkspaceGateway.prototype, 'harnessSetupsList').mockImplementationOnce(async () => ({ setups: [], nextAfter: cursor }))
    .mockImplementation(function(this: LocalWorkspaceGateway, after) { return originalList.call(this, after); });
  await open();
  fireEvent.click(await screen.findByRole('button', { name: 'Load more setups' }));
  expect(await screen.findByRole('button', { name: 'Undo setup 0C07398F for Codex for Research' })).toBeVisible();
  expect(list).toHaveBeenLastCalledWith(cursor);
});

it('requires explicit review, applies only the exact stored ID, and awaits acknowledgment', async () => {
  const pending = deferred<unknown>();
  operation = async (request) => request.method === 'harness_preview'
    ? { kind: 'plan', data: { plan: preview } } : pending.promise;
  await open();
  await review();
  expect(screen.getByRole('button', { name: 'Save settings' })).toBeDisabled();
  expect(requests).toEqual([{ method: 'harness_preview', params: { harness: 'codex', projectId, hermesProfile: null } }]);
  approve();
  fireEvent.submit(screen.getByRole('form', { name: 'Review harness setup' }));
  expect(requests).toHaveLength(2);
  expect(requests[1]).toEqual({ method: 'harness_execution_start', params: { action: 'apply', planId: '018f22e2-79b0-7cc8-98c4-dc0c0c07398f' } });
  expect(screen.queryByText(/Connected:/)).not.toBeInTheDocument();
  expect(screen.queryByRole('region', { name: /Finish setup/ })).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Review setup' })).toBeDisabled();
  await act(async () => pending.resolve(finished()));
  expect(await screen.findByText(/Settings saved:/)).toBeVisible();
  expect(screen.queryByText(/Connected:/)).not.toBeInTheDocument();
  const next = screen.getByRole('region', { name: 'Finish setup for Codex for Research' });
  expect(within(next).getByText('/hooks')).toBeVisible();
  expect(within(next).getByText('SessionStart')).toBeVisible();
  expect(within(next).getByText('Stop')).toBeVisible();
  expect(within(next).getByText(/Connection has not been verified/)).toBeVisible();
});

it('keeps Codex approval guidance with its saved project when the selection changes', async () => {
  await open(); await review(); approve();
  await screen.findByText(/Settings saved:/);
  fireEvent.change(screen.getByRole('combobox', { name: 'Project' }), { target: { value: secondProject } });
  fireEvent.change(screen.getByRole('combobox', { name: 'Harness' }), { target: { value: 'claude_code' } });
  const next = screen.getByRole('region', { name: 'Finish setup for Codex for Research' });
  expect(within(next).getByText(/Open the Codex CLI/)).toHaveTextContent('Research');
  expect(within(next).queryByText(/Second project/)).not.toBeInTheDocument();
  expect(requests.map(request => request.method)).toEqual(['harness_preview', 'harness_execution_start']);
});

it.each(['claude_code', 'hermes'] as const)('does not claim a verified connection or give Codex approval steps for %s', async (harness) => {
  preview.harness = harness;
  preview.harnessProfile = harness === 'hermes' ? 'default' : null;
  await open();
  fireEvent.change(screen.getByRole('combobox', { name: 'Harness' }), { target: { value: harness } });
  await review(); approve();
  await screen.findByText(/Settings saved:/);
  const next = screen.getByRole('region', { name: /Finish setup/ });
  expect(within(next).getByText('Connection has not been verified')).toBeVisible();
  expect(within(next).getByText(/Start a new/)).toHaveTextContent('Research');
  expect(within(next).queryByText('/hooks')).not.toBeInTheDocument();
  expect(screen.queryByText(/Connected:/)).not.toBeInTheDocument();
});

it('shows safe apply failure, clears approval and never creates a rollback success record', async () => {
  operation = async (request) => {
    if (request.method === 'harness_preview') return { kind: 'plan', data: { plan: preview } };
    throw new Error('PRIVATE-SECRET-PATH');
  };
  await open(); await review(); approve();
  await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(/Save reported a problem/i));
  expect(screen.queryByText(/PRIVATE-SECRET/)).not.toBeInTheDocument();
  expect(screen.queryByText(/Connected:/)).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: /Undo setup/ })).not.toBeInTheDocument();
  expect(screen.queryByRole('checkbox', { name: /I reviewed/ })).not.toBeInTheDocument();
  expect(requests.filter((r) => r.method === 'harness_execution_start')).toHaveLength(1);
});

it.each(['Project', 'Harness'])('clears approval when %s selection changes', async (label) => {
  await open(); await review();
  fireEvent.click(screen.getByRole('checkbox', { name: /I reviewed/ }));
  fireEvent.change(screen.getByRole('combobox', { name: label }), { target: { value: label === 'Project' ? secondProject : 'claude_code' } });
  expect(screen.queryByRole('button', { name: 'Save settings' })).not.toBeInTheDocument();
  expect(requests).toHaveLength(1);
});

it('ignores a late preview after selection changes and prevents overlapping previews', async () => {
  const pending = deferred<unknown>(); operation = async () => pending.promise;
  await open();
  fireEvent.click(screen.getByRole('button', { name: 'Review setup' }));
  await waitFor(() => expect(requests).toHaveLength(1));
  fireEvent.change(screen.getByRole('combobox', { name: 'Project' }), { target: { value: secondProject } });
  fireEvent.click(screen.getByRole('button', { name: /Checking harness/ }));
  expect(requests).toHaveLength(1);
  await act(async () => pending.resolve({ kind: 'plan', data: { plan: preview } }));
  expect(screen.queryByRole('heading', { name: 'Review setup changes' })).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Review setup' })).toBeEnabled();
});

it('ignores preview responses after leaving the screen', async () => {
  const pending = deferred<unknown>(); operation = async () => pending.promise;
  await open();
  fireEvent.click(screen.getByRole('button', { name: 'Review setup' }));
  await waitFor(() => expect(requests).toHaveLength(1));
  fireEvent.click(screen.getByRole('button', { name: 'Home' }));
  await act(async () => pending.resolve({ kind: 'plan', data: { plan: preview } }));
  fireEvent.click(screen.getByRole('button', { name: 'Harnesses' }));
  expect(screen.queryByRole('heading', { name: 'Review setup changes' })).not.toBeInTheDocument();
});

it('prefills the default Hermes profile, requires a name and clears approval when it changes', async () => {
  await open();
  fireEvent.change(screen.getByRole('combobox', { name: 'Harness' }), { target: { value: 'hermes' } });
  expect(screen.getByRole('textbox', { name: 'Hermes profile' })).toHaveValue('default');
  fireEvent.change(screen.getByRole('textbox', { name: 'Hermes profile' }), { target: { value: '' } });
  expect(screen.getByRole('button', { name: 'Review setup' })).toBeDisabled();
  fireEvent.change(screen.getByRole('textbox', { name: 'Hermes profile' }), { target: { value: 'coder' } });
  preview.harness = 'hermes'; preview.harnessProfile = 'coder';
  await review();
  expect(requests[0]).toEqual({ method: 'harness_preview', params: { harness: 'hermes', projectId, hermesProfile: 'coder' } });
  fireEvent.click(screen.getByRole('checkbox', { name: /I reviewed/ }));
  fireEvent.change(screen.getByRole('textbox', { name: 'Hermes profile' }), { target: { value: 'other' } });
  expect(screen.queryByRole('button', { name: 'Save settings' })).not.toBeInTheDocument();
});

it.each(['conflict', 'expiry'])('blocks approval because of %s independently', async (reason) => {
  if (reason === 'conflict') preview.semanticChanges = [{ class: 'conflict', target: 'config', summary: 'Existing managed block conflicts' }];
  else preview.expiresAt = '1' as DecimalU64;
  await open(); await review();
  expect(screen.getByText(reason === 'conflict' ? /Resolve the conflicting settings/i : /setup review has expired/i)).toBeVisible();
  expect(screen.getByRole('checkbox', { name: /I reviewed/ })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Save settings' })).toBeDisabled();
});

it('expires an approved plan while the screen is open', async () => {
  await open(); await review();
  fireEvent.click(screen.getByRole('checkbox', { name: /I reviewed/ }));
  vi.spyOn(Date, 'now').mockReturnValue(Number(preview.expiresAt) + 1);
  await waitFor(() => expect(screen.getByRole('button', { name: 'Save settings' })).toBeDisabled(), { timeout: 2000 });
  expect(requests).toHaveLength(1);
});

it('clears old review when refreshing a preview', async () => {
  await open(); await review();
  fireEvent.click(screen.getByRole('checkbox', { name: /I reviewed/ }));
  await review();
  expect(screen.getByRole('checkbox', { name: /I reviewed/ })).not.toBeChecked();
  expect(screen.getByRole('button', { name: 'Save settings' })).toBeDisabled();
});

it('retains rollback for the acknowledged plan after selection changes and requires confirmation', async () => {
  await open(); await review(); approve();
  await screen.findByText(/Settings saved:/);
  fireEvent.change(screen.getByRole('combobox', { name: 'Project' }), { target: { value: secondProject } });
  fireEvent.change(screen.getByRole('combobox', { name: 'Harness' }), { target: { value: 'claude_code' } });
  fireEvent.click(screen.getByRole('button', { name: 'Undo setup 0C07398F for Codex for Research' }));
  expect(requests).toHaveLength(2);
  fireEvent.click(await screen.findByRole('button', { name: 'Undo setup changes' }));
  await screen.findByText(/Setup changes undone:/);
  expect(screen.queryByRole('region', { name: /Finish setup/ })).not.toBeInTheDocument();
  expect(requests[2]).toEqual({ method: 'harness_execution_start', params: { action: 'rollback', planId: '018f22e2-79b0-7cc8-98c4-dc0c0c07398f' } });
});

it('keeps a pending apply exclusive across navigation and retains its acknowledged rollback', async () => {
  const pending = deferred<unknown>();
  operation = async (request) => request.method === 'harness_preview'
    ? { kind: 'plan', data: { plan: preview } } : pending.promise;
  await open(); await review(); approve();
  fireEvent.click(screen.getByRole('button', { name: 'Home' }));
  fireEvent.click(screen.getByRole('button', { name: 'Harnesses' }));
  expect(screen.getByRole('button', { name: 'Review setup' })).toBeDisabled();
  await act(async () => pending.resolve(finished()));
  expect(await screen.findByRole('button', { name: 'Undo setup 0C07398F for Codex for Research' })).toBeEnabled();
});

it('distinguishes repeated connections and retains each original change review for undo', async () => {
  const firstId = preview.planId;
  await open(); await review(); approve(); await screen.findByText(/Settings saved:/);
  preview = { ...preview, planId: '018f22e2-79b0-7cc8-98c4-dc0c0c073990' as SetupPlan['planId'],
    semanticChanges: [{ class: 'update', target: '.codex/config.toml', summary: 'Change the context permissions' }] };
  await review(); approve(); await screen.findByText(/Settings saved:/);
  const history = screen.getByRole('region', { name: 'Recent setup changes' });
  const entries = within(history).getAllByRole('heading', { level: 3, name: /Codex for Research · setup/ }).map((heading) => heading.closest('li')!);
  expect(entries).toHaveLength(2);
  expect(within(entries[0]).getByRole('button', { name: 'Undo setup 0C073990 for Codex for Research' })).toBeVisible();
  expect(within(entries[1]).getByRole('button', { name: 'Undo setup 0C07398F for Codex for Research' })).toBeVisible();
  fireEvent.click(within(entries[1]).getByText('View saved changes'));
  expect(within(entries[1]).getByText('Register Context Relay')).toBeVisible();
  fireEvent.click(within(entries[0]).getByText('View saved changes'));
  expect(within(entries[0]).getByText('Change the context permissions')).toBeVisible();
  fireEvent.click(within(entries[1]).getByRole('button', { name: /Undo setup .* for/ }));
  fireEvent.click(await screen.findByRole('button', { name: 'Undo setup changes' }));
  await screen.findByText(/Setup changes undone:/);
  expect(requests.at(-1)).toEqual({ method: 'harness_execution_start', params: { action: 'rollback', planId: firstId } });
  expect(within(entries[0]).getByRole('button', { name: /Undo setup .* for/ })).toBeEnabled();
  expect(within(entries[1]).queryByRole('button', { name: /Undo setup .* for/ })).not.toBeInTheDocument();
});

it('requires fresh approval after navigating away from a reviewed preview', async () => {
  await open(); await review();
  fireEvent.click(screen.getByRole('checkbox', { name: /I reviewed/ }));
  fireEvent.click(screen.getByRole('button', { name: 'Home' }));
  fireEvent.click(screen.getByRole('button', { name: 'Harnesses' }));
  expect(screen.queryByRole('button', { name: 'Save settings' })).not.toBeInTheDocument();
});

it('keeps rollback available after failure and requires new confirmation for retry', async () => {
  await open(); await review(); approve(); await screen.findByText(/Settings saved:/);
  operation = async () => { throw new Error('PRIVATE-ROLLBACK'); };
  fireEvent.click(screen.getByRole('button', { name: 'Undo setup 0C07398F for Codex for Research' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Undo setup changes' }));
  await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(/Undo reported a problem/));
  expect(screen.queryByText(/PRIVATE-ROLLBACK|Setup changes undone/)).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Undo setup changes' })).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Undo setup 0C07398F for Codex for Research' })).toBeEnabled();
});

it('can cancel rollback and awaits acknowledgment without duplicate or overlapping actions', async () => {
  await open(); await review(); approve(); await screen.findByText(/Settings saved:/);
  fireEvent.click(screen.getByRole('button', { name: 'Undo setup 0C07398F for Codex for Research' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Keep settings' }));
  expect(requests).toHaveLength(2);
  const pending = deferred<unknown>(); operation = async () => pending.promise;
  fireEvent.click(screen.getByRole('button', { name: 'Undo setup 0C07398F for Codex for Research' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Undo setup changes' }));
  fireEvent.click(screen.getByRole('button', { name: 'Undo setup 0C07398F for Codex for Research' }));
  expect(requests).toHaveLength(3);
  expect(screen.getByRole('button', { name: 'Review setup' })).toBeDisabled();
  expect(screen.queryByText(/Setup changes undone/)).not.toBeInTheDocument();
  await act(async () => pending.resolve(finished({ planId: preview.planId, action: 'rollback' })));
  expect(await screen.findByText(/Setup changes undone:/)).toBeVisible();
});

it('shows bytes when the native display string is empty', async () => {
  preview.executablePath = { ...preview.executablePath, display: '' };
  await open(); await review();
  fireEvent.click(screen.getByText('Technical verification details'));
  expect(screen.getByText(/Executable: windows bytes \(base64url\): YwA/)).toBeVisible();
});

it('rejects malformed previews without rendering plaintext errors or unsafe HTML', async () => {
  operation = async () => ({ kind: 'plan', data: { plan: { ...preview, batchHash: 'PRIVATE-MALFORMED' } } });
  await open(); fireEvent.click(screen.getByRole('button', { name: 'Review setup' }));
  expect(await screen.findByRole('alert')).toHaveTextContent(/Could not review this setup/i);
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
  expect(screen.getByText('--register')).not.toBeVisible();
  fireEvent.click(screen.getByText('Technical verification details'));
  expect(screen.getByText('--register')).toBeVisible();
  expect(screen.getByText('bridge.zip')).toBeVisible();
  expect(screen.getByText('Technical verification details')).toBeVisible();
});
