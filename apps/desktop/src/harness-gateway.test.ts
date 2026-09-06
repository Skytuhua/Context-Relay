import { readFileSync } from 'node:fs';
import { beforeEach, expect, it, vi } from 'vitest';
import type { DecimalU64, HarnessParams, ProjectId, SetupPlan } from './bindings';

const invoke = vi.hoisted(() => vi.fn());
vi.mock('@tauri-apps/api/core', () => ({ invoke }));
import { LocalWorkspaceGateway } from './workspace';

const projectId = '018f22e2-79b0-7cc8-98c4-dc0c0c075001' as ProjectId;
const params: HarnessParams = { harness: 'codex', projectId, hermesProfile: null };
function plan(): SetupPlan {
  const value = JSON.parse(readFileSync('../../crates/protocol/tests/fixtures/runtime-contracts-v1.json', 'utf8')).setupPlan as SetupPlan;
  return { ...value, expiresAt: '2000000000000' as DecimalU64, targetScopes: [{ scope: 'project', projectId, root: value.executablePath }] };
}
beforeEach(() => invoke.mockReset());

it('tracks the exact plan and action and reads its authoritative saved record', async () => {
  const gateway = new LocalWorkspaceGateway();
  const savedPlan = { ...plan(), rulesyncVersion: 'bridge-preview-v1' };
  const key = { planId: savedPlan.planId, action: 'apply' as const };
  const status = { ...key, phase: 'queued', error: null };
  invoke.mockResolvedValueOnce({ kind: 'harness_execution', data: { status } })
    .mockResolvedValueOnce({ kind: 'harness_execution_current', data: { status } })
    .mockResolvedValueOnce({ kind: 'harness_execution', data: { status: { ...status, phase: 'finished' } } })
    .mockResolvedValueOnce({ kind: 'harness_setup', data: { setup: { plan: savedPlan, state: 'applied', createdAt: '1900000000000' } } });
  expect((await gateway.harnessExecutionStart(key)).phase).toBe('queued');
  expect(await gateway.harnessExecutionCurrent()).toEqual(status);
  expect((await gateway.harnessExecutionStatus(key)).phase).toBe('finished');
  expect((await gateway.harnessSetupGet(savedPlan.planId)).state).toBe('applied');
  expect(invoke.mock.calls.map(call => call[1].request)).toEqual([
    { method: 'harness_execution_start', params: key }, { method: 'harness_execution_current', params: {} },
    { method: 'harness_execution_status', params: key }, { method: 'harness_setup_get', params: { planId: savedPlan.planId } },
  ]);
});

it('rejects mismatched identities, ambiguous attempts and malformed history', async () => {
  const gateway = new LocalWorkspaceGateway();
  const key = { planId: plan().planId, action: 'apply' as const };
  for (const status of [
    { ...key, action: 'rollback', phase: 'finished', error: null },
    { ...key, phase: 'running', error: { code: 'internal', message: 'Failure', fieldPath: null, retryable: false } },
    { ...key, phase: 'finished' },
  ]) {
    invoke.mockResolvedValue({ kind: 'harness_execution', data: { status } });
    await expect(gateway.harnessExecutionStatus(key)).rejects.toThrow();
  }
  invoke.mockResolvedValue({ kind: 'harness_setups', data: { page: { setups: [], nextAfter: key.planId } } });
  await expect(gateway.harnessSetupsList(key.planId)).rejects.toThrow();
  invoke.mockResolvedValue({ kind: 'harness_execution_current', data: {} });
  await expect(gateway.harnessExecutionCurrent()).rejects.toThrow();
});

it('previews native setup and sends only the stored ID for apply and rollback', async () => {
  invoke.mockResolvedValueOnce({ kind: 'plan', data: { plan: plan() } }).mockResolvedValue({ kind: 'empty' });
  const gateway = new LocalWorkspaceGateway();
  const preview = await gateway.harnessPreview(params);
  await gateway.harnessApply(preview.planId);
  await gateway.harnessRollback(preview.planId);
  expect(invoke.mock.calls).toEqual([
    ['local_request', { request: { method: 'harness_preview', params: { harness: 'codex', projectId, hermesProfile: null } } }],
    ['local_request', { request: { method: 'harness_apply', params: { planId: '018f22e2-79b0-7cc8-98c4-dc0c0c07398f' } } }],
    ['local_request', { request: { method: 'harness_rollback', params: { planId: '018f22e2-79b0-7cc8-98c4-dc0c0c07398f' } } }],
  ]);
});

it.each([
  null,
  { kind: 'empty' },
  { kind: 'plan', data: {} },
  { kind: 'plan', data: { plan: plan(), extra: 'unexpected' } },
  { kind: 'plan', data: { plan: plan() }, extra: 'unexpected' },
  { kind: 'plan', data: { plan: { ...plan(), expiresAt: 'secret-invalid' } } },
  { kind: 'plan', data: { plan: { ...plan(), harness: 'claude_code' } } },
  { kind: 'plan', data: { plan: { ...plan(), targetScopes: [{ scope: 'global' }] } } },
])('rejects unexpected, malformed or mismatched preview %#', async (response) => {
  invoke.mockResolvedValue(response);
  await expect(new LocalWorkspaceGateway().harnessPreview(params)).rejects.toThrow();
});

it('rejects a returned Hermes profile different from the requested profile', async () => {
  invoke.mockResolvedValue({ kind: 'plan', data: { plan: { ...plan(), harness: 'hermes', harnessProfile: 'other' } } });
  await expect(new LocalWorkspaceGateway().harnessPreview({ ...params, harness: 'hermes', hermesProfile: 'coder' })).rejects.toThrow();
});

it.each(['harnessApply', 'harnessRollback'] as const)('%s requires an empty acknowledgment', async (method) => {
  const gateway = new LocalWorkspaceGateway();
  for (const response of [null, { kind: 'plan', data: { plan: plan() } }, { kind: 'empty', data: 'unexpected' }]) {
    invoke.mockResolvedValue(response);
    await expect(gateway[method](plan().planId)).rejects.toThrow();
  }
});
