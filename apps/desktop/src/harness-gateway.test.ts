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
