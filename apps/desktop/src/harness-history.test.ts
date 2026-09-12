import { expect, it, vi } from 'vitest';
import type { HarnessSetupSummary, HarnessSetupsPage, PlanId, ProjectId } from './bindings';
import { projectHarnessSetups } from './harness-history';

const id = (number: number) => `018f22e2-79b0-7cc8-98c4-${number.toString(16).padStart(12, '0')}` as PlanId;
function setup(number: number, patch: Partial<HarnessSetupSummary> = {}): HarnessSetupSummary {
  return { planId: id(number), harness: 'codex', harnessProfile: null, targetScopes: [{ scope: 'project', projectId: 'project-a' }], state: 'applied', createdAt: '1', expiresAt: '2', ...patch } as HarnessSetupSummary;
}

it('loads matching history past an empty page and ignores other projects', async () => {
  const saved = setup(3);
  const harnessSetupsList = vi.fn<() => Promise<HarnessSetupsPage>>()
    .mockResolvedValueOnce({ setups: [], nextAfter: id(1) })
    .mockResolvedValueOnce({ setups: [setup(2, { targetScopes: [{ scope: 'project', projectId: 'project-b' as ProjectId }] }), saved], nextAfter: null });
  expect(await projectHarnessSetups({ harnessSetupsList }, 'project-a')).toEqual([saved]);
  expect(harnessSetupsList.mock.calls).toEqual([[null], [id(1)]]);
});

it.each(['applied', 'rolled_back', 'conflict'] as const)('uses the latest %s state from a later page', async state => {
  const latest = setup(3, { state });
  const harnessSetupsList = vi.fn<() => Promise<HarnessSetupsPage>>()
    .mockResolvedValueOnce({ setups: [setup(1, { state: 'previewed' })], nextAfter: id(1) })
    .mockResolvedValueOnce({ setups: [latest], nextAfter: null });
  expect(await projectHarnessSetups({ harnessSetupsList }, 'project-a')).toEqual([latest]);
});

it('keeps Hermes profiles separate and includes applicable global settings', async () => {
  const defaultProfile = setup(2, { harness: 'hermes', harnessProfile: 'default' });
  const coderProfile = setup(3, { harness: 'hermes', harnessProfile: 'coder', state: 'rolled_back' });
  const global = setup(4, { targetScopes: [{ scope: 'global' }] });
  const harnessSetupsList = vi.fn(async () => ({ setups: [setup(1, { harness: 'hermes', harnessProfile: 'default' }), defaultProfile, coderProfile, global], nextAfter: null }));
  expect(await projectHarnessSetups({ harnessSetupsList }, 'project-a')).toEqual([global, coderProfile, defaultProfile]);
});

it('rejects a repeated continuation cursor instead of looping indefinitely', async () => {
  const harnessSetupsList = vi.fn(async () => ({ setups: [], nextAfter: id(1) }));
  await expect(projectHarnessSetups({ harnessSetupsList }, 'project-a')).rejects.toThrow('Setup history did not advance.');
  expect(harnessSetupsList).toHaveBeenCalledTimes(2);
});

it('does not request another page after the caller cancels an in-flight read', async () => {
  const controller = new AbortController();
  let resolvePage!: (value: HarnessSetupsPage) => void;
  const harnessSetupsList = vi.fn(() => new Promise<HarnessSetupsPage>(resolve => { resolvePage = resolve; }));
  const pending = projectHarnessSetups({ harnessSetupsList }, 'project-a', controller.signal);
  const rejected = expect(pending).rejects.toMatchObject({ name: 'AbortError' });
  controller.abort();
  resolvePage({ setups: [setup(1)], nextAfter: id(1) });
  await rejected;
  expect(harnessSetupsList).toHaveBeenCalledTimes(1);
});
