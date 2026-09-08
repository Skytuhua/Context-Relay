import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { HarnessExecutionParams, HarnessExecutionStatus, HarnessSetupRecord } from './bindings';
import type { HarnessGateway } from './harness-gateway';
import { useHarnessExecution } from './use-harness-execution';

const key = { planId: '018f22e2-79b0-7cc8-98c4-dc0c0c073983', action: 'apply' } as HarnessExecutionParams;
const finished: HarnessExecutionStatus = { ...key, phase: 'finished', error: null };
const setup = { plan: { planId: key.planId }, state: 'applied', createdAt: '1' } as unknown as HarnessSetupRecord;
beforeEach(() => { vi.useFakeTimers(); });
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });

it('keeps mutations blocked after failed initial discovery until an idle response arrives', async () => {
  const harnessExecutionCurrent = vi.fn<() => Promise<HarnessExecutionStatus | null>>()
    .mockRejectedValueOnce(new Error('Service unavailable')).mockResolvedValue(null);
  const harnessExecutionStart = vi.fn();
  const gateway = { harnessExecutionCurrent, harnessExecutionStart } as unknown as HarnessGateway;
  const { result } = renderHook(() => useHarnessExecution(gateway, true));
  await act(async () => {});
  expect(result.current.busy).toBe(true);
  expect(result.current.checking).toBe(true);
  expect(result.current.error).toContain('Reconnecting');
  await act(async () => { await result.current.execute(key); });
  expect(harnessExecutionStart).not.toHaveBeenCalled();
  await act(async () => { await vi.advanceTimersByTimeAsync(2000); });
  expect(result.current.busy).toBe(false);
  expect(result.current.error).toBeNull();
});

it('does not unlock mutations until a finished attempt is reconciled with its persisted result', async () => {
  const harnessSetupGet = vi.fn<() => Promise<HarnessSetupRecord>>()
    .mockRejectedValueOnce(new Error('Vault read unavailable')).mockResolvedValue(setup);
  const harnessExecutionStart = vi.fn();
  const gateway = {
    harnessExecutionCurrent: vi.fn(async () => finished),
    harnessExecutionStatus: vi.fn(async () => finished),
    harnessSetupGet, harnessExecutionStart,
  } as unknown as HarnessGateway;
  const { result } = renderHook(() => useHarnessExecution(gateway, true));
  await act(async () => {});
  expect(result.current.busy).toBe(true);
  expect(result.current.outcome).toBeNull();
  await act(async () => { await result.current.execute(key); });
  expect(harnessExecutionStart).not.toHaveBeenCalled();
  await act(async () => { await vi.advanceTimersByTimeAsync(2000); });
  expect(harnessSetupGet).toHaveBeenLastCalledWith(key.planId);
  expect(result.current.outcome).toEqual({ status: finished, setup });
  expect(result.current.busy).toBe(false);
});

it('blocks a same-render save immediately when a status recheck is requested', async () => {
  const harnessExecutionCurrent = vi.fn<() => Promise<HarnessExecutionStatus | null>>().mockResolvedValue(null);
  const harnessExecutionStart = vi.fn();
  const gateway = { harnessExecutionCurrent, harnessExecutionStart } as unknown as HarnessGateway;
  const { result } = renderHook(() => useHarnessExecution(gateway, true));
  await act(async () => {});
  expect(result.current.busy).toBe(false);
  harnessExecutionCurrent.mockImplementation(() => new Promise<HarnessExecutionStatus | null>(() => {}));
  const controls = result.current;
  await act(async () => {
    controls.checkAgain();
    await controls.execute(key);
  });
  expect(harnessExecutionStart).not.toHaveBeenCalled();
  expect(result.current.busy).toBe(true);
});

it('keeps a submitted operation bound to its original identity after caller mutation', async () => {
  const target = { ...key };
  let resolve!: (status: HarnessExecutionStatus) => void;
  const harnessExecutionStart = vi.fn(() => new Promise<HarnessExecutionStatus>(done => { resolve = done; }));
  const harnessExecutionStatus = vi.fn(async () => finished);
  const gateway = {
    harnessExecutionCurrent: vi.fn(async () => null),
    harnessExecutionStart, harnessExecutionStatus,
    harnessSetupGet: vi.fn(async () => setup),
  } as unknown as HarnessGateway;
  const { result } = renderHook(() => useHarnessExecution(gateway, true));
  await act(async () => {});
  let operation!: Promise<void>;
  act(() => { operation = result.current.execute(target); });
  target.action = 'rollback';
  await act(async () => { resolve(finished); await operation; });
  expect(harnessExecutionStart).toHaveBeenCalledTimes(1);
  expect(harnessExecutionStart).toHaveBeenCalledWith(key);
  expect(harnessExecutionStatus).toHaveBeenCalledWith(key);
  expect(result.current.outcome).toEqual({ status: finished, setup });
});
