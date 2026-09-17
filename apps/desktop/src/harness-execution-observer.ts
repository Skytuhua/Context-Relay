import type { HarnessExecutionParams, HarnessExecutionStatus, HarnessSetupRecord } from './bindings';
import type { HarnessGateway } from './harness-gateway';

export type HarnessOutcome = { status: HarnessExecutionStatus; setup: HarnessSetupRecord };
type ObserverCallbacks = {
  onChecking: (checking: boolean) => void;
  onPending: (status: HarnessExecutionStatus | null) => void;
  onOutcome: (outcome: HarnessOutcome) => void;
  onError: (error: string | null) => void;
};
type Schedule = (callback: () => void, delay: number) => () => void;
type ReadGateway = Pick<HarnessGateway, 'harnessExecutionCurrent' | 'harnessExecutionStatus' | 'harnessSetupGet'>;
const scheduleTimeout: Schedule = (callback, delay) => {
  const timer = setTimeout(callback, delay);
  return () => clearTimeout(timer);
};

/** Read-only recovery. An unavailable status must never be interpreted as idle. */
export function observeHarnessExecution(
  gateway: ReadGateway,
  target: HarnessExecutionParams | null,
  callbacks: ObserverCallbacks,
  schedule: Schedule = scheduleTimeout,
): () => void {
  let canceled = false;
  let cancelTimer = () => {};
  let key = target ? { ...target } : null;
  let discover = true;
  callbacks.onChecking(true);

  async function readStatus(identity: HarnessExecutionParams): Promise<HarnessExecutionStatus> {
    const expected = { ...identity };
    const status = await gateway.harnessExecutionStatus({ ...expected });
    if (!status || status.planId !== expected.planId || status.action !== expected.action) {
      throw new Error('The execution status does not match the requested attempt.');
    }
    return status;
  }

  async function poll() {
    try {
      let status: HarnessExecutionStatus | null;
      if (discover) {
        const current = await gateway.harnessExecutionCurrent();
        if (canceled) return;
        if (current && (current.phase === 'queued' || current.phase === 'running' || !key)) {
          status = current;
        } else {
          status = key ? await readStatus(key) : current;
        }
        discover = false;
      } else {
        status = key ? await readStatus(key) : await gateway.harnessExecutionCurrent();
      }
      if (canceled) return;
      if (status === null) {
        callbacks.onPending(null); callbacks.onError(null); callbacks.onChecking(false);
        return;
      }
      if (!status) throw new Error('Execution discovery was not confirmed.');
      key = { planId: status.planId, action: status.action };
      if (status.phase === 'queued' || status.phase === 'running') {
        callbacks.onPending(status); callbacks.onError(null); callbacks.onChecking(false);
        cancelTimer = schedule(() => void poll(), 1000);
        return;
      }
      // Finished/Unknown describes the attempt, not whether its settings were saved.
      const setup = await gateway.harnessSetupGet(status.planId);
      if (canceled) return;
      if (setup.plan.planId !== status.planId) throw new Error('The setup result belongs to another plan.');
      callbacks.onOutcome({ status, setup });
      callbacks.onPending(null); callbacks.onError(null); callbacks.onChecking(false);
    } catch {
      if (canceled) return;
      callbacks.onError(key ? 'The setup result could not be confirmed. Reconnecting to check the same setup…' : 'Could not load setup progress. Reconnecting…');
      // Retain the mutation gate even when no pending attempt has been discovered.
      callbacks.onChecking(true);
      cancelTimer = schedule(() => void poll(), 2000);
    }
  }

  void poll();
  return () => { canceled = true; cancelTimer(); };
}
