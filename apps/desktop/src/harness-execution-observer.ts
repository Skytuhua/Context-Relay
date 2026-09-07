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
  let key = target;
  let discover = true;
  callbacks.onChecking(true);

  async function poll() {
    try {
      let status: HarnessExecutionStatus | null;
      if (discover) {
        const current = await gateway.harnessExecutionCurrent();
        if (canceled) return;
        if (current && (current.phase === 'queued' || current.phase === 'running' || !key)) {
          status = current;
        } else {
          status = key ? await gateway.harnessExecutionStatus(key) : current;
        }
        discover = false;
      } else {
        status = key ? await gateway.harnessExecutionStatus(key) : await gateway.harnessExecutionCurrent();
      }
      if (canceled) return;
      if (!status) {
        callbacks.onPending(null); callbacks.onError(null); callbacks.onChecking(false);
        return;
      }
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
