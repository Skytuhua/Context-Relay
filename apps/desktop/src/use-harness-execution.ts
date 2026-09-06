import { useEffect, useRef, useState } from 'react';
import type { HarnessExecutionParams, HarnessExecutionStatus, HarnessSetupRecord } from './bindings';
import type { HarnessGateway } from './harness-gateway';

export type HarnessOutcome = { status: HarnessExecutionStatus; setup: HarnessSetupRecord };

/** Observing/reconnecting never retries a settings mutation. */
export function useHarnessExecution(gateway: HarnessGateway, active: boolean) {
  const [target, setTarget] = useState<HarnessExecutionParams | null>(null);
  const [starting, setStarting] = useState(false);
  const submitting = useRef(false);
  const [checking, setChecking] = useState(true);
  const [pending, setPending] = useState<HarnessExecutionStatus | null>(null);
  const [outcome, setOutcome] = useState<HarnessOutcome | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);

  useEffect(() => {
    if (!active || starting) return;
    let canceled = false;
    let timer: number | undefined;
    let key = target;
    let discover = true;
    setChecking(true);
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
          setChecking(false); setPending(null); setError(null);
          return;
        }
        key = { planId: status.planId, action: status.action };
        if (status.phase === 'queued' || status.phase === 'running') {
          setPending(status); setChecking(false); setError(null);
          timer = window.setTimeout(() => void poll(), 1000);
          return;
        }
        // Finished is only an attempt hint. Read the exact persisted plan, including
        // after Unknown (daemon restart), before displaying any result.
        const setup = await gateway.harnessSetupGet(status.planId);
        if (canceled) return;
        setOutcome({ status, setup }); setPending(null); setChecking(false); setError(null);
      } catch {
        if (canceled) return;
        setError(key ? 'The setup result could not be confirmed. Reconnecting to check the same setup…' : 'Could not load setup progress. Reconnecting…');
        setChecking(false);
        timer = window.setTimeout(() => void poll(), 2000);
      }
    }
    void poll();
    return () => { canceled = true; window.clearTimeout(timer); };
  }, [active, gateway, target, starting, revision]);

  async function execute(key: HarnessExecutionParams) {
    if (submitting.current || pending || checking || !active) return;
    submitting.current = true;
    setStarting(true); setOutcome(null); setError(null);
    setPending({ ...key, phase: 'queued', error: null });
    setTarget(key);
    try {
      await gateway.harnessExecutionStart(key);
    } catch {
      // A lost acknowledgement may already have been accepted. Poll; do not resend.
      setError('The setup result could not be confirmed. Checking the same setup…');
    } finally {
      submitting.current = false; setStarting(false);
    }
  }

  return { execute, pending, outcome, error, checking, starting,
    clearOutcome: () => setOutcome(null),
    busy: checking || starting || pending !== null,
    checkAgain: () => { setChecking(true); setRevision(value => value + 1); },
  };
}
