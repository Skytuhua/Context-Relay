import { useEffect, useRef, useState } from 'react';
import type { HarnessExecutionParams, HarnessExecutionStatus } from './bindings';
import type { HarnessGateway } from './harness-gateway';

import { observeHarnessExecution, type HarnessOutcome } from './harness-execution-observer';

export type { HarnessOutcome } from './harness-execution-observer';

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
    return observeHarnessExecution(gateway, target, {
      onChecking: setChecking,
      onPending: setPending,
      onOutcome: setOutcome,
      onError: setError,
    });
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
