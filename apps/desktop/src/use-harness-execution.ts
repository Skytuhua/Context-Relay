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
  const observer = useRef<(() => void) | null>(null);
  const gate = useRef({ checking: true, pending: false });
  const [checking, setChecking] = useState(true);
  const [pending, setPending] = useState<HarnessExecutionStatus | null>(null);
  const [outcome, setOutcome] = useState<HarnessOutcome | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);

  useEffect(() => {
    gate.current.checking = true;
    if (!active || starting) return;
    const stop = observeHarnessExecution(gateway, target, {
      onChecking: value => { gate.current.checking = value; setChecking(value); },
      onPending: value => { gate.current.pending = value !== null; setPending(value); },
      onOutcome: setOutcome,
      onError: setError,
    });
    observer.current = stop;
    return () => {
      stop();
      if (observer.current === stop) {
        observer.current = null;
        gate.current.checking = true;
      }
    };
  }, [active, gateway, target, starting, revision]);

  async function execute(key: HarnessExecutionParams) {
    if (submitting.current || gate.current.checking || gate.current.pending || pending || checking || !active) return;
    submitting.current = true;
    gate.current = { checking: true, pending: true };
    // Invalidate reads synchronously; React may batch the following state updates.
    observer.current?.(); observer.current = null;
    const identity = { ...key };
    setStarting(true); setOutcome(null); setError(null);
    setPending({ ...identity, phase: 'queued', error: null });
    setTarget(identity);
    try {
      await gateway.harnessExecutionStart({ ...identity });
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
    checkAgain: () => {
      gate.current.checking = true;
      observer.current?.(); observer.current = null;
      setChecking(true); setRevision(value => value + 1);
    },
  };
}
