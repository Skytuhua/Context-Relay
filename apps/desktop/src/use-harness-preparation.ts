import { useEffect, useRef, useState } from 'react';
import type { HarnessParams, HarnessPreparationStatus, HarnessPrepareParams, OperationId } from './bindings';
import type { HarnessGateway } from './harness-gateway';
import { validateHarnessPreparation } from './protocol-validation';
import { uuidV7 } from './uuid';

const storageKey = 'context-relay.harness-preparation.v1';
function remembered(): HarnessPrepareParams | null {
  try {
    const key = JSON.parse(localStorage.getItem(storageKey) ?? 'null');
    if (!key || typeof key !== 'object' || Object.keys(key).length !== 2) return null;
    validateHarnessPreparation({ ...key, phase: 'inspecting', completedFiles: 0, completedBytes: 0, error: null });
    return key;
  } catch { return null; }
}
const terminal = (status: HarnessPreparationStatus | null) => status && ['ready', 'canceled', 'failed'].includes(status.phase);

/** Only operation identity and selection are remembered; settings and runtime paths stay in the vault. */
export function useHarnessPreparation(gateway: HarnessGateway, active: boolean) {
  const [target, setTarget] = useState(remembered);
  const [status, setStatus] = useState<HarnessPreparationStatus | null>(null);
  const [starting, setStarting] = useState(false);
  const [checking, setChecking] = useState(false);
  const [canceling, setCanceling] = useState(false);
  const [missing, setMissing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);
  const submitting = useRef(false);
  const cancelSubmitted = useRef(false);

  useEffect(() => {
    if (!active || !target) return;
    let canceled = false;
    let timer: number | undefined;
    setChecking(true);
    async function poll() {
      try {
        const next = await gateway.harnessPreparationStatus(target!);
        if (canceled) return;
        setStatus(next); setChecking(false); setMissing(false); setError(null);
        if (!terminal(next)) timer = window.setTimeout(() => void poll(), 1000);
      } catch (error) {
        if (canceled) return;
        setChecking(false);
        const notFound = error && typeof error === 'object' && 'code' in error && error.code === 'not_found';
        // NotFound cannot prove that an older native invocation will not be
        // admitted later. Keep this identity; only explicit same-ID retry is safe.
        if (notFound && !starting) {
          setMissing(true);
          setError('Preparation is unconfirmed. The service may have restarted, or the request may still be waiting. Check again or retry the same attempt.');
        } else {
          setError('Could not check preparation. Reconnecting to the same attempt…');
          timer = window.setTimeout(() => void poll(), 2000);
        }
      }
    }
    void poll();
    return () => { canceled = true; window.clearTimeout(timer); };
  }, [gateway, active, target, starting, revision]);

  async function begin(selection: HarnessParams) {
    if (!active || submitting.current || target) return;
    const key = { operationId: uuidV7() as OperationId, selection: structuredClone(selection) };
    try { localStorage.setItem(storageKey, JSON.stringify(key)); }
    catch { setError('Could not remember this preparation. Restart Context Relay and try again.'); return; }
    await submit(key);
  }

  async function submit(key: HarnessPrepareParams) {
    submitting.current = true; setStarting(true); setTarget(key); setMissing(false); setError(null);
    setStatus({ ...key, phase: 'inspecting', completedFiles: 0, completedBytes: 0, error: null });
    try { await gateway.harnessPrepare(key); }
    catch { setError('Preparation was not confirmed. Checking the same attempt…'); }
    finally { submitting.current = false; setStarting(false); }
  }

  async function retry() {
    if (!active || !target || !missing || submitting.current) return;
    await submit(target);
  }

  async function cancel() {
    if (!target || cancelSubmitted.current || missing || terminal(status)) return;
    cancelSubmitted.current = true; setCanceling(true);
    try { setStatus(await gateway.harnessPreparationCancel(target)); setError(null); }
    catch { setError('Cancellation was not confirmed. Checking preparation before trying again…'); }
    finally { cancelSubmitted.current = false; setCanceling(false); setRevision(value => value + 1); }
  }

  function dismiss() {
    if (starting || canceling || (target && (missing || !terminal(status)))) return;
    try { localStorage.removeItem(storageKey); }
    catch { setError('Could not dismiss this preparation. Try again.'); return; }
    setTarget(null); setStatus(null); setError(null); setMissing(false); setChecking(false);
  }

  return { target, status, error, missing, starting, checking, canceling, begin, retry, cancel, dismiss,
    busy: starting || canceling || (target !== null && !missing && (checking || !terminal(status) || error !== null)),
    checkAgain: () => { setChecking(true); setRevision(value => value + 1); },
  };
}
