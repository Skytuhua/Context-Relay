import { useCallback, useEffect, useRef, useState } from 'react';
import type { RecoveryRestoreStatus } from './bindings';
import type { DeviceGateway } from './workspace';

type Gateway = Pick<DeviceGateway, 'recoveryRestoreBegin' | 'recoveryRestoreOverview' | 'recoveryRestoreResume' | 'recoveryRestoreCancel'>;
type Action = 'overview' | 'begin' | 'resume' | 'cancel';

export function RecoveryRestorePanel({ gateway, onComplete }: { gateway: Gateway; onComplete: () => void }) {
  const [status, setStatus] = useState<RecoveryRestoreStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  const working = useRef(false);
  const generation = useRef(0);
  const heading = useRef<HTMLHeadingElement>(null);

  const run = useCallback(async (action: Action) => {
    if (working.current) return;
    working.current = true;
    const current = ++generation.current;
    setBusy(true);
    setError(false);
    const apply = (next: RecoveryRestoreStatus) => {
      if (generation.current !== current) return;
      setStatus(next);
      if (action !== 'overview' && next.state !== 'idle') heading.current?.focus();
      if (next.state === 'complete') onComplete();
    };
    try {
      const result = await (action === 'begin' ? gateway.recoveryRestoreBegin()
        : action === 'resume' ? gateway.recoveryRestoreResume()
        : action === 'cancel' ? gateway.recoveryRestoreCancel()
        : gateway.recoveryRestoreOverview());
      if (generation.current !== current) return;
      apply(result ?? await gateway.recoveryRestoreOverview());
    } catch {
      if (generation.current !== current) return;
      // A failed response may still have prepared or completed the operation.
      // Unknown durable state must never expose another Begin action.
      setStatus(null);
      let completed = false;
      if (action !== 'overview') {
        try {
          const recovered = await gateway.recoveryRestoreOverview();
          apply(recovered);
          completed = recovered.state === 'complete';
        } catch { /* Keep status unknown. */ }
      }
      if (generation.current === current) setError(!completed);
    } finally {
      if (generation.current === current) {
        working.current = false;
        setBusy(false);
      }
    }
  }, [gateway, onComplete]);

  useEffect(() => {
    void run('overview');
    return () => { generation.current += 1; working.current = false; };
  }, [run]);

  return (
    <section className="recovery-workspace" aria-labelledby="restore-device-title" aria-busy={busy}>
      <h2 id="restore-device-title" ref={heading} tabIndex={-1}>Recover this device</h2>
      <p>Sign in to your existing account, then use your saved 24-word phrase on a new installation.</p>
      {error && <p role="alert">Recovery could not be confirmed. Check your connection and account sign-in, then retry. Any saved recovery attempt is preserved.</p>}
      {busy && <p role="status">Waiting for recovery. If a native dialog is open, finish or cancel it there.</p>}
      {!busy && status === null && <button type="button" onClick={() => void run('overview')}>Check recovery status</button>}
      {status?.state === 'idle' && <>
        <p>Your phrase is entered in a native dialog and is never shown on this page.</p>
        <button className="primary-action" type="button" disabled={busy} onClick={() => void run('begin')}>Enter recovery phrase</button>
        <button type="button" disabled={busy} onClick={() => void run('cancel')}>Stop recovery attempt</button>
      </>}
      {status?.state === 'submitting' && <>
        <p role="status">A recovery attempt is saved. Resume it without entering your phrase again.</p>
        <button className="primary-action" type="button" disabled={busy} onClick={() => void run('resume')}>Resume recovery</button>
      </>}
      {status?.state === 'complete' && <p role="status">This device has been recovered.</p>}
      {status?.state === 'conflict' && <p role="alert">Recovery could not be completed because the workspace changed. Pair this installation from a trusted device or contact support.</p>}
    </section>
  );
}
