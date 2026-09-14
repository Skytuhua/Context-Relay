import { useCallback, useEffect, useRef, useState } from 'react';
import type { RecoveryRestoreStatus, RecoveryHistoryCandidatesPage, Sha256Digest } from './bindings';
import type { DeviceGateway } from './workspace';

type Gateway = Pick<DeviceGateway, 'recoveryRestoreBegin' | 'recoveryRestoreOverview' | 'recoveryRestoreResume' | 'recoveryRestoreCancel' | 'recoveryHistoryCandidates' | 'recoveryHistorySelect' | 'recoveryHistoryUnlock'>;
type Action = 'overview' | 'begin' | 'resume' | 'cancel' | 'list' | 'more' | 'select' | 'unlock';

function recordedTime(physicalMs: string): string {
  const date = new Date(Number(physicalMs));
  return Number.isFinite(date.getTime()) ? date.toISOString() : 'Outside the supported calendar range';
}

export function RecoveryRestorePanel({ gateway, onComplete }: { gateway: Gateway; onComplete: () => void }) {
  const [status, setStatus] = useState<RecoveryRestoreStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  const [page, setPage] = useState<RecoveryHistoryCandidatesPage | null>(null);
  const working = useRef(false);
  const generation = useRef(0);
  const heading = useRef<HTMLHeadingElement>(null);

  const run = useCallback(async (action: Action, checkpointSha256?: Sha256Digest) => {
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
      if (action === 'list' || action === 'more') {
        if (status?.state !== 'restoring_history') throw new Error('Recovery status changed.');
        const result = await gateway.recoveryHistoryCandidates({ restoreId: status.restoreId, acceptedEndpointSha256: status.acceptedEndpoint.stateSha256, cursor: action === 'more' ? page?.nextCursor ?? null : null });
        if (generation.current === current) setPage(result);
        return;
      }
      const target = (action === 'select' || action === 'unlock') && status?.state === 'restoring_history' && checkpointSha256
        ? { restoreId: status.restoreId, acceptedEndpointSha256: status.acceptedEndpoint.stateSha256, checkpointSha256 } : null;
      const result = await (action === 'select' && target ? gateway.recoveryHistorySelect(target)
        : action === 'unlock' && target ? gateway.recoveryHistoryUnlock(target)
        : action === 'begin' ? gateway.recoveryRestoreBegin()
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
  }, [gateway, onComplete, status, page]);

  useEffect(() => {
    // Only mounting loads status; state changes never choose or resume a target.
    void run('overview');
    return () => { generation.current += 1; working.current = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [gateway, onComplete]);

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
      {status?.state === 'restoring_history' && <>
        <p role="status">{status.history.state === 'unselected' ? 'Choose a history to restore. Your device admission is saved.'
          : status.history.state === 'historical_keys_needed' ? 'This history needs historical keys. Enter your phrase in the native dialog to unlock them.'
          : status.history.state === 'current_material_unavailable' ? 'Current workspace access is not ready. Unlocking older history cannot restore current access.'
          : status.history.state === 'stale_endpoint' ? 'Workspace membership changed. Choose a history again using the current accepted membership.'
          : 'Your recovery is saved. Your history is still being restored.'}</p>
        {status.history.state !== 'unselected' && <p>Selected checkpoint: <code>{status.history.checkpointSha256}</code></p>}
        {status.history.state === 'incomplete' && <button className="primary-action" type="button" disabled={busy} onClick={() => void run('resume')}>Resume recovery</button>}
        {status.history.state === 'historical_keys_needed' && <button type="button" disabled={busy} onClick={() => status.history.state === 'historical_keys_needed' && void run('unlock', status.history.checkpointSha256)}>Unlock historical keys</button>}
        <button type="button" disabled={busy} onClick={() => void run('list')}>Find recovery histories</button>
        {page && page.restoreId === status.restoreId && page.acceptedEndpoint.stateSha256 === status.acceptedEndpoint.stateSha256 && <>
          <p>These histories have verified signatures. Their display order does not establish which history is globally newest.</p>
          {page.candidates.length > 0 && <p role="status">{page.candidates.length} recovery histories available. Choose one to restore.</p>}
          {page.candidates.length === 0 && <p role="status">No more recovery histories are available.</p>}
          <ul>{page.candidates.map(candidate => <li key={candidate.checkpointSha256}>
            <p>Author device: <code>{candidate.authorDeviceId}</code>. Recorded time: {recordedTime(candidate.createdHlc.physicalMs)}, logical {candidate.createdHlc.logical}. Key epoch: {candidate.keyEpoch}.</p>
            <p>Checkpoint: <code>{candidate.checkpointSha256}</code></p>
            <p>{candidate.extent.state === 'supported' ? `Recorded frontier: ${candidate.extent.operationCount} operations across ${candidate.frontierDeviceCount} device histories.` : 'This history exceeds the supported reconstruction size.'}</p>
            <button type="button" disabled={busy || candidate.extent.state !== 'supported'} onClick={() => void run('select', candidate.checkpointSha256)}>Restore this history</button>
          </li>)}</ul>
          {page.nextCursor && <button type="button" disabled={busy} onClick={() => void run('more')}>More recovery histories</button>}
        </>}
      </>}
      {status?.state === 'conflict' && <p role="alert">Recovery could not be completed because the workspace changed. Pair this installation from a trusted device or contact support.</p>}
    </section>
  );
}
