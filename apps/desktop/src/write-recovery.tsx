import { useEffect, useRef, useState } from 'react';
import type { DesktopWrite, DesktopWriteSummary, OperationId, ProjectIdentity, ScopeRef } from './bindings';
import type { WorkspaceGateway } from './workspace';

type RecoveryGateway = Pick<WorkspaceGateway, 'pendingWrites' | 'pendingWrite' | 'retryWrite' | 'forgetWrite'>;

export function WriteRecovery({ gateway, projects, onBusy, onConfirmed }: { gateway: RecoveryGateway; projects: ProjectIdentity[]; onBusy?: (busy: boolean) => void; onConfirmed?: () => void }) {
  const [entries, setEntries] = useState<DesktopWriteSummary[]>([]);
  const [cursor, setCursor] = useState<OperationId | null>(null);
  const [review, setReview] = useState<{ summary: DesktopWriteSummary; write: DesktopWrite } | null>(null);
  const [busy, setBusy] = useState(false);
  const busyRef = useRef(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  const generation = useRef(0);

  useEffect(() => {
    const current = ++generation.current;
    setEntries([]); setReview(null); setCursor(null); setNotice(null);
    busyRef.current = false; setBusy(false);
    void gateway.pendingWrites(null).then((page) => {
      if (generation.current !== current) return;
      setEntries(page.writes); setCursor(page.nextCursor); setError(null);
    }).catch(() => {
      if (generation.current === current) setError('Unconfirmed changes could not be loaded. Try loading them again.');
    });
    return () => { generation.current = current + 1; onBusy?.(false); };
  }, [gateway, attempt, onBusy]);

  async function act(action: (active: () => boolean) => Promise<void>) {
    if (busyRef.current) return;
    busyRef.current = true; setBusy(true); setError(null); setNotice(null);
    onBusy?.(true);
    const current = generation.current;
    try { await action(() => generation.current === current); }
    catch {
      if (generation.current === current) setError('We could not confirm the result. Reload recovery copies to check what remains. Check the saved record before retrying; a newer edit may need to be kept.');
    } finally {
      if (generation.current === current) { busyRef.current = false; setBusy(false); onBusy?.(false); }
    }
  }

  async function open(summary: DesktopWriteSummary, active: () => boolean) {
    const write = await gateway.pendingWrite(summary.operationId);
    if (!active()) return;
    if (write) setReview({ summary, write });
    else {
      setEntries((values) => values.filter((entry) => entry.operationId !== summary.operationId));
      setNotice('This recovery copy has already been cleared.');
    }
  }

  function remove(id: OperationId) {
    setEntries((values) => values.filter((entry) => entry.operationId !== id));
    setReview(null);
  }

  if (!entries.length && !error && !notice && !cursor) return null;
  return <section className="write-recovery" aria-labelledby="write-recovery-title" aria-busy={busy}>
    <h2 id="write-recovery-title">Changes to check</h2>
    <p>These changes may already be saved. Review a recovery copy, then retry the same change or dismiss the copy. Nothing is submitted automatically.</p>
    {error && <p role="alert">{error} <button disabled={busy} onClick={() => setAttempt((value) => value + 1)}>Reload recovery copies</button></p>}
    {notice && <p role="status">{notice}</p>}
    <ul className="recovery-list">
      {entries.map((entry) => <li key={entry.operationId}>
        <div><strong>{entry.title}</strong><span>{entry.action}</span></div>
        <button aria-label={'Review change: ' + entry.title} disabled={busy} onClick={() => void act((active) => open(entry, active))}>Review change</button>
      </li>)}
    </ul>
    {cursor && <button disabled={busy} onClick={() => void act(async (active) => {
      const page = await gateway.pendingWrites(cursor);
      if (!active()) return;
      setEntries((values) => [...values, ...page.writes.filter((entry) => !values.some((value) => value.operationId === entry.operationId))]);
      setCursor(page.nextCursor);
    })}>Show more changes</button>}
    {review && <section className="recovery-review" aria-label={'Review change: ' + review.summary.title}>
      <h3>{review.summary.action}: {review.summary.title}</h3>
      <WriteDetails write={review.write} scope={review.summary.scope} projects={projects} />
      <p>Retry uses the original change, so an already saved change is not applied twice.</p>
      <div className="form-actions">
        <button disabled={busy} onClick={() => void act(async (active) => {
          const result = await gateway.retryWrite(review.write);
          if (!active()) return;
          onConfirmed?.();
          if (!result.cleanupPending) remove(review.write.params.operationId);
          setNotice(result.cleanupPending
            ? 'The change is confirmed saved. Its recovery copy could not be cleared yet; you can dismiss it later.'
            : 'The change is confirmed saved. Open Saved context or Tasks to see the latest version.');
        })}>{busy ? 'Working…' : 'Retry change'}</button>
        <button disabled={busy} onClick={() => void act(async (active) => {
          await gateway.forgetWrite(review.write.params.operationId);
          if (!active()) return;
          remove(review.write.params.operationId);
          setNotice('Recovery copy dismissed. Any saved change is still there.');
        })}>Dismiss recovery copy</button>
        <button disabled={busy} onClick={() => setReview(null)}>Close review</button>
      </div>
      <p className="help-text">Dismiss removes only this recovery copy. It does not delete or undo a saved change.</p>
    </section>}
  </section>;
}

function WriteDetails({ write, scope, projects }: { write: DesktopWrite; scope: ScopeRef | null; projects: ProjectIdentity[] }) {
  const params = write.params;
  const target = scope?.scope === 'global' ? 'All projects'
    : scope?.scope === 'project' ? projects.find((project) => project.projectId === scope.projectId)?.name ?? 'Original project' : null;
  return <>
    {target && <p>Project: {target}</p>}
    {'bodyMarkdown' in params && params.bodyMarkdown !== null && <pre className="recovery-body">{params.bodyMarkdown}</pre>}
    {'tags' in params && params.tags !== null && <p>Tags: {params.tags.length ? params.tags.join(', ') : 'None'}</p>}
    {write.method === 'memory_archive' && <p>Move this context to the archive.</p>}
    {write.method === 'candidate_review' && <p>{write.params.accepted ? 'Accept this suggestion.' : 'Reject this suggestion.'}</p>}
    {'status' in params && <p>Task status: {params.status.replaceAll('_', ' ')}</p>}
    {write.method === 'task_complete' && <><p>Mark this task complete with the following evidence:</p>
      {write.params.evidence.map((item, index) => <div key={index}><p>Evidence type: {item.kind}</p><pre className="recovery-body">{item.summary}</pre>{item.reference && <p>Reference: {item.reference}</p>}</div>)}
    </>}
  </>;
}
