import { useCallback, useEffect, useRef, useState } from 'react';
import type { AccountDeletionIntentSummary, AccountLifecycleIntentAction, LocalResult, OperationId } from './bindings';
import type { WorkspaceGateway } from './workspace';
import { uuidV7 } from './uuid';

type Gateway = Pick<WorkspaceGateway, 'accountDeletionStatus' | 'accountDeletionIntents' | 'accountDeletionBegin' | 'accountDeletionCancel'>;
type Status = Extract<LocalResult, { kind: 'account_deletion' }>['data'];
type Selection = { action: AccountLifecycleIntentAction; operationId?: OperationId };

export function AccountLifecyclePanel({ gateway }: { gateway: Gateway }) {
  const [status, setStatus] = useState<Status | null>(null);
  const [intents, setIntents] = useState<AccountDeletionIntentSummary[]>([]);
  const [historyReady, setHistoryReady] = useState(false);
  const [selection, setSelection] = useState<Selection | null>(null);
  const [confirmation, setConfirmation] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const working = useRef(false);
  const epoch = useRef(0);
  const heading = useRef<HTMLHeadingElement>(null);
  const reviewLegend = useRef<HTMLLegendElement>(null);
  const confirmationInput = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (selection) (confirmationInput.current ?? reviewLegend.current)?.focus();
  }, [selection]);

  const read = useCallback(async (after: OperationId | null) => {
    if (working.current) return;
    working.current = true;
    const current = epoch.current;
    setBusy(true);
    setError(null);
    try {
      const [remote, history] = await Promise.allSettled([
        gateway.accountDeletionStatus(), gateway.accountDeletionIntents(after),
      ]);
      if (epoch.current !== current) return;
      setStatus(remote.status === 'fulfilled' ? remote.value : null);
      setHistoryReady(history.status === 'fulfilled');
      if (history.status === 'fulfilled') setIntents(history.value);
      if (remote.status === 'rejected') {
        const cause: unknown = remote.reason;
        setError(cause && typeof cause === 'object' && 'code' in cause && cause.code === 'harness_unsupported'
          ? 'Account deletion is not available in this build.'
          : 'Account status could not be confirmed. Check sign-in and refresh before making a request.');
      } else if (history.status === 'rejected') setError('Previous requests could not be read. Refresh before making a request.');
    } catch {
      if (epoch.current === current) { setStatus(null); setHistoryReady(false); setError('Account status could not be confirmed. Check sign-in and refresh before making a request.'); }
    } finally {
      if (epoch.current === current) { working.current = false; setBusy(false); }
    }
  }, [gateway]);

  useEffect(() => {
    epoch.current += 1;
    working.current = false;
    setStatus(null); setIntents([]); setHistoryReady(false); setSelection(null); setConfirmation('');
    void read(null);
    return () => { epoch.current += 1; working.current = false; };
  }, [read]);

  const canSubmit = !!status && status.state !== 'purged' && historyReady && !!selection &&
    (!!selection.operationId || (selection.action === 'beginDeletion' ? status.state === 'active' : status.state === 'pending_delete'));
  async function submit() {
    if (working.current || !canSubmit || !selection || (selection.action === 'beginDeletion' && confirmation !== 'delete')) return;
    working.current = true;
    const current = epoch.current;
    setBusy(true); setError(null); setConfirmation('');
    try {
      const intent = { action: selection.action, operationId: selection.operationId ?? uuidV7() as OperationId };
      setSelection(intent);
      const next = await (intent.action === 'beginDeletion'
        ? gateway.accountDeletionBegin(intent.operationId, 'delete')
        : gateway.accountDeletionCancel(intent.operationId));
      if (epoch.current === current) { setStatus(next); setSelection(null); }
    } catch {
      if (epoch.current === current) {
        setStatus(null);
        setError('This request could not be confirmed. Refresh status, then explicitly retry this request.');
      }
    } finally {
      if (epoch.current === current) { working.current = false; setBusy(false); heading.current?.focus(); }
    }
  }
  function review(next: Selection) { setSelection(next); setConfirmation(''); }
  const deadline = status?.purgeDeadline ? new Date(Number(status.purgeDeadline)) : null;
  return <section className="recovery-workspace" aria-labelledby="account-deletion-title" aria-busy={busy}>
    <h2 id="account-deletion-title" ref={heading} tabIndex={-1}>Account deletion</h2>
    <p>Account deletion schedules permanent removal of hosted data. Keep a backup before requesting deletion.</p>
    {error && <p role="alert">{error}</p>}
    {busy && <p role="status">Checking your account request…</p>}
    {status?.state === 'active' && <p role="status">Your account is active.</p>}
    {status?.state === 'pending_delete' && <p role="status">Deletion is scheduled{deadline && !Number.isNaN(deadline.getTime()) ? ` for ${deadline.toLocaleString()}.` : '.'} You can request cancellation before permanent removal.</p>}
    {status?.state === 'purged' && <p role="status">Hosted account data has been permanently removed.</p>}
    <button type="button" disabled={busy} onClick={() => void read(null)}>Refresh account status and requests</button>
    {!selection && historyReady && status?.state === 'active' && <button type="button" disabled={busy} onClick={() => review({ action: 'beginDeletion' })}>Request account deletion</button>}
    {!selection && historyReady && status?.state === 'pending_delete' && <button type="button" disabled={busy} onClick={() => review({ action: 'cancelDeletion' })}>Cancel scheduled deletion</button>}
    {selection && <fieldset disabled={busy}>
      <legend ref={reviewLegend} tabIndex={-1}>{selection.action === 'beginDeletion' ? 'Review deletion request' : 'Review cancellation request'}</legend>
      {selection.operationId && <p>Retry the original request: <code>{selection.operationId}</code>. A retry does not create a new request.</p>}
      {selection.action === 'beginDeletion' && <div className="field"><label htmlFor="account-delete-confirmation">Type delete to confirm</label><input ref={confirmationInput} id="account-delete-confirmation" autoComplete="off" value={confirmation} onChange={event => setConfirmation(event.target.value)} /></div>}
      <button type="button" disabled={!canSubmit || (selection.action === 'beginDeletion' && confirmation !== 'delete')} onClick={() => void submit()}>{selection.action === 'beginDeletion' ? 'Confirm deletion request' : 'Confirm cancellation request'}</button>
      <button type="button" onClick={() => { setSelection(null); heading.current?.focus(); }}>Close request review</button>
    </fieldset>}
    <h3>Previous requests</h3>
    <p>These show what you requested, not whether the provider completed it. Refresh reads current status without retrying a request.</p>
    {historyReady && intents.length === 0 && <p>No previous requests on this page.</p>}
    <ul>{intents.map(intent => <li key={intent.operationId}><button type="button" disabled={busy} onClick={() => review(intent)}>Review {intent.action === 'beginDeletion' ? 'deletion' : 'cancel'} request {intent.operationId}</button></li>)}</ul>
    {historyReady && intents.length === 50 && <button type="button" disabled={busy} onClick={() => void read(intents[intents.length - 1].operationId)}>Next requests</button>}
  </section>;
}
