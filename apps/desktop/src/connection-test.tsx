import { useEffect, useRef, useState } from 'react';
import type { ConnectionCheckStatus, HarnessId, HarnessParams, MemoryRecord, OperationId, ProjectIdentity } from './bindings';
import type { WorkspaceGateway } from './workspace';
import { HARNESS_NAMES } from './harness-names';
import { copyHarnessCommand, harnessLaunchPresentation } from './harness-launch';

class CheckBindingError extends Error {}

function missingCheck(error: unknown): boolean {
  return !!error && typeof error === 'object' && 'code' in error && error.code === 'not_found';
}

interface Props {
  gateway: WorkspaceGateway;
  project: ProjectIdentity;
  harnesses: HarnessId[];
  noteId: string | null;
  checkId: string | null;
  onProgress: (noteId: string | null, checkId: string | null, harness: HarnessId) => void;
  onVerified: (verified: boolean) => void;
  onOpenHarness: (selection: HarnessParams) => Promise<void> | void;
  onCopyCommand?: (selection: HarnessParams) => Promise<void> | void;
  onCopyPrompt: (prompt: string) => Promise<void> | void;
  onBusy?: (busy: boolean) => void;
  hermesProfile?: string;
  onDone?: () => void;
  initialHarness?: HarnessId | null;
  onReceipt?: (receipt: ConnectionCheckStatus) => void;
}

export function ConnectionTest({ gateway, project, harnesses, noteId, checkId, onProgress, onVerified, onOpenHarness, onCopyCommand = copyHarnessCommand, onCopyPrompt, onBusy, hermesProfile = 'default', onDone, initialHarness, onReceipt }: Props) {
  const [harness, setHarness] = useState<HarnessId>(initialHarness && harnesses.includes(initialHarness) ? initialHarness : harnesses[0] ?? 'codex');
  const [body, setBody] = useState('Use clear, plain language and explain unfamiliar terms.');
  const [note, setNote] = useState<MemoryRecord | null>(null);
  const [check, setCheck] = useState<ConnectionCheckStatus | null>(null);
  const [actionBusy, setBusy] = useState(false);
  const [restoring, setRestoring] = useState(!!noteId);
  const [restoreFailed, setRestoreFailed] = useState(false);
  const [restoreAttempt, setRestoreAttempt] = useState(0);
  const [checkError, setCheckError] = useState<string | null>(null);
  const [statusAttempt, setStatusAttempt] = useState(0);
  const actionInFlight = useRef(false);
  const observation = useRef(0);
  const lastReceipt = useRef<string | null>(null);
  const busy = actionBusy || restoring;
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const attempt = useRef({});
  const mounted = useRef(true);
  const callbacks = useRef({ onProgress, onVerified, onReceipt });
  callbacks.current = { onProgress, onVerified, onReceipt };
  const selection: HarnessParams = { harness, projectId: project.projectId, hermesProfile: harness === 'hermes' ? hermesProfile : null };
  const name = HARNESS_NAMES[harness];
  const { canOpenWindow, terminal } = harnessLaunchPresentation();
  const macos = !canOpenWindow;
  const verified = check?.phase === 'verified' && !restoring && !restoreFailed && !checkError && !!note && matches(check, note);
  const prompt = note ? `Use the Context Relay context_relay_get tool to read saved context note ${note.id} in project ${project.projectId}. Read this exact note now, then quote its contents and explain how you will use it. Do not answer from an earlier message, a search result or another file.` : '';

  useEffect(() => {
    mounted.current = true;
    callbacks.current.onVerified(false);
    return () => { mounted.current = false; observation.current += 1; };
  }, []);
  useEffect(() => { onBusy?.(busy); }, [busy, onBusy]);

  function matches(value: ConnectionCheckStatus, record: MemoryRecord): boolean {
    return value.selection.projectId === project.projectId && value.selection.harness === harness &&
      value.selection.hermesProfile === (harness === 'hermes' ? hermesProfile : null) &&
      value.memoryId === record.id && value.expectedRevision === record.revision;
  }

  function publishVerification(value: ConnectionCheckStatus | null) {
    callbacks.current.onVerified(value?.phase === 'verified');
    if (value?.phase !== 'verified' || !value.verifiedAt) return;
    const identity = value.checkId + ':' + value.verifiedAt;
    if (lastReceipt.current !== identity) {
      lastReceipt.current = identity;
      callbacks.current.onReceipt?.(value);
    }
  }

  // Reconcile identifiers with current records and service state. Resuming never writes.
  useEffect(() => {
    if (!noteId) return;
    let active = true;
    let noteMissing = false;
    let readingCheck = false;
    observation.current += 1;
    setRestoring(true); setRestoreFailed(false); setCheckError(null); setError(null);
    callbacks.current.onVerified(false);
    void gateway.memories(project.projectId).then(async records => {
      if (!active) return;
      const record = records.find(item => item.id === noteId && !item.archived);
      if (!record) {
        noteMissing = true;
        setNote(null);
        throw new Error('The test note is no longer available. Save a new test note to continue.');
      }
      setNote(record);
      readingCheck = checkId !== null;
      const current = checkId ? await gateway.connectionCheckStatus(checkId as OperationId) : null;
      if (!active) return;
      if (current && (current.checkId !== checkId || !matches(current, record))) {
        throw new CheckBindingError('This check does not match the selected harness or current note. Start a new check.');
      }
      setCheck(current);
      publishVerification(current);
    }).catch(failure => {
      if (!active) return;
      setCheck(null);
      callbacks.current.onVerified(false);
      // A failed read is not proof of a missing note or a dead check. Preserve
      // the persisted identity and offer a read retry, not a duplicate mutation.
      // NotFound from the note list cannot prove that this check disappeared.
      const checkMissing = readingCheck && missingCheck(failure);
      const unavailable = noteMissing || failure instanceof CheckBindingError || checkMissing;
      setRestoreFailed(!unavailable);
      setError(noteMissing || failure instanceof CheckBindingError ? failure.message
        : checkMissing ? 'This check is no longer available. The service may have restarted. Start a new check.'
          : 'This test could not be restored. Retry restoring the same test when the local service is available.');
    }).finally(() => { if (active) setRestoring(false); });
    return () => { active = false; };
    // Selection changes invalidate old restoration callbacks as well as polls.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [gateway, project.projectId, noteId, checkId, harness, hermesProfile, restoreAttempt]);

  useEffect(() => {
    if (!check || !['waiting', 'verified'].includes(check.phase) || !note || restoring || actionBusy) return;
    let active = true;
    const generation = ++observation.current;
    let timer: number;
    const currentObservation = () => active && generation === observation.current;
    const poll = async () => {
      try {
        const current = await gateway.connectionCheckStatus(check.checkId);
        if (!currentObservation()) return;
        if (current.checkId !== check.checkId || !matches(current, note)) throw new CheckBindingError('The receipt does not match this check.');
        setCheck(current); setCheckError(null);
        publishVerification(current);
        // A verified check can still be invalidated by a changed/archived note,
        // replaced by another check, or lost when the daemon restarts.
        if (['waiting', 'verified'].includes(current.phase)) timer = window.setTimeout(() => void poll(), 1500);
      } catch (failure) {
        if (!currentObservation()) return;
        callbacks.current.onVerified(false);
        if (missingCheck(failure) || failure instanceof CheckBindingError) {
          setCheck(null);
          setCheckError('This connection check is no longer available or no longer matches. Start a new check.');
        } else {
          setCheckError('The connection check could not be refreshed. Reconnecting to the same check...');
          timer = window.setTimeout(() => void poll(), 2000);
        }
      }
    };
    timer = window.setTimeout(() => void poll(), statusAttempt ? 0 : 1500);
    return () => { active = false; window.clearTimeout(timer); };
    // Each observer belongs to the exact selection and is suspended during actions.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [gateway, check?.checkId, check?.phase, note, harness, hermesProfile, project.projectId, restoring, actionBusy, statusAttempt]);

  async function run(action: () => Promise<void>) {
    if (busy || restoreFailed || actionInFlight.current) return;
    actionInFlight.current = true;
    observation.current += 1;
    setBusy(true); setError(null); setNotice(null);
    try { await action(); }
    catch (failure) { if (mounted.current) setError(failure instanceof Error ? failure.message : 'The action could not finish. Try again.'); }
    finally { actionInFlight.current = false; if (mounted.current) setBusy(false); }
  }

  async function start(record: MemoryRecord) {
    const current = await gateway.connectionCheckStart({ selection, memoryId: record.id, expectedRevision: record.revision });
    if (!mounted.current) return;
    if (!matches(current, record) || current.phase !== 'waiting') throw new Error('The new check does not match this harness and note. Try again.');
    setCheck(current); setCheckError(null);
    callbacks.current.onVerified(false);
    callbacks.current.onProgress(record.id, current.checkId, harness);
  }

  async function retryCheck() {
    if (!note) return;
    const records = await gateway.memories(project.projectId);
    if (!mounted.current) return;
    const current = records.find(record => record.id === note.id && !record.archived);
    if (!current) {
      setNote(null); setCheck(null); attempt.current = {};
      callbacks.current.onProgress(null, null, harness);
      callbacks.current.onVerified(false);
      setError('The test note was archived or removed. Save a new test note to continue.');
      return;
    }
    setNote(current);
    await start(current);
  }

  return <section className="connection-test" aria-label="Try saved context">
    <p>Save a small note, then ask your harness to read it. This proves that the harness can retrieve context for <strong>{project.name}</strong>.</p>
    {harness === 'hermes' && <p className="help-text">This checks Hermes and the selected project. It cannot distinguish a read from another Hermes profile connected to the same project.</p>}
    {harnesses.length > 1 && <div className="field"><label htmlFor="test-harness">Harness to test</label><select id="test-harness" value={harness} disabled={busy || check?.phase === 'waiting'} onChange={event => { setHarness(event.target.value as HarnessId); setCheck(null); callbacks.current.onProgress(note?.id ?? null, null, event.target.value as HarnessId); callbacks.current.onVerified(false); }}>{harnesses.map(id => <option key={id} value={id}>{HARNESS_NAMES[id]}</option>)}</select></div>}
    {!note && !restoreFailed && <form onSubmit={event => { event.preventDefault(); void run(async () => {
      const saved = await gateway.createMemory(project.projectId, 'Setup test note', body.trim(), attempt.current);
      if (!mounted.current) return;
      setNote(saved); callbacks.current.onProgress(saved.id, null, harness);
      await start(saved);
    }); }}>
      <div className="field"><label htmlFor="test-note">Example note</label><textarea id="test-note" value={body} onChange={event => setBody(event.target.value)} disabled={busy} rows={3} /></div>
      <button className="primary-action" type="submit" disabled={busy || !body.trim()}>{busy ? 'Saving test note…' : 'Save test note'}</button>
      <p className="help-text">Nothing is saved until you choose Save test note.</p>
    </form>}
    {note && <>
      <blockquote>{note.bodyMarkdown}</blockquote>
      {check?.phase === 'waiting' && <>
        <p role="status">Waiting for {name} to read this note. The check expires in about {Math.max(1, Math.ceil(check.expiresInSeconds / 60))} minutes.</p>
        <ol><li>{macos ? `Copy the launch command and run it in Terminal to open ${name} for this project.` : `Open ${name} for this project.`} Complete any sign-in or project approval it requests.</li><li>Copy the test prompt below and send it in that harness.</li><li>Return here. Context Relay will confirm when the connected harness reads the note.</li></ol>
        <div className="toolbar-actions">
          {!macos && <button type="button" disabled={busy} onClick={() => void run(async () => { await onOpenHarness(selection); })}>Open {name}</button>}
          <button type="button" className={macos ? 'primary-action' : 'secondary-action'} disabled={busy} onClick={() => void run(async () => {
            await onCopyCommand(selection);
            if (mounted.current) setNotice(`Launch command copied. Run it in ${terminal}, then send the test prompt in your harness.`);
          })}>Copy launch command</button>
          <button type="button" disabled={busy} onClick={() => void run(async () => { await onCopyPrompt(prompt); setNotice('Test prompt copied. Paste it into your harness.'); })}>Copy test prompt</button>
        </div>
        <p className="help-text">The launch command is for {terminal}. The test prompt is for your harness after it opens.</p>
        <details><summary>View test prompt</summary><p>{prompt}</p></details>
        <button type="button" disabled={busy} onClick={() => void run(async () => { callbacks.current.onVerified(false); await gateway.connectionCheckCancel(check.checkId); setCheck(null); setCheckError(null); callbacks.current.onVerified(false); callbacks.current.onProgress(note.id, null, harness); })}>Cancel check</button>
      </>}
      {verified && <><p className="notice" role="status">Connection verified — {name} read this test note through its Context Relay connection.</p><p>You can keep this preference or archive the test note. Archived context will no longer be offered to your harness.</p><div className="toolbar-actions"><button type="button" disabled={busy} onClick={() => { setNotice('Test note kept in Context → Saved. Continue when you’re ready.'); onDone?.(); }}>Keep note</button><button type="button" disabled={busy} onClick={() => void run(async () => { await gateway.archiveMemory(note); setNote(null); setCheck(null); setCheckError(null); attempt.current = {}; callbacks.current.onVerified(false); callbacks.current.onProgress(null, null, harness); setNotice('Test note archived. Continue when you’re ready.'); onDone?.(); })}>Archive test note</button></div></>}
      {check && ['expired', 'canceled', 'invalidated'].includes(check.phase) && <p role="status">{check.phase === 'expired' ? 'The check expired before the harness read the note.' : check.phase === 'invalidated' ? 'The note changed after this check started.' : 'The check was canceled.'} Start a new check when you’re ready.</p>}
      {!restoreFailed && check?.phase !== 'waiting' && check?.phase !== 'verified' && <button type="button" className="primary-action" disabled={busy} onClick={() => void run(retryCheck)}>Start a new check</button>}
    </>}
    {restoreFailed && <button type="button" className="primary-action" disabled={busy} onClick={() => setRestoreAttempt(value => value + 1)}>Retry restoring test</button>}
    {checkError && <p className="form-error" role="alert">{checkError}{check && <button type="button" disabled={busy} onClick={() => setStatusAttempt(value => value + 1)}>Retry check status</button>}</p>}
    {notice && <p role="status">{notice}</p>}
    {error && <p className="form-error" role="alert">{error}</p>}
  </section>;
}
