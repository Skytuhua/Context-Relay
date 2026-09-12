import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import type { HarnessId, HarnessParams, HarnessSetupRecord, HarnessSetupState, HarnessSetupSummary, PlanId, ProbeReport, ProjectIdentity, SavedHookApproval, SavedMemoryHookApproval, SetupPlan, WireNativeValue } from './bindings';
import { type HarnessGateway, validateHarnessPlan, validateHarnessProbe } from './harness-gateway';
import { useHarnessExecution } from './use-harness-execution';
import { useHarnessPreparation } from './use-harness-preparation';
import { isServiceVersionMismatch, SERVICE_UPDATE_GUIDANCE } from './service-error';
import { copyHarnessCommand, harnessLaunchPresentation, openHarness } from './harness-launch';

const harnessNames: Record<HarnessId, string> = { claude_code: 'Claude Code', codex: 'Codex', hermes: 'Hermes' };
type ReviewedPlan = { plan: SetupPlan; params: HarnessParams; projectName: string; state?: HarnessSetupState };
type BusyAction = 'preview' | 'loading' | 'checking' | 'preparing' | 'apply' | 'rollback' | null;

export function HarnessesScreen({ gateway, projects, preferredProjectId, preferredHarness, preferredHermesProfile = 'default', onProfileChange, embedded = false, onBusy, onProjectChange, onAddProject, onSaveContext, active = true }: { gateway: HarnessGateway; projects: ProjectIdentity[]; preferredProjectId?: string; preferredHarness?: HarnessId; preferredHermesProfile?: string; onProfileChange?: (profile: string) => void; embedded?: boolean; onBusy?: (busy: boolean) => void; onProjectChange?: (id: string) => void; onAddProject?: () => void; onSaveContext?: () => void; active?: boolean }) {
  const [selectedProjectId, setProjectId] = useState<string | null>(null);
  const projectId = preferredProjectId ?? selectedProjectId ?? projects[0]?.projectId ?? '';
  const [harness, setHarness] = useState<HarnessId>('codex');
  const [profile, setProfile] = useState(preferredHermesProfile);
  const canonicalProfile = profile.trim().replace(/[A-Z]/g, (letter) => letter.toLowerCase());
  const validProfile = /^[a-z0-9][a-z0-9_-]{0,63}$/.test(canonicalProfile);
  const [review, setReview] = useState<ReviewedPlan | null>(null);
  const [discovery, setDiscovery] = useState<{ harness: HarnessId; report: ProbeReport } | null>(null);
  const [approved, setApproved] = useState(false);
  const execution = useHarnessExecution(gateway, active);
  const preparation = useHarnessPreparation(gateway, active);
  const [history, setHistory] = useState<HarnessSetupSummary[]>([]);
  const historyGeneration = useRef(0);
  const historyReadInFlight = useRef(false);
  const { canOpenWindow, terminal } = harnessLaunchPresentation();
  const [nextAfter, setNextAfter] = useState<PlanId | null>(null);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyRevision, refreshHistory] = useState(0);
  const [details, setDetails] = useState<Map<PlanId, HarnessSetupRecord>>(new Map());
  const [rollbackTarget, setRollbackTarget] = useState<PlanId | null>(null);
  const [localBusy, setBusy] = useState<BusyAction>(null);
  const busy: BusyAction = localBusy ?? (execution.busy ? execution.pending?.action ?? 'checking' : preparation.busy ? 'preparing' : null);
  const [error, setError] = useState<string | null>(null);
  const [launchNotice, setLaunchNotice] = useState<string | null>(null);
  const [now, setNow] = useState(Date.now);
  const busyRef = useRef<BusyAction>(null);
  const generation = useRef(0);
  const mounted = useRef(false);
  const resultHeadingRef = useRef<HTMLHeadingElement>(null);
  const errorRef = useRef<HTMLParagraphElement>(null);
  const project = projects.find((item) => item.projectId === projectId);
  const expired = review !== null && BigInt(review.plan.expiresAt) <= BigInt(now);
  const conflicts = review?.plan.semanticChanges.some((change) => change.class === 'conflict') ?? false;
  const matching = review !== null && (review.params.projectId === null || review.params.projectId === project?.projectId) &&
    review.params.harness === harness && review.params.hermesProfile === (harness === 'hermes' ? canonicalProfile : null);
  const canApply = approved && matching && !expired && !conflicts && !busy;
  const shownHistory = includeObservedSetup(history, execution.outcome?.setup);

  // Read-only discovery can block settings changes without trapping navigation.
  // Once a mutation is submitted or discovered, keep its navigation guard.
  const navigationBusy = localBusy !== null || execution.starting || execution.pending !== null || preparation.busy;
  const resultSelection = execution.outcome ? reviewed(execution.outcome.setup, projects).params : null;
  const currentResult = resultSelection !== null && resultSelection.harness === harness &&
    resultSelection.projectId === projectId && resultSelection.hermesProfile === (harness === 'hermes' ? canonicalProfile : null);
  const guidedSaved = embedded && currentResult && execution.outcome?.setup.state === 'applied' && execution.outcome.status.error === null;
  const needsProjectTrust = discovery?.harness === harness && harness === 'codex' &&
    discovery.report.capability === 'blocked' && discovery.report.policyConflicts.includes('project_untrusted') &&
    !discovery.report.policyConflicts.includes('managed_requirements_active');
  const showLaunchHelp = !embedded || (!busy && !review && !preparation.target && needsProjectTrust);

  useEffect(() => { onBusy?.(navigationBusy); }, [navigationBusy, onBusy]);

  useEffect(() => {
    if (!preferredHarness || preferredHarness === harness) return;
    generation.current += 1;
    setHarness(preferredHarness);
    setLaunchNotice(null);
    setReview(null);
    setDiscovery(null);
    setApproved(false);
  }, [preferredHarness, harness]);

  // Move focus with the visible result, before the browser can paint it.
  useLayoutEffect(() => {
    if (!active) return;
    const heading = resultHeadingRef.current;
    heading?.focus({ preventScroll: true });
    heading?.scrollIntoView?.({ block: 'start' });
  }, [active, discovery, review]);

  useLayoutEffect(() => {
    if (!active || !error) return;
    errorRef.current?.focus({ preventScroll: true });
    errorRef.current?.scrollIntoView?.({ block: 'center' });
  }, [active, error]);

  useEffect(() => {
    const revision = ++historyGeneration.current;
    historyReadInFlight.current = false;
    if (!active || execution.busy) { setHistoryLoading(false); return; }
    let canceled = false;
    const current = () => !canceled && revision === historyGeneration.current;
    setHistoryLoading(true);
    gateway.harnessSetupsList().then(page => {
      if (!current()) return;
      setHistory(includeObservedSetup(page.setups, execution.outcome?.setup)); setNextAfter(page.nextAfter); setHistoryError(null);
    }).catch(() => { if (current()) setHistoryError('Saved setup history could not be loaded.'); })
      .finally(() => { if (current()) setHistoryLoading(false); });
    return () => { canceled = true; historyGeneration.current += 1; };
  }, [gateway, active, execution.busy, execution.outcome, historyRevision]);

  useEffect(() => {
    if (!execution.outcome) return;
    const setup = execution.outcome.setup;
    // Preserve the acknowledged record when starting another explicit action
    // clears the transient outcome, even if the list refresh is unavailable.
    setHistory(current => includeObservedSetup(current, setup));
    setDetails(current => new Map(current).set(setup.plan.planId, setup));
  }, [execution.outcome]);

  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; generation.current += 1; };
  }, []);

  useEffect(() => {
    if (active) return;
    generation.current += 1;
    setLaunchNotice(null);
    setError(null);
    setReview(null);
    setDiscovery(null);
    setApproved(false);
    setRollbackTarget(null);
  }, [active]);

  useEffect(() => {
    generation.current += 1;
    setLaunchNotice(null);
    setError(null);
    setReview(current => current?.params.projectId === projectId || current?.params.projectId === null ? current : null);
    setDiscovery(null);
    setApproved(false);
    setRollbackTarget(null);
  }, [projectId]);

  useEffect(() => {
    if (!review) return;
    const timer = window.setInterval(() => setNow(Date.now()), 500);
    return () => window.clearInterval(timer);
  }, [review]);

  function clearReview() {
    generation.current += 1;
    setLaunchNotice(null);
    setReview(null);
    setDiscovery(null);
    setApproved(false);
    setError(null);
    execution.clearOutcome();
    setRollbackTarget(null);
  }

  function start(action: Exclude<BusyAction, null>) {
    if (!active || busyRef.current || execution.busy || preparation.busy) return false;
    busyRef.current = action;
    setBusy(action);
    setError(null);
    execution.clearOutcome();
    return true;
  }

  function finish() {
    busyRef.current = null;
    if (mounted.current) setBusy(null);
  }

  async function previewSetup() {
    if (preparation.target || !project || (harness === 'hermes' && !validProfile) || !start('preview')) return;
    clearReview();
    const revision = generation.current;
    const params: HarnessParams = { harness, projectId: project.projectId, hermesProfile: harness === 'hermes' ? canonicalProfile : null };
    try {
      const report = validateHarnessProbe(await gateway.harnessProbe(params), params);
      if (!mounted.current || revision !== generation.current) return;
      setDiscovery({ harness: params.harness, report: structuredClone(report) });
      if (report.capability !== 'full') {
        return;
      }
      const result = validateHarnessPlan(await gateway.harnessPreview(params), params);
      if (!mounted.current || revision !== generation.current) return;
      setNow(Date.now());
      // Keep the reviewed contents and their selection together for apply and rollback.
      setReview({ plan: structuredClone(result), params, projectName: project.name });
      refreshHistory(value => value + 1);
    } catch (error) {
      if (mounted.current && revision === generation.current) {
        setError(setupError(error, params.harness));
      }
    } finally { finish(); }
  }

  async function applySetup() {
    if (!canApply || !review || BigInt(review.plan.expiresAt) <= BigInt(Date.now())) return;
    const approvedReview = review;
    setDiscovery(null);
    setApproved(false);
    setRollbackTarget(null);
    setReview(null);
    setError(null);
    await execution.execute({ planId: approvedReview.plan.planId, action: 'apply' });
  }

  async function rollbackSetup(item: ReviewedPlan) {
    if (rollbackTarget !== item.plan.planId || busy) return;
    setDiscovery(null);
    setRollbackTarget(null);
    setApproved(false);
    setReview(null); setError(null);
    await execution.execute({ planId: item.plan.planId, action: 'rollback' });
  }

  async function reviewPreparedSetup() {
    const target = preparation.target;
    if (!target || preparation.status?.phase !== 'ready' || !start('preview')) return;
    const revision = generation.current;
    try {
      const plan = validateHarnessPlan(await gateway.harnessPreparedPreview(target), target.selection);
      if (!mounted.current || revision !== generation.current) return;
      const restored = reviewed({ plan, state: 'previewed', createdAt: '0' }, projects);
      setHarness(target.selection.harness); setProfile(target.selection.hermesProfile ?? 'default');
      if (target.selection.projectId !== null) {
        if (onProjectChange) onProjectChange(target.selection.projectId); else setProjectId(target.selection.projectId);
      }
      setNow(Date.now()); setReview(restored); setApproved(false); setDiscovery(null);
      preparation.dismiss(); refreshHistory(value => value + 1);
    } catch {
      preparation.checkAgain();
      if (mounted.current && revision === generation.current) setError('Could not confirm the prepared review. Checking preparation before offering the next action.');
    }
    finally { finish(); }
  }

  async function loadSetup(id: PlanId, intent: 'details' | 'review' | 'undo') {
    if (!start('loading')) return;
    const revision = generation.current;
    try {
      const setup = await gateway.harnessSetupGet(id);
      if (!mounted.current || revision !== generation.current) return;
      setDetails(current => new Map(current).set(id, setup));
      setHistory(current => current.map(item => item.planId === id ? { ...item, state: setup.state } : item));
      if (intent === 'undo' && ['applied', 'rolling_back'].includes(setup.state)) setRollbackTarget(id);
      if (intent === 'review' && ['previewed', 'applying'].includes(setup.state)) {
        const restored = reviewed(setup, projects);
        setHarness(restored.params.harness); setProfile(restored.params.hermesProfile ?? 'default');
        if (restored.params.projectId !== null) {
          if (onProjectChange) onProjectChange(restored.params.projectId); else setProjectId(restored.params.projectId);
        }
        setApproved(false); setNow(Date.now()); setReview(restored);
      }
    } catch { if (mounted.current && revision === generation.current) setError('Could not load this saved setup. Its changes have not been retried.'); }
    finally { finish(); }
  }

  async function loadMoreHistory() {
    if (!active || !nextAfter || historyLoading || historyReadInFlight.current || busy) return;
    const revision = historyGeneration.current;
    const current = () => mounted.current && revision === historyGeneration.current;
    historyReadInFlight.current = true;
    setHistoryLoading(true);
    try {
      const page = await gateway.harnessSetupsList(nextAfter);
      if (!current()) return;
      setHistory(records => [...records, ...page.setups.filter(item => !records.some(existing => existing.planId === item.planId))]);
      setNextAfter(page.nextAfter); setHistoryError(null);
    } catch { if (current()) setHistoryError('More saved setups could not be loaded. Try again.'); }
    finally {
      if (current()) { historyReadInFlight.current = false; setHistoryLoading(false); }
    }
  }

  async function launch(copy: boolean) {
    if (!active || busy || !project || (harness === 'hermes' && !validProfile)) return;
    const revision = generation.current;
    const selection: HarnessParams = { harness, projectId: project.projectId, hermesProfile: harness === 'hermes' ? canonicalProfile : null };
    setLaunchNotice(null); setError(null);
    try {
      if (copy) await copyHarnessCommand(selection); else await openHarness(selection);
      if (!mounted.current || revision !== generation.current) return;
      setLaunchNotice(copy ? 'Command copied. Paste it into ' + terminal + ' to open your harness in this project.'
        : 'Harness window opened. Review any prompts there, then return here.');
    } catch {
      if (!mounted.current || revision !== generation.current) return;
      setError(copy ? 'The command could not be copied. Check the installed harness and registered project folder, then try again.'
        : 'The harness window could not open. Use Copy command and run it in ' + terminal + ', or check that the harness is installed.');
    }
  }

  if (projects.length === 0) return <section className="screen-content empty-state" aria-label="Harness connection">
    <h2>Add a project first</h2>
    <p>Choose the folder whose context you want to share with your harness.</p>
    {onAddProject ? <button className="primary-action" type="button" onClick={onAddProject}>Add a project</button>
      : <p>Open Projects to add your folder, then return here.</p>}
  </section>;

  return (
    <section className="screen-content harness-connection" aria-label="Harness connection">
      <form className="capture-form" aria-label="Review harness setup" onSubmit={(event) => { event.preventDefault(); void previewSetup(); }}>
        <h2>{embedded ? `Connect ${harnessNames[harness]}` : 'Connect a harness'}</h2>
        <p>{embedded ? `Review the changes for ${project?.name ?? 'your project'}, then save the settings you approve.` : 'Choose your project and harness to check compatibility and review the settings.'}</p>
        {!embedded && <div className="field">
          <label htmlFor="harness-project">Project</label>
          <select id="harness-project" value={projectId} disabled={busy === 'apply' || busy === 'rollback' || preparation.busy} onChange={(event) => { clearReview(); if (onProjectChange) onProjectChange(event.target.value); else setProjectId(event.target.value); }}>
            <option value="">Choose your project</option>
            {projects.map((item) => <option key={item.projectId} value={item.projectId}>{item.name}</option>)}
          </select>
        </div>}
        {!embedded && <div className="field">
          <label htmlFor="harness-kind">Harness</label>
          <select id="harness-kind" value={harness} disabled={busy === 'apply' || busy === 'rollback' || preparation.busy} onChange={(event) => { clearReview(); setHarness(event.target.value as HarnessId); }}>
            {Object.entries(harnessNames).map(([id, name]) => <option key={id} value={id}>{name}</option>)}
          </select>
        </div>}
        {harness === 'hermes' && <div className="field">
          <label htmlFor="hermes-profile">Hermes profile</label>
          <input id="hermes-profile" value={profile} maxLength={64} required aria-invalid={!validProfile} aria-describedby="hermes-profile-help" disabled={busy === 'apply' || busy === 'rollback' || preparation.busy} onChange={(event) => { clearReview(); setProfile(event.target.value); const next = event.target.value.trim().toLowerCase(); if (/^[a-z0-9][a-z0-9_-]{0,63}$/.test(next)) onProfileChange?.(next); }} />
          <p id="hermes-profile-help">Use a profile name, such as default or coder. Leave default selected unless you created another profile. Folder paths are not profile names.</p>
        </div>}
        <button className={embedded && (review || guidedSaved) ? 'secondary-action' : 'primary-action'} type="submit" disabled={!!busy || preparation.target !== null || !project || (harness === 'hermes' && !validProfile)}>{busy === 'preview' ? 'Checking harness…' : 'Review setup'}</button>
      </form>
      {project && showLaunchHelp && <section className="help-content" aria-label="Open harness for project">
        <p>{canOpenWindow ? 'Open ' : 'Copy the launch command to open '}{harnessNames[harness]} in <strong>{project.name}</strong>{canOpenWindow ? '' : ' using Terminal'} to review its sign-in or project approval prompts. Return here and check again when you finish.</p>
        <div className="toolbar-actions">
          {canOpenWindow && <button type="button" disabled={!!busy || (harness === 'hermes' && !validProfile)} onClick={() => void launch(false)}>Open {harnessNames[harness]} for this project</button>}
          <button type="button" disabled={!!busy || (harness === 'hermes' && !validProfile)} onClick={() => void launch(true)}>Copy command</button>
          <button type="button" disabled={!!busy} onClick={() => void previewSetup()}>Check again</button>
        </div>
        {launchNotice && <p role="status">{launchNotice}</p>}
      </section>}
      {error && <p className="form-error" role="alert" ref={errorRef} tabIndex={-1}>{error}</p>}
      {preparation.error && <p className="form-error" role="alert">{preparation.error}{preparation.target && <button type="button" onClick={preparation.checkAgain}>Check preparation</button>}</p>}
      {preparation.target && <section className="record-card" aria-label="Harness preparation">
        <h2>Prepare Hermes setup</h2>
        <p>Hermes ({preparation.target.selection.hermesProfile}) for {projects.find(item => item.projectId === preparation.target?.selection.projectId)?.name ?? 'saved project'}</p>
        {!preparation.missing && <p role="status">{preparation.status ? preparationText(preparation.status.phase) : 'Checking preparation…'}</p>}
        {preparation.status && preparation.status.completedFiles > 0 && <p className="help-text">{preparation.status.completedFiles.toLocaleString()} files · {(preparation.status.completedBytes / 1024 / 1024).toLocaleString(undefined, { maximumFractionDigits: 1 })} MB processed</p>}
        <p>Preparation makes a private copy for Context Relay. Harness settings change only after you review and save them.</p>
        {preparation.busy && <p>This can take a few minutes. Keep this window open while preparation finishes.</p>}
        {preparation.busy && <button type="button" className="secondary-action" disabled={preparation.canceling || preparation.status?.phase === 'cancelling'} onClick={() => void preparation.cancel()}>Cancel preparation</button>}
        {!preparation.busy && !preparation.missing && preparation.status?.phase === 'ready' && <button type="button" className="primary-action" disabled={!!busy} onClick={() => void reviewPreparedSetup()}>Review prepared setup</button>}
        {preparation.missing && <button type="button" className="primary-action" disabled={!!busy} onClick={() => void preparation.retry()}>Retry same preparation</button>}
        {!preparation.busy && !preparation.missing && <button type="button" className="secondary-action" disabled={!!busy} onClick={preparation.dismiss}>Dismiss preparation</button>}
      </section>}
      {execution.error && <p className="form-error" role="alert">{execution.error} <button type="button" onClick={execution.checkAgain}>Check again</button></p>}
      {execution.outcome && (!embedded || currentResult) && <section aria-label="Setup result"><p className={execution.outcome.status.error ? 'form-error' : 'notice'} role={execution.outcome.status.error ? 'alert' : 'status'}>
        {outcomeText(execution.outcome.status.action, execution.outcome.setup.state, execution.outcome.status.error !== null)} {label(reviewed(execution.outcome.setup, projects))}.
      </p>{execution.outcome.setup.state === 'applied' && <SetupNextSteps item={reviewed(execution.outcome.setup, projects)} guided={guidedSaved} />}</section>}
      {discovery && discovery.report.capability !== 'full' && <section className="connection-result" aria-label="Harness availability">
        <h2 ref={resultHeadingRef} tabIndex={-1}>{harnessNames[discovery.harness]}{discovery.report.harnessVersion && discovery.report.harnessVersion !== 'unknown' ? ` ${discovery.report.harnessVersion}` : ''}</h2>
        <p role="status">{discovery.report.capability === 'missing'
          ? `${harnessNames[discovery.harness]} was not found. Install it, restart Context Relay and select Review setup again.`
          : discovery.report.capability === 'blocked'
            ? blockedSetupGuidance(discovery.harness, discovery.report)
            : preparationAvailable(discovery.harness, discovery.report)
              ? 'Hermes needs a private runtime copy before you can review its setup. Preparation can take a few minutes and can be canceled.'
            : discovery.harness === 'hermes' && discovery.report.policyConflicts.includes('python_runtime_not_qualified')
              ? 'Hermes uses a Python runtime that Context Relay does not support for automatic connection yet. Your Hermes installation does not need to be reinstalled.'
            : discovery.harness === 'hermes' && discovery.report.harnessVersion === 'unknown'
              ? 'Hermes was found, but this launcher cannot connect automatically yet. Context Relay cannot verify its version and runtime. You can still save context and tasks while launcher support is completed.'
              : 'This version cannot connect automatically yet. You can still save context and tasks in Context Relay while support for this version is completed.'}</p>
        <p>The harness is not connected. No setup changes were made.</p>
        {preparationAvailable(discovery.harness, discovery.report) && !preparation.target && <button type="button" className="primary-action" disabled={!!busy} onClick={() => {
          if (busy || !project) return;
          const selection: HarnessParams = { harness: 'hermes', projectId: project.projectId, hermesProfile: canonicalProfile };
          clearReview(); void preparation.begin(selection);
        }}>Prepare setup</button>}
        {onSaveContext && <button className="secondary-action" type="button" disabled={!!busy} onClick={onSaveContext}>Save context</button>}
        {discovery.report.executable && <details className="technical-details"><summary>Technical details</summary><p>Executable: {nativeText(discovery.report.executable)}</p>{discovery.harness === 'hermes' && discovery.report.policyConflicts.includes('python_runtime_not_qualified') && <p>Version read from installed package metadata. The Python runtime has not been executed or verified for connection.</p>}</details>}
      </section>}
      {discovery?.report.codexSavedHookApproval && <SavedHookApprovals approval={discovery.report.codexSavedHookApproval} />}
      {busy && busy !== 'preparing' && <p role="status">{busy === 'preview' ? 'Checking the installed harness…' : busy === 'loading' ? 'Loading saved setup…' : busy === 'checking' ? 'Checking for unfinished setup…' : busy === 'apply' ? 'Saving harness settings…' : 'Undoing setup changes…'}</p>}
      {execution.pending && <p className="help-text">This can take a few minutes. Keep this window open while settings are saved or restored. The result will appear here.</p>}
      {review && <section className="record-card" aria-labelledby="harness-review-title">
        <h2 id="harness-review-title" ref={resultHeadingRef} tabIndex={-1}>Review setup changes</h2>
        <p>{label(review)}</p>
        <PlanDetails plan={review.plan} projectName={review.projectName} />
        {review.params.harness === 'codex' && <p>After saving, review the Context Relay session hooks in the Codex CLI. Codex requires approval before new or changed hooks can run.</p>}
        {expired && <p className="form-error">This setup review has expired. Select Review setup again.</p>}
        {conflicts && <p className="form-error">Resolve the conflicting settings shown above, then select Review setup again.</p>}
        {!matching && <p className="form-error">The project or harness changed. Select Review setup again.</p>}
        {review.state === 'applying' && !expired && <p>The previous save was interrupted. Review these settings before resuming the same setup.</p>}
        <label>
          <input type="checkbox" checked={approved} disabled={!!busy || expired || conflicts || !matching} onChange={(event) => setApproved(event.target.checked)} />
          I reviewed and approve these settings.
        </label>
        <button className="primary-action" type="button" disabled={!canApply} onClick={() => void applySetup()}>{review.state === 'applying' ? 'Resume save' : 'Save settings'}</button>
      </section>}
      {(shownHistory.length > 0 || nextAfter !== null || historyError || historyLoading) && <section aria-label="Recent setup changes">
        <p className="help-text">Undo setup restores the harness settings from before that connection setup. Review the saved changes before you undo them.</p>
        <h2>Recent setup changes</h2>
        {historyError && <p className="form-error" role="alert">{historyError} <button type="button" disabled={!!busy} onClick={() => refreshHistory(value => value + 1)}>Reload history</button></p>}
        {historyLoading && <p role="status">Loading saved setups…</p>}
        <ul className="record-list">{shownHistory.filter(summary => summary.planId !== review?.plan.planId).map(summary => {
          const saved = execution.outcome?.setup.plan.planId === summary.planId ? execution.outcome.setup : details.get(summary.planId);
          const state = execution.outcome?.setup.plan.planId === summary.planId ? execution.outcome.setup.state : summary.state;
          const item = saved ? reviewed(saved, projects) : null;
          const name = summaryLabel(summary, projects);
          const reference = summary.planId.slice(-8).toUpperCase();
          return <li className="record-card" key={summary.planId}>
          <h3>{name} · setup {reference}</h3>
          <p>{execution.pending?.planId === summary.planId ? (execution.pending.action === 'apply' ? 'Saving settings…' : 'Undoing setup changes…') : setupStateText(state)}</p>
          <p className="help-text">{expiryText(summary.createdAt)}</p>
          {!embedded && item && state === 'applied' && saved?.state === 'applied' && execution.outcome?.setup.plan.planId !== summary.planId && <SetupNextSteps item={item} />}
          {item ? <details className="connection-history-details"><summary>View saved changes</summary><PlanDetails plan={item.plan} projectName={item.projectName} /></details>
            : <button type="button" className="secondary-action" disabled={!!busy} onClick={() => void loadSetup(summary.planId, 'details')}>View saved changes for {name}</button>}
          {(state === 'previewed' || state === 'applying') && <button type="button" className="secondary-action" disabled={!!busy} onClick={() => void loadSetup(summary.planId, 'review')}>Review saved setup for {name}</button>}
          {(state === 'applied' || state === 'rolling_back') && <button className="secondary-action" type="button" disabled={!!busy} onClick={() => void loadSetup(summary.planId, 'undo')}>{state === 'rolling_back' ? 'Resume Undo' : 'Undo setup'} {reference} for {name}</button>}
          {item && rollbackTarget === summary.planId && <div role="group" aria-label={`Confirm rollback of ${label(item)}`}>
            <p>Restore the configuration from before this setup? Context Relay will check for changes made since then.</p>
            <button type="button" className="primary-action" disabled={!!busy} onClick={() => void rollbackSetup(item)}>Undo setup changes</button>
            <button type="button" className="secondary-action" disabled={!!busy} onClick={() => setRollbackTarget(null)}>Keep settings</button>
          </div>}
        </li>; })}</ul>
        {nextAfter !== null && <button type="button" className="secondary-action" disabled={historyLoading || !!busy} onClick={() => void loadMoreHistory()}>Load more setups</button>}
      </section>}
    </section>
  );
}

function preparationAvailable(harness: HarnessId, report: ProbeReport) {
  return harness === 'hermes' && report.capability === 'import_only' && report.harnessVersion === '0.17.0' &&
    report.executable?.platform === 'windows' && report.policyConflicts.includes('python_runtime_preparation_required');
}

function preparationText(phase: import('./bindings').HarnessPreparationPhase) {
  const names: Record<typeof phase, string> = {
    inspecting: 'Checking the Hermes installation…', copying: 'Copying the Hermes runtime…',
    checking_source: 'Checking the source files…', checking_copy: 'Checking the prepared copy…',
    retaining: 'Finishing preparation…', cancelling: 'Canceling preparation…',
    ready: 'Preparation is ready. Review the changes before saving.', canceled: 'Preparation canceled.',
    failed: 'Preparation could not finish. Dismiss this attempt and review the harness to try again.',
  };
  return names[phase];
}

function reviewed(setup: HarnessSetupRecord, projects: ProjectIdentity[]): ReviewedPlan {
  const project = setup.plan.targetScopes.find(scope => scope.scope === 'project');
  const projectId = project?.scope === 'project' ? project.projectId : null;
  return { plan: setup.plan, state: setup.state,
    params: { harness: setup.plan.harness, hermesProfile: setup.plan.harnessProfile, projectId },
    projectName: projectId === null ? 'all projects' : projects.find(item => item.projectId === projectId)?.name ?? 'saved project',
  };
}

function summaryLabel(summary: HarnessSetupSummary, projects: ProjectIdentity[]) {
  const project = summary.targetScopes.find(scope => scope.scope === 'project');
  const projectName = project?.scope === 'project' ? projects.find(item => item.projectId === project.projectId)?.name ?? 'saved project' : 'all projects';
  return `${harnessNames[summary.harness]}${summary.harnessProfile ? ` (${summary.harnessProfile})` : ''} for ${projectName}`;
}

function setupStateText(state: HarnessSetupState) {
  const names: Record<HarnessSetupState, string> = {
    previewed: 'Saved review — settings have not been saved.', applying: 'Save interrupted — review before resuming.',
    applied: 'Settings saved', apply_restored: 'Save failed; previous settings were restored.',
    rolling_back: 'Undo interrupted — review before resuming.', rolled_back: 'Setup changes undone',
    rollback_restored: 'Undo failed; the attempted Undo was restored.', conflict: 'Settings changed — this setup needs review.',
    expired: 'This review expired. Select Review setup to create a new review.',
  };
  return names[state];
}

function outcomeText(action: 'apply' | 'rollback', state: HarnessSetupState, failed: boolean) {
  if (failed) return `${action === 'apply' ? 'Save' : 'Undo'} reported a problem. ${setupStateText(state)} `;
  if (action === 'apply' && state === 'applied') return 'Settings saved:';
  if (action === 'rollback' && state === 'rolled_back') return 'Setup changes undone:';
  return `${action === 'apply' ? 'Save' : 'Undo'} was not confirmed. ${setupStateText(state)} `;
}

function SavedHookApprovals({ approval }: { approval: SavedMemoryHookApproval }) {
  const labels: Record<SavedHookApproval, string> = {
    missing: 'Not saved', needs_approval: 'Needs your approval', approved: 'Approval saved',
    changed: 'Changed — review again', disabled: 'Disabled in saved settings',
  };
  return <section className="record-card connection-result" aria-label="Saved Codex hook approvals">
    <h3>Automatic context in Codex</h3>
    <dl>
      <dt>Allow Context Relay to load context when a session starts</dt><dd>{labels[approval.sessionStart]}</dd>
      <dt>Allow Context Relay to collect suggestions after a response</dt><dd>{labels[approval.stop]}</dd>
    </dl>
    <p>Loading context brings useful saved notes into a new session. Collected suggestions wait for your review before becoming saved context. Test a note to verify the connection.</p>
    <p className="help-text">This checks the user settings for the selected Codex installation. Select Review setup to refresh.</p>
  </section>;
}

function SetupNextSteps({ item, guided = false }: { item: ReviewedPlan; guided?: boolean }) {
  if (guided) return <section aria-label={`Finish setup for ${label(item)}`}>
    <h4>Test saved context next</h4>
    <p>Choose Continue to save a test note, select a harness, and ask it to read the note. The next screen has the launch command and the exact prompt to send.</p>
    <p>Settings are saved, but the connection has not been verified yet.</p>
    <details><summary>Automatic context and harness approvals</summary><SetupNextSteps item={item} /></details>
  </section>;
  return <section aria-label={`Finish setup for ${label(item)}`}>
    <h4>Connection has not been verified</h4>
    {item.params.harness === 'codex' ? <>
      <p>Allow Context Relay to load context when a session starts, so you do not have to repeat project facts. Codex asks you to approve these automatic actions.</p>
      <ol>
        <li>Open the Codex CLI in the folder for {item.projectName}.</li>
        <li>Enter <code>/hooks</code>. Review the Context Relay commands for <code>SessionStart</code> and <code>Stop</code>, then trust each command you approve.</li>
        <li>Start a new Codex session in that project.</li>
      </ol>
      <p>If these hooks are already trusted, you can start a new session. New or changed commands need review again.</p>
    </> : <p>Start a new {harnessNames[item.params.harness]} session for {item.projectName} to load the saved settings.</p>}
  </section>;
}

function blockedSetupGuidance(harness: HarnessId, report: ProbeReport): string {
  if (harness === 'codex' && report.policyConflicts.includes('project_untrusted') && !report.policyConflicts.includes('managed_requirements_active')) {
    return 'Codex needs your approval for this project folder. Open the project folder in the Codex CLI and review its trust prompt. Then return here and select Review setup again.';
  }
  return 'Local policy prevents automatic setup. Check the restrictions configured for this harness before trying again.';
}

function setupError(error: unknown, harness: HarnessId) {
  if (isServiceVersionMismatch(error)) return SERVICE_UPDATE_GUIDANCE;
  // Map only known daemon errors to fixed guidance. Never display raw native output.
  if (error && typeof error === 'object' && 'code' in error && 'message' in error && error.code === 'not_found') {
    if (harness === 'claude_code' && error.message === 'Claude Code executable was not found') {
      return 'The Claude Code command-line executable was not found. Install the native Claude Code CLI and restart Context Relay, then select Review setup again.';
    }
    if (harness === 'hermes' && error.message === 'Hermes profile was not found') {
      return 'That Hermes profile was not found. Enter the name of an existing profile, or use default for your main Hermes profile.';
    }
    if (harness === 'hermes' && error.message === 'Hermes default profile was not found') {
      return 'The Hermes home folder is unavailable. Open Hermes to check its setup, then select Review setup again. The profile field takes a name such as default, not the home folder path.';
    }
    if (harness === 'hermes' && error.message === 'Hermes executable was not found') {
      return 'The Hermes command-line executable was not found. Check your Hermes installation and restart Context Relay, then select Review setup again.';
    }
  }
  return 'Could not review this setup. Try again. If it still fails, restart Context Relay and make sure the project folder is available.';
}

function label(item: ReviewedPlan) {
  return `${harnessNames[item.plan.harness]}${item.plan.harnessProfile ? ` (${item.plan.harnessProfile})` : ''} for ${item.projectName}`;
}

function nativeText(value: WireNativeValue) {
  return value.display || `${value.platform} bytes (base64url): ${value.bytes}`;
}

function expiryText(value: string) {
  const milliseconds = Number(value);
  return milliseconds <= 8_640_000_000_000_000
    ? new Date(milliseconds).toLocaleString()
    : `${value} milliseconds since Unix epoch`;
}

function describeChange(change: SetupPlan['semanticChanges'][number], harness: HarnessId) {
  const name = harnessNames[harness];
  const action = { create: 'Add', update: 'Update', remove: 'Remove', enable: 'Enable', disable: 'Disable', preserve: 'Keep', conflict: 'Review a conflict in' }[change.class];
  if (/^(codex-mcp\||claude-mcp:|hermes-config\|)/.test(change.target)) {
    return { label: `${name} connection`, description: `${action} the Context Relay connection that lets ${name} retrieve your saved context.` };
  }
  if (/^native-memory-(source|watch):/.test(change.target)) {
    return { label: `Existing ${name} memory`, description: 'Register existing memory so Context Relay can track it. The existing memory files stay in place.' };
  }
  if (change.summary === 'Add instructions for using saved context') {
    return { label: 'Project instructions', description: `Add guidance that tells ${name} how to use your saved Context Relay notes.` };
  }
  if (change.summary === 'Add session hooks for saved context') {
    return { label: 'Session hooks', description: 'Set up automatic session actions for saved context. Your harness may ask you to approve these actions.' };
  }
  if (change.summary === "Turn off the harness's built-in memory" || change.summary === 'Connect the harness and turn off its built-in memory') {
    return { label: `${name} settings`, description: `Turn off ${name}’s built-in memory so Context Relay manages saved context instead. Existing memory files are kept.${change.summary.startsWith('Connect') ? ' Also connect the harness to Context Relay.' : ''}` };
  }
  if (change.summary === 'Export reviewed Context Relay memory to Hermes') {
    return { label: 'Hermes memory', description: 'Copy the reviewed Context Relay memory into Hermes.' };
  }
  return { label: `${name} settings`, description: `${action} the selected harness settings. The exact changes are listed in Technical verification details.` };
}

function PlanDetails({ plan, projectName }: { plan: SetupPlan; projectName: string }) {
  return <div className="connection-plan">
    <section>
    <h3>Where changes apply</h3>
    <ul>{plan.targetScopes.map((scope, index) => <li key={index}>{scope.scope === 'global' ? 'Harness settings for this user account' : `Project: ${projectName}`}</li>)}</ul>
    </section>
    <section>
    <h3>What will change</h3>
    {plan.semanticChanges.length ? <ul>{plan.semanticChanges.map((change, index) => {
      const description = describeChange(change, plan.harness);
      return <li key={index}><strong>{description.label}</strong><p>{description.description}</p></li>;
    })}</ul> : <p>No configuration changes.</p>}
    </section>
    <Delta title="Permission changes" added={plan.permissionDelta.added} removed={plan.permissionDelta.removed} />
    <Delta title="Network changes" added={plan.networkDelta.added.map((endpoint) => `${endpoint.scheme}://${endpoint.host}:${endpoint.port}`)} removed={plan.networkDelta.removed.map((endpoint) => `${endpoint.scheme}://${endpoint.host}:${endpoint.port}`)} />
    {plan.packageArtifacts.length ? <p><strong>Packages to install:</strong> {plan.packageArtifacts.length}. Review their exact files and sources in Technical verification details.</p> : <p>No packages to install.</p>}
    <details className="technical-details">
    <summary>Technical verification details</summary>
    <h3>Exact changes and targets</h3>
    <ul>{plan.targetScopes.map((scope, index) => <li key={index}>{scope.scope === 'global' ? 'Global user settings' : nativeText(scope.root)}</li>)}</ul>
    <ul>{plan.semanticChanges.map((change, index) => <li key={index}><strong>{change.class}: {change.target}</strong><p>{change.summary}</p></li>)}</ul>
    {plan.packageArtifacts.length ? <section><h3>Packages to install</h3><ul>{plan.packageArtifacts.map((artifact, index) => <li key={index}>
      <p>{nativeText(artifact.artifactPath)}</p><p>Source: {artifact.immutableSourceRef}</p><p>Commit: {artifact.resolvedCommit}</p>
      {artifact.dependencies.length > 0 && <ul>{artifact.dependencies.map((dependency, childIndex) => <li key={childIndex}>{dependency.name} {dependency.version} — {dependency.immutableSourceRef}</li>)}</ul>}
    </li>)}</ul></section> : <p>No packages to install.</p>}
    <p>Executable: {nativeText(plan.executablePath)}</p>
    <p>Version: {plan.harnessVersion}</p>
    <p>Review level: {plan.approvalClass}</p>
    <p>Expires: {expiryText(plan.expiresAt)}</p>
    {plan.expectedNativeDigests.length > 0 && <ul>{plan.expectedNativeDigests.map((item, index) => <li key={index}>{nativeText(item.target)} — {item.expectedDigest === null ? 'Must not exist' : 'Existing content must match its reviewed digest'}</li>)}</ul>}
    <h3>Commands to run</h3>
    {plan.cliOperations.length ? <ol>{plan.cliOperations.map((operation, index) => <li key={index}>
      <p>{nativeText(operation.executable)}</p>
      <ol aria-label="Arguments">{operation.arguments.map((argument, argumentIndex) => <li key={argumentIndex}>{nativeText(argument)}</li>)}</ol>
      <p>Timeout: {operation.timeoutMs} ms</p>
    </li>)}</ol> : <p>No Commands to run.</p>}
      <pre style={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify(plan, null, 2)}</pre>
    </details>
  </div>;
}

function Delta({ title, added, removed }: { title: string; added: string[]; removed: string[] }) {
  if (!added.length && !removed.length) return <p><strong>{title}:</strong> None.</p>;
  return <section><h3>{title}</h3>{added.length > 0 && <><p>Added</p><ul>{added.map((value, index) => <li key={index}>{value}</li>)}</ul></>}
    {removed.length > 0 && <><p>Removed</p><ul>{removed.map((value, index) => <li key={index}>{value}</li>)}</ul></>}</section>;
}


function includeObservedSetup(records: HarnessSetupSummary[], setup?: HarnessSetupRecord): HarnessSetupSummary[] {
  if (!setup) return records;
  const { plan } = setup;
  const summary: HarnessSetupSummary = {
    planId: plan.planId, harness: plan.harness, harnessProfile: plan.harnessProfile,
    targetScopes: plan.targetScopes.map(scope => scope.scope === 'global'
      ? { scope: 'global' } : { scope: 'project', projectId: scope.projectId }),
    state: setup.state, createdAt: setup.createdAt, expiresAt: plan.expiresAt,
  };
  // A successful per-plan read is useful even when the first history page is
  // empty, filtered, or unavailable. Undo still re-reads this exact saved plan.
  return [summary, ...records.filter(record => record.planId !== summary.planId)]
    .sort((a, b) => b.planId.localeCompare(a.planId));
}
