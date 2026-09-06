import { useEffect, useRef, useState } from 'react';
import type { HarnessId, HarnessParams, PlanId, ProbeReport, ProjectIdentity, SavedHookApproval, SavedMemoryHookApproval, SetupPlan, WireNativeValue } from './bindings';
import { type HarnessGateway, validateHarnessPlan, validateHarnessProbe } from './harness-gateway';

const harnessNames: Record<HarnessId, string> = { claude_code: 'Claude Code', codex: 'Codex', hermes: 'Hermes' };
type ReviewedPlan = { plan: SetupPlan; params: HarnessParams; projectName: string };
type AppliedPlan = ReviewedPlan & { setupNumber: number; savedAt: number };
type BusyAction = 'preview' | 'apply' | 'rollback' | null;

export function HarnessesScreen({ gateway, projects, preferredProjectId, onProjectChange, onAddProject, onSaveContext, active = true }: { gateway: HarnessGateway; projects: ProjectIdentity[]; preferredProjectId?: string; onProjectChange?: (id: string) => void; onAddProject?: () => void; onSaveContext?: () => void; active?: boolean }) {
  const [selectedProjectId, setProjectId] = useState<string | null>(null);
  const projectId = preferredProjectId ?? selectedProjectId ?? projects[0]?.projectId ?? '';
  const [harness, setHarness] = useState<HarnessId>('codex');
  const [profile, setProfile] = useState('default');
  const canonicalProfile = profile.trim().replace(/[A-Z]/g, (letter) => letter.toLowerCase());
  const validProfile = /^[a-z0-9][a-z0-9_-]{0,63}$/.test(canonicalProfile);
  const [review, setReview] = useState<ReviewedPlan | null>(null);
  const [discovery, setDiscovery] = useState<{ harness: HarnessId; report: ProbeReport } | null>(null);
  const [approved, setApproved] = useState(false);
  const [applied, setApplied] = useState<AppliedPlan[]>([]);
  const nextSetupNumber = useRef(1);
  const [rollbackTarget, setRollbackTarget] = useState<PlanId | null>(null);
  const [busy, setBusy] = useState<BusyAction>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [now, setNow] = useState(Date.now);
  const busyRef = useRef<BusyAction>(null);
  const generation = useRef(0);
  const mounted = useRef(false);
  const project = projects.find((item) => item.projectId === projectId);
  const expired = review !== null && BigInt(review.plan.expiresAt) <= BigInt(now);
  const conflicts = review?.plan.semanticChanges.some((change) => change.class === 'conflict') ?? false;
  const matching = review !== null && review.params.projectId === project?.projectId &&
    review.params.harness === harness && review.params.hermesProfile === (harness === 'hermes' ? canonicalProfile : null);
  const canApply = approved && matching && !expired && !conflicts && !busy;

  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; generation.current += 1; };
  }, []);

  useEffect(() => {
    if (active) return;
    generation.current += 1;
    setReview(null);
    setDiscovery(null);
    setApproved(false);
    setRollbackTarget(null);
  }, [active]);

  useEffect(() => {
    generation.current += 1;
    setReview(null);
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
    setReview(null);
    setDiscovery(null);
    setApproved(false);
    setError(null);
    setNotice(null);
    setRollbackTarget(null);
  }

  function start(action: Exclude<BusyAction, null>) {
    if (!active || busyRef.current) return false;
    busyRef.current = action;
    setBusy(action);
    setError(null);
    setNotice(null);
    return true;
  }

  function finish() {
    busyRef.current = null;
    if (mounted.current) setBusy(null);
  }

  async function previewSetup() {
    if (!project || (harness === 'hermes' && !validProfile) || !start('preview')) return;
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
    } catch (error) {
      if (mounted.current && revision === generation.current) {
        setError(setupError(error, params.harness));
      }
    } finally { finish(); }
  }

  async function applySetup() {
    if (!canApply || !review || BigInt(review.plan.expiresAt) <= BigInt(Date.now()) || !start('apply')) return;
    const approvedReview = review;
    setDiscovery(null);
    setApproved(false);
    setRollbackTarget(null);
    try {
      await gateway.harnessApply(approvedReview.plan.planId);
      if (!mounted.current) return;
      const saved = { ...approvedReview, setupNumber: nextSetupNumber.current++, savedAt: Date.now() };
      setApplied((items) => [...items.filter((item) => item.plan.planId !== approvedReview.plan.planId), saved]);
      setReview(null);
      // Apply acknowledges the configuration transaction, not a live harness session.
      setNotice(`Settings saved: ${label(approvedReview)}.`);
    } catch {
      if (mounted.current) {
        setReview(null);
        setError('Saving these settings could not be confirmed. Select Review setup to see the latest changes before retrying.');
      }
    } finally { finish(); }
  }

  async function rollbackSetup(item: ReviewedPlan) {
    if (rollbackTarget !== item.plan.planId || !start('rollback')) return;
    setDiscovery(null);
    setRollbackTarget(null);
    setApproved(false);
    try {
      await gateway.harnessRollback(item.plan.planId);
      if (!mounted.current) return;
      setApplied((items) => items.filter((current) => current.plan.planId !== item.plan.planId));
      setReview(null);
      setNotice(`Setup changes undone: ${label(item)}.`);
    } catch {
      if (mounted.current) setError('Undo could not be confirmed. Check the harness configuration before trying to undo these changes again.');
    } finally { finish(); }
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
        <h2>Connect a harness</h2>
        <p>Choose your project and harness to check compatibility and review the settings.</p>
        <div className="field">
          <label htmlFor="harness-project">Project</label>
          <select id="harness-project" value={projectId} disabled={busy === 'apply' || busy === 'rollback'} onChange={(event) => { clearReview(); if (onProjectChange) onProjectChange(event.target.value); else setProjectId(event.target.value); }}>
            <option value="">Choose your project</option>
            {projects.map((item) => <option key={item.projectId} value={item.projectId}>{item.name}</option>)}
          </select>
        </div>
        <div className="field">
          <label htmlFor="harness-kind">Harness</label>
          <select id="harness-kind" value={harness} disabled={busy === 'apply' || busy === 'rollback'} onChange={(event) => { clearReview(); setHarness(event.target.value as HarnessId); }}>
            {Object.entries(harnessNames).map(([id, name]) => <option key={id} value={id}>{name}</option>)}
          </select>
        </div>
        {harness === 'hermes' && <div className="field">
          <label htmlFor="hermes-profile">Hermes profile</label>
          <input id="hermes-profile" value={profile} maxLength={64} required aria-invalid={!validProfile} aria-describedby="hermes-profile-help" disabled={busy === 'apply' || busy === 'rollback'} onChange={(event) => { clearReview(); setProfile(event.target.value); }} />
          <p id="hermes-profile-help">Use a profile name, such as default or coder. Leave default selected unless you created another profile. Folder paths are not profile names.</p>
        </div>}
        <button className="primary-action" type="submit" disabled={!!busy || !project || (harness === 'hermes' && !validProfile)}>{busy === 'preview' ? 'Checking harness…' : 'Review setup'}</button>
      </form>
      {error && <p className="form-error" role="alert">{error}</p>}
      {notice && <p className="notice" role="status">{notice}</p>}
      {discovery && discovery.report.capability !== 'full' && <section className="connection-result" aria-label="Harness availability">
        <h2>{harnessNames[discovery.harness]}{discovery.report.harnessVersion && discovery.report.harnessVersion !== 'unknown' ? ` ${discovery.report.harnessVersion}` : ''}</h2>
        <p role="status">{discovery.report.capability === 'missing'
          ? `${harnessNames[discovery.harness]} was not found. Install it, restart Context Relay and select Review setup again.`
          : discovery.report.capability === 'blocked'
            ? 'Local policy prevents automatic setup. Check the restrictions configured for this harness before trying again.'
            : discovery.harness === 'hermes' && discovery.report.policyConflicts.includes('python_runtime_not_qualified')
              ? 'Hermes uses a Python runtime that Context Relay does not support for automatic connection yet. Your Hermes installation does not need to be reinstalled.'
            : discovery.harness === 'hermes' && discovery.report.harnessVersion === 'unknown'
              ? 'Hermes was found, but this launcher cannot connect automatically yet. Context Relay cannot verify its version and runtime. You can still save context and tasks while launcher support is completed.'
              : 'This version cannot connect automatically yet. You can still save context and tasks in Context Relay while support for this version is completed.'}</p>
        <p>The harness is not connected. No setup changes were made.</p>
        {onSaveContext && <button className="secondary-action" type="button" disabled={!!busy} onClick={onSaveContext}>Save context</button>}
        {discovery.report.executable && <details className="technical-details"><summary>Technical details</summary><p>Executable: {nativeText(discovery.report.executable)}</p>{discovery.harness === 'hermes' && discovery.report.policyConflicts.includes('python_runtime_not_qualified') && <p>Version read from installed package metadata. The Python runtime has not been executed or verified for connection.</p>}</details>}
      </section>}
      {discovery?.report.codexSavedHookApproval && <SavedHookApprovals approval={discovery.report.codexSavedHookApproval} />}
      {busy && <p role="status">{busy === 'preview' ? 'Checking the installed harness…' : busy === 'apply' ? 'Saving harness settings…' : 'Undoing setup changes…'}</p>}
      {review && <section className="record-card" aria-labelledby="harness-review-title">
        <h2 id="harness-review-title">Review setup changes</h2>
        <p>{label(review)}</p>
        <PlanDetails plan={review.plan} projectName={review.projectName} />
        {review.params.harness === 'codex' && <p>After saving, review the Context Relay session hooks in the Codex CLI. Codex requires approval before new or changed hooks can run.</p>}
        {expired && <p className="form-error">This setup review has expired. Select Review setup again.</p>}
        {conflicts && <p className="form-error">Resolve the conflicting settings shown above, then select Review setup again.</p>}
        {!matching && <p className="form-error">The project or harness changed. Select Review setup again.</p>}
        <label>
          <input type="checkbox" checked={approved} disabled={!!busy || expired || conflicts || !matching} onChange={(event) => setApproved(event.target.checked)} />
          I reviewed and approve these settings.
        </label>
        <button className="primary-action" type="button" disabled={!canApply} onClick={() => void applySetup()}>{busy === 'apply' ? 'Saving settings…' : 'Save settings'}</button>
      </section>}
      {applied.length > 0 && <section aria-label="Recent setup changes">
        <h2>Recent setup changes</h2>
        <ul className="record-list">{applied.map((item) => <li className="record-card" key={item.plan.planId}>
          <h3>{label(item)}</h3>
          <p className="help-text">Setup {item.setupNumber} · {new Date(item.savedAt).toLocaleString()} · Version {item.plan.harnessVersion}</p>
          <SetupNextSteps item={item} />
          <details className="connection-history-details"><summary>View saved changes</summary><PlanDetails plan={item.plan} projectName={item.projectName} /></details>
          <button className="secondary-action" type="button" disabled={!!busy} onClick={() => setRollbackTarget(item.plan.planId)}>Undo setup {item.setupNumber} for {label(item)}</button>
          {rollbackTarget === item.plan.planId && <div role="group" aria-label={`Confirm rollback of ${label(item)}`}>
            <p>Restore the configuration from before this setup? Context Relay will check for changes made since then.</p>
            <button type="button" className="primary-action" disabled={!!busy} onClick={() => void rollbackSetup(item)}>Undo setup changes</button>
            <button type="button" className="secondary-action" disabled={!!busy} onClick={() => setRollbackTarget(null)}>Keep settings</button>
          </div>}
        </li>)}</ul>
      </section>}
    </section>
  );
}

function SavedHookApprovals({ approval }: { approval: SavedMemoryHookApproval }) {
  const labels: Record<SavedHookApproval, string> = {
    missing: 'Not saved', needs_approval: 'Needs your approval', approved: 'Approval saved',
    changed: 'Changed — review again', disabled: 'Disabled in saved settings',
  };
  return <section className="record-card connection-result" aria-label="Saved Codex hook approvals">
    <h3>Saved Codex hook approvals</h3>
    <dl>
      <dt>Load context when a session starts</dt><dd>{labels[approval.sessionStart]}</dd>
      <dt>Collect context when a response finishes</dt><dd>{labels[approval.stop]}</dd>
    </dl>
    <p>These saved approvals do not confirm that hooks are enabled or that context is being shared.</p>
    <p className="help-text">This checks the user settings for the selected Codex installation. Select Review setup to refresh.</p>
  </section>;
}

function SetupNextSteps({ item }: { item: ReviewedPlan }) {
  return <section aria-label={`Finish setup for ${label(item)}`}>
    <h4>Connection has not been verified</h4>
    {item.params.harness === 'codex' ? <>
      <p>Codex needs your approval to run the session hooks that load and collect context.</p>
      <ol>
        <li>Open the Codex CLI in the folder for {item.projectName}.</li>
        <li>Enter <code>/hooks</code>. Review the Context Relay commands for <code>SessionStart</code> and <code>Stop</code>, then trust each command you approve.</li>
        <li>Start a new Codex session in that project.</li>
      </ol>
      <p>If these hooks are already trusted, you can start a new session. New or changed commands need review again.</p>
    </> : <p>Start a new {harnessNames[item.params.harness]} session for {item.projectName} to load the saved settings.</p>}
  </section>;
}

function setupError(error: unknown, harness: HarnessId) {
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

function PlanDetails({ plan, projectName }: { plan: SetupPlan; projectName: string }) {
  return <div className="connection-plan">
    <section>
    <h3>Where changes apply</h3>
    <ul>{plan.targetScopes.map((scope, index) => <li key={index}>{scope.scope === 'global' ? 'Harness settings for this user account' : `${projectName}: ${nativeText(scope.root)}`}</li>)}</ul>
    </section>
    <section>
    <h3>Changes and targets</h3>
    {plan.semanticChanges.length ? <ul>{plan.semanticChanges.map((change, index) => <li key={index}><strong>{change.class}: {change.target}</strong><p>{change.summary}</p></li>)}</ul> : <p>No configuration changes.</p>}
    </section>
    <Delta title="Permission changes" added={plan.permissionDelta.added} removed={plan.permissionDelta.removed} />
    <Delta title="Network changes" added={plan.networkDelta.added.map((endpoint) => `${endpoint.scheme}://${endpoint.host}:${endpoint.port}`)} removed={plan.networkDelta.removed.map((endpoint) => `${endpoint.scheme}://${endpoint.host}:${endpoint.port}`)} />
    {plan.packageArtifacts.length ? <section><h3>Packages to install</h3><ul>{plan.packageArtifacts.map((artifact, index) => <li key={index}>
      <p>{nativeText(artifact.artifactPath)}</p><p>Source: {artifact.immutableSourceRef}</p><p>Commit: {artifact.resolvedCommit}</p>
      {artifact.dependencies.length > 0 && <ul>{artifact.dependencies.map((dependency, childIndex) => <li key={childIndex}>{dependency.name} {dependency.version} — {dependency.immutableSourceRef}</li>)}</ul>}
    </li>)}</ul></section> : <p>No packages to install.</p>}
    <details className="technical-details">
    <summary>Technical verification details</summary>
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
      <pre style={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify({ planId: plan.planId, adapterVersion: plan.adapterVersion, executablePath: plan.executablePath, executableHash: plan.executableHash, expectedNativeDigests: plan.expectedNativeDigests, scannerReportHash: plan.scannerReportHash, rulesyncVersion: plan.rulesyncVersion, rulesyncHash: plan.rulesyncHash, batchHash: plan.batchHash, packageArtifacts: plan.packageArtifacts }, null, 2)}</pre>
    </details>
  </div>;
}

function Delta({ title, added, removed }: { title: string; added: string[]; removed: string[] }) {
  if (!added.length && !removed.length) return <p><strong>{title}:</strong> None.</p>;
  return <section><h3>{title}</h3>{added.length > 0 && <><p>Added</p><ul>{added.map((value, index) => <li key={index}>{value}</li>)}</ul></>}
    {removed.length > 0 && <><p>Removed</p><ul>{removed.map((value, index) => <li key={index}>{value}</li>)}</ul></>}</section>;
}
