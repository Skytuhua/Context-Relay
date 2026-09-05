import { useEffect, useRef, useState } from 'react';
import type { HarnessId, HarnessParams, PlanId, ProbeReport, ProjectIdentity, SetupPlan, WireNativeValue } from './bindings';
import { type HarnessGateway, validateHarnessPlan, validateHarnessProbe } from './harness-gateway';

const harnessNames: Record<HarnessId, string> = { claude_code: 'Claude Code', codex: 'Codex', hermes: 'Hermes' };
type ReviewedPlan = { plan: SetupPlan; params: HarnessParams; projectName: string };
type BusyAction = 'preview' | 'apply' | 'rollback' | null;

export function HarnessesScreen({ gateway, projects, preferredProjectId, onProjectChange, active = true }: { gateway: HarnessGateway; projects: ProjectIdentity[]; preferredProjectId?: string; onProjectChange?: (id: string) => void; active?: boolean }) {
  const [selectedProjectId, setProjectId] = useState<string | null>(null);
  const projectId = preferredProjectId ?? selectedProjectId ?? projects[0]?.projectId ?? '';
  const [harness, setHarness] = useState<HarnessId>('codex');
  const [profile, setProfile] = useState('');
  const canonicalProfile = profile.trim().replace(/[A-Z]/g, (letter) => letter.toLowerCase());
  const [review, setReview] = useState<ReviewedPlan | null>(null);
  const [discovery, setDiscovery] = useState<{ harness: HarnessId; report: ProbeReport } | null>(null);
  const [approved, setApproved] = useState(false);
  const [applied, setApplied] = useState<ReviewedPlan[]>([]);
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
    if (!project || (harness === 'hermes' && !profile.trim()) || !start('preview')) return;
    clearReview();
    const revision = generation.current;
    const params: HarnessParams = { harness, projectId: project.projectId, hermesProfile: harness === 'hermes' ? canonicalProfile : null };
    try {
      const report = validateHarnessProbe(await gateway.harnessProbe(params), params);
      if (!mounted.current || revision !== generation.current) return;
      if (report.capability !== 'full') {
        setDiscovery({ harness: params.harness, report: structuredClone(report) });
        return;
      }
      const result = validateHarnessPlan(await gateway.harnessPreview(params), params);
      if (!mounted.current || revision !== generation.current) return;
      setNow(Date.now());
      // Keep the reviewed contents and their selection together for apply and rollback.
      setReview({ plan: structuredClone(result), params, projectName: project.name });
    } catch {
      if (mounted.current && revision === generation.current) {
        setError('Setup preview could not be loaded. Check the local service, installed AI app and project folder, then request a new preview.');
      }
    } finally { finish(); }
  }

  async function applySetup() {
    if (!canApply || !review || BigInt(review.plan.expiresAt) <= BigInt(Date.now()) || !start('apply')) return;
    const approvedReview = review;
    setApproved(false);
    setRollbackTarget(null);
    try {
      await gateway.harnessApply(approvedReview.plan.planId);
      if (!mounted.current) return;
      setApplied((items) => [...items.filter((item) => item.plan.planId !== approvedReview.plan.planId), approvedReview]);
      setReview(null);
      setNotice(`Setup applied: ${label(approvedReview)}.`);
    } catch {
      if (mounted.current) {
        setReview(null);
        setError('Setup could not be confirmed. The local service may have rejected a changed or expired plan. Check the local service and request a fresh preview before trying again.');
      }
    } finally { finish(); }
  }

  async function rollbackSetup(item: ReviewedPlan) {
    if (rollbackTarget !== item.plan.planId || !start('rollback')) return;
    setRollbackTarget(null);
    setApproved(false);
    try {
      await gateway.harnessRollback(item.plan.planId);
      if (!mounted.current) return;
      setApplied((items) => items.filter((current) => current.plan.planId !== item.plan.planId));
      setReview(null);
      setNotice(`Rollback completed: ${label(item)}.`);
    } catch {
      if (mounted.current) setError('Rollback could not be confirmed. Check the local service and review the applied plan before confirming a retry.');
    } finally { finish(); }
  }

  return (
    <section className="screen-content" aria-label="AI app connection" style={{ overflowWrap: 'anywhere', minWidth: 0 }}>
      <form className="capture-form" aria-label="Check AI app connection" onSubmit={(event) => { event.preventDefault(); void previewSetup(); }}>
        <h2>Connect an AI app</h2>
        <p>Choose the app you use for this project. We will check its installed version and show any changes before you connect it.</p>
        {projects.length === 0 && <p>Add your project folder in Projects first, then return here to connect your AI app.</p>}
        <div className="field">
          <label htmlFor="harness-project">Project</label>
          <select id="harness-project" value={projectId} disabled={busy === 'apply' || busy === 'rollback'} onChange={(event) => { clearReview(); if (onProjectChange) onProjectChange(event.target.value); else setProjectId(event.target.value); }}>
            <option value="">Choose your project</option>
            {projects.map((item) => <option key={item.projectId} value={item.projectId}>{item.name}</option>)}
          </select>
        </div>
        <div className="field">
          <label htmlFor="harness-kind">AI app</label>
          <select id="harness-kind" value={harness} disabled={busy === 'apply' || busy === 'rollback'} onChange={(event) => { clearReview(); setHarness(event.target.value as HarnessId); }}>
            {Object.entries(harnessNames).map(([id, name]) => <option key={id} value={id}>{name}</option>)}
          </select>
        </div>
        {harness === 'hermes' && <div className="field">
          <label htmlFor="hermes-profile">Hermes profile</label>
          <input id="hermes-profile" value={profile} maxLength={512} required disabled={busy === 'apply' || busy === 'rollback'} onChange={(event) => { clearReview(); setProfile(event.target.value); }} />
        </div>}
        <button className="primary-action" type="submit" disabled={!!busy || !project || (harness === 'hermes' && !profile.trim())}>{busy === 'preview' ? 'Checking app…' : 'Check connection'}</button>
      </form>
      {error && <p className="form-error" role="alert">{error}</p>}
      {notice && <p className="notice" role="status">{notice}</p>}
      {discovery && <section className="record-card" aria-label="AI app availability">
        <h2>{harnessNames[discovery.harness]}{discovery.report.harnessVersion ? ` ${discovery.report.harnessVersion}` : ''}</h2>
        {discovery.report.executable && <p>Executable: {nativeText(discovery.report.executable)}</p>}
        <p role="status">{discovery.report.capability === 'missing'
          ? `${harnessNames[discovery.harness]} was not found. Install a supported version, restart Context Relay and request a new preview.`
          : discovery.report.capability === 'blocked'
            ? 'Local policy prevents automatic setup. Review the AI app policy before requesting a new preview.'
            : 'This version cannot connect automatically yet. You can still save context and tasks in Context Relay while support for this version is completed.'}</p>
        <p>The app is not connected. No setup changes were made.</p>
      </section>}
      {busy && <p role="status">{busy === 'preview' ? 'Checking the installed AI app…' : busy === 'apply' ? 'Applying the reviewed plan…' : 'Rolling back the confirmed plan…'}</p>}
      {review && <section className="record-card" aria-labelledby="harness-review-title">
        <h2 id="harness-review-title">Review connection changes</h2>
        <p>{label(review)}</p>
        <PlanDetails plan={review.plan} />
        {expired && <p className="form-error">This plan has expired. Request a new preview.</p>}
        {conflicts && <p className="form-error">Resolve conflicts before requesting a new preview. This plan cannot be applied.</p>}
        {!matching && <p className="form-error">The plan no longer matches the selection. Request a new preview.</p>}
        <label>
          <input type="checkbox" checked={approved} disabled={!!busy || expired || conflicts || !matching} onChange={(event) => setApproved(event.target.checked)} />
          I reviewed the targets, permissions, network changes and operations in this plan.
        </label>
        <button className="primary-action" type="button" disabled={!canApply} onClick={() => void applySetup()}>{busy === 'apply' ? 'Applying reviewed plan…' : 'Apply reviewed plan'}</button>
      </section>}
      {applied.length > 0 && <section aria-label="Applied setup plans">
        <h2>Applied setup plans</h2>
        <ul className="record-list">{applied.map((item) => <li className="record-card" key={item.plan.planId}>
          <h3>{label(item)}</h3>
          <p>Applied plan: {item.plan.planId}</p>
          <button className="secondary-action" type="button" disabled={!!busy} onClick={() => setRollbackTarget(item.plan.planId)}>Roll back {label(item)}</button>
          {rollbackTarget === item.plan.planId && <div role="group" aria-label={`Confirm rollback of ${label(item)}`}>
            <p>Roll back this applied plan? The local service checks whether the saved changes can be safely restored.</p>
            <button type="button" className="primary-action" disabled={!!busy} onClick={() => void rollbackSetup(item)}>Confirm rollback</button>
            <button type="button" className="secondary-action" disabled={!!busy} onClick={() => setRollbackTarget(null)}>Cancel rollback</button>
          </div>}
        </li>)}</ul>
      </section>}
    </section>
  );
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

function PlanDetails({ plan }: { plan: SetupPlan }) {
  return <>
    <p>Executable: {nativeText(plan.executablePath)}</p>
    <p>Version: {plan.harnessVersion}</p>
    <p>Review level: {plan.approvalClass}</p>
    <p>Expires: {expiryText(plan.expiresAt)}</p>
    <h3>Where changes apply</h3>
    <ul>{plan.targetScopes.map((scope, index) => <li key={index}>{scope.scope === 'global' ? 'Global' : `Project ${scope.projectId}: ${nativeText(scope.root)}`}</li>)}</ul>
    <h3>Changes and targets</h3>
    {plan.semanticChanges.length ? <ul>{plan.semanticChanges.map((change, index) => <li key={index}><strong>{change.class}: {change.target}</strong><p>{change.summary}</p></li>)}</ul> : <p>No configuration changes.</p>}
    {plan.expectedNativeDigests.length > 0 && <ul>{plan.expectedNativeDigests.map((item, index) => <li key={index}>{nativeText(item.target)} — {item.expectedDigest === null ? 'Must not exist' : 'Existing content must match its reviewed digest'}</li>)}</ul>}
    <h3>Permission changes</h3>
    <Delta added={plan.permissionDelta.added} removed={plan.permissionDelta.removed} />
    <h3>Network changes</h3>
    <Delta added={plan.networkDelta.added.map((endpoint) => `${endpoint.scheme}://${endpoint.host}:${endpoint.port}`)} removed={plan.networkDelta.removed.map((endpoint) => `${endpoint.scheme}://${endpoint.host}:${endpoint.port}`)} />
    <h3>Commands to run</h3>
    {plan.cliOperations.length ? <ol>{plan.cliOperations.map((operation, index) => <li key={index}>
      <p>{nativeText(operation.executable)}</p>
      <ol aria-label="Arguments">{operation.arguments.map((argument, argumentIndex) => <li key={argumentIndex}>{nativeText(argument)}</li>)}</ol>
      <p>Timeout: {operation.timeoutMs} ms</p>
    </li>)}</ol> : <p>No Commands to run.</p>}
    <h3>Packages to install</h3>
    {plan.packageArtifacts.length ? <ul>{plan.packageArtifacts.map((artifact, index) => <li key={index}>
      <p>{nativeText(artifact.artifactPath)}</p><p>Source: {artifact.immutableSourceRef}</p><p>Commit: {artifact.resolvedCommit}</p>
      {artifact.dependencies.length > 0 && <ul>{artifact.dependencies.map((dependency, childIndex) => <li key={childIndex}>{dependency.name} {dependency.version} — {dependency.immutableSourceRef}</li>)}</ul>}
    </li>)}</ul> : <p>No packages to install.</p>}
    <details>
      <summary>Technical verification details</summary>
      <pre style={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify({ planId: plan.planId, adapterVersion: plan.adapterVersion, executablePath: plan.executablePath, executableHash: plan.executableHash, expectedNativeDigests: plan.expectedNativeDigests, scannerReportHash: plan.scannerReportHash, rulesyncVersion: plan.rulesyncVersion, rulesyncHash: plan.rulesyncHash, batchHash: plan.batchHash, packageArtifacts: plan.packageArtifacts }, null, 2)}</pre>
    </details>
  </>;
}

function Delta({ added, removed }: { added: string[]; removed: string[] }) {
  if (!added.length && !removed.length) return <p>No changes.</p>;
  return <>{added.length > 0 && <><p>Added</p><ul>{added.map((value, index) => <li key={index}>{value}</li>)}</ul></>}
    {removed.length > 0 && <><p>Removed</p><ul>{removed.map((value, index) => <li key={index}>{value}</li>)}</ul></>}</>;
}
