import { useEffect, useRef, useState, type ReactNode } from 'react';
import type { HarnessId, ProbeReport, ProjectIdentity } from './bindings';
import type { SetupProgress, SetupStep } from './desktop-preferences';
import { ProjectForm } from './project-form';
import type { WorkspaceGateway } from './workspace';
import { HARNESS_NAMES } from './harness-names';
import { projectHarnessSetups } from './harness-history';

const STEPS: { id: SetupStep; label: string }[] = [
  { id: 'harnesses', label: 'Choose harnesses' }, { id: 'project', label: 'Choose a project' },
  { id: 'connect', label: 'Connect harnesses' }, { id: 'test', label: 'Try saved context' },
  { id: 'tour', label: 'Explore your dashboard' },
];

interface Props {
  gateway: WorkspaceGateway;
  projects: ProjectIdentity[];
  progress: SetupProgress;
  onChange: (progress: SetupProgress) => void;
  onProjectSaved: (project: ProjectIdentity) => void;
  onFinishLater: () => void;
  onTour: () => void;
  onSkipTour?: () => void;
  onOpenGuide: (harness: HarnessId) => void;
  renderConnection: (project: ProjectIdentity, harness: HarnessId) => ReactNode;
  renderTest: (project: ProjectIdentity, harnesses: HarnessId[]) => ReactNode;
  testComplete?: boolean;
  operationBusy?: boolean;
}

export function SetupWizard({ gateway, projects, progress, onChange, onProjectSaved, onFinishLater, onTour, onSkipTour, onOpenGuide, renderConnection, renderTest, testComplete = false, operationBusy = false }: Props) {
  const [reports, setReports] = useState<Partial<Record<HarnessId, ProbeReport | 'failed'>>>({});
  const [refresh, setRefresh] = useState(0);
  const [projectBusy, setProjectBusy] = useState(false);
  const [activeHarness, setActiveHarness] = useState<HarnessId>('codex');
  const [setupStates, setSetupStates] = useState<Partial<Record<HarnessId, string>>>({});
  const heading = useRef<HTMLHeadingElement>(null);
  const index = STEPS.findIndex(step => step.id === progress.step);
  useEffect(() => {
    if (progress.step !== 'connect' || !progress.projectId || operationBusy) return;
    let active = true;
    const controller = new AbortController();
    setSetupStates({});
    void projectHarnessSetups(gateway, progress.projectId, controller.signal).then(records => {
      if (!active) return;
      const next: Partial<Record<HarnessId, string>> = {};
      for (const record of records) {
        if (record.harness === 'hermes' && record.harnessProfile !== progress.hermesProfile) continue;
        next[record.harness] = record.state === 'applied' ? 'Settings saved · test next' : record.state === 'previewed' ? 'Review ready · save next' : record.state === 'rolled_back' ? 'Setup undone' : 'Needs review';
      }
      setSetupStates(next);
    }).catch(() => { if (active) setSetupStates({}); });
    return () => { active = false; controller.abort(); };
  }, [gateway, progress.step, progress.projectId, progress.hermesProfile, operationBusy]);
  const project = projects.find(item => item.projectId === progress.projectId);
  const harness = progress.harnesses.includes(activeHarness) ? activeHarness : progress.harnesses[0];

  useEffect(() => { heading.current?.focus(); }, [progress.step]);
  useEffect(() => {
    if (progress.step !== 'harnesses') return;
    let canceled = false;
    setReports({});
    for (const id of Object.keys(HARNESS_NAMES) as HarnessId[]) {
      void gateway.harnessProbe({ harness: id, projectId: null, hermesProfile: id === 'hermes' ? 'default' : null })
        .then(report => { if (!canceled) setReports(current => ({ ...current, [id]: report })); })
        .catch(() => { if (!canceled) setReports(current => ({ ...current, [id]: 'failed' })); });
    }
    return () => { canceled = true; };
  }, [gateway, progress.step, refresh]);

  function update(patch: Partial<SetupProgress>) { onChange({ ...progress, ...patch, status: 'in_progress' }); }
  function step(id: SetupStep) { update({ step: id }); }
  const canContinue = !projectBusy && (progress.step === 'harnesses' ? progress.harnesses.length > 0
    : progress.step === 'project' || progress.step === 'connect' ? !!project && progress.harnesses.length > 0
      : progress.step === 'test' ? testComplete : true);

  return <div className="onboarding-shell">
    <aside className="onboarding-rail">
      <p className="brand-name">Context Relay</p>
      <p>Context that follows your work.</p>
      <ol aria-label="Setup progress">{STEPS.map((item, stepIndex) => <li key={item.id} aria-current={progress.step === item.id ? 'step' : undefined}>
        <span aria-hidden="true">{stepIndex + 1}</span><span>{item.label}</span>
      </li>)}</ol>
      <p className="help-text">You can finish later. Your choices will be here when you return.</p>
    </aside>
    <main className="onboarding-content">
      <header><p className="help-text">Step {index + 1} of {STEPS.length}</p><h1 ref={heading} tabIndex={-1}>{STEPS[index].label}</h1></header>
      {progress.step === 'harnesses' && <section aria-label="Harness selection">
        <p>A harness is the tool you work in, such as Codex, Claude Code or Hermes. Choose the ones you want to use with your saved context.</p>
        <div className="harness-choices">{(Object.keys(HARNESS_NAMES) as HarnessId[]).map(id => {
          const report = reports[id];
          const text = !report ? 'Checking installation…' : report === 'failed' ? 'Could not check installation'
            : report.capability === 'missing' ? 'Not installed' : report.capability === 'import_only' ? 'Needs setup review'
              : report.capability === 'blocked' ? 'Installed · approval or policy needs review' : 'Installed';
          return <div className="harness-choice" data-selected={progress.harnesses.includes(id)} key={id}>
            <label><input type="checkbox" checked={progress.harnesses.includes(id)} onChange={event => update({ harnesses: event.target.checked ? [...progress.harnesses, id] : progress.harnesses.filter(value => value !== id) })} />
              <strong>{HARNESS_NAMES[id]}</strong></label>
            <p role="status">{text}{report && report !== 'failed' && report.harnessVersion ? ` · ${report.harnessVersion}` : ''}</p>
            {report && report !== 'failed' && report.capability === 'import_only' && <p className="help-text">We will explain the available connection options before changing any settings.</p>}
            {(report === 'failed' || report?.capability === 'missing') && <button type="button" className="secondary-action" onClick={() => onOpenGuide(id)}>Installation guide for {HARNESS_NAMES[id]}</button>}
            {report && report !== 'failed' && report.executable && <details><summary>Advanced details</summary><p className="native-path">{report.executable.display ?? 'Installed executable detected'}</p></details>}
          </div>;
        })}</div>
        <button type="button" className="secondary-action" onClick={() => setRefresh(value => value + 1)}>Check again</button>
      </section>}
      {progress.step === 'project' && <section aria-label="Project selection">
        <p>A project is the folder you work in. Its saved context and tasks stay together, so your harness gets the right information.</p>
        {projects.length > 0 && <fieldset><legend>Use an existing project</legend>{projects.map(item => <label className="status-row" key={item.projectId}>
          <input type="radio" name="setup-project" checked={progress.projectId === item.projectId} onChange={() => update({ projectId: item.projectId, noteId: null, checkId: null })} />{item.name}
        </label>)}</fieldset>}
        <ProjectForm gateway={gateway} ready onBusy={setProjectBusy} onSaved={item => { onProjectSaved(item); update({ projectId: item.projectId, noteId: null, checkId: null }); }} />
      </section>}
      {(progress.step === 'connect' || progress.step === 'test') && (!project || !harness ? <section>
        <p>Choose a project to continue. Your previous selection may no longer be available.</p><button type="button" onClick={() => step(progress.harnesses.length ? 'project' : 'harnesses')}>Choose a project</button>
      </section> : progress.step === 'connect' ? <section>
        <p>Connect each harness to <strong>{project.name}</strong>. Review the changes before saving. Approvals in the harness may still be required afterward.</p>
        <div className="context-tabs" aria-label="Selected harnesses">{progress.harnesses.map(id => <button type="button" disabled={operationBusy} key={id} aria-pressed={harness === id} onClick={() => setActiveHarness(id)}><span>{HARNESS_NAMES[id]}</span><small>{setupStates[id] ?? 'Review setup'}</small></button>)}</div>
        {renderConnection(project, harness)}
      </section> : renderTest(project, progress.harnesses))}
      {progress.step === 'tour' && <section className="help-content">
        <h2>Your workspace is ready to explore</h2>
        <p>A short tour shows you where to change projects, save context, review suggestions, continue tasks and check your harnesses.</p>
        <button className="primary-action" type="button" onClick={onTour}>Show me the dashboard</button>
        {onSkipTour && <button className="secondary-action" type="button" onClick={onSkipTour}>Skip tour and open dashboard</button>}
        <p className="help-text">You can replay the tour from Help at any time.</p>
      </section>}
      <footer className="onboarding-footer">
        <button className="secondary-action" type="button" disabled={index === 0 || projectBusy || operationBusy} onClick={() => step(STEPS[index - 1].id)}>Back</button>
        <button className="secondary-action" type="button" disabled={projectBusy || operationBusy} onClick={onFinishLater}>Finish later</button>
        {index < STEPS.length - 1 && <button className="primary-action" type="button" disabled={!canContinue || operationBusy} onClick={() => step(STEPS[index + 1].id)}>Continue</button>}
      </footer>
    </main>
  </div>;
}
