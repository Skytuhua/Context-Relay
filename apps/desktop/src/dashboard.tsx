import { useCallback, useEffect, useState, type ReactNode } from 'react';
import type { HarnessSetupState, MemoryRecord, TaskRecord, ProjectIdentity } from './bindings';
import type { WorkspaceGateway } from './workspace';
import type { VerifiedRead } from './desktop-preferences';
import { projectHarnessSetups } from './harness-history';

type DashboardProps = {
  gateway: WorkspaceGateway;
  project: ProjectIdentity | null;
  setupDeferred: boolean;
  onResumeSetup: () => void;
  onNavigate: (screen: 'projects' | 'memory' | 'review' | 'tasks' | 'harnesses') => void;
  onAddContext?: () => void;
  onNewTask?: () => void;
  onOpenContext?: (note: MemoryRecord) => void;
  onOpenTask?: (task: TaskRecord) => void;
  lastVerifiedRead?: VerifiedRead | null;
};

type Load<T> = { state: 'loading' } | { state: 'failed' } | { state: 'ready'; value: T };

function useSection<T>(read: (signal: AbortSignal) => Promise<T>) {
  const [result, setResult] = useState<Load<T>>({ state: 'loading' });
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    setResult({ state: 'loading' });
    void Promise.resolve().then(() => read(controller.signal)).then(
      value => { if (active) setResult({ state: 'ready', value }); },
      () => { if (active) setResult({ state: 'failed' }); },
    );
    return () => { active = false; controller.abort(); };
  }, [read, attempt]);
  return { result, retry: () => setAttempt(value => value + 1) };
}

function Section<T>({ title, description, action, load, children }: {
  title: string; description: string; action: ReactNode;
  load: ReturnType<typeof useSection<T>>; children: (value: T) => ReactNode;
}) {
  return <section className="dashboard-section" aria-label={title}>
    <header><h2>{title}</h2>{action}</header>
    <p className="muted">{description}</p>
    {load.result.state === 'loading' && <p role="status">Loading {title.toLowerCase()}…</p>}
    {load.result.state === 'failed' && <div role="alert">
      <p>{title} could not be loaded. Check that Context Relay is running, then retry.</p>
      <button onClick={load.retry}>Retry {title.toLowerCase()}</button>
    </div>}
    {load.result.state === 'ready' && children(load.result.value)}
  </section>;
}

const harnessNames = { codex: 'Codex', claude_code: 'Claude Code', hermes: 'Hermes' };
const setupStates: Record<HarnessSetupState, { label: string; next: string }> = {
  previewed: { label: 'Review needed', next: 'Review the proposed changes in Harnesses before saving.' },
  applying: { label: 'Saving settings', next: 'Open Harnesses to check progress or recovery options.' },
  applied: { label: 'Settings saved', next: 'Open Harnesses to review saved settings and any approvals for automatic session actions. Reading a test note does not approve those actions.' },
  apply_restored: { label: 'Settings restored', next: 'Open Harnesses to review why saving did not finish and retry.' },
  rolling_back: { label: 'Undo in progress', next: 'Open Harnesses to check Undo progress.' },
  rolled_back: { label: 'Setup undone', next: 'Open Harnesses when you are ready to set it up again.' },
  rollback_restored: { label: 'Undo did not finish', next: 'Open Harnesses to review the recovery options.' },
  conflict: { label: 'Changes need attention', next: 'Open Harnesses to review the conflict before trying again.' },
  expired: { label: 'Preview expired', next: 'Open Harnesses to prepare a fresh preview.' },
};

function ProjectDashboard({ gateway, project, onNavigate, onAddContext, onNewTask, onOpenContext, onOpenTask }: Omit<DashboardProps, 'setupDeferred' | 'onResumeSetup'> & { project: ProjectIdentity }) {
  const projectId = project.projectId;
  const notes = useSection(useCallback(() => gateway.memories(projectId), [gateway, projectId]));
  const tasks = useSection(useCallback(() => gateway.tasks(projectId), [gateway, projectId]));
  const suggestions = useSection(useCallback(() => gateway.candidates(projectId), [gateway, projectId]));
  const setups = useSection(useCallback((signal: AbortSignal) => projectHarnessSetups(gateway, projectId, signal), [gateway, projectId]));
  return <div className="dashboard-grid">
    <Section title="Saved context" description="Notes your harness can use so you do not have to explain the same details again."
      action={<button onClick={onAddContext ?? (() => onNavigate('memory'))}>Add context</button>} load={notes}>
      {records => {
        const recent = records.filter(record => !record.archived).sort((a, b) => {
          const aTime = BigInt(a.updatedHlc.physicalMs), bTime = BigInt(b.updatedHlc.physicalMs);
          return aTime === bTime ? b.updatedHlc.logical - a.updatedHlc.logical : aTime > bTime ? -1 : 1;
        }).slice(0, 4);
        return recent.length ? <ul>{recent.map(note => <li key={note.id}><button className="record-button" onClick={() => onOpenContext ? onOpenContext(note) : onNavigate('memory')}>{note.title}</button></li>)}</ul>
          : <p>No saved context yet.</p>;
      }}
    </Section>
    <Section title="Tasks to continue" description="Keep the next step and progress together when you return to a project."
      action={<button onClick={onNewTask ?? (() => onNavigate('tasks'))}>New task</button>} load={tasks}>
      {records => {
        const active = records.filter(task => task.status !== 'done' && task.status !== 'canceled').sort((a, b) => b.revision.localeCompare(a.revision)).slice(0, 4);
        return active.length ? <ul>{active.map(task => <li key={task.id} className="status-row"><button className="record-button" onClick={() => onOpenTask ? onOpenTask(task) : onNavigate('tasks')}>{task.title}</button><span className="status-label">{{ open: 'Open', in_progress: 'In progress', blocked: 'Blocked', done: 'Done', canceled: 'Canceled' }[task.status]}</span></li>)}</ul>
          : <p>No tasks to continue.</p>;
      }}
    </Section>
    <Section title="Suggestions" description="Review context proposed by a harness. You decide what becomes saved context."
      action={<button onClick={() => onNavigate('review')}>Review suggestions</button>} load={suggestions}>
      {records => {
        const pending = records.filter(record => record.state === 'pending').slice(0, 4);
        return pending.length ? <ul>{pending.map(candidate => <li key={candidate.id}><button className="record-button" onClick={() => onNavigate('review')}>{candidate.proposedMemory.title}</button></li>)}</ul>
          : <p>No suggestions waiting for review. Continue working in your harness; review proposed notes here when they arrive.</p>;
      }}
    </Section>
    <Section title="Harness setup" description="A harness is the coding assistant you work in, such as Codex, Claude Code, or Hermes."
      action={<button onClick={() => onNavigate('harnesses')}>Open Harnesses</button>} load={setups}>
      {records => records.length ? <ul>{records.map(setup => <li key={setup.planId} className="status-row"><div>
        <strong>{harnessNames[setup.harness]}{setup.harnessProfile ? ` · ${setup.harnessProfile}` : ''}</strong>
        <p>{setupStates[setup.state].next}</p>
      </div><span className="status-label">{setupStates[setup.state].label}</span></li>)}</ul>
        : <p>No setup history for this project. Open Harnesses to connect your coding assistant.</p>}
    </Section>
  </div>;
}

export function Dashboard(props: DashboardProps) {
  return <div data-tour-target="dashboard">
    <p>{props.project ? `Continue work in ${props.project.name}.` : 'Choose a project to see its context, tasks, and harness setup.'}</p>
    {props.lastVerifiedRead?.projectId === props.project?.projectId && props.lastVerifiedRead && <p className="help-text">Last successful context read: {harnessNames[props.lastVerifiedRead.harness]} · {new Date(Number(props.lastVerifiedRead.verifiedAt)).toLocaleString()}. This is a past test result; use setup to check again.</p>}
    {props.setupDeferred && <section className="status-row" aria-label="Setup progress"><div><strong>Finish connecting your harness</strong><p>Your setup progress is saved. Continue from where you left off.</p></div><button className="primary" onClick={props.onResumeSetup}>Resume setup</button></section>}
    {props.project ? <ProjectDashboard key={props.project.projectId} {...props} project={props.project} />
      : <button className="primary" onClick={() => props.onNavigate('projects')}>Choose a project</button>}
  </div>;
}
