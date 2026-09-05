import { type FormEvent, useEffect, useRef, useState } from 'react';

import type {
  MemoryCandidate,
  MemoryRecord,
  ProjectIdentity,
  StatusOutput,
  TaskRecord,
  TaskStatus,
} from './bindings';
import { DevicesScreen } from './devices';
import { HarnessesScreen } from './harnesses';
import { LocalWorkspaceGateway, type WorkspaceGateway } from './workspace';

type ScreenId =
  | 'home'
  | 'projects'
  | 'memory'
  | 'review'
  | 'tasks'
  | 'harnesses'
  | 'packages'
  | 'activity'
  | 'devices'
  | 'settings';

const SCREENS: ReadonlyArray<{ id: ScreenId; label: string; summary: string }> = [
  { id: 'home', label: 'Home', summary: 'See the state of this encrypted local workspace.' },
  { id: 'projects', label: 'Projects', summary: 'Bind trusted repositories to local context.' },
  { id: 'memory', label: 'Memory', summary: 'Capture and search durable context.' },
  { id: 'review', label: 'Review queue', summary: 'Approve or reject proposed memories.' },
  { id: 'tasks', label: 'Tasks', summary: 'Track work with durable evidence.' },
  { id: 'harnesses', label: 'Harnesses', summary: 'Inspect supported local AI harnesses.' },
  { id: 'packages', label: 'Packages', summary: 'Review portable Context Relay packages.' },
  { id: 'activity', label: 'Activity', summary: 'Audit local workspace outcomes.' },
  { id: 'devices', label: 'Devices', summary: 'Review trusted local devices.' },
  { id: 'settings', label: 'Settings', summary: 'Review local security settings.' },
];

const DEFAULT_GATEWAY = new LocalWorkspaceGateway();
const STARTUP_TIMEOUT_MS = 45_000;

export default function App({ gateway = DEFAULT_GATEWAY }: { gateway?: WorkspaceGateway }) {
  const [activeScreen, setActiveScreen] = useState<ScreenId>('home');
  const [status, setStatus] = useState<StatusOutput | null>(null);
  const [connectionState, setConnectionState] = useState<'connecting' | 'ready' | 'failed'>('connecting');
  const [connectionAttempt, setConnectionAttempt] = useState(0);
  const [projects, setProjects] = useState<ProjectIdentity[]>([]);
  const [activeProject, setActiveProject] = useState<ProjectIdentity | null>(null);
  const [memories, setMemories] = useState<MemoryRecord[]>([]);
  const [candidates, setCandidates] = useState<MemoryCandidate[]>([]);
  const [tasks, setTasks] = useState<TaskRecord[]>([]);
  const [editingMemory, setEditingMemory] = useState<MemoryRecord | null>(null);
  const [editingTask, setEditingTask] = useState<TaskRecord | null>(null);
  const [archiveTarget, setArchiveTarget] = useState<MemoryRecord | null>(null);
  const [evidence, setEvidence] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const hasNavigatedRef = useRef(false);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const dialogRef = useRef<HTMLDialogElement>(null);
  const dialogTriggerRef = useRef<HTMLButtonElement>(null);
  const archiveDialogRef = useRef<HTMLDialogElement>(null);
  const archiveTriggerRef = useRef<HTMLButtonElement>(null);
  const currentScreen = SCREENS.find((screen) => screen.id === activeScreen);

  useEffect(() => {
    let active = true;
    setConnectionState('connecting');
    // Bound the initial reads even if the native bridge never settles. Retrying
    // these reads must not replay any workspace mutation or accept stale results.
    const timeout = window.setTimeout(() => {
      active = false;
      setConnectionState('failed');
    }, STARTUP_TIMEOUT_MS);
    void Promise.all([gateway.status(), gateway.projects()])
      .then(([nextStatus, nextProjects]) => {
        if (!active) return;
        window.clearTimeout(timeout);
        setStatus(nextStatus);
        setProjects(nextProjects);
        setActiveProject((current) => nextProjects.find((project) => project.projectId === current?.projectId) ?? nextProjects[0] ?? null);
        setConnectionState('ready');
      })
      .catch(() => {
        if (!active) return;
        window.clearTimeout(timeout);
        setConnectionState('failed');
      });
    return () => {
      active = false;
      window.clearTimeout(timeout);
    };
  }, [gateway, connectionAttempt]);

  useEffect(() => {
    if (hasNavigatedRef.current) headingRef.current?.focus();
  }, [activeScreen]);

  if (!currentScreen) return null;

  async function selectScreen(screen: ScreenId) {
    hasNavigatedRef.current = true;
    setActiveScreen(screen);
    setError(null);
    setNotice(null);
    try {
      if (screen === 'memory') {
        setMemories(await gateway.memories(activeProject?.projectId ?? null));
      } else if (screen === 'review') {
        setCandidates(await gateway.candidates(activeProject?.projectId ?? null));
      } else if (screen === 'tasks' && activeProject) {
        setTasks(await gateway.tasks(activeProject.projectId));
      }
    } catch {
      setError('The local service is unavailable.');
    }
  }

  async function submitProject(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const name = String(data.get('name') ?? '').trim();
    const path = String(data.get('path') ?? '').trim();
    if (!name || !path) return setError('Enter a project name and local path.');
    try {
      const project = await gateway.createProject(name, path);
      setProjects((current) => [...current.filter((item) => item.projectId !== project.projectId), project]);
      setActiveProject(project);
      setNotice('Project added');
      setError(null);
      form.reset();
    } catch {
      setError('The project could not be saved.');
    }
  }

  async function submitMemory(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const title = String(data.get('title') ?? '').trim();
    const body = String(data.get('body') ?? '').trim();
    if (!title) return setError('Enter a title.');
    if (!body) return setError('Enter memory text.');
    try {
      const memory = await gateway.createMemory(activeProject?.projectId ?? null, title, body);
      setMemories((current) => [memory, ...current]);
      setNotice('Memory saved');
      setError(null);
      form.reset();
    } catch {
      setError('The memory could not be saved.');
    }
  }

  async function submitMemoryEdit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!editingMemory) return;
    const data = new FormData(event.currentTarget);
    const title = String(data.get('title') ?? '').trim();
    const body = String(data.get('body') ?? '').trim();
    if (!title || !body) return setError('Enter a title and memory text.');
    try {
      const memory = await gateway.updateMemory(editingMemory, title, body);
      setMemories((current) => replaceRecord(current, memory));
      setEditingMemory(null);
      setNotice('Memory updated');
      setError(null);
    } catch {
      setError('The memory changed before it could be updated.');
    }
  }

  async function archiveMemory(memory: MemoryRecord) {
    try {
      await gateway.archiveMemory(memory);
      setMemories((current) => current.filter((item) => item.id !== memory.id));
      setNotice('Memory archived');
    } catch {
      setError('The memory changed before it could be archived.');
    }
  }

  function openArchive(memory: MemoryRecord, trigger: HTMLButtonElement) {
    setArchiveTarget(memory);
    archiveTriggerRef.current = trigger;
    queueMicrotask(() => archiveDialogRef.current?.showModal());
  }

  async function searchMemory(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const query = String(new FormData(event.currentTarget).get('query') ?? '').trim();
    if (!query) return setMemories(await gateway.memories(activeProject?.projectId ?? null));
    try {
      setMemories(await gateway.searchMemories(query, activeProject?.projectId ?? null));
      setError(null);
    } catch {
      setError('Memory search failed.');
    }
  }

  async function review(candidate: MemoryCandidate, accepted: boolean) {
    try {
      await gateway.reviewCandidate(candidate, accepted);
      setCandidates((current) => current.filter((item) => item.id !== candidate.id));
      setNotice(accepted ? 'Candidate accepted' : 'Candidate rejected');
    } catch {
      setError('The candidate was already reviewed.');
    }
  }

  async function submitTask(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!activeProject) return setError('Add or select a project first.');
    const form = event.currentTarget;
    const data = new FormData(form);
    const title = String(data.get('title') ?? '').trim();
    const body = String(data.get('body') ?? '').trim();
    if (!title) return setError('Enter a task title.');
    if (!body) return setError('Enter task details.');
    try {
      const task = await gateway.createTask(activeProject.projectId, title, body);
      setTasks((current) => [task, ...current]);
      setNotice('Task saved');
      setError(null);
      form.reset();
    } catch {
      setError('The task could not be saved.');
    }
  }

  async function submitTaskEdit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!editingTask) return;
    const data = new FormData(event.currentTarget);
    const title = String(data.get('title') ?? '').trim();
    const body = String(data.get('body') ?? '').trim();
    if (!title || !body) return setError('Enter a title and task details.');
    try {
      const task = await gateway.updateTask(editingTask, title, body);
      setTasks((current) => replaceRecord(current, task));
      setEditingTask(null);
      setNotice('Task updated');
    } catch {
      setError('The task changed before it could be updated.');
    }
  }

  async function transitionTask(task: TaskRecord, next: TaskStatus) {
    try {
      const updated = await gateway.transitionTask(task, next);
      setTasks((current) => replaceRecord(current, updated));
    } catch {
      setError('The task changed before it could be updated.');
    }
  }

  async function completeTask(task: TaskRecord) {
    const summary = evidence[task.id]?.trim();
    if (!summary) return setError(`Enter completion evidence for ${task.title}.`);
    try {
      const updated = await gateway.completeTask(task, summary);
      setTasks((current) => replaceRecord(current, updated));
      setNotice('Task completed');
      setError(null);
    } catch {
      setError('The task changed before it could be completed.');
    }
  }

  function renderScreen(screen: ScreenId) {
    switch (screen) {
      case 'home':
        return (
          <section className="screen-content" aria-labelledby="home-status-title">
            <h2 id="home-status-title">Local workspace posture</h2>
            <p role="status">
              {connectionState === 'failed' ? 'Connection unavailable' : connectionState === 'connecting' ? 'Connecting' : status?.sync === 'offline' ? 'Offline' : status?.sync}
            </p>
            <ul aria-label="Local capability status">
              <li>Vault: {connectionState === 'failed' ? 'unavailable' : status?.vault ?? 'checking'}</li>
              <li>Projects, memory, review, and tasks use the authenticated local daemon.</li>
              <li>Hosted synchronization is not configured.</li>
            </ul>
          </section>
        );
      case 'projects':
        return (
          <section className="screen-content">
            <form aria-describedby={error ? 'workspace-error' : undefined} aria-label="Add project" className="capture-form" onSubmit={submitProject}>
              <h2>Add project</h2>
              <Field label="Project name" name="name" />
              <Field label="Local path" name="path" />
              <button className="primary-action" type="submit">Add project</button>
            </form>
            <RecordList title="Projects">
              {projects.map((project) => (
                <li key={project.projectId}>
                  <button
                    aria-pressed={activeProject?.projectId === project.projectId}
                    className="record-button"
                    onClick={() => setActiveProject(project)}
                    type="button"
                  >
                    {project.name}
                  </button>
                </li>
              ))}
            </RecordList>
          </section>
        );
      case 'memory':
        return (
          <section className="screen-content">
            <form aria-label="Memory search" role="search" className="inline-form" onSubmit={searchMemory}>
              <label htmlFor="memory-query">Search memory</label>
              <input id="memory-query" name="query" type="search" />
              <button className="secondary-action" type="submit">Search</button>
            </form>
            <form aria-describedby={error ? 'workspace-error' : undefined} aria-label="New memory" className="capture-form" onSubmit={submitMemory}>
              <h2>New memory</h2>
              <Field label="Title" name="title" />
              <Field label="Memory" name="body" multiline />
              <button className="primary-action" type="submit">Save memory</button>
            </form>
            {editingMemory && (
              <form aria-describedby={error ? 'workspace-error' : undefined} aria-label="Edit memory" className="capture-form edit-form" onSubmit={submitMemoryEdit}>
                <h2>Edit memory</h2>
                <Field label="Edit title" name="title" defaultValue={editingMemory.title} />
                <Field label="Edit memory" name="body" defaultValue={editingMemory.bodyMarkdown} multiline />
                <button className="primary-action" type="submit">Update memory</button>
                <button className="secondary-action" onClick={() => setEditingMemory(null)} type="button">Cancel edit</button>
              </form>
            )}
            <RecordList title="Saved memory">
              {memories.map((memory) => (
                <li className="record-card" key={memory.id}>
                  <h3>{memory.title}</h3>
                  <p>{memory.bodyMarkdown}</p>
                  <button aria-label={`Edit ${memory.title}`} onClick={() => setEditingMemory(memory)} type="button">Edit</button>
                  <button aria-label={`Archive ${memory.title}`} onClick={(event) => openArchive(memory, event.currentTarget)} type="button">Archive</button>
                </li>
              ))}
            </RecordList>
            <dialog
              aria-labelledby="archive-dialog-title"
              onClose={() => archiveTriggerRef.current?.focus()}
              ref={archiveDialogRef}
            >
              <h2 id="archive-dialog-title">Archive memory?</h2>
              <p>{archiveTarget?.title}</p>
              <button
                className="primary-action"
                onClick={() => {
                  if (archiveTarget) void archiveMemory(archiveTarget);
                  archiveDialogRef.current?.close();
                  setArchiveTarget(null);
                }}
                type="button"
              >
                Confirm archive
              </button>
              <button className="secondary-action" onClick={() => archiveDialogRef.current?.close()} type="button">Cancel</button>
            </dialog>
          </section>
        );
      case 'review':
        return (
          <section className="screen-content">
            <h2>Candidate review</h2>
            <ul className="record-list">
              {candidates.map((candidate) => (
                <li className="record-card" key={candidate.id}>
                  <h3>{candidate.proposedMemory.title}</h3>
                  <p>{candidate.proposedMemory.bodyMarkdown}</p>
                  <p>{candidate.evidenceSummary}</p>
                  <button aria-label={`Accept ${candidate.proposedMemory.title}`} onClick={() => void review(candidate, true)} type="button">Accept</button>
                  <button aria-label={`Reject ${candidate.proposedMemory.title}`} onClick={() => void review(candidate, false)} type="button">Reject</button>
                </li>
              ))}
            </ul>
          </section>
        );
      case 'tasks':
        return (
          <section className="screen-content">
            <form aria-describedby={error ? 'workspace-error' : undefined} aria-label="New task" className="capture-form" onSubmit={submitTask}>
              <h2>New task</h2>
              <Field label="Task title" name="title" />
              <Field label="Task details" name="body" multiline />
              <button className="primary-action" type="submit">Save task</button>
            </form>
            {editingTask && (
              <form aria-describedby={error ? 'workspace-error' : undefined} aria-label="Edit task" className="capture-form edit-form" onSubmit={submitTaskEdit}>
                <h2>Edit task</h2>
                <Field label="Edit task title" name="title" defaultValue={editingTask.title} />
                <Field label="Edit task details" name="body" defaultValue={editingTask.bodyMarkdown} multiline />
                <button className="primary-action" type="submit">Update task</button>
              </form>
            )}
            <RecordList title="Tasks">
              {tasks.map((task) => (
                <li className="record-card" key={task.id}>
                  <h3>{task.title}</h3>
                  <p>{task.bodyMarkdown}</p>
                  <p className="state-label">{task.status === 'done' ? 'Done' : task.status.replace('_', ' ')}</p>
                  <button aria-label={`Edit ${task.title}`} onClick={() => setEditingTask(task)} type="button">Edit</button>
                  {task.status !== 'done' && (
                    <>
                      <button aria-label={`Start ${task.title}`} onClick={() => void transitionTask(task, 'in_progress')} type="button">Start</button>
                      <label htmlFor={`evidence-${task.id}`}>Evidence for {task.title}</label>
                      <input
                        id={`evidence-${task.id}`}
                        onChange={(event) => setEvidence((current) => ({ ...current, [task.id]: event.target.value }))}
                        type="text"
                        value={evidence[task.id] ?? ''}
                      />
                      <button aria-label={`Complete ${task.title}`} onClick={() => void completeTask(task)} type="button">Complete</button>
                    </>
                  )}
                  {task.evidence.map((item) => <p key={`${task.id}-${item.summary}`}>{item.summary}</p>)}
                </li>
              ))}
            </RecordList>
          </section>
        );
      case 'harnesses':
        return null;
      case 'packages':
        return <Deferred title="Portable context packages" text="Package inspection remains disabled until a local adapter supports it." />;
      case 'activity':
        return <Deferred title="Local audit activity" text="Completed local writes are durable in the encrypted vault." />;
      case 'devices':
        return <DevicesScreen gateway={gateway} />;
      case 'settings':
        return (
          <section className="screen-content">
            <h2>Local security posture</h2>
            <p>Tokens and vault keys stay outside React in operating-system protected storage.</p>
            <button className="secondary-action" onClick={(event) => openSecurityDetails(event.currentTarget)} type="button">Security details</button>
            <dialog aria-labelledby="security-dialog-title" onClose={restoreDialogFocus} ref={dialogRef}>
              <h2 id="security-dialog-title">Local security details</h2>
              <p>The daemon is the only SQLCipher writer.</p>
              <button className="primary-action" onClick={() => dialogRef.current?.close()} type="button">Close security details</button>
            </dialog>
          </section>
        );
    }
  }

  function openSecurityDetails(trigger: HTMLButtonElement) {
    dialogTriggerRef.current = trigger;
    dialogRef.current?.showModal();
  }

  function restoreDialogFocus() {
    dialogTriggerRef.current?.focus();
  }

  return (
    <>
      <a className="skip-link" href="#workspace-main">Skip to workspace</a>
      <div className="app-shell">
        <aside className="sidebar">
          <div className="brand-block">
            <p className="brand-name">Context Relay</p>
            <p>Local encrypted workspace</p>
          </div>
          <nav aria-label="Workspace">
            {SCREENS.map((screen) => (
              <button
                aria-current={activeScreen === screen.id ? 'page' : undefined}
                key={screen.id}
                onClick={() => void selectScreen(screen.id)}
                type="button"
              >
                {screen.label}
              </button>
            ))}
          </nav>
        </aside>
        <main id="workspace-main">
          <header className="screen-header">
            <h1 ref={headingRef} tabIndex={-1}>{currentScreen.label}</h1>
            <p>{currentScreen.summary}</p>
            {activeProject && <p className="context-label">Active project: {activeProject.name}</p>}
          </header>
          {connectionState === 'failed' && (
            <div className="form-error" role="alert">
              <p>Could not connect to the local workspace. Retry the connection to continue.</p>
              <button onClick={() => setConnectionAttempt((attempt) => attempt + 1)} type="button">Retry connection</button>
            </div>
          )}
          {error && <p className="form-error" id="workspace-error" role="alert">{error}</p>}
          {notice && <p className="notice" role="status">{notice}</p>}
          {renderScreen(activeScreen)}
          <div hidden={activeScreen !== 'harnesses'}>
            <HarnessesScreen gateway={gateway} projects={projects} active={activeScreen === 'harnesses'} />
          </div>
        </main>
      </div>
    </>
  );
}

function Field({
  defaultValue,
  label,
  multiline = false,
  name,
}: {
  defaultValue?: string;
  label: string;
  multiline?: boolean;
  name: string;
}) {
  const id = `${name}-${label.toLowerCase().replaceAll(' ', '-')}`;
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      {multiline ? (
        <textarea defaultValue={defaultValue} id={id} name={name} required rows={5} />
      ) : (
        <input defaultValue={defaultValue} id={id} name={name} required type="text" />
      )}
    </div>
  );
}

function RecordList({ children, title }: { children: React.ReactNode; title: string }) {
  return (
    <section className="records" aria-labelledby={`records-${title.replaceAll(' ', '-')}`}>
      <h2 id={`records-${title.replaceAll(' ', '-')}`}>{title}</h2>
      <ul className="record-list">{children}</ul>
    </section>
  );
}

function Deferred({ text, title }: { text: string; title: string }) {
  return (
    <section className="deferred-state">
      <h2>{title}</h2>
      <p>{text}</p>
    </section>
  );
}

function replaceRecord<T extends { id: string }>(records: T[], replacement: T) {
  return records.map((record) => (record.id === replacement.id ? replacement : record));
}
