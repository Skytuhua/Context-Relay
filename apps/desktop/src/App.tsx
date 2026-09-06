import { type FormEvent, useCallback, useEffect, useRef, useState } from 'react';

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
import { ProjectForm } from './project-form';
import { WriteRecovery } from './write-recovery';
import { LocalWorkspaceGateway, RecoveryStorageFullError, type WorkspaceGateway } from './workspace';

type ScreenId =
  | 'home'
  | 'projects'
  | 'memory'
  | 'review'
  | 'tasks'
  | 'harnesses'
  | 'devices'
  | 'settings';

const SCREENS: ReadonlyArray<{ id: ScreenId; label: string; summary: string }> = [
  { id: 'home', label: 'Home', summary: 'Keep useful context for your next session.' },
  { id: 'projects', label: 'Projects', summary: 'Choose the folders you work on with your harnesses.' },
  { id: 'memory', label: 'Saved context', summary: 'Save decisions, preferences and notes for future AI sessions.' },
  { id: 'review', label: 'Suggestions', summary: 'Choose which notes from your harnesses are worth keeping.' },
  { id: 'tasks', label: 'Tasks', summary: 'Keep track of what to do next and what is finished.' },
  { id: 'harnesses', label: 'Harnesses', summary: 'Let Codex, Claude Code or Hermes use your saved context.' },
  { id: 'devices', label: 'Devices', summary: 'Review trusted local devices.' },
  { id: 'settings', label: 'Settings', summary: 'Review local security settings.' },
];

const NAV_GROUPS: ReadonlyArray<{ label: string; screens: ScreenId[] }> = [
  { label: 'Your work', screens: ['home', 'projects', 'memory', 'review', 'tasks'] },
  { label: 'Connections', screens: ['harnesses', 'devices'] },
  { label: 'App', screens: ['settings'] },
];

const DEFAULT_GATEWAY = new LocalWorkspaceGateway();
const STARTUP_TIMEOUT_MS = 45_000;
type SaveAction = 'memory' | 'task' | 'memory-edit' | 'task-edit' | 'archive' | 'review' | 'task-status' | 'task-complete';
const SAVE_MESSAGES: Partial<Record<SaveAction, string>> = {
  archive: 'Archiving context…',
  review: 'Saving your review…',
  'task-status': 'Starting task…',
  'task-complete': 'Completing task…',
};

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
  const [recoveryStorageFull, setRecoveryStorageFull] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [saving, setSaving] = useState<SaveAction | null>(null);
  const savingRef = useRef(false);
  const memoryDraft = useRef({});
  const taskDraft = useRef({});
  const [projectBusy, setProjectBusy] = useState(false);
  const projectBusyRef = useRef(false);
  const recoveryBusy = useCallback((value: boolean) => {
    projectBusyRef.current = value;
    setProjectBusy(value);
  }, []);
  const readGeneration = useRef(0);
  const [recordsLoading, setRecordsLoading] = useState(false);
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

  async function selectScreen(screen: ScreenId, scope = activeProject) {
    if (savingRef.current || projectBusyRef.current) return;
    setRecoveryStorageFull(false);
    if (screen !== activeScreen || scope?.projectId !== activeProject?.projectId) {
      memoryDraft.current = {};
      taskDraft.current = {};
    }
    const generation = ++readGeneration.current;
    hasNavigatedRef.current = true;
    setActiveScreen(screen);
    setError(null);
    setNotice(null);
    setEditingMemory(null);
    setEditingTask(null);
    setRecordsLoading(['memory', 'review', 'tasks'].includes(screen));
    setMemories([]);
    setCandidates([]);
    setTasks([]);
    try {
      if (screen === 'memory') {
        const records = await gateway.memories(scope?.projectId ?? null);
        if (generation === readGeneration.current) setMemories(records);
      } else if (screen === 'review') {
        const records = await gateway.candidates(scope?.projectId ?? null);
        if (generation === readGeneration.current) setCandidates(records);
      } else if (screen === 'tasks' && scope) {
        const records = await gateway.tasks(scope.projectId);
        if (generation === readGeneration.current) setTasks(records);
      }
    } catch {
      if (generation === readGeneration.current) setError('This list could not load. Select this page again to retry.');
    } finally { if (generation === readGeneration.current) setRecordsLoading(false); }
  }

  function selectProject(project: ProjectIdentity) {
    if (savingRef.current || projectBusyRef.current) return;
    setActiveProject(project);
    void selectScreen(activeScreen, project);
  }

  function projectSaved(project: ProjectIdentity) {
    readGeneration.current += 1;
    setProjects((current) => [...current.filter((item) => item.projectId !== project.projectId), project]);
    setActiveProject(project);
    setActiveScreen('home');
    setNotice('Project added');
    setError(null);
  }

  function refreshSavedRecords(kind: 'memory' | 'task' | 'review', projectId: string | null) {
    const generation = ++readGeneration.current;
    setRecordsLoading(true);
    const load = kind === 'memory'
      ? gateway.memories(projectId).then((records) => { if (generation === readGeneration.current) setMemories(records); })
      : kind === 'review' ? gateway.candidates(projectId).then((records) => { if (generation === readGeneration.current) setCandidates(records); })
      : gateway.tasks(projectId!).then((records) => { if (generation === readGeneration.current) setTasks(records); });
    void load.catch(() => {
      if (generation === readGeneration.current) setError('Your change was saved, but the list could not refresh. Select this page again to reload it.');
    }).finally(() => { if (generation === readGeneration.current) setRecordsLoading(false); });
  }

  function beginSave(action: SaveAction) {
    if (savingRef.current || projectBusyRef.current || connectionState !== 'ready') return false;
    savingRef.current = true;
    readGeneration.current += 1;
    setRecordsLoading(false);
    setSaving(action);
    setRecoveryStorageFull(false);
    setError(null);
    setNotice(null);
    return true;
  }

  function finishSave() {
    savingRef.current = false;
    setSaving(null);
  }

  function reportSaveError(failure: unknown, fallback: string) {
    const full = failure instanceof RecoveryStorageFullError;
    setRecoveryStorageFull(full);
    setError(full ? failure.message : fallback);
  }

  async function submitMemory(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (savingRef.current || connectionState !== 'ready') return;
    const form = event.currentTarget;
    const data = new FormData(form);
    const title = String(data.get('title') ?? '').trim();
    const body = String(data.get('body') ?? '').trim();
    if (!title) return setError('Enter a title.');
    if (!body) return setError('Enter memory text.');
    if (!beginSave('memory')) return;
    try {
      const memory = await gateway.createMemory(activeProject?.projectId ?? null, title, body, memoryDraft.current);
      setMemories((current) => current.some((item) => item.id === memory.id) ? current : [memory, ...current]);
      setNotice('Context saved');
      setError(null);
      form.reset();
      memoryDraft.current = {};
      refreshSavedRecords('memory', activeProject?.projectId ?? null);
    } catch (failure) {
      reportSaveError(failure, 'We could not confirm the save. Your draft is still here. Choose Save context again to retry this draft.');
    } finally { finishSave(); }
  }

  async function submitMemoryEdit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!editingMemory || savingRef.current || connectionState !== 'ready') return;
    const data = new FormData(event.currentTarget);
    const title = String(data.get('title') ?? '').trim();
    const body = String(data.get('body') ?? '').trim();
    if (!title || !body) return setError('Enter a title and memory text.');
    if (!beginSave('memory-edit')) return;
    try {
      const memory = await gateway.updateMemory(editingMemory, title, body);
      setMemories((current) => replaceRecord(current, memory, editingMemory.revision));
      setEditingMemory(null);
      setNotice('Memory updated');
      setError(null);
      refreshSavedRecords('memory', activeProject?.projectId ?? null);
    } catch (failure) {
      reportSaveError(failure, 'We could not confirm the update. Your draft is still here. Choose Update context again to retry these changes.');
    } finally { finishSave(); }
  }

  async function archiveMemory(memory: MemoryRecord) {
    if (!beginSave('archive')) return;
    try {
      await gateway.archiveMemory(memory);
      setMemories((current) => current.filter((item) => item.id !== memory.id));
      setEditingMemory((current) => current?.id === memory.id ? null : current);
      setNotice('Memory archived');
    } catch (failure) {
      reportSaveError(failure, 'We could not confirm the archive. Reload Saved context to check before trying again.');
    } finally { finishSave(); }
  }

  function openArchive(memory: MemoryRecord, trigger: HTMLButtonElement) {
    if (savingRef.current) return;
    setArchiveTarget(memory);
    archiveTriggerRef.current = trigger;
    queueMicrotask(() => archiveDialogRef.current?.showModal());
  }

  async function searchMemory(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (savingRef.current) return;
    const generation = ++readGeneration.current;
    setRecordsLoading(true);
    const query = String(new FormData(event.currentTarget).get('query') ?? '').trim();
    try {
      const records = await (query ? gateway.searchMemories(query, activeProject?.projectId ?? null) : gateway.memories(activeProject?.projectId ?? null));
      if (generation !== readGeneration.current) return;
      setMemories(records);
      setError(null);
    } catch {
      if (generation === readGeneration.current) setError('Search could not finish. Your saved context has not changed. Try searching again.');
    } finally { if (generation === readGeneration.current) setRecordsLoading(false); }
  }

  async function review(candidate: MemoryCandidate, accepted: boolean) {
    if (!beginSave('review')) return;
    try {
      await gateway.reviewCandidate(candidate, accepted);
      setCandidates((current) => current.filter((item) => item.id !== candidate.id));
      setNotice(accepted ? 'Candidate accepted' : 'Candidate rejected');
    } catch (failure) {
      reportSaveError(failure, 'We could not confirm your review. Reload Suggestions to check before trying again.');
    } finally { finishSave(); }
  }

  async function submitTask(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (savingRef.current || connectionState !== 'ready') return;
    if (!activeProject) return setError('Add or select a project first.');
    const form = event.currentTarget;
    const data = new FormData(form);
    const title = String(data.get('title') ?? '').trim();
    const body = String(data.get('body') ?? '').trim();
    if (!title) return setError('Enter a task title.');
    if (!body) return setError('Enter task details.');
    if (!beginSave('task')) return;
    try {
      const task = await gateway.createTask(activeProject.projectId, title, body, taskDraft.current);
      setTasks((current) => current.some((item) => item.id === task.id) ? current : [task, ...current]);
      setNotice('Task saved');
      setError(null);
      form.reset();
      taskDraft.current = {};
      refreshSavedRecords('task', activeProject.projectId);
    } catch (failure) {
      reportSaveError(failure, 'We could not confirm the save. Your draft is still here. Choose Save task again to retry this draft.');
    } finally { finishSave(); }
  }

  async function submitTaskEdit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!editingTask || !activeProject || savingRef.current || connectionState !== 'ready') return;
    const data = new FormData(event.currentTarget);
    const title = String(data.get('title') ?? '').trim();
    const body = String(data.get('body') ?? '').trim();
    if (!title || !body) return setError('Enter a title and task details.');
    if (!beginSave('task-edit')) return;
    try {
      const task = await gateway.updateTask(editingTask, title, body);
      setTasks((current) => replaceRecord(current, task, editingTask.revision));
      setEditingTask(null);
      setNotice('Task updated');
      refreshSavedRecords('task', activeProject.projectId);
    } catch (failure) {
      reportSaveError(failure, 'We could not confirm the update. Your draft is still here. Choose Update task again to retry these changes.');
    } finally { finishSave(); }
  }

  async function transitionTask(task: TaskRecord, next: TaskStatus) {
    if (!beginSave('task-status')) return;
    try {
      const updated = await gateway.transitionTask(task, next);
      setTasks((current) => replaceRecord(current, updated, task.revision));
      setNotice(next === 'in_progress' ? 'Task started' : 'Task updated');
    } catch (failure) {
      reportSaveError(failure, 'We could not confirm the task status. Reload Tasks to check before trying again.');
    } finally { finishSave(); }
  }

  async function completeTask(task: TaskRecord) {
    if (savingRef.current) return;
    const summary = evidence[task.id]?.trim();
    if (!summary) return setError(`Enter completion evidence for ${task.title}.`);
    if (!beginSave('task-complete')) return;
    try {
      const updated = await gateway.completeTask(task, summary);
      setTasks((current) => replaceRecord(current, updated, task.revision));
      setNotice('Task completed');
      setError(null);
    } catch (failure) {
      reportSaveError(failure, 'We could not confirm completion. Your evidence is still here. Reload Tasks to check before trying again.');
    } finally { finishSave(); }
  }

  function renderScreen(screen: ScreenId) {
    switch (screen) {
      case 'home':
        return (
          <section className="screen-content home-guide" aria-labelledby="home-start-title">
            {connectionState === 'ready' && <WriteRecovery gateway={gateway} projects={projects} onBusy={recoveryBusy} />}
            <h2 id="home-start-title">{activeProject ? 'What would you like to remember?' : 'Stop explaining the same things again'}</h2>
            <p>Save a decision, preference or project note once. A connected harness can find it when you start your next session.</p>
            {!activeProject ? <>
              <ol className="how-it-works" aria-label="How Context Relay works">
                <li><h3>Choose a project</h3><p>Pick the folder you work in. Its notes and tasks stay together.</p></li>
                <li><h3>Save useful context</h3><p>Add a preference or decision you want to keep, such as “Use TypeScript.”</p></li>
                <li><h3>Connect a harness</h3><p>Connect Codex, Claude Code or Hermes so it can retrieve those notes.</p></li>
              </ol>
              <button className="primary-action" type="button" disabled={connectionState !== 'ready'} onClick={() => void selectScreen('projects')}>Add your project folder</button>
            </> : <NextSteps onConnect={() => void selectScreen('harnesses')} onContext={() => void selectScreen('memory')} />}
            <p className="workspace-status" role="status">{connectionState === 'failed' ? 'Local workspace unavailable' : connectionState === 'connecting' ? 'Opening your workspace…' : status?.vault === 'unlocked' ? 'Ready on this computer' : 'Workspace locked'}</p>
            <p className="help-text">Saved on this computer. You can add notes and tasks before connecting a harness.</p>
          </section>
        );
      case 'projects':
        return (
          <section className="screen-content">
            <ProjectForm gateway={gateway} ready={connectionState === 'ready'} onSaved={projectSaved} onBusy={(value) => { projectBusyRef.current = value; setProjectBusy(value); }} />
            <RecordList title="Projects">
              {projects.map((project) => (
                <li key={project.projectId}>
                  <button
                    aria-pressed={activeProject?.projectId === project.projectId}
                    className="record-button"
                    disabled={projectBusy || !!saving}
                    onClick={() => selectProject(project)}
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
            <form key={'context-' + (activeProject?.projectId ?? 'global')} aria-describedby={error ? 'workspace-error' : undefined} aria-label="New context" className="capture-form" onSubmit={submitMemory}>
              <h2>Save something worth remembering</h2>
              <p>For example: “Use TypeScript for this project” or a decision you do not want to explain again.</p>
              <Field label="Title" name="title" disabled={!!saving} placeholder="For example, Writing preferences" />
              <Field label="What should your harness remember?" name="body" multiline disabled={!!saving} placeholder="A decision, preference or detail to use next time…" />
              <button className="primary-action" type="submit" disabled={!!saving || projectBusy || connectionState !== 'ready'}>{saving === 'memory' ? 'Saving…' : 'Save context'}</button>
            </form>
            {editingMemory && (
              <form key={editingMemory.id} aria-describedby={error ? 'workspace-error' : undefined} aria-label="Edit context" className="capture-form edit-form" onSubmit={submitMemoryEdit}>
                <h2>Edit context</h2>
                <Field label="Edit title" name="title" defaultValue={editingMemory.title} disabled={!!saving} />
                <Field label="Edit context" name="body" defaultValue={editingMemory.bodyMarkdown} multiline disabled={!!saving} />
                <button className="primary-action" type="submit" disabled={!!saving || projectBusy || connectionState !== 'ready'}>{saving === 'memory-edit' ? 'Saving changes…' : 'Update context'}</button>
                <button className="secondary-action" disabled={!!saving} onClick={() => setEditingMemory(null)} type="button">Cancel edit</button>
              </form>
            )}
            <RecordList title="Saved context" tools={<form aria-label="Context search" role="search" className="inline-form" onSubmit={searchMemory}>
                <label htmlFor="memory-query">Search saved context</label>
                <input id="memory-query" name="query" type="search" disabled={!!saving} />
                <button className="secondary-action" type="submit" disabled={!!saving}>Search</button>
              </form>}>
              {memories.length === 0 && <li className="empty-message">Saved notes will appear here. Add one above, or try another search.</li>}
              {memories.map((memory) => (
                <li className="record-card" key={memory.id}>
                  <h3>{memory.title}</h3>
                  <p>{memory.bodyMarkdown}</p>
                  <button aria-label={`Edit ${memory.title}`} disabled={!!saving} onClick={() => setEditingMemory(memory)} type="button">Edit</button>
                  <button aria-label={`Archive ${memory.title}`} disabled={!!saving || projectBusy || connectionState !== 'ready'} onClick={(event) => openArchive(memory, event.currentTarget)} type="button">Archive</button>
                </li>
              ))}
            </RecordList>
            <dialog
              aria-labelledby="archive-dialog-title"
              onClose={() => archiveTriggerRef.current?.focus()}
              ref={archiveDialogRef}
            >
              <h2 id="archive-dialog-title">Archive context?</h2>
              <p>{archiveTarget?.title}</p>
              <button
                className="primary-action"
                disabled={!!saving || projectBusy || connectionState !== 'ready'}
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
            <h2>Suggestions from harnesses</h2>
            <p>Harnesses can suggest notes to remember. Review each one before it becomes saved context.</p>
            <ul className="record-list">
              {candidates.length === 0 && <li className="empty-message">No suggestions to review. Suggestions from a connected harness will appear here.</li>}
              {candidates.map((candidate) => (
                <li className="record-card" key={candidate.id}>
                  <h3>{candidate.proposedMemory.title}</h3>
                  <p>{candidate.proposedMemory.bodyMarkdown}</p>
                  <p>{candidate.evidenceSummary}</p>
                  <button aria-label={`Accept ${candidate.proposedMemory.title}`} disabled={!!saving || projectBusy || connectionState !== 'ready'} onClick={() => void review(candidate, true)} type="button">Accept</button>
                  <button aria-label={`Reject ${candidate.proposedMemory.title}`} disabled={!!saving || projectBusy || connectionState !== 'ready'} onClick={() => void review(candidate, false)} type="button">Reject</button>
                </li>
              ))}
            </ul>
          </section>
        );
      case 'tasks':
        if (!activeProject) return <section className="screen-content">
          <h2>Choose a project for your tasks</h2>
          <p>Tasks belong to a project. Add its folder first.</p>
          <button className="primary-action" type="button" onClick={() => void selectScreen('projects')}>Add a project</button>
        </section>;
        return (
          <section className="screen-content">
            <form key={'task-' + activeProject.projectId} aria-describedby={error ? 'workspace-error' : undefined} aria-label="New task" className="capture-form" onSubmit={submitTask}>
              <h2>New task</h2>
              <p>Write down the next piece of work so you or your harness can pick it up later.</p>
              <Field label="Task title" name="title" disabled={!!saving} placeholder="For example, Fix the sign-in page" />
              <Field label="Task details" name="body" multiline disabled={!!saving} />
              <button className="primary-action" type="submit" disabled={!!saving || projectBusy || connectionState !== 'ready'}>{saving === 'task' ? 'Saving…' : 'Save task'}</button>
            </form>
            {editingTask && (
              <form key={editingTask.id} aria-describedby={error ? 'workspace-error' : undefined} aria-label="Edit task" className="capture-form edit-form" onSubmit={submitTaskEdit}>
                <h2>Edit task</h2>
                <Field label="Edit task title" name="title" defaultValue={editingTask.title} disabled={!!saving} />
                <Field label="Edit task details" name="body" defaultValue={editingTask.bodyMarkdown} multiline disabled={!!saving} />
                <button className="primary-action" type="submit" disabled={!!saving || projectBusy || connectionState !== 'ready'}>{saving === 'task-edit' ? 'Saving changes…' : 'Update task'}</button>
              </form>
            )}
            <RecordList title="Tasks">
              {tasks.length === 0 && <li className="empty-message">No tasks yet. Add the next thing you want to work on above.</li>}
              {tasks.map((task) => (
                <li className="record-card" key={task.id}>
                  <h3>{task.title}</h3>
                  <p>{task.bodyMarkdown}</p>
                  <p className="state-label">{task.status === 'done' ? 'Done' : task.status.replace('_', ' ')}</p>
                  <button aria-label={`Edit ${task.title}`} disabled={!!saving} onClick={() => setEditingTask(task)} type="button">Edit</button>
                  {task.status !== 'done' && (
                    <>
                      <button aria-label={`Start ${task.title}`} disabled={!!saving || projectBusy || connectionState !== 'ready'} onClick={() => void transitionTask(task, 'in_progress')} type="button">Start</button>
                      <label htmlFor={`evidence-${task.id}`}>Evidence for {task.title}</label>
                      <input
                        id={`evidence-${task.id}`}
                        disabled={!!saving}
                        onChange={(event) => setEvidence((current) => ({ ...current, [task.id]: event.target.value }))}
                        type="text"
                        value={evidence[task.id] ?? ''}
                      />
                      <button aria-label={`Complete ${task.title}`} disabled={!!saving || projectBusy || connectionState !== 'ready'} onClick={() => void completeTask(task)} type="button">Complete</button>
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
      case 'devices':
        return <DevicesScreen gateway={gateway} />;
      case 'settings':
        return (
          <section className="screen-content">
            <h2>Storage on this computer</h2>
            <p>Your saved context and tasks are encrypted on this computer. Windows or macOS protects the keys used to open them.</p>
            <button className="secondary-action" onClick={(event) => openSecurityDetails(event.currentTarget)} type="button">Security details</button>
            <dialog aria-labelledby="security-dialog-title" onClose={restoreDialogFocus} ref={dialogRef}>
              <h2 id="security-dialog-title">Local security details</h2>
              <p>A local background service reads and saves your encrypted records. The app does not expose the encryption keys.</p>
              <button className="primary-action" onClick={() => dialogRef.current?.close()} type="button">Close security details</button>
            </dialog>
            <h2>Features still in development</h2>
            <p>Package sharing, activity history and hosted sync are not available in this build.</p>
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
            <p>Context for your harnesses</p>
          </div>
          <nav aria-label="Workspace">
            {NAV_GROUPS.map((group) => <div className="nav-group" key={group.label} role="group" aria-label={group.label}>
              <p className="nav-group-label">{group.label}</p>
              {SCREENS.filter((screen) => group.screens.includes(screen.id)).map((screen) => (
              <button
                aria-current={activeScreen === screen.id ? 'page' : undefined}
                key={screen.id}
                disabled={!!saving || projectBusy}
                onClick={() => void selectScreen(screen.id)}
                type="button"
              >
                {screen.label}
              </button>
              ))}
            </div>)}
          </nav>
        </aside>
        <main id="workspace-main">
          <header className="screen-header">
            <h1 ref={headingRef} tabIndex={-1}>{currentScreen.label}</h1>
            <p>{currentScreen.summary}</p>
            {['home', 'memory', 'review', 'tasks'].includes(activeScreen) && projects.length > 0 && <div className="field project-switcher">
              <label htmlFor="active-project">Current project</label>
              <select id="active-project" value={activeProject?.projectId ?? ''} disabled={!!saving || projectBusy} onChange={(event) => {
                const project = projects.find((item) => item.projectId === event.target.value);
                if (project) selectProject(project);
              }}>{projects.map((project) => <option key={project.projectId} value={project.projectId}>{project.name}</option>)}</select>
            </div>}
          </header>
          {connectionState === 'failed' && (
            <div className="form-error" role="alert">
              <p>Could not connect to the local workspace. Retry the connection to continue.</p>
              <button onClick={() => setConnectionAttempt((attempt) => attempt + 1)} type="button">Retry connection</button>
            </div>
          )}
          {error && <p className="form-error" id="workspace-error" role="alert">{error}</p>}
          {notice && <div className="notice" role="status"><p>{notice}</p>
            {notice === 'Context saved' && activeProject && <button className="secondary-action" type="button" onClick={() => void selectScreen('harnesses')}>Connect a harness</button>}
          </div>}
          {saving && SAVE_MESSAGES[saving] && <p role="status">{SAVE_MESSAGES[saving]}</p>}
          {recordsLoading && <p role="status">Loading your saved records…</p>}
          {renderScreen(activeScreen)}
          {recoveryStorageFull && activeScreen !== 'home' && <WriteRecovery gateway={gateway} projects={projects} onBusy={recoveryBusy} onConfirmed={() => {
            if (activeScreen === 'memory' || activeScreen === 'tasks') refreshSavedRecords(activeScreen === 'memory' ? 'memory' : 'task', activeProject?.projectId ?? null);
            else if (activeScreen === 'review') refreshSavedRecords('review', activeProject?.projectId ?? null);
          }} />}
          <div hidden={activeScreen !== 'harnesses'}>
            <HarnessesScreen gateway={gateway} projects={projects} preferredProjectId={activeProject?.projectId} onProjectChange={(id) => {
              const project = projects.find((item) => item.projectId === id);
              if (project) setActiveProject(project);
            }} onAddProject={() => void selectScreen('projects')} onSaveContext={() => void selectScreen('memory')} active={activeScreen === 'harnesses'} />
          </div>
        </main>
      </div>
    </>
  );
}

function Field({
  defaultValue,
  disabled = false,
  placeholder,
  label,
  multiline = false,
  name,
}: {
  defaultValue?: string;
  disabled?: boolean;
  placeholder?: string;
  label: string;
  multiline?: boolean;
  name: string;
}) {
  const id = `${name}-${label.toLowerCase().replaceAll(' ', '-')}`;
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      {multiline ? (
        <textarea defaultValue={defaultValue} disabled={disabled} placeholder={placeholder} id={id} name={name} required rows={4} />
      ) : (
        <input defaultValue={defaultValue} disabled={disabled} placeholder={placeholder} id={id} name={name} required type="text" />
      )}
    </div>
  );
}

function RecordList({ children, title, tools }: { children: React.ReactNode; title: string; tools?: React.ReactNode }) {
  return (
    <section className="records" aria-labelledby={`records-${title.replaceAll(' ', '-')}`}>
      <h2 id={`records-${title.replaceAll(' ', '-')}`}>{title}</h2>
      {tools}
      <ul className="record-list">{children}</ul>
    </section>
  );
}

function NextSteps({ onConnect, onContext }: { onConnect: () => void; onContext: () => void }) {
  return <div className="next-steps" role="group" aria-label="Next steps">
    <div><h3>Save useful context</h3><p>Keep a writing preference, project decision or useful detail for next time.</p><button className="primary-action" type="button" onClick={onContext}>Save context</button></div>
    <div><h3>Connect a harness when you’re ready</h3><p>Check whether Codex, Claude Code or Hermes can connect to this project.</p><button className="secondary-action" type="button" onClick={onConnect}>Connect a harness</button></div>
  </div>;
}

function replaceRecord<T extends { id: string; revision: string }>(records: T[], replacement: T, expectedRevision: string) {
  // Replayed operations return their original snapshot. Preserve any version
  // that a newer read already placed on screen until the fresh list arrives.
  return records.map((record) => record.id === replacement.id &&
    (record.revision === expectedRevision || record.revision === replacement.revision) ? replacement : record);
}
