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
import { WorkspaceIcon } from './workspace-icon';
import { Dashboard } from './dashboard';
import { DashboardTour, HelpScreen } from './help-tour';
import { SetupWizard } from './setup-wizard';
import { ConnectionTest } from './connection-test';
import { openHarness, openHarnessGuide } from './harness-launch';
import { readPreferences, savePreferences, type DesktopPreferences, type SetupProgress, type Theme } from './desktop-preferences';
import { WriteRecovery } from './write-recovery';
import { SearchProgress } from './search-progress';
import { HostedSignIn } from './hosted-sign-in';
import { useSearchProgress } from './use-search-progress';
import { useScopedEditor } from './use-scoped-editor';
import { isServiceVersionMismatch, SERVICE_UPDATE_GUIDANCE } from './service-error';
import { LocalWorkspaceGateway, RecoveryStorageFullError, type WorkspaceGateway } from './workspace';

type ScreenId =
  | 'home'
  | 'projects'
  | 'memory'
  | 'review'
  | 'tasks'
  | 'harnesses'
  | 'devices'
  | 'help'
  | 'settings';

const SCREENS: ReadonlyArray<{ id: ScreenId; label: string; summary: string }> = [
  { id: 'home', label: 'Dashboard', summary: 'Your project context, work and harness connections.' },
  { id: 'projects', label: 'Projects', summary: 'Choose the folders you work on with your harnesses.' },
  { id: 'memory', label: 'Context', summary: 'Decisions, preferences and project facts your connected harness can retrieve.' },
  { id: 'review', label: 'Suggestions', summary: 'Choose which notes from your harnesses are worth keeping.' },
  { id: 'tasks', label: 'Tasks', summary: 'Keep track of what to do next and what is finished.' },
  { id: 'harnesses', label: 'Harnesses', summary: 'Let Codex, Claude Code or Hermes use your saved context.' },
  { id: 'devices', label: 'Devices', summary: 'Review trusted local devices.' },
  { id: 'settings', label: 'Settings', summary: 'Review local security settings.' },
  { id: 'help', label: 'Help', summary: 'Learn how to save context, continue work and connect your harnesses.' },
];

const NAV_GROUPS: ReadonlyArray<{ label: string; screens: ScreenId[] }> = [
  { label: 'Workspace', screens: ['home', 'memory', 'tasks', 'harnesses', 'projects'] },
  { label: 'App', screens: ['help', 'settings'] },
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
  const [preferences, setPreferences] = useState(readPreferences);
  const [preferenceError, setPreferenceError] = useState<string | null>(null);
  const tourStep = preferences.tourStep;
  const setTourStep = (tourStep: number | null) => updatePreferences(current => ({ ...current, tourStep }));
  const [testVerified, setTestVerified] = useState(false);
  const [setupBusy, setSetupBusy] = useState(false);
  const showSetup = preferences.setup.status === 'new' || preferences.setup.status === 'in_progress';
  const updatePreferences = useCallback((change: (current: DesktopPreferences) => DesktopPreferences) => {
    setPreferences(change);
  }, []);
  useEffect(() => {
    try { savePreferences(preferences); setPreferenceError(null); }
    catch { setPreferenceError('Your choices could not be saved on this computer. Keep this window open to continue setup.'); }
  }, [preferences]);
  const updateSetup = (setup: SetupProgress) => {
    // Navigation and selection changes require the test screen to revalidate.
    setTestVerified(false);
    updatePreferences(current => ({ ...current, setup }));
  };
  const resumeSetup = () => {
    if (savingRef.current || projectBusyRef.current) return;
    setTestVerified(false);
    // The workspace may have moved to another project while setup was deferred.
    // Use the same transition that preserves editors and invalidates old reads.
    transitionProject(preferences.setup.status === 'complete' ? null
      : projects.find(project => project.projectId === preferences.setup.projectId) ?? null);
    updatePreferences(current => ({ ...current, setup: current.setup.status === 'complete'
      ? { ...current.setup, status: 'in_progress', step: 'harnesses', projectId: null, noteId: null, checkId: null, testHarness: null }
      : { ...current.setup, status: 'in_progress' } }));
  };
  const startTour = () => {
    setTourStep(0);
    void selectScreen('home');
  };
  useEffect(() => {
    const media = window.matchMedia?.('(prefers-color-scheme: dark)');
    const apply = () => { document.documentElement.dataset.theme = preferences.theme === 'system' ? media?.matches ? 'dark' : 'light' : preferences.theme; };
    apply();
    media?.addEventListener('change', apply);
    return () => media?.removeEventListener('change', apply);
  }, [preferences.theme]);
  const [activeScreen, setActiveScreen] = useState<ScreenId>('home');
  const [status, setStatus] = useState<StatusOutput | null>(null);
  const [connectionState, setConnectionState] = useState<'connecting' | 'ready' | 'failed'>('connecting');
  const [connectionAttempt, setConnectionAttempt] = useState(0);
  const [serviceVersionMismatch, setServiceVersionMismatch] = useState(false);
  const [projects, setProjects] = useState<ProjectIdentity[]>([]);
  const [activeProject, setActiveProject] = useState<ProjectIdentity | null>(null);
  const [memories, setMemories] = useState<MemoryRecord[]>([]);
  const [candidates, setCandidates] = useState<MemoryCandidate[]>([]);
  const [tasks, setTasks] = useState<TaskRecord[]>([]);
  const [editingMemory, setEditingMemory, restoreMemoryEditor] = useScopedEditor<MemoryRecord>(activeProject?.projectId ?? null);
  const [editingTask, setEditingTask, restoreTaskEditor] = useScopedEditor<TaskRecord>(activeProject?.projectId ?? null);
  const [archiveTarget, setArchiveTarget] = useState<MemoryRecord | null>(null);
  const [evidence, setEvidence] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [recoveryStorageFull, setRecoveryStorageFull] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [saving, setSaving] = useState<SaveAction | null>(null);
  const savingRef = useRef(false);
  const memoryDraft = useRef({});
  const taskDraft = useRef({});
  const textDrafts = useRef(new Map<string, { title: string; body: string }>());
  const attemptDrafts = useRef(new Map<string, object>());
  const projectDraft = useRef({ name: '', path: '' });
  const editorSelections = useRef(new Map<string, { memory: MemoryRecord | null; task: TaskRecord | null }>());
  const [creatingContext, setCreatingContext] = useState(false);
  const [creatingTask, setCreatingTask] = useState(false);
  const draftScope = activeProject?.projectId ?? 'global';
  function rememberDraft(form: HTMLFormElement, key: string) {
    const data = new FormData(form);
    textDrafts.current.set(key, { title: String(data.get('title') ?? ''), body: String(data.get('body') ?? '') });
  }
  const [projectBusy, setProjectBusy] = useState(false);
  const projectBusyRef = useRef(false);
  const recoveryBusy = useCallback((value: boolean) => {
    projectBusyRef.current = value;
    setProjectBusy(value);
  }, []);
  const readGeneration = useRef(0);
  const [recordsLoading, setRecordsLoading] = useState(false);
  const [submittedSearch, setSubmittedSearch] = useState<{ query: string } | null>(null);
  const searchProgress = useSearchProgress(gateway, activeScreen === 'memory' && connectionState === 'ready');
  const searchRevision = searchProgress.status?.revision;
  const searchProjectId = activeProject?.projectId ?? null;
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
    setServiceVersionMismatch(false);
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
        setActiveProject((current) => nextProjects.find((project) => project.projectId === current?.projectId) ?? nextProjects.find(project => project.projectId === readPreferences().setup.projectId) ?? (readPreferences().setup.status === 'complete' ? nextProjects[0] ?? null : null));
        setConnectionState('ready');
      })
      .catch((failure: unknown) => {
        if (!active) return;
        window.clearTimeout(timeout);
        setServiceVersionMismatch(isServiceVersionMismatch(failure));
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

  useEffect(() => {
    if (activeScreen === 'memory' && creatingContext) document.getElementById('title-title')?.focus();
    if (activeScreen === 'tasks' && creatingTask) document.getElementById('title-task-title')?.focus();
  }, [activeScreen, creatingContext, creatingTask]);

  useEffect(() => {
    if (activeScreen !== 'memory' || !submittedSearch || connectionState !== 'ready') return;
    const generation = ++readGeneration.current;
    setRecordsLoading(true);
    const query = submittedSearch.query;
    let active = true;
    void (query ? gateway.searchMemories(query, searchProjectId) : gateway.memories(searchProjectId))
      .then((records) => {
        if (!active || generation !== readGeneration.current) return;
        setMemories(records);
        setError(null);
      }).catch(() => {
        if (active && generation === readGeneration.current) setError('Search could not finish. Your saved context has not changed. Try searching again.');
      }).finally(() => {
        if (active && generation === readGeneration.current) setRecordsLoading(false);
      });
    return () => { active = false; };
  }, [activeScreen, submittedSearch, searchRevision, searchProjectId, gateway, connectionState]);

  if (!currentScreen) return null;

  function transitionProject(project: ProjectIdentity | null) {
    if (project?.projectId !== activeProject?.projectId) {
      const nextScope = project?.projectId ?? 'global';
      editorSelections.current.set(draftScope, { memory: editingMemory, task: editingTask });
      attemptDrafts.current.set(`memory-${draftScope}`, memoryDraft.current);
      attemptDrafts.current.set(`task-${draftScope}`, taskDraft.current);
      memoryDraft.current = attemptDrafts.current.get(`memory-${nextScope}`) ?? {};
      taskDraft.current = attemptDrafts.current.get(`task-${nextScope}`) ?? {};
      const selection = editorSelections.current.get(nextScope);
      restoreMemoryEditor(selection?.memory ?? null, project?.projectId ?? null);
      restoreTaskEditor(selection?.task ?? null, project?.projectId ?? null);
      setArchiveTarget(null);
      readGeneration.current += 1;
      setSubmittedSearch(null);
      setRecordsLoading(false);
      setMemories([]);
      setCandidates([]);
      setTasks([]);
    }
    setActiveProject(project);
  }

  async function selectScreen(screen: ScreenId, scope = activeProject) {
    if (savingRef.current || projectBusyRef.current) return;
    setRecoveryStorageFull(false);
    transitionProject(scope);
    const generation = ++readGeneration.current;
    hasNavigatedRef.current = true;
    setSubmittedSearch(null);
    setActiveScreen(screen);
    setError(null);
    setNotice(null);
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
    void selectScreen(activeScreen, project);
  }

  function projectSaved(project: ProjectIdentity) {
    readGeneration.current += 1;
    setProjects((current) => [...current.filter((item) => item.projectId !== project.projectId), project]);
    // Registration has succeeded, but ProjectForm still owns its busy flag.
    // Complete the scope transition without treating it as another user action.
    transitionProject(project);
    setSubmittedSearch(null);
    setRecordsLoading(false);
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
    setSubmittedSearch(null);
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
      textDrafts.current.delete(`memory-${draftScope}`);
      setCreatingContext(false);
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
      textDrafts.current.delete(`edit-memory-${editingMemory.id}`);
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

  function searchMemory(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (savingRef.current) return;
    const query = String(new FormData(event.currentTarget).get('query') ?? '').trim();
    setSubmittedSearch({ query });
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
      textDrafts.current.delete(`task-${draftScope}`);
      setCreatingTask(false);
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
      textDrafts.current.delete(`edit-task-${editingTask.id}`);
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
        return <>
          {connectionState === 'ready' && <><WriteRecovery gateway={gateway} projects={projects} onBusy={recoveryBusy} />
            <Dashboard gateway={gateway} project={activeProject} lastVerifiedRead={preferences.lastVerifiedRead} setupDeferred={preferences.setup.status === 'deferred'} onResumeSetup={resumeSetup} onNavigate={screen => void selectScreen(screen)}
              onAddContext={() => { setCreatingContext(true); setEditingMemory(null); void selectScreen('memory'); }} onNewTask={() => { setCreatingTask(true); setEditingTask(null); void selectScreen('tasks'); }}
              onOpenContext={note => { setCreatingContext(false); setEditingMemory(note); void selectScreen('memory'); }} onOpenTask={task => { setCreatingTask(false); setEditingTask(task); void selectScreen('tasks'); }} /></>}
          {connectionState === 'connecting' && <p role="status">Opening your workspace…</p>}
        </>;
      case 'help':
        return <HelpScreen setupComplete={preferences.setup.status === 'complete'} onResumeSetup={resumeSetup} onStartTour={startTour} />;
      case 'projects':
        return (
          <section className="screen-content">
            <ProjectForm gateway={gateway} ready={connectionState === 'ready'} initialDraft={projectDraft.current} onDraft={value => { projectDraft.current = value; }} onSaved={projectSaved} onBusy={(value) => { projectBusyRef.current = value; setProjectBusy(value); }} />
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
          <section className="screen-content workbench">
<div className="work-detail">
            <form key={'context-' + (activeProject?.projectId ?? 'global')} aria-describedby={error ? 'workspace-error' : undefined} aria-label="New context" className="capture-form" hidden={!creatingContext} onChange={event => rememberDraft(event.currentTarget, `memory-${draftScope}`)} onSubmit={submitMemory}>
              <h2>Save something worth remembering</h2>
              <p>For example: “Use TypeScript for this project” or a decision you do not want to explain again.</p>
              <Field label="Title" name="title" defaultValue={textDrafts.current.get(`memory-${draftScope}`)?.title} disabled={!!saving} placeholder="For example, Writing preferences" />
              <Field label="What should your harness remember?" name="body" defaultValue={textDrafts.current.get(`memory-${draftScope}`)?.body} multiline disabled={!!saving} placeholder="A decision, preference or detail to use next time…" />
              <button className="primary-action" type="submit" disabled={!!saving || projectBusy || connectionState !== 'ready'}>{saving === 'memory' ? 'Saving…' : 'Save context'}</button>
            </form>
            {editingMemory && (
              <form key={editingMemory.id} aria-describedby={error ? 'workspace-error' : undefined} aria-label="Edit context" className="capture-form edit-form" onChange={event => rememberDraft(event.currentTarget, `edit-memory-${editingMemory.id}`)} onSubmit={submitMemoryEdit}>
                <h2>Edit context</h2>
                <Field label="Edit title" name="title" defaultValue={textDrafts.current.get(`edit-memory-${editingMemory.id}`)?.title ?? editingMemory.title} disabled={!!saving} />
                <Field label="Edit context" name="body" defaultValue={textDrafts.current.get(`edit-memory-${editingMemory.id}`)?.body ?? editingMemory.bodyMarkdown} multiline disabled={!!saving} />
                <button className="primary-action" type="submit" disabled={!!saving || projectBusy || connectionState !== 'ready'}>{saving === 'memory-edit' ? 'Saving changes…' : 'Update context'}</button>
                <button className="secondary-action" disabled={!!saving} onClick={() => setEditingMemory(null)} type="button">Cancel edit</button>
              </form>
            )}
            {!creatingContext && !editingMemory && <p className="empty-message">Select Edit beside a note to review or change it, or choose Add context.</p>}
            </div><div className="work-list">
            <SearchProgress progress={searchProgress} />
            <RecordList title="Saved context" tools={<form key={searchProjectId ?? 'global'} aria-label="Context search" role="search" className="inline-form" onSubmit={searchMemory}>
                <label htmlFor="memory-query">Search saved context</label>
                <input id="memory-query" name="query" type="search" disabled={!!saving} />
                <button className="secondary-action" type="submit" disabled={!!saving}>Search</button>
              </form>}>
              {memories.length === 0 && <li className="empty-message">Saved notes will appear here. Choose Add context to save a decision, preference or project fact.</li>}
              {memories.map((memory) => (
                <li className="record-card" key={memory.id}>
                  <h3>{memory.title}</h3>
                  <p>{memory.bodyMarkdown}</p>
                  <button aria-label={`Edit ${memory.title}`} disabled={!!saving} onClick={() => { setCreatingContext(false); setEditingMemory(memory); }} type="button">Edit</button>
                  <button aria-label={`Archive ${memory.title}`} disabled={!!saving || projectBusy || connectionState !== 'ready'} onClick={(event) => openArchive(memory, event.currentTarget)} type="button">Archive</button>
                </li>
              ))}
            </RecordList></div>
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
          <section className="screen-content workbench"><div className="work-detail">
            <form key={'task-' + activeProject.projectId} aria-describedby={error ? 'workspace-error' : undefined} aria-label="New task" className="capture-form" hidden={!creatingTask} onChange={event => rememberDraft(event.currentTarget, `task-${draftScope}`)} onSubmit={submitTask}>
              <h2>New task</h2>
              <p>Write down the next piece of work so you or your harness can pick it up later.</p>
              <Field label="Task title" name="title" defaultValue={textDrafts.current.get(`task-${draftScope}`)?.title} disabled={!!saving} placeholder="For example, Fix the sign-in page" />
              <Field label="Task details" name="body" defaultValue={textDrafts.current.get(`task-${draftScope}`)?.body} multiline disabled={!!saving} />
              <button className="primary-action" type="submit" disabled={!!saving || projectBusy || connectionState !== 'ready'}>{saving === 'task' ? 'Saving…' : 'Save task'}</button>
            </form>
            {editingTask && (
              <form key={editingTask.id} aria-describedby={error ? 'workspace-error' : undefined} aria-label="Edit task" className="capture-form edit-form" onChange={event => rememberDraft(event.currentTarget, `edit-task-${editingTask.id}`)} onSubmit={submitTaskEdit}>
                <h2>Edit task</h2>
                <Field label="Edit task title" name="title" defaultValue={textDrafts.current.get(`edit-task-${editingTask.id}`)?.title ?? editingTask.title} disabled={!!saving} />
                <Field label="Edit task details" name="body" defaultValue={textDrafts.current.get(`edit-task-${editingTask.id}`)?.body ?? editingTask.bodyMarkdown} multiline disabled={!!saving} />
                <button className="primary-action" type="submit" disabled={!!saving || projectBusy || connectionState !== 'ready'}>{saving === 'task-edit' ? 'Saving changes…' : 'Update task'}</button>
              </form>
            )}
            {!creatingTask && !editingTask && <p className="empty-message">Select Edit beside a task to review its details, or choose New task.</p>}
            </div><div className="work-list"><RecordList title="Tasks">
              {tasks.length === 0 && <li className="empty-message">No tasks yet. Choose New task to save work you want to continue later.</li>}
              {tasks.map((task) => (
                <li className="record-card" key={task.id}>
                  <h3>{task.title}</h3>
                  <p>{task.bodyMarkdown}</p>
                  <p className="state-label">{task.status === 'done' ? 'Done' : task.status.replace('_', ' ')}</p>
                  <button aria-label={`Edit ${task.title}`} disabled={!!saving} onClick={() => { setCreatingTask(false); setEditingTask(task); }} type="button">Edit</button>
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
            </RecordList></div>
          </section>
        );
      case 'harnesses':
        return null;
      case 'devices':
        return <DevicesScreen gateway={gateway} />;
      case 'settings':
        return (
          <section className="screen-content">
            <HostedSignIn gateway={gateway} />
            <h2>Appearance</h2>
            <div className="field"><label htmlFor="appearance-theme">Theme</label><select id="appearance-theme" value={preferences.theme} onChange={event => updatePreferences(current => ({ ...current, theme: event.target.value as Theme }))}><option value="dark">Dark</option><option value="light">Light</option><option value="system">System</option></select><p>System follows your computer’s appearance setting.</p></div>
            <h2>Devices</h2><p>Review the devices allowed to access this workspace.</p><button type="button" onClick={() => void selectScreen('devices')}>Manage devices</button>
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

  if (showSetup && connectionState === 'ready') return <>
    {preferenceError && <p className="form-error" role="alert">{preferenceError}</p>}
    {error && <p className="form-error" role="alert">{error}</p>}
    <SetupWizard gateway={gateway} projects={projects} progress={preferences.setup}
      onChange={next => { if (next.projectId !== preferences.setup.projectId) { setTestVerified(false); const project = projects.find(item => item.projectId === next.projectId); if (project || next.projectId === null) transitionProject(project ?? null); } updateSetup(next); }}
      onProjectSaved={project => { setProjects(current => current.some(item => item.projectId === project.projectId) ? current : [...current, project]); transitionProject(project); }}
      onFinishLater={() => updateSetup({ ...preferences.setup, status: 'deferred' })}
      onTour={() => { updateSetup({ ...preferences.setup, status: 'complete', step: 'tour' }); startTour(); }} onSkipTour={() => { updateSetup({ ...preferences.setup, status: 'complete' }); void selectScreen('home'); }}
      onOpenGuide={harness => { void openHarnessGuide(harness).catch(() => setError('The installation guide could not open. Check your default browser and try again.')); }}
      renderConnection={(project, harness) => <HarnessesScreen gateway={gateway} projects={projects} preferredProjectId={project.projectId} preferredHarness={harness} preferredHermesProfile={preferences.setup.hermesProfile} onProfileChange={hermesProfile => { setTestVerified(false); updatePreferences(current => ({ ...current, setup: { ...current.setup, hermesProfile, checkId: null } })); }} embedded onBusy={setSetupBusy} />}
      renderTest={(project, harnesses) => <ConnectionTest key={project.projectId} gateway={gateway} project={project} harnesses={harnesses} hermesProfile={preferences.setup.hermesProfile} noteId={preferences.setup.noteId} checkId={preferences.setup.checkId}
        initialHarness={preferences.setup.testHarness} onProgress={(noteId, checkId, testHarness) => updatePreferences(current => ({ ...current, setup: { ...current.setup, noteId, checkId, testHarness } }))}
        onVerified={setTestVerified} onReceipt={receipt => { if (receipt.verifiedAt && receipt.selection.projectId) updatePreferences(current => ({ ...current, lastVerifiedRead: { harness: receipt.selection.harness, projectId: receipt.selection.projectId!, checkId: receipt.checkId, verifiedAt: receipt.verifiedAt! } })); }} onBusy={setSetupBusy} onDone={() => { setSetupBusy(false); updatePreferences(current => ({ ...current, setup: { ...current.setup, step: 'tour' } })); }} onOpenHarness={openHarness} onCopyPrompt={prompt => navigator.clipboard.writeText(prompt)} />}
      testComplete={testVerified} operationBusy={setupBusy} />
  </>;

  return (
    <>
      <a className="skip-link" href="#workspace-main">Skip to workspace</a>
      <div className="app-shell">
        <aside className="sidebar">
          <div className="brand-block">
            <p className="brand-name">Context Relay</p>
            <p>Context for your harnesses</p>
<span className="help-text" role="status">{connectionState === 'ready' ? status?.vault === 'unlocked' ? 'Ready on this computer' : 'Workspace locked' : connectionState === 'connecting' ? 'Opening workspace…' : 'Service unavailable'}</span>
          </div>
          <nav aria-label="Workspace">
            {NAV_GROUPS.map((group) => <div className="nav-group" key={group.label} role="group" aria-label={group.label}>
              <p className="nav-group-label">{group.label}</p>
              {group.screens.map(id => SCREENS.find(screen => screen.id === id)!).map((screen) => (
              <button
                aria-current={activeScreen === screen.id || activeScreen === 'review' && screen.id === 'memory' ? 'page' : undefined}
                key={screen.id}
                disabled={!!saving || projectBusy}
                onClick={() => void selectScreen(screen.id)}
                type="button"
              >
                <WorkspaceIcon name={screen.id} />{screen.label}
              </button>
              ))}
            </div>)}
          </nav>
        </aside>
        <main id="workspace-main">
          <header className="app-toolbar">
            <h1 ref={headingRef} tabIndex={-1}>{currentScreen.label}</h1>

            {activeScreen === 'memory' && <button type="button" className="primary-action" disabled={!!saving} onClick={() => { setEditingMemory(null); setCreatingContext(true); }}>Add context</button>}
            {activeScreen === 'tasks' && activeProject && <button type="button" className="primary-action" disabled={!!saving} onClick={() => { setEditingTask(null); setCreatingTask(true); }}>New task</button>}
            {projects.length > 0 && <div className="field project-switcher">
              <label htmlFor="active-project">Current project</label>
              <select id="active-project" value={activeProject?.projectId ?? ''} disabled={!!saving || projectBusy} onChange={(event) => {
                const project = projects.find((item) => item.projectId === event.target.value);
                if (project) selectProject(project);
              }}><option value="">Choose a project</option>{projects.map((project) => <option key={project.projectId} value={project.projectId}>{project.name}</option>)}</select>
            </div>}
          </header>
          <div className="workspace-content">
          <p className="help-text">{currentScreen.summary}</p>
          {preferenceError && <p role="alert" className="form-error">{preferenceError}</p>}
          {tourStep !== null && <DashboardTour step={tourStep} onStep={setTourStep} onNavigate={screen => void selectScreen(screen)} onClose={() => { setTourStep(null); updatePreferences(current => ({ ...current, tourCompleted: true })); }} />}
          {(activeScreen === 'memory' || activeScreen === 'review') && <div className="context-tabs" role="group" aria-label="Context views"><button type="button" aria-pressed={activeScreen === 'memory'} onClick={() => void selectScreen('memory')}>Saved</button><button type="button" aria-pressed={activeScreen === 'review'} onClick={() => void selectScreen('review')}>Suggestions</button></div>}
          {connectionState === 'failed' && (
            <div className="form-error" role="alert">
              <p>{serviceVersionMismatch ? SERVICE_UPDATE_GUIDANCE : 'Could not connect to the local workspace. Retry the connection to continue.'}</p>
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
              if (project) selectProject(project);
            }} onAddProject={() => void selectScreen('projects')} onSaveContext={() => { setCreatingContext(true); setEditingMemory(null); void selectScreen('memory'); }} active={activeScreen === 'harnesses'} />
          </div>
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

function replaceRecord<T extends { id: string; revision: string }>(records: T[], replacement: T, expectedRevision: string) {
  // Replayed operations return their original snapshot. Preserve any version
  // that a newer read already placed on screen until the fresh list arrives.
  return records.map((record) => record.id === replacement.id &&
    (record.revision === expectedRevision || record.revision === replacement.revision) ? replacement : record);
}
