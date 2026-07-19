import { type FormEvent, useEffect, useRef, useState } from 'react';

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
  { id: 'home', label: 'Home', summary: 'See what is available in this local build.' },
  { id: 'projects', label: 'Projects', summary: 'Bind trusted repositories to local context.' },
  { id: 'memory', label: 'Memory', summary: 'Capture durable context for later sessions.' },
  { id: 'review', label: 'Review queue', summary: 'Approve or reject proposed memories.' },
  { id: 'tasks', label: 'Tasks', summary: 'Track work with durable evidence.' },
  { id: 'harnesses', label: 'Harnesses', summary: 'Inspect supported local AI harnesses.' },
  { id: 'packages', label: 'Packages', summary: 'Review portable Context Relay packages.' },
  { id: 'activity', label: 'Activity', summary: 'Audit local operations and sync outcomes.' },
  { id: 'devices', label: 'Devices', summary: 'Manage trusted devices and recovery.' },
  {
    id: 'settings',
    label: 'Settings',
    summary: 'Review local security and application settings.',
  },
];

type MemoryFormError = 'title-required' | 'body-required' | 'service-unavailable' | null;
type TaskFormError = 'title-required' | 'service-unavailable' | null;

const SERVICE_UNAVAILABLE = 'This service is not available in this build';

export default function App() {
  const [activeScreen, setActiveScreen] = useState<ScreenId>('home');
  const [memoryFormError, setMemoryFormError] = useState<MemoryFormError>(null);
  const [taskFormError, setTaskFormError] = useState<TaskFormError>(null);
  const hasNavigatedRef = useRef(false);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const dialogRef = useRef<HTMLDialogElement>(null);
  const dialogTriggerRef = useRef<HTMLButtonElement>(null);
  const currentScreen = SCREENS.find((screen) => screen.id === activeScreen);

  useEffect(() => {
    if (hasNavigatedRef.current) {
      headingRef.current?.focus();
    }
  }, [activeScreen]);

  if (!currentScreen) {
    return null;
  }

  function selectScreen(screen: ScreenId) {
    hasNavigatedRef.current = true;
    setActiveScreen(screen);
  }

  function submitMemory(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);
    const title = String(formData.get('title') ?? '').trim();
    const body = String(formData.get('body') ?? '').trim();

    if (!title) {
      setMemoryFormError('title-required');
      return;
    }
    if (!body) {
      setMemoryFormError('body-required');
      return;
    }
    setMemoryFormError('service-unavailable');
  }

  function submitTask(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);
    const title = String(formData.get('title') ?? '').trim();

    if (!title) {
      setTaskFormError('title-required');
      return;
    }
    setTaskFormError('service-unavailable');
  }

  function openSecurityDetails(trigger: HTMLButtonElement) {
    dialogTriggerRef.current = trigger;
    dialogRef.current?.showModal();
  }

  function restoreDialogFocus() {
    dialogTriggerRef.current?.focus();
  }

  function renderScreen(screen: ScreenId) {
    switch (screen) {
      case 'home':
        return (
          <section className="screen-content" aria-labelledby="home-status-title">
            <h2 id="home-status-title">Local workspace posture</h2>
            <p role="status">
              The encrypted daemon boundary is local to this device. Full workspace services are
              still arriving.
            </p>
            <ul aria-label="Local capability status">
              <li>Project path identification is available through the local daemon boundary.</li>
              <li>Single-memory reads are available through the local daemon boundary.</li>
              <li>Full workspace services remain deferred in this build.</li>
            </ul>
          </section>
        );
      case 'projects':
        return (
          <section className="deferred-state">
            <h2>Trusted project binding</h2>
            <p>
              Project binding will connect trusted repositories when the project lifecycle service
              arrives.
            </p>
          </section>
        );
      case 'memory':
        return (
          <section className="screen-content">
            <form
              aria-labelledby="new-memory-title"
              className="capture-form"
              noValidate
              onSubmit={submitMemory}
            >
              <h2 id="new-memory-title">New memory</h2>
              <p>Keep the text in this form until signed local writes are available.</p>
              <div className="field">
                <label htmlFor="memory-title">Title</label>
                <input
                  aria-describedby={
                    memoryFormError === 'title-required' ? 'memory-title-error' : undefined
                  }
                  aria-invalid={memoryFormError === 'title-required' ? true : undefined}
                  id="memory-title"
                  name="title"
                  required
                  type="text"
                />
                {memoryFormError === 'title-required' && (
                  <p className="field-error" id="memory-title-error" role="alert">
                    Enter a title.
                  </p>
                )}
              </div>
              <div className="field">
                <label htmlFor="memory-body">Memory</label>
                <textarea
                  aria-describedby={
                    memoryFormError === 'body-required' ? 'memory-body-error' : undefined
                  }
                  aria-invalid={memoryFormError === 'body-required' ? true : undefined}
                  id="memory-body"
                  name="body"
                  required
                  rows={7}
                />
                {memoryFormError === 'body-required' && (
                  <p className="field-error" id="memory-body-error" role="alert">
                    Enter memory text.
                  </p>
                )}
              </div>
              <button className="primary-action" type="submit">
                Save memory
              </button>
              {memoryFormError === 'service-unavailable' && (
                <p className="form-error" role="alert">
                  {SERVICE_UNAVAILABLE}
                </p>
              )}
            </form>
          </section>
        );
      case 'review':
        return (
          <section className="deferred-state">
            <h2>Candidate review</h2>
            <p>Memory candidates will appear after the local review service is available.</p>
          </section>
        );
      case 'tasks':
        return (
          <section className="screen-content">
            <form
              aria-labelledby="new-task-title"
              className="capture-form"
              noValidate
              onSubmit={submitTask}
            >
              <h2 id="new-task-title">New task</h2>
              <p>Keep the task title in this form until durable signed writes are available.</p>
              <div className="field">
                <label htmlFor="task-title">Task title</label>
                <input
                  aria-describedby={
                    taskFormError === 'title-required' ? 'task-title-error' : undefined
                  }
                  aria-invalid={taskFormError === 'title-required' ? true : undefined}
                  id="task-title"
                  name="title"
                  required
                  type="text"
                />
                {taskFormError === 'title-required' && (
                  <p className="field-error" id="task-title-error" role="alert">
                    Enter a task title.
                  </p>
                )}
              </div>
              <button className="primary-action" type="submit">
                Save task
              </button>
              {taskFormError === 'service-unavailable' && (
                <p className="form-error" role="alert">
                  {SERVICE_UNAVAILABLE}
                </p>
              )}
            </form>
          </section>
        );
      case 'harnesses':
        return (
          <section className="deferred-state">
            <h2>Local harness support</h2>
            <p>Harness inspection will appear when local discovery is connected.</p>
          </section>
        );
      case 'packages':
        return (
          <section className="deferred-state">
            <h2>Portable context packages</h2>
            <p>Package review will be available when portable package services are connected.</p>
          </section>
        );
      case 'activity':
        return (
          <section className="deferred-state">
            <h2>Local audit activity</h2>
            <p>Operation and sync outcomes will appear after the audit service is connected.</p>
          </section>
        );
      case 'devices':
        return (
          <section className="deferred-state">
            <h2>Trusted device management</h2>
            <p>Device trust and recovery controls will arrive with the device service.</p>
          </section>
        );
      case 'settings':
        return (
          <section className="screen-content">
            <h2>Local security posture</h2>
            <dl className="security-facts">
              <div>
                <dt>Endpoint access</dt>
                <dd>The daemon endpoint uses per-user operating system permissions.</dd>
              </div>
              <div>
                <dt>Credential ownership</dt>
                <dd>The operating system credential store owns tokens outside React.</dd>
              </div>
            </dl>
            <button
              className="secondary-action"
              onClick={(event) => openSecurityDetails(event.currentTarget)}
              type="button"
            >
              Security details
            </button>
            <dialog
              aria-labelledby="security-dialog-title"
              onCancel={(event) => {
                event.preventDefault();
                dialogRef.current?.close();
              }}
              onClose={restoreDialogFocus}
              ref={dialogRef}
            >
              <h2 id="security-dialog-title">Local security details</h2>
              <p>The daemon endpoint is limited by per-user operating system permissions.</p>
              <p>The operating system credential store owns tokens outside React.</p>
              <p>Malware running as the same user is outside the v1 threat model.</p>
              <button
                className="primary-action"
                onClick={() => dialogRef.current?.close()}
                type="button"
              >
                Close security details
              </button>
            </dialog>
          </section>
        );
      default: {
        const unreachable: never = screen;
        return unreachable;
      }
    }
  }

  return (
    <>
      <a className="skip-link" href="#workspace-main">
        Skip to workspace
      </a>
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
                onClick={() => selectScreen(screen.id)}
                type="button"
              >
                {screen.label}
              </button>
            ))}
          </nav>
        </aside>
        <main id="workspace-main">
          <header className="screen-header">
            <h1 ref={headingRef} tabIndex={-1}>
              {currentScreen.label}
            </h1>
            <p>{currentScreen.summary}</p>
          </header>
          {renderScreen(activeScreen)}
        </main>
      </div>
    </>
  );
}
