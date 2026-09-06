import { useRef, useState } from 'react';
import type { FormEvent } from 'react';
import type { ProjectIdentity } from './bindings';
import type { WorkspaceGateway } from './workspace';

export function ProjectForm({ gateway, ready, onSaved, onBusy }: {
  gateway: WorkspaceGateway;
  ready: boolean;
  onSaved: (project: ProjectIdentity) => void;
  onBusy: (busy: boolean) => void;
}) {
  const [name, setName] = useState('');
  const [path, setPath] = useState('');
  const [busy, setBusy] = useState<'folder' | 'save' | null>(null);
  const busyRef = useRef(false);
  const [error, setError] = useState<string | null>(null);

  async function chooseFolder() {
    if (busyRef.current) return;
    busyRef.current = true;
    onBusy(true);
    setBusy('folder');
    setError(null);
    try {
      const selected = await gateway.chooseProjectFolder();
      if (selected !== null) {
        setPath(selected);
        setName((current) => current || selected.replace(/[\\/]+$/, '').split(/[\\/]/).at(-1) || 'My project');
      }
    } catch {
      setError('The folder picker could not open. You can paste the full folder path below.');
    } finally {
      busyRef.current = false;
      onBusy(false);
      setBusy(null);
    }
  }

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busyRef.current || !ready) return;
    if (!name.trim() || !path.trim()) return setError('Choose a folder and give your project a name.');
    busyRef.current = true;
    onBusy(true);
    setBusy('save');
    setError(null);
    try {
      const project = await gateway.createProject(name.trim(), path.trim());
      onSaved(project);
      setName('');
      setPath('');
    } catch {
      setError('We could not finish adding this project. Check that the folder exists and is accessible. Your entries are still here.');
    } finally {
      busyRef.current = false;
      onBusy(false);
      setBusy(null);
    }
  }

  return <form aria-label="Add project" aria-describedby={error ? 'project-error' : 'project-help'} className="capture-form" onSubmit={save}>
    <h2>Add a project folder</h2>
    <p id="project-help">Choose the folder where you work with your harness. Context Relay keeps its saved context and tasks together.</p>
    <button className="secondary-action" type="button" disabled={!!busy} onClick={() => void chooseFolder()}>{busy === 'folder' ? 'Choosing folder…' : 'Choose folder…'}</button>
    <div className="field">
      <label htmlFor="project-folder">Project folder</label>
      <input id="project-folder" name="path" value={path} disabled={!!busy} onChange={(event) => setPath(event.target.value)} required placeholder="Choose a folder or paste its full path" />
    </div>
    <div className="field">
      <label htmlFor="project-name">Project name</label>
      <input id="project-name" name="name" value={name} disabled={!!busy} onChange={(event) => setName(event.target.value)} required placeholder="For example, My website" />
    </div>
    {!ready && <p>Connect to the local workspace before adding the project.</p>}
    {error && <p id="project-error" className="form-error" role="alert">{error}</p>}
    <button className="primary-action" type="submit" disabled={!!busy || !ready}>{busy === 'save' ? 'Adding project…' : 'Add project'}</button>
  </form>;
}
