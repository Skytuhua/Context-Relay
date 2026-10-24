import { useRef, useState } from 'react';
import type { ProjectIdentity } from './bindings';
import type { WorkspaceGateway } from './workspace';

export function ProjectFolderBinding({ gateway, project, ready, onBusy }: {
  gateway: WorkspaceGateway;
  project: ProjectIdentity;
  ready: boolean;
  onBusy: (busy: boolean) => void;
}) {
  const [busy, setBusy] = useState(false);
  const busyRef = useRef(false);
  const [path, setPath] = useState<string | null>(null);
  const [error, setError] = useState(false);

  async function choose() {
    if (!ready || busyRef.current) return;
    busyRef.current = true;
    setBusy(true);
    onBusy(true);
    setError(false);
    try {
      const selected = await gateway.chooseProjectFolder();
      if (selected === null) return;
      await gateway.bindProjectFolder(project.projectId, selected);
      setPath(selected);
    } catch {
      setError(true);
    } finally {
      busyRef.current = false;
      setBusy(false);
      onBusy(false);
    }
  }

  return <div>
    <button className="secondary-action" type="button" aria-label={`Choose local folder for ${project.name}`} disabled={!ready || busy} onClick={() => void choose()}>{busy ? 'Saving local folder…' : 'Choose local folder…'}</button>
    {path && <><p className="native-path">{path}</p><p role="status">Local folder saved. Review harness setup for this folder.</p></>}
    {error && <p className="form-error" role="alert">The local folder could not be saved. Choose an accessible folder that is not assigned to another project, then retry.</p>}
  </div>;
}
