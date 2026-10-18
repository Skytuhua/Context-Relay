import { useEffect, useRef, useState } from 'react';
import type { OpenCodeMcpExport, ProjectId, ProjectIdentity } from './bindings';
import { ConnectionTest, type ConnectionTestGateway } from './connection-test';
import { openHarnessGuide } from './harness-launch';
import { validateOpenCodeMcpExport } from './protocol-validation';

export type OpenCodeMcpGateway = ConnectionTestGateway & {
  opencodeMcpExport(projectId: ProjectId): Promise<OpenCodeMcpExport>;
};

const ignoreVerification = () => {};

export function OpenCodeMcpSetup({ gateway, project, disabled = false, onBusy }: {
  gateway: OpenCodeMcpGateway; project: ProjectIdentity; disabled?: boolean; onBusy?: (busy: boolean) => void;
}) {
  const [exported, setExported] = useState<OpenCodeMcpExport | null>(null);
  const [preparing, setPreparing] = useState(false);
  const [testBusy, setTestBusy] = useState(false);
  const [testing, setTesting] = useState(false);
  const [progress, setProgress] = useState<{ noteId: string | null; checkId: string | null }>({ noteId: null, checkId: null });
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const generation = useRef(0);
  const pending = useRef(false);
  const busy = preparing || testBusy;
  useEffect(() => { onBusy?.(busy); }, [busy, onBusy]);
  useEffect(() => () => onBusy?.(false), [onBusy]);
  useEffect(() => {
    generation.current += 1;
    pending.current = false; setPreparing(false); setTestBusy(false);
    setExported(null); setTesting(false); setProgress({ noteId: null, checkId: null }); setError(null); setNotice(null);
    return () => { generation.current += 1; };
  }, [project.projectId, gateway]);

  async function prepare() {
    if (disabled || busy || pending.current) return;
    pending.current = true;
    const revision = generation.current;
    setPreparing(true); setExported(null); setError(null); setNotice(null);
    try {
      const result = validateOpenCodeMcpExport(await gateway.opencodeMcpExport(project.projectId));
      if (revision !== generation.current) return;
      if (result.projectId !== project.projectId) throw new Error('OpenCode export does not match the selected project.');
      setExported(result);
    } catch (failure) {
      if (revision === generation.current) {
        const serviceMessage = failure && typeof failure === 'object' && 'code' in failure &&
          failure.code === 'invalid_request' && 'message' in failure && typeof failure.message === 'string'
          ? failure.message : null;
        setError(serviceMessage ?? 'OpenCode configuration could not be prepared. Check that the local service, installed MCP bridge, and registered project folder are available, then try again.');
      }
    } finally {
      if (revision === generation.current) { pending.current = false; setPreparing(false); }
    }
  }

  async function copy(value: string, label: string) {
    const revision = generation.current;
    try {
      await navigator.clipboard.writeText(value);
      if (revision === generation.current) setNotice(`${label} copied. Save and review it in your project. Copying does not verify a connection.`);
    } catch {
      if (revision === generation.current) setError('The clipboard is unavailable. Select and copy the text shown below.');
    }
  }

  return <section className="help-content" aria-label="OpenCode MCP setup">
    <h2>OpenCode · manual MCP setup</h2>
    <p>Connect OpenCode to saved context for <strong>{project.name}</strong>. Context Relay prepares project-specific configuration for your installed MCP bridge; you review and save the files yourself.</p>
    <p className="help-text">This supports MCP tools and a saved-context read test. Automatic memory import, memory settings, lifecycle hooks, and managed Undo are unavailable.</p>
    <div className="toolbar-actions">
      <button type="button" disabled={disabled || busy} onClick={() => void prepare()}>{preparing ? 'Checking OpenCode project files…' : 'Prepare OpenCode configuration'}</button>
      <button type="button" className="secondary-action" onClick={() => void openHarnessGuide('opencode').catch(() => setError('The installation guide could not be opened. Visit opencode.ai/docs in your browser.'))}>OpenCode installation guide</button>
    </div>
    {error && <p className="form-error" role="alert">{error}</p>}
    {notice && <p role="status">{notice}</p>}
    {exported && exported.projectId === project.projectId && <>
      <p className="native-path">Project folder: {exported.projectRoot.display ?? project.name}</p>
      <ol>
        <li>Open <code>{exported.configPath.display ?? 'opencode.json or opencode.jsonc in this project'}</code>. For a new file, use the fragment below as its contents. For an existing file, merge only <code>mcp.context-relay</code> into its MCP object and append <code>.context-relay-opencode.md</code> to its existing <code>instructions</code> array once. Keep other servers, settings, comments, and instruction paths.</li>
        <li>Save the instruction text below to <code>{exported.instructionPath.display ?? '.context-relay-opencode.md in this project'}</code>. Keep your existing <code>AGENTS.md</code> and <code>CLAUDE.md</code> content.</li>
        <li>Open your installed OpenCode CLI in this project folder and run <code>opencode mcp list</code> to inspect the server. Complete any OpenCode sign-in, trust, or tool approvals. Keep Context Relay running.</li>
        <li>Use the saved-context test below to confirm that OpenCode can read this project's context.</li>
      </ol>
      <label htmlFor="opencode-config">Project MCP fragment</label>
      <textarea id="opencode-config" readOnly value={exported.configFragment} rows={14} spellCheck={false} />
      <button type="button" className="secondary-action" disabled={disabled || busy} onClick={() => void copy(exported.configFragment, 'MCP fragment')}>Copy MCP fragment</button>
      <label htmlFor="opencode-instructions">Context Relay instructions for OpenCode</label>
      <textarea id="opencode-instructions" readOnly value={exported.instructionMarkdown} rows={6} spellCheck={false} />
      <button type="button" className="secondary-action" disabled={disabled || busy} onClick={() => void copy(exported.instructionMarkdown, 'Instructions')}>Copy instructions</button>
      <details><summary>Scope, troubleshooting, and removal</summary>
        <p>The 60-second MCP timeout allows for local service startup and recovery. OpenCode's other configuration layers and access policies can affect the final settings; this export does not inspect or approve those layers. Restart OpenCode after saving and recheck its MCP status if the tools are missing.</p>
        <p>Use OpenCode on the same operating system as Context Relay. A Windows export cannot launch a bridge inside WSL. If these project files change, prepare a fresh export before merging.</p>
        <p>To remove this connection, review and remove only the <code>context-relay</code> MCP entry, its instruction-array entry, and the dedicated instruction file. This manual configuration has no Context Relay setup receipt or automatic Undo.</p>
      </details>
      {!testing && <button type="button" className="primary-action" disabled={disabled || busy} onClick={() => setTesting(true)}>Test OpenCode with saved context</button>}
    </>}
    {testing && <ConnectionTest key={project.projectId} gateway={gateway} project={project} harnesses={['opencode']}
      noteId={progress.noteId} checkId={progress.checkId} onProgress={(noteId, checkId) => setProgress({ noteId, checkId })}
      onVerified={ignoreVerification} onBusy={setTestBusy} onOpenHarness={ignoreVerification}
      onCopyPrompt={prompt => navigator.clipboard.writeText(prompt)} />}
  </section>;
}
