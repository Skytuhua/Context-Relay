import { useCallback, useEffect, useRef, useState } from 'react';
import type { HostedAuthStartParams, HostedAuthStatus, OperationId } from './bindings';
import type { WorkspaceGateway } from './workspace';
import { uuidV7 } from './uuid';

type Gateway = Pick<WorkspaceGateway, 'hostedAuthStatus' | 'hostedAuthStart' | 'hostedAuthCancel' | 'hostedAuthLogout'>;
type Action = 'start' | 'cancel' | 'logout';

function description(state: HostedAuthStatus['state']): string {
  switch (state.phase) {
    case 'disabled': return 'Cloud sign-in is not available in this build.';
    case 'signed_out': return state.remoteRevoked === false
      ? 'Signed out on this computer. Ending the online session could not be confirmed.'
      : state.remoteRevoked === true ? 'Signed out on this computer and ended this session online.' : 'Signed out.';
    case 'signing_in': return 'Finish signing in with GitHub in your browser.';
    case 'restoring': return 'Restoring saved sign-in…';
    case 'connected': return 'Signed in on this computer.';
    case 'signing_out': return 'Signing out on this computer…';
    case 'failed': return {
      unavailable: 'Sign-in is temporarily unavailable. Check your connection or try again.',
      denied: 'Sign-in was declined. You can try again.',
      expired: 'Your sign-in has expired. Sign in again to reconnect.',
      credential_store: 'Your computer could not securely access sign-in credentials. Check your system account and try again.',
    }[state.reason];
  }
}

export function HostedSignIn({ gateway }: { gateway: Gateway }) {
  const [status, setStatus] = useState<HostedAuthStatus | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const [busy, setBusy] = useState<Action | null>(null);
  const busyRef = useRef(false);
  const epoch = useRef(0);
  const requestVersion = useRef(0);
  const pendingStart = useRef<HostedAuthStartParams | null>(null);
  const accept = useCallback((next: HostedAuthStatus) => {
    if (pendingStart.current && next.generation !== pendingStart.current.expectedGeneration) pendingStart.current = null;
    setStatus(next);
    setUnavailable(false);
  }, []);

  useEffect(() => {
    const current = ++epoch.current;
    setStatus(null);
    setUnavailable(false);
    setBusy(null);
    busyRef.current = false;
    pendingStart.current = null;
    let inFlight = false;
    async function poll() {
      if (inFlight || busyRef.current) return;
      inFlight = true;
      const version = ++requestVersion.current;
      try {
        const next = await gateway.hostedAuthStatus();
        if (current === epoch.current && version === requestVersion.current) accept(next);
      } catch {
        if (current === epoch.current && version === requestVersion.current) setUnavailable(true);
      } finally { inFlight = false; }
    }
    void poll();
    const timer = setInterval(() => void poll(), 1000);
    return () => { epoch.current = current + 1; clearInterval(timer); };
  }, [gateway, accept]);

  async function act(action: Action) {
    if (!status || unavailable || busyRef.current) return;
    busyRef.current = true;
    setBusy(action);
    const current = epoch.current;
    ++requestVersion.current;
    try {
      let next: HostedAuthStatus;
      if (action === 'start') {
        pendingStart.current ??= { operationId: uuidV7() as OperationId, expectedGeneration: status.generation };
        next = await gateway.hostedAuthStart(pendingStart.current);
      } else if (action === 'cancel') next = await gateway.hostedAuthCancel(status.generation);
      else next = await gateway.hostedAuthLogout(status.generation);
      if (current !== epoch.current) return;
      if (action === 'start') pendingStart.current = null;
      accept(next);
    } catch {
      if (current === epoch.current) setUnavailable(true);
    } finally {
      if (current === epoch.current) { busyRef.current = false; setBusy(null); }
    }
  }

  const phase = status?.state.phase;
  const message = unavailable ? 'We could not confirm sign-in. Checking again…'
    : busy ? { start: 'Opening sign-in…', cancel: 'Canceling sign-in…', logout: 'Signing out on this computer…' }[busy]
      : status ? description(status.state) : 'Checking sign-in…';
  return <section aria-labelledby="cloud-account-title" aria-busy={busy !== null}>
    <h2 id="cloud-account-title">Cloud account</h2>
    <p role="status">{message}</p>
    {!unavailable && <div className="form-actions">
      {(phase === 'signed_out' || phase === 'failed') && <button type="button" className="primary-action" disabled={busy !== null} onClick={() => void act('start')}>Sign in with GitHub</button>}
      {phase === 'signing_in' && <button type="button" disabled={busy !== null} onClick={() => void act('cancel')}>Cancel sign-in</button>}
      {(phase === 'connected' || phase === 'restoring' || phase === 'failed') && <button type="button" disabled={busy !== null} onClick={() => void act('logout')}>Sign out</button>}
    </div>}
  </section>;
}
