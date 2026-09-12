import { useEffect, useRef, useState } from 'react';
import type { SearchIndexStatus } from './bindings';
import type { WorkspaceGateway } from './workspace';

export function useSearchProgress(gateway: WorkspaceGateway, active: boolean) {
  const [status, setStatus] = useState<SearchIndexStatus | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const [retrying, setRetrying] = useState(false);
  const retryPending = useRef(false);
  const generation = useRef(0);
  const requestVersion = useRef(0);

  useEffect(() => {
    const current = ++generation.current;
    setStatus(null);
    setUnavailable(false);
    setRetrying(false);
    retryPending.current = false;
    if (!active) return;
    let inFlight = false;
    async function poll() {
      if (inFlight || retryPending.current) return;
      inFlight = true;
      const version = ++requestVersion.current;
      try {
        const next = await gateway.searchIndexStatus();
        if (current !== generation.current || version !== requestVersion.current) return;
        setStatus(next);
        setUnavailable(false);
      } catch {
        if (current === generation.current && version === requestVersion.current) setUnavailable(true);
      } finally { inFlight = false; }
    }
    void poll();
    const timer = setInterval(() => void poll(), 1000);
    return () => { generation.current += 1; clearInterval(timer); };
  }, [gateway, active]);

  async function retry() {
    if (!active || retryPending.current) return;
    retryPending.current = true;
    setRetrying(true);
    const current = generation.current;
    ++requestVersion.current;
    try {
      const next = await gateway.searchIndexRetry();
      if (current !== generation.current) return;
      setStatus(next);
      setUnavailable(false);
    } catch {
      if (current === generation.current) setUnavailable(true);
    } finally {
      if (current === generation.current) {
        retryPending.current = false;
        setRetrying(false);
      }
    }
  }
  return { status, unavailable, retrying, retry };
}
