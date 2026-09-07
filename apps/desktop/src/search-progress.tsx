import type { useSearchProgress } from './use-search-progress';

export function SearchProgress({ progress }: { progress: ReturnType<typeof useSearchProgress> }) {
  const { status, unavailable, retrying, retry } = progress;
  if (unavailable) return <p role="status">Search progress is unavailable. You can still try a search; progress will reconnect automatically.</p>;
  if (!status || status.phase === 'disabled') return null;
  return <div className="search-progress">
    <p role="status">{status.phase === 'preparing'
      ? 'Preparing search across your saved context. Keyword results are available while this finishes.'
      : status.phase === 'ready' ? 'Search is ready.'
        : 'Search preparation stopped. Your saved context is safe. Retry to continue where it stopped.'}</p>
    {(status.phase === 'failed' || retrying) && <button className="secondary-action" type="button" disabled={retrying} onClick={() => void retry()}>
      {retrying ? 'Retrying…' : 'Retry search preparation'}
    </button>}
  </div>;
}
