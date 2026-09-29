import type { HarnessSetupSummary, PlanId } from './bindings';
import type { HarnessGateway } from './harness-gateway';

/** Read-only history, not evidence that a harness can retrieve context. */
export async function projectHarnessSetups(
  gateway: Pick<HarnessGateway, 'harnessSetupsList'>,
  projectId: string,
  signal?: AbortSignal,
): Promise<HarnessSetupSummary[]> {
  const latest = new Map<string, HarnessSetupSummary>();
  let cursor: PlanId | null = null;
  const seen = new Set<PlanId>();
  do {
    signal?.throwIfAborted();
    const page = await gateway.harnessSetupsList(cursor);
    signal?.throwIfAborted();
    for (const record of page.setups) {
      if (!record.targetScopes.some(scope => scope.scope === 'global' || scope.projectId === projectId)) continue;
      const key = `${record.harness}:${record.harnessProfile ?? ''}`;
      const previous = latest.get(key);
      if (!previous || record.planId.localeCompare(previous.planId) > 0) latest.set(key, record);
    }
    // Filtering inverse or unrelated plans can produce an empty page with a
    // continuation cursor. Only the cursor determines whether reading is done.
    cursor = page.nextAfter;
    if (cursor !== null) {
      if (seen.has(cursor)) throw new Error('Setup history did not advance.');
      seen.add(cursor);
    }
  } while (cursor !== null);
  return [...latest.values()].sort((a, b) => b.planId.localeCompare(a.planId));
}
