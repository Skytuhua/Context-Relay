import type { HarnessId } from './bindings';

export const HARNESS_NAMES: Record<HarnessId, string> = { codex: 'Codex', claude_code: 'Claude Code', hermes: 'Hermes', opencode: 'OpenCode' };

/** Only these harnesses can satisfy the wizard's saved managed setup gate. */
export const MANAGED_HARNESS_IDS = ['codex', 'claude_code', 'hermes'] as const satisfies readonly HarnessId[];
export const isManagedHarness = (value: HarnessId): value is typeof MANAGED_HARNESS_IDS[number] =>
  MANAGED_HARNESS_IDS.some(id => id === value);
