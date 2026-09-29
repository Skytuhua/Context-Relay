import type { HarnessId } from './bindings';

export const PREFERENCES_KEY = 'context-relay.desktop-preferences.v1';
export type SetupStep = 'harnesses' | 'project' | 'connect' | 'test' | 'tour';
export type Theme = 'dark' | 'light' | 'system';
export type VerifiedRead = { harness: HarnessId; projectId: string; checkId: string; verifiedAt: string };
export interface SetupProgress {
  status: 'new' | 'in_progress' | 'deferred' | 'complete';
  step: SetupStep;
  harnesses: HarnessId[];
  projectId: string | null;
  noteId: string | null;
  checkId: string | null;
  hermesProfile: string;
  testHarness: HarnessId | null;
}
export interface DesktopPreferences {
  version: 1;
  theme: Theme;
  setup: SetupProgress;
  tourCompleted: boolean;
  tourStep: number | null;
  lastVerifiedRead: VerifiedRead | null;
}

export function defaultPreferences(): DesktopPreferences {
  return { version: 1, theme: 'dark', setup: { status: 'new', step: 'harnesses', harnesses: [], projectId: null, noteId: null, checkId: null, hermesProfile: 'default', testHarness: null }, tourCompleted: false, tourStep: null, lastVerifiedRead: null };
}

const identity = (value: unknown): string | null => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value) ? value : null;

function normalize(value: unknown): DesktopPreferences {
  const result = defaultPreferences();
  if (!value || typeof value !== 'object' || !('version' in value) || value.version !== 1) return result;
  const input = value as Partial<DesktopPreferences>;
  if (['dark', 'light', 'system'].includes(input.theme ?? '')) result.theme = input.theme!;
  result.tourCompleted = input.tourCompleted === true;
  const receipt = input.lastVerifiedRead;
  if (receipt && ['codex', 'claude_code', 'hermes'].includes(receipt.harness) && identity(receipt.projectId) && identity(receipt.checkId) &&
    typeof receipt.verifiedAt === 'string' && /^\d{1,16}$/.test(receipt.verifiedAt) && Number(receipt.verifiedAt) <= 8_640_000_000_000_000) {
    result.lastVerifiedRead = { harness: receipt.harness, projectId: receipt.projectId, checkId: receipt.checkId, verifiedAt: receipt.verifiedAt };
  }
  if (Number.isInteger(input.tourStep) && input.tourStep! >= 0 && input.tourStep! <= 4) result.tourStep = input.tourStep!;
  if (input.setup && typeof input.setup === 'object') {
    const setup = input.setup;
    if (['new', 'in_progress', 'deferred', 'complete'].includes(setup.status)) result.setup.status = setup.status;
    if (['harnesses', 'project', 'connect', 'test', 'tour'].includes(setup.step)) result.setup.step = setup.step;
    result.setup.harnesses = Array.isArray(setup.harnesses) ? [...new Set(setup.harnesses.filter((id): id is HarnessId => ['codex', 'claude_code', 'hermes'].includes(id)))] : [];
    result.setup.projectId = identity(setup.projectId);
    result.setup.noteId = identity(setup.noteId);
    result.setup.checkId = identity(setup.checkId);
    if (typeof setup.hermesProfile === 'string' && /^[a-z0-9][a-z0-9_-]{0,63}$/.test(setup.hermesProfile)) result.setup.hermesProfile = setup.hermesProfile;
    if (setup.testHarness && result.setup.harnesses.includes(setup.testHarness)) result.setup.testHarness = setup.testHarness;
  }
  return result;
}

export function readPreferences(): DesktopPreferences {
  try { return normalize(JSON.parse(localStorage.getItem(PREFERENCES_KEY) ?? 'null')); }
  catch { return defaultPreferences(); }
}

/** Persist only known non-secret UI choices. Writes throw so the UI can explain failure. */
export function savePreferences(value: DesktopPreferences): void {
  localStorage.setItem(PREFERENCES_KEY, JSON.stringify(normalize(value)));
}
