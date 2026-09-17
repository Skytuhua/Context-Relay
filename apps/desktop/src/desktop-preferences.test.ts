import { beforeEach, expect, it } from 'vitest';
import { defaultPreferences, readPreferences, savePreferences, PREFERENCES_KEY } from './desktop-preferences';

beforeEach(() => localStorage.removeItem(PREFERENCES_KEY));

it('starts with a deliberate project choice, dark theme and the first setup step', () => {
  expect(readPreferences()).toEqual(defaultPreferences());
  expect(readPreferences()).toMatchObject({ theme: 'dark', setup: { status: 'new', step: 'harnesses', projectId: null, harnesses: [] } });
});

it('resumes selected identities without persisting note content or unknown data', () => {
  const preferences = defaultPreferences();
  preferences.setup = { ...preferences.setup, status: 'deferred', step: 'test', harnesses: ['codex', 'hermes'], projectId: '018f22e2-79b0-7cc8-98c4-dc0c0c073980', noteId: '018f22e2-79b0-7cc8-98c4-dc0c0c073981' };
  savePreferences({ ...preferences, secret: 'never store this' } as typeof preferences);
  expect(readPreferences()).toEqual(preferences);
  expect(localStorage.getItem(PREFERENCES_KEY)).not.toContain('secret');
});

it('rejects corrupted or future state instead of silently skipping first-run setup', () => {
  localStorage.setItem(PREFERENCES_KEY, JSON.stringify({ version: 99, setup: { status: 'complete' } }));
  expect(readPreferences().setup.status).toBe('new');
  localStorage.setItem(PREFERENCES_KEY, '{broken');
  expect(readPreferences()).toEqual(defaultPreferences());
});

it('does not accept unsupported harnesses or arbitrary stored paths as project identities', () => {
  localStorage.setItem(PREFERENCES_KEY, JSON.stringify({ ...defaultPreferences(), setup: { ...defaultPreferences().setup, harnesses: ['codex', 'unknown', 'codex'], projectId: 'C:\\private' } }));
  expect(readPreferences().setup.harnesses).toEqual(['codex']);
  expect(readPreferences().setup.projectId).toBeNull();
});

it('preserves completed setup and dismissed tour independently of appearance', () => {
  const preferences = defaultPreferences();
  preferences.setup.status = 'complete'; preferences.tourCompleted = true; preferences.theme = 'system';
  savePreferences(preferences);
  expect(readPreferences()).toEqual(preferences);
});
