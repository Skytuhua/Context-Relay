import '@testing-library/jest-dom/vitest';
import { beforeEach } from 'vitest';
import { defaultPreferences, savePreferences } from './desktop-preferences';

// Most workspace regression tests exercise an existing installation. First-launch
// and preferences suites explicitly clear this fixture in their own beforeEach.
beforeEach(() => {
  const preferences = defaultPreferences();
  preferences.setup.status = 'complete';
  savePreferences(preferences);
});
