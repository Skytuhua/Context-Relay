export type ShortcutId =
  | 'dashboard' | 'context' | 'tasks' | 'harnesses' | 'projects' | 'devices' | 'settings' | 'help'
  | 'newContext' | 'newTask' | 'focusSearch' | 'nextProject' | 'previousProject' | 'showShortcuts';

export type Shortcut = {
  id: ShortcutId;
  /** `mod` is Command on macOS and Control elsewhere. */
  keys: string;
  label: string;
  group: 'Go to' | 'Create' | 'Switch project' | 'General';
};

/** The single source of truth, used for both handling and the help overlay. */
export const SHORTCUTS: readonly Shortcut[] = [
  { id: 'dashboard', keys: 'mod+1', label: 'Dashboard', group: 'Go to' },
  { id: 'context', keys: 'mod+2', label: 'Context', group: 'Go to' },
  { id: 'tasks', keys: 'mod+3', label: 'Tasks', group: 'Go to' },
  { id: 'harnesses', keys: 'mod+4', label: 'Harnesses', group: 'Go to' },
  { id: 'projects', keys: 'mod+5', label: 'Projects', group: 'Go to' },
  { id: 'devices', keys: 'mod+6', label: 'Devices', group: 'Go to' },
  { id: 'settings', keys: 'mod+7', label: 'Settings', group: 'Go to' },
  { id: 'help', keys: 'mod+8', label: 'Help', group: 'Go to' },
  { id: 'newContext', keys: 'mod+n', label: 'New context note', group: 'Create' },
  { id: 'newTask', keys: 'mod+shift+t', label: 'New task', group: 'Create' },
  { id: 'focusSearch', keys: 'mod+k', label: 'Search context', group: 'Create' },
  { id: 'nextProject', keys: 'mod+alt+right', label: 'Next project', group: 'Switch project' },
  { id: 'previousProject', keys: 'mod+alt+left', label: 'Previous project', group: 'Switch project' },
  { id: 'showShortcuts', keys: 'mod+/', label: 'Keyboard shortcuts', group: 'General' },
];

export const SCREEN_SHORTCUTS: Partial<Record<ShortcutId, string>> = {
  dashboard: 'home', context: 'memory', tasks: 'tasks', harnesses: 'harnesses',
  projects: 'projects', devices: 'devices', settings: 'settings', help: 'help',
};

const IS_APPLE = typeof navigator !== 'undefined' && /mac|iphone|ipad/i.test(navigator.platform || navigator.userAgent || '');

/** `mod+shift+t` → `mod` means Command on Apple platforms, Control elsewhere. */
export function displayKeys(keys: string): string {
  return keys
    .split('+')
    .map((part) => {
      switch (part) {
        case 'mod': return IS_APPLE ? '⌘' : 'Ctrl';
        case 'alt': return IS_APPLE ? '⌥' : 'Alt';
        case 'shift': return IS_APPLE ? '⇧' : 'Shift';
        case 'right': return '→';
        case 'left': return '←';
        case '/': return '/';
        default: return part.length === 1 ? part.toUpperCase() : part;
      }
    })
    .join(IS_APPLE ? '' : '+');
}

const EDITABLE = /^(input|textarea|select)$/i;

export function isEditableTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  // isContentEditable is not implemented in every engine and test environment,
  // so fall back to the attribute that drives it. A rich-text editor nested
  // inside a form must still count as typing, or "n" creates a note mid-sentence.
  return EDITABLE.test(target.tagName)
    || target.isContentEditable
    || target.getAttribute?.('contenteditable') === 'true';
}

/**
 * Resolve a keydown to a shortcut, or null when it should be left alone.
 *
 * Typing "n" inside a text field must never create a note, so any editable
 * target opts out. `mod+/` is the one exception, because the slash is the
 * character being typed rather than a letter that would collide with text.
 */
export function matchShortcut(event: Pick<KeyboardEvent, 'key' | 'ctrlKey' | 'metaKey' | 'altKey' | 'shiftKey'>, target?: EventTarget | null): ShortcutId | null {
  const parts: string[] = [];
  if (event.metaKey || event.ctrlKey) parts.push('mod');
  if (event.altKey) parts.push('alt');
  if (event.shiftKey) parts.push('shift');

  // Normalise the named keys browsers report: 'ArrowRight' → 'right', so the
  // SHORTCUTS table can stay readable. Without this an arrow shortcut silently
  // never matches.
  const raw = event.key.toLowerCase();
  const key = raw.startsWith('arrow') ? raw.slice(5) : raw;
  const combo = [...parts, key].join('+');

  const match = SHORTCUTS.find((shortcut) => shortcut.keys === combo);
  if (!match) return null;

  // A bare letter or number must not fire while the user is typing.
  const needsTypingRoom = !parts.includes('mod') && !parts.includes('alt');
  if (needsTypingRoom && isEditableTarget(target ?? null)) return null;

  // mod+/ is safe inside a field: '/' is not a word character.
  if (combo === 'mod+/') return match.id;
  if (isEditableTarget(target ?? null)) return null;
  return match.id;
}
