import { expect, it } from 'vitest';

import { SHORTCUTS, displayKeys, isEditableTarget, matchShortcut } from './keyboard-shortcuts';

/** Build a keydown-shaped object; `target` drives the editable-field guard. */
function key(combo: string, target: EventTarget | null = null) {
  const parts = combo.toLowerCase().split('+');
  const key = parts.pop() as string;
  const has = (name: string) => parts.includes(name);
  // A single character is reported as-is; a named key keeps its own name.
  return {
    key: key.length === 1 ? key : key,
    ctrlKey: has('mod') && !has('macctrl'),
    metaKey: false,
    altKey: has('alt'),
    shiftKey: has('shift'),
    target,
  };
}

function editable() {
  const input = document.createElement('input');
  document.body.append(input);
  return input;
}

it('maps every declared shortcut to itself', () => {
  for (const shortcut of SHORTCUTS) {
    expect(matchShortcut(key(shortcut.keys))).toBe(shortcut.id);
  }
});

it('declares no duplicate key combinations', () => {
  const seen = new Map<string, string>();
  for (const shortcut of SHORTCUTS) {
    expect(seen.has(shortcut.keys)).toBe(false);
    seen.set(shortcut.keys, shortcut.id);
  }
});

it('ignores a bare letter pressed inside a text field', () => {
  // "n" must never create a note while the user is typing one.
  expect(matchShortcut(key('n'), editable())).toBeNull();
  expect(matchShortcut(key('n'), null)).toBeNull();
});

it('ignores ctrl combinations inside a text field', () => {
  const input = editable();
  expect(matchShortcut(key('mod+n'), input)).toBeNull();
  // Except mod+/, which types a slash rather than a word character.
  expect(matchShortcut(key('mod+/'), input)).toBe('showShortcuts');
});

it('recognises contentEditable as a typing target', () => {
  const div = document.createElement('div');
  // jsdom does not reflect contentEditable onto the IDL property.
  div.setAttribute('contenteditable', 'true');
  document.body.append(div);
  expect(isEditableTarget(div)).toBe(true);
  expect(matchShortcut(key('mod+n'), div)).toBeNull();
});

it('normalises the key names browsers actually report', () => {
  // 'ArrowRight' is what a keydown reports; matching a bare 'right' would make
  // the project-cycling shortcuts silently dead.
  expect(matchShortcut({ key: 'ArrowRight', ctrlKey: true, metaKey: false, altKey: true, shiftKey: false })).toBe('nextProject');
  expect(matchShortcut({ key: 'ArrowLeft', ctrlKey: true, metaKey: false, altKey: true, shiftKey: false })).toBe('previousProject');
  // Uppercase letters arrive shifted, so they must still resolve.
  expect(matchShortcut({ key: 'N', ctrlKey: true, metaKey: false, altKey: false, shiftKey: false })).toBe('newContext');
  expect(matchShortcut({ key: '/', ctrlKey: true, metaKey: false, altKey: false, shiftKey: false })).toBe('showShortcuts');
});

it('returns null for unbound keys', () => {
  expect(matchShortcut(key('mod+q'))).toBeNull();
  expect(matchShortcut(key('shift+alt+f9'))).toBeNull();
});

it('renders keys with platform-appropriate symbols', () => {
  expect(displayKeys('mod+alt+right')).toMatch(/Right|→/);
  expect(displayKeys('mod+n')).toMatch(/Ctrl|⌘/);
  // Every shortcut's keys must be displayable without throwing.
  for (const shortcut of SHORTCUTS) expect(displayKeys(shortcut.keys)).toBeTruthy();
});

it('groups every shortcut for the help overlay', () => {
  expect(SHORTCUTS.every((s) => ['Go to', 'Create', 'Switch project', 'General'].includes(s.group))).toBe(true);
  // No group may be empty, or the overlay renders a heading with nothing under it.
  const groups = new Set(SHORTCUTS.map((s) => s.group));
  expect(groups.size).toBe(4);
});
