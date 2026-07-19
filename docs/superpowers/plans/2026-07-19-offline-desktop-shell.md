# Accessible Offline Desktop Shell Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the accessible, privacy-safe desktop shell portion of roadmap Task 8 without fabricating the offline memory/task services owned by later tasks.

**Architecture:** Keep this bounded slice in the existing React entry surface: `App.tsx` owns a typed ten-screen navigation model, uncontrolled Memory/Tasks forms, error-code-only React state, and a native security dialog; `styles.css` owns a restrained responsive product system; `App.test.tsx` verifies only public user behavior. No router, state library, mock database, browser storage, or Tauri service call is added.

**Tech Stack:** React 19, TypeScript 5.9, native HTML controls/dialog, CSS with OKLCH tokens, Vitest 3, Testing Library, ESLint, Vite.

## Global Constraints

- This is a partial Task 8 slice. Do not mark global Task 8 complete or use its final roadmap commit message.
- Render exactly these destinations: Home, Projects, Memory, Review queue, Tasks, Harnesses, Packages, Activity, Devices, Settings.
- Use native buttons, forms, inputs, textarea, and dialog. Do not add a router, component library, icon package, animation library, or state dependency.
- React state may contain only the selected screen and validation/service error identifiers. It must never retain submitted memory text, task titles, tokens, keys, credential identifiers, or record collections.
- Do not read or write localStorage, sessionStorage, IndexedDB, clipboard, console, or network APIs.
- Do not call Tauri IPC in this slice. Deferred valid operations report exactly `This service is not available in this build`.
- Do not render sample records, fake counters, success metrics, or "all caught up" states.
- Navigation changes move focus to the new screen heading. The skip link is first. Dialog close and cancel restore focus to the trigger.
- Labels, descriptions, `aria-invalid`, field-linked errors, `role="alert"`, and passive `role="status"` states must be present where specified.
- Use only OKLCH color tokens. Body text contrast must be comfortably above WCAG AA; focus indication must not rely on color alone.
- Support 320px width, 200% zoom, keyboard-only use, and `prefers-reduced-motion`.
- Preserve existing protocol/schema source files and generated artifacts.

## File Map

- Modify `apps/desktop/src/App.tsx`: typed shell, screen rendering, privacy-safe forms, focus management, native dialog.
- Modify `apps/desktop/src/App.test.tsx`: navigation, validation/privacy, dialog focus, deferred-state tests.
- Modify `apps/desktop/src/styles.css`: restrained product tokens, two-region layout, native control states, responsive behavior.
- Update ignored `.superpowers/sdd/task-8-shell-report.md`: RED/GREEN evidence and review disposition.
- Update ignored `.superpowers/sdd/progress.md`: record only the shell-slice commit and that global Task 8 remains in progress.

---

### Task 1: Build and verify the accessible ten-screen shell

**Files:**
- Modify: `apps/desktop/src/App.tsx`
- Modify: `apps/desktop/src/App.test.tsx`
- Modify: `apps/desktop/src/styles.css`
- Update ignored: `.superpowers/sdd/task-8-shell-report.md`
- Update ignored after clean review: `.superpowers/sdd/progress.md`

**Interfaces:**
- Produces: `type ScreenId`, constant `SCREENS`, default `App()` UI, `MemoryFormError`, and `TaskFormError`.
- Produces DOM contracts: `nav[aria-label="Workspace"]`, `button[aria-current="page"]`, `main#workspace-main`, one focused screen `<h1 tabIndex={-1}>`, named Memory/Tasks forms, and `dialog[aria-labelledby="security-dialog-title"]`.
- Consumes: React `FormEvent`, `useEffect`, `useRef`, and `useState` only; no app/backend module.

- [ ] **Step 1: Replace the bootstrap test with navigation RED**

In `App.test.tsx`, define the exact destination list and a focused test using Testing Library only:

```tsx
const destinations = [
  'Home',
  'Projects',
  'Memory',
  'Review queue',
  'Tasks',
  'Harnesses',
  'Packages',
  'Activity',
  'Devices',
  'Settings',
] as const;

it('exposes all workspace destinations and focuses each selected screen heading', () => {
  render(<App />);

  const navigation = screen.getByRole('navigation', { name: 'Workspace' });
  const buttons = within(navigation).getAllByRole('button');
  expect(buttons.map((button) => button.textContent)).toEqual(destinations);
  expect(screen.getByRole('button', { name: 'Home' })).toHaveAttribute('aria-current', 'page');

  for (const destination of destinations.slice(1)) {
    fireEvent.click(screen.getByRole('button', { name: destination }));
    const heading = screen.getByRole('heading', { level: 1, name: destination });
    expect(heading).toHaveFocus();
    expect(screen.getByRole('button', { name: destination })).toHaveAttribute(
      'aria-current',
      'page',
    );
  }
});
```

Also assert the first link is `Skip to workspace` with `href="#workspace-main"`, and that Home exposes a passive local-only status without claiming data was loaded.

- [ ] **Step 2: Run navigation RED**

Run:

```powershell
pnpm.cmd --filter @context-relay/desktop test --run src/App.test.tsx
```

Expected: FAIL because the bootstrap App has no Workspace navigation or ten headings.

- [ ] **Step 3: Implement the minimal typed navigation shell**

In `App.tsx`, use the exact model below:

```tsx
import { type FormEvent, useEffect, useRef, useState } from 'react';

type ScreenId =
  | 'home'
  | 'projects'
  | 'memory'
  | 'review'
  | 'tasks'
  | 'harnesses'
  | 'packages'
  | 'activity'
  | 'devices'
  | 'settings';

const SCREENS: ReadonlyArray<{ id: ScreenId; label: string; summary: string }> = [
  { id: 'home', label: 'Home', summary: 'See what is available in this local build.' },
  { id: 'projects', label: 'Projects', summary: 'Bind trusted repositories to local context.' },
  { id: 'memory', label: 'Memory', summary: 'Capture durable context for later sessions.' },
  { id: 'review', label: 'Review queue', summary: 'Approve or reject proposed memories.' },
  { id: 'tasks', label: 'Tasks', summary: 'Track work with durable evidence.' },
  { id: 'harnesses', label: 'Harnesses', summary: 'Inspect supported local AI harnesses.' },
  { id: 'packages', label: 'Packages', summary: 'Review portable Context Relay packages.' },
  { id: 'activity', label: 'Activity', summary: 'Audit local operations and sync outcomes.' },
  { id: 'devices', label: 'Devices', summary: 'Manage trusted devices and recovery.' },
  { id: 'settings', label: 'Settings', summary: 'Review local security and application settings.' },
];
```

`App` starts at `home`. Keep `hasNavigatedRef` false on mount. The navigation handler sets it true and changes the screen. A `useEffect` depending on the selected screen focuses `headingRef.current` only after `hasNavigatedRef.current` is true, avoiding initial-load focus theft.

Render:

```tsx
<>
  <a className="skip-link" href="#workspace-main">Skip to workspace</a>
  <div className="app-shell">
    <aside className="sidebar">
      <div className="brand-block">...</div>
      <nav aria-label="Workspace">
        {SCREENS.map((screen) => (
          <button
            aria-current={activeScreen === screen.id ? 'page' : undefined}
            key={screen.id}
            onClick={() => selectScreen(screen.id)}
            type="button"
          >
            {screen.label}
          </button>
        ))}
      </nav>
    </aside>
    <main id="workspace-main">
      <header className="screen-header">
        <h1 ref={headingRef} tabIndex={-1}>{currentScreen.label}</h1>
        <p>{currentScreen.summary}</p>
      </header>
      {renderScreen(activeScreen)}
    </main>
  </div>
</>
```

Use an exhaustive `switch` over every `ScreenId`. Each deferred screen gets purpose-specific copy and no data-shaped placeholders. Home uses `role="status"` and says the encrypted daemon boundary is local, while explicitly noting that full workspace services are still arriving.

- [ ] **Step 4: Run navigation GREEN**

Run the focused command from Step 2.

Expected: the navigation test passes; later form/dialog tests do not exist yet.

- [ ] **Step 5: Add Memory/Tasks validation and privacy RED tests**

Add two tests. Use `fireEvent.change` because no user-event dependency exists. For Memory:

```tsx
it('validates memory input without echoing submitted plaintext into status state', () => {
  render(<App />);
  fireEvent.click(screen.getByRole('button', { name: 'Memory' }));

  const form = screen.getByRole('form', { name: 'New memory' });
  const title = screen.getByRole('textbox', { name: 'Title' });
  const body = screen.getByRole('textbox', { name: 'Memory' });

  fireEvent.submit(form);
  expect(title).toHaveAttribute('aria-invalid', 'true');
  expect(screen.getByRole('alert')).toHaveTextContent('Enter a title.');

  fireEvent.change(title, { target: { value: 'Private title canary' } });
  fireEvent.submit(form);
  expect(body).toHaveAttribute('aria-invalid', 'true');
  expect(screen.getByRole('alert')).toHaveTextContent('Enter memory text.');

  fireEvent.change(body, { target: { value: 'Bulk plaintext canary' } });
  fireEvent.submit(form);
  const alert = screen.getByRole('alert');
  expect(alert).toHaveTextContent('This service is not available in this build');
  expect(alert).not.toHaveTextContent('Private title canary');
  expect(alert).not.toHaveTextContent('Bulk plaintext canary');
});
```

The Tasks test follows the same pattern with form name `New task`, textbox `Task title`, required message `Enter a task title.`, and the same exact unavailable message.

Add a privacy-side-effect test that spies on `Storage.prototype.setItem`, `console.log`, `console.info`, and `console.debug`, exercises successful-validation submissions, and expects zero calls. Restore all spies in `afterEach`.

- [ ] **Step 6: Run forms RED**

Run the focused App test file.

Expected: FAIL because Memory/Tasks forms and error contracts do not exist.

- [ ] **Step 7: Implement error-code-only uncontrolled forms**

Add exact unions:

```tsx
type MemoryFormError = 'title-required' | 'body-required' | 'service-unavailable' | null;
type TaskFormError = 'title-required' | 'service-unavailable' | null;
const SERVICE_UNAVAILABLE = 'This service is not available in this build';
```

Use `useState` only for those unions. In each submit handler, create `FormData(event.currentTarget)`, convert the one or two values to trimmed local strings, set the first applicable error identifier, and return. When validation succeeds, set only `service-unavailable`. Do not clear/reset the form, log, persist, call IPC, or store either local string.

Each input has a visible `<label>`, stable ID/name, and `aria-invalid` only for its corresponding required error. Its `aria-describedby` points to the rendered error paragraph when invalid. The service error is a form-level `<p role="alert">`. Set `noValidate` on the form so the same accessible error contract is deterministic in WebView and jsdom.

- [ ] **Step 8: Run forms GREEN**

Run the focused App test file.

Expected: navigation and form/privacy tests pass.

- [ ] **Step 9: Add native dialog focus RED**

In the test file, install deterministic `HTMLDialogElement` shims only when jsdom lacks the methods:

```tsx
beforeEach(() => {
  HTMLDialogElement.prototype.showModal = function showModal() {
    this.setAttribute('open', '');
  };
  HTMLDialogElement.prototype.close = function close() {
    this.removeAttribute('open');
    this.dispatchEvent(new Event('close'));
  };
});
```

Test that Settings renders `Security details`, clicking it opens a dialog named `Local security details`, clicking `Close security details` closes it, and focus returns to the trigger. Reopen it, dispatch a cancelable `cancel` event, assert it is prevented/closed, and assert focus again returns.

- [ ] **Step 10: Run dialog RED**

Run the focused App test file.

Expected: FAIL because Settings has no dialog.

- [ ] **Step 11: Implement the native security dialog**

Use `dialogRef` and `dialogTriggerRef`. `openSecurityDetails(event)` stores the native trigger and calls `dialogRef.current?.showModal()`. `restoreDialogFocus` calls `.focus()` on the stored trigger. The close button calls `.close()`. The dialog `onClose` restores focus. Its `onCancel` prevents default and calls `.close()` so the close event owns one restoration path.

The dialog body states only fixed security facts: per-user OS endpoint permissions, credential-store token ownership outside React, and the fact that same-user malware is outside the v1 threat model. It contains no credential identifier, token, key, path, or environment value.

- [ ] **Step 12: Run dialog GREEN**

Run the focused App test file.

Expected: all App tests pass.

- [ ] **Step 13: Implement the restrained responsive CSS system**

Replace the bootstrap CSS with the exact token roles from the design spec. Required structural rules:

- `box-sizing: border-box` globally; `body` has minimum 320px width, no horizontal page overflow, white canvas, ink, system sans.
- `.skip-link` is visually hidden off-canvas until `:focus-visible`, then appears at the top-left above the shell.
- `.app-shell` uses `grid-template-columns: minmax(13rem, 16rem) minmax(0, 1fr)` and `min-height: 100vh`.
- `.sidebar` uses the strong surface, one 1px divider, and sticky full-height positioning on wide screens.
- Navigation is a flex column; buttons are at least 40px tall, left-aligned, borderless at rest, and expose hover/current/focus states. The current button uses a subtle primary-tinted fill plus font weight, not a side stripe.
- Main content has a readable max width around 72rem; prose blocks cap near 70ch.
- Forms use a single column, visible labels, native controls, an 8px radius, strong focus ring, and danger border plus text for invalid fields.
- Deferred states use one simple bordered section or definition list where semantically useful; no nested cards, fake table skeletons, or decorative shadows.
- Dialog uses a max width around 34rem, 12px radius, no decorative shadow/border pairing, and a neutral `::backdrop`.
- At `max-width: 46rem`, the grid becomes one column, sidebar becomes static, and navigation becomes a horizontal overflow row with nonshrinking buttons.
- At `prefers-reduced-motion: reduce`, transitions are disabled.

- [ ] **Step 14: Run focused and accessibility source checks**

Run:

```powershell
pnpm.cmd --filter @context-relay/desktop test --run src/App.test.tsx
rg -n "localStorage|sessionStorage|indexedDB|console\.|background-clip:\s*text|border-(left|right):\s*[2-9]" apps/desktop/src/App.tsx apps/desktop/src/styles.css
```

Expected: App tests PASS. `rg` exits 1 with no matches; the command is a negative diagnostic and that exit is expected.

- [ ] **Step 15: Run full fresh gates**

Run:

```powershell
pnpm.cmd check:bindings
pnpm.cmd check:schemas
pnpm.cmd license:check
pnpm.cmd lint
pnpm.cmd typecheck
pnpm.cmd test --run
pnpm.cmd build
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo deny --locked check
node --test scripts/check-daemon-boundary.test.mjs
node scripts/check-daemon-boundary.mjs
git diff --check
```

Expected: every command exits 0. The existing ignored release-only search performance test and known vendored OpenSSL missing-PDB linker warnings are reported honestly.

- [ ] **Step 16: Request independent review and fix validated findings test-first**

Reviewer checks exact ten-screen coverage, keyboard/focus order, screen-reader semantics, form privacy/state, honest unavailable behavior, no fake data, native dialog restoration, 320px/responsive CSS, contrast/token discipline, scope, and dependency stability. Every validated Critical/Important finding gets a focused RED regression, minimal GREEN fix, affected/full gates, and re-review.

- [ ] **Step 17: Stage only the shell slice and commit**

Run:

```powershell
git status --short
git add -- apps/desktop/src/App.tsx apps/desktop/src/App.test.tsx apps/desktop/src/styles.css
git diff --cached --check
git diff --cached --name-only
git commit -m "feat: add accessible desktop workspace shell"
```

Expected staged paths are exactly the three desktop source files. Do not stage `.codex/`, `AGENTS.md`, `graphify-out/`, `.superpowers/`, generated bindings/schemas, or future backend work.

- [ ] **Step 18: Refresh graph and durable progress without closing Task 8**

Run `graphify update .`. Record the shell commit and clean review in `.superpowers/sdd/progress.md`, followed by `Task 8: in progress` and the exact deferred owners (Tasks 13, 14, 16, 20). Do not use the final roadmap message `feat: add offline desktop memory workspace` until the complete offline workflow gate genuinely passes.

## Self-Review Checklist

- [ ] The plan covers all ten named screens with no fake records or metrics.
- [ ] Every behavior change has an observed focused RED before GREEN.
- [ ] React state contains only screen/error identifiers.
- [ ] Memory/task plaintext stays only in uncontrolled native form controls/local submit variables.
- [ ] Navigation and dialog focus restoration are deterministic and tested.
- [ ] Every form control has visible labels and linked validation semantics.
- [ ] CSS uses OKLCH tokens, standard affordances, and no banned decorative patterns.
- [ ] No new dependency, storage API, IPC call, or router appears.
- [ ] Full repository gates and independent review precede the shell commit.
- [ ] Global Task 8 remains in progress after this partial shell slice.
