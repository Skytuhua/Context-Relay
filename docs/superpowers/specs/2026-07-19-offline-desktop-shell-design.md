# Offline Desktop Shell Design

## Status and scope

This design implements the immediately honest portion of roadmap Task 8: an accessible desktop product shell for Home, Projects, Memory, Review queue, Tasks, Harnesses, Packages, Activity, Devices, and Settings.

Task 8 remains in progress after this slice. A complete offline memory/task workflow depends on later signed-operation, review, task, and project services. This slice must not fabricate records, persist plaintext in browser storage, or present deferred services as working.

The roadmap and the user's explicit instruction to continue end to end without pauses authorize the recommended low-risk approach below.

## Approaches considered

1. **Single dependency-free shell (selected).** Keep navigation, screen metadata, honest forms, dialog focus handling, and deferred-service states in the existing `App.tsx`; test through the public UI; style in `styles.css`. This is the smallest slice that proves information architecture and accessibility without committing to a router or state model before real services exist.
2. **Component-per-screen plus router.** This scales once screens own real data, but today creates ten nearly empty components and a routing dependency with no URL/deep-link requirement.
3. **One scrolling dashboard.** This minimizes state but collapses ten distinct product areas into an unwieldy document and does not establish the navigation model the roadmap calls for.

## Product scene and visual system

The physical scene is a developer using a local encrypted workspace beside an editor during long, interruption-heavy sessions: the UI should feel like a quiet instrument whose status can be trusted at a glance.

Use a restrained light product palette with system typography:

- `--color-canvas: oklch(1 0 0)`
- `--color-surface: oklch(0.975 0.006 188)`
- `--color-surface-strong: oklch(0.94 0.012 188)`
- `--color-ink: oklch(0.22 0.025 205)`
- `--color-muted: oklch(0.47 0.025 205)`
- `--color-primary: oklch(0.55 0.105 188)`
- `--color-primary-strong: oklch(0.43 0.095 188)`
- `--color-accent: oklch(0.55 0.13 38)` for sparing warnings/attention only
- `--color-danger: oklch(0.48 0.16 25)`

The teal seed is used for the current destination, focus, and primary action only. Surfaces remain plain; there are no gradients, glass, decorative shadows, oversized rounding, or card grids. Controls use one consistent 8px radius and a strong visible focus ring. Motion is limited to 150ms state transitions and is removed under `prefers-reduced-motion`.

## Information architecture

The application is a two-region shell:

- A persistent `<aside>` contains the product name, local/offline posture, and a `<nav aria-label="Workspace">` with ten native buttons.
- The selected button has `aria-current="page"`; selecting it updates the main screen and moves focus to the screen heading so keyboard and screen-reader users receive a clear route change.
- A `<main>` region contains one screen header, short purpose statement, and the screen-specific honest state.
- At narrow widths, the navigation becomes a horizontally scrollable list above the main content. It remains keyboard reachable and never becomes a custom menu.

Screen intent:

- **Home:** local-first posture, the two currently available daemon capabilities (project path and single-memory read) stated without claiming a populated workspace, plus a concise roadmap-status list.
- **Projects:** explains that project binding is not available yet and provides a disabled-looking but still readable next-step state; no fake repository list.
- **Memory:** an uncontrolled native form with title and body inputs. Submit reads only the current form values, records validation/error codes rather than plaintext in React state, and shows field-linked required errors or the exact honest unavailable-service message. It does not clear the user's input on failure.
- **Review queue:** explains that candidate review arrives with the later review service; no candidate fixtures.
- **Tasks:** an uncontrolled native form with task title. It follows the same validation/privacy rules and honest unavailable state as Memory.
- **Harnesses, Packages, Activity, Devices:** one purpose-specific empty/deferred state each, with no sample rows or fake counters.
- **Settings:** shows local security facts and a `Security details` button that opens a native `<dialog>`. Closing by button or Escape returns focus to the trigger explicitly.

## State and data flow

React state stores only:

- the selected screen identifier;
- field/error identifiers such as `memory-body-required` or `service-unavailable`;

The security dialog is controlled through native `HTMLDialogElement.showModal()`/`close()` calls and refs, not duplicated React open-state.

React state never stores memory bodies, task titles, tokens, keys, credential identifiers, or record collections. Forms are uncontrolled. There is no localStorage/sessionStorage/indexedDB use and no console logging. No Tauri IPC request is sent in this slice because the required create/upsert services intentionally return unavailable until later roadmap tasks.

## Accessibility and interaction contract

- Every action is a native button, input, textarea, or dialog control.
- The skip link is the first focusable element and targets the main content.
- Navigation changes move focus to the new `<h1 tabindex="-1">` without adding it to normal tab order.
- Every form control has a visible label, description where useful, and `aria-describedby`/`aria-invalid` when validation fails.
- Submission errors use `role="alert"`; passive service posture uses `role="status"`.
- The dialog has an accessible name, a dedicated close button, Escape behavior, and explicit trigger focus restoration.
- Focus styles are never removed. Touch targets are at least 40px high. Color is never the sole carrier of state.
- The layout remains usable at 320px width and at 200% zoom.

## Error and empty-state language

Deferred valid services use the exact daemon message:

`This service is not available in this build`

Empty/deferred states identify what the screen will do and which later capability unlocks it. They do not say "all caught up," show zero metrics, or imply a successful query was performed.

## Test contract

`App.test.tsx` drives the public interface and must prove:

- all ten destinations are keyboard-reachable native buttons and the current destination is exposed;
- selecting a destination renders its named heading and moves focus there;
- Memory and Tasks have labels, required validation, linked error text, and an honest unavailable error for nonblank submission without putting submitted plaintext in rendered status/error output;
- the security dialog is named, closes by its button and Escape/cancel path, and restores focus to its trigger;
- no localStorage/sessionStorage access or console output occurs during these flows;
- deferred screens contain no sample records or success metrics.

Run the focused Vitest file first, then lint, typecheck, all desktop tests, production build, and repository diff checks.

## Deferred integration

- Task 13 supplies trusted memory read/search scope and real memory operations.
- Task 14 supplies candidate review.
- Task 16 supplies signed-sync mutation routing used by durable writes.
- Task 20 supplies project lifecycle.
- When those services land, extract screen components only when their real data/effects make `App.tsx` unwieldy, and add routing only when deep links or history become a requirement.
