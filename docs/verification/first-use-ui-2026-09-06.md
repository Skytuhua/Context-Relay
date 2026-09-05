# First-use desktop flow — 2026-09-06

The user reported that the installed desktop was difficult to understand and
asked for the term **harness**. The revised flow gives a new user an ordered
path: choose a project folder, save useful context, then connect a harness.
Creating a project returns to Home with Save context as the first action.
Saving context offers a direct route to Harnesses. An empty Harnesses screen
links to project creation; an unavailable harness offers a route back to saving
context and explicitly says that it is not connected.

Navigation groups work, connections and settings. Narrow windows wrap the
navigation so every destination is visible. Forms use context-oriented labels
and examples. Search appears with saved records below the capture form.
Connection review keeps scopes, semantic changes, permission/network changes
and package information visible. Executable paths, digests, command arguments
and verification JSON remain available in closed technical details.

Acknowledged connections retain their original cloned review. Each has a stable
connection number, acknowledgment time and harness version, with a distinct
Undo button. A new regression applies two different plans, opens both original
reviews and verifies that undoing the first sends its exact plan ID while
preserving the second connection number. Approval, expiry, selection and busy
guards remain in place. Connection numbers and recent connections are scoped to
the running desktop session; this does not implement durable setup history.

## Verification

- All **140 frontend tests in 14 files** pass, including four new first-use
  regressions and the repeated-connection regression. The first-use tests and
  undo distinction each failed before their implementation.
- TypeScript checking, ESLint and the production Vite build pass.
- Independent read-only review identified the original ambiguous Undo entries;
  the correction and regression were approved with no further findings.
- The actual React app and stylesheet were exercised in a fresh **headless
  Edge** context with an isolated in-memory gateway at 1166 × 800 and 390 × 844.
  The flow covered project creation, context saving, unavailable harness guidance
  and connection review. Eight screenshots were inspected. The Connect button
  stayed disabled before explicit approval. No browser runtime errors or
  horizontal document overflow were observed.
- Measured palette contrast: body 17.20:1, muted text against the light surface
  6.29:1 and primary button text 7.45:1. This is a scoped check, not a complete
  accessibility audit or screen-reader acceptance.

Local logs and screenshots are under
`.codex/context-relay-closeout-2026-09-05/first-use-ui*`; the browser fixture is
`verify-first-use-ui.mjs`. It injects no test mode into the shipped app and does
not use the normal daemon, vault, harness configuration or native desktop.

## Remaining acceptance

This verifies the revised frontend against controlled responses. It does not
prove that an installed harness can complete automatic connection, nor does it
replace native installer, physical keyboard/screen-reader or clean-machine
acceptance. The installed runtime compatibility gates remain unchanged. The
synthetic project named `Installer verification 專案 🚀` is preserved and is not
an application feature. The candidate is unsigned; no signing service exists.
