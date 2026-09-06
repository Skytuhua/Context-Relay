# Desktop save retries — 2026-09-06

An explicit retry previously generated a new operation ID. If the service had
committed a context note or task but its reply was lost, the second click could
create a duplicate. Updates could instead report a revision conflict after the
original update had already succeeded.

The desktop gateway now retains the operation ID for an unconfirmed exact
request and reuses it on explicit retry. This covers context create/update/archive,
task create/update/status/completion and suggestion review. It sends no automatic
retries. Changed input has a different identity, and an expected, usable response
finishes the attempt. A malformed response keeps the identity available for retry.

Creation attempts also bind to the visible form's lifetime. Same-page reload,
search and failed submission preserve that identity. An acknowledged form reset
or a new form/project starts another draft, even if its contents are identical.
The token is client-only and never enters IPC parameters. Forms have explicit
kind/project keys so React does not carry uncontrolled text from Saved context
into Tasks while rotating the retry identity. A later acknowledged action on
the created record also retires an earlier uncertain creation attempt.

The service already stores immutable operation results. Its replay returns the
original acknowledgment, which may predate a later edit or archive. The desktop
therefore avoids adding a second card for an already visible creation, and
preserves a visible revision that differs from an edit's expected revision.
A fresh list read remains authoritative. Failed refreshes retain the existing
warning instead of claiming that the list is current.

## Verification

The initial 18 gateway regressions failed before implementation. Review added
failing-first cases for intentional creation after an acknowledged later action,
new form identity, older edit acknowledgments over newer visible data, and
context/task field reuse. Gateway, UI and lifecycle tests cover both context and
tasks. Existing backend replay checks verify immutable results, later mutations
and vault reopen.

The final frontend suite passes all 176 tests across 16 files. Type checking,
lint and the production frontend build pass. All five selected backend replay
tests pass, including update and task-transition replay after vault reopen.

A headless Edge fixture renders the actual App and LocalWorkspaceGateway against
an isolated in-memory service. At widths 1166 and 390, context and task creation
each commit once, lose the first reply, reload the same page, then succeed on
explicit retry. The draft remains available until acknowledgment and each list
contains one card. Four requests produce one context record and one task record
per browser context. Eight screenshots record the uncertain and confirmed states;
there is no horizontal overflow or page error. This does not use native desktop
control or the normal daemon.

Local evidence under .codex/context-relay-closeout-2026-09-05/ includes
workspace-retry-red-final.log, workspace-retry-review-red.log,
workspace-retry-draft-red.log, workspace-retry-form-red.log,
workspace-retry-desktop-final.log, workspace-retry-core-replay.log and
workspace-retry-browser.log. The browser script is verify-workspace-retry-ui.mjs;
screenshots and results are in workspace-retry-ui/.

## Limits

Retry identities currently live in the running gateway. This change does not
persist plaintext drafts, introduce another credential store, or claim recovery
of unsent/unconfirmed drafts after app restart. Durable draft/attempt recovery,
clear revision-conflict resolution and installed acceptance remain open work.
No protocol, service mutation, harness version gate or installer changed.
