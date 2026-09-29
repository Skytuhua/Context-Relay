# Desktop save recovery — 2026-09-06

This change extends the [current-session save retry fix](desktop-save-retry-2026-09-06.md) to submitted requests retained across desktop and local-service restarts. It does not qualify the installed application or complete the release acceptance ledger.

## Behavior

Before sending a context, task or suggestion mutation, the desktop prepares its exact typed request and operation ID in the existing SQLCipher vault. An uncertain preparation does not send the ordinary mutation. Explicit identical attempts retain their identity. A usable acknowledgment must match the target record and operation revision, or the requested suggestion decision. Only then may its recovery copy be removed. Cleanup failure does not turn an acknowledged save into an unknown save.

Home reads a Changes to check panel. The user can review the original text, scope, status or decision, explicitly retry the stored request unchanged, or dismiss its recovery copy. Startup never replays a write. Dismissing a copy does not undo a committed change; uncertain dismissal directs the user to reload.

Recovery actions lock navigation until their acknowledgments finish. Storage exhaustion offers recovery copies below the current form, preserving the draft while the user clears older copies. A recovered change refreshes the currently visible context, task or suggestion list without applying an older immutable acknowledgment over newer data.

## Storage and protocol

- Schema migration 26 adds a local journal outside records, operations and outbox tables.
- Preparation validates the seven allowed record mutation methods. Harness setup, credentials, account deletion and nested preparation are not accepted.
- An immediate transaction checks exact operation binding and quotas: 256 copies and 64 MiB including stored summaries. Identical preparation remains valid at capacity. No eviction occurs.
- Lists use keyset pagination, at most 50 summaries per page; a separate read returns one complete request. Removing earlier pages does not skip later entries.
- Journal payloads use the vault's encryption. They are not synced. Existing complete encrypted-vault backups include recovery copies; they are excluded from saved-record counts. Reopening such a backup does not apply its pending changes.
- Protocol 1.7 adds Desktop-only prepare/list/get/forget methods. Ordinary IPC clients require the exact protocol. The private Windows upgrade shutdown path still authenticates versions 1.4, 1.5 and 1.6.

## Verification

All tests used isolated vaults, credential fixtures, IPC endpoints or browser services. Native Computer Use remained paused.

| Check | Result |
| --- | --- |
| Core journal, offline service and vault storage integration suites | 41 passed |
| Daemon library suite, including worker restart and encrypted backup reopen | 61 passed, 1 ignored |
| Protocol and local IPC suites, including role matrices, HMAC vectors and legacy shutdown children | 198 passed, 3 ignored |
| Desktop tests | 192 passed in 18 files |
| TypeScript, ESLint, production frontend build | Passed |
| Generated bindings, schemas and daemon dependency boundary | Passed |
| Clippy, four affected Rust crates and all targets, warnings denied | Passed |

Failure-first regressions cover the absent prepare protocol, wrong record and stale revision acknowledgments, navigation during recovery, and refreshing a recovered suggestion decision. The journal tests cover encrypted reopen without record creation, altered operation reuse, both quotas, pagination after deletion, and exact committed-save replay after reopening the vault.

The headless Edge browser fixture runs the actual App and LocalWorkspaceGateway against an isolated service that commits each first context/task save and drops its reply. A full page reload discards all gateway/form state. Startup and review only read; explicit retry returns the original record and clears its copy. At widths 1166 and 390, four mutation requests produce exactly one context record and one task, with no remaining recovery copies, page errors or horizontal overflow. Twelve screenshots cover recovered, reviewed and confirmed states.

Local evidence is under .codex/context-relay-closeout-2026-09-05: durable-write-core-final.log, durable-write-daemon-final.log, durable-write-contracts.log, durable-write-desktop-final.log, durable-write-frontend-final.log, durable-write-generated.log, durable-write-clippy.log, durable-write-browser-final.log and durable-write-ui/. The browser fixture is verify-durable-write-ui.mjs. Protocol 1.7 HMAC vectors were independently calculated using Python's standard hmac implementation before the Rust tests.

## Limits

Unsubmitted keystrokes are not autosaved by this journal. The guarantee begins when preparation reaches the encrypted vault; closing before that can still lose an unsent draft. A definitive revision conflict still needs a fuller comparison/edit resolution flow. Tests exercise full browser reload and vault/worker reopen, not installed native UI acceptance or an abrupt operating-system power failure.

This change does not promote Codex 0.144.6 or Claude Code 2.1.202 beyond ImportOnly, qualify the Hermes runtime, provide code signing, or authorize an installed-app update. Those release requirements remain open.
