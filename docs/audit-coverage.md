# Audit coverage

Areas the July 2026 audit reviewed by hand, and what was checked in each. Recorded so
a later reader knows which surfaces have been looked at and which have not.

## Verified defects, fixed

| PR | Area | Defect |
|---|---|---|
| #31 | `context-mcp/src/server.rs` | Five `lock().unwrap()` on `std::sync::Mutex` with no `catch_unwind`: one panic poisoned the registry permanently and killed the stdio bridge. |
| #33 | `core/src/devices/memory_transport.rs` | Expired pairing invites were only dropped once a caller read them, so 120 invites over 120 hours all stayed resident. Anonymous join session ids were inserted unbounded. |

## Checked and found correct

**Local IPC** (`crates/local-ipc/`) — HMAC-SHA256 with domain separation for client and
server, `verify_slice` for constant-time comparison rather than `==`, `Zeroizing` on
token material, redacted `Debug` impls, and mutual authentication (the daemon proves
itself, not just the client). Frame length is bounded on both read and write, and the
daemon caps concurrent connections with a `Semaphore`.

**Pairing provider** (`core/src/devices/memory_transport.rs`) — codes are Crockford
base32 generated from `OsRng` via `try_fill_bytes` (no panic path), stored HMAC'd under
a pepper rather than in plaintext, compared with `verify_slice`, and de-duplicated
against existing invites before insertion. Code guessing is capped at five attempts per
session. Invite lifetime, terminal states and the cancel/approve/deny transitions are
each validated.

**MCP JSON-RPC** (`context-mcp/src/`) — unknown methods return `METHOD_NOT_FOUND`
rather than falling through, the `initialize` lifecycle is enforced so it cannot be
repeated, every handler parses and validates its own params, and frame size is bounded
with `checked_sub`/`saturating_add`. Tool calls are gated by a token-bucket rate limit
and a `MAX_IN_FLIGHT_TOOL_CALLS` semaphore; the bucket uses `saturating` arithmetic so
it cannot overflow.

**Credential storage** (`core/src/auth/`) — `StoredLogin` wraps the refresh token in
`Zeroizing` and redacts `Debug`. Records are version-pinned, bound to the project URL,
size-capped, and every UUID is canonicalised. Keyring entry names are SHA-256 digests
of project and profile, so credentials are not addressable by guessable name.
`valid_header_secret` rejects non-graphic characters and is applied to every value that
reaches an auth header, which blocks CRLF injection. `logout` invalidates local state
and clears the store *before* attempting the network call, so a network failure cannot
leave a credential behind. Refresh is generation-guarded with no lock held across the
network call.

**Vault durability** (`core/src/vault.rs`) — `journal_mode = DELETE` with
`synchronous = FULL`, plus `secure_delete`, `trusted_schema = false`,
`SQLITE_DBCONFIG_DEFENSIVE`, and `cipher_memory_security`. `verify_runtime` asserts at
open time that SQLite and SQLCipher are at or above the pinned minimums, that FTS5 is
compiled in, and that `synchronous` is genuinely FULL rather than trusting the pragma.
Both connection-open paths call it.

**Native memory watcher** (`contextd/src/native_memory.rs`) — pending and in-flight
sets are keyed by source id, the join set is drained each loop iteration, and a
`JoinSet` drain prevents duplicate submissions. Debounce is a bounded state machine.

**Command authorization** (`local-ipc/src/connection.rs`, `contextd/src/lib.rs`) —
every inbound frame is checked by `role_allows` in the connection read loop, before
the daemon sees it, and an unauthorized request gets `ScopeDenied` without being
dispatched. Verified that the narrower checks inside `route_request` are
defense-in-depth rather than the primary gate: a probe showed `route_request` does
not deny `ProjectUpsert`, `TasksList` or `AccessSet` for `McpBridge`/`Installer`
roles, but the IPC layer refuses them first. `role_allows` itself is exhaustive per
variant — `MemoryCreate`, `AccessSet`, `AccountDeletionBegin` and `Shutdown` are all
`Desktop`-only, `Health` is shared, and `Hello` is denied to everyone.

**Filesystem boundary** (`core/src/`) — `..` and `.` path components are rejected
explicitly in four separate boundary modules, wire paths are validated against the
declared platform and reject NUL bytes, containment checks compare
`canonicalize()`d paths rather than raw strings, and native-state writes are staged and
`fsync`ed before rename.

**Workspace parameter handling** (`contextd/src/lib.rs`, `core/src/service.rs`) —
the 37 workspace-queue handlers were walked for the request types that carry
attacker-influenced data. Registering a project validates both the identity and the
path before touching the database, and refuses to rebind an existing project to a
different path or name, so a repeated registration cannot redirect a bound project.
`WireNativeValue::validate` is called on *deserialization* as well as on use, so an
oversized path never reaches a handler. Memory search rejects an empty query,
resolves and authorizes the scope before searching, and caps results at 100. The
lexical half of the search goes through `quote_fts_query`, which wraps the query in
double quotes and doubles any embedded quote — the documented FTS5 escape — so the
`MATCH` clause is not injectable, and it is bound as a parameter rather than
interpolated.

**Recovery enrollment** (`contextd/src/recovery_enrollment*`, ~3.1k lines) — the
phrase is BIP39 with a checksum: `from_words` parses through
`Mnemonic::parse_in(Language::English)` and requires exactly 24 words, so a wrong
phrase fails the checksum before any key derivation runs. Entropy is 256-bit and
both the parsed and stored phrase live in `Zeroizing`, with an explicit `drop` of
the phrase immediately after derivation. `authenticate_recovery_root` verifies
entirely locally against the canonical record — digest, then derivation, then public
key match — so there is no online oracle to rate-limit. The membership walk is
fail-closed: a repeated `state_sha256` is rejected via a `BTreeSet` seen-set, and
the object count is capped by `BUDGET.max_events`.

**Ledger transaction integrity** (`vault/native_transactions.rs`,
`native_transaction/journal.rs`) — every state change runs inside a SQL
transaction, and the step transition uses a compare-and-swap `UPDATE` that fails if
`changed != 1`, so a concurrent writer is detected rather than overwritten. Step
entry is idempotent, which is what lets crash recovery re-enter a step it had
already entered. `commit_native_success` cross-checks the legacy and native
receipts against each other (target counts, per-target fingerprints, duplicate
targets) and is idempotent on replay. Because each WAL transition commits on its
own, a compensation that fails partway leaves the earlier transitions durable, so
resumption has to dispatch on each record's current state rather than replay a
fixed step list; `finish_compensated` does exactly that, with an explicit no-op arm
for a record already restored, and #38 exercises it. The journal releases its profile lock on
every error path and composes both the primary and the compensation error when a
rollback also fails. The gap found here was in the tests rather than the code, and
is now covered by #35.

**Bridge install** (`contextd/src/bridge_install.rs`, `core/src/mcp/install.rs`) —
the module holds no direct filesystem writes in production code; it builds a plan and
hands it to the native transaction engine, so it inherits the guarantees above rather
than reimplementing them. The trait boundary is explicit about it: implementations
receive protocol DTOs only, and callers cannot inject paths, digests, commands or
plan bodies into apply or rollback. No shell is ever invoked. The executable is
attested before use: the path must be absolute and free of control characters,
`symlink_metadata` (not `metadata`, so it does not follow the link) must show a
regular file that is neither a symlink nor a reparse point, it must carry the
executable bit, and the value that gets stored and launched is the `canonicalize`d
path rather than the supplied one.

**Sync retry and backoff** (`core/src/sync/`) — `BackoffPolicy::next_delay` is
overflow-safe: the exponent shift is guarded by `attempt >= u64::BITS`, the multiply
is `saturating_mul`, and the `bound + 1` case that would wrap on `u64::MAX` is
special-cased rather than computed. In-memory transport loops cap at
`MAX_ATTEMPTS = 3`. The persisted outbox is bounded differently and deliberately: a
non-retryable error, or a row that cannot fit a request, is deferred by
`PERMANENT_RETRY_MS = i64::MAX`, and the due query filters on
`next_attempt_ms <= ?1`, so a parked row never becomes due again. `attempt_count`
still increments on a parked row, but nothing reads it after that.

**Hosted auth** (`contextd/src/hosted_auth.rs`) — the session maintenance task is
generation-scoped and every state write goes through `publish`, which re-checks
`closed` and the generation under the lock, so a late task cannot overwrite a newer
attempt. Cancellation is a token rather than a flag on shared state, and a late
cancel after the session is connected is covered by
`late_cancel_preserves_connected_session_and_shutdown_preserves_credentials`. The
refresh loop after the wait loop was unbounded — no deadline, no cancellation check,
exiting only when the error stopped being retryable — and is fixed in #37.

**Dispatch outside the workspace queue** (`contextd/src/lib.rs`) — the pairing and
recovery executors are unavailable unless a service is injected, and
`HarnessPrepare` delegates to `bridge_install::prepare`, which builds a plan rather
than touching the filesystem. `ProjectPathSet` goes to `put_path`, which rejects an
empty id and validates the value; every other caller is test support. The `Desktop`
role is enforced by `role_allows` at the IPC layer for all of these, not by the
narrower list inside `route_request`.

**Harness launch** (`src-tauri/src/harness_launch.rs`) — the executable is spawned
with `Command::new` and an explicit `args` array, never a shell, so a harness path
cannot become a shell command. The plan is re-validated on the Tauri side rather than
trusted from the daemon: the executable and root must both be absolute, the
executable must be a file, the root a directory, and a Hermes profile is only
accepted for harnesses that take one. The Tauri command surface is small and
deliberate — eleven commands, with recovery behind its own four.

**Desktop privilege separation** (`src-tauri/src/main.rs`,
`apps/desktop/src/local-client.ts`) — recovery runs under a distinct
`DesktopRecoveryHost` role rather than `Desktop`. Phrase entry and confirmation are
`DesktopRecoveryHost`-only while read-only status queries stay `Desktop`, so the
renderer cannot drive an approval it has no host prompt for. The recovery phrase is
entered in a native prompt and never crosses the JavaScript boundary, and the generic
`call()` throws if a recovery method is routed through it, making the dedicated
native command the only path. The prompt's failure modes are `&'static str`, so no
runtime value can reach an error message, and the word-count rejection does not echo
what was typed. No `dangerouslySetInnerHTML`, `innerHTML` or `eval`
appears anywhere in the front end.

**Screen interaction and focus** (`apps/desktop/src/*.tsx`) — the modal surfaces use
the native `<dialog>` element with `showModal()`, which supplies focus trapping and
Escape handling rather than hand-rolling them, and each captures its trigger and
restores focus from `onClose`. Surfaces that are not actually modal — the account
deletion review, for instance — are inline `fieldset`/`legend` with `tabIndex={-1}`
and move focus to the legend on open, which is the semantically correct choice
instead of pretending to be a dialog. Errors use `role="alert"` and progress uses
`role="status"`, and navigation moves focus to the new screen's heading.

**Design system conformance** (`apps/desktop/DESIGN.md`, `src/styles.css`) — the
visual layer was checked against its own written specification rather than by
inspecting the CSS alone. Every measurable contract in the document holds: the
canvas, surface and primary values, a 200px sidebar, 36px controls, 6px and 8px
corners, a 72ch prose measure, and the coarse-pointer 44px expansion. The two
documented breakpoints are present as `64rem` and `46rem` rather than the pixel
equivalents, which is the better choice given the same document requires headings to
stay at fixed rem sizes. The stacked rail is capped at `30dvh`, matching the "at most
30% of the viewport" rule, and reduced-motion and forced-colors both have explicit
rules, including a system-colour outline for selected navigation and choices.

Contrast was computed rather than eyeballed. Body text reaches 15.3:1 on the dark
canvas and 15.6:1 on the light one, supporting text 8.7:1 and 6.5:1, and the primary
action's own text reaches 7.1:1 on its fill in dark and 6.0:1 in light. The action
boundary against the canvas clears the 3:1 requirement at 6.7:1 and 5.7:1. Every
text-on-surface pairing required to clear 4.5:1 does.

## Not yet reviewed

Nothing in the audit scope is still unreviewed. What remains is narrower than the
original plan, and is recorded so the limit of this pass is visible:

- A compensation pass failing *mid-walk* is covered for the write-ahead log and the
  CLI WAL by #38. The sandbox cleanup path has the same structure and was reasoned
  about, not exercised.
- Rendered acceptance at the sizes DESIGN.md names (1180x760, 900x600, 600px, 200%
  text). Those need a running app; the browser tool here refuses localhost, so this
  pass verified the tokens, dimensions and contrast arithmetic rather than the
  rendered result.
