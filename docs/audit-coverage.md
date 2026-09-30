# Audit coverage

Areas the July 2026 audit reviewed by hand, and what was checked in each. Recorded so
a later reader knows which surfaces have been looked at and which have not.

## Verified defects, fixed

| PR | Area | Defect |
|---|---|---|
| #31 | `context-mcp/src/server.rs` | Five `lock().unwrap()` on `std::sync::Mutex` with no `catch_unwind`: one panic poisoned the registry permanently and killed the stdio bridge. |
| #33 | `core/src/devices/memory_transport.rs` | Expired pairing invites were only dropped once a caller read them, so 120 invites over 120 hours all stayed resident. Anonymous join session ids were inserted unbounded. |
| #22 | `core` daemon records | The daemon returned records that the app rendered without validating them first. |
| #23 | `apps/desktop` setup wizard | The primary action style was lost and setup progress was not shown, so the wizard gave no sense of where it was. |
| #24 | `apps/desktop` setup wizard | Setup could advance past a step before a harness had actually been saved. |
| #25 | `apps/desktop` | A render failure inside one screen lost the whole app instead of being contained. |
| #26 | `apps/desktop` revocation | A rejected revocation was not reported inside the dialog that started it. |
| #27 | `apps/desktop` account deletion | Account deletion requests were not reachable from the screen that manages them. |
| #28 | `apps/desktop` pairing | An expired pairing code counted down instead of saying it had expired. |
| #30 | `apps/desktop` | Keyboard shortcuts for navigation, creation and projects. |
| #34 | `docs/audit-coverage.md` | Recorded which surfaces this audit had actually covered. |
| #35 | `core/src/native_transaction/` | The native step state machine had no dedicated test, so a transition regression would only surface as a confusing runtime failure. |
| #36 | `core/src/probe/` | The process probe test failed under CPU load, making the suite unreliable as a signal. |
| #37 | `contextd` hosted session | The session refresh loop was unbounded and could spin without limit. |
| #38 | `core` native WAL | An interrupted compensation pass had no coverage for the native WAL or the CLI WAL, only the happy path. |
| #39 | `apps/desktop/vite.config.ts` | `style-src 'self'` blocked Vite's injected dev styles, so the dev server rendered the app unstyled. |
| #40 | `apps/desktop/index.html` | The CSP meta tag repeated `frame-ancestors`, which browsers ignore in a `<meta>` tag, so the document claimed clickjacking protection it did not have and logged an error on every load. |
| #41 | `native-runner` Windows tests | The `windows_management` tests sampled `WaitForSingleObject` with a zero timeout against an asynchronous job-object termination, failing about one run in ten. A panic also poisoned the shared `SERIAL` mutex, reporting one failure as three. |
| #43 | `apps/desktop/src/devices.tsx` | A failed recovery-expiry cancel was swallowed, so the user was told setup was expired while the local service still held an enrollment the screen could no longer show or stop. Visibility, not safety: `RecoveryEnrollment::cancel` runs `expire_pending` first, so an expired enrollment is cleared regardless. |
| #42 | `apps/desktop` connection failure | Every connection failure showed the same sentence, and the cause was discarded after one boolean test, so a stopped service, a firewall, and a version mismatch were indistinguishable to the user. |

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

## Windows process management

`crates/native-runner` had not been exercised at all before now. Running its
suite turned up a real defect, in the tests rather than the runner: the
`windows_management` assertions checked that a job object had already terminated
a grandchild by sampling `WaitForSingleObject` with a zero timeout. Termination
is asynchronous, so the sample raced it and failed about one run in ten.

Two problems were fixed together in #41. The assertion now waits on the handle
for up to ten seconds. And because `SERIAL.lock().unwrap()` poisons the shared
mutex on panic, a single real failure was being reported as three; the guards now
recover from poisoning so a panic fails only its own test.

Measured over 30 consecutive runs each, on the same machine: 3 failing runs
before, 0 after. No production code changed. I could not force the race on
demand, so the comparison is the evidence rather than any single run.

The rest of the crate is sound as written. `path_policy` rejects traversal,
absolute paths, control characters, over-long components, Windows reserved names
and trailing dots, and resolves collisions with platform-correct semantics: NFKC
plus `CompareStringOrdinal` on Windows, NFD plus lowercase on macOS, failing
closed if the comparison errors. `report_validation` checks scanner output with
exact-key and closed-enum matching rather than allowlists of expected values, and
all three of its public validators have dedicated tests.

## Protocol crate

`crates/protocol` was reviewed without finding a defect. Its 6,632 lines carry
36 integration-test files plus unit tests, and `cargo clippy --all-targets
-D warnings` plus the full `cargo test -p context-relay-protocol` both pass
locally.

`canonical_cbor.rs` was read in full. Encoding is deterministic by construction
(explicit integer keys in fixed order, one CBOR type per field) and decoding is
strictly canonical: exact map length, `expect_key` in order, exact schema version,
UUID-v7 field checks, and a hard `MAX_CBOR_OPERATION_BYTES` bound on both encode
and decode. The signing preimage omits the signature field (19 keys) and the AAD
omits nonce, ciphertext, and ciphertext hash (16 keys), each map length matching
its field list, so the three encodings cannot be confused.

The pairing types are strict: `PairingCode` is exactly 11 bytes with a Crockford
alphabet excluding I, L, O and U, `PairingSafetyNumber` is five hex groups, and
both redact themselves in `Debug` so they cannot leak into logs. No lock
unwraps, TODOs, or non-test `unwrap()`s exist in the crate.

## Daemon and local-IPC crates

`crates/contextd` (22,791 lines) and `crates/local-ipc` (4,671 lines) were
reviewed without finding a defect.

`contextd` needed `--features test-support` to build locally — its test imports
of `SupabaseHttpClient` are gated behind that feature, matching how CI invokes
it. With the feature enabled, all 165 tests across 12 targets pass, including a
368-second main-suite run. The recovery-enrollment history flow was read in
detail: every authorized action re-checks the login session both before and after
the action, and a denial inside the action is converted to `AuthRequired` rather
than leaking the vault error, so an expired session cannot be sandwiched between
check and effect.

`local-ipc`'s named-pipe transport is hardened the way Windows documentation
recommends: the pipe DACL is built for the current user's SID, remote clients are
rejected outright, `first_pipe_instance` catches a second daemon as
`AlreadyRunning`, and the runtime suffix is restricted to bounded ASCII
alphanumerics and hyphens. No lock unwraps exist outside test code in either
crate.

## Cost of the Windows test job

`Rust tests (windows-x64)` is now the slowest thing in this repository's CI. It
runs `cargo test --workspace --all-targets` and has taken just under two hours on
recent runs: 1h55m on #41 and 2h45m on #43, both passing. Everything else in
the workflow finishes in minutes, so this single job sets the wall-clock cost of
every PR, including ones that touch only TypeScript — #42 and #43 change no Rust
at all and still wait on it.

Worth addressing at some point, in rough order of value: cache the cargo build
directory between runs, split the workspace suite so frontend-only PRs do not wait
on it, and cut it with `cargo-nextest`, which isolates each test and reports
failures directly instead of waiting for a suite to finish. None of this is a
correctness problem, so it is recorded rather than fixed here.

## Not yet reviewed

Nothing in the audit scope is still unreviewed. Every crate (`core`, `protocol`,
`contextd`, `context-mcp`, `local-ipc`, `native-runner`), the desktop app, the
Supabase functions and their scripts, the CI workflows, and the docs have each
been read, exercised, or both, and `cargo clippy --workspace -D warnings` plus
`cargo fmt --check` are clean on `main`. What remains is narrower than the
original plan, and is recorded so the limit of this pass is visible:

- A compensation pass failing *mid-walk* is covered for the write-ahead log and the
  CLI WAL by #38. The sandbox cleanup path was originally recorded here as
  "reasoned about, not exercised", which was wrong: two existing tests in
  `native_journal_v1.rs` already cover it.
  `terminal_cleanup_reclaims_wal_and_before_images_under_a_tiny_cap` calls
  `finish_native_cleanup` twice and asserts the second call succeeds, which is
  precisely the resumption case — at step 20 with a `Cleaned` disposition the
  function returns early rather than rejecting. And
  `cleanup_conflict_accepts_a_durably_entered_terminal_cleanup_step` covers the
  `Conflict` disposition the same way. So this item is closed, not outstanding.
- Rendered acceptance was carried out against the production build, not the dev
  server, at the four sizes DESIGN.md names. The sidebar measures exactly 200px at
  1180x760, 900x600 and 200% text; the first control is 37px tall, rising to 58px
  when text is doubled; no viewport scrolls horizontally; and no button, link or
  input falls below 44px in any of the four. The 46rem breakpoint was observed
  switching the sidebar to a horizontal top region, and at 200% text the sidebar
  stacks vertically rather than overflowing, which is the intended reflow.

  Both themes were rendered. Dark computes to `rgb(28, 28, 31)` on `rgb(243, 243,
  244)` and light to `rgb(250, 250, 250)` on `rgb(32, 32, 36)`, matching the tokens
  exactly, and each was inspected visually for legibility of the sidebar, the
  selected row and the error banner. Note the default preference is `dark`, not
  `system`, so the app does not follow the OS appearance until a user changes it.

  That pass turned up a real defect in passing: `vite dev` rendered the app
  completely unstyled, and #39 fixes it. The CSP meta tag in `index.html` blocks
  the styles Vite injects at runtime, so the dev server served bare HTML. The
  packaged app was never affected, because Tauri supplies the same policy as a
  real response header. Worth keeping in mind that "the dev server looks broken"
  and "the app is broken" are separate claims, and measuring both is cheap.

  One finding, now fixed in #40: `index.html` repeats the full CSP in a
  `<meta http-equiv>` tag, and browsers ignore `frame-ancestors` when it arrives that
  way, so the document advertised clickjacking protection it did not have and logged
  an error on every load. Tauri injects a byte-identical policy as a real header
  from `tauri.conf.json`, so the shipped app was never actually exposed. #40 removes
  the directive from the meta copy only, leaving the enforced policy untouched and
  the misleading one gone.
