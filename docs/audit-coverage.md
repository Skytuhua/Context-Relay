# Audit coverage

This document retains the July 2026 audit's reported coverage, with corrections
from the 18 October 2026 source review. Unless a result is explicitly attributed
to that later review, execution counts, elapsed times, visual measurements, and
claims that commands passed are historical reports from the original audit, not
fresh runs against the revised PRs. Coverage of a listed area does not establish
that every path or platform in that area was verified.

## Review corrections — 18 October 2026

These corrections describe the reviewed follow-up patches and the later Linux
rehearsal results. Windows-specific execution remains a separate acceptance gate.

| PR | What the source review established | Corrective behavior and validation limit |
|---|---|---|
| #33 | The original 64-session cap had no removal path. The first 64 distinct IDs could therefore occupy capacity for the provider's lifetime. | Reclaim records after one hour of monotonic inactivity only when no join client or clone retains them. Live and recently used sessions keep their five-attempt history; a reclaimed idle ID starts a new session if reused. Three session regressions and thirteen pairing retention/transport tests passed in the Linux rehearsal. Windows qualification remains separate. |
| #37 | Transient refresh failures already used backoff; this was not a busy loop. The proposed 15-minute terminal cutoff abandoned automatic recovery after a longer outage. | Continue transient `Unavailable`/`Busy` retries with a 5-to-60-second backoff, checking generation cancellation before another attempt. Terminal auth errors stop the task; login, logout, and shutdown also cancel/abort its ownership. Three paused-time tests exercise the production retry helper, including recovery after a 16-minute outage. The existing service-level expiry and credential tests are retained; their revised native run was pending. |
| #38 | The original added tests copied the compensation walk and did not call `finish_compensated` or reopen the vault. They could pass while that production method regressed. | The replacement journal unit tests call the real finalizer, inject a database failure on its second row, close and reopen the encrypted vault, and resume the finalizer under a reacquired profile lock. They check durable terminal state and cleanup, including retained CLI conflicts. Both real Rust regressions passed in the Linux rehearsal; Windows qualification remains separate. |
| #41 | Waiting up to ten seconds after cleanup returns weakens the assertion that ownership is returned only after descendants stop. Opening a PID only afterward also leaves process-identity reuse unexcluded. | The revised fixtures retain a handle to the live descendant before allowing its parent to exit. They record `WaitForSingleObject(handle, 0)` immediately after the management call returns, before joining the observer. This removes PID ambiguity and preserves the assertion; it does not establish that PID reuse caused the historical failures. Windows execution of those revised tests was pending. |
| #45 | Exiting the original skip-detection step did not skip either later Cargo test step: neither had a condition. A successful classifier result alone did not verify workflow wiring. | A step output now conditions both Cargo test commands. Only explicitly recognized frontend/documentation changes may skip; unknown paths, scripts, native inputs, invalid or missing bases, and non-PR events run the tests. Three Node tests covering classification, real Git changes, and the actual workflow conditions passed during the local Linux review. Required jobs and their names remain present; this is not a measurement of the complete Windows job's runtime. |

The #31 follow-up also replaces its copied poison-recovery test helper with an
import of the server's actual helper and checks that existing entries survive.
The #36 follow-up uses one shared 20-second observation window for all five
descendant cases, replacing five sequential windows; its native assertions and
probe deadline remain in place. The two production-helper tests for #31 and the
shared descendant test for #36 passed on Linux; the latter took 20.73 seconds.

The combined desktop rehearsal passed all 59 suites and 492 tests, whole-app
typechecking, full lint, and the production build. The native rehearsal passed
138 focused protocol, local-IPC, MCP, and core tests with Rust 1.97.1, serde
1.0.229, and thiserror 2.0.19. Production daemon compilation and generated
binding/schema parity also passed. Windows-only binding and process tests,
the hosted-auth unit-test module, and installed first-launch behavior remain
separate gates; these Linux results do not establish them.

## Findings and changes recorded by the original audit

| PR | Area | Recorded finding or change |
|---|---|---|
| #31 | `context-mcp/src/server.rs` | Five mutex unwrap sites could turn a poisoned lock into repeated panics. The follow-up tests the real recovery helper and checks retained state rather than a copied implementation. |
| #33 | `core/src/devices/memory_transport.rs` | Unread expired invites and anonymous join-session IDs accumulated. The audit reported 120 retained invites over 120 hours. The first proposed session cap required the lifetime correction described above. |
| #22 | `core` daemon records | The daemon returned records that the app rendered without validating them first. |
| #23 | `apps/desktop` setup wizard | The primary action style was lost and setup progress was not shown, so the wizard gave no sense of where it was. |
| #24 | `apps/desktop` setup wizard | Setup could advance past a step before a harness had actually been saved. |
| #25 | `apps/desktop` | A render failure inside one screen lost the whole app instead of being contained. |
| #26 | `apps/desktop` revocation | A rejected revocation was not reported inside the dialog that started it. |
| #27 | `apps/desktop` account deletion | Account deletion requests were not reachable from the screen that manages them. |
| #28 | `apps/desktop` pairing | An expired pairing code counted down instead of saying it had expired. |
| #30 | `apps/desktop` | Keyboard shortcuts for navigation, creation and projects. |
| #34 | `docs/audit-coverage.md` | Recorded which surfaces this audit had actually covered. |
| #35 | `core` native step guards | Added focused entry/order guard tests. This does not imply that the pre-existing native transaction and recovery suites covered only successful execution. |
| #36 | `core/src/codex/hook_readback.rs` | The audit reported process-probe failures under load. The revised observation window is shared across cases rather than added once per case. |
| #37 | `contextd` hosted session | Reviewed retry lifetime and cancellation. Backoff was already present; the proposed 15-minute cutoff needed correction to preserve recovery after prolonged outages. |
| #38 | `core` native WAL | Added intended midpoint-compensation coverage. The copied-walk tests needed replacement with actual finalizer interruption and resumption; existing recovery and cleanup tests were already present. |
| #39 | `apps/desktop/vite.config.ts` | `style-src 'self'` blocked Vite's injected dev styles, so the dev server rendered the app unstyled. |
| #40 | `apps/desktop/index.html` | The CSP meta tag repeated `frame-ancestors`, which browsers ignore in a `<meta>` tag, so the document claimed clickjacking protection it did not have and logged an error on every load. |
| #41 | `native-runner` Windows tests | The audit reported intermittent descendant checks and cascading `SERIAL` poisoning. The ten-second post-return wait did not prove the ownership contract; the corrected tests pin descendant identity and retain the immediate assertion. |
| #43 | `apps/desktop/src/devices.tsx` | A failed recovery-expiry cancel was swallowed, so the user was told setup was expired while the local service still held an enrollment the screen could no longer show or stop. Visibility, not safety: `RecoveryEnrollment::cancel` runs `expire_pending` first, so an expired enrollment is cleared regardless. |
| #44 | `apps/desktop/src/harnesses.tsx` | A setup review that failed because the local service was down showed generic harness guidance, sending the user to check configuration instead of the missing service. Now routed through the same classifier as #42. |
| #42 | `apps/desktop` connection failure | Every connection failure showed the same sentence, and the cause was discarded after one boolean test, so a stopped service, a firewall, and a version mismatch were indistinguishable to the user. |

## Historical areas reviewed

The entries below retain the original audit's specific observations. The dated
corrections above supersede the affected conclusions; these entries are not a
claim of exhaustive verification or a new test run.

**Local IPC** (`crates/local-ipc/`) — HMAC-SHA256 with domain separation for client and
server, `verify_slice` for constant-time comparison rather than `==`, `Zeroizing` on
token material, redacted `Debug` impls, and mutual authentication (the daemon proves
itself, not just the client). Frame length is bounded on both read and write, and the
daemon caps concurrent connections with a `Semaphore`.

**Pairing provider** (`core/src/devices/memory_transport.rs`) — codes are Crockford
base32 generated from `OsRng` via `try_fill_bytes` (no panic path), stored HMAC'd under
a pepper rather than in plaintext, compared with `verify_slice`, and de-duplicated
against existing invites before insertion. Code guessing is capped at five attempts per
stored session. The revised idle-retention rule keeps that history for live and
recently used sessions rather than deleting it whenever an RPC client is dropped.
Invite lifetime, terminal states and the cancel/approve/deny transitions were
among the historical checks.

**MCP JSON-RPC** (`context-mcp/src/`) — unknown methods return `METHOD_NOT_FOUND`
rather than falling through, the `initialize` lifecycle is enforced so it cannot be
repeated, every handler parses and validates its own params, and frame size is bounded
with `checked_sub`/`saturating_add`. Tool calls are gated by a token-bucket rate limit
and a `MAX_IN_FLIGHT_TOOL_CALLS` semaphore; the bucket uses `saturating` arithmetic so
it cannot overflow.

**Credential storage** (`core/src/auth/`) — `StoredLogin` wraps the refresh token in
`Zeroizing` and redacts `Debug`. Records are version-pinned, bound to the project URL,
size-capped, and every UUID is canonicalised. Keyring entry names are SHA-256 digests
of project and profile, binding their namespace to those inputs. The digest is
not secret access control and does not make known project/profile inputs unguessable.
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
fixed step list. `finish_compensated` has an explicit no-op arm for an already
restored record, but the original #38 tests copied that dispatch rather than
exercising it. The replacement tests described above call the real method.
A failed durable write can leave the profile lock held by the journal; the
replacement tests check that it remains held after the injected interruption and
is released after terminal finalization. The owned lock is also released when the
journal is dropped. The earlier claim that every error path released it
immediately was incorrect. #35 covers specific step-entry/order guards, not every
possible compensation or cleanup failure.

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
generation-scoped. `publish` checks `closed` and the generation under the lock;
the inline transition to `Connected` performs its own checks under that lock.
The earlier statement that every state write used `publish` was inaccurate.
Cancellation uses a generation token, and the existing
`late_cancel_preserves_connected_session_and_shutdown_preserves_credentials`
test covers a late cancel after connection. The original refresh loop already
slept between transient errors and capped its backoff at 60 seconds. The #37
follow-up keeps automatic recovery available after a prolonged outage while
checking cancellation before another attempt; it does not use a terminal
15-minute cutoff. Expired access tokens are not displayed as connected merely
because refresh maintenance continues.

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
original audit reported checking the visual layer against its written
specification and finding the following measured contracts satisfied: the
canvas, surface and primary values, a 200px sidebar, 36px controls, 6px and 8px
corners, a 72ch prose measure, and the coarse-pointer 44px expansion. The two
documented breakpoints are present as `64rem` and `46rem` rather than the pixel
equivalents, which is the better choice given the same document requires headings to
stay at fixed rem sizes. The stacked rail is capped at `30dvh`, matching the "at most
30% of the viewport" rule, and reduced-motion and forced-colors both have explicit
rules, including a system-colour outline for selected navigation and choices.

The original audit reported computed contrast values. Body text reached 15.3:1 on the dark
canvas and 15.6:1 on the light one, supporting text 8.7:1 and 6.5:1, and the primary
action's own text reaches 7.1:1 on its fill in dark and 6.0:1 in light. The action
boundary against the canvas clears the 3:1 requirement at 6.7:1 and 5.7:1. Every
text-on-surface pairing it checked against 4.5:1 was reported to pass. These
measurements were not recomputed for this documentation correction.

## Windows process management

The original audit reported its first `crates/native-runner` suite execution and
attributed intermittent `windows_management` descendant failures to asynchronous
termination. It reported 30 consecutive runs before and after the original #41
test change, with 3 failures before and 0 afterward on the same machine, and
said it could not reproduce the race on demand. Those are retained historical
reports, not newly reproduced measurements or evidence of a particular root
cause.

The original change waited up to ten seconds after the management call returned.
That can observe eventual termination but cannot prove that returning the runtime
owner was already safe. The zero-time assertion expresses the required
at-return contract. The October revision keeps it and acquires the descendant's
handle before parent exit, avoiding a later lookup of a potentially reused PID.
If that immediate assertion fails on the retained handle, production cleanup
needs investigation; another post-return wait would hide the distinction. No
production cleanup change is included in this test revision, and its native
execution was pending when this correction was written.

The separate `SERIAL` poison recovery remains: a panic in one test should not
make later tests fail only because the serialization mutex is poisoned.

The historical review also noted these specific boundaries: `path_policy`
rejects traversal,
absolute paths, control characters, over-long components, Windows reserved names
and trailing dots, and resolves collisions with platform-correct semantics: NFKC
plus `CompareStringOrdinal` on Windows, NFD plus lowercase on macOS, failing
closed if the comparison errors. `report_validation` checks scanner output with
exact-key and closed-enum matching rather than allowlists of expected values, and
all three of its public validators have dedicated tests.

## Protocol crate

The original audit reported no defect in its `crates/protocol` review and counted
6,632 lines and 36 integration-test files plus unit tests. It reported local
passes for `cargo clippy --all-targets -D warnings` and the full
`cargo test -p context-relay-protocol`. These counts and runs have not been
re-established by this documentation correction.

`canonical_cbor.rs` was read in full. Encoding is deterministic by construction
(explicit integer keys in fixed order, one CBOR type per field) and decoding is
strictly canonical: exact map length, `expect_key` in order, exact schema version,
UUID-v7 field checks, and a hard `MAX_CBOR_OPERATION_BYTES` bound on both encode
and decode. The signing preimage omits the signature field (19 keys) and the AAD
omits nonce, ciphertext, and ciphertext hash (16 keys), each map length matching
its field list, so the three encodings cannot be confused.

The pairing types are strict: `PairingCode` is exactly 11 bytes with a Crockford
alphabet excluding I, L, O and U, `PairingSafetyNumber` is five hex groups, and
both redact themselves in `Debug`. The historical sweep reported no lock
unwraps, TODOs, or non-test `unwrap()`s in the crate; that is a scoped observation,
not a guarantee that sensitive values cannot reach any log path.

## Daemon and local-IPC crates

The original audit counted `crates/contextd` at 22,791 lines and
`crates/local-ipc` at 4,671 lines and reported no additional defect in that pass.

`contextd` needed `--features test-support` to build locally — its test imports
of `SupabaseHttpClient` are gated behind that feature, matching how CI invokes
it. The original audit reported 165 passing tests across 12 targets with that
feature enabled, including a 368-second main-suite run. Those are historical
counts and timings. The recovery-enrollment history flow was read in
detail: every authorized action re-checks the login session both before and after
the action, and a denial inside the action is converted to `AuthRequired` rather
than leaking the vault error, so an expired session cannot be sandwiched between
check and effect.

`local-ipc`'s named-pipe transport is hardened the way Windows documentation
recommends: the pipe DACL is built for the current user's SID, remote clients are
rejected outright, `first_pipe_instance` catches a second daemon as
`AlreadyRunning`, and the runtime suffix is restricted to bounded ASCII
alphanumerics and hyphens. The original sweep reported no lock unwraps outside
test code in either crate.

The later startup review found that `Client::connect` allowed only five seconds
for a newly launched daemon to bind, although credential, vault, and startup
recovery work happens before binding. A separate correction raises this
endpoint-only allowance to 30 seconds and adds an eight-second simulated
readiness case. The Windows verifier reported all seven endpoint tests passing
on 18 October. Authentication and request deadlines are unchanged. That result
checks retry behavior; it does not measure cold installed-app startup latency.

## Cost of the Windows test job

The original audit identified `Rust tests (windows-x64)` as the longest CI job
and reported passing durations of 1h55m on #41 and 2h45m on #43. Both numbers are
historical reports; 2h45m is not "just under two hours." They combine job work and
do not establish whether compilation, test bodies, or setup dominated. That
requires the corresponding run's step logs and timings. The historical report
also noted that frontend-only #42 and #43 waited for the native job.

The original audit suggested evaluating build caching, selective suite execution,
and a different test runner. Those were suggestions, not measured improvements
or an assessment of the caches already configured. Changed Rust and other native
inputs still require the native checks; neither branch protection nor assertions
should be weakened to reduce elapsed time.

The original #45 guard did not skip the Cargo test steps: `exit 0` ended only
the detection step. The audit's reported examples — #42 classified as frontend,
#41 and #38 as Rust — describe the intended classification; they do not establish
that either Cargo step was actually skipped. The correction wires a step output to both the macOS guardian Cargo
test and the workspace Cargo test. Its skip set is deliberately narrow, and an
unknown path or uncertain Git base runs the tests. The required job remains
present on each matrix platform. Other required native build/lint jobs remain,
so this does not remove every compilation cost from a frontend-only PR.

The #36 follow-up removes four redundant 20-second observation windows from a
passing test by observing all five started fixtures together. That explains an
approximately 80-second wait reduction in that test's source, not the multi-hour
Windows job as a whole. No fresh end-to-end CI timing is claimed here.

## Panic-site sweep

The original audit recorded a whole-crate sweep for panic-capable constructs in
production code
(`.unwrap()`, `.expect`, `panic!`, `unreachable!`, `todo!`, indexing, `.first().`),
excluding `#[cfg(test)]` modules, `*_tests.rs` files, and `tests/` directories.

The raw counts are misleading and are recorded here so the sweep is not repeated
or mistaken for a defect list: `core` 416, `local-ipc` 142, `native-runner` 120,
`contextd` 75, `protocol` 14, `context-mcp` 12. Ranking by *file* showed the
largest counts are test modules the first pass had miscounted
(`hermes/native_setup_tests.rs` 78, `claude_code/session_tests.rs` 66,
`codex/native_setup_tests.rs` 63).

The audit classified the remaining reviewed production occurrences into two groups:

- Provable invariants — `RecordId::new(Uuid::now_v7())`,
  `HmacSha256::new_from_slice(..)`, `write!` into a `String`, and `serde_json`
  serialization of known-shaped types.
- `unreachable!()` arms guarded by an enclosing match, at
  `core/src/service.rs:225` and `:358`. Both are unreachable because the outer
  pattern already excludes the variant, and adding a variant to either enum
  would break compilation at the outer match rather than reach the panic.

The original audit reported no defect and no resulting change from this sweep.
Its counts and classifications are historical evidence of that pass, not a
statement that every possible panic or error path has been exercised.

## Coverage limits and follow-up validation

The original audit reported reading, exercising, or both for every listed crate
(`core`, `protocol`, `contextd`, `context-mcp`, `local-ipc`, `native-runner`), the
desktop app, Supabase functions and scripts, workflows, and documentation. It
also reported clean workspace Clippy and formatting checks on its then-current
`main`. Those statements are retained as historical scope and execution reports;
they do not make every area universally verified or establish that the revised
branches pass. The October correction records the specific behavior and Linux
execution results above. The remaining Windows runs, CI timing breakdown, and
installed first-run behavior remain separate validation work.

- The replacement #38 tests exercise a partial commit from the production
  compensation finalizer and reopen the vault before resumption; both passed
  in the later Linux rehearsal. Two older tests in
  `native_journal_v1.rs` already exercised terminal-cleanup idempotence, so the
  previous description of all sandbox cleanup as "reasoned about, not exercised"
  was also too broad.
  `terminal_cleanup_reclaims_wal_and_before_images_under_a_tiny_cap` calls
  `finish_native_cleanup` twice and asserts the second call succeeds, which is
  the already-terminal retry case: at step 20 with a `Cleaned` disposition the
  function returns early rather than rejecting. And
  `cleanup_conflict_accepts_a_durably_entered_terminal_cleanup_step` covers the
  `Conflict` disposition the same way. Neither test by itself establishes
  interruption coverage at every earlier cleanup boundary.
- The original audit reported rendered acceptance against the production build,
  at the four sizes DESIGN.md names. It recorded a sidebar width of 200px at
  1180x760, 900x600 and 200% text; the first control is 37px tall, rising to 58px
  when text is doubled; no viewport scrolls horizontally; and no button, link or
  input falls below 44px in any of the four. The 46rem breakpoint was observed
  switching the sidebar to a horizontal top region, and at 200% text the sidebar
  stacks vertically rather than overflowing, which is the intended reflow.

  Both themes were reported as rendered. The recorded background/text pairs were
  dark `rgb(28, 28, 31)` / `rgb(243, 243, 244)` and light
  `rgb(250, 250, 250)` / `rgb(32, 32, 36)`, reported as matching the tokens.
  Each was reported as visually inspected for legibility of the sidebar, the
  selected row and the error banner. The report noted a then-default preference
  of `dark` rather than `system`.

  That audit reported unstyled `vite dev` output due to the meta CSP blocking
  injected styles, addressed by #39. Development and packaged policy behavior
  require their respective checks; the retained production-build measurements
  are not new acceptance results for the current development server or installer.

  The #40 finding concerns `index.html` repeating CSP in a
  `<meta http-equiv>` tag, and browsers ignore `frame-ancestors` when it arrives that
  way, so the document advertised clickjacking protection it did not have and logged
  a browser warning. #40 removes that directive from the meta copy while retaining
  it in Tauri's configured policy. That source distinction does not by itself
  establish the behavior of every previously shipped package.
