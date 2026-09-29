# Responsive Hermes runtime preparation

The current desktop preview request uses the daemon's single vault worker. The
existing request cancellation mechanism skips queued work but does not interrupt
active work. Calling the minutes-long Python capture from this worker would also
delay unrelated vault actions. Preparation must run outside that worker, with
bounded ownership, visible progress and cancellation, before enabling the desktop
connection flow.

## Implemented preparation control

Passive capture and retention now accept a cancellation flag and synchronous
progress callback. The adapter exposes the combined operation. Callbacks contain
only a closed phase and completed file/byte counts, with no source paths or secret
values. Counts reset per active phase; Ready retains the retention totals. They
describe completed work rather than an invented percentage or completion estimate.

Phases are Inspecting, Copying, CheckingSource, CheckingCopy, Retaining and Ready.
Copy and read verification check cancellation at 64 KiB chunks. Directory walks,
startup-file inspection, projection normalization, manifest validation and Unicode
path-collision comparisons also check cancellation. Retention checks between
native file hashes and directory flushes and before publishing the reference.

Cancellation before publication returns Canceled and drops the temporary copy's
owner. Its files and pinned directories clean up without touching source files.
Ready is emitted after publication; cancellation after that point returns the
committed reference rather than reporting failure for a retained copy. Individual
filesystem calls, native hashes/flushes and bounded parser/sort calls remain
synchronous. This is cooperative cancellation, not a hard completion deadline.

The existing path-policy API keeps its behavior. A cancellable variant adds
checkpoints inside Windows ordinal alias comparisons and returns a distinct
cancellation error. Large directories with non-ASCII filenames no longer require
finishing a quadratic comparison pass before observing cancellation.

## Verification

New tests first failed to compile because controlled preparation did not exist.
Five focused preparation tests then passed: cancellation before any installation
read, cancellation during copy/source/copy checks, retention cancellation,
cancellation after either final directory flush, and successful phase counts with
a cancel arriving after publication. Canceled copies are removed and source bytes
are preserved. Two native path tests verify comparison-time cancellation and
unchanged collision rejection.

Review identified an uncanonicalized macOS temporary-path fixture and the missed
Unicode comparison loop. Both were corrected. Native-runner library tests pass
56 cases. The broader Hermes library suite passes 77 tests with three opt-in
checks excluded. Core/contextd/native-runner all-target Clippy passes with test
support and warnings denied. Formatting and whitespace checks pass. Independent
review approved both corrections with no further actionable findings.

## Implemented daemon ownership and IPC

The daemon now owns one background preparation worker. Start briefly resolves
the registered project on the vault worker, then snapshots Python installation
metadata and captures the runtime on the separate worker. This discovery path
cannot enter the native version-command branch. A bounded channel admits one
preparation at a time; progress coalesces into one in-memory status. Status and
Cancel requests bypass the vault queue. Repeating the current operation ID and
selection returns its status before resolving mutable project inputs again.
Other active starts return Busy; reusing the current ID with different inputs
returns Conflict. Replacing a terminal operation expires its old status.

Protocol 1.8 adds Desktop-only harness_prepare, harness_preparation_status and
harness_preparation_cancel. Start binds an operation ID and harness selection;
status/cancel take only that ID. Replies contain a closed phase, bounded counts,
selection and a fixed error. No runtime path, manifest reference or command is
accepted or returned. Older ordinary clients still require an exact version;
authenticated installer shutdown also accepts the previous 1.7 candidate.

PreparedRuntime owns the unused holder and releases its pins before cleanup.
The worker owns a successful result until explicit setup consumption.
Replacing an unused result cleans it on the worker, outside the status lock.
Ready is published only after the owned result returns; a late cancel cannot turn
a successful result into Canceled. The durable core API still transfers cleanup
ownership before reporting Ready. Daemon shutdown closes admission, cancels and
joins the worker before releasing instance ownership. Async shutdown retains its
join handle across awaits, so dropping the future does not detach the writer.

Four coordinator tests cover nonblocking status/cancel, idempotency, result
ownership, panic redaction and joined shutdown. Two core tests verify cleanup of
an unused copy and persistence of an explicitly transferred copy. Authenticated
IPC tests exercise background progress, unrelated project reads, cancellation,
role denials, retry without a second factory call, and status loss after restart.
The factory deliberately fails if called again, reproducing the review finding
that a renamed project could otherwise break a lost-response retry.

Current validation passes 79 Hermes library tests (three opt-in checks ignored),
66 daemon library tests (one ignored), all 13 harness setup IPC tests, the full
protocol/local-IPC suites, frontend type checking and 193 frontend tests.
Core/contextd/protocol/local-IPC all-target Clippy passes with test support and
warnings denied. Independent review approved the replay and passive-discovery
corrections. The test build initially exhausted disk space; Cargo cleanup scoped
to the two affected project crates reclaimed 30.1 GiB before the successful runs.

## Remaining desktop and setup work

Setup preview now carries the adapter-selected installed runtime into the v2
approval hash and sealed plan. The same identity survives vault reopening and
the linked Undo plan. Preview rejects identity changes during rendering; the
watch-only path rejects a binding acquired during probe, source registration or
digest callbacks before saving an unbound plan. A valid watch-only baseline still
succeeds. These checks do not enable Python execution or consume daemon results.

The three runtime-plan tests and all 17 primary-memory setup tests pass. The
watch-only regression first reproduced a saved plan that discarded the newly
acquired binding. Core/contextd all-target Clippy with test support and warnings
denied passes. Independent review approved the final watch-only check. The plan
apply/Undo fixture uses a recording executor, so it verifies sealed identity and
idempotency rather than an actual harness connection.

- Connect the desktop to the prepared-operation request described below.
  Unfinished or orphaned copies never become implicit launch authority.
- Show plain-language stages and a Cancel action. Selection changes and late
  replies must not replace the current selection's review. Existing setup review
  supplies the user's approval; do not add confirmation steps for implementation
  details.
- Propagate the reference into setup approval and reopen the exact authenticated
  plan in daemon apply/recovery before removing the current entry guards.
- Qualify actual connection, restart and Undo before enabling Full and issuing a
  replacement installer. No installed service, normal harness state or native UI
  was changed by preparation-control tests.

## Owned passive Hermes preview

`HermesAdapter::into_setup_preview` now consumes a prepared runtime and returns
an opaque `PreparedHermesSetup`. It checks the selected launcher digest, version
0.17.0 and supported configuration shape. The private adapter can render a
preview but explicitly rejects native reprobe, configuration execution and
approved-runtime reopening. Normal adapter discovery remains ImportOnly.

The preview uses the existing bridge/memory planner and captures its rollback
states. Only after the complete plan is sealed does it transfer the runtime to
durable ownership, immediately before writing the plan into the encrypted vault.
Earlier errors clean up the unused copy. A failed vault acknowledgement preserves
the durable copy because the plan might actually have committed. Unreferenced
durable-copy collection remains future work.

The new fixture uses non-executable Python and launcher bytes. Real preview and
vault reopening preserve the exact runtime identity and approval hash, with
planned native mutations but unchanged Hermes configuration. A mismatched project
fails and removes the unused holder. This qualifies passive planning, not command
execution, native setup acceptance, or a replacement installer.

Validation passes 80 Hermes unit tests with three opt-in checks ignored, and all
54 selected bridge preview/apply/rollback, runtime-plan and primary-memory tests.
Core/contextd all-target Clippy passes with test support and warnings denied.
Clippy initially caught an adapter-size increase; the optional preview identity
now uses a box, and the focused inert preview test passes after that correction.
Independent review approved ownership transfer and the passive execution boundary.

## Exact daemon consumption and protocol 1.9

`harness_prepared_preview` takes the same operation ID and selection used for
preparation. It is Desktop-only and runs on the owned vault worker. Admission
takes the artifact once under a short lock; plan construction and cleanup run
outside that lock. Status and Cancel remain responsive. Another preparation or
consumer cannot replace the operation during preview. Successful plans and
failed results are cached for the same operation/selection, including a client
reconnect after a lost response. Changed selection conflicts. Daemon restart
expires the in-memory operation; it does not rediscover an arbitrary copy.

Production preparation now retains the captured adapter inside PreparedHermesSetup
along with the canonical vault path and device identity. Consumption validates
the current workspace and registered project before invoking the passive core
preview. Production consumers explicitly reject the test-only fixture artifact.
Preview panic payloads are redacted, and failures cannot consume the copy again.

Protocol 1.9 makes the new method explicit and updates generated bindings,
schemas, fixtures and independently computed .NET authentication vectors.
Authenticated installer shutdown accepts the preceding 1.8 candidate alongside
1.4–1.7. Ordinary clients still require the exact protocol version.

Six coordinator tests cover lifecycle, nonblocking status, single consumption,
selection conflict and success/failure replay. The authenticated IPC fixture
checks the new route, client reconnect, changed selection, one factory/preview
call, restart expiration and denials for Installer/MCP/RecoveryHost roles. It
uses a recording engine and a test-only artifact; production runtime execution
is not qualified by that fixture. Live retained-runtime apply/recovery and the
desktop progress/cancel flow remain unfinished.

Validation passes all 14 authenticated harness IPC tests, 68 daemon unit tests
(one opt-in ignored), full protocol/local-IPC suites, 193 frontend tests and 37
affected MCP lifecycle/dispatcher tests. Frontend type checking passes. Clippy
with test support and warnings denied passes core, daemon, protocol and local-IPC
targets. Initial runs caught missing test imports, stale protocol fixtures, a
Windows metadata-file lock, and the cached plan enlarging the worker message.
Fixtures/imports were corrected, builds completed before the lock retry, and the
cached result now uses a box. Independent review approved the consumer, workspace
binding, role checks and shutdown ordering. No native UI or ordinary harness
configuration was used for these checks.
