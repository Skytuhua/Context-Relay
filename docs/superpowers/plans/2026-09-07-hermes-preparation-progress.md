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
The worker owns a successful result until later setup consumption is implemented.
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

- Preserve the completed reference for sealing into the reviewed setup plan;
  unfinished or orphaned copies must never become implicit launch authority.
- Show plain-language stages and a Cancel action. Selection changes and late
  replies must not replace the current selection's review. Existing setup review
  supplies the user's approval; do not add confirmation steps for implementation
  details.
- Propagate the reference into setup approval and reopen the exact authenticated
  plan in daemon apply/recovery before removing the current entry guards.
- Qualify actual connection, restart and Undo before enabling Full and issuing a
  replacement installer. No installed service, normal harness state or native UI
  was changed by preparation-control tests.
