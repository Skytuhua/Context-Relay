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

## Remaining daemon and desktop work

- Prepare the selected adapter and project binding briefly on the vault worker,
  then run passive preparation on a separately owned, bounded worker.
- Keep one operation's selection, progress, cancellation and resulting reference
  together. Polling status/cancel must not queue behind the long preparation.
- Preserve the completed reference for sealing into the reviewed setup plan;
  unfinished or orphaned copies must never become implicit launch authority.
- Stop admitting preparation at shutdown, request cancellation and settle the
  owned worker. Cancellation/completion races must produce one terminal result.
- Show plain-language stages and a Cancel action. Selection changes and late
  replies must not replace the current selection's review. Existing setup review
  supplies the user's approval; do not add confirmation steps for implementation
  details.
- Propagate the reference into setup approval and reopen the exact authenticated
  plan in daemon apply/recovery before removing the current entry guards.
- Qualify actual connection, restart and Undo before enabling Full and issuing a
  replacement installer. No installed service, normal harness state or native UI
  was changed by preparation-control tests.
