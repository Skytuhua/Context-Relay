# Tracked harness Save and durable setup history

The daemon used to wait up to 29 seconds for a harness settings change. A native
setup can take minutes, so the caller could receive a timeout while the worker
continued and eventually committed. The desktop also held saved setup identities
only in component state.

## Implemented backend contract

Protocol 1.10 adds five Desktop-only requests:

- `harness_execution_start`: original PlanId and action (`apply` or `rollback`).
  The daemon accepts owned work promptly; repeated starts join an active matching
  attempt. A different active attempt returns Busy. Explicit starts after an
  attempt finishes return through the existing persisted-plan validation again.
- `harness_execution_status`: immediate observation for that exact pair.
- `harness_execution_current`: immediate discovery of the newest accepted attempt,
  including its identity, so a reopened desktop can recover without the vault queue.
- `harness_setup_get`: authoritative validated original settings plan and lifecycle.
- `harness_setups_list`: a bounded page of redacted summaries, newest IDs first.
  `after` continues the traversal. Each page scans at most 50 stored plans, with
  one lookahead ID; a filtered empty page can still have a continuation cursor.

Queued and Running are daemon-owned attempt states. Finished describes the
attempt, **not** the current durable settings state. Unknown means the observation
is unavailable, including after daemon restart or cache eviction. Completion must
be resolved against the exact persisted plan. A failed Undo may leave an Applied
plan; that lifecycle alone is never evidence that Undo succeeded.

The coordinator keeps at most 16 attempt hints and one active owner. Its short
locks never surround vault access, native execution, or queue callbacks. Bounded
queue rejection removes the reservation. An execution ticket owns admission even
after the caller disconnects; worker completion or ticket destruction publishes
the outcome or uncertainty. Shutdown joins accepted work using the existing vault
worker. No second vault writer or detached native task is introduced.

Start, Status, Current, preparation Status/Cancel, and Health use the desktop's
separate cached control connection. Other requests use the ordinary connection.
Authentication and daemon routing both restrict the new requests to Desktop.
Ordinary clients still require the exact protocol version. Installer shutdown
alone also accepts authenticated candidates on protocols 1.4 through 1.9.

History validates sealed approval and stored identity before returning an original
`bridge-preview-v1` plan. It excludes linked inverse plans, watch-only registration,
and memory export. Summaries omit native paths and setting contents. The encrypted
vault remains the durable authority; observing history never executes a plan.

## Verification

- Protocol round trips reject extra fields, missing nullable fields, ambiguous
  status/error combinations, invalid history states and oversized pages.
- Coordinator tests cover response drop, active deduplication, competing requests,
  queue rejection, worker destruction, bounded cache, and redacted action-specific
  errors.
- An authenticated disposable daemon test blocks the worker for 31 seconds,
  reconnects, recovers its identity, polls and rejoins within two seconds, then
  confirms shutdown waits for exactly one owned execution.
- Core integration tests reopen a saved plan and traverse filtered pages; linked
  Undo returns the original as RolledBack and hides its Applied inverse.
- The actual Tauri transport test blocks an ordinary request while all immediate
  control requests complete over a single reused authenticated connection.
- Protocol 1.10 client/server HMAC vectors were independently calculated with
  .NET HMACSHA256.

The separate actual copied-runtime Hermes qualification passed in 1622.25 seconds
using code from 0d0cc00. It exercises native Save, fresh-process discovery, vault
reopen, reapply, Undo and readback through Hermes's own settings loader. It used
disposable profiles and a copied runtime, not the user's ordinary harness state.

## Remaining integration

The screen still uses the older synchronous Save/Undo methods. Wire the tracked
requests into visible polling, recovery after screen changes/restart, exact-plan
review and Undo, and purpose-filtered history. Queue acceptance must never display
Settings saved. Applying/RollingBack with no live owner must display interrupted
or unconfirmed, with explicit recovery rather than an endless spinner.

The visible preparation progress/cancel flow, production Full gates, live harness
connection validation, rebuilt installer and installed acceptance remain unfinished.
Native Computer Use remains paused. No new EXE is claimed by this backend change.
