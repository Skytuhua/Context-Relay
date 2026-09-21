# Hermes adapter runtime integration

HermesAdapter can passively prepare a durable runtime reference and reopen the
exact reference in an authenticated, opened setup plan. Reopening checks the
harness, adapter version, selected profile, project, executable path/hash and
reported version before opening the store. The caller still authenticates the
sealed plan; accepting a Rust plan value is not proof of user approval.

The retained launcher's captured digest and management banner version must match
the adapter. Clones share one serialized runtime owner and cancellation flag.
Projected configuration is checked through the owned core facade. Failure leaves
all clones unable to reuse the lost owner; there is no ordinary-launcher fallback.
Installation revalidation also checks retained bytes while their leases remain
held. Attaching a runtime keeps the adapter ImportOnly until connection, restart
and Undo qualification is complete.

Review corrected an initial preparation method that launched a version check
before the runtime could be bound into approval. Preparation now only captures,
rechecks and retains bytes, returning their reference without running code. The
reviewer approved the correction and found no further ownership or fallback issue.

Validation:

- Four adapter tests pass, covering shared-owner contention/cancellation,
  captured-launcher and version mismatch, ten changed approval bindings rejected
  before opening a missing store, and exact-reference reopening after failure.
- The actual configuration dispatch uses an inert compiled native process. It
  checks the projected profile, returns configuration output, and injects stderr
  failure. A panic-on-use ordinary launcher proves that path is never reached.
- The broader Hermes library group passes 72 tests, with three opt-in tests
  ignored. Initial parallel process fixtures correctly encountered the runner's
  global Busy limit; a shared test-only guard now serializes their executions.
- All 72 Hermes adapter integration tests pass. Core and contextd all-target
  Clippy with test support and warnings denied passes. Formatting and whitespace
  checks pass; the code knowledge graph is refreshed.

No daemon or desktop caller is connected to these preparation/reopening APIs yet.
Preparing, retaining and locking still include long synchronous work; cancellation
is checked at preparation boundaries and during commands, not inside each copy or
inventory loop. A responsive preparation workflow, setup-plan propagation, daemon
consumption, real connection/restart/Undo and installed acceptance remain open.
The existing unsigned local EXE is unchanged.
