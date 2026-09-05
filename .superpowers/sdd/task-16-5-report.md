# Task 16.5 implementation report

## Review remediation RED evidence

- Lost-hint consumption RED: `cargo test -p context-relay-core --test sync_engine_v1 deterministic_faults_are_nondestructive_and_lost_hints_do_not_block_pull` failed at the second `take_change_hint` assertion. Root cause: the lost-hint counter returned `false` without consuming the corresponding pending hint, so the same hint could be retrieved later.
- Cursor binding RED: `cargo test -p context-relay-core --test sync_engine_v1 mismatched -- --nocapture` failed both adversarial tests. A main-row cursor ID/timestamp mismatch applied one operation, and a range-row cursor ID mismatch committed the repair plus blocker. Root cause: page structure was checked, but `ReceivedOperation.cursor` was never bound to the routed/canonical operation and `received_at` was validated only inside mutating Vault paths.
- Gap byte-progress RED: `cargo test -p context-relay-core --test sync_engine_v1 large_gap_prefix_commits_before_blocker_budget_and_resumes_after_reopen -- --nocapture` reported `gaps_repaired = 0` instead of 1. Root cause: the engine charged the >4 MiB blocking row before fetching its >4 MiB missing prefix, exhausting the 8 MiB cycle budget before any repair could commit.
- Provider namespace RED: the explicit `SyncProvider::{Memory,Supabase}` cursor-isolation test failed to compile because no provider type existed and `SyncEngine::new` accepted only scope. Root cause: engine cursor reads/writes used a module-level hardcoded `"memory"` constant.
- Durable quarantine RED: the regression was written before the migration/API and referenced absent `SyncQuarantineWrite`, `SyncQuarantineDisposition`, and Vault quarantine methods. The baseline schema version was 14 and contained no quarantine table, so the required atomic insert/readback/replay behavior had no implementation surface. The isolated Rust toolchain became available after the production patch; the focused regression then passed as part of the GREEN evidence below.
- Oversized pull analysis: the reviewed pre-fix order reserved cycle bytes before enforcing the 5 MiB canonical envelope limit. A malicious oversized row could therefore return `more_work` indefinitely. The first fix advanced the cursor without durable rejection evidence; final re-review correctly rejected that unaudited skip.
- Durable oversized-rejection RED: `cargo test -p context-relay-core --features test-support --test sync_vault_v1 oversized_rejection_insert_replay_conflict_and_cursor_advance_are_atomic_and_durable -- --exact --nocapture` failed with E0432 for absent `SyncRejectionDisposition`/`SyncRejectionWrite` and E0599 for absent rejection insert/read methods (seven compile errors). The baseline schema-v15 engine path used cursor-only `advance_rejected_sync_cursor`.

## Status

DONE: the in-memory ciphertext transport, bounded one-cycle sync engine, and forward-only durable quarantine/rejection migrations are implemented. All review findings are covered by focused regressions and the required gates pass.

## What was implemented

- Added the exact ciphertext-only `SyncTransport` values and trait, plus stable allowlisted `TransportError` classes.
- Added account/workspace-partitioned `InMemoryTransport` operation and checkpoint stores.
- Enforced canonical envelope/routing agreement, exact-byte operation-ID duplicates, unique device sequences, 256-item batches/pages/ranges, the fixed 8 MiB transport-request ceiling, strict `(received_at, operation_id)` cursor order, and bounded batch/checkpoint bytes.
- Added deterministic counters for transient push/pull/range errors, dropped pulls, delayed pulls, duplicated deliveries, reversed deliveries, and lost hints. Faults only affect delivery; accepted provider state remains invariant.
- Added `SyncEngine::sync_once` with an oldest-due prefix that fits 256 rows and 8 MiB, complete duplicate-free receipt validation, exact acknowledgement/defer behavior, durable polling, sorted pages, sequential device-gap repair, admission/merge, representative embedding resolver forwarding, and explicit operation/byte bounds.
- Added safe status mapping: transient persistence failures remain transient, unknown/revoked device material returns `revoked`, cryptographic/integrity failures are durably quarantined before cursor advancement, and no raw provider/Vault error text escapes.
- Narrowly factored Vault admitted application so a range-repair operation persists its real validated receipt timestamp without advancing the global provider cursor. The blocking row later applies with cursor advancement in its existing atomic transaction. The helper is crate-private.
- Added migration `0015_sync_quarantine.sql` with only scoped receipt/routing metadata, an allowlisted reason/time, and the exact bounded signed envelope. Insert or exact replay and optional cursor advancement are one transaction; altered bytes at the same receipt cursor fail closed.
- Added forward migration `0016_sync_rejections.sql` for oversized receipts. It stores only scoped routing/cursor metadata, an allowlisted reason, checked claimed length, the SHA-256 of all exact received bytes, and first rejection time—never the oversized bytes or a truncated prefix. Insert/exact replay and optional cursor advancement are atomic; altered digest, length, or routing conflicts before cursor movement.
- Added end-to-end tests for exact and altered duplicates, valid sequence reuse conflicts, scoped stores, provider cursor isolation, 256-row/timestamp-tie pagination, checkpoint duplicate/bounds, all deterministic delivery faults, durable outbox retry/reopen, accepted-before-ack crash replay, every malformed receipt matrix shape, cursor binding, durable quarantine/reopen, broken-device isolation, oversized poison rows, revoked status, ordered/chunked gap repair, crash between repair and blocking operation, exact replay cursor advancement, and clean-vs-faulted convergence.

## TDD evidence

### Initial RED

Command:

`cargo test -p context-relay-core --test sync_engine_v1`

Expected failure observed before production code:

```text
error[E0432]: unresolved imports ... CanonicalOperation, FaultSchedule,
InMemoryTransport, SyncEngine, SyncScope, SyncTransport, TransportError
```

This proved the new test target exercised the absent Task 16.5 public interfaces.

### Additional RED regressions found during self-review

- `checkpoint_transport_is_scoped_exact_and_bounded` failed because an oversized checkpoint was accepted. The provider now rejects checkpoint bytes above the canonical operation limit.
- `invalid_pulled_ciphertext_is_counted_and_blocks_cursor_without_decryption` failed because invalid routing/ciphertext returned early instead of contributing the stable quarantine count. Its replacement now proves exact bounded ciphertext readback, atomic cursor advancement, reopen durability, and no device-head mutation.
- `revoked_or_unknown_device_is_stable_and_never_mislabeled_as_quarantine` failed because `InvalidIdentity` was counted as quarantine. Admission failures are now classified into `revoked`, `transient`, or quarantine.
- `push_uses_oldest_prefix_fitting_eight_mib_and_leaves_remainder_due` failed because the provider accepted two individually valid signed canonical operations whose aggregate exceeded 8 MiB. The provider now rejects over-limit requests, while the engine sends the oldest fitting prefix and leaves the remainder due for the next cycle.
- The expanded reverse-fault assertion revealed that duplicate and reverse counters intentionally combine on one eligible delivery. The test now schedules the reverse counter explicitly for an independent deterministic assertion.

### Final GREEN

Fresh final commands and results:

- `cargo fmt --all -- --check`: pass.
- `cargo test -p context-relay-core --test sync_engine_v1 --test sync_admission_v1 --test sync_merge_v1 --test sync_operation_v1 --test crypto_v1`: 54/54 pass (23 engine, 7 admission, 11 merge, 9 operation, 4 crypto).
- `cargo test -p context-relay-core --features test-support --test sync_vault_v1 --test vault_storage_v1 -- --test-threads=1`: 32/32 pass (14 sync Vault, 18 Vault storage).
- `cargo test -p context-relay-core --doc`: 3/3 pass.
- `cargo clippy -p context-relay-core --lib --features test-support -- -D warnings -A clippy::large-enum-variant -A clippy::too-many-arguments`: pass. The two allowed lints are pre-existing Task 16 API shapes, not Task 16.5 findings.

## Files changed

- `crates/core/src/sync/transport.rs` (new)
- `crates/core/src/sync/memory.rs` (new)
- `crates/core/src/sync/engine.rs` (new)
- `crates/core/src/sync/mod.rs`
- `crates/core/src/vault.rs` (schema version and migration runner)
- `crates/core/src/vault/sync.rs` (gap-repair/cursor and quarantine transactions)
- `crates/core/migrations/0015_sync_quarantine.sql` (new)
- `crates/core/migrations/0016_sync_rejections.sql` (new)
- `crates/core/tests/sync_engine_v1.rs` (new)
- `crates/core/tests/sync_vault_v1.rs`
- `crates/core/tests/vault_storage_v1.rs`

## Self-review

- Trust boundaries: transport APIs expose only signed ciphertext bytes and routing IDs; no mutation, key, certificate secret, plaintext, or raw error crosses the boundary.
- Cursor safety: normal apply/replay advances cursor atomically with durable state; repair apply never advances global cursor; crash/reopen coverage proves a repaired prefix cannot skip its blocking row.
- Quarantine safety: a bounded poison row and its cursor commit atomically, exact replay is idempotent, altered replay fails with an integrity code, quarantined device heads never move, and unrelated devices continue.
- Oversized rejection safety: the exact received bytes are measured and fully hashed but never stored; rejection evidence commits before/with cursor movement. Exact replay is idempotent, altered digest/length/routing cannot move the cursor, range rejection does not advance the global cursor, and schema 15→16 preserves existing quarantine rows.
- Gap repair: ranges are scoped, split to at most 256, prevalidated as complete and duplicate-free by exact sequence before mutation, applied in device order, and bounded by the cycle operation/byte budgets.
- Receipts/outbox: accepted and duplicate IDs must be a complete, disjoint, duplicate-free set equal to the pushed prefix before any acknowledgement; every failure keeps and durably defers only the involved rows under a stable safe code, while valid rows beyond the 8 MiB prefix remain due and unmodified.
- Provider invariants: all batch operations validate before insertion, so altered IDs/sequences or later invalid rows cannot partially mutate provider state.
- Representative embedding: the engine passes the trusted material and resolver into Vault only after admission; Vault invokes it for the exact merge-selected representative from Task 16.4.
- Diagnostics: only allowlisted codes are returned/persisted. No ciphertext/plaintext/raw provider error is logged or embedded in the cycle report.

## Residual concern

None for the reviewed Task 16.5 scope. Paid Apple Developer capabilities remain outside this task and were not required for implementation or verification.
