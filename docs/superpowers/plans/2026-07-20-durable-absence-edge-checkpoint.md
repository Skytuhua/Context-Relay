# Durable Absence-Edge Checkpoint Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make same-parent delete rollback fail closed across the restore-to-rebind crash interval by durably authorizing one exact absence-generation edge on the later WAL row.

**Architecture:** A later `RestorePrepared` WAL row stores the nearest earlier same-parent delete sequence and exact old/new absence tokens after its exact filesystem restore. Recovery may update the earlier row only from that durable edge and only while the live earlier target still has the edge's exact new token. A restart that sees the later target restored without the required edge marks the earlier delete `Conflict`.

**Tech Stack:** Rust, rusqlite/SQLCipher WAL metadata, Windows/macOS native filesystem adapters, subprocess crash-fault integration tests.

## Global Constraints

- Restore and recovery remain strict descending `target_sequence`.
- A nearer same-parent non-delete is a barrier; an edge cannot skip it.
- Checkpoint and rebind writes are exact, immutable, and idempotent.
- No schema-version bump: migration `0003_native_transactions.sql` is unreleased.
- External recreate/delete before or after a durable boundary is preserved as `Conflict`.

---

### Task 1: Persist the authorized edge

**Files:**
- Modify: `crates/core/migrations/0003_native_transactions.sql`
- Modify: `crates/core/src/vault/native_transactions.rs`
- Test: `crates/core/tests/native_journal_v1.rs`

**Interfaces:**
- Produces: `NativeWalAbsenceEdge { target_sequence, old_token, new_token }` on `NativeWalRecord`.
- Produces: `Vault::checkpoint_native_wal_absence_edge(transaction_id, target_sequence, later_sequence, old_token, new_token)`.
- Tightens: `Vault::rebind_native_wal_applied_absence(...)` to require the exact stored edge.

- [ ] **Step 1: Write failing Vault tests**

Add tests that checkpoint the exact nearest delete, reject skipped/non-delete/cross-parent/different-token edges, prove exact idempotency, and prove rebind fails without a checkpoint.

- [ ] **Step 2: Run the journal test**

Run: `cargo test -p context-relay-core --test native_journal_v1 -q`

Expected: FAIL because the edge fields and checkpoint method do not exist.

- [ ] **Step 3: Add all-or-none edge columns and strict Vault validation**

Store the target sequence and both complete tokens on the later row. Validate restoring status, later `RestorePrepared` state, exact restored provenance, earlier `RestorePrepared` state, nearest same-parent row, delete-token shape, same parent, immutable exact replay, and old/new CAS.

- [ ] **Step 4: Run the journal test**

Run: `cargo test -p context-relay-core --test native_journal_v1 -q`

Expected: PASS.

### Task 2: Checkpoint before live and recovery rebind

**Files:**
- Modify: `crates/core/src/native_transaction/engine.rs`
- Modify: `crates/core/src/native_transaction/filesystem.rs`
- Modify: `crates/core/src/native_transaction/journal.rs`
- Modify: `crates/core/src/native_transaction/recovery.rs`
- Test: `crates/core/tests/native_transaction_v1.rs`
- Test: `crates/core/tests/native_recovery_v1.rs`

**Interfaces:**
- Produces: `CheckpointAppliedAbsence` callback before `RebindAppliedAbsence`.
- Produces: `RecoveryAction::CheckpointAbsence` before/after fault points.
- Consumes: the exact Vault edge from Task 1.

- [ ] **Step 1: Update fakes with failing checkpoint-order assertions**

Assert that an exact later restore calls checkpoint before rebind, a live token mismatch after checkpoint is a conflict, and replay without an edge never captures an arbitrary current generation.

- [ ] **Step 2: Run focused unit tests**

Run: `cargo test -p context-relay-core --test native_transaction_v1 --test native_recovery_v1 -q`

Expected: FAIL on missing callback/action behavior.

- [ ] **Step 3: Implement checkpoint and replay modes**

For a fresh exact restore: prepare the nearest earlier delete, capture its post-restore absence token, persist the edge, then exact-live-validate and rebind. For an already-restored replay: consume an exact stored edge; if it is absent, mark the earlier delete `Conflict` without capturing live state.

- [ ] **Step 4: Run focused unit tests**

Run: `cargo test -p context-relay-core --test native_transaction_v1 --test native_recovery_v1 -q`

Expected: PASS.

### Task 3: Prove crash and ABA outcomes

**Files:**
- Modify: `crates/core/tests/native_recovery_crash_v1.rs`
- Modify: `docs/superpowers/specs/2026-07-20-isolated-native-runner-design.md`

**Interfaces:**
- Consumes: `RecoveryAction::CheckpointAbsence`.
- Verifies: checkpoint-before crash conflicts; checkpoint-after crash resumes; recreate/delete on either side conflicts.

- [ ] **Step 1: Add four subprocess cases**

Crash at `CheckpointAbsence::{Before,After}` with no mutation, then repeat both crashes and recreate/delete the earlier absent target before restart.

- [ ] **Step 2: Run the crash suite**

Run: `cargo test -p context-relay-core --test native_recovery_crash_v1 -q`

Expected: PASS with conservative conflict before the checkpoint, successful replay after it, and conflict for both ABA cases.

- [ ] **Step 3: Update the specification**

Replace automatic reconstruction language with the fail-closed rule: the irreducible restore-to-checkpoint crash gap becomes explicit `Conflict`, and a durable edge authorizes only its exact live new token.

- [ ] **Step 4: Run final focused gates**

Run: `cargo fmt --all -- --check`

Run: `cargo clippy -p context-relay-core --all-targets -- -D warnings`

Run: `cargo test -p context-relay-core --test native_journal_v1 --test native_transaction_v1 --test native_recovery_v1 --test native_recovery_crash_v1 --test native_filesystem_windows_v1 -q`

Expected: all commands PASS.
