# Native Transaction Profile Lock Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development and execute each RED/GREEN cycle inline. Do not commit this task.

**Goal:** Serialize native transactions across processes with one real nonblocking OS lock per explicit canonical Vault-private profile/harness root.

**Architecture:** `VaultNativeJournal` receives an existing canonical lock root and acquires a private `ProfileTransactionLock` inside `acquire_lock_and_begin`, before calling the Vault. Unix opens the root with `O_DIRECTORY | O_NOFOLLOW` and locks that held directory; Windows holds a no-reparse directory handle that denies delete/rename and locks a fixed no-reparse child file whose handle also denies delete/rename. The journal retains the handles until durable committed/compensated cleanup succeeds or the journal drops during unwind/crash.

**Tech Stack:** Rust 1.97 `File::{try_lock, unlock}`, Unix `open(2)` flags through `libc`, Windows `OpenOptionsExt`, existing Vault journal and transaction engine.

## Global Constraints

- Do not modify native filesystem, launcher, or hydration files.
- Use nonblocking exclusive locks; contention fails closed before Vault begin, adapter reprobe, or native filesystem access.
- Never delete the lock root, lock object, or unrelated files.
- Keep unsupported/test targets compiling and do not commit.

---

### Task 1: Lock behavior and engine ordering tests

**Files:**
- Create: `crates/core/tests/native_transaction_lock_v1.rs`
- Modify: `crates/core/tests/native_transaction_v1.rs`

**Interfaces:**
- Consumes: `VaultNativeJournal::new(&mut Vault, canonical_lock_root, transaction_id, identity, payload, created_ms, policy)`.
- Proves: same-root duplicate and child-process contenders receive `BoundaryError`; different roots and post-drop/post-crash acquisition succeed; a blocked engine makes zero adapter/filesystem calls; symlink/reparse roots fail and canaries remain.

- [ ] Add genuine same-process and cross-process contention tests using the integration-test executable as the child holder.
- [ ] Add different-root, Drop/crash-release, unsafe-topology, and unrelated-canary assertions.
- [ ] Run `cargo test -p context-relay-core --test native_transaction_lock_v1 --test native_transaction_v1` and observe RED because the constructor has no lock-root parameter or OS lock.

### Task 2: Minimal held OS lock

**Files:**
- Modify: `crates/core/src/native_transaction/journal.rs`
- Modify: `crates/core/Cargo.toml`
- Modify: `Cargo.lock` only if Cargo changes it mechanically

**Interfaces:**
- Produces: private `ProfileTransactionLock::acquire(&Path) -> Result<Self, BoundaryError>` and `release(self) -> Result<(), BoundaryError>`.
- Updates: `VaultNativeJournal::new` accepts an explicit canonical root; `acquire_lock_and_begin` stores the lock before `Vault::begin_native_transaction`; terminal cleanup releases it only after the durable cleanup call succeeds.

- [ ] Implement canonical/no-link root binding and platform-specific held handles.
- [ ] Use `File::try_lock` for immediate exclusive acquisition and `File::unlock` only after durable terminal completion.
- [ ] Run the focused tests GREEN and update every constructor call site.

### Task 3: Design and verification

**Files:**
- Modify: `docs/superpowers/specs/2026-07-20-isolated-native-runner-design.md`

**Interfaces:**
- Documents: exact per-profile/harness root, step-one acquisition, platform topology, contention behavior, and release lifetime.

- [ ] Update the design wording without claiming a database-only or in-process lock.
- [ ] Run `cargo fmt --all -- --check`, focused strict Clippy, native transaction/journal/lock tests, and supported cross-target checks.
- [ ] Run `graphify update .` and report constructor integration implications without committing.
