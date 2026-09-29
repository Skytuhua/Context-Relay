# Retained Hermes Runtime Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Retain and reopen the exact captured Windows Hermes runtime for subsequent sealed setup and recovery.

**Architecture:** Keep a private manifest beside the captured payload, publish a typed
reference only after durability barriers, and require that reference when reopening.
Reuse the native filesystem's held-path and security descriptor primitives.

**Tech Stack:** Rust, serde JSON, SHA256, existing Windows native filesystem layer.

**Spec:** ../specs/2026-09-06-hermes-retained-runtime.md

## Constraints

- Windows retention; no ordinary harness/configuration/daemon mutation.
- 48 MiB manifest, 32,768 entries, depth 32, 64 MiB per file, 1 GiB total.
- No source reread on reopen, no implicit approval, no replacement publication.
- Native Computer Use stays paused; no Full runtime promotion.

## Task 1: Retained storage and fresh-handle recovery

**Files:**
- Modify: crates/core/src/hermes/python_runtime.rs (private container layout).
- Create: crates/core/src/hermes/python_runtime/retained.rs (reference, retain, reopen).
- Modify: crates/native-runner/src/native_fs/mod.rs and windows.rs (private reopen and durability barriers).
- Tests: focused unit tests in retained.rs and existing Windows native filesystem tests.

**Interfaces:** CapturedRuntime::retain consumes temporary ownership and returns a
RetainedRuntime; RetainedRuntime::reference provides a serializable versioned
identity; RetainedRuntime::open(store, reference) verifies an existing runtime.
Root/manifest/identity access remains available for later contained execution.

- [x] Add failing synthetic retention/reopen/source-removal tests.
- [x] Add the minimal private-directory reopen and flush operations, with tests
  for permissions, no-follow behavior and completed directory/file synchronization.
- [x] Implement the private container layout, bounded manifest and publication.
- [x] Verify tampering, invalid references, missing publication and failure cleanup.
- [x] Run affected tests, lint and independent review; update graph and evidence.

Results: 2026-09-06-hermes-retained-runtime-verification.md. The retained API is
complete for this task; production connection integration below remains open.

## Subsequent connection integration

The returned reference must become a distinct versioned member of sealed transaction
approval, with backward compatibility for existing plans. Management commands must
then execute only retained bytes under the qualified containment policy. Actual
connection, restart and Undo must pass before enabling the installed Hermes version.
