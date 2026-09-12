# Hermes Runtime Approval Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Bind the retained Hermes runtime identity in native setup and reversible recovery plans.

**Architecture:** Make the retained identity portable while keeping Windows filesystem operations gated. Add an optional, explicitly versioned installed-runtime binding to the internal native plan. Preserve existing approval preimages and omit absent bindings from sealed output.

**Tech Stack:** Rust, serde, existing canonical CBOR approval hashing and JSON plan envelopes.

**Spec:** ../specs/2026-09-06-hermes-retained-runtime.md

## Constraints

Preserve existing approval v1/v2 behavior for plans without runtime bindings. Approval v1 rejects new bindings. Hermes Python v1 is Windows-only and separate from shipped sidecars and launcher hashes. This change does not authorize execution or enable Full support. Normal harness files, daemon and native UI remain untouched.

## Task 1: Approval and persisted identity

Files: core/src/hermes/python_runtime.rs and retained.rs; native_transaction/model.rs, approval.rs, planner.rs; setup.rs constructors; affected test fixtures; tests/native_approval_v2.rs.

Review extends the entry checks to native_transaction/engine.rs, contextd/src/bridge_install.rs
and the core watch-only verifier. A saved binding must not be silently ignored by existing
adapters or trigger ordinary launcher discovery before rejection. Native file compensation
does not need Python execution; keep recovery binding readable and preserve its identity.

- [x] Add failing round-trip, binding tamper/removal, wrong platform/harness and legacy compatibility tests.
- [x] Move RetainedRuntimeReference and validation to the portable runtime module; retain the Windows re-export.
- [x] Add InstalledRuntimeBinding::HermesPythonV1 and optional NativeTransactionPlan.installed_runtime.
- [x] Preserve three/four-member v2 preimages when absent. When present append a fifth tagged binding after an explicit native-memory member. Reject it under v1.
- [x] Seal/open the exact binding with strict deserialization and hash verification; preserve reversible envelopes.
- [x] Reject unconsumed bindings before engine journal work, production discovery and watch-only verification. Exercise these entry points with regression tests.
- [x] Finish graph refresh and record the verified change.

Evidence: 2026-09-06-hermes-runtime-approval-verification.md.

## Next connection step

The adapter must consume the approved reference, reopen the managed store and execute the retained bootstrap with file locks and bounded descendants/output. Runtime preparation must complete before approval persistence. Actual Hermes connection, restart and Undo still require qualification; merely adding this binding cannot enable them.
