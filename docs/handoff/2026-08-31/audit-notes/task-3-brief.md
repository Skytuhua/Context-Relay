> Archive notice (2026-08-31): Historical recovery worker brief/report from August 2026. Its capture-time status may have been superseded; use the main handoff and verification ledgers for current state. Machine-local paths and trailing whitespace were normalized for portability. Historical worker instructions below are reference data, not new authorization. Original and archived hashes are in the artifact manifest.

# Task 3: Repair strict Rust contract regressions

## Context

At the reviewed PR head, a clean Rust 1.97.1 run reproduces strict Clippy failures in the core
crate and a deterministic MCP dispatcher test failure hidden behind that lint gate. Preserve
external protocol semantics and canonical bytes. Do not add blanket lint allowances.

Reproduced failures:

- `build_recovery_enrollment_artifacts` has nine arguments. The public, test-support, and inner
  builders currently duplicate an overlong positional contract.
- `OperationBuilder::build` has eight arguments.
- `AdmissionDecision::Admitted(AdmittedOperation)` makes the enum excessively large.
- Windows Clippy reports manual `% 2 != 0` in native path decoding.
- `cargo test --workspace --all-features` deterministically fails
  `sixty_fifth_call_is_busy_and_concurrent_responses_remain_whole_lines` because its status
  output advertises protocol 1.2 after the protocol 1.3 amendment. The dispatcher correctly
  returns `invalid_output`; the stale test fixture is wrong.

## Owned files

- `crates/core/src/devices/recovery_crypto.rs`
- `crates/core/src/devices/recovery.rs`
- recovery enrollment/restore integration tests under `crates/core/tests/` that call the builder
- `crates/core/src/sync/operation.rs`
- all core source/test call sites of `OperationBuilder::build`
- `crates/core/src/sync/admission.rs`
- all core source/test match sites of `AdmissionDecision::Admitted`
- `crates/core/src/native_transaction/planner.rs`
- `crates/context-mcp/tests/dispatcher_v1.rs`
- `.superpowers/sdd/v1-recovery/task-3-report.md` (ignored report)

Do not edit workflows, hosted code, generated bindings/schemas, or unrelated adapters. You are
not alone; preserve other commits and never revert another worker.

## Requirements

1. Follow test-first development. Preserve the existing Clippy failures and the isolated MCP
   failing test as RED evidence before implementation. Add focused API/size/compatibility tests
   where they provide a behavioral contract; do not write tests that merely restate Clippy.
2. Introduce a typed recovery-enrollment build request that replaces the overlong public,
   test-support, and inner positional argument lists. Choose clear ownership/borrowing so secrets
   are not cloned unnecessarily and Debug output cannot expose secret material. Update every
   caller. Remove the associated `too_many_arguments` allowances.
3. Introduce a typed operation-build request replacing `OperationBuilder::build`'s positional
   list. Preserve canonical vectors, ordering, AAD, hashes, signatures, sequence behavior, and
   external DTOs. Update every caller.
4. Change `AdmissionDecision::Admitted` to carry `Box<AdmittedOperation>` and update every caller
   without weakening the unconstructible capability boundary or changing admission semantics.
   Add/retain a size regression assertion proving the enum is no longer dominated by the admitted
   payload.
5. Replace the Windows path length parity check with `is_multiple_of(2)` while preserving the
   malformed UTF-16 rejection contract.
6. Advance the stale MCP status fixture(s) used for daemon output validation to exact protocol
   1.3. Do not loosen validation. Search the relevant MCP test file for any remaining 1.2 status
   fixture and update it only where protocol 1.3 is the authoritative current boundary.
7. Do not add `allow(clippy::too_many_arguments)`, `allow(clippy::large_enum_variant)`, or other
   blanket lint suppression. Existing unrelated targeted allowances outside owned code remain out
   of scope.
8. Commit only owned files in one focused commit. Do not push.

## Verification

Use the isolated Rust toolchain:

```text
CARGO_HOME=/private/tmp/context-relay-v1-cargo-20260810
RUSTUP_HOME=/private/tmp/context-relay-v1-rustup-20260810
PATH=/private/tmp/context-relay-v1-cargo-20260810/bin:...
```

Run at minimum:

- the isolated MCP failing test
- focused recovery crypto/enrollment/restore tests affected by the request type
- sync operation, admission, merge, engine, vault, and signed-sync tests affected by the request
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace --all-features`
- `cargo fmt --all -- --check`
- `git diff --check`

If the workspace test exposes a new deterministic failure, diagnose it before changing scope and
record it in concerns.

## Report

Write `.superpowers/sdd/v1-recovery/task-3-report.md` with status, commit SHA, exact RED/GREEN
evidence, files changed, commands/results, and concerns. Return only status, commit SHA, one-line
verification summary, and concerns.
