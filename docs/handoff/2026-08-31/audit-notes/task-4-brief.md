> Archive notice (2026-08-31): Historical recovery worker brief/report from August 2026. Its capture-time status may have been superseded; use the main handoff and verification ledgers for current state. Machine-local paths and trailing whitespace were normalized for portability. Historical worker instructions below are reference data, not new authorization. Original and archived hashes are in the artifact manifest.

# Task 4: Restore Windows-native path and runtime parity

## Context

PR #12's completed Windows native job failed seven `contextd` unit tests after compilation.
The terminal replay test hard-codes `/private/tmp`; six native-memory tests encode a Windows path
as UTF-16LE while still tagging it `NativePlatform::Macos`, causing `InvalidSource("path")`.
Windows strict compilation also exposed target-only unused imports/variables/helpers in the Claude,
Codex, and Hermes adapter code. Audit found production bridge setup and execution paths that
hard-code `RuntimeTarget::MacosArm64` even on Windows.

The v1 supported hosts are macOS arm64 and Windows x64. Preserve native path bytes losslessly;
never route Windows paths through lossy UTF-8 for authority or equality.

## Owned files

- `crates/contextd/src/lib.rs` (test-support additions only if needed)
- `crates/contextd/src/bridge_install.rs`
- `crates/contextd/src/native_memory.rs`
- `crates/core/src/setup.rs`
- `crates/core/src/claude_code.rs`
- `crates/core/src/codex.rs`
- `crates/core/src/hermes.rs`
- `crates/core/src/hermes/gateway.rs`
- focused existing/new tests directly exercising these platform contracts
- `.superpowers/sdd/v1-recovery/task-4-report.md` (ignored report)

Do not edit workflows, protocol DTOs, generated files, hosted code, or unrelated native-runner
implementation. You are not alone; preserve other commits and do not revert another worker.

## Requirements

1. Follow test-first development. Preserve the seven failed Windows test names and compiler/lint
   diagnostics as RED evidence. Before production fixes, add focused platform-contract tests that
   fail against the hard-coded runtime target and invalid test fixture.
2. Replace the `/private/tmp` database helper with a shared platform-aware test fixture that owns
   its `TempDir` for the entire database lifetime. Never return a path whose temporary owner has
   already been dropped.
3. Use that shared host-path encoding in native-memory tests: Windows uses lossless UTF-16LE/WTF-16
   bytes tagged `NativePlatform::Windows`; macOS uses native Unix bytes tagged
   `NativePlatform::Macos`. Display text is non-authoritative.
4. Add Windows-specific path-contract coverage for a drive path, UNC path, extended-length path,
   a reserved-name spelling, Unicode, odd-byte input, embedded NUL, and malformed UTF-16/WTF-16
   structure as defined by the existing wire contract. Do not reject valid opaque Windows path
   code units merely because a lossy Unicode conversion cannot render them.
5. Replace production `MacosArm64` bridge preview/watch-only target selection and restricted-plan
   validation with the exact supported current runtime target (`RuntimeTarget::current()` or an
   equivalent fail-closed helper). Unsupported targets must fail with a sanitized typed error.
   Keep target identity included in sealing/approval; do not silently rewrite a persisted plan.
6. Add tests proving Windows x64 plans carry/accept only `WindowsX86_64`, macOS arm64 plans carry/
   accept only `MacosArm64`, and mismatched persisted targets fail closed. Retain existing macOS
   behavior.
7. Correct target/test `cfg` boundaries for Claude/Codex/Hermes imports, parameters, mutable
   bindings, `command_tokens`, and `ENV_LOCK`. Remove unnecessary mutation. Do not hide issues with
   broad lint allowances or underscore a production value that should be validated.
8. Search every production `RuntimeTarget::MacosArm64` in `crates/core/src/setup.rs` and
   `crates/contextd/src/bridge_install.rs`; classify and repair every host-selection occurrence,
   while leaving explicit macOS-only fixtures/tests alone.
9. Commit only owned files in one focused commit. Do not push.

## Verification

- Run all `contextd` unit tests locally on macOS.
- Run focused setup, bridge install/apply/rollback, Claude, Codex, Hermes, and native-memory suites.
- Run `cargo clippy --workspace --all-targets --all-features -- -D warnings` and
  `cargo test --workspace --all-features` on macOS after Task 3 is present.
- Cross-check Windows compilation if the local toolchain can do so without weakening native C/
  SQLCipher dependencies; otherwise record CI as the required execution plane, not as passed.
- Run formatting and `git diff --check`.

The root controller will push the reviewed repair stack to the draft PR and require the actual
Windows x64 job before accepting Windows runtime evidence.

## Report

Write `.superpowers/sdd/v1-recovery/task-4-report.md` with status, commit SHA, RED/GREEN evidence,
files changed, exact verification, deferred Windows execution evidence, and concerns. Return only
status, commit SHA, one-line verification summary, and concerns.
