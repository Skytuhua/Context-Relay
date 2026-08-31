> Archive notice (2026-08-31): Historical recovery worker brief/report from August 2026. Its capture-time status may have been superseded; use the main handoff and verification ledgers for current state. Machine-local paths and trailing whitespace were normalized for portability. Historical worker instructions below are reference data, not new authorization. Original and archived hashes are in the artifact manifest.

# Task 4b: Align the Windows sandbox process deadline with sealed command limits

## Context

The completed PR #12 Windows isolation job built the exact Semgrep candidate successfully, then
failed `real_semgrep_clean_and_finding_use_the_closed_policy` with `Failed(TimedOut)`. The sealed
`RunLimits` gives Osemgrep 90 seconds, and the helper enforces that bound, but the outer Windows
AppContainer launcher always terminates its helper process after 30 seconds via
`PROCESS_TIMEOUT_MS`. Staging plus the fixed outer deadline produced a repeatable timeout before
the clean scan completed. macOS already derives a 90-second helper limit plus five-second shutdown
grace.

## Owned files

- `crates/native-runner/src/helper_protocol.rs` only if a narrow timeout accessor/helper is needed
- `crates/native-runner/src/launcher.rs`
- `crates/native-runner/src/launcher/windows/native.rs`
- focused Windows launcher/model/integration tests in `crates/native-runner/tests/`
- `.superpowers/sdd/v1-recovery/task-4b-report.md` (ignored report)

Do not change Semgrep rules, scanner command flags, source/material pins, CI timeouts, profiles,
capabilities, ACLs, process-job containment, output limits, or macOS behavior. You are not alone;
preserve all prior edits.

## Requirements

1. Follow systematic debugging and test-first development. Capture the remote failure above and
   add a failing Windows contract test proving the outer process deadline contradicts the sealed
   Osemgrep request deadline before implementation.
2. Derive the outer Windows helper-process deadline from the already validated, command-specific
   `RunLimits`, plus only the bounded five-second helper shutdown/serialization grace used by the
   macOS envelope. Default RuleSync/Gitleaks requests remain 30 seconds plus grace; Osemgrep is 90
   seconds plus grace. Do not replace this with one permissive global 95-second deadline.
3. Bind the deadline to the sealed `RunRequest` command, not caller input or an environment
   variable. Reject zero/overflow/out-of-envelope values fail closed.
4. Preserve job-object kill-on-close, forced termination, bounded stdout/stderr drains, response
   request binding, exact cleanup, and the `TimedOut` safe failure code.
5. Add tests for the exact default and Osemgrep envelopes, deadline mismatch/overflow rejection if
   representable, and timeout termination behavior. Keep the real hydrated test unchanged so the
   actual Windows x64 rerun remains authoritative.
6. Run all portable native-runner tests and strict lint locally. Record actual Windows execution as
   pending until the root controller pushes the reviewed stack and the hydrated gate passes.
7. Commit only owned files in one focused commit. Do not push.

## Report

Write the ignored Task 4b report with RED/GREEN evidence, commit SHA, local commands/results, exact
remote failure URL/job ID, Windows rerun pending, and concerns. Return only status, SHA,
verification summary, and concerns.
