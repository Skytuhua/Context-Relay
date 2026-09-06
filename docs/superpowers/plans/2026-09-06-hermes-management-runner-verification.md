# Windows Hermes management runner verification

Implemented the closed Version/ConfigCheck runner described in
../specs/2026-09-06-hermes-management-runner.md. The implementation owns an unnamed
kill-on-close job, starts suspended, verifies assignment before resuming, captures
overlapped output with bounded buffers and retains the runtime owner through
cleanup. A static slot preserves pending state across cleanup errors and unwind.

The initial synthetic suite failed to compile because the runner did not exist.
After implementation, focused process tests passed. Independent review found that
a successful zero-byte read was incorrectly treated as EOF. A real zero-byte
WriteFile fixture did not reproduce that kernel completion on this host, so a
deterministic completion regression was added. It failed the prior !finished
assertion, then passed after the correction. The integration fixture still checks
later marker output and output caps following a zero-byte write.

Final synthetic verification:

- Native-runner complete library suite: 54 passed, including ten management test
  functions (one is the child fixture entry point).
- Process cases cover stdout/stderr, Unicode, flood, timeout, cancellation, parent
  exit with a descendant retaining pipes or using closed pipes, assignment/resume
  failures, and an output limit discovered deterministically in final drain.
- A real native read lease prevents writes/deletion/ancestor rename while an
  injected cleanup-query failure retains the command. A new check is refused;
  clearing the fault permits reap, releases files and allows a subsequent command.
- Injected unwind after resume retains the owner in the poisoned-mutex slot. A
  later call reaps the child, releases ownership and clears poison before launch.
- Core/native-runner all-target Clippy with core test-support and warnings denied:
  passed in 24 seconds. Both crates compile with the new opt-in actual test.
- Independent review approved the corrected implementation with no remaining
  actionable findings.

Logs are under .codex/context-relay-closeout-2026-09-05/hermes-management-*.log.
The opt-in actual installed-runtime capture/check is running and is not yet a
passing qualification claim. Its exact test is
installed_retained_management_checks_use_owned_runtime_and_isolated_home.
It holds the copied runtime, private home pin and containing temporary directory
together through Version/ConfigCheck and verifies inventory after each command.
No normal harness configuration, credentials, service or native UI are modified.

Production runtime-aware discovery, adapter validation, daemon execution,
registration/recovery, actual setup/restart/Undo and Full support remain open.
No replacement local EXE is supplied by synthetic process tests.
