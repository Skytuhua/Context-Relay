# Isolated Codex hook-readback qualification

The hook-readback experiment is compiled only under `cfg(test)`, with no daemon,
desktop or production adapter entry point. `process-wrap` is a dev dependency
and is absent from the normal core dependency tree. The initial proposed passive
API was withdrawn during review because native startup can change the profile.

The qualification method `CodexAdapter::read_native_hooks` opens and verifies the
observed executable, binds the existing explicit profile/user-home/project/cwd
context, and performs app-server initialization followed by `hooks/list` for that
directory. Wrapper installations are rejected. It sends no thread, turn, trust
approval, hook execution or configuration-write request. This describes the RPC
requests only; it does not make app-server startup passive.

Pinned Codex [personality migration](https://github.com/openai/codex/blob/5d1fbf26c43abc65a203928b2e31561cb039e06d/codex-rs/core/src/personality_migration.rs)
writes a marker even in an empty profile and can write `personality = pragmatic`
to a profile with recorded sessions. Its [plugin startup tasks](https://github.com/openai/codex/blob/5d1fbf26c43abc65a203928b2e31561cb039e06d/codex-rs/core-plugins/src/manager.rs)
can refresh repositories, upgrade installed plugins and contact authenticated
catalogs. Startup also initializes profile state. Process containment limits
lifetime, not filesystem or network effects. Launching this probe against a
normal profile could invalidate setup/Undo fingerprints. Normal-profile
integration is prohibited until these startup effects are contained or an
appropriate existing-process readback is available. Disabling plugins to hide
this problem would change the effective hooks being inspected.

The response must contain exactly the selected directory and no load errors or
warnings. Duplicate JSON keys are rejected recursively using the existing strict
reader. Diagnostic and unknown notifications are rejected. Only the pinned
`remoteControl/status/changed` notification with an exact inactive payload is
allowed after initialization: status disabled, no environment, and the four
specified fields. It remains subject to the cumulative output budget; remote
activity and extra envelope fields are rejected. Identity strings are neither
logged nor returned. Required metadata fields are decoded without treating unknown status
strings as approval. The method returns native metadata, not a connected result.
An empty hook list alone cannot distinguish disabled hooks from missing hooks.
Consumers still need to compare the exact expected commands, events, source
paths, matcher, timeout and status before reporting managed hook approval.

The test transport uses `process-wrap` 10.0.0 with only std, creation-flags, job-object
and process-group features. Windows starts the child suspended, assigns its job
before resuming, and preserves CREATE_NO_WINDOW. Unix uses a separate process
group; Linux/Android preserve the existing sealed-memfd fork/exec contract.
This is process cleanup, not a security sandbox. The RPC has a 30-second
deadline and 256 KiB output budget; stderr is separately bounded and nonempty
diagnostics reject the result. Success and failure both terminate the process
tree. Cleanup and reader completion have bounded waits and incomplete shutdown
cannot return success. Existing CLI mutation execution is unchanged.

## Verification

The initial RPC test failed against an unavailable implementation, then passed
after implementation. Nine targeted tests cover the exact initialize/initialized/
hooks-list sequence, invalid/error/unexpected responses, byte budgets, returned
directory and incomplete metadata, and descendant cleanup on success, malformed
output, timeout and stdout/stderr overflow. The fixture is an inert compiled
native process with a descendant canary; every canary was stopped. Additional
regressions cover the prepared executable path, wrapper rejection, duplicate
keys, warnings and the narrowly allowed inactive notification. Warning and
duplicate-key regressions failed before correction. The prepared-image test
runs on each platform; this session's execution evidence is Windows only.

Final core library tests: 123 passed, eight opt-in tests ignored, 5.02 seconds.
Core all-target Clippy with test support and warnings denied passes (8.18s),
as do formatting, diff checks and the unchanged daemon boundary checker.
The first Clippy invocation omitted the repository's test-support feature and
failed to compile integration-test helpers; the corrected invocation passes.

Actual Codex 0.144.6, SHA-256
`4b76ded066d0239115ca97473d010c92072bc5c5550a45dd7cbebe1e9eb956a7`, passes four
native queries through this test-only adapter method in a disposable custom profile:
two untrusted hooks, two trusted hooks, zero hooks after explicit feature disable,
and two modified hooks after changing their definitions. The outer test uses an
owned job, a stdin gate and a 100-second deadline. Its wrong ambient profile,
selected settings and hook files remain unchanged by queries; executable hash is
unchanged, and the custom user home acquires no fallback `.codex` directory.
An actual marker executable verifies that no hook was invoked. The test also
asserts creation of `.personality_migration`, confirming a native startup write
even though its selected settings files remain unchanged. Only disposable
fixture trust is written by the test. Final native result: 22.41 seconds.
No normal profile or installed desktop was used. Independent review approved
the final test-only scope; it did not approve passive normal-profile integration.

Logs in `.codex/context-relay-closeout-2026-09-05/`:
`hook-readback-rpc-red.log`, `hook-readback-rpc-green.log`,
`hook-readback-process-tests.log`, `hook-readback-lib-final.log`,
`hook-readback-clippy-final.log`, and `hook-readback-native-final.log`.
`hook-readback-warning-red.log` and `hook-readback-duplicate-red.log` retain
the two reproduced parser defects. The warning diagnostic log records why the
known inactive status notification needs the narrow exception above.

```powershell
cargo test --locked --config 'profile.dev.package.sha2.opt-level=3' -p context-relay-core --lib
# Set CONTEXT_RELAY_TEST_CODEX_EXE explicitly to the pinned installation first.
cargo test --locked --config 'profile.dev.package.sha2.opt-level=3' -p context-relay-core --lib pinned_codex_reads_native_hook_trust_without_executing_hooks -- --ignored --nocapture
```

## Remaining acceptance

This retains a qualification mechanism, not a product connection check.
Startup-effect containment must precede normal-profile use. Typed managed-hook assessment, daemon
IPC, desktop status/action wiring and remaining platform qualification are still
required. It does not enable a Full runtime version, establish bridge credential
binding, prove full native setup/recovery, rebuild or install the local candidate,
or complete the wider first-use/release goal. Codex 0.144.6 remains ImportOnly.
