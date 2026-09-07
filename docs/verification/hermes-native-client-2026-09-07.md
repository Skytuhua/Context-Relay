# Native Hermes MCP client qualification — 2026-09-07

Status: the actual copied Hermes 0.17.0 MCP client passed on Windows. The complete
fixture, including final runtime/profile checks and cleanup, finished in 1,098.69
seconds. All 11 tools were discovered; project binding, remember/get/search and
task create/complete/list assertions passed.

The earlier production setup qualification drove the MCP bridge directly. This
additional opt-in test imports the actual copied Hermes 0.17.0 MCP client and
tool registry, reads a disposable profile's YAML, discovers the complete tool
list and dispatches project status, remember/get/search and task
create/complete/list operations through the production bridge dispatcher.

The explicit installed launcher is read only as runtime metadata. Production
capture/retention code copies its runtime, verifies its inventory and locks its
bytes before the copied CPython runs. The fixture executes the verified
projection's existing path-probe initialization, retains its DLL-directory
handles, then imports Hermes's actual client. It does not alter the production
bootstrap's closed management command set.

The whole fixture starts behind an stdin gate in a Windows job before bridge
identification. The Python client has an additional 90-second owned job and
64 KiB stdout/stderr thresholds checked every 20 ms; output may overshoot between
checks. An independent noisy-writer canary passed in 0.50 seconds, proving the
threshold terminates a running writer. The first canary attempt failed because
Node's cleared environment omitted Windows system-root variables; those two
variables were restored before the passing run.

Profiles, credentials, vault and IPC namespace are synthetic. The bridge image
identifies its closed test entry point and remains protected against replacement.
Python uses isolated/no-site/no-bytecode flags, only copied import paths, a
cleared environment and a loopback-only network audit hook. This hook is a test
guard, not an OS sandbox. Ordinary Hermes Python, configuration, credentials,
Context Relay records and the installed daemon are not used.

Build and core/daemon all-target test-support Clippy pass. Focused review found
two wrapper issues—identification outside the job and checking output only after
exit—and approved their corrections. The subsequent native run passed, including
verification that all 14,629 runtime files and the original synthetic YAML and
environment-file canaries remained unchanged.

The first native run verified and locked all 14,629 runtime files in 616.67
seconds, then stopped before importing Hermes: a lexical ancestry check treated
ordinary Windows paths and their `\\?\` aliases as different directories. A
small synthetic probe using the bundled non-Hermes Python reproduced that
behavior. The fixture now resolves existing paths strictly and checks filesystem
identity against their ancestors. The exact extracted predicate accepts ordinary
and verbatim aliases and rejects outside/prefix-lookalike directories. Focused
review approved the correction. The second complete native run passed. Capture
completed at 610.60 seconds, retention at 751.09 seconds, inventory locking at
949.18 seconds and the actual MCP client round trip at 1,086.90 seconds. These
fixture timings are not installed-release performance acceptance.

After the shared bridge-image helper extraction, all 19 ordinary authenticated
harness setup tests passed in 51.27 seconds (two opt-in entry points excluded).
The process-tree cleanup regression passed in 5.07 seconds, covering parent exit
and timeout. The separate pre-journal recovery regression also passed on Windows
in 2.98 seconds.

To repeat, explicitly select `CONTEXT_RELAY_HERMES_METADATA_EXE` and
`CONTEXT_RELAY_TEST_MCP_FIXTURE_EXE` (the test-only `codex-bridge-fixture` example,
which also supports the closed Hermes fixture namespace), then run:

```text
cargo test --config 'profile.dev.package.sha2.opt-level=3' -p context-relay-contextd --features test-support --test native_hermes_client_v1 actual_hermes_client_discovers_and_uses_the_production_bridge -- --ignored --nocapture
```

This qualifies the actual MCP client and registry against synthetic saved
settings, separately from the production Save/Undo composition. It is not an
actual model conversation, full CLI session, installed credential check or
installed release acceptance. No version or platform gate changes.
