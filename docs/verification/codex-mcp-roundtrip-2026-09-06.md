# Codex MCP discovery and round trips — 2026-09-06

An actual Codex 0.144.6 session exposed only the first eight Context Relay tools.
The bridge split its eleven tools after `context_relay_upsert_task`, so Codex
could not see `context_relay_complete_task`, `context_relay_create_handoff`, or
`context_relay_status`. Existing dispatcher tests manually requested the second
page and therefore did not detect this harness behavior.

`tools/list` now advertises all eleven tools in its first response. The old
opaque cursor still returns the final three tools; invalid cursors retain their
existing error. No tool names, schemas, permissions, lifecycle negotiation or
dispatch rules changed. A regression checks the exact list, both schema objects
per tool, and the response-size bound. This replaces the earlier fixed two-page
choice in [Task 13](task-13.md), while preserving its cursor compatibility.
[MCP permits server-selected page sizes and non-paginated responses](https://modelcontextprotocol.io/specification/2025-11-25/server/utilities/pagination).

## Native qualification

The ignored Windows test `native_codex_v1` uses the exact Codex 0.144.6 binary,
SHA-256 `4b76ded066d0239115ca97473d010c92072bc5c5550a45dd7cbebe1e9eb956a7`.
Its CLI and app-server both connect to the production MCP `Server` and daemon
request dispatcher through a test-only process entry point and authenticated
local IPC. A temporary encrypted vault and selected-project policy hold all data.
After both sessions, a new daemon instance reads the two saved memories and two
completed tasks.

Each session verifies:

1. All eleven tools are advertised to the model.
2. The production-generated, explicitly trusted SessionStart hook delivers its
   reminder to the model. App-server reports both lifecycle hooks completed.
3. Status returns the unlocked vault and exact selected project.
4. Remember, get and search return the new context with the correct project.
5. Task creation returns an open task; completion records matching evidence and
   returns done; task listing includes that exact completed task.
6. Exactly eight local model requests complete the seven tool calls and final
   response. Codex configuration bytes remain unchanged throughout each session.

The fixture uses a local Responses server and dummy key, with cleared environment
and fresh homes. The path includes spaces, Chinese, a smart apostrophe, ampersand
and brackets. The stdin-gated Windows job contains Codex and its bridge/hook
descendants; a 180-second outer deadline, 60-second child deadlines and output
bounds prevent abandoned subprocesses. Both executable hashes are checked again.
An identification flag rejects an accidentally selected production bridge before
Codex can invoke it. The fixture bridge accepts only an explicitly named test
runtime, never the installed daemon or the user's credential store.

The local model fixture follows the pinned Responses format: function calls use
separate namespace/name fields; Codex wraps returned MCP JSON in timing text.
Early runs exposed and corrected these fixture assumptions. They are not product
protocol changes. The initial discovery evidence independently showed the eight
advertised tools, and the lifecycle regression failed before the server fix.

## Reproduction and evidence

Build the explicit test-only example, then select its path along with the pinned
Codex and Node paths in `CONTEXT_RELAY_TEST_MCP_FIXTURE_EXE`,
`CONTEXT_RELAY_TEST_CODEX_EXE` and `CONTEXT_RELAY_TEST_NODE_EXE`:

```powershell
cargo build --config 'profile.dev.package.sha2.opt-level=3' -p context-relay-context-mcp --features test-support --example codex-bridge-fixture
cargo test --config 'profile.dev.package.sha2.opt-level=3' -p context-relay-context-mcp --features test-support --test native_codex_v1 -- --ignored --nocapture
```

Final native test: both sessions and restart readback pass in 6.91 seconds.
The MCP all-target test-support suite passes 66 tests, with the native opt-in
test ignored by default. This includes 17 lifecycle, 20 dispatcher, 13 hook,
10 daemon end-to-end, five stdout and one library test. Clippy with warnings
denied passes all MCP targets. Independent source review approved the change.

Local logs under `.codex/context-relay-closeout-2026-09-05/`:
`codex-mcp-native-first.log`, `codex-mcp-discovery-red.log`,
`codex-mcp-native-final.log`, `codex-mcp-discovery-suites.log`, and
`codex-mcp-discovery-clippy.log`. Intermediate native logs retain fixture-format
diagnostics. No normal user data, installed configuration or native UI was used.

## Test dependency correction

The next hosted CI run, `34003571753`, caught a direct core dev-dependency in
the native MCP fixture. The unchanged daemon-boundary checker correctly rejected
it. The fixture now obtains production-generated hooks through the daemon's
feature-gated test-support interface, removing the direct client/core dependency.
The production dispatcher and client dependency policy are unchanged.

The boundary checker and all seven boundary tests pass. A separate compilation
probe imports only the new helper: it must fail with an unresolved import in a
production build and compile with test support. This prevents another missing
test-only symbol from masking an accidental export. Independent review approved
the correction and the isolated probe. Core, daemon and MCP all-target Clippy
with test support and warnings denied passes. After rebuilding the fixture,
both real Codex sessions and restart readback pass again in 6.58 seconds.

Evidence: `ci86-daemon-boundary.log`, `codex-native-boundary-red.log`,
`codex-native-boundary-green.log`, `codex-native-boundary-tests-final.log`,
`codex-project-trust-mcp-build.log`, `codex-project-trust-mcp-native.log` and
`codex-project-trust-clippy-complete.log` in the same local evidence directory.
Local success does not change the failed hosted result for the previous commit.

## Remaining acceptance

This qualifies real Codex clients against production dispatcher logic, using an
isolated IPC/credential binding. It does not qualify the installed process entry
point, credential store, automatic setup, effective hook-trust readback, custom
runtime settings, macOS, or clean-machine acceptance. The production daemon and
user harness configuration were not changed. Codex 0.144.6 remains ImportOnly;
the local 11d6740 installer is unchanged. Full connection and release acceptance
remain open.
