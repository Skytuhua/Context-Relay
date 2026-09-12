# Actual Codex sessions against the installed service — 2026-09-07

Pinned Codex 0.144.6 completed an authenticated Context Relay status request in
both `exec` and `app-server` sessions against the already-running installed
protocol 1.11 service. The opt-in Windows test passed in 2.85 seconds. Both
sessions returned an unlocked vault and no resolved project for the disposable
working directory.

## Scope and isolation

`crates/context-mcp/tests/installed_harness_status_v1.rs` runs the actual Codex
executable with a new profile and project on the local NTFS scratch volume.
The Responses API is a loopback fixture with a dummy key; no account credentials
are copied into Codex. Its configuration advertises only
`context_relay_status`, and the model fixture verifies that inventory before
requesting exactly one status call per session. No context or task data is read
or written, and no project is registered in the ordinary workspace.

The bridge is a hash-verified copy of the installed production executable. Held
read-only Windows handles prevent the Codex and bridge executables from being
written or replaced during qualification. The copied bridge has no sibling
daemon, so loss of the ordinary service fails the test rather than starting a
service inside the test's process job. The prior direct installed-path checks
are recorded in [the approved update evidence](service-version-feedback-2026-09-07.md).

Codex itself uses disposable HOME/profile locations. Its MCP child explicitly
receives the normal Windows profile/environment directories and reads the
installation credential internally through production code. The production
bridge never runs with the disposable HOME. The test does not extract, log or
modify installation credentials.

The Node owner is gated on stdin before it can spawn Codex, then placed inside
the existing kill-on-close Windows job with bounded time and output. The ordinary
service is outside this job. Its instance nonce is checked before and after,
and the normal Codex `config.toml`, `hooks.json` and `.personality_migration`
contents/absence are checked for changes. All these checks passed, including
after the initial failed fixture run; service PID 32720 remained running.

## Reproduction and review

Run the ignored test only after explicitly choosing the installed bridge and
verifying its hash against the candidate manifest. Required environment:

- `CONTEXT_RELAY_TEST_CODEX_EXE`: pinned Codex 0.144.6, SHA-256
  `4b76ded066d0239115ca97473d010c92072bc5c5550a45dd7cbebe1e9eb956a7`.
- `CONTEXT_RELAY_TEST_NODE_EXE`: explicit Node executable.
- `CONTEXT_RELAY_TEST_INSTALLED_MCP_EXE`: the current user's installed Context
  Relay bridge. The fixture requires the expected installation path.
- `CONTEXT_RELAY_TEST_INSTALLED_MCP_SHA256`: for installed candidate `e09d206`,
  `0bffcd4eeaef410a418496da36d6ba6769fd0d0fc96d90c5b95d824c6319d909`.
- `TEMP` and `TMP`: an NTFS scratch directory with enough room for the copy.

```powershell
$env:CARGO_ENCODED_RUSTFLAGS='-Ctarget-feature=+crt-static'
cargo test -p context-relay-context-mcp --release --target x86_64-pc-windows-msvc --test installed_harness_status_v1 actual_codex -- --ignored --nocapture
```

The first run exposed an incorrect fixture expectation: status returns a
protocol range, not one protocol version. Independent read-only review found
the same mismatch. Correcting the expected `{min, max}` shape made both actual
sessions pass; no production code change was needed. Review found no additional
containment issues. Local logs: `.codex/installed-codex-status-first-run.log`
and `.codex/installed-codex-status-test.log`.

Scoped release Clippy with warnings denied, Rust formatting, JavaScript syntax
and diff checks pass. A default invocation confirms the installed-service test
is ignored unless explicitly selected. The AST knowledge graph was refreshed.

## Remaining boundary

This verifies actual Codex sessions and production installed-service
authentication for status. It does not qualify the normal Codex profile,
interactive hook trust, the complete setup/Save workflow or model-provider
behavior. The subsequent [Claude check](installed-claude-status-2026-09-07.md)
also passes actual client status access; Hermes still has direct installed bridge
status evidence without an actual installed-service client session.
The subsequent [Windows x64 setup decision](windows-harness-setup-2026-09-07.md)
uses this evidence alongside the native transaction fixtures to enable the exact
qualified setup version on that platform. This test-only addition
does not require rebuilding or reinstalling the `e09d206` application.
