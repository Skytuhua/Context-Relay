# Actual Claude session against the installed service — 2026-09-07

Pinned Claude Code 2.1.202 completed a status-only MCP request against the
already-running installed Context Relay 1.11 service. Its actual `--print`
client returned the unlocked-vault status to the loopback model fixture and
completed successfully. The existing Codex exec/app-server cases also pass after
sharing their Windows process owner: two tests, three harness surfaces, 6.15
seconds total.

`crates/context-mcp/tests/installed_harness_status_v1.rs` replaces the former
Codex-only test target. Its shared owner retains the same image pins, copied
installed bridge with no sibling daemon, stdin-gated kill-on-close job,
normal production bridge profile directories, and service instance nonce check
documented in [the Codex evidence](installed-codex-status-2026-09-07.md).

The Claude fixture creates a disposable HOME, project and CLAUDE_CONFIG_DIR.
Actual `mcp add-json` writes only that disposable profile, with explicit normal
profile directory overrides for the production bridge process. No hooks are
installed. Native automatic memory is disabled in the temporary settings.
Built-in tools are disabled and every Context Relay tool except status is
explicitly disallowed. The local Messages API fixture verifies that only status
is advertised before emitting exactly one status call. The result must contain
protocol range 1.11–1.11, an unlocked vault and no resolved project.

The credential used for the model fixture is synthetic. The installation
credential stays inside production bridge/OS credential-store code and is not
extracted or logged. No project, context or task record is created or changed in
the ordinary workspace. Hash canaries cover the ordinary Claude configuration
state/settings; the disposable MCP declaration and settings also remain intact.
The pre-existing daemon instance remains running after the fixture's children
exit. Independent read-only review approved the fixture with no material findings.

## Reproduction

Use the explicit installed bridge path/hash, Node path and NTFS TEMP/TMP
documented in the Codex report. Add `CONTEXT_RELAY_TEST_CLAUDE_EXE` pointing to
Claude 2.1.202 with SHA-256
`7ff0787ebdc19fc509ccea8886ebf6a53ad8213407fa3a2b7c6d1446efc419f6`.

```powershell
$env:CARGO_ENCODED_RUSTFLAGS='-Ctarget-feature=+crt-static'
cargo test -p context-relay-context-mcp --release --target x86_64-pc-windows-msvc --test installed_harness_status_v1 actual_claude -- --ignored --nocapture
```

Both installed-service cases are ignored by default. Local run evidence:
`.codex/installed-harness-status-test.log`. This addition changes tests and
documentation only; the installed application remains candidate `e09d206`.

Scoped release Clippy with warnings denied, Rust formatting, JavaScript syntax
and diff checks pass. A default test invocation confirms both installed-service
cases remain ignored.

## Remaining boundary

This closes actual Claude client status access to the installed service in a
disposable profile. It does not qualify ordinary-profile setup, hooks or full
Save/Undo behavior. The subsequent [Windows x64 setup decision](windows-harness-setup-2026-09-07.md)
uses this evidence alongside the native transaction fixtures to enable the exact
qualified setup version on that platform. Installed
Hermes client sessions and the broader first-use/release requirements remain open.
