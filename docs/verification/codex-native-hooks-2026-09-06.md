# Codex Windows lifecycle qualification — 2026-09-06

Context Relay's old Windows hook command quoted an executable as though Codex
used cmd.exe. The pinned Codex 0.144.6 instead selects PowerShell for its local
environment. The command failed with PowerShell `UnexpectedToken`; a trusted
hook could not deliver its lifecycle event. The corrected renderer uses the
call operator and a single-quoted native path. It validates the path before
removing its verbatim prefix, doubles every PowerShell single-quote delimiter,
and retains old Context Relay commands only for replacement or archival.

PowerShell recognizes ASCII apostrophes and U+2018–U+201B as delimiters. The
renderer escapes all five and the recognizer accepts only matching doubled
pairs. Smart double quotes remain ordinary path characters. The delimiter set
matches [PowerShell's parser](https://github.com/PowerShell/PowerShell/blob/master/src/System.Management.Automation/engine/parser/CharTraits.cs).
Review found the smart-quote defect; a native failing test preceded its fix.

## Exact runtime and isolated test

Executable: Codex CLI 0.144.6, Windows x64, SHA-256
`4b76ded066d0239115ca97473d010c92072bc5c5550a45dd7cbebe1e9eb956a7`.
The matching upstream tag resolves to
`5d1fbf26c43abc65a203928b2e31561cb039e06d`; its
[hook construction](https://github.com/openai/codex/blob/5d1fbf26c43abc65a203928b2e31561cb039e06d/codex-rs/core/src/session/mod.rs)
uses the selected environment shell.

`codex/session_tests.rs` and `codex-local-session.mjs` run actual CLI `exec`
and app-server sessions against a loopback Responses fixture with a dummy key.
An inert compiled Rust hook records only synthetic input. All homes, project
folders, logs and generated state are disposable. No account credentials,
normal daemon, installed configuration or native desktop UI are used.

The parent checks the executable digest, local-drive canonical path and
round trip, then puts the stdin-gated Node process in the existing kill-on-close
Windows job. Descendants inherit containment. Each CLI has a 20-second deadline
and 64-KiB output bound; the outer fixture has a 150-second deadline. The cleared
environment supplies only Windows runtime paths, explicit synthetic homes,
standard executable extensions and the dummy fixture key.

The 24-session matrix passes:

- Both CLI and app-server with ordinary paths, spaces/Chinese/apostrophe/`$HOME`,
  shell punctuation/brackets, and all four smart single quotes.
- Untrusted definitions remain inactive. In each disposable home, the fixture
  then assigns only its two inert definitions the exact discovered hashes,
  following the pinned upstream test's `hooks.state` representation.
- Trusted definitions deliver SessionStart and Stop with matching session IDs
  and project working directories. App-server reports both hooks completed.
- Changing the definitions' status messages makes them modified and inactive.
- Every session uses exactly one local model request and preserves config bytes.
  No trust-bypass flag is used; the executable digest is checked again at exit.

To reproduce, set `CONTEXT_RELAY_TEST_CODEX_EXE` and
`CONTEXT_RELAY_TEST_NODE_EXE` to the exact native Codex and Node paths, then run:

```powershell
cargo test --config 'profile.dev.package.sha2.opt-level=3' -p context-relay-core --features test-support --lib pinned_codex_sessions_require_exact_hook_trust_and_deliver_generated_commands -- --ignored --nocapture
```

Evidence under `.codex/context-relay-closeout-2026-09-05/`:
`codex-native-hooks-red.log`, `codex-native-hooks-smart-quote-red.log`, and
`codex-native-hooks-reviewed-runtime.log` (24 sessions, 15.56 seconds).
Core library checks pass 107 tests with five opt-in tests ignored; Codex and
Claude adapter checks pass 67 and 63. The 17 primary-memory setup tests cover
the native transaction and recovery. Core/daemon/MCP all-target test-support
Clippy passes. Independent review found no remaining issues after the fix.
The shared capture change also passes all 20 actual Claude 2.1.202 synthetic
sessions and its descendant-cleanup canaries (33.89 seconds).

## End-to-end fixture correction and remaining work

Both platforms' CI at `8a9af0a` exposed a test wrapper still advertising Codex
adapter v1 while delegating v2's combined native mutation. It now forwards the
production version, native bridge planning and reservation checks, and rejects
CLI writes with `NoBridgeCliExecutor`. Its obsolete fake MCP CLI state was
removed. The existing setup/watcher/review/MCP chain additionally asserts v2,
no CLI operations and the persisted managed MCP table. This is test-support
correction, not a relaxed production validation check.
The final Windows end-to-end suite passes all 10 tests in 17.45 seconds;
`codex-native-hooks-final-e2e.log` records the result. Hosted checks for the new
commit remain separate from this local verification.

This evidence qualifies generated commands in the tested Windows environment.
It does not implement the product's hook-trust review, qualify custom shells,
prove live production bridge delivery, or qualify macOS/installed acceptance.
Codex requires [review of the exact current definitions](https://learn.chatgpt.com/docs/hooks).
The fixture's trust writes must not be reused to silently trust real user hooks.
Codex 0.144.6 remains ImportOnly. The local unsigned 11d6740 installer is unchanged
and predates these corrections. Full connection and the product goal remain open.
