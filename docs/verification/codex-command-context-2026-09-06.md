# Codex command configuration binding — 2026-09-06

The adapter read its selected `codex_home`, but native subprocesses inherited
`CODEX_HOME` and other environment settings from the daemon. A runner could also
choose a working directory when consuming a verified command. Readback and
legacy CLI operations could therefore target a different configuration from the
one inspected during setup.

Every adapter command now carries its selected configuration folder, user home,
project root and working directory. These paths are canonicalized and checked
again before launch. The subprocess receives an explicit environment and cannot
inherit another profile or a preload setting. Windows invocations remain hidden.
The runner consumes the bound command without supplying a working directory.
Only `--version` discovery can use the process route without a configuration
context; it does not load the harness's configuration.

The existing sealed-plan mechanism now includes a `codex-v1` CLI context. All
five CLI executor entry points reject missing or changed bindings before
invoking a runner. Apply, compensation, committed recovery and Undo carry the
same context. Old envelopes and their hashes remain readable; an old unbound
CLI plan requires a new preview before executing. The native file-based bridge
writer and its exact Undo remain unchanged. No Full version is enabled.

## Evidence

The executable regression failed before the correction because the child did
not receive the selected configuration home. It now observes the selected
`CODEX_HOME`, `HOME`, `USERPROFILE` and working directory. A separate child probe
checks that explicit ambient profile, XDG and preload overrides are discarded.

The opt-in Windows test
`codex::command_context::tests::pinned_codex_cli_reads_and_writes_only_the_selected_profile`
passes against actual Codex 0.144.6, SHA-256
`4b76ded066d0239115ca97473d010c92072bc5c5550a45dd7cbebe1e9eb956a7`.
Both a default home and a separate custom configuration folder pass native MCP
list/add/get/remove/list through the production command runner. Unrelated server
settings remain intact, the selected declaration returns to its initial state,
and competing profiles remain byte-identical. A custom home receives no fallback
`.codex/config.toml`. The executable hash is unchanged after all commands.

The native test runs in an owned Windows job with a stdin startup gate and a
90-second outer deadline. Its advertised scratch directory and profile folders
are siblings inside a disposable root. The first fixture layout put its profile
under its advertised TEMP directory; Codex rejected PATH alias creation there.
The test layout was corrected without relaxing stderr checks. Codex's own MCP
writer rewrites comments, so the fixture verifies unrelated server semantics
rather than requiring native CLI comment preservation. It executes no model,
hook or configured MCP server, and uses no normal user configuration.

Final native result: two profiles, ten commands, 38.79 seconds. The affected Rust
checks pass 114 core library, 69 Codex adapter, 22 approval-v1, 23 approval-v2,
14 CLI transaction, 17 primary-memory setup, five bridge-installation and ten
MCP end-to-end tests (274 total). Seven opt-in core tests are ignored by the
ordinary suite. Context tampering is rejected by both sealed-plan validation and
each CLI executor entry point. Independent review approved the production
correction and final test delta. Core, daemon and MCP all-target Clippy with
test support and warnings denied passes. An initial layout lint was corrected
by placing implementation items before the test module.

Logs under `.codex/context-relay-closeout-2026-09-05/`:
`codex-command-context-red.log`, `codex-command-context-green.log`,
`codex-command-context-native-final.log`, `codex-command-context-lib-final.log`,
`codex-command-context-suites.log`, `codex-command-context-contracts.log`, and
`codex-command-context-mcp-chain.log`, and `codex-command-context-clippy-final.log`.
Select the explicit pinned executable in
`CONTEXT_RELAY_TEST_CODEX_EXE`, then run:

```powershell
cargo test --config 'profile.dev.package.sha2.opt-level=3' -p context-relay-core --lib pinned_codex_cli_reads_and_writes_only_the_selected_profile -- --ignored --nocapture
```

## CI fixture corrections

CI run `34005214789` exposed two test issues on the previous commit:

- The boundary test's exact unresolved-import assertion did not account for
  `CARGO_TERM_COLOR=always`. Its Cargo probes now explicitly request no color.
  The compiler must still reject the isolated helper without test support and
  compile it with test support. All seven boundary tests pass locally with
  forced color in the parent environment.
- The MCP end-to-end materializer still used a physical Windows path as its
  synthetic Codex trust key. It now uses the original native temporary-project
  spelling and asserts that it resolves to the bound physical path. The actual
  setup/watcher/review/MCP chain and all ten end-to-end tests pass locally.

The original temporary-path correction above was insufficient: CI run
`34021397684` still failed when Windows TEMP itself used a verbatim path. Both
the MCP and authoritative-daemon materializers now use `dunce::simplified`
solely for their synthetic Codex trust keys, retaining physical path bindings.
The MCP chain test always supplies a canonical Windows project path so ordinary
local runs also exercise this regression. `dunce` is a Windows-only test
dependency in these two crates and was already present in the lockfile.

Forced-verbatim TEMP/TMP reproduced the original failures in both suites before
the correction. Afterwards all ten MCP end-to-end tests and all four
authoritative-daemon tests passed (18.15 and 7.31 seconds). The permanent MCP
regression also passed with ordinary TEMP (5.49 seconds). Formatting, diff checks
and daemon/MCP all-target Clippy with test support and warnings denied pass.
Independent review found no actionable issues. Evidence is retained in
`mcp-verbatim-temp-{red,green,regression}.log`,
`daemon-verbatim-temp-{red,green}.log` and `verbatim-fixtures-clippy.log`.
The installer, Secret Scan and Supabase workflows for `2e24749` passed; its
general CI run still contains the Windows fixture failure and is not green.

The source dependency checker and product trust policy are unchanged. Exact
hosted failures are retained in `ci-baefedc-boundary.log` and
`ci-baefedc-windows-tests.log`; `codex-command-context-boundary.log` records the
forced-color success. Local corrections do not rewrite the previous CI results.

## Remaining acceptance

This fixes the execution target required for reliable native readback. It does
not add the live hook-trust endpoint or prove full setup on the installed app.
Managed/profile/launch overrides, remaining root and platform behavior, native
credential binding and clean-machine acceptance remain open. Codex 0.144.6
remains ImportOnly. Native desktop control is still paused; the existing local
11d6740 installer predates these changes and has not been replaced or installed.
