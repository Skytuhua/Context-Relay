# Context Relay

[![CI](https://github.com/Skytuhua/Context-Relay/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Skytuhua/Context-Relay/actions/workflows/ci.yml)
[![Secret Scan](https://github.com/Skytuhua/Context-Relay/actions/workflows/secret-scan.yml/badge.svg?branch=main)](https://github.com/Skytuhua/Context-Relay/actions/workflows/secret-scan.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Context Relay keeps one encrypted memory and configuration workspace in sync across Claude Code, Codex, and Hermes on Windows and macOS.

> **Status:** Pre-alpha. The repository is under active development and is not ready for production use.

## Planned v1 support

| Harness | Platform |
| --- | --- |
| Claude Code | Windows 11 24H2+ (x64), macOS 14+ (Apple Silicon) |
| Codex | Windows 11 24H2+ (x64), macOS 14+ (Apple Silicon) |
| Hermes | Windows 11 24H2+ (x64), macOS 14+ (Apple Silicon) |

## How it works

Context Relay is the authoritative local memory and shared task ledger for its
configured harnesses. Managed project instructions tell each harness to search
Context Relay at session start, save explicit decisions with
`context_relay_remember`, send inferred knowledge to the review queue with
`context_relay_propose_memory`, and keep tasks current through the MCP task
tools. Native harness memory remains an import and recovery surface.

Setup is previewed once and applied as one reviewed native transaction. For
the exact supported harness versions, setup disables native memory generation
with documented settings, installs the project instruction contract and local
MCP bridge, and registers only the declared high-level Markdown sources.
Existing native content appears once in the review queue; later edits appear
after their digest is stable for 750 ms. Context Relay exports are ledgered and
do not re-import themselves.

The daemon owns observation and the MCP bridge owns harness access. Both keep
working while the desktop UI is closed. Native hooks forward only validated
session identifiers, working-directory binding, locally generated timestamps,
and explicit task evidence; prompts, responses, transcript paths, tool input,
tool output, and unknown fields are excluded.

Exact per-version settings and source bindings are documented in the
[Claude Code](adapters/claude-code/capabilities.md),
[Codex](adapters/codex/capabilities.md), and
[Hermes](adapters/hermes/capabilities.md) capability pages.

### Components

| Component | Crate / app | Role |
| --- | --- | --- |
| Desktop UI | `apps/desktop` (Tauri) | Review queue, approvals, setup previews |
| Daemon | `crates/contextd` | Filesystem observation, native memory watch, ledger |
| MCP bridge | `crates/context-mcp` | The local MCP server the harnesses connect to |
| Core | `crates/core` | Adapters, setup planning, semantic diffing, native transactions |
| Native runner | `crates/native-runner` | Sandboxed filesystem and CLI execution for transactions |
| Protocol | `crates/protocol` | Wire types, bindings, and schema export |
| Local IPC | `crates/local-ipc` | Daemon ⇄ desktop/bridge transport |

## Development

Requirements:

- Node.js `24` (see `.node-version`) and pnpm `11.9`
- The pinned Rust toolchain (see `rust-toolchain.toml`; currently `1.97.1` with
  `clippy` and `rustfmt`)
- Windows: MSVC toolchain and Strawberry Perl on `PATH` for the vendored
  OpenSSL/SQLCipher build

```sh
pnpm install
npm run hydrate:sidecars   # developer/CI build-time sidecar hydration
pnpm tauri:dev             # run the desktop app against a local daemon
```

Sidecar hydration is a developer/CI build-time command. Running
`npm run hydrate:sidecars` requires the repository's pinned Rust toolchain and
a trusted `cargo` executable on `PATH`; hydration invokes the fixed native
installer from this workspace with Cargo.

Common checks:

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
pnpm typecheck && pnpm test
pnpm license:check
```

To build an unsigned Windows x64 installer candidate on Windows:

```sh
pnpm package:windows
```

The command builds the desktop and its four companion executables, then writes
an NSIS setup `.exe` under
`target/x86_64-pc-windows-msvc/release/bundle/nsis/` (or your configured Cargo
target directory). It installs for the current user and includes the WebView2
bootstrapper; installing WebView2 requires internet if it is absent. Packaging
uses static CRT linkage and locked Cargo dependencies. Relevant pull requests
also build a candidate with checksums in GitHub Actions.

These are internal candidates. Signing, installed-product testing, hosted
functionality and the remaining [release acceptance requirements](docs/verification/windows-app-release.md)
must pass before claiming a complete product release.

## Security

Please report security issues through [GitHub private vulnerability reporting](https://github.com/Skytuhua/Context-Relay/security/advisories/new). Do not open a public issue for a suspected vulnerability.

Every push is scanned with the hash-pinned Gitleaks release (see
`docs/repository-settings.md`). Sync credentials live only in the OS keyring
through the direct local-ipc dependency; the daemon is the only component
allowed to write the installation-token credential.

## License

Context Relay is licensed under the [Apache License 2.0](LICENSE).
