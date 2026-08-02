# Context Relay

Context Relay keeps one encrypted memory and configuration workspace in sync across Claude Code, Codex, and Hermes on Windows and macOS.

> **Status:** Pre-alpha. The repository is under active development and is not ready for production use.

## Planned v1 support

- Claude Code, Codex, and Hermes
- Windows 11 24H2 or newer on x64
- macOS 14 or newer on Apple Silicon

## Primary memory contract

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

## Development

Sidecar hydration is a developer/CI build-time command. Running `npm run hydrate:sidecars` requires the repository's pinned Rust toolchain and a trusted `cargo` executable on `PATH`; hydration invokes the fixed native installer from this workspace with Cargo.

## Security

Please report security issues through [GitHub private vulnerability reporting](https://github.com/Skytuhua/Context-Relay/security/advisories/new). Do not open a public issue for a suspected vulnerability.

## License

Context Relay is licensed under the [Apache License 2.0](LICENSE).
