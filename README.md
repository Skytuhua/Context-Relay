# Context Relay

Context Relay keeps one encrypted memory and configuration workspace in sync across Claude Code, Codex, and Hermes on Windows and macOS.

> **Status:** Pre-alpha. The repository is under active development and is not ready for production use.

## Planned v1 support

- Claude Code, Codex, and Hermes
- Windows 11 24H2 or newer on x64
- macOS 14 or newer on Apple Silicon

## Development

Sidecar hydration is a developer/CI build-time command. Running `npm run hydrate:sidecars` requires the repository's pinned Rust toolchain and a trusted `cargo` executable on `PATH`; hydration invokes the fixed native installer from this workspace with Cargo.

## Security

Please report security issues through [GitHub private vulnerability reporting](https://github.com/Skytuhua/Context-Relay/security/advisories/new). Do not open a public issue for a suspected vulnerability.

## License

Context Relay is licensed under the [Apache License 2.0](LICENSE).
