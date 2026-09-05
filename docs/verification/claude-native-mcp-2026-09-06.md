# Claude Code native MCP inspection qualification

This corrects the assumption that Claude's MCP list/get commands are passive
configuration inspection. It does not qualify full Claude connection support.

## Runtime evidence

The locally installed desktop bundle contains Claude Code 2.1.202 at
`%LOCALAPPDATA%/Packages/Claude_pzs8sxrjxfjjc/LocalCache/Roaming/Claude/claude-code/2.1.202/claude.exe`.
The binary is 252,038,816 bytes; SHA-256 is
`7ff0787ebdc19fc509ccea8886ebf6a53ad8213407fa3a2b7c6d1446efc419f6`.
Each experiment rechecked that digest and used a fresh synthetic home,
configuration, project, and explicit environment. No account credentials or
normal harness configuration were copied. No model session was requested.
These experiments did not use an OS sandbox and do not prove isolation.

The official CLI behaved as follows:

- User-scope `mcp add-json` wrote the supplied stdio object into
  `CLAUDE_CONFIG_DIR/.claude.json`, under `mcpServers.context-relay`, alongside
  initialization metadata.
- `mcp get` returned plain text, including scope, connection status, command,
  and a flattened argument string. Its help exposes no JSON switch. A missing
  declaration returned exit 1 with a fixed missing-server message.
- `mcp list` returned a health-check heading and plain-text server statuses.
- `plugin list --json` returned an empty array in the empty fixture.
- User-scope `mcp remove` removed the managed entry from the same JSON file.
- Local-scope `mcp add-json` stored the project key with forward slashes and
  without a Windows verbatim prefix, for example `C:/.../project 專案`.

A second experiment registered two synthetic Node commands which only appended
their names to a temporary marker and exited. Add-json created no marker. Get
started the requested command once. List then started both commands, including
the unrelated one. Thus these commands cannot satisfy the requirement that
preview and transaction readback never start configured servers.

Local evidence lives in `.codex/context-relay-closeout-2026-09-05/`:
`qualify-claude-cli.mjs`, `claude-cli-help.log`, `claude-cli-mcp-real.log`,
`claude-cli-health-canary.log`, and `claude-cli-local-scope.log`.
The corresponding synthetic evidence roots end in `QpDIgP`, `ArrImC`,
`0A8PXc`, and `CwHLWY`. Paths and marker contents are synthetic test data.

## Implementation correction

Claude preview, CLI transaction comparisons, post-command readback, compensation
and rollback now inspect the saved JSON directly. Official `mcp add-json` and
`mcp remove` remain the only declaration writers. The approval-bound operations,
canonical declaration fingerprints, WAL and conditional restoration are
unchanged. Inspection is a point-in-time read; it does not make the later CLI
mutation atomic with that read.

The reader bounds each input to 1 MiB, rejects non-files and linked/reparse
paths, verifies the opened file identity, and rejects duplicate JSON keys at
every depth. Only an exact canonical, secret-free user declaration is accepted.
Local/project same-name declarations and ambiguous Windows project aliases
reject; Windows lookup recognizes the actual CLI path spelling. The known
`managed-mcp.json` policy path rejects because it replaces normal MCP sources.
That precedence is documented in [Claude's managed MCP contract](https://code.claude.com/docs/en/managed-mcp).

Effective validation reads the bounded native MCP inventory and no longer runs
MCP list/get. The existing doctor/plugin checks and version allowlist remain.
The old fixture-only MCP output parsers and validation-command injection API
were removed. Mutation tests now change actual temporary JSON files, so a
successful command response without a saved declaration cannot pass readback.

## Verification and remaining gates

The two passive-preview regressions failed before implementation. Real Windows
local-key spelling and managed-policy regressions also failed before correction.
The latest local checks pass 42 Claude adapter tests, 11 primary-memory setup
tests and 12 Claude unit tests, plus core all-target test-support Clippy with
warnings denied. Unix parent-link coverage was added but cannot be executed on
this Windows host. Independent review checked the scoped change.

Claude 2.1.202 remains ImportOnly. Its interactive doctor behavior, actual
nonempty plugin output, native memory paths/settings, hook trust and payloads,
CLI environment/project binding, live transaction recovery and installed
acceptance remain unqualified. This patch must not be described as a completed
connection or used alone to expand Full capability. No installer or installed
configuration was changed by the qualification experiments.
