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

## Follow-up: selected configuration and Windows project lookup

Claude commands previously inherited the daemon's working directory and
environment, although the adapter inspected a separately selected configuration.
The launcher now constructs a command context from the adapter's configuration,
state file and project. It sets the selected project as the working directory,
uses an explicit environment, and distinguishes default `HOME/.claude.json`
from overridden `CLAUDE_CONFIG_DIR/.claude.json`. Configuration/state combinations
the CLI cannot represent reject before launch. The environment is not an OS
sandbox and does not establish filesystem, network or child-process confinement.

Inspection of the digest-pinned runtime also found that `.config.json` takes
precedence when present in the configuration directory, the directory is
normalized to NFC, and a custom OAuth override selects a different state suffix.
Management operations reject legacy-state redirection and non-NFC configuration
spelling; discovery rejects a custom OAuth override rather than silently selecting
the ordinary state. Existing path checks run again at inspection and command
launch. These are point-in-time checks, not atomic filesystem guarantees.

Project trust, project MCP approval and local MCP import now use the same strict
Windows-aware project lookup as passive declaration inspection. Previously the
CLI's forward-slash project key was missed by those three paths. Tests reproduce
existing trust, conflicting approval lists and local server imports with that
actual key spelling, including spaces and Chinese characters.

The opt-in Windows unit test
`pinned_claude_cli_writes_only_the_selected_default_and_override_configuration`
ran through the real core launcher with the exact 2.1.202 executable and digest
recorded above. For both fresh default and overridden homes, official local-scope
add-json wrote the inert declaration to the selected state/project entry, and
remove removed it. It passed in 23.09 seconds. No bridge was started, no model
session was requested, and no normal harness configuration was intentionally
modified. Evidence: `claude-context-real-cli.log` in the local evidence directory.

This establishes the tested launch target, not full setup capability. Persisted
approval/recovery binding of that context still needs an explicit model; doctor,
nonempty plugin output, native memory, hooks and real transactional recovery are
also open. Version 2.1.202 remains ImportOnly.

Follow-up validation passes 45 Claude adapter tests, 11 primary-memory setup
tests, 5 bridge-install tests, and 17 Claude unit tests (the real-runtime test is
ignored in the ordinary suite and was explicitly run separately). Core all-target
Clippy with test-support and warnings denied passes. The project-lookup and NFC
regressions failed before their fixes. Independent review found a Windows-only
closure that would fail non-Windows Clippy; it was moved into its conditional
block. macOS/Linux execution remains a hosted/physical follow-up.

## Follow-up: persist the approved command context

A regression reproduced reusing a Claude preview with a different configuration
or project, because the previous sealed operations bound only the executable,
arguments and declaration. `ApprovedCliMutation` now carries an optional typed
`ClaudeCodeV1` execution context with exact configuration, state-file and
project-root paths. Its presence and contents are part of approval v2 and the
sealed envelope. All Claude executor entrypoints and native apply-time reprobe
require the current adapter context to match before inspecting or mutating a
declaration. The default and overridden state locations are distinct bindings.

The absent field retains the legacy v2 preimage and envelope representation.
Old plans remain readable, but unbound Claude operations cannot execute; a fresh
preview is required. Inverse plans and recovery retain the original context.
Discovery of a different context refuses recovery rather than silently changing
its target. The WAL still selects its mutation from the authenticated sealed
plan; it does not become a second authority for launch paths. This change does
not add arbitrary environment variables, expand supported versions or claim
atomic filesystem/context identity across a command.

The wrong-context replay test failed before correction. Approval roundtrip and
wrong-harness tests also failed before implementation. Current checks include
47 Claude adapter tests, 22 approval-v1 and 21 approval-v2 tests, 14 CLI
transaction tests, 9 CLI recovery/crash tests, 34 bridge preview/apply/rollback
tests, and 11 primary-memory setup tests. These recovery tests use synthetic
CLI executors; they do not establish real installed CLI crash recovery.

Final library checks pass all 58 daemon and 88 core tests (one opt-in runtime
test ignored). Core and daemon all-target test-support Clippy passes with
warnings denied. Independent review found no actionable scoped issue and
confirmed the context is retained by inverse plans, compensation and production
recovery. Graphify was refreshed; SQL and OCaml extraction remain unavailable
because their optional parsers are absent.

## Nonempty plugin evidence for the next compatibility correction

Using the same pinned executable, a fresh temporary configuration and an inert
local marketplace, official plugin validate/add/install/list commands succeeded.
The fixture follows Claude's [local marketplace format](https://code.claude.com/docs/en/plugin-marketplaces#walkthrough-create-a-local-marketplace)
and contains only a static skill note, without hooks, MCP servers or executable
code. No model session or normal configuration was used. Manifest validation
reported only missing optional author/description warnings.

The actual `plugin list --json` entry has `id`, `version`, `scope`, `enabled`,
`installPath`, `installedAt` and `lastUpdated`. It omits `errors` when none exist.
The current production parser instead requires exactly `id`, `version`,
`enabled`, `errors`, so it would reject this normal installed-plugin result.
This parser is not corrected by the command-context patch. Bounded embedded
source inspection also shows optional `projectPath`, `mcpServers`, `errors`,
`notes`, and session-scoped records; those forms need appropriate qualification
before changing validation. In particular, optional MCP details may contain
configuration that must not be exposed in user-facing errors.

Evidence is in `qualify-claude-plugin.mjs`, `claude-plugin-help.log` and
`claude-plugin-nonempty.log` in the local evidence directory. The synthetic
installation is contained under the temporary root ending `4jft8y` and is
retained as evidence. This experiment is not a confinement or general plugin
execution-safety proof.

## Follow-up: noninteractive version and installed-plugin validation

Discovery and effective validation now use the bounded `--version` contract,
requiring the live version to match the selected layout. They no longer invoke
the interactive doctor command or expect its fictional fixed diagnostic line.
Plugin validation accepts the observed installed metadata and optional bounded
fields while preserving the previous four-field fixture contract. Nonempty or
malformed errors, unknown fields and recursive duplicate JSON keys are rejected.
Optional MCP configuration is inspected for shape only and never placed in
returned errors. This does not expand the Full version allowlist.

The renamed opt-in test
`pinned_claude_cli_uses_selected_configuration_and_validates_installed_plugin`
passed with the real digest-pinned 2.1.202 executable through the core launcher.
It adds/removes a local MCP declaration, checks the actual version, installs an
inert local plugin and validates its nonempty JSON output in both fresh default
and overridden configurations. It passed in 63.11 seconds. Its initial marketplace
setup failed because Claude rejects a Windows verbatim prefix as a marketplace
source; a separate real CLI experiment reproduced the exact source-format error.
The fixture now supplies the ordinary drive path for that source argument.

A separate temporary plugin experiment supplied synthetic MCP and SessionStart/
Stop hook marker commands. Validate, marketplace add, plugin install and JSON
listing succeeded without creating either marker. Listing did include synthetic
MCP environment configuration. This result covers that fixture and these commands,
not universal plugin helper or network isolation. No normal configuration or
model session was used.

Regressions failed before correction. Final checks pass 92 core library tests
(one opt-in test ignored in the ordinary suite), 47 Claude adapter tests and
11 primary-memory setup tests. Core and daemon all-target test-support Clippy
passes with warnings denied. Independent review approved the scoped correction.
Evidence: `claude-cli-validation-red.log`, `claude-cli-validation-suites.log`,
`claude-cli-validation-real-final.log`, `claude-cli-validation-clippy.log`,
`claude-plugin-canary.log` and `claude-plugin-verbatim.log` in the local evidence
directory. The latest 24038b9 installer predates this correction.

Native memory remains a separate qualification gap. The installed 2.1.202 source
and current [memory documentation](https://code.claude.com/docs/en/memory#storage-location)
reject ordinary relative autoMemoryDirectory values, whereas current adapter
fixtures resolve them against the project. The source also resolves settings
precedence/trust, repository/worktree roots, Windows path spelling and long
project keys differently from the adapter's simple canonical-path substitution.
These findings are not yet corrected here and do not establish a full connection.
