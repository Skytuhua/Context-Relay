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

## Follow-up: correct memory directory-key encoding

The key-encoding part of that gap is now corrected. Rust's canonical Windows
prefix is removed before encoding the ordinary drive/UNC path. Replacement uses
UTF-16 units, including two hyphens for a supplementary character, and long keys
use Claude's 200-unit prefix plus absolute signed wrapping hash in base36.
Non-Unicode paths are rejected instead of silently changing their identity.

The checked-in 2.1.202 memory-key vectors were generated from only the three pure
string helpers in the digest-pinned executable. They were evaluated in a VM
without module initialization, process, filesystem or network access. They cover
spaces, accented/Chinese/supplementary characters and both sides of the length
boundary. Two regressions reproduced the extra Windows prefix and supplementary
character mismatch before correction. All 94 ordinary core library, 47 Claude
adapter and 11 primary-memory setup tests pass; core/daemon all-target
test-support Clippy passes. Independent read-only review approved the translation.

This corrects encoding of an already selected path. It does not yet correct
repository/worktree root selection, relative explicit directory values, settings
precedence/trust or override environments. Those remain required qualification
work before Full support. Evidence: `qualify-claude-memory-key.mjs`,
`claude-memory-key-vectors.log`, `claude-memory-key-red.log`,
`claude-memory-key-suites.log` and `claude-memory-key-clippy.log` in the local
evidence directory. The fixture records the executable digest and evidence scope.

## Follow-up: explicit home and working Windows startup hooks

Claude's selected user home is now independent of a custom configuration
directory. The layout retains it, the command environment uses it, and the
ClaudeCodeV2 execution context binds it into approval and the sealed plan.
Apply, rollback and recovery reject a changed home just as they reject changed
configuration or project paths. V1 envelopes remain readable but require a new
preview before execution. The child-process regression reproduced the previous
incorrect HOME. The pinned CLI's MCP/plugin qualification also passed with the
custom configuration below a separate home (73.47 seconds).

Real 2.1.202 `--init-only` qualification found that Windows command hooks run
through Git Bash. Old double-quoted verbatim executable paths failed to launch;
literal `$HOME` in a double-quoted filename expanded. Claude still returned zero
when the hook failed. The Claude-specific renderer now validates the Windows
path before removing its verbatim prefix, uses forward slashes and Bash single
quotes, and escapes apostrophes. Codex's Windows renderer is unchanged. New
components reject the old syntax; merging still recognizes exact older managed
entries for replacement and archival without removing unrelated hooks.

The opt-in test `pinned_claude_cli_executes_generated_windows_startup_hook`
compiles an inert local capture executable whose path contains spaces, `$HOME`,
an apostrophe and Chinese characters. It installs the production-generated hook
only in temporary configurations, invokes the digest-pinned CLI through the core
launcher and verifies the captured SessionStart event, arguments and project.
It passed both default and overridden configurations in 12.48 seconds. No normal
configuration, model request or Context Relay service was used. The test checks
hook execution rather than relying on CLI exit status. Initial test assertions
incorrectly assumed that the future transcript directory existed and that its
path omitted the Windows verbatim prefix; those assertions were corrected.

Validation passes 98 ordinary core library tests (two explicit runtime tests
ignored in the ordinary suite), 48 Claude adapter, 64 Codex adapter, 22 approval,
5 bridge-install, 11 primary-memory setup and 58 Windows daemon tests. Core and daemon all-target
test-support Clippy passes with warnings denied. Independent review approved
the production changes and the explicit-home binding; its cross-platform test
lint finding was fixed. Graphify was refreshed (14,955 nodes, 43,107 edges).

The macOS recovery fixture also needed updating after hosted job 101364841165
failed on 71d5c73: it emitted a bare version, simulated get/list responses and
seeded an unbound CLI plan. It now writes native `.claude.json` state, seals V2
home/configuration/project paths and accepts only the exact version and rollback
remove commands. Its three prepared/committed recovery cases and nonlaunching
bridge canary are retained. Independent review approved the fixture correction;
its macOS execution still needs the next hosted run.

Evidence: `claude-user-home-red.log`, `claude-user-home-final-suites.log`,
`claude-user-home-real.log`, `claude-bash-hook-red.log`,
`claude-init-hook-literal-dollar.log`, `claude-init-hook-verbatim.log`,
`claude-init-hook-bash-quote.log`, `claude-bash-hook-real-complete.log`,
`claude-home-hooks-suites.log`, `claude-home-hooks-clippy.log` and
`ci-71-macos-rust-failure.log` in the local evidence directory. The first local
release test build used a different target cache and was stopped during OpenSSL
compilation; the completed real test uses the x64 static-CRT release target.

This qualifies startup command rendering and event delivery, not Stop events,
full memory setup, real transaction/crash recovery or installed acceptance.
Memory settings precedence, directory selection and repository/worktree binding
remain open. No Full support was enabled for the installed 2.1.202 runtime.

## Configured memory directory correction

The adapter previously joined ordinary relative `autoMemoryDirectory` values
to the selected project. The pinned 2.1.202 string helper instead ignores them
and falls back to its default. The adapter now expands `~/` and `~\` from the
selected home, normalizes dot segments and Unicode, and distinguishes ignored
values from valid but unsupported bindings. A valid explicit directory whose
normalized representation is too long remains unavailable; it cannot silently
become the default directory. Long input or a NUL-containing component that is
removed by normalization follows the native helper's order of operations.
Windows drive-rooted paths bind to the selected project's drive. Unknown
versions still require an explicit supported binding and cannot guess defaults.

The pure helper was extracted from the same digest-pinned native artifact and
run with isolated path modules and synthetic homes. The committed fixture has
44 Windows and 44 POSIX input cases plus three Windows verbatim-home cases.
It includes Unicode, tilde expansion, ordinary relative paths, drive prefixes,
long input, removable NUL components and verbatim/UNC rejection. No third-party
helper source is shipped in the fixture. Windows tests pass all 47 applicable
vectors; POSIX execution remains a hosted gate. This tests path-string behavior,
not the native runtime's effective settings or its home lookup.

Filesystem binding now checks every ancestor and removes terminal separators
before inspection. Review caught the Unix trailing-slash behavior that can
follow a directory symlink despite `symlink_metadata`; the new Unix regression
covers existing and dangling linked directories and missing children beneath a
linked ancestor. That Unix regression requires hosted execution. The fixture
homes preserve canonical POSIX paths while removing Windows verbatim prefixes.
Synthetic release fixtures now configure an actual home-relative directory
instead of relying on the incorrect project-relative behavior.

Local checks pass 100 ordinary core tests, 51 Claude adapter tests and 11 primary
memory setup tests, plus core/daemon all-target test-support Clippy with warnings
denied. The existing rollback/privacy matrix still passes. Red regressions were
observed for home expansion, relative fallback and long-input normalization.
Evidence is in `claude-memory-directory-*.log`, the isolated generator
`qualify-claude-memory-directory.mjs`, and the committed
`claude-code-2.1.202-memory-directories.json` fixture.

The [current storage documentation](https://code.claude.com/docs/en/memory#storage-location)
also describes absolute and home-relative settings. It includes features newer
than the pinned artifact, so this correction follows the pinned helper rather
than assuming every documented feature exists in 2.1.202.

This does not close user/local/managed/environment precedence, effective disable
settings, repository/worktree default selection, source revalidation, full native
setup or installed acceptance. No Full support was enabled. The existing
11d6740 installer predates this source correction. The earlier macOS recovery
fixture (5d92f4f) has since passed hosted CI33989730248.

## File settings precedence and transaction revalidation

Claude memory inspection now includes the selected configuration's user
settings, project settings and `settings.local.json`, in that priority order.
The pinned artifact's settings loader (`aUn`/`pOt`) and memory selector (`EQd`)
were inspected without starting the harness. A local `autoMemoryEnabled` value
selects the local file as the disable target; changing only the project file
would otherwise leave the local override active. Unrelated values and exact
original bytes are preserved through rollback. Existing managed-file memory
settings still produce watch-only capability and are never written.

Every inspected layer uses the bounded, unique-key JSON reader and ancestor
checks also used for native MCP configuration. Full setup seals user, project,
local and configured managed-file dependencies, including absent files. It
rechecks these dependencies and the exact memory sources before writing,
between writes and during final validation. A newly added local override or
changed managed setting invalidates the reviewed plan. Files modified by the
plan use exact restorable fingerprints so global hook updates and inverse
transactions can pass through their two reviewed states. Legacy Full plans
without these dependencies require a new preview. The subsequent
[read-only registration correction](read-only-memory-registration-2026-09-06.md)
also covers ImportOnly preview-to-apply settings revalidation and startup recovery.

Review also reproduced an absent-to-present Windows directory spelling change.
Missing roots now bind through their nearest canonical existing ancestor, so
creating the same memory folder retains its descriptor and source ID. The
expanded recovery matrix found that undo-to-absence could select an adjacent
transaction backup as a metadata template. Reserved `.context-relay-*` files
are now excluded from template selection.

Four settings regressions and the Windows directory-creation regression were
observed failing before their fixes. Local validation passes 100 ordinary core
tests (two real-runtime tests remain opt-in), 58 Claude adapter tests and 11
primary-memory setup tests. Coverage includes local true/false overrides,
directory precedence, ambiguous/non-file layers, drift, global hook writes,
intermediate checks, watch-only Full transactions, legacy plans, exact undo and
recovery after commit. Logs are `claude-memory-settings-*.log` in the local
evidence directory.

Core/daemon all-target test-support Clippy passes with warnings denied;
independent review approved the settings patch and its two follow-up fixes.
`graphify update .` completed (15,031 nodes, 43,263 edges). Hosted CI33992307102
has now passed the preceding configured-directory source's macOS Rust tests,
including its POSIX path regressions; the current settings patch has only been
run locally on Windows so far.

This is a file-layer correction, not complete effective-runtime qualification.
Interactive trust, launch flags and environment, managed drop-ins/registry,
repository/worktree defaults, native Stop events and full real setup/recovery
remain open. No additional version was enabled. The existing unsigned installer
from source 11d6740 does not include this change or the preceding configured-path
correction; it has not been installed or tested through native desktop control.

## Read-only registration follow-up

ImportOnly preview now seals the same memory-selection file dependencies.
Apply/resume checks the current installation, settings and exact source list
without launching the harness. Startup no longer publishes an interrupted,
unverified registration. The [cross-harness evidence](read-only-memory-registration-2026-09-06.md)
records the production canary, recovery/Undo matrix and Windows path correction.
This closes the registration revalidation gap above, not full runtime connection
qualification. No additional version is enabled and the installer is unchanged.

## Default repository and worktree memory roots

The default memory key previously used the selected project folder directly.
Pinned 2.1.202 `vQd`/`rf` instead select the nearest repository ancestor and, for
a verified linked worktree, its common repository root. The adapter now walks
ancestor `.git` markers without starting Git or Claude. It checks the worktree
metadata layout, `commondir` and reverse `gitdir` before sharing a main repository's
memory folder. Bare common repositories retain their own directory as the key;
submodules and malformed or incomplete worktree declarations retain the native
fallback repository root. Non-repository projects retain the selected folder.
Explicit memory settings continue to take precedence.

The two relevant functions were extracted from the same SHA-256-pinned executable
and run against virtual filesystems with Windows and POSIX path modules. The
committed `claude-code-2.1.202-memory-repositories.json` contains 16 cases per
platform: plain/nested repositories, linked and bare worktrees, submodules,
absolute/relative pointers, BOM whitespace, malformed prefixes and broken
backlinks. The generator executes only those bounded helpers and a synthetic
read-only filesystem; no native initialization, project contents or model calls.
The [current memory documentation](https://code.claude.com/docs/en/memory#storage-location)
also describes repository-level memory shared across worktrees. Pinned helper
evidence remains authoritative for this implementation's version-specific rules.

Metadata reads use the existing bounded reader and reject symlinks, reparse
points, unsafe ancestors and unqualified network/device pointers. Uninspectable
bindings remain unavailable rather than silently selecting another folder.
Windows comparisons preserve case and use the ordinary spelling expected by the
native helper. Converting a canonical path must resolve back to that same path,
preventing trailing-dot/space aliases or generic volume prefixes from redirecting
the walk. Known versions use the corrected default; unknown versions still need
an explicit qualified memory directory.

Two adapter regressions failed before the fix: selecting a repository ancestor
and sharing linked-worktree memory. They also verify that a newly added nested
repository or changed backlink invalidates existing setup and reservation checks.
Review identified a mixed relative/absolute Windows prefix mismatch, reproduced
with a failing native vector and corrected. Additional Windows tests cover
generic device/volume prefixes and real trailing-dot/space sibling directories.
The Unix link tests are committed and await hosted execution.

Final local checks pass 104 ordinary core library tests (two opt-in real-runtime
tests not run), 60 Claude adapter tests and 16 primary-memory setup tests.
All 16 Windows native-helper vectors pass. Independent review approved the
lookup and final Windows conversion corrections. Evidence logs in the local
closeout directory are `claude-repository-memory-red.log`,
`claude-repository-memory-common-path-red.log`,
`claude-repository-memory-vectors.log` and
`claude-repository-memory-final-suites.log`.

Core/daemon all-target test-support Clippy passes with warnings denied
(`claude-repository-memory-clippy-final.log`). The final `graphify update .`
completed with 15,112 nodes and 43,523 edges
(`claude-repository-memory-graphify-final.log`).

This closes the default repository/worktree helper mismatch. Native session
project-root selection, trust/flags/environment, other managed settings sources,
Stop events and full real setup/recovery still need qualification. No additional
version is enabled, and the existing 11d6740 unsigned installer is unchanged.
