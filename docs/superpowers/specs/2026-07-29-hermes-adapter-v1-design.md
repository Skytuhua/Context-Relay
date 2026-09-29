# Hermes Adapter V1 Design

**Status:** Approved for implementation planning on 2026-07-29.

## Objective

Add a production-safe Context Relay adapter for Hermes Agent 0.18.2 and
0.18.1. The adapter imports reviewed profile and project state, preserves
unmanaged native state, plans rollback-safe native changes, reports semantic
losses before approval, and validates effective configuration without starting
a Hermes gateway or any configured extension.

The adapter is explicitly profile-scoped. One adapter instance represents one
canonical profile name and one canonical `HERMES_HOME`. It never aggregates
multiple profiles into a single mutation boundary.

## Source Baseline

Hermes behavior is pinned to the signed upstream releases:

- Hermes Agent 0.18.2, tag `v2026.7.7.2`
- Hermes Agent 0.18.1, tag `v2026.7.7`

The design follows the version-pinned upstream profile, context-file, plugin,
hook, MCP, security, configuration, and gateway-status behavior rather than
current-main behavior. The upstream repository was verified as
`NousResearch/hermes-agent`, public, active (`archived = false`), and above the
project's source-acceptance threshold.

Important native facts:

- The default profile is the platform-native Hermes root.
- Named profiles are immediate directories under `<default-root>/profiles/`.
- Valid named-profile identifiers match
  `[a-z0-9][a-z0-9_-]{0,63}`; invalid directory names are ignored by Hermes.
- Each profile has independent configuration, secrets, memory, skills,
  sessions, plugins, and gateway state.
- `HERMES_HOME` is the profile boundary; `HOME` remains the OS user's home on
  normal host installs.
- `SOUL.md` is profile-global and independent of project context.
- Project context chooses one active context type. Hermes-native project files
  have the highest priority, with `.hermes.md` preferred over `HERMES.md` in
  the same directory.
- Gateway liveness is profile-scoped and uses `gateway.pid`,
  `gateway.lock`, and `gateway_state.json`, with PID start-time and command-line
  identity checks to avoid PID-reuse false positives.

## Scope

### Included

- Explicit default and named-profile discovery.
- `config.yaml` reviewed configuration.
- `SOUL.md`.
- `.hermes.md` and `HERMES.md` project instructions and shadowing.
- `memories/MEMORY.md` and `memories/USER.md`.
- Profile skills rooted under `skills/`.
- User plugin manifests and enabled/disabled state.
- Gateway hooks and shell-hook declarations.
- MCP server definitions and tool filtering.
- Exact Hermes permission declarations that Context Relay can preserve.
- Visible loss reporting for declarations without an exact cross-harness
  meaning.
- Native transaction planning and effective-state validation.

### Excluded

- `.env` and all values loaded from it.
- `auth.json`, auth locks, credential pools, provider API keys, OAuth data,
  cookies, private keys, and passwords.
- Gateway platform and channel configuration, bot tokens, pairing data, and
  channel directories.
- Sessions, transcripts, `state.db` and related databases, histories,
  checkpoints, backups, caches, logs, and process registries.
- `gateway.pid`, `gateway.lock`, and `gateway_state.json` as imported data.
  They are read only for the apply interlock.
- Cron jobs and messaging delivery state.
- Automatic installation or execution of plugin code, hook code, MCP servers,
  skills, or provider backends during import or validation.
- Profile creation, deletion, rename, clone, export, import, alias management,
  and sticky-profile changes.
- Automatic permission weakening or trust approval.

## Architecture

The public module follows the repository's existing flat adapter namespace:

```text
crates/core/src/hermes.rs
crates/core/src/hermes/profile.rs
crates/core/src/hermes/yaml.rs
crates/core/src/hermes/gateway.rs
crates/core/src/hermes/import.rs
crates/core/src/hermes/render.rs
crates/core/tests/hermes_adapter_v1.rs
crates/core/tests/fixtures/hermes-0.18.2.json
crates/core/tests/fixtures/hermes-0.18.1.json
adapters/hermes/capabilities.md
```

`hermes.rs` owns the public types and the `HarnessAdapter` and `NativeAdapter`
implementations. Focused private modules own profile resolution, YAML
projection, gateway liveness, import, and rendering. This avoids another
single-file adapter accumulating unrelated parser, discovery, and process
identity logic.

The public surface is:

```rust
pub enum HermesExecutableKind {
    Native,
    Wrapper,
    Unknown,
}

pub struct HermesProfile {
    pub name: String,
    pub hermes_home: PathBuf,
}

pub struct HermesLayout {
    pub executable: PathBuf,
    pub executable_kind: HermesExecutableKind,
    pub version: String,
    pub installation_method: InstallationMethod,
    pub default_hermes_home: PathBuf,
    pub profile: HermesProfile,
    pub project_root: PathBuf,
    pub working_directory: PathBuf,
}

pub struct HermesAdapter { /* private attested state */ }
```

The adapter exposes discovery/from-layout construction, the normal
`HarnessAdapter` interface, profile and project wire paths, approved native
mutation planners, and a typed native-memory snapshot interface. Native memory
documents remain distinguishable as agent memory (`MEMORY.md`) or user profile
memory (`USER.md`) instead of being flattened into an ambiguous instruction.

## Explicit Profile Discovery

Discovery resolves a profile before any profile content is read:

1. Resolve and canonicalize the default Hermes root:
   - macOS: `$HOME/.hermes`, unless an explicit `HERMES_HOME` selects a custom
     default root.
   - Windows: `%LOCALAPPDATA%\hermes`, with Hermes's documented fallback when
     `LOCALAPPDATA` is unavailable.
2. Enumerate the default profile only when its root is a real directory.
3. Enumerate immediate child directories of `<default-root>/profiles/`.
4. Accept only names matching Hermes's exact profile identifier grammar.
5. Reject symlinks, reparse-point escapes, non-directories, nested profile
   names, case-colliding names, and paths that canonicalize outside the
   profiles root.
6. Sort accepted profiles by canonical name.
7. Match `ProbeContext.requested_profile` exactly after Hermes-compatible
   lowercase normalization. `default` selects the default root.
8. Return `NotFound` for an unknown requested profile. Never synthesize a
   directory and never fall back to another profile.

An adapter instance stores the canonical selected profile and requires every
later probe, import, render, native plan, and validation request to match that
same selection. A caller cannot switch profiles by changing only the probe
context.

Custom `HERMES_HOME` layouts are allowed only when the exact root is explicitly
selected during discovery or supplied in a test/attested layout. Arbitrary
paths supplied through profile names are never accepted.

## Capability and Attestation

Full apply requires all of the following:

- Version is exactly `0.18.2` or `0.18.1`.
- Executable is classified as native rather than a shell, batch, PowerShell,
  Python, or other wrapper.
- Executable, profile root, project root, and working directory are safe,
  representable native paths.
- Working directory is inside the canonical project root.
- Profile root is the exact selected default root or a valid immediate named
  profile directory.
- Executable identity and SHA-256 are unchanged since discovery.
- `config.yaml`, when present, is a regular non-link file with supported YAML
  topology.

Unknown versions, wrappers, unknown executable formats, and unsupported YAML
topologies are import-only. Missing installations report `Missing`. Unsafe
paths or malformed explicit profiles fail closed.

Every external command rechecks the executable digest, runs in an
adapter-controlled working directory, receives no user credential environment,
has a 30,000 ms timeout, caps stdout and stderr at 65,536 bytes each, and
rejects unexpected output. Validation uses an isolated staged `HERMES_HOME`;
no command receives the real profile's `.env`.

## Import Model

Import is an allowlist walk. It never recursively walks all of
`HERMES_HOME`.

### `config.yaml`

The YAML importer parses the complete document for structural validity, then
projects only these reviewed surfaces:

- `approvals`
- `command_allowlist`
- `plugins.enabled`
- `plugins.disabled`
- `mcp_servers`
- `hooks`

The projection preserves names, enabled state, safe transport declarations,
tool filters, timeouts, and declarative behavior. It excludes secret-bearing
leaves before a `ComponentRecord` is constructed.

The importer rejects duplicate mapping keys, unsafe custom tags, merge keys or
aliases that cross a managed-section boundary, non-string mapping keys,
overlong scalars, and nesting/collection sizes above protocol bounds.

### Instructions

Instruction order is explicit:

1. Profile `SOUL.md`, independently active.
2. Project Hermes context selected from the working directory toward the Git
   root.
3. The nearest directory wins.
4. Within one directory, `.hermes.md` wins over `HERMES.md`.

Active instructions include `precedenceIndex`, `structuralLocation`,
`profile`, and `contextRole` metadata. Existing lower-priority candidates are
not imported as active instructions; the probe reports deterministic shadowing
conflicts.

`SOUL.md` is not searched in the project and project `SOUL.md` files are not
treated as Hermes-native context.

### Memory

`memories/MEMORY.md` and `memories/USER.md` are read as separate typed native
memory documents with stable source identity and digests. Empty or absent files
are omitted.

Native memory planning updates only a Context Relay managed fenced section in
the selected target file. Existing Hermes-authored text outside the fence is
preserved byte-for-byte. The plan rejects duplicate, nested, malformed, or
overlapping markers and enforces the applicable Hermes character bound before
approval. Changes take effect for new Hermes sessions; validation does not
pretend to alter an already-frozen session prompt.

### Skills

Only regular `SKILL.md` files below the selected profile's `skills/` root are
imported. Excluded/cache directories, symlinks, unsafe topology, and files
outside the root are rejected. Referenced assets and scripts remain local
unless a later reviewed package flow imports them explicitly.

### Plugins

The adapter imports:

- A regular `plugin.yaml` manifest from each safe immediate plugin root.
- The three Hermes states: enabled, disabled, and discovered-but-not-enabled.
- The selected provider-plugin names represented in safe configuration.

It does not import or execute Python modules, entry points, dependency files,
or `requires_env` values. Project-local plugins are excluded in V1 because
their activation depends on a process environment trust switch rather than a
durable project declaration.

Plugin apply changes only `plugins.enabled` and `plugins.disabled`. Installing,
updating, or removing plugin source is reserved for the reviewed package
workflow.

### Hooks

The adapter imports shell-hook declarations from the `hooks` configuration
section and gateway-hook manifests from safe `hooks/<name>/HOOK.yaml` paths.
Gateway `handler.py` content is imported only as an executable hook component
with active-change classification and only after the general text-secret scan
passes; it is never executed during import or validation.

Rendering preserves unrelated hook directories and files. A gateway-hook
change may target only the exact reviewed `HOOK.yaml` and `handler.py` paths
inside one selected hook directory.

### MCP

MCP components preserve safe declarative transport and filtering fields:

- `command`
- `args`
- `url`
- `timeout`
- `connect_timeout`
- `idle_timeout_seconds`
- `max_lifetime_seconds`
- `enabled`
- `supports_parallel_tool_calls`
- `tools.include`
- `tools.exclude`
- `tools.prompts`
- `tools.resources`

Credential-bearing fields are excluded or redacted:

- `env` values
- HTTP header values
- client key material or key passphrases
- inline bearer tokens, API keys, passwords, cookies, and authorization values
- any resolved `${ENV_VAR}` value

Environment-variable placeholders may be preserved by variable name only.
Redacted MCP components are importable for review but cannot be rendered until
the native profile already provides the corresponding local secret reference.
Validation never connects to an MCP server.

## Secret Boundary

Secret classification runs before serialization into protocol records. It is
centralized and recursive rather than maintained independently by each import
branch. YAML values receive structural classification; Markdown, skill
documents, plugin manifests, hook manifests, and hook handlers receive the
same bounded token/private-key/credential scan before their content is
accepted.

A field is secret-bearing when either:

- Its normalized key is a known credential name (`api_key`, `token`,
  `password`, `secret`, `authorization`, `cookie`, `client_key`, and exact
  version-pinned equivalents).
- Its structural location is a credential container (`env`, headers,
  provider credentials, channel/platform configuration, gateway auth, or
  pairing state).
- Its scalar resembles a supported token, private key, authorization header,
  or embedded credential URL.

Secret values are never copied into component bodies, metadata, findings,
errors, digests displayed to users, logs, snapshots, or test diagnostics.
Errors identify only the safe structural path.

Rendering rejects any desired component containing redaction sentinels or
newly detected secret-bearing values. Context Relay never writes `.env` or
`auth.json`.

## YAML Preservation

`config.yaml` is not rewritten from a generic in-memory object. The adapter:

1. Parses the whole file to validate structure and derive semantic state.
2. Locates exact top-level managed section spans.
3. Re-renders only a managed section that actually changed.
4. Preserves every unrelated byte, comment, ordering choice, scalar style, and
   unknown key outside changed managed spans.
5. Preserves unknown keys inside a managed mapping unless that exact key is
   owned by the requested component.
6. Rejects flow/alias/tag structures that cannot be patched without semantic
   ambiguity.
7. Produces zero files and zero writes for a semantic no-op.

Each planned mutation snapshots the exact target and binds expected and
intended fingerprints through the existing native transaction engine.

## Permission Mapping and Preview

Hermes permission declarations are imported exactly. The adapter does not
convert `smart`, `manual`, `off`, deny globs, permanent allowlists, cron
behavior, or confirmation switches into a weaker generic rule.

Each permission component receives:

- `nativePermissionPath`
- `mappingFidelity` (`exact` or `lossy`)
- `mappingReason` for lossy mappings
- `profile`

`ProbeReport.policy_conflicts` contains deterministic safe identifiers for
native declarations that cannot be represented exactly. `classify` converts a
requested lossy cross-harness change into a `ChangeClass::Conflict` preview
entry with a safe summary. `render` and native planning reject unresolved
lossy changes. A caller must retain the native declaration or explicitly
replace it with an exact Hermes declaration.

## Gateway Interlock

Active apply is blocked while the selected profile's gateway is live. Active
changes include:

- `config.yaml`
- permissions
- plugin state
- MCP configuration
- shell hooks
- gateway-hook manifests or handlers

The interlock:

1. Reads only the selected profile's `gateway.pid`, `gateway.lock`, and
   `gateway_state.json`.
2. Validates bounded JSON without importing it.
3. Checks the OS-owned runtime lock where supported.
4. Validates PID existence without sending a signal on Windows.
5. Compares the recorded process start time when available.
6. Requires a real Hermes `gateway run`/runtime command line.
7. Requires the command line or record to belong to the selected profile.
8. Treats a verified stale record for a dead process as a non-blocking finding.
9. Treats malformed or unverifiable runtime state as
   `gateway_state_unverifiable` and blocks active apply rather than guessing.
10. Repeats the full check at native `reprobe_live_state` immediately before
   commit.

The adapter never stops, restarts, drains, signals, or cleans up a gateway.
The user must stop it through Hermes.

Passive managed Markdown and memory-section changes may be planned while the
gateway is idle or running, but the preview states that existing sessions keep
their frozen prompt snapshot. Passive changes still require normal digest and
concurrency validation.

## Effective Validation

Validation has two layers:

1. Internal validation re-reads the exact selected profile and verifies YAML,
   Markdown markers, manifests, path topology, expected component state, and
   resulting digests.
2. For a supported native executable, bounded `hermes config check` runs
   against an isolated staged `HERMES_HOME` containing only the effective
   non-secret `config.yaml` projection and required safe scaffolding. The real
   profile's `.env`, auth, plugins, hooks, sessions, channels, and operational
   files are neither copied nor exposed to the command.

Validation never runs:

- `hermes` chat or TUI
- `hermes gateway`
- `hermes doctor --fix`
- `hermes config migrate`
- plugin registration or plugin Python
- hook handlers
- MCP discovery, connection, login, reload, or configured commands
- provider setup or authentication

Missing optional credentials are expected in the isolated validation home and
do not invalidate non-secret configuration. Unexpected output, executable
drift, timeout, oversized output, non-zero structural failure, or evidence
that an extension started fails validation.

## Error Handling

- Invalid caller input: `InvalidRequest`.
- Missing executable, profile, or explicitly required native file: `NotFound`.
- Unsupported version, wrapper, unknown executable, or unpatchable YAML:
  `HarnessUnsupported` for apply while import remains available where safe.
- Live selected gateway, concurrent edit, profile drift, executable drift, or
  unresolved lossy mapping: `Conflict`.
- Secret-bearing desired state or unsafe topology: fail closed with a
  non-secret `InvalidRequest`.

Errors never include source file contents, YAML scalar values, tokens,
credentials, channel identifiers, or gateway messages.

## Testing Strategy

Golden fixtures for 0.18.2 and 0.18.1 share one schema and differ only where
the releases differ. Fixtures contain canary secrets at every excluded
surface, including nested YAML credential paths.

Required integration coverage:

- Both supported releases probe as full and import all reviewed surfaces.
- Default and named profiles are independent explicit targets.
- Unknown, invalid, nested, symlinked, and case-colliding profiles are never
  modified.
- One adapter cannot be redirected to another profile after construction.
- `.hermes.md`/`HERMES.md` and nearest-directory precedence are exact.
- `SOUL.md` remains independent.
- Memory files stay distinct and unmanaged text survives managed-section
  updates.
- YAML unknown fields, comments, order, and unrelated scalar styles survive.
- Secret-bearing YAML values, `.env`, auth, provider, channel, session,
  database, log, and operational canaries never enter serialized imports.
- Redacted desired state cannot be applied.
- Plugin code, hook handlers, and MCP servers never execute during import or
  validation.
- Unsupported permission mappings are visible in probe and classified preview.
- A real selected-profile gateway blocks every active render/plan and is
  rechecked at the native commit boundary.
- Stale, recycled, foreign-profile, and malformed gateway records do not
  produce unsafe writes or false live-gateway matches.
- Unknown versions and wrappers are import-only.
- Concurrent edits invalidate the plan.
- Semantic no-ops produce zero writes.
- Native rollback and metadata/topology guarantees remain intact.
- Existing Claude Code and Codex adapter suites remain green.
- Workspace formatting, linting, and all-feature tests remain green on their
  supported runners.

## Acceptance Criteria

The design is complete when Task 12 can demonstrate:

1. Exact per-profile isolation with no implicit fallback.
2. Complete reviewed import for the named Hermes surfaces.
3. Zero secret canary leakage.
4. Visible lossy permission mappings before approval.
5. Live-gateway blocking at preview and commit boundaries.
6. Effective validation that starts no gateway, extension, hook, provider, or
   MCP server.
7. Transaction-safe, concurrency-safe native changes with unrelated state
   preserved.
8. Passing Hermes golden fixtures and Claude/Codex regressions.

## Primary References

- [Hermes 0.18.2 release](https://github.com/NousResearch/hermes-agent/releases/tag/v2026.7.7.2)
- [Hermes 0.18.1 release](https://github.com/NousResearch/hermes-agent/releases/tag/v2026.7.7)
- [0.18.2 profile behavior](https://raw.githubusercontent.com/NousResearch/hermes-agent/v2026.7.7.2/website/docs/user-guide/profiles.md)
- [0.18.2 context-file behavior](https://raw.githubusercontent.com/NousResearch/hermes-agent/v2026.7.7.2/website/docs/user-guide/features/context-files.md)
- [0.18.2 plugin behavior](https://raw.githubusercontent.com/NousResearch/hermes-agent/v2026.7.7.2/website/docs/user-guide/features/plugins.md)
- [0.18.2 hook behavior](https://raw.githubusercontent.com/NousResearch/hermes-agent/v2026.7.7.2/website/docs/user-guide/features/hooks.md)
- [0.18.2 MCP behavior](https://raw.githubusercontent.com/NousResearch/hermes-agent/v2026.7.7.2/website/docs/user-guide/features/mcp.md)
- [0.18.2 security behavior](https://raw.githubusercontent.com/NousResearch/hermes-agent/v2026.7.7.2/website/docs/user-guide/security.md)
- [0.18.2 profile implementation](https://raw.githubusercontent.com/NousResearch/hermes-agent/v2026.7.7.2/hermes_cli/profiles.py)
- [0.18.2 gateway identity implementation](https://raw.githubusercontent.com/NousResearch/hermes-agent/v2026.7.7.2/gateway/status.py)
