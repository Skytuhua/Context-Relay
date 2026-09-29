# Hermes Adapter V1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a production-safe Context Relay adapter for Hermes Agent 0.18.2 and 0.18.1 that binds one adapter instance to one explicit profile, imports only reviewed non-secret state, preserves unmanaged YAML and Markdown bytes, blocks active changes while that profile's gateway is live, exposes lossy permission mappings before approval, and validates effective configuration without starting a gateway or extension.

**Architecture:** Add a public `hermes` adapter module with focused private modules for profile identity, YAML projection, import, rendering, and gateway liveness. The adapter uses a full semantic YAML parse plus a conservative block-path index so it can patch only owned YAML paths and preserve every unrelated byte. All apply paths use the existing native transaction engine; no Hermes CLI write command is used. Effective validation first re-reads the native result internally, then runs only `hermes config check` against an isolated, non-secret staged `HERMES_HOME`.

**Tech Stack:** Rust 2024, `context-relay-protocol`, `context-relay-native-runner`, `serde`, `serde_json`, `serde_yaml_ng = 0.10.0`, `sha2`, native filesystem transactions, platform process/lock APIs, golden JSON fixtures.

## Global Constraints

- The normative design is `docs/superpowers/specs/2026-07-29-hermes-adapter-v1-design.md`; implementation choices must not weaken it.
- Support Hermes Agent `0.18.2` and `0.18.1` for full apply. Unknown versions, wrappers, unknown executable formats, and unsupported YAML topology are import-only.
- One adapter instance represents exactly one canonical profile name and one canonical `HERMES_HOME`. It never aggregates profiles and never falls back to another profile.
- The default profile is named `default`. Named profiles are valid immediate directories below `<default-root>/profiles/` whose names match `[a-z0-9][a-z0-9_-]{0,63}`.
- Reject symlinked, reparse-point, nested, path-escaping, and case-colliding profile entries. Never create, rename, delete, clone, or repair a profile.
- Import is an allowlist walk. Never recursively walk the whole profile root.
- Never import or write `.env`, `auth.json`, credential pools, provider keys, OAuth data, channel/platform configuration, pairing data, sessions, transcripts, databases, histories, cron state, caches, logs, backups, gateway records, or process registries.
- Secret classification runs before a protocol record is constructed. Errors and findings name only safe structural paths; they never include the rejected scalar.
- Import or validation must never execute plugin code, hook code, MCP commands, providers, skills, gateway commands, migrations, setup flows, or doctor fixes.
- `config.yaml` updates use the original bytes plus exact owned-path replacements. Do not serialize the whole parsed YAML document.
- Preserve comments, ordering, scalar style, unknown fields, line endings, and unrelated bytes outside exact replaced paths. Preserve unknown children inside managed sections by replacing only owned leaf/subtree paths.
- Reject a targeted YAML path when its patch span contains a flow collection, custom tag, anchor, alias, merge key, tab indentation, non-string key, duplicate key, or ambiguous comment boundary.
- Semantic no-ops produce zero rendered files and zero native mutations.
- Memory and Markdown changes only alter the Context Relay fenced section and preserve all other bytes. Existing sessions retain their frozen prompt snapshot.
- Treat `smart`, `manual`, `off`, deny globs, permanent allowlists, cron behavior, and confirmation switches as exact Hermes declarations. Never silently weaken them to a generic permission.
- Every lossy mapping must have `mappingFidelity=lossy`, a deterministic `mappingReason`, a probe policy conflict, and a `ChangeClass::Conflict` preview. Render and native planning reject unresolved lossy mappings.
- Active changes include `config.yaml`, permissions, plugin state, MCP configuration, shell hooks, and gateway hook manifests/handlers. The selected profile's live or unverifiable gateway blocks them at preview, planning, and native `reprobe_live_state`.
- A verified dead stale gateway record is non-blocking and reported as `gateway_state_stale`. The adapter never stops, signals, restarts, drains, or cleans a gateway.
- Every external command rechecks the executable SHA-256, has a 30,000 ms timeout, caps stdout and stderr at 65,536 bytes each, uses null stdin, and runs with a minimal adapter-owned environment.
- `hermes config check` receives an isolated staged `HERMES_HOME` containing only the reviewed non-secret `config.yaml` projection and safe scaffolding. It never receives the real `.env`.
- Native mutations snapshot the exact regular file, preserve native metadata, bind expected and intended fingerprints, reject unsafe topology through `OsNativeFileSystem`, and remain rollback-safe under concurrent edits.
- Do not weaken existing Claude Code or Codex behavior. Keep both adapter integration suites green.
- Never force-push, never use `pull_request_target`, and never publish generated sidecars manually.

---

### Task 1: Bind Adapter Identity to One Explicit Hermes Profile

**Files:**
- Create: `crates/core/src/hermes.rs`
- Create: `crates/core/src/hermes/profile.rs`
- Create: `crates/core/tests/hermes_adapter_v1.rs`
- Create: `crates/core/tests/fixtures/hermes-0.18.2.json`
- Create: `crates/core/tests/fixtures/hermes-0.18.1.json`
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `crates/core/Cargo.toml`
- Modify: `crates/core/src/lib.rs`

**Public interfaces:**

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HermesExecutableKind {
    Native,
    Wrapper,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HermesProfile {
    pub name: String,
    pub hermes_home: PathBuf,
}

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
pub struct HermesAdapter {
    layout: HermesLayout,
    project_id: ProjectId,
    origin_device: DeviceId,
    observed_hlc: HybridLogicalClock,
    executable_hash: Sha256Digest,
}

impl HermesAdapter {
    pub fn discover(
        project_root: impl Into<PathBuf>,
        working_directory: impl Into<PathBuf>,
        requested_profile: &str,
        project_id: ProjectId,
        origin_device: DeviceId,
        observed_hlc: HybridLogicalClock,
    ) -> Result<Self, ClientError>;

    pub fn from_layout(
        layout: HermesLayout,
        project_id: ProjectId,
        origin_device: DeviceId,
        observed_hlc: HybridLogicalClock,
    ) -> Result<Self, ClientError>;

    pub fn discover_profiles(
        default_hermes_home: impl AsRef<Path>,
    ) -> Result<Vec<HermesProfile>, ClientError>;

    pub fn profile_home_wire(&self) -> WireNativeValue;
    pub fn project_root_wire(&self) -> WireNativeValue;
}
```

- [ ] **Step 1: Add the frozen release fixtures**

Both JSON files use this exact top-level schema:

```json
{
  "version": "0.18.2",
  "profile": {
    "name": "coder",
    "configYaml": "# profile heading\nunknown_root: 'preserve-single-quotes'\napprovals:\n  mode: smart\n  deny:\n    - 'rm -rf *'\ncommand_allowlist:\n  - cargo test\nplugins:\n  unknown_child: preserve-me\n  enabled:\n    - reviewer\n  disabled:\n    - legacy\nmcp_servers:\n  docs:\n    url: https://example.com/mcp\n    enabled: true\n    tools:\n      include: [search]\n    headers:\n      Authorization: must-not-import-yaml-header\n  local:\n    command: node\n    args: [server.js]\n    env:\n      DOCS_TOKEN: must-not-import-yaml-env\nhooks:\n  shell:\n    post_tool:\n      command: check-write\nprovider:\n  api_key: must-not-import-provider-key\n",
    "files": {
      "SOUL.md": "# Soul\nPrefer small verified changes.\n",
      "memories/MEMORY.md": "# Agent memory\nHermes-owned prefix.\n",
      "memories/USER.md": "# User memory\nUser prefers concise output.\n",
      "skills/review/SKILL.md": "---\nname: review\ndescription: Review a change.\n---\nReview the diff.\n",
      "plugins/reviewer/plugin.yaml": "name: reviewer\nversion: 1.2.3\ndescription: Review changes.\nrequires_env:\n  - REVIEW_TOKEN\n",
      "plugins/reviewer/plugin.py": "raise RuntimeError('must-not-execute-plugin')\n",
      "hooks/audit/HOOK.yaml": "name: audit\nevents: [post_tool]\n",
      "hooks/audit/handler.py": "print('safe handler body; must-not-execute-hook')\n",
      ".env": "OPENROUTER_API_KEY=must-not-import-env\n",
      "auth.json": "{\"token\":\"must-not-import-auth\"}\n",
      "sessions/session.jsonl": "{\"token\":\"must-not-import-session\"}\n",
      "state.db": "must-not-import-database",
      "gateway.pid": "{\"pid\":999999,\"kind\":\"gateway\",\"argv\":[\"hermes\",\"gateway\",\"run\",\"--profile\",\"coder\"],\"start_time\":1}\n",
      "gateway_state.json": "{\"channel_token\":\"must-not-import-gateway-token\"}\n",
      "channels/telegram.json": "{\"bot_token\":\"must-not-import-channel\"}\n",
      "logs/hermes.log": "must-not-import-log"
    }
  },
  "project": {
    "HERMES.md": "# Root fallback\nRoot context.\n",
    ".hermes.md": "# Root preferred\nUse Rust 2024.\n",
    "service/HERMES.md": "# Service fallback\nFallback context.\n",
    "service/.hermes.md": "# Service preferred\nPreserve wire contracts.\n"
  }
}
```

Use the exact block above for `hermes-0.18.2.json`. Use the same complete block for `hermes-0.18.1.json` with only `"version": "0.18.1"` changed. JSON fixture materialization writes `profile.files` below the selected profile root, writes `profile.configYaml` to `config.yaml`, and writes `project` below a canonical temporary project root.

- [ ] **Step 2: Write the RED profile-identity integration tests**

Create a fixture harness in `crates/core/tests/hermes_adapter_v1.rs` that:

- canonicalizes `std::env::temp_dir()` before appending a unique directory;
- creates a default root, a default profile, named profiles `coder` and `writer`, and `project/service`;
- writes a native-looking fixture executable;
- constructs `HermesAdapter::from_layout` for `coder`;
- uses a process-wide mutex around environment-dependent discovery tests;
- removes only its exact unique test directory in `Drop`.

The general fixture constructor removes the frozen `gateway.pid` and
`gateway_state.json` canaries after the import-exclusion assertions have taken
their source snapshot. Gateway-specific tests materialize reviewed records
explicitly, so an operational canary cannot accidentally make unrelated
render tests report an unverifiable live state.

Add these tests with the stated assertions:

| Test | Required assertions |
|---|---|
| `supported_release_fixtures_bind_one_named_profile` | Both versions construct successfully; probe reports `CapabilityLevel::Full`, `active_profile == Some("coder")`, and only the selected profile root in the profile-specific config roots. |
| `default_and_named_profiles_are_distinct_explicit_targets` | Discovery returns `default`, `coder`, `writer` in sorted order; the three canonical roots differ; selecting each yields its own exact `HERMES_HOME`. |
| `unknown_profile_is_rejected_without_fallback_or_creation` | Selecting `missing` returns `NotFound`; `profiles/missing` is absent before and after; the default and named profile bytes are unchanged. |
| `invalid_nested_symlinked_and_case_colliding_profiles_are_ignored` | Invalid names, a nested `coder/child`, a profile symlink/reparse point, and `Coder` plus `coder` never appear as separate accepted targets. |
| `adapter_cannot_be_redirected_after_construction` | A `coder` adapter rejects a probe requesting `writer` or `default`; it does not read either profile's canary file. |
| `working_directory_must_stay_inside_project_root` | `from_layout` rejects an outside working directory and an unresolved/unsafe project path. |
| `unknown_versions_and_wrappers_are_import_only` | `9.9.9`, shebang, `.cmd`, `.bat`, and `.ps1` layouts probe as `ImportOnly`; render returns `HarnessUnsupported`. |

- [ ] **Step 3: Run the profile test and capture RED**

Run:

```bash
cargo test -p context-relay-core --test hermes_adapter_v1 supported_release_fixtures_bind_one_named_profile
```

Expected: compilation fails because `context_relay_core::hermes` and its public types do not exist.

- [ ] **Step 4: Add the YAML dependency and module skeleton**

Add to `[workspace.dependencies]` in `Cargo.toml`:

```toml
serde_yaml_ng = "0.10.0"
```

Add to `crates/core/Cargo.toml`:

```toml
serde_yaml_ng.workspace = true
```

Extend Windows features for read-only process identity and file locking:

```toml
"Win32_System_Threading",
"Win32_System_IO",
```

Export the module in `crates/core/src/lib.rs`:

```rust
pub mod hermes;
```

In `hermes.rs`, define:

```rust
const SUPPORTED_VERSIONS: [&str; 2] = ["0.18.2", "0.18.1"];
const CLI_TIMEOUT_MS: u32 = 30_000;
const CLI_OUTPUT_LIMIT: u64 = 64 * 1024;
const MANAGED_START: &str = "<!-- context-relay:start -->";
const MANAGED_END: &str = "<!-- context-relay:end -->";
const DEFAULT_PROFILE: &str = "default";
```

`from_layout` must canonicalize and attest the executable, default root, selected profile root, project root, and working directory; require the working directory below the project root; require the selected profile to equal either the default root or one accepted immediate named profile; and hash the executable exactly once for the attested snapshot. Do not read profile content until this identity check succeeds.

`discover` resolves the default profile root before enumerating profiles:

```text
explicit HERMES_HOME             -> exact custom default root
macOS without HERMES_HOME        -> $HOME/.hermes
Windows without HERMES_HOME      -> %LOCALAPPDATA%\hermes
Windows LOCALAPPDATA unavailable -> $HOME/.hermes
```

Executable discovery considers the first safe native candidate named `hermes`
(`hermes.exe` on Windows) on `PATH`, then `$HOME/.local/bin/hermes` on macOS.
It classifies file magic before execution, hashes the candidate, and runs only
`--version` through the bounded runner. Version parsing strips ANSI, requires
exactly one semantic version token, requires that token to equal the layout
version, and rejects any control text. A wrapper or unknown-format candidate
may construct an import-only adapter from an attested layout but is never
executed during discovery.

- [ ] **Step 5: Implement strict profile enumeration and selection**

In `profile.rs`, add these private interfaces:

```rust
pub(super) fn enumerate_profiles(
    default_root: &Path,
) -> Result<Vec<HermesProfile>, ClientError>;

pub(super) fn select_profile(
    default_root: &Path,
    requested: &str,
) -> Result<HermesProfile, ClientError>;

pub(super) fn validate_profile_binding(
    default_root: &Path,
    selected: &HermesProfile,
) -> Result<(), ClientError>;
```

Enumeration algorithm:

1. Require a canonical real default root; return `NotFound` when the explicit root is absent.
2. Add `default` bound to that root.
3. Read only immediate entries of `<default-root>/profiles`.
4. Accept only real directories with names matching `[a-z0-9][a-z0-9_-]{0,63}`.
5. Reject file types reporting symlink/reparse-point status before canonicalization.
6. Canonicalize the profiles root and candidate; require `candidate.parent() == canonical_profiles_root`.
7. Normalize accepted names with ASCII lowercase, detect more than one source spelling for the same normalized name, and reject the entire collision from enumeration.
8. Sort by normalized name and reject duplicate canonical roots.
9. `select_profile` applies the same ASCII-lowercase normalization to caller input, requires exact membership, and never joins unvalidated caller text to a path.

`HermesAdapter::probe` validates `HarnessId::Hermes` and requires `requested_profile` to match the adapter's stored profile after normalization. Its capability is:

```rust
fn capability(&self) -> CapabilityLevel {
    if SUPPORTED_VERSIONS.contains(&self.layout.version.as_str())
        && self.layout.executable_kind == HermesExecutableKind::Native
        && self.yaml_topology_supported()
    {
        CapabilityLevel::Full
    } else {
        CapabilityLevel::ImportOnly
    }
}
```

For this first isolated commit, implement the complete `HarnessAdapter` trait
with real `probe` and `discover_scopes`; `import`, `render`, `classify`,
`plan_cli_ops`, and `validate_effective` return the stable
`HarnessUnsupported` error `Hermes adapter phase is not available`. The public
native planner methods are introduced only with their RED tests in Task 3.
Tasks 2 through 4 replace these safe closed behaviors test-first; no panic or
partial write stub is permitted.

- [ ] **Step 6: Reach GREEN and commit the profile unit**

Run:

```bash
cargo test -p context-relay-core --test hermes_adapter_v1 default_and_named_profiles_are_distinct_explicit_targets
cargo test -p context-relay-core --test hermes_adapter_v1 unknown_profile_is_rejected_without_fallback_or_creation
cargo test -p context-relay-core --test hermes_adapter_v1 invalid_nested_symlinked_and_case_colliding_profiles_are_ignored
cargo test -p context-relay-core --test hermes_adapter_v1 adapter_cannot_be_redirected_after_construction
cargo test -p context-relay-core --test hermes_adapter_v1 unknown_versions_and_wrappers_are_import_only
```

Expected: all five tests pass.

Commit:

```bash
git add Cargo.toml Cargo.lock crates/core/Cargo.toml crates/core/src/lib.rs crates/core/src/hermes.rs crates/core/src/hermes/profile.rs crates/core/tests/hermes_adapter_v1.rs crates/core/tests/fixtures/hermes-0.18.2.json crates/core/tests/fixtures/hermes-0.18.1.json
git commit -m "feat: discover Hermes profiles safely"
```

---

### Task 2: Import Reviewed Hermes State Without Crossing the Secret Boundary

**Files:**
- Create: `crates/core/src/hermes/yaml.rs`
- Create: `crates/core/src/hermes/import.rs`
- Modify: `crates/core/src/hermes.rs`
- Modify: `crates/core/tests/hermes_adapter_v1.rs`
- Modify: `crates/core/tests/fixtures/hermes-0.18.2.json`
- Modify: `crates/core/tests/fixtures/hermes-0.18.1.json`

**Internal interfaces:**

```rust
#[derive(Clone, Debug)]
pub(super) struct ParsedHermesYaml {
    pub source: Vec<u8>,
    pub value: serde_yaml_ng::Value,
    pub patch_index: YamlPatchIndex,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct YamlSpan {
    pub start: usize,
    pub end: usize,
    pub indent: usize,
}

#[derive(Clone, Debug, Default)]
pub(super) struct YamlPatchIndex {
    pub paths: BTreeMap<Vec<String>, YamlSpan>,
}

pub(super) fn parse_config(bytes: &[u8]) -> Result<ParsedHermesYaml, ClientError>;
pub(super) fn project_reviewed_config(
    parsed: &ParsedHermesYaml,
    profile: &str,
) -> Result<Vec<ComponentRecord>, ClientError>;
pub(super) fn scan_text_secret(bytes: &[u8], safe_location: &str) -> Result<(), ClientError>;
```

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HermesMemoryKind {
    Agent,
    User,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HermesMemoryDocument {
    pub kind: HermesMemoryKind,
    pub body_markdown: String,
    pub source_digest: Sha256Digest,
}

impl HermesAdapter {
    pub fn import_native_memory(&self) -> Result<Vec<HermesMemoryDocument>, ClientError>;
}
```

- [ ] **Step 1: Add RED import and secret-exclusion tests**

Add these integration tests:

| Test | Required assertions |
|---|---|
| `supported_releases_import_every_reviewed_component_kind` | Both fixtures import all seven `ComponentKind` values; the plugin states, MCP names, shell hook, gateway hook, skill, instructions, and permissions have deterministic names and metadata. |
| `import_serialization_contains_no_secret_or_operational_canary` | Serialize `ImportedState` and native memory snapshots; none contains `must-not-import`, `OPENROUTER_API_KEY`, `Authorization`, `.env`, `auth.json`, `sessions`, `state.db`, `gateway.pid`, `gateway_state.json`, `channels`, or `logs`. |
| `secret_bearing_yaml_fields_are_removed_before_component_creation` | Nested MCP `env` and header values and provider `api_key` never appear in body, metadata, error, or finding text; MCP metadata retains only safe placeholder names and marks the component redacted. |
| `soul_and_nearest_project_context_have_exact_precedence` | `SOUL.md` imports independently with `contextRole=soul`; only `service/.hermes.md` is active project context; `.hermes.md` wins over `HERMES.md`; metadata contains exact `precedenceIndex`, `structuralLocation`, `profile`, and `contextRole`. |
| `memory_documents_remain_typed_and_separate` | `MEMORY.md` yields `HermesMemoryKind::Agent`; `USER.md` yields `User`; their digests and bodies differ; neither is flattened into an instruction component. |
| `skills_plugins_and_hooks_are_allowlist_walks` | Only regular safe `SKILL.md`, `plugin.yaml`, `HOOK.yaml`, and scanned `handler.py` enter imports; plugin Python and dependency files are absent; executable bodies are never run. |
| `malformed_yaml_and_unsafe_topology_fail_closed_without_values` | Duplicate keys, custom tags, aliases crossing managed paths, merge keys, non-string keys, depth/collection overflow, symlinked files, and secret-like Markdown fail with safe path-only errors. |
| `disabled_components_respect_include_disabled` | Disabled plugin/MCP/hook components are absent when false and present with `archived=true` or `enabled=false` metadata when true. |

Use sentinel files in the plugin, hook, and MCP fixture commands; assert import leaves every sentinel absent.

- [ ] **Step 2: Run import tests and capture RED**

Run:

```bash
cargo test -p context-relay-core --test hermes_adapter_v1 import_serialization_contains_no_secret_or_operational_canary
cargo test -p context-relay-core --test hermes_adapter_v1 soul_and_nearest_project_context_have_exact_precedence
```

Expected: failures because the reviewed YAML projection and import walkers do not exist.

- [ ] **Step 3: Implement whole-document validation and the conservative YAML patch index**

`parse_config` must:

1. Require UTF-8, at most 1 MiB, one YAML document, and a root mapping.
2. Parse with `serde_yaml_ng::from_slice`, which rejects duplicate mapping keys.
3. Recursively require string mapping keys, depth at most 32, at most 256 entries per collection, and scalar text within protocol limits.
4. Scan physical lines without normalizing them. Reject tab indentation, directives, a second `---`, merge key `<<`, and targeted-path tags/anchors/aliases/flow syntax.
5. Build a block-mapping path index. A key span starts at its key line and ends before the leading blank/comment prefix attached to the next sibling key. A container span ends at the first non-blank line with indentation less than or equal to the container's parent indentation.
6. Record only paths rooted at `approvals`, `command_allowlist`, `plugins.enabled`, `plugins.disabled`, `mcp_servers`, and `hooks`, plus owned children below those roots.
7. Verify every indexed path resolves to the same semantic node in the parsed tree. If a target cannot be indexed without ambiguity, mark apply import-only; do not guess a span.

Secret classification uses normalized structural paths:

```rust
fn secret_key(key: &str) -> bool {
    matches!(
        normalize_key(key).as_str(),
        "apikey"
            | "token"
            | "password"
            | "secret"
            | "authorization"
            | "cookie"
            | "clientkey"
            | "clientkeypassphrase"
            | "credential"
    )
}

fn credential_container(path: &[String]) -> bool {
    path.iter().any(|part| {
        matches!(
            normalize_key(part).as_str(),
            "env"
                | "headers"
                | "httpheaders"
                | "credentials"
                | "channels"
                | "platforms"
                | "gatewayauth"
                | "pairing"
        )
    })
}
```

Also reject scalar patterns for private-key headers, bearer/basic authorization, supported token prefixes, and URLs with embedded user info. Preserve environment placeholder names only when the scalar is exactly `${[A-Z_][A-Z0-9_]{0,127}}`; never resolve the variable.

- [ ] **Step 4: Implement reviewed import projection**

In `import.rs`, use exact allowlists:

```text
config.yaml:
  approvals
  command_allowlist
  plugins.enabled
  plugins.disabled
  mcp_servers
  hooks

profile files:
  SOUL.md
  memories/MEMORY.md
  memories/USER.md
  skills/*/SKILL.md and safe nested skill directories
  plugins/*/plugin.yaml
  hooks/*/HOOK.yaml
  hooks/*/handler.py

project files:
  one nearest active .hermes.md or HERMES.md from working directory toward project root
```

Use `read_dir` with explicit depth and entry-count bounds; inspect file type before canonicalization; reject links/reparse points; require the canonical result under its allowlisted root. Do not use a recursive walk of the profile root.

The reviewed MCP projection allows only:

```text
command
args
url
timeout
connect_timeout
idle_timeout_seconds
max_lifetime_seconds
enabled
supports_parallel_tool_calls
tools.include
tools.exclude
tools.prompts
tools.resources
```

Configuration-backed component bodies use canonical compact JSON, never raw
secret-bearing YAML. Convert reviewed YAML nodes to `serde_json::Value` only
after requiring string mapping keys, sort object keys recursively with
`BTreeMap`, then serialize with `serde_json::to_string`. File-backed
instruction, skill, manifest, and handler components retain their scanned
source text. Every component includes:

```rust
("profile".into(), profile_name.into()),
("structuralLocation".into(), safe_relative_location),
("nativeFormat".into(), "json".into() /* or "markdown", "yaml", "python" */),
```

The exact structural-location namespaces are:

```text
config:<dot-separated-reviewed-path>
profile:SOUL.md
profile:skills/<safe-relative-path>/SKILL.md
profile:plugins/<safe-name>/plugin.yaml
profile:hooks/<safe-name>/HOOK.yaml
profile:hooks/<safe-name>/handler.py
project:<safe-relative-directory>/.hermes.md
project:<safe-relative-directory>/HERMES.md
```

Rendering resolves a target from `ComponentKind` plus
`structuralLocation`; it never derives a native path from `ComponentRecord.name`.

An MCP declaration containing excluded credential structure remains importable only with those values removed and metadata:

```rust
("redacted".into(), "true".into()),
("secretReferenceNames".into(), sorted_placeholder_names.join(",")),
("profile".into(), profile_name.into()),
```

Permission components receive:

```rust
("nativePermissionPath".into(), path),
("mappingFidelity".into(), "exact".into() /* or "lossy" */),
("mappingReason".into(), deterministic_reason),
("profile".into(), profile_name.into()),
```

Use these stable lossy reasons and probe conflicts:

```text
approval_mode_not_portable
deny_pattern_not_portable
permanent_allowlist_not_portable
cron_permission_not_portable
confirmation_switch_not_portable
```

`HarnessAdapter::discover_scopes` returns global plus the configured project. `HarnessAdapter::import` rejects any scope not bound to the stored profile/project and rejects repeated scopes. Components and source digests are sorted deterministically.

- [ ] **Step 5: Reach GREEN, scan for leaked canaries, and commit**

Run:

```bash
cargo test -p context-relay-core --test hermes_adapter_v1 supported_releases_import_every_reviewed_component_kind
cargo test -p context-relay-core --test hermes_adapter_v1 import_serialization_contains_no_secret_or_operational_canary
cargo test -p context-relay-core --test hermes_adapter_v1 secret_bearing_yaml_fields_are_removed_before_component_creation
cargo test -p context-relay-core --test hermes_adapter_v1 soul_and_nearest_project_context_have_exact_precedence
cargo test -p context-relay-core --test hermes_adapter_v1 memory_documents_remain_typed_and_separate
cargo test -p context-relay-core --test hermes_adapter_v1 skills_plugins_and_hooks_are_allowlist_walks
rg -n "must-not-import-(env|auth|session|database|gateway|channel|log|provider|yaml)" crates/core/src/hermes.rs crates/core/src/hermes
```

Expected: all focused tests pass; the `rg` command returns no production-code matches.

Commit:

```bash
git add crates/core/src/hermes.rs crates/core/src/hermes/yaml.rs crates/core/src/hermes/import.rs crates/core/tests/hermes_adapter_v1.rs crates/core/tests/fixtures/hermes-0.18.2.json crates/core/tests/fixtures/hermes-0.18.1.json
git commit -m "feat: import reviewed Hermes state"
```

---

### Task 3: Render Owned Paths and Enforce the Gateway Interlock

**Files:**
- Create: `crates/core/src/hermes/render.rs`
- Create: `crates/core/src/hermes/gateway.rs`
- Modify: `crates/core/src/hermes.rs`
- Modify: `crates/core/src/hermes/yaml.rs`
- Modify: `crates/core/tests/hermes_adapter_v1.rs`

**Public mutation interfaces:**

```rust
impl HermesAdapter {
    pub fn plan_native_config(
        &self,
        desired: &DesiredState,
    ) -> Result<Option<ApprovedMutation>, ClientError>;

    pub fn plan_native_markdown(
        &self,
        component: &ComponentRecord,
    ) -> Result<Option<ApprovedMutation>, ClientError>;

    pub fn plan_native_memory(
        &self,
        kind: HermesMemoryKind,
        body_markdown: &str,
    ) -> Result<Option<ApprovedMutation>, ClientError>;

    pub fn plan_native_gateway_hook(
        &self,
        manifest: &ComponentRecord,
        handler: Option<&ComponentRecord>,
    ) -> Result<Vec<ApprovedMutation>, ClientError>;
}
```

**Gateway interfaces:**

```rust
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum GatewayStatus {
    Idle,
    Stale,
    Live,
    Unverifiable,
}

pub(super) fn inspect_gateway(
    profile: &HermesProfile,
) -> Result<GatewayStatus, ClientError>;

pub(super) fn require_gateway_idle(
    profile: &HermesProfile,
) -> Result<(), ClientError>;
```

- [ ] **Step 1: Add RED preservation, permission-preview, and gateway tests**

Add these tests:

| Test | Required assertions |
|---|---|
| `yaml_patch_preserves_unowned_bytes_comments_order_and_scalar_style` | Change one owned approval leaf and one plugin state; root comments, single quotes, unknown root, `plugins.unknown_child`, MCP sibling fields, and CRLF/LF choice survive byte-for-byte outside exact replaced spans. |
| `semantic_noop_produces_no_rendered_file_or_mutation` | Desired state equal to imported semantics returns no `RenderedFile` and `Ok(None)` from native config/Markdown/memory planning. |
| `managed_markdown_and_memory_preserve_unmanaged_bytes` | Insert/update/remove only the fenced section; prefixes/suffixes survive; duplicate, nested, missing-half, and reversed markers fail closed. |
| `redacted_or_secret_bearing_desired_state_cannot_render` | `<redacted>`, inline tokens, private keys, authorization values, and embedded-credential URLs return `InvalidRequest`; no returned error contains the rejected scalar. |
| `unsupported_permission_mappings_are_visible_in_probe_and_preview` | Probe has stable policy conflicts; `classify` returns `ChangeClass::Conflict` with a safe reason; exact Hermes-to-Hermes permission changes remain active changes. |
| `unresolved_lossy_permission_change_cannot_render_or_plan` | `render` and `plan_native_config` reject lossy desired permission metadata with `Conflict`; native bytes remain unchanged. |
| `live_selected_profile_gateway_blocks_every_active_change` | Config, permission, plugin, MCP, shell-hook, and gateway-hook render/plan paths all return `Conflict`; passive Markdown/memory planning still succeeds with `frozen_session_snapshot` finding metadata. |
| `other_profile_gateway_does_not_block_selected_profile` | A verified live `writer` gateway does not block a `coder` adapter. |
| `stale_dead_gateway_is_nonblocking_and_reported` | Dead PID plus matching stale records allows active planning and reports `gateway_state_stale`. |
| `malformed_recycled_or_foreign_gateway_state_blocks_active_apply` | Malformed JSON, live PID with changed start time, non-Hermes command, or wrong-profile command yields `gateway_state_unverifiable` and blocks. |
| `concurrent_native_edit_invalidates_planned_config_and_memory` | Editing either target after planning makes native before-image creation reject the stale expected fingerprint; rollback restores original bytes and metadata. |

Gateway tests use injected pure process/lock observations in unit tests. One platform integration test may use the current test process only as a foreign-process case; it must never signal or terminate a process.

- [ ] **Step 2: Run render/interlock tests and capture RED**

Run:

```bash
cargo test -p context-relay-core --test hermes_adapter_v1 yaml_patch_preserves_unowned_bytes_comments_order_and_scalar_style
cargo test -p context-relay-core --test hermes_adapter_v1 live_selected_profile_gateway_blocks_every_active_change
```

Expected: failures because owned-path replacement and gateway liveness are not implemented.

- [ ] **Step 3: Implement exact YAML owned-path rendering**

In `yaml.rs`, add:

```rust
pub(super) fn patch_owned_paths(
    parsed: &ParsedHermesYaml,
    replacements: &BTreeMap<Vec<String>, Option<serde_yaml_ng::Value>>,
) -> Result<Vec<u8>, ClientError>;
```

Algorithm:

1. Reject replacement paths outside the reviewed allowlist.
2. Sort replacement spans by descending byte offset and reject overlaps.
3. For an existing path, render only that value/subtree with the original key and indentation; preserve the source line-ending convention.
4. For a removed path, remove exactly its indexed key span.
5. For a new child, insert after the last existing sibling inside the indexed parent, using block style and parent indentation plus two spaces.
6. Preserve leading comments attached to unrelated siblings.
7. Reparse the result, rerun topology checks, and project reviewed semantics.
8. Compare projected before/after semantics. If equal, return the original bytes unchanged and let the caller emit no mutation.
9. Reject any result that changes an unowned semantic path.

Only `serde_yaml_ng::to_string` the isolated replacement value. Never call it on the complete source document.

`render_managed_markdown` uses:

```text
<!-- context-relay:start -->
<body, ending with one newline>
<!-- context-relay:end -->
```

It accepts zero or one well-formed marker pair, rejects any marker text in the desired body, preserves all bytes outside the pair, and keeps the source line-ending convention. Archive removes only the managed block. Memory files enforce the Hermes release character bound before planning.

- [ ] **Step 4: Implement active/passive classification and permission conflict previews**

`HarnessAdapter::classify`:

1. Validates the semantic diff.
2. Parses permission change targets using the exact grammar below; other
   Hermes targets retain their supplied valid class.
3. Uses a safe summary `lossy Hermes permission mapping: <stable reason>`.
4. Preserves exact Hermes-native permission changes as active updates.
5. Does not reject the whole diff merely because preview conflicts exist.

```text
hermes-permission|<profile>|exact|<native-permission-path>|-
hermes-permission|<profile>|lossy|<native-permission-path>|<stable-reason>
```

`<profile>` must equal the adapter profile, `<native-permission-path>` must be
one of the reviewed permission paths emitted by import, and `<stable-reason>`
must be one of the five stable reasons from Task 2. Any other permission target
is invalid. This grammar is necessary because `SemanticDiff` carries
classified targets and summaries, not component metadata.

`HarnessAdapter::render`:

- validates the desired state and bound scopes;
- rejects any unresolved lossy permission or redaction;
- calls `require_gateway_idle` when any active component exists;
- renders config, component-backed Markdown, and gateway-hook files without invoking Hermes;
- returns no CLI operations;
- sorts files by wire path and omits semantic no-ops.

Native memory is intentionally outside `DesiredState`, because the protocol
has no memory `ComponentKind`. It is rendered and planned only through
`plan_native_memory(HermesMemoryKind, body_markdown)`.

`HarnessAdapter::plan_cli_ops` validates changes and returns `CliOperations(vec![])`; Hermes V1 performs no CLI write operations.

- [ ] **Step 5: Implement profile-scoped gateway liveness**

Parse `gateway.pid` and `gateway_state.json` as bounded JSON objects with `deny_unknown_fields` structs for the reviewed identity fields. Never include record contents in errors.

Create a pure evaluator:

```rust
pub(super) struct GatewayObservation {
    pub record_present: bool,
    pub record_valid: bool,
    pub lock_held: Option<bool>,
    pub process_exists: Option<bool>,
    pub start_time_matches: Option<bool>,
    pub command_is_gateway: Option<bool>,
    pub profile_matches: Option<bool>,
}

pub(super) fn evaluate_gateway(
    observation: &GatewayObservation,
) -> GatewayStatus;
```

Evaluation table:

```text
no records and lock not held                         -> Idle
valid record and verified dead process               -> Stale
held lock + live process + start/command/profile match -> Live
live process + start/command/profile match           -> Live
any malformed record                                 -> Unverifiable
live process with any identity mismatch or unknown   -> Unverifiable
held lock with missing/unknown identity               -> Unverifiable
PID reuse/start-time mismatch                        -> Unverifiable
foreign profile command                              -> Unverifiable
```

On Unix, open an existing `gateway.lock` with read and write access but without
create or truncate flags, then use a non-blocking advisory lock probe; use
`kill(pid, 0)` only as an existence check and
`ps -p <pid> -o lstart= -o command=` through the bounded non-shell runner for
start/argv identity. Never send a terminating signal.

On Windows, use `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE)`, `GetExitCodeProcess`, `GetProcessTimes`, and `QueryFullProcessImageNameW`; probe `gateway.lock` with `LockFileEx` in fail-immediately mode and release an acquired probe lock. Close every handle. If command/profile identity cannot be established from the reviewed record plus OS start time, return `Unverifiable`.

Require the command identity to contain Hermes plus `gateway run` and either the exact canonical selected `HERMES_HOME` or exact selected `--profile` name. Do not infer profile identity from PID alone.

- [ ] **Step 6: Implement native mutation planners**

For config, Markdown, memory, and hook files:

1. Require full capability.
2. Revalidate profile binding.
3. Require gateway idle for active targets.
4. Snapshot the exact path with `OsNativeFileSystem`.
5. Require an existing regular file for `config.yaml`, `SOUL.md`, memory files, and existing hook files. A new reviewed hook file may start from an approved absence snapshot.
6. Render against snapshot bytes.
7. Return `Ok(None)` for byte-identical output.
8. Preserve metadata in `NativeState::regular_file`.
9. Build the exact mutation:

```rust
ApprovedMutation {
    target: wire_path(&path),
    kind: MutationKind::Payload,
    content: intended
        .encode_v1()
        .map_err(|_| invalid("Hermes native state is not representable"))?,
    expected: RestorableStateFingerprint(Sha256Digest(*snapshot.fingerprint())),
    intended: RestorableStateFingerprint(Sha256Digest(intended.fingerprint())),
}
```

Never mutate `.env`, auth, provider, channel, session, database, gateway record, log, or profile-management paths.

- [ ] **Step 7: Reach GREEN and commit the rendering/interlock unit**

Run:

```bash
cargo test -p context-relay-core --test hermes_adapter_v1 yaml_patch_preserves_unowned_bytes_comments_order_and_scalar_style
cargo test -p context-relay-core --test hermes_adapter_v1 semantic_noop_produces_no_rendered_file_or_mutation
cargo test -p context-relay-core --test hermes_adapter_v1 managed_markdown_and_memory_preserve_unmanaged_bytes
cargo test -p context-relay-core --test hermes_adapter_v1 unsupported_permission_mappings_are_visible_in_probe_and_preview
cargo test -p context-relay-core --test hermes_adapter_v1 live_selected_profile_gateway_blocks_every_active_change
cargo test -p context-relay-core --test hermes_adapter_v1 stale_dead_gateway_is_nonblocking_and_reported
cargo test -p context-relay-core --test hermes_adapter_v1 concurrent_native_edit_invalidates_planned_config_and_memory
```

Expected: all focused tests pass.

Commit:

```bash
git add crates/core/src/hermes.rs crates/core/src/hermes/yaml.rs crates/core/src/hermes/render.rs crates/core/src/hermes/gateway.rs crates/core/tests/hermes_adapter_v1.rs
git commit -m "feat: plan safe Hermes changes"
```

---

### Task 4: Validate in an Isolated Home, Close the Native Boundary, and Document Capabilities

**Files:**
- Create: `adapters/hermes/capabilities.md`
- Modify: `crates/core/src/hermes.rs`
- Modify: `crates/core/src/hermes/gateway.rs`
- Modify: `crates/core/src/hermes/import.rs`
- Modify: `crates/core/src/hermes/render.rs`
- Modify: `crates/core/tests/hermes_adapter_v1.rs`
- Modify: `crates/core/tests/claude_code_adapter_v1.rs` only if a platform-neutral fixture correction is required
- Modify: `crates/core/tests/codex_adapter_v1.rs` only if a platform-neutral fixture correction is required

**Validation interfaces:**

```rust
#[derive(Clone, Debug, Eq, PartialEq)]
struct HermesValidationRequest {
    executable: PathBuf,
    argv: Vec<String>,
    working_directory: PathBuf,
    staged_hermes_home: PathBuf,
    executable_hash: Sha256Digest,
}

impl HermesAdapter {
    fn validate_effective_with(
        &self,
        receipt: &ApplyReceipt,
        execute: impl FnMut(&HermesValidationRequest) -> Result<Vec<u8>, ClientError>,
    ) -> Result<ValidationReport, ClientError>;
}
```

- [ ] **Step 1: Add RED isolated-validation and native-boundary tests**

Add these tests:

| Test | Required assertions |
|---|---|
| `effective_validation_uses_only_isolated_nonsecret_home` | Request argv is exactly `["config", "check"]`; `HERMES_HOME` is a unique staged directory; staged `config.yaml` contains reviewed non-secret projection; no `.env`, auth, plugin, hook, MCP executable, session, channel, gateway, provider, or canary file exists there. |
| `validation_never_starts_gateway_plugins_hooks_mcp_or_provider` | The captured request contains no `gateway`, `doctor`, `migrate`, `setup`, `plugin`, `hook`, `mcp`, chat, provider, configured command, or configured URL argument; all sentinel files remain absent. |
| `config_check_output_parser_accepts_both_frozen_release_contracts` | ANSI-stripped 0.18.2 and 0.18.1 outputs with `Configuration Status`, one `Config version:` line, `Required:`, and `Optional:` parse; missing credentials are findings, not structural failure. |
| `unexpected_oversized_stderr_or_nonzero_validation_fails_closed` | Unknown sections, duplicate required headers, invalid UTF-8, output over 65,536 bytes, non-empty stderr, timeout, and non-zero exit each fail validation. |
| `native_adapter_rechecks_gateway_profile_executable_and_digests` | `reprobe_live_state` rejects live/unverifiable gateway, changed profile binding, version/path/hash drift; `compare_approved_digests` rejects changed native bytes. |
| `native_adapter_rejects_staged_hash_and_receipt_changes` | Staged semantic/scanner hash mismatch, plan ID mismatch, and resulting fingerprint mismatch all fail. |
| `unknown_version_or_wrapper_never_runs_validation_command` | Import-only layouts return `HarnessUnsupported`; injected executor call count remains zero. |
| `validation_stage_is_removed_on_success_and_failure` | The unique stage directory is absent after successful parsing and after injected executor error. |
| `rollback_restores_all_hermes_targets_and_metadata` | Config, Markdown, memory, and hook native mutations restore original bytes and metadata after an injected later-step failure. |

- [ ] **Step 2: Run validation tests and capture RED**

Run:

```bash
cargo test -p context-relay-core --test hermes_adapter_v1 effective_validation_uses_only_isolated_nonsecret_home
cargo test -p context-relay-core --test hermes_adapter_v1 native_adapter_rechecks_gateway_profile_executable_and_digests
```

Expected: failures because isolated CLI validation and the complete `NativeAdapter` implementation do not exist.

- [ ] **Step 3: Implement isolated effective validation**

Internal validation:

1. Validate the receipt and require full capability.
2. Revalidate exact profile binding and executable digest.
3. Re-read the selected profile's effective files through the same safe import/render parsers.
4. Validate YAML topology, Markdown markers, manifests, allowlisted component
   projection, and safe source digests. `HarnessAdapter::validate_effective`
   cannot compare desired components because its protocol input contains only
   `ApplyReceipt`; intended native fingerprints are checked later by
   `NativeAdapter::validate_effective`, which also receives the transaction
   plan.
5. Do not infer active/passive state from `ApplyReceipt`; that DTO has no
   approval class. The active gateway recheck belongs to
   `NativeAdapter::reprobe_live_state`, where the full `NativeTransactionPlan`
   is available.

Create a unique stage below `std::env::temp_dir()` using 16 bytes from the OS random source. Create it with owner-only permissions where the platform exposes them. Store the exact created path in an RAII guard whose `Drop` removes only that validated child path.

Populate only:

```text
<stage>/config.yaml
<stage>/memories/
```

The staged `config.yaml` is a deterministic block-style YAML document built from the reviewed, already-redacted projection. Omit all credential containers and all extension code. Do not copy the real profile's `.env`, `auth.json`, `SOUL.md`, skills, plugins, hooks, MCP executable files, sessions, channels, gateway state, or logs.

Run exactly:

```text
hermes config check
```

Environment:

```text
HERMES_HOME=<exact staged path>
HOME=<empty adapter-owned directory below stage>
NO_COLOR=1
TERM=dumb
PATH=<minimal platform system path required to start the attested executable>
```

Remove inherited variables whose names end in `_KEY`, `_TOKEN`, `_SECRET`, `_PASSWORD`, `_COOKIE`, `_CREDENTIAL`, or begin with `HERMES_`, then set only the four variables above. Use null stdin, piped stdout/stderr, the fixed timeout/output caps, and executable hash recheck immediately before spawn.

Parse output after ANSI removal. Require exactly one `Configuration Status`, one `Config version:`, one `Required:`, and one `Optional:` header in that order. Allow only indented credential-name status rows and the version-pinned `new config option(s) available` notice. Missing required or optional credentials become safe findings such as `isolated_credential_missing`; they do not invalidate structural config. Any other non-empty line fails closed. A non-zero exit, stderr, timeout, invalid UTF-8, or oversized stream is invalid.

- [ ] **Step 4: Implement the complete native transaction boundary**

`impl NativeAdapter for HermesAdapter` must:

```rust
fn reprobe_live_state(
    &mut self,
    plan: &NativeTransactionPlan,
) -> Result<(), BoundaryError>;

fn compare_approved_digests(
    &mut self,
    plan: &NativeTransactionPlan,
) -> Result<(), BoundaryError>;

fn validate_staged_output(
    &mut self,
    plan: &NativeTransactionPlan,
    run: &RestrictedRun,
) -> Result<FrozenOutput, BoundaryError>;

fn validate_effective(
    &mut self,
    plan: &NativeTransactionPlan,
    receipt: &ApplyReceipt,
) -> Result<(), BoundaryError>;
```

`reprobe_live_state` requires:

- `plan.setup.harness == HarnessId::Hermes`;
- exact adapter version, executable wire path, and executable hash;
- exact stored profile binding and canonical selected root;
- when `plan.setup.approval_class == ApprovalClass::Active`, no
  live/unverifiable gateway;
- no profile root or project root drift.

`compare_approved_digests` decodes every expected target and compares the exact current digest or approved absence. `validate_staged_output` requires both the expected semantic hash and scanner hash. Native effective validation requires the receipt's plan ID and resulting digests to equal every intended mutation fingerprint in order.

Convert every boundary error to a stable non-secret message. Never include paths below credential/operational roots or file content.

- [ ] **Step 5: Write the Hermes capability matrix**

Create `adapters/hermes/capabilities.md` with this exact table:

| Surface | Import | Apply | Gateway rule | Secret treatment |
|---|---:|---:|---|---|
| `SOUL.md` | Yes | Managed fence | Passive; existing sessions remain frozen | Bounded text secret scan |
| `.hermes.md` / `HERMES.md` | Active nearest file | Managed fence | Passive; existing sessions remain frozen | Bounded text secret scan |
| `memories/MEMORY.md` | Typed agent memory | Managed fence | Passive; existing sessions remain frozen | Bounded text secret scan |
| `memories/USER.md` | Typed user memory | Managed fence | Passive; existing sessions remain frozen | Bounded text secret scan |
| `config.yaml` reviewed paths | Yes | Exact owned paths | Block while live or unverifiable | Recursive structural redaction |
| Skills | `SKILL.md` only | Existing managed file only | Passive | Bounded text secret scan |
| Plugin state | Manifest and enabled/disabled state | State only | Block while live or unverifiable | Never import code/env values |
| Shell hooks | Declaration | Exact owned path | Block while live or unverifiable | Reject secret-bearing declarations |
| Gateway hooks | Manifest and scanned handler | Reviewed files only | Block while live or unverifiable | Handler scan; never execute |
| MCP | Safe declaration and filters | Exact owned paths | Block while live or unverifiable | Values excluded; placeholder names only |
| Permissions | Exact native declaration | Exact Hermes mapping only | Block while live or unverifiable | Lossy mappings conflict |
| `.env`, auth, providers, channels, sessions, databases, logs, gateway records | No | No | Read gateway records only for interlock | Always excluded |

Below the table, document supported versions, explicit profile binding, validation command/environment, stable lossy mapping reasons, and the import-only rules for wrappers/unknown versions/unpatchable YAML.

- [ ] **Step 6: Run focused and regression verification**

Run:

```bash
cargo test -p context-relay-core --test hermes_adapter_v1
cargo test -p context-relay-core hermes::tests
cargo test -p context-relay-core --test claude_code_adapter_v1
cargo test -p context-relay-core --test codex_adapter_v1
```

Expected: all Hermes, Claude Code, and Codex adapter tests pass.

- [ ] **Step 7: Run repository verification**

Run:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
pnpm test --run
git diff --check
```

Expected: formatting and Clippy are clean; all Rust workspace and frontend tests pass; no whitespace errors are reported. If a platform-only test cannot run on the current host, record the exact unavailable runner and keep its compile-time `cfg` coverage green.

- [ ] **Step 8: Perform final security and correctness review**

Review the complete diff against every acceptance criterion in the approved design. Run:

```bash
rg -n "\\.env|auth\\.json|api_key|authorization|cookie|client_key|gateway_state|sessions|channels|state\\.db" crates/core/src/hermes.rs crates/core/src/hermes adapters/hermes
rg -n "Command::new|\\.spawn\\(|\\.status\\(|\\.output\\(" crates/core/src/hermes.rs crates/core/src/hermes
rg -n "serde_yaml_ng::to_string" crates/core/src/hermes.rs crates/core/src/hermes
git status --short
```

Expected:

- sensitive path/key matches occur only in denylist logic, safe documentation, or tests;
- process execution occurs only in version discovery, bounded gateway identity inspection, and isolated `config check`;
- full-document YAML serialization does not exist;
- only Task 12 files and this plan are changed.

Request a code review focused on profile isolation, secret flow, YAML byte preservation, gateway PID reuse, and native transaction freshness. Resolve every correctness or security finding, rerun Step 7, and retain review evidence in the task handoff.

- [ ] **Step 9: Commit the completed adapter**

Commit:

```bash
git add Cargo.toml Cargo.lock crates/core/Cargo.toml crates/core/src/lib.rs crates/core/src/hermes.rs crates/core/src/hermes crates/core/tests/hermes_adapter_v1.rs crates/core/tests/fixtures/hermes-0.18.2.json crates/core/tests/fixtures/hermes-0.18.1.json adapters/hermes/capabilities.md docs/superpowers/specs/2026-07-29-hermes-adapter-v1-design.md docs/superpowers/plans/2026-07-29-hermes-adapter-v1.md
git commit -m "feat: add Hermes adapter"
```

Expected: the commit contains the complete Task 12 adapter, capability matrix, fixtures, tests, design, and implementation plan.
