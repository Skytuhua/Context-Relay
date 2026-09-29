# Codex Adapter V1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a production-safe Context Relay adapter for Codex CLI 0.144.1 and 0.144.0 that imports reviewed native state, preserves unmanaged TOML and Markdown, plans only approved mutations, and validates with bounded machine-readable CLI commands.

**Architecture:** Follow the public shape and native-transaction boundary established by `crates/core/src/claude_code.rs`, but keep Codex behavior in a dedicated `crates/core/src/codex.rs` module. The adapter enumerates only allowlisted configuration surfaces, records instruction precedence explicitly, treats native policy/auth/session/approval state as read-only, uses `toml_edit::DocumentMut` for mixed `config.toml` updates, and uses Codex's official `--json` plugin/MCP inspection commands without starting configured MCP servers.

**Tech Stack:** Rust 2024, `context-relay-protocol`, `context-relay-native-runner`, `serde_json`, `sha2`, `toml_edit`, native filesystem transactions, golden JSON fixtures.

## Global Constraints

- Discover native Windows and macOS Codex installations and respect `CODEX_HOME`; the default is `$HOME/.codex`, and an explicit `CODEX_HOME` must already exist.
- Support only Codex CLI `0.144.1` and `0.144.0` for apply; unknown versions, wrapper scripts, and unknown executable formats are import-only.
- `$HOME/.agents/skills` is a distinct user-skill root and must never be derived from `CODEX_HOME`; repository skills come from `.agents/skills` along the repository-root-to-working-directory chain.
- Global instructions use `$CODEX_HOME/AGENTS.override.md` before `$CODEX_HOME/AGENTS.md`; project instructions use `AGENTS.override.md`, then `AGENTS.md`, then configured fallback names at each directory, and nearer directories have higher precedence.
- Project `.codex/config.toml`, project hooks, and project rules are active only for trusted repositories; repository `AGENTS.md` and `.agents/skills` discovery remains separate from that trust gate.
- Import only allowlisted configuration, instruction, rule, skill, plugin, MCP, hook, and declarative-permission surfaces; never import secrets from auth, sessions, history, logs, SQLite state, OAuth stores, or native approval records.
- System `requirements.toml`, repository trust declarations, authentication, sessions, and native approvals are read-only. Their presence may produce policy conflicts, but no render or mutation path may target them.
- Preserve TOML comments, ordering, formatting, and unknown fields outside the exact managed keys wherever `toml_edit` permits.
- Plugin inspection uses `codex plugin list --json`; MCP inspection uses `codex mcp list --json` and `codex mcp get <name> --json`.
- Plugin writes use only `codex plugin add <plugin@marketplace> --json` and `codex plugin remove <plugin@marketplace> --json`.
- Global MCP writes use only `codex mcp add <name> ...` and `codex mcp remove <name>`; project-scoped MCP is import-only in V1 because Codex 0.144.x exposes no project-scope write flag.
- Effective-state validation may run `plugin list --json`, `mcp list --json`, and `mcp get <name> --json`; it must never run `codex doctor`, `codex mcp-server`, an MCP configured command, or any MCP login flow.
- Every external command rechecks the executable SHA-256, has a 30,000 ms timeout, caps stdout and stderr at 65,536 bytes each, rejects non-empty stderr, and rejects unreviewed JSON shapes.
- Native mutation planning must snapshot the exact target, preserve file metadata, bind the expected and intended fingerprints, reject symlink/path escapes through the native runner, and remain rollback-safe under concurrent edits.
- Never write generated sidecars manually; never use `pull_request_target`; never force-push.

---

### Task 1: Codex Adapter V1

**Files:**
- Create: `crates/core/src/codex.rs`
- Create: `crates/core/tests/codex_adapter_v1.rs`
- Create: `crates/core/tests/fixtures/codex-0.144.1.json`
- Create: `crates/core/tests/fixtures/codex-0.144.0.json`
- Modify: `Cargo.toml`
- Modify: `crates/core/Cargo.toml`
- Modify: `crates/core/src/lib.rs`
- Modify: `crates/core/tests/claude_code_adapter_v1.rs`

**Interfaces:**
- Consumes: `context_relay_protocol::HarnessAdapter`, `context_relay_core::native_transaction`, `context_relay_native_runner::{NativeState, OsNativeFileSystem}`, and the adapter DTOs already used by `ClaudeCodeAdapter`.
- Produces:
  - `pub struct CodexLayout`
  - `pub enum CodexExecutableKind { Native, Wrapper, Unknown }`
  - `pub struct CodexAdapter`
  - `CodexAdapter::discover(project_root, working_directory, project_id, origin_device, observed_hlc) -> Result<Self, ClientError>`
  - `CodexAdapter::from_layout(layout, project_id, origin_device, observed_hlc) -> Result<Self, ClientError>`
  - `CodexAdapter::project_root_wire() -> WireNativeValue`
  - `CodexAdapter::project_config_path() -> PathBuf`
  - `CodexAdapter::plan_native_config(desired, scope) -> Result<ApprovedMutation, ClientError>`
  - `CodexAdapter::plan_native_markdown(component) -> Result<ApprovedMutation, ClientError>`
  - `CodexAdapter::plan_native_hooks_json(component) -> Result<ApprovedMutation, ClientError>`
  - `impl HarnessAdapter for CodexAdapter`
  - `impl NativeAdapter for CodexAdapter`

- [ ] **Step 1: Make the existing Claude fixture use a canonical temporary root**

Change only the root construction in `crates/core/tests/claude_code_adapter_v1.rs` so macOS's `/var` to `/private/var` alias does not look like a symlink ancestor to the native runner:

```rust
let root = fs::canonicalize(std::env::temp_dir())
    .unwrap()
    .join(format!(
        "context-relay-claude-code-{}-{}",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    ));
```

- [ ] **Step 2: Verify the environmental regression test is green before Codex production code**

Run:

```bash
cargo test -p context-relay-core --test claude_code_adapter_v1
```

Expected: all existing Claude adapter integration tests pass with the default environment.

- [ ] **Step 3: Add golden Codex 0.144.x fixtures**

Both fixture files must use the same schema and differ only in `"version"`. Include:

```json
{
  "version": "0.144.1",
  "executableKind": "native",
  "pluginListJson": {
    "installed": [
      {
        "pluginId": "formatter@team",
        "name": "formatter",
        "marketplaceName": "team",
        "version": "1.2.3",
        "installed": true,
        "enabled": true,
        "source": {
          "source": "git",
          "url": "https://example.com/team/plugins.git",
          "ref": "v1.2.3"
        },
        "installPolicy": "AVAILABLE",
        "authPolicy": "ON_USE"
      }
    ],
    "available": []
  },
  "mcpListJson": [
    {
      "name": "docs",
      "enabled": true,
      "disabled_reason": null,
      "transport": {
        "type": "streamable_http",
        "url": "https://example.com/mcp",
        "bearer_token_env_var": "DOCS_TOKEN",
        "http_headers": null,
        "env_http_headers": null
      },
      "startup_timeout_sec": null,
      "tool_timeout_sec": null,
      "auth_status": "bearer_token"
    }
  ],
  "mcpGetJson": {
    "name": "docs",
    "enabled": true,
    "disabled_reason": null,
    "transport": {
      "type": "streamable_http",
      "url": "https://example.com/mcp",
      "bearer_token_env_var": "DOCS_TOKEN",
      "http_headers": null,
      "env_http_headers": null
    },
    "enabled_tools": null,
    "disabled_tools": null,
    "startup_timeout_sec": null,
    "tool_timeout_sec": null
  },
  "codexHome": {
    "AGENTS.md": "# Global instructions\nUse the stable toolchain.\n",
    "AGENTS.override.md": "# Global override\nPrefer the smallest safe change.\n",
    "config.toml": "# user heading\nunknown_user_key = \"preserve-me\"\napproval_policy = \"on-request\"\nsandbox_mode = \"workspace-write\"\n\n[projects.\"$PROJECT\"]\ntrust_level = \"trusted\"\n\n[plugins.\"formatter@team\"]\nenabled = true\n\n[mcp_servers.docs]\nurl = \"https://example.com/mcp\"\nbearer_token_env_var = \"DOCS_TOKEN\"\n\n[hooks]\n# inline hook comment\n[[hooks.PostToolUse]]\nmatcher = \"^Write$\"\n\n[[hooks.PostToolUse.hooks]]\ntype = \"command\"\ncommand = \"check-write\"\n",
    "hooks.json": "{\"description\":\"global hooks\",\"unknown\":{\"keep\":true},\"hooks\":{\"PreToolUse\":[]}}\n",
    "rules/default.rules": "prefix_rule(pattern=[\"cargo\", \"test\"], decision=\"allow\")\n",
    "auth.json": "{\"OPENAI_API_KEY\":\"must-not-import\"}\n",
    "sessions/2026/session.jsonl": "{\"token\":\"must-not-import\"}\n",
    "history.jsonl": "{\"text\":\"must-not-import\"}\n",
    "state_5.sqlite": "must-not-import",
    "native-approvals.json": "{\"approval\":\"must-not-import\"}\n"
  },
  "userSkills": {
    "review/SKILL.md": "---\nname: review\ndescription: Review a change.\n---\nReview the diff.\n"
  },
  "project": {
    "AGENTS.md": "# Repository instructions\nUse Rust 2024.\n",
    "service/AGENTS.md": "# Service instructions\nKeep protocol compatibility.\n",
    "service/AGENTS.override.md": "# Service override\nPreserve wire contracts.\n",
    ".agents/skills/release/SKILL.md": "---\nname: release\ndescription: Prepare a release.\n---\nVerify artifacts.\n",
    "service/.agents/skills/audit/SKILL.md": "---\nname: audit\ndescription: Audit this service.\n---\nCheck invariants.\n",
    ".codex/config.toml": "# project heading\nunknown_project_key = \"preserve-me\"\napproval_policy = \"untrusted\"\n",
    "service/.codex/config.toml": "# nested heading\ndefault_permissions = \":workspace\"\n",
    ".codex/hooks.json": "{\"description\":\"project hooks\",\"unknown\":{\"keep\":true},\"hooks\":{\"Stop\":[]}}\n",
    ".codex/rules/project.rules": "prefix_rule(pattern=[\"git\", \"status\"], decision=\"allow\")\n"
  },
  "requirements": "allowed_approval_policies = [\"untrusted\", \"on-request\"]\n"
}
```

Replace `"version"` with `"0.144.0"` in the second fixture. The fixture harness substitutes the canonical project root for `$PROJECT` before writing `config.toml`.

- [ ] **Step 4: Write failing integration tests for discovery classification, trust, precedence, and secret exclusion**

Create `crates/core/tests/codex_adapter_v1.rs` with a fixture harness patterned after `claude_code_adapter_v1.rs`. Canonicalize `std::env::temp_dir()`, materialize a native-looking fixture executable, keep `codex_home` and `home/.agents/skills` separate, set the working directory to `project/service`, and construct `CodexAdapter::from_layout`.

Add these tests before the production module exists:

| Test | Required assertions |
|---|---|
| `supported_release_fixtures_import_reviewed_surfaces_without_secrets` | Both fixtures probe as `Full`; imports contain every `ComponentKind`; imports contain the reviewed plugin and MCP server; serialized imports contain none of the forbidden secret/state markers listed below. |
| `codex_home_and_user_skill_roots_are_distinct` | The `review` user skill comes from the separately materialized `$HOME/.agents/skills`; no `$CODEX_HOME/skills` path is synthesized; the probe reports both roots as distinct entries. |
| `instructions_follow_global_root_to_cwd_precedence` | The active global file is `AGENTS.override.md`; repository root `AGENTS.md` precedes service `AGENTS.override.md`; precedence metadata is exactly `0`, `1`, `2`; shadowed `AGENTS.md` files are absent. |
| `shadowed_instructions_and_managed_requirements_are_reported` | Probe conflicts are exactly `global_instructions_shadowed`, `managed_requirements_active`, and `project_instructions_shadowed`, in sorted order. |
| `untrusted_projects_skip_project_config_hooks_and_rules` | After changing trust to `untrusted`, the probe adds `project_untrusted`; project config permissions/hooks/rules are absent; repository instructions and repository skills remain present. |
| `unknown_versions_and_wrapper_executables_are_import_only` | Version `9.9.9` and `CodexExecutableKind::Wrapper` each probe as `ImportOnly`; offline import is non-empty; render and native mutation planning return `HarnessUnsupported`. |

The supported-fixture assertion must require all seven `ComponentKind` values, verify only `AGENTS.override.md` is active at each shadowed instruction layer, verify root instructions precede nested instructions through numeric `precedenceIndex` metadata, and assert serialized imports contain none of `must-not-import`, `OPENAI_API_KEY`, `auth.json`, `sessions`, `history.jsonl`, `state_5.sqlite`, or `native-approvals`.

- [ ] **Step 5: Run the Codex integration test and capture the expected RED state**

Run:

```bash
cargo test -p context-relay-core --test codex_adapter_v1
```

Expected: compilation fails because `context_relay_core::codex`, `CodexAdapter`, `CodexLayout`, and `CodexExecutableKind` do not exist.

- [ ] **Step 6: Add dependencies and the adapter module skeleton**

Add this workspace dependency:

```toml
toml_edit = "0.25.13"
```

Add this core dependency:

```toml
toml_edit.workspace = true
```

Export the module in `crates/core/src/lib.rs`:

```rust
pub mod codex;
```

Start `crates/core/src/codex.rs` with:

```rust
const SUPPORTED_VERSIONS: [&str; 2] = ["0.144.1", "0.144.0"];
const CLI_TIMEOUT_MS: u32 = 30_000;
const CLI_OUTPUT_LIMIT: u64 = 64 * 1024;
const MANAGED_START: &str = "<!-- context-relay:start -->";
const MANAGED_END: &str = "<!-- context-relay:end -->";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodexExecutableKind {
    Native,
    Wrapper,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct CodexLayout {
    pub executable: PathBuf,
    pub executable_kind: CodexExecutableKind,
    pub version: String,
    pub installation_method: InstallationMethod,
    pub codex_home: PathBuf,
    pub user_skills_dir: PathBuf,
    pub project_root: PathBuf,
    pub working_directory: PathBuf,
    pub requirements_paths: Vec<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct CodexAdapter {
    layout: CodexLayout,
    project_id: ProjectId,
    origin_device: DeviceId,
    observed_hlc: HybridLogicalClock,
    executable_hash: Sha256Digest,
}
```

`from_layout` validates the version string, requires the executable, `codex_home`, project root, and working directory to be safely representable, requires the working directory to be at or below the project root, hashes the executable, and never opens auth/session/approval state.

- [ ] **Step 7: Implement allowlisted discovery, trust, instructions, rules, skills, hooks, permissions, MCP, and plugins**

Implement `HarnessAdapter::probe`, `discover_scopes`, and `import` with these exact behaviors:

```rust
fn capability(&self) -> CapabilityLevel {
    if SUPPORTED_VERSIONS.contains(&self.layout.version.as_str())
        && self.layout.executable_kind == CodexExecutableKind::Native
    {
        CapabilityLevel::Full
    } else {
        CapabilityLevel::ImportOnly
    }
}
```

The probe's `config_roots` are, in order: `codex_home`, `user_skills_dir`, and `project_root`. Policy conflicts use stable strings:

```text
managed_requirements_active
global_instructions_shadowed
project_instructions_shadowed
project_untrusted
```

Add each string only when its condition is present; return them sorted and deduplicated.

Import allowlists:

```text
Global instructions: $CODEX_HOME/AGENTS.override.md or AGENTS.md
Global config:       $CODEX_HOME/config.toml
Global hooks:        $CODEX_HOME/hooks.json and inline config [hooks]
Global rules:        $CODEX_HOME/rules/**/*.rules
User skills:         $HOME/.agents/skills/*/SKILL.md
Project instructions: one selected instruction file per directory from repo root through working directory
Repo skills:         .agents/skills/*/SKILL.md at every directory from repo root through working directory
Trusted config:      .codex/config.toml at every directory from repo root through working directory
Trusted hooks:       .codex/hooks.json and inline config [hooks] at those layers
Trusted rules:       .codex/rules/**/*.rules at those layers
Plugins:             reviewed [plugins."<plugin@marketplace>"] config tables
MCP:                 reviewed `[mcp_servers]` tables, redacted before component creation
Permissions:         approval_policy, approvals_reviewer, sandbox_mode, default_permissions, and [permissions]
```

Instruction components include:

```rust
metadata: vec![
    ("structuralLocation".to_owned(), relative_or_global_location),
    ("precedenceIndex".to_owned(), precedence_index.to_string()),
]
```

The global instruction has precedence index `0`; project files increment from repo root toward the working directory. When both `AGENTS.override.md` and `AGENTS.md` are non-empty at one layer, import only the override and report the matching shadow conflict. Respect `project_doc_fallback_filenames` only when neither standard filename is non-empty. Reject fallback names containing separators, `.` or `..`, or non-UTF-8/control characters.

Read trust only from the user `config.toml` entry matching the canonical project root. Any value other than `trust_level = "trusted"` is untrusted. Untrusted projects still import repository instructions and repository skills, but skip every project `.codex` config, hook, and rule.

Parse only allowlisted TOML keys into components. Redact keys containing `token`, `secret`, `password`, `authorization`, `cookie`, or `credential` recursively. A redacted MCP component is importable but not applicable.

Plugin and MCP effective-state validation helpers accept only the reviewed 0.144.x JSON shapes represented in the fixtures. Import itself remains offline and reads the allowlisted `[plugins]` and `[mcp_servers]` config tables; it does not invoke the CLI. Reject unknown top-level fields, duplicate names/IDs, control characters, more than 256 entries, and payloads larger than the command output cap.

- [ ] **Step 8: Run focused import tests to reach GREEN**

Run:

```bash
cargo test -p context-relay-core --test codex_adapter_v1 supported_release_fixtures_import_reviewed_surfaces_without_secrets
cargo test -p context-relay-core --test codex_adapter_v1 instructions_follow_global_root_to_cwd_precedence
cargo test -p context-relay-core --test codex_adapter_v1 untrusted_projects_skip_project_config_hooks_and_rules
cargo test -p context-relay-core --test codex_adapter_v1 unknown_versions_and_wrapper_executables_are_import_only
```

Expected: each focused test passes.

- [ ] **Step 9: Write failing mutation-preservation and official-CLI tests**

Add these exact test cases:

| Test | Required assertions |
|---|---|
| `mixed_toml_preserves_comments_unknown_fields_trust_and_rolls_back` | Apply changes only the managed permission/hook keys; `# user heading`, `unknown_user_key`, `[projects]`, `[plugins]`, and `[mcp_servers]` survive; rollback restores byte-for-byte original content. |
| `managed_markdown_preserves_unmanaged_bytes_and_rejects_malformed_markers` | Apply preserves unmanaged prefix/suffix; rollback restores bytes; missing, reversed, and duplicate marker pairs are rejected. |
| `hooks_json_preserves_unknown_fields_and_rolls_back` | Apply changes only `"hooks"`; `"description"` and `"unknown"` survive; rollback restores bytes. |
| `plugin_and_global_mcp_changes_use_only_official_cli_argv` | Rendered argument arrays equal the four arrays below and contain no shell command strings. |
| `project_mcp_changes_are_import_only` | A project-scoped MCP desired component returns `HarnessUnsupported` from render and mutation planning. |
| `redacted_mcp_configuration_cannot_be_applied` | Any `<redacted>` marker in a transport, header, URL, command, argument, or environment value makes render fail closed. |
| `concurrent_native_edit_invalidates_the_planned_config_mutation` | Editing `config.toml` after planning makes native before-image creation reject the stale expected fingerprint. |

The exact expected CLI argument arrays are:

```rust
vec![
    vec!["plugin", "add", "formatter@team", "--json"],
    vec!["plugin", "remove", "old-plugin@team", "--json"],
    vec![
        "mcp",
        "add",
        "docs",
        "--url",
        "https://example.com/mcp",
        "--bearer-token-env-var",
        "DOCS_TOKEN",
    ],
    vec!["mcp", "remove", "old-docs"],
]
```

For STDIO MCP components, render:

```text
mcp add <name> --env <KEY=VALUE>... -- <command> <arg>...
```

Sort environment keys before rendering. Reject empty commands, unsafe names, secret/redacted environment values, unsupported transport fields, project scope, and HTTP header forms that the official 0.144.x write CLI cannot reproduce.

- [ ] **Step 10: Run the mutation tests and capture the expected RED state**

Run:

```bash
cargo test -p context-relay-core --test codex_adapter_v1 mixed_toml_preserves_comments_unknown_fields_trust_and_rolls_back
cargo test -p context-relay-core --test codex_adapter_v1 plugin_and_global_mcp_changes_use_only_official_cli_argv
```

Expected: failures because config mutation and Codex CLI render planning are not implemented.

- [ ] **Step 11: Implement mixed-file mutation planning and CLI operation planning**

Use `toml_edit::DocumentMut` for `config.toml`. `plan_native_config` must:

1. Require `CapabilityLevel::Full`.
2. Validate the desired state and configured scope.
3. Reject project scope when the repository is untrusted.
4. Snapshot the existing regular file through `OsNativeFileSystem`.
5. Parse without normalizing the document.
6. Replace or remove only `approval_policy`, `approvals_reviewer`, `sandbox_mode`, `default_permissions`, `permissions`, and `hooks` represented by desired components for that scope.
7. Never change `[projects]`, `[mcp_servers]`, provider/auth keys, unknown fields, or comments outside replaced managed items.
8. Preserve native metadata in the intended `NativeState`.
9. Return `ApprovedMutation` with exact expected/intended fingerprints.

Use the same managed Markdown marker contract as the Claude adapter for instructions, rules, and skills. Mutate only an existing regular file; preserve unmanaged prefix/suffix bytes; reject missing/duplicate/reversed markers; and make archive remove only the managed block.

For `hooks.json`, parse an existing object, replace or remove only the top-level `"hooks"` member, preserve every other member, serialize deterministically, and use the same native snapshot/fingerprint contract.

`render` emits `RenderedFile` entries for managed config/Markdown/hooks changes and `CliOperation` entries only for global plugin/MCP changes. `plan_cli_ops` accepts the existing change-target grammar with Codex-specific prefixes:

```text
codex-plugin|global|<plugin@marketplace>
codex-mcp|global|<server-name>
```

Every plugin write includes `--json`; MCP write commands use the official arguments from Step 9. No command is represented as a shell string.

- [ ] **Step 12: Run focused mutation tests to reach GREEN**

Run:

```bash
cargo test -p context-relay-core --test codex_adapter_v1 mixed_toml_preserves_comments_unknown_fields_trust_and_rolls_back
cargo test -p context-relay-core --test codex_adapter_v1 managed_markdown_preserves_unmanaged_bytes_and_rejects_malformed_markers
cargo test -p context-relay-core --test codex_adapter_v1 hooks_json_preserves_unknown_fields_and_rolls_back
cargo test -p context-relay-core --test codex_adapter_v1 plugin_and_global_mcp_changes_use_only_official_cli_argv
cargo test -p context-relay-core --test codex_adapter_v1 project_mcp_changes_are_import_only
cargo test -p context-relay-core --test codex_adapter_v1 concurrent_native_edit_invalidates_the_planned_config_mutation
```

Expected: all focused mutation tests pass.

- [ ] **Step 13: Write failing command-validation, native-boundary, and platform-discovery tests**

Add unit tests in `crates/core/src/codex.rs` for private parsers and command selection:

| Test | Required assertions |
|---|---|
| `frozen_release_outputs_match_reviewed_json_contracts` | Plugin list, MCP list, and MCP get JSON from both frozen fixtures parse successfully and yield the expected `formatter@team` and `docs` identities. |
| `unreviewed_plugin_and_mcp_json_is_rejected` | Unknown fields, duplicate IDs/names, wrong nullability, invalid transport tags, control characters, and a 257th entry are rejected. |
| `validation_commands_never_start_mcp_servers` | The command vectors equal the three arrays below; no vector contains `mcp-server`, `login`, a configured transport command, or a configured URL as an executable. |
| `native_executable_magic_is_classified_without_executing_wrappers` | Mach-O, PE, and ELF prefixes are `Native`; shebang and wrapper extensions are `Wrapper`; arbitrary bytes are `Unknown`. |
| `platform_candidates_include_native_macos_and_windows_locations` | Pure candidate construction returns exactly the five paths listed in Step 15 when supplied synthetic macOS and Windows homes. |

Expected validation command arrays:

```rust
vec![
    vec!["plugin", "list", "--json"],
    vec!["mcp", "list", "--json"],
    vec!["mcp", "get", "docs", "--json"],
]
```

Add integration tests:

| Test | Required assertions |
|---|---|
| `native_adapter_rejects_executable_digest_and_receipt_changes` | Changing the executable bytes makes `reprobe_live_state` fail; changing the receipt plan ID or resulting digests makes native effective validation fail. |
| `validation_parsers_do_not_execute_fixture_mcp_commands` | Parsing fixture STDIO MCP JSON does not create the sentinel file named by that transport command. |

- [ ] **Step 14: Run validation tests and capture the expected RED state**

Run:

```bash
cargo test -p context-relay-core codex::tests
cargo test -p context-relay-core --test codex_adapter_v1 native_adapter_rejects_executable_digest_and_receipt_changes
```

Expected: failures because bounded command validation, executable classification, platform candidates, and the native boundary are incomplete.

- [ ] **Step 15: Implement bounded validation, native boundary checks, and native installation discovery**

Use a private command enum:

```rust
enum CodexCommand {
    PluginList,
    McpList,
    McpGet(String),
}
```

The command runner must mirror the Claude adapter's digest-before-spawn, null stdin, piped/capped stdout and stderr, timeout, kill/wait, UTF-8, and clean-stderr checks. Set the child working directory to `layout.working_directory`. Do not include a Doctor variant.

`HarnessAdapter::validate_effective`:

1. Validates the receipt and requires full capability.
2. Runs plugin list JSON, then MCP list JSON.
3. Collects enabled configured MCP names from the reviewed list.
4. Runs `mcp get <name> --json` for each name in sorted order.
5. Returns `configured_mcp_server_missing` if an imported configured name is absent.
6. Never invokes any command found inside an MCP transport object.

`NativeAdapter` mirrors the Claude adapter boundary with `HarnessId::Codex`, exact version/path/hash checks, exact expected native digests, staged-output hash checks, and receipt intended-fingerprint checks.

Discovery checks PATH plus platform candidates without executing non-native candidates:

```text
macOS bundled: /Applications/ChatGPT.app/Contents/Resources/codex
macOS user app: $HOME/Applications/ChatGPT.app/Contents/Resources/codex
macOS standalone: $HOME/.local/bin/codex
Windows standalone: %LOCALAPPDATA%\Programs\OpenAI\Codex\bin\codex.exe
Windows bundled: %LOCALAPPDATA%\Programs\ChatGPT\resources\codex.exe
```

Classify Mach-O, PE, and ELF magic as native; a shebang, `.cmd`, `.bat`, or `.ps1` as wrapper; everything else as unknown. Symlinks may resolve to a native binary, but wrapper contents never receive full capability. After choosing a candidate, hash it, run only `--version`, parse exactly `codex-cli <version>` or `codex <version>`, and construct the layout.

- [ ] **Step 16: Run the complete focused adapter verification**

Run:

```bash
cargo test -p context-relay-core --test codex_adapter_v1
cargo test -p context-relay-core codex::tests
cargo test -p context-relay-core --test claude_code_adapter_v1
```

Expected: all tests pass with pristine output.

- [ ] **Step 17: Run repository verification**

Run:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
pnpm test --run
```

Expected: formatting and Clippy are clean; all Rust workspace and frontend tests pass. If daemon tests require their default runtime directory, run them with the default environment; do not force `TMPDIR=/private/tmp`.

- [ ] **Step 18: Review the diff and commit**

Confirm:

```bash
git diff --check
git status --short
```

Expected: no whitespace errors; only the files listed by this task are changed.

Commit:

```bash
git add Cargo.toml Cargo.lock crates/core/Cargo.toml crates/core/src/lib.rs crates/core/src/codex.rs crates/core/tests/codex_adapter_v1.rs crates/core/tests/fixtures/codex-0.144.1.json crates/core/tests/fixtures/codex-0.144.0.json crates/core/tests/claude_code_adapter_v1.rs docs/superpowers/plans/2026-07-27-codex-adapter-v1.md
git commit -m "feat: add Codex adapter"
```
