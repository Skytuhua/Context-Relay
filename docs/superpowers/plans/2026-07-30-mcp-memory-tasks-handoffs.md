# Scoped MCP Memory, Tasks, and Handoffs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a scoped stdio MCP bridge that exposes all eleven Context Relay v1 memory, task, handoff, and status tools through the single-writer daemon and installs through all three harness adapters.

**Architecture:** `context-mcp` owns bounded newline-delimited MCP JSON-RPC and delegates one authenticated `McpCall` per tool invocation. `contextd` routes that call to `core::mcp`, where the daemon resolves the calling harness, canonical active project, access policy, typed tool operation, handoff projection, and adapter registration without accepting a project ID from MCP tool input.

**Tech Stack:** Rust 1.97, Tokio 1.53, Serde/serde_json, UUIDv7, SQLCipher-backed `Vault`, existing length-prefixed local IPC, MCP revisions `2025-11-25` and `2025-06-18`.

## Global Constraints

- The normative design is `docs/superpowers/specs/2026-07-30-mcp-memory-tasks-handoffs-design.md`; implementation choices must not weaken it.
- Primary MCP revision is exactly `2025-11-25`; compatibility revision is exactly `2025-06-18`.
- Expose exactly the eleven names in `context_relay_protocol::MCP_TOOL_NAMES`.
- MCP stdin/stdout is newline-delimited UTF-8 JSON-RPC; stdout contains no non-MCP bytes.
- Each MCP line and local IPC frame is bounded by `MAX_IPC_FRAME_BYTES` (8 MiB).
- Permit at most 64 in-flight tool calls and fail excess calls with retryable `busy`.
- Tool inputs never accept harness IDs, project IDs, working directories, native paths, setup plans, credentials, or secret values.
- The daemon resolves the longest canonical registered project root containing the bridge working directory; equal-specificity ambiguity fails closed.
- Default access is global plus active project; no policy grants arbitrary other-project access.
- Read-only and disabled policies block every MCP write, including inferred proposals.
- Expected revisions remain mandatory for memory update/archive and task update/completion.
- Task completion evidence is nonempty and bounded.
- Handoffs contain project identity, selected memories, recent decisions, open/blocked tasks, completion evidence, and instruction references; they contain no transcript source or secret-like text.
- Handoff creation is a read projection and does not persist a handoff row.
- Writes are never automatically retried after an unknown outcome; replay with the same `operationId` is idempotent.
- Ordinary memory/task calls never enter native adapter planning or approval code.
- Bridge installation is the global `context-relay` MCP declaration and is always an active setup change.
- Claude Code, Codex, and Hermes—the three harnesses—must resolve the same registered project state.
- Adapter validation inspects configuration without starting the bridge.
- No new third-party dependency is permitted unless the task cannot be completed with the pinned workspace dependencies.

---

### Task 1: Add the scoped MCP local-IPC envelope

**Files:**
- Modify: `crates/protocol/src/ipc.rs`
- Modify: `crates/protocol/src/mcp.rs`
- Modify: `crates/protocol/src/bin/export-bindings.rs`
- Create: `crates/protocol/tests/mcp_ipc_v1.rs`
- Modify: `crates/local-ipc/src/auth.rs`
- Modify: `crates/local-ipc/tests/ipc_v1.rs`
- Modify: `crates/contextd/src/lib.rs`
- Modify: `apps/desktop/src/bindings.ts` (generated)

**Interfaces:**
- Produces: `McpBinding { harness, working_directory }`.
- Produces: `McpCallParams { binding, name, arguments }`.
- Produces: `LocalRequest::McpCall(McpCallParams)`.
- Produces: `LocalResult::McpOutput { name, output }`.
- Changes authorization so `ClientRole::McpBridge` may use only `Health`, `Cancel`, and `McpCall`.

- [ ] **Step 1: Write failing protocol and authorization tests**

```rust
use context_relay_local_ipc::role_allows;
use context_relay_protocol::{
    ClientRole, HarnessId, LocalRequest, LocalResult, McpBinding, McpCallParams,
    NativePlatform, WireNativeValue, validate_mcp_fixture,
};
use serde_json::json;

fn binding() -> McpBinding {
    McpBinding {
        harness: HarnessId::Codex,
        working_directory: WireNativeValue {
            platform: NativePlatform::Macos,
            bytes: b"/workspace".to_vec(),
            display: Some("/workspace".into()),
        },
    }
}

#[test]
fn mcp_call_validates_the_frozen_tool_input_and_output() {
    let request = LocalRequest::McpCall(McpCallParams {
        binding: binding(),
        name: "context_relay_status".into(),
        arguments: json!({}),
    });
    assert!(request.validate().is_ok());
    assert!(role_allows(ClientRole::McpBridge, &request));

    let output = json!({
        "protocol":{"min":{"major":1,"minor":0},"max":{"major":1,"minor":0}},
        "vault":"unlocked",
        "resolvedProject":null,
        "sync":"offline",
        "access":{"mode":"default"}
    });
    assert!(validate_mcp_fixture("context_relay_status", false, &output).is_ok());
    assert!(LocalResult::McpOutput {
        name: "context_relay_status".into(),
        output
    }.validate().is_ok());
}

#[test]
fn mcp_bridge_cannot_bypass_the_scoped_envelope() {
    for request in raw_memory_task_and_status_fixtures() {
        assert!(!role_allows(ClientRole::McpBridge, &request));
    }
}
```

- [ ] **Step 2: Run the focused tests and confirm RED**

Run:

```bash
env CARGO_HOME=/private/tmp/context-relay-cargo RUSTUP_HOME=/private/tmp/context-relay-rustup /private/tmp/context-relay-cargo/bin/cargo test -p context-relay-protocol --test mcp_ipc_v1
```

Expected: compilation fails because `McpBinding`, `McpCallParams`, and the new enum variants do not exist.

- [ ] **Step 3: Implement the validated envelope**

Add the DTOs beside the other local IPC parameter types:

```rust
params!(McpBinding {
    harness: HarnessId,
    working_directory: WireNativeValue
});
params!(McpCallParams {
    binding: McpBinding,
    name: String,
    arguments: serde_json::Value
});
```

Add the variants:

```rust
McpCall(McpCallParams),

McpOutput {
    name: String,
    output: serde_json::Value,
},
```

Validate both boundaries:

```rust
Self::McpCall(params) => {
    params.binding.working_directory.validate()?;
    crate::validate_mcp_fixture(&params.name, true, &params.arguments)
}

Self::McpOutput { name, output } => {
    crate::validate_mcp_fixture(name, false, output)
}
```

Update `role_allows` so the MCP bridge's positive cases are:

```rust
LocalRequest::Health(_) | LocalRequest::Cancel(_) => true,
LocalRequest::McpCall(_) => matches!(role, Desktop | McpBridge),
```

All raw memory, search, candidate, task, handoff, access, and status cases remain Desktop-only.

Keep the intermediate workspace buildable by adding a temporary fail-closed
daemon route:

```rust
LocalRequest::McpCall(_) => RoutedRequest::Immediate(Err(unsupported_error(
    "Scoped MCP execution is not available in this build",
))),
```

Add `mcp_call` to contextd's exhaustive request fixture table and assert this
temporary route performs no vault work. Task 5 replaces this arm with the
queued `McpWorkspace` path.

Add `McpBinding` and `McpCallParams` to `export-bindings.rs`, regenerate
`apps/desktop/src/bindings.ts`, and confirm the generated `LocalRequest` and
`LocalResult` unions contain `mcp_call` and `mcp_output`.

- [ ] **Step 4: Update exhaustive wire fixtures and run GREEN**

Add `mcp_call` to the protocol/local-IPC method tables and assert unknown tool names, malformed native paths, invalid arguments, and mismatched output names fail.

Run:

```bash
env CARGO_HOME=/private/tmp/context-relay-cargo RUSTUP_HOME=/private/tmp/context-relay-rustup /private/tmp/context-relay-cargo/bin/cargo test -p context-relay-protocol --test mcp_ipc_v1
env CARGO_HOME=/private/tmp/context-relay-cargo RUSTUP_HOME=/private/tmp/context-relay-rustup /private/tmp/context-relay-cargo/bin/cargo test -p context-relay-local-ipc --test ipc_v1
env CARGO_HOME=/private/tmp/context-relay-cargo RUSTUP_HOME=/private/tmp/context-relay-rustup /private/tmp/context-relay-cargo/bin/cargo test -p context-relay-contextd --lib
env PATH=/Users/skytuhua/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin CARGO_HOME=/private/tmp/context-relay-cargo RUSTUP_HOME=/private/tmp/context-relay-rustup CONTEXT_RELAY_CARGO=/private/tmp/context-relay-cargo/bin/cargo /Users/skytuhua/.cache/codex-runtimes/codex-primary-runtime/dependencies/bin/fallback/pnpm check:bindings
```

Expected: all suites and binding parity pass; the MCP bridge authorization
count contains only health, cancel, and `mcp_call`.

- [ ] **Step 5: Commit**

```bash
git add crates/protocol/src/ipc.rs crates/protocol/src/mcp.rs crates/protocol/src/bin/export-bindings.rs crates/protocol/tests/mcp_ipc_v1.rs crates/local-ipc/src/auth.rs crates/local-ipc/tests/ipc_v1.rs crates/contextd/src/lib.rs apps/desktop/src/bindings.ts
git commit -m "feat: add scoped MCP IPC envelope"
```

### Task 2: Resolve harness access and the canonical active project

**Files:**
- Modify: `crates/core/src/lib.rs`
- Create: `crates/core/src/mcp/mod.rs`
- Create: `crates/core/src/mcp/binding.rs`
- Create: `crates/core/tests/mcp_binding_v1.rs`

**Interfaces:**
- Produces: `ResolvedMcpBinding { harness, active_project, policy }`.
- Produces: `McpAccess` methods `read_scope`, `write_scope`, `require_tasks`, and `allows_record_scope`.
- Consumes: daemon-owned `Vault::projects`, `Vault::path`, and `Vault::access_policy`.

- [ ] **Step 1: Write failing binding tests**

```rust
#[test]
fn longest_registered_root_resolves_without_accepting_a_project_id() {
    let root = tempdir().unwrap();
    let repo = root.path().join("repo");
    let package = repo.join("packages/app");
    std::fs::create_dir_all(&package).unwrap();

    let mut fixture = vault_fixture();
    fixture.register_project(project_a(), &repo);
    fixture.register_project(project_b(), &package);

    let resolved = resolve(&mut fixture.vault, HarnessId::Codex, &package).unwrap();
    assert_eq!(resolved.active_project, Some(project_b().project_id));
}

#[test]
fn selected_project_and_read_only_policies_fail_closed() {
    let mut fixture = two_project_fixture();
    fixture.set_policy(HarnessId::Codex, HarnessAccessPolicy::SelectedProject {
        project_id: fixture.project_a,
        read_only: false,
    });
    let error = resolve_at_project_b(&mut fixture).unwrap_err();
    assert_eq!(error.code, ErrorCode::ScopeDenied);

    fixture.set_policy(HarnessId::Codex, HarnessAccessPolicy::ReadOnly);
    let resolved = resolve_at_project_a(&mut fixture).unwrap();
    assert!(resolved.access.read_scope(McpScopeSelector::ActiveProject).is_ok());
    assert_eq!(
        resolved.access.write_scope(McpScopeSelector::ActiveProject).unwrap_err().code,
        ErrorCode::ScopeDenied
    );
}
```

Also cover: no project -> global only, nested roots, equal-specificity ambiguity, missing roots, disabled, global-only, active-project-only, selected-project, Windows case folding in a pure path-key unit test, and a record from another project.

- [ ] **Step 2: Run the binding suite and confirm RED**

Run:

```bash
env CARGO_HOME=/private/tmp/context-relay-cargo RUSTUP_HOME=/private/tmp/context-relay-rustup /private/tmp/context-relay-cargo/bin/cargo test -p context-relay-core --test mcp_binding_v1
```

Expected: compilation fails because `core::mcp::binding` does not exist.

- [ ] **Step 3: Implement native-path decoding and project selection**

Expose the module:

```rust
pub mod mcp;
```

Use focused public types:

```rust
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedMcpBinding {
    pub harness: HarnessId,
    pub active_project: Option<ProjectIdentity>,
    pub policy: HarnessAccessPolicy,
    pub access: McpAccess,
}

pub fn resolve_binding(
    vault: &Vault,
    binding: &McpBinding,
) -> Result<ResolvedMcpBinding, ClientError>;
```

The resolver decodes the native path without `display`, requires an absolute canonical directory, canonicalizes registered roots, chooses the longest containing root, and rejects equal-length conflicting matches. Build `McpAccess` only from `AllowedSearchScope::resolve`; do not expose its internal grant.

- [ ] **Step 4: Implement the complete policy matrix**

Provide explicit methods instead of scattered matches:

```rust
impl McpAccess {
    pub fn read_scope(&self, requested: McpScopeSelector) -> Result<ScopeRef, ClientError>;
    pub fn write_scope(&self, requested: McpScopeSelector) -> Result<ScopeRef, ClientError>;
    pub fn require_tasks(&self, write: bool) -> Result<ProjectId, ClientError>;
    pub fn allows_record_scope(&self, scope: &ScopeRef, write: bool) -> bool;
}
```

Map every denial to:

```rust
ClientError {
    code: ErrorCode::ScopeDenied,
    message: "The calling harness is not allowed to access this scope".into(),
    field_path: None,
    retryable: false,
}
```

- [ ] **Step 5: Run GREEN and commit**

```bash
env CARGO_HOME=/private/tmp/context-relay-cargo RUSTUP_HOME=/private/tmp/context-relay-rustup /private/tmp/context-relay-cargo/bin/cargo test -p context-relay-core --test mcp_binding_v1
git add crates/core/src/lib.rs crates/core/src/mcp/mod.rs crates/core/src/mcp/binding.rs crates/core/tests/mcp_binding_v1.rs
git commit -m "feat: resolve scoped MCP harness bindings"
```

Expected: all binding and policy cases pass.

### Task 3: Implement MCP memory, proposal, search, get, and status tools

**Files:**
- Modify: `crates/core/src/mcp/mod.rs`
- Create: `crates/core/src/mcp/tools.rs`
- Modify: `crates/core/src/service.rs`
- Modify: `crates/core/src/vault.rs`
- Create: `crates/core/tests/mcp_memory_tools_v1.rs`

**Interfaces:**
- Produces: `McpWorkspace::call(McpCallParams) -> Result<serde_json::Value, ClientError>`.
- Produces: idempotent `OfflineWorkspace::propose_memory`.
- Produces: scoped instruction search/list helpers needed by search and handoffs.

- [ ] **Step 1: Write one failing test per memory/status tool**

```rust
#[test]
fn explicit_memory_replay_returns_one_record() {
    let mut fixture = mcp_fixture(HarnessAccessPolicy::Default);
    let input = json!({
        "operationId": OPERATION,
        "kind": "note",
        "title": "Decision context",
        "markdown": "Use the daemon-owned binding.",
        "tags": ["mcp"],
        "scope": {"scope":"active_project"}
    });
    let first = fixture.call("context_relay_remember", input.clone()).unwrap();
    let second = fixture.call("context_relay_remember", input).unwrap();
    assert_eq!(first, second);
    assert_eq!(fixture.project_memories().len(), 1);
}

#[test]
fn record_id_does_not_bypass_project_scope() {
    let mut fixture = two_project_mcp_fixture();
    let other = fixture.insert_project_b_memory();
    let error = fixture.call(
        "context_relay_get",
        json!({"recordId": other.id.to_string()}),
    ).unwrap_err();
    assert_eq!(error.code, ErrorCode::ScopeDenied);
}

#[test]
fn inferred_proposal_is_pending_and_attributed_to_the_harness() {
    let mut fixture = mcp_fixture(HarnessAccessPolicy::Default);
    let output = fixture.call("context_relay_propose_memory", proposal_input()).unwrap();
    assert_eq!(output["candidate"]["state"], "pending");
    assert_eq!(output["candidate"]["sourceHarness"], "codex");
    assert!(fixture.project_memories().is_empty());
}
```

Add cases for search global/active project, instruction results, get memory,
get instruction, missing get -> `record: null`, update revision conflict,
archive revision conflict, read-only/disabled writes, proposal replay, status
policy/project, and output validation.

- [ ] **Step 2: Run the memory-tool suite and confirm RED**

```bash
env CARGO_HOME=/private/tmp/context-relay-cargo RUSTUP_HOME=/private/tmp/context-relay-rustup /private/tmp/context-relay-cargo/bin/cargo test -p context-relay-core --test mcp_memory_tools_v1
```

Expected: compilation fails because `McpWorkspace` and tool dispatch do not exist.

- [ ] **Step 3: Add idempotent proposal and scoped record helpers**

Implement:

```rust
pub fn propose_memory(
    &mut self,
    input: ProposeMemoryInput,
    scope: ScopeRef,
    harness: HarnessId,
) -> Result<MemoryCandidate, ClientError> {
    let ProposeMemoryInput {
        operation_id,
        kind,
        title,
        markdown,
        tags,
        evidence_summary,
        scope: _,
    } = input;
    let id = CandidateId::new(operation_id.into_uuid())
        .map_err(|_| invalid_request())?;
    if let Some(existing) = vault(self.vault.candidate(&id))? {
        return Ok(existing);
    }
    let memory_id = MemoryId::new(operation_id.into_uuid())
        .map_err(|_| invalid_request())?;
    let clock = operation_clock(operation_id, self.device_id);
    let proposed_memory = MemoryRecord {
        id: memory_id,
        scope,
        kind,
        title,
        body_markdown: markdown,
        tags,
        origin: MemoryOrigin::Inferred,
        provenance: Provenance {
            origin_device: self.device_id,
            harness: Some(harness),
            source: None,
            created_hlc: clock,
        },
        revision: operation_id,
        created_hlc: clock,
        updated_hlc: clock,
        archived: false,
    };
    let candidate = MemoryCandidate {
        id,
        proposed_memory,
        evidence_summary,
        source_harness: harness,
        state: CandidateState::Pending,
    };
    candidate.validate().map_err(|_| invalid_request())?;
    vault(self.vault.put_candidate(&candidate))?;
    Ok(candidate)
}
```

Add bounded vault helpers that return non-archived instructions for an allowed
scope and search hits by record kind. Do not expose SQL or a caller-selected
project ID outside `McpAccess`.

- [ ] **Step 4: Implement typed dispatch for seven tools**

Dispatch by exact name and parse the frozen DTO:

```rust
pub fn call(&mut self, params: McpCallParams) -> Result<Value, ClientError> {
    let McpCallParams { binding, name, arguments } = params;
    let resolved = resolve_binding(self.vault, &binding)?;
    let output = match name.as_str() {
        "context_relay_search" => output(self.search(&resolved, parse(arguments)?)?)?,
        "context_relay_get" => output(self.get(&resolved, parse(arguments)?)?)?,
        "context_relay_remember" => output(self.remember(&resolved, parse(arguments)?)?)?,
        "context_relay_propose_memory" => output(self.propose(&resolved, parse(arguments)?)?)?,
        "context_relay_update_memory" => output(self.update(&resolved, parse(arguments)?)?)?,
        "context_relay_archive_memory" => output(self.archive(&resolved, parse(arguments)?)?)?,
        "context_relay_status" => output(self.status(&resolved, parse(arguments)?)?)?,
        _ => self.call_task_or_handoff(&resolved, &name, arguments)?,
    };
    validate_mcp_fixture(&name, false, &output)
        .map_err(|_| internal_error("The MCP output was invalid"))?;
    Ok(output)
}
```

For Task 3, define the remaining four-tool branch explicitly so the crate
stays green before Task 4 replaces these results with implementations:

```rust
fn call_task_or_handoff(
    &mut self,
    _resolved: &ResolvedMcpBinding,
    name: &str,
    _arguments: Value,
) -> Result<Value, ClientError> {
    if matches!(
        name,
        "context_relay_list_tasks"
            | "context_relay_upsert_task"
            | "context_relay_complete_task"
            | "context_relay_create_handoff"
    ) {
        return Err(ClientError {
            code: ErrorCode::HarnessUnsupported,
            message: "This MCP tool is not available in this build".into(),
            field_path: None,
            retryable: false,
        });
    }
    Err(invalid_request("The MCP tool name is invalid"))
}
```

Preserve title, tags, and scope on MCP update; update Markdown only. Check
record scope before calling the existing revision-enforcing operation.

- [ ] **Step 5: Run GREEN and commit**

```bash
env CARGO_HOME=/private/tmp/context-relay-cargo RUSTUP_HOME=/private/tmp/context-relay-rustup /private/tmp/context-relay-cargo/bin/cargo test -p context-relay-core --test mcp_memory_tools_v1
git add crates/core/src/mcp/mod.rs crates/core/src/mcp/tools.rs crates/core/src/service.rs crates/core/src/vault.rs crates/core/tests/mcp_memory_tools_v1.rs
git commit -m "feat: add scoped MCP memory tools"
```

### Task 4: Implement scoped tasks and complete handoffs

**Files:**
- Modify: `crates/core/src/mcp/tools.rs`
- Create: `crates/core/src/mcp/handoff.rs`
- Create: `crates/core/src/mcp/secret_text.rs`
- Modify: `crates/core/src/vault.rs`
- Create: `crates/core/tests/mcp_tasks_handoffs_v1.rs`

**Interfaces:**
- Completes: `McpWorkspace::call` for list/upsert/complete/create-handoff.
- Produces: `build_handoff(vault, resolved, input) -> HandoffPayload`.
- Produces: `reject_secret_like(&str) -> Result<(), ClientError>`.

- [ ] **Step 1: Write failing task and handoff tests**

```rust
#[test]
fn task_completion_requires_evidence_and_expected_revision() {
    let mut fixture = mcp_fixture(HarnessAccessPolicy::Default);
    let created = fixture.upsert_new_task();
    let error = fixture.call("context_relay_complete_task", json!({
        "operationId": NEXT_OPERATION,
        "taskId": created.id,
        "expectedRevision": created.revision,
        "evidence": []
    })).unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidRequest);
}

#[test]
fn handoff_contains_required_context_without_secret_sources() {
    let mut fixture = complete_handoff_fixture();
    let output = fixture.call("context_relay_create_handoff", handoff_input()).unwrap();
    let payload = &output["payload"];
    assert_eq!(payload["project"]["projectId"], fixture.project_id.to_string());
    assert!(payload["decisions"].as_array().unwrap().len() >= 1);
    assert!(payload["tasks"].as_array().unwrap().iter().any(|task| task["status"] == "blocked"));
    assert!(payload["markdown"].as_str().unwrap().contains("## Completion evidence"));
    assert!(!payload["instructionRefs"].as_array().unwrap().is_empty());
    assert!(!output.to_string().contains("transcript"));
}

#[test]
fn handoff_rejects_secret_like_text_without_echoing_it() {
    let mut fixture = mcp_fixture(HarnessAccessPolicy::Default);
    let memory = fixture.insert_memory("Authorization: Bearer must-not-echo");
    let error = fixture.create_handoff_with(memory.id).unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidRequest);
    assert!(!error.message.contains("must-not-echo"));
}
```

Also cover task status filtering, create/update pair invariants, task replay,
cross-project task IDs, read-only list versus writes, selected record order,
wrong-kind decisions, archived records, recent-decision ordering, open/blocked
auto-inclusion, done evidence, instruction relevance, bounds, and deterministic
Markdown.

- [ ] **Step 2: Run the focused suite and confirm RED**

```bash
env CARGO_HOME=/private/tmp/context-relay-cargo RUSTUP_HOME=/private/tmp/context-relay-rustup /private/tmp/context-relay-cargo/bin/cargo test -p context-relay-core --test mcp_tasks_handoffs_v1
```

Expected: task dispatch and handoff modules are absent.

- [ ] **Step 3: Implement task mappings**

Use only the resolved project:

```rust
fn list_tasks(&mut self, resolved: &ResolvedMcpBinding, input: ListTasksInput)
    -> Result<ListTasksOutput, ClientError>
{
    let project_id = resolved.access.require_tasks(false)?;
    let mut tasks = OfflineWorkspace::new(self.vault, self.device_id).tasks(project_id)?;
    if let Some(status) = input.status {
        tasks.retain(|task| task.status == status);
    }
    Ok(ListTasksOutput { tasks })
}
```

Complete the exact dispatch arms:

```rust
"context_relay_list_tasks" => {
    output(self.list_tasks(&resolved, parse(arguments)?)?)?
}
"context_relay_upsert_task" => {
    output(self.upsert_task(&resolved, parse(arguments)?)?)?
}
"context_relay_complete_task" => {
    output(self.complete_task(&resolved, parse(arguments)?)?)?
}
"context_relay_create_handoff" => {
    output(self.create_handoff(&resolved, parse(arguments)?)?)?
}
```

For upsert and complete, call `require_tasks(true)`, reject any loaded task
whose project differs, and delegate expected-revision/idempotency handling to
`OfflineWorkspace`. `output` is:

```rust
fn output(value: impl serde::Serialize) -> Result<Value, ClientError> {
    serde_json::to_value(value)
        .map_err(|_| internal_error("The MCP output could not be serialized"))
}
```

- [ ] **Step 4: Implement secret rejection and deterministic handoff projection**

`secret_text.rs` must reject, without echoing matches:

```rust
const PRIVATE_KEY_MARKERS: [&str; 2] = [
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
];
const SENSITIVE_KEYS: [&str; 8] = [
    "authorization", "api_key", "apikey", "access_token",
    "refresh_token", "password", "secret", "credential",
];

pub fn reject_secret_like(text: &str) -> Result<(), ClientError> {
    if has_private_key_marker(text)
        || has_authorization_header(text)
        || has_sensitive_assignment(text)
        || has_bounded_token_shape(text)
    {
        return Err(invalid("The handoff contains secret-like text"));
    }
    Ok(())
}
```

`build_handoff` loads all selections, validates scope/kind/archive state, adds
recent decisions by descending `updated_hlc`, adds open/blocked tasks, selects
instruction IDs through the existing allowed search surface, runs
`reject_secret_like` over every rendered field, and validates the final
`HandoffPayload`.

- [ ] **Step 5: Run GREEN and commit**

```bash
env CARGO_HOME=/private/tmp/context-relay-cargo RUSTUP_HOME=/private/tmp/context-relay-rustup /private/tmp/context-relay-cargo/bin/cargo test -p context-relay-core --test mcp_tasks_handoffs_v1
git add crates/core/src/mcp/tools.rs crates/core/src/mcp/handoff.rs crates/core/src/mcp/secret_text.rs crates/core/src/vault.rs crates/core/tests/mcp_tasks_handoffs_v1.rs
git commit -m "feat: add MCP tasks and complete handoffs"
```

### Task 5: Route scoped MCP calls through the daemon

**Files:**
- Modify: `crates/contextd/src/lib.rs`
- Modify: `crates/local-ipc/src/auth.rs`
- Create: `crates/contextd/tests/mcp_bridge_v1.rs`

**Interfaces:**
- Consumes: `McpWorkspace::call`.
- Returns: `LocalResult::McpOutput`.
- Preserves: local request ID cancellation, queue timeout, busy behavior, and single-writer ordering.

- [ ] **Step 1: Write failing daemon boundary tests**

```rust
#[tokio::test]
async fn authenticated_bridge_executes_only_scoped_mcp_calls() {
    let fixture = daemon_fixture().await;
    let mut bridge = fixture.connect(ClientRole::McpBridge).await;
    let result = bridge.call(LocalRequest::McpCall(status_call())).await.unwrap();
    let LocalResult::McpOutput { name, output } = result else { panic!("wrong result") };
    assert_eq!(name, "context_relay_status");
    assert_eq!(output["resolvedProject"], fixture.project_id.to_string());

    let denied = bridge.call(raw_project_b_search()).await.unwrap_err();
    assert_eq!(denied.code, ErrorCode::ScopeDenied);
}

#[tokio::test]
async fn queued_mcp_call_can_be_canceled_and_timeout_is_structured() {
    let fixture = daemon_fixture_with_blocked_worker().await;
    let request_id = record_id(41);
    let call = fixture.spawn_call(request_id, remember_call()).await;
    fixture.wait_until_enqueued().await;
    fixture.cancel(request_id).await.unwrap();
    fixture.release_worker();
    let error = call.await.unwrap().unwrap_err();
    assert_eq!(error.code, ErrorCode::Canceled);
    assert!(fixture.project_memories().await.is_empty());

    let timeout = fixture.spawn_timed_out_status_call().await.unwrap_err();
    assert_eq!(timeout.code, ErrorCode::Timeout);
    assert!(timeout.retryable);
}
```

- [ ] **Step 2: Run and confirm RED**

```bash
env CARGO_HOME=/private/tmp/context-relay-cargo RUSTUP_HOME=/private/tmp/context-relay-rustup /private/tmp/context-relay-cargo/bin/cargo test -p context-relay-contextd --test mcp_bridge_v1
```

Expected: `McpCall` is not routed.

- [ ] **Step 3: Add one workspace command route**

Route:

```rust
LocalRequest::McpCall(params) => {
    McpWorkspace::new(&mut state.vault, state.device_id)
        .call(params.clone())
        .map(|output| LocalResult::McpOutput {
            name: params.name,
            output,
        })
}
```

Include `McpCall` in the existing queued `VaultCommand::Workspace` path, not an
immediate path. Remove the old unscoped `SyncStatus` MCP shortcut. Keep
request registration, worker admission, cancellation, busy, and timeout
behavior unchanged.

- [ ] **Step 4: Run daemon and IPC regression suites**

```bash
env CARGO_HOME=/private/tmp/context-relay-cargo RUSTUP_HOME=/private/tmp/context-relay-rustup /private/tmp/context-relay-cargo/bin/cargo test -p context-relay-contextd --test mcp_bridge_v1
env CARGO_HOME=/private/tmp/context-relay-cargo RUSTUP_HOME=/private/tmp/context-relay-rustup /private/tmp/context-relay-cargo/bin/cargo test -p context-relay-contextd --lib
env CARGO_HOME=/private/tmp/context-relay-cargo RUSTUP_HOME=/private/tmp/context-relay-rustup /private/tmp/context-relay-cargo/bin/cargo test -p context-relay-local-ipc
```

Expected: scoped calls, denial, queued cancellation, timeout, busy, and all prior daemon/IPC tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/contextd/src/lib.rs crates/contextd/tests/mcp_bridge_v1.rs crates/local-ipc/src/auth.rs
git commit -m "feat: route scoped MCP calls through contextd"
```

### Task 6: Implement the bounded MCP wire protocol and lifecycle

**Files:**
- Modify: `crates/context-mcp/Cargo.toml`
- Create: `crates/context-mcp/src/lib.rs`
- Create: `crates/context-mcp/src/daemon.rs`
- Create: `crates/context-mcp/src/protocol.rs`
- Create: `crates/context-mcp/src/server.rs`
- Modify: `crates/context-mcp/src/main.rs`
- Create: `crates/context-mcp/tests/lifecycle_v1.rs`
- Modify: `crates/context-mcp/tests/stdout_v1.rs`

**Interfaces:**
- Produces: `RpcId`, bounded MCP request/notification parsing, and compact responses.
- Produces: lifecycle state `AwaitInitialize -> AwaitInitialized -> Ready`.
- Produces: `Server<D>::run(reader, writer)`.
- Produces: the injectable `Daemon` trait with a deterministic fake used by lifecycle tests.
- Consumes in Task 7: the production `LocalDaemon` implementation.

- [ ] **Step 1: Add failing lifecycle/list/stdout tests**

```rust
#[tokio::test]
async fn initializes_then_lists_exact_frozen_tools() {
    let input = lines([
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-11-25",
            "capabilities":{},
            "clientInfo":{"name":"test","version":"1"}
        }}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})
    ]);
    let output = run_server(FakeDaemon::default(), input).await;
    let messages = parse_stdout_lines(&output);
    assert_eq!(messages[0]["result"]["protocolVersion"], "2025-11-25");
    let names = messages[1]["result"]["tools"].as_array().unwrap()
        .iter().map(|tool| tool["name"].as_str().unwrap()).collect::<Vec<_>>();
    assert_eq!(names, MCP_TOOL_NAMES);
    assert!(messages[1]["result"]["tools"][0].get("outputSchema").is_some());
}
```

Add tests for compatibility negotiation, unsupported revision, tool use before
initialized, ping, unknown method, invalid params, parse error, 8 MiB bound,
no embedded physical newlines, EOF, and a subprocess assertion that every
stdout line parses as one JSON-RPC object. Update the existing null-stdin
subprocess test to pass `--harness codex`; it must exit successfully with empty
stdout. A separate missing-binding test must exit with code 2 and empty
stdout.

- [ ] **Step 2: Run and confirm RED**

```bash
env CARGO_HOME=/private/tmp/context-relay-cargo RUSTUP_HOME=/private/tmp/context-relay-rustup /private/tmp/context-relay-cargo/bin/cargo test -p context-relay-context-mcp --test lifecycle_v1
```

Expected: protocol/server modules do not exist.

- [ ] **Step 3: Add only pinned workspace dependencies**

```toml
[dependencies]
context-relay-local-ipc = { version = "0.1.0", path = "../local-ipc" }
context-relay-protocol = { version = "0.1.0", path = "../protocol" }
serde.workspace = true
serde_json.workspace = true
tokio.workspace = true
uuid.workspace = true
```

- [ ] **Step 4: Implement the bounded parser and lifecycle**

Use:

```rust
pub const MCP_REVISION: &str = "2025-11-25";
pub const MCP_COMPAT_REVISION: &str = "2025-06-18";

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum RpcId {
    Number(i64),
    String(String),
}

enum Lifecycle {
    AwaitInitialize,
    AwaitInitialized,
    Ready,
}

pub trait Daemon: Clone + Send + Sync + 'static {
    fn call(
        &self,
        request_id: RecordId,
        call: McpCallParams,
    ) -> impl std::future::Future<Output = Result<Value, BridgeError>> + Send;
    fn cancel(
        &self,
        request_id: RecordId,
    ) -> impl std::future::Future<Output = Result<(), BridgeError>> + Send;
}
```

Read with `AsyncBufReadExt::read_until(b'\n', ...)`, rejecting a buffer as soon
as it exceeds `MAX_IPC_FRAME_BYTES`. Serialize with `serde_json::to_writer`
semantics into a bounded `Vec<u8>`, append exactly one newline, and write only
through the server's single writer.

`tools/list` maps `mcp_schema(name)` to `inputSchema` and `outputSchema`; it
does not advertise list changes or MCP task augmentation.

`tools/call` requires exactly `{"name": string, "arguments": object}`, rejects
an unknown name before daemon dispatch, validates `arguments` with
`validate_mcp_fixture(name, true, arguments)`, and submits the admitted call to
the Task 7 dispatcher.

- [ ] **Step 5: Parse the CLI binding without stdout side effects**

`main` must:

```rust
#[tokio::main]
async fn main() {
    let Some(harness) = parse_harness(std::env::args_os()) else {
        eprintln!("Context Relay MCP requires one supported harness binding");
        std::process::exit(2);
    };
    if let Err(error) = run_stdio(harness).await {
        eprintln!("Context Relay MCP stopped: {}", error.redacted_message());
        std::process::exit(1);
    }
}
```

Accept exactly `claude-code`, `codex`, or `hermes`; current-directory/native
path encoding happens after parsing and is never logged.

- [ ] **Step 6: Run GREEN and commit**

```bash
env CARGO_HOME=/private/tmp/context-relay-cargo RUSTUP_HOME=/private/tmp/context-relay-rustup /private/tmp/context-relay-cargo/bin/cargo test -p context-relay-context-mcp --test lifecycle_v1
env CARGO_HOME=/private/tmp/context-relay-cargo RUSTUP_HOME=/private/tmp/context-relay-rustup /private/tmp/context-relay-cargo/bin/cargo test -p context-relay-context-mcp --test stdout_v1
git add Cargo.lock crates/context-mcp/Cargo.toml crates/context-mcp/src crates/context-mcp/tests/lifecycle_v1.rs crates/context-mcp/tests/stdout_v1.rs
git commit -m "feat: add bounded MCP stdio lifecycle"
```

### Task 7: Add daemon calls, cancellation, timeout, and backpressure

**Files:**
- Modify: `crates/context-mcp/src/daemon.rs`
- Modify: `crates/context-mcp/src/server.rs`
- Create: `crates/context-mcp/tests/dispatcher_v1.rs`
- Create: `crates/context-mcp/tests/end_to_end_v1.rs`

**Interfaces:**
- Consumes: the `Daemon` trait used by the server and tests.
- Produces: `LocalDaemon` using authenticated `ClientRole::McpBridge`.
- Produces: active MCP-ID -> local UUIDv7 request-ID map and 64-permit dispatcher.

- [ ] **Step 1: Write failing dispatcher tests**

```rust
#[tokio::test]
async fn sixty_five_concurrent_calls_fail_the_last_with_retryable_busy() {
    let daemon = BlockingDaemon::new();
    let server = started_server(daemon.clone()).await;
    for id in 1..=64 {
        server.send(tool_call(id, "context_relay_status", json!({}))).await;
    }
    daemon.wait_for_calls(64).await;
    server.send(tool_call(65, "context_relay_status", json!({}))).await;
    let busy = server.response_for(65).await;
    assert_eq!(busy["result"]["isError"], true);
    assert_eq!(busy["result"]["_meta"]["contextRelay"]["code"], "busy");
    assert_eq!(busy["result"]["_meta"]["contextRelay"]["retryable"], true);
}

#[tokio::test]
async fn cancellation_targets_the_local_request_and_emits_no_late_response() {
    let daemon = BlockingDaemon::new();
    let server = started_server(daemon.clone()).await;
    server.send(tool_call("call-1", "context_relay_status", json!({}))).await;
    let local_id = daemon.next_local_id().await;
    server.send(cancel_notification("call-1")).await;
    assert_eq!(daemon.next_cancel_id().await, local_id);
    daemon.finish(local_id, status_output()).await;
    assert!(server.no_response_for("call-1").await);
}
```

Add timeout with paused Tokio time, daemon unavailable, vault locked, revision
conflict, duplicate active MCP ID, sequential ID reuse, invalid output, write
unknown-outcome no-retry, and stdout interleaving tests.

- [ ] **Step 2: Run and confirm RED**

```bash
env CARGO_HOME=/private/tmp/context-relay-cargo RUSTUP_HOME=/private/tmp/context-relay-rustup /private/tmp/context-relay-cargo/bin/cargo test -p context-relay-context-mcp --test dispatcher_v1
```

Expected: no daemon dispatcher exists.

- [ ] **Step 3: Implement the injectable daemon boundary**

```rust
pub trait Daemon: Clone + Send + Sync + 'static {
    fn call(
        &self,
        request_id: RecordId,
        call: McpCallParams,
    ) -> impl std::future::Future<Output = Result<Value, BridgeError>> + Send;
    fn cancel(
        &self,
        request_id: RecordId,
    ) -> impl std::future::Future<Output = Result<(), BridgeError>> + Send;
}
```

`LocalDaemon::call` opens one `Client::connect(ClientRole::McpBridge)`, sends
one `McpCall`, requires the matching `McpOutput` name, and never retries.
`cancel` opens a separate authenticated connection and sends `Cancel`.

- [ ] **Step 4: Implement bounded dispatch and error mapping**

Use `Arc<Semaphore>::try_acquire_owned`, one UUIDv7 `RecordId` per admitted
call, an `Arc<Mutex<HashMap<RpcId, ActiveCall>>>`, and a single
`mpsc::Sender<Vec<u8>>` writer.

Success:

```json
{
  "content": [{"type":"text","text":"<canonical-json>"}],
  "structuredContent": {},
  "isError": false
}
```

Tool failure:

```json
{
  "content": [{"type":"text","text":"The local vault is locked"}],
  "isError": true,
  "_meta": {
    "contextRelay": {
      "code":"vault_locked",
      "retryable":true,
      "fieldPath":null
    }
  }
}
```

Do not include `structuredContent` on failures. After valid cancellation, mark
the active call canceled before sending daemon cancel and suppress every late
response.

- [ ] **Step 5: Run process and real-daemon integration GREEN**

```bash
env CARGO_HOME=/private/tmp/context-relay-cargo RUSTUP_HOME=/private/tmp/context-relay-rustup /private/tmp/context-relay-cargo/bin/cargo test -p context-relay-context-mcp --test dispatcher_v1
env CARGO_HOME=/private/tmp/context-relay-cargo RUSTUP_HOME=/private/tmp/context-relay-rustup /private/tmp/context-relay-cargo/bin/cargo test -p context-relay-context-mcp --test end_to_end_v1
```

Expected: call, cancel, timeout, overload, locked/unavailable, replay, restart/reconnect, and stdout-purity cases pass.

- [ ] **Step 6: Commit**

```bash
git add crates/context-mcp/src/daemon.rs crates/context-mcp/src/server.rs crates/context-mcp/tests/dispatcher_v1.rs crates/context-mcp/tests/end_to_end_v1.rs
git commit -m "feat: connect MCP stdio to the local daemon"
```

### Task 8: Install the bridge through Claude Code, Codex, and Hermes

> **Implementation correction (2026-07-31):** Repository inspection found
> that the adapter renderers exist, but production setup-plan orchestration
> and transactional execution/recovery of `CliOperation` do not. Complete the
> canonical component/rendering portion below, then execute
> `docs/superpowers/plans/2026-07-31-transactional-mcp-adapter-install.md`
> before claiming Task 8 apply/rollback acceptance or starting Task 9. The
> normative correction is
> `docs/superpowers/specs/2026-07-31-transactional-mcp-adapter-install-design.md`.

**Files:**
- Create: `crates/core/src/mcp/install.rs`
- Modify: `crates/core/src/mcp/mod.rs`
- Modify: `crates/core/src/claude_code.rs`
- Modify: `crates/core/src/codex.rs`
- Modify: `crates/core/src/hermes.rs`
- Create: `crates/core/tests/mcp_bridge_install_v1.rs`

**Interfaces:**
- Produces: `bridge_component(harness, executable, origin_device, created_hlc) -> ComponentRecord`.
- Produces: adapter-specific canonical MCP JSON with no environment or secret field.
- Preserves: adapter render/classify/plan/apply/validate/rollback boundaries.

- [ ] **Step 1: Write failing cross-adapter install tests**

```rust
#[test]
fn bridge_components_are_global_active_and_secret_free() {
    let root = tempfile::tempdir().unwrap();
    let executable = root.path().join("context-relay-context-mcp");
    std::fs::write(&executable, b"attested bridge fixture").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    for harness in [HarnessId::ClaudeCode, HarnessId::Codex, HarnessId::Hermes] {
        let component = bridge_component(
            harness,
            &executable,
            device_id(),
            clock(),
        ).unwrap();
        assert_eq!(component.name, "context-relay");
        assert_eq!(component.kind, ComponentKind::McpServer);
        assert_eq!(component.scope, ScopeRef::Global);
        let value: Value = serde_json::from_str(&component.body_markdown).unwrap();
        assert_eq!(value["command"], executable.to_str().unwrap());
        assert_eq!(value["args"], json!(["--harness", harness_cli_name(harness)]));
        assert!(value.get("env").is_none());
        assert!(!component.body_markdown.contains("token"));
    }
}
```

For each fixture adapter, render the component, assert exact official CLI argv
or Hermes YAML, classify/plan it as active, confirm rejected setup has no
write, confirm validation does not execute the bridge, and confirm rollback
restores the original declaration.

- [ ] **Step 2: Run and confirm RED**

```bash
env CARGO_HOME=/private/tmp/context-relay-cargo RUSTUP_HOME=/private/tmp/context-relay-rustup /private/tmp/context-relay-cargo/bin/cargo test -p context-relay-core --test mcp_bridge_install_v1
```

Expected: `bridge_component` does not exist.

- [ ] **Step 3: Implement canonical harness-specific declarations**

```rust
pub const BRIDGE_SERVER_NAME: &str = "context-relay";

pub fn bridge_component(
    harness: HarnessId,
    executable: &Path,
    origin_device: DeviceId,
    created_hlc: HybridLogicalClock,
) -> Result<ComponentRecord, ClientError> {
    let command = absolute_non_link_executable(executable)?;
    let body = json!({
        "type": "stdio",
        "command": command,
        "args": ["--harness", harness_cli_name(harness)]
    });
    Ok(ComponentRecord {
        id: stable_bridge_record_id(harness),
        scope: ScopeRef::Global,
        kind: ComponentKind::McpServer,
        name: BRIDGE_SERVER_NAME.into(),
        body_markdown: canonical_json(&body)?,
        metadata: bridge_metadata(harness),
        provenance: Provenance {
            origin_device,
            harness: None,
            source: None,
            created_hlc,
        },
        archived: false,
    })
}
```

For Hermes metadata, use exact structural location
`config:mcp_servers.context-relay`. Claude Code and Codex receive only metadata
their existing renderer understands. If a renderer requires a harmless shape
difference (`type` accepted/omitted), produce it inside `bridge_component`
while keeping command/args identical.

- [ ] **Step 4: Make active classification explicit**

Any create/update/enable/disable/remove of this MCP executable declaration
must set `ApprovalClass::Active` in the setup plan. Reuse existing adapter MCP
rendering and native transaction code; do not add a direct file or CLI write.
Validation continues to use `mcp list/get` or Hermes shape inspection and must
not launch the configured command.

- [ ] **Step 5: Run all three adapter suites and commit**

```bash
env CARGO_HOME=/private/tmp/context-relay-cargo RUSTUP_HOME=/private/tmp/context-relay-rustup /private/tmp/context-relay-cargo/bin/cargo test -p context-relay-core --test mcp_bridge_install_v1
env CARGO_HOME=/private/tmp/context-relay-cargo RUSTUP_HOME=/private/tmp/context-relay-rustup /private/tmp/context-relay-cargo/bin/cargo test -p context-relay-core --test claude_code_adapter_v1
env CARGO_HOME=/private/tmp/context-relay-cargo RUSTUP_HOME=/private/tmp/context-relay-rustup /private/tmp/context-relay-cargo/bin/cargo test -p context-relay-core --test codex_adapter_v1
env CARGO_HOME=/private/tmp/context-relay-cargo RUSTUP_HOME=/private/tmp/context-relay-rustup /private/tmp/context-relay-cargo/bin/cargo test -p context-relay-core --test hermes_adapter_v1
git add crates/core/src/mcp/install.rs crates/core/src/mcp/mod.rs crates/core/src/claude_code.rs crates/core/src/codex.rs crates/core/src/hermes.rs crates/core/tests/mcp_bridge_install_v1.rs
git commit -m "feat: install the MCP bridge through adapters"
```

### Task 9: Complete MCP acceptance verification and publish Task 13

> **Status (2026-08-01): Complete — Task 13 published.** The final
> three-harness scenario, acceptance matrix, repository gates, and independent
> review are complete. The only full-workspace exceptions were the macOS
> native-filesystem tests affected by Codex-applied `com.apple.provenance`;
> every Task 13 and adjacent suite passed independently.

**Files:**
- Modify: `crates/context-mcp/tests/end_to_end_v1.rs`
- Modify: `docs/superpowers/plans/2026-07-30-mcp-memory-tasks-handoffs.md`

**Interfaces:**
- Verifies every Task 13 acceptance criterion in a fresh context.
- Produces final roadmap commit: `feat: add scoped MCP memory and task bridge`.

- [x] **Step 1: Add the final three-harness acceptance scenario**

Exercise one registered project through bridge bindings for Claude Code,
Codex, and Hermes:

```rust
#[tokio::test]
async fn three_harnesses_share_one_scoped_project_without_native_approval() {
    let fixture = running_workspace().await;
    let memory = fixture.codex.remember(project_memory()).await.unwrap();
    assert_eq!(fixture.claude.get(memory.id).await.unwrap(), memory);
    assert!(fixture.hermes.search("daemon-owned").await.unwrap().contains(&memory));
    let task = fixture.claude.upsert_task(open_task()).await.unwrap();
    let done = fixture.hermes.complete_task(task, evidence()).await.unwrap();
    assert_eq!(done.status, TaskStatus::Done);
    assert_eq!(fixture.native_approval_count(), 0);
}
```

Also assert another registered project is denied, a daemon restart reconnects,
and replay after an unknown write result returns one record.

- [x] **Step 2: Run the Task 13 acceptance matrix**

```bash
env CARGO_HOME=/private/tmp/context-relay-cargo RUSTUP_HOME=/private/tmp/context-relay-rustup /private/tmp/context-relay-cargo/bin/cargo test -p context-relay-protocol --test mcp_schema_parity_v1
env CARGO_HOME=/private/tmp/context-relay-cargo RUSTUP_HOME=/private/tmp/context-relay-rustup /private/tmp/context-relay-cargo/bin/cargo test -p context-relay-protocol --test mcp_ipc_v1
env CARGO_HOME=/private/tmp/context-relay-cargo RUSTUP_HOME=/private/tmp/context-relay-rustup /private/tmp/context-relay-cargo/bin/cargo test -p context-relay-local-ipc
env CARGO_HOME=/private/tmp/context-relay-cargo RUSTUP_HOME=/private/tmp/context-relay-rustup /private/tmp/context-relay-cargo/bin/cargo test -p context-relay-contextd
env CARGO_HOME=/private/tmp/context-relay-cargo RUSTUP_HOME=/private/tmp/context-relay-rustup /private/tmp/context-relay-cargo/bin/cargo test -p context-relay-context-mcp
env CARGO_HOME=/private/tmp/context-relay-cargo RUSTUP_HOME=/private/tmp/context-relay-rustup /private/tmp/context-relay-cargo/bin/cargo test -p context-relay-core --test mcp_binding_v1 --test mcp_memory_tools_v1 --test mcp_tasks_handoffs_v1 --test mcp_bridge_install_v1
```

Expected: initialize, list, every tool call, cancellation, timeout,
backpressure, stdout purity, scope denial, replay, no-approval writes,
locked/unavailable errors, complete handoffs, and all adapter registrations
pass.

- [x] **Step 3: Run repository gates**

```bash
env CARGO_HOME=/private/tmp/context-relay-cargo RUSTUP_HOME=/private/tmp/context-relay-rustup /private/tmp/context-relay-cargo/bin/cargo fmt --all -- --check
env CARGO_HOME=/private/tmp/context-relay-cargo RUSTUP_HOME=/private/tmp/context-relay-rustup /private/tmp/context-relay-cargo/bin/cargo clippy --workspace --all-targets --all-features -- -D warnings
env PATH=/Users/skytuhua/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin /Users/skytuhua/.cache/codex-runtimes/codex-primary-runtime/dependencies/bin/fallback/pnpm --dir apps/desktop test --run
git diff --check
```

Expected: formatting, Clippy, desktop tests, and diff checks pass. Run the full
Rust workspace suite as a final regression gate; if the same pre-existing nine
`native_filesystem_macos_v1` `UnsafeTopology` failures remain, record them
verbatim and prove every Task 13 and adjacent suite passed independently.

- [x] **Step 4: Request fresh code review and resolve every actionable finding**

Review the complete branch diff from `e103ab49` through HEAD against the
design, with special attention to project binding, output validation,
cancellation races, idempotency, stdout purity, and adapter activation.
Implement findings with a new failing test before each fix, then rerun the
focused and repository gates.

- [x] **Step 5: Create the roadmap feature commit if the task commits need a final integration commit**

```bash
git add crates/context-mcp crates/contextd crates/core crates/local-ipc crates/protocol Cargo.lock docs/superpowers/specs/2026-07-30-mcp-memory-tasks-handoffs-design.md docs/superpowers/plans/2026-07-30-mcp-memory-tasks-handoffs.md
git commit -m "feat: add scoped MCP memory and task bridge"
```

If all implementation changes are already committed in Tasks 1-8, use an
empty integration commit only when repository policy explicitly requires the
roadmap's exact commit subject; otherwise retain the meaningful task commits
and use the exact roadmap subject for the final substantive fix.

- [ ] **Step 6: Push the branch and continue to Task 14**

```bash
git push -u origin codex/mcp-memory-task-bridge
```

Expected: the remote branch points at the verified Task 13 head. Update the
goal plan to Task 14, “Make product memory authoritative,” without pausing for
routine choices.
