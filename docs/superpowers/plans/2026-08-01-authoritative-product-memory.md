# Authoritative Product Memory Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Context Relay the primary memory and shared task ledger for
Claude Code, Codex, and Hermes while automatically previewing native-memory
edits and never collecting conversation content.

**Architecture:** A pure `core::native_memory` engine owns source identity,
managed-fence parsing, 750 ms debounce state, candidate classification, and
loop suppression. Adapters declare exact native sources and supported config
mutations. `contextd` polls those sources every 250 ms and serializes ready
observations through the vault worker. `context-mcp` gains a strict hook mode
that projects vendor JSON into an allowlisted local-IPC event.

**Tech Stack:** Rust 1.97, Tokio 1.53, Serde/serde_json, toml_edit,
serde_yaml_ng, SHA-256, UUID, SQLCipher-backed `Vault`, existing reversible
native transactions, existing length-prefixed local IPC, Vitest/TypeScript for
generated desktop bindings.

**Normative design:**
`docs/superpowers/specs/2026-08-01-authoritative-product-memory-design.md`

## Global Constraints

- Use test-driven development for every behavior change: write one focused
  failing test, observe the expected failure, implement the minimum behavior,
  and rerun the focused test before broader gates.
- Do not read, write, import, hash, copy, or open prompts, assistant messages,
  transcripts, rollout JSONL, history, state databases, logs, or raw session
  files.
- Native source paths come only from a bound adapter. Hook callers never supply
  a source path.
- Use only version-supported settings. Unknown/import-only versions receive no
  guessed mutation.
- Preserve unmanaged bytes and exact rollback state through the existing native
  transaction engine.
- All native content enters the existing pending candidate review queue. No
  native content is accepted automatically.
- The native-memory engine is synchronous and filesystem-free. Tokio, polling,
  and wall-clock ownership stay in `contextd`.
- Poll only adapter-declared files. Never recursively scan a harness home or a
  session/history directory.
- A stable observation is ready at 750 ms, not before. Polling cadence is 250
  ms.
- Loop suppression binds source ID, full digest, unmanaged digest, imported
  digest, and applied digest.
- Duplicate, nested, or partial managed markers fail closed.
- Hook input is bounded before JSON parsing. Only allowlisted scalars enter IPC.
- `ClientRole::McpBridge` remains limited to bridge calls, hook events, health,
  and cancellation. It gains no desktop/setup authority.
- Watcher activation occurs after startup native-transaction recovery and MCP
  bridge reconciliation.
- The desktop UI is not a runtime dependency.
- Do not add a third-party dependency; the standard library and pinned
  workspace crates are sufficient.
- Do not run the deferred native Semgrep compilation/Task 9R.

---

### Task 1: Add the sanitized native-hook IPC contract

**Files:**

- Modify: `crates/protocol/src/ipc.rs`
- Modify: `crates/protocol/src/bin/export-bindings.rs`
- Create: `crates/protocol/tests/native_hook_ipc_v1.rs`
- Modify: `crates/local-ipc/src/auth.rs`
- Modify: `crates/local-ipc/tests/ipc_v1.rs`
- Modify: `apps/desktop/src/bindings.ts` (generated)

**Interfaces:**

```rust
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeHookEvent {
    SessionStart { session_id: String },
    SessionStop { session_id: String },
    TaskEvidence {
        session_id: String,
        task_id: TaskId,
        evidence: Vec<CompletionEvidenceInput>,
    },
}

pub struct NativeHookEventParams {
    pub binding: McpBinding,
    pub event: NativeHookEvent,
    pub occurred_at_ms: u64,
}
```

The wire serializer uses the existing decimal-u64 convention. Session IDs are
nonempty and bounded by `MAX_TITLE_BYTES`. Task evidence reuses existing
nonempty evidence validation and limits.

- [ ] **Step 1: Write RED protocol tests**

Cover exact snake-case JSON, decimal timestamp encoding, unknown-field
rejection, empty/oversized session IDs, empty/oversized task evidence, and
invalid native paths.

```bash
cargo test -p context-relay-protocol --test native_hook_ipc_v1
```

Expected RED: hook DTOs and `LocalRequest::NativeHookEvent` do not exist.

- [ ] **Step 2: Implement the bounded DTO and request variant**

Add validation to `LocalRequest::validate`. Use `McpBinding` so harness and
working directory keep the already-frozen path encoding and validation.
`LocalResult::Empty` is the only result.

- [ ] **Step 3: Write RED authorization fixtures**

Prove `McpBridge` may submit `NativeHookEvent`, while `Installer` may not.
Desktop may submit it only for acceptance-test control. Re-run every request
fixture so adding the enum arm cannot reduce coverage.

```bash
cargo test -p context-relay-local-ipc --test ipc_v1
```

- [ ] **Step 4: Implement authorization and regenerate bindings**

Update the exhaustive role match and export the new protocol types. Do not add
a new client role.

```bash
cargo run -p context-relay-protocol --bin export-bindings
npm --prefix apps/desktop test -- --run
```

- [ ] **Step 5: Run focused gates and commit**

```bash
cargo test -p context-relay-protocol
cargo test -p context-relay-local-ipc
cargo fmt --all -- --check
git diff --check
git commit -m "feat: add sanitized native hook events"
```

---

### Task 2: Build the pure native-memory reconciliation engine

**Files:**

- Modify: `crates/core/src/lib.rs`
- Create: `crates/core/src/native_memory/mod.rs`
- Create: `crates/core/src/native_memory/model.rs`
- Create: `crates/core/src/native_memory/debounce.rs`
- Create: `crates/core/src/native_memory/markdown.rs`
- Create: `crates/core/src/native_memory/reconcile.rs`
- Create: `crates/core/tests/native_memory_engine_v1.rs`

**Interfaces:**

```rust
pub const NATIVE_MEMORY_POLL_MS: u64 = 250;
pub const NATIVE_MEMORY_DEBOUNCE_MS: u64 = 750;

pub struct NativeMemorySource { /* bound source metadata, no file bytes */ }
pub struct NativeMemoryLedger { /* persisted digest state */ }
pub enum NativeMemorySnapshot { Absent, Regular(Vec<u8>) }
pub enum ReconcileDecision {
    Pending,
    NoContent,
    AlreadyImported,
    SelfExport,
}

pub fn observe(
    state: &mut DebounceState,
    source_id: NativeMemorySourceId,
    digest: Option<Sha256Digest>,
    now_ms: u64,
) -> Option<StableObservation>;

pub fn reconcile(
    source: &NativeMemorySource,
    ledger: &NativeMemoryLedger,
    bytes: &[u8],
) -> Result<ReconcileDecision, NativeMemoryError>;
```

- [ ] **Step 1: Write RED debounce tests**

Cover 0/749/750 ms, digest reset, independent sources, absence, monotonic-time
regression, and eviction after delivery.

```bash
cargo test -p context-relay-core --test native_memory_engine_v1 debounce
```

- [ ] **Step 2: Implement the minimum debounce state machine**

Use `BTreeMap`, checked time subtraction, and no async/runtime types. A ready
observation is removed only after the caller acknowledges delivery; a busy
worker can therefore retry it.

- [ ] **Step 3: Write RED managed-Markdown tests**

Cover absent fence, one well-formed fence, CRLF preservation, empty unmanaged
content, unmanaged content before/after the fence, body containing sentinels,
and partial/duplicate/nested markers.

```bash
cargo test -p context-relay-core --test native_memory_engine_v1 markdown
```

- [ ] **Step 4: Implement strict fence extraction**

Reuse the existing exact markers. Normalize only final-newline differences for
the unmanaged digest. Do not trim or rewrite candidate Markdown.

- [ ] **Step 5: Write RED reconciliation tests**

Cover self-export, already-imported, empty, initial-preview, and live-edit
decisions. Prove managed content is never returned as candidate content.

- [ ] **Step 6: Implement reconciliation and source identity**

Derive source ID from the versioned canonical tuple using SHA-256. Validate
scope, document kind, path, and limits before hashing.

- [ ] **Step 7: Run focused gates and commit**

```bash
cargo test -p context-relay-core --test native_memory_engine_v1
cargo clippy -p context-relay-core --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
git diff --check
git commit -m "feat: add native memory reconciliation engine"
```

---

### Task 3: Persist source ledgers and atomic native candidates

**Files:**

- Create: `crates/core/migrations/0010_native_memory_reconciliation.sql`
- Modify: `crates/core/src/vault.rs`
- Modify: `crates/core/src/service.rs`
- Modify: `crates/core/src/native_memory/model.rs`
- Modify: `crates/core/src/native_memory/reconcile.rs`
- Create: `crates/core/tests/native_memory_vault_v1.rs`
- Modify: `crates/core/tests/vault_storage_v1.rs`
- Modify: `crates/core/tests/offline_service_v1.rs`

**Interfaces:**

```rust
impl Vault {
    pub fn native_memory_ledger(
        &self,
        id: &NativeMemorySourceId,
    ) -> Result<Option<NativeMemoryLedger>, VaultError>;

    pub fn put_native_memory_candidate(
        &mut self,
        ledger: &NativeMemoryLedger,
        candidate: Option<&MemoryCandidate>,
    ) -> Result<(), VaultError>;
}

impl OfflineWorkspace<'_> {
    pub fn reconcile_native_memory(
        &mut self,
        ready: ReadyNativeMemory,
    ) -> Result<Option<MemoryCandidate>, ClientError>;
}
```

- [ ] **Step 1: Write RED migration/storage tests**

Cover fresh schema, v9-to-v10 migration, global/project scope checks, ledger
round trip, malformed payload rejection, and preservation of all prior records.

```bash
cargo test -p context-relay-core --test vault_storage_v1
cargo test -p context-relay-core --test native_memory_vault_v1 migration
```

- [ ] **Step 2: Add schema v10 and ledger storage**

Use one row per source. Store only digests and validated metadata; never store a
native body outside the existing candidate record.

- [ ] **Step 3: Write RED atomic-candidate tests**

Cover deterministic IDs from `(source_id, unmanaged_digest)`,
`MemoryOrigin::NativeImport`, initial/live evidence labels, exact tags, bound
scope/harness, transaction rollback, retry replay, and conflict on altered
content with the same deterministic identity.

- [ ] **Step 4: Implement candidate construction and one transaction**

Add a native-import-specific builder. Do not call `propose_memory`, which
correctly uses `MemoryOrigin::Inferred`. Candidate insert and ledger advance
must commit together.

- [ ] **Step 5: Write RED review-path regression**

Accepting the pending native candidate must create the proposed memory through
the existing candidate review. Rejecting it must leave no memory. Neither path
changes the source ledger's imported digest.

- [ ] **Step 6: Run focused gates and commit**

```bash
cargo test -p context-relay-core --test native_memory_vault_v1
cargo test -p context-relay-core --test offline_service_v1
cargo test -p context-relay-core --test vault_storage_v1
cargo fmt --all -- --check
git diff --check
git commit -m "feat: persist native memory review state"
```

---

### Task 4: Render the shared primary-memory instruction contract

The 2026-08-10 strengthening amendment treats native task completion as
compatible only when a frozen payload supplies an explicit current Context
Relay task ID and bounded evidence. Until such a bounded payload schema is
captured and reviewed, every harness uses the typed MCP completion instruction
and no model supplies a session ID or bridge path.

**Files:**

- Create: `crates/core/src/native_memory/instruction.rs`
- Modify: `crates/core/src/native_memory/mod.rs`
- Modify: `crates/core/src/claude_code.rs`
- Modify: `crates/core/src/codex.rs`
- Modify: `crates/core/src/hermes/render.rs`
- Modify: `crates/core/tests/claude_code_adapter_v1.rs`
- Modify: `crates/core/tests/codex_adapter_v1.rs`
- Modify: `crates/core/tests/hermes_adapter_v1.rs`

**Interface:**

```rust
pub const PRIMARY_MEMORY_INSTRUCTIONS: &str = "...";

pub fn primary_memory_instruction_component(
    harness: HarnessId,
    project_id: ProjectId,
    origin_device: DeviceId,
    clock: HybridLogicalClock,
) -> Result<ComponentRecord, ClientError>;
```

- [ ] **Step 1: Write RED semantic-contract tests**

Assert the rendered block contains all and only the required behaviors:
session-start search, primary-memory statement, remember, propose, and the
three task-ledger tools. Task completion uses the typed
`context_relay_complete_task` tool with an explicit current Context Relay task
ID and bounded evidence; the instruction contains no bridge executable,
session-ID placeholder, or vendor task identifier. Assert the shared constant
is byte-identical across harnesses.

- [ ] **Step 2: Implement the shared instruction component**

Create adapter-specific metadata/structural locations while keeping the body
shared. Targets are project-root `CLAUDE.md`, `AGENTS.md`, and `.hermes.md`.

- [ ] **Step 3: Write RED native-render tests**

Cover absent target using an existing metadata template, existing unmanaged
content, existing managed block replacement, archive/removal, CRLF, reapply,
rollback, and marker conflicts.

- [ ] **Step 4: Route through existing managed-Markdown planners**

Do not add a second marker format. Preserve each adapter's current topology and
metadata rules.

- [ ] **Step 5: Run focused gates and commit**

```bash
cargo test -p context-relay-core --test claude_code_adapter_v1 primary_memory
cargo test -p context-relay-core --test codex_adapter_v1 primary_memory
cargo test -p context-relay-core --test hermes_adapter_v1 primary_memory
cargo fmt --all -- --check
git diff --check
git commit -m "feat: render primary memory instructions"
```

---

### Task 5: Add version-bound disable settings and source descriptors

**Files:**

- Create: `crates/core/src/native_memory/capability.rs`
- Modify: `crates/core/src/native_memory/mod.rs`
- Modify: `crates/core/src/claude_code.rs`
- Modify: `crates/core/src/codex.rs`
- Modify: `crates/core/src/hermes/render.rs`
- Modify: `crates/core/src/hermes/yaml.rs`
- Modify: `crates/core/tests/fixtures/claude-code-2.1.214.json`
- Modify: `crates/core/tests/fixtures/claude-code-2.1.213.json`
- Modify: `crates/core/tests/fixtures/codex-0.144.1.json`
- Modify: `crates/core/tests/fixtures/codex-0.144.0.json`
- Modify: `crates/core/tests/fixtures/hermes-0.18.2.json`
- Modify: `crates/core/tests/fixtures/hermes-0.18.1.json`
- Modify: all three adapter contract test files

**Interfaces:**

```rust
pub struct NativeMemoryCapabilities {
    pub disable: NativeMemoryDisable,
    pub sources: Vec<NativeMemorySource>,
}

pub enum NativeMemoryDisable {
    Supported(Vec<ApprovedMutation>),
    WatchOnly,
    Unavailable,
}

pub trait NativeMemoryAdapter {
    fn native_memory_capabilities(
        &self,
    ) -> Result<NativeMemoryCapabilities, ClientError>;
}
```

- [ ] **Step 1: Write RED capability-matrix tests**

For each frozen full version assert exact disable keys and exact source paths.
For unknown versions/wrappers assert no mutation. Assert no descriptor contains
`sessions`, `history`, `rollout`, `raw_memories`, a database extension, or an
unbound sibling-project path.

- [ ] **Step 2: Implement Claude capability**

Render only project setting `autoMemoryEnabled: false`. Preserve explicit
`autoMemoryDirectory` if valid and supported. Otherwise bind the frozen default
project-memory path; if exact binding is impossible, return unavailable rather
than scanning sibling project directories. Allow `MEMORY.md` plus bounded
direct topic Markdown files.

- [ ] **Step 3: Implement Codex capability**

Render only:

```toml
[memories]
generate_memories = false
use_memories = false
```

Preserve unrelated tables and comments. Watch only `MEMORY.md` and
`memory_summary.md` under the exact Codex memories root. Do not watch
`raw_memories.md`, rollout summaries, state, history, or sessions.

- [ ] **Step 4: Implement Hermes capability**

Render only:

```yaml
memory:
  memory_enabled: false
  user_profile_enabled: false
```

Preserve all other YAML bytes/values through the existing structural renderer.
Bind profile `MEMORY.md` and `USER.md`.

- [ ] **Step 5: Write RED rollback and policy tests**

Prove prior true/false/absent values restore exactly, managed policy conflicts
block writes, an unsupported setting is never synthesized, and sources remain
watchable after supported disable.

- [ ] **Step 6: Run focused gates and commit**

```bash
cargo test -p context-relay-core --test claude_code_adapter_v1 native_memory
cargo test -p context-relay-core --test codex_adapter_v1 native_memory
cargo test -p context-relay-core --test hermes_adapter_v1 native_memory
cargo fmt --all -- --check
git diff --check
git commit -m "feat: bind native memory capabilities"
```

---

### Task 6: Render lifecycle hooks without content capture

**Files:**

- Create: `crates/core/src/native_memory/hooks.rs`
- Modify: `crates/core/src/claude_code.rs`
- Modify: `crates/core/src/codex.rs`
- Modify: `crates/core/src/hermes/import.rs`
- Modify: `crates/core/src/hermes/render.rs`
- Modify: all three adapter fixtures and adapter contract tests

**Interface:**

```rust
pub fn managed_memory_hooks(
    harness: HarnessId,
    bridge_executable: &WireNativeValue,
) -> Result<Vec<ComponentRecord>, ClientError>;
```

- [ ] **Step 1: Write RED exact-hook tests**

Claude full versions render `SessionStart` and `Stop`. Their frozen fixtures
record the vendor `TaskCompleted` event separately from the Context
Relay-compatible event allowlist. Its bounded payload schema has not been
captured or reviewed, so compatibility is not proven and the event remains
disabled. Codex renders `SessionStart` and `Stop`. Hermes renders only
compatible events present in its frozen fixture contract. Unsupported events
are absent, not emulated through a different trigger; task completion remains
available through the typed MCP instruction.

- [ ] **Step 2: Implement canonical argv generation**

Every command uses the attested installed bridge executable plus literal
arguments:

```text
--hook-event <event> --harness <harness>
```

No shell interpolation, transcript path, or user-controlled argument enters
the command.

- [ ] **Step 3: Write RED merge/rollback tests**

Prove unrelated user hooks survive, the managed hook is deduplicated, reapply
is byte-stable, and rollback restores exact prior bytes. Codex project hook
trust limitations remain enforced.

- [ ] **Step 4: Implement through existing hook planners**

Keep the existing supported native formats: Claude settings hooks, Codex
hooks/config structures, and Hermes frozen hook structures. Do not add a new
script file or Python dependency.

- [ ] **Step 5: Run focused gates and commit**

```bash
cargo test -p context-relay-core --test claude_code_adapter_v1 memory_hooks
cargo test -p context-relay-core --test codex_adapter_v1 memory_hooks
cargo test -p context-relay-core --test hermes_adapter_v1 memory_hooks
cargo fmt --all -- --check
git diff --check
git commit -m "feat: render product memory lifecycle hooks"
```

---

### Task 7: Add strict hook mode to the MCP bridge

**Files:**

- Create: `crates/context-mcp/src/hook.rs`
- Modify: `crates/context-mcp/src/lib.rs`
- Modify: `crates/context-mcp/src/main.rs`
- Modify: `crates/context-mcp/src/daemon.rs`
- Create: `crates/context-mcp/tests/hook_v1.rs`
- Modify: `crates/context-mcp/tests/stdout_v1.rs`
- Modify: `crates/context-mcp/tests/lifecycle_v1.rs`

**Interfaces:**

```rust
pub enum Invocation {
    Mcp { harness: HarnessId },
    Hook { harness: HarnessId, event: HookInvocationKind },
}

pub fn project_hook_input(
    harness: HarnessId,
    event: HookInvocationKind,
    bytes: &[u8],
    cwd: &Path,
    now_ms: u64,
) -> Result<NativeHookEventParams, BridgeError>;
```

- [ ] **Step 1: Write RED CLI parser tests**

Cover exact MCP invocation compatibility, all supported hook invocations,
duplicate/missing/unknown arguments, non-UTF-8 arguments, and trailing tokens.

- [ ] **Step 2: Implement one strict invocation parser**

Do not loosen `parse_harness` semantics for MCP startup. Dispatch hook mode
before starting Tokio stdio MCP framing.

- [ ] **Step 3: Write RED vendor-projector tests**

Fixtures must contain memorable sentinel strings in `prompt`, `response`,
`last_assistant_message`, `transcript_path`, tool input/output, and unknown
nested objects. Assert none of those strings appear in the serialized local
request, stdout, stderr, debug formatting, or returned error.

Assert only session ID, event kind, working directory, and explicit task
evidence survive. Bound stdin before parse and reject malformed/oversized
input.

- [ ] **Step 4: Implement allowlist projectors**

Parse into `serde_json::Value` only after the byte bound. Extract required
allowlisted scalar fields by exact event/harness. Never open
`transcript_path`. Generate the timestamp locally.

- [ ] **Step 5: Write RED daemon-call/output tests**

Hook mode connects as `McpBridge`, sends exactly one native-hook request, and
exits. Session start prints only the fixed bounded reminder after
acknowledgement. Stop/evidence print no stdout. Daemon unavailable and protocol
errors print one redacted error with no input echo.

- [ ] **Step 6: Implement hook delivery**

Reuse `LocalDaemon` connection/token behavior. Do not run an MCP server in hook
mode.

- [ ] **Step 7: Run focused gates and commit**

```bash
cargo test -p context-relay-context-mcp --test hook_v1
cargo test -p context-relay-context-mcp --test stdout_v1
cargo test -p context-relay-context-mcp --test lifecycle_v1
cargo fmt --all -- --check
git diff --check
git commit -m "feat: deliver sanitized harness lifecycle events"
```

---

### Task 8: Route hook events and task evidence in the daemon

**Files:**

- Create: `crates/core/migrations/0011_native_hook_sessions.sql`
- Modify: `crates/core/src/vault.rs`
- Modify: `crates/contextd/src/lib.rs`
- Create: `crates/contextd/tests/native_hook_v1.rs`
- Modify: `crates/core/src/service.rs`
- Modify: `crates/core/tests/offline_service_v1.rs`

- [ ] **Step 1: Write RED routing tests**

Prove hook events enter the vault worker, respect role authorization, resolve
the longest canonical registered project root, reject ambiguity, and return
`Empty`. No project match is an acknowledged no-op.

- [ ] **Step 2: Implement routing**

Add `LocalRequest::NativeHookEvent` to the workspace worker path. Reuse the MCP
project resolver; do not trust a project ID from the event.

- [ ] **Step 3: Write RED event-handling and storage tests**

Add `native_hook_sessions`, keyed by `(harness, session_id)`, with project ID,
start time, optional stop time, and validated payload JSON. Session start/stop
upsert only that bounded lifecycle metadata. A v10-to-v11 migration preserves
every existing record. Task evidence updates only the identified existing task
using its expected current revision and existing evidence limits. A
missing/stale task is a conflict, not an inferred new task.

Assert hook DTO JSON contains no conversation-content fields and raw fixture
session files remain byte-identical.

- [ ] **Step 4: Implement minimal event handling**

Add narrow vault APIs for the sanitized session row. Task evidence reuses the
service's task transition/completion machinery and never updates task JSON
directly. Bound retained session rows with deterministic replacement by the
same `(harness, session_id)` identity; no append-only event log is introduced.

- [ ] **Step 5: Run focused gates and commit**

```bash
cargo test -p context-relay-contextd --test native_hook_v1
cargo test -p context-relay-core --test offline_service_v1
cargo test -p context-relay-local-ipc
cargo fmt --all -- --check
git diff --check
git commit -m "feat: handle product memory hook events"
```

---

### Task 9: Run the daemon-owned watcher and one-time preview

**Files:**

- Create: `crates/contextd/src/native_memory.rs`
- Modify: `crates/contextd/src/lib.rs`
- Modify: `crates/core/src/native_memory/mod.rs`
- Modify: `crates/core/src/native_memory/reconcile.rs`
- Modify: `crates/core/src/setup.rs`
- Create: `crates/contextd/tests/native_memory_watch_v1.rs`
- Modify: `crates/contextd/tests/harness_setup_v1.rs`

**Interfaces:**

```rust
struct NativeMemorySupervisor { /* join handle and shutdown channel */ }

enum VaultCommand {
    // existing variants
    NativeMemoryObservation(ReadyNativeMemory),
}
```

- [ ] **Step 1: Write RED supervisor-ordering tests**

Use injected clocks/probes. Prove no probe runs before vault open, startup
native recovery, and bridge reconciliation. Prove startup failure launches no
supervisor. Prove daemon shutdown joins it before vault teardown.

- [ ] **Step 2: Implement lifecycle with injected boundaries**

Use a Tokio task for the 250 ms schedule and existing safe native filesystem
snapshots for file reads. The task owns no SQLite connection. It submits ready
observations to the bounded worker and retains them when the queue is busy.

- [ ] **Step 3: Write RED initial-preview tests**

Existing nonempty content produces one pending candidate. Restart produces no
duplicate. Missing/empty/managed-only files merely mark the initial preview
complete. An unsupported topology never advances the ledger.

- [ ] **Step 4: Implement descriptor registration and initial scan**

Register sources only after a successful Task 14 setup apply. Reload persisted
descriptors/digests at daemon start. Make initial/live classification explicit
in the ready observation.

- [ ] **Step 5: Write RED live-edit/debounce tests**

Modify a real fixture file twice inside 749 ms and once after 750 ms. Assert one
candidate for the final stable content. Cover delete/recreate, atomic rename,
busy worker retry, oversized content, link replacement, and identity race.

- [ ] **Step 6: Implement polling and worker reconciliation**

Digest a file only after safe snapshot. Keep polling bounds and file limits
per descriptor. Submit candidate/ledger changes through
`OfflineWorkspace::reconcile_native_memory`.

- [ ] **Step 7: Write RED export-loop tests**

Record an intended managed digest, apply it through the native transaction
engine, observe it, and assert no candidate. Then add an unmanaged paragraph
and assert only that paragraph becomes a pending candidate.

- [ ] **Step 8: Bind applied digests to native plan state**

Record the intended digest with the sealed plan/ledger transition so recovery
can resume idempotently. Watcher startup remains after recovery.

- [ ] **Step 9: Run focused gates and commit**

Unix-socket daemon tests may require the existing approved unsandboxed test
route.

```bash
cargo test -p context-relay-contextd --test native_memory_watch_v1
cargo test -p context-relay-contextd --test harness_setup_v1
cargo test -p context-relay-core --test native_memory_vault_v1
cargo fmt --all -- --check
git diff --check
git commit -m "feat: reconcile native memory in contextd"
```

---

### Task 10: Compose memory setup into transactional harness apply

**Files:**

- Modify: `crates/core/src/setup.rs`
- Modify: `crates/core/src/native_transaction/model.rs`
- Modify: `crates/core/src/native_transaction/approval.rs`
- Modify: `crates/core/src/native_memory/capability.rs`
- Modify: `crates/core/src/native_memory/hooks.rs`
- Modify: all three adapter implementations
- Modify: `crates/contextd/src/lib.rs`
- Modify: `crates/contextd/tests/harness_setup_v1.rs`
- Create: `crates/core/tests/primary_memory_setup_v1.rs`
- Modify: `crates/core/tests/native_approval_v2.rs`

- [ ] **Step 1: Write RED preview-composition tests**

One preview must classify and seal the canonical MCP bridge, primary-memory
instruction, supported disable setting, managed hooks, and source descriptor
registration. Preview performs no native mutation. Batch hash changes if any
member changes.

- [ ] **Step 2: Extend bridge setup composition**

Preserve the existing public IPC methods and service type names. Extend
`BridgeInstallService::preview` to build one `DesiredState` and one sealed
native transaction plan for bridge plus Task 14 surfaces. Add validated source
descriptors to `NativeTransactionPlan` and the approval-v2 preimage. Prove a
descriptor path, limit, scope, or document-kind change changes the approval
hash. Claude/Codex bridge CLI mutation and file/config mutations may coexist
only when approval-v2 validation binds both exact classes. Hermes remains
native-only.

- [ ] **Step 3: Write RED apply/rollback/recovery tests**

Cover all three harnesses:

- apply produces exact config/instruction/hook changes;
- source descriptors activate only after successful apply;
- reapply is idempotent;
- live divergence is conflict;
- rollback restores config/instruction/hooks and unregisters only Task 14
  sources from that plan;
- crash recovery converges before watcher activation;
- raw session/history fixtures remain byte-identical.

- [ ] **Step 4: Implement transactional composition**

Reuse existing before-images, CLI WAL, native mutation ordering, and approval
hash. Do not add an out-of-band config write for any Task 14 surface.

- [ ] **Step 5: Run focused gates and commit**

```bash
cargo test -p context-relay-core --test primary_memory_setup_v1
cargo test -p context-relay-contextd --test harness_setup_v1
cargo test -p context-relay-core --test native_approval_v2
cargo test -p context-relay-core --test native_cli_journal_v1
cargo fmt --all -- --check
git diff --check
git commit -m "feat: transact authoritative memory setup"
```

---

### Task 11: Prove Task 14 acceptance end to end

**Files:**

- Create: `crates/contextd/tests/authoritative_memory_v1.rs`
- Modify: `crates/context-mcp/tests/end_to_end_v1.rs`
- Modify: `apps/desktop/src/offline-workflow.test.tsx`
- Modify: `README.md`
- Create: `docs/verification/task-14.md`
- Create: `adapters/claude-code/capabilities.md`
- Create: `adapters/codex/capabilities.md`
- Modify: `adapters/hermes/capabilities.md`

- [ ] **Step 1: Write the acceptance fixture**

Start a real daemon with a registered project and frozen harness fixture, apply
setup, close/drop the desktop test client, edit a declared native memory file,
advance past 750 ms, reconnect, and assert the pending candidate appears.

Then accept the candidate and query it through `context_relay_search` from the
MCP bridge. Assert instruction and task-ledger contract files remain present
while no desktop client is connected.

- [ ] **Step 2: Add the self-export and unsupported-version acceptance cases**

Prove a Context Relay managed export never becomes a candidate. Prove an
unknown/import-only harness version receives no disable key and reports
watch-only/unavailable according to its exact source binding.

- [ ] **Step 3: Add the hook privacy sentinel acceptance case**

Run session-start, stop, and task-evidence hook modes with unique sentinel
strings in every excluded content field. Search all test-owned vault rows,
native outputs, captured stdout/stderr, and IPC fixtures; none may contain a
sentinel. Assert raw session fixture digests are unchanged.

- [ ] **Step 4: Update documentation and acceptance ledger**

Document the primary-memory contract, supported settings, one-time preview,
review queue, 750 ms observation, hook field allowlist, and desktop-independent
runtime. Mark Task 14 complete only after all gates below pass.

- [ ] **Step 5: Run focused and adjacent suites**

```bash
cargo test -p context-relay-protocol
cargo test -p context-relay-local-ipc
cargo test -p context-relay-core
cargo test -p context-relay-context-mcp
cargo test -p context-relay-contextd
npm --prefix apps/desktop test -- --run
npm --prefix apps/desktop run lint
npm --prefix apps/desktop run typecheck
```

- [ ] **Step 6: Run strict repository gates**

Use the pinned direct Rust toolchain and fresh Cargo home documented in the
goal handoff when the ambient Rustup cache is unavailable. Restore the two
tracked rusqlite `Cargo.lock` source lines with `apply_patch` after commands
that use local path patches.

```bash
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
git diff --check
git status --short
```

The full workspace gate excludes only the already documented native-runner
environment cases if macOS provenance metadata still makes those exact
fixtures inapplicable. Do not weaken or modify their expected behavior as part
of Task 14.

- [ ] **Step 7: Independent ordinary code review**

Request a correctness/regression review of the Task 14 diff. Address every
validated finding with a new failing regression test before the fix. Do not use
a cybersecurity review workflow.

- [ ] **Step 8: Final implementation commit**

```bash
git commit -m "feat: make Context Relay the primary harness memory"
```

- [ ] **Step 9: Publish and synchronize the checkpoint**

Push `codex/mcp-memory-task-bridge`, fetch and fast-forward
`/Users/skytuhua/Desktop/Context-Relay`, verify local/remote/Desktop heads are
identical, and verify both worktrees are clean. Then update the active goal plan
and continue directly to Task 15.

## Completion Evidence

Record exact counts and commands in the Task 14 acceptance ledger. Completion
requires evidence for each roadmap assertion:

- native-memory edit appears automatically;
- Context Relay export does not re-import itself;
- unsupported disable settings are never guessed;
- raw session files are untouched;
- existing native memory is previewed once;
- lifecycle/task evidence excludes conversation content;
- primary instructions and MCP access work with the desktop closed.
