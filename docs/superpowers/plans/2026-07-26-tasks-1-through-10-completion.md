# Tasks 1 Through 10 Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish every requirement in Tasks 1 through 10, prove the final
source locally and on hosted Windows/macOS runners, configure the required live
GitHub governance, and leave `main` and `codex/bootstrap-v1` at the same
verified commit.

**Architecture:** Extend the existing encrypted Vault and single-writer daemon
instead of adding a second persistence path. The Tauri desktop remains a typed
IPC client, and the Claude Code adapter continues using the existing
`HarnessAdapter` and native-transaction boundaries. Task 9 remains the
single-build V1; release qualification stays isolated in Task 9R.

**Tech Stack:** Rust 1.97.1, SQLCipher/rusqlite, Tokio local IPC, Tauri 2,
React 19, TypeScript 5.9, Vitest/Testing Library, Node 24, pnpm 11, GitHub
Actions and repository rulesets.

## Global Constraints

- Preserve untracked `.codex/`, `AGENTS.md`, and `graphify-out/`.
- Do not execute Task 9R or manually publish a release.
- Do not rebuild native Semgrep for evidence-only changes.
- Preserve all Task 9 runtime isolation, hash, report, no-Python, private-root,
  frozen-command, and output-boundary controls.
- The daemon is the only SQLCipher writer; desktop and MCP clients use typed
  authenticated IPC only.
- Unknown Claude Code versions remain import-only.
- OAuth, trust, session, cache, project-history, unmanaged Markdown, and
  unmanaged JSON remain untouched.
- No new production dependency is introduced.
- Every behavioral change follows RED/GREEN TDD.
- Run `graphify update .` after code changes.
- Push the same commit atomically to `main` and `codex/bootstrap-v1`.

---

### Task 1: Add Vault primitives for the offline workspace

**Files:**

- Create: `crates/core/migrations/0002_offline_workspace.sql`
- Modify: `crates/core/src/vault.rs`
- Test: `crates/core/tests/offline_workspace_v1.rs`

**Interfaces:**

- Produces:
  - `Vault::put_project(&ProjectIdentity) -> Result<(), VaultError>`
  - `Vault::projects() -> Result<Vec<ProjectIdentity>, VaultError>`
  - `Vault::memories(Option<ProjectId>, bool) -> Result<Vec<MemoryRecord>, VaultError>`
  - `Vault::put_local_memory(&MemoryRecord, &Embedding384) -> Result<(), VaultError>`
  - `Vault::candidates(Option<ProjectId>) -> Result<Vec<MemoryCandidate>, VaultError>`
  - `Vault::review_candidate(CandidateId, CandidateState, Option<&MemoryRecord>, Option<&Embedding384>) -> Result<(), VaultError>`
  - `Vault::tasks(ProjectId) -> Result<Vec<TaskRecord>, VaultError>`
  - `Vault::set_access_policy(HarnessId, &HarnessAccessPolicy) -> Result<(), VaultError>`
  - `Vault::access_policy(HarnessId) -> Result<HarnessAccessPolicy, VaultError>`
- Preserves the current `put_memory` signed-operation path for later sync.

- [ ] **Step 1: Write failing Vault tests**

Add tests proving project ordering, scoped memory listing, archived filtering,
candidate filtering, task ordering, access-policy persistence, restart
durability, and duplicate/idempotent writes:

```rust
#[test]
fn offline_records_survive_restart_and_remain_scope_filtered() {
    let fixture = Fixture::new();
    let mut vault = fixture.open();
    vault.put_project(&project()).unwrap();
    vault
        .put_local_memory(&memory(), &embedding("alpha"))
        .unwrap();
    vault.put_candidate(&candidate()).unwrap();
    vault.put_task(&task()).unwrap();
    drop(vault);

    let vault = fixture.open();
    assert_eq!(vault.projects().unwrap(), vec![project()]);
    assert_eq!(
        vault.memories(Some(project().project_id), false).unwrap(),
        vec![memory()]
    );
    assert_eq!(vault.candidates(Some(project().project_id)).unwrap(), vec![candidate()]);
    assert_eq!(vault.tasks(project().project_id).unwrap(), vec![task()]);
}
```

- [ ] **Step 2: Run the focused test and verify RED**

Run:

```powershell
cargo test -p context-relay-core --test offline_workspace_v1 --all-features
```

Expected: compilation fails because the listed Vault methods do not exist.

- [ ] **Step 3: Add the migration and minimal Vault methods**

The migration adds only locally required metadata tables:

```sql
CREATE TABLE projects (
    id TEXT PRIMARY KEY,
    payload_json BLOB NOT NULL
);

CREATE TABLE harness_access (
    harness TEXT PRIMARY KEY CHECK (harness IN ('claude_code', 'codex', 'hermes')),
    payload_json BLOB NOT NULL
);
```

Implement list queries by reading existing encrypted `records`, `candidates`,
and `tasks` payloads. `put_local_memory` reuses `put_searchable_record`, FTS,
embedding storage, provenance storage, and the embedding cache but does not
enqueue an unsigned sync operation.

- [ ] **Step 4: Run focused Vault and migration tests**

Run:

```powershell
cargo test -p context-relay-core --test offline_workspace_v1 --all-features
cargo test -p context-relay-core --test vault_storage_v1 --all-features
cargo test -p context-relay-core --test vault_v1 --all-features
```

Expected: PASS.

- [ ] **Step 5: Commit the Vault slice**

```powershell
git add -- crates/core/migrations/0002_offline_workspace.sql crates/core/src/vault.rs crates/core/tests/offline_workspace_v1.rs
git commit -m "feat: add offline workspace storage"
```

---

### Task 2: Implement revision-safe offline domain operations

**Files:**

- Create: `crates/core/src/service.rs`
- Modify: `crates/core/src/lib.rs`
- Test: `crates/core/tests/offline_service_v1.rs`

**Interfaces:**

- Produces `OfflineWorkspace<'a>` backed by `&'a mut Vault` and a stable local
  `DeviceId` supplied by the daemon.
- Consumes the existing protocol request DTOs and returns existing domain
  records.
- Operation IDs supply deterministic create IDs and revisions, making retries
  idempotent without a second idempotency table.

- [ ] **Step 1: Write failing service tests**

Cover memory create/get/update/archive/search, revision conflict, candidate
accept/reject, task create/update/transition/complete with evidence, project
and path mapping, and retries:

```rust
#[test]
fn memory_update_rejects_a_stale_revision_without_changing_the_record() {
    let mut fixture = ServiceFixture::new();
    let created = fixture.service().create_memory(create_params()).unwrap();
    let stale = OperationId::new(Uuid::now_v7()).unwrap();

    let error = fixture
        .service()
        .update_memory(update_params(created.id, stale))
        .unwrap_err();

    assert_eq!(error.code, ErrorCode::RevisionConflict);
    assert_eq!(fixture.service().memory(created.id).unwrap(), Some(created));
}
```

- [ ] **Step 2: Run the focused test and verify RED**

```powershell
cargo test -p context-relay-core --test offline_service_v1 --all-features
```

Expected: compilation fails because `OfflineWorkspace` does not exist.

- [ ] **Step 3: Implement the minimum service**

Use operation UUIDv7 values as create identifiers:

```rust
fn memory_id(operation_id: OperationId) -> Result<MemoryId, ClientError> {
    MemoryId::new(operation_id.into_uuid())
        .map_err(|_| invalid_request("operationId"))
}
```

Use the operation UUID timestamp for HLC physical time and the daemon's stable
local device ID for the HLC node. Use a deterministic normalized 384-dimension
token-hash embedding for both record and query text so hybrid search works
offline without downloading a model. Keep this helper private and test
normalization plus token-overlap ranking.

Every update compares `expected_revision` before writing. Candidate acceptance
uses `Vault::review_candidate` so the proposed memory and candidate state are
written in one Vault transaction.
Task completion converts `CompletionEvidenceInput` into bounded
`TaskEvidence`.

- [ ] **Step 4: Run focused service and search tests**

```powershell
cargo test -p context-relay-core --test offline_service_v1 --all-features
cargo test -p context-relay-core --test search_v1 --all-features
```

Expected: PASS.

- [ ] **Step 5: Commit the service slice**

```powershell
git add -- crates/core/src/service.rs crates/core/src/lib.rs crates/core/tests/offline_service_v1.rs
git commit -m "feat: add offline memory and task services"
```

---

### Task 3: Route every required Task 7 IPC family

**Files:**

- Modify: `crates/protocol/src/ipc.rs`
- Modify: `crates/protocol/src/mcp.rs`
- Modify: `crates/protocol/src/bin/export-bindings.rs`
- Modify: `crates/protocol/src/bin/export-schemas.rs`
- Modify: `crates/contextd/src/lib.rs`
- Modify: `crates/contextd/tests/` only if a platform integration test belongs
  outside the existing unit-test module
- Modify generated: `apps/desktop/src/bindings.ts`
- Modify generated: `schemas/`

**Interfaces:**

- Adds `ProjectUpsert(ProjectUpsertParams)` so the desktop can establish a
  local project identity before binding its path.
- Adds `SyncState::Offline` as an additive protocol-v1 state.
- Extends `VaultCommand` so all database-backed work stays on the one worker.

- [ ] **Step 1: Add RED protocol and daemon routing tests**

Protocol tests must reject malformed project names and accept the additive
offline status. Daemon tests must assert that no Task 7 request family returns
the generic unavailable error:

```rust
#[tokio::test]
async fn required_local_methods_never_fall_through_to_generic_unavailable() {
    let daemon = fixture_daemon().await;
    for request in required_task_7_requests() {
        let result = daemon.call(request).await;
        assert_ne!(
            result.err().map(|error| error.message),
            Some("This service is not available in this build".into())
        );
    }
}
```

- [ ] **Step 2: Run protocol/contextd tests and verify RED**

```powershell
cargo test -p context-relay-protocol --all-features
cargo test -p context-relay-contextd --all-features
```

Expected: the new protocol and routing assertions fail.

- [ ] **Step 3: Implement real worker routing**

Route projects, memories, candidates, tasks, handoffs, access, export, sync
status, and device status to the worker. Preserve typed behavior for later
online features:

- `sync_status` returns `SyncState::Offline`;
- `sync_retry`, pairing, and recovery return a typed `HarnessUnsupported` or
  `ApprovalRequired` error explaining that hosted configuration is absent;
- harness and package requests invoke an available local adapter/inspector or
  return typed `HarnessUnsupported`, never the generic build placeholder;
- account deletion maintains a local state machine and requires the existing
  confirmation field;
- export produces bounded encrypted-vault-derived chunks without exposing
  secrets in logs.

- [ ] **Step 4: Re-run all IPC security and daemon tests**

```powershell
cargo test -p context-relay-protocol --all-features
cargo test -p context-relay-local-ipc --all-features
cargo test -p context-relay-contextd --all-features
node --test scripts/check-daemon-boundary.test.mjs
node scripts/check-daemon-boundary.mjs
pnpm check:bindings
pnpm check:schemas
```

Expected: PASS, including singleton, cross-user denial, wrong-token denial,
pre-allocation frame rejection, restart durability, bounded queue,
cancellation, timeouts, and single-writer checks.

- [ ] **Step 5: Commit the daemon slice**

```powershell
git add -- crates/protocol crates/contextd apps/desktop/src/bindings.ts schemas
git commit -m "feat: complete local daemon services"
```

---

### Task 4: Build the complete networking-disabled desktop workflow

**Files:**

- Create: `apps/desktop/src/local-client.ts`
- Create: `apps/desktop/src/workspace.ts`
- Modify: `apps/desktop/src/App.tsx`
- Modify: `apps/desktop/src/App.test.tsx`
- Modify: `apps/desktop/src/styles.css`
- Test: `apps/desktop/src/offline-workflow.test.tsx`
- Test: `apps/desktop/src/local-client.test.ts`

**Interfaces:**

- `LocalClient.call(request: LocalRequest): Promise<LocalResult>` wraps only
  `invoke('local_request', { request })`.
- `WorkspaceGateway` exposes typed projects, memories, candidates, tasks, and
  status operations to React.
- Tests inject a fake `WorkspaceGateway`; production uses the Tauri client.

- [ ] **Step 1: Write RED typed-client and end-to-end component tests**

The workflow test covers project creation/path mapping, memory
create/edit/archive/search, candidate accept/reject, task
create/edit/transition/complete/evidence, and offline status:

```tsx
it('completes memory and task work with networking disabled', async () => {
  const gateway = new FakeWorkspaceGateway();
  render(<App gateway={gateway} />);

  await createProjectAndPath();
  await createAndEditMemory();
  await searchForMemory();
  await acceptCandidate();
  await createAndCompleteTaskWithEvidence();

  expect(gateway.networkCalls).toBe(0);
  expect(screen.getByText('Offline')).toBeVisible();
});
```

Add tests proving every navigation/action is keyboard reachable, validation
errors are associated with controls, destructive dialogs restore trigger
focus, and no code references `localStorage`, `sessionStorage`, or
`indexedDB`.

- [ ] **Step 2: Run desktop tests and verify RED**

```powershell
pnpm --filter @context-relay/desktop test --run
```

Expected: the workflow fails because the current shell reports service
unavailable.

- [ ] **Step 3: Implement the typed client and bounded workspace state**

Use the generated `LocalRequest` and `LocalResult` unions directly. Keep only
the active lists and selected records in React state; refetch after mutations.
Do not cache keys, tokens, or the whole Vault in the browser.

Split navigation sections into focused components only where the existing
`App.tsx` would otherwise retain multiple independent forms in one component.
Use native form controls and `<dialog>` behavior, with explicit focus
restoration already established by the shell.

- [ ] **Step 4: Run frontend verification**

```powershell
pnpm lint
pnpm typecheck
pnpm test --run
pnpm build
cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml --all-features
```

Expected: PASS.

- [ ] **Step 5: Commit the desktop slice**

```powershell
git add -- apps/desktop
git commit -m "feat: add offline desktop memory workspace"
```

---

### Task 5: Complete Claude Code discovery and effective validation

**Files:**

- Modify: `crates/core/src/claude_code.rs`
- Modify: `crates/core/tests/claude_code_adapter_v1.rs`
- Modify: `crates/core/tests/fixtures/claude-code-2.1.213.json`
- Modify: `crates/core/tests/fixtures/claude-code-2.1.214.json`

**Interfaces:**

- Private `ClaudeCommand` builds a closed argv and bounded execution policy.
- Private parsers accept reviewed `doctor`, plugin JSON, MCP list, and MCP get
  outputs.
- `plan_native_file` returns `ApprovedMutation` for managed Markdown blocks
  using the existing native transaction fingerprints.

- [ ] **Step 1: Add RED fixture and command-policy tests**

Extend both golden fixtures with:

```json
{
  "doctorOutput": "Claude Code diagnostics: OK\n",
  "pluginListJson": [{"id":"formatter@team","version":"1.2.3","enabled":true,"errors":[]}],
  "mcpListOutput": "docs: https://example.com/mcp (HTTP)\n",
  "mcpGetOutput": {"name":"docs","type":"http","url":"https://example.com/mcp"},
  "projectMcpApprovals": {
    "enableAllProjectMcpServers": false,
    "enabledMcpjsonServers": ["docs"],
    "disabledMcpjsonServers": ["blocked"]
  }
}
```

Tests assert the exact official argv:

```rust
assert_eq!(commands, vec![
    vec!["doctor"],
    vec!["plugin", "list", "--json"],
    vec!["mcp", "list"],
    vec!["mcp", "get", "docs"],
]);
```

Tests also prove validation never starts an MCP server, malformed or unbounded
output fails closed, and output secrets are redacted or rejected.

- [ ] **Step 2: Run the Claude adapter test and verify RED**

```powershell
cargo test -p context-relay-core --test claude_code_adapter_v1 --all-features
```

Expected: new discovery/validation and approval assertions fail.

- [ ] **Step 3: Implement bounded official CLI validation**

Run `--version` and `doctor` during discovery. For supported versions,
effective validation runs `plugin list --json`, `mcp list`, then `mcp get` for
only the bounded names discovered from reviewed configuration. Apply the
existing timeout, output-size, executable-hash, and safe-error policies.

Parse native project approval keys only from the reviewed project settings:

```rust
const PROJECT_MCP_APPROVAL_KEYS: [&str; 3] = [
    "enableAllProjectMcpServers",
    "enabledMcpjsonServers",
    "disabledMcpjsonServers",
];
```

Detect these fields and report conflicts or approval state without mutating
them. Continue checking `hasTrustDialogAccepted` only as native trust state.

- [ ] **Step 4: Add RED Markdown transaction tests**

Test a file containing unmanaged text before and after a managed block:

```markdown
# User preface

<!-- context-relay:start -->
old managed text
<!-- context-relay:end -->

User footer
```

Assert apply changes only the block, a concurrent edit invalidates the plan,
and rollback restores the exact original bytes. Cover `CLAUDE.md`, rules, and
skills.

- [ ] **Step 5: Implement managed-block file mutations**

Reuse `ApprovedMutation`, `NativeState`, and
`RestorableStateFingerprint`. Refuse multiple, nested, reversed, malformed, or
oversized marker pairs. For unmanaged files without markers, require explicit
creation of one bounded managed block rather than replacing the file.

- [ ] **Step 6: Run focused and native transaction tests**

```powershell
cargo test -p context-relay-core --test claude_code_adapter_v1 --all-features
cargo test -p context-relay-core --test native_transaction_v1 --all-features
cargo test -p context-relay-core --test native_recovery_v1 --all-features
```

Expected: PASS.

- [ ] **Step 7: Commit exactly the Task 10 deliverable**

```powershell
git add -- crates/core/src/claude_code.rs crates/core/tests/claude_code_adapter_v1.rs crates/core/tests/fixtures/claude-code-2.1.213.json crates/core/tests/fixtures/claude-code-2.1.214.json
git commit -m "feat: add Claude Code adapter"
```

---

### Task 6: Reverify Tasks 1 through 10 locally

**Files:**

- Modify: `.superpowers/sdd/progress.md`
- Modify only if evidence changed: `third_party/sidecars/semgrep/MANIFEST.sha256.md`

- [ ] **Step 1: Run Task 9 non-native material tests**

```powershell
node --test scripts/apply-semgrep-source-patches.test.mjs
node --test scripts/hydrate-sidecars.test.mjs
node --test scripts/native-ci-workflow.test.mjs
node --test scripts/native-smoke-evidence.test.mjs
node --test scripts/prepare-semgrep-runtime.test.mjs
node --test scripts/semgrep-source-bundle.test.mjs
```

Expected: PASS. Do not run Task 9R or rebuild Semgrep.

- [ ] **Step 2: Run complete local verification**

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo test -p context-relay-core --release --test search_v1 search_10k_p95_is_below_150ms_with_warm_injected_query_embedding -- --ignored --exact --nocapture
pnpm lint
pnpm typecheck
pnpm test --run
pnpm build
pnpm check:bindings
pnpm check:schemas
pnpm license:check
cargo deny check
git diff --check
graphify update .
```

Expected: every command passes; the search P95 remains below 150 ms.

- [ ] **Step 3: Update the requirement ledger**

Record exact current evidence for each requirement. State explicitly that Task
9 V1 is single-build-per-platform and Task 9R remains deferred.

- [ ] **Step 4: Commit verification metadata**

```powershell
git add -- .superpowers/sdd/progress.md
git commit -m "docs: verify Tasks 1-10 completion"
```

---

### Task 7: Push, obtain hosted proof, and apply GitHub governance

**Files:** Live GitHub repository settings plus the already committed policy
files.

- [ ] **Step 1: Confirm source state before push**

```powershell
git status --short
git diff --check
git rev-parse HEAD
git rev-parse main
git rev-parse codex/bootstrap-v1
```

Expected: only protected untracked paths remain and both local branches can
fast-forward to `HEAD`.

- [ ] **Step 2: Atomically push both branches**

```powershell
git push --atomic origin HEAD:refs/heads/main HEAD:refs/heads/codex/bootstrap-v1
```

- [ ] **Step 3: Run one final hosted V1 matrix**

Retain one exact-tip run with successful Rust, frontend, Windows native, macOS
native, Windows Task 9 isolation, and macOS Task 9 isolation jobs. Do not
dispatch publication and do not run Task 9R.

- [ ] **Step 4: Apply live repository settings**

Use GitHub's repository and ruleset APIs to enable:

- secret scanning, push protection, non-provider patterns, validity checks;
- Dependabot alerts and security updates;
- private vulnerability reporting;
- Actions read-only default token;
- squash-only merging;
- `main` pull request, zero approvals, required exact-tip CI checks,
  conversation resolution, linear history, no force push/delete, owner-only
  emergency bypass;
- `v*` update/delete protection.

- [ ] **Step 5: Verify live protections**

Read every setting back through the API. Push a disposable branch containing a
synthetic push-protection test pattern and require GitHub to reject it. Do not
use a real credential.

- [ ] **Step 6: Run the final completion audit**

For every requirement in Tasks 1 through 10, link one authoritative current
source, local check, hosted job, or live GitHub response. Treat missing or
indirect evidence as incomplete.

- [ ] **Step 7: Confirm final GitHub handoff**

```powershell
git fetch origin
git rev-parse HEAD
git rev-parse main
git rev-parse codex/bootstrap-v1
git rev-parse origin/main
git rev-parse origin/codex/bootstrap-v1
```

Expected: all five revisions are identical to the hosted verified commit.
