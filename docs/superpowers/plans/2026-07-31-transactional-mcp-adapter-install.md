# Transactional MCP Adapter Installation Implementation Plan

> Inserted prerequisite for Task 8 of
> `2026-07-30-mcp-memory-tasks-handoffs.md`.

**Goal:** Make the existing harness preview/apply/rollback IPC operations
install the canonical Context Relay MCP bridge through approval-bound,
crash-recoverable adapter transactions.

**Architecture:** Canonical bridge declarations remain pure adapter data.
Preview persists a sealed native plan using approval v2. Claude Code and Codex
registration changes execute through a narrow CLI mutation WAL inside the
native transaction engine; Hermes remains a native YAML mutation. Contextd
routes preview/apply/rollback through the same ordered daemon workspace.

**Normative design:**
`docs/superpowers/specs/2026-07-31-transactional-mcp-adapter-install-design.md`

**Global constraints:**

- No direct Claude/Codex configuration write.
- No caller-supplied approval class, rollback command, or bridge path.
- Only the stable global `context-relay` MCP declaration is eligible for CLI
  transaction execution.
- Preview performs no harness or configuration mutation.
- Validation must not launch the configured bridge.
- Live divergence is a conflict, never an overwrite.
- Preserve approval v1 and legacy file-only recovery.

---

### Task 1: Bind CLI mutations into approval v2

**Files:**

- Modify: `crates/core/src/native_transaction/model.rs`
- Modify: `crates/core/src/native_transaction/approval.rs`
- Modify: `crates/core/src/native_transaction/mod.rs`
- Create: `crates/core/tests/native_approval_v2.rs`
- Modify: native transaction test fixtures constructing `NativeTransactionPlan`

**Step 1: Write RED tests**

Cover:

- expected/intended canonical declarations affect the hash;
- forward and rollback operations affect the hash;
- order affects the hash;
- duplicate stable ID and duplicate harness/server target reject;
- declaration fingerprint mismatch rejects;
- flattened forward operations must equal `SetupPlan.cli_operations`;
- operation executable must equal the attested harness executable;
- approval v1 remains stable for existing fixtures.

Run:

```bash
cargo test -p context-relay-core --test native_approval_v2
```

**Step 2: Add the internal model**

Add `CanonicalCliDeclaration`, `ApprovedCliMutation`, and
`NativeTransactionPlan::cli_mutations`.

Keep declaration bodies canonical, bounded, and secret-free. Validate only
Claude Code/Codex `context-relay` targets; Hermes plans require an empty list.

**Step 3: Add `approval_hash_v2`**

Use domain `context-relay/native-plan/v2\0`. Bind the complete v1 plan
preimage plus ordered CLI mutations. Do not change `approval_hash_v1`.

**Step 4: Run gates and commit**

```bash
cargo test -p context-relay-core --test native_approval_v2
cargo test -p context-relay-core --test native_approval_v1
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
git diff --check
git commit -m "feat: bind CLI mutations into native approval v2"
```

---

### Task 2: Persist preview plans and CLI WAL in schema v9

**Files:**

- Create: `crates/core/migrations/0009_setup_cli_transactions.sql`
- Modify: `crates/core/src/vault.rs`
- Modify: `crates/core/src/vault/native_transactions.rs`
- Create: `crates/core/tests/setup_plan_vault_v1.rs`
- Create: `crates/core/tests/native_cli_journal_v1.rs`
- Modify: `crates/core/tests/vault_storage_v1.rs`

**Step 1: Write RED storage tests**

Cover:

- preview plan round-trip with schema/approval version;
- exact canonical payload and approval hash preservation;
- duplicate plan with altered bytes conflicts;
- lifecycle CAS and apply/rollback replay;
- expired plan claim rejects;
- CLI WAL state transitions and invalid transition rejection;
- v8 to v9 migration preserves operation bindings/results and native rows.

**Step 2: Add schema v9**

Add `setup_plan_lifecycle` linked to `native_plans` with states:

```text
previewed, applying, applied, apply_restored, rolling_back,
rolled_back, rollback_restored, conflict, expired
```

Add `native_cli_wal` keyed by transaction/sequence with stable ID,
harness/server target, expected/intended declaration bytes and fingerprints,
forward/rollback bytes, and states:

```text
prepared, applied, restore_prepared, restored, conflict
```

**Step 3: Add vault APIs**

Add bounded validated `put/setup/claim/finish` plan lifecycle methods and CLI
WAL prepare/transition/read methods. Refactor native transaction begin so a
preview-persisted plan can be claimed without replacing its canonical bytes.

**Step 4: Run gates and commit**

```bash
cargo test -p context-relay-core --test setup_plan_vault_v1
cargo test -p context-relay-core --test native_cli_journal_v1
cargo test -p context-relay-core --test vault_storage_v1
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
git diff --check
git commit -m "feat: persist setup plans and CLI mutation WAL"
```

---

### Task 3: Transact approval-bound CLI mutations

**Files:**

- Create: `crates/core/src/native_transaction/cli.rs`
- Modify: `crates/core/src/native_transaction/mod.rs`
- Modify: `crates/core/src/native_transaction/engine.rs`
- Modify: `crates/core/src/native_transaction/journal.rs`
- Create: `crates/core/tests/native_cli_transaction_v1.rs`

**Step 1: Write RED engine tests**

Cover:

- expected-state mismatch before command;
- WAL prepared before command;
- success requires intended declaration reprobe;
- command error with expected state is no write;
- command error with intended state compensates;
- unknown state conflicts;
- validation failure restores CLI then native mutations;
- reverse-order CLI compensation;
- compensation never overwrites divergence;
- existing file-only step order remains unchanged.

**Step 2: Add `NativeCliExecutor`**

Implement compare/apply/restore/finish methods over
`ApprovedCliMutation`. The executor returns semantic fingerprints and never
accepts arbitrary command input.

**Step 3: Integrate without renumbering top-level steps**

Compare CLI targets during step 14. Apply CLI mutations as a WAL-backed
subphase of step 17 after activation-reference writes. Validate at step 18.
Compensate CLI mutations in reverse sequence before native file restoration.

**Step 4: Run gates and commit**

```bash
cargo test -p context-relay-core --test native_cli_transaction_v1
cargo test -p context-relay-core --test native_transaction_v1
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
git diff --check
git commit -m "feat: transact approval-bound adapter CLI operations"
```

---

### Task 4: Recover interrupted CLI mutations

**Files:**

- Modify: `crates/core/src/native_transaction/recovery.rs`
- Modify: `crates/core/src/vault/native_transactions.rs`
- Create: `crates/core/tests/native_cli_recovery_v1.rs`
- Create: `crates/core/tests/native_cli_recovery_crash_v1.rs`

**Step 1: Write RED recovery tests**

Inject failures:

- before command;
- after command before applied checkpoint;
- after applied checkpoint;
- before restore command;
- after restore command before restored checkpoint;
- committed cleanup;
- live-state divergence.

**Step 2: Add `NativeCliRecoveryIo`**

Probe and restore using the sealed plan payload and CLI WAL row. A no-op
implementation errors whenever CLI WAL is nonempty.

**Step 3: Integrate recovery ordering**

Pending/restoring transactions recover CLI rows in reverse order before
native rows. Committed transactions finish CLI cleanup before native cleanup.
Resolve prepared rows by probing expected versus intended state.

**Step 4: Run gates and commit**

```bash
cargo test -p context-relay-core --test native_cli_recovery_v1
cargo test -p context-relay-core --test native_cli_recovery_crash_v1
cargo test -p context-relay-core --test native_recovery_v1
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
git diff --check
git commit -m "feat: recover interrupted adapter CLI mutations"
```

---

### Task 5: Implement concrete adapter CLI executors

This task may be split into three independently reviewed commits after Task 3
establishes `NativeCliExecutor`. Adapter-specific declaration parsing and
operation-generation tests may begin after Task 1, but trait implementations
must wait for Task 3.

#### Task 5A: Claude Code

**Files:**

- Modify: `crates/core/src/claude_code.rs`
- Modify: `crates/core/tests/claude_code_adapter_v1.rs`

Use only official user-scope MCP add-json/remove and list/get operations.
Include global `.claude.json` names in validation. Add injected operation and
validation runners. Recheck the harness executable with `symlink_metadata`.

#### Task 5B: Codex

**Files:**

- Modify: `crates/core/src/codex.rs`
- Modify: `crates/core/tests/codex_adapter_v1.rs`

Use only official MCP add/remove and plugin/MCP list/get operations. Preserve
argv boundaries and spaces without shell quoting. Recheck the harness
executable with `symlink_metadata`.

#### Task 5C: Hermes

**Files:**

- Modify: `crates/core/src/hermes.rs`
- Modify: `crates/core/src/hermes/render.rs`
- Modify: `crates/core/tests/hermes_adapter_v1.rs`

Reject nonempty CLI mutations. Preserve native YAML planning, gateway-idle
gate, before images, and rollback. Accept only the exact managed bridge
authority exception.

**Required tests for each adapter:**

- expected/intended declaration fingerprinting;
- exact forward and rollback operations;
- refusal of malformed, redacted, secret-bearing, or unmanaged prior state;
- bridge and harness executable digest changes;
- validation never executes the bridge;
- restore only while live state equals intended.

**Commit subjects:**

```text
feat: transact Claude Code MCP registrations
feat: transact Codex MCP registrations
feat: transact Hermes MCP registrations
```

---

### Task 6: Preview and persist bridge installation plans

**Files:**

- Create: `crates/core/src/native_transaction/planner.rs`
- Modify: `crates/core/src/native_transaction/mod.rs`
- Create: `crates/core/src/setup.rs`
- Modify: `crates/core/src/lib.rs`
- Modify: `crates/core/src/mcp/install.rs`
- Create: `crates/core/tests/bridge_setup_preview_v1.rs`

**Step 1: Write RED preview tests**

Cover exact adapter import/diff/render/classify path, active derivation, bridge
digest binding, conflicting prior declaration, persisted canonical plan,
expiry, replay, and no harness/config write.

**Step 2: Add plan builder and service**

`BridgeInstallService::preview` takes harness, optional registered project,
the internally located bridge path, and time. It builds
`NativeTransactionPlan`, computes approval v2, persists a versioned sealed
envelope, and returns `SetupPlan`.

**Step 3: Run gates and commit**

```bash
cargo test -p context-relay-core --test bridge_setup_preview_v1
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
git diff --check
git commit -m "feat: preview and persist bridge installation plans"
```

---

### Task 7: Apply and explicitly roll back persisted plans

**Files:**

- Modify: `crates/core/src/setup.rs`
- Modify: `crates/core/src/native_transaction/planner.rs`
- Modify: `crates/core/src/vault/native_transactions.rs`
- Create: `crates/core/tests/bridge_setup_apply_v1.rs`
- Create: `crates/core/tests/bridge_setup_rollback_v1.rs`

**Step 1: Write RED apply/rollback tests**

Cover approval/expiry reload, lifecycle CAS, apply replay, rollback replay,
inverse-plan construction, exact prior-state restoration, unknown command
outcome, validation failure, and divergence conflict/no write.

**Step 2: Add service methods**

`apply` loads only persisted bytes, revalidates approval v2, claims lifecycle,
and invokes the native engine. `rollback` creates and persists a fresh inverse
plan linked to the original public plan ID.

**Step 3: Run gates and commit**

```bash
cargo test -p context-relay-core --test bridge_setup_apply_v1
cargo test -p context-relay-core --test bridge_setup_rollback_v1
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
git diff --check
git commit -m "feat: apply and roll back persisted bridge plans"
```

---

### Task 8: Route setup through contextd

**Files:**

- Create: `crates/contextd/src/bridge_install.rs`
- Modify: `crates/contextd/src/lib.rs`
- Create: `crates/contextd/tests/harness_setup_v1.rs`

**Step 1: Write RED daemon tests**

Cover preview returning `LocalResult::Plan`, declined preview/no write,
apply/rollback, replay, digest change, validation without bridge launch,
restart recovery, and authorization.

**Step 2: Add bridge locator and queued routes**

Production locates the platform-named bridge beside `contextd`. Tests inject a
path. Route preview/apply/rollback through the ordered vault/setup worker.
Keep `HarnessRepair` unsupported.

**Step 3: Run gates and commit**

```bash
cargo test -p context-relay-contextd --test harness_setup_v1
cargo test -p context-relay-contextd --lib
cargo test -p context-relay-local-ipc
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
git diff --check
git commit -m "feat: route transactional harness setup through contextd"
```

---

### Task 9: Prove cross-adapter installation acceptance

**Files:**

- Create or extend: `crates/core/tests/mcp_bridge_install_v1.rs`
- Extend: `crates/contextd/tests/harness_setup_v1.rs`
- Extend: native CLI recovery crash tests
- Modify:
  `docs/superpowers/plans/2026-07-30-mcp-memory-tasks-handoffs.md`

Run an exact acceptance matrix:

- Claude Code, Codex, and Hermes declaration output;
- active create/update/enable/disable/remove;
- bridge digest change before apply;
- declined preview/no write;
- validation without bridge execution;
- compensation and crash recovery;
- rollback to absence and exact prior declaration;
- divergence conflict;
- idempotent apply/rollback;
- public contextd preview/apply/rollback.

Then run full adapter, native transaction/recovery, contextd, local IPC,
workspace check, strict Clippy, formatting, and diff gates.

Commit:

```text
test: prove transactional MCP bridge installation
```

Only after this task passes may original Task 8 and Task 9 acceptance be
marked complete.
