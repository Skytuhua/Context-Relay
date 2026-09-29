# Signed Sync Replica Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the provider-independent Task 16 replica core so encrypted local replicas converge through a fault-injected in-memory transport with durable outbox, cursor, admission, merge, quarantine, and checkpoint behavior.

**Architecture:** Extend operation schema version 1 with a strictly canonical encrypted mutation payload and operation AAD, while using independent checkpoint schema version 2 for scope-bound signed checkpoints. Add narrow SQLCipher sync state beside the existing Vault tables, then layer pure causal/admission/merge modules over a synchronous provider-independent transport. The first end-to-end checkpoint uses only an in-memory ciphertext provider; Supabase admission and HTTP/Realtime are separate follow-on plans built against these interfaces.

**Tech Stack:** Rust 1.97, `minicbor`, `serde_json`, `sha2`, existing Ed25519/XChaCha helpers, SQLCipher through `rusqlite`, deterministic Rust tests.

## Global Constraints

- Preserve the immutable `SyncOperationV1` and `CheckpointV1` outer CBOR layouts.
- Verify certificate trust, signature, ciphertext hash, sequence, frontier, epochs, and device hash chain before decryption.
- Never use wall-clock last-write-wins.
- Accept a duplicate only when complete canonical signed bytes match.
- Keep plaintext, content keys, JWTs, and secrets out of transport values, quarantine diagnostics, and logs.
- Make local materialized mutation and outgoing encrypted outbox append one Vault transaction.
- Realtime is outside this slice and remains only a future pull hint.
- Do not add a paid dependency or require Apple Developer membership.
- Every validated review finding receives a failing regression before its fix.

---

### Task 1: Canonical encrypted mutation payload and AAD

**Files:**
- Create: `crates/protocol/src/sync_payload.rs`
- Create: `crates/protocol/tests/sync_payload_v1.rs`
- Create: `crates/protocol/tests/fixtures/sync-mutation-v1.hex`
- Modify: `crates/protocol/src/canonical_cbor.rs`
- Modify: `crates/protocol/src/lib.rs`
- Modify: `docs/protocols/cbor-v1.md`
- Modify: `docs/protocols/protocol-v1.md`

**Interfaces:**
- Produces: `RecordMutationV1`, `encode_record_mutation_v1`, `decode_record_mutation_v1`, and `encode_sync_operation_aad_v1`.
- Consumes: existing domain records, `RecordKind`, `MutationKind`, `SyncOperationV1`, and strict canonical-CBOR helpers.

- [ ] **Step 1: Write failing mutation round-trip and canonicality tests**

Create tests covering all seven upsert variants and a tombstone. The fixture test must use a memory record with non-ASCII Markdown and compare exact bytes:

```rust
#[test]
fn fixed_memory_mutation_matches_the_version_one_fixture() {
    let mutation = RecordMutationV1::UpsertMemory(fixed_memory());
    let encoded = encode_record_mutation_v1(&mutation).unwrap();
    assert_eq!(hex(&encoded), include_str!("fixtures/sync-mutation-v1.hex").trim());
    assert_eq!(decode_record_mutation_v1(&encoded).unwrap(), mutation);
}

#[test]
fn mutation_decoder_rejects_noncanonical_and_mismatched_payloads() {
    assert_rejected(duplicate_key_fixture());
    assert_rejected(out_of_order_key_fixture());
    assert_rejected(trailing_bytes_fixture());
    assert_rejected(memory_kind_with_task_json_fixture());
    assert_rejected(noncanonical_json_fixture());
}
```

Add an AAD test that changes each included outer field and proves the bytes
change, while changing nonce/ciphertext/hash/signature does not change AAD.

- [ ] **Step 2: Run the focused tests and confirm RED**

Run:

```bash
cargo test -p context-relay-protocol --test sync_payload_v1
```

Expected: compile failure because the four new public interfaces do not exist.

- [ ] **Step 3: Add the strict mutation DTO and validation**

Implement this public shape in `sync_payload.rs`:

```rust
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordMutationV1 {
    UpsertMemory(MemoryRecord),
    UpsertMemoryCandidate(MemoryCandidate),
    UpsertTask(TaskRecord),
    UpsertSecretRef(SecretRef),
    UpsertInstruction(InstructionRecord),
    UpsertComponent(ComponentRecord),
    UpsertProject(ProjectIdentity),
    Tombstone { record_id: RecordId, record_kind: RecordKind },
}

impl RecordMutationV1 {
    pub fn record_id(&self) -> RecordId;
    pub const fn record_kind(&self) -> RecordKind;
    pub const fn mutation_kind(&self) -> MutationKind;
    pub fn validate(&self) -> Result<(), ValidationError>;
}
```

Use a five-key definite CBOR map: `0 => schema_version`, `1 => record_kind`,
`2 => mutation_kind`, `3 => record_id`, `4 => canonical_json_bytes_or_null`.
Upserts serialize the typed record with compact `serde_json::to_vec`; decoding
must reject unknown fields through the existing DTOs, call `validate`,
serialize again, and require byte equality. Tombstones require `null` at key 4.

- [ ] **Step 4: Add canonical operation AAD encoding**

Add:

```rust
pub fn encode_sync_operation_aad_v1(
    operation: &SyncOperationV1,
) -> Result<Vec<u8>, ProtocolError>;
```

Encode a definite 16-entry integer-key map containing outer operation keys
`0..=13`, `17`, and `18`, in that order. Reuse the existing UUID, frontier,
blob-reference, and HLC encoders. Do not include keys 14, 15, 16, or 19.

- [ ] **Step 5: Run protocol tests and export checks**

Run:

```bash
cargo fmt --all -- --check
cargo test -p context-relay-protocol --test sync_payload_v1
cargo test -p context-relay-protocol
pnpm check:bindings
pnpm check:schemas
```

Expected: all pass and generated bindings/schemas remain unchanged because the
encrypted mutation type is an internal binary protocol, not an IPC DTO.

- [ ] **Step 6: Commit**

```bash
git add crates/protocol docs/protocols
git commit -m "feat: define canonical encrypted sync mutations"
```

---

### Task 2: Outgoing operation construction and tamper order

**Files:**
- Create: `crates/core/src/sync/mod.rs`
- Create: `crates/core/src/sync/identity.rs`
- Create: `crates/core/src/sync/operation.rs`
- Create: `crates/core/tests/sync_operation_v1.rs`
- Create: `crates/core/tests/fixtures/signed-sync-operation-v1.hex`
- Modify: `crates/core/src/crypto.rs`
- Modify: `crates/core/src/lib.rs`

**Interfaces:**
- Produces: `SyncIdentity`, `OperationChainHead`, `OperationBuilder`, `BuiltOperation`, and `verify_operation_envelope`.
- Consumes: Task 1 mutation/AAD encoders, `ContentKey`, `DeviceKeys`, and existing operation signing encoding.

- [ ] **Step 1: Write fixed-vector and one-bit tamper tests**

Use deterministic test-only device seeds, content key, nonce source, IDs, HLC,
frontier, and plaintext. Assert exact canonical bytes and hash. Table-drive one
bit changes through every signed or AAD-bound field:

Keep deterministic device construction and injected-nonce encryption
crate-private. The fixed-vector builder assertion may live in the operation
module's unit tests so production consumers never receive deterministic secret
constructors; the integration test still owns the public build/verify and
pre-decryption tamper behavior.

```rust
#[test]
fn every_signed_or_aad_bound_field_rejects_tampering_before_plaintext() {
    for mutate in operation_mutators() {
        let mut candidate = fixed_built_operation();
        mutate(&mut candidate.operation);
        let probe = CountingDecryptor::default();
        assert!(verify_operation_envelope(&candidate.operation, &trusted(), &probe).is_err());
        assert_eq!(probe.calls(), 0);
    }
}
```

- [ ] **Step 2: Run the focused test and confirm RED**

Run:

```bash
cargo test -p context-relay-core --test sync_operation_v1
```

Expected: compile failure because `context_relay_core::sync` does not exist.

- [ ] **Step 3: Define identity and chain inputs**

Implement:

```rust
pub struct SyncIdentity<'a> {
    pub account_id: AccountId,
    pub workspace_id: WorkspaceId,
    pub device_id: DeviceId,
    pub control_epoch: u32,
    pub key_epoch: u32,
    pub device_keys: &'a DeviceKeys,
    pub content_key: &'a ContentKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationChainHead {
    pub sequence: u64,
    pub canonical_hash: Sha256Digest,
}
```

`SyncIdentity` must have a redacted `Debug` implementation and must not be
serializable.

- [ ] **Step 4: Build, encrypt, hash, and sign in one direction**

Implement:

```rust
pub struct BuiltOperation {
    pub operation: SyncOperationV1,
    pub canonical_bytes: Vec<u8>,
    pub canonical_hash: Sha256Digest,
}

impl<'a> OperationBuilder<'a> {
    pub fn build(
        &self,
        operation_id: OperationId,
        project_id: Option<ProjectId>,
        mutation: &RecordMutationV1,
        causal_frontier: Vec<DeviceSequence>,
        previous: Option<OperationChainHead>,
        blob_refs: Vec<BlobRef>,
        created_hlc: HybridLogicalClock,
    ) -> Result<BuiltOperation, SyncError>;
}
```

The builder validates/sorts the frontier, creates the unsigned routing
envelope, encodes AAD, encrypts the mutation bytes, computes ciphertext SHA-256,
signs, canonical-encodes, and computes the canonical SHA-256. Sequence is 1 and
previous hash is zero for genesis; otherwise sequence is `previous + 1` and the
hash is exact. Persisted nonce uniqueness is Task 3; the process-lifetime guard
remains a second line of defense.

- [ ] **Step 5: Add fail-closed envelope verification**

`verify_operation_envelope` must validate DTO/scope/certificate fields,
signature, ciphertext hash, expected sequence/hash, and frontier before calling
the decryptor. It then decrypts with Task 1 AAD, strict-decodes the mutation,
and matches record ID/kind/mutation kind/project scope.

- [ ] **Step 6: Run crypto and sync tests**

Run:

```bash
cargo fmt --all -- --check
cargo test -p context-relay-core --lib sync::operation::tests
cargo test -p context-relay-core --test sync_operation_v1
cargo test -p context-relay-core --test crypto_v1
```

Expected: all pass; logs and `Debug` output contain neither vector plaintext nor
secret bytes.

- [ ] **Step 7: Commit**

```bash
git add crates/core
git commit -m "feat: build and verify encrypted sync operations"
```

---

### Task 3: Durable Vault sync state

**Files:**
- Create: `crates/core/migrations/0014_signed_sync.sql`
- Create: `crates/core/src/vault/sync.rs`
- Create: `crates/core/tests/sync_vault_v1.rs`
- Modify: `crates/core/src/vault.rs`
- Modify: `crates/core/tests/vault_storage_v1.rs`

**Interfaces:**
- Produces: durable `SyncCursor`, `StoredDeviceHead`, `StoredRecordHead`, `DueOutboxOperation`, and atomic Vault sync methods.
- Consumes: Task 2 `BuiltOperation` and Task 1 `RecordMutationV1`.

- [ ] **Step 1: Write migration, atomicity, replay, cursor, and canary tests**

Tests must prove: schema upgrade/reopen; one transaction for materialized record
plus operation/meta/outbox/head/nonce; exact replay no-op; altered replay
rollback; due/deferred/acknowledged outbox state is durable; and the plaintext
canary is absent from every sync table cell. Task 4 owns the admitted incoming
page transaction and must prove its cursor cannot advance on rollback, because
the admission and merge inputs do not exist before that task.

- [ ] **Step 2: Run the focused test and confirm RED**

Run:

```bash
cargo test -p context-relay-core --features test-support --test sync_vault_v1
```

Expected: failure because schema version 14 and sync Vault methods do not exist.

- [ ] **Step 3: Add forward-only schema version 14**

Create these exact tables/indexes, using canonical decimal text for `u64`
sequence values and BLOB length checks for hashes/nonces:

```sql
ALTER TABLE outbox ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0);
ALTER TABLE outbox ADD COLUMN next_attempt_ms INTEGER NOT NULL DEFAULT 0 CHECK (next_attempt_ms >= 0);
ALTER TABLE outbox ADD COLUMN safe_error_code TEXT;

CREATE TABLE sync_operation_meta (
    operation_id TEXT PRIMARY KEY REFERENCES operations(id) ON DELETE CASCADE,
    account_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    device_sequence TEXT NOT NULL,
    canonical_sha256 BLOB NOT NULL CHECK (length(canonical_sha256) = 32),
    direction TEXT NOT NULL CHECK (direction IN ('outgoing', 'incoming')),
    state TEXT NOT NULL CHECK (state IN ('queued', 'admitted', 'applied', 'quarantined')),
    safe_error_code TEXT,
    received_at TEXT,
    applied_at_ms INTEGER,
    UNIQUE(workspace_id, device_id, device_sequence)
);

CREATE TABLE sync_device_heads (
    workspace_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    device_sequence TEXT NOT NULL,
    canonical_sha256 BLOB NOT NULL CHECK (length(canonical_sha256) = 32),
    PRIMARY KEY(workspace_id, device_id)
);

CREATE TABLE sync_record_heads (
    workspace_id TEXT NOT NULL,
    record_id TEXT NOT NULL,
    operation_id TEXT NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    record_kind TEXT NOT NULL,
    mutation_kind TEXT NOT NULL,
    canonical_sha256 BLOB NOT NULL CHECK (length(canonical_sha256) = 32),
    PRIMARY KEY(workspace_id, record_id, operation_id)
);

CREATE TABLE sync_cursors (
    workspace_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    received_at TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    PRIMARY KEY(workspace_id, provider)
);

CREATE TABLE sync_checkpoint_meta (
    state_hash TEXT PRIMARY KEY REFERENCES checkpoints(state_hash) ON DELETE CASCADE,
    canonical_sha256 BLOB NOT NULL CHECK (length(canonical_sha256) = 32),
    accepted_at_ms INTEGER NOT NULL,
    pinned INTEGER NOT NULL CHECK (pinned IN (0, 1))
);

CREATE TABLE sync_nonces (
    key_epoch INTEGER NOT NULL CHECK (key_epoch >= 0),
    nonce BLOB NOT NULL CHECK (length(nonce) = 24),
    operation_id TEXT NOT NULL UNIQUE,
    PRIMARY KEY(key_epoch, nonce)
);

CREATE TABLE secret_refs (
    id TEXT PRIMARY KEY,
    payload_json BLOB NOT NULL
);

CREATE TABLE components (
    id TEXT PRIMARY KEY,
    payload_json BLOB NOT NULL
);
```

Add indexes for due outbox order, operation workspace/device sequence, record
heads, and incoming receipt order. The two materialized tables complete the
seven record kinds carried by `RecordMutationV1`; existing Vault tables remain
the materialized view for the other five kinds. Raise `LATEST_SCHEMA_VERSION`
to 14.

- [ ] **Step 4: Implement narrow atomic Vault APIs**

Expose these exact storage types:

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitDisposition { Inserted, ExactReplay }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncCursor {
    pub received_at: String,
    pub operation_id: OperationId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoredDeviceHead {
    pub sequence: u64,
    pub canonical_hash: Sha256Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredRecordHead {
    pub operation_id: OperationId,
    pub record_kind: RecordKind,
    pub mutation_kind: MutationKind,
    pub canonical_hash: Sha256Digest,
    pub operation: SyncOperationV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DueOutboxOperation {
    pub operation_id: OperationId,
    pub canonical_bytes: Vec<u8>,
    pub attempt_count: u32,
}
```

Expose these exact methods:

```rust
pub fn commit_outgoing_operation(
    &mut self,
    mutation: &RecordMutationV1,
    built: &BuiltOperation,
    embedding: Option<&Embedding384>,
) -> Result<CommitDisposition, VaultError>;

pub fn due_outbox(&self, now_ms: u64, limit: usize)
    -> Result<Vec<DueOutboxOperation>, VaultError>;
pub fn acknowledge_outbox(&mut self, accepted: &[OperationId]) -> Result<(), VaultError>;
pub fn defer_outbox(&mut self, ids: &[OperationId], next_ms: u64, code: &str)
    -> Result<(), VaultError>;
pub fn device_head(&self, workspace: WorkspaceId, device: DeviceId)
    -> Result<Option<StoredDeviceHead>, VaultError>;
pub fn record_heads(&self, workspace: WorkspaceId, record: RecordId)
    -> Result<Vec<StoredRecordHead>, VaultError>;
pub fn sync_cursor(&self, workspace: WorkspaceId, provider: &str)
    -> Result<Option<SyncCursor>, VaultError>;
```

Keep SQL and row decoding in `vault/sync.rs`. Public mutation APIs call one
shared internal materializer so incoming operations never enter the outbox.

- [ ] **Step 5: Run Vault regression tests**

Run:

```bash
cargo fmt --all -- --check
cargo test -p context-relay-core --features test-support --test sync_vault_v1
cargo test -p context-relay-core --features test-support --test vault_storage_v1
```

Expected: all pass, schema version is 14, and old Vault fixtures migrate
forward without data loss.

- [ ] **Step 6: Commit**

```bash
git add crates/core
git commit -m "feat: persist durable signed sync state"
```

---

### Task 4: Causal ordering, admission, and deterministic merge

**Files:**
- Create: `crates/core/src/sync/causal.rs`
- Create: `crates/core/src/sync/admission.rs`
- Create: `crates/core/src/sync/merge.rs`
- Create: `crates/core/tests/sync_admission_v1.rs`
- Create: `crates/core/tests/sync_merge_v1.rs`
- Modify: `crates/core/src/sync/mod.rs`
- Modify: `crates/core/src/vault/sync.rs`

**Interfaces:**
- Produces: `CausalOrder`, `AdmissionDecision`, `AdmittedOperation`, `MergeDecision`, and `apply_admitted_operation`.
- Consumes: Tasks 1–3 payload, crypto, and Vault head interfaces.

- [ ] **Step 1: Write the causal truth table and gap tests**

Cover same-device order, cross-device dominance, concurrency, missing-device
entries, duplicate frontier devices, unsorted frontiers, and sequence overflow:

```rust
assert_eq!(compare_operations(&a_after_b, &b), CausalOrder::After);
assert_eq!(compare_operations(&b, &a_after_b), CausalOrder::Before);
assert_eq!(compare_operations(&concurrent_a, &concurrent_b), CausalOrder::Concurrent);
assert_eq!(missing_range(Some(known_head), &sequence_four), Ok(Some(2..=3)));
```

- [ ] **Step 2: Write RED admission and merge matrix tests**

Table-drive exact replay, altered operation ID, reused sequence, broken previous
hash, bad signature, bad ciphertext hash, missing gap, bad frontier, wrong
epoch, decryption failure, payload mismatch, older write, newer tombstone,
concurrent updates, concurrent update/delete, and a later resolving operation.
Assert every pre-decryption failure leaves a counting decryptor at zero.
Also prove that an injected failure before the admitted page transaction commits
rolls back every operation/head/materialized change and leaves the durable
`(received_at, operation_id)` cursor unchanged; replaying the page then commits
the data and cursor together.

- [ ] **Step 3: Run both tests and confirm RED**

Run:

```bash
cargo test -p context-relay-core --test sync_admission_v1 --test sync_merge_v1
```

Expected: compile failure because the causal/admission/merge modules are absent.

- [ ] **Step 4: Implement causal comparison without wall time**

Implement:

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CausalOrder { Before, Equal, After, Concurrent }

pub fn compare_operations(left: &SyncOperationV1, right: &SyncOperationV1)
    -> CausalOrder;
pub fn missing_range(known: Option<StoredDeviceHead>, incoming: &SyncOperationV1)
    -> Result<Option<RangeInclusive<u64>>, SyncError>;
```

Same-device sequence participates directly. Cross-device knowledge comes only
from normalized frontier entries. HLC is never consulted for ordering.

- [ ] **Step 5: Implement fail-closed admission**

Define the exact trust and result boundary:

```rust
pub struct TrustedDevice {
    pub certificate: DeviceCertificateV1,
    pub active_control_epoch: u32,
    pub active_key_epoch: u32,
}

pub trait TrustedSyncMaterial {
    fn trusted_device(
        &self,
        account: AccountId,
        workspace: WorkspaceId,
        device: DeviceId,
    ) -> Result<TrustedDevice, SyncError>;
    fn content_key(
        &self,
        workspace: WorkspaceId,
        key_epoch: u32,
    ) -> Result<&ContentKey, SyncError>;
}

pub struct AdmittedOperation {
    pub operation: SyncOperationV1,
    pub mutation: RecordMutationV1,
    pub canonical_bytes: Vec<u8>,
    pub canonical_hash: Sha256Digest,
}

pub enum AdmissionDecision {
    ExactReplay(OperationId),
    Gap(RangeInclusive<u64>),
    Admitted(AdmittedOperation),
}
```

`admit_operation` follows the eleven-step order in the design and returns only
these decisions or a stable quarantine error. Never put raw
cryptographic/provider error text in `SyncError::safe_code()`.
For tombstones, load the existing materialized record scope from the Vault and
pass it through Task 2's explicit trusted-scope verifier input; absence or
mismatch fails closed before decryption. Upserts continue to prove scope from
their canonical payload.

- [ ] **Step 6: Implement the head-set merge state machine**

Implement:

```rust
pub enum MergeDecision {
    NoLiveChange,
    ReplaceHeads { remove: Vec<OperationId> },
    AddConflictHead,
    ResolveConflict { remove: Vec<OperationId> },
}

pub fn decide_merge(
    incoming: &AdmittedOperation,
    current: &[StoredRecordHead],
) -> Result<MergeDecision, SyncError>;
```

Sort head IDs canonically before storage. Apply the materialized record,
operation, device head, record heads, conflict row, and cursor in one Vault
transaction. A later operation that dominates every head clears the conflict.
`Vault::record_heads` joins each head to its validated legacy-compatible
`operations.payload_json`, so `StoredRecordHead.operation` supplies the causal
frontier to the pure merge decision without a hidden database dependency.
For unresolved concurrent heads, retain every signed operation/head and make
the canonically smallest operation ID the temporary single-row materialized
representative. Reordering arrival must not change the local view.

- [ ] **Step 7: Run focused and Vault tests**

Run:

```bash
cargo fmt --all -- --check
cargo test -p context-relay-core --test sync_admission_v1 --test sync_merge_v1
cargo test -p context-relay-core --features test-support --test sync_vault_v1
```

Expected: all pass and no invalid operation changes a record, head, conflict,
device head, or cursor.

- [ ] **Step 8: Commit**

```bash
git add crates/core
git commit -m "feat: admit and merge signed sync operations"
```

---

### Task 5: In-memory transport and one-cycle engine

**Files:**
- Create: `crates/core/src/sync/transport.rs`
- Create: `crates/core/src/sync/memory.rs`
- Create: `crates/core/src/sync/engine.rs`
- Create: `crates/core/tests/sync_engine_v1.rs`
- Modify: `crates/core/src/sync/mod.rs`

**Interfaces:**
- Produces: `SyncTransport`, `InMemoryTransport`, `FaultSchedule`, `SyncEngine`, and `SyncCycleReport`.
- Consumes: Tasks 2–4 outgoing, Vault, admission, and merge APIs.

- [ ] **Step 1: Write RED push/pull/retry/gap/crash tests**

Tests must prove oldest-due batching, exact duplicate acknowledgement, altered
duplicate rejection, 256-row pagination, cursor tie-breaking, missing-range
repair, dropped/delayed/reordered pages, and outbox retention on failure.

```rust
#[test]
fn lost_hint_and_dropped_first_page_still_converge_by_durable_pull() {
    let mut provider = InMemoryTransport::with_faults(FaultSchedule::drop_pull(1));
    let mut a = replica("a");
    let mut b = replica("b");
    a.write(memory_mutation("needle"));
    sync_until_idle(&mut a, &mut provider);
    sync_until_idle(&mut b, &mut provider);
    assert_eq!(a.state_hash(), b.state_hash());
}
```

- [ ] **Step 2: Run the engine test and confirm RED**

Run:

```bash
cargo test -p context-relay-core --test sync_engine_v1
```

Expected: compile failure because transport and engine interfaces are absent.

- [ ] **Step 3: Define ciphertext-only transport values**

Implement these exact value types and trait:

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncScope {
    pub account_id: AccountId,
    pub workspace_id: WorkspaceId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalOperation {
    pub operation_id: OperationId,
    pub device_id: DeviceId,
    pub device_sequence: u64,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceivedOperation {
    pub cursor: SyncCursor,
    pub operation: CanonicalOperation,
}

pub struct PushReceipt {
    pub accepted: Vec<OperationId>,
    pub duplicates: Vec<OperationId>,
}

pub struct PullPage {
    pub rows: Vec<ReceivedOperation>,
    pub next_cursor: Option<SyncCursor>,
}

pub struct CanonicalCheckpoint {
    pub state_hash: Sha256Digest,
    pub bytes: Vec<u8>,
}

pub struct CheckpointReceipt { pub duplicate: bool }
pub struct CheckpointPage {
    pub rows: Vec<(SyncCursor, CanonicalCheckpoint)>,
    pub next_cursor: Option<SyncCursor>,
}

pub trait SyncTransport {
    fn push_operations(&mut self, scope: SyncScope, batch: &[CanonicalOperation])
        -> Result<PushReceipt, TransportError>;
    fn pull_operations(&mut self, scope: SyncScope, after: Option<&SyncCursor>, limit: usize)
        -> Result<PullPage, TransportError>;
    fn pull_device_range(&mut self, scope: SyncScope, device: DeviceId, range: RangeInclusive<u64>)
        -> Result<Vec<ReceivedOperation>, TransportError>;
    fn push_checkpoint(&mut self, scope: SyncScope, checkpoint_version: u16, checkpoint: &CanonicalCheckpoint)
        -> Result<CheckpointReceipt, TransportError>;
    fn pull_checkpoints(&mut self, scope: SyncScope, checkpoint_version: u16, after: Option<&SyncCursor>, limit: usize)
        -> Result<CheckpointPage, TransportError>;
}
```

All canonical values contain signed ciphertext bytes plus receipt routing only.
No method accepts `RecordMutationV1`, `ContentKey`, or `DeviceKeys`.

- [ ] **Step 4: Implement deterministic provider faults**

`InMemoryTransport` partitions by account/workspace, assigns monotonically
ordered synthetic receipt timestamps, compares exact canonical bytes for
duplicate IDs, and enforces unique device sequence. `FaultSchedule` supports
drop, delay, duplicate, reverse, transient failure, and lost-hint counters with
no randomness in unit tests.

- [ ] **Step 5: Implement `SyncEngine::sync_once`**

The cycle order is:

```text
load oldest due outbox -> push -> durably acknowledge/defer
load durable cursor -> pull page -> repair each gap -> admit/apply transaction
repeat pages until empty or configured work bound -> checkpoint decision
```

Return counts and stable status only:

```rust
pub struct SyncCycleReport {
    pub pushed: usize,
    pub duplicates: usize,
    pub pulled: usize,
    pub applied: usize,
    pub conflicts: usize,
    pub quarantined: usize,
    pub gaps_repaired: usize,
    pub more_work: bool,
}
```

- [ ] **Step 6: Run engine and admission regressions**

Run:

```bash
cargo fmt --all -- --check
cargo test -p context-relay-core --test sync_engine_v1
cargo test -p context-relay-core --test sync_admission_v1 --test sync_merge_v1
```

Expected: all pass; provider faults change delivery, never the final admitted
state.

- [ ] **Step 7: Commit**

```bash
git add crates/core
git commit -m "feat: synchronize through an in-memory ciphertext transport"
```

---

### Task 6: Signed checkpoints and deterministic retry scheduling

**Files:**
- Create: `crates/core/src/sync/checkpoint.rs`
- Create: `crates/core/src/sync/backoff.rs`
- Create: `crates/core/tests/sync_checkpoint_v1.rs`
- Create: `crates/core/tests/sync_backoff_v1.rs`
- Modify: `crates/core/src/sync/engine.rs`
- Modify: `crates/core/src/vault/sync.rs`

**Interfaces:**
- Produces: `StateSummaryV1`, `build_checkpoint`, `verify_checkpoint`, `BackoffPolicy`, and checkpoint scheduling in `SyncEngine`.
- Consumes: current record head sets, Task 2 identity/signing, and Task 5 transport.

- [ ] **Step 1: Write RED state-hash, fork, pin, and backoff tests**

Use fixed head sets in different insertion orders and require one state hash.
Reject altered state/frontier/previous hash/key epoch/signature. Prove a fork
behind a locally pinned checkpoint is an integrity error. Table-drive full
jitter bounds for attempts 0 through 63 with an injected random source.

- [ ] **Step 2: Run focused tests and confirm RED**

Run:

```bash
cargo test -p context-relay-core --test sync_checkpoint_v1 --test sync_backoff_v1
```

Expected: compile failure because checkpoint/backoff modules do not exist.

- [ ] **Step 3: Implement deterministic state summaries**

Encode a definite array ordered by record UUID. Each entry contains record UUID,
record kind, ordered canonical head hashes, and tombstone/conflict booleans.
`state_hash` is SHA-256 of those bytes. The checkpoint builder uses the signed
account/workspace IDs, current frontier, last canonical checkpoint hash or zero,
current key epoch, creator device, and injected HLC, then signs and
canonical-hashes the checkpoint. Verification rejects any out-of-band scope
relabel even when the same device key is trusted in both scopes.

The ten-field scoped checkpoint uses `CHECKPOINT_SCHEMA_VERSION = 2`, while
operations remain `SYNC_SCHEMA_VERSION = 1`. Every checkpoint transport method
selects version 2 explicitly and providers partition/filter checkpoint logs by
that version. Pre-contract remote version 1 logs must be retained separately or
retired; old clients cannot join a version 2 chain. This is a pre-release
contract change and no hosted checkpoint transport exists yet.

Use these exact summary types:

```rust
pub struct StateSummaryEntryV1 {
    pub record_id: RecordId,
    pub record_kind: RecordKind,
    pub head_hashes: Vec<Sha256Digest>,
    pub tombstoned: bool,
    pub conflicted: bool,
}

pub struct StateSummaryV1 {
    pub entries: Vec<StateSummaryEntryV1>,
}
```

- [ ] **Step 4: Verify and pin checkpoints**

Verify signed scope, certificate trust, and signature before state
recomputation. Authenticate every historical link independently of current
local state; compare frontier/state only for the newest provider endpoint.
Persist a provider-scoped hash-anchored scan cursor so a chain longer than the
per-cycle bound resumes after reopen. Require the chain to include the exact
newest local pin, unless no pin exists, and switch the workspace pin atomically
only to the newest applicable endpoint. The Vault endpoint API must accept the
row, replace the pin, reset the schedule, and rebase the provider scan in one
transaction. `SyncTransport::checkpoint_by_hash` is required and every wrapper
must forward exact scoped lookup. Schema 18 requests replacement checkpoints
and retires all pre-scope-bound pins first, then their checkpoint rows; it never
decodes the old eight-field bytes. Never accept omission, cursor-anchor
tampering, or a server fork around a pin.

When checkpoint generation is due and a complete authenticated endpoint lags
local state, the same cycle builds the new checkpoint after that endpoint,
verifies the complete chain against the unchanged local pin, and atomically
pins the new node while removing the scan. Before pinning every local append,
re-read the provider. A previously empty log must contain only the signed local
genesis; an authenticated endpoint must have the signed local checkpoint as its
sole next node; both require an empty tail. Provider append is conditional on
the current endpoint. If a provider nevertheless reports an omitted checkpoint
or concurrent sibling as accepted, the endpoint proof fails and leaves the
local pin and requested schedule unchanged.

- [ ] **Step 5: Implement full-jitter retry policy**

```rust
pub struct BackoffPolicy {
    pub base_ms: u64,
    pub cap_ms: u64,
}

impl BackoffPolicy {
    pub const DEFAULT: Self = Self { base_ms: 1_000, cap_ms: 60_000 };
    pub fn next_delay(&self, attempt: u32, random_u64: u64) -> u64;
}
```

Compute the capped exponential bound without overflow, then return
`random_u64 % (bound + 1)`. Only `offline`, `transient`, and provider 5xx
failures schedule retries. Stable integrity/auth/revocation/quota errors remain
blocked until state changes. The Vault records checkpoint age from injected
local commit/apply time, never signed HLC. An explicit state-change API may
resume only selected rows whose stable error matches that change, without
resetting attempt counts; integrity quarantine cannot use this API.

- [ ] **Step 6: Run checkpoint, engine, and Vault suites**

Run:

```bash
cargo fmt --all -- --check
cargo test -p context-relay-core --test sync_checkpoint_v1 --test sync_backoff_v1
cargo test -p context-relay-core --test sync_engine_v1
cargo test -p context-relay-core --features test-support --test sync_vault_v1
```

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add crates/core
git commit -m "feat: add signed sync checkpoints and retry policy"
```

---

### Task 7: Randomized offline convergence checkpoint

**Files:**
- Create: `crates/core/tests/signed_sync_e2e_v1.rs`
- Create: `docs/verification/task-16.md`
- Modify only files required by validated review findings

**Interfaces:**
- Consumes: complete replica-core interface from Tasks 1–6.
- Produces: a reviewed, documented in-memory end-to-end checkpoint for the next cloud-admission plan.

- [ ] **Step 1: Write deterministic randomized convergence tests**

Implement a small fixed xorshift generator in the test file; do not add a random
dependency. For seeds `0..256`, create two to five replicas and generate
upserts, tombstones, concurrent updates, disconnects, reconnects, duplicate,
delay, drop, reverse, crash/reopen, and lost-hint actions. Bound every run to
10,000 actions. After faults stop, call `sync_until_idle` and assert:

```rust
assert_equal_state_hashes(&replicas);
assert_equal_frontiers(&replicas);
assert_equal_ordered_conflicts(&replicas);
assert_all_outboxes_empty(&replicas);
assert_no_plaintext_canary(&replicas, &provider, &captured_logs);
```

Add explicit non-convergence cases for a quarantined broken chain and assert the
same safe quarantine reason on every observing replica.

- [ ] **Step 2: Run the end-to-end test and confirm GREEN**

Run:

```bash
cargo test -p context-relay-core --features test-support --test signed_sync_e2e_v1
```

Expected: all 256 seeds pass; quarantined-chain cases stop safely and do not
claim convergence.

- [ ] **Step 3: Run independent security and correctness reviews**

Review the complete replica-core diff for signature-before-decryption order,
certificate trust, nonce reuse, sequence/hash/frontier bypass, canonical replay,
cursor skipping, transaction atomicity, conflict loss, unsafe errors, canary
leaks, migration determinism, and test quality. Add a failing regression before
each validated fix and re-review until both dispositions approve.

- [ ] **Step 4: Run focused and workspace gates**

Run:

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
pnpm lint
pnpm typecheck
pnpm test --run
pnpm build
pnpm check:bindings
pnpm check:schemas
pnpm license:check
git diff --check
git status --short
```

Expected: all pass. If this Mac still lacks Cargo, do not modify unrelated code;
record the exact environment blocker and run every available Node/desktop gate.

- [ ] **Step 5: Write the Task 16 replica-core ledger**

Record exact commits, vectors, seed count, focused/workspace gate results,
security/correctness review dispositions, plaintext-canary evidence, and the
remaining cloud-admission/transport work. Do not claim Task 16 complete until
the Supabase and credential-dependent completion evidence exists.

- [ ] **Step 6: Commit the checkpoint**

```bash
git add crates docs/verification/task-16.md
git commit -m "feat: add signed sync replica core"
```

Do not push or merge without a separate publication request.
