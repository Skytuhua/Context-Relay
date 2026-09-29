# Existing-Device Pairing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement an existing-device pairing flow that issues an exact signed device certificate
and encrypted workspace key grant, proven end to end between two SQLCipher-backed daemon replicas
through an injected in-memory provider.

**Architecture:** Canonical protocol request types feed a core `PairingCoordinator`. The
coordinator owns cryptographic verification and durable Vault transitions while a narrow
`PairingTransport` owns locator-code, expiry, attempt, and compare-and-set provider state. Private
device keys stay behind a protected device identity store; React consumes phase-specific local IPC
results and never sees private or workspace keys.

**Tech Stack:** Rust 1.97.1, deterministic CBOR/minicbor, Ed25519, X25519,
XChaCha20-Poly1305, HMAC-SHA-256, SQLCipher/rusqlite, Tokio contextd worker, Tauri 2, React,
TypeScript, Vitest, Testing Library.

## Global Constraints

- Pairing codes are ten Crockford Base32 characters displayed as `XXXXX-XXXXX`.
- Codes expire exactly 600,000 milliseconds after provider creation and a provider-authenticated
  join session is exhausted after five wrong submissions.
- A code locates one invite and never grants trust; a yes/no decision binds one exact digest.
- The daemon supplies device ID, native platform, request nonce, public keys, signatures, and
  encrypted key material. IPC callers supply only code, device name, pairing ID, exact digest, and
  yes/no where appropriate.
- Existing-device approval binds account, workspace, request nonce, device ID, signing key,
  wrapping key, and active control epoch.
- Unknown fields, changed canonical bytes, replay substitutions, and state conflicts fail closed.
- No raw pairing code, device private key, workspace root key, active epoch key, or decrypted grant
  may enter React, logs, provider records, or unencrypted files.
- The daemon process lock is acquired before the protected device identity store is read or written;
  this slice does not claim cross-process compare-and-set semantics from the OS keyring.
- The in-memory provider is a deterministic proof transport, not a production cross-device
  service. When no production transport is configured, the UI reports pairing unavailable.
- No Supabase mutation, GitHub OAuth change, paid Apple Developer action, recovery, revocation,
  reassociation, or deletion is part of this plan.
- Each task is implemented test-first, committed separately, and reviewed before the next task.

---

## File structure

- `crates/protocol/src/pairing.rs`: public pairing request schema, canonical CBOR, and validation.
- `crates/core/src/devices/crypto.rs`: request signing/verification, certificate/grant encoding,
  key-bundle wrapping, and exact grant verification.
- `crates/core/src/devices/transport.rs`: provider trait and bounded data transfer objects.
- `crates/core/src/devices/memory_transport.rs`: deterministic provider-like test transport.
- `crates/core/src/devices/identity.rs`: protected local device-key loading and generation.
- `crates/core/src/devices/pairing.rs`: coordinator state machine and crash-resume orchestration.
- `crates/core/src/vault/devices.rs`: SQLCipher certificate, request, decision, and join persistence.
- `crates/contextd/src/pairing.rs`: local IPC adapter from daemon commands to the coordinator.
- `apps/desktop/src/devices.tsx`: accessible Devices screen with invite, join, review, and result UI.

The existing large `vault.rs`, `contextd/lib.rs`, and `App.tsx` files receive only module wiring and
dispatch changes; feature logic remains in the focused files above.

---

### Task 1: Freeze canonical pairing request and IPC phases

**Files:**
- Create: `crates/protocol/src/pairing.rs`
- Create: `crates/protocol/tests/pairing_request_v1.rs`
- Create: `crates/protocol/tests/fixtures/pairing-request-v1.hex`
- Create: `crates/protocol/tests/fixtures/pairing-request-signing-preimage-v1.hex`
- Modify: `crates/protocol/src/lib.rs`
- Modify: `crates/protocol/src/ids.rs`
- Modify: `crates/protocol/src/ipc.rs`
- Modify: `crates/protocol/src/bin/export-bindings.rs`
- Modify: `crates/protocol/tests/pairing_v1.rs`
- Modify: `crates/protocol/tests/fixtures/runtime-contracts-v1.json`
- Modify: `apps/desktop/src/bindings.ts`
- Test: `apps/desktop/src/protocol-contracts.test.ts`

**Interfaces:**
- Produces: `PAIRING_SCHEMA_VERSION: u16 = 1`.
- Produces: `DeviceCertificateId`, a UUIDv7 newtype distinct from every record/device/pairing ID.
- Produces: `PairingRequestV1`, `encode_pairing_request_v1`,
  `decode_pairing_request_v1`, and `encode_pairing_request_signing_preimage_v1`.
- Produces: phase-specific `PairingInviteInfo`, `PairingRequestInfo`, and
  `PairingCompletionInfo` IPC result payloads.
- Changes: `PairingJoinParams` to `{ code: PairingCode, device_name: String }`.
- Preserves: `PairingDecisionParams { pairing_id, request_digest, approve }`.

- [ ] **Step 1: Write failing canonical-vector and mutation tests**

Add a fixed `PairingRequestV1` fixture with all fields nonzero. Assert an exact canonical hex
vector, signing-preimage vector, decode round trip, deterministic re-encode, 8 KiB request ceiling,
and rejection for map-size, field-order, unknown-key, duplicate-key, invalid platform, invalid
UUIDv7, invalid name, and trailing-byte mutations.

```rust
#[test]
fn pairing_request_v1_matches_the_frozen_vectors() {
    let request = support::pairing_request_fixture();
    assert_eq!(
        hex::encode(encode_pairing_request_v1(&request).unwrap()),
        include_str!("fixtures/pairing-request-v1.hex").trim()
    );
    assert_eq!(
        hex::encode(encode_pairing_request_signing_preimage_v1(&request).unwrap()),
        include_str!("fixtures/pairing-request-signing-preimage-v1.hex").trim()
    );
}
```

- [ ] **Step 2: Run the focused protocol test and capture RED**

Run:

```bash
cargo test -p context-relay-protocol --test pairing_request_v1 -- --nocapture
```

Expected: compilation fails because `PairingRequestV1` and its canonical functions do not exist.

- [ ] **Step 3: Implement the request schema and strict canonical codec**

Use a fixed nine-entry signed map and eight-entry signing-preimage map. Domain-separate the
preimage with `context-relay/pairing-request/v1`. Validate before encoding and after decoding.

```rust
pub const PAIRING_SCHEMA_VERSION: u16 = 1;
pub const MAX_PAIRING_REQUEST_BYTES: usize = 8 * 1024;

pub struct PairingRequestV1 {
    pub schema_version: u16,
    pub pairing_id: PairingId,
    pub request_nonce: PairingRequestNonce,
    pub device_id: DeviceId,
    pub device_name: String,
    pub platform: NativePlatform,
    pub signing_public_key: Ed25519PublicKeyBytes,
    pub wrapping_public_key: X25519PublicKeyBytes,
    pub signature: Ed25519SignatureBytes,
}
```

The decoder must require the exact schema version and exact integer keys; it must not accept a
generic serde map.

- [ ] **Step 4: Write failing IPC phase tests**

Prove that a React/local IPC join request cannot supply device ID, platform, nonce, or keys, and
that create/status responses can represent an invite before a joining request exists.

```rust
assert_eq!(
    serde_json::to_value(LocalRequest::PairingJoin(PairingJoinParams {
        code: PairingCode::new("01234-ABCDE".into()).unwrap(),
        device_name: "new laptop".into(),
    })).unwrap()["params"],
    serde_json::json!({"code":"01234-ABCDE","deviceName":"new laptop"})
);
```

- [ ] **Step 5: Implement phase-specific IPC results and regenerate bindings**

Replace the overloaded pairing result with:

```rust
PairingInvite { invite: PairingInviteInfo, status: PairingState },
PairingInviteStatus { invite: PairingInviteStatusInfo, status: PairingState },
PairingRequest { request: PairingRequestInfo, status: PairingState },
PairingApproval { approval: PairingApprovalInfo },
PairingCompletion { completion: PairingCompletionInfo },
```

`PairingInviteInfo` contains pairing ID, code, created time, and expiry time. `PairingRequestInfo`
contains no code and uses provider receipt time. Regenerate `apps/desktop/src/bindings.ts` with the
repository binding command and update only the affected runtime-contract hashes.
`PairingInviteStatusInfo` contains only the pairing ID and timestamps so a provider-backed pending
invite survives daemon restart without recovering, persisting, or returning the raw code again.
The authenticated provider status also preserves rejected and canceled terminal states so refresh
or restart cannot regress a terminal approval flow to pending.
`PairingApprovalInfo` carries the reviewed request and the approver-only full safety number.
`PairingConfirmParams { pairing_id, safety_number }` is a separate Desktop-only method; it is the
only IPC route that can invoke join confirmation, and joining status never returns the expected
number.

- [ ] **Step 6: Run protocol, binding, and desktop parity gates**

Run:

```bash
cargo test -p context-relay-protocol --all-features
pnpm check:bindings
pnpm --dir apps/desktop test --run protocol-contracts.test.ts schema-parity.test.ts
cargo fmt --all -- --check
git diff --check
```

Expected: every command passes; the full protocol integration count is at least the Task 16
baseline of 93 plus the new pairing tests.

- [ ] **Step 7: Commit the frozen contracts**

```bash
git add crates/protocol apps/desktop/src/bindings.ts apps/desktop/src/protocol-contracts.test.ts
git commit -m "feat: freeze signed pairing requests"
```

---

### Task 2: Implement request proof, exact certificate, and encrypted grant

**Files:**
- Create: `crates/core/src/devices/mod.rs`
- Create: `crates/core/src/devices/crypto.rs`
- Create: `crates/core/tests/device_pairing_crypto_v1.rs`
- Create: `crates/core/tests/fixtures/pairing-grant-v1.hex`
- Modify: `crates/core/src/lib.rs`
- Modify: `crates/core/src/crypto.rs`
- Modify: `crates/core/tests/crypto_v1.rs`

**Interfaces:**
- Consumes: canonical `PairingRequestV1` functions from Task 1.
- Produces: `SignedPairingRequest::build` and `verify_pairing_request`.
- Produces: zeroizing `PairingKeyBundle` with account/workspace/control/key epochs and two 32-byte
  secrets.
- Produces: `PairingGrant`, `encode_pairing_grant_v1`, `decode_pairing_grant_v1`,
  `build_pairing_grant`, and `verify_and_open_pairing_grant`.
- Produces: `pairing_request_fingerprint`, SHA-256 over the two algorithm-tagged public keys.

- [ ] **Step 1: Write failing signing, substitution, and wrapping tests**

Cover exact signature verification, request-field mutations, use of the wrong signing key, use of
the wrong wrapping key, account/workspace/control/key epoch changes, request/certificate digest
changes, wrong issuer, and AAD changes. Require `Debug` output for request/grant wrappers and secret
bundle to omit secret bytes.

```rust
let signed = SignedPairingRequest::build(pairing_id, device_id, "Laptop", platform, &joiner)?;
verify_pairing_request(signed.request())?;
let grant = build_pairing_grant(&signed, approval, &issuer_keys, &bundle)?;
let opened = verify_and_open_pairing_grant(&grant, &signed, &issuer_certificate, &joiner)?;
assert_eq!(opened.control_epoch(), 7);
```

- [ ] **Step 2: Run focused crypto RED**

Run:

```bash
cargo test -p context-relay-core --features test-support --test device_pairing_crypto_v1 -- --nocapture
```

Expected: compilation fails on the missing `devices` module and grant APIs.

- [ ] **Step 3: Add dedicated request signing methods**

Keep the generic Ed25519 signer private. Add domain-specific methods to `DeviceKeys`:

```rust
pub fn sign_pairing_request(&self, request: &mut PairingRequestV1) -> Result<(), CryptoError>;
pub fn verify_pairing_request(&self, request: &PairingRequestV1) -> Result<(), CryptoError>;
```

The public verifier uses `request.signing_public_key`; the method verifier additionally requires it
to equal the key object's public key.

- [ ] **Step 4: Implement zeroizing key-bundle and grant encoding**

Use a fixed canonical map for the public grant. Encode the secret bundle into a `Zeroizing<Vec<u8>>`,
wrap it with `wrap_secret`, and immediately zeroize the plaintext buffer. The AAD must be built by
one function used on both build and open paths:

```rust
fn grant_aad(
    pairing_id: PairingId,
    request_digest: Sha256Digest,
    certificate_digest: Sha256Digest,
    scope: SyncScope,
    control_epoch: u32,
    key_epoch: u32,
) -> Vec<u8>;
```

Convert `DeviceCertificateV1` to and from the grant wire format explicitly; never serialize its
`Debug` representation.

- [ ] **Step 5: Enforce exact approval fields**

Before signing a certificate, require request digest equality, request signature validity, active
issuer certificate equality, issuer private/public key equality, and exact scope/control epoch.
After opening, recheck every certificate field against the durable request before returning keys.

- [ ] **Step 6: Run crypto and protocol regressions**

Run:

```bash
cargo test -p context-relay-core --features test-support --test device_pairing_crypto_v1
cargo test -p context-relay-core --test crypto_v1
cargo test -p context-relay-protocol --all-features
cargo fmt --all -- --check
git diff --check
```

Expected: all pass and the existing crypto vectors remain unchanged.

- [ ] **Step 7: Commit the cryptographic grant**

```bash
git add crates/core/src/devices crates/core/src/crypto.rs crates/core/tests/device_pairing_crypto_v1.rs crates/core/tests/fixtures/pairing-grant-v1.hex
git commit -m "feat: issue exact encrypted pairing grants"
```

---

### Task 3: Build the provider-like in-memory pairing transport

**Files:**
- Create: `crates/core/src/devices/transport.rs`
- Create: `crates/core/src/devices/memory_transport.rs`
- Create: `crates/core/tests/device_pairing_transport_v1.rs`
- Modify: `crates/core/src/devices/mod.rs`
- Modify: `crates/core/Cargo.toml`

**Interfaces:**
- Produces: `PairingTransport`, `PairingTransportError`, `PairingInvite`, `PairingInviteStatus`,
  `StoredPairingRequest`, `PairingDecisionEnvelope`, `PairingResult`, and exact receipt types.
- Produces: `InMemoryPairingProvider::existing_device_client(scope, device_id)` and
  `join_session_client(session_id)`; caller identity is bound to the returned handle.
- Consumes: canonical requests and grants from Tasks 1–2.

- [ ] **Step 1: Write failing state-machine tests**

Create deterministic entropy/time fixtures and cover:

1. ten-character Crockford format and 600,000 ms expiry boundary;
2. four wrong codes followed by a correct code succeeds;
3. the fifth wrong code exhausts only that bound join session;
4. a second join session has an independent budget;
5. exact request retry is idempotent;
6. changed bytes for the same pairing ID conflict;
7. cancel/reject/approve are terminal compare-and-set transitions;
8. exact approval retry returns the same receipt;
9. changed grant, digest, scope, or caller conflicts;
10. no provider record contains the raw code or plaintext canary.

- [ ] **Step 2: Run focused transport RED**

```bash
cargo test -p context-relay-core --features test-support --test device_pairing_transport_v1 -- --nocapture
```

Expected: compile failure for the missing transport module.

- [ ] **Step 3: Implement bounded caller-scoped trait handles**

Use separate traits so a join client cannot call approval methods and an existing-device client
cannot reset attempt state:

```rust
pub trait PairingJoinTransport: Send + Sync {
    fn resolve_code(&self, code: &PairingCode, now_ms: u64) -> Result<PairingId, PairingTransportError>;
    fn submit_request(&self, pairing_id: PairingId, canonical: &[u8], now_ms: u64)
        -> Result<PairingRequestReceipt, PairingTransportError>;
    fn result(&self, pairing_id: PairingId, digest: Sha256Digest, now_ms: u64)
        -> Result<PairingResult, PairingTransportError>;
}

pub trait PairingApprovalTransport: Send + Sync {
    fn create_invite(&self, now_ms: u64) -> Result<PairingInvite, PairingTransportError>;
    fn invite_status(&self, pairing_id: PairingId, now_ms: u64)
        -> Result<PairingInviteStatus, PairingTransportError>;
    fn request(&self, pairing_id: PairingId, now_ms: u64)
        -> Result<Option<StoredPairingRequest>, PairingTransportError>;
    fn decide(&self, envelope: PairingDecisionEnvelope, now_ms: u64)
        -> Result<PairingDecisionReceipt, PairingTransportError>;
    fn cancel(&self, pairing_id: PairingId, now_ms: u64) -> Result<(), PairingTransportError>;
}
```

- [ ] **Step 4: Implement provider state and HMAC locator storage**

Add `hmac.workspace = true` to core. Store `HMAC-SHA-256(pepper, normalized_code)` and never the
code. Use provider-created UUIDv7 pairing IDs, checked arithmetic for expiry, bounded request/grant
bytes, and constant-time digest equality from the HMAC verification API. Remove expired records
only after state is first reported so expiry behavior is testable.

- [ ] **Step 5: Add exact idempotency and safe error codes**

Define stable `safe_code()` values only:

```text
pairing_invalid, pairing_exhausted, pairing_expired, pairing_canceled,
pairing_rejected, pairing_conflict, pairing_unauthorized, transient
```

`Display` and `Debug` must not contain codes, HMACs, request bytes, signatures, or grants.

- [ ] **Step 6: Run focused and static gates**

```bash
cargo test -p context-relay-core --features test-support --test device_pairing_transport_v1
cargo clippy -p context-relay-core --features test-support --test device_pairing_transport_v1 -- -D warnings
cargo fmt --all -- --check
git diff --check
```

Expected: all pass.

- [ ] **Step 7: Commit the transport**

```bash
git add Cargo.toml crates/core/Cargo.toml crates/core/src/devices crates/core/tests/device_pairing_transport_v1.rs
git commit -m "feat: add bounded pairing transport"
```

---

### Task 4: Persist device identity in the protected OS credential store

**Files:**
- Create: `crates/core/src/devices/identity.rs`
- Create: `crates/core/tests/device_identity_store_v1.rs`
- Modify: `crates/core/src/devices/mod.rs`
- Modify: `crates/core/src/crypto.rs`

**Interfaces:**
- Produces: `DeviceIdentityStore` with `load` and `store_if_absent`.
- Produces: `PlatformDeviceIdentityStore`, using a distinct `context-relay-device` keyring service.
- Produces: `load_or_create_device_keys(store, credential_id)` returning `DeviceKeys` without
  exposing seeds outside `devices::identity` and `crypto`.

- [ ] **Step 1: Write failing identity-store tests**

Use an in-memory store and prove first creation, second load, wrong byte length rejection, store
failure, load failure, zeroizing buffers, redacted debug output, and stable public keys after reopen.

```rust
let first = load_or_create_device_keys(&store, "device-a")?;
let signing = first.signing_public_key();
drop(first);
assert_eq!(load_or_create_device_keys(&store, "device-a")?.signing_public_key(), signing);
```

- [ ] **Step 2: Run identity-store RED**

```bash
cargo test -p context-relay-core --features test-support --test device_identity_store_v1 -- --nocapture
```

Expected: missing `DeviceIdentityStore` symbols.

- [ ] **Step 3: Implement a fixed 64-byte secret record**

Generate the two 32-byte seeds before constructing `DeviceKeys`, store one versioned 65-byte
record (`version || signing_seed || wrapping_seed`), and zeroize every temporary. `DeviceKeys`
receives a crate-private constructor accepting zeroizing seeds; it does not gain a public export.

- [ ] **Step 4: Implement the platform keyring adapter**

Follow the database key-store error and service-name patterns, but use a different keyring entry.
Never fall back to a file or SQLCipher row. A missing credential creates keys; malformed existing
credentials fail closed.

- [ ] **Step 5: Run identity and existing crypto tests**

```bash
cargo test -p context-relay-core --features test-support --test device_identity_store_v1
cargo test -p context-relay-core --test crypto_v1
cargo fmt --all -- --check
git diff --check
```

Expected: all pass.

- [ ] **Step 6: Commit protected identity persistence**

```bash
git add crates/core/src/crypto.rs crates/core/src/devices crates/core/tests/device_identity_store_v1.rs
git commit -m "feat: persist protected device identity"
```

---

### Task 5: Add forward-only Vault pairing persistence

**Files:**
- Create: `crates/core/migrations/0020_device_pairing.sql`
- Create: `crates/core/src/vault/devices.rs`
- Create: `crates/core/tests/device_pairing_vault_v1.rs`
- Modify: `crates/core/src/vault.rs`
- Modify: schema-version assertions in `crates/core/tests/sync_vault_v1.rs`,
  `sync_checkpoint_v1.rs`, `sync_engine_v1.rs`, `signed_sync_e2e_v1.rs`, and
  `vault_storage_v1.rs`

**Interfaces:**
- Produces: schema version 20.
- Produces: `Vault::store_device_certificate`, `device_certificate`, and `devices`.
- Produces: `prepare_pairing_decision`, `finish_pairing_decision`,
  `store_pairing_join_request`, and `finish_pairing_join` with exact replay dispositions.
- Produces: `pending_pairing_decisions` for restart resume.

- [ ] **Step 1: Write failing migration and exact-replay tests**

Require schema-19 upgrade preservation, schema-20 reopen, table constraints, UUID/kind validation,
unique `(account, workspace, device)` certificates, canonical hash/byte equality, prepared decision
resume, exact finish idempotency, conflicting finish rollback, exact join completion, and absence of
raw codes/private keys.

- [ ] **Step 2: Run Vault RED**

```bash
cargo test -p context-relay-core --features test-support --test device_pairing_vault_v1 -- --nocapture
```

Expected: schema remains 19 and the pairing persistence APIs are missing.

- [ ] **Step 3: Add schema 20 tables and constraints**

Create:

```sql
CREATE TABLE device_certificates (... canonical_bytes BLOB NOT NULL, canonical_sha256 BLOB NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('active','revoked')), UNIQUE(account_id,workspace_id,device_id));
CREATE TABLE pairing_decisions (... state TEXT NOT NULL CHECK (state IN ('prepared','accepted','rejected')),
    request_digest BLOB NOT NULL, canonical_grant BLOB, grant_sha256 BLOB, ...);
CREATE TABLE pairing_joins (... canonical_request BLOB NOT NULL, request_sha256 BLOB NOT NULL,
    certificate_id TEXT, wrapped_key_bundle BLOB, state TEXT NOT NULL CHECK (...));
```

Use full explicit column lists, 32-byte digest checks, state/nullable-field consistency checks, and
foreign keys from completed joins/decisions to certificate rows where applicable.

- [ ] **Step 4: Implement transaction-only persistence helpers**

Every insert computes SHA-256 from canonical bytes internally. Exact replay returns the existing
disposition; a different byte string under the same ID returns `VaultError::OperationConflict`.
Approval preparation stores the exact canonical grant before any provider call.

- [ ] **Step 5: Update migration fixtures without weakening downgrade tests**

Replace current-version literals with `LATEST_SCHEMA_VERSION`. Tests that deliberately recreate an
older schema must drop schema-20 tables before lowering `user_version`; do not edit historical
migration files.

- [ ] **Step 6: Run Vault, Task 16, and migration gates**

```bash
cargo test -p context-relay-core --features test-support --test device_pairing_vault_v1
cargo test -p context-relay-core --features test-support --test sync_vault_v1 --test vault_storage_v1
cargo test -p context-relay-core --features test-support --test signed_sync_e2e_v1
cargo fmt --all -- --check
git diff --check
```

Expected: all pass, including the 256-seed Task 16 regression.

- [ ] **Step 7: Commit Vault persistence**

```bash
git add crates/core/migrations/0020_device_pairing.sql crates/core/src/vault.rs crates/core/src/vault crates/core/tests
git commit -m "feat: persist exact pairing decisions"
```

---

### Task 6: Implement the crash-resumable pairing coordinator

**Files:**
- Create: `crates/core/src/devices/pairing.rs`
- Create: `crates/core/tests/device_pairing_e2e_v1.rs`
- Create: `crates/core/migrations/0021_pairing_confirmation.sql`
- Modify: `crates/core/src/devices/mod.rs`
- Modify: `crates/core/src/devices/crypto.rs`
- Modify: `crates/core/src/devices/transport.rs`
- Modify: `crates/core/src/devices/memory_transport.rs`
- Modify: `crates/core/src/vault/devices.rs`
- Modify: `crates/core/src/vault.rs`
- Test: `crates/core/tests/device_pairing_crypto_v1.rs`
- Test: `crates/core/tests/device_pairing_transport_v1.rs`
- Test: `crates/core/tests/device_pairing_vault_v1.rs`

**Interfaces:**
- Consumes: Tasks 1–5.
- Produces: `PairingCoordinator`, `WorkspacePairingMaterial`, `PairingClock`, and
  `PairingCycleError` with safe codes.
- Produces coordinator methods `create_invite`, `join`, `request_status`, `decide`, `cancel`,
  `join_status`, `confirm_join`, `completed_material`, and `resume_prepared_decisions`.
- Produces canonical `PairingApprovedPayloadV1`, `UnconfirmedPairingGrant`, and the fixed-format
  80-bit `PairingSafetyNumber`. No public opening API accepts caller/provider issuer bytes as trust.

- [ ] **Step 1: Write the complete two-replica RED scenario**

Open two real SQLCipher Vaults with independent device identities and one shared in-memory provider.
Seed the existing Vault with a recovery-root-signed genesis certificate and workspace material.
Execute invite, join, display, exact approve, poll, awaiting-confirmation persistence, exact safety
number entry, complete, close/reopen, and list devices. Assert the new certificate and reopened
sealed key bundle exactly match the active scope and epochs.

- [ ] **Step 2: Add negative and fault RED scenarios**

Cover five wrong codes, exact expiry boundary, cancel, reject, request substitution, digest
substitution, issuer certificate change between display and decision, control-epoch change,
certificate substitution, wrapping-key substitution, a self-consistent malicious issuer/grant
substitution, wrong/cross-pairing safety numbers, confirm-before-display, provider acceptance
followed by local crash, local preparation followed by transient provider failure, join completion
rollback, and exact retry. Prove no issuer, certificate, epoch, or opened key is persisted before
confirmation.

Use failpoints around the two non-atomic provider boundaries; do not use sleeps.

- [ ] **Step 3: Run coordinator RED**

```bash
cargo test -p context-relay-core --features test-support --test device_pairing_e2e_v1 -- --nocapture
```

Expected: missing `PairingCoordinator` methods.

- [ ] **Step 4: Implement create and join paths**

`join` resolves the code, creates and signs the request inside the daemon, persists the exact
request before submission, then submits by pairing ID. It never persists the raw code. A lost
submission receipt resumes from the stored pairing ID/request bytes.

- [ ] **Step 5: Implement exact review and resumable decision**

`request_status` re-verifies canonical bytes/signature/digest before producing display fields.
`decide` refetches and compares the exact digest, requires the active recovery-root-signed genesis
issuer and current epochs, loads workspace root/epoch keys through a coordinator-owned trusted
`PairingMaterialSource` that cannot be populated from decision IPC, builds one grant plus canonical
approved payload, persists `prepared`, sends the exact payload, and finishes the receipt. It returns
the locally derived safety number for display, and an accepted-decision getter recomputes the same
display after reopen.
`resume_prepared_decisions` sends only stored canonical payloads.

- [ ] **Step 6: Implement join verification and atomic completion**

Poll using the durable pairing ID/digest. On approval, inspect and persist the exact canonical
approved payload in schema 21 without opening it. `confirm_join` reloads/re-verifies the exact row,
compares the complete user-entered safety number, then opens and atomically persists certificate,
exact active inviter certificate, sealed grant/active epochs, transcript digest, and completion
receipt. The joining status never exposes its independently computed expected safety number.
Raw inspection/opening typestates and their transcript/safety getters are crate-private in normal
builds; only `test-support` exposes them for exact cryptographic regression tests. The legacy raw
Vault completion helper is likewise test-only, so `confirm_join` is the sole normal pre-completion
opening path. Authenticated join/approval transports are moved into the coordinator at the trusted
daemon composition root, and normal approved transport results plus stored Vault transcripts are
opaque projections that do not expose any approved-payload hash/bytes needed to derive the safety
number.
`completed_material` reopens only a confirmed durable payload with the stable protected device keys.
On rejection, expiry,
cancellation, mismatch, or conflict, do not mutate trust or keys.

- [ ] **Step 7: Add plaintext-canary evidence**

Put `TASK_17_PAIRING_KEY_CANARY_DO_NOT_LEAK` inside test key material. Check raw Vault, WAL, SHM,
provider records, captured safe errors, formatted `Debug`, and result JSON. The canary may appear
only after an explicit test-only decrypt inside the joining coordinator.

- [ ] **Step 8: Run e2e and broad core gates**

```bash
cargo test -p context-relay-core --features test-support --test device_pairing_e2e_v1
cargo test -p context-relay-core --features test-support --test device_pairing_crypto_v1 --test device_pairing_transport_v1 --test device_pairing_vault_v1
cargo test -p context-relay-core --features test-support --test signed_sync_e2e_v1
cargo clippy -p context-relay-core --all-features --lib -- -D warnings
cargo fmt --all -- --check
git diff --check
```

Expected: all pairing tests, all 256 Task 16 seeds, and static gates pass.

- [ ] **Step 9: Commit the coordinator**

```bash
git add crates/core/src/devices crates/core/src/vault/devices.rs crates/core/tests/device_pairing_e2e_v1.rs
git commit -m "feat: pair trusted device replicas"
```

---

### Task 7: Route pairing through contextd and authenticated local IPC

**Files:**
- Create: `crates/contextd/src/pairing.rs`
- Modify: `crates/contextd/src/lib.rs`
- Modify: `crates/local-ipc/tests/ipc_v1.rs`
- Test: `crates/contextd/tests/device_pairing_ipc_v1.rs` or the existing in-file contextd test module

**Interfaces:**
- Consumes: `PairingCoordinator` and phase-specific protocol results.
- Produces: `PairingService` injected into `VaultConfig`; absence returns one stable unavailable
  error without creating local-only invites.
- Changes: pairing, explicit confirmation, and device-list requests route to the single Vault
  worker.

- [x] **Step 1: Write failing route and authorization tests**

Assert pairing methods remain Desktop-only, are serialized through the Vault worker, return
unavailable when no service exists, and return phase-specific results with a configured shared
provider. Prove MCP/bridge roles cannot create, join, inspect, decide, or cancel pairing.

- [x] **Step 2: Run contextd/local IPC RED**

```bash
cargo test -p context-relay-contextd device_pairing -- --nocapture
cargo test -p context-relay-local-ipc pairing -- --nocapture
```

Expected: pairing requests still return the existing hosted-unavailable error.

- [x] **Step 3: Add injected service configuration**

Extend `VaultConfig` with an optional `Arc<PairingService>`, protected identity credential ID,
device name, and platform. Keep production default `None`; test builders explicitly inject one
shared in-memory provider through separate caller-scoped handles.

- [x] **Step 4: Route commands on the Vault worker**

Add `VaultCommand::Pairing(LocalRequest)` and handle create, join, status, decision, confirmation,
and cancel in `contextd/src/pairing.rs`. Convert only safe coordinator errors to `ClientError`;
never interpolate the raw internal error. `DevicesList` loads Vault device summaries rather than
returning a hard-coded current device.

- [x] **Step 5: Prove restart and queue behavior**

Close and reopen the approving daemon between preparation and provider retry. Ensure the worker
resumes the same decision before accepting a new decision. Saturate the request queue and prove no
pairing command bypasses single-writer admission. Reconstruct the service before a join request and
prove the provider-backed invite status remains pending without exposing the one-time raw code.

- [x] **Step 6: Run daemon, IPC, and protocol gates**

```bash
cargo test -p context-relay-contextd
cargo test -p context-relay-local-ipc
cargo test -p context-relay-protocol --all-features
cargo check --workspace --all-targets --all-features
cargo fmt --all -- --check
git diff --check
```

Expected: all pass.

- [x] **Step 7: Commit daemon integration**

```bash
git add crates/contextd crates/local-ipc
git commit -m "feat: expose exact device pairing over local IPC"
```

---

### Task 8: Build the accessible Devices pairing screen

**Files:**
- Create: `apps/desktop/src/devices.tsx`
- Create: `apps/desktop/src/devices.test.tsx`
- Modify: `apps/desktop/src/App.tsx`
- Modify: `apps/desktop/src/workspace.ts`
- Modify: `apps/desktop/src/styles.css`
- Modify: `apps/desktop/src/offline-workflow.test.tsx`

**Interfaces:**
- Consumes: Task 1 bindings and Task 7 local IPC behavior.
- Produces: `DeviceGateway` methods `devices`, `createPairingInvite`, `joinPairing`,
  `pairingStatus`, `decidePairing`, `confirmPairing`, and `cancelPairing`.
- Produces: `<DevicesScreen>` with list, invite, join, exact-review dialog, and status regions.

- [x] **Step 1: Write failing component tests**

Test trusted-device rendering/current marker, code creation/expiry text, cancel, join form, unavailable
state, exact review fields, request-digest change rejection, approver-only safety display, complete
joining safety entry, wrong-number rejection, yes/no actions, focus restoration, keyboard operation,
status announcement, and absence of key material in DOM snapshots.

```tsx
expect(screen.getByRole('dialog', { name: 'Approve new device' })).toHaveTextContent('Key fingerprint');
expect(screen.getByRole('button', { name: 'Approve device' })).toBeEnabled();
expect(screen.getByRole('button', { name: 'Reject device' })).toBeEnabled();
```

- [x] **Step 2: Run Devices screen RED**

```bash
pnpm --dir apps/desktop test --run devices.test.tsx
```

Expected: the Devices screen module and gateway methods are missing.

- [x] **Step 3: Implement typed gateway methods**

Map only exact `LocalResult` variants and throw on mismatches. Generate no device IDs, nonces, or
keys in TypeScript. Poll status only while an invite/request is pending and stop on unmount or a
terminal state.

- [x] **Step 4: Implement the Devices screen**

Move all Devices UI out of `App.tsx`. Use a form for code/name entry, a live status region for
expiry/result, and a native dialog for one yes/no approval. Capture the opening button and restore
focus on close. Before approval show only the fingerprint and digest supplied by the daemon; after
approval show the approver-only full safety number and require all five groups on the joining
device.

- [x] **Step 5: Preserve offline/unconfigured truthfulness**

When pairing is unavailable, keep the trusted-device list visible and show: `Pairing needs the
hosted device service and is not available in this build.` Do not create a process-local invite or
claim another physical device can connect.

- [x] **Step 6: Run desktop gates**

```bash
pnpm --dir apps/desktop test --run
pnpm --dir apps/desktop lint
pnpm --dir apps/desktop typecheck
pnpm --dir apps/desktop build
pnpm check:bindings
pnpm check:schemas
pnpm license:check
```

Expected: all pass and no secret-shaped field appears in rendered output.

- [x] **Step 7: Commit the Devices screen**

```bash
git add apps/desktop
git commit -m "feat: add exact device pairing screen"
```

---

### Task 9: Final verification, evidence ledger, and independent review

**Files:**
- Create: `docs/verification/task-17-pairing.md`
- Create: `.superpowers/sdd/task-17-pairing-report.md`
- Modify: `.superpowers/sdd/progress.md`

**Interfaces:**
- Consumes: all preceding tasks.
- Produces: exact RED/GREEN evidence, canonical hashes, gate results, review dispositions, and a
  handoff list for recovery-root enrollment and hosted transport.

- [x] **Step 1: Run the complete clean gate matrix**

Run each command fresh and record exact counts and runtimes:

```bash
cargo test -p context-relay-protocol --all-features
cargo test -p context-relay-core --features test-support --test device_pairing_crypto_v1 --test device_pairing_transport_v1 --test device_identity_store_v1 --test device_pairing_vault_v1 --test device_pairing_e2e_v1
cargo test -p context-relay-core --features test-support --test signed_sync_e2e_v1
cargo test -p context-relay-contextd
cargo test -p context-relay-local-ipc
cargo check --workspace --all-targets --all-features
cargo clippy -p context-relay-core --all-features --lib -- -D warnings
cargo fmt --all -- --check
pnpm --dir apps/desktop test --run
pnpm --dir apps/desktop lint
pnpm --dir apps/desktop typecheck
pnpm --dir apps/desktop build
pnpm check:bindings
pnpm check:schemas
pnpm license:check
git diff --check
```

Do not conceal inherited no-feature or strict-workspace lint failures; reproduce and record them
separately if they remain outside this diff.

- [x] **Step 2: Write the verification ledger**

Record commit range, fixture hashes, code/expiry/attempt boundaries, exact retry behavior,
crash-resume points, canary scan locations, two-daemon outcome, unavailable production behavior,
and every residual hosted dependency. State explicitly that Task 17 and hosted pairing are not
complete.

- [x] **Step 3: Request independent correctness and security reviews**

Correctness review focuses on state transitions, exact replay, persistence/reopen, queue routing,
and UI truthfulness. Security review focuses on code guessing, request proof, certificate fields,
issuer/epoch races, envelope AAD, key storage, provider caller binding, secret leakage, and replay.

Any Critical or Important finding returns to a focused failing regression and a follow-up review.
Do not accept the slice until both reviewers report no Critical or Important issue.

- [x] **Step 4: Run final hygiene and commit the ledger**

```bash
git status --short
git diff --check
git add docs/verification/task-17-pairing.md
git add -f .superpowers/sdd/task-17-pairing-report.md
git commit -m "docs: verify exact device pairing"
git status --short
```

Expected: clean worktree, no push, no merge, and a locally committed reviewed pairing slice.
