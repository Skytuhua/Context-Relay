# Recovery-Root Enrollment and First-Device Bootstrap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enroll a recovery root and first device from a one-time 24-word phrase, persist only
authenticated encrypted workspace material, survive daemon restart, and use that material to pair
and reopen a second SQLCipher replica.

**Architecture:** A phase-specific local IPC contract drives a core recovery coordinator. The
coordinator owns the memory-only phrase/challenge session, strict canonical recovery record, exact
provider compare-and-set, and atomic Vault activation; contextd supplies one ordered worker and the
Desktop renders the one-time phrase without browser persistence. The completed Vault becomes the
real material source for the existing safety-number-confirmed pairing flow.

**Tech Stack:** Rust 1.97.1, bip39, HKDF-SHA-256, Ed25519, X25519,
XChaCha20-Poly1305, deterministic CBOR/minicbor, SQLCipher/rusqlite, Tokio contextd worker,
authenticated local IPC, Tauri 2, React, TypeScript, Vitest, Testing Library.

## Global Constraints

- The phrase is BIP39 English: exactly 24 words generated from 256 bits of OS randomness.
- An unconfirmed enrollment exists only in daemon memory and expires at exactly 600,000
  milliseconds.
- Exactly four unique, sorted, one-based positions in 1 through 24 are challenged.
- A wrong, missing, extra, duplicate, or reordered answer consumes the session and requires a new
  phrase.
- The phrase and recovery private keys are never stored in SQLCipher, the protected identity store,
  browser storage, provider state, logs, errors, or crash evidence.
- The full phrase crosses authenticated local IPC only into the trusted Tauri Rust host, appears in
  one OS-native blocking dialog, and never enters a Tauri command result, JavaScript, React state,
  or the DOM.
- Recovery signing and wrapping keys use the frozen independent HKDF-SHA-256 labels.
- The canonical registration is signed by the recovery root under
  context-relay/recovery-enrollment-record/v1 followed by a NUL byte.
- Provider-only state is untrusted Conflict. Complete requires one exact locally active pin plus an
  identical provider projection.
- Provider compare-and-set coordinates honest races; it is not an independent root of trust for a
  completely unpinned client.
- Context Relay v1 binds one account to one workspace; every handle, record, receipt, and Vault row
  carries the same account/workspace pair.
- Initial control and key epochs are exactly 1.
- Recovery metadata and device material use separate complete AAD layouts and separate encrypted
  envelopes.
- Device private keys remain only in the context-relay-device protected store. Recovery private
  keys are never persisted there.
- Ordinary Desktop local IPC may invoke overview/status/cancel. Phrase-returning begin and final
  confirmation require the distinct DesktopRecoveryHost role, reached only through dedicated
  trusted Tauri Rust commands and OS-native phrase/approval dialogs. The generic renderer
  local_request path cannot select that role or dispatch begin/confirm.
- IPC never supplies scope, device identity, keys, certificate fields, epochs, entropy, or provider
  handles.
- Unconfigured production builds report that hosted recovery setup is unavailable.
- No Supabase mutation, GitHub OAuth change, Apple Developer action, deployment, push, or merge is
  part of this plan.
- Every task starts RED, becomes GREEN with the narrowest implementation, runs its regression gate,
  receives correctness/security review where indicated, and is committed separately.

---

## File structure

- crates/protocol/src/ids.rs owns type-distinct enrollment and recovery-root UUIDv7 IDs.
- crates/protocol/src/ipc.rs owns the five enrollment requests and phase-specific safe results.
- crates/core/src/devices/recovery_crypto.rs owns canonical registration, recovery-root signature,
  both encrypted envelopes, exact AAD construction, and opened material validation.
- crates/core/src/devices/recovery_transport.rs owns the authenticated provider contract and bounded
  projections.
- crates/core/src/devices/memory_recovery_transport.rs owns deterministic provider-like
  compare-and-set proof infrastructure.
- crates/core/src/vault/recovery.rs owns schema-22 row validation, prepared/active/conflict
  transitions, material reopen, and activation transaction.
- crates/core/src/devices/recovery.rs owns the memory-only challenge session and restart-safe
  coordinator.
- crates/contextd/src/recovery_enrollment.rs adapts authenticated local IPC to one ordered Vault
  worker.
- apps/desktop/src/devices.tsx renders recovery enrollment below trusted-device management.

Large existing files receive only exports, migration registration, dependency-root wiring, and
dispatch arms. Recovery behavior stays in the focused files above.

---

### Task 1: Freeze protocol 1.3 recovery-enrollment IPC

**Files:**
- Modify: crates/protocol/src/lib.rs
- Modify: crates/protocol/src/ids.rs
- Modify: crates/protocol/src/ipc.rs
- Modify: crates/protocol/src/bin/export-bindings.rs
- Create: crates/protocol/tests/recovery_enrollment_v1.rs
- Modify: crates/protocol/tests/protocol_v1.rs
- Modify: crates/protocol/tests/fixtures/runtime-contracts-v1.json
- Modify: crates/local-ipc/src/auth.rs
- Modify: crates/local-ipc/src/handshake_tests.rs
- Modify: crates/local-ipc/tests/ipc_v1.rs
- Modify: docs/protocols/protocol-v1.md
- Modify: apps/desktop/src/bindings.ts
- Modify: apps/desktop/src/protocol-contracts.test.ts
- Modify: apps/desktop/src/schema-parity.test.ts
- Modify: apps/desktop/src/App.test.tsx
- Modify: apps/desktop/src/offline-workflow.test.tsx

**Interfaces:**
- Produces: RecoveryEnrollmentId and RecoveryRootId UUIDv7 newtypes.
- Produces: ClientRole::DesktopRecoveryHost, confined to RecoveryEnrollmentBegin,
  RecoveryEnrollmentConfirm, and RecoveryEnrollmentCancel.
- Produces: RecoveryEnrollmentBegin, RecoveryEnrollmentOverview,
  RecoveryEnrollmentConfirm, RecoveryEnrollmentStatus, and RecoveryEnrollmentCancel requests.
- Produces: RecoveryEnrollmentPhrase, RecoveryEnrollmentChallenge, RecoveryEnrollmentStatus,
  RecoveryEnrollmentComplete, RecoveryEnrollmentHostBeginResult,
  RecoveryEnrollmentHostConfirmResult, RecoveryEnrollmentState, RecoveryWordConfirmation, and
  RecoveryEnrollmentIdParams. The two Host result enums are word-free projections returned by the
  dedicated Tauri commands.
- Changes: exact local protocol version from 1.2 to 1.3.
- Removes: unused generic RecoveryParams, RecoveryState, recovery_begin, recovery_complete, and
  LocalResult::Recovery.

- [x] **Step 1: Write failing strict IPC tests**

Add cases that deserialize the exact five methods, reject unknown scope/device/key/epoch fields,
validate four strictly increasing confirmations, and enforce status nullability.

~~~rust
let request = serde_json::from_value::<JsonRpcRequestV1>(json!({
    "jsonrpc": "2.0",
    "id": record_id(),
    "protocol": {"major": 1, "minor": 3},
    "daemonInstanceNonce": daemon_nonce(),
    "method": "recovery_enrollment_confirm",
    "params": {
        "enrollmentId": enrollment_id(),
        "confirmations": [
            {"position": 2, "word": "abandon"},
            {"position": 7, "word": "ability"},
            {"position": 13, "word": "able"},
            {"position": 24, "word": "about"}
        ]
    }
}))?;
assert!(matches!(request.request, LocalRequest::RecoveryEnrollmentConfirm(_)));
~~~

Add negative JSON fixtures for three/five entries, positions 0/25, duplicate/reordered positions,
uppercase/blank/33-byte words, full recoveryPhraseWords, accountId, workspaceId, deviceId, keys,
epochs, certificate, and unknown fields. Assert RecoveryEnrollmentPhrase Debug redacts all words
and that no non-phrase result serializes a word field. Format RecoveryWordConfirmation,
RecoveryEnrollmentConfirmParams, LocalRequest::RecoveryEnrollmentConfirm, and the containing RPC
request with Debug and assert none contains any submitted challenge word.
Add role-matrix assertions: Desktop permits overview/status/cancel but denies begin/confirm;
DesktopRecoveryHost permits begin/confirm/cancel only; MCP bridge and installer deny every
enrollment operation. The existing generic Tauri command receives ordinary Desktop in every case.

- [x] **Step 2: Run the focused protocol RED**

Run:

~~~bash
cargo test -p context-relay-protocol --test recovery_enrollment_v1 -- --nocapture
~~~

Expected: compilation fails because the enrollment identifiers, requests, and results do not
exist.

- [x] **Step 3: Implement the exact DTOs and validation**

Add the identifiers through the existing id_type macro. Replace the generic recovery DTOs with:

~~~rust
params!(RecoveryEnrollmentIdParams {
    enrollment_id: RecoveryEnrollmentId
});

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct RecoveryWordConfirmation {
    pub position: u8,
    pub word: String,
}

impl Drop for RecoveryWordConfirmation {
    fn drop(&mut self) {
        self.word.zeroize();
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct RecoveryEnrollmentConfirmParams {
    pub enrollment_id: RecoveryEnrollmentId,
    pub confirmations: Vec<RecoveryWordConfirmation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryEnrollmentState {
    Idle,
    AwaitingConfirmation,
    Submitting,
    Complete,
    Conflict,
}
~~~

RecoveryEnrollmentPhrase contains the ID, RecoveryPhraseWords, four positions, created_at_ms, and
expires_at_ms. RecoveryEnrollmentStatus contains optional ID/created/transitioned values and
validate() enforces the exact state matrix from the design. RecoveryEnrollmentComplete contains
the enrollment ID and DeviceSummary. LocalResult receives three explicit result variants:
RecoveryEnrollmentPhrase, RecoveryEnrollmentStatus, and RecoveryEnrollmentComplete. Implement
custom Debug for RecoveryWordConfirmation and RecoveryEnrollmentConfirmParams so only positions,
count, and a [REDACTED] marker survive recursive request/RPC formatting. RecoveryWordConfirmation
implements Drop with Zeroize on its String; cloned request values receive the same cleanup when
their independent ownership ends.
RecoveryEnrollmentChallenge contains only enrollment ID, confirmation positions, created_at_ms,
and expires_at_ms; it never contains words. Export these exact Tauri boundary results:

~~~rust
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum RecoveryEnrollmentHostBeginResult {
    Challenge(RecoveryEnrollmentChallenge),
    Status(RecoveryEnrollmentStatus),
}

#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum RecoveryEnrollmentHostConfirmResult {
    Canceled,
    Complete(RecoveryEnrollmentComplete),
    Status(RecoveryEnrollmentStatus),
}
~~~

Neither host enum has a Phrase variant. Include both in generated bindings and assert their JSON
schemas cannot carry recoveryPhraseWords.
Add DesktopRecoveryHost to ClientRole. In local-ipc role_allows, do not group it with Desktop:
match RecoveryEnrollmentBegin and RecoveryEnrollmentConfirm exclusively to DesktopRecoveryHost,
allow the shared cancellation primitive, and keep every other application request denied.

- [x] **Step 4: Capture protocol-version and generated-binding RED**

Set tests to expect PROTOCOL_VERSION 1.3, exact 1.2-to-1.3 handshake rejection in both directions,
and generated TypeScript carrying all new methods/types. Run:

~~~bash
cargo test -p context-relay-protocol --test protocol_v1 --test recovery_enrollment_v1
cargo test -p context-relay-local-ipc handshake_tests -- --nocapture
pnpm --dir apps/desktop test --run protocol-contracts.test.ts schema-parity.test.ts
~~~

Expected: current 1.2 constants, handshakes, and generated bindings fail the new assertions.

- [x] **Step 5: Bump exact local IPC to 1.3 and regenerate**

Set PROTOCOL_MINOR to 3, update frozen HMAC handshake vectors affected by the version-bound
transcript, update exact current-range fixtures, regenerate apps/desktop/src/bindings.ts with the
repository binding exporter, and refresh only runtime-contract hashes whose canonical bytes
changed.

- [x] **Step 6: Run the protocol compatibility gate**

Run:

~~~bash
cargo test -p context-relay-protocol --all-features
cargo test -p context-relay-local-ipc
pnpm check:bindings
pnpm --dir apps/desktop test --run protocol-contracts.test.ts schema-parity.test.ts App.test.tsx offline-workflow.test.tsx
pnpm --dir apps/desktop typecheck
cargo fmt --all -- --check
git diff --check
~~~

Expected: every command exits 0; 1.2 peers fail before application dispatch and current-to-current
1.3 succeeds.

- [x] **Step 7: Commit the frozen protocol boundary**

~~~bash
git add crates/protocol crates/local-ipc docs/protocols/protocol-v1.md apps/desktop/src/bindings.ts apps/desktop/src/protocol-contracts.test.ts apps/desktop/src/schema-parity.test.ts apps/desktop/src/App.test.tsx apps/desktop/src/offline-workflow.test.tsx
git commit -m "feat: freeze recovery enrollment protocol"
~~~

---

### Task 2: Implement canonical recovery registration and encrypted material

**Files:**
- Create: crates/core/src/devices/recovery_crypto.rs
- Modify: crates/core/src/devices/mod.rs
- Modify: crates/core/src/devices/crypto.rs
- Modify: crates/core/src/crypto.rs
- Create: crates/core/tests/recovery_enrollment_crypto_v1.rs
- Create: crates/core/tests/fixtures/recovery-enrollment-record-v1.hex
- Create: crates/core/tests/fixtures/recovery-enrollment-signing-preimage-v1.hex

**Interfaces:**
- Consumes: RecoveryPhrase, RecoveryKeys, DeviceKeys, DeviceCertificateV1,
  PairingKeyBundle, WrappedKeyEnvelope, SyncScope, the two new IDs, and NativePlatform.
- Produces: RECOVERY_ENROLLMENT_SCHEMA_VERSION = 1.
- Produces: MAX_RECOVERY_ENROLLMENT_RECORD_BYTES = 32 * 1024.
- Produces: RecoveryEnrollmentRecordV1 and RecoveryEnrollmentArtifacts.
- Produces: build_recovery_enrollment_artifacts, encode/decode record, encode signing preimage,
  open_recovery_metadata, and open_device_workspace_material.
- Changes: PairingKeyBundle canonical encode/decode helpers become crate-visible, not public.
- Produces under test-support only: deterministic phrase-from-entropy and artifact-with-RNG helpers;
  normal builds retain OS randomness and expose no caller-selected wrapping nonce/ephemeral key.

- [x] **Step 1: Write failing frozen-vector and exact-binding tests**

Use fixed UUIDv7 values, entropy, device seeds, request nonce, workspace keys, and wrapping
randomness. Freeze the 24-word phrase, recovery public keys, genesis certificate, unsigned
registration preimage, signed registration record, recovery envelope, and device envelope.

~~~rust
let fixture = support::recovery_enrollment_fixture();
assert_eq!(
    hex::encode(encode_recovery_enrollment_record_v1(&fixture.record)?),
    include_str!("fixtures/recovery-enrollment-record-v1.hex").trim()
);
assert_eq!(
    hex::encode(encode_recovery_enrollment_signing_preimage_v1(&fixture.record)?),
    include_str!("fixtures/recovery-enrollment-signing-preimage-v1.hex").trim()
);
assert_eq!(open_recovery_metadata(&fixture.record, &fixture.recovery_keys)?, fixture.bundle);
assert_eq!(
    open_device_workspace_material(
        &fixture.record,
        &fixture.device_material_envelope,
        fixture.device_id,
        &fixture.device_keys,
    )?,
    fixture.bundle
);
~~~

Mutate every record field, signature byte, map length/key/order, ciphertext bound, certificate
binding, display name/platform, both AAD fields, device keys, epochs, and cross-enrollment
envelopes. Require all mutations to fail and all secret-bearing Debug implementations to redact.
Add a test-support-only RecoveryPhrase::from_entropy_for_test([u8; 32]) and
build_recovery_enrollment_artifacts_with_rng with the production builder's complete argument list
plus a final &mut (impl CryptoRng + RngCore) so the frozen vector exercises the production algorithm
with deterministic entropy rather than hard-coded ciphertext. Compile-fail documentation must
prove neither helper exists without test-support.

- [x] **Step 2: Run focused crypto RED**

Run:

~~~bash
cargo test -p context-relay-core --features test-support --test recovery_enrollment_crypto_v1 -- --nocapture
~~~

Expected: compilation fails because recovery_crypto and its record APIs do not exist.

- [x] **Step 3: Add domain-specific recovery signing without exposing a generic signer**

Add crate-visible methods to RecoveryKeys and one public-key verifier path:

~~~rust
pub(crate) fn sign_enrollment_record(
    &self,
    preimage: &[u8],
) -> Ed25519SignatureBytes;

pub(crate) fn verify_enrollment_record_signature(
    signing_public_key: Ed25519PublicKeyBytes,
    preimage: &[u8],
    signature: Ed25519SignatureBytes,
) -> Result<(), CryptoError>;
~~~

The preimage begins with the exact NUL-terminated domain and appends one strict canonical map
containing every record field except recovery_root_signature. Do not reuse the certificate domain
or accept a caller-defined domain.

- [x] **Step 4: Implement the fixed canonical record codec**

Use one integer-keyed definite CBOR map, strict ascending keys, exact field count, canonical
re-encode comparison, and input-size check before decoder allocation.

~~~rust
pub struct RecoveryEnrollmentRecordV1 {
    pub schema_version: u16,
    pub enrollment_id: RecoveryEnrollmentId,
    pub recovery_root_id: RecoveryRootId,
    pub account_id: AccountId,
    pub workspace_id: WorkspaceId,
    pub recovery_signing_public_key: Ed25519PublicKeyBytes,
    pub recovery_wrapping_public_key: X25519PublicKeyBytes,
    pub genesis_certificate_id: DeviceCertificateId,
    pub genesis_certificate: DeviceCertificateV1,
    pub device_name: String,
    pub device_platform: NativePlatform,
    pub key_epoch: u32,
    pub encrypted_recovery_metadata: WrappedKeyEnvelope,
    pub recovery_root_signature: Ed25519SignatureBytes,
}
~~~

Validation requires schema 1; account/workspace/control/key epoch 1; nonblank UTF-8 name no longer
than 256 bytes; a RecoveryRoot genesis issuer matching the recovery signing key; exact device
keys/scope; contributory wrapping keys; and a valid full-record signature before returning decoded
data.

- [x] **Step 5: Implement the two envelope AADs and zeroizing bundle path**

Make PairingKeyBundle encode/decode crate-visible. Preallocate its fixed canonical buffer, keep it
inside Zeroizing<Vec<u8>>, and wrap identical bytes twice. Build AAD only through these functions:

~~~rust
fn recovery_metadata_aad(
    record: &RecoveryEnrollmentRecordV1,
    certificate_sha256: Sha256Digest,
) -> Vec<u8>;

fn device_workspace_material_aad(
    record: &RecoveryEnrollmentRecordV1,
    certificate_sha256: Sha256Digest,
    device_id: DeviceId,
    device_keys: &DeviceKeys,
) -> Vec<u8>;
~~~

Append fixed identifier/key bytes directly and epochs as big-endian u32. Include device ID,
signing key, and wrapping key only in the device AAD. The signed canonical record authenticates
device name/platform and the complete recovery envelope.

- [x] **Step 6: Implement one artifact builder and strict openers**

~~~rust
pub struct RecoveryEnrollmentArtifacts {
    pub record: RecoveryEnrollmentRecordV1,
    pub canonical_record: Vec<u8>,
    pub canonical_record_sha256: Sha256Digest,
    pub device_material_envelope: WrappedKeyEnvelope,
    pub device_material_envelope_sha256: Sha256Digest,
}

pub fn build_recovery_enrollment_artifacts(
    enrollment_id: RecoveryEnrollmentId,
    recovery_root_id: RecoveryRootId,
    certificate_id: DeviceCertificateId,
    certificate: DeviceCertificateV1,
    device_name: String,
    device_platform: NativePlatform,
    recovery_keys: &RecoveryKeys,
    device_keys: &DeviceKeys,
    material: &PairingKeyBundle,
) -> Result<RecoveryEnrollmentArtifacts, RecoveryEnrollmentCryptoError>;
~~~

The builder rejects mismatched certificate/material/device inputs before wrapping. Both openers
decode the canonical bundle, compare scope/epochs to the record and certificate, and return a
zeroizing PairingKeyBundle owner. The normal builder passes OsRng into one internal generic
implementation; the test-support helper passes the supplied deterministic CryptoRng/RngCore
instance into that same implementation.

- [x] **Step 7: Run focused and existing crypto gates**

Run:

~~~bash
cargo test -p context-relay-core --features test-support --test recovery_enrollment_crypto_v1 -- --nocapture
cargo test -p context-relay-core --features test-support --test crypto_v1 --test device_pairing_crypto_v1
cargo clippy -p context-relay-core --lib --all-features -- -D warnings -A clippy::large-enum-variant -A clippy::too-many-arguments
cargo fmt --all -- --check
git diff --check
~~~

Expected: frozen vectors and all mutation cases pass; existing certificate/pairing vectors remain
unchanged.

- [x] **Step 8: Commit recovery cryptography**

~~~bash
git add crates/core/src/crypto.rs crates/core/src/devices crates/core/tests/recovery_enrollment_crypto_v1.rs crates/core/tests/fixtures/recovery-enrollment-record-v1.hex crates/core/tests/fixtures/recovery-enrollment-signing-preimage-v1.hex
git commit -m "feat: add signed recovery enrollment records"
~~~

---

### Task 3: Implement authenticated provider compare-and-set proof

**Files:**
- Create: crates/core/src/devices/recovery_transport.rs
- Create: crates/core/src/devices/memory_recovery_transport.rs
- Modify: crates/core/src/devices/mod.rs
- Create: crates/core/tests/recovery_enrollment_transport_v1.rs

**Interfaces:**
- Consumes: RecoveryEnrollmentRecordV1 codec and SyncScope.
- Produces: RecoveryEnrollmentTransport, RecoveryRootStatus,
  RecoveryEnrollmentReceipt, RecoveryTransportError.
- Produces: InMemoryRecoveryEnrollmentProvider and scope-bound
  InMemoryRecoveryEnrollmentTransport.
- Keeps: provider construction and captured canonical bytes behind test-support or crate-owned
  dependency-root APIs; local IPC never accepts a transport.

- [x] **Step 1: Write failing transport contract tests**

Create two account/workspace handles and prove exact first registration, exact retry with identical
timestamp/receipt, same-account concurrent different-record conflict, different-workspace
conflict, wrong authenticated scope, forged record signature, invalid genesis certificate,
non-initial epochs, oversized bytes, changed canonical byte, and safe errors.

~~~rust
let receipt = handle.register(&canonical, 1_000)?;
assert_eq!(handle.root_status()?, Some(receipt.clone().into_status()));
assert_eq!(handle.register(&canonical, 9_999)?, receipt);
assert_eq!(
    handle.register(&changed_canonical, 10_000),
    Err(RecoveryTransportError::Conflict)
);
~~~

Scan provider captures and Debug output for a phrase canary, workspace root key, active epoch key,
and raw encrypted-envelope bytes. Captures may expose only bounded lengths/digests and public IDs.

- [x] **Step 2: Run focused transport RED**

Run:

~~~bash
cargo test -p context-relay-core --features test-support --test recovery_enrollment_transport_v1 -- --nocapture
~~~

Expected: compilation fails because recovery_transport and memory_recovery_transport are missing.

- [x] **Step 3: Define the exact scope-bound contract**

~~~rust
pub trait RecoveryEnrollmentTransport: Send + Sync {
    fn scope(&self) -> SyncScope;
    fn root_status(&self) -> Result<Option<RecoveryRootStatus>, RecoveryTransportError>;
    fn register(
        &self,
        canonical_record: &[u8],
        now_ms: u64,
    ) -> Result<RecoveryEnrollmentReceipt, RecoveryTransportError>;
}
~~~

Both projection structs carry enrollment ID, root ID, account ID, workspace ID, genesis
certificate ID, canonical SHA-256, and registered_at_ms. Add
validate_for(scope, record, digest, expected_registered_at_ms) methods that compare every field.

- [x] **Step 4: Implement strict in-memory provider registration**

Decode and verify before acquiring the terminal CAS write lock. Under the lock, key accepted records
by account ID and require the same workspace. Store the exact canonical bytes once. Exact byte retry
returns the original receipt; any different canonical record for that account conflicts. The
provider test helper may inject transient failures and forged projections without exposing raw
payload to normal callers.

- [x] **Step 5: Run transport and crypto regression gates**

Run:

~~~bash
cargo test -p context-relay-core --features test-support --test recovery_enrollment_transport_v1 --test recovery_enrollment_crypto_v1
cargo clippy -p context-relay-core --lib --all-features -- -D warnings -A clippy::large-enum-variant -A clippy::too-many-arguments
cargo fmt --all -- --check
git diff --check
~~~

Expected: both suites pass and no provider-only projection is treated as local trust.

- [x] **Step 6: Commit the provider proof boundary**

~~~bash
git add crates/core/src/devices crates/core/tests/recovery_enrollment_transport_v1.rs
git commit -m "feat: add recovery enrollment transport"
~~~

---

### Task 4: Persist schema-22 recovery enrollment atomically

**Files:**
- Create: crates/core/migrations/0022_recovery_enrollment.sql
- Create: crates/core/src/vault/recovery.rs
- Modify: crates/core/src/vault.rs
- Create: crates/core/tests/recovery_enrollment_vault_v1.rs
- Modify: crates/core/tests/vault_storage_v1.rs
- Modify: crates/core/tests/device_pairing_vault_v1.rs
- Modify: crates/core/tests/signed_sync_e2e_v1.rs
- Modify: crates/core/tests/sync_checkpoint_v1.rs
- Modify: crates/core/tests/sync_engine_v1.rs

**Interfaces:**
- Consumes: RecoveryEnrollmentArtifacts, DeviceKeys, strict record/open functions,
  RecoveryEnrollmentReceipt, and existing device-certificate storage validation.
- Produces: LATEST_SCHEMA_VERSION = 22.
- Produces: StoredRecoveryEnrollment, RecoveryEnrollmentPersistenceState, and
  RecoveryEnrollmentWrite.
- Produces Vault methods: prepare_recovery_enrollment, recovery_enrollment,
  mark_recovery_enrollment_conflict, activate_recovery_enrollment, and
  enrolled_workspace_material.

- [x] **Step 1: Write schema and API compile RED**

Write tests for an empty schema-21 Vault upgrading to 22 and for missing public APIs:

~~~rust
let disposition = vault.prepare_recovery_enrollment(&write)?;
assert_eq!(disposition, CommitDisposition::Inserted);
let stored = vault.recovery_enrollment()?.expect("prepared row");
assert_eq!(stored.state, RecoveryEnrollmentPersistenceState::Prepared);
~~~

Run:

~~~bash
cargo test -p context-relay-core --features test-support --test recovery_enrollment_vault_v1 -- --nocapture
~~~

Expected: compilation fails on the missing recovery Vault module and methods.

- [x] **Step 2: Add the strict migration**

Create one recovery_enrollments table with exact text UUID columns, canonical registration bytes
and 32-byte hash, device envelope bytes and 32-byte hash, duplicated public keys/epochs, state,
nullable activated_certificate_id, and four timestamps. Add checks:

~~~sql
CHECK (control_epoch = 1),
CHECK (key_epoch = 1),
CHECK (length(canonical_record_sha256) = 32),
CHECK (length(device_envelope_sha256) = 32),
CHECK (
  (state = 'prepared' AND activated_certificate_id IS NULL
    AND provider_accepted_at_ms IS NULL AND completed_at_ms IS NULL
    AND conflict_at_ms IS NULL)
  OR
  (state = 'active' AND activated_certificate_id = genesis_certificate_id
    AND provider_accepted_at_ms IS NOT NULL AND completed_at_ms IS NOT NULL
    AND conflict_at_ms IS NULL)
  OR
  (state = 'conflict' AND activated_certificate_id IS NULL
    AND completed_at_ms IS NULL AND conflict_at_ms IS NOT NULL)
),
FOREIGN KEY (activated_certificate_id)
  REFERENCES device_certificates(certificate_id)
~~~

Use unique account_id, unique workspace_id, unique recovery_root_id, and unique device_id
constraints to enforce the single-workspace/account v1 model. Register migration 22 after 21 and
preserve every schema-21 table/row.

- [x] **Step 3: Implement one strict stored-row decoder**

Select every column for every read/transition. Recompute both hashes; decode and verify the signed
record; compare all duplicated IDs, scope, device/certificate/public keys, epochs, state, and
timestamps. Reject any mismatch as VaultError::Validation before returning or mutating.

~~~rust
pub struct RecoveryEnrollmentWrite {
    pub canonical_record: Vec<u8>,
    pub canonical_record_sha256: Sha256Digest,
    pub device_material_envelope: WrappedKeyEnvelope,
    pub device_material_envelope_sha256: Sha256Digest,
    pub prepared_at_ms: u64,
}
~~~

prepare_recovery_enrollment is Inserted or ExactReplay only; a changed byte, hash, timestamp,
envelope, root, device, or scope is OperationConflict.

- [x] **Step 4: Capture atomic activation RED**

Add a test-only SQLite trigger that aborts after the certificate insert but before the enrollment
update. Call activate, close/reopen, and assert no active certificate, no active material, and the
prepared row remains retryable.

~~~rust
assert!(vault.activate_recovery_enrollment(&receipt, &device_keys, 3_000).is_err());
drop(vault);
let mut reopened = reopen(path, key);
assert!(reopened.device_certificate(certificate_id)?.is_none());
assert_eq!(
    reopened.recovery_enrollment()?.unwrap().state,
    RecoveryEnrollmentPersistenceState::Prepared
);
~~~

- [x] **Step 5: Implement one activation transaction**

Within one Transaction, reload/validate the prepared row, exact-validate the receipt, open the
device envelope with stable DeviceKeys, validate the material against record/certificate, insert
or exact-validate the active genesis certificate and display, set activated_certificate_id, store
provider/completed timestamps, and transition to active. Any error rolls back every sub-write.

enrolled_workspace_material reloads the full active row and certificate, verifies both hashes and
all bindings, opens only on demand, and returns WorkspacePairingMaterial without caching plaintext.

- [x] **Step 6: Add persisted-row tamper and migration coverage**

Individually alter every duplicated ID, public key, epoch, canonical hash, envelope hash, state,
timestamp, activated certificate, display field, and canonical/envelope byte column through a raw
test connection. Assert getters, exact replay, activation, and material open fail closed. Seed real
schema-21 device/pairing/sync rows before migration and prove they remain readable after version 22.

- [x] **Step 7: Run Vault and inherited schema gates**

Run:

~~~bash
cargo test -p context-relay-core --features test-support --test recovery_enrollment_vault_v1 -- --nocapture
cargo test -p context-relay-core --features test-support --test vault_storage_v1 --test device_pairing_vault_v1 --test signed_sync_e2e_v1 --test sync_checkpoint_v1 --test sync_engine_v1
cargo clippy -p context-relay-core --lib --all-features -- -D warnings -A clippy::large-enum-variant -A clippy::too-many-arguments
cargo fmt --all -- --check
git diff --check
~~~

Expected: schema 21 upgrades to 22, every tamper fails closed, injected activation failure rolls
back, and all pairing/sync migrations remain green.

- [x] **Step 8: Commit schema-22 persistence**

~~~bash
git add crates/core/migrations/0022_recovery_enrollment.sql crates/core/src/vault.rs crates/core/src/vault/recovery.rs crates/core/tests
git commit -m "feat: persist recovery enrollment"
~~~

---

### Task 5: Build the recovery coordinator and real recovery-to-pairing proof

**Files:**
- Create: crates/core/src/devices/recovery.rs
- Modify: crates/core/src/devices/mod.rs
- Modify: crates/core/src/devices/pairing.rs
- Modify: crates/core/tests/device_pairing_e2e_v1.rs
- Create: crates/core/tests/recovery_enrollment_e2e_v1.rs

**Interfaces:**
- Consumes: schema-22 Vault API, RecoveryEnrollmentTransport, DeviceKeys, RecoveryPhrase,
  RecoveryKeys, DeviceCertificateV1, RecoveryEnrollmentArtifacts, and protocol result DTOs.
- Produces: RecoveryEnrollmentClock, RecoveryEnrollmentEntropy,
  RecoveryEnrollmentCoordinator, RecoveryEnrollmentCycleError, and
  VaultPairingMaterialSource.
- Changes: PairingMaterialSource::current_material receives &mut Vault and &DeviceKeys so the
  production source can decrypt active material while test sources remain deterministic.

- [x] **Step 1: Write the coordinator compile RED and deterministic session tests**

Use a fixed clock and xorshift entropy source. Assert begin returns 24 words once, four unique
sorted positions, no Vault/provider write before confirmation, status never returns words, and the
same session cannot be replayed.

~~~rust
let phrase = coordinator.begin(&mut vault, device_id, "First Mac", NativePlatform::Macos, &keys)?;
assert_eq!(phrase.recovery_phrase_words.as_words().len(), 24);
assert_eq!(phrase.confirmation_positions.len(), 4);
assert!(vault.recovery_enrollment()?.is_none());
assert!(transport.root_status()?.is_none());
~~~

Run:

~~~bash
cargo test -p context-relay-core --features test-support --test recovery_enrollment_e2e_v1 coordinator_ -- --nocapture
~~~

Expected: compilation fails because the coordinator and traits do not exist.

- [x] **Step 2: Implement the memory-only pending session**

Define a non-Clone pending struct holding RecoveryPhrase, RecoveryKeys, PairingKeyBundle,
artifacts, four positions, and timestamps. Give it redacted Debug; Drop relies on zeroizing owners.
Generate entropy, IDs, nonce, workspace keys, certificate, artifacts, and positions only after
both local and provider discovery are absent.

~~~rust
pub trait RecoveryEnrollmentClock: Send + Sync {
    fn now_ms(&self) -> u64;
}

pub trait RecoveryEnrollmentEntropy: Send + Sync {
    fn fill_bytes(&self, output: &mut [u8]) -> Result<(), RecoveryEnrollmentCycleError>;
}
~~~

Normal construction uses OsRng; deterministic constructors are crate-visible under test-support.
Derive four positions by unbiased rejection sampling, then sort and deduplicate before exposing.

- [x] **Step 3: Implement exact confirmation, expiry, and cancellation**

Every begin/overview/status/confirm/cancel first consumes sessions with now_ms greater than or equal
to expires_at_ms. confirm requires the same enrollment ID and four exact sorted position/word
pairs. On any mismatch, remove the pending session before returning one safe invalid-confirmation
error. On success, prepare the Vault row, drop the plaintext phrase/keys/material, register the
canonical record, exact-check receipt, and activate.

Test boundary times 599,999 and 600,000; wrong word/position, missing/extra/reordered answers;
cross-enrollment ID; duplicate confirm; cancel wrong ID; correct cancel; and coordinator Drop.

- [x] **Step 4: Implement restart discovery and provider reconciliation**

overview never generates. begin performs overview first. Durable prepared state exact-retries the
same canonical bytes; a matching receipt activates. Local active plus matching provider is
Complete. Provider-only, local-only, missing accepted state, forged field, or digest mismatch is
Conflict and never creates a phrase or certificate.

Test crash before confirm, crash after prepare/before provider, provider accept/before local
activation, reopen after active, provider deletion, provider-only injection, and changed receipt
fields.

- [x] **Step 5: Capture pairing-material integration RED**

Replace the static material source only in a new end-to-end case. Enroll Vault A, close/reopen it,
construct VaultPairingMaterialSource, create an invite, join from Vault B, approve with A's real
genesis certificate and reopened material, compare the full safety number, confirm on B, then
close/reopen both.

~~~rust
let first_material =
    first_vault.enrolled_workspace_material(&first_device_keys)?;
let second_material =
    second_vault.completed_pairing_material(pairing_id, &second_device_keys)?;
assert_eq!(first_material.scope(), second_material.scope());
assert_eq!(first_material.workspace_root_key(), second_material.workspace_root_key());
assert_eq!(first_material.active_epoch_key(), second_material.active_epoch_key());
~~~

Expected RED: PairingMaterialSource cannot access a Vault or stable DeviceKeys and the static
fixture remains required.

- [x] **Step 6: Add VaultPairingMaterialSource and finish the two-replica proof**

Change the trait to:

~~~rust
pub trait PairingMaterialSource: Send + Sync {
    fn current_material(
        &self,
        vault: &mut Vault,
        device_keys: &DeviceKeys,
        scope: SyncScope,
    ) -> Result<WorkspacePairingMaterial, PairingCycleError>;
}
~~~

VaultPairingMaterialSource calls enrolled_workspace_material and compares scope. Update existing
static test implementations to accept and ignore the two trusted inputs. In the end-to-end test,
also compare control/key epochs, inviter/child certificate graph, active states, and reopened
material from both SQLCipher files.

- [x] **Step 7: Add canary and broken-state coverage**

Use phrase, root-key, workspace-key, and epoch-key canaries. Scan raw Vault/WAL/SHM bytes,
test-support plaintext cells, provider safe captures, Debug/errors, and post-terminal coordinator
state. The authenticated initial phrase result is the single explicit allowed occurrence. Assert a
signed-record/certificate/envelope mutation prevents convergence and leaves no trust/material.

- [x] **Step 8: Run core recovery, pairing, and signed-sync gates**

Run:

~~~bash
cargo test -p context-relay-core --features test-support --test recovery_enrollment_e2e_v1 -- --nocapture
cargo test -p context-relay-core --features test-support --test recovery_enrollment_crypto_v1 --test recovery_enrollment_transport_v1 --test recovery_enrollment_vault_v1 --test device_pairing_crypto_v1 --test device_pairing_transport_v1 --test device_pairing_vault_v1 --test device_pairing_e2e_v1
cargo test -p context-relay-core --features test-support --test signed_sync_e2e_v1 --test sync_engine_v1 --test sync_checkpoint_v1 --test sync_backoff_v1
cargo check --workspace --all-targets --all-features
cargo clippy -p context-relay-core --lib --all-features -- -D warnings -A clippy::large-enum-variant -A clippy::too-many-arguments
cargo fmt --all -- --check
git diff --check
~~~

Expected: first-device enrollment and second-device pairing survive two Vault reopens; existing
pairing/signed-sync suites remain green.

- [x] **Step 9: Commit coordinator and integration**

~~~bash
git add crates/core/src/devices crates/core/tests
git commit -m "feat: bootstrap pairing from recovery enrollment"
~~~

---

### Task 6: Integrate contextd and authenticated local IPC

**Files:**
- Create: crates/contextd/src/recovery_enrollment.rs
- Modify: crates/contextd/src/lib.rs
- Modify: crates/contextd/src/pairing.rs
- Modify: crates/contextd/tests/daemon_v1.rs
- Create: crates/contextd/tests/recovery_enrollment_v1.rs
- Modify: crates/local-ipc/tests/ipc_v1.rs
- Modify: crates/local-ipc/src/frame.rs
- Modify: crates/local-ipc/src/connection.rs
- Modify: apps/desktop/src-tauri/Cargo.toml
- Modify: apps/desktop/src-tauri/src/main.rs

**Interfaces:**
- Consumes: RecoveryEnrollmentCoordinator, shared protected DeviceKeys, Vault, protocol DTOs, and
  the five enrollment requests.
- Produces: CoordinatorRecoveryEnrollmentService and UnavailableRecoveryEnrollmentService.
- Produces: OS-native Tauri 2 phrase-display and confirmation commands backed by
  tauri-plugin-dialog version 2 and a separate DesktopRecoveryHost authenticated client slot.
- Preserves: one daemon instance lock, one ordered bounded Vault worker, and listener readiness only
  after recovery/pairing resume.

- [x] **Step 1: Write failing role and unavailable-boundary tests**

Prove ordinary Desktop can call overview/status/cancel but receives ScopeDenied for begin/confirm.
Prove DesktopRecoveryHost can call begin/confirm/cancel but no other application method, and MCP
bridge and installer are denied before service dispatch. Prove no IPC parameter contains
scope/key/certificate/entropy fields and an unconfigured daemon returns exactly:

~~~text
Recovery setup needs the hosted workspace service and is not available in this build.
~~~

Run:

~~~bash
cargo test -p context-relay-local-ipc recovery_enrollment -- --nocapture
cargo test -p contextd --test recovery_enrollment_v1 unavailable -- --nocapture
~~~

Expected: compile/dispatch failures because the requests have no contextd service.

Add local-IPC unit coverage for an internal encode_json_frame helper returning
Zeroizing<Vec<u8>>. Assert its live bytes contain a phrase/confirmation canary for transmission,
explicit zeroize clears the allocation, and Debug does not print the payload. Cover server receive,
client request serialization, server response serialization, and client response parsing so raw
phrase/confirmation JSON buffers are wrapped immediately rather than dropped as ordinary Vec<u8>.

In apps/desktop/src-tauri tests, inject RecoveryPhrasePrompt/RecoveryApprovalPrompt plus delegates
into recovery_enrollment_begin_with and recovery_enrollment_confirm_with. Begin must delegate with
DesktopRecoveryHost, show the exact 24 numbered words only to the prompt, and return only
RecoveryEnrollmentHostBeginResult::Challenge. Declining phrase display must send exact cancel and
return RecoveryEnrollmentHostBeginResult::Status(Idle) only after that cancellation succeeds; a
cancel failure returns a safe retryable error and no phrase/challenge projection.
Declining/closing confirmation calls the confirm delegate zero times. Accepted confirmation
delegates exactly once with DesktopRecoveryHost, the exact enrollment ID/answers, and no
renderer-supplied role. The generic local_request_with helper rejects both begin and confirm before
its delegate.

- [x] **Step 2: Add a focused contextd service adapter**

Define a RecoveryEnrollmentService trait with begin, overview, confirm, status, cancel, and
resume_prepared. CoordinatorRecoveryEnrollmentService owns the coordinator and immutable device
metadata; every method accepts &mut Vault from the existing worker closure. Map core errors to
bounded client errors without source chains.

- [x] **Step 3: Wire identity and startup ordering**

Load/create the protected DeviceKeys after the instance guard whenever pairing or recovery is
configured. Build both services from the same stable keys. During startup:

~~~text
acquire instance guard
  -> load protected device identity
  -> open and migrate Vault
  -> resume prepared recovery enrollment
  -> resume prepared pairing decisions/joins
  -> publish authenticated listener
~~~

Inject a barrier recorder in tests and assert this exact order. A transient resume leaves the
durable row prepared but reports startup failure before listener readiness; a conflict records safe
conflict and permits read-only status without creating another phrase.

- [x] **Step 4: Route all five requests through the ordered Vault queue**

Add dispatch arms that capture only validated protocol fields and enqueue one Vault worker job.
Queue-full returns the existing bounded busy error. begin returns Phrase or Status depending on
discovery; overview/status return RecoveryEnrollmentStatus; confirm returns Complete or Status;
cancel returns Status Idle. The server role allowlist admits phrase-returning begin and confirm only
from DesktopRecoveryHost; contextd still validates that role before enqueuing either operation.

Change write_json to serialize into Zeroizing<Vec<u8>> before write_frame. Wrap every read_frame
result in Zeroizing before serde parsing inside read_json and ServerConnection::next_request, and
make ClientConnection request serialization use the same zeroizing encoder. Keep write_frame/read_frame
wire signatures stable for non-JSON framing tests; no sensitive payload is cloned into a second
ordinary Vec inside the connection path.

- [x] **Step 5: Add trusted native user-presence enforcement**

Add tauri-plugin-dialog = "2" and zeroize.workspace = true to the Desktop Rust shell and initialize
the dialog plugin with tauri_plugin_dialog::init(). Define private RecoveryPhrasePrompt and
RecoveryApprovalPrompt traits for tests. The production phrase prompt builds one numbered 24-word
Zeroizing<String> entirely in Rust:

~~~rust
use std::fmt::Write as _;
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};
use zeroize::Zeroizing;

let mut message = Zeroizing::new(String::from(
    "Never share these words. Write them down in this exact order. Context Relay cannot restore a lost phrase.\n\n",
));
for (index, word) in phrase.recovery_phrase_words.as_words().iter().enumerate() {
    writeln!(&mut *message, "{}. {}", index + 1, word)
        .expect("writing to a String is infallible");
}
let saved = app
    .dialog()
    .message(message.as_str())
    .title("Save your 24-word recovery phrase")
    .buttons(MessageDialogButtons::OkCancelCustom(
        "I saved all 24 words".into(),
        "Go back".into(),
    ))
    .blocking_show();
~~~

The generic local_request Tauri command rejects RecoveryEnrollmentBegin and
RecoveryEnrollmentConfirm before delegation. Dedicated recovery_enrollment_begin uses a second
cached Client connection initialized with DesktopRecoveryHost, calls begin, and supplies the phrase
result directly to the native prompt without serializing it to the renderer. On saved, return only
RecoveryEnrollmentHostBeginResult::Challenge. On decline/close, send exact cancel and return
RecoveryEnrollmentHostBeginResult::Status(Idle). A daemon begin result other than Phrase or Status
is rejected before any Tauri response. If exact cancel fails, return the bounded retryable client
error instead of falsely reporting Idle; the daemon expiry remains the backstop.

Dedicated recovery_enrollment_confirm formats the exact four submitted position/word pairs inside
the native dialog plus the permanent-activation warning. Only its Activate recovery button sends
RecoveryEnrollmentConfirm through DesktopRecoveryHost. Decline/close returns a safe canceled
RecoveryEnrollmentHostConfirmResult::Canceled but leaves the daemon memory session and React
challenge intact. Successful daemon outcomes map only to Complete or Status host variants; every
other result is rejected. The renderer cannot submit a role, obtain the full phrase, or call the
host connection through generic LocalRequest.

The application-owned phrase/answer builders are Zeroizing<String>. Do not claim that the native
dialog toolkit zeroizes its internal trusted-process/OS copies; verify instead that their lifetime
ends with blocking_show and that they never enter persistence, logs, Tauri results, or renderer
state.

~~~rust
let mut message = Zeroizing::new(String::new());
for answer in &params.confirmations {
    writeln!(&mut *message, "Word {}: {}", answer.position, answer.word)
        .expect("writing to a String is infallible");
}
message.push_str(
    "\nContinue only if these match the phrase you personally saved. Activating permanently establishes recovery for this workspace.",
);
let approved = app
    .dialog()
    .message(message.as_str())
    .title("Activate this recovery phrase?")
    .buttons(MessageDialogButtons::OkCancelCustom(
        "Activate recovery".into(),
        "Go back".into(),
    ))
    .blocking_show();
~~~

- [x] **Step 6: Write two-daemon local-IPC recovery-to-pairing GREEN**

Start daemon A with an in-memory recovery provider, enroll through authenticated local IPC, restart
A, start daemon B with the shared pairing provider, and pair B through the already reviewed local
IPC safety-number flow. Reopen both daemon Vaults and assert both trusted-device lists and material
digests agree. Also cover crash after durable prepare and exact startup resume.

Run the socket test outside the sandbox when macOS denies Unix socket binding:

~~~bash
cargo test -p contextd --test recovery_enrollment_v1 -- --nocapture
cargo test -p contextd device_pairing_crosses_two_authenticated_daemons_without_exposing_joiner_safety -- --nocapture
cargo test -p context-relay-local-ipc
~~~

Expected: all tests pass; phrase bytes appear only in the authenticated begin response and native
phrase prompt, never in a Tauri command result, subsequent frame, renderer capture, or daemon log.

- [x] **Step 7: Run full daemon/local IPC and Tauri host regression gates**

Run:

~~~bash
cargo test -p contextd
cargo test -p context-relay-local-ipc
cargo test -p context-relay-desktop
cargo check --workspace --all-targets --all-features
cargo fmt --all -- --check
git diff --check
~~~

Expected: all commands exit 0. If the sandbox blocks Unix sockets, repeat only the socket-bearing
test command with the existing cargo-test escalation and record both results.

- [x] **Step 8: Commit daemon enrollment and native approval**

~~~bash
git add crates/contextd crates/local-ipc apps/desktop/src-tauri Cargo.lock
git commit -m "feat: require native recovery approval"
~~~

---

### Task 7: Add the one-time Desktop recovery experience

**Files:**
- Modify: apps/desktop/src/local-client.ts
- Modify: apps/desktop/src/local-client.test.ts
- Modify: apps/desktop/src/workspace.ts
- Modify: apps/desktop/src/devices.tsx
- Modify: apps/desktop/src/devices.test.tsx
- Modify: apps/desktop/src/styles.css
- Modify: apps/desktop/src/protocol-contracts.test.ts

**Interfaces:**
- Consumes: the five generated requests and three phase-specific results.
- Produces: gateway methods recoveryEnrollmentBegin, recoveryEnrollmentOverview,
  recoveryEnrollmentConfirm, recoveryEnrollmentStatus, and recoveryEnrollmentCancel.
- Changes: recoveryEnrollmentBegin and recoveryEnrollmentConfirm invoke dedicated Tauri commands;
  neither passes its LocalRequest variant through generic LocalClient.call/local_request.
- Preserves: no browser persistence, clipboard, download, telemetry, or key-shaped payload.

- [x] **Step 1: Write failing accessible UI tests**

Render the Devices screen with Idle, AwaitingConfirmation, Submitting, Complete, Conflict, and
unavailable gateway responses. Assert:

- Set up recovery appears only for Idle/available.
- Begin returns only RecoveryEnrollmentChallenge and immediately renders exactly four inputs labeled
  by challenged positions plus the exact 10-minute countdown.
- No phrase word is ever present in a gateway return, React prop/state, rendered element, hidden
  attribute, error, console capture, or snapshot.
- Confirm sends only enrollmentId and four position/word pairs.
- Generic local_request is never called with RecoveryEnrollmentBegin or
  RecoveryEnrollmentConfirm. The dedicated native begin command is called once; its canceled result
  remains Idle. The dedicated native confirm command is called once; a canceled native approval
  leaves the four challenge inputs visible.
- Wrong confirmation, expiry, terminal error, cancel, and unmount remove every challenge word from
  the DOM.
- Submitting after remount polls the exact durable ID without browser storage.
- Complete focuses the Recovery heading and refreshes DevicesList.
- Conflict never offers begin or phrase generation.
- localStorage/sessionStorage/clipboard/download/analytics are never called.

~~~tsx
await user.click(screen.getByRole("button", { name: "Set up recovery" }));
expect(nativeBegin).toHaveBeenCalledTimes(1);
expect(document.documentElement.outerHTML).not.toContain("abandon ability able");
expect(screen.getAllByRole("textbox")).toHaveLength(4);
expect(gateway.recoveryEnrollmentConfirm).toHaveBeenCalledWith({
  enrollmentId,
  confirmations: expectedFourAnswers,
});
expect(JSON.stringify(gateway.recoveryEnrollmentConfirm.mock.calls)).not.toContain(
  "recoveryPhraseWords",
);
~~~

- [x] **Step 2: Run focused Desktop RED**

Run:

~~~bash
pnpm --dir apps/desktop test --run devices.test.tsx
~~~

Expected: recovery controls and gateway methods are missing.

- [x] **Step 3: Implement gateway methods with generated types**

Overview/status/cancel use the existing authenticated generic invoke path and exact generated
request/result kind. recoveryEnrollmentBegin calls
invoke<RecoveryEnrollmentHostBeginResult>("recovery_enrollment_begin") and accepts only its
challenge/status variants. recoveryEnrollmentConfirm imports the generated params/result types and
calls invoke<RecoveryEnrollmentHostConfirmResult>("recovery_enrollment_confirm", { params })
directly. Neither method constructs a role or sends its request through local_request. Do not
define handwritten duplicates of protocol types. Status methods reject an unexpected result kind
before updating React state.

- [x] **Step 4: Implement challenge and terminal cleanup state**

React receives no phrase. Store only enrollment ID, four positions, timestamps, and the four words
the user types from their separately saved phrase. Update remaining validity from the local clock,
while the daemon remains authoritative. On unmount, clear all challenge inputs synchronously and
issue best-effort cancel for an awaiting in-memory session. Explicit cancel awaits acknowledgement
before reporting Idle.

Use visible one-based position labels, autocomplete off, spellcheck false, an aria-live status
region, and deterministic focus transitions. Do not render any full phrase, hidden phrase
attribute, form default, error string, or phrase-bearing test ID.

- [x] **Step 5: Add restart and canary DOM/storage tests**

Unmount/remount at AwaitingConfirmation and prove overview never returns words; UI cancels the lost
session and explains that the old phrase is invalid. Remount at Submitting and prove exact resume.
After native begin and every terminal path, scan document.documentElement.outerHTML, React
snapshots, localStorage, sessionStorage, mocked clipboard calls, Tauri command results, generic
gateway calls, and console captures for all 24 words and key canaries.

- [x] **Step 6: Run the Desktop gate**

Run:

~~~bash
pnpm --dir apps/desktop test --run
pnpm --dir apps/desktop typecheck
pnpm --dir apps/desktop lint
pnpm check:bindings
pnpm check:schemas
git diff --check
~~~

Expected: all Desktop tests pass, bindings/schemas remain generated, and renderer tests never
observe the full phrase.

Deviation: the generated-type separation assertions were already present in
`protocol-contracts.test.ts` from the native-host slice, so Task 7 did not rewrite them. The App and
offline-workflow gateway fixtures were updated to cover the expanded typed gateway surface, and a
focused gateway regression now proves cancellation decodes the daemon's Idle status result.

- [x] **Step 7: Commit the recovery UI**

~~~bash
git add apps/desktop
git commit -m "feat: add recovery enrollment experience"
~~~

---

### Task 8: Verify the full slice and publish evidence

**Files:**
- Create: docs/verification/task-17-recovery-enrollment.md
- Create: .superpowers/sdd/task-17-recovery-enrollment-report.md
- Modify: .superpowers/sdd/task-17-recovery-enrollment-progress.md
- Modify: .superpowers/sdd/progress.md
- Modify: this plan by checking completed task boxes and recording deviations beside the affected
  step.

**Interfaces:**
- Consumes: every Task 1 through 7 command and artifact.
- Produces: reproducible public verification ledger, detailed local report, clean worktree commit,
  and explicit handoff to phrase-based lost-device recovery.

- [x] **Step 1: Run the final core matrix from a clean process**

Run:

~~~bash
cargo test -p context-relay-core --features test-support --test recovery_enrollment_crypto_v1 --test recovery_enrollment_transport_v1 --test recovery_enrollment_vault_v1 --test recovery_enrollment_e2e_v1 --test device_pairing_crypto_v1 --test device_pairing_transport_v1 --test device_pairing_vault_v1 --test device_pairing_e2e_v1 --test signed_sync_e2e_v1 --test sync_engine_v1 --test sync_checkpoint_v1 --test sync_backoff_v1
~~~

Expected: zero failures; record the exact test count and wall time.

- [x] **Step 2: Run protocol, workspace, and daemon gates**

Run:

~~~bash
cargo test -p context-relay-protocol --all-features
cargo test -p context-relay-local-ipc
cargo test -p contextd
cargo check --workspace --all-targets --all-features
~~~

Expected: every command exits 0. Repeat socket-bearing tests outside the sandbox only when the
first output is the known macOS Operation not permitted bind denial.

- [x] **Step 3: Run Desktop and generated-artifact gates**

Run:

~~~bash
pnpm --dir apps/desktop test --run
pnpm --dir apps/desktop typecheck
pnpm --dir apps/desktop lint
pnpm check:bindings
pnpm check:schemas
pnpm check:licenses
~~~

Expected: every command exits 0 and generated artifacts have no diff after regeneration.

Deviation: the repository exposes the license gate as `pnpm license:check`, not the planned
`pnpm check:licenses`. The first corrected invocation lacked the pinned Rust environment and failed
before running the checker; the final full-environment `pnpm license:check` invocation passed.

- [x] **Step 4: Run static hygiene**

Run:

~~~bash
cargo clippy -p context-relay-core --lib --all-features -- -D warnings -A clippy::large-enum-variant -A clippy::too-many-arguments
cargo fmt --all -- --check
git diff --check
git status --short
~~~

Expected: scoped Clippy, format, and diff checks exit 0. Status contains only intentional evidence
and plan files before the final commit.

- [x] **Step 5: Perform independent correctness and security review**

Give reviewers the design, this plan, baseline commit, live diff, and exact verification outputs.
Require separate checks for:

- provider-only and provider-missing fail-closed behavior;
- full recovery-record signature and both envelope AADs;
- phrase/key/material lifetime and canary absence;
- schema-22 full-row validation and atomic rollback;
- startup ordering and role allowlist;
- ordinary Desktop begin/confirmation denial, native phrase/approval prompt decline/accept,
  dedicated Tauri commands, and DesktopRecoveryHost confinement;
- recovery-to-pairing two-Vault trust graph;
- trusted native one-time phrase display, word-free renderer boundary, React challenge cleanup, and
  terminal cleanup.

Any Critical or Important finding returns to focused RED/GREEN remediation and affected gates.
Acceptance requires no unresolved Critical or Important finding and Ready yes from both reviews.

- [x] **Step 6: Write the evidence ledger**

Record baseline/final commits, test counts, wall times, RED causes, GREEN fixes, cryptographic
fixture sizes/SHA-256 values, schema version, protocol version, expected sandbox reruns, known
inherited warnings, reviewer verdicts, no-paid/no-hosted boundary, and residual fully-unpinned
provider limitation. Do not include phrase words, private keys, workspace keys, raw envelopes, or
safety numbers.

- [x] **Step 7: Commit the verified slice**

~~~bash
git add docs/verification/task-17-recovery-enrollment.md docs/superpowers/plans/2026-08-09-recovery-root-enrollment.md
git add -f .superpowers/sdd/task-17-recovery-enrollment-report.md .superpowers/sdd/task-17-recovery-enrollment-progress.md .superpowers/sdd/progress.md
git diff --cached --check
git commit -m "docs: verify recovery-root enrollment"
~~~

- [x] **Step 8: Confirm the handoff state without publishing**

Run:

~~~bash
git status --short
git log -8 --oneline
~~~

Expected: worktree clean and the branch contains separate protocol, crypto, transport, persistence,
coordinator, daemon, UI, and evidence commits. Do not push or merge. The next independent design is
user-entered phrase recovery on a fresh installation; hosted provider deployment and Apple signing
remain blocked on credentials and payment.
