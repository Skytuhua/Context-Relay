# Fresh-Install Recovery Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore a fresh encrypted device from the saved 24-word phrase, coordinate one exact
recovery-root-signed device claim with an untrusted provider, atomically install trust and sealed
material, and prove the recovered device can pair a third SQLCipher replica.

**Architecture:** The client authenticates the provider's exact enrolled recovery record with
phrase-derived keys, decrypts the existing recovery envelope, and creates a separately canonical
recovery-device claim plus device-bound material envelope. A scope-bound provider accepts the
claim through generation compare-and-set and exact retained-claim lookup; a forward-only Vault
transaction installs the genesis and recovered certificates only after both receipt and retained
bytes are proven. Phrase input remains a trusted core caller boundary and is not exposed through
React or generic local IPC in this slice.

**Tech Stack:** Rust 1.97.1, BIP39, HKDF-SHA-256, Ed25519, X25519,
XChaCha20-Poly1305, deterministic CBOR/minicbor, SHA-256, SQLCipher/rusqlite, existing pairing
coordinator, deterministic in-memory providers.

## Global Constraints

- Implement the approved design at
  `docs/superpowers/specs/2026-08-09-fresh-install-recovery-core-design.md` without widening scope.
- A wrong or invalid 24-word phrase creates no Vault row, provider claim, certificate, or trust.
- Provider root bytes, receipts, generations, and retained claims are untrusted and must be
  canonical, scope-bound, hash-bound, and signature-verified before use.
- `RecoveryDeviceClaimV1` schema is 1 and its canonical size ceiling is exactly 32 KiB.
- Recovery claim signing domain is `context-relay/recovery-device-claim/v1\0`.
- Recovered device material AAD domain is `context-relay/recovered-device-material/v1\0` and binds
  every field specified in the design.
- Provider generation begins at zero and is capped at `i64::MAX`; first acceptance requires exact
  expected generation below that cap, stores exact claim bytes, and returns accepted generation
  `expected + 1`.
- Exact replay is resolved by restore ID and bytes before checking the current generation. Later
  valid claims do not invalidate an earlier accepted claim.
- Provider receipt alone is insufficient. Exact retained-claim bytes and receipt projection must
  be proven before local activation.
- Phrase, recovery private keys, and plaintext workspace material are zeroizing and never persisted,
  logged, formatted, uploaded, or returned through renderer/local-IPC DTOs.
- The target Vault must be pristine. Recovery into any Vault with materialized user data, sync
  state, pairing state, device certificates, enrollment, or another restore fails closed.
- Root genesis certificate, recovered device certificate, sealed material, provider proof, and
  active restore state commit atomically or not at all.
- Schema advances forward-only from 22 to 23. Existing schema-22 enrollment data is preserved.
- No GitHub identity reassociation, revocation, epoch rotation, deletion, native phrase-input UI,
  hosted provider, Supabase mutation, paid Apple action, push, or merge is part of this plan.
- Every task begins RED, becomes GREEN with the narrowest implementation, runs its regression gate,
  receives a fresh correctness/security inspection, and is committed separately.

---

## File structure

- `crates/protocol/src/ids.rs` owns the type-distinct `RecoveryRestoreId` UUIDv7 identifier.
- `crates/core/src/devices/recovery_restore_crypto.rs` owns root authentication, canonical claim,
  claim signature, recovered-device envelope AAD, and opened-material validation.
- `crates/core/src/devices/recovery_restore_transport.rs` owns the provider snapshot/CAS/proof
  contract and bounded projections.
- `crates/core/src/devices/memory_recovery_transport.rs` remains the one deterministic provider
  backing both initial enrollment and restore.
- `crates/core/src/vault/recovery_restore.rs` owns schema-23 row validation, exact replay, atomic
  activation, and recovered material reopen.
- `crates/core/src/devices/recovery_restore.rs` owns the phrase-consuming/resumable coordinator.
- Focused integration tests mirror those four boundaries and one full recovery-to-pairing proof.

---

### Task 1: Authenticate the root and freeze recovery-device claim crypto

**Files:**
- Modify: `crates/protocol/src/ids.rs`
- Modify: `crates/core/src/crypto.rs`
- Modify: `crates/core/src/devices/mod.rs`
- Create: `crates/core/src/devices/recovery_restore_crypto.rs`
- Create: `crates/core/tests/recovery_restore_crypto_v1.rs`
- Create: `crates/core/tests/fixtures/recovery-device-claim-v1.hex`
- Create: `crates/core/tests/fixtures/recovery-device-claim-signing-preimage-v1.hex`

**Interfaces:**
- Consumes: `RecoveryPhrase`, `RecoveryKeys`, `DeviceKeys`, `PairingKeyBundle`,
  `RecoveryEnrollmentRecordV1`, the existing strict certificate/envelope codecs, and `SyncScope`.
- Produces: `RecoveryRestoreId`, `RECOVERY_DEVICE_CLAIM_SCHEMA_VERSION = 1`,
  `MAX_RECOVERY_DEVICE_CLAIM_BYTES = 32 * 1024`, `RecoveryDeviceClaimV1`,
  `AuthenticatedRecoveryRoot`, and `RecoveryDeviceClaimArtifacts`.
- Produces: `authenticate_recovery_root`, `build_recovery_device_claim`, deterministic test-support
  builder, crate-visible generic-RNG inner builder, claim encode/decode/preimage functions,
  `verify_recovery_device_claim`, and `open_recovered_device_material`.
- Changes: `RecoveryKeys` gains only crate-visible domain-specific claim signing. It does not expose
  a generic public signer or private seed.

- [x] **Step 1: Write the compile-RED and frozen-vector tests**

Add `recovery_restore_crypto_v1.rs` with a fixed valid enrollment record, fixed 24-word test
phrase, target device keys/ID/name/platform, restore ID, certificate ID, request nonce, provider
generation, and wrapping randomness. The test should use the intended API:

```rust
let authority = authenticate_recovery_root(
    &fixture.canonical_enrollment,
    fixture.enrollment_sha256,
    fixture.phrase,
)?;
let artifacts = build_recovery_device_claim_with_rng(
    authority,
    fixture.restore_id,
    fixture.expected_generation,
    fixture.certificate_id,
    fixture.request_nonce,
    fixture.device_id,
    "Recovered Mac",
    NativePlatform::Macos,
    &fixture.device_keys,
    &mut fixture.rng,
)?;
assert_eq!(
    hex(&artifacts.canonical_claim),
    include_str!("fixtures/recovery-device-claim-v1.hex").trim(),
);
assert_eq!(
    hex(&encode_recovery_device_claim_signing_preimage_v1(&artifacts.claim)?),
    include_str!("fixtures/recovery-device-claim-signing-preimage-v1.hex").trim(),
);
assert_bundle_eq(
    &open_recovered_device_material(
        &fixture.enrollment_record,
        &artifacts.claim,
        &fixture.device_keys,
    )?,
    &fixture.material,
);
```

Add tests for wrong phrase word with both invalid and accidentally valid BIP39 checksum, wrong
enrollment digest, wrong scope/root/public keys, tampered enrollment signature/certificate/AAD,
and wrong device keys. Assert none returns an authenticated capability or opened bundle.

- [x] **Step 2: Run the focused compile RED**

Run:

```bash
cargo test -p context-relay-core --features test-support --test recovery_restore_crypto_v1 -- --nocapture
```

Expected: compilation fails on the absent `RecoveryRestoreId`, module, DTOs, constants, and
functions. Record that failure before production edits.

- [x] **Step 3: Add the type-distinct restore ID and opaque authority**

Add `id_type!(RecoveryRestoreId)` beside the other recovery IDs. In the new module, define:

```rust
pub const RECOVERY_DEVICE_CLAIM_SCHEMA_VERSION: u16 = 1;
pub const MAX_RECOVERY_DEVICE_CLAIM_BYTES: usize = 32 * 1024;

pub struct AuthenticatedRecoveryRoot {
    record: RecoveryEnrollmentRecordV1,
    canonical_record_sha256: Sha256Digest,
    recovery_keys: RecoveryKeys,
    material: PairingKeyBundle,
}

pub fn authenticate_recovery_root(
    canonical_record: &[u8],
    expected_sha256: Sha256Digest,
    phrase: RecoveryPhrase,
) -> Result<AuthenticatedRecoveryRoot, RecoveryRestoreCryptoError>;
```

The function checks size/hash and strict-decodes the existing record, derives `RecoveryKeys`,
requires both derived public keys to equal the signed record, opens recovery metadata, and checks
scope/epochs. `AuthenticatedRecoveryRoot` is non-Clone, has private fields, and Debug renders only
the enrollment/root IDs, digest, and `[REDACTED]`. Test-support getters may expose only references
needed for assertions; normal builds keep them crate-visible.

- [x] **Step 4: Implement the strict claim DTO and codec**

Define the exact design fields and encode a fixed CBOR map of 15 entries when signed and 14 entries
for the preimage. Use ordered integer keys `0..=14`; key 14 is the recovery-root signature. Reuse
the strict nested certificate/envelope codecs rather than serializing with serde.

The decoder must reject input above 32 KiB before parsing, indefinite/wrong map size, wrong key
order, duplicate/unknown keys, trailing bytes, noncanonical re-encoding, invalid IDs, zero epoch,
blank or greater-than-256-byte device name, wrong platform, weak/noncanonical keys, malformed
envelope, and any record/certificate/claim mismatch.

- [x] **Step 5: Build, sign, and open the device-bound claim**

Add crate-visible `RecoveryKeys::sign_restore_claim`. The builder consumes the opaque authority,
requires a target device distinct from the genesis device, issues a recovery-root-signed
certificate, encrypts the exact pairing bundle under the design's complete recovered-device AAD,
signs the complete canonical preimage, and returns only public/ciphertext artifacts:

```rust
pub struct RecoveryDeviceClaimArtifacts {
    pub claim: RecoveryDeviceClaimV1,
    pub canonical_claim: Vec<u8>,
    pub canonical_claim_sha256: Sha256Digest,
}
```

`open_recovered_device_material` must strict-validate the enrollment record and claim graph,
certificate signature, root digest, scope, generation, display, epochs, target device/key binding,
and envelope shape before AEAD open. The opened bundle must match scope and epochs exactly.
The production builder uses `OsRng`; the test-support wrapper and core coordinator both delegate to
one `pub(crate) fn build_recovery_device_claim_inner<R: CryptoRng + RngCore>(...)` so deterministic
tests do not create a caller-selected randomness surface in normal external APIs.

- [x] **Step 6: Add exhaustive mutation and redaction coverage**

Mutate every claim field, every certificate field/signature byte, root record digest, expected
generation, display value, key epoch, envelope ephemeral key/nonce/ciphertext, map size/order/key,
and claim signature. Transplant valid certificates/envelopes between two restore claims and require
failure. Assert `Debug`/`Display` for the authority, artifacts, claim, errors, phrase, keys, bundle,
and envelope never contains phrase words, private seeds, plaintext key canaries, or raw ciphertext.

- [x] **Step 7: Run crypto and protocol regression gates**

Run:

```bash
cargo test -p context-relay-core --features test-support --test recovery_restore_crypto_v1 --test recovery_enrollment_crypto_v1 --test device_pairing_crypto_v1
cargo test -p context-relay-protocol --all-features
cargo fmt --all -- --check
git diff --check
```

Expected: all focused crypto vectors/mutations and the existing protocol suite pass. Adding the
core-only ID does not change protocol version 1.3 or renderer bindings.

- [x] **Step 8: Review and commit claim cryptography**

Inspect signature/preimage map counts, all AAD fields, opaque capability visibility, zeroization,
weak-key handling, and normal-build API reachability. Then commit:

```bash
git add crates/protocol/src/ids.rs crates/core/src/crypto.rs crates/core/src/devices crates/core/tests/recovery_restore_crypto_v1.rs crates/core/tests/fixtures/recovery-device-claim-v1.hex crates/core/tests/fixtures/recovery-device-claim-signing-preimage-v1.hex
git commit -m "feat: authenticate recovery device claims"
```

---

### Task 2: Add exact recovery restore provider compare-and-set

**Files:**
- Create: `crates/core/src/devices/recovery_restore_transport.rs`
- Modify: `crates/core/src/devices/mod.rs`
- Modify: `crates/core/src/devices/memory_recovery_transport.rs`
- Create: `crates/core/tests/recovery_restore_transport_v1.rs`

**Interfaces:**
- Consumes: the strict enrollment/claim codecs, claim verifier, `SyncScope`, and the existing
  scope-bound `InMemoryRecoveryEnrollmentProvider`.
- Produces: `RecoveryRootSnapshot`, `RecoveryRestoreReceipt`, `RecoveryRestoreProjection`, and
  `RecoveryRestoreTransport`.
- Changes: the in-memory enrollment provider retains the accepted root's exact canonical record,
  current recovery generation, and exact accepted restore claims. Test-support captures remain
  digest/length-only.

- [x] **Step 1: Write provider snapshot, CAS, replay, and proof RED tests**

Create a valid enrolled root through the existing `register` API, then use the intended restore
transport:

```rust
let restore = provider.restore_transport(scope);
let snapshot = restore.root_snapshot()?.expect("registered root");
assert_eq!(snapshot.recovery_generation, 0);
let receipt = restore.submit_restore(&fixture.canonical_claim, 2_000)?;
assert_eq!(receipt.accepted_generation, 1);
let projection = restore.restore_claim(fixture.restore_id)?.expect("retained claim");
assert_eq!(projection.canonical_claim, fixture.canonical_claim);
assert_eq!(projection.receipt, receipt);
```

Cover exact retry after generation advanced, changed bytes under one restore ID, stale generation,
two concurrent claims with one winner, reused target device/certificate IDs, wrong scope/root,
invalid claim signature/certificate/envelope shape, missing root, transient failures, forged receipt,
forged retained projection, bounded input, and redacted captures.

- [x] **Step 2: Run the focused transport RED**

Run:

```bash
cargo test -p context-relay-core --features test-support --test recovery_restore_transport_v1 -- --nocapture
```

Expected: compile failure because restore transport types/methods do not exist.

- [x] **Step 3: Implement bounded transport projections**

Define private-field or fully validated constructors and redacted Debug implementations. Receipt
and projection bind:

```rust
pub struct RecoveryRestoreReceipt {
    pub restore_id: RecoveryRestoreId,
    pub enrollment_id: RecoveryEnrollmentId,
    pub recovery_root_id: RecoveryRootId,
    pub account_id: AccountId,
    pub workspace_id: WorkspaceId,
    pub certificate_id: DeviceCertificateId,
    pub canonical_record_sha256: Sha256Digest,
    pub canonical_claim_sha256: Sha256Digest,
    pub accepted_generation: u64,
    pub accepted_at_ms: u64,
}
```

`RecoveryRestoreProjection` contains the exact bounded canonical claim plus that receipt.
`validate_for` methods recompute hashes, strict-decode records/claims, and cross-check every field.

- [x] **Step 4: Extend the in-memory provider state atomically**

For each accepted enrollment, retain:

```rust
struct AcceptedEnrollment {
    canonical_record: Vec<u8>,
    receipt: RecoveryEnrollmentReceipt,
    recovery_generation: u64,
    restores: BTreeMap<RecoveryRestoreId, AcceptedRestore>,
    device_ids: BTreeSet<DeviceId>,
    certificate_ids: BTreeSet<DeviceCertificateId>,
}
```

The initial enrollment seeds the genesis device/certificate sets. `submit_restore` locks once,
checks transient injection, strict-verifies the claim against the stored root, resolves exact replay
first, requires expected generation equal current and below `i64::MAX`, rejects identity reuse,
checked-adds generation, stores bytes/receipt, then returns. Integer overflow is Conflict and
changes nothing.

- [x] **Step 5: Add forged/missing provider proof controls**

Test-support hooks may return one forged snapshot/receipt/projection or omit a retained claim, but
must never expose or mutate phrase/plaintext. `test_delete_account` removes root and claims together.
Safe captures include only scope, IDs, digests, canonical lengths, generation, and timestamps.

- [x] **Step 6: Run transport and enrollment regressions**

Run:

```bash
cargo test -p context-relay-core --features test-support --test recovery_restore_transport_v1 --test recovery_enrollment_transport_v1 --test recovery_restore_crypto_v1
cargo clippy -p context-relay-core --lib --all-features -- -D warnings -A clippy::large-enum-variant -A clippy::too-many-arguments
cargo fmt --all -- --check
git diff --check
```

Expected: all transport/crypto cases pass and scoped Clippy is clean with only the two inherited
Task 16 allowances.

- [x] **Step 7: Review and commit provider CAS**

Verify exact replay ordering, one-lock atomicity, checked generation arithmetic, scope isolation,
retained-byte proof, bounded allocations, redaction, and test-support-only provider visibility.
Then commit:

```bash
git add crates/core/src/devices crates/core/tests/recovery_restore_transport_v1.rs
git commit -m "feat: coordinate recovery device claims"
```

---

### Task 3: Persist and atomically activate schema-23 recovery restores

**Files:**
- Create: `crates/core/migrations/0023_recovery_restore.sql`
- Modify: `crates/core/src/vault.rs`
- Create: `crates/core/src/vault/recovery_restore.rs`
- Create: `crates/core/tests/recovery_restore_vault_v1.rs`
- Modify: schema-version expectations in recovery/pairing/sync migration tests selected by `rg -n "schema_version\(\).*22|user_version.*22|LATEST_SCHEMA_VERSION" crates/core/tests`

**Interfaces:**
- Consumes: `RecoveryRootSnapshot`, `RecoveryDeviceClaimArtifacts`,
  `RecoveryRestoreReceipt`, `RecoveryRestoreProjection`, strict root/claim/open functions,
  certificate persistence helpers, and protected `DeviceKeys`.
- Produces: `RecoveryRestorePersistenceState`, `RecoveryRestoreWrite`,
  `StoredRecoveryRestore`, and Vault methods `prepare_recovery_restore`, `recovery_restore`,
  `mark_recovery_restore_conflict`, `activate_recovery_restore`,
  `recovered_workspace_material`, and `trusted_workspace_material`.
- Changes: `LATEST_SCHEMA_VERSION` from 22 to 23 with a forward transaction only.

- [x] **Step 1: Write schema/row/replay/rollback RED tests**

Start with an empty schema-23 Vault API expectation:

```rust
let write = RecoveryRestoreWrite::new(snapshot, artifacts, 3_000)?;
assert_eq!(vault.prepare_recovery_restore(&write)?, CommitDisposition::Inserted);
assert_eq!(vault.prepare_recovery_restore(&write)?, CommitDisposition::ExactReplay);
let stored = vault.recovery_restore()?.expect("prepared restore");
assert_eq!(stored.state, RecoveryRestorePersistenceState::Prepared);
assert!(vault.device_certificate(stored.claim.certificate_id)?.is_none());
```

Add raw-row tampering for every duplicated ID/scope/key/epoch/display/hash/generation/timestamp/state
column and both canonical byte columns. Add changed replay, non-pristine Vault, wrong device keys,
forged receipt/projection, trigger-aborted activation, exact active replay, reopen, and schema-22
real-data preservation tests.

- [x] **Step 2: Run the focused Vault RED**

Run:

```bash
cargo test -p context-relay-core --features test-support --test recovery_restore_vault_v1 -- --nocapture
```

Expected: compilation fails on missing schema-23 persistence types/methods.

- [x] **Step 3: Add forward migration 23 and exact SQL state constraints**

Create one `recovery_restores` row keyed by restore ID. Store duplicated enrollment/root/scope,
genesis/recovered device and certificate IDs/keys, display, control/key epochs, expected and accepted
generations, canonical root bytes/hash, canonical claim bytes/hash, state, prepared/provider/
completed/conflict timestamps, and activated certificate FKs.

SQL CHECKs must enforce UUIDv7 text shape, 32-byte hashes/keys, positive epochs, nonnegative
generations/timestamps, name length 1..=256, supported platform, nonempty bounded canonical blobs,
and exact state nullability:

```text
prepared -> no accepted generation/provider/completed/conflict/certificate FK
active   -> accepted = expected + 1, both certificate FKs present,
            provider time >= prepared, completed >= provider, no conflict
conflict -> no accepted generation/provider/completed/certificate FK,
            conflict >= prepared
```

Register the migration after 22 in one transaction and update hard-coded upgrade fixtures without
dropping or rewriting schema-22 enrollment rows.

- [x] **Step 4: Implement strict full-row loading and pristine preparation**

`RecoveryRestoreWrite::new` recomputes both canonical hashes, strict-decodes root and claim, and
cross-checks the complete graph before constructing a write. `prepare_recovery_restore` uses one
transaction and requires zero rows in recovery enrollment/restore, device certificates, pairing
decision/join/transcript tables, sync metadata/head/outbox/quarantine tables, and every user record
table. Define the exact checked table list in one helper and test one nonempty row from each trust/
user-data category.

Loading selects every column, enforces at most one restore row, strict-decodes both canonical blobs,
recomputes both hashes, verifies signatures and envelope shape, parses every duplicated value, and
validates the state matrix before returning `StoredRecoveryRestore`.

- [x] **Step 5: Implement one-transaction activation**

`activate_recovery_restore` accepts the exact receipt and retained projection, revalidates them
against the prepared row, opens the recovered device envelope using the current protected keys,
and inside the same transaction:

1. inserts/exact-validates the enrollment record's genesis certificate and display;
2. inserts/exact-validates the recovered certificate and claim display;
3. updates exactly one prepared row to active with both certificate IDs, accepted generation,
   provider timestamp, and completion timestamp; and
4. commits only after a final exact row-count check.

Any validation, FK, uniqueness, trigger, or row-count error rolls back both certificates and the
state change. Exact active replay rechecks every durable byte/field but treats certificate
`stored_at_ms` as its original trust timestamp rather than requiring it to equal a later replay
call time.

- [x] **Step 6: Add recovered and common material reopen**

`recovered_workspace_material` requires active state, both active exact certificates, matching
protected device public keys, and successful complete-graph envelope open. It returns the existing
zeroizing `WorkspacePairingMaterial`.

`trusted_workspace_material` returns enrollment material when exactly one active enrollment exists,
restore material when exactly one active restore exists, and Validation for neither, conflict, or
both. Update `VaultPairingMaterialSource` to call this common accessor without changing its trusted
scope check.

- [x] **Step 7: Run Vault, migration, pairing, and sync regressions**

Run:

```bash
cargo test -p context-relay-core --features test-support --test recovery_restore_vault_v1 --test recovery_enrollment_vault_v1 --test device_pairing_vault_v1
cargo test -p context-relay-core --features test-support --test sync_vault_v1 --test vault_storage_v1 --test signed_sync_e2e_v1
cargo check --workspace --all-targets --all-features
cargo fmt --all -- --check
git diff --check
```

Expected: schema 23 migrates from real schema-22 state, restore activation/reopen is atomic, pairing
and all 256 signed-sync convergence seeds remain green.

- [x] **Step 8: Review and commit restore persistence**

Review SQL/Rust state agreement, full-row selection, pristine checks, transaction boundaries,
certificate graph/timestamps, exact replay, migration preservation, and plaintext-cell scans. Then
commit:

```bash
git add crates/core/migrations/0023_recovery_restore.sql crates/core/src/vault.rs crates/core/src/vault/recovery_restore.rs crates/core/src/devices/pairing.rs crates/core/tests
git commit -m "feat: persist fresh-install recovery"
```

---

### Task 4: Restore a fresh Vault and prove recovered-device pairing

**Files:**
- Create: `crates/core/src/devices/recovery_restore.rs`
- Modify: `crates/core/src/devices/mod.rs`
- Create: `crates/core/tests/recovery_restore_e2e_v1.rs`
- Modify: `crates/core/tests/device_pairing_e2e_v1.rs` only if the common material-source fixture
  needs an exact recovered-authority variant

**Interfaces:**
- Consumes: phrase/root authentication, claim builder, restore transport, schema-23 Vault API,
  existing enrollment clock/entropy traits, protected device identity, and pairing coordinator.
- Produces: `RecoveryRestoreIdentity`, `RecoveryRestoreCoordinator`,
  `RecoveryRestoreCycleError`, `RecoveryRestoreOutcome`, and `resume_prepared`.
- Preserves: no local IPC/renderer DTO and no normal production provider implementation.

- [x] **Step 1: Write wrong-word/no-mutation and happy-path RED tests**

Create an enrolled source Vault/provider fixture and retain only the saved phrase plus provider
state. Close the source Vault. On a target with different protected keys:

```rust
let outcome = coordinator.recover(
    &mut target,
    phrase_words,
    &RecoveryRestoreIdentity {
        device_id: recovered_device_id,
        device_name: "Recovered Mac".into(),
        platform: NativePlatform::Macos,
        keys: &recovered_keys,
    },
)?;
assert!(matches!(outcome, RecoveryRestoreOutcome::Complete { .. }));
assert_material_eq(
    &source_material,
    &target.trusted_workspace_material(&recovered_keys)?,
);
```

Before that GREEN case, mutate one input word and assert provider captures, restore row, device
certificates, and trusted material remain absent.

- [x] **Step 2: Run the focused coordinator RED**

Run:

```bash
cargo test -p context-relay-core --features test-support --test recovery_restore_e2e_v1 -- --nocapture
```

Expected: compile failure on the absent coordinator/identity/outcome.

- [x] **Step 3: Implement the phrase-consuming coordinator**

Reuse `RecoveryEnrollmentClock` and `RecoveryEnrollmentEntropy` so production uses system time and
OS randomness while tests inject fixed sources. Define safe outcomes:

```rust
pub enum RecoveryRestoreOutcome {
    Submitting { restore_id: RecoveryRestoreId },
    Complete { restore_id: RecoveryRestoreId, device: DeviceSummary },
    Conflict { restore_id: RecoveryRestoreId },
}
```

`recover` validates the daemon-owned identity display, requires no existing restore, fetches one
root snapshot, strict-validates its scope/hash/status, consumes `RecoveryPhraseWords` into
`RecoveryPhrase`, authenticates/decrypts, generates UUIDv7 restore/certificate IDs and request
nonce, builds the claim, drops phrase/authority/plaintext, prepares the Vault, then calls the shared
resume path.

Map checksum, phrase-key mismatch, root/envelope failure, and malformed input to one redacted
Invalid error. Missing root is Unavailable; provider scope denial is Unauthorized; changed pins,
forged state, and CAS loss are Conflict; retryable provider/database failures are Transient.

- [x] **Step 4: Implement deterministic submit/prove/activate resume**

`resume_prepared` loads the exact row, requires identity ID/keys/display to match its recovered
claim, and first opens its device envelope to prove the stable protected keys. It exact-submits the
canonical claim, validates the receipt, fetches the retained claim, validates exact bytes/receipt,
then calls atomic Vault activation.

Transient submit or lookup returns Submitting without changing durable bytes. Invalid/conflicting
provider state marks the prepared row Conflict and returns that outcome. A crash or injected error
after provider acceptance but before activation resumes the same restore ID and bytes without the
phrase. Active exact resume returns Complete after full local material/certificate revalidation
without requiring the provider to be online.

- [x] **Step 5: Add crash, race, malicious-provider, and canary cases**

Cover:

- crash/reopen after prepare, after provider accept, and inside activation;
- exact active replay;
- two target Vaults racing the same provider generation, exactly one provider winner, loser with no
  trust;
- self-consistent attacker root, wrong scope, mutated signed root, forged receipt, omitted and
  substituted retained claim, wrong protected device keys, and persisted row tampering;
- provider account deletion after local activation does not delete or downgrade the local pin, and
  the active target still reopens material offline; a new provider operation returns Unavailable;
- raw target DB/WAL/SHM, provider captures, plaintext cells, errors, Debug output, and post-terminal
  coordinator state contain no full phrase, derived recovery secret, workspace root key, or epoch
  key.

- [x] **Step 6: Prove recovered-device pairing for a third Vault**

Use `VaultPairingMaterialSource` with the active recovered Vault and recovered certificate ID to
approve a normal pairing request from a third device. Compare the full 80-bit safety number,
confirm, close/reopen both target and third Vaults, and assert scope, control/key epochs, both
plaintext key arrays, active certificate states, and expected root/recovered/third-device graph.
No static material fixture may be used in this case.

- [x] **Step 7: Run the full core regression matrix**

Run:

```bash
cargo test -p context-relay-core --features test-support --test recovery_restore_crypto_v1 --test recovery_restore_transport_v1 --test recovery_restore_vault_v1 --test recovery_restore_e2e_v1 --test recovery_enrollment_crypto_v1 --test recovery_enrollment_transport_v1 --test recovery_enrollment_vault_v1 --test recovery_enrollment_e2e_v1 --test device_pairing_crypto_v1 --test device_pairing_transport_v1 --test device_pairing_vault_v1 --test device_pairing_e2e_v1 --test signed_sync_e2e_v1 --test sync_engine_v1 --test sync_checkpoint_v1 --test sync_backoff_v1
cargo test -p context-relay-protocol --all-features
cargo check --workspace --all-targets --all-features
cargo clippy -p context-relay-core --lib --all-features -- -D warnings -A clippy::large-enum-variant -A clippy::too-many-arguments
cargo fmt --all -- --check
git diff --check
```

Expected: all new restore paths, existing enrollment/pairing, all 256 signed-sync seeds, protocol,
workspace, format, and scoped lint gates pass.

- [x] **Step 8: Review and commit coordinator/e2e**

Review wrong-phrase timing/error equivalence, phrase ownership/drop paths, provider proof ordering,
prepared/active retry, identity matching, local pin preservation, recovered pairing authority, and
canary surfaces. Then commit:

```bash
git add crates/core/src/devices crates/core/tests
git commit -m "feat: restore devices from recovery phrase"
```

---

### Task 5: Verify and publish the fresh-install recovery core evidence

**Files:**
- Create: `docs/verification/task-17-fresh-install-recovery-core.md`
- Create: `.superpowers/sdd/task-17-fresh-install-recovery-core-report.md`
- Create: `.superpowers/sdd/task-17-fresh-install-recovery-core-progress.md`
- Modify: `.superpowers/sdd/progress.md`
- Modify: this plan by checking every completed box and recording deviations at the affected step

**Interfaces:**
- Consumes: every prior RED/GREEN command, fixture, commit, and reviewer disposition.
- Produces: a secret-free public ledger, detailed local report, clean evidence commit, and explicit
  handoff to trusted native phrase entry and later identity reassociation.

- [x] **Step 1: Run the final matrix from a clean process**

Run the exact Task 4 core matrix again, then:

```bash
cargo test -p context-relay-local-ipc
cargo test -p context-relay-contextd
pnpm --dir apps/desktop test --run
pnpm --dir apps/desktop typecheck
pnpm --dir apps/desktop lint
pnpm check:bindings
pnpm check:schemas
pnpm license:check
```

Socket-bearing local-IPC/contextd cases may be repeated outside the macOS filesystem sandbox only
after a first `Operation not permitted` bind denial. Record both outputs rather than hiding the
expected sandbox limitation.

- [x] **Step 2: Perform final correctness and security inspection**

Review the full design range for canonical signature/AAD coverage, phrase/root/material lifetime,
provider snapshot/CAS/exact lookup, generation replay/race, schema-23 full-row validation,
pristine-Vault enforcement, activation rollback, root/recovered certificate graph, reopened
material, recovered-device pairing, normal-build/test-support visibility, and secret-free
diagnostics. Any Critical or Important finding returns to a focused failing regression and affected
gate reruns. Acceptance requires no unresolved Critical or Important issue.

- [x] **Step 3: Write the evidence ledgers**

Record baseline/final commits, test counts and wall times, RED causes, GREEN fixes, canonical claim
fixture sizes/SHA-256 values, schema 23, unchanged protocol 1.3, expected sandbox reruns, inherited
lint allowances, review verdicts, no-paid/no-hosted boundary, and the residual malicious-provider
availability/transparency limitation. Do not include phrase words, private keys, plaintext workspace
keys, raw envelopes, or pairing safety numbers.

- [x] **Step 4: Run final hygiene and commit**

Run:

```bash
cargo fmt --all -- --check
git diff --check
git status --short
git add docs/verification/task-17-fresh-install-recovery-core.md docs/superpowers/plans/2026-08-09-fresh-install-recovery-core.md
git add -f .superpowers/sdd/task-17-fresh-install-recovery-core-report.md .superpowers/sdd/task-17-fresh-install-recovery-core-progress.md .superpowers/sdd/progress.md
git diff --cached --check
git commit -m "docs: verify fresh-install recovery core"
git status --short
git log -6 --oneline
```

Expected: clean worktree and separate crypto, transport, persistence, coordinator/e2e, and evidence
commits. Do not push or merge. The next design is a trusted native cross-platform 24-word entry
surface; GitHub reassociation/revocation/rotation remain later independent state machines.

## Recorded execution notes

- Task 3 added two review-driven checks beyond the initial examples: prepared replay/conflict now
  rejects an unexpectedly installed certificate, and active restore loading rejects a revoked
  certificate graph after reopen.
- Task 4 added focused RED/GREEN coverage for entropy failure during envelope construction and for
  local clock rollback during a terminal provider conflict. Both cases now preserve the specified
  Transient/Conflict semantics without early trust.
- The final local-IPC and contextd commands first reproduced the expected macOS socket sandbox
  denial and then passed unchanged outside that filesystem sandbox.
- Desktop tests/typecheck/lint passed after adding the bundled Node path. Binding, schema, and
  license scripts additionally required the pinned Rust path because they spawn `cargo`; the
  launcher-only failures changed no source or dependency.
- No protocol DTO or renderer surface was added, protocol remains 1.3, and no hosted or paid
  provider action was performed.
