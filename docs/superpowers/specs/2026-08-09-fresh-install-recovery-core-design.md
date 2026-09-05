# Fresh-Install Recovery Core and Two-Vault Proof Design

Date: 2026-08-09

Status: approved for local implementation under the user's standing instruction to continue
autonomously without clarification questions. This is a reversible, credential-free slice. It
does not deploy a provider, change a remote account, or require paid Apple access.

## Goal

Use the saved 24-word recovery phrase on a fresh installation to authenticate the exact enrolled
recovery root, decrypt workspace material, authorize the fresh device, and atomically install a
usable encrypted local replica.

The end-to-end proof begins with an enrolled source Vault, destroys all reliance on that local
Vault, restores into a different SQLCipher Vault with different protected device keys, reopens the
restored material, and uses the recovered device to approve the existing exact pairing flow for a
third replica.

## Scope

This slice implements the core cryptographic claim, provider compare-and-set contract, encrypted
Vault persistence, recovery coordinator, and deterministic provider-like end-to-end proof. It does
not yet expose phrase entry to React or generic local IPC. The phrase enters through a trusted
caller abstraction so the later native-input design cannot be bypassed by widening the renderer
boundary.

The slice does not implement GitHub identity reassociation, device revocation, epoch rotation,
account deletion, hosted Edge Functions, Supabase persistence, or Apple packaging. Those remain
separate state machines and review boundaries.

## Alternatives

### Reuse the pairing flow with the recovery root as a virtual device

This would reuse certificate/grant machinery, but it would also add locator, join-session, and
safety-number semantics to a flow where phrase possession is already the independent authority.
It would obscure the provider compare-and-set and complicate crash recovery. Rejected.

### Restore locally without a provider claim

The phrase could authenticate and decrypt the enrollment record, and the fresh Vault could install
a new certificate immediately. That certificate would have no coordinated provider state, exact
retry receipt, or deterministic race behavior. It would also be a poor base for future revocation.
Rejected.

### Sign an exact recovery-device claim and publish it with compare-and-set — selected

The fresh client fetches the canonical enrollment record, derives recovery keys from the phrase,
proves that the derived public keys match the signed record, opens its recovery envelope, and signs
one exact device claim. The provider atomically accepts only the expected recovery generation and
returns an exact receipt. The client proves that the provider retained the same claim before one
Vault transaction installs trust and sealed material.

This keeps phrase authority, provider coordination, and local trust installation separate and
auditable.

## Trust model

- The 24-word phrase is the only fresh-install recovery secret. The provider never receives it,
  any recovery private key, or plaintext workspace material.
- The authenticated provider handle supplies one account/workspace scope. A caller cannot put
  account IDs, workspace IDs, epochs, keys, certificates, provider handles, or timestamps inside a
  trusted coordinator call.
- Provider bytes are untrusted. No provider status, record, receipt, or claim installs trust until
  exact canonical decoding, signatures, scope, keys, epochs, hashes, and encrypted material all
  validate locally.
- A wrong phrase fails before a durable row or trust mutation. The public error is the same bounded
  invalid-recovery class for a checksum failure, public-key mismatch, or AEAD failure.
- The provider may deny, hide, delay, or fork data and cause safe non-availability. It cannot forge
  a recovery-root signature or an envelope that opens under the saved phrase.
- A completely malicious provider may present a private, internally consistent view to one client.
  The client therefore keeps the exact root and accepted claim as durable local pins. This slice
  does not claim global transparency or availability.
- Same-user malware and trusted native-host compromise remain outside the v1 guarantee. The normal
  renderer remains an untrusted input surface and receives no phrase API in this slice.

## Canonical root snapshot

The provider recovery boundary returns a bounded `RecoveryRootSnapshot` containing:

```rust
pub struct RecoveryRootSnapshot {
    pub scope: SyncScope,
    pub canonical_record: Vec<u8>,
    pub canonical_record_sha256: Sha256Digest,
    pub registered_at_ms: u64,
    pub recovery_generation: u64,
}
```

The client decodes `canonical_record` with the existing strict recovery-enrollment codec,
recomputes the hash, validates the enrollment-record signature and recovery-root-signed genesis
certificate, and requires exact scope and provider status agreement. Generation begins at zero,
is capped at signed SQLite's `i64::MAX`, and is provider-owned compare-and-set state; it is not
treated as cryptographic authority.

After parsing the user-entered phrase, the client derives `RecoveryKeys` and requires both derived
public keys to match the signed record before attempting decryption. It then opens the existing
recovery metadata envelope and validates account, workspace, control epoch, and key epoch against
the record.

## Canonical recovery-device claim

Core adds a deterministic bounded `RecoveryDeviceClaimV1`:

```rust
pub struct RecoveryDeviceClaimV1 {
    pub schema_version: u16,
    pub restore_id: RecoveryRestoreId,
    pub enrollment_id: RecoveryEnrollmentId,
    pub recovery_root_id: RecoveryRootId,
    pub account_id: AccountId,
    pub workspace_id: WorkspaceId,
    pub canonical_record_sha256: Sha256Digest,
    pub expected_recovery_generation: u64,
    pub certificate_id: DeviceCertificateId,
    pub certificate: DeviceCertificateV1,
    pub device_name: String,
    pub device_platform: NativePlatform,
    pub key_epoch: u32,
    pub device_material_envelope: WrappedKeyEnvelope,
    pub recovery_root_signature: Ed25519SignatureBytes,
}
```

`RecoveryRestoreId` is a type-distinct UUIDv7. The claim schema is version 1 and the canonical
record is capped at 32 KiB. Its signature preimage is:

```text
"context-relay/recovery-device-claim/v1\0" ||
canonical_cbor(claim_without_recovery_root_signature)
```

Every map field is included. The strict decoder requires the fixed map size, ordered integer keys,
canonical nested certificate/envelope encoding, no unknown/duplicate/trailing bytes, valid UUIDv7
values, bounded nonblank display metadata, nonzero epochs, canonical/strong public keys, and exact
re-encoding.

The recovered device certificate is issued directly by the derived recovery root. It binds the
snapshot account/workspace, current control epoch, a fresh request nonce, the new protected
device's ID, and its Ed25519/X25519 public keys. The claim requires the certificate issuer to equal
the enrollment record's recovery signing key and requires the recovered device to differ from the
genesis device.

## Recovered-device material envelope

The already decrypted workspace bundle is re-encrypted to the fresh protected device's X25519 key
before any durable write. The new envelope uses a separate domain:

```text
"context-relay/recovered-device-material/v1\0" ||
restore_id || enrollment_id || recovery_root_id || account_id || workspace_id ||
canonical_record_sha256 || expected_recovery_generation ||
certificate_id || SHA256(canonical_recovered_certificate) ||
control_epoch || key_epoch || device_id ||
device_signing_public_key || device_wrapping_public_key
```

The recovery-root claim signature covers the complete encrypted envelope in addition to this AEAD
binding. Decryption requires the same protected `DeviceKeys`, revalidates the claim/certificate
graph, and validates the opened bundle's scope and epochs. The phrase, recovery keys, and plaintext
bundle are dropped before the prepared Vault transaction commits.

## Provider compare-and-set

A separate `RecoveryRestoreTransport` is implemented by the same scope-bound provider handle:

```rust
pub trait RecoveryRestoreTransport: Send + Sync {
    fn scope(&self) -> SyncScope;
    fn root_snapshot(&self) -> Result<Option<RecoveryRootSnapshot>, RecoveryTransportError>;
    fn submit_restore(
        &self,
        canonical_claim: &[u8],
        now_ms: u64,
    ) -> Result<RecoveryRestoreReceipt, RecoveryTransportError>;
    fn restore_claim(
        &self,
        restore_id: RecoveryRestoreId,
    ) -> Result<Option<RecoveryRestoreProjection>, RecoveryTransportError>;
}
```

The provider strictly verifies the claim against its exact registered root. First acceptance
requires `expected_recovery_generation == current_generation < i64::MAX`, stores the exact
canonical claim, increments the generation by one, and returns a receipt binding scope, root IDs,
restore ID, certificate ID, root-record digest, claim digest, accepted generation, and provider
time.

An exact retry is checked by restore ID and canonical bytes before the current-generation check and
returns the original receipt. Changed bytes under the same restore ID, reused device/certificate
identity, stale generation, or another account/workspace fail Conflict. Provider validation never
decrypts the device envelope.

After submission, the coordinator calls `restore_claim`. It requires the exact canonical bytes and
receipt projection, including `accepted_generation == expected_recovery_generation + 1`, before
local activation. A matching receipt alone is insufficient. A later independently accepted
recovery may advance the provider's current generation without invalidating this already accepted
claim; revocation will be a separate control-epoch state machine. Missing, substituted, reordered,
or forged state fails closed with no certificate or material installation.

The in-memory provider stores only bounded canonical ciphertext/public metadata. Its Debug and
test capture projections contain IDs, digests, lengths, generations, and timestamps, never phrase,
private keys, or plaintext material.

## Vault schema and atomic activation

Forward migration 23 creates `recovery_restores`. One row contains the exact canonical root record
and hash, exact canonical claim and hash, duplicated scope/root/device/certificate/generation
columns, state, and timestamps. States are:

- `prepared`: exact root and claim are durable; no device certificate or trust was installed;
- `active`: the exact provider receipt/projection was proven and both certificates were installed;
- `conflict`: provider or persisted state contradicted the prepared pins; no trust was installed.

All digest columns are 32 bytes, epochs are positive, identifiers are UUIDv7-shaped, and SQL CHECKs
make nullable timestamp/certificate/generation fields exact for each state. Rust row loading decodes
both canonical records and cross-checks every duplicated field, hash, state invariant, and
certificate/envelope binding before returning a typed value.

`prepare_recovery_restore` is Inserted or ExactReplay only and requires an otherwise untrusted
fresh Vault: no recovery enrollment/restore row, no device certificate, and no existing workspace
trust state. It never stores a phrase or plaintext bundle.

`activate_recovery_restore` runs one SQLite transaction. It revalidates the root record, claim,
receipt, provider projection, and device envelope using the current protected device keys; inserts
or exact-validates the root's genesis certificate and the recovered device certificate as active;
updates the restore row to active; and records the exact accepted generation/timestamps. Any
conflict or injected failure rolls back both certificates and the state transition.

`recovered_workspace_material` revalidates the complete stored graph and opens the device envelope
on demand. A common trusted-material accessor selects exactly one active local enrollment or one
active recovery restore, never both, so the existing pairing material source can operate from the
recovered device without persisting plaintext keys.

## Coordinator and crash behavior

`RecoveryRestoreCoordinator` has two entry points:

```rust
fn recover(
    &self,
    vault: &mut Vault,
    phrase_words: RecoveryPhraseWords,
    identity: &RecoveryRestoreIdentity,
) -> Result<RecoveryRestoreOutcome, RecoveryRestoreCycleError>;

fn resume_prepared(
    &self,
    vault: &mut Vault,
    identity: &RecoveryRestoreIdentity,
) -> Result<RecoveryRestoreOutcome, RecoveryRestoreCycleError>;
```

The identity contains daemon-owned device ID/name/platform and protected `DeviceKeys`; it is not a
wire DTO. `recover` consumes and zeroizes all 24 words, authenticates/decrypts the root snapshot,
builds and persists the exact claim, and then follows the same submit/prove/activate path as
`resume_prepared`.

`resume_prepared` needs no phrase. It reopens the prepared claim's device envelope with the stable
protected keys, submits or exact-replays the claim, proves provider retention, and activates. A
crash before prepare leaves no durable trace and requires re-entry. A crash after prepare but
before provider acceptance, after provider acceptance but before proof, or during activation
resumes deterministically from the same bytes. Active exact replay is idempotent. Conflict is
terminal and installs no trust.

Once active, local material and trust remain available without the provider. An active replay
revalidates only the complete durable local graph and does not downgrade or erase the pin when the
provider is offline or omits the account; later provider operations report availability separately.

Errors are bounded and redacted: invalid phrase/record/material, conflict, unauthorized,
unavailable, and transient. Debug output exposes only safe IDs/digests/state where needed.

## End-to-end proof

The deterministic test creates an enrolled source Vault and provider record, retains only the
saved phrase and provider state, and closes the source Vault. A fresh target uses different
protected device keys and an empty SQLCipher Vault. Recovery must:

1. authenticate the exact provider root with the phrase;
2. prepare, submit, prove, and atomically activate one recovery claim;
3. reopen equivalent scope, control/key epochs, workspace root key, and active epoch key;
4. retain the original genesis certificate plus the recovered device's root-signed certificate;
5. close/reopen the target and recover material again without the phrase;
6. use the recovered device as the approving authority in the existing safety-number pairing flow
   for a third Vault; and
7. reopen the second and third Vaults with identical material and expected certificate graph.

Negative cases cover one wrong phrase word, invalid checksum, provider-only attacker record,
scope/root/hash/signature/certificate/envelope mutations, wrong protected device keys, stale and
concurrent generation, forged receipt, omitted/substituted retained claim, prepared crash/reopen,
activation rollback, persisted-row tampering, and restore into a nonempty Vault.

Canary tests scan the target Vault plus WAL/SHM, provider captures, persisted plaintext cells,
errors, Debug output, and post-terminal coordinator state for the full phrase, derived recovery
secrets, workspace root key, and active epoch key. The input phrase and in-memory cryptographic
operation are the only allowed plaintext locations.

## Native/UI handoff

No normal-build public API accepts raw phrase words from React. The later native-input slice must
provide an isolated trusted Rust caller that collects all 24 words, owns them in zeroizing buffers,
and passes them over a separately authenticated role to the daemon without exposing them in a
Tauri result, ordinary renderer command, browser storage, logs, clipboard, download, or telemetry.

If a safe cross-platform native text-entry mechanism is not available, production recovery remains
truthfully unavailable rather than moving the phrase into the existing renderer. This limitation
does not block the credential-free core and two-Vault proof in this design.

## Acceptance

- One wrong word or any untrusted record/receipt/claim mutation installs no trust or material.
- Exact prepared and accepted retries are crash-safe and idempotent.
- Concurrent claims against one generation have exactly one accepted winner.
- Provider receipt plus exact retained-claim proof is required before activation.
- Root genesis and recovered device certificates, sealed material, and active restore state commit
  atomically or not at all.
- The recovered device reopens material and successfully approves pairing for a third replica.
- Phrase, recovery private keys, and plaintext workspace keys are absent from every scanned durable,
  provider, diagnostic, and renderer surface.
- Existing enrollment, pairing, signed-sync, migration, and plaintext-canary suites remain green.
- No remote service, paid Apple action, push, or merge occurs.
