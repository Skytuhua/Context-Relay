# Recovery-Root Enrollment and First-Device Bootstrap Design

Date: 2026-08-09

Status: approved for implementation from the frozen Context Relay v1 plan and the user's standing
instruction to continue autonomously without clarification questions. Ambiguous choices are
resolved conservatively from the existing threat model, pairing design, and credential-free local
proof strategy.

## Goal

Implement the next independently testable Task 17 slice: a first authenticated installation
generates a 24-word recovery phrase, proves that the user recorded randomly selected words,
registers one recovery root, creates the recovery-root-signed genesis device certificate, and
stores the first workspace key material so it can be reopened by that device after restart.

The slice must then use that real enrolled certificate and material to pair a second SQLCipher
replica through the existing exact pairing coordinator. An injected in-memory enrollment provider
proves provider compare-and-set and crash recovery without Supabase credentials, remote mutation,
or paid Apple work.

## Scope decomposition

This slice implements only recovery-root enrollment and first-device bootstrap. It does not use the
phrase to recover a lost installation, reassociate a workspace with a new GitHub identity, revoke
devices, rotate epochs, delete an account, deploy an Edge Function, or package/sign an app. Those
remain separate state machines and review boundaries.

The complete local proof is:

```text
first daemon begins enrollment
        -> displays one 24-word phrase
        -> challenges four random word positions
        -> prepares an exact encrypted registration
        -> provider compare-and-set accepts it
        -> one local transaction activates root + genesis cert + sealed material
        -> first daemon reopens material after restart
        -> first daemon approves the existing Task 17 pairing flow
        -> second daemon confirms the 80-bit safety number and installs the same material
```

## Alternatives considered

### A. Store the phrase or recovery private keys in the platform credential store

This permits seamless restart before confirmation, but it turns compromise of one enrolled device
into compromise of the independent recovery root and contradicts the phrase's one-time display
contract. Rejected.

### B. Keep the unconfirmed phrase only in memory, then persist only encrypted material — selected

The daemon generates the phrase and recovery keys, returns the phrase once over authenticated
Desktop IPC, and holds the pending enrollment only in memory. Confirmation persists exact
canonical registration bytes, a recovery-key-encrypted metadata envelope, and a separately
device-key-encrypted material envelope. The phrase and derived private recovery keys are then
zeroized. A crash before confirmation invalidates that phrase and begins again; a crash after
confirmation resumes from encrypted exact bytes without needing the phrase.

This preserves recovery-root independence while retaining deterministic provider/local replay.

### C. Generate and confirm the phrase in React

This would avoid a daemon-to-renderer secret response, but it moves cryptographic randomness,
canonical derivation, certificate issuance, and key-envelope construction into the least trusted
application layer. Rejected.

## Frozen security and product constraints

- The recovery phrase is BIP39 English, 24 words from 256 bits of OS randomness.
- BIP39/HKDF behavior remains compatible with the existing frozen cross-platform vectors.
- Recovery signing and wrapping keys remain distinct HKDF-SHA-256 derivations under the existing
  `context-relay/recovery/v1`, signing, and wrapping domain labels.
- The phrase is never uploaded or stored in SQLCipher, the platform credential store, browser
  storage, application preferences, logs, crash reports, or provider records.
- The phrase appears once in authenticated local IPC and then only in the trusted Tauri Rust host's
  OS-native blocking phrase dialog. It never crosses the Tauri command boundary into JavaScript,
  React state, or the DOM. Rust phrase/frame buffers are zeroizing; the OS dialog lifetime ends
  before the host returns the redacted challenge projection.
- The Tauri host builds its phrase/answer message in Zeroizing<String>. The native dialog toolkit
  may make internal trusted-process/OS copies that the application cannot prove were zeroized; they
  are bounded to the blocking dialog lifetime and never enter logs, persistence, command results, or
  the renderer. Same-user process-memory inspection remains outside the v1 guarantee.
- An unconfirmed in-memory enrollment expires exactly 600,000 milliseconds after creation. Expiry
  or explicit cancellation zeroizes the pending phrase, recovery keys, and plaintext material.
- Exactly four unique randomly selected one-based positions are challenged. Confirmation supplies
  only those four positions and words, never all 24 words.
- Any wrong, missing, repeated, reordered, or extra confirmation invalidates the in-memory session,
  makes no durable/provider/trust change, and requires a new phrase.
- A locally active, strictly validated recovery root cannot be reset by enrollment. Only the exact
  matching local pin plus provider projection is Complete. Provider-only state is untrusted and
  returns Conflict; it never installs trust, authorizes another root, or produces Complete.
- The provider-facing root is account-scoped; the bootstrap registration binds one exact workspace,
  device, genesis certificate, control epoch, key epoch, and encrypted recovery metadata.
- Context Relay v1 has exactly one encrypted workspace per account. The provider handle and every
  root/status/receipt therefore bind one identical account/workspace pair. A second workspace for
  the same account is invalid rather than silently reported as already enrolled.
- Initial `control_epoch` and `key_epoch` are exactly 1. Zero and caller-selected epochs are invalid.
- Device private keys continue to live only in the distinct `context-relay-device` protected store.
  Recovery private keys are never added to that store.
- Account/workspace scope comes only from a trusted provider handle injected into the daemon. Local
  IPC cannot submit account IDs, workspace IDs, device IDs, keys, nonces, epochs, or certificates.
- The React renderer is an untrusted input surface. It never receives the full phrase. Dedicated
  Tauri Rust begin displays the daemon-returned phrase in an OS-native dialog and returns only
  enrollment ID, four positions, and timestamps to React. Final confirmation uses a second native
  dialog showing the exact four submitted position/word pairs. Both operations use the distinct
  authenticated DesktopRecoveryHost local role; generic renderer local_request and the ordinary
  Desktop role cannot dispatch RecoveryEnrollmentBegin or RecoveryEnrollmentConfirm.
- Normal builds without an enrollment provider remain truthful and return that recovery setup needs
  the hosted workspace service. The in-memory provider is proof infrastructure, not a production
  cross-device service.
- Provider compare-and-set coordinates honest concurrent first-device attempts; it is not an
  independent recovery-root trust anchor. A completely unpinned client cannot distinguish an empty
  account from a malicious provider that hid an earlier root. This local slice therefore proves and
  preserves the first device's durable pin, but does not claim account-wide continuity after all
  local pins are lost. The subsequent phrase-based recovery slice must prove the enrolled phrase
  and exact root before trusting provider state; a hosted malicious-provider claim additionally
  requires an independently authenticated transparency/pinning design.
- No Supabase, GitHub OAuth, Apple Developer, or other paid/remote action is part of this slice.

## Protocol boundary

The existing unused generic `recovery_begin` / `recovery_complete` routes are replaced by
phase-specific enrollment messages. This is a local-IPC compatibility change and advances the
exact protocol boundary from 1.2 to 1.3.

New UUIDv7 identifiers remain type-distinct:

```rust
pub struct RecoveryEnrollmentId(Uuid);
pub struct RecoveryRootId(Uuid);
```

The enrollment requests are:

```rust
RecoveryEnrollmentBegin(EmptyParams)
RecoveryEnrollmentOverview(EmptyParams)
RecoveryEnrollmentConfirm(RecoveryEnrollmentConfirmParams {
    enrollment_id: RecoveryEnrollmentId,
    confirmations: Vec<RecoveryWordConfirmation>,
})
RecoveryEnrollmentStatus(RecoveryEnrollmentIdParams {
    enrollment_id: RecoveryEnrollmentId,
})
RecoveryEnrollmentCancel(RecoveryEnrollmentIdParams {
    enrollment_id: RecoveryEnrollmentId,
})
```

Overview, status, and cancel require the ordinary Desktop role. Begin and confirm require the
DesktopRecoveryHost role, which is never selected by the generic Tauri local_request command.
Dedicated Rust begin calls the daemon, receives RecoveryEnrollmentPhrase, and presents the actual
numbered words in a native blocking dialog through the official Tauri 2 dialog plugin. Only after
the user selects I saved all 24 words does the host return this redacted projection to React:

```rust
RecoveryEnrollmentChallenge {
    enrollment_id,
    confirmation_positions,
    created_at_ms,
    expires_at_ms,
}
```

The dedicated Tauri boundary uses closed word-free unions:

```rust
RecoveryEnrollmentHostBeginResult =
    Challenge(RecoveryEnrollmentChallenge) | Status(RecoveryEnrollmentStatus)
RecoveryEnrollmentHostConfirmResult =
    Canceled | Complete(RecoveryEnrollmentComplete) | Status(RecoveryEnrollmentStatus)
```

Neither union can carry RecoveryEnrollmentPhrase.

The phrase dialog title is Save your 24-word recovery phrase. Its message begins Never share these
words. Write them down in this exact order. Context Relay cannot restore a lost phrase, followed by
the 24 one-based numbered words. Its buttons are Go back and I saved all 24 words.

Closing or declining the phrase dialog cancels the exact memory session and returns Idle without
exposing words only after cancellation succeeds; a cancel failure returns a safe retryable error
and the daemon expiry remains the backstop. Dedicated Rust confirm displays the exact four submitted
position/word pairs plus the warning Continue only if these match the phrase you personally saved.
Activating permanently establishes recovery for this workspace. Its buttons are Go back and
Activate recovery. Closing or declining sends no confirm request and makes no durable/provider
change. On approval, the trusted host sends the same ID/answers over its separately authenticated
DesktopRecoveryHost connection.
The daemon allowlist binds that role to begin/confirm/cancel only. Generic local_request Rust
rejects begin and confirm before delegation, so typed or hand-written renderer input cannot obtain
the phrase or bypass native approval. Same-user accessibility automation or compromise of the
native Rust host remains outside the v1 threat model.

`RecoveryWordConfirmation { position: u8, word: String }` is canonical at the JSON boundary:
exactly four entries, strictly increasing unique positions in `1..=24`, lowercase BIP39-sized text,
and no unknown fields.

Results are phase-specific:

```rust
RecoveryEnrollmentPhrase {
    enrollment_id,
    recovery_phrase_words,
    confirmation_positions,
    created_at_ms,
    expires_at_ms,
}
RecoveryEnrollmentStatus {
    enrollment_id: Option<RecoveryEnrollmentId>,
    state: Idle | AwaitingConfirmation | Submitting | Complete | Conflict,
    created_at_ms: Option<DecimalTimestamp>,
    transitioned_at_ms: Option<DecimalTimestamp>,
}
RecoveryEnrollmentComplete {
    enrollment_id,
    device: DeviceSummary,
}
```

Only the local IPC phrase result contains all words, and only the trusted Tauri host can request it.
The confirmation request owns only four challenged words, zeroizes them on drop, and has
recursively redacted Debug output. The Tauri command result, status, errors, Debug output, bindings,
schemas, and every subsequent result omit phrase words, root private keys, and workspace key
material. Non-Desktop roles are denied before dispatch; ordinary Desktop is also denied for begin
and confirmation. `Idle` requires all three optional status fields to be null; every other state
requires an enrollment ID and creation time, while Submitting/Complete/Conflict also requires a
transition time.

## Canonical enrollment record

Core defines a bounded deterministic `RecoveryEnrollmentRecordV1` and freezes its canonical CBOR
vector. Its signed public and encrypted fields are:

```rust
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
```

The record rejects unknown/reordered/duplicate/trailing/noncanonical fields, invalid identifiers,
bad key shapes, non-genesis certificates, mismatched scope/device/keys/epoch, blank or oversized
display metadata, and oversized ciphertext before allocation. The provider receipt binds SHA-256
of the exact canonical bytes. `recovery_root_signature` signs a domain-separated canonical preimage
containing every preceding field, including exact device name/platform bytes, the complete genesis
certificate, and the encrypted recovery envelope:

```text
"context-relay/recovery-enrollment-record/v1\0" ||
canonical_cbor(record_without_recovery_root_signature)
```

The decoder re-encodes the signed preimage and verifies this signature against
`recovery_signing_public_key` before any display metadata, provider receipt, or encrypted envelope
is accepted. The genesis-certificate signature and record signature are separate proofs with
separate domains.

The recovery metadata plaintext reuses the existing canonical `PairingKeyBundle`: account,
workspace, control epoch, key epoch, workspace root key, and active epoch key. It is wrapped to the
recovery X25519 public key with associated data:

```text
"context-relay/recovery-metadata/v1\0" ||
enrollment_id || recovery_root_id || account_id || workspace_id ||
recovery_signing_public_key || recovery_wrapping_public_key ||
genesis_certificate_id || SHA256(canonical_genesis_certificate) ||
control_epoch || key_epoch
```

A second envelope wraps the exact same canonical bundle to the first device's X25519 public key.
Its complete AAD byte layout is:

```text
"context-relay/device-workspace-material/v1\0" ||
enrollment_id || recovery_root_id || account_id || workspace_id ||
recovery_signing_public_key || recovery_wrapping_public_key ||
genesis_certificate_id || SHA256(canonical_genesis_certificate) ||
control_epoch || key_epoch || device_id ||
device_signing_public_key || device_wrapping_public_key
```

Both epoch values are big-endian `u32`; identifiers and key/digest values use their exact fixed
wire bytes. The provider never receives this device-local envelope. Frozen AAD mutation tests flip
every field and reject transplanting an envelope between enrollments for the same scope/device.

## Provider boundary and compare-and-set

`RecoveryEnrollmentTransport` is constructed by the daemon dependency root with one authenticated
account/workspace/caller binding. It exposes only:

```rust
fn scope(&self) -> SyncScope;
fn root_status(&self) -> Result<Option<RecoveryRootStatus>, RecoveryTransportError>;
fn register(
    &self,
    canonical_record: &[u8],
    now_ms: u64,
) -> Result<RecoveryEnrollmentReceipt, RecoveryTransportError>;
```

The provider projections are frozen and bounded rather than boolean/opaque:

```rust
pub struct RecoveryRootStatus {
    pub enrollment_id: RecoveryEnrollmentId,
    pub recovery_root_id: RecoveryRootId,
    pub account_id: AccountId,
    pub workspace_id: WorkspaceId,
    pub genesis_certificate_id: DeviceCertificateId,
    pub canonical_record_sha256: Sha256Digest,
    pub registered_at_ms: u64,
}

pub struct RecoveryEnrollmentReceipt {
    pub enrollment_id: RecoveryEnrollmentId,
    pub recovery_root_id: RecoveryRootId,
    pub account_id: AccountId,
    pub workspace_id: WorkspaceId,
    pub genesis_certificate_id: DeviceCertificateId,
    pub canonical_record_sha256: Sha256Digest,
    pub registered_at_ms: u64,
}
```

`root_status` returns only an accepted registration. All identifiers, scope, certificate ID,
digest, and timestamp must equal the local canonical row/receipt; a boolean `active`, caller-supplied
scope, missing digest, or partially matching projection is never sufficient.

Registration is exact compare-and-set per account and its single v1 workspace. The provider
validates canonical bytes, the complete recovery-record signature, recovery/genesis signatures and
bindings, authenticated scope, initial epochs, and bounds before storing anything. Identical
retries return the same receipt; any changed root, workspace, device, certificate, metadata
envelope, or bytes conflicts. A pre-existing root with a different workspace is a conflict; only
the exact registered account/workspace/digest is Complete.

The in-memory implementation stores only the canonical public/encrypted record, digest, timestamps,
and terminal state. Debug/errors/provider capture scans redact envelope contents and never contain a
phrase or plaintext key. A later Edge Function may translate this exact operation into the existing
`recovery_roots`, `device_certificates`, account, and binding tables without changing core state.

## Coordinator state machine

The coordinator owns one in-memory pending enrollment per daemon:

```text
absent
  -> phrase_displayed
  -> confirmation_checked
  -> locally_prepared
  -> provider_accepted
  -> locally_active
```

`overview` is the restart/discovery route and never generates a phrase. It validates the local row
and provider status and returns Idle, an in-memory AwaitingConfirmation ID without words, the exact
durable Submitting enrollment ID/timestamps, the exact Complete enrollment ID/timestamps, or
Conflict. A renderer that has lost the words for an AwaitingConfirmation state cancels that exact
session and asks the user to begin again; it cannot redisplay or confirm it.

`begin` performs the same discovery first. If a local prepared row exists, it exact-retries provider
registration, finishes activation when possible, and returns that durable enrollment's Submitting
or Complete status without words. This makes a restarted renderer recoverable without persisting an
enrollment ID. If both local and provider report the same exact active root, `begin` returns Complete
without words. If only one side reports an active root, or any enrollment/root/scope/certificate/
registration digest differs, it returns Conflict. Only an absent local and provider root generates
the phrase, recovery keys, enrollment/root/certificate IDs, request nonce, workspace keys, exact
genesis certificate, both encrypted envelopes, and four challenge positions. No Vault/provider
write occurs before confirmation.

`status` returns only the exact ID-bound state and timestamps. It never reconstructs or redisplays a
phrase. `cancel` consumes and zeroizes only the exact in-memory enrollment. At the exact expiry
boundary, every begin/status/confirm/cancel path first consumes and zeroizes the expired session.

`confirm` consumes the pending session. A mismatch zeroizes it and returns one generic invalid
confirmation error. A match writes the exact record plus device envelope as `prepared` in SQLCipher,
then zeroizes the phrase, recovery keys, and plaintext bundle before calling the provider. Provider
success is verified against enrollment ID, scope, and canonical digest before one local transaction
activates the recovery root, genesis certificate, and device material.

If the provider call is transient, the durable row remains `prepared`. Startup and status retry the
same canonical bytes, verify the same receipt, and finish locally. If the provider accepted before
a crash, the exact retry returns the same receipt. A conflicting provider result marks a terminal
local conflict and installs no certificate or usable material.

A crash before confirmation loses only the in-memory session: the displayed phrase is invalid and
the user begins again. It is deliberately not recoverable from disk.

## SQLCipher persistence

Forward migration 22 adds one strict `recovery_enrollments` table. It stores:

- enrollment/root/account/workspace/device/certificate identifiers;
- a nullable `activated_certificate_id` foreign key that is absent while prepared/conflicted and
  equals the canonical genesis certificate ID only while active;
- canonical registration bytes and SHA-256;
- canonical device-material envelope and SHA-256;
- duplicated control/key epochs and public-key metadata;
- `prepared | active | conflict` state;
- prepared, provider-accepted, completed, and conflict timestamps with exact nullability checks.

Unique constraints enforce one recovery root and one workspace bootstrap per account, plus one
bootstrap record per workspace and device. Digest widths are 32 bytes, epochs are positive,
timestamps are nonnegative, and active rows require the exact `activated_certificate_id` foreign
key while non-active rows require it to be null. Schema 21 rows are preserved unchanged.

Every getter reloads and validates all canonical bytes, hashes, duplicated identifiers, certificate
signature, root public keys, state, timestamps, and envelope bounds. `enrolled_workspace_material`
decrypts the device envelope only on demand with the stable protected `DeviceKeys`, revalidates the
complete AAD and canonical bundle, and returns zeroizing `WorkspacePairingMaterial`. It never caches
or persists opened key bytes.

Preparation, activation, and exact replay use single SQL transactions. A forced failure after any
activation sub-write rolls back root state, certificate insertion, material activation, and receipt
together.

## Pairing integration

The existing `PairingMaterialSource` boundary is extended to receive the authoritative Vault and
issuer device keys. `VaultPairingMaterialSource` calls `enrolled_workspace_material`; test-only
static sources may ignore those additional inputs. Pairing approval still checks the active exact
genesis certificate, device keys, scope, and control epoch before building a grant.

The end-to-end test therefore contains no fixture-only genesis or plaintext material source:

1. enroll first Vault through the recovery coordinator;
2. close/reopen and recover its sealed material;
3. inject `VaultPairingMaterialSource` into the existing pairing coordinator;
4. pair the second Vault through the shared in-memory pairing provider;
5. compare both scopes, epochs, workspace root keys, active epoch keys, and certificate graph;
6. reopen both Vaults and repeat the comparison.

This proves that recovery enrollment supplies the real trust and key-material root consumed by the
already reviewed pairing flow.

## Daemon ordering and failure behavior

`contextd` loads the protected device identity when either pairing or recovery enrollment is
configured. Recovery enrollment is a distinct optional service but shares the ordered bounded Vault
worker and immutable local device identity. Startup resumes prepared enrollment before listener
readiness, then resumes prepared pairing decisions.

The five enrollment requests route only through the Vault worker. Overview/status/cancel use the
ordinary Desktop role; phrase-returning begin and final confirm reach the worker only from the
DesktopRecoveryHost role through their dedicated native Tauri commands. Queue-full, startup,
provider, validation, conflict, declined-user-presence, and unavailable errors are bounded and
safe. Without a configured recovery service, requests return `Recovery setup needs the hosted
workspace service and is not available in this build.` Trusted device listing and existing offline
functionality remain available.

## Desktop experience

The Devices screen adds a Recovery section below the trusted-device list:

- `Set up recovery` invokes the dedicated Tauri Rust begin command only when overview reports Idle.
- On mount, `RecoveryEnrollmentOverview` discovers Idle, a durable Submitting enrollment after
  restart, Complete, or Conflict without generating or redisplaying a phrase. A Submitting status
  polls/resumes the exact stored enrollment ID.
- The actual ordered phrase appears only in the modal OS-native dialog built by trusted Rust, with a
  prominent one-time/cannot-reset warning. It never appears in React or the DOM.
- The screen shows the exact remaining validity of the memory-only enrollment and automatically
  clears challenge inputs when its 600,000 ms lifetime ends.
- The UI offers no automatic clipboard, file download, local-storage, analytics, or telemetry path.
- After the native phrase dialog returns its redacted challenge projection, exactly four labeled
  challenge inputs appear in React.
- The React confirmation action invokes the dedicated Tauri Rust approval command, never generic
  local_request. That command shows the four submitted pairs in the OS-native permanent-enrollment
  prompt. Only an explicit native approval sends them under DesktopRecoveryHost.
- Wrong confirmation clears the challenge immediately and requires a new enrollment.
- Success clears all challenge state, announces completion, focuses the Recovery heading, and
  refreshes the trusted-device list so the current genesis device is visible.
- Unmount sends a best-effort authenticated cancel and always clears local challenge state; explicit
  cancel waits for the daemon acknowledgement. The daemon's 600,000 ms expiry is the backstop if an
  unmount cancel cannot be delivered. Daemon restart before confirmation and terminal errors clear
  challenge words from the DOM and explain that the prior phrase is invalid.
- If hosted enrollment is unavailable, the screen remains truthful and no phrase is generated.

## Verification

Focused RED/GREEN coverage must prove:

- the exact 24-word BIP39/HKDF vector, NFKD behavior, domain-separated root keys, canonical record,
  complete recovery-root record signature, both AADs, recovery/device unwrap, and mutation
  rejection, including changed device name/platform and ciphertext;
- four random unique sorted challenge positions and rejection of one wrong word, changed position,
  missing/extra/reordered entries, replay, and cross-enrollment confirmation;
- exact 600,000 ms in-memory expiry, explicit cancellation, unmount best-effort cancellation, and
  phrase/key/material zeroization on confirm, mismatch, cancel, expiry, and service drop;
- no Vault/provider/certificate/material mutation before exact confirmation;
- exact provider registration retry, concurrent-account enrollment conflict, forged receipt,
  authenticated-scope/single-workspace mismatch, every changed status/receipt field, ciphertext
  bounds, and redacted captures;
- provider-only accepted state and locally pinned/provider-missing state both remain Conflict and
  never become Complete or generate replacement trust;
- schema 21 to 22 migration, exact prepared/active replay, all persisted-row tamper cases, forced
  activation rollback, restart before and after provider acceptance, and device-envelope reopen;
- renderer/daemon restart after durable preparation discovers the exact enrollment without browser
  persistence, reuses its registration digest, and never generates or redisplays another phrase;
- first-device enrollment followed by real second-device pairing and two-Vault reopen;
- single-writer daemon ordering, identity load before ready, prepared enrollment resume before
  listener publication, generic-renderer begin/confirmation denial, native phrase
  display/cancel/accept, native approval cancel/accept, DesktopRecoveryHost confinement, protocol
  1.3 parity, and unavailable behavior;
- accessible native phrase and React challenge/completion behavior, DOM cleanup, focus/status
  announcements, no browser persistence, no full-phrase confirmation request, and no key-shaped
  fields;
- canary absence from SQLCipher database/WAL/SHM bytes, provider captures, plaintext database
  projections, Debug/errors, Tauri command results, browser storage, and every DOM state. The one
  expected initial authenticated IPC phrase response and trusted native dialog message are tested
  separately and are not mislabeled as leaks.

Protocol, core recovery, existing pairing/signed-sync, local IPC, contextd, desktop, binding,
schema, format, diff, and scoped Clippy gates must pass. Independent correctness and security review
must report no Critical or Important finding before acceptance.

## Handoff after this slice

The next Task 17 recovery slice can accept a user-entered phrase on a fresh installation, derive and
validate the exact registered root, decrypt recovery metadata, issue a new recovery-root certificate,
and require deterministic reassociation/session-revocation rules. Hosted enrollment remains blocked
on an authorized provider adapter and credentials. Device revocation/epoch rotation and account
deletion remain later independent designs. Apple Developer access is not required here.
