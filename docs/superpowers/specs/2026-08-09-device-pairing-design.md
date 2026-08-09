# Existing-Device Pairing and Exact Certificate Approval Design

Date: 2026-08-09

Status: approved for implementation from the frozen Context Relay v1 plan. The user requested
continuous autonomous development without clarification questions, so this design resolves the
remaining choices conservatively from the existing protocol, threat model, and architecture.

## Goal

Build the first independently testable slice of Task 17: an existing trusted device creates a
short-lived pairing code, a new device proves possession of its proposed signing key, the existing
device approves or rejects the exact request, both devices authenticate the exact approval through
a mandatory out-of-band safety-number comparison, and an approved new device receives a verifiable
device certificate plus encrypted workspace key material.

The slice must work end to end between two simulated daemons backed by real SQLCipher Vaults and a
shared in-memory provider. It must leave a narrow transport boundary for later Supabase Edge
Functions without claiming hosted pairing is complete.

## Scope decomposition

Task 17 combines five security-sensitive lifecycle systems that should not share one implementation
or review boundary:

1. existing-device pairing and exact certificate approval;
2. recovery-key enrollment and recovery-root pairing;
3. account reassociation to a new GitHub identity;
4. revocation, signed cutoffs, epoch rotation, and key-envelope publication;
5. seven-day deletion, export, cancellation, and purge.

This design covers only item 1. It establishes certificate, device, transport, and persistence
interfaces that later slices may consume. It does not implement recovery, revocation, reassociation,
deletion, hosted Edge Functions, or production cross-device networking.

## Alternatives considered

### A. Cloud-first Edge Functions

Implement pairing directly against the existing Supabase tables. This would exercise the final
provider early, but it would couple protocol correctness to credentials, deployment state, and
hosted debugging. It also conflicts with the successful sync sequence, which proved the state
machine against an in-memory transport before adding a hosted adapter.

### B. Durable core plus an injected provider boundary — selected

Freeze canonical request/grant contracts, implement a durable pairing coordinator and Vault
records, and prove the complete flow against a shared in-memory provider. Daemon and desktop
surfaces consume the same coordinator boundary. A later hosted adapter implements the provider
trait and Edge Functions without changing the cryptographic state machine.

This option gives deterministic tests for expiry, retries, replay, substitution, approval, and
crash/reopen behavior without requiring a paid service or private credential.

### C. Daemon-only temporary state

Keep invites and decisions in process memory and sign certificates in request handlers. This is
smaller, but restart behavior becomes ambiguous, exact retries cannot be proven, and later hosted
work would need to replace rather than implement a boundary. It is rejected.

## Frozen constraints

- Pairing codes contain ten Crockford Base32 characters displayed as `XXXXX-XXXXX`.
- A code is a request locator, not an authenticator or approval.
- Codes are one-time, expire after exactly ten minutes, and permit at most five failed attempts.
- The code remains a locator and never authenticates the issuer. Before local trust changes, the
  joining user must enter the complete 80-bit safety number shown by the approving device.
- An existing device receives one yes-or-no decision for the exact request digest.
- The approval display includes device name, platform, request time, and key fingerprint.
- Approval binds account ID, workspace ID, request nonce, device ID, Ed25519 signing key,
  X25519 wrapping key, and the active control epoch.
- The daemon owns randomness, device identity, key generation, signing, wrapping, Vault writes, and
  provider calls. React and the Tauri shell never receive private keys or plaintext workspace keys.
- Secret buffers are zeroized and no raw code, private key, workspace key, or decrypted grant is
  written to logs.
- Windows remains Windows 11 24H2+ x64; macOS remains macOS 14+ Apple Silicon. No paid Apple
  Developer action is part of this slice.
- Protocol maps and signing inputs are deterministic and reject unknown fields.

## Architecture

```text
React Devices screen
        |
authenticated local IPC
        |
contextd pairing commands
        |
PairingCoordinator ---- DeviceKeySource
        |                       |
        |                       +-- private device keys outside React
        |
        +---- SQLCipher Vault (certificates, exact decisions, grant receipts)
        |
        +---- PairingTransport
                    |
                    +-- InMemoryPairingTransport (this slice)
                    +-- Supabase Edge Function adapter (later slice)
```

`PairingCoordinator` contains the cryptographic and state-machine rules. `PairingTransport` stores
only public request data, digests, state, and encrypted grants. The Vault is authoritative for local
trusted certificates and exact decisions. Private device keys remain behind `DeviceKeySource`; the
first implementation uses injected keys in tests and the daemon's protected local key source.

## Canonical protocol contracts

### Pairing request

`PairingRequestV1` is canonical CBOR with a dedicated domain-separated signing preimage:

```rust
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

The new device signs every field with the proposed Ed25519 private key. The provider and approving
device verify the signature before trusting the request. The request digest is SHA-256 over the
canonical signed bytes. Exact bytes are retained so an identical retry is idempotent; the same
pairing ID, nonce, device ID, or code with different bytes is a conflict.

The displayed request time is the provider's receipt time, not a joining-device wall clock.

The request deliberately excludes account, workspace, and epoch values. The code locates an invite
created inside an authenticated account/workspace, and only the approving active device is allowed
to bind that server-selected scope into a certificate.

### Pairing key bundle

`PairingKeyBundleV1` is plaintext only inside the approving and joining daemons:

```rust
pub struct PairingKeyBundleV1 {
    pub schema_version: u16,
    pub account_id: AccountId,
    pub workspace_id: WorkspaceId,
    pub control_epoch: u32,
    pub key_epoch: u32,
    pub workspace_root_key: SecretBytes,
    pub active_epoch_key: SecretBytes,
}
```

The bundle is encoded canonically, wrapped to the request's X25519 public key with the existing
XChaCha20-Poly1305 envelope, and zeroized after use. Its associated data binds the pairing ID,
request digest, certificate digest, account, workspace, control epoch, and key epoch.

### Pairing grant

`PairingGrantV1` contains only public certificate material and the encrypted key envelope:

```rust
pub struct PairingGrantV1 {
    pub schema_version: u16,
    pub pairing_id: PairingId,
    pub request_digest: Sha256Digest,
    pub certificate_id: DeviceCertificateId,
    pub certificate: DeviceCertificateV1,
    pub key_epoch: u32,
    pub wrapped_key_bundle: WrappedKeyEnvelope,
}
```

The approving daemon may build a grant only when the issuer is its currently active exact device
certificate. The joining daemon accepts the grant fields for inspection only when the pairing ID
and request digest equal its durable request and the certificate fields exactly equal the request
plus approved scope/epoch. A fresh joiner does not treat that issuer as trusted until safety-number
confirmation.

### Approved payload and trust bootstrap

`PairingGrantV1` remains frozen. Provider approval carries a separate canonical
`PairingApprovedPayloadV1` containing its own schema version, the exact inner canonical-grant bytes,
the approving device's exact certificate ID and canonical certificate bytes, and its bounded device
name/platform display metadata. The outer payload is bounded and rejects unknown, trailing,
reordered, or noncanonical values; provider CAS
and receipt digests cover its exact outer bytes. The first coordinator slice permits only an active
recovery-root-signed genesis certificate as the approving certificate; later certificate-chain
work may generalize this without changing the safety-number rule.

A fresh joining Vault has no issuer trust anchor. It therefore must not accept a provider-returned
certificate, a caller-injected certificate, or an authenticated-provider lookup as authority. Both
devices instead derive the same transcript digest from the exact approved payload:

```text
SHA-256(
  "context-relay/pairing-safety/v1\0" ||
  pairing_id || request_digest || SHA-256(canonical_approved_payload)
)
```

The approving device displays the first 80 bits as five groups of four hexadecimal characters and
can recover the same display after restart from its validated durable decision. The joining daemon
never returns its independently computed expected number to the UI and never obtains a number from
a provider field: the user enters all 20 hexadecimal digits shown on the approving device, and the
daemon compares them without prefix acceptance. Debug and safe-error output redact the value. The
full digest and exact approved payload are durably retained. Provider substitution then
changes the safety number; guessing a matching value is bounded by 2^-80 per approved transcript.
The locator code is deliberately excluded.

Inspection and opening are separate typestates. `inspect_pairing_approval` verifies canonical
request/payload bytes, the genesis certificate shape and signature, child-certificate signature and
all request/scope/epoch/key bindings, but cannot mutate trust or decrypt workspace keys. The raw
inspection/opening helpers and transcript/safety getters are internal coordinator capabilities in
normal builds; the `test-support` feature exposes them only for protocol regression tests. Only
`confirm_join` accepts pairing ID plus the user-entered safety number, reloads and re-verifies
the durable transcript, and opens the bundle with the joining device key. It never opens an
in-memory or caller-supplied transcript that was not first persisted.

## Pairing state machine

Provider-visible state is:

```text
created -> located -> request_bound -> approved
   |          |            |            |
   +----------+------------+-> cancelled
   +----------+------------+-> expired
              +------------+-> exhausted
                           +-> rejected
                           +-> result_retained_for_exact_retry
```

The public v1 IPC continues to present `pending`, `approved`, `rejected`, and `canceled`; `created`,
`request_bound`, `expired`, and `exhausted` are precise internal provider states with stable safe
errors.

### 1. Create invite

An authenticated active device asks the coordinator to create an invite for its exact account and
workspace. The provider generates a UUIDv7 pairing ID and 50 random bits, renders the Crockford
code, and stores only `HMAC-SHA-256(provider_pepper, normalized_code)`. Active code digests are
unique; a collision is regenerated. The raw code is returned once to the creating daemon, never
logged, and expires at `created_at + 600_000 ms`.

### 2. Submit request

The joining daemon first resolves the code through its provider-authenticated joining session. The
provider normalizes only the single required hyphen and uppercase Crockford text, checks time, then
looks up the HMAC digest and returns the pairing ID. Wrong codes increment a durable counter scoped
to that provider-authenticated joining session; the session identity is supplied by the transport
adapter and is never accepted from request JSON. Attempt five exhausts that session's join budget,
and later correct codes remain rejected. Hosted rate limits may additionally bind the budget to the
invite, account, source, or installation without changing the core contract.

After resolving the locator, the joining daemon generates or loads its device keys, derives public
keys, generates a 32-byte request nonce, builds and signs `PairingRequestV1` containing that exact
pairing ID, durably records its request, and submits the canonical bytes by pairing ID. A valid
request changes the invite to `request_bound` and makes the code unusable for any other request.
An exact retry by pairing ID is idempotent; a different request conflicts.

### 3. Review exact request

The existing daemon fetches the exact signed bytes, verifies the request signature, recomputes the
digest and fingerprint, and returns display-only fields to React. React sends back only pairing ID,
request digest, and yes/no. The coordinator refetches the request and refuses any digest mismatch,
expired state, changed request bytes, inactive issuer, or control-epoch change.

### 4. Approve or reject

For rejection the provider performs a compare-and-set from `request_bound` to `rejected`.

For approval, the coordinator signs `DeviceCertificateV1` with the active device key and obtains
the current workspace root and epoch material from a trusted daemon-owned material source. Key
material is never accepted from approval IPC or another caller-supplied decision field. It wraps
that material, stores an exact local decision receipt plus canonical approved payload, and asks the
provider to compare-and-set the same request digest to that exact payload. Repeating the identical
approval returns the prior payload. A different issuer
certificate, certificate, envelope, digest, or decision conflicts. The approving result includes
the locally derived safety number for display.

The local decision and provider transition cannot share one database transaction. The coordinator
therefore writes a resumable `prepared` decision before the provider call and records the returned
grant receipt afterward. Reopen resumes only the same canonical grant; it never signs a replacement.

### 5. Complete on the joining device

The joining daemon polls by pairing ID and its durable request digest. On approval it verifies and
durably stores the exact approved payload in an `awaiting_confirmation` state without unwrapping or
changing trust. Only after the user enters the complete matching safety number does it re-verify the
durable transcript, unwrap, and atomically store the certificate, sealed grant/epoch material, and
exact completion receipt in its Vault. The sealed canonical payload is the durable key-material
source and is reopened only with the protected joining-device keys; no second plaintext key copy is
stored. An exact retry is idempotent. A substituted request, issuer, grant, certificate, envelope,
or safety number is rejected without changing trust or keys.

## Vault schema

Schema 20 adds three focused tables:

- `device_certificates`: canonical certificate bytes and hash keyed by certificate ID, unique by
  `(account_id, workspace_id, device_id)`, with active/revoked state and display metadata;
- `pairing_decisions`: pairing ID, request digest, decision, canonical grant bytes/hash, preparation
  and completion state, and local timestamps;
- `pairing_joins`: the joining device's canonical request bytes/hash and completed certificate ID.

The tables never store a raw pairing code or private key. Secret key bundles are stored only through
the existing encrypted secret boundary required by later sync identity loading; tests additionally
scan raw database, WAL, provider payload, and safe-log bytes for a plaintext canary.

Every state transition uses a transaction and exact canonical-byte comparison. Conflicting replays
fail closed rather than overwriting rows.

A forward-only schema 21 extends decision and join rows with the exact canonical request/hash,
canonical approved-payload bytes/hash, the full transcript digest, exact inviter certificate ID,
duplicated scope/control/key epochs, and confirmation metadata. Its `stored`,
`awaiting_confirmation`, `completed`, and
`legacy_unconfirmed` nullability checks are exact; hashes are 32 bytes, epochs are positive, and
timestamps are nonnegative. Schema-20 rows predate a coordinator and become terminal
`legacy_unconfirmed`, never confirmed trust. New coordinator writes persist preparation or
`awaiting_confirmation` atomically. Confirmation inserts or validates both the inviter and child
certificate rows as active and persists their IDs, sealed outer payload/inner grant, epochs, full
transcript, and completion receipt in one transaction. Strict getters revalidate canonical
bytes/hashes, duplicated scope/epochs, both certificate rows/states, and joining DeviceKeys before
reopening completed material.

## Transport boundary

The transport boundary exposes role-separated operations rather than generic table access. A
joining handle cannot create or decide invites, and an approving handle cannot reset join-session
attempt state. The trusted daemon composition root moves both authenticated handles into the
pairing coordinator; IPC/request callers never provide a transport implementation to an operation.
The join transport's approved result is opaque outside the core: adapters may construct it, but
only the coordinator can extract the exact payload/receipt. This prevents a joining caller from
recovering the approved-payload digest needed to derive its own expected safety number:

```rust
pub trait PairingJoinTransport {
    fn resolve_code(&self, code: &PairingCode, now_ms: u64)
        -> Result<PairingId, PairingError>;
    fn submit_request(&self, pairing_id: PairingId, request: &[u8], now_ms: u64)
        -> Result<PairingReceipt, PairingError>;
    fn result(&self, pairing_id: PairingId, request_digest: Sha256Digest, now_ms: u64)
        -> Result<PairingResult, PairingError>;
}

pub trait PairingApprovalTransport {
    fn create_invite(&self, now_ms: u64) -> Result<PairingInvite, PairingError>;
    fn invite_status(&self, pairing_id: PairingId, now_ms: u64)
        -> Result<PairingInviteStatus, PairingError>;
    fn request(&self, pairing_id: PairingId, now_ms: u64)
        -> Result<Option<StoredPairingRequest>, PairingError>;
    fn decide(&self, decision: PairingDecisionEnvelope, now_ms: u64)
        -> Result<PairingDecisionReceipt, PairingError>;
    fn cancel(&self, pairing_id: PairingId, now_ms: u64)
        -> Result<(), PairingError>;
}
```

Each transport handle carries provider-authenticated caller context. Existing-device handles are
bound to an active account/workspace/device; joining handles are bound to a server-side join-session
identity used for the five-attempt budget. Core request fields cannot replace either identity.

The in-memory implementation is provider-like: it owns its pepper and randomness, enforces scope,
expiry, per-session attempts, one-time binding, and compare-and-set decisions, and returns only
bounded records. Tests can inject deterministic entropy and time. Production code never exposes
test-only fixed codes, peppers, or join-session identities.

## Local IPC and desktop behavior

The current `PairingJoinParams` incorrectly lets a desktop client supply device identity, nonce, and
public keys even though the daemon owns cryptography. It changes to accept only the pairing code and
user-visible device name. The daemon supplies platform, device ID, nonce, and public keys.

Pairing results become phase-specific rather than forcing request fields before a device has joined:

- `PairingInviteInfo`: pairing ID, code, creation time, expiry time;
- `PairingInviteStatusInfo`: pairing ID, creation time, and expiry time, with no code, for
  provider-backed restart/status recovery after the one-time invite response;
- `PairingRequestInfo`: pairing ID, device name, platform, request time, key fingerprint, digest;
- `PairingApprovalInfo`: the exact reviewed request plus the approver-only full safety number;
- `PairingCompletionInfo`: pairing ID and trusted `DeviceSummary`.

`PairingConfirmParams` contains only the pairing ID and the complete five-group safety number typed
by the joining user. It is a distinct Desktop-only local method. Join/status results never include
the joining device's independently computed value.

The Devices screen will:

- list trusted devices and clearly mark the current device;
- create an invite, show the code and remaining validity, and allow cancel;
- accept a code on a joining device without exposing generated keys;
- show one modal with name, platform, request time, and fingerprint for yes/no approval;
- after approval, show the full five-group safety number on the approving device, require the user
  to enter it on the joining device, and never expose the joiner's independently computed value;
- never auto-approve, hide a changed digest, or retry a rejection as approval;
- restore focus and announce status/errors accessibly.

When no production `PairingTransport` is configured, the app reports hosted pairing unavailable. It
does not silently create a process-local invite that another physical device cannot reach. End-to-
end tests inject one shared in-memory provider into two daemon instances.

## Errors and safe strings

Internal errors distinguish invalid code, attempts exhausted, expired, canceled, rejected, state
conflict, request conflict, digest mismatch, invalid request signature, inactive issuer, epoch
changed, invalid certificate, invalid grant, safety-number mismatch, persistence failure, and
transient transport failure.

User-visible and log-safe strings contain stable categories only. They never include codes, request
bytes, public-key fingerprints beyond the explicitly approved UI field, envelopes, decrypted key
material, or signatures. Invalid code and unknown invite use the same user-visible message.

## Verification

### Protocol and crypto

- canonical request and grant vectors are stable and round-trip exactly;
- unknown fields, noncanonical bytes, invalid signatures, key substitution, nonce substitution,
  pairing-ID replay, and digest substitution fail;
- certificate fields equal the approved request and active scope/epoch exactly;
- wrapped key material decrypts only with the joining device's X25519 key and exact associated data.
- the approved-payload canonical vector and safety-number vector are stable; a self-consistent
  provider-supplied issuer/grant substitution produces a different safety number and cannot mutate
  trust before exact confirmation.

### Provider state machine

- codes are exactly ten Crockford characters and expire at ten minutes;
- five wrong attempts permanently exhaust the invite;
- a correct code is one-time and binds one exact request;
- identical submission and decision retries are idempotent;
- changed request, decision, grant, or scope conflicts;
- cancel, reject, expire, and approve transitions are terminal as specified.

### Persistence and restart

- prepared approval resumes after close/reopen without signing a second grant;
- a crash before or after provider acceptance converges to one exact local receipt;
- joining completion is atomic and idempotent;
- awaiting confirmation survives reopen with the same full transcript and safety number, and no
  decrypted workspace material is stored before or after confirmation;
- conflicting certificate/device rows roll back;
- raw SQLCipher/WAL/provider/safe-log scans contain no plaintext key canary or raw pairing code.

### End to end

Two real daemon/Vault instances share one in-memory provider. The existing device creates an invite,
the new device joins, the existing device sees exact display fields, approval produces one
certificate/grant, and the new device verifies and persists trust plus key material. Negative flows
cover wrong-code exhaustion, expiry boundaries, rejection, cancel, replay, request substitution,
certificate substitution, issuer revocation between display and decision, epoch change, and crash
recovery.

Protocol, core, local IPC, contextd, desktop component, binding, schema, formatting, lint, and scoped
Clippy gates must pass. Correctness and security reviews must report no Critical or Important issue
before the slice is accepted.

## Non-goals and handoff

This slice does not deploy or mutate Supabase, use GitHub OAuth, enroll a recovery root, rotate an
epoch, revoke a device, reassociate an account, delete an account, export user data, or sign an Apple
application. The next Task 17 slice can implement recovery-root enrollment against the same
certificate and key-bundle contracts. A later hosted slice implements `PairingTransport` with Edge
Functions and the existing `pairing_requests` table.
