# Signed Synchronization Design

**Date:** 2026-08-05  
**Status:** Approved direction derived from the frozen Context Relay v1 plan  
**Scope:** Task 16 — signed end-to-end encrypted synchronization

## Goal

Add a deterministic synchronization engine that lets complete encrypted local
replicas exchange signed ciphertext through an in-memory transport and then the
Task 15 Supabase boundary. Offline writes remain available, retries are
idempotent, tampering is quarantined before decryption, and Realtime remains an
optional pull hint rather than a source of truth.

## Fixed constraints

- Every device keeps a complete encrypted local replica.
- `SyncOperationV1` remains operation schema version 1. The scope-bound
  `CheckpointV1` DTO uses independent checkpoint schema version 2 and canonical
  RFC 8949 CBOR; the Rust type name is retained for API continuity.
- An operation signature is verified against a database-admitted certificate
  before its ciphertext is decrypted.
- The cloud sees only ciphertext and the routing metadata already frozen in
  Task 15.
- A duplicate operation ID succeeds only when the canonical bytes match.
- Device-sequence conflicts, gaps, bad frontiers, bad epochs, hash-chain
  breaks, invalid signatures, ciphertext-hash mismatches, and decryption
  failures are quarantined and never mutate live records.
- Wall-clock last-write-wins is prohibited.
- Concurrent body changes retain both operations and create a conflict.
- A tombstone defeats causally older writes. A concurrent update and delete
  creates a conflict.
- Realtime carries only `{ "v": 1, "kind": "pull_now" }` on the exact private
  `account:<uuid>:sync` topic.
- Database, Storage, Realtime, and logs must never contain the plaintext canary.
- Writes stop cleanly at the exact 524,288,000-byte cloud quota while local
  reads and local mutation remain available.
- No paid service, billing integration, Apple Developer membership, or signed
  Apple distribution work is part of this task.

## Approaches considered

### 1. Local deterministic core, then narrow cloud adapters — selected

Build one pure merge/admission engine around an in-memory transport, persist its
state in the encrypted Vault, and reuse the same contracts for Supabase. This
allows randomized offline convergence and tamper testing without network
credentials, keeps provider behavior out of merge logic, and follows the
explicit Task 16 sequence.

### 2. Cloud-first synchronization

Implement the Edge Function and hosted database calls before local convergence.
This would exercise the deployment surface earlier, but it would mix network,
authentication, admission, storage, and merge failures in the first test loop.
It also makes deterministic offline property tests harder. This approach is
rejected.

### 3. Replace the Vault with a new event-store abstraction

Rebuild local storage around a new event-sourcing layer before adding sync. This
could produce a cleaner theoretical model, but the Vault already has encrypted
operations, outbox, checkpoints, conflicts, and atomic record mutations. A
rewrite would expand risk without improving the version 1 wire contract. This
approach is rejected.

## Delivery slices

Task 16 is delivered as three reviewable slices that share one design:

1. **Replica core:** canonical encrypted mutation payloads, admission, durable
   device heads/cursors, deterministic merge, checkpoints, in-memory transport,
   and randomized two-device convergence.
2. **Cloud admission:** a forward-only database migration plus one JWT-protected
   `sync` Edge Function for operation/checkpoint admission and blob-ticket
   orchestration. The Edge Function verifies canonical bytes and Ed25519
   signatures using a certificate loaded from the trusted database chain, then
   calls service-only definer RPCs.
3. **Supabase transport:** authenticated pull, paginated gap repair, Storage
   upload/download, private Realtime pull hints, full-jitter backoff, quota
   behavior, and local/hosted end-to-end verification.

Each slice has an independent security and correctness review. A later slice
does not weaken an earlier slice's invariants.

## Existing foundation

The implementation extends, rather than replaces, these existing boundaries:

- `crates/protocol/src/sync.rs` owns the immutable operation/checkpoint DTOs.
- `crates/protocol/src/canonical_cbor.rs` owns deterministic encoding and strict
  decoding.
- `crates/core/src/crypto.rs` owns XChaCha20-Poly1305 and Ed25519 helpers.
- `crates/core/src/vault.rs` already persists operations, outbox entries,
  checkpoints, and record conflicts inside SQLCipher.
- Task 15 denies client mutation, provides account-scoped authenticated reads,
  charges inline ciphertext atomically, and exposes only narrow service RPCs.

The existing local MCP mutation methods intentionally do not create cloud
envelopes yet. Task 16 adds an optional configured sync identity and makes the
record mutation plus encrypted outbox append one Vault transaction. An
unconfigured device remains a fully functional offline-only replica.

## Protocol additions

### Encrypted mutation payload

`RecordMutationV1` is a strict tagged union containing exactly one version 1
record payload or one tombstone:

```rust
pub enum RecordMutationV1 {
    UpsertMemory(MemoryRecord),
    UpsertMemoryCandidate(MemoryCandidate),
    UpsertTask(TaskRecord),
    UpsertSecretRef(SecretRef),
    UpsertInstruction(InstructionRecord),
    UpsertComponent(ComponentRecord),
    UpsertProject(ProjectIdentity),
    Tombstone {
        record_id: RecordId,
        record_kind: RecordKind,
    },
}
```

It uses its own core-deterministic CBOR encoder/decoder. The mutation map has
integer keys for version, record kind, mutation kind, record ID, and one
canonical JSON byte string (or `null` for a tombstone). Canonical JSON is the
exact compact `serde_json` struct serialization; decoding deserializes the
typed variant, validates it, serializes it again, and requires byte equality.
All synchronized record DTOs use fixed struct field order, reject unknown
fields, and represent metadata maps as ordered vectors, so no unordered JSON
object enters this payload. The decoded ID, kind, project scope, and mutation
kind must agree with the outer operation.

### Operation encryption AAD

`encode_sync_operation_aad_v1` encodes the immutable routing fields needed
before encryption: schema version, operation/account/workspace/project/record
IDs, record and mutation kinds, device ID and sequence, causal frontier,
control/key epochs, previous-device hash, blob references, and creation HLC.
It excludes nonce, ciphertext, ciphertext hash, and signature, avoiding any
circular dependency. The XChaCha nonce is the envelope nonce. After encryption,
the ciphertext hash is SHA-256 of the exact ciphertext, and the device signs the
existing operation signing preimage, which binds every field.

### Hash chains

`previous_device_hash` is SHA-256 of the previous complete canonical signed
operation from the same device and workspace. The first operation uses 32 zero
bytes. Checkpoints use the same rule over complete canonical signed checkpoint
bytes. The hosted operation/checkpoint rows add a 32-byte `canonical_sha256`
column so the service wrapper can validate the next link without storing a
second copy of the ciphertext.

Checkpoint transport append, pull, and exact-hash lookup select checkpoint
schema version 2 explicitly. Providers partition checkpoint logs by version
and append only when the signed predecessor is the current endpoint. A due
local checkpoint extends an authenticated complete lagging endpoint from the
same pull cycle; the Vault pins that extension and retires the durable scan in
one transaction. Before pinning every locally built checkpoint, the engine
re-reads the provider: a previously empty log must contain only the signed local
genesis, while an authenticated endpoint must have the signed local checkpoint
as its sole next node; both paths require an empty tail. A concurrent provider
extension rejects the sibling append; even a provider that reports an omitted
or competing checkpoint as accepted fails that endpoint proof, so the local pin
remains unchanged. Legacy unscoped checkpoint version 1 logs
must remain in a separate partition or be retired and can never join version 2
chains. This is a pre-release contract change with no hosted checkpoint
transport deployed.

### Cursor

The durable remote cursor is the pair `(received_at, id)`, ordered
lexicographically. Timestamp alone is not unique. Pull queries request rows
strictly after the pair and use a fixed maximum page of 256 operations.
Advancing the cursor and committing the admitted page happen in one local Vault
transaction. A crash can replay a page but cannot skip one.

## Local components

The sync module is split by responsibility:

- `payload.rs`: strict mutation CBOR and outer-envelope consistency.
- `admission.rs`: certificate, signature, hash, sequence, frontier, epoch,
  ciphertext hash, AAD, decryption, and payload checks in fail-closed order.
- `causal.rs`: frontier normalization, dominance, concurrency, and gap
  calculation.
- `merge.rs`: deterministic record-head and conflict transitions.
- `checkpoint.rs`: deterministic state summary, state hash, signing, chain
  validation, and local checkpoint pins.
- `transport.rs`: provider-independent push/pull/checkpoint/blob interface.
- `memory.rs`: deterministic in-memory provider used by property tests.
- `engine.rs`: outbox push, paginated pull, gap repair, apply transaction,
  checkpoint scheduling, and status.
- `backoff.rs`: injected-clock, injected-random full-jitter scheduling.
- `supabase.rs`: HTTP/Data API/Storage/Realtime adapter only; no merge rules.

The provider-independent transport uses typed batches and stable error classes.
It never receives a plaintext record or a content key.

## Durable Vault state

Forward migration `0014_signed_sync.sql` adds:

- outbox attempt count, next-attempt time, and last safe error code;
- canonical operation hash and admission/apply/quarantine status;
- one device head per workspace/device with sequence and canonical hash;
- one record head set per workspace/record, including a tombstoned flag;
- one remote `(received_at, id)` cursor per workspace/provider;
- checkpoint canonical hashes and locally pinned newest checkpoint;
- durable nonce identifiers per key epoch; and
- quarantine rows containing only envelope identifiers, safe reason codes, and
  the signed ciphertext envelope.

No table stores an epoch key, signing secret, decrypted mutation, or plaintext
diagnostic. Existing SQLCipher record tables remain the materialized local
view. Search indexes are rebuilt from the selected live record state.

## Admission order

Incoming operations are handled in this exact order:

1. Enforce batch and byte limits and decode canonical CBOR.
2. Validate the immutable protocol DTO and outer routing scope.
3. Load the creator certificate through the trusted local certificate store.
4. Verify the certificate chain and active control/key epoch.
5. Verify the operation Ed25519 signature over canonical preimage bytes.
6. Verify the SHA-256 ciphertext hash.
7. Classify an exact canonical replay, operation-ID conflict, device-sequence
   conflict, gap, or previous-device-hash break.
8. Validate the causal frontier against known and fetched device heads.
9. Decrypt using the epoch key and `encode_sync_operation_aad_v1`.
10. Strictly decode `RecordMutationV1` and match it to the outer fields.
11. Apply the deterministic merge transaction and advance heads/cursor.

No decryption attempt occurs before steps 1–8 succeed. A gap pauses that device
chain, retrieves the missing range, and retries in sequence. A malformed or
cryptographically invalid operation is quarantined; later rows from that device
remain blocked behind the broken chain.

## Deterministic merge

For two operations targeting one record:

- Exact canonical replay: no-op success.
- Incoming causally dominates every current head: replace the heads and apply
  the incoming upsert/tombstone.
- Every current head causally dominates incoming: retain the historical
  operation, with no live-state change.
- Concurrent upsert/upsert: retain both signed head operations, expose the head
  with the canonically smallest operation ID as the temporary single-row local
  representative, and create a conflict.
- Concurrent upsert/tombstone: retain both signed head operations, use the same
  canonical representative rule for the temporary live/tombstoned local view,
  and create a conflict.
- Tombstone causally newer than all upserts: tombstone becomes the sole head.
- A later resolution operation whose frontier dominates every conflict head
  becomes the sole head and clears the conflict.

Head ordering, conflict display ordering, state-summary ordering, and batch
application ordering use canonical operation ID bytes as the final tie-breaker.
Physical wall time never chooses a winner.

The existing materialized Vault tables remain one row per record. Concurrent
versions are durably retained by their signed operation rows and record-head
set; the canonical representative rule prevents arrival order from changing
the temporary local view while a conflict is unresolved.

## Checkpoints and rollback detection

The state hash is SHA-256 of a canonical CBOR array ordered by record UUID. Each
entry contains record ID, kind, the ordered canonical hashes of all current
heads, and the tombstone/conflict flags. A checkpoint is generated after 1,024
newly applied operations or 24 hours from the locally observed commit/apply time
of the first uncheckpointed operation, whichever comes first, and may also be
requested explicitly. Signed operation HLC values never drive this local clock.

A checkpoint signs its exact account and workspace IDs and is accepted only
after scope, certificate, signature, frontier, key epoch, prior-checkpoint hash,
and recomputed state hash validation. Historical nodes are authenticated for
scope/signature/link continuity without comparing each historical state to the
current replica. A bounded pull persists a provider-scoped hash-anchored scan
cursor; only the newest endpoint whose frontier/state matches the current Vault
is atomically pinned. Endpoint row acceptance, pin replacement, schedule reset,
and provider-scan rebase share one Vault transaction, so an abort cannot leave
an accepted pin with a stale scan base. Every transport implementation must
provide exact scoped lookup by canonical checkpoint hash; wrappers cannot
silently substitute absence. A server response that omits a pinned hash, forks
the chain, or cannot resume from the exact stored anchor is an integrity error.

Schema 18 never attempts to reinterpret schema-17 checkpoint bytes, whose
eight-field signature omitted account and workspace. During migration it marks
each affected checkpoint schedule requested, deletes pins before their signed
rows, and then creates the durable scan table in the same migration
transaction. Operations, device frontier, record heads, and materialized state
remain intact so a fresh ten-field scoped checkpoint can be generated. The
documented v1 limitation remains: a genuinely fresh device with no local
checkpoint pin cannot distinguish an older valid snapshot from the newest valid
snapshot.

Permanent auth, revocation, quota, and configuration outbox blocks never become
time-due. A caller may resume selected rows only through the explicit matching
state-change API, which preserves attempt history and resets the next-attempt
time. Integrity-quarantined rows are excluded from this recovery path.

## Cloud admission boundary

One JWT-protected `sync` Edge Function exposes versioned actions for operation
push, checkpoint push, and blob reservation/finalization/release. Pulls continue
through authenticated Data API and Storage requests under Task 15 RLS.

The Edge request body is strict JSON containing base64url-encoded complete
canonical CBOR envelopes. A maximum of 256 operations and 8 MiB total request
bytes is enforced before decode. The function:

1. validates the caller JWT and extracts only its signed `sub` and `session_id`;
2. calls a service-only identity-context RPC to obtain the active binding,
   account, workspace, epochs, certificate ID, and database-trusted certificate
   chain;
3. canonical-decodes the submitted bytes and verifies the admitted chain and
   operation/checkpoint signature with Web Crypto Ed25519;
4. passes only verified decoded fields plus the JWT-derived identity and exact
   canonical SHA-256 to a service-only definer append RPC;
5. lets the RPC revalidate the same active binding, certificate, epochs,
   per-device sequence/hash head, duplicate equality, and quota in one database
   transaction; and
6. sends the private `pull_now` Broadcast only after commit. Broadcast failure
   never rolls back or changes the durable append result.

The service key remains an Edge environment secret. It is never accepted in a
request, returned, written to the Vault, or logged. The function uses fixed safe
error codes and logs only request IDs, counts, timing, and safe classifications.

New database functions remain `SECURITY DEFINER`, owned by the existing
`NOLOGIN NOINHERIT NOBYPASSRLS` owner, use `search_path = ''`, fully qualify all
references, revoke default execution immediately, and grant only the exact
service-role signatures. The service role receives no direct relation grant.

## Supabase transport and scheduling

- Push the oldest due outbox batch first. Remove outbox rows only after exact
  accepted/duplicate acknowledgements are durably recorded.
- Pull pages by `(received_at, id)` until empty. Realtime invokes the same pull
  path; it carries no data.
- Poll every 30 seconds while online even when Realtime is connected, so lost
  hints cannot prevent convergence.
- Retry transient network and 5xx errors with full jitter: random delay in
  `[0, min(60 seconds, 1 second * 2^attempt)]`.
- Do not retry authentication, revocation, malformed envelope, signature,
  epoch, sequence-conflict, hash-chain, or quota errors until relevant local
  state changes.
- Refresh the JWT before expiry, tear down the old private channel, and create a
  fresh authorization. A failure returns to polling only.
- Quota rejection retains the local outbox and reports a stable blocked status.
  Offline reads and new local changes remain available, but no cloud write is
  claimed as synchronized.

## Blob orchestration

Large ciphertext is split into 1–16 parts, each at most 33,554,432 bytes. The
Edge Function returns exact JWT-authenticated Storage paths from a database
reservation; it never returns a signed bearer URL. The client uploads each part
without upsert, finalizes the reservation, and only then pushes an operation
whose signed `BlobRef` commits the storage UUID, digest, and logical byte count.
Download reassembles the finalized object set and validates every part size and
the signed logical digest before exposing bytes to decryption.

## Error and status model

Stable safe classes are: `offline`, `transient`, `auth_required`, `revoked`,
`quota_blocked`, `gap_pending`, `integrity_quarantined`, `conflict`, and
`configuration_error`. Raw provider messages, JWTs, keys, canonical payloads,
ciphertext, and plaintext are never included in UI status or logs.

## Verification strategy

- Fixed cross-platform vectors cover mutation CBOR, operation AAD, ciphertext,
  complete operation bytes/hash, and checkpoint state/hash/signature.
- Unit tests flip every signed or AAD-bound field and prove rejection.
- Deterministic randomized tests run two to five in-memory replicas through
  offline writes, duplicate/reordered/delayed/dropped batches, lost hints,
  crash/reopen points, and conflict resolution; every unblocked replica must
  converge to identical heads, conflicts, and state hashes.
- Vault tests prove atomic record/outbox creation, replay after crash, durable
  cursor semantics, nonce uniqueness, quarantine isolation, and plaintext-canary
  absence from all cells and logs.
- Node tests exercise strict Edge request parsing, canonical CBOR parity,
  database-trusted certificate selection, signature-before-RPC ordering,
  response redaction, and Broadcast-after-commit ordering.
- pgTAP tests exercise exact duplicate acceptance, altered duplicate rejection,
  sequence/hash gaps, revocation races, epoch mismatch, quota boundaries, and
  privilege/owner/search-path invariants.
- Hosted tests use two ephemeral users and devices, upload ciphertext only,
  force polling without Realtime, revoke a session, and roll back/delete every
  fixture. Credential-dependent hosted gates remain explicitly pending when a
  private service credential is unavailable.

## Documented limitations

- A cloud operator can delete, fork, delay, or withhold ciphertext. Clients
  detect integrity violations only relative to locally pinned history.
- A new device without a checkpoint pin cannot prove it received the newest
  valid snapshot.
- A revoked offline device may retain plaintext and historical keys already
  cached locally.
- Task 17 owns pairing, recovery, reassociation, revocation orchestration, epoch
  rotation publication, and fresh-auth deletion gates. Task 16 consumes those
  identities and epochs but does not broaden their APIs.
