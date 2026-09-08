# Hosted Pairing Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task by task. Keep the full release goal open until live acceptance is recorded.

**Goal:** Complete the production provider and daemon path for existing-device pairing, including restart, exact retries and human safety-number confirmation.

**Architecture:** Extend the existing `PairingCoordinator`, transport traits and encrypted Vault records. Use the existing hosted Auth owner and HTTP boundary for credentials, and service-only Supabase transactions for admission. Preserve the canonical pairing request, approved payload and safety transcript.

**Tech Stack:** Rust, SQLCipher, existing reqwest client, Supabase PostgreSQL and Edge JavaScript.

**Spec:** [Existing-device pairing design](../specs/2026-08-09-device-pairing-design.md). This plan implements its deferred hosted adapter; it does not replace the signed protocol.

## Constraints and inspected gaps

- Ten Crockford characters, exactly 600,000 ms lifetime, five failed lookups per authenticated joining session. Codes locate requests; they never authorize trust.
- Request, grant and approved-payload limits remain 8 KiB, 16 KiB and 32 KiB. Reject noncanonical input and unknown fields before mutation.
- The complete 80-bit safety number remains mandatory before local grant decryption or trust installation.
- Auth user/session must come from verified credentials. Bind durable local attempts to their original project/user/session; changed login cannot adopt prepared work.
- Server expiry uses server time, rechecked after locks. Client time cannot extend an invite or cause a provider receipt to be mistaken for a local timestamp.
- No raw code, token, private key or decrypted grant in logs, provider rows or renderer status.
- `crates/core/src/devices/transport.rs` already defines the required join and approval operations; the only current provider is `memory_transport.rs`.
- `crates/contextd/src/pairing.rs` currently assumes a fixed scope and issuer certificate. A fresh joining device has neither; production wiring must not manufacture approval authority for it.
- `public.pairing_requests` requires a request payload and keys at insertion. It cannot represent an empty invite as currently defined. Add a private invite/session record; retain the public request table for submitted requests rather than inserting fabricated placeholders.

## Task 1: Verified hosted wire contracts

**Files:** `crates/core/src/devices/crypto.rs`, existing protocol pairing fixtures, `supabase/functions/enrollment/crypto.mjs`, new `supabase/functions/pairing/crypto.mjs` and its Node tests.

- [x] Freeze independent Rust/Edge vectors for canonical request and approved-payload validation. Reuse existing canonical readers and strict Ed25519/key checks.
- [x] Verify every request field and signature; verify the approval's issuer/child certificate, request digest, scope, epochs and encrypted grant without exposing its plaintext.
- [x] Define operation-specific device proofs binding verified Auth user/session and exact operation bytes. An approval signature alone must not bind a copied request to another session. Verify against the server-selected installed device key, never a caller-selected authority.
- [x] Exercise malformed encoding, oversized input, wrong keys, wrong session, substituted issuer and changed exact-retry bytes. Run Node checks and the corresponding Rust vectors, then review the immutable patch.

## Task 2: Atomic provider admission

Task 1 progress: `supabase/functions/pairing/crypto.mjs` now structurally decodes
and verifies the existing signed request using shared canonical/key validators.
The Node test matches the frozen Rust signing preimage and exercises valid
signatures, tampering, malformed encoding and noncontributory wrapping keys.
The approval verifier now checks the canonical nested grant and genesis/child
certificates against the exact signed request and server-selected root, issuer,
scope and epochs. A Rust-generated public approval fixture is checked by both
implementations. All 13 Rust pairing crypto tests and 68 affected Node checks
pass. Request/approval possession-proof helpers now bind the original Auth
user/session and exact payload under separate signing domains (14 Rust and 69
affected Node checks pass). Frozen request and approval proof signatures are
reproduced by Rust and verified at the Edge (70 Node checks pass). Endpoint enforcement
remains required; these helpers do not authorize admission or prove ciphertext
integrity. The joining
device still authenticates the complete approval through the safety number and
decrypts the grant before installing local trust. This is not live pairing evidence.

**Files:** new migration under `supabase/migrations/`, new `supabase/tests/0003_hosted_pairing_test.sql`, new `supabase/functions/pairing/{core,adapter}.mjs` and tests, `index.ts`, `supabase/config.toml`.

- [ ] Add bounded private invites and failed-attempt accounting using existing ownership/role patterns. Generate 50 random locator bits; store only a peppered HMAC. Define expiry and cleanup without resetting exhausted live sessions.
- [ ] Implement create/status/resolve/request/decision/result/cancel. Resolve scope from active server bindings. Reject inactive accounts, revoked issuers and foreign users/sessions; retain exact original session binding for retries.
- [ ] Lock and recheck live Auth, account/device authority, expiry and epoch after waits. Atomically store the reviewed decision, child certificate and original joining-session binding. Exact retries return the original receipt and never reactivate revoked trust.
- [ ] Ensure anonymous/authenticated SQL callers cannot bypass Edge verification. Verify approved payload before invoking the privileged commit.
- [ ] Test two-user isolation, concurrent guesses, fifth failure, exact expiry, competing decisions, changed payload, post-lock logout/revocation/rotation and response loss. Run the disposable SQL harness and Edge tests before deployment.

## Task 3: Native transport and durable identity binding

**Files:** new `crates/core/src/devices/supabase_pairing.rs`, `devices/mod.rs`, existing Vault pairing persistence, new hosted transport integration test.

- [x] Implement existing `PairingJoinTransport` and `PairingApprovalTransport` using the Auth/HTTP patterns in `supabase_enrollment.rs`. Validate exact response fields, lengths, IDs, digests and states; preserve safe errors and credential cancellation.
- [x] Persist the original hosted identity before first request/decision preparation. Reopen must reuse the exact signed request and approval; do not adopt an unbound historical prepared row.
- [ ] Keep fresh joining and active approving authority distinct. Derive installed keys from the existing protected device identity.
- [ ] Test lost responses, restart, expired/replaced sessions, malicious response projections and provider/local clock skew. Run targeted core tests with `test-support` and Clippy.

## Task 4: Production daemon integration

Task 3 persistence foundation: Vault schema 32 now provides immutable per-pairing
project/user/session/role bindings. Exact retries retain the original identity;
existing unbound requests, decisions and approval transcripts cannot acquire
a new login. Native transports now supply this identity to the coordinator, which
stores/checks it before preparing or resuming signed work. Native approval proofs
use the durable signed request rather than requiring a new server read. Production
daemon integration is implemented; broader failure-path qualification remains unfinished.

Integration findings: use the daemon-owned protected keys and current Auth owner
at the existing production recovery-service initialization. A fresh joiner has
no scope or issuer certificate; the coordinator service now supports that role.
Reconcile one requested prepared approval through `resume_prepared_decision`
instead of replaying unrelated sessions. Startup must remain local while Auth
restores, as it does for recovery. Schema 33 now saves immutable public request
reviews with the original provider timestamp and scope before preparing a
decision. Accepted status and approval retries use that review without a fresh
provider lookup, preserving certificate/epoch validation. Legacy decisions
without a saved review still need the existing provider lookup; migration must
not invent their original timestamps. The production wrapper now builds clients
from the daemon Auth owner and protected identity. Saved IDs retain their original
project/user/session/role; provider calls require the current matching session,
while local terminal paths can use the saved identity after logout. Startup only
validates pending local transcripts, and an explicit status request reconciles
its own prepared approval. Active matching recovery-root certificates and local
material establish approval authority; fresh joiners have no approval client.
Two-device hosted approval/confirmation and terminal-after-logout qualification
remain required before completing the integration checklist below.

**Files:** `crates/contextd/src/pairing.rs`, `lib.rs`, existing hosted Auth service and pairing daemon tests.

- [ ] Wire the hosted service into the existing ordered Vault worker. Fresh joiners can join/check/confirm without a preexisting scope or issuer; approval operations require verified active material.
- [ ] Preserve local-only completed status and exact prepared resume. Reconcile logout/account replacement before every queued provider operation.
- [ ] Keep existing desktop request/approval/safety surfaces. Change renderer code only if a verified protocol gap requires it.
- [ ] Exercise two daemon/Vault instances through authenticated IPC, provider response loss, restart and complete human confirmation; check secret canaries and all role restrictions.

## Task 5: Live qualification

- [ ] After the pending OAuth configuration is resolved, deploy reviewed migrations/functions and prove two real sessions on installed Windows/macOS devices.
- [ ] Record invite, approval/rejection/cancel, restart on both sides, wrong/full safety number, lost response, logout and revoked-device denial.
- [ ] Verify signed sync accepts only the resulting authorized device binding; complete the separate sync/lifecycle gates as well.
- [ ] Update the master audit and release ledger with exact head, machines and execution evidence. Component tests do not qualify this task or the full release.

No production deployment or live pairing acceptance is implied by this plan. Signing, clean-machine matrices, package workflows and all other PR #16 release requirements remain required.
