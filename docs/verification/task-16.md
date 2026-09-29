# Task 16 signed-sync replica-core verification

Date: 2026-08-31

Status: local replica core, concrete Supabase transport, cloud-admission migration, and Edge
boundary are implemented and locally verified. Task 16 is **not hosted-complete**: the migration
has not been applied to a hosted project, credentialed multi-account/device behavior has not been
executed, and daemon wiring awaits the authenticated session/key lifecycle completed by Task 17.

## Exact repository checkpoints

The verified Task 16 history starts from the deterministic-conflict contract and ends at the
clean Task 16.6 base used for this checkpoint:

| Commit | Subject |
| --- | --- |
| `1c27caf` | `docs: define deterministic conflict representative` |
| `d77e6b2` | `feat: admit and merge signed sync operations` |
| `1c4e126` | `fix: harden sync admission and partial merge` |
| `d8190cf` | `fix: bind embeddings to merge representatives` |
| `ef50cf1` | `feat: synchronize through an in-memory ciphertext transport` |
| `b837f51` | `fix: harden sync transport and quarantine poison rows` |
| `e388bcd` | `fix: persist oversized sync rejections` |
| `caeb720` | `feat: add signed sync checkpoints and retry policy` |
| `d296ded` | `fix: bind and resume signed checkpoints safely` |
| `2f795af` | `fix: retire and atomically pin scoped checkpoints` |
| `b3a81da` | `fix: version and extend checkpoint chains safely` |
| `ec8905e` | `fix: prove every checkpoint append before pinning` |
| `a2c7654` | `feat: add signed sync replica core` |

The schema-19 migration-consistency follow-up is carried by the commit containing the latest
version of this ledger, with subject `fix: reconcile legacy sync record owners`. Its final SHA is
recorded in Git and the handoff because a commit cannot embed its own SHA without changing that
SHA. Migration 19 was updated directly because `a2c7654` is local and unpublished; no schema 20
was added.

## Canonical vectors

The SHA-256 values below hash the decoded bytes represented by each `.hex` file.

| Vector | SHA-256 |
| --- | --- |
| `crates/protocol/tests/fixtures/sync-mutation-v1.hex` | `04e1ce4895ae3dc490b7936d7ecb63b02fea212a4361bfc4506fbfa79309ccff` |
| `crates/protocol/tests/fixtures/sync-operation-v1.hex` | `dcc2bc452c5be8b463b31cb7ee3007d3a19dc5013292fd91ab8c80517614bb1d` |
| `crates/protocol/tests/fixtures/sync-operation-signing-preimage-v1.hex` | `2296851ec7e26897c7a4282e436d8585eb4331aedc747316f60110c1314009cf` |
| `crates/protocol/tests/fixtures/checkpoint-v1.hex` | `aae1dcfb4f2e4a56251218c6f24019eed3545f515bcb66ba874f1cc2a02e99ac` |
| `crates/protocol/tests/fixtures/checkpoint-signing-preimage-v1.hex` | `82a027960bf6f821079eba6206327f9c396e381bb0d4c494e7335f0b7148dfd5` |
| `crates/core/tests/fixtures/signed-sync-operation-v1.hex` | `d4af94e56f0aab319e4e535b80df6b71865b7303a14c285895fa2808e3af1290` |
| `crates/core/tests/fixtures/checkpoint-schema17-v1.hex` | `d3aa5c0c389ab2404942987b1262166fb8243d0d0ef81c6822d5d49b35da6163` |

`runtime-contracts-v1.json` now records the current checkpoint schema-2 byte and signing-preimage
hashes. The desktop parity test was RED at both stale Task 16.6 hashes, then GREEN after only those
two metadata values were corrected.

## Randomized convergence evidence

- Generator: fixed in-test `XorShift64`; no `rand` dependency.
- Seeds: every integer in `0..256` (256 deterministic seeds).
- Replicas: xorshift-selected 2–5 real SQLCipher Vaults per seed.
- Bound: 10,000 permitted high-level actions; exactly 16 executed per seed (13 mandatory coverage
  actions plus 3 xorshift-selected actions). A tombstone may establish a prerequisite signed
  upsert, but does not increment the high-level action count.
- Every seed covers upsert, tombstone, concurrent update, disconnect/reconnect, duplicate pull,
  delayed pull, dropped pull, reverse delivery, lost hint, and crash/reopen.
- After clearing faults and reconnecting every replica, `sync_until_idle` requires two quiet
  rounds within 128 rounds. It proves equal canonical state hashes, exact frontiers, canonically
  ordered conflict pairs, and empty outboxes.
- The explicit adversarial chain uses a valid, signed sequence-2 operation with a deliberately
  incorrect prior canonical hash. Two observers durably record the identical singleton safe
  reason `integrity_quarantined`, retain it after reopen, and never claim convergence.

The original Task 16.7 checkpoint passed 9/9 tests. After the schema-19 consistency follow-up and
review-driven typed coverage, the fresh final run passed 16/16 in 180.89 seconds, including all
256 seeds and every focused regression described below.

## TDD regressions and fixes

1. The initial 28-line e2e scaffold failed to compile with nine missing scenario/helper symbols.
   Helpers were implemented only after this RED.
2. Seed 0 exposed local causal successors retaining the previous record head. Focused RED:
   two heads instead of one. Outgoing commit now requires causal succession of every current head,
   atomically replaces heads, and clears resolved conflict state.
3. Seed 13 exposed a valid causal tombstone being quarantined after a concurrent tombstone removed
   materialization. Focused RED: one quarantine instead of zero. Tombstone admission can now derive
   strict record scope from durable same-workspace heads when no live row remains.
4. Review found the broken-chain scenario corrupted bytes rather than testing a signed link.
   Focused RED failed the old two-quarantine assumption; the corrected valid signed bad link now
   produces the same stable `integrity_quarantined` reason on every observer.
5. Security review found that a signed operation in scope B could reuse a scope-A materialized UUID.
   Focused RED admitted the foreign upsert. Schema 19 now persists immutable record ownership as
   `(record_id, account_id, workspace_id, record_kind)` and backfills unambiguous signed heads.
   Admission rejects a foreign upsert or tombstone before key lookup/materialized scope access, and
   transactional outgoing/apply guards preserve the boundary.
6. Security re-review found that a direct offline Vault row had no signed head and was still
   claimable. Focused RED admitted a foreign upsert over a directly written Memory. Existing
   ownerless materialization now fails closed; the narrow explicit binding API requires exactly one
   matching materialized kind, is exact/idempotent, and permits only the selected scope. Owner rows
   survive tombstones. A migration regression proves unambiguous backfill and collision rollback.
7. Correctness re-review found a `record_id`-only head scan would be quadratic and then found the
   schema bump broke migration tests hard-coded to version 18. Moving authority to the schema-19
   primary-key owner table removes the hot scan, and migration tests now use
   `LATEST_SCHEMA_VERSION` while explicitly dropping later tables before downgrade fixtures.
8. Migration-consistency review found that schema 18 could contain a signed durable head followed
   by a newer direct local materialization with the same record ID. Treating the migrated head as
   final ownership let a later signed upsert or tombstone replace that newer row. The focused RED
   was inherited as a runtime reproduction; the first local RED run of the complete follow-up
   matrix then failed compilation with two E0425 errors because
   `legacy_owner_matches_materialization` did not exist.
9. Schema 19 now distinguishes fresh/exact `verified` owners from migrated `legacy_pending`
   candidates. Admission and apply decrypt the operation-ID-sorted durable representative through
   `TrustedSyncMaterial`, validate every head's owner and kind, and require exact typed equality to
   the current materialization or complete absence for a tombstone. Apply repeats the check and
   promotes in the same transaction as materialization; a forced post-promotion apply error proves
   rollback leaves the owner pending.
10. Focused GREEN covers mismatch blocking, matching upsert promotion, matching and mismatching
    tombstone representatives, deterministic multi-head promotion, explicit reconciliation,
    outgoing non-promotion, verified-owner immutability, and migration collision rollback. A
    compact review-driven loop additionally proves matching promotion and changed-materialization
    rejection for MemoryCandidate, Task, SecretRef, Instruction, Component, and Project.

Seed 2 was also minimized and classified as harness invalidity: the generator attempted a tombstone
without local materialization. The generator now establishes a signed upsert prerequisite; no
production change was made for that trace.

## Plaintext-canary evidence

Every randomized and adversarial scenario embeds
`TASK_16_PLAINTEXT_CANARY_DO_NOT_LEAK` in mutation plaintext. Before evidence collection each Vault
performs a full WAL checkpoint. The test scans raw SQLCipher database, `-wal`, and `-shm` bytes for
every replica, every captured provider ingress/egress envelope and checkpoint, and every
harness-captured safe log string. No scan contains the canary. No plaintext, key, nonce secret,
credential, or private signing material is written to this ledger.

## Historical Task 16.7 local gates

| Gate | Result |
| --- | --- |
| `cargo test -p context-relay-protocol --all-features` | Green: 93 integration tests, zero failures; unit/doc targets also green. |
| Focused Task 16 core suites | Green: 118/118 (crypto 4, admission 7, backoff 4, checkpoint 8, engine 43, merge 11, operation 9, sync Vault 14, Vault storage 18). |
| `cargo test -p context-relay-core --features test-support --test signed_sync_e2e_v1` | Green: 16/16 in 180.89 seconds; 256/256 randomized seeds. |
| `cargo fmt --all -- --check` | Green. |
| `cargo check --workspace --all-targets --all-features` | Green (5.79 seconds). |
| `cargo check --workspace --all-targets` | Inherited gate defect reproduced in 5.96 seconds: `sync_vault_v1` calls `with_nonce_for_test` and `test_plaintext_cells` without enabling `test-support`. |
| `cargo test --workspace` | Same inherited feature-gating compile failure in `sync_vault_v1`; a final `--no-run` reproduction took 26.57 seconds. |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | Inherited lint blockers reproduced in 5.47 seconds: `AdmissionDecision` (`large_enum_variant`) and `OperationBuilder::build` (`too_many_arguments`). Task-owned e2e Clippy is green with only those two inherited warnings allowed (0.61 seconds); the core all-feature library is likewise green (6.45 seconds). |
| `pnpm lint` / `pnpm typecheck` | Green (1.82 / 1.67 seconds). |
| `pnpm test --run` | Green: 28/28 after checkpoint vector metadata RED→GREEN (2.03 seconds). |
| `pnpm build` | Green: 33 modules built (1.22 seconds). |
| `pnpm check:bindings` / `pnpm check:schemas` / `pnpm license:check` | Green (1.24 / 0.85 / 0.35 seconds). |
| `cargo clippy -p context-relay-core --lib --features test-support -- -D warnings -A clippy::large-enum-variant -A clippy::too-many-arguments` | Green. |
| `cargo clippy -p context-relay-core --features test-support --test signed_sync_e2e_v1 -- -D warnings -A clippy::large-enum-variant -A clippy::too-many-arguments` | Green. |
| `git diff --check` | Green. |

These are preserved historical Task 16.7 results, not the current branch state. The recorded
feature-gating and strict-Clippy blockers were repaired during PR stabilization (including the
boxed admission payload and typed operation request); current recovery-pass gates are recorded
below.

## Independent review

- Correctness review: earlier Important findings on malformed-byte chain coverage, a proposed
  unindexed hot-path lookup, and hard-coded schema-18 tests were each validated and fixed. The
  consistency follow-up review found no Critical or Important issue, suggested typed/tombstone
  coverage, and the final re-review after that coverage reported no finding at any severity;
  Ready: yes.
- Security review: earlier Important cross-scope UUID collisions for both signed-head and
  direct-offline rows were validated and fixed with durable owners, explicit binding, and
  defense-in-depth transactional guards. The consistency follow-up review and final re-review
  reported no finding at any severity; Ready: yes.
- No Critical finding was reported in any review pass.

## Recovery completion: concrete Supabase transport and admission boundary

The 2026-08-31 recovery pass added the concrete daemon-side transport implementation and the
hosted boundary without changing `SyncTransport` or exposing a renderer-facing API:

- `SupabaseTransport` pushes signed opaque operations in bounded chunks with stable
  idempotency, pulls stable cursor pages and exact hash ranges, and pushes/pulls checkpoint-v2
  rows. It reconstructs canonical bytes from Data API rows and verifies `canonical_sha256` before
  returning data to the replica core.
- Provider responses and failures are converted to bounded sanitized receipts/errors. Access
  tokens and API keys are zeroized and excluded from `Debug`; temporary authorization-header
  copies are zeroized on drop. The credential-observing custom HTTP seam is available only under
  `test-support`, and no transport credential is accepted from the renderer.
- Retry uses the existing sealed exponential-backoff policy with full jitter and an injectable
  test-only runtime. Operation batches remain below the Edge 8 MiB request limit.
- The `sync` Edge boundary verifies the platform JWT through `getClaims`, derives account/device
  ownership from the verified subject and session, bounds streaming input before authentication,
  verifies canonical CBOR, certificate chains, epochs, prior hashes, and Ed25519 signatures before
  append, and emits only a post-commit opaque private-Realtime hint.
- Migration `20260810070712_signed_sync_cloud_admission.sql` adds service-only operation,
  checkpoint, blob-ticket, and hint boundaries. Every mutation serializes on the account row and
  revalidates the session after acquiring that lock, closing the concurrent-revocation stale-write
  race. The identity resolvers are `VOLATILE`, so PostgreSQL takes fresh snapshots rather than
  reusing the calling query's pre-lock `STABLE` snapshot. Checkpoint continuity selects the unique
  unreferenced chain tip rather than relying on timestamp uniqueness, and fails closed on missing or
  branched tips. Checkpoint pagination has an index matching
  `(account_id, workspace_id, schema_version, received_at, canonical_sha256)`.
- Blob reservations use conflict-safe insertion and derive exact Storage ownership from the
  verified session. Operation/checkpoint insertion timestamps are assigned after account
  serialization so a committed row cannot fall behind a previously issued pull cursor.
- Duplicate operation identifiers within one request are rejected before hosted mutation, avoiding
  a committed append followed by a receipt-validation failure.
- A focused Codex Security diff scan found that a 256-row Data API request could exceed the fixed
  20 MiB response cap with only three valid maximum-size ciphertext rows. The transport now treats
  the cap as a distinct signal, halves normal operation pages, and retries range repair in bounded
  subranges without weakening the cap or losing exact ordered-range semantics. Both paths have
  RED/GREEN regressions; the sealed pre-fix report is retained outside the repository as scan
  `5f81c78e-ef6e-4600-84bb-cbb5a874e3ef`.

### Recovery-pass local evidence

| Gate | Result |
| --- | --- |
| `cargo test -p context-relay-core --test supabase_sync_transport_v1 --all-features` | Green: 9/9 transport contracts, including authenticated opaque push, stable idempotency/retry, adaptive byte-safe pull/range reconstruction, checkpoint-v2, strict UTC cursor parsing, canonical-hash rejection, pagination, and sanitized errors. |
| Task 16 Edge/admission/workflow/Rust-boundary Node suites | Green: 42/42. Covers pre-auth size limits, strict ownership-free request JSON, signature/certificate/epoch validation, duplicate request identifiers, receipt injection, checkpoint append/tip continuity, blob reserve/finalize/release, post-lock fresh-snapshot revocation, private hints, the temporary table-owner migration-role lifecycle, the test-only credential-observing seam, workflow pinning, and database contract text. |
| `node scripts/check-supabase-contract.mjs` | Green against the complete local migration/fixture/config set. |
| Strict core all-target/all-feature Clippy | Green after the recovery transport changes. |
| `git diff --check` | Green. |

The SQL test plan was extended to 518 assertions, including the private locked identity helper,
fresh-snapshot resolver volatility, checkpoint cursor/tip indexes, and ownership/privilege
contracts. It is implemented but **not executed locally** because this host
has no Docker/Postgres service; static Node contract checks are not a substitute for pgTAP.

## Remaining hosted and credential-dependent work

Task 16 is implemented locally but remains **partial** until the following evidence is collected:

- apply the migration to an explicitly approved hosted Supabase project and run the 518-assertion
  pgTAP suite plus database advisors;
- exercise live RLS/Auth identity, JWT expiry, concurrent revocation, quota, private Storage, and
  private Realtime behavior with at least two accounts and multiple devices;
- verify multi-device upload/pull/range repair, checkpoint retention/freshness, reconnect, and
  provider-outage behavior against the hosted service;
- connect `SupabaseTransport` to `contextd` only after Task 17 supplies a trusted authenticated
  session and device key/certificate lifecycle. The current daemon correctly remains offline and
  does not accept environment- or renderer-supplied transport credentials;
- collect hosted logs/advisors and repeat the plaintext-canary scan across the real provider and
  credential boundary.

No hosted project was selected, linked, created, migrated, or otherwise mutated by this recovery
pass, and no private credential was requested or recorded.
