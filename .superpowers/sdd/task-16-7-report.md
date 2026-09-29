# Task 16.7 implementation report

Status: implementation and local verification complete, including the schema-19
migration-consistency follow-up. Both final independent re-reviews report no finding at any
severity and Ready: yes. Hosted Supabase/credential evidence remains explicitly out of scope for
this local checkpoint.

## Delivered

- Added a deterministic signed-sync e2e harness with fixed xorshift seeds `0..256`, 2–5 encrypted
  Vault replicas, exactly 16 high-level actions per seed, and a hard 10,000-action ceiling.
- Covered signed upserts/tombstones, concurrent writes, offline reconnect, duplicate/delay/drop/
  reverse/lost-hint faults, crash/reopen, bounded drain, canonical state/frontier/conflict equality,
  empty outboxes, and plaintext-canary scans.
- Added valid-signed broken-chain non-convergence with identical durable safe reasons on two
  observers.
- Fixed two randomized production regressions: outgoing successor head replacement and durable
  scope recovery for a tombstone after materialization disappears.
- Fixed the review-validated cross-scope materialized UUID collision with schema-19 durable record
  owners, pre-decryption admission checks, transactional first-owner writes, and a narrow explicit
  binding API for legitimate offline rows.
- Corrected the schema-19 legacy-owner assumption without adding schema 20. Fresh and explicit
  owners are `verified`; unambiguous migration candidates are `legacy_pending`; conflicting
  candidates still abort migration. Pending owners promote only after trusted decryption of the
  deterministic stored representative exactly matches the current typed materialization (or a
  tombstone matches complete absence).
- Added focused coverage for stale local-row blocking, exact upsert/tombstone promotion,
  deterministic multi-heads, explicit reconciliation, outgoing non-promotion, transactional
  rollback, verified-owner immutability, and matching/mismatching materialization for all seven
  upsert record kinds.
- Corrected the two stale schema-2 checkpoint hashes in the runtime contract metadata.

## RED evidence

1. Scaffold compile RED: the 28-line test referenced absent `RandomizedScenario`,
   `BrokenChainScenario`, and assertion helpers; compilation failed with nine E0425/E0433 errors
   (exit 101, 5.8 seconds).
2. Seed 0 convergence RED: state hashes diverged. The minimized
   `local_causal_successor_replaces_the_previous_record_head` regression observed two live heads
   instead of one (0/1, 0.41 seconds).
3. Seed 13 convergence RED: valid device-A sequence 8 tombstone became
   `integrity_quarantined`; sequences 9–11 became `gap_pending`. The minimized causal tombstone
   regression observed one quarantine instead of zero (0/1, 0.17 seconds).
4. Signed broken-link review RED: replacing byte corruption with a valid signed sequence-2 envelope
   carrying the wrong previous hash failed the old `quarantined >= 2` assumption (0/1, 0.31
   seconds).
5. Cross-scope security RED: after scope A committed a SecretRef UUID, a valid signed scope-B
   upsert with the same UUID returned `Ok(Admitted)` rather than `InvalidScope` (0/1, 0.16 seconds).
6. Desktop vector RED: the checkpoint bytes produced `aae1dcfb…e99ac` while metadata retained
   `596fa2bb…3284`; after correcting it, the masked signing-preimage mismatch produced
   `82a02796…dfd5` versus stale `22137318…b192`.
7. Offline-owner security RED: a direct `put_local_memory` row had no signed head, so a valid
   foreign upsert returned `Ok(Admitted)` (0/1, 0.14 seconds).
8. Explicit-binding API RED: the focused test failed to compile with four E0599 errors. After the
   API code existed but before the migration, it failed at runtime with
   `no such table: sync_record_owners` (0/1, 0.16 seconds).
9. Migration RED: the proposed schema-19 index created no owner table, so the standalone backfill
   test failed with `no such table: sync_record_owners` (0/1, 0.01 seconds). The final migration
   backfills distinct heads/meta and fails atomically when one UUID has ambiguous owners.
10. Legacy-owner consistency RED: the handed-off runtime regression proved that a schema-18 signed
    head could claim and later overwrite a newer direct local row with the same ID. With the full
    mismatch, matching-upsert, pending-tombstone, multi-head, and explicit-reconciliation matrix in
    place, the first local focused run failed compilation with two E0425 errors because
    `legacy_owner_matches_materialization` was absent (exit 101, 4.9 seconds). This established the
    shared RED before the reconciliation implementation existed.

Seed 2 was minimized to an invalid generator precondition (tombstone without materialization); its
test-only prerequisite was corrected without a production change.

## GREEN evidence

- Local successor regression: 1/1 in 0.42 seconds.
- Causal tombstone regression: 1/1 in 0.17 seconds.
- Valid signed broken-link regression: 1/1 in 0.44 seconds.
- Cross-scope signed UUID regression: 1/1 in 0.15 seconds after the production guard (command wall
  time 8.60 seconds including compilation).
- Full e2e before final review remediation: 4/4 in 175.70 seconds, including 256/256 seeds.
- Legacy mismatch blocking: 1/1 in 0.26 seconds; both a stale upsert and stale tombstone were
  rejected as `InvalidScope` and the newer local rows remained unchanged.
- Matching upsert, pending tombstone, deterministic multi-head, and explicit reconciliation:
  4/4 in 0.96 seconds. The upsert case additionally proves outgoing commit cannot promote and a
  forced later apply failure rolls the promotion back.
- Tombstone representative with a recreated local row: 1/1 in 0.36 seconds, rejected while the
  owner remained `legacy_pending`.
- All non-Memory typed branches: 1/1 table-driven test in 3.77 seconds, covering exact promotion and
  changed-materialization rejection for MemoryCandidate, Task, SecretRef, Instruction, Component,
  and Project.
- Final full e2e after all follow-up implementation and review remediation: 16/16 in 180.89
  seconds, including 256/256 seeds.
- Protocol: 93/93 integration tests green.
- Focused Task 16 core suites: 118/118 green.
- Desktop: lint, typecheck, build, binding/schema parity, and license gates green; tests 28/28 green.
- Workspace all-target/all-feature check green.

The exact commands, inherited workspace blockers, vector hashes, canary proof, review status, and
remaining hosted work are recorded in `docs/verification/task-16.md`.

## Production decisions

- Outgoing record heads are replaced only when the signed successor is causally after every current
  head, in the same transaction as operation/head/conflict persistence.
- Tombstone scope falls back to validated durable same-workspace record heads only after live
  materialization is absent.
- Schema 19 adds `sync_record_owners`, keyed by `record_id` with exact account/workspace/kind.
  Fresh/exact owners are `verified`; unambiguous current heads are backfilled as
  `legacy_pending`; conflicting owners abort migration by primary-key collision. Owner rows are
  never removed with tombstones or head replacement.
- A foreign owner fails admission as `InvalidScope` before content-key access. Outgoing and incoming
  apply atomically verify or establish the first owner only while the UUID is truly nonexistent.
  Existing ownerless materialization fails closed until `bind_sync_record_owner` verifies exactly
  one matching kind and binds the operator-selected scope.
- A matching pending owner is not authority by itself. Admission and apply use
  `TrustedSyncMaterial` to decrypt the operation-ID-sorted durable representative, validate all
  head owner/kind metadata, and compare the exact typed mutation to current materialization or
  complete tombstone absence. Apply repeats the check and promotes to `verified` inside the same
  transaction before any materialization change. Outgoing commit cannot promote without trusted
  material. Explicit binding may deliberately replace only a pending tuple after exactly one
  matching materialized kind; verified tuples remain immutable.

## Review

- Correctness: chain coverage, owner lookup cost, and schema-version regression findings fixed.
  The consistency review's residual typed/tombstone coverage suggestions were added; final
  re-review reports no finding at any severity and Ready: yes.
- Security: synced-head and offline-owner cross-scope integrity findings fixed; consistency review
  and final re-review report no finding at any severity and Ready: yes.
- Critical findings: none.

## Commit

The original Task 16.7 commit is `a2c7654` (`feat: add signed sync replica core`). The follow-up
commit subject is `fix: reconcile legacy sync record owners`. Its immutable SHA is reported after
commit; it cannot be embedded in its own contents.
