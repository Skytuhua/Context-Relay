# Membership transfer and activation implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a newly confirmed device recover all authorized earlier workspace data and activate current keys without accepting a stale or conflicting device history.

**Architecture:** Reuse authenticated membership replay and the existing pairing, rotation, envelope and checkpoint codecs. Persist accepted public history separately from staged secrets; bind ordinary current-key activation to the accepted endpoint, and historical installation to that endpoint and its selected read target. Existing current-write admission stays strict while a separate historical-read path verifies older authority and exact revocation cutoffs.

**Tech Stack:** Rust, existing minicbor/crypto helpers, SQLCipher/rusqlite transactions, existing sync transport and checkpoint verification.

**Spec:** Full release requirements in `docs/verification/v1-master-plan-audit.md` and `docs/verification/pr16-release-continuation-2026-09-08.md`; codec candidate and independent vectors in `docs/protocols/historical-key-transfer-v1.md`. The earlier C/D proposal and review are local at `.codex/pr16-historical-key-transfer-analysis.md` and `.codex/pr16-historical-transfer-contract-review.md`. This plan does not ratify unimplemented proposal details.

## Global constraints

- Apple-related work and anything requiring payment are deferred by the user.
- C is the exact independently confirmed recipient admission successor; D is the locally accepted transfer-authorizing endpoint on C's verified lineage. Neither a downloaded header nor a larger epoch selects D.
- Transfer all historical epochs `1..E_D-1`, including both root and epoch keys; privately verify current epoch E_D separately.
- No new cryptographic dependency, provider-roster trust, implicit V1-to-V2 promotion, or re-pairing of an existing device identity.
- Canonical bytes, signatures, scope, enrollment pin, recipient certificate, budgets and exact endpoints remain mandatory.
- Key inventory completion, historical reconstruction and current-write activation are different facts.
- Preserve existing evidence and Git history. Do not launch the real daemon with no arguments or use `--shutdown` in tests.

## Verified starting point

At `3d92013`, membership replay proves exact C-to-D lineage, retains all authenticated rotation commitments and retains the latest rotation's verified predecessor. Its public state accessor is the accepted endpoint only when the caller independently accepted that endpoint; it is not durable acceptance by itself.

Schema 38 stores rotation-only public evidence indexed by control epoch. Additions preserve that epoch, so this table cannot serve as the complete membership log. Its production append and replay methods currently have test callers only. Schema 39 intentionally stores immutable root-only enrollment evidence; do not reinterpret or update its enrollment-time accepted tip as a live endpoint.

`Vault::trusted_sync_material` still obtains one original enrollment/restore/V1-pairing bundle through `trusted_workspace_material_and_certificates`. Adding historical content-key lookup alone cannot advance this authority or enable historical admission.

## Task 1: Implement and review the historical transfer codec

Files: a focused devices crypto module, its module declaration, focused tests and tracked protocol documentation.

- [x] Require the independently confirmed V2 transcript and exact signed membership successor C, plus verified C-to-D lineage; reject genesis or unrelated-event anchors.
- [x] Implement the reviewed fixed signed header and bounded, recipient-encrypted, hash-linked canonical pages using existing bundle2 and envelope codecs.
- [x] Bind every page to the complete header context; check exact epoch inventory and signed rotation commitments. Epoch 1 has an explicit active-exporter trust requirement and must equal a previously trusted local value when one exists.
- [x] Verify empty inventory, multiple pages, hostile canonical encodings, substitutions, recipient revocation, wrong scope/pin, missing/reordered pages and golden bytes/signatures. Confirmed transcript and lineage do not by themselves prove checkpoint reconstruction or current-key possession.
- [x] Review implementation and protocol vectors before connecting vault or transport callers.

## Task 2: Persist complete accepted membership history

Files: a new migration after the actual latest schema, `vault.rs`, a focused vault membership module, and SQLCipher integration tests. Keep schema 39's historical meaning unchanged.

- [x] Store exact canonical ADD evidence (statement/signature/request/approved payload) and REVOKE evidence (statement/signature/transition), linked by authenticated parent and successor hashes. Use hashes rather than control epoch as event identity because additions preserve epochs.
- [x] Store a separate scope/enrollment-pin-bound locally accepted endpoint. Bootstrap only from authenticated local enrollment completion or the staged confirmed V2 admission path. Never backfill acceptance from arbitrary certificate rows or provider snapshots.
- [x] Reuse complete cryptographic replay before accepting an extension. In an immediate transaction, compare the persisted endpoint with the proof's exact expected parent, persist all required evidence, then advance to the verified endpoint atomically. A stale parent conflicts even if epochs match. Exact retry must match persisted bytes and endpoint; it must not revive an old branch.
- [x] On restart, reauthenticate stored canonical history from its pinned origin to the persisted endpoint under explicit per-call budgets. Bound SQL allocations before loading BLOBs. Missing or damaged evidence leaves authority unavailable, not silently reconstructed from rows.
- [x] Immediately gate all current-material readers and current mutations on agreement with the accepted endpoint. This includes `trusted_workspace_material_and_certificates`, `trusted_sync_material_with_certificates` and already-created owned sync capabilities. Incomplete/corrupt activation must not fall back to original enrollment/restore/V1 material or promote a hosted certificate snapshot. Addition-only advancement may reuse the same keys only after rebuilding authority from the verified new endpoint.
- [x] Test addition-only extension, add/revoke mixtures, competing same-epoch successors, stale and exact retries, scope/pin substitution, corruption, process restart and transaction rollback. Update enrollment/restore empty-vault checks for the new tables.

## Task 3: Persist staged historical secrets and current material

Files: extend the same vault module/migration while unpublished, or add the next migration if already published; focused vault integration tests.

- [x] Retain per-epoch root and content keys inside the encrypted vault with authenticated provenance. Preserve prior keys before rotating; do not derive them from the latest random keys or overwrite earlier epochs.
- [x] Store immutable transfer header/ciphertext identity and selected checkpoint target. Selection CAS must compare both D and the previously selected target hash/revision; same-D concurrent replacements cannot regress the target.
- [x] Commit a verified page's sealed secrets and progress together, comparing transfer identity, D, expected page index and expected hash. Exact retries preserve the original ciphertext and keys.
- [x] Authenticate current material independently: reuse confirmed current material for addition-only descendants or open the latest verified rotation using its retained predecessor. Verify the original plaintext commitment before associating the enrollment pin.
- [x] A known D advance supersedes partial transfer work. Retain verified staging; start a new transfer identity under the new accepted endpoint if the recipient remains active. Never relabel ciphertext or discard previously completed historical installations.
- [x] Test crash/restart at each transaction boundary, conflicting page retries, missing pages, wrong keys/commitments, current-material absence, same-D replacement races and recipient revocation before commit.

Task3 reviewed through `b69dcab`: retained-device intermediate rotations and role-aware durable preservation corrected in two review rounds. Task4 still owns semantic checkpoint frontier domination, reconstruction and activation; Task3 completion covers storage and selection CAS. Legacy-root provenance and dependency warning limits remain recorded in the continuation ledger.

## Task 4: Activate current material and install reconstructed history

Files: `sync/admission.rs`, existing checkpoint/chain verification, vault sync integration, and focused cross-epoch tests.

- [ ] Add a deliberate historical-read admission path using the certificate authorized at the operation's historical state, verified device-chain prefixes, exact signed revocation cutoff hash, and causal dependencies. Preserve all current-write epoch checks.
- [ ] Require every replacement target to dominate previously required frontiers with consistent verified chain prefixes. A signed checkpoint predecessor link or larger scalar sequence is insufficient.
- [ ] Reconstruct the selected target and reproduce its exact state hash. Missing chain/cutoff evidence remains repairable; do not mark historical reads complete merely because keys arrived.
- [ ] Implement ordinary current-rotation activation independently of historical transfer: require the exact accepted endpoint, verified predecessor/transition, privately opened current material and recipient authority in one transaction. Enrolled/root and retained devices need no pairing anchor C or historical-transfer checkpoint for this path. Rebuild sync authority from accepted history, not a mutable active-certificate snapshot.
- [ ] Commit historical transfer installation/completion only when accepted D, target identity, complete historical inventory, reconstructed target and privately authenticated current material still agree in one transaction. This joint gate must not prevent independently valid ordinary current-rotation activation while earlier history is unavailable.
- [ ] Test accepting a revocation, interrupting before activation, restarting and attempting sync/pairing through old material readers and stale owned capabilities; no stale authority may resume.
- [ ] Verify offline joining across rotations, retained children, restart during reconstruction, forks, withheld history, replacement exporter, known revocation and interruption before/after activation.

## Task 5: Connect hosted transport and installed workflows

- [ ] Extend the existing bounded transport and durable retry coordinator for addressed header/page/public-history retrieval and publication. Enforce current server-side identity/recipient authorization independently of cryptographic verification.
- [ ] Integrate create/pair/recover/resume screens and daemon orchestration with honest incomplete/conflict/revoked states. No direct secret material in diagnostics or logs.
- [ ] Complete real login, pairing, sync, restart, recovery and clean-machine Windows acceptance required by the master plan. Respect the prior hosted-deployment policy rejection; do not bypass it. Codec/component tests cannot clear these gates.

Every task needs a failing behavioral check before implementation, focused passing verification, review and updated evidence. None of this replaces the other nondeferred package, harness, security, product or release requirements.
