# Production hosted sync integration

Full PR16 release acceptance requires real synchronized records, not an empty
transport cycle or a successful unauthenticated endpoint probe. The hosted schema
and sync Edge Function are deployed; native daemon integration remains open.

Current source: contextd routes SyncRetry to unavailable and status starts offline.
SyncEngine and SupabaseTransport implement the replica protocol. The native
transport now supports original-session guards and refreshed bearer tokens.
OfflineWorkspace can sign memory create/update/archive, MCP proposal creation,
and task upsert/transition/completion with an explicitly configured identity, including
native-hook task evidence. Original request receipts join the existing atomic
Vault record/operation/outbox transaction. The daemon does not yet configure this path.
Other record kinds, trust material and complete mutation routing remain required
before enabling sync. Unconfigured offline-only work remains functional.

1. Bind every native sync HTTP attempt and response to the current original Auth
   generation/identity and configured project, including retries and response-size
   failures. A valid refresh supplies the new bearer without changing request
   bytes/idempotency. Logout/replacement cancels the cycle before applying results.
2. Derive installed scope, content keys and certificate authority from verified
   enrollment/recovery/pairing evidence. Build TrustedSyncMaterial with anchored
   certificate verification; never trust raw certificate rows or provider claims.
3. Connect configured local mutations across desktop/MCP/native-hook callers to
   existing OperationBuilder and Vault atomic record/operation/outbox persistence.
   Cover every synchronized record kind, tombstones, existing offline records,
   exact replay and rollback. Do not upload local plaintext or key material.
4. Connect bounded cycles and explicit retry to daemon-owned services/status,
   preserving the ordered Vault boundary and responsive offline operations.
   Reuse existing due-outbox/backoff/cursor/quarantine/checkpoint APIs. Do not
   report synced while unsigned local work or blocked/quarantined rows remain.
5. Verify two installed devices: local edit, offline edit, restart/retry,
   concurrent merge, deletion, scope isolation, revoke/rotate and account switch.
   Include original session cancellation during requests, exact outbox receipts
   and real hosted Auth/Storage/Realtime behavior. These gates remain independent
   of component tests and the three deployed anonymous-denial probes.

Begin with the native session guard, then trace each mutation transaction before
choosing its integration point. No new provider, schema replacement or alternate
Vault writer is implied by this plan. Signing/clean-machine/product/security/beta
requirements remain prerequisites for merge.

Fresh MCP proposals now derive a separate memory ID from their candidate ID;
saved response replay also accepts the original shared-ID format. Native-import
proposals still use shared IDs, and existing candidates retain their saved IDs.
The sync owner table binds each record ID to a single record kind, so legacy
candidate synchronization still needs explicit reconciliation. Preserve that
ownership check. CandidateReviewParams now has a dedicated durable operation-ID
binding, including exact replay and changed-request rejection. Schema 35 preserves
existing receipts while adding the candidate_review kind. Acceptance updates
candidate, memory and receipt in one transaction; retain that atomic boundary
when signing both mutations. Signed approval itself remains unfinished.
