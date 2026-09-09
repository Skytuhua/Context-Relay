# Production hosted sync integration

Full PR16 release acceptance requires real synchronized records, not an empty
transport cycle or a successful unauthenticated endpoint probe. The hosted schema
and sync Edge Function are deployed; native daemon integration remains open.

Current source: contextd routes SyncRetry to unavailable and status starts offline.
SyncEngine and SupabaseTransport implement the replica protocol, but the native
transport owns a static bearer token. OperationBuilder has no production callers;
OfflineWorkspace/MCP writes must join the signed-operation path before enabling
sync. Preserve fully functional offline-only work when unconfigured.

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
