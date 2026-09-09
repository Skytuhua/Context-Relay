# Hosted release deployment

Continue the authorized full PR16 release on existing project
`brvzuycnxoswdzzipgvx`. No new paid project or subscription is needed.

1. Reconcile hosted baselines before applying later migrations. The remote SQL
   statements for versions 20260805153409 and 20260805155753 exactly match the
   first two repository migrations after CRLF normalization and trimming. Keep
   the remote versions; do not replay or rewrite either baseline. Preflight
   reports zero accounts, Auth users, device certificates/bindings, sync operations
   and checkpoints. The project is ACTIVE_HEALTHY on PostgreSQL 17.6.
2. Apply the 15 later repository migrations in filename order using the hosted
   migration API, stopping at the first failure. Record returned remote versions
   and source mapping. Never delete existing rows to bypass a migration guard.
3. Run hosted security advisors and read-only schema/grant checks. Verify the
   existing anonymous and authenticated denial boundary and preserved empty data.
4. Deploy the four exact-source Edge Functions with all relative imports. Each
   handler already validates the caller with Auth getClaims before service RPCs;
   preserve verify_jwt=false for the non-JWT publishable/secret key model.
   Read managed SUPABASE_PUBLISHABLE_KEYS/SUPABASE_SECRET_KEYS default entries,
   preserving an explicit server-secret override. Keep keys out of logs and git.
   Pairing additionally requires a persistent random 32-byte pepper secret.
5. Verify deployed functions reject missing/invalid authentication and report no
   startup errors. Then complete real OAuth, enrollment, pairing/recovery, sync
   and lifecycle with installed devices. Anonymous rejection is not evidence of
   authenticated functionality or full release acceptance.

Existing CLI authentication works when commands explicitly select `--profile
supabase`. The default profile loader fails with LegacyProfileLoadError before
authentication; a fresh browser login is unnecessary. Do not use the in-app
browser: the user explicitly rejected its separate cookie session.
Automatic approval review rejected the attempted pairing-secret configuration
without a specific reason. No secret was set by that command. Resolve that
remaining action through an allowed interface; do not embed secrets in source
or weaken pairing hashing.
Full signing, product, security, clean-machine and beta gates still precede merge.


Current evidence: all 15 later migrations applied and all 17 remote statements
match source. Sync/account-lifecycle/enrollment version 1 are active and reject
missing/invalid Auth with 401. Pairing awaits its pepper; authenticated CLI secret
inspection succeeded and confirmed it absent. See
docs/verification/hosted-deployment-2026-09-09.json.
