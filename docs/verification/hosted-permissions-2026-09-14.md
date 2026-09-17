# Hosted configuration and permissions — 2026-09-14

This is a read-only control-plane and catalog snapshot for Supabase project
`brvzuycnxoswdzzipgvx` (Context Relay), observed September14 in Taipei. Existing
authenticated access worked. No deployment, migration, policy, user account,
application row or secret value was changed or read by these checks.

| Check | Observed result | Limit |
| --- | --- | --- |
| Project | ACTIVE_HEALTHY; PostgreSQL17.6.1.155 | Does not prove user workflows work. |
| Edge Functions | Only active version1 sync, enrollment, account-lifecycle | Pairing is absent from the complete list. Function bodies were not retrieved. |
| Migrations | 17 rows, ending20260909021501/prune_expired_pairing | Stored SQL was not compared with repository files in this check. |
| Security advisor | 12 INFO findings, all rls_enabled_no_policy | An advisor scan is not a complete security audit. |
| Those12 tables | RLS enabled; FORCE RLS false; no anon/authenticated SELECT, INSERT, UPDATE or DELETE grants | Owner and privileged-function paths require separate validation. |
| SECURITY DEFINER inventory | 49 functions across public/context_relay_private, below query LIMIT51; all explicit empty search_path and no anon EXECUTE | Other schemas and function-body authorization were not audited. |
| Public SECURITY DEFINER functions | All32 also deny authenticated EXECUTE | This is catalog privilege evidence, not HTTP/session/cross-account testing. |

The other17 SECURITY DEFINER functions are in context_relay_private. Six grant
authenticated EXECUTE: can_read_ciphertext_object, can_upload_ciphertext_object,
current_read_account_id, current_read_device_id, current_write_account_id and
current_write_device_id. These are policy helpers; the grant alone neither proves
correct authorization nor establishes direct exposure through the Data API.

The12 advisor tables are eight private tables (account_lifecycle_rate_limits,
account_lifecycle_receipts, blob_upload_reservations, enrollment_commits,
enrollment_reservations, pairing_invites, pairing_lookup_sessions,
recovery_commits) and four public tables (deletion_requests, github_installations,
pairing_requests, recovery_roots). Preserve their access restrictions rather than
adding permissive policies to silence an [informational notice](https://supabase.com/docs/guides/database/database-linter?lint=0008_rls_enabled_no_policy).

All three functions report verify_jwt=false. They rely on application-level
authentication; this setting alone is not evidence of anonymous authorization.
Management-reported bundle SHA-256 values are recorded below, without claiming
a local bundle download, byte rehash or match to current PR source:

- sync: c087f4269d43789d690381fa82e742ec1aba800a5f0e816af1f1188c346ba2bc
- account-lifecycle: d65cc293cfbd85aa2a6370d5be4f1d6525b21a443016054393a46d08328a84b4
- enrollment: fc87a24760b3f957902abacdf781ec7c9a30b6ee8ca701492762f63aab433e72

Evidence: Supabase MCP get_project, list_edge_functions, list_migrations and
get_advisors(security), followed by two catalog-only execute_sql queries using
pg_class/pg_namespace and pg_proc, has_table_privilege and has_function_privilege.
Local snapshots are `.codex/pr16-hosted-state-2026-09-14.json`,
`.codex/pr16-hosted-security-advisors-2026-09-14.json` and
`.codex/pr16-hosted-permission-metadata-2026-09-14.json`.

OAuth provider configuration was not rechecked; its existing observation remains
dated September12. Login, pairing deployment, installed sync/recovery,
cross-account/session-revocation tests and clean Windows acceptance remain open.
This evidence does not complete RB-SYNC or the release checklist. Apple-related
work and paid steps remain deferred.
