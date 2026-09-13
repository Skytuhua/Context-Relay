# Pairing and sync verification checkpoint — September 14, 2026

Task5 remains in progress. These are local test results from evolving,
uncommitted source after baseline `f59c394527f8e76d37e4e00cdb2aea584a135f50`.
They do not qualify a release revision or establish deployed-service behavior.
Apple work and anything requiring payment remain deferred, not passed.

## Observed results

Logs are retained under
`.superpowers/sdd/2026-09-13-membership-transfer-activation/`.

| Coverage | Terminal evidence | Result |
| --- | --- | --- |
| Two authenticated daemons pair, retain pending confirmation across restart, and confirm offline | `task-5-pairing-green4.log`, handle21851 | 1 passed, 20.78s |
| Hosted adapter pairing resumes after a lost approval response | `task-5-hosted-pairing-green1.log`, handle43648 | 1 passed, 45.39s |
| Hosted adapter sync receives searchable memory and restores its checkpoint after restart | `task-5-hosted-sync-green1.log`, handle46023 | 1 passed, 95.23s |
| Confirmed pairing with missing proof resumes after restart | `task-5-pairing-proof2.log`, handle61265 | 1 passed, 12.51s |
| Existing pairing, new proof/receipt negatives, transport, and hosted intent coverage | `task-5-pairing-covering1.log`, handle3630 | 23 passed, 1 failed |
| Exact failed schema31/32 upgrade case after correcting the downgrade fixture | `task-5-pairing-schema-green.log`, handle41837 | 1 passed, 7.30s |

The covering failure was a downgrade fixture that retained schema42 tables
before replaying their creation. Its targeted rerun passed; this does not turn
the earlier covering command into a successful full run.

The sync fixture now admits its sender through actual V2 pairing and independent
confirmation, rather than expecting a provider certificate alone to authorize
sync. Production membership checks remain strict. The hosted cases use the real
Rust adapter with a simulated HTTP provider, not the deployed Supabase service.

## Remaining work

The implementer subsequently tightened the receipt and original hosted-intent
check inside the authority transaction. Earlier results do not verify that later
change; covering verification and independent review remain required.

Server authorization and publication, complete history/key transfer, recovery,
desktop progress and error handling, actual hosted login/pair/sync/recovery, and
clean Windows installed acceptance remain open. Existing OpenSSL debug-symbol
warnings remain unresolved. No merge, deployment, final source approval, or
full-release completion is established by this checkpoint.
