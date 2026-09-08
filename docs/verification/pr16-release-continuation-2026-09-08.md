# PR 16 full-release continuation — 2026-09-08

The user explicitly requires the complete product-release checklist before merging
PR #16. Passing the current desktop/setup checks is insufficient. The
[Windows acceptance ledger](windows-app-release.md) and
[v1 audit](v1-master-plan-audit.md) retain their requirements.

## Fresh source verification

Reviewed GitHub PR #16 at `f3dc22b908492ea2ed97764d446b1ed64babb6e9`, based on
`b3d487e0965a87f69a0d7acf07066daa6a29f132`. All executable checks passed, including
Windows/macOS native tests, installer assembly and the Supabase contract job.
CodeRabbit skipped review because the PR exceeded its file limit. A bounded
independent review found no additional P1/P2 issues in the newest desktop
changes and selected receipt, launch and installer boundaries; it did not review
every file or establish installed-release acceptance.

A fresh local frontend run failed one of 345 tests. A focused rerun exposed two
navigation timing failures: the tests clicked Continue or Claude Code as soon as
the saved-result heading appeared, before the parent navigation guard cleared.
Both tests now explicitly await enabled controls. Production guards and existing
result assertions are unchanged. The focused eight tests and full 345 tests in
39 files pass; TypeScript, ESLint, production build and whitespace checks pass.

## Release work remains

1. Recover and validate the account-lifecycle work preserved in `6eb5ec8` and
   `485886c`. Its own ledger identifies incompatible legacy SQL grants/tests,
   missing executable session/replay/expiry coverage, and unavailable production
   transport ownership. Do not merge the entire historical branch or restore
   revoked service authority to satisfy obsolete tests.
2. Complete daemon-owned GitHub OAuth sessions, provisioning and production
   sync/pairing/recovery transports. Verify expiry, refresh, logout, device
   revocation/rotation, reassociation, deletion/purge and export end to end.
3. Complete repository identity and package quarantine/scanning/approval/install/
   removal, followed by conflict/history/import/export/diagnostic product flows.
4. Qualify the installed desktop and all supported harnesses, offline/restart/
   recovery paths, accessibility and performance on the required platforms.
5. Complete protected signing/notarization/updater signing, provenance, clean
   install/update/uninstall and security/reliability gates before release and merge.

Read-only hosted inspection found the Context Relay project active, with only
`20260805153409_context_relay_ciphertext_boundary` and
`20260805155753_revoke_context_relay_internal_execute` applied, and no deployed
Edge Functions. No hosted mutation or deployment was performed. Docker and psql
were not found on this shell's PATH; this is not proof that no alternative test
runtime exists. Hosted production is not a disposable SQL test database.

Signing identities and clean Windows/macOS acceptance-machine availability have
been requested from the user. Neither those gates nor installed-product
acceptance is claimed complete. PR #16 remains unmerged.

## Account lifecycle recovery: local evidence

Recovered the bounded `6eb5ec8` implementation onto the current branch without
merging its historical branch. Preserved both the current connection-check test
and the restored ordered-worker lifecycle test when resolving their overlapping
insertion. Production still uses the unavailable lifecycle transport.

An independent review found two defects: transaction-start timestamps could
accept authority that expired during a lock wait, and replaying an old receipt
could show obsolete state after an opposite action. The migration now checks
Auth-session expiry after acquiring its row lock, checks binding expiry after
both authority locks, and returns current locked state for a matching receipt
without repeating the transition. Legacy service-role entrypoints stay revoked;
their old pgTAP expectations were corrected.

On a dedicated loopback PostgreSQL 17.11 instance, the original six regression
cases produced five failures. After the fixes, all four migrations applied from
an empty database and all ten checks in
`scripts/verify-account-lifecycle-postgres.mjs` passed. They cover both replay
directions, binding/session expiry behind either lock, credential expiry behind
the account lock, stale credentials, foreign workspace, deleted session, stale
epoch, opposite-action receipt reuse, legacy privilege denial and rate limits.
The workflow now runs this script before its existing full pgTAP suite.

The 21 focused Node workflow/Edge/boundary checks also pass. Rust verification
is still running; full Supabase pgTAP execution remains pending. The portable
database uses minimal Auth/Storage/Realtime schema substitutes, so these local
results establish PostgreSQL behavior only, not Supabase or hosted acceptance.

Durable caller request identity across IPC retries and restart is still absent.
The existing encrypted `desktop_writes` storage is a candidate for retaining
intent, but its protocol currently excludes lifecycle operations. Production
activation requires that boundary, daemon-owned authenticated sessions, and
the remaining release gates; this recovery does not satisfy them.
