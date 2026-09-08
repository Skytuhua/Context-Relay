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
