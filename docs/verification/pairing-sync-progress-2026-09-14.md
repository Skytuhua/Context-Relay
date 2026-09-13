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

## Subsequent local PostgreSQL checkpoint

All18 migrations, including the evolving
`20260913210523_membership_public_history_v2.sql`, applied transactionally in a
fresh `task5_clean` database on isolated PostgreSQL17.11 at127.0.0.1:55439.
The six enrollment-anchor tests passed (terminal0,1443.5847ms), recorded in
`task-5-postgres-clean-applied.log` and `task-5-postgres-anchor-clean-green.log`.

These cases verify the exact canonical genesis anchor, unsupported-version
rejection, rollback of enrollment writes when initialization fails, preservation
of a descendant head and inactive genesis member, conflicting pin/receipt
rejection, and denied direct access to the private initializer. An earlier
5-pass/1-fail run differed only by a Windows carriage return in the test output;
the fix normalized line endings and retained the exact value assertions.

The database uses minimal existing provider-schema fixtures. This proves local
PostgreSQL transaction behavior, not live Supabase Auth, Storage or Realtime.
Authorized history-access RPCs remain under implementation; later changes to the
same migration require new covering verification. Task5 and release acceptance
remain incomplete.

## Subsequent local authorization and history-object checkpoint

`task-5-postgres-objects-green1.log` records 10 passed, 0 failed in
2065.4087ms. It adds live-session and exact active-device checks, explicit
enrollment initialization without reactivation, atomic V2 approval/public ADD
publication, and addressed history/result binding to the original recipient,
request, enrollment pin and live membership. The preceding objects test run
had 9 passed and 1 failed because the retrieval RPC was absent.

This remains evolving local SQL with minimal provider fixtures. Complete
history/key transfer, recovery, final clean migration replay, independent review
and deployed/installed acceptance remain open.

A fresh read of Windows CI job `103744496873` in run `34765079727` at pushed
head `30589c010af29b1bd0caf543eaab539baedd044c` confirmed 103 daemon tests
passed, 3 failed and 4 ignored. Its three failures are the original pairing,
hosted pairing and hosted sync regressions listed above. Their later local
results do not clear that remote failure or qualify the evolving full diff.
PR16 remains open and blocked; no new CI run, deployment or merge was initiated.

## Integrated server coverage and recovery boundary

The subsequent server covering run passed all 21 tests in 309.6586ms
(`task-5-server-covering2.log`); the PostgreSQL covering run passed all 14 in
4720.5407ms (`task-5-postgres-covering3.log`). Coverage includes the actual
request handler and production adapter calling database RPCs through a local
psql test bridge. External Auth claims are stubbed; this does not exercise
deployed Supabase Auth or PostgREST.

The account-deletion regression is covered in both directions: deleting a
referenced certificate alone fails at commit and preserves that certificate;
deleting the account succeeds and removes its account/head/member records.

`task-5-recovery-rotated-red.log` records the compiled
destroyed-device recovery case failing in 1.24s: existing recovery returns
control/key epochs `(1,1)` instead of the verified rotated parent `(2,2)`.
The subsequent exact test passed in 1.72s after a 51.51s compile
(`task-5-recovery-rotated-green1.log`, handle71752, terminal0). The implementer
reports exact epoch2 key recovery and canonical V2 roundtrip coverage. Recovery
history replay, durable key retention and hosted integration remain open; this
single test does not establish complete recovery acceptance.

A separate `task5_replay` database was prepared with only the minimal provider
bootstrap for a fresh migration replay; preparation alone is not successful
replay evidence.

## Subsequent recovery storage and preservation evidence

The expanded server migration subsequently replayed all 18 migrations into
`task5_replay`; all 14 database tests passed in 5156.3808ms. Evidence is in
`task-5-postgres-expanded-replay-applied.log` and
`task-5-postgres-expanded-replay-green.log`. The provider-fixture limitations
above still apply, and later SQL changes require renewed verification.

Recovery event decoding/replay passed in 1.94s, followed by vault storage/restart
in 7.50s and root-opened key retention checks in 8.72s. These are successively
expanded versions of the same test, not three independent full recovery suites.
Their logs are `task-5-recovery-event-green1.log`,
`task-5-recovery-vault-green1.log` and `task-5-recovery-retention-green1.log`.

The covering command in `task-5-recovery-covering1.log` finished successfully
(handle57972, terminal0): 2 membership crypto tests, 4 membership vault tests,
7 existing recovery-format tests and 1 expanded recovery test passed. The latter
includes exact eight-column preservation of ADD/revocation rows and failed-copy
rollback retaining rows and user_version42. This uses direct in-memory table DDL,
not a full schema42 vault upgrade through the production migration driver.
Durable recovery integration, complete reconstruction/transfer, deployed behavior,
installed upgrades and final independent review remain open.

## Durable recovery fault checks and server verifier

The expanded recovery test now passes after restart, signature/session
substitution checks and forced SQLCipher insertion rollback
(`task-5-recovery-durable-green2.log`: 1 passed in 21.87s). This verifies local
prepared recovery storage; it does not authorize membership or establish
complete history installation.

The subsequent covering command stopped with 3 passed and 1 failed because the
simulated schema40 fixture retained a newer SQLite44 table. After correcting
that fixture, its targeted rerun passed in 5.79s
(`task-5-recovery-schema40-green.log`). The failed covering command remains
recorded in `task-5-recovery-durable-covering1.log`; the targeted fix is not a
replacement for final broad regression coverage.

The server recovery verifier passed all 8 tests in 256.994ms
(`task-5-recovery-edge-green2.log`), including the native recovery vector,
malformed encodings, changed signatures, exact record/session bindings and
invalid embedded certificates. Server recovery transactions, native/UI
integration and deployed/installed acceptance remain incomplete.
The first local server recovery transaction test passed in 273.6249ms
(`task-5-recovery-postgres-green1.log`, total 439.4802ms), following a
missing-RPC failure in `task-5-recovery-postgres-red.log`. The test covers
recovery publication at the exact parent/generation and an exact retry. Its
rotated parent is seeded from a Rust-verified vector; this is not a live
revocation-publication test. Failure-case coverage and fresh full migration
replay after this SQL change remain required.
