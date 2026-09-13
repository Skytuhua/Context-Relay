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

## Recovery server failure cases and history access

All four recovery database tests passed in 1165.6965ms
(`task-5-recovery-postgres-covering1.log`, implementer confirms terminal0).
They cover stale parent/generation rejection, rollback after public-event
insertion failure, and retries requiring the current recipient and original
live session. The rotated parent remains a seeded component fixture.

The adapter covering run passed 9 tests in 265.613ms
(`task-5-recovery-adapter-green.log`). The expanded HTTP handler run passed
10 in 274.8299ms (`task-5-recovery-http-green1.log`). The adapter test uses a
fake RPC and the handler test uses simulated authentication/history dependencies;
these results do not establish an integrated handler-to-database or deployed test.

`task-5-recovery-history-green1.log` passed one database test in 321.7299ms
(total). It proves addressed history access from a new unbound owner session,
missing-object handling and dead-session endpoint rejection. Existing device
rows remain active in this fixture. Explicit all-devices-inactive and wrong
owner/workspace/enrollment checks were requested before claiming that broader
coverage. Complete native recovery, real revocation/recovery concurrency, fresh
migration replay and hosted/installed acceptance remain open.

The expanded history test subsequently passed in 714.5419ms total
(`task-5-recovery-history-green2.log`). Its fixture explicitly makes every prior
member inactive and binding revoked, asserts zero active rows, then retrieves
history from the new owner session. It rejects wrong owners on both reads,
wrong enrollment pin on the endpoint, wrong workspace on the event, and dead
sessions on both reads. Direct private-helper execution remains denied to anon,
authenticated and service_role. Revocation state is seeded by the fixture;
this does not qualify actual signed revocation publication or its concurrent
interaction with recovery.

The subsequent integrated local recovery test passed in 1867.4192ms total
(`task-5-recovery-http-postgres1.log`). It connects the real handler and
production adapter to service-role PostgreSQL transactions through a psql
bridge, verifies exact receipt retries, status and public-event bytes, and
rejects an invalid proof before committing. Auth claims and SDK transport are
stubbed; the rotated parent is still seeded. This closes the local integration
gap above, not deployed Supabase Auth/PostgREST acceptance.

## Fresh replay including recovery SQL

All 18 migrations applied to the separately bootstrapped
`task5_recovery_replay` database (`task-5-recovery-clean-applied.log`). The
complete database test command passed all 20 tests in 8205.5712ms
(`task-5-recovery-clean-green.log`), including pairing and recovery integrations.
The enrollment/recovery Edge covering command passed all 28 tests in 344.0145ms
(`task-5-recovery-edge-covering.log`). The implementer confirms all three
commands completed successfully, as did the earlier integrated recovery test.

These results qualify the current local SQL replay with minimal provider
fixtures. Auth/SDK stubs and seeded revocation limitations above still apply.
At this checkpoint the native recovery coordinator uses V1; integrating V2 and complete
history reconstruction remains necessary before full recovery acceptance.

## Native recovery preparation and admission

The native coordinator initially submitted V1 instead of V2
(`task-5-recovery-coordinator-red2.log`: 1 failed in 3.94s). After integration,
the V2 rotated-claim preparation/restart/retry test passed in 12.24s
(`task-5-recovery-coordinator-green1.log`, handle63824 terminal0).

Its expanded admission test passed in 46.42s
(`task-5-recovery-coordinator-green3.log`, handle14291 terminal0). It requires
the exact published event as well as the receipt/projection, preserves admission
across restart and exact replay, rejects wrong recipient keys, and keeps
`trusted_sync_material` unavailable after admission alone. The preceding run
failed on an unsuitable test assertion: `has_sync_authority` reports membership
presence, not activation. The correction exercises the actual material gate;
no production guard was relaxed.

Current-key activation remains an explicit independent operation under the
existing verified-current-state guards. History installation is separate;
these tests do not establish complete history restoration or hosted acceptance.
The next hosted transport test fails with `recovery_unauthorized` at the existing
fail-closed history method (`task-5-recovery-hosted-transport-red.log`, 0.41s).

The hosted transport subsequently passed in 1.76s
(`task-5-recovery-hosted-transport-green1.log`, handle67641 terminal0), covering
addressed reads, explicit-null versus omitted objects, original-session proof,
receipt/status agreement and cancellation without further requests. HTTP
responses are simulated.

The broader `task-5-recovery-native-covering1.log` records 25 hosted transport
tests passing in 23.65s and the expanded native recovery test passing in 56.68s.
The latter injects a final admission INSERT failure, verifies zero rows across
accepted membership, events, retained secrets, admission and activation tables,
retains prepared recovery, then reopens and retries successfully. Successful
admission still leaves trusted sync material unavailable without explicit
activation. Complete reconstruction and deployed/installed acceptance remain open.

## Recovery target selection

The expanded native test passed in 84.43s after a 53.16s compile
(`task-5-recovery-target-green2.log`, handle33560 terminal0). It adds the exact
307-byte recovery target, recipient-signed selection bound to the original
intent, historical checkpoint-author validation, negative input checks,
transaction rollback, exact retry and restart. The earlier target runs stopped
at compile errors; they are not behavioral failure evidence.

Selecting a target does not reconstruct or install history. The next test
currently fails to compile because the reconstruction, installation and
installation-status methods are absent
(`task-5-recovery-reconstruction-red.log`). Sharing the existing private
reconstruction algorithm is in progress; its previous pairing regressions must
be verified again after the shared changes. Reselection remains incomplete.

## Initial recovery reconstruction

The subsequent `task-5-recovery-reconstruction-green1.log` records one expanded
native recovery test passing in 130.86s after compilation in 52.11s. This first
case reconstructs an empty historical checkpoint, installs it and checks restart.
It does not yet establish nonempty-history, missing-range, cutoff, receipt-tamper
or shared Task4 regression acceptance. The earlier compile-only status above
is superseded for these APIs, not for the remaining coverage.

Explicit replacement of an unreconstructed candidate must preserve every existing
verified reconstruction baseline. Selecting an incomplete intermediate candidate
must not let a later selection bypass an earlier reconstructed or installed
history. The implementer is adding this bounded reselection rule and its tests;
it is not yet accepted implementation evidence.