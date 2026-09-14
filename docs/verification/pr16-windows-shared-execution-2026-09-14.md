# PR16 Windows/shared execution ledger — September 14, 2026

This is the execution index for the [approved plan](../superpowers/plans/2026-09-14-pr16-windows-shared-acceptance.md). It supplements the [master audit](v1-master-plan-audit.md), which retains every T01–T24 and all eight release-blocking requirements. No row below is full release acceptance merely because component tests pass.

## Approved scope

Merge only after all unpaid Windows/shared requirements pass. Apple implementation/qualification and paid requirements stay deferred, not passed. Unsigned builds are internal candidates, never public beta. User approved a bounded explicit recovery candidate list, internal N-1 build1468327, candidate version0.1.1, four hours per fuzz target, physical-PC qualification as amended below, and deferral of exactly four required macOS CI contexts. Existing other protections and all18 Windows/shared contexts remain required.

The user subsequently superseded the VM/ISO choice: use only this physical PC. The [physical-PC procedure](windows-physical-pc-acceptance-2026-09-14.md) uses two isolated Windows test-user profiles and fresh profile pairs for two acceptance passes. No VM/ISO work continues. Fresh profiles do not prove clean-OS or independent-host requirements; preserve those limitations as open gates.

The published source-only alpha is not a historical binary installer. Qualifying1468327 as internal N-1 establishes an explicitly chosen internal upgrade boundary; do not relabel it as a public release. Fresh September14 verification matches the installer and all18 manifest files in both extracted and installed locations (36 comparisons), version0.1.0 and source ancestry; [raw identity evidence](windows-internal-n-1-2026-09-14.json) does not establish the pending upgrade.

The [requirement ledger](pr16-windows-shared-acceptance.csv) preserves all24 task rows and123 original matrix bullets verbatim, with stable IDs, source lines and hashes. Mixed obligations have186 separately statused execution children (333 total rows): Windows/shared unpaid work remains open, Apple and paid obligations are deferred. Original historical procedures are retained separately from current scoped procedures. Unknown statuses mean final acceptance is not established; historical scoped results remain in the master audit and are not erased.

## Evidence record format

For each individual master-matrix requirement retain: ID; exact source revision (or uncommitted patch identity); artifact SHA256; OS/hardware/VM and hosted versions; command/manual steps; start/end and terminal exit; log/evidence path; limitations; status. Allowed execution statuses: passed, failed, running, unknown, deferred, awaiting user action. Split mixed-platform requirements. Synthetic Auth or database fixtures never establish real hosted acceptance.

## Work packages

| Package | Requirements covered | Current execution status | Required next gate |
| --- | --- | --- | --- |
| Ownership and evidence | T01, all acceptance records | running | Ownership transferred at 00:53 UTC; current worker owns source/Cargo/DB/graph. Requirement evidence reconciliation continues. |
| Durable recovery and history | T04–T05, T16–T17; RB-CRYPTO/RB-SYNC | running | Terminal conflict, full caller covering, candidate selection and composed workflow. |
| Hosted lifecycle | T15–T17; RB-SYNC | awaiting user action for pepper; implementation open | Reviewed deployment, real Auth/Storage/Realtime and installed lifecycle. |
| Repository App/packages | T18–T19; RB-PACKAGE | unknown | Least-privilege App, complete exact-byte package workflow and adversarial matrix. |
| Desktop/harness/MCP | T06–T14, T20–T21; RB-LOCAL/RB-NATIVE/RB-MCP | unknown | Complete product surfaces and real harness/physical checks. |
| Security/governance | T02–T05, T09, T23; RB-REP and all boundary reviews | unknown | Independent review, fuzz/fault tests, dependency and license dispositions. |
| Windows artifacts/acceptance | T22–T24; RB-RELEASE | running | N-1 artifact identity verified. User canceled VM/ISO work; prepare dedicated physical-PC test accounts. Final candidate, two fresh-profile passes, upgrade and physical/performance checks remain. Clean-OS limitations stay open. |
| Protected merge | T01–T24, all eight matrices | unknown | Exact-head current checks, final acceptance audit and protected squash merge. |

## Starting checkpoint and limitations

Local committed HEAD86f5f37343978351f1d0cb1e13e28ce9c91a8ffd; last verified PR head30589c010af29b1bd0caf543eaab539baedd044c. Task5 source is substantial and uncommitted. Its fixed independent-review baseline is f59c394527f8e76d37e4e00cdb2aea584a135f50, not HEAD~1.

Latest owner-reported terminal component evidence includes historical22pass412.09s, missing-selector recovery1pass443.78s, all5 daemon recovery tests45.32s, regenerated bindings/schema, desktop TypeScript and8panel/gateway tests. The current worker is draining its last focused pairing test before handing off. Full recovery caller coverage and installed/hosted acceptance remain open. Exact owner report and logs remain under the preserved membership-transfer-activation evidence directory.

The latest read-only hosted snapshot has17 migrations and version1 sync/enrollment/account-lifecycle functions, with pairing absent. Saved GitHub OAuth provider and loopback redirect configuration is complete; actual installed login remains open.

## External-action preparation

The earlier pairing-pepper setup was rejected by automatic approval review with only `blocked by policy`. Preserve that rejection; no alternate route may replay it. Before requesting user action, prepare exact deployment source, a secure dashboard procedure for CONTEXT_RELAY_PAIRING_PEPPER (32 random bytes encoded as64 lowercase hexadecimal characters), and a presence/behavior check that never reveals its value. Do not ask for credentials in chat.

Prepare exact installers and dedicated test-account procedures before native user actions. Tests use disposable scopes and supported app UI; never stop or launch the user's production daemon for qualification. The earlier VM tooling/empty definitions remain unused and powered off; no OS media was downloaded and no guest installation occurred.

Read-only Supabase CLI secret-metadata listing (profile `supabase`, project `brvzuycnxoswdzzipgvx`) exited0 on September14 and found no `CONTEXT_RELAY_PAIRING_PEPPER` among7 entries. No secret values were returned or displayed, and no setup was retried. The prerequisite remains open until the reviewed deployment and secure user procedure are ready.

## Fuzz environment preparation

Installed separately named `nightly-2026-09-13-x86_64-pc-windows-msvc`, rustc1.100.0-nightly (`809936eac`, September12), minimal profile plus llvm-tools-preview; rustup exited0. No default or repository override changed; the application remains pinned to1.97.1. Existing Visual Studio2022 MSVC14.44.35207 provides the Windows AddressSanitizer DLL and llvm-symbolizer. Raw toolchain/component/hash metadata is in `E:\Context Relay Releases\qualification-tools\fuzz-windows\preflight.json`.

This follows the [Rust Fuzz Book Windows prerequisites](https://rust-fuzz.github.io/book/cargo-fuzz/windows/setup.html). cargo-fuzz installation/build waits for the serial Cargo lease. No target or four-hour fuzz run has passed; all five targets still need final-source qualification, seeds, coverage, duration and crash artifacts.

## Recovery integration checkpoint — September 14, following R1 review

Execution Task1 records passed independent specification and quality re-review. The333-row acceptance ledger retains147 original requirements and186 scoped execution children; no original release gate was promoted by the documentation review.

The complete inherited Task5 source review uses baseline f59c394527f8e76d37e4e00cdb2aea584a135f50 and immutable package SHA2566ee330111606871efc95e2cac4336de21b39c88ccf5add90beb46d9c59f4681f. Its only actionable finding, interrupted pairing finalization after legitimate same-epoch membership advancement, was repaired and independently re-reviewed. The three-file fix package SHA256 is b1d003c445cfe4b9ece7e3c11144b24e2c31cc201cdecfda9892f826b2c45ed7. Both source verdicts passed conditionally on remaining validation; task-2-fix1-review-source-manifest.json identifies all69 reviewed source/test paths. These source packages remain local evidence under .superpowers/sdd/2026-09-14-pr16-windows-shared-acceptance/.

Pre-R1 source passed recoveryV1 13, recoveryV2 1, daemon recovery6, shared callers43 and historical22 with actual terminal exit0. R1's expanded pairing target passed6/6 in66.01s after the real two-role regression failed0/2 with Conflict. Updated source also passed TypeScript and desktop Vitest44files/376tests in72.37s. The two composed daemon pairing tests passed2/2 in73.69s with the ordinary CI feature bundle. Exact commands and raw log/exit-file locations are in task-2-report.md; all are component evidence.

The composed hosted-sync checkpoint/restart test remains FAILED:0/1 in85.95s, exit101, .codex/task-2-fix1-daemon-sync.log/.exit. Its60-second cycle deadline elapsed; that alone does not identify a progress loop, finite expensive validation, or an authority defect. The same exclusive implementer is measuring bounded test-only progress/timing before selecting a root-cause fix. Identity1/1, membership4/4 and explicit V1 restore-vault11/11 subsequently passed; the remaining recovered-device caller, Clippy and protocol generation comparisons are not yet recorded as passed. Execution Task2 and original hosted/installed Task5 remain in progress.

The reviewed pairing-secret user procedure is prepared in pairing-secret-user-procedure-2026-09-14.md, but no secret setup has been requested or attempted. The exact deployment manifest and rollback must be ready first. Future verification uses user dashboard confirmation plus sanitized deployed behavior, not a general all-secrets response. Separate dependency23 and OpenSSL PDB preflights retain both gates open; no exception was approved. No source commit, push, deployment or merge has occurred in this continuation.

Node component covering: node --test with15 explicit enrollment/pairing test files passed50/50,0skipped,652.4454ms,exit0. Raw .codex/task-2-edge-composed-final.log/.exit; separate input/command/environment manifest .codex/task-2-edge-composed-final-manifest.json SHA256fd8ab53b28a767314ed56113b14da14cec5465e0b1feb746a1f18beeefab052c covers69 input files (all Edge mjs, selected tests and all core fixtures), with0post-run hash mismatches. The earlier50/50 run is retained; this rerun closed its incomplete input-manifest scope. Injected HTTP/Auth adapters remain component evidence, not actual hosted authorization.

## Durable recovery correction — final component checkpoint

The earlier sync timeout was resolved by constructing verified sync material once per actor step using the applicable certificate snapshot. No cross-step authority cache or timeout increase was introduced. A subsequent stalled-HTTP responsiveness failure was traced to empty background backfill rebuilding trusted material; the shared backfill now checks conservatively for actual work before constructing that material. Actual work retains the original authorization, migration and transaction checks, including corrupt already-owned legacy candidates. Independent reviews passed both fixes and the separate mechanical lint/format changes. The final one-file test-helper lint delta is awaiting final independent reconciliation at this checkpoint.

The complete final Task5 source identity contains71 paths: local `task-2-final-review-source-manifest.json`, SHA256 `4eea440bfb8348d17096c02ec15b9e305a2dff392795c1ca647f415100e68863`. It includes the inherited source from baseline `f59c394527f8e76d37e4e00cdb2aea584a135f50` plus every subsequent reviewed delta. Source remains uncommitted at this checkpoint. Local report `task-2-report.md`, SHA256 `91c364ccbbbc2c6aadc2a1c455be86e461bfb8ebc4f035f14713c1d9df972db5`, preserves exact commands, environments, earlier failures, source boundaries and terminal receipts under `.superpowers/sdd/2026-09-14-pr16-windows-shared-acceptance/`.

| Final component check | Result and raw evidence under `.codex/` |
| --- | --- |
| Shared backfill obligations, rollback and corrupt owned candidate | 2/2,47.99s,exit0; `task-2-backfill-core.log/.exit` |
| Clean daemon sync completion/restart and stalled-HTTP responsiveness | 2/2,69.36s,exit0; `task-2-backfill-sync-clean.log/.exit`; unchanged1s read and60s cycle deadlines, no temporary diagnostics |
| Deterministic signed-sync ownership/migration coverage | 15/15,129.06s,exit0; `task-2-signed-sync-covering.log/.exit`; one randomized test explicitly filtered |
| Strict workspace all-target Clippy with documented ordinary CI feature bundle | exit0,1m06s; `task-2-clippy3.log/.exit` |
| Full workspace formatting and diff whitespace | exit0; `task-2-fmt-final.log/.exit`, `task-2-diff-final.log/.exit` |
| Real binding/schema generators with exact byte/file-set comparison | both exit0; `task-2-bindings-final.log/.exit`, `task-2-schemas-final.log/.exit`; unique isolated TEMP outputs, reviewed files unchanged |

The first full signed-sync run was intentionally interrupted during its256-seed randomized tail after15 deterministic cases reported success; its actual exit is-1, not a pass (`task-2-signed-sync-final.log/.exit`). The subsequent15-test command explicitly skips that test. Full randomized convergence remains an open release check. Earlier tests belong to their recorded source revisions; mechanical formatter equivalence was independently reproduced for24/24 files rather than relabeling those older runs as final-source executions.

All source/Cargo/PostgreSQL/graph leases were released after terminal verification; no owned handle remains. Final Graphify update exited0, including retained scratch Rust evidence and the existing parser limitations. Original Task5 still requires explicit history-selection implementation, hosted deployment and installed acceptance. No original release requirement, hosted acceptance, clean-OS claim or merge gate closes from these component results.

Final independent reconciliation passed specification and code quality with no open actionable Task2 finding. The subsequent full staged check found one trailing space in the previously untracked, unpublished migration; that byte was removed and independently verified to preserve every other byte and SQL semantics. Final71-path working-byte manifest SHA256 is `7d3c60f81a0046a745d3cabc1e688bd71c7db4dfd98eab84f0f423fd299ab18a`. Commit `924348a36900e89df6bc8b41fa6162127c24b8b3` contains exactly those71 source/test/migration paths. The [source identity record](pr16-durable-recovery-source-2026-09-14.json) links preserved working bytes to Git-normalized committed blobs; Git line-ending normalization is distinguished from the tested working bytes. No push, deployment or merge occurred. Execution Task2 is complete within its bounded implementation scope; original hosted/installed Task5 remains open. The fresh Task3 implementer now owns source/Cargo/DB/graph work for explicit history selection.

Isolated fuzz tooling is now installed: cargo-fuzz0.13.2, install/version checks exit0, binary SHA256 `8aaa972f5529bf7f978abdfe15aa5cef3192ed98973169c0ff63c687d09c2c9e`. Exact log, exit and metadata are under `E:/Context Relay Releases/qualification-tools/fuzz-windows/`; the installation uses the separately named nightly and its own target/install roots. The application toolchain and global PATH remain unchanged. This is tool preparation only: no fuzz target was compiled or run and no four-hour duration was credited.

<a id="task3-explicit-history-final-component"></a>
## Explicit recovery history selection — final component checkpoint

Task3 implements explicit authenticated recovery-history listing and selection, exact selected-target Resume, native-only missing-historical-key reentry and durable reconstruction/installation. Protocol1.16 adds Desktop candidate/select operations and a DesktopRecoveryHost-only unlock operation. The renderer/native command carries only nonsecret recovery and endpoint identifiers; recovery words remain confined to the native host path. Current-epoch write activation remains separate from historical completion.

Commit `aa241cf59057c55d3466e5496e8c4f9a1959f7ea`, parent `c2419ff5ce3e0564130e5af4f458b712cd315bfd`, contains exactly the39 reviewed Task3 source/test/protocol/schema paths. Frozen working-source manifest `task-3-final-source-manifest.json` has SHA256 `9f42794634b9a4b8ea77f932f1c48e743776f9b720c1f4532af90e97691f3f22`; implementation report `task-3-report.md` has SHA256 `f909299857271deb9f0cd4a43d23e21c741e2c153eec2e5ff41928eb4a7956fd`. Final independent review passed specification and code quality with no remaining actionable Task3 source finding; `task-3-final-review.md` has SHA256 `32a2c72ec1df6e09e7c3ca27c9ca8f9271d67ff36e31408cebe4408b3eea9d64`. The [source identity record](pr16-history-selection-source-2026-09-14.json), SHA256 `3f8c78c7f63024939e1a77b8184429206dd79e50cf698dac96712eb5355b057e`, maps all39 reviewed working-byte hashes to their committed Git blob and SHA256 identities, preserving Git-normalization distinctions. The unrelated Task6 documentation in parent commit `c2419ff...` is not Task3 implementation evidence.

| Final Task3 component check | Terminal result and preserved evidence under `.superpowers/sdd/2026-09-14-pr16-windows-shared-acceptance/` |
| --- | --- |
| Core explicit history, receipt and descendant batch | 2 passed, exit0; `task-3-core-batch-restored.log` |
| Original-session cancellation at transaction and final-result boundaries | 1 passed, exit0,113.48s total; `task-3-fix1-daemon-green.log` |
| Routed Resume of signed Memory and Instruction with persisted embeddings, local search and reopen | 1 passed, exit0,225.79s total; `task-3-fix2-daemon-green.log` |
| Descendant/cutoff recovery after restart | 1 passed, exit0,285.85s total; `task-3-descendant-final-green.log` |
| Strict shared historical cryptography, reconstruction, caller bounds and rollback | 22 passed, exit0,535.74s total; `task-3-historical-shared-final.log` |
| Full V2 rotated recovery, rollback and restart integration | 1 passed, exit0,431.75s total; `task-3-recovery-v2-shared-final.log` |
| Native desktop recovery host | 20 passed, exit0; `task-3-native-tests.log` |
| Local IPC role/transport coverage | 69 unit passed with3 ignored fixture helpers, 1 parity passed and26 integration passed, exit0; `task-3-ipc-final.log` |
| Focused desktop recovery/protocol/gateway coverage | 42 passed across3 files, exit0; `task-3-desktop-final.log` |
| Protocol package and generated comparisons | Protocol exit0/257.0s; bindings exit0/2.03s; schemas exit0/1.52s; `task-3-final-check-results.json` |
| Final strict workspace all-target Clippy | exit0/71.52s with the ordinary four-package feature bundle and `-D warnings`; `task-3-final-clippy-green.log` and `.result.json` |

R1's final authorization callbacks and post-result check preserve the ruled cancellation ordering and durable offline overview. R2 uses the existing production `sync_embedding` helper so reconstructed Memory and Instruction records regain searchable local representation. Shared history tests cover exact selection/CAS, applied metadata, record frontiers, off-prefix heads, dependencies, receipts, cutoff behavior, revoked historical authority, rollback, restart and supersession. These are component results from this Windows11 x64 physical-PC development workspace with isolated Cargo target and local/injected providers.

The acceptance ledger attaches this checkpoint only to16 directly applicable Windows/shared rows, leaving every status unknown. No installed candidate, fresh-profile pass, clean-OS or independent-host proof, live hosted provider, N-1 upgrade, cross-platform run, real-model benchmark, randomized convergence campaign or release acceptance is established. Original hosted/installed recovery, physical-PC acceptance and aggregate release gates remain open.
