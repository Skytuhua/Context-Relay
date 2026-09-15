# Context Relay PR16: complete Windows/shared acceptance and merge

**Execution amendment — September 14, 2026:** The user superseded the VM choice: “no VM”, “I dont want to use ISO”, “Just use this computer.” All Windows qualification now uses this physical PC and dedicated disposable Windows test-user profiles. No VM or ISO work continues. Fresh profiles are not clean OS installations; requirements they cannot demonstrate remain explicitly open rather than being silently passed.

## 1. Goal and confirmed decisions

Complete every applicable requirement in T01–T24 and all eight release-blocking matrix sections, then merge PR16 into `main`. Completion requires working installed and hosted workflows, verified release artifacts, independent review, and evidence tied to the final revision.

The authoritative requirements remain the [original implementation plan](<E:/Context Relay Releases/workspaces/pr16-release/docs/context-relay-v1-implementation-plan.md>), [master acceptance audit](<E:/Context Relay Releases/workspaces/pr16-release/docs/verification/v1-master-plan-audit.md>), and [Task5 protocol rulings](<E:/Context Relay Releases/workspaces/pr16-release/.superpowers/sdd/2026-09-13-membership-transfer-activation/task-5-rulings.md>). This plan supplies the execution order and incorporates the decisions made in this conversation.

**Confirmed scope and defaults:**

- Merge after all unpaid Windows/shared requirements pass. Preserve Apple and paid requirements as deferred.
- Do not publish or describe an unsigned candidate as public beta.
- Use a bounded recovery-history candidate list with explicit “Restore this history” actions.
- Formally qualify preserved build `1468327` as the **internal N-1 predecessor**. It is not a previous public binary release.
- Run each required fuzz target for **four hours**.
- Use only this physical PC, with dedicated Windows test-user profiles for isolated installation, multi-device sessions and physical checks. Do not use VMs or ISO media.
- Defer exactly four required macOS CI checks; preserve all 18 Windows/shared checks and every other repository protection.
- Continue using regular Chrome, existing authenticated access, existing dependencies and established native transaction facilities.
- Preserve the user’s installed service, vault, credentials, public Git history and existing work.

Use Superpowers `executing-plans` for implementation, with independent review at the boundaries below. The user has authorized execution; progress and exact evidence are recorded in the execution ledger.

## 2. Resume from the actual checkpoint

### Task 1 — Reconcile ownership, evidence and acceptance records

**Deliverable:** one accurate continuation checkpoint and a requirement-by-requirement acceptance ledger.

- [ ] Work explicitly in `E:\Context Relay Releases\workspaces\pr16-release`.
- [ ] Re-query Context Relay and retrieve current task revisions. Record this conversation’s scope, recovery UI, N-1, fuzz-duration, environment and CI decisions.
- [ ] Obtain the existing Task5 worker’s scoped handoff before overlapping source changes, Cargo execution, PostgreSQL use or graph updates.
- [ ] Recheck tracked and untracked files. Preserve the Task5 review baseline `f59c394527f8e76d37e4e00cdb2aea584a135f50`.
- [ ] Continue from current implementation rather than replaying the September 14 handoff mechanically.

**Fresh checkpoint established during planning:**

| Item | Current evidence |
|---|---|
| Local committed HEAD | `86f5f37`, plus substantial uncommitted Task5 source |
| Remote PR head | `30589c0`; PR remains open and blocked |
| Historical shared suite | 22 tests passed; worker recorded terminal exit 0 |
| Recovery stage-one suite | Passed before the subsequently added missing-selector regression |
| Daemon V2 regression | Reproduced “Idle instead of Submitting”; production fix present, verification pending |
| Additional recovery gap | Missing selection singleton must not erase earlier authenticated history constraints |
| Hosted deployment | 17 migrations; version-one sync, enrollment and account-lifecycle functions; pairing absent |

For every acceptance row, record requirement ID, source revision, artifact hash where relevant, environment, command or manual procedure, terminal result, evidence location and limitations. Separate `passed`, `failed`, `running`, `unknown`, `deferred` and `awaiting user action`.

A mixed requirement retains its Windows/shared work. Historical local passes do not become installed or hosted passes.

## 3. Ordered implementation work

### Task 2 — Finish and qualify Task5’s durable recovery integration

**Deliverable:** V2 recovery survives interruption and restart without replacing identity, losing authenticated history or reporting premature completion.

- [ ] Drain the worker’s current serial run and record each command’s actual result.
- [ ] Verify the existing daemon fix across Overview, Begin, Resume, Cancel and startup. Preserve the original recipient, enrollment pin, canonical claim and original hosted session intent.
- [ ] Reject simultaneous V1/V2 durable state. Retain explicit V1 compatibility without promoting V1 data into V2 authority.
- [ ] Keep prepared V2 attempts after failed cancellation; return Conflict rather than discarding or replacing preparation. Deny hosted resume after Auth cancellation or session substitution.
- [ ] Fix the missing-selector case at the shared history-validation boundary. Validate all earlier authenticated reconstruction/installation receipts even when the current-selection singleton is absent.
- [ ] Preserve valid earlier history through initial bad candidates, incomplete replacements, missing downloads and restart. Corrupt or partially missing receipts must fail closed.
- [ ] Re-run relevant Task4 reconstruction, activation and rollback coverage after changes to shared private code.

**Required regression outcomes:**

- Prepared recovery reports Submitting before and after restart.
- Admitted recovery reports RestoringHistory.
- Admission alone does not activate writes or establish installed history.
- A → incomplete B → regressive C rejects C, including after deletion of only the selection singleton.
- Missing operations remain repairable.
- Failed transactions preserve durable preparation and leave no partial authority or installation.
- Final receipt signatures count toward aggregate storage limits before commit.

### Task 3 — Connect explicit history selection to the real recovery workflow

**Deliverable:** the installed application can select, download, reconstruct and install recoverable history.

**Public interface changes:**

- Add desktop-only `RecoveryHistoryCandidates` and `RecoveryHistorySelect` IPC operations.
- Candidate results expose bounded summaries, the recovery identifier, exact accepted membership endpoint identifier and canonical checkpoint hash.
- Selection submits the recovery identifier, exact accepted endpoint hash and exact checkpoint hash. The daemon resolves canonical bytes and revalidates them.
- Keep `RecoveryRestoreResume(EmptyParams)` for an already selected target. It must never silently select the provider’s newest checkpoint.
- Advance the current local protocol from 1.15 to 1.16 and update the complete compatibility bundle: bindings, schemas, validators, role/routing matrices, runtime fixtures, handshake proofs and documentation.

**Implementation:**

- [ ] Display candidate summaries using authenticated checkpoint metadata, including author, recorded time and history extent. Describe them as recovery candidates, without claiming global freshness.
- [ ] Require an explicit action for initial selection and replacement. Reject stale selections if accepted membership or the recovery identity changed.
- [ ] Reuse existing bounded HTTP, session cancellation, retry, membership replay, checkpoint and operation transport facilities.
- [ ] Connect the existing `select_recovery_history`, `reconstruct_recovery_history`, `install_recovery_history` and receipt-validation APIs through the daemon.
- [ ] Download and validate complete signed prefixes, cutoff proofs and dependency closure; reconstruct actual state before installation.
- [ ] Reuse retained historical keys. Request native phrase reentry only when required root-encrypted material was unavailable before phrase disposal.
- [ ] Keep current write activation governed by the existing explicit accepted-endpoint checks. History progress must not introduce a blanket history-before-writes rule.
- [ ] Call the desktop completion callback only after durable completion is verified, including after restart.

Preserve the existing limits: 4,096 history events/pages, applicable 64 MiB aggregate categories, 100,000 operations, one million dependencies and the 1 MiB checkpoint limit.

**Tests:** stale candidate, substituted hash, revoked historical author with valid historical authority, false checkpoint state, missing-key reentry, offline retry, interrupted installation, invalid receipt, keyboard operation and screen-reader status announcements.

### Task 4 — Complete hosted membership, synchronization and device lifecycle

**Deliverable:** actual authenticated Windows clients perform the complete lifecycle against deployed Supabase services.

- [ ] Finish production pairing, revocation, rotation and reassociation coordination using the accepted membership/control-history protocol.
- [ ] Propagate exact accepted tips, signed cutoffs and epoch material through production transport. Preserve parent/generation compare-and-swap and atomic event/member/head/receipt updates.
- [ ] Complete uploads, pulls, checkpoints, gap repair, quotas, Realtime reconnect/loss handling, offline convergence and account deletion through final purge.
- [ ] Test pending/revoked devices, retained children, stale sessions, competing rotations, delayed offline devices and old receipt replay.
- [ ] Replay all migrations on an isolated clean database and run handler-plus-adapter tests against real PostgreSQL.
- [ ] Build a reviewed deployment manifest listing exact migrations, function source identities, configuration names and rollback procedures. Preserve published migration files.
- [ ] Resolve the existing pairing-secret prerequisite through the permitted user action described in Section 5, then deploy reviewed migrations before their dependent functions.
- [ ] Verify deployed function and migration identities and run real Auth, Storage, Realtime and HTTP authorization tests.

Use actual client sessions for hosted acceptance. Stubbed Auth and local PostgreSQL fixtures remain component evidence. Realtime qualification must use supported policies and APIs; current Supabase restrictions prohibit arbitrary changes to its managed Realtime schema. [Supabase change notice](https://supabase.com/changelog/realtime-schema-locked-down-against-modification)

**Installed scenarios:** GitHub browser login and callback, refresh, restart, logout, cancellation, enrollment, second-device pairing, destroyed-vault recovery, reassociation, revocation, rotation, deletion grace/cancel/purge and cross-account rejection.

### Task 5 — Implement the separate GitHub App and complete package installation

**Deliverable:** selected repository content can be inspected and installed with exact-byte authorization.

**GitHub access:**

- [ ] Create the separate App with only Metadata read and Contents read.
- [ ] Bind installation access to verified GitHub identity plus live Context Relay account/device authorization. A callback-supplied installation ID is insufficient.
- [ ] Use expiring GitHub App user access tokens for user-initiated repository inspection/download, as explicitly approved on September 14, 2026. Verify the GitHub identity and current user-accessible installation/repository set, and fail closed if requested-repository narrowing is not established. This supersedes the original installation-token choice. [GitHub user access tokens](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app)
- [ ] Keep repository access and refresh tokens only in native memory; clear them on logout/disconnect/expiry/restart and never return them to React. Keep the authorization-code/refresh client secret in hosted secret storage. Distinguish local discard from provider token revocation and verify disconnect behavior.
- [ ] Persist installation IDs, repository IDs and metadata only. Reconcile `encrypted_token_reference` through an additive migration without storing access tokens.
- [ ] Resolve branches/tags to immutable commits and download archives directly from GitHub.

**Package processing:**

- [ ] Reuse existing package DTOs, immutable dependency descriptions, scanner runner, sealed setup plans, ownership tracking and transaction receipts.
- [ ] Add bounded quarantine and archive inspection. Use pinned `zip = 8.6.0`, with default features disabled and only the required Deflate reader support, because the workspace currently lacks a ZIP reader. [ZIP reader documentation](https://docs.rs/zip/8.6.0/zip/read/struct.ZipArchive.html)
- [ ] Reject traversal, absolute paths, ADS, normalized-name collisions, links, special files, overlapping entries, excessive expansion and unexpected executable payloads.
- [ ] Resolve the complete dependency closure before scanning or approval. Enforce the existing scanner/runner limits and fail clearly when a complete package exceeds them.
- [ ] Scan the exact installable bytes with Gitleaks and Semgrep.
- [ ] Bind approval to the full immutable closure, scan results, target configuration and native setup plan. Changes invalidate approval.
- [ ] Apply passive changes under existing policy. Require one exact yes/no approval for active or executable batches.
- [ ] Install approved active content disabled, verify installed bytes, run native validation, then enable.
- [ ] Preserve user data, credentials and unrelated dependencies during removal. Mutable-refetch CLIs remain manual-only.

**Tests:** selected public/private repositories, unselected denial, disconnect, token leakage, malicious archives, nested packages, dependency changes, scanner failure, missing license, secret canaries, approval expiry/change, rejection with zero native writes, partial CLI failure, running-harness refusal and safe removal.

### Task 6 — Finish desktop workflows and all three harness integrations

**Deliverable:** a user can complete onboarding and use the same project context in Claude Code, Codex and Hermes.

- [ ] Complete create/pair/recover onboarding, phrase confirmation, device naming, project mapping, import preview, active setup approval, validation, smoke tests and final health reporting.
- [ ] Complete harness cards with version/path, support level, access scopes, memory mode, conflicts, missing secrets, validation, sync health, repair and rollback.
- [ ] Finish side-by-side conflict resolution, manual merge and compensating-operation undo.
- [ ] Complete encrypted portable export/import and explicitly confirmed plaintext JSON/Markdown export. Preserve stable IDs, tombstones and provenance.
- [ ] Complete user-initiated redacted diagnostics, quota reporting and recovery/revocation/deletion warnings.
- [ ] Exercise actual current and previous supported harness installations. Unknown versions and unsupported wrappers remain import-only.
- [ ] Verify explicit memories, reviewed inferred/native-fallback memories, expected-revision conflicts, evidence-backed task completion, scoped access, handoffs and queue reconciliation.
- [ ] Verify that interrupted native setup resumes or rolls back exactly, and that reapplying an unchanged setup performs zero writes.

Reuse existing workspace, export, setup, history and native-memory paths. Extend their missing behavior without introducing parallel implementations.

### Task 7 — Close security, reliability, repository and licensing gates

**Deliverable:** independently reviewed boundaries with reproducible failure coverage and resolved release findings.

- [ ] Independently review recovery, enrollment, hosted authorization, IPC, native transactions, packages and updater behavior.
- [ ] Run five fuzz targets: canonical operations, JSON-RPC frames, package manifests, archive paths and native configuration parsers. Run each for four hours on qualified final source; preserve seeds, coverage, durations and crash artifacts.
- [ ] Use Windows sanitizer support with an isolated fuzz toolchain; keep the application’s pinned build toolchain unchanged. [Windows fuzzing setup](https://rust-fuzz.github.io/book/cargo-fuzz/windows/setup.html)
- [ ] Inject crashes at every durable transaction boundary and verify rollback/restart behavior.
- [ ] Test plaintext and secret canaries across vault side files, cloud payloads, logs, diagnostics, exports, crash output and native backups.
- [ ] Resolve dependency alert 23 through a compatible remediation. If remediation is unavailable, prepare fresh reachability evidence and a concrete time-bounded exception for explicit approval; no implicit waiver.
- [ ] Resolve the OpenSSL PDB packaging/linker issue or obtain an explicit evidence-backed disposition.
- [ ] Verify actual bundled licenses, notices, model licenses and Semgrep source/relinking obligations.
- [ ] Complete repository governance, fork-secret isolation, name clearance, privacy/terms documentation, deletion limitations and visible cloud-cost monitoring using unpaid resources.

### Task 8 — Produce the Windows candidate and qualify installation

**Deliverable:** a traceable current-source candidate and repeatable fresh-profile installation/upgrade evidence on this physical PC, with clean-OS limitations explicitly recorded.

- [ ] Qualify the preserved `1468327` installer and manifest as internal N-1.
- [ ] Use version `0.1.1` for candidate N so upgrade detection can distinguish it from installed version `0.1.0`; also record source SHA and artifact hashes.
- [ ] Complete updater signature verification and protected signing-key handling. Tauri updater signatures remain in scope; paid Authenticode enrollment remains deferred.
- [ ] Produce checksums, SPDX SBOM, provenance, updater metadata and the complete license/source-obligation bundle.
- [ ] Preserve the previous executable until migration and startup validation succeed. Use encrypted migration backups and exact rollback.
- [ ] Reject tampered binaries, manifests, signatures, models, sidecars and checksums.
- [ ] Prepare two dedicated Windows test-user identities on this PC, with separate per-user installations, vaults, IPC credentials, Auth sessions and enrolled device identities. Do not copy the normal user's profile or enrolled vault.
- [ ] Use fresh test-user pairs for the two acceptance passes. Record existing machine-wide runtimes, policies and dependencies; test-profile isolation cannot prove a clean OS has no hidden prerequisites.
- [ ] Perform native and accessibility checks through supported user interaction in these test accounts. Keep the user’s normal installed service and vault intact. Do not reinstall Windows, use ISO media, or start VMs.
- [ ] Record any original clean-OS or independent-host requirement that cannot be demonstrated on this PC as open, with its exact limitation. Do not convert that limitation into a release pass or an implicit waiver.

Native GUI steps require supported user interaction. Prepare exact installer hashes, instructions and evidence collection before requesting those actions.

## 4. Verification and acceptance gates

Each implementation task follows the same sequence: reproduce or add the meaningful failing check, implement the smallest complete fix, run focused coverage, inspect the full diff, resolve review findings and commit only reviewed source/evidence.

Run Cargo serially using the existing qualification environment. Never start an unconfigured production daemon or issue production `--shutdown` during tests.

**Immediate Task5 checks include:**

```text
cargo test -p context-relay-contextd --features test-support --lib recovery_enrollment::hosted_expiry_tests::hosted_restore_resumes_exact_claim_after_restart_without_reentering_phrase -- --nocapture
cargo test -p context-relay-core --features test-support --test recovery_restore_e2e_v2 -- --nocapture
cargo test -p context-relay-core --features test-support --lib devices::historical_crypto::tests::
pnpm generate:bindings
pnpm generate:schemas
pnpm check:bindings
pnpm check:schemas
pnpm typecheck
pnpm --filter @context-relay/desktop test --run
```

Run the complete applicable CI commands afterward, including ordinary-feature Rust tests/Clippy, protocol fixtures, Edge/PostgreSQL tests, native isolation, dependency/license gates and installer checks. Explicitly run required ignored release tests.

**Final matrix coverage:**

| Gate | Required Windows/shared evidence |
|---|---|
| **RB-REP** | Preserved history, Apache detection, complete notices/source obligations, fork-secret isolation, protected main/tags and dependency dispositions |
| **RB-CRYPTO** | Deterministic vectors, signed/AAD tampering, replay/substitution, phrase mutation, forks/gaps, control races, interrupted rotation, cutoffs and secret lifetime |
| **RB-LOCAL** | Wrong/missing key, migration crash, competing daemons, cross-user denial, invalid token, malformed/oversized frames, locked vault, MCP-write restart and plaintext scans |
| **RB-SYNC** | Real Auth/RLS/Storage/Realtime isolation, spoofed/pending/revoked devices, direct-write denial, reordered/dropped/replayed traffic, convergence, quotas and deletion through purge |
| **RB-NATIVE** | All three harness version matrices; policy, malformed files, concurrent edits, locks, disk/AV faults, Windows path/link/ACL cases, crash boundaries, exact rollback and zero-write reapply |
| **RB-PACKAGE** | Repository permissions, immutable closure, hostile archives, scanner failures, exact approval, rejected/expired batches, partial failure, disabled installation, validation, enablement and safe removal |
| **RB-MCP** | Explicit/inferred memory rules, project access, read-only restrictions, revision conflicts, completion evidence, secret-free handoffs, stdout purity, reconnect and offline convergence |
| **RB-RELEASE** | Complete onboarding and failure states, keyboard/screen-reader/contrast/reduced-motion checks, clean installation, qualified internal N-1 upgrade, updater tamper rejection, interrupted rollback and artifact scope |

Execute the complete applicable Windows acceptance matrix **twice using fresh isolated Windows test-user profiles on this physical PC**. Record the test-user, installation and device identities for each pass, plus shared host configuration. These runs establish physical-PC and fresh-profile behavior; they do not establish clean-OS or independent-hardware behavior. Keep any unsatisfied original requirement open and preserve the distinction in the acceptance dossier.

Measure on the installed candidate:

- Search P95 **below 150 ms** with 10,000 memories and the packaged production model/runtime. Report cold initialization separately.
- Online sync P95 **at most 10 seconds**, measured from a committed write becoming readable on the other device.
- Preserve raw measurements and environment details; do not reuse timings from injected-vector or older builds.

Any release-affecting change after qualification requires rerunning affected gates. A replacement final candidate must have its own artifact identity and acceptance evidence.

## 5. Deployment dependencies and final merge

**External actions must be concrete before requesting user participation.**

- Existing GitHub OAuth configuration is complete; do not request the same provider secret or redirect save again.
- Pairing requires `CONTEXT_RELAY_PAIRING_PEPPER`. The previous automatic approval review rejected its setup with only “blocked by policy.” Do not retry through another route. Prepare the secure dashboard procedure and verification first, then request the necessary user action without requesting or displaying the secret.
- Prepare GitHub App permissions, callbacks and secret-storage instructions before account-owner setup.
- Prepare installers and test procedures before requesting native UI, sign-in, accessibility or physical-device actions.
- If a required unpaid gate lacks resources or a permitted action, leave that gate open and continue independent work.

**Finalization sequence:**

1. Review the complete final Task5 diff from `f59c394`, including untracked source, then independently review subsequent subsystem changes.
2. Update Graphify after source changes. Stage explicit files; exclude incidental `.codex`, `AGENTS.md`, graph output and Python caches.
3. Record the approved deferral in CI and remove only these four required contexts: `Rust lint (macos-arm64)`, `Rust tests (macos-arm64)`, `Native build (macos-arm64)` and `native-isolation-macos-arm64`. Defer their Apple jobs without reporting them as passed.
4. Verify that the other 18 required contexts, strict freshness checks, review-thread resolution, linear history and no-force-push protections remain intact.
5. Push reviewed commits normally. Require current-head Windows/shared CI, applicable additional checks and the complete acceptance dossier to pass.
6. Reconcile every T01–T24 and matrix requirement to passed evidence or an explicitly authorized deferral. Local tests alone cannot close hosted or installed rows.
7. Rewrite PR16’s description around the final behavior, evidence and deferrals. Resolve every actionable review finding.
8. Squash-merge using the exact qualified PR head, matching the repository’s allowed merge method. Do not use owner bypass to avoid failed applicable gates.
9. Verify the merged commit, accepted source tree, resulting checks and post-merge dependency status. Preserve the distinction between the pre-merge artifact SHA and merged commit SHA.
10. Complete the full Context Relay task using its freshly retrieved task ID and bounded evidence. Close Task5 only when its hosted and installed requirements are satisfied. Preserve deferred Apple, paid-signing and dependent public-beta publication requirements separately.

**The end result is PR16 merged with fully evidenced Windows/shared acceptance, a qualified internal Windows candidate, and explicit deferred release obligations.**
