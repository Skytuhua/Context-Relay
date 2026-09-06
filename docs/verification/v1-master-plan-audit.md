# Context Relay v1 master-plan audit

This is the authoritative audit baseline for PR #12 at
`3c2a371aef74f4962af64d0fe71545557244f21a`, compared with base
`367b32e15d06a7d46b6b8d04676d38dc368ae235`. The v1 implementation plan remains
the product and security authority. The development report is a claims ledger:
counts and assertions from it are not verification unless a repository evidence
ledger below identifies the execution plane and its limitations.

Status meanings:

- `verified`: linked evidence verifies the stated, explicitly scoped requirement.
- `implemented-unverified`: implementation is present, but no authoritative execution evidence covers it.
- `partial`: only part of the requirement or required execution planes have evidence.
- `missing`: the required v1 capability or release evidence is absent.
- `amended`: a reviewed pre-release contract change supersedes the original wording.

Local evidence never implies hosted, credentialed, physical-device, signing, or
deployment evidence. A task is not release-complete while its next gate remains.

## Graph navigation baseline

The 2026-08-10 Graphify snapshot covers 453 supported files, 12,456 nodes,
39,200 post-build directed edges, and 427 communities. Integrity accounting also
found 1,792 dangling edges and 2,060 collapsed directed endpoint pairs. The graph
is a navigation aid, not proof of source, test, or release coverage; the evidence
links and gates below remain authoritative.

## Task and release-blocker matrix

| ID | Requirement | Implementation / evidence pointers | Status | Next gate |
| --- | --- | --- | --- | --- |
| T01 | Preserve public history and align the canonical repository without force-push. | [Tasks 1–10 ledger](tasks-1-10.md), [repository settings](../repository-settings.md) | partial | Audit the live remote, tracking branch, and protected history against the recorded base/head. |
| T02 | Add Apache-2.0 licensing and public-repository governance. | [LICENSE](../../LICENSE), [notices](../../THIRD_PARTY_NOTICES.md), [security policy](../../SECURITY.md), [secret-scan exception rationale](../security/secret-scan-exceptions.md), [Tasks 1–10 ledger](tasks-1-10.md) | partial | Verify GitHub license detection, push protection, branch/tag protection, fork-secret isolation, and name clearance live. |
| T03 | Establish the pinned Rust/Tauri workspace and fully pinned CI. | [PR #12 stabilization ledger](pr-12-stabilization.md), [dependency-alert recovery](dependency-alerts-2026-08-10.md), [CI workflow](../../.github/workflows/ci.yml), [independent-gate contract](../../scripts/ci-gates-workflow.test.mjs), [A-004 feature-scope amendment](../protocols/contract-amendments.md), [workspace manifest](../../Cargo.toml), [Tasks 1–10 ledger](tasks-1-10.md) | partial | Run every independent gate remotely on Windows x64 and macOS arm64, then clear all remaining public CI failures without skipped required checks. |
| T04 | Freeze protocol v1 and the threat model. | [Protocol 1.5](../protocols/protocol-v1.md), [canonical CBOR](../protocols/cbor-v1.md), [threat model](../security/threat-model.md), [amendments](../protocols/contract-amendments.md) | amended | Ratify all recorded amendments together and rerun cross-platform protocol/binding fixtures. |
| T05 | Implement recovery/device cryptography and fixed vectors. | [crypto implementation](../../crates/core/src/crypto.rs), [pairing evidence](task-17-pairing.md), [recovery evidence](task-17-recovery-enrollment.md) | verified | Repeat vectors and secret-lifetime checks on supported Windows and macOS release machines. |
| T06 | Provide a SQLCipher vault and local hybrid search. | [vault implementation](../../crates/core/src/vault.rs), [search implementation](../../crates/core/src/search.rs), [Tasks 1–10 ledger](tasks-1-10.md) | verified | Exercise Keychain/Credential Manager loss and the 10,000-record P95 gate on supported physical machines. |
| T07 | Run one daemon writer behind authenticated per-user local IPC. | [daemon](../../crates/contextd/src/lib.rs), [local IPC](../../crates/local-ipc/src/lib.rs), [Task 14 evidence](task-14.md), [Windows concurrency repair](pr-12-stabilization.md#windows-follow-up-2026-08-31) | partial | Pass the repaired busy-pipe and 64-call/cancellation gates in Windows CI, then repeat cross-user denial, crash/restart, and 8 MiB frame gates on physical Windows and macOS. |
| T08 | Deliver the complete offline desktop workspace. | [desktop](../../apps/desktop/src/App.tsx), [offline tests](../../apps/desktop/src/offline-workflow.test.tsx), [Tasks 1–10 ledger](tasks-1-10.md) | verified | Perform physical keyboard, screen-reader, renderer-plaintext, and network-disabled acceptance on both platforms. |
| T09 | Isolate RuleSync/scanners and apply native changes transactionally. | [native runner](../../crates/native-runner/src/lib.rs), [native transaction tests](../../crates/core/tests/native_transaction_v1.rs), [Tasks 1–10 ledger](tasks-1-10.md) | partial | Complete deferred Task 9R and native sidecar/network/filesystem qualification on both release OSes. |
| T10 | Implement the Claude Code adapter. | [capability contract](../../adapters/claude-code/capabilities.md), [adapter tests](../../crates/core/tests/claude_code_adapter_v1.rs), [Tasks 1–10 ledger](tasks-1-10.md) | verified | Validate current/previous/unknown and rollback behavior against real supported installations on both OSes. |
| T11 | Implement the Codex adapter. | [Task 11 ledger](task-11.md), [capability contract](../../adapters/codex/capabilities.md), [adapter tests](../../crates/core/tests/codex_adapter_v1.rs) | partial | Execute the current/previous/unknown, wrapper, precedence, NTFS owner-only ACL, and exact rollback matrix on clean macOS arm64 and Windows x64 hosts. |
| T12 | Implement the Hermes adapter. | [Task 12 ledger](task-12.md), [capability contract](../../adapters/hermes/capabilities.md), [adapter tests](../../crates/core/tests/hermes_adapter_v1.rs) | partial | Execute the real profile, gateway, secret-redaction, permission-loss, crash-recovery, and rollback matrix on clean macOS arm64 and Windows x64 hosts; wrapper and PE/MZ installs remain import-only until their complete runtime closure is authenticated. |
| T13 | Expose scoped MCP memory, tasks, and handoffs. | [Task 13 ledger](task-13.md), [MCP server](../../crates/context-mcp/src/server.rs), [MCP end-to-end tests](../../crates/context-mcp/tests/end_to_end_v1.rs), [protocol 1.4 amendment](../protocols/contract-amendments.md) | partial | Repeat the complete MCP/daemon/adapter matrix against physical macOS arm64 and Windows x64 installs, including locked recovery, multi-profile Hermes, stdout capture, and offline convergence. |
| T14 | Make Context Relay authoritative memory for all three harnesses. | [Task 14 ledger](task-14.md), [native-memory core](../../crates/core/src/native_memory/mod.rs) | verified | Repeat the verified local chain against physical supported harness installations and current public CI. |
| T15 | Create the hosted Supabase schema, RLS, Storage, and Realtime boundary. | [Task 15 ledger](task-15.md), [migrations](../../supabase/migrations/20260804000000_context_relay_ciphertext_boundary.sql) | partial | Run credentialed Storage HTTP, private two-user Realtime, hosted JWT-setting, and GitHub OAuth checks. |
| T16 | Implement signed synchronization through the real hosted provider. | [Task 16 ledger](task-16.md), [local sync engine](../../crates/core/src/sync/engine.rs), [Supabase transport](../../crates/core/src/sync/supabase.rs), [hosted admission migration](../../supabase/migrations/20260810070712_signed_sync_cloud_admission.sql) | partial | Apply the migration only after explicit approval, connect the transport after Task 17 provides daemon-owned authenticated sessions, and prove credentialed multi-device upload, repair, checkpoint, quota, Realtime-loss, and canary behavior. |
| T17 | Complete pairing, recovery, reassociation, revocation, rotation, and deletion. | [pairing](task-17-pairing.md), [enrollment](task-17-recovery-enrollment.md), [fresh recovery core](task-17-fresh-install-recovery-core.md) | partial | Add native phrase entry, production provider transports, reassociation, revocation/rotation, and end-to-end deletion/export. |
| T18 | Add the read-only GitHub App and repository identity. | Product identity primitives exist in [domain protocol](../../crates/protocol/src/domain.rs); no production GitHub App client is present. | missing | Configure the least-privilege GitHub App and prove selected/private denial and memory-only token handling. |
| T19 | Inspect packages and require exact active-setup approval. | DTO/schema groundwork: [package schema](../../schemas/context-relay-package-v1.json), [package protocol](../../crates/protocol/src/packages.rs). | missing | Build quarantine, dependency closure, exact-byte scanners, approval invalidation, disabled install, native validation, and attack fixtures. |
| T20 | Complete onboarding and one-click harness setup. | Guided project-folder setup, atomic project registration and harness discovery are implemented; installed verification of the revised UI remains pending. See [Windows acceptance](windows-app-release.md). | partial | Implement and physically verify both-platform create, pair/recover, import, approval, smoke-test, resume, and rollback flows. |
| T21 | Add conflict UI, history, export, and diagnostics. | Export DTO groundwork exists in [export schema](../../schemas/context-relay-export-v1.json); complete product surfaces are absent. | missing | Implement conflict resolution, compensating undo, encrypted/plaintext export, import, and redacted diagnostics with canary tests. |
| T22 | Ship signed Windows/macOS installers and updates. | Unsigned Windows NSIS candidates build locally and in CI; earlier installed versions pass ordinary install and running-service update. [Windows acceptance](windows-app-release.md) distinguishes source, candidate and installed evidence. | partial | Add protected signing, notarization, updater signatures, SBOM/provenance, N-1 migration, and tamper/interruption tests; qualify and publish both-platform releases. |
| T23 | Complete independent release security/reliability hardening. | Slice reviews are recorded in Tasks 15–17 and the [dependency-alert recovery ledger](dependency-alerts-2026-08-10.md) records the current candidate Node repair plus the still-open Linux-only Rust alert. No whole-product release review/fuzz/fault/license/privacy gate exists. | missing | Run the full independent review, fuzz duration, durable-boundary crash matrix, license inventory, and policy review with no high findings; resolve or explicitly approve the time-bounded unreachable-target Rust alert. |
| T24 | Pass personal-alpha and public-beta gates. | The product is explicitly not deployed or released; no signed release checklist exists. | missing | Pass the full physical matrix twice from clean machines and record the signed checklist in the protected release tag. |
| RB-REP | Release blockers: repository and licensing. | [Tasks 1–10 ledger](tasks-1-10.md), [dependency-alert recovery](dependency-alerts-2026-08-10.md), [notices](../../THIRD_PARTY_NOTICES.md), [repository settings](../repository-settings.md) | partial | Verify every license, fork-secret, `main`, and `v*` protection gate live; confirm npm alerts close after merge, resolve or explicitly approve the unreachable-target Rust alert, and clear all public CI/security alerts. |
| RB-CRYPTO | Release blockers: cryptography and devices. | [Task 16 ledger](task-16.md), [pairing](task-17-pairing.md), [recovery](task-17-fresh-install-recovery-core.md) | partial | Add physical cross-platform vectors, hosted device lifecycle, revocation cutoff, epoch rotation, and interrupted-rotation proof. |
| RB-LOCAL | Release blockers: local storage and IPC. | [Tasks 1–10 ledger](tasks-1-10.md), [Task 14 ledger](task-14.md), [local IPC tests](../../crates/local-ipc/tests/ipc_v1.rs) | partial | Run the complete wrong/missing-key, migration-crash, cross-user, malformed-frame, restart, and plaintext scan matrix on both OSes. |
| RB-SYNC | Release blockers: synchronization and Supabase. | [Task 15 ledger](task-15.md), [Task 16 ledger](task-16.md) | partial | Prove real hosted Storage/Realtime/auth, offline convergence, quota, deletion lifecycle, provider metadata, and backup-limit documentation. |
| RB-NATIVE | Release blockers: adapters and native files. | [Tasks 1–10 ledger](tasks-1-10.md), [native runner tests](../../crates/native-runner/tests/portable_policy_v1.rs), Codex/Hermes test pointers above | partial | Run every master-plan fixture on both filesystems/OSes, including locks, disk/AV faults, path edge cases, crash steps, exact rollback, and zero-write reapply. |
| RB-PACKAGE | Release blockers: packages and setup. | Only [package schema](../../schemas/context-relay-package-v1.json) and protocol bounds exist. | missing | Implement and pass every public/private repository, archive, scanner, approval, CLI failure, enablement, and removal case. |
| RB-MCP | Release blockers: memory, tasks, and MCP. | [Task 14 ledger](task-14.md), [MCP end-to-end tests](../../crates/context-mcp/tests/end_to_end_v1.rs) | partial | Prove all access, conflict, evidence, stdout, restart, three-harness, and offline hosted-convergence cases on physical installs. |
| RB-RELEASE | Release blockers: desktop and releases. | [desktop tests](../../apps/desktop/src/App.test.tsx); Tasks 20–24 have no release evidence. | partial | Pass onboarding/state/accessibility plus signed clean install, N-1 update, tamper rejection, interruption rollback, and artifact-scope gates. |

## Baseline disposition

Tasks 18–24 are not complete. Public CI, credentialed hosted transports,
physical-device coverage, package installation, release signing/notarization,
revocation/rotation/deletion, and beta readiness remain release-blocking. Future
claims must update this matrix and the linked evidence ledger in the same
change; a test count alone does not change a status.

2026-09-05 Codex qualification update: isolated 0.144.6 app-server reads reproduce trusted-project memory overrides and native hook trust remaining untrusted. The adapter now plans and revalidates active project memory settings with exact rollback coverage. This does not complete T11/T20: full real CLI setup/rollback must account for MCP rewriting the same global config file, native hook trust/execution, installed acceptance and durable setup recovery. See the [Windows acceptance evidence](windows-app-release.md).

2026-09-06 Claude qualification update: real pinned 2.1.202 startup now executes
the production-generated Windows hook in default and custom configurations,
including special-character executable paths. The actual home is separately
bound into execution, approval and recovery. This does not complete T10/T14/T20:
effective memory settings/root selection, Stop delivery, full native setup and
installed recovery remain open. The [Claude evidence](claude-native-mcp-2026-09-06.md)
records the scoped tests and the macOS recovery-fixture CI correction.

2026-09-06 first-use update: the desktop now orders project creation, context
capture and harness connection, uses grouped navigation and preserves distinct
Undo targets for repeated connections. All 140 frontend tests, type checking,
lint and the production build pass. Isolated headless Edge checks cover desktop
and narrow layouts; [the evidence](first-use-ui-2026-09-06.md) distinguishes this
from installed acceptance. T08/T20 and the broader product goal are not closed
by these frontend checks. The macOS recovery fixture correction passed hosted
Rust tests in CI run 33989730248.

2026-09-06 configured-directory update: Claude's explicit memory path rules now
match pinned string-helper evidence, including home expansion, relative fallback
and normalization before applying adapter limits. Ancestor checks cover memory
bindings; POSIX symlink execution still needs CI. Local checks pass 100 core,
51 Claude adapter and 11 primary-memory tests. The [Claude evidence](claude-native-mcp-2026-09-06.md)
keeps effective settings precedence, default repository/worktree selection and
full native/installed connection acceptance open; T10/T14/T20 are not completed.

2026-09-06 file-settings update: Claude now reads user/project/local memory
settings, targets effective local overrides and seals/rechecks file dependencies
through Full setup and undo. Windows missing-root identity and recovery metadata
template regressions are corrected. Local checks pass 100 core, 58 Claude adapter
and 11 primary-memory tests. The [Claude evidence](claude-native-mcp-2026-09-06.md)
retains runtime trust/flags/environment, other managed sources,
repository/worktree defaults and full installed
qualification as open. T10/T14/T20 remain incomplete and the installer is unchanged.

2026-09-06 registration follow-up: ImportOnly plans now seal memory-setting
dependencies and revalidate current installation and exact sources at apply or
explicit resume. Startup does not publish an unverified interrupted registration.
The production verifier launches no harness, proven by a twelve-case isolated
canary. All 322 selected core tests and 59 daemon tests pass. The
[registration evidence](read-only-memory-registration-2026-09-06.md) retains Full
connection and installed acceptance as open; T10/T14/T20 are not completed.

2026-09-06 default-root update: Claude memory lookup now follows the pinned
repository/worktree helper, with 16 native vectors per platform and live source
revalidation. Local checks pass 104 core library, 60 Claude adapter and 16 memory
setup tests. The macOS registration canary passed; a stale watcher integration
fixture was corrected and its four tests pass locally. The [Claude evidence](claude-native-mcp-2026-09-06.md)
and [registration evidence](read-only-memory-registration-2026-09-06.md) retain
session settings, full native setup/recovery and installed acceptance as open.
T10/T14/T20 remain incomplete; no additional harness version is enabled.

2026-09-06 native-session update: twenty actual noninteractive Claude sessions
pass against a loopback model stub, verifying selected memory roots and generated
startup/Stop hook delivery. A settings-provided environment override that defeated
native-memory disable is now handled transactionally, including Windows casing
and exact Undo. Local checks pass 104 core library, 63 adapter and 16 setup tests.
The [Claude evidence](claude-native-mcp-2026-09-06.md) retains interactive/runtime
settings, production bridge delivery, full setup/recovery and installed acceptance
as open. T10/T14/T20 and the full product goal remain incomplete.

2026-09-06 Codex writer update: fixed managed bridge setup composes MCP and
global memory settings into one native write, preserving exact approvals and
Undo. Real 0.144.6 configuration readback matches the official CLI in synthetic
profiles. The [Codex evidence](codex-staged-generation-2026-09-06.md) records the
Windows path-resolution diagnosis, native transaction coverage and remaining
hook/bridge/installed qualification. The obsolete generator requirement is
superseded, without weakening native CAS or sandbox boundaries. No additional
Full version is enabled; T10/T14/T20 remain incomplete.


2026-09-06 Codex lifecycle update: Windows hook commands now use PowerShell
invocation and escape all single-quote delimiters. The [native evidence](codex-native-hooks-2026-09-06.md)
records 24 actual CLI/app-server sessions with synthetic hooks, exact trust and
modified-definition rejection. The obsolete daemon test wrapper now exercises
the current native writer. Product trust review, production bridge delivery,
custom runtime settings and installed acceptance remain open. No Full version
is enabled; T10/T14/T20 and the full product goal remain incomplete.

2026-09-06 setup status update: the desktop's apply result says settings were
saved and explains the Codex CLI trust-review step without asserting a verified
connection. The [evidence](harness-setup-status-2026-09-06.md) covers 143 frontend
tests, desktop/narrow browser checks and an expanded 32-session native matrix
with default-enabled and explicitly disabled hooks. Native trust readback,
production bridge delivery and installed acceptance remain required.

2026-09-06 MCP discovery update: actual Codex sessions missed three tools after
the old first page. The bridge now advertises all eleven; [native qualification](codex-mcp-roundtrip-2026-09-06.md)
passes memory and task exchanges on CLI/app-server with production dispatch,
isolated authenticated IPC and daemon-restart persistence. The 66-test MCP suite
and all-target Clippy pass. Installed process/credential binding, full native
setup and effective trust readback remain open; this does not enable a Full version.
