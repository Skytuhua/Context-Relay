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
| T04 | Freeze protocol v1 and the threat model. | [Protocol 1.4](../protocols/protocol-v1.md), [canonical CBOR](../protocols/cbor-v1.md), [threat model](../security/threat-model.md), [amendments](../protocols/contract-amendments.md) | amended | Ratify all recorded amendments together and rerun cross-platform protocol/binding fixtures. |
| T05 | Implement recovery/device cryptography and fixed vectors. | [crypto implementation](../../crates/core/src/crypto.rs), [pairing evidence](task-17-pairing.md), [recovery evidence](task-17-recovery-enrollment.md) | verified | Repeat vectors and secret-lifetime checks on supported Windows and macOS release machines. |
| T06 | Provide a SQLCipher vault and local hybrid search. | [vault implementation](../../crates/core/src/vault.rs), [search implementation](../../crates/core/src/search.rs), [Tasks 1–10 ledger](tasks-1-10.md) | verified | Exercise Keychain/Credential Manager loss and the 10,000-record P95 gate on supported physical machines. |
| T07 | Run one daemon writer behind authenticated per-user local IPC. | [daemon](../../crates/contextd/src/lib.rs), [local IPC](../../crates/local-ipc/src/lib.rs), [Task 14 evidence](task-14.md) | verified | Repeat cross-user denial, crash/restart, and 8 MiB frame gates on physical Windows and macOS. |
| T08 | Deliver the complete offline desktop workspace. | [desktop](../../apps/desktop/src/App.tsx), [offline tests](../../apps/desktop/src/offline-workflow.test.tsx), [Tasks 1–10 ledger](tasks-1-10.md) | verified | Perform physical keyboard, screen-reader, renderer-plaintext, and network-disabled acceptance on both platforms. |
| T09 | Isolate RuleSync/scanners and apply native changes transactionally. | [native runner](../../crates/native-runner/src/lib.rs), [native transaction tests](../../crates/core/tests/native_transaction_v1.rs), [Tasks 1–10 ledger](tasks-1-10.md) | partial | Complete deferred Task 9R and native sidecar/network/filesystem qualification on both release OSes. |
| T10 | Implement the Claude Code adapter. | [capability contract](../../adapters/claude-code/capabilities.md), [adapter tests](../../crates/core/tests/claude_code_adapter_v1.rs), [Tasks 1–10 ledger](tasks-1-10.md) | verified | Validate current/previous/unknown and rollback behavior against real supported installations on both OSes. |
| T11 | Implement the Codex adapter. | [Task 11 ledger](task-11.md), [capability contract](../../adapters/codex/capabilities.md), [adapter tests](../../crates/core/tests/codex_adapter_v1.rs) | partial | Execute the current/previous/unknown, wrapper, precedence, NTFS owner-only ACL, and exact rollback matrix on clean macOS arm64 and Windows x64 hosts. |
| T12 | Implement the Hermes adapter. | [Task 12 ledger](task-12.md), [capability contract](../../adapters/hermes/capabilities.md), [adapter tests](../../crates/core/tests/hermes_adapter_v1.rs) | partial | Execute the real profile, gateway, secret-redaction, permission-loss, crash-recovery, and rollback matrix on clean macOS arm64 and Windows x64 hosts; wrapper and PE/MZ installs remain import-only until their complete runtime closure is authenticated. |
| T13 | Expose scoped MCP memory, tasks, and handoffs. | [Task 13 ledger](task-13.md), [MCP server](../../crates/context-mcp/src/server.rs), [MCP end-to-end tests](../../crates/context-mcp/tests/end_to_end_v1.rs), [protocol 1.4 amendment](../protocols/contract-amendments.md) | partial | Repeat the complete MCP/daemon/adapter matrix against physical macOS arm64 and Windows x64 installs, including locked recovery, multi-profile Hermes, stdout capture, and offline convergence. |
| T14 | Make Context Relay authoritative memory for all three harnesses. | [Task 14 ledger](task-14.md), [native-memory core](../../crates/core/src/native_memory/mod.rs) | verified | Repeat the verified local chain against physical supported harness installations and current public CI. |
| T15 | Create the hosted Supabase schema, RLS, Storage, and Realtime boundary. | [Task 15 ledger](task-15.md), [migrations](../../supabase/migrations/20260804000000_context_relay_ciphertext_boundary.sql) | partial | Run credentialed Storage HTTP, private two-user Realtime, hosted JWT-setting, and GitHub OAuth checks. |
| T16 | Implement signed synchronization through the real hosted provider. | [Task 16 ledger](task-16.md), [local sync engine](../../crates/core/src/sync/engine.rs) | partial | Implement/deploy the Supabase transport and prove credentialed multi-device upload, repair, checkpoint, quota, and canary behavior. |
| T17 | Complete pairing, recovery, reassociation, revocation, rotation, and deletion. | [pairing](task-17-pairing.md), [enrollment](task-17-recovery-enrollment.md), [fresh recovery core](task-17-fresh-install-recovery-core.md) | partial | Add native phrase entry, production provider transports, reassociation, revocation/rotation, and end-to-end deletion/export. |
| T18 | Add the read-only GitHub App and repository identity. | Product identity primitives exist in [domain protocol](../../crates/protocol/src/domain.rs); no production GitHub App client is present. | missing | Configure the least-privilege GitHub App and prove selected/private denial and memory-only token handling. |
| T19 | Inspect packages and require exact active-setup approval. | DTO/schema groundwork: [package schema](../../schemas/context-relay-package-v1.json), [package protocol](../../crates/protocol/src/packages.rs). | missing | Build quarantine, dependency closure, exact-byte scanners, approval invalidation, disabled install, native validation, and attack fixtures. |
| T20 | Complete onboarding and one-click harness setup. | Offline shell and device screens exist in [desktop](../../apps/desktop/src/App.tsx); the required end-to-end onboarding sequence does not. | missing | Implement and physically verify both-platform create, pair/recover, import, approval, smoke-test, resume, and rollback flows. |
| T21 | Add conflict UI, history, export, and diagnostics. | Export DTO groundwork exists in [export schema](../../schemas/context-relay-export-v1.json); complete product surfaces are absent. | missing | Implement conflict resolution, compensating undo, encrypted/plaintext export, import, and redacted diagnostics with canary tests. |
| T22 | Ship signed Windows/macOS installers and updates. | No release/updater workflow or signing/notarization evidence exists. | missing | Add protected signing, notarization, updater signatures, SBOM/provenance, N-1 migration, and tamper/interruption tests. |
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
