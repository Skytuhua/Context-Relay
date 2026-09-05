# Windows app release acceptance

User objective (2026-09-05): deliver an `.exe` with everything working as originally intended. A source archive, a bare GUI executable, or a passing build alone does not satisfy this objective.

This ledger supplements the [v1 master-plan audit](v1-master-plan-audit.md); it does not retire its requirements. Existing specifications, protocol boundaries, encryption guarantees, native approval rules, and cross-platform regression requirements remain authoritative.

## Acceptance map

| Requirement | Current evidence | Remaining acceptance |
| --- | --- | --- |
| Downloadable Windows x64 installer | Source-only alpha has no assets; base Tauri bundling disabled. | Reproducible NSIS `.exe`, verified contents, signatures/provenance/checksums, attached to a release. |
| Clean installation and launch | Shared IPC already starts the adjacent daemon and waits for the authenticated endpoint. | Include desktop, daemon, bridge, native helper and runtime resources; install without Rust/Node/source checkout; launch and reopen successfully under a normal Windows user. |
| Durable local workspace | Core and frontend tests cover projects, memory, review, tasks. | Exercise these flows through the installed app, including restart, offline operation, invalid input, conflicts, and credential failure. |
| Semantic memory search | BGE verifier/engine exists, but `OfflineWorkspace` uses token-hash vectors in `text_embedding`. | Wire the intended pinned model/runtime into production search, verify offline asset integrity and semantic retrieval with relevant paraphrases, and pass the specified latency/scale gates. |
| Harness setup and shared memory | Three adapters, preview/apply/rollback and MCP services exist. Desktop now exposes project/profile selection, reviewed setup and session rollback. | Real supported-installation tests; standalone probe/repair; durable UI resume/history; import, round-trip memory/tasks and rollback. |
| Login, hosted sync and device lifecycle | Production daemon lacks pairing/recovery provider injection; account lifecycle routes return unavailable. A WIP branch contains partial lifecycle code. | Complete production authentication, provider wiring, two-device sync, pairing, recovery, reassociation, revocation/rotation and deletion/export; verify hosted policies and recovery failure cases. |
| Packages and repository identity | Protocol/schema groundwork; full product flows absent. | GitHub integration, quarantine/scanning, exact approval, install/remove and attack fixtures from T18–19. |
| Onboarding and product surfaces | Offline shell exists; several screens are descriptive placeholders. | Complete T20–21 onboarding, history/conflicts, export/import and redacted diagnostics; all visible controls must work. |
| Qualified native runtime | Ordinary native CI passes; independent release qualification/publication incomplete. | Produce and verify required runtime closures, licenses and source obligations; bundle or install from trusted pinned assets without developer tooling. |
| Install/update/uninstall lifecycle | No installer lifecycle evidence. | Clean user install, running-daemon update, preserved vault, interrupted update, tamper rejection, uninstall with explicit data retention/deletion behavior. |
| Release assurance | PR #12 tree passed CI; exact post-squash literal fix is PR #15. | Current full CI, independent review, clean-machine and physical acceptance, accessibility, release security/reliability requirements in T22–24. |

## Execution sequence

1. Establish and test the Windows package assembly and actual NSIS build. Treat its output as an internal candidate until the rest of this ledger passes.
2. Complete first-run and harness setup from the existing native transaction APIs, keeping user approval bound to the real preview.
3. Review and recover useful account-lifecycle WIP changes, then complete authenticated production sync, pairing and recovery.
4. Complete repository/package, conflict/history, export/diagnostic and settings workflows against the original contracts.
5. Qualify all runtime assets and exercise the installed product through clean install, restart, offline, update, failure and uninstall paths.
6. Run independent release review and publish the verified installer with truthful evidence. Do not silently replace or retag the existing source-only alpha.

## Decisions and limits

- The user's approval authorizes implementation and preparing the usable release. Routine reversible implementation decisions do not require another confirmation.
- Windows x64 NSIS is the requested deliverable; existing macOS compatibility and specified cross-platform evidence are preserved.
- Use the existing adjacent-daemon startup code; do not duplicate daemon ownership in the GUI.
- No credential, hosted deployment, signing identity, or clean-machine test is claimed without direct evidence.
- Preserve unrelated untracked workspace files and the historical reviewed branches.

## Progress

2026-09-05: inspected current tree and live release/CI state. Corrected the initial assumption that daemon autostart was absent: it exists in `crates/local-ipc/src/connection.rs`. The immediate distribution defect is that the required sibling executables are not packaged. Installer assembly work starts on `codex/windows-app-release`, based on the reviewed PR #15 fingerprint fix.

2026-09-05: restored the existing Context Relay hosted project `brvzuycnxoswdzzipgvx` on its verified free organization plan. The control plane now reports `ACTIVE_HEALTHY`. Read-only inspection found only migrations `20260805153409` and `20260805155753`, and no deployed Edge Functions. No new project, subscription, migration, or credential was created. Production cloud deployment and wiring remain incomplete.

2026-09-05: installer assembly implementation has nine passing staging tests and validates against the installed Tauri 2.8.4 schema. The actual MSVC release build is in progress. The target directory contained an old July desktop executable; that artifact is not accepted as a build of the current source.

2026-09-05: the user confirmed there is no Windows signing certificate or signing service. Continue unsigned build and installation testing; publisher signing remains an explicitly unresolved release item, not a reason to stop implementation. No certificate purchase is authorized.

2026-09-05: corrected a Windows project-path encoding defect that discarded low UTF-16 surrogates (for example in emoji). A gateway regression test first reproduced the defect; all four path cases now pass, including CJK, supplementary characters, lone surrogates, and unchanged macOS UTF-8. The full frontend suite passes 58 tests, type checking and lint. Independent read-only review approved both the assembly slice and the path fix with no actionable findings. Installed-app verification remains pending.

2026-09-05: the initial MSVC companion build completed successfully in 19m03s, with vendored OpenSSL missing-debug-PDB linker warnings. `dumpbin /dependents` found an undeclared `VCRUNTIME140.dll` dependency in the bridge executable. The package command now enforces static CRT linkage for every target crate; a new build and subsequent dependency inspection are required. The first successful compile is not accepted as a redistributable candidate.

2026-09-05: implemented the bounded harness screen plan in `docs/superpowers/plans/2026-09-05-harness-setup-screen.md`. All 31 focused harness tests and all 89 frontend tests pass; type checking/lint pass. Independent review approved the slice. Navigation invalidates preview approval while retaining pending apply results and acknowledged rollback records. Those rollback records remain in memory for the current app session; a durable listing/resume route and real-installation verification are still required.

2026-09-05: added a separate read-only Windows candidate workflow with pinned actions, staging tests, locked builds and installer/executable checksums. Hosted execution has not yet occurred. Existing workflow policy checks pass 7 cases; the unrelated committed-whitespace fixture cannot start its hardcoded `/bin/bash` on this Windows host. Direct `git diff --check` passes. Independent review approved the workflow and static CRT environment handling; all 12 packaging tests pass. The rebuilt bridge has no VCRUNTIME DLL import according to `dumpbin`; the daemon and final desktop/installer build are still pending.
