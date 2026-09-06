# Windows app release acceptance

Current user feedback (2026-09-05): connecting AI apps and creating projects,
context or tasks failed during their own EXE test, and the interface was too
hard to understand. Usability and successful ordinary-user workflows are release
requirements. Passing source tests alone does not resolve this report.

User objective (2026-09-05): deliver an `.exe` with everything working as originally intended. A source archive, a bare GUI executable, or a passing build alone does not satisfy this objective.

This ledger supplements the [v1 master-plan audit](v1-master-plan-audit.md); it does not retire its requirements. Existing specifications, protocol boundaries, encryption guarantees, native approval rules, and cross-platform regression requirements remain authoritative.

## Acceptance map

| Requirement | Current evidence | Remaining acceptance |
| --- | --- | --- |
| Downloadable Windows x64 installer | Locked NSIS candidates built locally and in CI; normal Explorer installation tested. Existing source-only alpha still has no assets. | Full release qualification, signatures/provenance/checksums, attached to a release. |
| Clean installation and launch | Normal Explorer installation, Finish-page launch and a cold reopen start the adjacent daemon and unlock the vault. All five installed executables verified against the build, accounting for Tauri's NSIS marker. | Clean-machine qualification without developer tools; broader runtime and first-run acceptance below. |
| Durable local workspace | Installed GUI/MCP checks cover Unicode project creation, memory creation/search/edit, candidate review, task start/completion and persistence through restart/update. | Broader offline operation, invalid input, conflicts, credential failure and scale checks. |
| Semantic memory search | BGE verifier/engine exists, but `OfflineWorkspace` uses token-hash vectors in `text_embedding`. | Wire the intended pinned model/runtime into production search, verify offline asset integrity and semantic retrieval with relevant paraphrases, and pass the specified latency/scale gates. |
| Harness setup and shared memory | Three adapters, preview/apply/rollback and MCP services exist. Desktop exposes project/profile selection, reviewed setup and session rollback. Read-only probe routing and capability display are implemented and tested in source. Codex memory settings include active project overrides and reject late drift. | Rebuilt installed discovery verification; real supported-installation setup/rollback, including MCP CLI rewrites of the same config file; native hook trust and execution; repair; durable UI resume/history; native import and harness session memory/tasks. |
| Login, hosted sync and device lifecycle | Production daemon lacks pairing/recovery provider injection; account lifecycle routes return unavailable. A WIP branch contains partial lifecycle code. | Complete production authentication, provider wiring, two-device sync, pairing, recovery, reassociation, revocation/rotation and deletion/export; verify hosted policies and recovery failure cases. |
| Packages and repository identity | Protocol/schema groundwork; full product flows absent. | GitHub integration, quarantine/scanning, exact approval, install/remove and attack fixtures from T18–19. |
| Onboarding and product surfaces | Offline shell exists; several screens are descriptive placeholders. | Complete T20–21 onboarding, history/conflicts, export/import and redacted diagnostics; all visible controls must work. |
| Qualified native runtime | Ordinary native CI passes; independent release qualification/publication incomplete. | Produce and verify required runtime closures, licenses and source obligations; bundle or install from trusted pinned assets without developer tooling. |
| Install/update/uninstall lifecycle | Current-user normal installation, cold restart and running-daemon update pass; completed task and memory survive. Uninstall UI is blocked by Computer Use policy. | Clean-machine installation, interrupted update, tamper rejection, uninstall with explicit data retention/deletion behavior. |
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

2026-09-05, installed-product testing: the locked static-CRT package build completed, and Windows candidate workflow `33959064275` passed. All five installed executables matched their build hashes; the desktop is AMD64 Windows GUI and the companions have no VCRUNTIME import. This is current-user testing, not clean-machine qualification. The initial installed desktop was observed stuck on Connecting with no daemon running. Starting the installed daemon manually and reopening the desktop restored access; a subsequent launch with the daemon stopped successfully auto-started it. The initial native startup failure remains unrooted. Code inspection and regression tests established that startup errors disappeared on navigation and that an unresolved startup had no deadline or recovery control.

2026-09-05, startup recovery: commit `95d0064` adds a persistent connection failure, a 45-second bound on startup reads, and a Retry connection control that ignores late results and preserves the current form. It also accepts the surrounding quotes produced by Windows Copy as path while preserving UTF-16 and macOS path behavior. Three new regression cases failed before implementation; all 93 frontend tests, type checking and lint pass afterward. Independent review approved this scoped fix. This improves recovery and path input; it is not evidence that the original intermittent native failure is fixed.

2026-09-05, real local persistence: through the installed GUI, created the synthetic project `Installer verification 專案 🚀` bound to `.codex/installer-smoke-專案-🚀`, saved `Installer smoke memory`, and saved the task `Verify installer restart`. The installed MCP executable, launched with that repository as its working directory, authenticated, resolved the same project, retrieved the memory via search, and listed the task. Scratch verification: `.codex/context-relay-closeout-2026-09-05/installed-workspace-readback.mjs`. Semantic paraphrase quality, task transitions, review and full harness setup are not claimed by this readback.

2026-09-05, update defect reproduced: rerunning the corrected installer after closing the desktop failed to overwrite `context-relay-contextd.exe` because the adjacent daemon remained running. The installer was aborted instead of skipping the file; the vault and original service remain intact. This is a release blocker. Implementing authenticated, bounded shutdown of the exact named-pipe server process in preinstall/preuninstall hooks; the upgrade from the older daemon must work without requiring it to understand new command-line flags.

2026-09-05, quoted-path verification: reopened the updated installed desktop (SHA-256 `7bdb8570e0cfc731b83b4b105b7a6c54df99278ccb8d7cd8c610b27c848fde35`) and created `Quoted path verification` using the synthetic repository `.codex/installer-quoted-path-smoke` with the path surrounded by literal double quotes. The GUI reported Project added and listed the project. The original synthetic project also remained visible after reopening.

2026-09-05, service-aware update: the installer candidate SHA-256 `acb4e6d0fc7f9c40a1af1607c92dd47a63392ceb390fc3cc552d30fd3501e639` successfully stopped the old named-pipe server through authenticated IPC and completed the actual GUI upgrade. All five installed executable hashes matched the build, and the synthetic projects, memory and task survived. The shutdown slice passed 54 local-IPC unit tests, 25 integration tests, three daemon CLI tests, eight desktop Rust tests and scoped Clippy with warnings denied. Independent review found no actionable issue. Computer Use's product policy blocked launching the uninstaller; no uninstall was attempted through another mechanism, and uninstall acceptance remains pending.

2026-09-05, remaining launch defects: selecting Run Context Relay on NSIS Finish reproduced Connection unavailable with no running daemon. After the installed MCP bridge started the daemon, Retry connection restored both projects without restarting the desktop, including after navigating to Projects. Direct launch of the physical installed desktop path had previously started the daemon successfully. The cause of the NSIS launch difference is still being measured; a temporary diagnostic build records only enum labels, existence booleans and numeric Windows spawn errors. Separately, a process fixture proves that an auto-started daemon retains the bridge's redirected stderr pipe after the bridge exits. Redirecting daemon stderr alone does not fix the inherited-handle leak; a Windows process-launch fix is in progress. Neither defect is marked fixed.

2026-09-05, startup diagnosis and process fix: the diagnostic desktop launched from the original NSIS Finish path recorded `parent_exists=0 daemon_exists=0 spawn_error=3` and `ipc_error=Io`. The process image was reported under logical LocalAppData while Computer Use located the running image under the Codex MSIX package's `LocalCache/Local` folder. Thus the launcher could not find the adjacent daemon in its reported executable directory. Direct physical-path launch had worked; validation through ordinary File Explorer is next. No arbitrary-directory daemon search or machine-specific path fallback was added. The independent MCP pipe defect is fixed by a small Windows `CreateProcessW` call with explicit UTF-16 application path and handle inheritance disabled. The real process regression now observes stderr EOF while the child daemon remains alive. All 55 IPC unit tests and 25 integration tests pass; independent review approved the production change. Temporary probes were removed before rebuilding the candidate.

2026-09-05, aligned build dependencies: the diagnostic rebuild exposed JavaScript Tauri 2.8 versus locked Rust Tauri 2.11. Exact npm API `2.11.1` and CLI `2.11.4` now match the Rust minor version as required by [Tauri's dependency guidance](https://v2.tauri.app/develop/updating-dependencies/). All 93 frontend tests, type checking, lint, 12 packaging tests and the Node dependency advisory floor check pass. The aligned CLI also patches the NSIS bundle type successfully, removing the prior missing-bundle-type warning. CI run `33959064236` completed successfully; its Windows convergence test took about 50 minutes and was not hung. Current source still needs a final installed-product check and exact-commit CI.

2026-09-05, normal Windows installation verified: launched the final candidate by double-clicking it in ordinary File Explorer, then completed Setup with Run Context Relay selected. The normal installed desktop started its adjacent daemon without manual intervention and displayed Vault: unlocked. Candidate size is 10,859,845 bytes, SHA-256 `98ad387ff030fb748f75611804cbc58dc91aeda6c8daea49c0d58b830d36af62`. The earlier Codex-package installation and its synthetic vault remain separate and intact. No clean-VM or full-release claim follows from this current-user test.

2026-09-05, installed contents and local workflows: in the normal installation, created the synthetic Unicode project using a quoted path, saved the memory and task, started the task, closed the app, gracefully stopped the exact service, and reopened the installed desktop from Explorer. Automatic startup restored the project and In Progress task. Completed the task with the observed restart evidence; the GUI displayed Done. The MCP bridge read the project, memory and task successfully. Copied only the five installed executables through ordinary Explorer into `.codex/context-relay-closeout-2026-09-05/normal-installed-files` for inspection, leaving the vault untouched. Four companions match the build byte-for-byte. The desktop differs only in Tauri's three-byte bundle marker (`NSS` versus unbundled `UNK`), confirmed against local `tauri-utils` source; no other bytes differ. Raw installed desktop SHA-256 is `5187349a790ffc99b4ef2174b96b3f7b68c7cf0d18e4a23299d480ce3809fb30`. Inspection script and results are `verify-normal-installed-files.mjs` and `normal-installed-hashes.json` in that scratch directory.

2026-09-05, packaged MCP cold startup verified: with the service stopped, the copied installed bridge auto-started its copied sibling daemon, completed all three readback checks against the earlier synthetic Codex-package vault, and the Node launcher exited successfully in about 1.3 seconds while the daemon remained running. The daemon was then gracefully stopped and the normal desktop reopened to verify its separate persisted task. This directly verifies the packaged handle-inheritance fix without confusing the two local vaults. Final desktop Rust tests pass all eight cases; Clippy for desktop, local IPC and daemon passes with warnings denied. Graphify AST update completed. Exact-commit CI and the remaining acceptance map are still required.

2026-09-05, normal running-service update verified: closed the normal installed desktop while its daemon (PID 8588) remained running, then opened the final candidate from ordinary Explorer and selected Add/Reinstall. The preinstall hook stopped that daemon and Setup completed. Finish with Run selected automatically opened the new desktop (PID 37976) and daemon (PID 21416). The vault unlocked, the synthetic project returned, and `Verify installer restart` remained Done with its completion evidence. The installed bridge passed the same three project/memory/task readback checks after the update.

2026-09-05, installed harness failure reproduced: Codex Preview setup in the normal installed app returned the generic preview failure. A temporary authenticated desktop-role client sent the same preview for only the synthetic project and received `InvalidRequest: Codex executable changed`. The client was removed after inspection. The installed standalone Codex path contains directory junctions rejected by the adapter's executable topology checks. Separately, an isolated real Codex 0.144.6 CLI profile exposed `transport.env: null` for absent overrides; strict parsing expected an empty object. The compatibility patch does not qualify 0.144.6 for Full setup: persisted hook trust and the remaining native semantics still require verification. No real Codex configuration was changed.

2026-09-05, installed review round trip: the packaged MCP bridge proposed `Installer MCP review candidate` in the synthetic project. It appeared in the desktop Review queue and was absent from authoritative MCP search while pending. Desktop Accept removed it from the queue and displayed Candidate accepted; MCP search then returned its exact Unicode body. The desktop Memory search displayed it first for its title query. Scratch runner: `installed-review-roundtrip.mjs` in the closeout directory. An initial scratch assertion used the wrong field name (`status` instead of the protocol's `state`); the proposal had succeeded and was not resubmitted.

2026-09-05, installed memory editing: appended one synthetic verification line to `Installer smoke memory` through its desktop Edit/Update memory controls. The form closed, the saved record showed the change, and `installed-review-roundtrip.mjs verify-edit` read the exact multiline Unicode body through the packaged bridge.

2026-09-05, harness probe source implementation: `HarnessProbe` now runs through the authenticated ordered setup worker, reads the registered project binding, and delegates to existing adapter discovery/probe without creating a setup plan or invoking apply. The desktop probes before preview, displays unsupported/blocked capability and version without offering approval, and ignores stale discovery before it can request a plan. Project-bound preview validation and explicit approval remain intact. Hermes profile requests use the adapter's ASCII lowercase canonical name. Eleven new frontend cases were observed failing before implementation; all 104 frontend tests, type checking and lint pass. The native endpoint regression first failed with HarnessUnsupported; all 11 daemon harness setup tests then passed. Independent review approved frontend and routing. Adapter discovery errors are preserved unchanged; fixture handling of a Missing capability is not evidence of ordinary absent-installation detection. Current Codex 0.144.6 remains ImportOnly pending full native behavior qualification. Rebuild and real installed discovery remain required.

2026-09-05, standalone Codex compatibility: the discovery-only Windows resolver now validates the two known standalone aliases and binds their physical release executable. Junction, retargeting and replacement regressions pass, together with 20 Codex unit and 58 adapter integration tests and scoped core Clippy. The actual 0.144.6 MCP CLI was separately exercised with a synthetic configuration (add/get/list/remove, paths with spaces, exact unmanaged-content preservation); its `env: null` shape is now supported. Independent review approved both fixes. This does not qualify 0.144.6 for Full setup, hook trust, or native memory control. A locked installer containing the probe/resolver fixes built successfully (10,869,111 bytes, SHA-256 `78382e9485db9005610ad5557ced291a6745cb20846ac8e5b5546f443b075566`). It was not installed: the user stopped Computer Use with Escape.

2026-09-05, usability source changes: Home now starts with a project folder and offers real next actions. A native folder picker fills the path and derives an editable name; cancellation preserves entries. AI apps, Saved context and Suggestions replace developer terminology, task creation explains its project prerequisite, and unimplemented package/activity pages are described in Settings. Save controls prevent duplicate submissions and preserve failed drafts. Project selection is shared with the AI connection shortcut. Deferred lists/search errors are ignored after navigation or newer reads; acknowledged saves trigger a fresh list so earlier records remain visible. Regression tests reproduced the first-run and late-response defects before their fixes. All 114 frontend tests, type checking, lint, eight desktop Rust tests, desktop Clippy and daemon-boundary checks pass. The usability installer rebuild and installed visual/folder-picker verification are separate acceptance steps; desktop control remains paused after Escape.

2026-09-05, project registration source fix: creating a project previously sent separate identity and folder writes, so a failed second write could leave an incomplete entry. Protocol 1.5 adds Desktop-only `project_register`: validate the existing native directory and commit both records in one vault transaction. The desktop reuses the most recent uncertain registration ID for an explicit identical retry. An injected path-write failure leaves neither record after reopening; exact replay, conflicting identity/path rejection, matching legacy partial completion, role authorization, invalid-folder rejection and daemon restart tests pass. All 116 frontend tests, full protocol and local-IPC suites, 12 daemon setup tests, 21 vault-storage tests and 25 core memory-tool tests pass, along with type checking, lint, generated contract parity and scoped Clippy. Retry identity is retained only for the most recent attempt in the current process; folder deduplication and durable retry recovery are not claimed.

2026-09-05, protocol-transition upgrade fix: review caught that using an installed executable as a shutdown helper would launch pre-flag daemons or fail to stop them. Preinstall always extracts the new helper. A private authenticated shutdown-only path supports the frozen 1.4 wire while ordinary application clients require exactly 1.5. Isolated real Windows process fixtures verify legacy/current shutdown, exact process-exit waiting, invalid proof/version/acknowledgment rejection, timeouts without forced termination, and absent-service success without startup or credentials. The legacy regression failed before the fix and passes afterward. No running user service was stopped during these tests. Installed 1.4-to-1.5 upgrade and current UI verification remain pending while desktop control is paused.

2026-09-05, registration review and broader checks: independent review approved the atomic registration and corrected upgrade path. A valid wrong-result acknowledgment fixture was corrected and rerun successfully. All 66 MCP tests pass, including real authenticated sockets, replay/restart, scoped task completion and cancellation; 19 package/daemon-boundary tests pass. Graphify AST output was updated. Hosted CI for b45c0c6 is now successful; e6fcbdd's Windows installer workflow is successful, with its full Windows Rust job still running at the last check. These hosted results precede the protocol 1.5 changes.

2026-09-05, protocol 1.5 candidate built at 22:00:36: the locked Windows packaging command succeeded and produced `Context Relay_0.1.0_x64-setup.exe`, 10,864,225 bytes, SHA-256 `25e073cc44d3915e54ca4953213e8516b9727af5d26b8ecf172f130e958bd390`. Authenticode reports NotSigned. The daemon's full request-routing matrix also passes with the new method. This candidate includes the prior usability/discovery fixes and atomic project registration; it has not been installed. The normal installed app still predates those changes. Signing, full AI-app connection and the rest of the acceptance map remain open.

2026-09-05, isolated Codex 0.144.6 configuration qualification: the physical standalone executable (SHA-256 `4b76ded066d0239115ca97473d010c92072bc5c5550a45dd7cbebe1e9eb956a7`) was run as an app-server with a fresh synthetic CODEX_HOME, synthetic Git project, and no copied account credentials. `config/read` reported global `memories.generate_memories=false` and `use_memories=false`; a second trusted synthetic project with both values true overrode them in the effective response. `hooks/list` reported both synthetic SessionStart/Stop hooks as enabled but untrusted, with current hashes. No model session or hook was executed; the process exited normally and input config bytes were unchanged. Evidence is in the local closeout runner `qualify-codex-read-state.mjs` and its two temporary evidence directories. The installed schema and [official hook documentation](https://learn.chatgpt.com/docs/hooks) confirm that hook trust is a separate native user-review step. No trust was bypassed; 0.144.6 remains ImportOnly.

2026-09-05, Codex memory-layer correction: the adapter now includes explicit true memory flags in every active trusted project layer, preserving comments, unrelated settings and inherited keys. Missing project config directories require no writes. Overlapping global/project paths are deduplicated with global semantics. Uninspectable Full Codex settings fail at preview; ImportOnly registration remains available. Setup rechecks newly added/changed memory settings before writes and at final validation. Only the exact reviewed before/after pair is accepted during intermediate writes; final validation rejects restored forward values while allowing inverse restoration. Multiple-file setup previously failed approval canonicalization because semantic entries were identical; entries now show each file and a readable action.

Regression evidence: 63 Codex adapter tests, 11 primary-memory setup tests and 11 bridge rollback tests pass; scoped core all-target Clippy passes with warnings denied. Regressions were observed failing for project overrides, missing directories, post-preview drift and reverted final state before their fixes. The full native transaction matrix includes global, project and nested-project settings, crash recovery, idempotence, exact rollback and raw-file privacy. These frozen CLI fixtures do not rewrite config bytes when adding MCP declarations. A real Codex MCP add does rewrite the same global config file, so complete setup/rollback is still unqualified until that interaction is exercised and corrected. No normal installed app, daemon, vault or AI configuration was changed during this work.

2026-09-05, memory-layer candidate built at 22:47:49: locked Windows packaging succeeded, producing `Context Relay_0.1.0_x64-setup.exe`, 10,865,507 bytes, SHA-256 `6593f6914d216dbd0defb842b1393b9eacfb88c0909591419952ba7a6cad83e1`. Authenticode remains NotSigned. After the readable-entry refinement, all 13 bridge-preview, 10 bridge-apply and 11 primary-memory setup tests passed. Graphify AST output updated to 14,474 nodes and 41,638 edges. The installer was not launched or installed. Hosted full CI for e6fcbdd has passed; d1c7026's Windows candidate, Supabase and secret checks have passed, while its full CI was still running at the last check. These results precede this memory-layer change.

2026-09-05, production recovery prerequisites corrected: the CLI recovery binder rejected every plan containing native mutations, although full setup now includes native memory/instruction/hook changes. It now accepts the exact CLI subset of a validated reversible plan while retaining all approval and WAL-byte checks. Production project recovery selects the sealed project root and ID instead of the vault directory; legacy global-only selection is preserved. Codex reattestation also binds the exact native memory source descriptors so a changed CODEX_HOME cannot pass merely because the replacement home's memory flags are already false.

The binder and wrong-project regressions were observed failing before correction, as was changed-Codex-home reattestation. The full matrix now interrupts at native CommitOwnershipAndReceipt before CLI/file WAL cleanup and invokes the real recovery binder, adapter reprobe and OsNativeRecoveryIo before setup-source reconciliation and rollback. It still uses an in-memory CLI declaration fixture; it does not qualify shared-file replacement. Results: 64 Codex adapter, 11 primary-memory setup, 10 bridge apply, 4 CLI recovery, 5 CLI recovery crash and 3 daemon bridge-install unit tests pass. Core and daemon all-target Clippy pass with warnings denied. Independent focused review approved the changes.

An isolated real Codex 0.144.6 add/get/remove run (local runner qualify-codex-shared-config.mjs, temporary evidence context-relay-codex-shared-config-GEYk9b) confirms that MCP add changes the approved disabled config bytes and remove restores those bytes in this fixture. Exact metadata/provenance after replacement is not thereby qualified. The [staged MCP design](../superpowers/specs/2026-09-05-codex-staged-mcp-design.md) describes the next implementation: official CLI authorship from nonsecret empty-stage input followed by one native live-file transaction, with real sandbox and approval binding requirements. No staged production path or full 0.144.6 capability is claimed yet.

2026-09-05, recovery candidate built at 23:24:55: locked Windows packaging succeeded and produced `Context Relay_0.1.0_x64-setup.exe`, 10,867,388 bytes, SHA-256 `234235eaefd1f1521249c86b1d0470f64227f4537a5de27dade52f6bd8ee7a0f`; Authenticode reports NotSigned. Graphify AST updated to 14,508 nodes and 41,725 edges. The candidate has not been installed. A second isolated Codex 0.144.6 CLI run generated and read back the managed entry from an empty synthetic home and removed it back to empty bytes (context-relay-codex-shared-config-zWIBhS). This proves empty-input CLI behavior only, not sandbox isolation. Hosted 74a4301 installer, Supabase and secret workflows passed; its full CI was still in progress at the last check.

The complete daemon library suite also passed all 58 tests, including startup recovery before listener binding and authenticated two-daemon pairing fixtures. These are automated fixture results, not installed-app acceptance or production hosted-sync qualification.

2026-09-05, staged Codex merge boundary: added host-side closed generation input and
strict TOML/JSON output validation in `codex::staged_mcp`. Only the canonical local
Context Relay command and fixed Codex arguments are accepted. Extra settings,
servers, environment, duplicate/unknown readback keys, mismatched declarations
and excessive output reject. The validated item merges with global memory
booleans into one intended native file state; unrelated settings/comments and
the original live metadata are preserved, and the function performs no writes.
The existing memory adapter shares the same boolean-edit implementation.

The initial unavailable implementation failed four new tests. Independent review
then found that a first connection without any MCP section created an inline
parent table, which the adapter would reject. A focused regression reproduced
that defect; the merge now creates an ordinary table explicitly. Tests include
first connection, repeated merge, existing bridge comments, inline memory,
foreign declarations, malformed data and host-only secret canaries. This is a
host-side component only: it does not prove official CLI authorship, sandbox
isolation, approval binding, or a working installed connection. The restricted
generator, generation evidence, setup integration and full rollback acceptance
remain pending. Codex 0.144.6 remains ImportOnly. The latest installer is still
the earlier 2042a1f recovery candidate; this component has not been packaged or
installed, and desktop control remains paused.

Focused verification passes 7 staged-input/output/merge tests, 64 Codex adapter
tests and 11 primary-memory setup tests. The corrected merge received independent
approval. These results do not qualify the staged runner or installed workflow.

2026-09-06, real generator incompatibility: the pinned Codex 0.144.6 executable
was tested in the production AppContainer launcher with an empty private stage.
Version reporting succeeds, but MCP add exits 1 because configuration loading
cannot canonicalize the private CODEX_HOME (Windows error 5). Private directory
enumeration succeeds. The tested prototype was removed from release source;
the host-side merger remains. Codex's alternate restricted-token CLI reports
that restricted reads require its elevated Windows backend, which was not set
up for the isolated test. The [qualification record](codex-staged-generation-2026-09-06.md)
contains exact scope, runtime identity, cleanup disposition and reproduction
evidence. No Full capability, installed-app or release-readiness claim follows.

2026-09-06, record editing fixes: switching between two existing notes or tasks
reused uncontrolled form fields from the previous record. The edit form now
belongs to the selected record ID. Edits use the same pending-save guard as
creation: duplicate submits, navigation, project changes and competing controls
are disabled until acknowledgment. Unconfirmed edits retain their draft and
show an uncertainty message instead of claiming a version conflict. Older reads
cannot overwrite a successful edit; subsequent archive/start/complete actions
also invalidate a pending post-edit refresh.

Four target-switch/duplicate-submit cases failed before correction. Independent
review identified the subsequent-mutation refresh race, and three additional
regressions reproduced it before correction. All 124 frontend tests pass,
including eight edit/ordering regressions; type checking and lint pass. The
corrected scoped patch received independent review. These tests use the real
React UI with a controlled workspace gateway; installed Windows acceptance is
still pending while desktop control remains paused. They do not qualify durable
retries, every record-mutation race, or the full usability/release objective.

2026-09-06, 01:11:00 candidate: locked Windows packaging of `beb7727` production
source succeeded. `Context Relay_0.1.0_x64-setup.exe` is 10,866,780 bytes, SHA-256
`4abffa1b49921817eef405c2a8d86611dc4ef4810f5d885487b6d1ca228fb9fb`,
Authenticode NotSigned. This replaces the previous local candidate and includes
the staged host merger and record-editing fixes, but no working staged generator.
It remains uninstalled; the normal installation is still the earlier b45 build.

2026-09-06, user screenshot follow-up: the user explicitly requests “harness”
terminology. Navigation, field labels, onboarding and other desktop copy now use
that term. Hermes starts with the `default` profile and explains that this input
is a name, not a folder path. Invalid names cannot send a probe. Known missing
executable/profile/home errors receive fixed guidance rather than raw native
messages; an unqualified Hermes launcher is described separately from a known
unsupported version.

An authenticated read-only probe of the existing installed daemon returned
`NotFound: Claude Code executable was not found`, and Hermes `ImportOnly` with
profile `default` and version `unknown`. It used the production installation
credential without printing it and never started/stopped the daemon or applied
setup. Successful current-protocol authentication also supersedes the older
assumption that the user's running installation still uses protocol 1.4; its
exact installed source revision has not been established. The screenshot's
`Installer verification 專案 🚀` is the project created during the earlier
documented installation/persistence tests, not an application setting.

Further inspection found the actual Claude desktop-bundled Code executable in
`%LOCALAPPDATA%/Packages/Claude_pzs8sxrjxfjjc/LocalCache/Roaming/Claude/claude-code/2.1.202/claude.exe`.
It is 252,038,816 bytes, SHA-256
`7ff0787ebdc19fc509ccea8886ebf6a53ad8213407fa3a2b7c6d1446efc419f6`.
With an empty synthetic configuration, `--version` returns `2.1.202 (Claude
Code)` and `doctor` times out after ten seconds without output. Discovery now
preserves PATH priority, checks the native user's `.local/bin` fallback and known
desktop Code cache roots, sorts valid numeric release directories, and rejects
reparse/non-PE candidates. Unsupported versions do not run interactive doctor
just to report availability. The Full allowlist and its existing strict doctor
gate remain unchanged. The actual updated adapter successfully discovered this
binary and returned `ImportOnly`, version `2.1.202`, using a synthetic config;
this was not an installation, native setup or full connection test.

Hermes's installed launcher is a Python console wrapper. Its local source
metadata says 0.17.0; this is not an executed or attested runtime version. The
adapter deliberately does not execute this unqualified wrapper. Runtime support
remains unfinished, as does Codex 0.144.6's staged-generation support. The UI and
discovery fixes must not be described as completed harness connections.

Record action fixes in this same candidate extend the existing synchronous
save guard to Start, Complete, Archive, Accept and Reject. Repeated/competing
actions and navigation are disabled until acknowledgment, progress is visible,
uncertain errors retain completion evidence and avoid false conflict claims,
and archiving clears that record's editor only after acknowledgment.

Verification: six new record-action regressions, four harness feedback cases
and three native Claude discovery regressions failed before correction. All
135 frontend tests pass, with type checking and lint; 12 Claude unit tests,
36 Claude adapter tests and 11 primary-memory setup tests pass. Core all-target
Clippy with test-support passes with warnings denied. Independent review approved
the scoped changes. Temporary diagnostic examples were preserved in the local
scratch evidence directory and removed from release source. No normal harness
configuration or project records were modified during this follow-up.

The locked Windows candidate rebuilt successfully at 2026-09-06 01:42:55:
`Context Relay_0.1.0_x64-setup.exe`, 10,875,686 bytes, SHA-256
`f7d0ec6a49385f6cf29f8e1cf29e15feb95140d1f2dbd31bbf807e95118215df`,
Authenticode NotSigned. It includes the harness terminology, feedback, bundled
Claude discovery and record-action changes above. This candidate was not
installed or visually verified; full connection and release acceptance remain
open.

## 2026-09-06: passive Claude MCP inspection correction

Real bundled Claude 2.1.202 qualification showed that MCP list/get return plain
text and start configured servers. A synthetic marker experiment confirmed get
starts its target and list also starts an unrelated server. Connection preview
and transaction readback now inspect bounded, duplicate-free native JSON;
official add/remove, approval fingerprints, WAL and conditional rollback remain.
Windows local-project key spelling, project shadowing and exclusive managed MCP
policy are checked. See the [qualification evidence](claude-native-mcp-2026-09-06.md)
for exact scope and remaining gates. This is source progress; 2.1.202 remains
ImportOnly, and the previously recorded installer does not include this patch.

## 2026-09-06: Claude command target and project lookup

Claude commands now use the selected project and explicit default/overridden
configuration context. The real digest-pinned 2.1.202 executable successfully
added and removed inert local MCP declarations in both temporary configurations
through the core launcher. Trust, approval and local import also recognize the
Windows project keys written by that CLI. The follow-up qualification document
records exact scope, tests and remaining gates. All 45 Claude adapter, 11
primary-memory setup, 5 bridge-install and 17 ordinary Claude unit tests pass,
as does core all-target test-support Clippy with warnings denied. This still
does not enable Full support, qualify persisted command-context recovery, or
change the installed app. The latest local installer remains the 3cbe619 build.

The subsequent saved-plan correction now persists a typed Claude command context
in the approval and sealed envelope. Apply, rollback and recovery refuse a
different configuration/state/project, and legacy unbound operations need a new
preview. Sealing, tamper rejection, legacy readability and the existing synthetic
transaction/recovery suites pass. This closes the omitted command-context field;
real installed transaction recovery and full harness qualification remain open.

The locked installer rebuilt from production source `24038b9` at
2026-09-06 03:06:27: `Context Relay_0.1.0_x64-setup.exe`, 10,893,198 bytes,
SHA-256 `b02ca151f4a512963415d8574300af116d728462c75c8d4b037ca2221d291ea9`,
Authenticode NotSigned. It includes passive MCP inspection, selected command
context, Windows project lookup and persisted approval/recovery binding.
Packaging completed successfully; the candidate was not installed or visually
verified. The nonempty plugin experiment found another existing validation
schema mismatch, recorded in the Claude evidence document. Full harness support
and release acceptance remain unfinished.

The subsequent Claude validation correction replaces interactive doctor with
exact live-version checking and accepts actual installed-plugin metadata while
rejecting reported errors and duplicate JSON keys. The pinned 2.1.202 test now
passes plugin installation/list validation and local MCP add/remove through the
core launcher in default and overridden temporary configurations. All 92 ordinary
core library, 47 Claude adapter and 11 primary-memory setup tests pass, as does
core/daemon all-target test-support Clippy. The 24038b9 installer above predates
this patch. Native memory location/settings, hooks and real transaction recovery
remain open; no Full support or installed acceptance is claimed. See the Claude
qualification document for evidence and the newly identified memory mismatch.

The memory-key follow-up corrects Windows canonical-prefix handling, UTF-16
replacement and Claude's long-key suffix, using vectors from the pinned native
artifact's pure string helpers. All 94 core library, 47 Claude adapter and 11
memory setup tests pass, as does core/daemon all-target Clippy. Independent review
approved the scoped correction. Repository/worktree selection, relative explicit
directories, settings precedence and full connection qualification remain open.

The locked installer was rebuilt from production source `47266f7` at
2026-09-06 03:41:06: `Context Relay_0.1.0_x64-setup.exe`, 10,890,944 bytes,
SHA-256 `e952fbfa197c89f6c72c613015dcb47ef7926d314484cbdacdf1e7e29f4f1af1`,
Authenticode NotSigned. Packaging completed successfully. This candidate includes
the noninteractive validation and memory-key corrections, plus prior harness
wording, discovery, record-action and command-context fixes. It was not installed
or visually verified and does not enable Full support for the installed runtimes.

The next Claude correction binds the actual user home separately from a custom
configuration directory in both process execution and saved-plan approval.
It also fixes Windows startup hook commands: the real harness uses Git Bash,
so the former double-quoted verbatim paths could fail or expand path text.
The production-generated command now passed actual pinned-CLI startup in both
default and custom temporary configurations, including a path with `$HOME`, an
apostrophe, spaces and Chinese characters. Older managed commands remain
recognizable for replacement. See the Claude qualification document for the
exact runtime scope, regression checks and macOS recovery-fixture follow-up.
The 47266f7 installer above predates these changes; full connection and installed
acceptance remain open.

The locked installer rebuilt from production source `5d92f4f` at
2026-09-06 04:21:36: `Context Relay_0.1.0_x64-setup.exe`, 10,907,394 bytes,
SHA-256 `57199e121b7319d0d62398b36b3a02849bc197e14dd57d6e17f1b4266a84b197`,
Authenticode NotSigned. Packaging completed successfully. It includes the
explicit-home and Windows startup-hook corrections. This candidate was not
installed or visually verified; Full support and release acceptance remain open.

## 2026-09-06: clearer first-use flow

The frontend now leads through choosing a project, saving context and connecting
a harness. Navigation is grouped and wraps in narrow windows. Empty and
unavailable connection states have a useful next action. Technical details are
expandable, while consent-relevant changes remain visible. Repeated connections
retain distinct Undo targets and the original change review. All 140 frontend
tests, type checking, lint and the production build pass. Eight isolated
headless Edge screenshots and the first-use interaction flow were checked;
this does not exercise the installed native app. See the
[first-use evidence](first-use-ui-2026-09-06.md). The 5d92f4f candidate above
predates this frontend change.

Hosted CI run 33989730248 also passed the corrected macOS Rust tests, macOS lint
and macOS native build. Windows Rust tests were still running at this check;
this is not a claim that every required CI or native qualification gate passed.

The locked installer rebuilt from production source `11d6740` at
2026-09-06 04:50:37: `Context Relay_0.1.0_x64-setup.exe`, 10,910,977 bytes,
SHA-256 `a18e2051f1fc30a9d7cf66dec71ac747f6f54facf03485fa826447d233d326bf`,
Authenticode NotSigned. Packaging completed successfully. It includes the
revised first-use frontend and the prior Claude home/hook corrections. It was
not installed or tested through native desktop control. Full harness connection
and release acceptance remain unfinished.

The following source correction now resolves Claude's configured memory paths
using pinned native behavior: home expansion, lexical normalization, ignored
relative values and an unavailable result for unsupported explicit bindings.
Ancestor validation also protects memory directory inspection. Local core,
adapter and setup regressions pass; the [Claude evidence](claude-native-mcp-2026-09-06.md)
records exact scope and pending POSIX/runtime checks. The 11d6740 installer above
does not include this subsequent source change. Full connection remains open.

Claude file-layer inspection now respects user, project and local memory
settings. Local overrides are disabled in the file that actually controls them.
Full setup binds settings dependencies and revalidates them during apply and
undo; missing memory folders retain stable Windows source IDs when created.
Local checks pass 100 core, 58 Claude adapter and 11 primary-memory setup tests,
including the recovery/undo-to-absence case. The [Claude evidence](claude-native-mcp-2026-09-06.md)
records the boundaries: runtime flags/environment/trust, other managed sources
and full installed acceptance remain open. ImportOnly registration revalidation
is covered by the follow-up below. The 11d6740 installer also predates this
source-only correction.

Read-only registration now checks the approved harness installation, memory
settings and source list before committing. Startup ends interrupted attempts
without registering stale sources. A production-path canary verifies that all
three harnesses remain unlaunched during verification, including changed PATH
and executable cases. Windows ordinary/canonical path mismatches are covered.
All 322 selected core tests and 59 daemon tests pass; the
[registration evidence](read-only-memory-registration-2026-09-06.md) describes
scope and recovery/Undo coverage. This source change neither enables Full
connection nor updates the 11d6740 installer. Installed acceptance remains open.

Claude default memory lookup now uses the repository ancestor and verified common
worktree root. Local tests pass 104 core library, 60 Claude adapter and 16
primary-memory setup cases, including source revalidation and Windows pointer
alias checks. The [Claude evidence](claude-native-mcp-2026-09-06.md) distinguishes
native-helper conformance from full session qualification. The prior registration
change passed its macOS production canary but exposed an outdated watcher test
executor; the corrected four-test daemon integration suite passes locally.
The [registration evidence](read-only-memory-registration-2026-09-06.md) records
that hosted failure and its correction. Full connection, installed acceptance
and the 11d6740 installer status are unchanged.

Twenty real noninteractive Claude sessions now pass against a local model stub,
including production-generated startup/Stop commands and selected memory roots.
They exposed a file-environment control that could defeat native-memory disable.
The adapter now handles that control in the effective project/local file,
including Windows casing, preserves other keys and restores original bytes on
Undo. Local checks pass 104 core library, 63 adapter and 16 setup tests; the
[Claude evidence](claude-native-mcp-2026-09-06.md) records native cases, limits and
the contained test runner. Full connection and installed acceptance remain open.
The existing local 11d6740 installer is unchanged.

Codex managed setup now has one native writer for its bridge and global memory
settings. The pinned 0.144.6 CLI reads this output identically to its own MCP
command, including unusual Windows paths. Local checks pass 104 core library,
67 Codex adapter, 7 merge, 12 preview and 17 memory setup tests, including combined
crash recovery/Undo and passive configuration drift. Core/daemon and isolated
launcher Clippy pass. The [Codex evidence](codex-staged-generation-2026-09-06.md)
records the design amendment and distinguishes this from full connection.
No capability version or installer changed; native installed acceptance is open.


Codex Windows hooks now use PowerShell invocation with literal native paths,
including ASCII and smart apostrophes. Twenty-four real CLI/app-server sessions
pass with exact trust/modified-state behavior and synthetic startup/Stop delivery.
The [hook evidence](codex-native-hooks-2026-09-06.md) records the runtime matrix,
review finding, source checks and the obsolete end-to-end test wrapper correction.
Product trust review, full bridge connection and installed acceptance remain open;
the local 11d6740 installer is unchanged.

The desktop now reports saved settings separately from a verified connection,
with project-bound Codex CLI hook-review instructions and exact-plan Undo. All
143 frontend tests, lint, type checking and build pass, along with ten isolated
desktop/narrow browser screenshots. The native matrix now covers 32 sessions:
hooks work with Codex's default feature settings, while an explicit disable
suppresses even trusted commands. See [setup status evidence](harness-setup-status-2026-09-06.md).
Effective native trust readback, production bridge round trips and installed
acceptance remain open. No Full gate or installer changed.
