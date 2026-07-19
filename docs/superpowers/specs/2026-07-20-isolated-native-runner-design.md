# Isolated Native Runner Design

**Date:** 2026-07-20

**Status:** Approved for implementation by the standing instruction to continue the frozen roadmap end to end

**Roadmap scope:** Task 9 -- isolated RuleSync and scanner runner

## Purpose

Context Relay must render and validate harness configuration without giving RuleSync, Gitleaks, Semgrep, or their runtimes access to the user's real home, credentials, or network. Applying the result must preserve unmanaged content, bind every mutation to an unexpired approved plan, and recover conservatively from a failure at any transaction step.

This design implements the exact 20-step native transaction frozen in the session handoff. It does not weaken the daemon boundary established by Tasks 5-7 and does not expose a general-purpose command runner.

## Constraints

- RuleSync is exactly `14.0.1`; Gitleaks and Semgrep are separately pinned sidecars.
- The v1 shipped targets are exactly Windows x86_64 and macOS arm64. Other upstream hashes may be recorded for provenance but are disabled and cannot enter a v1 runtime closure.
- A sidecar is unavailable when any expected byte, manifest field, source pin, or platform sandbox prerequisite is missing or mismatched. There is no unsandboxed fallback.
- The daemon owns plans, locks, before-images, ownership, compare-and-swap checks, native writes, receipts, and recovery.
- The restricted helper can see only a transaction stage and its own fake user directories. It never receives a Vault key, installation token, provider token, real-home path, or daemon IPC endpoint.
- Every process launch is an executable plus an argument array. No adapter or helper constructs a shell command string.
- Native files are untrusted even when they are user-owned. Links, reparse points, alternate streams, hardlinks, special files, ambiguous names, and topology changes fail closed.
- Imported content remains unmanaged. Context Relay owns only semantic items it created and can still identify by stable ID and last-applied digest.

## Decision

Use a split implementation:

```text
authenticated IPC
      |
      v
contextd -> core transaction engine -> native filesystem + encrypted Vault journal
                         |
                         v
                 native-runner host
                         |
             OS sandbox boundary
                         |
                         v
              restricted helper -> pinned sidecar
                         |
                    staged roots only
```

`crates/core` owns the deterministic transaction state machine and storage-facing traits. A new low-level `crates/native-runner` crate owns provenance verification, portable stage validation, the restricted helper protocol, and platform sandbox launchers. `contextd` is the only application consumer: Task 9 wires startup recovery now, while later adapter tasks enable harness-specific apply routing.

The helper request carries a closed `SidecarCommand` enum and content-addressed input frames. It never carries arbitrary argv, an executable path, or a working directory. The helper constructs the exact executable and arguments from a versioned command template whose only substitutions are validated stage-relative paths. Templates reject response files, unknown flags, absolute paths, traversal, and path-bearing options outside the command schema. The host resolves the sidecar from a validated manifest, re-hashes the copied executable immediately before launch, and the sandboxed helper verifies it again before spawning it.

### Alternatives considered

1. **Launch sidecars directly from the daemon.** This is smaller, but environment stripping is not isolation and cannot prove denial of real-home or network access. Rejected.
2. **Put the whole transaction in a privileged helper.** This expands the most exposed process, duplicates Vault/ownership logic, and makes recovery harder to audit. Rejected.
3. **Use one small sandbox helper and keep orchestration in core.** This gives a narrow OS-specific boundary, testable pure policy, and one authoritative transaction writer. Selected.

## Component boundaries

### `crates/native-runner`

The crate contains:

- `manifest`: strict, versioned, `deny_unknown_fields` provenance records and streaming SHA-256 verification;
- `path_policy`: relative-path parsing, structural allowlists, collision detection, and native topology inspection;
- `environment`: an allowlist-built child environment and fake-root contract;
- `stage`: private transaction layout, bounded input copying, and staged-output enumeration;
- `helper_protocol`: bounded length-prefixed request/response records with no secret fields;
- `launcher`: a `SandboxLauncher` trait plus Windows AppContainer and macOS App Sandbox implementations;
- `context-relay-native-helper`: the only binary that can spawn a manifest-selected sidecar.

The crate has no dependency on `core`, SQLite, keyrings, IPC authentication, Tauri, or harness adapters.

### `crates/core`

`native_transaction` contains:

- the exact `TransactionStep` enum below;
- `NativeTransactionPlan`, which pairs the already-approved `SetupPlan` with content-addressed staging inputs and a per-version structural allowlist;
- narrow traits for probing/rendering/semantic validation, sandbox execution, live filesystem mutation, and encrypted journaling;
- the apply state machine, compare-and-swap commit, ownership checks, receipt creation, and conservative compensation;
- a deterministic fault-injection seam available to tests without conditional production behavior.

The engine accepts immutable plan data rather than looking up paths or commands from ambient state. Adapter code must recompute the semantic diff and approval hash from staged output before any live mutation.

### Receipt boundary

The frozen protocol `ApplyReceipt.resulting_digests` list is not authoritative for recovery because it does not associate a digest with a target. Core therefore stores `NativeApplyReceipt`, whose entries pair each lossless `WireNativeValue` target with the SHA-256 of its canonical `RestorableStateFingerprint`; duplicate or colliding targets are rejected. A protocol `ApplyReceipt` is derived only for `HarnessAdapter::validate_effective`, with digests in the plan's validated canonical target order. Recovery, rollback, compare-and-swap, and ownership use only the target-associated native receipt. The Vault writes both projections atomically at step 19, preserving protocol v1 without weakening recovery.

### Canonical approval preimage

The transaction engine defines and hashes one strict canonical preimage. It contains every existing `SetupPlan` field except `batch_hash`, plus:

- helper policy and manifest schema versions;
- helper, RuleSync, Gitleaks, native Semgrep closure, source-bundle, and build-toolchain hashes;
- command-template IDs and their exact normalized arguments;
- adapter-version structural-allowlist digest;
- exact staged-input paths, lengths, and content digests;
- expected semantic output and scanner-result digests;
- target-associated complete native-state fingerprints;
- immutable bytes selected for each payload, disabled executable package, and activation reference.

`batch_hash` is the output, never an input: `SHA256("context-relay/native-plan/v1\0" || canonical-cbor-v1(preimage))`. The domain separator, field order, and encoder version are frozen by immutable golden vectors. The daemon freezes the validated output bytes before step 12, requires the recomputed value to equal `SetupPlan.batch_hash`, and writes those exact frozen bytes in steps 15-17. A receipt maps each native target to its resulting complete-state fingerprint; an unassociated list of digests is insufficient for transaction recovery.

### Encrypted persistence

The SQLCipher-backed Vault gains durable records for:

- approved native plans and their expiry;
- pending native transactions and the last completed step;
- encrypted before-images, including absence as a first-class state;
- before-metadata and directory topology;
- per-semantic-item ownership with stable ID and last-applied digest;
- apply receipts and resulting complete-state target fingerprints.

A pending journal is written before native mutation and is sufficient for restart recovery. Mixed-file before-images remain encrypted and local-only and are never synchronized.

`contextd` wires the real journal and filesystem recovery service during Task 9. Startup completes recovery of every pending transaction before publishing the authenticated IPC listener. Harness-specific apply routing may remain unavailable until the adapter tasks, but production startup recovery is not deferred.

## Sidecar provenance

`third_party/sidecars/manifest.v1.json` is the single source of executable provenance. Each platform asset records the upstream project, version, immutable source revision, original download URL, archive SHA-256, extracted executable-relative path, executable SHA-256, license identifier, license path, source-material path, and whether the asset is enabled for packaging. The manifest and verifier never trust a filename alone.

Pinned inputs are:

| Sidecar | Version / revision | Platform artifact pins | License |
|---|---|---|---|
| RuleSync | `14.0.1`, commit `4c5574fd2a2633f99c879c4a3cc386c4933d1caf` | Windows x64 `b735108ff1a93f929f2d166054f7f35d46ab4dc275f51484f8ddac811dc59ff2`; macOS arm64 `8b1c7fb10b98d32bdb1c2f4a6a2b72f063c95d2cd0c93755697d2fe0f01e92e2`; packaging-disabled macOS x64 `47774a477172f6c1ffda2cdbfba8b9d13a353e8dad96bca520262a61d1b493cf` | MIT |
| Gitleaks | `8.30.1`, commit `83d9cd684c87d95d656c1458ef04895a7f1cbd8e` | Windows x64 archive `d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e`; macOS arm64 archive `b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5`; packaging-disabled macOS x64 archive `dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709` | MIT |
| Semgrep | `1.170.0`, public commit `bd614accba811b407ae5c9ec6f1eecd3bdc29911`, annotated tag object `ebb842c9cbc9cfad8fb3e6f9ac6d81b8b6443cf6` | Research pins: official Windows x64 wheel `feddf137913a58c600675f4ed63ddc1b2c7a2f7b5394eca268413932490d9776`; official macOS arm64 wheel `de7c86d9163bedd482c5496092f1f2bcaee45f573ae2703620438ffdff2f016f`; packaging-disabled macOS x64 wheel `60eb9a27562048e219ab7529dab90c9c4d413e330a37bff43a87e8f6e00a12f3`; sdist `525dd0e3d96aa9cb62cd6d75a523a9597e7c00ce9740330b8ec46eab89f366cb` | LGPL-2.1-or-later |

RuleSync's immutable GitHub release also publishes `SHA256SUMS` with SHA-256 `ad17c6bc28ddeb6f9b47c4c2cc701e53a9285c529fee9e40d14ef2e405ed2175`. Gitleaks' release is mutable and unsigned, so the exact downloaded bytes are pinned independently; its checksum file has SHA-256 `061476c21adaf5441516f96f185c1a4706a83cd6329b9b38762271b3d4a52fae`.

Semgrep is invoked as an unmodified, replaceable, separate native `osemgrep` process; it is not linked into Context Relay. The repository includes the LGPL text, notices, relinking/replacement instructions, a recursive source lock, and a deterministic corresponding-source bundle recipe. The recipe captures the public commit, every pinned recursive submodule, interfaces, Dune/opam files and lockfiles, build/install scripts, documentation, and any patches. The PyPI sdist alone is not accepted as complete corresponding source because its native engine is copied into the wheel from an external build.

The official PyPI wheels remain research pins with `enabled_for_packaging = false`: their Trusted Publishing attestations identify private source commit `semgrep/semgrep-proprietary@bda7855c097344c0e9de5e21efdd30fc550a33fd`, which does not establish that public commit `bd614accba811b407ae5c9ec6f1eecd3bdc29911` is their complete corresponding source. Task 9 enables only native `osemgrep` artifacts built without source modification from the recursively locked public commit on the frozen targets, with the resulting executable and runtime-library hashes added to the manifest. If either public-source target build cannot be reproduced, Semgrep stays unavailable and Task 9 is not complete. Every enabled build has a materialized, deterministic, hashed complete-corresponding-source archive, the LGPL text, notices, and replacement instructions. Task 22 packages those exact materials and never resolves or substitutes them.

### Native Semgrep closure

Task 9 builds the `osemgrep` executable directly from the recursively locked Semgrep source instead of shipping pysemgrep, a CPython runtime, or a wheelhouse. Upstream's `make core` target builds one `Main` executable that selects the native CLI only when its basename is exactly `osemgrep` or `osemgrep.exe`. The scan path otherwise raises a pysemgrep fallback unless `--experimental` is present. The helper therefore exposes exactly `osemgrep scan --experimental --oss-only --metrics=off --disable-version-check --strict --error --json --quiet --no-git-ignore --x-ignore-semgrepignore-files --jobs=1 --timeout=30 --timeout-threshold=1 --max-target-bytes=8388608 --config <staged-rule> <staged-target>`; both substitutions are validated stage-relative paths from the closed request type, and a golden smoke test invokes this literal template. Before launch, enumeration rejects any staged target larger than 8 MiB. Exit 0 means a clean scan and exit 1 means findings, but either is accepted only when bounded schema-valid JSON reports exactly the pre-enumerated target set in `paths.scanned`, an empty skipped-target set, and no timeout or error entries. Every mismatch, other exit, or fallback/runtime lookup is a scanner failure.

The source-build lock records the Semgrep commit and recursive submodule commits, pinned opam-repository commit `78d29aba187e8362b8ab86c189790c0af9153d4b`, Semgrep's locked opam inputs, Semgrep OCaml compiler-fork revision `3499e5708b0637c12d24d973dd103406a32b8fe8` validated by upstream's `validate-compiler-sha.sh`, and hashes for every fetched source archive and build script. Windows uses the public MinGW build route and includes only the DLLs reported by the locked executable-closure recipe; macOS builds natively for arm64. The resulting per-target inventory records every relative path, length, SHA-256, executable bit, and runtime dependency. Two clean builds in the pinned target environment must produce identical inventories and bytes before an artifact hash can be enabled; hydration accepts only that reproduced inventory.

Upstream Apple Silicon CI provides bootstrap evidence from the exact release tree: an unmodified `semgrep-core`/`osemgrep` `Main` artifact of 209,002,504 bytes with SHA-256 `13484adba7c30b6ae0bf0fef45d674a0a7afdeea1ee345a35aa04bf11ad0e7dd`, dynamically linked only to macOS system libraries. That retention-limited artifact is research-only until the project-controlled two-build and post-signing inventory gate reproduces it. Public Windows CI for this source generation was removed after persistent Cygwin/MinGW failures; the checked-in Windows lock and build path are evidence of intent, not a usable artifact. Windows Semgrep remains capability-disabled, and package inspection fails closed, until the exact-commit builder produces two matching executable/DLL inventories and passes the native no-Python smoke tests. Official PyPI wheels never fill this gap.

The build lock also records SPDX expressions, license-file paths and hashes, immutable source URLs and hashes, and required notices for the compiler, native libraries, and every shipped runtime file. Unknown, missing, or disallowed license material disables the target artifact. A deterministic build verifier rejects unexpected archive members, source drift, compiler-revision drift, extra runtime files, and any output-tree mismatch before the sidecar can be selected.

Task 9 owns and tests hydration of RuleSync, Gitleaks, the public-source native Semgrep build, and Semgrep corresponding-source material. Generated binary/cache directories remain untracked; the signed distribution in Task 22 packages only outputs that reproduce the committed locks and inventories.

This is an engineering compliance posture, not a legal conclusion; the separate-process classification and release bundle should be confirmed by counsel before distribution.

## Platform isolation

### Windows

The host uses stable AppContainer APIs:

1. durably journal a unique per-transaction profile moniker before creating the AppContainer profile and SID;
2. place the verified helper, sidecar closure, fake roots, and stage in that profile's own folder rather than widening an external DACL;
3. populate a `SECURITY_CAPABILITIES` structure with the exact AppContainer SID and an empty capability list;
4. create only the bounded protocol pipes as inheritable handles, use an explicit handle list, and keep every other daemon handle non-inheritable;
5. hold the helper executable open against writers while hashing and through `CreateProcessW`;
6. launch suspended with `CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW`;
7. assign the suspended process to a Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`;
8. verify `TokenIsAppContainer`, exact `TokenAppContainerSid`, and an empty `TokenCapabilities` group before `ResumeThread`;
9. terminate the whole job on timeout or protocol failure; and
10. delete the recorded temporary profile only after a durable result or recovery.

The experimental `CreateProcessInSandbox` API is not used. With no network capability the helper cannot create client or server network connections. Windows native tests prove both denial against a loopback listener and denial against a canary in the real profile. A restart reuses a profile only when its moniker and SID match a pending encrypted journal; every unjournaled collision fails closed.

### macOS

The distribution contains a Developer ID-signed, notarized helper template. For each transaction the daemon verifies the template code hash, copies it into a fresh private app-like wrapper, writes a bundle identifier `com.contextrelay.native-runner.<32-lowercase-hex>`, and invokes the SIP-protected `/usr/bin/codesign` directly with a fixed argument array to apply a local ad hoc signature, hardened runtime, the unique identifier, and the committed entitlement file. It never uses a shell, `--deep`, a user-selected identity, or inherited signing configuration. The daemon then runs strict signature verification, reads back the code identifier and entitlements, rejects any field beyond `com.apple.security.app-sandbox = true`, hashes the complete signed generation, and records that result before launch. Native release-like CI starts from the quarantined/notarized product and proves that this locally generated helper executes.

Each bundle identifier and App Sandbox container is single-use. The generation moves durably through `Prepared -> Active -> Retired | Poisoned`; `Active` is committed before child creation, and daemon startup converts any leftover `Active` generation to `Poisoned`. Neither retired nor poisoned identifiers are ever launched again. Because the helper's parent daemon is unsandboxed, this top-level helper creates the sandbox; direct children with no sandbox entitlement inherit it.

Hydration and every launch inspect each actual sidecar Mach-O signature and entitlement dictionary. V1 accepts only an empty entitlement dictionary: `app-sandbox`, `inherit`, network, file, application-group, `get-task-allow`, and every unknown entitlement fail closed. Unsigned code is also rejected on Apple silicon; public-source native artifacts receive and record an entitlement-free ad hoc signature before their hashes are frozen. A purpose-built entitlement-free child follows the identical direct-spawn path and runtime-proves inherited real-home and loopback denial, and the exact inspected RuleSync, Gitleaks, and `osemgrep` artifacts must then pass their real sandbox smoke tests. An upstream signature can never silently select a different sandbox.

The daemon never opens or seeds `~/Library/Containers/<helper-id>`. It sends bounded, content-addressed input-file frames over anonymous stdin and receives bounded output/report frames over stdout. The helper validates every relative path and digest, materializes the private stage inside its own container, executes fixed command templates, validates the output topology, and streams accepted output bytes back. This avoids cross-container access prompts and keeps real-home paths out of the protocol.

A process group bounds ordinary descendants and is signaled on timeout, but the design does not claim that `killpg` reaches a child that deliberately creates a new session. Every abnormal termination poisons the already-active generation before signaling its original group and rejects all output. A cleanly detaching child leaves the generation retired, but the unique container is still never reused and therefore cannot observe any later transaction stage. Native fixtures cover both timeout and clean-exit `setsid`/double-fork cases: a surviving child must remain unable to read a real-home canary, reach loopback, or read a second transaction's separately identified container. A helper deletes its own stage before normal exit; a poisoned generation is retained for boot-scoped cleanup diagnostics and cannot block a fresh, independently identified generation.

Task 9 CI signs and verifies the immutable template with a CI identity, then performs the same per-generation local ad hoc re-signing used at runtime and proves real-home and loopback-network denial. Task 22 replaces only the distributed template's CI identity with Developer ID signing and notarization; every single-use runtime generation remains locally ad hoc signed with the exact Task 9 entitlement file. Entitlement inspection and runtime denial tests are both mandatory; the presence of a signature alone is not accepted as isolation proof.

### Fail-closed behavior

Unsupported platforms, absent signing support, profile creation failure, entitlement mismatch, executable hash mismatch, manifest mismatch, or a failed denial self-test return `SidecarUnavailable`. The runner never retries outside the sandbox.

## Stage and environment contract

Every transaction gets a fresh 128-bit random stage identifier and private directory. Its fixed subdirectories are `input`, `output`, `home`, `config`, `data`, `cache`, `temp`, `runtime`, and `reports`. Inputs are copied individually from an adapter-version allowlist. A whole harness home or whole mixed configuration file is never copied merely for convenience; in particular, `~/.claude.json` is never round-tripped wholesale.

On macOS, "copy" in step 6 means that the daemon frames only allowlisted bytes and the helper writes them into its container-local stage; it never means daemon filesystem access to the helper container. On Windows the same frame contract is used after the profile-local closure is prepared.

The helper starts from `env_clear` and sets only controlled values required by the target runtime:

- fake `HOME` and `USERPROFILE`;
- fake `APPDATA`, `LOCALAPPDATA`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, and `XDG_CACHE_HOME`;
- private `TMP`, `TEMP`, and `TMPDIR`;
- a controlled runtime-only `PATH`;
- fixed locale/encoding values and the minimum platform runtime variables;
- explicit native sidecar library variables only when present in the hashed runtime manifest.

No variable is copied by prefix from the daemon environment. Credential, keychain, proxy, shell-startup, provider, cloud, Git, SSH, package-registry, tracing-exporter, and daemon-IPC variables are therefore absent by construction. Tests seed sentinel values across every denied family and inspect the child environment.

Requests, arguments, stdout, stderr, reports, path counts, file sizes, total bytes, and runtime are bounded. On timeout Windows terminates the Job Object; macOS poisons the active generation, signals the original process group, rejects the result, and never reuses that container. Logs contain sidecar ID, pinned digest, exit status, durations, and path/digest metadata, never file contents or environment values.

## Path and topology policy

All manifest and stage paths are strict relative paths. Validation rejects:

- absolute, rooted, UNC, drive-relative, or extended-device paths;
- empty, `.` or `..` components and NUL bytes;
- Windows colons/alternate data streams, reserved device names, and components ending in a dot or space;
- separator, case, or Unicode-normalization collisions on a platform that aliases them;
- paths not present in the exact adapter-version structural allowlist;
- symlinks, macOS aliases encountered as links, Windows reparse points/junctions, mount-point escapes, hardlinks, sockets, FIFOs, block/character devices, and other special files;
- unexpected alternate data streams or multiple names for the same native file identity.

Enumeration uses no-follow metadata and platform identity/link-count checks. Mutation opens targets and parents with no-follow semantics, rechecks identity immediately before use, creates adjacent temporary files exclusively, flushes file data, atomically replaces the target, and flushes the containing directory where the platform supports it. A topology or identity change between inspection and use is a compare-and-swap conflict, not a retry against the new object.

## Exact transaction sequence

`TransactionStep` has these values, in this order, with no hidden mutation step:

1. `AcquireLock` -- acquire the per-harness and per-profile lock.
2. `ReprobeLiveState` -- re-probe executable, version, and live roots.
3. `CompareApprovedDigests` -- compare current digests with the approved plan.
4. `CreateBeforeImages` -- create encrypted local before-images.
5. `RecordNativeMetadata` -- record file type, ACL, mode, extended attributes, links, and directory topology.
6. `CopyAllowlistedInputs` -- copy only structurally allowlisted inputs into staging.
7. `CreateFakeRoots` -- create fake home, config, app-data, XDG, and temporary roots.
8. `BuildRestrictedEnvironment` -- strip credential, keychain, proxy, shell, and provider environment variables by constructing the allowlist environment.
9. `RunRestrictedTools` -- run RuleSync or scanners in the restricted helper.
10. `RejectUnsafeTopology` -- reject unexpected paths, links, hardlinks, device files, and root escapes.
11. `ValidateStagedOutput` -- parse and validate staged output.
12. `RecomputeApproval` -- recompute the semantic diff and approval hash.
13. `CheckPlanFreshness` -- stop if the plan changed or approval expired.
14. `CompareAndSwapTargets` -- recheck all target digests with compare-and-swap.
15. `WritePayloads` -- write payload files first through adjacent temporary files.
16. `InstallExecutablesDisabled` -- install executable packages in a disabled state.
17. `WriteActivationReferences` -- write activation references last.
18. `ValidateEffectiveConfiguration` -- validate effective native configuration without starting MCP servers or hooks.
19. `CommitOwnershipAndReceipt` -- commit the ownership ledger and apply receipt.
20. `RestoreMatchingAppliedTargets` -- on failure, restore only targets whose current complete-state fingerprint still matches the product-applied fingerprint.

The journal records entry and completion for every step, plus a write-ahead row before every individual filesystem, metadata, ownership, receipt, or compensation mutation in steps 15-20. Each target row stores an observation-only `NativeObjectToken`, an encrypted complete before-state reference, restorable pre-state fingerprint, intended applied-state fingerprint, intended restored-state fingerprint, operation kind, and `Prepared | Applied | RestorePrepared | Restored | Conflict` state. `NativeObjectToken` contains ephemeral volume/file identity and reparse/type identity and is used only to detect races while the observed handle remains open. `RestorableStateFingerprint` covers presence/type, bytes, Windows ACL/native attributes or POSIX mode/ACL, extended attributes, link count, and directory topology, but excludes ephemeral object identity because atomic replacement necessarily changes it.

Before each target mutation the engine durably records `Prepared`. After the atomic replace/delete/metadata operation and parent durability, it records `Applied`. Before compensation it durably records `RestorePrepared` with the intended restored fingerprint. Recovery interprets current state equal to before/restored state as not applied or already restored, current state equal to intended applied state as safe to restore, and every other state as a concurrent-change conflict. A crash after restore but before the `Restored` row is therefore idempotent. A user or another process changing bytes or metadata after Context Relay wrote a target is never overwritten.

A test-only fault hook may fail after every completed enum step and immediately before/after every durable database or native mutation. Crash tests terminate a child process at those hooks, including each target within multi-target steps 15-20, then start the real recovery path. Any caught apply failure enters step 20 exactly once. An unexpected process exit is recovered by `contextd` before IPC publication.

Step 19's SQLite commit is the transaction linearization point: it atomically commits ownership, target-associated receipt fingerprints, and committed status. A caught error or process death before that commit compensates; a restart or injected crash after the durable commit finalizes success and never rolls back. Step 20 runs only for pre-commit failure, or records that no restoration was required after ordinary success, and removes the pending journal only after the receipt is durable. Fault tests encode this distinction explicitly rather than expecting rollback after the commit point.

On a no-change reapply, "writes nothing" means zero writes, renames, deletes, permission changes, or timestamp changes to live harness targets. Safety-required encrypted journal and private staging writes still occur because the frozen sequence explicitly requires before-images and restricted execution on every apply. Exhausting the inherited 200 MiB before-image budget fails during step 4 before staging or live mutation and never evicts pending, failed, or unresolved transaction state.

## Ownership and mixed files

- Import creates source records, not ownership.
- Ownership is per semantic item. Each owned item stores a stable Context Relay ID, adapter version, structural location, last-applied semantic digest, and last-applied native digest.
- A managed-system-policy item is read-only and reported as a conflict.
- Native trust databases, OAuth approvals, session/auth state, and history are read-only.
- Unmanaged fields and Markdown outside marked Context Relay blocks are preserved byte-for-byte.
- If an owned block's current digest differs from its last-applied digest, apply stops with an edited-owned-item conflict.
- Structural allowlists are versioned with the adapter and are part of the approval hash.
- Executable packages are fully materialized but disabled before activation references are written last.

## Testing and release gates

### Pure and fake-boundary tests

- manifest parsing rejects unknown fields, duplicate IDs, wrong platform, missing material, and every single-byte hash mismatch before launcher invocation;
- table-driven path tests cover traversal, ADS, reserved/device paths, links, junctions, hardlinks, special files, and alias collisions;
- environment tests prove denied sentinel variables are absent and all user roots resolve inside the stage;
- the helper protocol rejects arbitrary executable paths/argv, response files, unknown/path-redirecting flags, malformed frames, oversize streams, output overflow, and timeout;
- fault injection after steps 1 through 18 and before/after every target/database mutation, plus interrupted step-20 compensation, restores the exact modeled state or records a concurrent-change conflict without overwriting it; a kill before step 19's commit restores, while a kill after that commit finalizes success;
- reapply of unchanged output records zero live-target mutations;
- edited managed and unmanaged mixed-file cases prove conflict and preservation behavior.
- Vault budget tests prove step-4 failure cannot evict pending, failed, or unresolved before-state;
- daemon startup tests prove pending recovery finishes before the IPC listener is published.

### Native CI tests

The Windows x64 and macOS arm64 jobs run a purpose-built fixture sidecar through the real sandbox. The fixture attempts to read a randomly generated real-home canary, connect to a loopback listener, print denied environment sentinels, and create disallowed topology. The gate passes only when home and network access are denied, the environment is clean, the sandbox identity/entitlements match policy, and unsafe output is rejected.

The same jobs hydrate and smoke-run the exact enabled RuleSync, Gitleaks, and public-source Semgrep artifacts inside that real sandbox with offline/no-network flags and harmless staged fixtures. A fixture-only pass cannot complete Task 9.

Native filesystem tests create real symlinks, Windows junctions/reparse points and alternate streams, hardlinks, FIFOs/devices where permitted, then assert fail-closed behavior. Windows also tests long/extended path forms. macOS must mount a case-sensitive APFS test disk image and run the same corpus there and on the default case-insensitive volume; inability to create or mount the native image fails the target job, while a mandatory simulated collision-policy test supplies additional coverage but is not a substitute. Packaging checks verify exact manifest hashes, materialized license/source/replacement material, the macOS signature and entitlements, and absence of unlisted or unsupported-platform sidecars.

### Repository gates

Task 9 is complete only when formatting, strict Clippy, full workspace tests, dependency policy, license/provenance checks, daemon-boundary checks, Windows native isolation tests, macOS native isolation tests, fault-injection tests, and unchanged-reapply instrumentation all pass. Native tests may be platform-conditioned, but neither platform implementation may be replaced by a mock in its native CI job.

## Explicit deferrals and non-deferrals

- Developer ID signing and notarization of the immutable distributed template remain release-pipeline work; Task 9 owns the exact entitlement file, per-generation local ad hoc signing, strict signature/entitlement verification, and runtime sandbox proof.
- Harness-specific rendering remains with the later adapter tasks; Task 9 supplies and tests the transaction interfaces and fixture adapter needed to prove all 20 steps.
- UI progress and approval presentation remain later integration work.
- Sidecar provenance, LGPL material, real platform sandbox launchers, recovery behavior, and all Task 9 security gates are not deferred.

## Security invariants

1. No verified sandbox, no execution.
2. No exact provenance match, no execution.
3. No exact approved-plan match, no live mutation.
4. No structurally allowlisted relative path, no staging or mutation.
5. No complete-state compare-and-swap match, no write or rollback.
6. No ownership proof, no overwrite.
7. No executable activation before payload durability.
8. No receipt before effective-config validation.
9. No secrets or real-home paths cross the helper boundary.
10. No shell command strings exist at any process boundary.
