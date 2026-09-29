# Isolated Native Runner and Transaction Engine Implementation Plan

## 2026-07-24 Task 9 scope amendment

Task 9 V1 completes after one current-revision native build and network-denied
runtime smoke succeeds on Windows x64 and macOS arm64, together with the normal
JavaScript, Rust, schema, manifest-material, formatting, and Clippy gates. The
runtime remains no-Python, hash-pinned, `--jobs=1`, bounded, private-rooted, and
isolated by the existing platform boundary.

Independent A/B native builds, byte reproducibility, same-attempt comparison,
publication approval/release creation, final published-evidence binding, and
release-grade attestation are deferred to **Task 9R — Semgrep release
qualification**. V1 completion does not satisfy or claim those release gates.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task by task. Use superpowers:test-driven-development for each behavior change and superpowers:verification-before-completion before any completion claim.

**Goal:** Implement roadmap Task 9: pinned RuleSync, Gitleaks, and public-source native Semgrep sidecars; strict staged execution in a real Windows AppContainer or single-use signed macOS App Sandbox; and an exact, crash-recoverable 20-step native transaction that never mutates live state outside the approved bytes.

**Architecture:** `context-relay-native-runner` owns strict provenance parsing, closed command templates, staged-path/environment policy, helper framing, topology inspection, and platform sandbox launchers. `context-relay-core::native_transaction` owns approval hashing, the exact state machine, compare-and-swap mutation, encrypted journaling, compensation, and startup recovery. `contextd` opens and recovers the Vault before binding IPC. Generated sidecar bytes remain ignored under `target/sidecars`; committed locks, source manifests, licenses, command-template hashes, and corresponding-source instructions make every enabled binary reproducible and replaceable.

**Tech Stack:** Rust 1.97, serde/minicbor/sha2, SQLCipher through rusqlite, Windows AppContainer/Job Objects through `windows-sys`, macOS codesign/sandbox primitives through fixed system commands and FFI, Node 24 hydration checks, RuleSync 14.0.1, Gitleaks 8.30.1, native `osemgrep` from Semgrep 1.170.0 source.

## Global Constraints

- Keep protocol v1 and generated bindings/schemas unchanged. Persist `NativeApplyReceipt` in core and derive the frozen `ApplyReceipt.resulting_digests` only for adapter validation.
- Production requests expose closed enums and bounded content frames. Never accept an executable path, arbitrary argv, shell string, response file, working directory, or environment map from an adapter or IPC caller.
- Sidecar hash, version, target, source-bundle hash, runtime-closure hash, and command-template hash must match the committed manifest before launch. Any mismatch disables that capability.
- RuleSync and scanners run only over allowlisted staged inputs, staged outputs, fake home/temp/config roots, and a credential-free allowlist environment. No sidecar reads a live harness path.
- Windows uses an AppContainer token with zero capabilities, explicit inherited pipe handles, suspended creation, token/SID verification before resume, and a kill-on-close Job Object.
- macOS uses a fresh helper bundle ID and container for every transaction. The top-level helper has exactly `com.apple.security.app-sandbox = true`; each directly spawned sidecar Mach-O has an empty entitlement dictionary and inherits the helper sandbox. Signing is inside-out without `--deep`, with strict entitlement/readback verification, process-group cleanup, and permanent poisoning of interrupted identities.
- Reject absolute paths, parent traversal, alternate data streams, drive/UNC/device syntax, reserved names, Unicode/case collisions, symlinks, junctions/reparse points, hardlinks, FIFOs/sockets/devices, and unexpected executable content before any sidecar or live mutation.
- Native macOS topology tests run on a case-sensitive APFS image. Platform tests may be `cfg`-conditioned locally, but neither native CI job may substitute a mock launcher.
- Semgrep is the separate unmodified native `osemgrep[.exe]` program built from complete public source. Do not ship Pysemgrep, CPython, official private-source wheels, or a hidden fallback.
- Step 19's single SQLCipher commit is the success linearization point. Faults before it compensate; recovery after it finalizes success. Restore only a target whose current complete-state fingerprint is exactly the journaled intended applied state.
- A reapply whose target bytes and native metadata are unchanged performs zero live writes.
- No apply IPC route or harness-specific production adapter is added in Task 9. A fixture adapter proves the transaction contract; Tasks 10–12 own real adapters.
- Do not stage `.codex/`, `AGENTS.md`, `graphify-out/`, `.superpowers/`, hydrated binaries, build caches, signing material, or unrelated files.

## Frozen Provenance and Command Inputs

- RuleSync source commit: `4c5574fd2a2633f99c879c4a3cc386c4933d1caf`, tag `v14.0.1`, MIT.
- RuleSync Windows executable: 107,349,504 bytes, SHA-256 `b735108ff1a93f929f2d166054f7f35d46ab4dc275f51484f8ddac811dc59ff2`.
- RuleSync macOS arm64 executable: 72,379,106 bytes, SHA-256 `8b1c7fb10b98d32bdb1c2f4a6a2b72f063c95d2cd0c93755697d2fe0f01e92e2`.
- RuleSync `SHA256SUMS`: SHA-256 `ad17c6bc28ddeb6f9b47c4c2cc701e53a9285c529fee9e40d14ef2e405ed2175`.
- Gitleaks source commit: `83d9cd684c87d95d656c1458ef04895a7f1cbd8e`, tag `v8.30.1`, MIT.
- Gitleaks source tree: `18ffe9bab74b97087f58f56c9cfe0fe28ddc97a6`; upstream default policy is 100,940 bytes, SHA-256 `554effdde4d972c52f1c267a26bd65821e2e4622784faadeb65d6d61a1ff76d5`; the trusted empty ignore file is zero bytes, SHA-256 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
- Gitleaks Windows archive SHA-256 `d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e`; extracted executable 22,575,104 bytes, SHA-256 `17157e2ee8b76fc8b1d8bee607a250e34b8a8023c8bc81822d4b5ee4d78fcb7c`.
- Gitleaks macOS arm64 archive SHA-256 `b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5`; extracted executable 21,324,882 bytes, SHA-256 `ba52fb1bfabbcde42f032afad3d6e0b19dff8ed105229a16e7caa338bbc0e84f`.
- Gitleaks checksum file SHA-256 `061476c21adaf5441516f96f185c1a4706a83cd6329b9b38762271b3d4a52fae`.
- Semgrep source commit: `bd614accba811b407ae5c9ec6f1eecd3bdc29911`; annotated tag object `ebb842c9cbc9cfad8fb3e6f9ac6d81b8b6443cf6`; LGPL-2.1-or-later.
- Semgrep compiler fork `3499e5708b0637c12d24d973dd103406a32b8fe8`; opam repository `78d29aba187e8362b8ab86c189790c0af9153d4b`.
- Research-only macOS bootstrap artifact: 209,002,504 bytes, SHA-256 `13484adba7c30b6ae0bf0fef45d674a0a7afdeea1ee345a35aa04bf11ad0e7dd`. It cannot become a release artifact until two clean public-source builds and inventories match.
- Windows Semgrep V1 requires one native build with exact DLL closure and no-Python AppContainer smoke. Two byte-identical builds remain a Task 9R release-qualification gate.

The command-template builders emit exactly these logical arrays, substituting only validated stage-relative paths and closed target/feature enums:

```text
rulesync generate --targets <closed-target> --features <closed-features> --output-roots output --config rulesync.jsonc --input-root input --silent

gitleaks --no-banner --no-color --log-level=info --redact=100 --exit-code=10 --report-format=json --report-path=- --config <trusted-stage-config> --gitleaks-ignore-path <trusted-empty-ignore> --ignore-gitleaks-allow --max-target-megabytes=0 --max-archive-depth=0 --max-decode-depth=1 --timeout=30 --diagnostics= dir --follow-symlinks=false <stage-scan-root>

osemgrep scan --experimental --oss-only --metrics=off --disable-version-check --strict --error --json --quiet --no-git-ignore --x-ignore-semgrepignore-files --jobs=1 --timeout=30 --timeout-threshold=1 --max-target-bytes=8388608 --config <staged-rule> <staged-target>
```

RuleSync runs with the transaction stage as cwd. The helper creates `input/rulesync.jsonc` with canonical `{}\n` bytes, an `input/.rulesync/` tree, and sibling `output/`; because `--input-root input` makes RuleSync resolve `--config rulesync.jsonc` under `input/`, no root-sibling config is used. The helper rejects every config key, any `input/rulesync.local.jsonc`, curated skills not explicitly allowed by the closed request, and every non-allowlisted input object; CLI values are authoritative. RuleSync succeeds only on exit 0 with exactly empty stdout/stderr and an exact validated output topology/semantic manifest. Gitleaks scans a helper-created wrapper root whose only child is `payload/`, so a package-root `.gitleaksignore` cannot become the scanner ignore file. It clears both Gitleaks config environment variables, accepts no baseline, and pins the trusted config/empty-ignore digests. Exit 0 is clean, 10 is findings, and all other exits fail. Both accepted exits require bounded redacted JSON and exactly one byte-count diagnostic matching pre-enumeration. Exit 10 additionally requires the single expected `leaks found: N` warning to match the JSON finding count; every other warning/error and every partial-scan diagnostic fails. The JSON top level must be an array with the exact source-reviewed field set; Git/symlink metadata and `Link`/`Fragment` are forbidden, paths and fingerprints are validated, `Secret` must be `REDACTED`, and raw `Match`/`Secret` values are discarded without persistence after validation. Semgrep accepts exits 0/1 only with bounded schema-valid JSON, exact `paths.scanned`, empty skipped targets, and no timeout/error entries.

## File Map

### Provenance and hydration

- Create `third_party/sidecars/manifest.v1.json` and per-tool source locks.
- Create exact license texts under `third_party/sidecars/licenses/`.
- Create `third_party/sidecars/semgrep/source-lock.v1.json`, `RELINKING.md`, deterministic public-source build scripts, patch inventory, and complete-corresponding-source manifest rules.
- Create `third_party/sidecars/policies/gitleaks.toml`, `gitleaks.empty-ignore`, and Semgrep rules used by package inspection.
- Create `scripts/hydrate-sidecars.mjs` and `scripts/hydrate-sidecars.test.mjs`.
- Modify `scripts/check-license-metadata.mjs`, its tests, `package.json`, and `THIRD_PARTY_NOTICES.md`.

### Native runner

- Create `crates/native-runner/Cargo.toml` and add it to the workspace.
- Create focused modules: `manifest`, `command`, `path_policy`, `environment`, `helper_protocol`, `stage`, `native_fs`, and `launcher`.
- Create binaries `context-relay-native-helper` and development-only `sidecarctl`.
- Create `resources/macos/Info.plist` and the helper entitlement plist containing only `com.apple.security.app-sandbox = true`; sidecar Mach-Os are verified to have empty entitlement dictionaries.
- Create portable, topology, isolation, and real-sidecar integration tests plus `examples/isolation-probe.rs`.

### Core transaction and daemon recovery

- Create `crates/core/src/native_transaction/{mod,model,approval,engine,recovery}.rs`.
- Create `crates/core/src/vault/native_transactions.rs` and migration `0003_native_transactions.sql`.
- Add approval, journal, state-machine, and subprocess crash-matrix tests.
- Modify core exports/dependencies and Vault migration/runtime policy.
- Modify `contextd` so recovery completes before `VaultWorker::spawn` signals readiness and therefore before `Listener::bind`.
- Extend `.github/workflows/ci.yml` with real Windows x64 and Apple Silicon native-isolation jobs.

---

### Task 1: Commit strict sidecar provenance, policies, and deterministic hydration

**Files:** provenance/hydration paths listed above, `THIRD_PARTY_NOTICES.md`, `package.json`.

- [ ] Add RED Node tests proving unknown manifest keys, duplicate IDs/targets, abbreviated or malformed hashes, one-byte archive/executable/source changes, missing license/source/relink material, target substitution, redirects outside the allowlisted release host, and enabled Windows Semgrep without a reproducible public-source inventory all fail.
- [ ] Add RED tests proving hydration extracts only the single expected file, enforces archive entry count/name/type/size, hashes compressed and extracted bytes, uses a temporary sibling plus atomic rename, never executes downloaded bytes, and leaves no partial enabled directory after interruption.
- [ ] Run `node --test scripts/hydrate-sidecars.test.mjs scripts/check-license-metadata.test.mjs`; observe RED for missing implementation.
- [ ] Implement a strict versioned manifest parser with `additionalProperties: false` behavior, complete 64-hex hashes, HTTPS allowlisted URLs, per-target enabled/disabled reasons, license/source references, command-template digests, and extracted closure inventories.
- [ ] Record complete RuleSync/Gitleaks release hashes from authoritative release metadata. Never commit the abbreviated research notes above.
- [ ] Implement hydration under ignored `target/sidecars/<target>/<manifest-digest>/`, using Node standard library only. A `--verify-only` mode validates an existing cache offline.
- [ ] Commit exact MIT notices and Semgrep LGPL/relinking/source-bundle instructions. The Semgrep source lock recursively names every submodule, opam source/pin, patch, action SHA, toolchain, build command, license, and deterministic `MANIFEST.sha256` rule.
- [ ] Update license checks to distinguish first-party package metadata from intentionally bundled third-party executables and to reject every unaccounted binary/license.
- [ ] Run the focused Node tests GREEN and `pnpm.cmd license:check`.

### Task 2: Build the portable closed native-runner boundary

**Files:** workspace manifests and native-runner portable modules/tests.

- [ ] Add RED Rust tests for manifest strictness and verified closure matching.
- [ ] Add RED path tests for absolute/parent paths, empty segments, `.` aliases, slash/backslash ambiguity, drives/UNC/extended paths, ADS/colons, control characters, trailing dot/space, Windows reserved names, Unicode normalization/case collisions, and overlong paths.
- [ ] Add RED command tests proving arbitrary argv/env/cwd/response files cannot be represented, and golden tests for the three literal command arrays above. RuleSync tests also prove config resolves to `input/rulesync.jsonc`, a root-sibling config has no effect, local overlays/poison keys/curated inputs fail, and exit 0 with any stdout/stderr or partial output fails.
- [ ] Add RED frame tests for invalid magic/version/type, noncanonical order, duplicate paths, length overflow, trailing bytes, partial reads, output count/aggregate limits, and secret-bearing diagnostic fields.
- [ ] Add RED environment tests with sentinel credentials/proxies/Git config/runtime injection variables and real-home paths.
- [ ] Run `cargo test -p context-relay-native-runner --test manifest_v1 --test portable_policy_v1 --test helper_protocol_v1`; observe RED.
- [ ] Implement `RuntimeTarget`, `SidecarId`, typed `SidecarCommand`, `VerifiedClosure`, bounded `ContentFrame`, `RunLimits`, `RunRequest`, `RunResponse`, and `SandboxLauncher` without arbitrary string surfaces.
- [ ] Implement validated stage-relative paths, closed RuleSync target/features, the exact command builders, allowlist environment, fake home/temp/config roots, and a bounded binary helper protocol.
- [ ] Ensure production library/binary dependencies contain no archive/network client; keep hydration in Node and development tooling only.
- [ ] Run focused tests GREEN, `cargo fmt --all -- --check`, and strict Clippy for the crate.

### Task 3: Enforce native topology and real platform isolation

**Files:** native-runner stage/native_fs/launcher modules, helper binary, resources, and native tests.

- [ ] Add platform RED tests that create real symlinks, junctions/reparse points, hardlinks, ADS, FIFOs/sockets/devices where supported, case/normalization collisions, read-only/locked paths, and post-enumeration swaps.
- [ ] Add RED isolation probes for real-home canary reads, fake-home writes, loopback and external network connects, inherited handle/fd enumeration, credential environment, child/grandchild escape, timeout, crash, and detached-process cleanup.
- [ ] Add Windows RED assertions for zero AppContainer capabilities, expected package SID, suspended launch, explicit pipe-only inheritance, executable opened/hashed before process creation, verified token before resume, and job membership/kill-on-close.
- [ ] Add macOS RED assertions for a unique 32-hex bundle suffix, `Prepared -> Active -> Retired|Poisoned` durable generation state, no reuse, strict code-sign verification, inspection of every Mach-O, exactly the single app-sandbox entitlement on the helper, empty entitlement dictionaries on its sidecars, inherited runtime denial, and no `--deep`.
- [ ] Run native topology/isolation tests; observe RED on the current platform.
- [ ] Implement staging with create-new/no-follow primitives, post-copy handle-based identity verification, immutable input permissions, and fresh output roots.
- [ ] Implement `OsNativeFileSystem` complete snapshots including bytes, ACL/permissions, ownership, timestamps, xattrs/ADS, link/topology facts, ephemeral object token, and stable restorable-state fingerprint.
- [ ] Implement Windows AppContainer + Job launcher and macOS single-use signed helper launcher. Before Windows profile creation, durably record the unique transaction moniker; on restart reuse only an exact pending moniker/SID match, fail on every unjournaled collision, and delete the profile only after durable completion/recovery. Fixed `/usr/bin/codesign` calls are constructed internally with exact argv; no shell.
- [ ] Require case-sensitive APFS image setup in macOS tests. Prove an old/poisoned container cannot read a later generation's container.
- [ ] Run native focused tests GREEN on Windows and through the macOS native CI job.

### Task 4: Implement canonical approval and the pure exact 20-step engine

**Files:** core native_transaction model/approval/engine and tests.

- [ ] Define `TransactionStep` with discriminants 1–20 matching the approved design exactly; add a compile/runtime golden order test.
- [ ] Add RED approval tests for every `SetupPlan` field except `batch_hash`, policy/manifest/input/output/target/mutation/ownership fields, domain separator, canonical set ordering, preserved operation ordering, duplicate rejection, and a committed golden CBOR/hash vector.
- [ ] Add RED state-machine tests for expiry, changed executable/version/live roots, changed input/target/manifest/scanner bytes, unsafe topology, output schema failure, stale approval, role-order violation, effective-validation failure, and fault injection before/after every step.
- [ ] Add RED instrumentation proving rejected plans and unchanged reapply perform zero native writes; passive plans still use the same transaction boundary.
- [ ] Implement `NativeTransactionPlan`, `ApprovedInput`, `ApprovedOutput`, target-associated fingerprints, mutations, ownership changes, `NativeApplyReceipt`, and canonical approval preimage `SHA256("context-relay/native-plan/v1\0" || canonical-cbor-v1(preimage))`.
- [ ] Implement the smallest engine over four seams only: `NativeAdapter`, `RestrictedExecutor`, `NativeFileSystem`, and `NativeJournal`. Pass `now_ms` directly.
- [ ] Freeze staged output bytes at step 12. Steps 15–17 consume only those exact bytes, write payloads before activation references, and keep executable packages disabled.
- [ ] Treat step 19 as success linearization; step 20 is compensation/recovery behavior, never part of a successful forward mutation list.
- [ ] Run `cargo test -p context-relay-core --test native_approval_v1 --test native_transaction_v1` GREEN.

### Task 5: Add the encrypted native journal and atomic commit

**Files:** migration 0003, Vault child module, Vault tests.

- [ ] Add RED migration tests for v2→v3, rollback on each statement fault, unknown future version, strict foreign keys, and schema round trips.
- [ ] Add RED tests proving `PRAGMA synchronous=FULL` is set and verified alongside existing SQLCipher requirements.
- [ ] Add RED all-or-nothing before-image tests where the total batch exceeds budget after earlier individual images would have fit.
- [ ] Add RED WAL transition tests for `Prepared|Applied|RestorePrepared|Restored|Conflict`, monotonic target sequence, exact expected/intended/restored fingerprints, durable `RestorePrepared` before compensation, idempotent duplicate records, and invalid transition rejection.
- [ ] Add RED step-19 tests proving ownership changes, legacy receipt, authoritative native receipt, and committed status are all present or all absent under injected SQLite faults.
- [ ] Create tables `native_plans`, `native_transactions`, `native_mutation_wal`, `native_ownership`, and `native_receipts`; keep encrypted complete-state blobs in existing `before_images`. Transaction rows include the Windows AppContainer profile moniker/SID and macOS generation identity/state needed for exact startup recovery.
- [ ] Implement one atomic `put_native_before_images` reservation/prune/insert transaction; never loop through the single-image public API.
- [ ] Implement pending transaction queries and a single atomic `commit_native_transaction` for step 19.
- [ ] Run `cargo test -p context-relay-core --test native_journal_v1 --test vault_storage_v1` GREEN.

### Task 6: Prove subprocess crash recovery at every durable boundary

**Files:** native transaction recovery module and crash harness/tests.

- [ ] Build a child-process fault harness that aborts immediately before and after every DB transition and native mutation for every target in steps 4 and 14–20. In-process panic tests are insufficient.
- [ ] Add RED cases for: never applied; exactly intended applied state; concurrently changed bytes; concurrently changed metadata/topology; crash after `RestorePrepared`; interrupted restore; crash before step-19 commit; crash after commit before cleanup; leftover Active macOS generation; Windows crash before/after profile creation; exact pending moniker/SID reuse; unjournaled collision; mismatched SID; and profile deletion only after durable completion.
- [ ] Assert recovery restores only exact intended applied fingerprints, preserves any third-party/concurrent state as conflict, and is idempotent across a second crash/restart.
- [ ] Assert before-state and restored fingerprints omit ephemeral object identity while compare-and-swap tokens use it only within the live attempt.
- [ ] Implement deterministic recovery classification and durable status transitions. Committed transactions finalize success; precommit transactions compensate; conflicts remain explicit and never overwrite.
- [ ] Run `cargo test -p context-relay-core --test native_recovery_crash_v1 -- --nocapture` GREEN repeatedly.

### Task 7: Recover before publishing the daemon endpoint

**Files:** contextd Vault worker/startup tests.

- [ ] Add a private test-only `StartupRecovery` seam to `VaultConfig`.
- [ ] Add RED tests proving the endpoint is absent while recovery blocks, a recovery failure releases the singleton and publishes no endpoint, and listener binding occurs only after every pending transaction is restored or conflict-finalized.
- [ ] Wire recovery inside `VaultWorker::spawn`: open Vault, recover pending transactions, then signal ready. Preserve `Daemon::start` ordering so `Listener::bind` remains later.
- [ ] Run focused exact tests and all contextd tests GREEN.

### Task 8: Hydrate and smoke the real sidecars in native CI

**Files:** source build scripts, real-sidecar tests, CI workflow.

- [ ] Build RuleSync/Gitleaks command smoke fixtures for clean/finding/error, malicious ignore directives, home/network attempts, timeout, and output-limit overflow inside the real sandbox.
- [ ] Build Semgrep from the recursive public-source lock twice per target in clean builders; compare executable and dynamic-library inventories byte-for-byte. Record compiler provenance accurately (Cygwin/MinGW for Semgrep Windows, never MSVC).
- [ ] Verify the exact `osemgrep` basename, no Python in PATH or closure, mandatory `--experimental`, clean/finding/invalid-rule behavior, exact scanned paths, empty skips, no timeouts/errors, and network denial.
- [ ] Produce the deterministic complete-corresponding-source archive and prove an offline rebuild uses only the bundled opam/source cache. Validate its sorted manifest and replacement instructions.
- [ ] Add a Windows x64 native-isolation CI job that hydrates verified artifacts, runs AppContainer/topology tests, and real sidecars.
- [ ] Add an Apple Silicon macOS job that asserts `uname -m = arm64`, creates the case-sensitive APFS image, signs inside-out, inspects entitlements, and runs topology/isolation/real-sidecar tests.
- [ ] Do not turn a disabled target green by skipping it. Task 9 remains open until both native jobs have actually passed with enabled public-source Semgrep artifacts.

### Task 9: Fresh verification, independent review, commit, and ledger

- [ ] Run focused Task 9 tests first, then all fresh repository gates:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo deny --locked check
node --test scripts/check-daemon-boundary.test.mjs
node scripts/check-daemon-boundary.mjs
node --test scripts/check-license-metadata.test.mjs scripts/hydrate-sidecars.test.mjs
pnpm.cmd check:bindings
pnpm.cmd check:schemas
pnpm.cmd license:check
pnpm.cmd lint
pnpm.cmd typecheck
pnpm.cmd test --run
pnpm.cmd build
git diff --check
```

- [ ] Inspect the complete staged diff and dependency closure. Generated protocol artifacts must be unchanged.
- [ ] Request independent review focused on arbitrary-command reachability, path/topology races, sandbox escape, environment leakage, provenance/license completeness, exact approval coverage, crash idempotence, step-19 atomicity, and unchanged-write instrumentation.
- [ ] Resolve every validated Critical/Important finding with a focused observed RED, minimal GREEN, affected gates, and re-review.
- [ ] Confirm both real native CI jobs are green. A workflow file or conditional test is not evidence of a passing gate.
- [ ] Stage only Task 9 paths, verify the cached path list/diff, and commit `feat: add isolated RuleSync transaction runner`.
- [ ] Run `graphify update .`, record the commit and clean review in ignored `.superpowers/sdd/progress.md`, and mark Task 9 complete only when all platform gates above are evidenced.

## Self-Review Checklist

- [ ] No arbitrary executable, argv, cwd, environment, response file, URL, or shell surface is reachable from production input.
- [ ] Every enabled sidecar byte and dependency closure matches complete committed provenance.
- [ ] RuleSync/scanners cannot read real home, inherit credentials, or reach loopback/external network.
- [ ] Gitleaks findings are distinguishable from partial scan; attacker ignores cannot hide content; scan byte accounting is exact.
- [ ] Semgrep is native public-source `osemgrep` with no Python/private-wheel fallback and complete LGPL material.
- [ ] All path, topology, identity, Unicode/case, link, ADS, and device hazards fail closed before mutation.
- [ ] Approval binds every relevant input, output, sidecar, scanner report, target complete-state fingerprint, and ordered mutation.
- [ ] The exact 20-step order is test-locked; step 19 is the sole success linearization point.
- [ ] Subprocess crash injection covers every durable boundary and every target; restore never clobbers concurrent state.
- [ ] Rejection and unchanged reapply make zero live writes.
- [ ] Daemon recovery completes before IPC publication.
- [ ] Windows and macOS real sandbox/sidecar jobs are actually green before Task 9 is closed.
