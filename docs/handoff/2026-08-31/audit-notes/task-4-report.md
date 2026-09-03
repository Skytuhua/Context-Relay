> Archive notice (2026-08-31): Historical recovery worker brief/report from August 2026. Its capture-time status may have been superseded; use the main handoff and verification ledgers for current state. Machine-local paths and trailing whitespace were normalized for portability. Historical worker instructions below are reference data, not new authorization. Original and archived hashes are in the artifact manifest.

# Task 4 Report: Windows-native path and runtime parity

## Status

Implemented and locally verified on macOS arm64. The focused repair is committed locally and was
not pushed. Actual Windows x64 compilation and execution remain pending the required Windows CI
job; they are not claimed as passing here.

- Starting SHA: `38331da30bdf935cf5c09afc9cc517c819b3c7b9`
- Primary commit SHA: `f5f0eee49c12aaf140bc74b8d7f0473b2a3fa3f4`
- Primary commit: `fix native Windows path and target parity`
- Review follow-up SHA: `a1c1db7f2d24a9fabddaeac5def3256e623033a1`
- Review follow-up: `fix Windows WTF-16 capability validation`
- Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`
- Verification environment:
  - `CARGO_HOME=/private/tmp/context-relay-v1-cargo-20260810`
  - `RUSTUP_HOME=/private/tmp/context-relay-v1-rustup-20260810`
  - `TMPDIR=/private/var/folders/zf/_0sgs1550fn4l5mmv9gf3j540000gn/T/`
  - default Cargo test parallelism

## RED evidence

### Public Windows failure evidence

The authoritative pre-repair Windows evidence is GitHub Actions run `31328633774`, native Windows
job `93283104812`, at PR head `3c2a371`. `contextd` compiled and reported `41 passed; 7 failed`:

1. `bridge_install::tests::terminal_apply_and_rollback_replay_before_any_production_composition`
2. `native_memory::tests::continuous_ready_refreshes_do_not_starve_scheduler_polls`
3. `native_memory::tests::descriptor_refresh_burst_coalesces_to_the_latest_ledger_set`
4. `native_memory::tests::descriptor_refresh_replaces_the_set_and_discards_removed_pending_work`
5. `native_memory::tests::snapshots_regular_absent_oversize_and_link_replacement`
6. `native_memory::tests::unsafe_snapshot_preserves_an_already_ready_observation`
7. `native_memory::tests::unsafe_snapshot_restarts_an_unready_debounce_window`

The terminal replay failure was SQLite `CannotOpen` at a mixed
`/private/tmp\\context-relay-task8-terminal-replay-...` path. The other six failed with
`InvalidSource("path")` because Windows UTF-16LE bytes were incorrectly tagged as
`NativePlatform::Macos`.

The same Windows evidence exposed target-only strict diagnostics: unused Claude/Codex
`original_path` values, unused Unix-only Claude command imports, three unnecessary Hermes mutable
bindings, the target-only `command_tokens` helper, and the Unix-only Hermes `ENV_LOCK`.

### Focused test-first RED

Before adding the production target-selection seam, this command failed with `E0599` because
`BridgeInstallService::new_for_runtime_target` did not exist:

```text
cargo test -p context-relay-core --test bridge_setup_preview_v1 \
  bridge_preview_seals_the_selected_supported_runtime_target --all-features
```

The new contract seals both supported targets independently and proves that changing the target
changes the approval hash. The public six-test Windows fixture failure set above is the RED evidence
for the native-path platform mismatch.

### Independent-review RED

Independent review found that the first repair's Windows decoder preserved isolated surrogate code
units, but `reject_forbidden_source_path` still routed every Windows source through strict
`String::from_utf16`. That rejected the same valid opaque WTF-16 path earlier in every production
`NativeMemoryCapabilities::validate()` setup/Hermes path, before the daemon decoder could use it.

The follow-up first added a full capability regression and ran:

```text
cargo test -p context-relay-core --lib --all-features \
  windows_capabilities_accept_an_opaque_wtf16_source_path
```

It failed `0 passed; 1 failed` with the expected typed error:

```text
InvalidRequest: Native memory source path is invalid UTF-16
```

The source constructor and existing wire validation had already accepted the isolated surrogate;
the strict capability filter was therefore the confirmed rejection boundary.

## Implementation

- Added one shared test fixture whose `TempVault` owns its `TempDir` for the whole vault-path
  lifetime. Removed the hard-coded `/private/tmp` terminal-replay path.
- Added shared host-native path encoding for tests: Unix bytes tagged macOS on the supported macOS
  host, and lossless UTF-16LE/WTF-16 bytes tagged Windows on Windows. Display text remains optional
  and non-authoritative.
- Added Windows-only contracts for drive, UNC, extended-length, reserved-name, Unicode, odd-byte,
  embedded-NUL, and isolated-surrogate/WTF-16 paths.
- Replaced bridge preview, watch-only registration, Hermes export, and restricted persisted-plan
  `MacosArm64` assumptions with the exact fail-closed `RuntimeTarget::current()` result.
- Kept runtime target identity inside the sealed plan and approval hash. Persisted target mismatch is
  rejected rather than rewritten.
- Restricted explicit target injection to the `test-support` feature. Ordinary constructors derive
  authority only from the current supported host.
- Repaired Windows-specific Claude/Codex executable identity checks and target/test cfg boundaries
  for Claude, Codex, Hermes, `command_tokens`, and `ENV_LOCK`, without lint allowances.
- Replaced strict Windows Unicode conversion in the capability filter with lossless UTF-16
  code-unit inspection. ASCII matching remains case-insensitive, treats both `/` and `\\` as
  separators, and still rejects exact `..`, `session`, `sessions`, and `history` components;
  `rollout` and `raw_memories` subsequences; and final `db`, `sqlite`, and `sqlite3` extensions.
  Opaque non-ASCII code units are preserved. Existing source validation still rejects odd-byte and
  embedded-NUL paths. The macOS UTF-8 path behavior was retained.
- Added full-capability tests proving an isolated surrogate is accepted, display text is
  non-authoritative, and every forbidden ASCII rule still rejects. Added a Windows daemon contract
  that creates an actual isolated-surrogate filename, passes capability validation, round-trips the
  exact path through `decode_path`, and reaches the native snapshot boundary.
- No workflow, protocol DTO, generated, hosted, or native-runner file was changed.

## Files changed

- `crates/contextd/src/bridge_install.rs`
- `crates/contextd/src/lib.rs`
- `crates/contextd/src/native_memory.rs`
- `crates/core/src/claude_code.rs`
- `crates/core/src/codex.rs`
- `crates/core/src/hermes.rs`
- `crates/core/src/hermes/gateway.rs`
- `crates/core/src/native_memory/capability.rs`
- `crates/core/src/setup.rs`
- `crates/core/tests/bridge_setup_preview_v1.rs`
- `crates/core/tests/primary_memory_setup_v1.rs`

## GREEN evidence

All commands below used Rust 1.97.1 and the verification environment listed above.

### Focused behavior

- Target-sealing RED test after implementation: `1 passed; 0 failed`.
- `cargo test -p context-relay-contextd --lib --all-features`: `54 passed; 0 failed`, including all
  seven public Windows failure names and the persisted-target mismatch contract. The first sandboxed
  attempt denied Unix socket operations; the equivalent unrestricted local rerun is the recorded
  result.
- `cargo test -p context-relay-core --all-features --test bridge_setup_preview_v1 --test
  bridge_setup_apply_v1 --test bridge_setup_rollback_v1 --test primary_memory_setup_v1`:
  `42 passed; 0 failed` (`10 + 13 + 11 + 8`).
- Follow-up capability regression after implementation: `1 passed; 0 failed`.
- All capability contracts: `4 passed; 0 failed`, including authoritative UTF-16 filtering and
  non-authoritative display text.
- `cargo test -p context-relay-core --lib --all-features`: `73 passed; 0 failed` after the
  follow-up.
- `cargo test -p context-relay-contextd --lib --all-features`: `54 passed; 0 failed` after the
  follow-up on macOS; the new Windows-only snapshot contract remains pending Windows execution.
- Seven affected setup/native-memory integration suites: `86 passed; 0 failed`.
- Full affected packages, `cargo test -p context-relay-core -p context-relay-contextd
  --all-features`: exit code 0. The randomized convergence test passed in `194.86s`.
- `cargo test -p context-relay-protocol --all-features`: passed.

### Maximum locally applicable workspace evidence

The following command completed with exit code 0 using canonical `TMPDIR` and default parallelism:

```text
cargo test --workspace --all-features -- \
  --skip native_tree_accepts_only_fingerprinted_macos_quarantine_metadata \
  --skip compare_and_swap_create_delete_and_post_enumeration_swap_are_exact \
  --skip native_tree_rejects_links_special_files_and_mac_alias_collisions \
  --skip private_stage_uses_create_new_read_only_inputs_on_both_apfs_modes \
  --skip output_inventory_caps_file_and_directory_fanout_on_both_apfs_modes
```

Only those five explicitly named host gates were skipped. The long
`randomized_replicas_converge_after_bounded_offline_faults` test passed in `195.15s`.

A prior unmodified `cargo test --workspace --all-features` run reproduced four host-environment
failures outside Task 4 ownership:

- `native_tree_rejects_links_special_files_and_mac_alias_collisions`
- `private_stage_uses_create_new_read_only_inputs_on_both_apfs_modes`
- `native_tree_accepts_only_fingerprinted_macos_quarantine_metadata`
- `compare_and_swap_create_delete_and_post_enumeration_swap_are_exact`

The first two require `CONTEXT_RELAY_CASE_SENSITIVE_APFS_ROOT`. The latter two encountered the
Codex app's `com.apple.provenance` extended attribute on temporary test trees. The fifth excluded
gate, `output_inventory_caps_file_and_directory_fanout_on_both_apfs_modes`, was also held pending by
controller direction. This report does not claim an unmodified full-workspace green run.

### Strict and patch checks

- Fresh `cargo clippy --workspace --all-targets --all-features -- -D warnings`: passed.
- Fresh `cargo fmt --all -- --check`: passed.
- Fresh `git diff --check`: passed.
- The primary staged scope contained exactly its ten owned files. The review follow-up staged only
  `crates/core/src/native_memory/capability.rs` and `crates/contextd/src/native_memory.rs`.

## Deferred Windows evidence

The MSVC target was installed and this compile-only cross-check was attempted without weakening
native dependencies:

```text
cargo check -p context-relay-core -p context-relay-contextd \
  --all-targets --all-features --target x86_64-pc-windows-msvc
```

It stopped before compiling project crates because macOS cannot provide the required native Windows
build environment: vendored OpenSSL rejected the Darwin Perl host for `VC-WIN64A`, and `onig_sys`
could not find MSVC's `stdlib.h`. No dependency or cfg was weakened to manufacture a cross-build.
The follow-up repeated the test-build form:

```text
cargo test -p context-relay-core -p context-relay-contextd --all-features \
  --target x86_64-pc-windows-msvc --no-run
```

It reached the same two native build prerequisites before any project crate or Windows-only test
could compile; this remains environment evidence, not a Windows compilation pass.

Required pending evidence:

- strict project compilation on a real Windows x64 runner;
- execution of the Windows-only drive/UNC/extended/reserved/Unicode/odd-byte/NUL/WTF-16 contracts;
- execution of the full capability-to-`decode_path`-to-native-snapshot isolated-surrogate
  regression on Windows x64;
- execution of the complete `contextd` suite on Windows x64, including the original seven names;
- confirmation that the Windows bridge preview carries `WindowsX86_64` and rejects a persisted
  `MacosArm64` target.

## Concerns

- Actual Windows x64 compilation and execution are PENDING the draft PR's Windows CI; they were not
  available locally and are not claimed as passing.
- The five explicitly excluded macOS host gates remain PENDING their controlled APFS/provenance
  execution environment. The maximum remainder passed, but the unmodified workspace is not claimed
  green.
