> Archive notice (2026-08-31): Historical recovery worker brief/report from August 2026. Its capture-time status may have been superseded; use the main handoff and verification ledgers for current state. Machine-local paths and trailing whitespace were normalized for portability. Historical worker instructions below are reference data, not new authorization. Original and archived hashes are in the artifact manifest.

# Task 3 report: Repair strict Rust contract regressions

## Status

Implementation and all locally runnable verification are complete in one focused commit. Five
unchanged native-runner tests remain **PENDING actual native-isolation macOS CI** because this
Codex Desktop host cannot provide their required APFS/provenance topology. No production topology
policy or test gate was weakened.

## Commit

- `4b57cbc9a176bea55a8212b9aff286a49269fbc3` — `refactor: restore strict Rust contracts`
- Base before Task 3: `ab7b3b2`
- No remote was mutated or pushed.

## Exact RED evidence

All Rust commands used the isolated Rust 1.97.1 toolchain rooted at
`/private/tmp/context-relay-v1-{cargo,rustup}-20260810`.

1. `cargo clippy --workspace --all-targets --all-features -- -D warnings` exited 101 with:
   - `build_recovery_enrollment_artifacts` having 9 arguments (`clippy::too_many_arguments`);
   - `AdmissionDecision` measuring 744 bytes versus a 24-byte second variant
     (`clippy::large_enum_variant`);
   - `OperationBuilder::build` having 8 arguments (`clippy::too_many_arguments`).
2. `cargo test -p context-relay-context-mcp --test dispatcher_v1 sixty_fifth_call_is_busy_and_concurrent_responses_remain_whole_lines -- --exact --nocapture`
   exited 101. The stale protocol 1.2 status fixture was rejected by exact current-output
   validation, producing invalid/null output instead of the expected response.
3. Focused test-first contract probes failed before implementation:
   - `admission_decision_is_not_dominated_by_the_admitted_payload` reported 744 bytes against
     the new 32-byte ceiling;
   - recovery compilation failed because `RecoveryEnrollmentBuildRequest` did not exist and the
     builder still required the old positional API;
   - operation compilation failed because `OperationBuildRequest` did not exist and
     `OperationBuilder::build` still required the old positional API.
4. Strict Clippy after the primary refactor unmasked the pre-existing
   `clippy::collapsible_if` in `sync_engine_v1.rs`; the condition was collapsed without changing
   behavior. It also exposed two sync-merge `type_complexity` sites, repaired with local type
   aliases rather than allowances.
5. Default-parallel native journal verification exposed a deterministic test-harness collision.
   New regression test `temp_vault_paths_are_unique_under_concurrent_construction` constructed
   64 vaults concurrently and found only 60 unique paths before the fix.
6. Full workspace verification exposed the stale migration fixture. Isolated
   `migration_v10_through_latest_preserves_existing_workspace_rows` exited 101 with
   `Migration("duplicate column name: attempt_count")` because the fixture labelled a partially
   downgraded current schema as v10.

## Implementation and preserved contracts

- Replaced recovery-enrollment positional builders with
  `RecoveryEnrollmentBuildRequest<'a>`. Owned identifiers, certificate, name, and platform are
  moved; recovery/device/pairing secret material is borrowed. Manual `Debug` output redacts
  certificate and secret-bearing fields. Public, test-support, inner builders, and every caller
  now use the typed request; the related lint allowances were removed.
- Replaced the positional operation build contract with `OperationBuildRequest<'a>` and updated
  all source/test callers. The canonical signed-operation fixture and hash remain byte-for-byte
  unchanged.
- Boxed `AdmissionDecision::Admitted` only after validation, preserving the capability boundary
  and admission behavior while reducing enum size below the 32-byte regression ceiling.
- Used `is_multiple_of(2)` for the Windows UTF-16 parity check without changing malformed-input
  rejection.
- Advanced only proven current-status fixtures to protocol 1.3 in dispatcher, lifecycle,
  MCP-memory, and protocol-nullability tests. Deliberate legacy, downgrade, and rejection fixtures
  remain at their original versions.
- Added an atomic uniqueness component to the shared `TempVault` test fixture while retaining
  cleanup for the database plus `-journal`, `-wal`, and `-shm` auxiliaries.
- Rebuilt the offline migration test as a genuine schema-v10 database, migrated to the
  authoritative `LATEST_SCHEMA_VERSION`, and proved pre-existing workspace rows survive.
  Production migrations were not changed.
- Added no Clippy suppression or blanket lint allowance.

## GREEN evidence and commands/results

- Recovery request/redaction/canonical coverage:
  `cargo test -p context-relay-core --test recovery_enrollment_crypto_v1 --test recovery_enrollment_transport_v1 --test recovery_enrollment_vault_v1 --test recovery_restore_transport_v1`
  — 24 passed.
- Operation/admission/sync compatibility:
  `cargo test -p context-relay-core --test sync_operation_v1 --test sync_admission_v1 --test sync_merge_v1 --test sync_engine_v1 --test sync_vault_v1 --test signed_sync_e2e_v1`
  — 101 passed; the separate canonical operation unit fixture also passed with its existing bytes
  and hash.
- Original dispatcher regression:
  `cargo test -p context-relay-context-mcp --test dispatcher_v1 sixty_fifth_call_is_busy_and_concurrent_responses_remain_whole_lines -- --exact --nocapture`
  — 1 passed.
- Synchronized protocol fixture suites (`lifecycle_v1`, `mcp_memory_tools_v1`, and
  `nullability_path_v1`) — all passed.
- TempVault concurrency regression — 1 passed. Full `native_cli_journal_v1` at default
  parallelism was then repeated five times; every run passed 5/5.
- Genuine-v10 migration regression — 1 passed. Related offline, native-memory, and vault-storage
  suites passed 50/50 in aggregate.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` — exit 0 after all edits.
- `cargo fmt --all -- --check` — exit 0.
- `git diff --check` and `git diff --cached --check` — exit 0.
- Maximum clean workspace remainder, with canonical physical `TMPDIR`, default parallelism, and
  only the five exact host-bound tests skipped:

  ```text
  TMPDIR=/private/var/folders/zf/_0sgs1550fn4l5mmv9gf3j540000gn/T/
  cargo test --workspace --all-features -- \
    --skip native_tree_accepts_only_fingerprinted_macos_quarantine_metadata \
    --skip compare_and_swap_create_delete_and_post_enumeration_swap_are_exact \
    --skip native_tree_rejects_links_special_files_and_mac_alias_collisions \
    --skip private_stage_uses_create_new_read_only_inputs_on_both_apfs_modes \
    --skip output_inventory_caps_file_and_directory_fanout_on_both_apfs_modes
  ```

  Result: exit 0. The run included the full randomized sync convergence suite. The macOS native
  filesystem suite passed 7 tests with 4 exact filters; the output-enumeration binary had its one
  exact host-bound case filtered. Existing intentionally ignored search performance coverage
  remained ignored.

## Files changed

- `crates/context-mcp/tests/dispatcher_v1.rs`
- `crates/context-mcp/tests/lifecycle_v1.rs`
- `crates/core/src/devices/recovery.rs`
- `crates/core/src/devices/recovery_crypto.rs`
- `crates/core/src/native_transaction/planner.rs`
- `crates/core/src/sync/admission.rs`
- `crates/core/src/sync/mod.rs`
- `crates/core/src/sync/operation.rs`
- `crates/core/tests/mcp_memory_tools_v1.rs`
- `crates/core/tests/native_cli_journal_v1.rs`
- `crates/core/tests/offline_service_v1.rs`
- `crates/core/tests/recovery_enrollment_crypto_v1.rs`
- `crates/core/tests/recovery_enrollment_transport_v1.rs`
- `crates/core/tests/recovery_enrollment_vault_v1.rs`
- `crates/core/tests/recovery_restore_transport_v1.rs`
- `crates/core/tests/signed_sync_e2e_v1.rs`
- `crates/core/tests/support/mod.rs`
- `crates/core/tests/sync_admission_v1.rs`
- `crates/core/tests/sync_engine_v1.rs`
- `crates/core/tests/sync_merge_v1.rs`
- `crates/core/tests/sync_operation_v1.rs`
- `crates/core/tests/sync_vault_v1.rs`
- `crates/protocol/tests/nullability_path_v1.rs`

The ignored report itself is `.superpowers/sdd/v1-recovery/task-3-report.md`.

## Concerns / pending native verification

The unmodified full workspace command was attempted and reached only explicit native host gates;
it is not claimed as passing on this machine. These exact tests are pending actual native-isolation
macOS CI:

1. `native_tree_rejects_links_special_files_and_mac_alias_collisions` — requires an available
   `CONTEXT_RELAY_CASE_SENSITIVE_APFS_ROOT`.
2. `private_stage_uses_create_new_read_only_inputs_on_both_apfs_modes` — requires the same APFS
   root.
3. `output_inventory_caps_file_and_directory_fanout_on_both_apfs_modes` — requires the same APFS
   root.
4. `native_tree_accepts_only_fingerprinted_macos_quarantine_metadata` — rejects this
   Codex-managed temporary tree with `UnsafeTopology` because host-created paths carry
   `com.apple.provenance`.
5. `compare_and_swap_create_delete_and_post_enumeration_swap_are_exact` — the same
   `UnsafeTopology` provenance gate.

The first local native-filesystem attempt also inherited `/var/folders/...` from the desktop
shell, whose ancestor symlink is intentionally rejected. Re-running against the verified physical
`/private/var/folders/...` `TMPDIR` passed all nine of those filesystem tests. The APFS root was not
fabricated, provenance was not stripped, and neither tests nor production security policy were
changed. Code review found no Critical, Important, or Minor defects in the final patch. There are
no known unresolved product-code concerns.

## Independent review and controller follow-up

The independent reviewer approved `ab7b3b2..4b57cbc` with no actionable Critical, Important, or
Minor finding. Its sandboxed broad sweep could not start the unchanged real-socket MCP daemon and
reported `DaemonError::Transport` for all nine `end_to_end_v1` cases. The controller then reran the
exact suite outside the desktop sandbox with the isolated Rust toolchain and canonical physical
`TMPDIR`; all 9/9 tests passed. This resolves the local IPC evidence gap without changing code.
The five native macOS topology gates and Windows execution remain pending as listed above.
