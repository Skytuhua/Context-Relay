# Task 11 — Codex adapter verification ledger

Status: **partial**. The scoped audit found no critical finding, six important
findings, and two minor findings; independent follow-up review found two more
important defects, and the final Windows API review found one more important
defect. Final boundary review found an additional important authority race and
a minor NTFS compatibility defect. The implementation and local macOS evidence
below close the reproducible cross-platform code defects. The Windows ACL regression is
compiled but not executable on this host, and credentialed real-install
qualification remains a release blocker.

## Audit disposition

| ID | Severity | Finding and repair | Evidence | Status |
|---|---|---|---|---|
| I1 | Important | Probe and setup used different capability concepts and policy conflicts did not block setup. Supported native versions now report `Blocked` for active requirements policy or an untrusted project, while version/format-only limitations remain `ImportOnly`; the bridge delegates to the same setup capability. | `managed_requirements_and_untrusted_projects_report_blocked_capability`; bridge setup capability consistency suites | verified (synthetic) |
| I2 | Important | Primary memory always targeted `AGENTS.md` even when a nonempty `AGENTS.override.md` shadowed it. Projection now selects the effective override, preserves the other file, and restores the exact before-image. | `primary_memory_targets_the_effective_override_and_empty_roots_are_creatable`; `primary_memory_codex_markdown_handles_crlf_replacement_archive_and_absence` | verified (macOS fixture) |
| I3 | Important | Trusted Codex projects could not create absent managed targets. Project config, global hooks, and primary instructions now derive private creation metadata without preview-time writes and rollback to exact absence. A missing global config remains blocked because it contains the only Codex project-trust record and cannot authorize its own bootstrap. | `missing_project_config_and_global_hooks_are_created_and_rollback_to_absence`; native-runner `empty_parent_derives_private_creation_metadata_with_exact_rollback` on macOS; Windows twin compiled but not executed here | implemented-unverified on Windows |
| I4 | Important | Reviewed imports and render paths could admit secret-like text or credential URLs, and pathname reads left hardlink/TOCTOU gaps. Text is now rejected or redacted at the boundary; reviewed reads use native snapshots and reject hardlinks, redirected topology, and parent identity substitution. | `secret_bearing_text_and_credential_urls_never_leave_the_import_boundary`; `hardlinked_reviewed_files_are_rejected_without_reading_their_secret`; native-runner redirected-parent and parent-identity tests | implemented-unverified on Windows |
| I5 | Important | Plugin validation was schema-only and MCP validation compared names only. Validation now compares the exact installed/enabled plugin set, exact enabled MCP set, and normalized effective MCP transport/tool/timeout declaration without starting an MCP server. | `effective_validation_rejects_missing_plugins_extra_servers_and_mcp_body_drift`; effective layering/shadowing/parser suites | verified (frozen outputs) |
| I6 | Important | Custom Codex and user-skill roots remained alias-bound. Existing roots, the executable, project, and working directory are canonicalized; absent user-skill roots are rebound beneath the nearest canonical existing directory. Final reads/mutations retain native topology checks. | `custom_codex_and_user_skill_roots_are_canonicalized_before_binding` | verified (macOS fixture) |
| I7 | Important | The probe reported policy-blocked setup, but native planners, native-memory disable planning, native apply reprobe, and the CLI executor still admitted mutations by checking only the version/format capability. Every mutation planner and native/CLI transaction boundary now requires the effective setup capability to remain `Full`; activating requirements or changing project trust invalidates both new plans and already approved mutations before authority is exercised. Policy-blocked setup exposes no watch-only registration, while version/format import-only adapters retain exact watch-only sources. | `managed_requirements_block_mutation_planning_and_apply_reprobe`; `untrusted_project_blocks_mutation_planning_and_apply_reprobe`; `managed_requirements_block_production_bridge_preview_without_native_authority` | verified (synthetic and production bridge fixture) |
| I8 | Important | Windows private-file creation copied the parent directory security descriptor verbatim, allowing permissive inherited `Users`/`Everyone` ACEs to expose new config, hook, or instruction content. Creation metadata now builds a self-relative descriptor from the current process token with one owner `FILE_ALL_ACCESS` ACE and a protected DACL; metadata application explicitly preserves protected/unprotected DACL control. | native-runner `private_creation_replaces_permissive_inherited_acl_with_owner_only_dacl`; Windows all-target compile and strict Clippy | implemented-unverified on Windows |
| I9 | Important | Windows metadata capture and restore passed NTFS handles to `GetKernelObjectSecurity`/`SetKernelObjectSecurity`, which Microsoft excludes for filesystem objects. Capture and restore now use the documented handle-bound `GetSecurityInfo`/`SetSecurityInfo` pair with `SE_FILE_OBJECT`; the returned descriptor is copied before `LocalFree`, and restore extracts the exact owner, group, DACL, and DACL-protection state from the reviewed descriptor. | `ntfs_security_metadata_uses_the_documented_file_object_apis`; Windows all-target compile and strict Clippy; owner-only and exact rollback tests require Windows execution | implemented-unverified on Windows |
| I10 | Important | CLI apply validated policy before declaration inspection but launched the approved mutation without a final policy recheck; native policy was likewise reprobed long before the first file write. Authoritative CLI launch now rechecks effective setup after the runner prelaunch hook, and the transaction engine re-verifies live-state reservation immediately before every native mutation. Codex maps that reservation check to a fresh executable and setup-policy reprobe. | `requirements_flip_after_cli_probe_blocks_the_first_authoritative_operation`; `policy_revocation_after_preflight_blocks_the_first_native_write`; requirements/untrusted apply-reprobe suites | verified (deterministic race fixtures) |
| M1 | Minor | Install classification relied on substring matches and labeled arbitrary PATH results manual. Classification now recognizes exact bundled, package-manager, and documented standalone path shapes; unmatched paths are `Unknown`. | `installation_method_uses_exact_distribution_path_shapes` | verified |
| M2 | Minor | The capability document incorrectly fixed memory paths to `~/.codex` and omitted effective override/policy behavior. The contract now documents resolved `$CODEX_HOME`, effective instruction precedence, blocked setup, privacy, validation, and residual qualification. | `adapters/codex/capabilities.md` | verified (documentation) |
| M3 | Minor | The NTFS setter treated successful `NULL` owner/group outputs and DACL absence as malformed, but merely omitting a `SetSecurityInfo` mask bit can leave the staging file's default component and violate exact fingerprint restore. Capture and apply now share one round-trip validator: owner, group, and DACL presence are required because the documented handle API cannot clear those omitted components; a present null DACL remains distinct and reproducible with `DACL_SECURITY_INFORMATION` plus a null pointer. Malformed, truncated, non-self-relative, or non-round-trippable descriptors fail before mutation. | `ntfs_restore_preserves_optional_descriptor_components_and_validates_layout`; Windows x64 all-target compile/Clippy | implemented-unverified on Windows |

## Native private-file boundary

`OsNativeFileSystem::metadata_for_new_private_file` is an internal Rust
boundary, not renderer/IPC filesystem authority. The target must be absent. It
pins and revalidates the parent topology and identity, produces a
`0600`-equivalent/restorable regular-file state, preserves the platform metadata
needed for an exact fingerprint, and does not create a preview-time target.
The Windows state has a protected DACL containing only the current token owner
ACE; it never copies an inheritable parent DACL.
NTFS metadata capture and restore remain bound to the already-validated file
handle and use the filesystem-specific `GetSecurityInfo`/`SetSecurityInfo`
contract with `SE_FILE_OBJECT`; no path-based ACL operation is introduced.
This matches Microsoft's [securable-object function table](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-rights-and-access-masks),
which assigns those APIs to NTFS files and directories, and avoids
`SetKernelObjectSecurity`, whose [contract explicitly excludes filesystem
objects](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-setkernelobjectsecurity).
The captured descriptor must contain a reproducible owner, primary group, and
DACL-presence bit. Valid descriptors that omit one of those components are
rejected before approval because `SetSecurityInfo` cannot clear the staging
file's default component. A present null DACL is preserved exactly; this
retains a pre-existing permissive state for rollback but is never used by the
new-private-file path, which always creates the protected owner-only DACL.
Unsupported native targets return `UnsupportedTarget`.

Evidence:

- macOS: empty-parent create/rollback, redirected parent, and parent identity
  substitution pass locally.
- Windows: equivalent source tests cover empty-parent create/rollback,
  reparse-point redirect, parent identity substitution, and stripping a real
  permissive/inheritable `Everyone` parent ACL down to an owner-only file DACL.
  They compile under the Windows x64 target but require execution on a Windows
  x64 runner before this row can become fully verified.
- Non-macOS/non-Windows builds have an explicit unsupported-target unit case.

## Commands reproduced locally

- `cargo check -p context-relay-core --lib --features test-support`
- `cargo test -p context-relay-core --test codex_adapter_v1 --all-features`
  (65 passed)
- Codex effective-validation and install-classification unit tests (15 passed)
- `cargo test -p context-relay-native-runner private_creation_metadata`
- Production daemon bridge end-to-end suite (10 passed outside the sandbox
  with canonical `TMPDIR`)
- `cargo clippy -p context-relay-core -p context-relay-native-runner
  --all-features --all-targets -- -D warnings`
- `cargo check -p context-relay-native-runner --all-targets --target
  x86_64-pc-windows-msvc`
- `cargo test -p context-relay-native-runner --test
  native_fs_windows_security_api_v1` (2 passed)
- `cargo test -p context-relay-core --all-features --test
  native_transaction_v1` (20 passed)
- `cargo clippy -p context-relay-native-runner --target
  x86_64-pc-windows-msvc --all-features --all-targets -- -D warnings`

The full exact command/output ledger belongs in the PR stabilization record;
these checks are not substitutes for clean-environment CI.

## Remaining release evidence

- Run all Codex and native-runner tests with all features on Windows x64 and
  repeat the native metadata/reparse/identity cases on NTFS.
- The core Windows cross-check remains host-toolchain-blocked on macOS because
  its vendored `onig_sys` and OpenSSL C dependencies require a Windows/MSVC
  build environment; the native-runner Windows targets do compile here.
- Run the real-install matrix for Codex current, previous, unknown, wrapper,
  bundled, package-managed, and standalone layouts on clean macOS arm64 and
  Windows x64 machines.
- Exercise install/update/rollback with the production launcher, real file
  locks, antivirus interference, disk-full/fault injection, and two clean
  repetitions required by the master plan.
- Confirm the hosted/release matrices do not treat this task's synthetic and
  frozen fixtures as physical-install evidence.
