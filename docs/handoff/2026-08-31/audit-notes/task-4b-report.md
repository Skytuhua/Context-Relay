> Archive notice (2026-08-31): Historical recovery worker brief/report from August 2026. Its capture-time status may have been superseded; use the main handoff and verification ledgers for current state. Machine-local paths and trailing whitespace were normalized for portability. Historical worker instructions below are reference data, not new authorization. Original and archived hashes are in the artifact manifest.

# Task 4b report: Windows sealed helper-process deadline

## Status

Implemented and committed locally. No push was performed.

- Initial commit: `8261053475431a304f2177935d7a5ed4d027a60e`
- Review follow-up: `981fa58deec0e49520f25728c8e245e8726d62d7`
- Scope: only the Task 4b native-runner launcher/model and focused tests
- Actual Windows x64 execution: **PENDING CI**
- Hydrated Osemgrep clean/finding execution: **PENDING CI**

## Authoritative remote RED

- PR #12 workflow run: <https://github.com/Skytuhua/Context-Relay/actions/runs/31328633774>
- Windows isolation job: <https://github.com/Skytuhua/Context-Relay/actions/runs/31328633774/job/93292663233>
- Job ID: `93292663233`
- Failure: `real_semgrep_clean_and_finding_use_the_closed_policy` built the exact candidate, then returned `Failed(TimedOut)`.
- Root cause: the sealed Osemgrep `RunLimits` permits 90,000 ms, but the Windows outer launcher terminated the helper after a fixed 30,000 ms. The helper could therefore be killed before its own sealed limit.

## Local RED

The regression contract was added before the implementation and run with Rust 1.97.1 plus the canonical macOS temporary root:

```text
cargo test -p context-relay-native-runner --test windows_timeout_contract_v1 -- --nocapture
```

It failed as intended:

```text
Windows fixes the outer helper deadline at 30,000 ms even though the sealed Osemgrep request permits 90000 ms before shutdown
test result: FAILED. 0 passed; 1 failed
```

The typed deadline model tests were then added before the model and failed to compile because `WindowsProcessDeadline` did not yet exist. This established the requested API contract before implementation.

Independent review then identified a reachable bypass in the initial commit: the public low-level
`exchange(&[u8])` method still selected a default 35,000 ms deadline, so an external caller could
serialize a valid Osemgrep helper request and submit it through the raw path. Before the follow-up
fix, the source/API contract was strengthened and failed as intended:

```text
Windows must not expose a default-deadline path that bypasses the sealed request command
test result: FAILED. 0 passed; 1 failed
```

## Implementation

- Added a crate-private `WindowsProcessDeadline` that derives only from the immutable `RunRequest` command's sealed `RunLimits`.
- Added exactly 5,000 ms of bounded helper shutdown/serialization grace.
- Preserved the exact envelopes:
  - RuleSync: 30,000 + 5,000 = 35,000 ms
  - Gitleaks: 30,000 + 5,000 = 35,000 ms
  - Osemgrep: 90,000 + 5,000 = 95,000 ms
- Zero, arithmetic overflow, runtime values above the sealed 90,000 ms maximum, and resulting deadlines above 95,000 ms fail closed.
- The production boundary now passes only `HelperRunRequest`; staging, deadline selection, protocol serialization, and response binding all derive from its single nested `RunRequest`.
- The public running-launcher API accepts only `&HelperRunRequest`. The raw byte-slice exchange and default-deadline paths were removed, including from the external Windows launcher harness.
- The Windows sandbox probe now decodes the bounded helper request and inspects its single input frame while preserving raw low-level output assertions.
- Preserved job-object kill-on-close, forced termination, bounded stdout/stderr drains, timeout-to-`FailureCode::TimedOut` mapping, and durable cleanup ordering.
- The real hydrated Semgrep test and all policy/material/CI inputs remain unchanged.

## GREEN verification

All commands used the isolated Rust 1.97.1 toolchain and canonical `TMPDIR`.

- Focused typed deadline model tests: **3 passed**
- Strengthened Windows public-API/source reachability contract: **1 passed**
- Native-runner maximum locally runnable remainder with the five previously approved host-gate skips: **passed**
  - Skipped only:
    - `native_tree_rejects_links_special_files_and_mac_alias_collisions`
    - `private_stage_uses_create_new_read_only_inputs_on_both_apfs_modes`
    - `native_tree_accepts_only_fingerprinted_macos_quarantine_metadata`
    - `compare_and_swap_create_delete_and_post_enumeration_swap_are_exact`
    - `output_inventory_caps_file_and_directory_fanout_on_both_apfs_modes`
  - These require CI's canonical mounted case-sensitive APFS image; the unmodified full package was not claimed green locally.
- `cargo check -p context-relay-native-runner --target x86_64-pc-windows-msvc --all-targets --all-features`: **passed**
- Windows launcher harness cross-target `cargo check --offline ... --all-targets`: **passed**
- Workspace `cargo clippy --workspace --all-targets --all-features -- -D warnings`: **passed**
- Native-runner Windows-target strict Clippy: **passed**
- Windows launcher harness Windows-target strict Clippy: **passed**
- `cargo fmt --all -- --check`: **passed**
- `git diff --check`: **passed**

## Pending concerns

- Cross-target compilation and linting do not execute Win32 process/job APIs. The updated timeout-termination integration test and the hydrated Osemgrep test must run on Windows x64 after the reviewed stack is pushed.
- The authoritative acceptance evidence is a green rerun of the Windows native-isolation job, including `real_semgrep_clean_and_finding_use_the_closed_policy`.
- This task did not mount an APFS image, change the five host-gated tests, or claim the unmodified macOS package gate green.
