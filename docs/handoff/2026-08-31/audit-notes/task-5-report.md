> Archive notice (2026-08-31): Historical recovery worker brief/report from August 2026. Its capture-time status may have been superseded; use the main handoff and verification ledgers for current state. Machine-local paths and trailing whitespace were normalized for portability. Historical worker instructions below are reference data, not new authorization. Original and archived hashes are in the artifact manifest.

# Task 5 Report: Independent and complete required CI gates

## Status

Implemented and locally verified to the limits of the macOS Codex host. The focused repair is
committed locally and was not pushed. Actual Windows x64 execution and the new remote macOS arm64
matrix run remain pending; no workflow was triggered.

- Starting SHA: `3599b7b4b60d0da700f15608d124fb4c4b348780`
- Primary commit SHA: `85a59ed519b5bd24b78e9af384c347626a2e4d5b`
- Primary commit: `ci: split required gates by responsibility`
- Review follow-up SHA: `db55e76aeb7f3b2e0ea42fe2caf64f7987f1bcad`
- Review follow-up: `ci: check committed whitespace ranges`
- Bundled Node: `v24.14.0`
- Rust: `rustc 1.97.1 (8bab26f4f 2026-07-14)`
- Cargo Deny: `0.20.2`

## RED evidence

Before changing the workflow, the new static contract ran six tests and failed all six. It proved
that the existing `rust` job serialized lint, tests, daemon ownership, generated artifacts,
licenses, dependency policy, and whitespace; the frontend commands were serialized; native builds
were coupled to limited tests; supported-host lint/test matrices and ordinary feature selection
were absent; workspace-wide `--all-features` activated the exceptional candidate feature; and
ordinary checkouts retained credentials.

After adding the macOS workspace-test requirement, the focused static test failed because the
matrix had no case-sensitive APFS mount or
`CONTEXT_RELAY_CASE_SENSITIVE_APFS_ROOT`. A final least-privilege RED assertion also failed because
ordinary jobs inherited top-level `actions: read` rather than overriding permissions to only
`contents: read`.

## Implementation and job map

- `rust`: retained compatibility name; Ubuntu formatting check only.
- `rust-lint`: independent `windows-2025` x64 and `macos-15` arm64 matrix; strict `-D warnings`.
- `rust-tests`: independent matching host matrix; exact ordinary feature set, canonical macOS
  `TMPDIR`, the unchanged launcher guardian, and a canonical case-sensitive APFS fixture.
- `daemon-boundary`, `bindings`, `schemas`, `licenses`, `dependency-policy`, and `whitespace`:
  individually visible jobs with no lint dependency.
- `frontend`: four visible, non-fail-fast matrix cells for lint, typecheck, tests, and build.
- `native`: two independent build-only cells for Windows x64 and macOS arm64; test failure cannot
  hide native Tauri compilation.
- Every ordinary job overrides permissions to only `contents: read`; every checkout sets
  `persist-credentials: false`; all third-party actions remain full-SHA pinned.
- The pre-existing native Semgrep build/isolation, artifact reuse, source lock, qualification, and
  protected publication sections are unchanged. The publication request still intentionally skips
  unless its protected release predicate is true and is not treated as an ordinary required pass.
- Workspace lint/tests explicitly enable only:
  `context-relay-core/test-support`, `context-relay-local-ipc/test-support`,
  `context-relay-contextd/test-support`, and `context-relay-context-mcp/test-support`.
  `ci-candidate-sidecar-smoke` remains enabled exactly twice, only for the two registered ignored
  Semgrep candidate tests.
- A-004 records this strengthening interpretation and why sealed historical
  `workflowGitBlob` metadata must not be rewritten by live ordinary-CI edits. The native contract
  still verifies identical nonzero lowercase 40-hex historical blobs, the exact source-lock SHA,
  current action revisions, runners, and toolchains.

## GREEN evidence

- New CI contract plus native, Supabase, and secret-scan workflow contracts: `37 passed; 0 failed`.
- All five workflow YAML files parsed with `js-yaml` duplicate-key rejection.
- `cargo fmt --all -- --check`: exit 0.
- Strict ordinary-feature workspace Clippy with all targets and `-D warnings`: exit 0.
- Daemon-boundary unit contract: `5 passed; 0 failed`; live workspace policy checker: exit 0.
- Generated bindings, generated schemas, and license metadata checks: exit 0.
- `cargo deny check`: exit 0; `advisories ok, bans ok, licenses ok, sources ok` (informational
  duplicate-version warnings remain within the existing policy).
- Frontend lint and typecheck: exit 0; frontend tests: `54 passed; 0 failed`; frontend production
  build: exit 0.
- Local macOS arm64 Tauri build with bundling disabled: exit 0; produced the release executable at
  `target/aarch64-apple-darwin/release/context-relay-desktop`.
- The prior PR snapshot `3c2a371aef74f4962af64d0fe71545557244f21a` used the same unchanged
  native-isolation definition and its `native-isolation-macos-arm64` check succeeded in GitHub
  Actions run `31328633774`, job `93286360410`.
- Fresh workflow contract/YAML/diff checks after the final edit: recorded below before commit.

## Local host limitations (not claimed green)

The unmodified exact command

```text
cargo test --workspace --all-targets --features \
  context-relay-core/test-support,context-relay-local-ipc/test-support,context-relay-contextd/test-support,context-relay-context-mcp/test-support
```

passed the broader workspace through the long randomized sync suite, then stopped with four
fail-closed `UnsafeTopology` failures in `native_fs_macos_v1`:

1. `native_tree_accepts_only_fingerprinted_macos_quarantine_metadata`
2. `native_tree_rejects_links_special_files_and_mac_alias_collisions`
3. `compare_and_swap_create_delete_and_post_enumeration_swap_are_exact`
4. `private_stage_uses_create_new_read_only_inputs_on_both_apfs_modes`

Residual default-volume and case-sensitive-APFS trees carried Codex-injected
`com.apple.provenance` on their roots and files; the quarantine case also carried only its
deliberately set quarantine value. This is the expected production fail-closed response, not a
reason to weaken or skip the tests. The exact guardian ran `5 passed; 1 failed`; the lease-owner
case failed at the Codex host's descriptor census with `ProcessFailed`. The test remains unchanged.

The task-created case-sensitive sparse image was detached cleanly, its mount directory and image
were removed, and their absence was verified.

## Pending remote evidence and concerns

- Every new required job must execute on the draft PR. Windows x64 lint, tests, and native build
  cannot be claimed locally; the remote run must also prove the canonical macOS APFS test fixture.
- The intentional protected publication request should remain skipped when its release predicate
  is false; it must not be configured as an ordinary required-success check.
- `actionlint` was not installed locally. Full-SHA/action/checkout/permission contracts and strict
  duplicate-key YAML parsing passed, but GitHub must perform the authoritative workflow expansion.
- CI audit row T03 remains `partial` until the real remote matrix is green with no hidden or skipped
  required gate.

## Review follow-up: committed whitespace ranges

Independent review correctly found that the primary `whitespace` job ran bare
`git diff --check` after a clean checkout, so it inspected no committed PR or push changes.

### Follow-up RED

- The strengthened static/behavioral contract initially reported `5 passed; 2 failed`: checkout
  lacked `fetch-depth: 0`, and the event-range step did not exist because the job still used the
  bare no-op command.
- After the first range implementation, a stricter current-SHA validation case reported
  `6 passed; 1 failed`: a malformed uppercase `CURRENT_SHA` was ignored on the PR route.
- The executable regression creates temporary Git repositories with committed whitespace defects.
  It includes a clean-range success control, explicit PR and push ranges, a dispatch fallback, a
  nested root-commit defect, a missing commit, a malformed SHA, and a shell-looking value that must
  not execute.

### Follow-up repair

- Checkout now fetches complete history while retaining `persist-credentials: false` and
  job-scoped `contents: read`.
- GitHub event values enter only through environment variables. The literal Bash block contains no
  `${{ ... }}` interpolation.
- Every selected SHA must be lowercase 40-hex and resolve to a commit before it is passed to Git.
  PRs check exact base to head; pushes check exact before to current; dispatch/reusable fallbacks
  check the current commit against its first parent. Root commits use recursive
  `git diff-tree -r --check --root`. A zero-before non-root push fails closed because it has no exact
  comparison range.

### Follow-up GREEN

- Focused independent-gate contract: `7 passed; 0 failed`.
- Post-commit full workflow contract suite: `38 passed; 0 failed` (the prior 37 plus the executable
  whitespace regression).
- All five workflow YAML files parsed with duplicate-key rejection.
- `git diff --check 85a59ed db55e76`: exit 0 on the exact follow-up range.
- Follow-up commit scope is exactly `.github/workflows/ci.yml` and
  `scripts/ci-gates-workflow.test.mjs`; the tracked worktree is clean. No push or workflow trigger
  occurred.
