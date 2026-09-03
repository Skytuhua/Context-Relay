> Archive notice (2026-08-31): Historical recovery worker brief/report from August 2026. Its capture-time status may have been superseded; use the main handoff and verification ledgers for current state. Machine-local paths and trailing whitespace were normalized for portability. Historical worker instructions below are reference data, not new authorization. Original and archived hashes are in the artifact manifest.

# Task 5: Make required CI gates independent and complete

## Context

The current `rust` job is a serial chain on Windows. Its strict Clippy failure hides workspace
tests, daemon-boundary policy, generated binding/schema drift, license inventory, Cargo dependency
policy, and whitespace checks. The `native` job mixes limited crate tests with Tauri builds and
does not provide independently visible full supported-host lint/test gates. Basic CI checkout
steps also persist GitHub credentials by default.

The native Semgrep candidate verifier has one deliberately gated feature,
`ci-candidate-sidecar-smoke`, that must remain confined to the exact ignored smoke tests. Do not
enable that feature across the workspace merely to claim `--all-features`; test every ordinary
`test-support` feature on both supported hosts and keep the candidate verifier's exact isolated
gates. Record this strengthening clarification in the amendment ledger.

## Owned files

- `.github/workflows/ci.yml`
- all other `.github/workflows/*.{yml,yaml}` only if a static provenance test finds an actual
  mutable action or unnecessary persisted checkout credential
- `scripts/ci-gates-workflow.test.mjs` (new)
- `scripts/native-ci-workflow.test.mjs` only for a necessary, security-preserving assertion update
- `docs/protocols/contract-amendments.md` (A-004 CI feature-scope clarification)
- `docs/verification/v1-master-plan-audit.md` (evidence/next-gate update only)
- `.superpowers/sdd/v1-recovery/task-5-report.md` (ignored report)

Do not change application behavior, dependencies, generated artifacts, Semgrep provenance pins,
publication authorization, or hosted workflows outside a proven contract issue. You are not
alone; preserve all other commits and do not revert another worker.

## Requirements

1. Follow test-first development. Add a static workflow contract that fails against the current
   serial/masked CI before editing workflows.
2. Every third-party `uses:` in every workflow must use a full 40-character commit SHA. Local
   reusable workflows are allowed. Every ordinary checkout that does not intentionally push must
   set `persist-credentials: false`. Preserve least-privilege top/job permissions and the protected
   publication workflow's intentional job-scoped write grant.
3. Keep an independently visible compatibility check named `rust`, but make strict formatting/
   lint failure unable to prevent these separate jobs from starting:
   - supported-host Rust tests,
   - daemon-boundary policy,
   - generated Rust/TypeScript binding drift,
   - JSON schema drift,
   - license inventory,
   - Cargo dependency policy,
   - whitespace/diff policy,
   - frontend lint/typecheck/tests/build,
   - supported native Tauri builds.
   Use separate jobs (or a matrix whose individual checks remain visible) with no lint dependency.
4. Run strict Rust lint and workspace tests on both Windows x64 and macOS arm64. Exercise all
   ordinary feature surfaces, including every `test-support` feature, without broadly enabling
   `ci-candidate-sidecar-smoke`. That feature remains enabled only for the exact registered ignored
   Semgrep candidate tests already locked by `native-ci-workflow.test.mjs`.
5. Keep native builds independent from tests so a test failure does not hide whether the supported
   Tauri artifact compiles. Preserve the existing exact macOS guardian test and contextd/local-IPC
   host coverage in the appropriate independent test job.
6. Keep frontend gates independent and unchanged in strength.
7. Do not weaken or silently skip the native-isolation jobs. Preserve reusable qualification,
   artifact reuse, publication, source-lock, and protected-environment semantics. Avoid triggering
   native Semgrep material rebuilds solely from a test-file path unless the workflow itself must
   change.
8. Add static assertions for job independence, exact host matrices, strict warnings, ordinary
   feature coverage, candidate-feature confinement, action pinning, checkout credentials,
   permissions, and every independently visible gate.
9. A-004 must explain why broad Cargo `--all-features` is not semantically correct for the
   release-candidate-only verifier, list the exact ordinary features executed, preserve/strengthen
   the master plan, and identify compatibility/evidence impact. Update the audit matrix without
   marking CI `verified` before a real remote run.
10. Commit only owned files in one focused commit. Do not push.

## Verification

- Run the new CI contract test, existing native CI workflow test, Supabase workflow test, and
  secret-scan workflow test with bundled Node 24.
- Run all repository workflow/static policy checkers affected by the edit.
- Parse/inspect workflow YAML with an available repository/runtime parser if possible, including
  duplicate-key rejection.
- Run `git diff --check`.
- Do not claim remote job execution. The root controller will push the reviewed stack to the draft
  PR and require every check to complete without hidden/skipped required gates.

## Report

Write `.superpowers/sdd/v1-recovery/task-5-report.md` with status, commit SHA, RED/GREEN evidence,
job map, commands/results, remote evidence still pending, and concerns. Return only status, commit
SHA, one-line verification summary, and concerns.
