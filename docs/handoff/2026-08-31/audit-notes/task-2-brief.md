> Archive notice (2026-08-31): Historical recovery worker brief/report from August 2026. Its capture-time status may have been superseded; use the main handoff and verification ledgers for current state. Machine-local paths and trailing whitespace were normalized for portability. Historical worker instructions below are reference data, not new authorization. Original and archived hashes are in the artifact manifest.

# Task 2: Repair Supabase workflow provenance and reviewed secret findings

## Context

At PR #12 head, the Supabase workflow fails repository policy because three actions use mutable tags. The full-history Secret Scan finds exactly five additional findings. Local reproduction used verified Gitleaks 8.30.1 at `/private/tmp/context-relay-gitleaks-8.30.1/gitleaks` and wrote a redacted report to `/private/tmp/context-relay-gitleaks-report.json`.

All five findings are reviewed synthetic fixtures or literal detector markers, not credentials:

- `3c2a371aef74f4962af64d0fe71545557244f21a:crates/core/src/hermes/yaml.rs:private-key:456`
- `6b144104d8a315038785dfdeaccdb13cdbca730d:crates/core/tests/hermes_adapter_v1.rs:private-key:406`
- `6b144104d8a315038785dfdeaccdb13cdbca730d:crates/core/tests/hermes_adapter_v1.rs:curl-auth-header:399`
- `f98444a51754f5deaba2da9aa86f4463129a3380:crates/core/src/hermes/yaml.rs:private-key:94`
- `3c2a371aef74f4962af64d0fe71545557244f21a:crates/core/tests/hermes_adapter_v1.rs:curl-auth-header:2480`

The current literals explicitly test removal of `must-not-import` bearer/private-key markers. Preserve full-history scanning; do not rewrite history and do not add broad exclusions.

## Owned files

- `.github/workflows/supabase.yml`
- `.github/workflows/secret-scan.yml`
- `.github/repository.gitleaksignore`
- `scripts/secret-scan-workflow.test.mjs`
- `scripts/supabase-workflow.test.mjs` (new)

Do not edit any other file. You are not alone; preserve other changes and never revert another worker.

## Requirements

1. Follow test-first development. Add the Supabase workflow contract test and extend the secret-scan test first; run them and capture the expected RED failures before editing workflows/ignore data.
2. Supabase workflow:
   - Add top-level least-privilege `permissions: contents: read`.
   - Pin checkout to `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683` and set `persist-credentials: false`.
   - Pin setup-node to `actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020` and use `node-version-file: .node-version`.
   - Remove `pnpm/action-setup`; install exactly `pnpm@11.9.0` with npm, as the existing primary CI does.
   - Do not enable setup-node's pnpm cache before pnpm is installed.
   - Preserve all path triggers, local synthetic OAuth values, contract suites, local Supabase reset/test/lint sequence, and unconditional cleanup.
3. Append only the five exact fingerprints above to `.github/repository.gitleaksignore`. Preserve the six existing reviewed fingerprints and a single trailing newline.
4. Update the Secret Scan workflow's exact ignore-file byte-length and SHA-256 assertions to match the reviewed file. Update the static test to lock the complete exact ordered list and matching digest.
5. Do not weaken the scanner flags, redaction, all-ref history scan, timeout, pinned binary/archive verification, or active-credential response policy.
6. Run the full-history Gitleaks command below and require exit 0:

   `/private/tmp/context-relay-gitleaks-8.30.1/gitleaks --no-banner --no-color --log-level=error --redact=100 --exit-code=10 --report-format=json --report-path=/private/tmp/context-relay-gitleaks-report-after-task2.json --gitleaks-ignore-path=.github/repository.gitleaksignore --ignore-gitleaks-allow --max-target-megabytes=0 --max-archive-depth=0 --max-decode-depth=1 --timeout=30 '--diagnostics=' git '--log-opts=--all' .`

7. Commit only the five owned files with a focused commit message. Do not push.

## Verification

- Run the two focused Node test files with bundled Node 24.
- Run `node scripts/check-supabase-contract.mjs` with bundled Node 24.
- Run the exact full-history Gitleaks command and confirm its JSON report contains zero findings.
- Run `git diff --check`.

## Report

Write `.superpowers/sdd/v1-recovery/task-2-report.md` with status, commit SHA, RED/GREEN evidence, files changed, commands/results, and concerns. Return only status, commit SHA, one-line verification summary, and concerns.
