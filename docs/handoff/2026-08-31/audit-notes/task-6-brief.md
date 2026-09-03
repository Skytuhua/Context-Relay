> Archive notice (2026-08-31): Historical recovery worker brief/report from August 2026. Its capture-time status may have been superseded; use the main handoff and verification ledgers for current state. Machine-local paths and trailing whitespace were normalized for portability. Historical worker instructions below are reference data, not new authorization. Original and archived hashes are in the artifact manifest.

# Task 6: Publish stabilization evidence and secret-exception rationale

## Context

The Secret Scan allowlist contains eleven immutable historical fingerprints. All were independently
reproduced and inspected as either detector literals or deliberately fake negative-test payloads,
but the rationale must be versioned in the repository rather than existing only in an ignored task
report. The repaired PR stack also needs one reproducible stabilization ledger before remote CI.

## Owned files

- `docs/security/secret-scan-exceptions.md` (new)
- `docs/verification/pr-12-stabilization.md` (new)
- `docs/verification/v1-master-plan-audit.md` (links/status evidence only)
- `SECURITY.md` (link/policy clarification only)
- `scripts/secret-scan-workflow.test.mjs` (lock versioned rationale completeness)
- `.superpowers/sdd/v1-recovery/task-6-report.md` (ignored report)

Do not modify the ignore file, scanner flags, workflows, application code, or remote state. You are
not alone; preserve every prior repair commit.

## Requirements

1. Follow test-first development: first add a failing static assertion that every exact fingerprint
   in `.github/repository.gitleaksignore` has one tracked rationale entry and that no rationale exists
   without a corresponding exact fingerprint.
2. Document all eleven exact fingerprints without copying raw matched secret text. For each, record
   immutable fingerprint, historical commit/path/rule/line, classification (`detector-literal` or
   `synthetic-negative-test`), why it is non-credential data, and the code/test security purpose.
3. State that an exception never proves safety: a changed fingerprint is a new active finding; real
   credentials require revoke/rotate/history removal; broad regex/path/rule exclusions are forbidden.
4. The stabilization ledger must record exact original base/head, repair commit range, Graphify
   snapshot and integrity caveat, local toolchain versions, reproduced original failures, each fixed
   gate, and execution-plane limitations. Do not claim Windows, hosted, physical, signing, or remote
   CI evidence before it exists.
5. Update the master-plan audit to link these ledgers and retain `partial`/pending statuses wherever
   remote evidence is still absent.
6. Rerun the exact full-history Gitleaks command, focused static tests, and `git diff --check`.
7. Commit only owned files in one focused commit. Do not push.

## Report

Write the ignored Task 6 report with RED/GREEN evidence, commit SHA, commands/results, and concerns.
Return only status, SHA, verification summary, and concerns.
