> Archive notice (2026-08-31): Historical recovery worker brief/report from August 2026. Its capture-time status may have been superseded; use the main handoff and verification ledgers for current state. Machine-local paths and trailing whitespace were normalized for portability. Historical worker instructions below are reference data, not new authorization. Original and archived hashes are in the artifact manifest.

# Task 6 report: Stabilization evidence and secret-exception rationale

## Status

Implementation and local verification are complete from the exact clean starting SHA
`f8376450892aed6395268645c7f791f8ebe2b47f`. The focused tracked commit is recorded below. Nothing
was pushed or otherwise mutated remotely.

## Commit

- `7a3bc8caf9fca940f1bb7cdfcef30b356e811f38` — `docs: publish PR stabilization evidence`

## Independent historical inspection

Every one of the eleven exact `.github/repository.gitleaksignore` fingerprints was resolved to its
historical Git object and inspected without emitting the matched payload. The classifications are:

- 2 `detector-literal` entries: the two historical locations of the Hermes
  `scan_text_secret` private-key marker.
- 9 `synthetic-negative-test` entries: two native real-sidecar scanner fixtures, four Rust/TypeScript
  package-extension rejection fixtures, and three Hermes embedded-secret redaction fixtures.

No current-path inference or earlier claims ledger was used as a substitute for the historical
objects. The tracked rationale records exact commit, path, rule, line, non-credential basis, and
security purpose without copying a raw match.

## RED evidence

The first test-only edit added the one-to-one rationale contract, required metadata and allowed
classification checks, and raw-payload-shape denial. With no rationale document present, the
focused command ran 4 tests and reported 3 passed / 1 failed with the intended message:

```text
the tracked secret-scan exception rationale document is missing
```

The test-only contract was then expanded to cover the SECURITY policy/link and audit links while
requiring T03 to remain `partial`. Before any production document was edited, the focused command
ran 5 tests and reported 2 passed / 3 failed for exactly the missing rationale, missing policy/link,
and missing audit links.

## GREEN evidence

After the two ledgers and link/policy edits were added, the first focused run reported 4 passed /
1 failed because its policy regex did not permit Markdown line wrapping. The assertion was corrected
to recognize whitespace without weakening the required sentence. The fresh focused run then passed
5/5.

The combined workflow contract command passed 40/40:

```text
<origin-host>/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node --test \
  scripts/secret-scan-workflow.test.mjs \
  scripts/supabase-workflow.test.mjs \
  scripts/ci-gates-workflow.test.mjs \
  scripts/native-ci-workflow.test.mjs
```

The ignore file was not modified: it remains 1,103 bytes with SHA-256
`651da29e101f61580d789284520431ca8aaf944f933394b86130149b865d6032`.

The exact required full-history scan command was run:

```text
/private/tmp/context-relay-gitleaks-8.30.1/gitleaks --no-banner --no-color --log-level=error --redact=100 --exit-code=10 --report-format=json --report-path=/private/tmp/context-relay-gitleaks-report-after-task6.json --gitleaks-ignore-path=.github/repository.gitleaksignore --ignore-gitleaks-allow --max-target-megabytes=0 --max-archive-depth=0 --max-decode-depth=1 --timeout=30 '--diagnostics=' git '--log-opts=--all' .
```

- Pre-commit scan: exit 0; parsed JSON top level was an array with 0 findings.
- Post-commit scan at `7a3bc8caf9fca940f1bb7cdfcef30b356e811f38`: exit 0; parsed JSON
  top level was an array with 0 findings.
- Post-commit focused secret-scan contracts: 5 passed / 0 failed.
- `git diff --check HEAD^ HEAD`: exit 0.
- `git show --name-only HEAD`: exactly the five owned tracked files listed below.
- Final tracked worktree: clean; the report remains ignored and was not committed.

## Tracked files

- `docs/security/secret-scan-exceptions.md`
- `docs/verification/pr-12-stabilization.md`
- `docs/verification/v1-master-plan-audit.md`
- `SECURITY.md`
- `scripts/secret-scan-workflow.test.mjs`

The ignored report is `.superpowers/sdd/v1-recovery/task-6-report.md`.

## Concerns and limits

- Actual GitHub-hosted Windows x64/macOS arm64 execution, workflow expansion, and the canonical APFS
  fixture remain pending. T03 is still `partial`.
- The Task 4 MSVC core/contextd check did not compile project crates; it stopped at vendored
  OpenSSL/`onig_sys` host prerequisites. The ledger does not claim a Windows Task 4 build pass.
- Hosted, credentialed, physical-device, signing, deployment, publication, and release evidence are
  not claimed. No approval-gated action was performed.
