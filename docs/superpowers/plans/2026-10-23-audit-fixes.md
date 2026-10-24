# Audit Fixes Implementation Plan

> **For agentic workers:** Execute the seven authorized audit fixes with regression tests and a final independent code review.

**Goal:** Fix all seven findings from the October 23 repository audit.

**Architecture:** Preserve the existing daemon, vault, desktop gateway, and hosted API boundaries. Reuse existing project path binding and bounded request reading; add bounded continuation to record lists and preserve device sequence during retries.

**Tech Stack:** Rust, SQLCipher, React/TypeScript, Tauri, Node tests, Supabase Edge Functions.

**Spec:** The seven numbered findings in this task's audit report, reviewed at main dcbdfb59600dc08547a42edb05762786d7a77195.

## Constraints and review focus

- Preserve saved records, stable project IDs, deterministic import IDs, authorization, and existing error mapping.
- Gate later sync operations behind deferred, blocked, or otherwise ineligible predecessors.
- Bound serialized list pages, including escaped JSON, and expose continuation without silent truncation.
- Bind an existing project to a validated local directory without creating another project.
- Keep dependency versions pinned and update lockfile/policy checks together.
- Serialize Rust builds with debug symbols and incremental compilation disabled to limit disk use.
- Do not deploy, publish, or migrate a live service as part of these local fixes.

## Tasks

### 1. Ordered sync retries
- [x] Add a regression proving a deferred predecessor gates later operations, including the hosted admission rule.
- [x] Fix selection in `crates/core/src/vault/sync.rs` and update the previous unsafe retry expectation.
- [x] Run focused sync engine and vault sync tests.

### 2. Patched development dependencies
- [x] Update `scripts/dependency-policy.test.mjs` to require Vite 7.3.7 and Vitest 4.1.12; observe the old pins fail.
- [x] Update `apps/desktop/package.json` and `pnpm-lock.yaml` with the patched versions.
- [x] Run the policy test, dependency audit, frontend tests, typecheck, lint, and build.

### 3. Bounded list pages
- [x] Add tests that page valid records beyond the 8 MiB IPC and 2 MiB MCP output ceilings without loss or duplication.
- [x] Add validated continuation to protocol/vault/daemon lists and MCP task lists.
- [x] Update generated bindings/schema and desktop readers to consume all pages.
- [x] Run protocol, vault, daemon/MCP, binding/schema, and frontend tests.

### 4. Existing project folder binding
- [x] Add frontend tests that bind an existing project while preserving its ID and handle invalid folders.
- [x] Expose `project_path_set` through the gateway and reachable project/onboarding UI; preserve daemon directory validation.
- [x] Run focused project/workspace/onboarding tests and daemon path tests.

### 5. Import timestamps
- [x] Add a regression separating deterministic import identity from actual observed time.
- [x] Fix native-memory candidate clocks and callers without losing deduplication.
- [x] Run native-memory reconciliation/service tests.

### 6. Development port
- [x] Configure Vite port 1420 with `strictPort: true` in `apps/desktop/vite.config.ts`.
- [x] Resolve Vite configuration and assert it matches Tauri's `devUrl`.

### 7. Shared bounded request reader
- [x] Run existing sync tests for size limits, malformed streams, cancellation, and error mapping.
- [x] Replace the duplicated reader in `supabase/functions/sync/core.mjs` with the existing account-lifecycle helper.
- [x] Run sync, account-lifecycle, pairing, and enrollment Node tests.

## Final verification
- [x] Run relevant complete test suites with bounded concurrency; report platform or environment failures by name.
- [x] Run formatting, type/lint/build, dependency audit, generated-contract checks, and `git diff --check`.
- [x] Obtain independent code review, resolve material findings, and rerun affected tests.
- [x] Report remaining native/live acceptance limits and leave all changes reviewable locally.

## Verification receipts

- Desktop: **511 passed across 61 files**, full final run with one worker and no file parallelism.
- Backend/Edge Functions: **252 passed**; the existing Realtime verifier is excluded because it rejects Windows at startup.
- Release/script contracts: **152 passed, 5 skipped** for platform/tool availability.
- `pnpm typecheck`, `pnpm lint`, `pnpm build`, `pnpm check:bindings`, `pnpm check:schemas`, Rust formatting, and whitespace checks passed.
- Strict Clippy passed for protocol, local IPC, core, daemon, and MCP, including all targets and test-support features.
- `pnpm audit --audit-level low`: **no known vulnerabilities** after updating Vite, Vitest, fast-uri, and undici pins.
- Independent correctness and security reviews found no material blocker; generated contracts were reviewed after regeneration.
- Relevant Rust suites: **733 passed, 13 ignored, zero failures**, including the complete **256-scenario** randomized convergence test. The two new retry-order regressions also passed independently.

| Rust scope | Passed | Ignored |
| --- | ---: | ---: |
| Core: 19 integration suites | 285 | 0 |
| Protocol and local IPC | 241 | 3 |
| Daemon library and harness setup | 137 | 6 |
| MCP bridge | 70 | 4 |

Rust builds used `CARGO_TARGET_DIR=target/audit-fixes`, debug symbols disabled, incremental compilation disabled, and two build jobs. The final 17 core suites used two test threads after contention in the initial parallel attempt. Logs are saved under `%TEMP%/context-relay-audit-fixes-*.log`.

## Preserved data and acceptance boundaries

- New native imports receive actual observation clocks. Existing imported clocks remain unchanged because they are part of saved candidate identity, replay receipts, and potentially signed history; repair requires a separate data migration.
- Existing integrity quarantines still require forensic recovery. The retry fix prevents new ordering-induced quarantines.
- Individual MCP records that exceed its serialized output ceiling return an explicit limit error. List pages never silently truncate record bodies.
- Page traversal uses live keysets rather than snapshot isolation during concurrent edits.
- Installed-app, live cloud/two-PC, macOS, and native packaging acceptance were not run. This change does not qualify or publish a release.
- Compiler-backed sidecar hydration, Semgrep-runtime preparation, and daemon-boundary script test suites were excluded; the relevant Rust daemon tests and strict Clippy checks passed.
