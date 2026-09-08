# Account lifecycle integration plan

> **For agentic workers:** Use superpowers:executing-plans to implement and verify each task. The full release ledger remains open after this slice.

**Goal:** Recover the preserved account-lifecycle boundary without stale authority, stale replay state, or newly authorized mutations on recovery.

**Architecture:** Reuse the Rust transport, ordered daemon worker and session-bound Edge/SQL implementation in `6eb5ec8`, with whitespace correction `485886c`. Keep the unavailable production transport until daemon-owned authentication and durable operation recovery are implemented and verified. Never cherry-pick the entire historical branch.

**Stack:** Existing Rust/reqwest, Node test runner, Supabase/PostgreSQL/pgTAP and pinned GitHub Actions.

## 1. Recover the reviewed source

- [ ] Apply the two preserved commits without committing, resolve only the changed daemon worker integration, and inspect every resulting hunk against current HEAD. Preserve desktop writes, search and harness execution.
- [ ] Run the existing Edge/transport checks listed in `docs/verification/task-17-account-lifecycle-wip.md`. These are a baseline, not SQL execution evidence.
- [ ] Adapt the existing Supabase workflow path filters and test commands to include lifecycle tests without weakening any existing gate.

## 2. Reproduce and fix authority expiry after lock waits

- [ ] Add a real PostgreSQL two-connection check: create isolated Auth/session/device/account fixtures with a short-lived binding; hold the account lock in connection A; start a lifecycle request in B; confirm B is waiting; wait past expiry; release A. B must reject with `revoked`, leaving account state and receipts unchanged. Use bounded lock/statement timeouts and always close connections.
- [ ] Run it against the preserved migration and observe failure before editing authority checks.
- [ ] Replace transaction-start-time binding expiry checks with wall-clock checks. Revalidate session and binding expiry after all potentially blocking authority locks, including the Auth session lock. Preserve account/device/epoch/session matching and legacy privilege revocations.
- [ ] Repeat for Auth-session expiry and credential freshness while blocked, plus valid nonexpired requests.

## 3. Reconcile replay with current state

- [ ] Add executable SQL cases for begin A → cancel B → replay A and cancel A → begin B → replay A. Replays must not mutate, must preserve the intervening transition and must return current authoritative state rather than a historical receipt projection.
- [ ] Keep receipt identity checks (account, user, session, workspace, action and request bytes). On a matching receipt, return the account projection under the existing account lock; do not rerun the transition.
- [ ] Verify wrong action/session/workspace reuse remains denied, receipt storage remains bounded and no duplicate mutation occurs on replay.

## 4. Reconcile legacy pgTAP contracts

- [ ] Preserve denial of direct legacy begin/cancel calls by `service_role`; update old grant expectations and internal state tests to their proper owner role.
- [ ] Exercise public session wrappers through the real service role: missing/deleted/expired Auth sessions; foreign user/workspace; stale epoch; revoked binding; malformed IDs; rate limits; freshness and replay.
- [ ] Run all migrations and the complete pgTAP suite from an empty disposable database, followed by lint/advisors. Do not use the connected production project as a scratch database.

## 5. Define durable caller operation identity before activation

- [ ] Trace desktop→IPC→ordered worker→vault and reuse durable write/operation storage where compatible. A begin/cancel intent must retain one request ID across a lost acknowledgment and restart; explicit new user actions get new IDs.
- [ ] Write the bounded interface/storage design with exact retry and cancellation semantics before implementation. Existing empty cancel params and begin confirmation alone do not express durable identity.
- [ ] Test lost acknowledgment, daemon restart and intervening opposite actions. Status reconciliation must not replay a mutation or manufacture fresh credential approval.

## 6. Verify and record the boundary

- [ ] Run affected Rust suites and Clippy with one Cargo job at a time; Node/Edge tests; schema/binding/daemon-boundary and whitespace checks; full disposable SQL checks.
- [ ] Request independent review of the integrated patch and address actionable findings.
- [ ] Update the release and lifecycle ledgers with exact source, commands, failures/fixes and limitations; run Graphify update.
- [ ] Commit/push only the verified slice. Keep PR16 unmerged until all product, hosted, signing and physical acceptance requirements pass.

## Separately required release work

Production OAuth/session provisioning and refresh, sync and pairing/recovery transport wiring, reassociation/revocation/rotation, native recovery phrase entry, final purge/export, package workflows, remaining desktop surfaces, signing and physical qualification remain necessary after this boundary is repaired. This plan does not mark any of them complete.
