# Task 17 account lifecycle — preservation checkpoint

Date: 2026-08-31. Status: **partial; draft preservation PR, not ready to merge or deploy**.
Base: PR #12 at `435367d8d8ba24aac413a094a4b8b5bc61d52d22`.
Branch: `codex/task17-account-lifecycle-wip`.

The user explicitly requested that unfinished local work be preserved on GitHub
for another device. This checkpoint preserves that work without implying that
Task 17 or its database integration is finished. Only Rust formatting was
normalized during preservation; the pending functionality was not completed.

## Included work

- `crates/core/src/devices/account_lifecycle.rs`: session-bound transport trait,
  strict seven-day deletion projection, sanitized errors.
- `crates/core/src/devices/supabase_account_lifecycle.rs`: concrete HTTPS transport
  for status/begin/cancel, bounded retries, strict response parsing, opaque
  32-byte mutation request IDs retained across retries.
- `crates/contextd/src/account_lifecycle.rs` and daemon wiring: lifecycle requests
  use the ordered vault worker; production defaults to unavailable. The renderer
  cannot provide a transport, account/session authority, or trusted projection.
- `crates/core/src/sync/supabase.rs`: crate-private shared HTTP plumbing;
  HTTPS-only requests with redirects disabled. External inspection seams remain
  behind `test-support`.
- `supabase/functions/account-lifecycle/{core.mjs,adapter.mjs,index.ts}`: bounded
  request parsing, verified JWT claims, signed OAuth AMR freshness, service-only
  RPC invocation, and redacted errors.
- `supabase/migrations/20260831051540_account_lifecycle.sql`: live Auth-session
  validation, serialized account checks, rate budget, durable replay receipts,
  seven-day state projection, and session-bound RPC wrappers. This migration was
  created with the pinned Supabase CLI; it has **not been executed here**.
- Rust, Edge, static SQL, workflow tests, and Supabase function configuration.

## Fresh preservation verification

Host: macOS arm64; Rust 1.97.1; bundled Node 24.19.0 (repository/CI pin:
24.14.0). No hosted credentials used.

| Command | Result |
| --- | --- |
| `node --test scripts/tests/account-lifecycle-edge.test.mjs scripts/tests/account-lifecycle-cloud-admission.test.mjs scripts/tests/supabase-sync-rust-boundary.test.mjs scripts/supabase-workflow.test.mjs` | 21 passed |
| `node scripts/check-supabase-contract.mjs` | Exit 0 |
| `cargo +1.97.1 test -p context-relay-core --features test-support --test account_lifecycle_transport_v1 --test supabase_account_lifecycle_v1` | 3 passed |
| `cargo +1.97.1 test -p context-relay-contextd --features test-support --lib account_lifecycle -- --nocapture` | 2 passed with real local-socket access |
| `cargo +1.97.1 clippy -p context-relay-core -p context-relay-contextd --all-targets --features context-relay-core/test-support,context-relay-contextd/test-support -- -D warnings` | Exit 0 |

These 26 focused tests do not execute the migration, exercise real OAuth, prove
cross-account isolation on a hosted project, or enable production deletion.
The Node SQL assertions inspect source text, not PostgreSQL behavior.

### First public preservation run

[Draft PR #13](https://github.com/Skytuhua/Context-Relay/pull/13) preserves this
slice at `485886c2d3ad5105c5ea5114851d18045c25fc74`.
GitHub's disposable local Supabase stack in
[run 33385426361](https://github.com/Skytuhua/Context-Relay/actions/runs/33385426361)
successfully reset through the migration, then reproduced the expected legacy
test incompatibility: assertion 122 failed, and line 2703 aborted with permission
denied for `service_begin_account_deletion`. The suite ran 469 of 518 planned
assertions, with one failed assertion and 49 not run. This is CI-container
execution evidence, not hosted project deployment or proof that the new wrappers
are correct. Database lint was not reached. Secret Scan passed on the new head.

## Known unfinished integration — start here

1. The new migration revokes `service_role` execution of legacy
   `service_begin_account_deletion(uuid)` and `service_cancel_account_deletion(uuid)`.
   The existing `supabase/tests/0001_context_relay_ciphertext_boundary_test.sql`
   still expects those grants (around lines 686–687) and calls them as
   `service_role` (deletion section around lines 2698–2855). This is a known
   incompatible test contract. The full SQL workflow is expected to remain red
   until the old internal-state tests and new public-boundary tests are reconciled.
   Do not restore the revoked public authority merely to make tests pass.
2. Add executable pgTAP coverage for the new session-bound wrappers: actual
   Auth-session revocation/expiry, binding expiry, stale epochs, foreign account
   and workspace rejection, post-lock credential freshness, rate limiting,
   receipt binding, and replay after intervening begin/cancel actions.
3. Run migrations and the complete SQL suite from an empty disposable local
   Supabase database, then lint/advisors. Docker/PostgreSQL were unavailable on
   the originating host; there is no local SQL execution evidence for this file.
4. The ordinary daemon still constructs `UnavailableAccountLifecycleTransport`.
   Production authenticated-session ownership, provisioning, transport injection,
   refresh/expiry handling, and lifecycle UI freshness UX are not implemented.
5. The first signed AMR entry (`claims.amr[0]`, currently assumed newest) must
   be `method: "oauth"` and at most 300 seconds old. Verify the real supported
   GitHub OAuth claim shape and ordering before activation; refreshing a JWT
   must not manufacture fresh credential evidence.
6. New request IDs survive retries within a transport call. Define and test
   caller retry/crash behavior before claiming full user-operation idempotency.
7. This slice does not implement the final purge scheduler, export product flow,
   reassociation, device revocation/epoch rotation, pairing/recovery production
   transports, or native fresh-recovery phrase entry.

## Security invariants to preserve

- User/session authority comes from verified JWT claims, never request ownership
  fields or user-editable metadata.
- Check the live `auth.sessions` row; a signed but stale JWT is insufficient for
  immediate revocation guarantees.
- Serialize account transitions, then recheck session/device/workspace/epoch
  authority and credential freshness.
- Mutation request IDs are exact 64-character lowercase hex (32 bytes). Receipts
  bind account, auth user, session, workspace, action, and projection.
- Receipts are not evicted while the account exists; the draft implementation
  fails closed at 10,000 receipts per account. Rate budget is 30 requests/60 s.
- No privileged keys in the renderer, logs, ordinary IPC, or committed config.
- `verify_jwt = false` at the Edge gateway does not mean unauthenticated service:
  the function must verify claims itself before the service client is used.
- Fresh database/hosted approval is still required before any deployment or
  production migration. A draft PR is source preservation only.
