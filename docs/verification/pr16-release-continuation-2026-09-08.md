# PR 16 full-release continuation — 2026-09-08

The user explicitly requires the complete product-release checklist before merging
PR #16. Passing the current desktop/setup checks is insufficient. The
[Windows acceptance ledger](windows-app-release.md) and
[v1 audit](v1-master-plan-audit.md) retain their requirements.

## Fresh source verification

Reviewed GitHub PR #16 at `f3dc22b908492ea2ed97764d446b1ed64babb6e9`, based on
`b3d487e0965a87f69a0d7acf07066daa6a29f132`. All executable checks passed, including
Windows/macOS native tests, installer assembly and the Supabase contract job.
CodeRabbit skipped review because the PR exceeded its file limit. A bounded
independent review found no additional P1/P2 issues in the newest desktop
changes and selected receipt, launch and installer boundaries; it did not review
every file or establish installed-release acceptance.

A fresh local frontend run failed one of 345 tests. A focused rerun exposed two
navigation timing failures: the tests clicked Continue or Claude Code as soon as
the saved-result heading appeared, before the parent navigation guard cleared.
Both tests now explicitly await enabled controls. Production guards and existing
result assertions are unchanged. The focused eight tests and full 345 tests in
39 files pass; TypeScript, ESLint, production build and whitespace checks pass.

## Release work remains

1. Recover and validate the account-lifecycle work preserved in `6eb5ec8` and
   `485886c`. Its own ledger identifies incompatible legacy SQL grants/tests,
   missing executable session/replay/expiry coverage, and unavailable production
   transport ownership. Do not merge the entire historical branch or restore
   revoked service authority to satisfy obsolete tests.
2. Complete daemon-owned GitHub OAuth sessions, provisioning and production
   sync/pairing/recovery transports. Verify expiry, refresh, logout, device
   revocation/rotation, reassociation, deletion/purge and export end to end.
3. Complete repository identity and package quarantine/scanning/approval/install/
   removal, followed by conflict/history/import/export/diagnostic product flows.
4. Qualify the installed desktop and all supported harnesses, offline/restart/
   recovery paths, accessibility and performance on the required platforms.
5. Complete protected signing/notarization/updater signing, provenance, clean
   install/update/uninstall and security/reliability gates before release and merge.

Read-only hosted inspection found the Context Relay project active, with only
`20260805153409_context_relay_ciphertext_boundary` and
`20260805155753_revoke_context_relay_internal_execute` applied, and no deployed
Edge Functions. No hosted mutation or deployment was performed. Docker and psql
were not found on this shell's PATH; this is not proof that no alternative test
runtime exists. Hosted production is not a disposable SQL test database.

Signing identities and clean Windows/macOS acceptance-machine availability have
been requested from the user. Neither those gates nor installed-product
acceptance is claimed complete. PR #16 remains unmerged.

## Account lifecycle recovery: local evidence

Recovered the bounded `6eb5ec8` implementation onto the current branch without
merging its historical branch. Preserved both the current connection-check test
and the restored ordered-worker lifecycle test when resolving their overlapping
insertion. Production still uses the unavailable lifecycle transport.

An independent review found two defects: transaction-start timestamps could
accept authority that expired during a lock wait, and replaying an old receipt
could show obsolete state after an opposite action. The migration now checks
Auth-session expiry after acquiring its row lock, checks binding expiry after
both authority locks, and returns current locked state for a matching receipt
without repeating the transition. Legacy service-role entrypoints stay revoked;
their old pgTAP expectations were corrected.

On a dedicated loopback PostgreSQL 17.11 instance, the original six regression
cases produced five failures. After the fixes, all four migrations applied from
an empty database and all ten checks in
`scripts/verify-account-lifecycle-postgres.mjs` passed. They cover both replay
directions, binding/session expiry behind either lock, credential expiry behind
the account lock, stale credentials, foreign workspace, deleted session, stale
epoch, opposite-action receipt reuse, legacy privilege denial and rate limits.
The workflow now runs this script before its existing full pgTAP suite.

The 21 focused Node workflow/Edge/boundary checks also pass. Rust verification
is still running; full Supabase pgTAP execution remains pending. The portable
database uses minimal Auth/Storage/Realtime schema substitutes, so these local
results establish PostgreSQL behavior only, not Supabase or hosted acceptance.

Durable caller request identity across IPC retries and restart is still absent.
The existing encrypted `desktop_writes` storage is a candidate for retaining
intent, but its protocol currently excludes lifecycle operations. Production
activation requires that boundary, daemon-owned authenticated sessions, and
the remaining release gates; this recovery does not satisfy them.

## Full Supabase follow-up

At `9910011629701b209ea02b9d342d761bd42c10b4`,
[Supabase CI 34217794460](https://github.com/Skytuhua/Context-Relay/actions/runs/34217794460)
passed migration reset, all ten concurrent lifecycle checks, all 520 pgTAP
assertions and database lint. Earlier attempts exposed fixture-role assumptions:
Supabase's non-superuser `postgres` retains an admin-only owner membership.
The verifier now temporarily adds a self-grant and restores only that grant's
previous options, preserving managed grants. A local non-superuser run passed
all ten checks and confirmed its separate admin-only membership survived.
Independent review found no further P1/P2 issues in this correction.

The three focused Rust core/transport tests passed. Daemon validation initially
failed during linking when C: filled up (LNK1201). After copying and verifying
the generated cache on E:, both configured and unavailable daemon lifecycle
tests passed (88 unrelated unit tests filtered out). Automatic approval review
rejected removing the old C: cache without a detailed reason, so it remains
untouched; subsequent builds use E:. Clippy remains in progress.

Browser inspection confirmed no GitHub OAuth apps under Skytuhua and the GitHub
provider disabled on the Context Relay Supabase project. A registration form
is prepared for Context Relay with the exact hosted `/auth/v1/callback` URL;
wildcard matching and device flow remain disabled. Registration awaits the
browser tool's required confirmation. No OAuth app, client secret, hosted
provider change, signing account, or paid enrollment has been created.

## Caller operation identity

Protocol 1.13 requires the existing validated UUIDv7 operation ID for deletion
begin and cancel. The daemon forwards it unchanged; the hosted transport hashes
the fixed domain prefix and UUID bytes into the existing 32-byte receipt key.
The operation keeps its ID across repeated calls and recreated transports;
changing an action under that ID still encounters the server's receipt conflict
check. A fixed hash vector protects this mapping from accidental changes.

The missing-IPC-field and transport-call tests failed before implementation.
All 130 protocol tests and all 345 frontend tests now pass; frontend typecheck,
lint and production build also pass. Bindings and schemas were regenerated.
Independent review identified that the version bump would prevent shutdown of
a running 1.12 daemon during installer upgrade. A frozen-version regression
reproduced that failure, then passed after adding explicit shutdown-only 1.12
compatibility. All 16 shutdown tests pass, with one internal child fixture
ignored in the parent test run; ordinary clients still reject 1.12.

All four core lifecycle tests, both daemon lifecycle tests, 26 IPC integration
tests and 25 MCP memory tests pass. The protocol bump also required updating
the two frozen authentication transcript vectors, independently recalculated
with Node HMAC-SHA256 before the passing IPC rerun. Generated binding/schema
checks, daemon-boundary, formatting and whitespace checks pass. All 21 Edge,
SQL-source and workflow checks pass; Graphify update completed. The prior
local Clippy run was stopped intentionally to run the new regression cases;
it does not establish a passing lint result for this change. The replacement
Clippy run passed for protocol, core, local-ipc and contextd, all targets with
test-support and warnings denied, at pushed commit `1ae7c3d`. Durable encrypted
intent storage, original account/session binding and recovery UI remain absent.
This interface change alone does not complete restart recovery or permit
production lifecycle activation.

Git's automatic maintenance after that commit failed because C: was full; the
commit and push both succeeded. A read-only temporary pack remained. Automatic
approval review rejected its forced removal without a detailed reason, so it
remains untouched. Continued work uses a fresh checkout at
`E:/Context Relay Releases/workspaces/pr16-release`, verified at the same commit.
The hosted-login regression test first failed because the core auth module was
absent. The initial two callback tests then passed after implementing a
single-use PKCE attempt with exact loopback/state binding, monotonic expiry,
bounded callback parsing and redacted secret exchange material. The existing
HTTPS project-URL validation is shared with sync. Independent bounded review
found no concrete P1/P2 issue. Both expanded callback/exchange-body tests, all
nine existing Supabase transport tests and the fixed RFC PKCE vector pass.
Core Clippy passes with all targets, test-support and warnings denied. Graphify
update, formatting and whitespace checks pass. At `365a4a7` this did not yet
include a listener, token exchange, credential store, desktop sign-in surface,
trusted-device provisioning or hosted acceptance.

## Loopback callback receiver

The daemon library now binds an ephemeral IPv4 loopback listener before exposing
the authorization URL. It checks the exact Host and callback state/path, accepts
only bodyless GET requests, bounds headers/targets, limits each socket and the
overall lifetime, and closes when its owning future is aborted. Browser
responses contain no callback code or provider details. Valid provider denial
ends the attempt after checking its state.

The missing listener and denial tests failed before implementation. All four
socket tests and three core login tests pass, including idle/oversized traffic,
denial, replay, cancellation and deadline cleanup. Independent bounded review
found no concrete P1/P2 issue; its suggested socket cases were added. Core and
daemon Clippy passes for all targets with test-support and warnings denied;
Graphify update, formatting and whitespace checks pass. IPC ownership, opening the system browser, exchanging/storing tokens,
refresh/logout, provisioning and real hosted acceptance remain unfinished.

## Hosted token exchange

The core client now binds an exchange to its original project, sends its code
and verifier to the PKCE token endpoint without automatic replay, and checks
the returned identity against `/user` using that exact access token. Parsed JWT
fields are metadata until that hosted verification succeeds. Issuer, audience,
canonical nonnil user/session IDs and expiry are checked; provider tokens are
discarded. The session retains its originating project and redacts credentials.
The shared HTTP client enforces a 64 KiB response limit for Auth requests and
clears retained request/response buffers, including response-read failures.

The missing-client test failed before implementation. The initial 17 login,
sync and lifecycle transport tests passed. Independent review found no confirmed
P1/P2 issue and requested more malformed-identity cases. All 18 expanded tests
pass, including rejection before `/user` for malformed IDs, issuer, audience
and excessive expiry. Core/daemon Clippy passes for all targets with test-support
and warnings denied; the two HTTP-boundary Node checks, formatting, whitespace
and Graphify update also pass. `/user` verification is not device authorization or proof
that a session remains live indefinitely. Production callers must enforce expiry
and use the live server authorization checks for protected actions. Credential
storage, refresh/logout, IPC/browser wiring, provisioning and real hosted
acceptance remain required before activation.

## Refresh and remote logout transport

Refresh now rejects a changed project, user or session and verifies the renewed
access token through the same hosted identity checks as initial login. It returns
replacement credentials without mutating the original session or automatically
retrying a failed request. Remote logout explicitly uses `scope=local` and requires
HTTP 204; local credential deletion remains the session owner's responsibility.

The missing-method tests failed before implementation. All six hosted transport
tests pass, including rotated tokens, identity substitution, wrong-project calls,
failed refresh without replay and refusal to accept HTTP 200 as logout confirmation.
Independent bounded review found no concrete P1/P2 issue. Core and daemon Clippy
passes for all targets with test-support and warnings denied; formatting and
whitespace checks pass. Secure persistence, refresh/logout coordination and all
previously listed activation and release acceptance requirements remain open.
