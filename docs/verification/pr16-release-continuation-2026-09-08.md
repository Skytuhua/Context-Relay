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

## Restart credential persistence

The OS login store persists a versioned refresh-only record bound to the hosted
project, user and session, in a separate slot for each local profile/project.
Access and GitHub provider tokens are not persisted. Loading yields unverified
restart material; restoring it uses refresh and the same remote identity checks,
including the original user/session binding. Malformed, extra-field and oversized
records fail closed. Oversized encoded writes are rejected before replacing the
previous credential, and native credential-store errors remain sanitized.

The missing-restore test failed before implementation. Seven hosted transport
tests pass. The record validation check and explicitly invoked Windows credential
round-trip check pass; the latter creates a random synthetic slot, verifies that
oversized writes preserve its prior value, reopens it, then deletes it and checks
idempotent deletion. This is local Windows evidence, not clean-machine or macOS
acceptance. The native Windows blob limit can reject records below the portable
record limit; a failed save must prevent the manager from publishing that login.
The session manager, persistence-before-publication and logout/refresh races are
still required before production activation.
Independent review verified closure of the encoded-size finding and reported
no new issue. Core/daemon all-target Clippy passes with test-support and warnings
denied; formatting, whitespace and Graphify update checks pass.

## Session ownership and cancellation

The core session owner now serializes credential writes and publication while
keeping network calls outside its state lock. Opaque generations reject results
from superseded login/refresh work. Logout invalidates in-memory state even when
the OS refuses deletion, and reports local deletion separately from remote
revocation. Failed persistence never publishes a replacement. Startup restoration
can explicitly retry temporary read/network failures; logout and ambiguous save
failures cannot be undone by reloading credentials in the same owner. Terminal
authentication failures withdraw the session and clear credentials. Expiry is
checked after network and storage work.

Missing-owner checks failed first. Review then found offline restore could not
retry and terminal refresh denial retained a session; a regression reproduced the
retry failure, both were fixed, and review confirmed closure. All ten hosted auth
tests pass, including temporary OS-store read failure, offline retry, rejected
publication, superseded attempts, and a controlled refresh/logout race with failed
local deletion. The owner still needs daemon blocking-worker, loopback cancellation
and IPC integration before production activation. This does not close the remaining
hosted provisioning, product workflows, signing or clean-machine release gates.
Core/daemon all-target Clippy passes with test-support and warnings denied;
formatting, whitespace and Graphify update checks pass.

## Daemon loopback/session integration

`DaemonLogin` now owns the callback listener and session attempt together. It
creates cancellation ownership before dispatching blocking work; a canceled
queued worker checks that reservation under the owner lock before mutating state.
Callback exchange and credential persistence run outside the async runtime's
workers and outside the ordered vault worker. Dropping a flow immediately marks
its generation canceled and schedules conditional cleanup; explicit cancellation
waits for cleanup and reports failures. Successful completion disarms that guard.
The owner rejects canceled generations before exchange and after credential writes,
and no longer exposes canceled sessions through its transport accessor.

The missing cancellation check failed before implementation. Twelve core auth
tests pass, including cancellation during an OS-store write and rejection of a
canceled queued start without clearing a newer login. Four existing loopback tests
pass. Four daemon flow tests cover successful persisted login, listener cleanup,
aborted exchange and canceled queued start; runtime draining verifies detached
work cannot publish late. Independent review identified the queued-start race,
then verified its fix with no remaining concrete P1/P2 finding. This is tested
daemon flow plumbing; IPC routing, browser launch, production configuration and
the remaining full-release gates are still unfinished.
Core/daemon all-target Clippy passes with test-support and warnings denied;
formatting, whitespace and Graphify update checks pass.

## Hosted desktop controls (integration in progress)

The daemon now routes Desktop-only hosted sign-in controls outside the vault
worker. The service reserves generations before spawning work, opens the native
browser after the loopback listener is ready, restores credentials asynchronously,
and publishes only sanitized status for the current generation. Shutdown withdraws
in-memory authority while preserving persisted restart credentials.

Two service tests pass: duplicate starts and stale controls cannot replace newer
state; a successful callback remains connected after a late Cancel, and shutdown
retains credentials while withdrawing the session. Read-only review identified
the late-Cancel race and confirmed the guard fixes it, with no additional concrete
P1/P2 in the reviewed service/routing paths. Protocol 1.14 and shutdown-only 1.13
compatibility pass all 223 protocol/local IPC tests. Generated bindings, schemas,
MCP fixtures and strict desktop validation use the new version. The desktop
gateway preserves caller-owned operation/generation values and rejects mismatched
start acknowledgments or responses containing unexpected fields.

Desktop typechecking, lint, build and all 347 tests pass. Twelve core auth tests
and 25 MCP tests pass. The daemon unit suite passes 89 tests with four existing
tests ignored; both callback lifecycle suites pass four tests each. These ignored
tests and packaged/live acceptance are not proven by this run. Independent review
also confirmed the frozen authentication vectors and gateway/routing changes.
Core/daemon Clippy passes for all targets with test-support and warnings denied;
generated bindings/schema checks, whitespace and Graphify update pass.
Refresh/expiry handling, the desktop sign-in surface and production configuration remain
unfinished. These checks do not establish live hosted or full-release acceptance.

## Hosted session maintenance

The daemon refreshes established sessions before expiry and retries temporary
refresh or startup network failures with delays increasing from five to sixty
seconds. Refresh failures retain credentials; terminal provider failures remain
subject to the owner's credential cleanup. Displayed status and transport access
both use monotonic expiry bounds, so clock rollback cannot extend the original
session lifetime. Every queued refresh/restore checks its original cancellation
reservation under the owner lock before accessing a session or stored credentials.

Regression checks first reproduced stale Connected status, clock-rollback revival,
and startup recovery failing to retry. All 13 core auth tests and four daemon
service tests now pass, including expired-session recovery without credential loss,
offline startup recovery without browser launch, and delayed work preserving a
newer login. Review found a queued-refresh generation race and confirmed its fix;
the startup cancellation review found no additional concrete P1/P2.
Both existing callback lifecycle suites pass all eight tests. Core/daemon
all-target Clippy with test-support and warnings denied, whitespace and Graphify
update checks pass.

Production hosted configuration remains disabled. The desktop sign-in surface,
live provider acceptance and full release checklist remain unfinished.

## Desktop hosted sign-in controls

Settings now displays daemon-owned sign-in status and offers GitHub sign-in,
cancellation and sign-out for the acknowledged generation. Uncertain start
responses retain the caller's operation ID for retry. Polls cannot overwrite a
newer action, and results from an obsolete gateway are ignored. Errors use closed,
sanitized messages; local sign-out distinguishes confirmed remote revocation.

All five new panel tests pass, including duplicate-click prevention, uncertain
retry, stale polling, gateway replacement and remote logout wording. The full
desktop suite passes 352 tests across 41 files; typechecking, lint and the
production build pass. Read-only review found no concrete P1/P2 issues.
The built browser preview visually confirms the Settings layout; it has no native
bridge and therefore does not establish native or live provider acceptance.
Production hosted configuration and the remaining release gates are unfinished.

## Hosted production configuration

The daemon now reads hosted configuration embedded at compile time, initializes
the HTTP client and OS credential store on a blocking worker, and begins restoring
login only after acquiring its instance guard. Build validation requires both URL
and publishable key, rejects secret/legacy JWT keys, and leaves unconfigured builds
offline. Runtime URL validation uses the existing shared auth boundary.

The existing enabled publishable key for project `brvzuycnxoswdzzipgvx` was read
through the Supabase connector. Both public build values were saved as GitHub
repository variables and wired into the Windows installer candidate workflow.
No OAuth provider configuration or account enrollment was changed.

The daemon library suite passes 92 tests with four existing ignored tests,
including the build-validator regression check. The four hosted service tests
also pass separately. Read-only review found no concrete P1/P2 in initialization,
configuration validation or packaging-variable propagation. These checks do not
prove live GitHub login, native credential acceptance or signed release readiness.
All-target daemon Clippy with test-support and warnings denied passes with the
actual hosted configuration embedded. Whitespace and Graphify update pass.

## Native Windows hosted-credential check

Explicitly ran the normally ignored
`auth::storage::tests::platform_login_roundtrip_and_clear` test in the core crate
with test-support. It passed against this machine's native credential store using
a random qualification profile and the synthetic `qualification.invalid` project.
The check saved and reopened a synthetic refresh token, rejected oversized records
and Windows-native oversized blobs without replacing the prior value, and cleared
the entry twice. Log: `.codex/pr16-auth-native-store.log`.

This proves the bounded credential operation on this Windows machine. It does not
prove macOS Keychain behavior, a live provider token rotation, packaged first-run
behavior or clean-machine acceptance. The first-device enrollment source audit
confirmed the existing recovery coordinator/record should be extended through a
real hosted transport; the implementation sequence and required race/failure checks
are recorded in the hosted-login plan. Those hosted components remain unimplemented.

## Hosted enrollment device proof

Added a domain-separated Ed25519 proof binding the reservation, hosted user,
session, nonce and canonical recovery-record digest. The Rust signer requires
the installed signing/wrapping keys to match the validated genesis certificate.
The Edge helper verifies the same proof but intentionally provides no endpoint,
reservation authorization or device activation; those checks remain required.

The new Rust test first failed on missing proof APIs. All seven recovery enrollment
crypto tests now pass, including the proof vector independently generated by Node.
The Node Edge check passes and rejects substitutions of every context field,
record mutation, oversized/empty input, invalid key length and invalid signature.
Supabase CI now runs it and watches its fixtures. Read-only review found no
concrete P1/P2 issues. Supabase contract and whitespace checks pass.
Core all-target Clippy with test-support and warnings denied, and Graphify update,
also pass.
Logs: `.codex/pr16-enrollment-proof{,-red,-clippy,-graph}.log`.

## Hosted recovery-record decoding

Added the structural Edge decoder for the existing Rust canonical recovery record,
reusing the sync canonical reader. It checks exact map/key order, UUIDv7 fields,
initial epochs, platform values, bounded UTF-8 and ciphertext, matching certificate
scope/root key, distinct signing/wrapping keys, and complete input consumption.
It owns its input bytes and constructs the same root-signature preimage as Rust.
This is structural decoding only; cryptographic key/signature verification and
live reservation authorization remain required before any hosted activation.

The decoder test first failed for the missing module. The combined Node enrollment
and sync suites now pass 42 tests, including every truncated record prefix,
noncanonical/trailing data, scope/key substitution, invalid UUID and malformed
UTF-8, plus exact agreement with the Rust record/signing-preimage fixtures.
Supabase contract, whitespace, Graphify update and read-only decoder review pass.
Log: `.codex/pr16-enrollment-record.log`.

CI Secret Scan run `34241019698` flagged the exact synthetic enrollment-proof
fixture fingerprint from commit `770a39d`. Inspection of the historical Git object
and independent review confirmed deterministic test identifiers and public
cryptographic values, with no provider credential or private key. Added only that
commit/path/rule/line fingerprint to the reviewed ignore file and rationale ledger,
updating its pinned byte count and digest. All five secret-scan workflow tests pass.
Scanner detectors, full-history coverage and redaction remain unchanged. A clean
full-history result was confirmed by local Gitleaks (exit 0) and GitHub Secret Scan
run `34242184513` on `adb65877c33354c6531fd913238f8b2d99a1d896` (success).

## Hosted enrollment cryptographic verification

The composed verifier now checks the recovery-root signature, genesis certificate
signature and reservation-bound device proof over the Rust-compatible preimages.
Native Web Crypto performs Ed25519 verification and X25519 contributory checks;
explicit canonical-point and small-order rejection match the Rust key boundary.
The verifier owns input, nonce and proof bytes before asynchronous work.

The enrollment and sync Node suites pass 46 tests. Regressions include weak and
noncanonical points, noncanonical signature scalars, caller-buffer mutation,
invalid certificates and invalid wrapping keys even with valid outer signatures.
The five secret-scan policy tests and Supabase contract check pass. Read-only
review found no concrete P1/P2 issues. This verifies cryptography only: live
reservation/session authorization, atomic hosted commit and production transport
remain unfinished. No hosted endpoint or device authority is enabled by this work.

## First-device reservation qualification in progress

Added a private per-user reservation and service-only RPC. It checks live Auth
before insertion and after reservation locks, denies existing-account enrollment,
returns the original challenge on a live same-operation retry, rejects competing
operations, and permits bounded replacement after expiry. Reservations create no
account or device authority. Scope IDs and nonce must come from the trusted Edge
service; that endpoint and the atomic enrollment commit remain unfinished.

Added ten pgTAP assertions and a dedicated Supabase CI step for permissions,
stable retries, competing requests, expiry, rate limiting and expired sessions.
These database assertions are pending execution; concurrent lock-wait expiry is
also unverified. Read-only review found no concrete P1/P2 issue in this slice.
Supabase contract and whitespace checks pass. The preceding crypto commit
`2a809e9` passed Supabase run `34243369285` and Secret Scan run `34243369314`.

The first reservation CI run (`34243901193`) exposed an ownership transition
error before the pgTAP assertions: Supabase's migration role could not enable RLS
after transferring the table. The migration now switches to the table owner
immediately after that transfer. Local PostgreSQL's superuser did not expose this
managed-role difference; a successful Supabase rerun remains required.

Extended the existing disposable PostgreSQL harness with enrollment retries and
session expiry during Auth/reservation lock waits. The initial 13 checks passed
locally; review then tightened the retry check to hold the first transaction open
and observe the second request blocked. The final variant passes all 13 checks
on the disposable local PostgreSQL database. Log: `.codex/pr16-enrollment-postgres.log`.

## Atomic enrollment commit

Added the service-only transaction that creates the account at epochs one, recovery
root, genesis certificate, active session binding and private canonical record/
receipt together. The transaction binds all mutable reservation fields, rechecks
the live session and expiry after possible insert waits, and returns the original
receipt for an exact canonical-record retry. It rejects changed records and does
not reactivate bindings on replay. The Edge verifier must supply the decoded
fields; the production endpoint is still unfinished.

All 15 disposable PostgreSQL checks pass, including rollback after a late
certificate collision and session expiry during an account-insert FK wait.
Log: `.codex/pr16-enrollment-commit-postgres.log`. Read-only review found no
concrete P1/P2 issue. Supabase contract and whitespace checks pass. Managed
Supabase migration/pgTAP qualification remains pending; local stub Auth tables
cannot establish that evidence.

## Enrollment status lookup

The reservation correction passed managed Supabase run `34244491895` on
`99590b6`: all 520 existing and ten enrollment pgTAP assertions passed. This
evidence predates the atomic-commit and status migrations.

Added a service-only status RPC bound to the verified user, session and reservation.
It rechecks the live Auth session after the reservation lock and permits an expired
challenge only when returning its committed receipt. It grants no direct table
access. All 15 local PostgreSQL checks pass with expired committed receipts,
foreign/deleted sessions and denied authenticated-role calls covered.
Log: `.codex/pr16-enrollment-status-postgres.log`.

The canonical decoder now returns the exact encrypted metadata envelope slice for
the commit RPC; its eight Node tests pass. Read-only review found no concrete P1/P2
issue. Contract and whitespace checks pass. The Edge HTTP endpoint/adapter and
managed qualification of the new migrations remain unfinished.
