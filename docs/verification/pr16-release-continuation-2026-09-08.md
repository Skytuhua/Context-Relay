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

## Enrollment HTTP handler

Added the bounded reserve/status/commit handler. It reuses the lifecycle streaming
reader with a 68 KiB cap, rejects client ownership fields and malformed encodings,
binds proofs to the authenticated identity and stored challenge, verifies canonical
record signatures before commit, and checks the returned receipt against that record.
Unknown provider failures return a closed transient error without provider text.

All 26 enrollment/lifecycle Node checks pass. Read-only review found no concrete
P1/P2 issue; contract and whitespace checks pass. Log: `.codex/pr16-enrollment-edge.log`.
The production Supabase adapter and entrypoint remain unfinished; this handler is
not a deployed endpoint. Atomic-commit Supabase run `34245086183` on `9ad81a2`
passed; that run predates the status migration and this handler.

## Enrollment Supabase adapter and entrypoint

Wired the handler to separate non-persisting Auth/service clients, reusing the
lifecycle client's configuration validation. Authentication derives identity only
from verified `getClaims` results. Reservation calls generate UUIDv7 account and
workspace IDs and a random 32-byte nonce on the server. Commit maps the verified
record to the 18-argument service-only transaction. Provider text stays internal.

Added the pinned Supabase entrypoint and function configuration; platform JWT
verification is disabled because the handler verifies the caller's Auth token in
code before all service calls. Nothing has been deployed.

All 28 enrollment/lifecycle and 38 sync Node checks pass, including client
isolation, missing verified claims, server-generated scope, canonical metadata
mapping and sanitized failures. Read-only review found no concrete P1/P2 issue.
Contract and whitespace checks pass. Logs: `.codex/pr16-enrollment-adapter.log`
and `.codex/pr16-enrollment-adapter-sync.log`. Native transport integration and
live hosted acceptance remain unfinished.

## Native enrollment session ownership

Added `HostedSessionOwner::session_for` to resolve credentials for an original
login generation and verified identity under the same lock. It permits token
refresh within that login and rejects replacement logins, including replacement
with identical claims. Existing expiry/cancellation checks are shared with
`current_session`. This is the guard required by the upcoming native transport;
the returned session is a snapshot and must not be cached across operations.

All 14 hosted-auth transport tests pass, including refresh, foreign identity,
replacement and cancellation. Read-only review found no concrete P1/P2 issue.
Core all-target Clippy with test-support and warnings denied, formatting and
whitespace checks pass.

## Native enrollment status and commit

Extended the session-bound native client with status and commit calls sharing the
same bounded HTTP/ownership checks. Status must match the complete original
reservation. Commit decodes the canonical record, checks its reserved scope,
signs the original identity/challenge with the installed device keys, and verifies
the returned receipt against the record IDs and digest.

All 16 hosted-auth tests pass. The new test checks status, the actual submitted
proof signature and canonical bytes, and rejection of a forged receipt digest.
Read-only review found no new concrete P1/P2 issue. Durable coordinator integration
must still validate status receipts against the intended local record before
activation. Log: `.codex/pr16-enrollment-commit-client-test.log`.
Core all-target Clippy with test-support and warnings denied, formatting and
whitespace checks pass.
Log: `.codex/pr16-enrollment-owner.log`. Status-migration Supabase run
`34245530149` on `6c49e8c` passed; the later Edge adapter still needs managed
qualification and live acceptance.

## Native reservation HTTP client

Added a daemon-owned reservation client using the existing HTTPS-only bounded
HTTP implementation. It resolves credentials for the original identity/generation,
checks the configured project, sends only the stable operation ID, and rechecks
ownership after the request before returning a strictly decoded reservation.
No credentials are included in the reservation. Status/commit and durable native
enrollment integration remain unfinished.

The 15 hosted-auth tests pass, including the native request shape and denial before
network access after login replacement. Review caught an upper-bound expiry check
that rejected normal server clock skew; it was removed and a server-ahead
regression passes. The database remains authoritative for challenge expiry.
Log: `.codex/pr16-enrollment-client-test.log`.
Core all-target Clippy with test-support and warnings denied, formatting and
whitespace checks pass.

## Durable hosted enrollment intent (September 9)

Schema 28 stores the public project/hosted identity/operation intent in the encrypted
vault before networking. Only that exact intent may acquire its reservation;
subsequent identity, scope or challenge replacement is rejected. An existing
prepared enrollment cannot acquire a hosted intent, and hosted preparation requires
the reserved account/workspace. No token, phrase or private key enters this record.

Local verification: 7 enrollment vault tests, 21 general vault tests and 7 search
tests pass. The search suite's 8 existing asset/performance tests remain ignored;
this run does not qualify those release gates. Historical-schema fixture teardown
now removes schema 28 before exercising earlier upgrades. Read-only review found
no concrete P1/P2 in this persistence slice. Graphify update completed.
Logs: `.codex/pr16-enrollment-intent-test-final.log` and
`.codex/pr16-enrollment-intent-graph.log`.

The production transport/coordinator integration and explicit handling of expired
reservations or changed hosted sessions remain unfinished. This is local
persistence evidence, not live enrollment or release acceptance. PR #16 stays open.
Core all-target Clippy with test-support and warnings denied also passes.
Log: `.codex/pr16-enrollment-intent-clippy.log`.

## Native coordinator transport and clock domains (September 9)

The hosted client now implements the existing recovery transport through an adapter
bound to the saved project, Auth identity, reservation and installed device keys.
It resolves credentials through the original login generation for every request.
The coordinator retains canonical-record validation of status receipts.

Review found a real clock-domain bug: activation compared the server receipt time
to the desktop's request-start time. Schema 29 preserves enrollment rows while
removing that cross-clock ordering. Server acceptance remains the exact receipt
value; local completion is refreshed after networking and cannot precede local
preparation. Signature, record digest, identity and certificate checks remain.

The initial local run passed 17 hosted-auth/native-adapter tests, 12 enrollment
end-to-end tests, 7 enrollment vault tests, 7 search tests and 21 general vault
tests. Eight existing search asset/performance tests remain ignored. Follow-up
coverage exercises lost commit responses and restart reconciliation under server
clock skew, plus an active schema-28 enrollment upgrade. Final follow-up results
are recorded below. This does not enable the daemon or establish live acceptance.

Follow-up results: all 17 hosted-auth/native-adapter tests pass, including immediate
and lost-response commits with server clocks five seconds ahead/behind, followed
by vault reopen and coordinator reconciliation. Both native-memory drift tests
pass after repairing their incomplete historical-schema fixture. The active-row
schema-28 upgrade regression passes. Core all-target Clippy with test-support and
warnings denied, formatting and whitespace checks pass. Read-only review closed
the clock-domain finding and found no further concrete P1/P2.
Logs: `.codex/pr16-enrollment-clock-{test,final,fixture,upgrade,clippy}.log`.
Daemon wiring, reservation/session recovery, live acceptance and release gates
remain incomplete; PR #16 is not merged.

## Production daemon enrollment and expiry recovery (September 9)

The build-configured daemon now connects hosted Auth to the existing enrollment
coordinator through its ordered vault worker and shares its installed device keys.
Startup validates local enrollment state without requiring hosted Auth restoration
or network availability. An initial overview is read-only; Begin persists a scoped
intent before reserve, then persists the challenge before creating the coordinator.

Review found and corrected two expiry failures. The native transport now preserves
an exact reservation-expired response separately from authentication denial. An
explicit Begin may discard only an exact unprepared expired intent. Prepared
records remain intact after expired commits. A service-only renewal RPC locks the
original reservation, checks its live Auth session, and rotates only an expired,
uncommitted challenge, retaining the operation/account/workspace and rate limit.
Live and committed renewal retries keep their challenge. The vault compares the
old intent before storing renewal; no prepared canonical record is replaced.

Local evidence:
- Earlier full daemon run: 93 passed, 4 existing ignored.
- Expired-error transport/enrollment/recovery run: 17 + 12 + 13 passed.
- Renewal native transport and vault run: 18 + 7 passed.
- Updated daemon recovery tests: 6 passed, including lost reserve response/reset
  and expired commit/renewal/reconciliation with identical canonical record bytes.
  The mock checks durable intent before reserve and durable preparation before commit.
- Local PostgreSQL: 16 passed, including scope-preserving renewal, unchanged retry,
  old-nonce denial, runtime role/session denial and committed receipt preservation.
- Enrollment Edge tests: 14 passed. Supabase contract check passed.

Logs: `.codex/pr16-enrollment-{daemon-test,expired-test,renew-native-test,expiry-flow,
renew-postgres,renew-node}.log`. This SQL migration was applied only to the local
disposable PostgreSQL database. Managed Supabase CI and live product acceptance
remain required. No hosted deployment or release publication has occurred.
The final PostgreSQL run also passes the renewal rate-limit assertion (16/16).
Core and daemon all-target Clippy with test-support and warnings denied pass;
three nested-condition style fixes were applied, then formatting/whitespace checks
passed. Logs: `.codex/pr16-enrollment-renew-postgres-final.log` and
`.codex/pr16-enrollment-renew-clippy-fix.log`.

### Desktop recovery reconciliation

Confirmation failures now read the daemon's saved enrollment status before offering
new setup. Completed/submitting records remain visible, and an unavailable status
keeps setup closed with an explicit retry. Initial overview and submitting-poll
failures use the same retry action. Entered words are cleared after failed confirmation.

Verification: five new cases cover completed/submitting outcomes, an unavailable
confirmation status, initial-load failure and failed polling. The four initial cases
failed before the fix. The full desktop suite passes 357 tests across 41 files;
TypeScript and ESLint pass. Read-only review found no concrete P1/P2 in this diff.
Logs: `.codex/pr16-recovery-ui-{red,green,suite}.log`.
Managed Supabase run 34254584913 at 368c942 completed successfully. This does not
replace live login, enrollment, second-device, signing or clean-machine acceptance.

### Hosted recovery snapshot boundary

Added the service-only `service_recovery_snapshot_for_session` RPC and the closed
`{v:1, action:"snapshot"}` enrollment endpoint action. A live authenticated owner
session can fetch its committed canonical recovery record without knowing the
original enrollment reservation or holding a device binding. Account ownership,
active deletion state and unrevoked root are checked under locks; session liveness
is rechecked after waits. No device trust is granted by this read. The root now
stores a nonnegative recovery generation, initially zero, for signed restore claims.
The Edge checks exact projection fields, record encoding, scope and SHA-256.
A live session is required; this read does not impose a recent-login age limit.

Evidence: the new SQL test failed before the RPC existed. All 19 local PostgreSQL
lifecycle/enrollment tests now pass, including fresh-session read, zero binding
creation, cross-user denial, role denial, revoked/deleting exclusions, and expiry
while waiting on account/root locks. All 16 enrollment Node tests pass, including
closed snapshot input/projection, digest/scope rejection and null-result handling.
Supabase contract and whitespace checks pass. Read-only review found no concrete
P1/P2. Logs: `.codex/pr16-snapshot-{red,green,postgres,node,edge-red,edge-green}.log`.

The migration is applied only to the disposable local database. Hosted deployment,
native snapshot transport, signed restore submission/reconciliation, live acceptance
and all signing/clean-machine gates remain incomplete. Supabase run 34255498040
passed at a723fcb before this change; new-head managed CI must run separately.

### Native recovery snapshot reader

The existing hosted enrollment client now reads the snapshot action with the same
original user/session/project checks before and after HTTP. Only snapshot responses
allow 68 KiB for a hex-encoded 32 KiB record; other enrollment responses retain the
16 KiB bound. The reader requires an explicit snapshot field, accepts explicit null,
and rejects extra fields, invalid version/hex, oversized records, invalid timestamps
or generations, altered scope/digest, and invalid signatures through the existing
canonical recovery validator. Fetching a snapshot grants no device authority.

All 19 hosted-auth transport tests pass, including a new snapshot regression with
missing/null separation and a forged signature whose digest matches the forged bytes.
An account-login replacement is rejected without sending another request. Initial
compilation failed before the snapshot method existed. Read-only review found no
additional P1/P2 beyond the missing/null issue, which was fixed before the final run.
Logs: `.codex/pr16-native-snapshot-{red,test,final}.log`.
This is the native reader, not completed restore: daemon restore wiring, root-signed
claim admission/receipt reconciliation and real hosted/installed acceptance remain.
Core all-target Clippy with test-support and warnings denied passes after replacing
the manual even-length test with `is_multiple_of(2)`; formatting and whitespace
checks pass. Log: `.codex/pr16-native-snapshot-clippy.log`.

### Hosted signed-restore verifier

Added the hosted verifier for the existing canonical 15-field recovery-device claim.
It reuses the strict reader, recovery-record/certificate verification and WebCrypto
signature/wrapping-key checks. Claim/root IDs, scope and record digest must agree;
a claim cannot reuse the genesis device/certificate. Both epochs remain one, matching
the existing genesis recovery-record format. The generation must be below i64::MAX.
Input bytes and proof context are captured before asynchronous verification.

Device possession is separately required: sign ASCII
`context-relay/hosted-recovery-device-proof/v1` plus NUL, then authenticated user UUID
bytes, session UUID bytes and SHA-256 of the canonical claim. UUID bytes use network
order. The exact claim includes the restore ID and expected generation. No challenge
nonce is introduced: admission must be atomic and idempotent for the exact claim and
same session, with live-session/owner/root checks and a generation compare-and-set.
The proof alone does not grant authority. Native proof signing and admission are pending.

Verification: 20 enrollment Node tests pass, including the frozen Rust claim/preimage,
truncation/trailing/noncanonical input, mutated records/signatures, caller-buffer
mutation, wrong/missing device proof, and user/session substitution. Re-signing the
outer claim cannot hide a corrupt inner certificate, wrapping key or record digest.
Existing enrollment proof tests still pass after shared verification was extracted.
Supabase contract and whitespace checks pass. Logs:
`.codex/pr16-restore-verifier-{red,green}.log`. This adds no deployed restore endpoint,
trusted binding, daemon restore command or completed release acceptance.
Read-only review found no concrete P1/P2 in this verifier slice; admission remains separately required.

### Native recovery device proof

Added native proof construction/signing for the hosted recovery domain. The signer
checks both installed device public keys against the claim and validates the signed
canonical claim before hashing. The existing internal signing primitive is reused;
first-enrollment proof bytes remain unchanged. The Node-generated
`hosted-recovery-proof-v1.json` is consumed by both native and hosted tests; CI watches
recovery fixture changes as well as enrollment fixtures.

Native enrollment crypto: 7 passed; native restore crypto: 7 passed. Hosted enrollment
Node tests: 21 passed. New native tests also reject a changed wrapping key, nil user
identity and tampered claim signature. Read-only review found no concrete P1/P2.
Logs: `.codex/pr16-recovery-proof-{red,native,node}.log`. Actual hosted restore
admission, transport and daemon/desktop commands remain to be implemented.
Core all-target Clippy with test-support and warnings denied also passes (.codex/pr16-recovery-proof-clippy.log).

### Hosted restore admission and projection

Added service-only restore commit/projection RPCs and connected the closed restore
and restore_status actions to the existing enrollment endpoint. Admission selects the
owner's stored root, verifies the canonical claim and session-bound device proof, and
passes only decoded fields plus verified Auth identity to SQL. The returned receipt
is checked independently against the original claim's IDs, hashes and next generation.
Read projections require the requested restore ID and consistent exact claim/receipt.
Only snapshot/projection reads permit a null provider result; commits cannot.

The database serializes account/root updates, binds the original session and canonical
claim to the durable receipt, rejects changed retries/stale generations/wrong owners,
and inserts certificate, binding, generation and receipt in one transaction. Exact
retries return their original receipt without reactivating revoked bindings, even
after a later restore advances the generation. New restores require active account,
unrevoked root, unused device/session and epochs matching the current genesis format.
Auth session liveness is checked again after potentially blocking inserts.

Evidence: 25 local PostgreSQL tests pass, including two competing claims proven blocked
at a lock barrier, exact old receipt after a newer restore, revoked/deleting/wrong-owner
denial and expiry after account/root locks. Expiry while a certificate insert waits
rolls back certificate, binding, receipt and generation. The initial test failed before
the RPC existed. All 23 enrollment Node tests pass, including cryptography-to-RPC
mapping, invalid proof, absent root, altered receipt generation/hash and nullable reads.
Supabase contract and whitespace checks pass. Read-only review found no concrete P1/P2.
Logs: `.codex/pr16-restore-admission-{red,green,final}.log` and
`.codex/pr16-restore-api-{red,green}.log`.

The migration was applied only to disposable local PostgreSQL. These synthetic SQL
fixtures test transactional authority separately from the Edge's frozen crypto vectors;
they do not establish live Supabase or installed-product acceptance. Native restore
transport, durable daemon/desktop restore workflow, deployment and full release gates
remain required. No release has been published or PR merged.

### Native hosted restore transport and clock domains

The native restore transport now reuses the hosted client's original-session and
project checks. It binds to the discovered canonical root, signs restore claims with
the installed device key, and validates exact claim/receipt IDs, hashes, generation
and bounded server timestamps. Projection reads distinguish a missing field from null
and reject a different requested restore ID. No recovery phrase crosses this HTTP boundary.

The transport-to-coordinator regression exposed a clock-domain defect: local activation
compared server acceptance time to desktop preparation and pre-request completion time.
The coordinator now samples completion after HTTP reconciliation. Vault schema 30 and
runtime/reload validation retain server acceptance independently, while enforcing local
completion at or after local preparation. The migration preserves existing restore rows.

The regression covers signed fixture requests, altered receipts, login replacement,
encrypted-vault restart and simulated HTTP time with server clocks five seconds ahead
and behind. It failed with a terminal conflict before the clock fix. Read-only review
confirmed the fix and found no further concrete P1/P2. Validation logs are
`.codex/pr16-native-restore-{test,clock-red,green}.log`.

Validation: 20 hosted Auth/transport tests, 13 recovery flow tests and nine vault tests
pass. The additional schema-29 preservation test passes for both prepared and active
rows (`.codex/pr16-native-restore-migration.log`).
Core all-target Clippy with test-support and warnings denied passes
(`.codex/pr16-native-restore-clippy.log`), as does `git diff --check`.

This is the core transport, not the complete product workflow. Durable hosted restore
intent must still bind the original Auth identity and project across daemon restart;
trusted native phrase input and daemon/desktop commands remain required. Live hosted
acceptance, signing, clean-machine qualification and the full release gates remain open.

### Durable hosted restore identity

Vault schema 31 adds a bounded public restore intent containing only the original
Supabase project, Auth user and session. It is saved before claim preparation, survives
restart, permits exact retries and cannot be reassigned to a different login. An existing
claim without hosted provenance cannot acquire an arbitrary owner. Only the exact intent
without a prepared claim may be discarded. Pending enrollment and restore intents are
mutually exclusive.

The native restore constructor now requires this intent and checks its project/user/session
against the authenticated client. The pristine-vault check validates and permits the
restore intent itself while preserving unrelated-data blockers. Its first regression
failed when preparation incorrectly treated that required row as conflicting data.
Existing schema downgrade fixtures now remove the new table before exercising migration.

All 20 hosted Auth/transport tests, seven enrollment vault tests and 11 restore vault
tests pass (`.codex/pr16-restore-intent-green.log`). These include original-project,
user and session mismatch denial, exact restart replay, unprepared discard, mutual
intent exclusion, missing provenance, migration and existing tamper rejection. The
initial failure is retained in `.codex/pr16-restore-intent-red.log`; read-only review
confirmed its fix and found no further concrete P1/P2.
The schema-26 search and schema-24 native-memory migration checks also pass, as does
core all-target Clippy with test-support and warnings denied (40 tests total;
`.codex/pr16-restore-intent-{search-migration,native-migration,clippy}.log`).

This establishes durable core provenance. Daemon orchestration must still persist/read
the intent and dispatch recovery through the native phrase-input flow; it is not yet
installed-product or live hosted acceptance.

### Daemon recovery commands

The production hosted recovery service now handles restore begin, overview, resume
and cancel through the existing ordered vault worker. Begin is restricted to the
authenticated native recovery host. Desktop/native-host overview and resume expose
only public status; the generic renderer bridge rejects phrase submission in both
TypeScript and Tauri. The phrase wrapper remains zeroizing and debug-redacted.

Begin saves the original hosted intent before fetching the owner's root and preparing
the claim. Resume validates the installed device identity, original Auth user/session,
project and canonical root, then retries the durable claim. Completed local material
and overview remain available without login. Cancel discards only an unprepared intent;
prepared claims remain intact. Successful unprepared enrollment cancellation also clears
its hosted intent and cached coordinator so it cannot block a subsequent restore.

The hosted regression checks login gating, intent-before-network ordering, enrollment
cancellation, wrong-phrase cancellation, prepared-cancel rejection and a lost restore
response followed by reopening the vault and service. The same claim completes without
reentering the phrase. Protocol testing caught and fixed an empty-status serde variant
that accepted extra fields; Idle now uses a strict empty struct variant. These are local
synthetic provider tests, not live hosted or installed acceptance.

Validation so far: nine protocol tests, 26 local IPC tests and the full daemon unit
suite pass (95 passed, four existing ignored). The seven renderer bridge tests and
TypeScript/ESLint checks pass. Logs are `.codex/pr16-restore-{protocol-test,ipc-test,
daemon-final,renderer-test,typecheck,renderer-lint}.log`; the protocol regression's
initial failure is `.codex/pr16-restore-protocol-red.log`. Read-only review found no
remaining concrete P1/P2 after the cancellation fixes.

Trusted native phrase-input UI and desktop recovery screens remain to be connected.
Signing, clean-machine qualification and the other full release gates are still open.

The Tauri boundary regression passes (one test), and all-target Clippy for the
protocol, local IPC and daemon crates passes with test support and warnings denied.
Logs: `.codex/pr16-restore-tauri-test.log` and `.codex/pr16-restore-daemon-clippy.log`.

Previous-head CI at b876ed5 has a failed Windows Semgrep build-a job
(34264073501 / 102191165003): exact builder verification rejects the installed
Cygwin version against pinned 3.6.10. Its log does not report the observed version.
This environment qualification remains unresolved; the version check is retained.

### Windows Cygwin provisioning correction

The complete b876ed5 job log shows setup-ocaml installed
`cygwin 3.7.0-0.590.gdae171e433cd` from the current mirror. The setup action's
cache key was 3.6.9, but that key does not pin the package selected by its installer.
The signed-metadata installer now explicitly requests `cygwin=3.6.10-1` in the
existing dependency provisioning step. Exact runtime/provenance verification remains
unchanged, and rejection now reports the observed runtime version.

The package is present in the mirror index inspected on September 9. The supported
`--packages package=version` syntax is documented in the
[Cygwin setup change](https://cygwin.com/pipermail/cygwin-apps-cvs/2021q2/002308.html).
All 25 native workflow checks pass; the added pin check first failed before the fix
(`.codex/pr16-cygwin-pin-{red,green}.log`). Actual hosted build qualification is still
required; this local check alone does not establish a successful Cygwin install.

### Windows native recovery phrase entry

The dedicated `recovery_restore_begin` Tauri command takes no phrase parameters
from the renderer. It holds the existing native-host mutex, reads local overview,
and opens the input dialog only while idle. Existing submitting/complete/conflict
states return directly. Cancel sends no Begin request. Accepted words travel only
through the authenticated native recovery-host IPC role; the command returns public
status or cancellation.

Windows uses a parent-owned Win32 modal dialog with a password edit control,
Recover/Cancel buttons, keyboard navigation, a 1024-character input limit and a
DWORD-aligned template. Rust temporary phrase buffers are zeroizing; input and undo
buffers are cleared on completion, cancellation and destruction. Invalid characters
are rejected before allocating decoded text. Uppercase ASCII words normalize to
lowercase and exactly 24 words are required; the daemon performs cryptographic
validation. The implementation follows the platform's
[modal dialog contract](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-dialogboxindirectparamw).

All 19 desktop Rust tests pass, including the real Win32 template/control/callback
accept and cancel paths (closed during initialization, before display). Native host
regressions verify no repeat prompt for durable state, no submit on cancellation,
and native-only submission. Eight renderer bridge tests, TypeScript and scoped
ESLint pass. Logs are `.codex/pr16-native-input-{red,final,renderer,typecheck}.log`.
Independent read-only review found no concrete P1/P2. This is not interactive installed
acceptance: visual/accessibility checks, macOS native input and the desktop recovery
screen remain pending. Non-Windows hosts currently return an explicit unavailable
error for this new command.

Desktop all-target Clippy also passes with warnings denied (.codex/pr16-native-input-clippy.log). The daemon-boundary and whitespace checks pass.

### macOS native recovery entry

The same no-argument native recovery command now opens an AppKit NSAlert with an
NSSecureTextField on the main thread. Recover and Escape/Cancel remain native; only
public status returns through the command. The field has an accessibility label,
initial focus and completion disabled. Submit commits current editing, reads at most
1024 UTF-16 units into zeroizing Rust storage, and uses the shared 24-word parser.
Submit/cancel abort editing and clear the field; invalid input presents another
native attempt. Per-attempt autorelease pools release native temporary strings.
This does not claim that AppKit's internal immutable string storage is zeroized.

The actual macOS module and native-string-reader tests pass Apple-target type checking
and Clippy with warnings denied using a temporary minimal crate that includes the
source module and shared parser. This verifies AppKit 0.3.2 calls; it does not execute
Mac tests or prove the complete desktop build. The full Apple-target check on Windows
stopped at objc2-exception-helper because its C compiler was unavailable. Logs:
`.codex/pr16-mac-input-{api-check,api-clippy,check}.log`. All 19 Windows desktop tests
still pass (`.codex/pr16-mac-input-windows-test.log`). Independent source review found
no concrete P1/P2. A real Mac build and interactive focus, Return/Escape, paste,
invalid-input retry and accessibility acceptance remain required before merge.

Separately, Windows CI run 34268002866 / job 102203605599 at 6d33098 passed both
Cygwin dependency provisioning and exact builder verification, and reached the
pinned runtime build. This confirms the package-selection fix; the entire build and
current-head release qualification are not yet established.

Windows desktop all-target Clippy also passes with warnings denied
(`.codex/pr16-mac-input-windows-clippy.log`).

### Desktop recovery workflow

The Devices screen now connects native phrase entry to public restore overview,
resume and cancellation. A saved submitting attempt offers Resume without phrase
entry. Lost responses reconcile against durable status; unknown status blocks Begin,
and confirmed completion clears a stale error and refreshes trusted devices.
Cancellation is available whenever Idle, including after remount when an unprepared
hosted intent may remain. Prepared claims cannot be canceled by this screen.

The gateway validates exact public-status shapes, UUIDs and recovered-device fields
before exposing them to React. No phrase input or phrase-bearing command arguments
exist in the renderer. Existing workspace styling is reused; action transitions to
non-idle status focus the recovery heading, and status/errors are announced.

Review found that error-only cancellation would hide Stop after remount. The new
wrong-phrase/remount/cancel test first reproduced that bug, then passed after Stop
was made independent of transient errors. Six panel tests cover this, StrictMode,
cancellation, unknown-state retry and lost-response submitting/complete paths.
The entire desktop suite passes: 366 tests across 42 files. After the final style/focus
change, all six panel tests pass again. TypeScript and scoped ESLint pass. Logs:
`.codex/pr16-restore-screen-{full,final,typecheck,lint,cancel-red}.log`.
Independent follow-up review found no remaining concrete P1/P2.

These are component and gateway checks. Installed visual/accessibility acceptance,
real hosted enrollment/recovery across devices, full Mac execution, signing and the
rest of the product release checklist remain required before merge.

### Hosted pairing request compatibility and macOS build

The signed `hosted-pairing-request-v1.hex` fixture is consumed by both the Rust
pairing crypto test and the Edge verifier. It was generated with Node Ed25519
using fixed test-only seeds; it contains public request data and a signature.
All 12 Rust pairing crypto tests and 26 combined Node pairing/enrollment checks
pass. Approval verification and hosted admission remain incomplete.

At `2a83bcc`, GitHub CI run `34271537065` completed macOS all-target Clippy
(job `102214057767`) and the full macOS Tauri build (`102214058208`) successfully.
This supersedes the earlier full-build limitation from the Windows-only
cross-check. Interactive native input, accessibility, installed behavior and the
complete release matrix remain unverified.

### Canonical text parity repair

The shared Edge CBOR reader consumed a leading UTF-8 BOM and used JavaScript
`trim`, which disagrees with Rust on U+0085 and U+FEFF. A failing regression
reproduced the mismatch. Canonical text now preserves U+FEFF and checks Unicode
White_Space, matching Rust's required-text validation. The JSON decoder is
unchanged. The redundant recovery-name trim check was also removed after a second failing regression. All 66 affected sync, enrollment and pairing Node tests pass.

### Hosted approval public-cryptography verifier

The new Edge approval verifier consumes a real Rust-generated public fixture.
It checks canonical grant/certificate structure, both signatures, exact request
bindings, selected root/issuer/scope/epochs, wrapping keys and bounded ciphertext.
Caller-owned inputs are copied before asynchronous verification. All 13 Rust
pairing crypto tests and 68 affected Node checks pass. Device operation proof,
provider admission, live sessions and the joining device's safety confirmation
remain required; this helper alone grants no authority.
