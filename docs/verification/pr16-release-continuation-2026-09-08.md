# PR 16 full-release continuation — 2026-09-08

## Distinct IDs for fresh native proposals — 2026-09-09

Native reconciliation still created shared candidate/proposed-memory IDs, which
would stop the new backfill worker. Fresh native proposals now derive the memory
ID under a separate hash domain while preserving the existing candidate ID and
revision derivation. This prevents new cross-kind ownership collisions.

Persistence rejects newly introduced shared IDs. Existing legacy candidates
retain their stored identity: exact replay and source-content reversion accept
their old memory ID without rewriting the candidate, accepted memory or review
receipt. The compatibility comparison still checks all other immutable fields,
and source/ledger validation remains mandatory. Independent review found no
actionable boundary or compatibility issue.

The original duplicate-ID assertion reproduced the defect. All 26 native engine,
28 native vault and 23 service tests pass (77 total). New coverage rejects fresh
shared-ID persistence and verifies deterministic distinct IDs, pending/accepted/
rejected legacy content reversion, unchanged accepted-memory identity, and exact
review receipt replay after reopening.

Scoped Clippy with warnings denied and the normal production daemon library
check pass. Graphify update completed after the final code change. Local logs:
`.codex/pr16-native-ids-{red,tests,green,clippy,production,graph}.log`.

Saved shared-ID candidates still require migration before signed backfill can
own them. This change prevents new collisions; it does not complete legacy
migration, native signed updates, hosted sync or full release acceptance.

## Daemon background backfill admission — 2026-09-09

The production vault worker now admits one offline-record backfill operation
when its request queue is empty and search indexing has no pending work. It
rechecks requests under the existing submission/shutdown gate, releases that
gate before vault work, and returns to admission after each record. Opening a
workspace schedules a check; commands wake idle backfill so enrollment and new
offline records are discovered. Unenrolled workspaces become idle without keys.

Verification or migration failure pauses backfill for the rest of that worker
run and publishes SyncState::Error. Later reads do not silently clear the error
or repeatedly retry failed work. Restart permits another attempt. Local queue
success retains Offline; it does not claim hosted synchronization. Independent
review found no actionable admission, trust or error-state issue.

All 102 daemon library tests pass (four pre-existing ignored). The extended
enrollment regression covers unenrolled idle state, unchanged snapshot backfill,
verified-key failure and failure pausing. It also runs the actual worker loop:
a read arriving at background admission wins, one record is then backfilled,
and shutdown/reopen preserves the record and queued operation. This is local
worker evidence, not live hosted or installed acceptance.

Daemon library/test Clippy with warnings denied and the normal production
library check pass. Graphify update completed after the final code change.
Local logs: `.codex/pr16-backfill-worker-{suite,clippy,production,graph}.log`.

Legacy shared-ID/queue migration, native mutation reconciliation, hosted network
cycles, certificate refresh and the full installed/signing acceptance gates
remain unfinished. An explicit sync retry must eventually coordinate these
parts; this change does not redefine the currently unsupported network retry.

## Bounded offline record backfill — 2026-09-09

The vault can now queue up to 32 unchanged offline snapshots in one transaction
using verified enrollment/recovery/pairing authority and matching device keys.
It reuses signed persistence for ownership, causal/device chains and outbox
entries while preserving record contents, revisions, search caches and original
request receipts. Committed ownership makes subsequent batches resumable without
replacing signed bytes. Ambiguous record kinds and legacy candidates sharing
their proposed memory ID fail without committing the batch.

The focused regression passes for all seven record kinds, injected second-enqueue
failure, bounded batches, reopen/replay and legacy collision rejection. The
instruction fixture retains its pre-existing legacy queue entry separately from
the eight newly signed snapshots. Independent implementation review found no
actionable trust-boundary or transaction issues.

All 23 service and 14 sync-storage regressions pass, along with the focused
backfill test (38 total). Scoped Clippy with warnings denied and the normal
production daemon library check pass. Graphify update completed. Local evidence:
`.codex/pr16-backfill-{all-kinds,regression,clippy,production,graph}.log`.

This is a storage primitive; production scheduling does not invoke it yet.
Legacy queue/shared-ID migration, native import reconciliation, hosted transport
cycles and the full installed/signing/clean-machine release gates remain open.

## Bind offline records during signed updates — 2026-09-09

The first signed local update to an ownerless memory or task now binds it to
the configured sync scope inside the existing transaction. Binding requires
the expected stored revision, unchanged ID and scope/project, an allowed local
update kind and exactly one materialized record kind. Existing owners retain
their normal checks; remote admission and unbound outgoing writes cannot use
this path to claim local records.

The memory regression reproduced the ownerless update failure. Memory and task
regressions now verify owner/record rollback on outbox failure, successful retry,
unchanged IDs, original create receipts and exact signed bytes after reopening.
All 23 service tests and six ownership-focused sync tests pass. The extended
daemon dispatcher test also passes: it creates a note before enrollment and
updates it afterward, alongside signed desktop/MCP writes and invalid-key guards.
Scoped Clippy with warnings denied and the normal production daemon library
check pass. Independent review found no trust-boundary or rollback issues.
Graphify update completed after the code changes.

This binds records when explicitly updated. Backfill of untouched offline
records, shared-ID legacy candidate migration, native imports and hosted sync
cycles still remain, alongside the rest of the full-release checklist.

## Daemon-owned local signing — 2026-09-09

Enrolled daemon desktop memory/task/candidate mutations and native-hook writes
now load verified vault material and match the installed device's signing and
wrapping keys before configuring OfflineWorkspace. Established sync ownership
cannot silently fall back to unsigned writes when keys/proofs are unavailable.
Fresh or pending unenrolled workspaces retain local operation. Reads do not load
signing material and remain available offline.

MCP mutation dispatch passes the same verified identity into McpWorkspace, which
now propagates it to its underlying workspace service. Its regression reproduced
a successful MCP write with zero outbox entries, then verified signed persistence
and original response/bytes after reopening. The daemon dispatcher regression
completes enrollment, signs desktop and MCP writes without a network session,
checks exact retries, rejects mismatched/missing keys and preserves read access.
All 102 daemon tests pass (four pre-existing ignored), as do 26 MCP memory and
17 MCP task/handoff tests. Core/daemon library and test Clippy with warnings
denied and the normal production daemon library check pass. Independent review
found no new actionable issues. Graphify update completed after the final code change.

Updates to pre-enrollment ownerless memory/task records still need explicit
migration before signed persistence can accept them. Native-import migration,
hosted transport/cycle wiring, certificate refresh, installed acceptance,
signing and all other full-release gates remain open.

## Verified vault sync authority — 2026-09-09

VaultSyncMaterial now implements the sync engine's TrustedSyncMaterial contract
using existing verified enrollment, recovery or completed pairing proofs. The
shared material loader also returns their exact certificate anchors. Anchors
must match active stored certificates; additional devices require active rows,
the same workspace/control epoch and valid signatures from trusted issuers.
Unknown roots, orphaned issuers and revoked devices do not gain authority.
The decrypted content key is limited to its workspace and active key epoch.
Snapshots must be rebuilt for each cycle to observe local revocation changes.

All 32 enrollment/recovery/pairing vault tests pass. The added regression covers
absent/prepared enrollment, active trusted children, an untrusted recovery root,
wrong keys/scope/epoch and revocation after reopening. Its final focused check
also admits a valid child-signed operation and rejects that operation after
revocation. Scoped Clippy with warnings denied and the normal production daemon
library check pass. Independent review found no actionable P1/P2. Graphify
update completed after the final test change.

This provides the production trust implementation; daemon transport/cycle
wiring, certificate refresh and installed two-device acceptance remain open.
All other full-release requirements remain in force before merge.

## Atomic configured candidate decisions — 2026-09-09

Configured review of a sync-owned pending candidate now commits its signed
decision, optional signed accepted memory, original request/response receipt,
outbox and device chain in one transaction. The accepted memory operation has
a separate domain-derived ID and follows the decision in its chain and causal
frontier. Shared outgoing persistence retains the existing validation and only
updates the search cache after commit.

The regression first reproduced missing queued operations. It now verifies
rollback when rejection enqueue fails or the second acceptance enqueue fails,
then successful retry and exact response/operation bytes after reopening.
All 21 service and 14 sync-storage tests pass. Scoped Clippy with warnings
denied and the normal production daemon library check pass.
Review caught an ownerless legacy-candidate compatibility issue;
the corrected path retains local review and its saved memory ID after sync is
configured. The extended legacy regression passes; re-review has no remaining
actionable findings. Graphify update completed.

Ownerless offline/native candidates still require explicit sync migration.
Production daemon sync configuration, installed hosted qualification, signing,
clean-machine acceptance and the remaining full-release gates are unfinished.

## Durable candidate approval receipts — 2026-09-09

Candidate approval now binds its operation ID to the original candidate and
decision before mutation. Reused IDs from another operation, candidate or
decision are rejected. Exact retries return the original response after restart.
The approval receipt, candidate decision and accepted memory share the existing
transaction. Recording a receipt for an already accepted legacy decision does
not overwrite later edits to its memory.

Schema 35 adds the dedicated candidate_review operation kind while preserving
existing bindings, response bytes and foreign keys. Validation passes all 20
service, three offline-workspace, 21 storage and four pairing-intent tests. The
regression reproduced ignored operation IDs, then verified receipt-failure
rollback, restart replay and preservation of later memory edits. The migration
test preserves an existing v10 receipt and checks foreign-key integrity.
Independent review found one stale schema-version assertion; it now uses the
current schema constant and its pairing migration test passes.
Scoped Clippy with warnings denied and the normal daemon library check also pass.

These are local approval receipts. Signing the candidate and accepted-memory
operations atomically remains unfinished, as do native-import and legacy sync
reconciliation, production daemon configuration and full release acceptance.

## Atomic configured MCP proposal writes — 2026-09-09

Configured proposal creation now signs an UpsertMemoryCandidate through the
existing atomic record/operation/outbox/request-receipt transaction. Its scope
comes from the proposed memory. It does not materialize an accepted memory;
unconfigured local creation and original response replay retain their behavior.

The regression failed before integration because proposal creation bypassed the
outbox. It now verifies rollback on an injected outbox failure, a single candidate
operation without the plaintext canary, absence of accepted memory, exact bytes
and response after reopening, and rejection of a changed request. All 19 service
tests, scoped Clippy with warnings denied and the normal daemon library check
pass. Independent review found no actionable issues.

Approval, native-import proposals, legacy sync reconciliation and production
daemon configuration remain unfinished. Signed approval must preserve its
two-record atomic update and use its own durable operation-kind binding.

## Separate fresh proposal and memory identities — 2026-09-09

Fresh MCP proposals derive a distinct proposed-memory ID using a versioned hash
domain and the candidate ID, preserving UUIDv7 timestamp/version/variant fields.
Candidate IDs and request IDs remain unchanged. Saved response replay accepts
either that mapping or the old shared-ID format; existing candidates and accepted
memories are not rewritten. This avoids a new candidate/memory record-kind
collision without weakening sync ownership validation.

The fresh-ID regression failed before the change and now passes. A saved v1
row/receipt fixture verifies legacy replay and acceptance preserve the original
memory ID. All 18 service tests, scoped Clippy with warnings denied and the
normal daemon library check pass. Independent review found no actionable issues.

Native-import identities still use their existing mapping. Legacy candidate sync
reconciliation, proposal signing and atomic signed approval remain unfinished.
Correction to earlier investigation: CandidateReviewParams has an operation ID;
the current service ignores it. Bind it when integrating approval retries.

## Atomic configured task writes — 2026-09-09

Task upsert, transition and completion now use the shared signed mutation helper
when OfflineWorkspace has a configured identity. Native-hook completion reaches
the same transaction and preserves its recorded event clock. Original request
replay remains ahead of signing; unconfigured local behavior is unchanged.

All 17 offline-service tests pass, including both direct and native-hook task
completion. The new regression first failed because a transition bypassed the
outbox; it now verifies an injected outbox failure leaves the task unchanged,
then retries, completes, reopens and checks the original response and signed
bytes without duplicate operations. Scoped Clippy with warnings denied and the
normal production daemon library check pass. Independent review found no
concrete correctness issues.

This remains configured core behavior, not installed daemon sync acceptance.
Candidate review/proposal, other record kinds, offline data binding, verified
trust material and live two-device operation remain open. Candidate and proposed
memory IDs currently overlap; resolve that compatibility issue before signing
both kinds, without weakening the single-kind sync ownership invariant.

## Atomic configured memory writes — 2026-09-09

OfflineWorkspace accepts an optional sync identity and uses the existing signed
operation builder for memory create, update and archive. The persisted device
head and workspace frontier determine sequence and causality. The existing Vault
transaction now also stores the original local request binding and response,
alongside the record, signed operation, outbox and chain state. Unconfigured
workspaces retain their offline behavior. Checkpoint timing uses commit time,
not a caller-supplied operation timestamp.

All 16 offline-service and 14 sync-Vault tests pass. The new regression injects
an outbox insertion failure, checks complete rollback, then verifies three memory
mutations and original response/byte replay after reopening. Changed request reuse
is rejected. Scoped Clippy with warnings denied and the normal daemon library
check pass; independent review found no actionable P1/P2. These tests do not
directly exercise a local update after incoming remote operations.

The daemon does not configure this path yet. Other record kinds, candidate review,
existing offline data, verified trust material, incoming merge integration and
installed two-device qualification remain required. This is staged integration,
not evidence of complete hosted sync or release acceptance.

## Existing Supabase CLI access recovered — 2026-09-09

`pnpm exec supabase secrets list --project-ref brvzuycnxoswdzzipgvx --profile
supabase` succeeds with the existing saved login. The failure without the profile
flag is configuration selection, not evidence of an expired login. This supersedes
the earlier dashboard sign-in requirement. The user explicitly prohibits the
in-app browser because it does not preserve their regular browser cookies.

The authenticated list confirms the pairing pepper is absent. Automatic approval
review rejected the attempted secure random secret setup before execution, with
only "blocked by policy" and no specific reason. Pairing remains undeployed;
do not retry through another route to evade that rejection. No secret value or
credential is stored in this ledger. Production sync and every full-release gate
remain open.

## Native sync session guard — 2026-09-09

The shared Supabase sync executor can now bind requests to the original Auth
owner, generation, identity and project. Each attempt uses the current matching
session token; every response or HTTP error is checked again before processing.
Logout, replacement login and authority withdrawal during backoff stop retries.
Existing request bodies and idempotency headers are preserved by cloning the
original request and replacing only its authorization value.

Validation: all 24 hosted-auth transport tests and nine Supabase sync transport
tests pass. Scoped core library/test Clippy with warnings denied and a normal
daemon library check without test-support pass. Independent read-only review
found no actionable correctness or security issues. The new guard regression
uses GET requests; its refresh test does not directly prove mutation-body replay.

This is transport foundation only. Production sync still needs verified trust
material, atomic signed local mutations/outbox integration, bounded daemon
cycles and installed two-device qualification. The production-sync plan records
those remaining steps. Full signing, product, security and beta gates still apply.

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

### Hosted pairing possession proofs

Request and approval proofs use distinct domains followed by authenticated user
UUID bytes, session UUID bytes and SHA-256 of the exact canonical payload. Rust
signing validates existing payload bindings and both installed device keys;
Edge verification snapshots inputs before asynchronous work. UUID validation
agrees on RFC variant and versions 1 through 8. The affected Node suite passes
69 checks and the Rust pairing crypto suite passes 14 tests. Independent review
found no actionable P1/P2 issues. Live authorization and atomic admission remain
mandatory and are not implemented by these helpers.

### Frozen pairing proofs and macOS test qualification

The public hosted approval fixture now includes request and approval possession
proofs generated by Rust from fixed test-only device seeds. Rust reproduces both
signatures exactly; Edge verifies the same bytes after canonical request/approval
validation. All 14 Rust pairing tests, scoped Clippy and 70 affected Node checks
pass. No fixture-generation filesystem writes remain in the tests.

MacOS Rust test job 102214058009 in run 34271537065 at `2a83bcc` completed
successfully. Its downloaded log is retained locally. Existing opt-in model,
credential and installation tests remain ignored, so this does not close the
physical/credentialed release matrix. Full macOS build and Clippy previously
passed on that same head. Current-head qualification remains required.

### Hosted pairing locator boundary

Pairing locators use ten uniformly random Crockford symbols (50 bits), rendered
as `XXXXX-XXXXX`. Lookup uses HMAC-SHA256 over the ten symbols without the hyphen,
matching the existing Rust provider. The helper accepts only the strict protocol
format and copies/clears its temporary pepper buffer. Tests verify the digest
against Node's independent HMAC implementation, rejected formats and input
mutation isolation. All 71 affected Node checks pass. No invite table, expiry,
lookup-attempt accounting or endpoint admission is claimed by this helper.

### Hosted invite creation transaction

Migration `20260909030000_hosted_pairing_invites.sql` adds private invite storage
and a service-only create RPC. It requires live Auth, an active account/device
binding, a current genesis certificate and an unrevoked root. Account locking
serializes a six-per-hour creation limit; exact retries retain the original
10-minute lifetime and changed inputs conflict. Only the keyed code digest is
stored. API roles cannot read the table or bypass the service boundary.

An observed unique-index wait reproduced expiry-after-insert acceptance in the
initial function. The final post-write Auth/time check rolls back that case.
The final local PostgreSQL suite passes 27 tests, including concurrent creation
and the observed wait regression; all 140 contract tests and check:supabase pass.
The migration has only been applied to the disposable local database. Lookup,
five-attempt exhaustion, cancellation, request/approval commits, endpoint wiring
and real hosted acceptance remain unfinished.

### Hosted code lookup and session reservation

Migration `20260909040000_resolve_hosted_pairing.sql` adds a private failed-guess
counter tied to the live Auth session. Concurrent guesses serialize on that row;
the fifth failure persists and exhausts later lookups. Session deletion cleans
up its counter. Only invites owned by the authenticated account can be located,
and the first successful joining session reserves the invite permanently.
Lookup rechecks current issuer binding, root, epochs and server expiry after
locks. It creates no certificate or device trust.

The local PostgreSQL suite passes 29 tests. The two new tests cover competing
sessions, foreign ownership, eight concurrent guesses, exact retry, expiry,
SQL permissions and an observed account-lock wait with joining-session expiry.
Both lookup tests pass again after adding an Auth recheck following the counter
lock. `check:supabase` passes; independent review found no P1/P2 in this slice.
Only the disposable local database has been migrated. Cancellation, request and
decision admission, Edge wiring, native transport and live pairing remain open.

CI run `34271537065` at `2a83bcc` additionally reports successful macOS native
Semgrep build-a and native-isolation jobs. Windows Rust tests and native Semgrep
build-a remain in progress. This is scoped historical evidence, not current-head
or installed-product qualification.

### Hosted invite cancellation and status

Migration `20260909050000_control_hosted_pairing.sql` adds terminal invite state
and an original-issuer-session-only status/cancel RPC. It checks live Auth,
account, binding, certificate, root and epochs under locks, then rechecks time.
Cancellation is idempotent and cannot overwrite approval or rejection. Terminal
states survive the invite deadline; pending invites cannot be canceled after
expiry. Lookup now rejects canceled, rejected and approved invites.

All 31 local PostgreSQL tests pass (`.codex/pr16-cancel-full.log`), including an
observed account-lock wait where issuer binding expiry prevents cancellation.
Tests also cover concurrent cancellation, wrong session, invalid action,
SQL permissions, revoked roots and terminal precedence. Approved/rejected rows
in this test are synthetic arbitration fixtures, not approval admission evidence.
`check:supabase` and diff checks pass; independent review found no P1/P2. Only
the disposable local database has been migrated. Request/decision admission,
Edge/native wiring and the full release gates remain unfinished.

### Hosted request storage and approver retrieval

Migration `20260909060000_submit_hosted_pairing.sql` stores exact request bytes
and server-calculated SHA-256 in the existing request table. Submission requires
the original located joining session and current issuer authority. Both Auth
sessions are locked before account locks. Exact retries retain their first
receipt; changed bytes or keys conflict. Post-write Auth/authority checks roll
back delayed writes after expiry. Approver retrieval uses the original issuer
session; canceled requests cannot be retrieved. Cancellation also updates the
public request state while retaining exact submission receipts.

All 33 local PostgreSQL tests pass on the final functions
(`.codex/pr16-request-final.log`), including an observed request-row wait with
joining-session expiry. A synthetic legacy row with a colliding ID reproduced
a missing scope check in the initial fetch. Retrieval and cancellation now
match account/workspace as well as ID; the regression verifies neither foreign
read nor cancellation occurs. `check:supabase` and diff checks pass. These SQL
tests use synthetic decoded fields; Edge signature/proof enforcement, approval
admission, native wiring and live hosted acceptance remain required. No device
binding is created by request submission. Only the local disposable database
has been migrated.

### Atomic hosted pairing decisions and results

Migration `20260909070000_decide_hosted_pairing.sql` commits approval as one
transaction: child certificate, original joining-session binding, request state,
approved bytes and receipt. It reuses current issuer checks, locks both Auth
sessions before account/device locks, and rechecks authority and invite expiry
after writes. Rejection installs no trust. Exact decisions return their stored
receipt without reinstalling or reactivating a binding, including after expiry.
Joining-result retrieval requires the original session and exact request digest.

All 37 local PostgreSQL tests pass (`.codex/pr16-decision-full.log`). New tests
cover approval/rejection, conflicting decisions, concurrent arbitration, revoked
binding retries and an observed certificate-insertion wait where joining-session
expiry rolls back every write. Two decision tests pass again with additional
wrong-session, changed-epoch and post-expiry receipt assertions
(`.codex/pr16-decision-final-extra.log`). `check:supabase`, diff checks and a
bounded independent SQL review pass. The tests use synthetic decoded fields;
the service RPC requires Edge canonical/signature/proof verification, which is
not yet wired. This migration has only run in the local disposable database.
Live hosted and full release acceptance remain unproven.

### Pairing verification context and Supabase adapter

Migration `20260909080000_pairing_verification_context.sql` selects the stored
request and original issuer/root keys for Edge approval verification. New
decisions require live authority; committed decisions retain historical context
for exact receipt replay after revocation. Original issuer session, account and
workspace checks apply to both. The commit RPC remains the authority to install
new trust.

The pairing adapter maps all provider operations to service-only RPCs, hashes
codes with a required 32-byte pepper, and sanitizes provider errors. It reuses
the existing Supabase session clients and enrollment authentication/encoding
helpers. No pairing HTTP endpoint is enabled by this change.

All 38 local PostgreSQL tests pass (`.codex/pr16-context-full.log`); all 50
affected enrollment, sync and pairing Node tests pass
(`.codex/pr16-pairing-adapter-full.log`). Tests verify active versus historical
context, wrong session/scope, keyed-only code storage and RPC field/error
mapping. `check:supabase`, diff checks and bounded independent review pass.
Strict HTTP request/response validation, endpoint proof enforcement, native
integration and live/full-release acceptance remain required.

### Pairing HTTP proof enforcement

The pairing HTTP handler now covers create, resolve, status, cancel, request,
submit, approve, reject and result. It verifies Auth claims, closes request and
response shapes, bounds streamed bodies and canonical bytes, and checks IDs,
scope, timestamps and receipt digests. Request and approval signatures plus
original-session possession proofs are verified before their mutation RPCs.
Approval verification uses server-selected authority. Reject/cancel continue
to require original issuer authorization in SQL and install no trust.

All 53 affected Node tests pass (`.codex/pr16-pairing-http-full.log`); all four
handler tests pass after adding a composed HTTP/adapter test
(`.codex/pr16-pairing-http-composed.log`). They use frozen Rust/Edge proofs,
reject changed sessions/proofs/payloads, unknown fields and oversized requests,
and verify bad proofs never reach the approval commit RPC. `check:supabase`,
diff checks and bounded independent review pass. The function entry point and
configuration are present but have not been deployed. Result retrieval checks
the payload digest; native cryptographic verification and human safety-number
confirmation remain mandatory before local installation. Native transport,
daemon wiring, expired-invite cleanup and live/full-release acceptance remain
unfinished.

### Expired pairing cleanup

Migration `20260909090000_prune_expired_pairing.sql` prunes expired pending and
canceled invites during the next new invite creation for the same account.
It preserves the complete one-hour creation-limit window, committed decision
receipts, foreign request rows and exhausted live-session lookup counters.
Cleanup shares the existing account lock and final Auth/expiry rechecks.

The regression failed before the migration and passes afterward. All 39 local
PostgreSQL checks pass (`.codex/pr16-cleanup-full.log`); `check:supabase`,
whitespace checks and bounded independent review pass. Graphify is updated.
These are disposable-database results, not deployed or live acceptance.
Native hosted transport, daemon integration and all full-release gates remain.

### Current-head dependency and secret-scan corrections

GitHub at `75b7add` failed Node dependency policy for
[GHSA-82fw-gwwq-j7x9](https://github.com/advisories/GHSA-82fw-gwwq-j7x9).
Vitest and its mocker now resolve to patched 4.1.11. All 366 desktop tests in
42 files pass on the new major version; TypeScript and production build pass,
and `pnpm audit --audit-level moderate` reports no known vulnerabilities.
The dependency-floor regression fails before the upgrade and passes afterward.

The same head's full-history secret scan found three public verification keys
in historical synthetic pairing fixtures. Both exact historical objects and
their companion Rust tests were independently reviewed. Only the three exact
fingerprints are added to the existing exception ledger, with rationale and
updated byte/digest pins. No detector or scanned ref is disabled. The pinned
Gitleaks 8.30.1 full-ref scan returns zero after the correction; policy checks
pass. This does not establish current-head GitHub CI or full release acceptance.

### Native pairing identity persistence foundation

Vault schema 32 stores the original hosted project, user, session and role for
each pairing ID. Exact retries preserve that binding; changed identities and
adoption of historical unbound requests, decisions or transcripts are rejected.
The record contains no credentials or device secrets. Native transport and
coordinator enforcement still need wiring before this protects hosted operations.

All 27 affected pairing-intent, enrollment, restore and search tests pass, with
eight existing model/performance tests ignored (`.codex/pr16-pairing-intent-full.log`).
The new restart/identity and schema-31 migration checks pass; targeted Clippy
with warnings denied, formatting and diff checks pass. Independent review found
one omitted schema-29 downgrade-fixture update; it is corrected and its real-row
migration check passes. Graphify is updated. No live or full-release acceptance
is claimed.

### Native hosted joining client

`devices/supabase_pairing.rs` now implements code resolution, signed request
submission and result retrieval through the existing login owner and HTTP client.
It binds proofs to the original verified Auth user/session, checks cancellation
and project identity before and after HTTP, and validates bounded response
shapes, IDs, timestamps and receipt/payload digests. Provider timestamps remain
separate from the local clock used for login expiry.

The new wire regression exposed Serde's acceptance of extra fields on unit enum
variants; empty struct variants now reject them. Nullable decision digests must
be explicitly present. Tests cover the frozen Rust/Edge proof, altered receipts,
unknown/missing fields, timestamp overflow, approved payload hashes and logout.
All 21 hosted transport tests and targeted Clippy with warnings denied pass
(`.codex/pr16-pairing-native-full.log`, `.codex/pr16-pairing-native-clippy.log`).
Bounded independent review found no P1/P2 issues. Full approval verification and
human safety confirmation remain in the coordinator; this transport installs no
trust. Approval operations, durable-intent enforcement, daemon wiring and live
acceptance remain unfinished.

### Native hosted approval client

The native client now implements create, status, request review, approval,
rejection and cancellation with frozen account/workspace/device scope. Approval
envelopes carry the original signed request from the durable coordinator record;
all three preparation/retry paths supply it. Proof signing therefore needs no
fresh request lookup that could fail after revocation. Raw legacy envelopes are
rejected by the hosted transport before networking.

All 39 affected hosted transport, in-memory transport and pairing coordinator
tests pass (`.codex/pr16-native-approval-full.log`), as does targeted Clippy with
warnings denied. Wire checks exercise frozen approval proofs, exact replay with
one commit request, foreign scope, request-null versus missing fields, invalid
invite lifetimes, rejection and confirmed cancellation. Independent review found
no P1/P2 issues. Durable identity enforcement and production daemon wiring remain
required before live hosted pairing qualification.

### Coordinator enforcement of original hosted identity

Native transports now expose their fixed project/user/session and joining or
approving role. The coordinator persists that binding before signed preparation
and submission, and requires an exact existing binding before polling,
confirmation or approval resume. A transport without hosted identity cannot
adopt a hosted-bound record. Code resolution necessarily precedes binding a new
join because the pairing ID is not yet known; no signed request is submitted
under a changed binding.

All 34 affected coordinator, hosted transport and identity-persistence tests pass
(`.codex/pr16-pairing-bind-full.log`); targeted Clippy with warnings denied passes.
The regression reopens the vault, verifies byte-identical request reuse, and
blocks submission/result calls for changed project, user, session, role or absent
hosted metadata. Independent review found no P1/P2 issues. Production daemon
integration and live installed acceptance remain required.

### Fresh joining daemon authority

The coordinator-backed daemon service now has a fresh-joiner constructor with
no workspace or issuer certificate. Create, decision, cancel and approver-status
operations require approval authority; joining status and human confirmation
remain available. The authenticated two-daemon IPC regression now uses this
constructor and explicitly checks those forbidden commands before completing
pairing. All nine daemon pairing tests pass, and targeted daemon Clippy with
warnings denied passes (`.codex/pr16-daemon-joiner-{green,clippy}.log`). Independent
review of the authority refactor found no P1/P2 issues. Production hosted service
wiring and live acceptance remain unfinished.

### Newly reported Node dependency advisory

GitHub job 102261628862 on head 83a8b58 failed for
[GHSA-2883-xcg3-v3hh](https://github.com/advisories/GHSA-2883-xcg3-v3hh).
The existing js-yaml override and lockfile now resolve 4.3.2, the patched version.
Local pnpm audit reports no known vulnerabilities and desktop lint passes
(`.codex/pr16-js-yaml-{audit,lint}.log`). Current-head CI remains required; this
dependency fix does not complete any outstanding installed release gate.

### Scoped prepared-approval resume and dependency policy follow-up

The coordinator can now resume one requested prepared approval, using the same
original-identity and exact-receipt checks as batch resume. A restart regression
proves unrelated/missing IDs leave pending work intact, an accepted ID does not
resubmit, and changed project/user/session/role or missing hosted metadata fails
before provider submission. All 13 affected pairing coordinator and identity
tests pass; targeted Clippy with warnings denied passes
(`.codex/pr16-pairing-single-resume-final{,-clippy}.log`). Independent review of
the resume implementation found no P1/P2 issues. Production wiring is still open.

Current-head job 102265572882 exposed a missed dependency-policy assertion that
still demanded js-yaml 4.3.1. Its required version is now 4.3.2 and its rejection
pattern includes 4.3.1. The actual CI command sequence (frozen install, policy
test, low-severity audit) passes locally with no known vulnerabilities
(`.codex/pr16-node-policy-final.log`). Hosted CI must still qualify the new head.

### Durable public request reviews

Vault schema 33 saves the verified public signed request, original provider scope,
digest and timestamp before decision preparation. Reads verify canonical bytes
and signatures; writes accept only an exact replay. An unbound cached review
cannot acquire a hosted identity. Cached metadata contains no approval payload
or safety number and does not replace certificate/epoch or receipt validation.

Accepted daemon status and decision retries prefer this saved review. Legacy
approvals without a review retain the provider lookup; migration does not
fabricate timestamps. The production hosted wrapper and live acceptance remain
unfinished.

Ten coordinator tests, 29 migration/persistence tests and the nine daemon pairing
tests pass. The migration suite includes schema 31/32 upgrades, immutable
timestamps/scope, changed digests, overflow, corrupted reads and unbound-review
adoption denial; eight existing model/performance tests remain ignored.
Core and daemon library/test Clippy with warnings denied passes. Independent
review found no P1/P2 issues. Evidence is in
`.codex/pr16-review-persistence-{core,migrations,daemon,clippy}.log`.
The final two-daemon regression also passes after reconstructing the approver
with both transports unavailable: accepted status and approval retry return the
same original review (`.codex/pr16-review-persistence-offline-final.log`).

GitHub dependency-policy job 102267351743 passed at e87860a. Six superseded
workflow cancellation requests were accepted to free the runner queue; that
historical head and local tests do not qualify the next pushed head for release.

### Production hosted pairing client wiring

Daemon startup now configures pairing beside hosted recovery using the same
Auth owner and protected device identity. The service derives approval authority
from a unique active matching recovery-root certificate and validated local
workspace material. Fresh joiners have no scoped approval client. Saved pairing
IDs keep their original project/user/session/role, and every provider call still
checks current session authority. Startup validates local pending transcripts
without network work; explicit status resumes only its own prepared approval.

All 40 affected core tests and the full daemon suite pass (97 passed, four
pre-existing ignored). Library/test Clippy with warnings denied and a normal
daemon library check without test-support pass. Two final hosted guard tests
pass, covering offline startup, login-before-join, fresh-device approval denial,
lost submission response with identical bytes after reopen, wrong keys/project/
role, logout and replacement-session denial before provider submission.
Logs: `.codex/pr16-hosted-pairing-{core-final,daemon-all,clippy,normal-check,guards-final}.log`.
Independent bounded review found no P1/P2 issues. An initial test directory setup
error was fixed; normal-build validation also confirmed that opaque transcript
fields remain private.

This is component evidence. The function is still undeployed, and composed
hosted two-device approval/confirmation, terminal behavior after logout and
installed live acceptance remain required. No full-release checkbox or merge
is justified by these results alone.


### Composed native hosted pairing qualification

The existing two-daemon pairing test now runs against both its memory transport
and a simulated HTTP provider with real native hosted clients and Auth owners.
The hosted variant verifies session proofs, commits an approval before dropping
its response, reconstructs the approving daemon/Vault/service, and compares the
replayed payload and receipt exactly. The joining daemon receives no full safety
number from status and installs matching workspace material only after explicit
confirmation. Both Auth owners execute logout before confirmation and accepted
status/decision retries; these local operations make no pairing HTTP calls.
Fresh joining-device approval and MCP bridge pairing remain denied.

All 12 daemon pairing tests pass on this Windows host, including both composed
variants (`.codex/pr16-hosted-two-daemon-final.log`). Bounded independent review
found no P1/P2; its evidence correction replaced session invalidation with the
actual logout method before the final run. This simulated provider does not
qualify live Supabase revocation, deployment, installed macOS/Windows acceptance,
signing, clean machines or the remaining full-release checklist. PR #16 stays open.

Final daemon library/test Clippy with warnings denied also passes (.codex/pr16-hosted-two-daemon-clippy-final.log).


### Joining-device restart before confirmation

The two-daemon memory and hosted HTTP variants now send a guaranteed-different,
well-formed safety number after logout. Both reject it with InvalidRequest.
After stopping the joining daemon, direct Vault inspection proves no trusted
device was installed and the awaiting-confirmation record remains durable.
A reconstructed joining daemon returns the same public status, then accepts the
correct number and installs the matching workspace material. The hosted case
makes no pairing HTTP calls during wrong confirmation, restart/status or correct
confirmation. Both composed tests pass on Windows
(`.codex/pr16-pairing-joiner-restart.log`). This strengthens component recovery
evidence and does not replace the required live installed acceptance matrix.

Daemon library/test Clippy with warnings denied also passes
(`.codex/pr16-pairing-joiner-restart-clippy.log`); independent bounded review
found no P1/P2 issues.


### Durable account-lifecycle intent prerequisite

Vault schema 34 stores the original operation ID, begin/cancel action, hosted
project, Auth user/session, account and workspace in an immutable bounded payload.
It reuses hosted-identity validation, validates reads and rejects an embedded ID
that differs from the requested key. Exact writes are idempotent; changed action
or authority conflicts. No credentials, automatic mutation, rebinding or deletion
API is introduced. Migration creates no historical authority records.

The first test failed for missing storage APIs. The implemented storage tests
pass, covering reopen, every immutable identity field, invalid new identities,
corrupted key/payload association and schema-33 upgrade. Independent read-only
review found no P1/P2. Production account lifecycle remains unavailable: it still
needs current-session checks around each HTTP attempt, verified scope, intent
persistence before dispatch, and explicit retry/reconciliation UI. Storing an
intent alone is not permission to replay a mutation or evidence of hosted deletion.

Final validation: two lifecycle intent tests and 29 affected pairing/recovery/
search tests pass; eight existing model/performance cases remain ignored.
Core library and the new integration-test Clippy check pass with warnings denied.
Logs: `.codex/pr16-lifecycle-intent.log`,
`.codex/pr16-lifecycle-intent-migrations.log`, and
`.codex/pr16-lifecycle-intent-clippy.log`. Graphify updated to 17,725 nodes;
optional SQL/OCaml parsers remain unavailable. Six superseded GitHub workflow
cancellation requests were accepted; current-head CI is still required.


### Account-lifecycle session guards

The existing lifecycle transport can now bind to the daemon Auth owner and an
original identity/generation. Every attempt validates that binding and the
configured project, obtains the current session token, and checks authority again
after HTTP completion (including errors). Backoff cannot revive canceled work;
valid refresh changes the token while preserving exact operation/request bytes.
The response limit is supplied to the HTTP client as well as checked after read.
Existing static transport construction remains available for its prior boundary;
production must select the guarded path when lifecycle integration is completed.

The missing guard regression failed before implementation. All 27 affected Auth
and lifecycle tests pass. The new check covers withdrawn authority before send,
during HTTP success/error and during backoff; wrong project/identity; same-identity
replacement login; successful requests; and valid refresh between identical retries.
Independent bounded review found no P1/P2. Evidence:
`.codex/pr16-lifecycle-session-final.log`. No live request or production lifecycle
activation occurred. Durable intent dispatch, verified scope and explicit
retry/reconciliation UI remain required before activation.

Core library and all three affected integration-test targets pass Clippy with
warnings denied (`.codex/pr16-lifecycle-session-clippy.log`).


### Lifecycle intent persistence before daemon dispatch

The existing ordered daemon service now obtains read-only authenticated intent
metadata from its transport and commits it before begin/cancel dispatch. It rejects
metadata with a different operation/action and refuses an unbound transport's
attempt to adopt an existing hosted intent. Status bypasses mutation intent
handling and cannot replay a begin/cancel. Storage errors stop dispatch.
The guarded native transport supplies normalized project, original user/session,
workspace and the daemon-provided account after checking current session authority;
this metadata read performs no HTTP call.

Four daemon lifecycle tests pass. The new test opens a separate Vault from inside
the simulated transport call, proving the original intent was already committed.
It then exercises a lost response, service/Vault reconstruction, exact retry,
status-only reconciliation and changed-session/action/unbound denial. Independent
bounded review found no P1/P2. Evidence: `.codex/pr16-lifecycle-dispatch.log`.
The initial test also needed its OperationId import corrected after exposing the
missing transport metadata method.

Production still selects the unavailable lifecycle transport. Derivation of
verified account/workspace authority, discovery of unresolved operations and the
explicit retry UI remain necessary before production activation. No live account
transition, export, purge or full-release acceptance is implied.

Final validation also passes all 27 affected core Auth/lifecycle tests, and
core/daemon library and test Clippy with warnings denied. Logs:
`.codex/pr16-lifecycle-dispatch-core.log` and
`.codex/pr16-lifecycle-dispatch-clippy.log`. Graphify completed with 17,735 nodes;
its missing optional SQL/OCaml parsers do not affect these executable checks.
The new metadata test covers withdrawn/replaced authority, not a timed-expiry
case. Existing provider freshness checks remain mandatory on every mutation.

### Required nullable lifecycle response fields

The shared native lifecycle decoder now requires both `requestedAtMs` and
`purgeDeadlineMs` keys while accepting explicit null. Previously Serde treated
omitted optional fields as null, accepting malformed active/purged projections
that the Edge contract rejects. This applies to status, begin and cancel.

The regression reproduced acceptance of an active response missing
`requestedAtMs` before the fix. One test covers either/both missing keys for
active/purged across all three actions and verifies valid explicit-null replies.
All 28 affected lifecycle/Auth tests and scoped core library/test Clippy with
warnings denied pass. Independent bounded review found no semantic issues.
Evidence: `.codex/pr16-lifecycle-null-red.log`,
`.codex/pr16-lifecycle-null-final.log`, and
`.codex/pr16-lifecycle-null-clippy.log`. Graphify update completed (17,737 nodes).
These are local boundary checks; production lifecycle activation, live provider
acceptance and the full release gates remain unfinished.

### Lifecycle intent discovery after restart

Added a read-only vault query returning at most 50 original lifecycle intents,
ordered by operation ID and exclusively after an optional cursor. It reuses the
existing bounded payload and exact embedded-ID validation. Discovery does not
classify provider completion or submit/rebind any operation. No migration needed.

The missing-API test failed before implementation. Both lifecycle intent tests
pass, including 52 stored intents inserted out of order, restart, exclusive
pagination, exhaustion, exact repeat and corrupted payload rejection. Scoped
core library/test Clippy passes with warnings denied. Independent review found
no actionable P1/P2. Logs: `.codex/pr16-lifecycle-discovery-red.log`,
`.codex/pr16-lifecycle-discovery-final.log`, and
`.codex/pr16-lifecycle-discovery-clippy.log`.

Daemon discovery IPC, explicit retry UI and production scope integration remain
open. Certificate-row decoding is not signature-chain verification; the plan
now records that distinction. Paired devices have an existing
`completed_pairing_approval` path that checks protected keys and reopens the
validated confirmed transcript. Full hosted, signing and installed release
acceptance is still required before merge.

### Desktop-only lifecycle discovery IPC

Protocol 1.15 adds `account_deletion_intents` with an explicit nullable operation
cursor. The ordered worker reads the existing bounded vault query and returns
only original operation IDs and begin/cancel actions. Project, account, user and
session bindings stay in the vault. Summaries must be ordered, unique and at
most 50 entries. Discovery does not call the lifecycle provider or infer whether
an operation committed. The core action enum is re-exported from protocol with
unchanged stored serde values. Bindings and status schema are regenerated.

The new protocol request failed before implementation. All 227 protocol/local
IPC tests now pass (three existing ignored fixtures); 19 frontend protocol tests
and TypeScript checks pass. The first full IPC run exposed the desktop-method
count changing from 63 to 64; each role's per-method assertions pass after its
expected count was corrected. Independent review identified a protocol upgrade
regression: 1.15 needed explicit shutdown-only support for the prior 1.14 daemon.
The frozen test reproduced ProtocolVersionUnsupported; explicit compatibility
and frozen accept/ordinary-client-reject tests now pass. Review closed that P2.

Evidence: `.codex/pr16-lifecycle-ipc-red.log`,
`.codex/pr16-lifecycle-ipc-contracts-final.log`,
`.codex/pr16-lifecycle-ipc-upgrade-red.log`,
`.codex/pr16-lifecycle-ipc-frontend.log`, and
`.codex/pr16-lifecycle-ipc-typecheck.log`.
Production lifecycle scope/transport activation and the explicit retry UI remain
required. No live account transition or full-release acceptance is claimed.

The five daemon lifecycle tests and routing test pass. The new worker test reads
original summaries across two worker lifetimes with the provider unavailable,
checks exclusive-cursor exhaustion and confirms the stored intent is unchanged.
All 27 affected core tests pass. Scoped protocol/local IPC/daemon/core Clippy
passes with warnings denied, as do frontend lint and generated binding/schema
and daemon-boundary checks. Evidence: `.codex/pr16-lifecycle-ipc-daemon.log`,
`.codex/pr16-lifecycle-ipc-core.log`, `.codex/pr16-lifecycle-ipc-clippy.log`,
`.codex/pr16-lifecycle-ipc-frontend-lint.log`, and
`.codex/pr16-lifecycle-ipc-check-generated.log`. Graphify completed after the
final code change (17,751 nodes).

A normal daemon library check without test-support also passes:
`.codex/pr16-lifecycle-ipc-production-check.log`.

### Desktop lifecycle confirmation and explicit retry controls

Settings now includes account lifecycle status, confirmed begin/cancel actions,
and bounded previous-request pages. Refresh performs reads only. A failed
mutation retains its original ID in the open review, clears the confirmation and
requires a status refresh before explicit retry. Reopening the panel discovers
durable original action/ID summaries through daemon IPC. The UI describes these
as previous requests, not proof of provider completion. Unknown status disables
submission; the unavailable production transport produces an honest unavailable
message. The gateway validates closed response fields, state/deadline/export
consistency, strict operation IDs and advancing bounded history pages.

All 375 frontend tests pass, including nine new focused cases covering lost
responses/exact retry, StrictMode, remount discovery, no replay on reads,
unknown state, duplicate submission, stale gateway responses, pagination, request
ID generation failure and focus restoration. TypeScript, ESLint and the production
frontend build pass. Logs: `.codex/pr16-lifecycle-ui-full-final.log`,
`.codex/pr16-lifecycle-ui-typecheck-final.log`,
`.codex/pr16-lifecycle-ui-lint-final.log`, and
`.codex/pr16-lifecycle-ui-build-final.log`.

A temporary local Vite fixture with an in-memory gateway was inspected in the
Codex browser. It exposed lost keyboard focus when the opening trigger vanished;
the regression failed before fixing focus entry to the confirmation input or
cancellation legend. The final browser pass verified disabled-until-confirmed
submission, the simulated pending result, heading focus after completion/close,
and Tab reaching Refresh. No hosted request occurred. The temporary fixture was
removed and its server stopped. A separate regression exposed request-ID creation
outside the cleanup boundary; generation now runs inside try/finally, releasing
the busy guard on failure. Focus and RNG red logs:
`.codex/pr16-lifecycle-ui-focus-red.log` and
`.codex/pr16-lifecycle-ui-random-red.log`. Independent review found no actionable
P1/P2, including these follow-ups.

Production lifecycle transport/scope activation, installed Windows/macOS native
qualification, live Auth/account transitions, export/purge and the full release
gates remain open. This browser fixture is not live or clean-machine acceptance.


### Confirmed paired workspace authority (2026-09-09)

`trusted_workspace_material` now supports a paired joiner only when neither
recovery enrollment nor restore is present and exactly one completed joiner
transcript exists. It reuses `completed_pairing_approval`, including matching
protected keys, verified sealed material, durable join metadata and active
issuer/child certificates. No authority is inferred from certificate rows alone.
Daemon pairing approval still requires a recovery-root-issued certificate.

The existing restart regression failed before the fix. It now verifies the
exact scope, epochs and both keys after a completed-vault reopen, denial before
confirmation, wrong-key denial and denial after certificate revocation.
All 37 affected pairing-vault, recovery-vault and recovery end-to-end tests pass;
the final expanded regression and scoped core library/test Clippy with warnings
denied also pass. Independent read-only review found no actionable P1/P2.
Evidence: `.codex/pr16-paired-scope-red.log`,
`.codex/pr16-paired-scope-tests.log`, `.codex/pr16-paired-scope-final.log`,
`.codex/pr16-paired-scope-clippy.log`. Graphify update completed.

This is a local authority prerequisite. Production lifecycle wiring and composed
service qualification, live hosted acceptance and every broader release gate
remain unfinished. PR #16 remains open.


### Production account lifecycle wiring (2026-09-09)

Configured daemon startup now installs `HostedAccountLifecycleService` alongside
hosted pairing and recovery. Before constructing the native transport, it checks
the Auth owner/current project, obtains workspace material from verified local
provisioning, and requires one active certificate matching the installed device,
both protected public keys, scope and control epoch. The existing guarded
transport checks original session authority around HTTP attempts, and the ordered
service commits immutable intent before begin/cancel dispatch. Changed login,
project, scope or action cannot adopt the original operation. Status never replays
an intent; existing desktop-role and explicit deletion-confirmation guards remain.

The native-service regression uses the existing simulated Auth fixture and a
bounded lifecycle HTTP fixture. It verifies no dispatch before provisioning,
correct workspace selection, lost-response retry after reopening the vault with
identical request bytes, replacement-login and changed-action rejection,
wrong-project/device denial, read-only status and logout denial. The first build
failed because the production service was missing; the implemented test passes.
This test calls the service directly; composed lifecycle through authenticated
IPC and live provider/installed qualification remain required.

Validation: all 101 daemon library tests passed, with four pre-existing ignored;
daemon library/test Clippy with warnings denied and normal production library
check without test-support passed. Independent read-only review found no
actionable P1/P2. Graphify update completed. Logs:
`.codex/pr16-native-lifecycle-red.log`,
`.codex/pr16-native-lifecycle-focused.log`,
`.codex/pr16-native-lifecycle-daemon.log`,
`.codex/pr16-native-lifecycle-clippy.log`,
`.codex/pr16-native-lifecycle-production.log`.

No live hosted deployment, signing, clean-machine acceptance or merge is claimed.
The full release checklist remains the merge prerequisite.


### Paired-device lifecycle over authenticated IPC (2026-09-09)

The existing two-daemon hosted-pairing scenario now continues with the confirmed
paired device and native lifecycle service over authenticated local IPC. It
checks MCP denial and incorrect confirmation before provider access, a committed
begin whose responses are lost, daemon/vault restart, read-only discovery of the
original action/operation ID, pending status, exact request bytes on retry,
cancellation, and an old begin retry returning current active state without
restarting deletion. Logout prevents further lifecycle HTTP dispatch.

The simulated provider retains original session/request bytes and counts actual
state transitions independently of requests. The scenario passes, as does the
affected direct native-service regression and daemon library/test Clippy with
warnings denied. Independent review found no concrete P1/P2. Evidence:
`.codex/pr16-lifecycle-ipc-composed.log`,
`.codex/pr16-lifecycle-ipc-composed-native.log`,
`.codex/pr16-lifecycle-ipc-composed-clippy.log`.

Limits: the test explicitly injects the native service and retains the same Auth
owner across daemon restart. It does not test production startup selection or
credential-store restoration. HTTP is simulated; server SQL idempotency, live
OAuth/provider behavior and installed acceptance require their own evidence.

Hosted deployment inventory was rechecked read-only: project
`brvzuycnxoswdzzipgvx` is ACTIVE_HEALTHY, PostgreSQL 17.6.1.155. It still has only
migrations `20260805153409` and `20260805155753`, no Edge Functions, zero Auth users,
zero sync operations and zero sync checkpoints. The 15 subsequent repository
migrations and four Edge Functions therefore remain deployment work; reconcile
existing migration identities before rollout. No hosted mutation occurred.


### Hosted schema and initial Edge deployment (2026-09-09)

The two hosted baseline SQL statements were read back and exactly matched the
repository sources after CRLF normalization and trimming. Their original remote
versions were preserved. All 15 later repository migrations were applied in
order to `brvzuycnxoswdzzipgvx`; all 17 stored statements then matched their
repository source. Version mapping and deployed bundle digests are recorded in
[the deployment evidence](hosted-deployment-2026-09-09.json).

All public/private tables have RLS enabled. None of the 32 public service
functions is executable by anon or authenticated. Six existing private helpers
retain the baseline grants required by RLS/storage policies. Security advisors
report no error/warning and 12 informational RLS-without-policy notices for
private/service-only tables that deliberately deny direct client access. Auth
users, accounts, sync operations and checkpoints remained empty.

Deployment exposed an environment-contract gap: entrypoints read a singular
publishable variable, while managed Supabase supplies named key JSON maps.
All four now use a shared reader for SUPABASE_PUBLISHABLE_KEYS and
SUPABASE_SECRET_KEYS defaults, preserving explicit overrides and sanitizing JSON
parse errors. Forty-one affected Node checks and the Supabase contract check
pass; independent review found no actionable P1/P2. Graphify update completed.
Evidence: `.codex/pr16-edge-environment-{red,tests,contract,graph}.log`.

Sync, account-lifecycle and enrollment were deployed at version 1 with exact
source dependencies. Their own Auth validation remains mandatory with gateway
verify_jwt=false. Valid request shapes with missing and invalid bearer tokens
returned HTTP 401/auth_required on all three; initial malformed-body probes
returned 400 and were not counted as authentication proof. Results are in
`.codex/pr16-hosted-edge-auth.json` and the deployment evidence above.

Pairing remains undeployed until its persistent random pepper can be configured.
The dashboard requires user sign-in; CLI secret inspection failed with
LegacyProfileLoadError. A sign-in request is pending. No secret was placed in
source or logs. Anonymous rejection does not establish authenticated functionality,
credential restoration, installed acceptance or full release completion.

### Local shared-ID candidate migration (2026-09-09)

Schema 36 stores local aliases for legacy candidates whose ID equals their
proposed memory ID. Bounded signed backfill renames those candidate IDs and
creates aliases in its existing transaction. Accepted memory IDs and original
request receipts remain unchanged. Old-ID review requests return their original
requested ID while signed operations use the canonical candidate ID. Native
re-observation and content reversion resolve the same stored candidate.

The focused regression verifies rollback on outbox failure, alias preservation,
signed old-ID approval and exact retry after reopening. The final service,
lifecycle, pairing and sync-storage regression passes 43 tests; four affected
schema-upgrade checks pass. The native-vault suite passed 28 tests before the
final acknowledgment and downgrade-fixture corrections. Core library/test Clippy
with warnings denied and a production daemon library check both pass. Review's
acknowledgment-ID and downgrade-fixture findings are fixed. Graphify update
completed. Logs: `.codex/pr16-candidate-alias-{final-test,final-regression,upgrades,clippy,production,graph}.log`.

This is local migration evidence. Incoming canonical candidates do not yet
reconstruct aliases on another device; validated receive/replay and collision
handling remain required before network sync acceptance. Legacy queue migration,
hosted sync cycles and all installed/signing/clean-machine gates remain open.

Signing enrollment is being prepared in regular Chrome. Apple requires account
sign-in. A one-year Certum Standard Cloud certificate cart quotes EUR 209 with
Taiwan selected, but account creation, purchase and identity verification are
unfinished. No certificate purchase or agreement acceptance is claimed.
Supabase CLI access works with the existing `supabase` profile; no new Supabase
sign-in is needed. Pairing deployment still requires the persistent pepper whose
configuration was rejected by automatic approval review.

### Receiving migrated candidates (2026-09-09)

A two-vault regression reproduced loss of old-ID candidate lookup after receiving
an actual migrated signed chain and reopening. The receive transaction now
reconstructs deterministic legacy aliases, rejects unrelated local candidates,
ownerless memory collisions and incompatible existing owners, and rolls alias
creation back with failed operation persistence. Admission and persistence check
the canonical candidate's ownership before permitting use of an aliased memory
ID; explicit ownership binding applies the same check.

Review found that accepted legacy memory could precede its canonical candidate
in a one-record backfill batch. Backfill now selects migrated candidates before
other records, after projects. The regression uses IDs for which ordinary UUID
ordering would select memory first, then verifies candidate-first signing,
reopening, rejection of foreign binding and completion without duplicate work.
The signed receive regression also checks exact replay, local candidate
collision preservation and injected-write rollback. Both focused tests pass;
six existing signed-sync ownership tests passed before the final ordering and
public-binding corrections. Both bounded review findings are closed.

Core library/test Clippy with warnings denied and the production daemon library
check pass. Graphify update completed. Logs are
`.codex/pr16-candidate-alias-receive-{red,order-final,owners,clippy,production,graph-final}.log`.
This remains component evidence; hosted network-cycle wiring and installed
cross-device/full-release acceptance are not complete.

### Retiring superseded legacy queue entries (2026-09-09)

Signed backfill now retires legacy queue entries for the replaced record in the
same transaction, retaining original operation payloads and receipts. It validates
operation identity, record kind and upsert shape. Entries referenced by signed
nonce storage or record heads cannot be retired merely because metadata is
missing. Cleanup processes at most 32 legacy entries per selected record.

Already-backfilled records also receive bounded cleanup. Their matching verified
owner and signed representative must rehydrate to the current materialized state
before an old queue entry can be retired. This handles restart from earlier PR
checkpoints that had signed the snapshot but left its legacy envelope queued.
Unverifiable replacements and orphaned legacy entries are not silently discarded.

The regression first reproduced the stale ninth queue entry, then verifies its
removal with original operation preservation, transactional rollback when queue
deletion fails, cleanup after reopening an already-backfilled vault, and signed
receive/replay after migration. A real signed creation followed by signed review
also verifies that removing only the creation's metadata cannot cause retirement
of its queued predecessor. Both focused backfill tests pass. The review's restart
and signed-predecessor findings are fixed and closed.

This remains local migration evidence. Orphan/corrupt legacy queue handling,
production hosted sync integration and installed/full-release gates remain open.

Core library/test Clippy with warnings denied and the normal production daemon
library check pass. Graphify update completed. Evidence logs:
`.codex/pr16-legacy-queue-{red,protected,clippy,production,graph}.log`.

### Search projection for signed receive (2026-09-09)

The shared service `sync_embedding` resolver validates the admitted mutation and
reuses local lexical embedding logic for memory and instruction representatives.
Other record kinds need no vector. Model-derived semantic vectors remain local,
resumable indexing work. The real signed-chain receiver regression now uses this
resolver instead of a constant fixture vector and verifies the accepted memory
is searchable after reopening. Both focused backfill/receive tests pass; bounded
review found no actionable issue.

Daemon tracing confirms SyncRetry remains unsupported. Production startup already
owns the Auth session and protected device identity, and SupabaseTransport checks
that original session around HTTP attempts. SyncEngine currently holds a mutable
vault through synchronous transport calls; safe daemon integration must separate
network waits from local vault admission without creating stale search caches or
allowing canceled/replaced sessions to apply results. This integration is still
required before installed hosted acceptance.

Core library/test Clippy with warnings denied and the production daemon library
check pass; Graphify update completed. Logs:
`.codex/pr16-sync-search{,-clippy,-production,-graph}.log`.

### Resumable push stages (2026-09-09)

SyncEngine now separates bounded push preparation from receipt completion. The
prepared value owns immutable canonical operations, scope/provider and captured
retry attempts, with no vault borrow across HTTP. Finishing validates scope and
stored bytes, then applies the existing receipt and backoff rules only to the
captured IDs. The existing synchronous driver calls these same stages.

The staged regression exercises wrong-scope rejection, committed remote push with
lost acknowledgment, local writes during the network interval, exact retry after
reopening and a newer queue entry surviving the older acknowledgment. It first
exposed a missing more-work signal for intervening writes; finishing now rechecks
for due work. Review found no additional actionable issue. This is a core stage
extraction, not a completed daemon network driver: the host still must revalidate
the original session before accepting queued completions and use completion time
for retry deadlines. Pull/repair stages and the single-flight daemon supervisor
remain required, along with the full release checklist.

All 44 sync-engine tests pass (175.74 seconds), including malformed push receipts,
byte limits, scoped cursor/receipt binding, lost acknowledgments, durable retries,
gap repair and checkpoint flows through the existing driver. Graphify update
completed. Evidence: `.codex/pr16-staged-push-{red,tests,graph}.log`.

Core library/test Clippy with warnings denied and the normal production daemon
library check also pass. Logs: `.codex/pr16-staged-push-{clippy,production}.log`.
GitHub current-head CI was still queued at this checkpoint; no CI/release/merge
completion is inferred from local checks.

### Resumable pull and gap repair (2026-09-09)

SyncEngine now returns owned operation-page and device-range requests between
local vault turns. The existing synchronous driver uses these same stages, so
page validation, operation/byte budgets, quarantine, gap repair and transactional
cursor advancement share one implementation. Completion rejects a changed scope,
provider, budget configuration or durable cursor before applying a response.
The host must still recheck the original authenticated session and current trust.

All 45 sync-engine tests pass (179.60 seconds). The new staged regression performs
ordinary local work while a range request is pending, repairs the gap, rejects a
stale page completion and verifies the device head, cursor and local record after
reopening. Bounded review found no actionable issue. Graphify update completed.
Evidence: `.codex/pr16-staged-pull-{focus,tests,graph}.log`.

This completes core push/pull operation staging, not production daemon sync.
SyncRetry remains unsupported until the single-flight supervisor, original-session
completion checks, refreshed trust and checkpoint stages are wired and verified.
The full release acceptance checklist remains required before merge.

Core library/test Clippy with warnings denied and the normal production daemon
library check pass. Logs: `.codex/pr16-staged-pull-{clippy,production}.log`.
GitHub checks remained queued at the preceding pushed head.

### Daemon operation-sync supervisor (2026-09-09, integration in progress)

The daemon now wires SyncRetry and a single-flight periodic supervisor to the
shared engine stages. Actual Supabase transport calls run outside the sole vault
actor. Each queued stage rechecks its original Auth session/generation, hosted
project and verified local workspace scope, then rebuilds current local trust.
Shutdown closes admission and aborts the supervisor; already-running HTTP remains
bounded by the transport's deadlines and cannot submit its late result.

Review identified three integration gaps, now fixed in source: preserve pending
push work through pull completion; clear stale Syncing status after authority
loss; and recover authentication-blocked outgoing rows only on an admitted
verified session change. Completion rechecks newly due writes; pending work runs
another bounded cycle. Scoped unblock preserves attempt counts, bytes and other
block reasons. No further actionable issue was found in the bounded follow-up.

The focused authenticated-transport stall test passes: ordinary reads and
supervisor shutdown remain responsive, and reopening preserves queued bytes and
attempt counts. The scoped unblock regression passes for wrong account/workspace,
matching reason, repeated invocation and reopen. These are simulated HTTP and
component checks. They do not prove an installed sync cycle, HTTP cancellation,
certificate refresh or checkpoint acceptance. Certificate refresh and checkpoint
staging remain required before production cross-device qualification.

All 103 active daemon library tests pass (207.59 seconds); four existing tests
remain ignored. Logs: `.codex/pr16-sync-supervisor-{tests,all-tests}.log` and
`.codex/pr16-sync-unblock-tests.log`. Graphify update completed.

After the enum storage adjustment, the expanded focused regression also passes
(6.44 seconds): it acknowledges a push through the real Supabase adapter, stalls
the subsequent pull, and verifies shutdown and the acknowledged queue after
reopening. Evidence: `.codex/pr16-sync-supervisor-final-focus.log`.

Final core/daemon library and test Clippy with warnings denied passes, as does the
normal production daemon library check. Logs:
`.codex/pr16-sync-supervisor-clippy-final.log` and
`.codex/pr16-sync-supervisor-production.log`. Final Graphify update completed.

### Hosted certificate refresh (2026-09-09)

The operation supervisor fetches scoped, keyset-paged certificates before push and
after each received operation page/range. Network parsing validates scope, field
widths, issuer shape and signatures; the vault anchors chains in current verified
local enrollment/pairing authority before use. Hosted records cannot replace a
pinned certificate or resurrect locally revoked issuers and descendants. Trust
is cycle-local and refreshed after restart; no display/platform metadata is
invented or persisted. Requests remain bound to the original Auth session.

Missing device metadata stops admission with a retryable cursor, rather than
quarantining an operation merely because its certificate is absent. Refresh after
the received page covers a device paired while that page was in flight. Review's
revoked-subtree issue is fixed: descendants are excluded while independent valid
branches continue. The bounded follow-up found no additional actionable issue.

Focused transport regression passes (4.60 seconds): scoped pagination, repeated
or out-of-order rows, oversized pages, malformed fields and invalid signatures.
Expanded vault regression passes (6.73 seconds): reversed chains, missing issuers,
duplicates, tampering, foreign roots/scope, pinned metadata and local revocation
precedence. The daemon authenticated-HTTP/read/shutdown regression passes with
certificate fetching (7.80 seconds). Logs:
`.codex/pr16-certificate-refresh-{transport-tests,vault-tests,daemon-tests}.log`.

These are component/simulated-HTTP checks. Authenticated remote revocation and
signed cutoff/epoch propagation, checkpoint staging and full installed cross-device
acceptance remain required. The certificate snapshot is bounded to 4096 devices;
a larger account currently fails safely rather than accepting partial trust.

Core/daemon library and test Clippy with warnings denied and the normal production
daemon library check pass. Graphify update completed. Evidence:
`.codex/pr16-certificate-refresh-{clippy,production,graph}.log`.


### Checkpoint network stages (2026-09-09)

SyncEngine exposes owned checkpoint requests and completion stages. Its existing
synchronous driver uses those same stages for pin lookup, bounded durable history
scans, due checkpoint publication and append/tail confirmation. Completion rejects
changes to scope, provider, budget, durable pin or scan. Ordinary local writes can
continue during HTTP; final acceptance verifies the current local state again.

The daemon runs these requests after operation pull, outside the sole vault
worker. Every response returns through original-session and workspace admission,
with a fresh certificate snapshot and current local identity/key epoch. Missing
creator metadata leaves history retryable. Current trust is also reapplied to a
cached chain anchor before accepting a published extension; the new regression
reproduced acceptance through a removed issuer before that shared-verifier fix.

The expanded daemon regression stalls checkpoint history HTTP, verifies local
reads and shutdown responsiveness, then reopens the vault with the checkpoint
request still pending and no pin accepted. This covers shutdown during history fetching
and responsiveness. It does not prove cancellation of blocking HTTP, complete
hosted checkpoint publication or installed cross-device acceptance. Full hosted success, remote revocation/cutoff/epoch
propagation and the remaining release gates still require qualification.

Bounded review found no remaining actionable P1/P2 after the anchor-trust fix.
Core/daemon library and test Clippy with warnings denied passes. Graphify update
completed with 18236 nodes. Logs: `.codex/pr16-checkpoint-stages-clippy.log` and
`.codex/pr16-checkpoint-stages-graph.log`.

Final validation passes: all 47 engine integration tests (274.37 seconds), the
expanded authenticated-HTTP daemon regression (12.91 seconds), and the normal
production daemon library check. The full daemon suite was not rerun for this
checkpoint slice. Evidence:
`.codex/pr16-checkpoint-stages-final-tests.log`,
`.codex/pr16-checkpoint-daemon-final-tests.log`, and
`.codex/pr16-checkpoint-stages-production.log`.


### Complete daemon checkpoint cycle and reopen (2026-09-09)

A new simulated-HTTP test drives the real Supabase adapter and daemon cycle through
signed operation upload, checkpoint publication, exact history/tail confirmation
and local pin acceptance on the sole vault actor. Reopening checks the canonical
pin bytes, cleared checkpoint request and empty outbox. A second cycle retains the
provider checkpoint and verifies that no duplicate checkpoint is published.
The fixture checks exact account/workspace/version and hash/cursor filters.

Both hosted-sync daemon regressions pass (21.72 seconds), including the existing
stalled push/pull/checkpoint read/shutdown test. Daemon library/test Clippy with
warnings denied passes (52.03 seconds). Logs:
`.codex/pr16-checkpoint-completion-tests.log` and
`.codex/pr16-checkpoint-completion-clippy.log`.

This slice changes only test code and reuses the existing signed enrollment and
verified-session fixtures. It does not prove Auth restoration after process
restart, a live provider, second-device receive/search or installed acceptance.
Bounded review found no actionable P1/P2. The full release gates remain open.

Fourteen superseded queued/running PR workflows were canceled and confirmed
completed/cancelled, preserving the then-current e1fd562 workflows. Their old
commits ranged from dae8a954 to e2dad0e. Current-head CI is not yet qualified.

Graphify update completed (18243 nodes); log:
`.codex/pr16-checkpoint-completion-graph.log`.


### Second-device receive and search through the daemon (2026-09-09)

The composed checkpoint test now includes a real signed memory created in a
separate source vault, using a second device certificate issued by the enrolled
local device. The HTTP fixture withholds that certificate until after returning
the operation page, requiring the daemon's post-response certificate refresh.
It serves the same canonical operation and exact scoped cursor across reopen.

After the receive and checkpoint cycle, reopening verifies the exact memory,
finds it through the daemon MemorySearch path, and checks a checkpoint frontier
containing both devices. A second cycle reuses the durable operation cursor and
pin without republishing. Remote certificate metadata remains absent from local
storage, so the reopened cycle fetches trust again.

Both hosted-sync regressions pass (26.90 seconds); daemon library/test Clippy with
warnings denied passes (13.29 seconds). Bounded review found no actionable P1/P2.
Logs: `.codex/pr16-remote-receive-tests.log` and
`.codex/pr16-remote-receive-clippy.log`. This extends test coverage only.
It proves composed signed receive and lexical search with simulated HTTP, not
actual pairing, Auth restoration, live-provider or installed acceptance.

On bae554d, GitHub's macOS native build, frontend lint/typecheck/tests/build,
Supabase contract, schema/binding/boundary and secret/dependency/license checks
passed at observation. Windows/macOS Rust tests/lint and native Semgrep work were
still running. No full CI or release qualification is claimed.

Graphify update completed (18246 nodes);
`.codex/pr16-remote-receive-graph.log`.

## Native device-revocation statement (2026-09-09)

Added a domain-separated fixed-width signed statement binding revocation operation,
account/workspace, issuer/target, current epochs, cutoff sequence/hash and the digest
of the complete canonical key-rotation transition. It rejects non-incrementable
epochs, sequences outside PostgreSQL bigint, inconsistent empty cutoffs and empty
transition digests. Signing requires both installed public keys to match the issuer
certificate. Older immutable certificates are permitted; future/zero certificate
epochs and mismatched scope/device are rejected.

This primitive deliberately does not establish certificate-chain trust, current
roster authorization or transition correctness. Its caller must independently
recompute the full transition digest and enforce current authority and atomic epoch
changes. Hosted revocation, encrypted rotation manifests, historical-key/cutoff
admission, daemon wiring and installed acceptance remain unfinished. The execution
plan is `docs/superpowers/plans/2026-09-09-device-revocation.md`.

The regression first failed for the missing API, then passed (2.99 seconds). It
includes an independently generated Node Ed25519 vector, byte-by-byte preimage
tampering, certificate scope and installed-key mismatches, epoch/sequence bounds,
empty-cutoff rules and self-revocation statement support. Core library plus focused
test Clippy with warnings denied passed (30.73 seconds). Bounded read-only review
found no actionable security/correctness issue. Local logs:
`.codex/pr16-revocation-red.log`, `.codex/pr16-revocation-test.log`,
`.codex/pr16-revocation-clippy.log`. No full revocation or release acceptance claimed.

## Canonical revocation rotation transition (2026-09-09)

The native revocation module now canonically encodes and verifies the complete
public rotation manifest: previous control-state hash, next control/key epochs,
canonical plaintext key-bundle commitment, sorted remaining-device certificates
and encrypted envelopes, and the recovery root/wrapping key/envelope. Encoding is
length-delimited, limits the roster to 4096 and ciphertexts to 1024 bytes, and
rejects duplicate/unsorted recipients, empty commitments and invalid envelope keys.
The statement signature binds the digest of all these bytes.

Verification takes a separate caller-authenticated current control state. It requires
an active issuer and target, matching account/workspace and current epochs, exact
one-step epoch advancement, the expected previous-state hash and recovery recipient,
and every remaining current certificate exactly once. A signed request cannot omit
another active device, include the revoked target or substitute certificate fields.
Last-device self-revocation preserves a recovery envelope with no device recipients.

The two focused crypto regressions pass (3.12 seconds); core library and focused-test
Clippy with warnings denied passes (21.11 seconds). The new API first failed its
regression as missing, before implementation. Review found no actionable P1/P2.
Logs: `.codex/pr16-rotation-red.log`, `.codex/pr16-rotation-test.log`, and
`.codex/pr16-rotation-clippy.log`.

This is canonical native manifest verification, not completed key rotation. Wire
decoding, secure key generation/envelope construction and recipient decryption with
AAD/plaintext-commitment checks, historical-key persistence, cutoff/head CAS, hosted
atomic mutation, control propagation and installed acceptance remain required.
Opaque ciphertext cannot prove that recipients received equivalent valid keys;
recipients must verify their decrypted canonical bundle against the signed digest.

## Bounded revocation wire decoding (2026-09-09)

Added strict decoders for the signed statement preimage and canonical rotation
transition. Both preserve typed UUIDv7 validation and require exact re-encoding;
nonminimal nested CBOR certificates and trailing data cannot silently change the
bytes covered by the signature. The transition decoder bounds total input to 8 MiB,
recipient count to 4096, certificate slices to 512 bytes and encrypted payloads to
1024 bytes before allocation. It reuses the existing certificate decoder and uses
checked borrowed slices for fixed-width fields and length-prefixed input.

Regression coverage includes every truncated prefix, oversized counts/certificate
and ciphertext lengths, a nonminimal nested CBOR map length, trailing bytes and
single-byte mutations across the complete wire payload. Any accepted mutation must
round-trip byte-exactly and fail the original signed-state verification. The first
statement round-trip caught an incorrect fixed-length guard; the corrected layout
matches the independent 197-byte vector. Both focused regressions pass (13.39 seconds)
and core library/focused-test Clippy with warnings denied passes (14.60 seconds).
Bounded review found no actionable P1/P2. Logs:
`.codex/pr16-rotation-decode-red.log`, `.codex/pr16-rotation-decode-test.log`,
`.codex/pr16-rotation-decode-clippy.log`.

Decoding does not authenticate a sender. Callers must still verify the decoded
statement/transition against independently authenticated current control state.
Secure envelope construction/decryption, durable historical-key/cutoff handling,
hosted atomic revocation and installed acceptance remain unfinished.

## Native rotation key generation and opening (2026-09-09)

The rotation builder now generates independent fresh workspace-root and epoch keys
with OS randomness in zeroizing buffers, encodes them with the existing canonical
zeroizing key-bundle codec and wraps the same bundle separately for every remaining
active device and the recovery root. It computes the plaintext commitment, signs
the completed manifest and verifies it against the supplied current authority.
The statement's final transition digest is replaced by the generated manifest hash.
Exact generated artifacts must be persisted for retries; rebuilding an operation
would generate different key material and is not an idempotent retry mechanism.

Separate device/recovery AAD domains bind the immutable statement context (all
signed fields except the final transition digest), previous control-state hash,
plaintext commitment, recipient ID and either complete certificate digest or
recovery wrapping public key. Excluding the final transition hash avoids a circular
ciphertext dependency. The existing statement golden vector remains unchanged.

Opening verifies the full signed manifest/current authority first, checks installed
keys, authenticates the envelope and verifies the canonical plaintext commitment,
account/workspace and next epochs before returning zeroizing material. The regression
proves identical keys for two remaining devices and recovery, fresh keys between
builds, target exclusion, wrong-key rejection, a resigned cross-rotation envelope
transplant, and validly signed/authenticated envelopes with a wrong commitment or
epoch. Last-device self-revocation leaves recovery access with no device envelope.

Both focused regressions pass (13.68 seconds); core library/focused-test Clippy with
warnings denied passes (15.55 seconds). Initial regression failed for the missing
builder API before implementation. Bounded review found no actionable P1/P2.
Logs: `.codex/pr16-rotation-material-red.log`, `.codex/pr16-rotation-material-test.log`
and `.codex/pr16-rotation-material-clippy.log`.

These functions do not persist intent, activate new keys or mutate hosted state.
Durable exact-artifact retries, historical keys/control-chain storage, signed cutoff
admission/head CAS, hosted atomic mutation, daemon wiring and installed acceptance
remain required before revocation is a complete release workflow.

2026-09-09 revocation intent persistence: schema 37 adds SQLCipher storage for
exact signed revocation statements, canonical rotation envelopes, issuer
certificates and original project/user/session identity. A new intent verifies
caller-supplied current control authority before insertion. Existing operation
IDs accept only identical artifacts, preserving generated keys across restarts;
storage acceptance is not permission to replay HTTP after a session change and
is not hosted acceptance or local key activation. Listing uses bounded canonical
operation IDs; loading bounds byte lengths before allocation and verifies the
stored signature, canonical encodings and manifest digest.

The affected account lifecycle, pairing, enrollment, recovery and search suites
passed 49 active tests, with eight existing model/performance tests ignored
(`.codex/pr16-revocation-intent-migrations.log`). Schema downgrade fixtures now
remove the new table before representing older databases. Independent review
found a SQLite embedded-NUL text-length bypass and unbounded/noncanonical listed
IDs. The added regression failed before correction; final persistence and
schema-36 upgrade tests passed 2/2 in 6.99s, including exact recovered key equality,
changed-payload rejection and corrupt-storage SQL NULL rejection before Rust
allocation (`.codex/pr16-revocation-bounds-{red,test}.log`). Core library/all-test
Clippy with test-support and -D warnings passed in 1m48s. Reviewer reinspection
closed the finding. Graph update completed with 18,305 nodes and 51,684 edges.
Historical epoch/control-chain persistence, hosted atomic mutation, receiving
admission, daemon integration and full live/installed acceptance remain open.

2026-09-09 retained-certificate admission prerequisite: immutable device
certificates can precede the current control epoch when the authenticated current
roster explicitly retains them. The previous operation and checkpoint checks
incorrectly required issuance/current epoch equality. One shared identity check
now enforces scope, device, positive issuance epoch no later than current control,
and exact positive current key epoch. Operation verification receives the
caller-authenticated control epoch internally and still requires exact operation
epoch equality; the public legacy context constructor retains certificate-epoch
behavior. Missing current-roster devices and zero/future certificates remain
rejected before requesting decryption keys. Vault roster discovery remains strict
until authenticated control-chain persistence exists; this does not enable
production rotation or admit historical operations beyond a signed cutoff.

Both new admission/checkpoint regressions failed with InvalidIdentity before the
fix. All 27 tests in sync_operation_v1, sync_admission_v1 and sync_checkpoint_v1
passed (19.44s admission, 12.77s checkpoint, 0.28s operation); focused core Clippy
with test-support and -D warnings passed in 13.15s. Logs are local
`.codex/pr16-retained-{certificate,checkpoint}-red.log`,
`.codex/pr16-retained-certificate-test.log` and
`.codex/pr16-retained-certificate-clippy.log`. Read-only review found no actionable
P1/P2. Historical epoch/control-chain storage, hosted mutation, cutoff admission
and full installed acceptance remain required before merge.

2026-09-09 authenticated revocation history: a verified state-advance operation
now checks each transition against its preceding authenticated roster, then
returns a privately constructed next roster, epochs and signed cutoff evidence.
This preserves a retained child's authority after its issuer is revoked, without
allowing the revoked issuer to authorize a later transition. The control-state
commitment is SHA-256 of `context-relay/revocation-control-state/v1\0`, followed
by the exact 197-byte statement signing preimage and 64-byte signature. The
statement commits to the transition, which commits to the preceding state.
Independent Python UUID/struct/hashlib generation over the existing Ed25519
vector yields `16011f91fb578aa91814bbe5af72d4495d4c2067ded3f9b25a8f3bb25f6f4aea`.

Schema 38 stores exact signed entries and encrypted rotation envelopes, using
an immediate SQLCipher transaction to compare the pinned previous hash/epochs
before appending. Exact retries preserve existing rows; conflicting branches
fail. Bounded one-entry reads check canonical bytes and metadata, but explicitly
do not establish authority. The caller must reauthenticate every link from a
trusted anchor and verify hosted acceptance separately. Existing rotation keys
can be reopened from retained envelopes; this does not yet distribute historical
keys to newly joined devices or activate keys in the production workspace loader.

The new APIs had failing missing-API regressions before implementation. Final
crypto/history and intent suites passed 5/5 (12.19s and 5.15s). Coverage includes
reopen and full two-step chain reauthentication, old/new recovery keys, wrong
pinned-tip rejection, same-epoch competing branches, revoked-issuer reuse,
altered cutoffs, replay/skipped entries and damaged stored signatures. Nine
selected older-schema migrations passed. Read-only review found no actionable
P1/P2. Local evidence: `.codex/pr16-control-history-red.log`,
`.codex/pr16-control-store-{red,final}.log`, and
`.codex/pr16-control-history-migrations.log`.

Superseded CI run 34331420501 at 9cab71f reported a Windows daemon failure:
the composed sync/checkpoint test exceeded its ten-second functional completion
limit (103 passed, one failed, four ignored). The failure was retained in
`.codex/pr16-ci-9cab-windows-failed.log`. The test-only completion budget is now
60 seconds for full-suite SQLCipher contention; separate one-second read and
shutdown assertions remain. The full local daemon library suite passed all
104 active tests with four existing ignored tests in 212.08s, including the
previously failing test and HTTP-stall responsiveness
(`.codex/pr16-control-history-daemon.log`). Current-head hosted CI must still pass.

Superseded runs 34334576281, 34334576362, 34331420501 and 34330392647 were
confirmed terminal/cancelled; the observed failure above is not erased by that
workflow conclusion. Final graph update completed: 18,319 nodes, 51,747 edges.
Production trusted-anchor reconstruction, cutoff-aware historical admission,
atomic key activation, hosted/daemon propagation and full release acceptance
remain required; no merge or live release qualification is claimed.
Core and daemon library/all-test Clippy with test-support and -D warnings passed
in 1m20s (`.codex/pr16-control-history-clippy.log`).

2026-09-09 initial revocation trust anchor: `initial_revocation_control_state`
requires an independently pinned enrollment-record hash and expected account/
workspace. The existing canonical enrollment encoder verifies record and genesis
signatures. The helper requires the exact genesis certificate, a nonempty roster
of at most 4096 devices, matching map IDs/scope, epoch-one certificates and valid
public keys. Every supplied chain must terminate at the pinned recovery root;
orphan/cyclic chains fail when no progress is possible. The bounded traversal
matches existing vault roster discovery and never invents a root from a server
response. Completeness, freshness and provenance of the pin remain caller duties.

The initial state hash is SHA-256 of `context-relay/revocation-anchor/v1\0`,
32-byte canonical enrollment-record hash, four-byte big-endian device count, then
sorted pairs of raw 16-byte device ID and 32-byte canonical certificate digest.
It binds membership and the complete signed recovery record, including the
recovery-wrapping recipient. This is only an initial-epoch commitment; later
state must advance through verified history rather than reconstruct a fresh
initial roster after revocation.

The focused enrollment test failed with the missing API before implementation,
then passed in 0.82s. It builds a first rotation from real enrollment/child
certificates and rejects changed pins/records/scope/signatures/keys/epochs,
self-cycles and missing genesis. Existing revocation crypto/history and intent
regressions passed 5/5 (12.35s and 5.69s). Focused core library/test Clippy with
test-support and -D warnings passed in 13.53s. Read-only review found no
P1/P2. Evidence: `.codex/pr16-revocation-anchor-{red,test,regressions,clippy}.log`.

Source tracing identified a remaining pairing prerequisite: its current key
bundle and approval do not provide an authenticated enrollment-record pin.
Obtain that pin through signed pairing before allowing a newly paired device to
bootstrap control history; do not trust a digest accompanying the same untrusted
record. Production history loading, cutoff admission, key activation/distribution,
hosted lifecycle and the full release acceptance gates remain unfinished.


### Enrollment pin propagation through confirmed pairing (2026-09-09)

The encrypted pairing bundle now has an explicit v2 encoding carrying the nonzero
canonical enrollment-record SHA-256. Active enrollment and recovery vault loaders
attach their verified stored record hash. The complete approved ciphertext is bound
to the safety number, and the joined vault preserves the confirmed pin after reopen.
Legacy v1 bundles remain readable with no pin; they cannot bootstrap control history.
Older applications cannot decode v2, and downgrade negotiation is not implemented.
The pairing design records that both peers need v2 support for new enrolled approvals.

The existing real enrollment-to-pairing/reopen test initially failed with the missing
pin API, then passed in 7.93s. The codec test covers both versions, maximum epochs,
all truncated prefixes, wrong maps/versions/field lengths, zero pins, trailing data
and noncanonical encoding. Its initial size expectation was corrected from 123 to
121 bytes for v1 (156 for v2); the final test passes. A ciphertext-pin mutation
cannot reuse the original safety number or pass authenticated decryption. Legacy
joined material remains unpinned; restored material exposes its verified record pin.
All 58 tests across seven affected pairing, recovery and revocation integration
suites pass. Core library and all-test Clippy with test-support and
`-D warnings` passes in 1m03s (`.codex/pr16-pairing-pin-clippy.log`). The longest corruption suite completed in 158.92s. Evidence:
`.codex/pr16-pairing-pin-{red,test,codec,regressions}.log`.

Read-only review found no P1/P2. Graph update completed with 18,328 nodes and 51,793
edges. Graph extraction still lacks SQL/OCaml parsers and reports a local scratch
C++ syntax warning; it is navigation assistance, not verification of those files.
Production initial-roster provenance/history loading, historical cutoff admission
and key distribution, atomic activation, hosted mutation and daemon propagation
remain unfinished, along with all broader release acceptance gates. No merge or
full release qualification is claimed.


### Reauthenticate stored control history against a pinned tip (2026-09-09)

`Vault::verify_device_revocation_history` now reads a contiguous sequence from a
caller-authenticated anchor through an independently trusted final epoch/hash.
One database transaction keeps all reads in the same snapshot. Each bounded entry
passes the existing full transition verifier against the preceding verified state;
only the final verified state is returned, after its hash matches the supplied pin.
A valid prefix cannot satisfy a later tip. A missing entry is an error, not the end
of history. Reading one manifest at a time avoids buffering the entire history.

The existing two-rotation/reopen regression initially failed with the missing API.
It now verifies the full history and an explicitly pinned prefix, rejects wrong
anchors, final hashes and epochs, and checks missing intermediate entries. It also
replaces an old signature with zeros and recomputes its stored hash: the canonical
single-entry read succeeds, while the new chain verifier rejects the signature.
All five revocation crypto/history/intent tests pass (12.40s and 5.25s); focused
core library/test Clippy with test-support and `-D warnings` passes in 9.55s.
Read-only review found no P1/P2. Logs: `.codex/pr16-history-loader-{red,tests,clippy}.log`.

The caller still must establish initial-roster provenance and persist the accepted
tip independently; deriving the pin from the same history defeats rollback checks.
This API does not prove hosted acceptance, cutoff ancestry or decryptability, and
has not yet been wired into sync authority/key activation. Those integrations and
the full release checklist remain required before merge.


### Retry transient source-archive HTTP failures (2026-09-09)

Older CI run 34337253370 (c9aaf05), macOS Semgrep producer job 102419480412,
failed while fetching the pinned domain-name 0.5.0 archive: GitHub returned HTTP
500 for SHA-256 `9ec7ae2c22772c150b84cfa3f21d9bf25fae14a796f31e20df52d86f46499d89`.
The job log was retrieved through the jobs API while the overall run was active:
`.codex/pr16-ci-c9aaf05-macos-semgrep-failed.log`. Cancellation does not erase this
failure or count as a successful gate.

The shared source-archive downloader previously attempted each URL once. It now
makes at most three attempts for transient HTTP 408/429/500/502/503/504 responses,
with 250/500ms backoff, sharing the existing deadline across retries and redirects.
Non-200 response streams are released before retry, redirect or failure. URL,
redirect, checksum, size-budget and atomic-cache publication checks are retained.
The regression initially reproduced HTTP 500, then passed with recovery on the
second attempt, bounded exhaustion, immediate 404 failure and checksum-drift rejection.
All 27 source-bundle tests and 39 inventory/resealing/native-workflow tests pass.
Read-only review found no P1/P2. A live fetch of the exact failing archive returned
9,413 bytes and passed both locked SHA-256 and SHA-512 checks; this does not prove
that the macOS native build passes. Logs: `.codex/pr16-archive-retry-{red,tests,regressions,live}.log`.

Four superseded workflows were verified terminal/canceled after preserving the
failure: 34339932913, 34338206278, 34337253370 and 34339932921. Current-head CI,
full native producer qualification and all remaining product-release gates remain
required before merge.


### Correct the archive generator material pin (2026-09-09)

CI 34340949348 at 2e867b5 failed the licenses gate (job 102431337138). The
archive retry change updated `scripts/semgrep-source-bundle.mjs` without updating
its byte pin in the sidecar manifest. The full `node scripts/check-license-metadata.mjs`
command reproduced the SHA-256 mismatch locally. The manifest now pins the actual
generator SHA-256 `367f3abd61c7ff848032aa89e21d8bc66c55701332ebea5eb38d69dd36480888`.

Historical bundle evidence still records its original generator hash and bundle
bytes. Its test no longer requires a later generator revision to equal the historical
hash; the adjacent committed-manifest test verifies current material bytes. Existing
tamper checks and the enabled-target requirement that bundle evidence match the
pinned generator remain intact. The full license/material command and all 28
license/hydration tests pass. Read-only review found no P1/P2. Evidence:
`.codex/pr16-license-retry-failure.log`, `.codex/pr16-license-pin-{check,tests}.log`.
New CI must verify this correction. Native Semgrep remains disabled pending its
required build evidence; the broader release checklist is unchanged.


### Pin and stage macOS arm64 search inputs (2026-09-09)

The shared search-resource stager now selects the Windows x64 or macOS arm64
runtime manifest from an explicit target. Windows packaging uses the same verified
staging path. Unsupported targets fail before reading/writing resources; the full
model/runtime set is verified before any staged file is changed.

Microsoft's exact ONNX Runtime 1.24.2 macOS archive matched the release API's
31,604,221-byte size and SHA-256. Its selected regular dylib/license/notice members
are pinned in `crates/core/models/onnxruntime-osx-arm64-1.24.2/manifest.json`;
the adjacent README records provenance, member paths and static Mach-O inspection.
No native Mac library was loaded or executed on this Windows host.

The test initially failed with the missing target-aware staging export. With real
pinned model, Windows runtime and Mac runtime files, all 18 packaging/resource/icon
tests pass without skips. They verify exact runtime bytes, reject same-size dylib
tampering without replacing prior output, reject Windows inputs for the Mac target,
and retain Windows C++ dependency and companion tests. The full license/material
gate passes. Logs: `.codex/pr16-macos-search-stage-{red,tests}.log` and
`.codex/pr16-macos-search-license.log`. Native loader, Mac application packaging,
signing and clean-machine acceptance remain unfinished; input hashes are not proof
of a signed output. Full release scope remains required before merge.


The latest b1975c5 licenses failure (CI 34341326601, job 102432541817) exposed a
line-ending mistake in the previous pin correction: the local generator had CRLF,
while `.gitattributes` stores/checks it out with LF. The previous hash matched only
the Windows working copy. The manifest now pins the exact Git blob SHA-256
`d51cb59c41ddb0c1e090c1c9a5d465681ec898ea04b5f6fb5ba197338e0188ca`; the local file
was restored to those same LF bytes. No generator logic or historical evidence was
changed. The full license/material check and all 46 combined packaging/resource/
license/hydration tests pass, with real Mac and Windows assets and no skips.
Logs: `.codex/pr16-license-pin-lf-{ci,check}.log` and
`.codex/pr16-macos-search-stage-final.log`. Read-only review of staging found no
P1/P2. Native macOS loading and current-head CI remain unverified.


### Refresh pending source-bundle evidence from actual assemblies (2026-09-09)

The archive retry change also changes the generator bundled under `support/`.
The license pin correction alone therefore left native builders rejecting the
historical evidence. The restored committed-evidence generator check reproduced
this mismatch before the evidence update.

Three actual CI assemblies returned the same verified deterministic tar result:

- [Windows, 2e867b5](https://github.com/Skytuhua/Context-Relay/actions/runs/34340949348/job/102431371187).
- [macOS, 2e867b5](https://github.com/Skytuhua/Context-Relay/actions/runs/34340949348/job/102431371275).
- [Windows, b1975c5](https://github.com/Skytuhua/Context-Relay/actions/runs/34341326601/job/102432686898).

Each completed `--build`, which verifies the deterministic tar before reporting
its result, then failed the subsequent stale generator-evidence check. The
reported SHA-256 is
`67d52f6a45cad45f2dbf1fbea46787867348f885df4387c08a1ee5fb1532526f`,
size 1,149,643,776 bytes, 39,542 payload entries and 222 recorded links.
All default support inputs and the source lock are unchanged from 2e867b5 to
b5440d3. Their Git blobs use canonical LF. The generator digest is
`d51cb59c41ddb0c1e090c1c9a5d465681ec898ea04b5f6fb5ba197338e0188ca`.

The pending bundle record now names these observed bytes; its manifest pin is
updated with it. Historical generator `092fe285...72007` and bundle
`a7367b50...ac626` remain recorded in the preceding Git revisions. Qualification
stays at `source_bundle_v1_native_builds_pending`, one build and no two-build
qualification claim. These assembly results do not prove native executable
builds, runtime closure, sandbox acceptance or published corresponding source.
The source URL remains predeclared; the named GitHub release does not exist yet.

All 80 hydration, license-metadata, source-bundle and native-workflow tests pass
with no skips; the full license metadata gate passes. The actual generator-byte
comparison is restored in the early hydration test to catch future evidence
drift. Current-head remote native verification remains required. Full release
acceptance and PR16 merge remain incomplete.
