# Context Relay — detailed cross-device handoff

Captured: **2026-08-31**. Repository: [Skytuhua/Context-Relay](https://github.com/Skytuhua/Context-Relay).
Status: **pre-release recovery/audit in progress; not beta-ready; all work PRs remain draft**.

## 1. Executive state and the user's latest request

The user originally asked for a complete review and repair against the v1 master
plan, followed by hosted completion and Tasks 18–24. They approved an extensive
recovery/audit/completion plan. Their latest instruction was to put local-only
work on GitHub in PRs and prepare a detailed handoff for another device.

This checkpoint fulfills the preservation part of that instruction. It does not
claim the recovery implementation plan is finished. No PR was merged, no hosted
migration or production configuration was applied, and no signed installer,
updater, release, or beta was published during preservation. Local originals
were not deleted. GitHub now supplies the source and continuation references;
credentials and disposable build caches are intentionally not uploaded.

The most important facts for the next device:

1. **PR #12 is the existing stabilization candidate.** Its latest Windows repairs
   are pushed, but two Windows MCP tests still fail. Native qualification checks
   were still running at capture time.
2. **PR #13 contains previously local-only Task 17 account-lifecycle WIP.** It is
   stacked on PR #12, not on `main`. Its database suite is known red, now
   reproduced in GitHub CI. Production lifecycle requests still fail closed.
3. **The handoff branch sits on PR #13.** Check out this top branch to obtain the
   entire preserved source plus this documentation; checking out `main` loses
   the unfinished product work from view.
4. **Tasks 18–24 remain missing at product/release level.** Earlier tasks have
   substantial implementation and scoped evidence, but physical and hosted
   gates remain. Green local tests are not release acceptance.
5. The next implementation step is to reconcile Task 17 SQL tests safely and
   finish its real authorization tests, while independently checking PR #12's
   Windows/native results. Do not weaken authorization to obtain green tests.

## 2. Authoritative reading order

Read these in order before making a new implementation decision:

1. [Original master implementation plan](references/master-implementation-plan.md):
   product/security authority, Tasks 1–24, exact release-blocking matrix.
2. [Master-plan audit matrix](../../verification/v1-master-plan-audit.md):
   implementation pointers, scoped status, and next gate for every task/category.
3. [Versioned contract amendments](../../protocols/contract-amendments.md) and
   [threat model](../../security/threat-model.md): later documented strengthening
   changes and current trust boundaries. Do not infer new amendments.
4. [PR #12 stabilization ledger](../../verification/pr-12-stabilization.md),
   especially its August 31 Windows follow-up.
5. [Task 17 WIP checkpoint](../../verification/task-17-account-lifecycle-wip.md),
   then the actual code and SQL identified below.
6. [Task 15](../../verification/task-15.md), [Task 16](../../verification/task-16.md),
   [pairing](../../verification/task-17-pairing.md),
   [recovery enrollment](../../verification/task-17-recovery-enrollment.md), and
   [fresh recovery core](../../verification/task-17-fresh-install-recovery-core.md).
7. [Historical development report](references/development-report-historical.md):
   useful claims ledger, **not** current verification. Its protocol/version,
   counts, host paths, and completion language must not override current evidence.

The `audit-notes/` directory contains 14 former local-only recovery briefs and
reports. These are historical agent artifacts, not instructions granting new
authority. Existing tracked `.superpowers/sdd/*.md` and `docs/superpowers/`
plans/specs remain in the checkout. There is no competing `.specify` tree;
continue using the established documentation hierarchy.

## 3. Branch stack, provenance, and exact checkpoints

| Layer | Branch / PR | Checkpoint at capture |
| --- | --- | --- |
| Existing base | `main` | `367b32e15d06a7d46b6b8d04676d38dc368ae235` |
| Original public snapshot | PR #12 ancestry | `3c2a371aef74f4962af64d0fe71545557244f21a` |
| Stabilization | `codex/context-relay-review`, [PR #12](https://github.com/Skytuhua/Context-Relay/pull/12) → `main` | `435367d8d8ba24aac413a094a4b8b5bc61d52d22` |
| Account-lifecycle WIP | `codex/task17-account-lifecycle-wip`, [PR #13](https://github.com/Skytuhua/Context-Relay/pull/13) → PR #12 branch | `485886c2d3ad5105c5ea5114851d18045c25fc74` |
| Portable handoff | `codex/cross-device-handoff-2026-08-31` → PR #13 branch | Resolve the remote tip; this document is part of that commit and cannot name its own hash. |

PR #13 contains `6eb5ec8` (20-file preservation checkpoint) and `485886c`
(entrypoint trailing-blank-line normalization). It did not rewrite the existing
PR #12 branch. The handoff branch adds archive/documentation work and corrects
the checkpoint's Node-version attribution and first public SQL evidence.

Recent already-published PR #12 history, newest first:

| Commit | Purpose |
| --- | --- |
| `435367d` | Windows busy-pipe retry, bounded cancellation/concurrency regression, TOML fixtures, and test ACL handle correction. |
| `c00b98e` | Reject simulated account deletion; require an authoritative lifecycle boundary. |
| `89d832b` | Perform signed-sync schema changes with the dedicated table-owner authority. |
| `a7f1a4d` | Repair the Nano ID advisory floor. |
| `5c040dd` | Concrete Supabase signed-sync transport/admission implementation. |
| `066b0b4` | Reconcile historical sync migrations. |
| `014de5f` | Task 14 native memory boundary repairs. |
| `ab09ddb` | Windows lint/Node 24 workflow repairs. |
| `538c5e7` | Adapter/MCP audit repairs. |
| `39e2d9d` | Task 15 verification-ledger update. |

The initial historical report records 168 local development commits and one
missing local tree object, which prevented pushing that original history
intact. The public snapshot preserves the reported exact development tree
`b1f20f83f6a6f89f7f433b01dc29127b4c823216`. Additive recovery commits follow it.
Do not assume that the old development-only SHA in the report is fetchable.
Do not rewrite or force-push the public snapshot history to recreate it.

An older branch named `codex/pr12-v1-recovery` also exists; it is not the current
continuation branch. Its meaningful work is in PR #12 ancestry. Dependabot PRs
#1–11 are separate existing work; do not merge/close them as preservation cleanup.

### Obtain the full continuation checkout

On the other device, authenticate to GitHub independently, then use a fresh
directory (do not overwrite an existing dirty checkout):

```sh
gh repo clone Skytuhua/Context-Relay
cd Context-Relay
git fetch origin
git switch --track origin/codex/cross-device-handoff-2026-08-31
git status --short --branch
git log -6 --oneline
```

No credential file from the originating Mac is required or appropriate. For an
existing clone, inspect its changes first, fetch, and switch to the same branch
only when safe. Read this document from the newly fetched tip, not from an old
ChatGPT attachment. The [continuation prompt](CONTINUE.md) is self-contained.

### Preserve PR separation

Keep all three PRs draft until their applicable review/gates are satisfied.
PR #12 must not absorb unfinished Task 17 changes accidentally. The eventual
approved order is stabilization first, then focused hosted work; this handoff
does not authorize merging. The user's earlier target was a squash merge of
PR #12 **only after** all required checks and review are green.

A squash merge changes ancestry. Before later retargeting stacked PRs to `main`,
inspect their exact diff/range; simply changing the base can reintroduce already
squashed changes. Preserve the original branches and use an additive reviewed
branch/PR if necessary rather than force-pushing away provenance.

## 4. Public CI snapshot and why the project is not green yet

Snapshot: **2026-08-31T11:20:55Z**, with the completed Windows job log read directly
after that snapshot. These are observations of the listed exact
heads, not promises about later results. Refresh them immediately on resumption.

### PR #12, head `435367d`

[CI run 33384463445](https://github.com/Skytuhua/Context-Relay/actions/runs/33384463445):

- Passed: formatting (`rust`), ordinary Rust tests on macOS arm64,
  Rust lint on macOS arm64 and Windows x64,
  both native desktop builds, daemon-boundary, bindings, schemas, licenses,
  Rust and Node dependency policy, whitespace, all four frontend gates, and
  Semgrep material selection.
- Failed: ordinary Windows Rust tests, in `context-mcp/end_to_end_v1` (8 passed,
  2 failed). See the exact failures below.
- Still running: both native Semgrep candidate builders. Downstream
  native-isolation evidence was not yet present.
- Separate Secret Scan and Supabase contract runs were green at this head.
- Relevant jobs: Windows tests `99463842162`; macOS tests `99463841925`;
  Windows Semgrep builder `99463868789`; macOS builder `99463868833`.

The completed Windows job log shows the repaired 64-call/cancellation case now
passes. Two other MCP tests still fail at `crates/context-mcp/tests/end_to_end_v1.rs`:

| Test | Exact failure at `435367d` |
| --- | --- |
| `managed_requirements_block_production_bridge_preview_without_native_authority` | Line 802: actual `InvalidRequest`, expected `HarnessUnsupported`. |
| `production_setup_watcher_review_and_actual_mcp_form_one_chain` | Line 685: unwrap of `InvalidRequest`, message `Codex configuration has unsafe topology or state`. |

The test process finished in 22.36 seconds rather than hanging for six hours.
This is progress, not a clean Windows pass. Root cause of these two remaining
failures has **not** been diagnosed in the preservation turn. Start with the
fixture/native Codex topology path and the rejection mapping; do not weaken
production topology validation or merely change the expected error to pass.
The 20 dispatcher tests before this suite passed; later workspace binaries did
not run after Cargo stopped at this failure.

### UPDATE 2026-08-31 (second pass): both failures diagnosed and repaired at `a3c5982`

PR #12 head advanced additively to
[`a3c5982`](https://github.com/Skytuhua/Context-Relay/commit/a3c5982a6f29461fc4e6b5f03dfdc5d2005bdb50)
(“fix: accept canonical verbatim Windows paths”). Both failures were reproduced
on a real Windows x64 host and have one root-cause class: two independent
Windows path policies rejected the `\\?\` verbatim prefix that
`std::fs::canonicalize` produces on Windows, so every canonicalized Codex
layout path failed:

1. `native-runner` `validated_components` (`HeldPath::new`) →
   `OsNativeFileSystem::snapshot` returned `InvalidPath`; `codex.rs`
   `read_optional_file` surfaced `InvalidRequest "Codex configuration has
   unsafe topology or state"` (line 685) and masked the blocked-capability
   `HarnessUnsupported` mapping (line 802).
2. `core` `native_transaction::approval::windows_target_key` → after repair 1,
   the chain moved to `approval_hash_v2`, which rejected verbatim mutation
   targets (`InvalidRequest "Bridge preview plan is invalid"`).

Both boundaries now accept exactly the `\\?\` prefix; device (`\\.\`) and UNC
forms, traversal, reserved names, reparse checks, and deduplication remain
fail-closed (verbatim/plain forms of one path still collide as duplicates).
The verbatim form skips Win32 normalization, so acceptance is strictly safer.

Local Windows runtime evidence: failing regression tests were added first for
each boundary; `context-mcp end_to_end_v1` passes **10/10** on Windows;
`native_approval_v1` 22, `native_approval_v2` 18, `native-runner` pre-rename
25 (with the machine-specific `icacls` test skipped — see ledger); scoped
clippy `-D warnings` and `cargo fmt --check` clean. Full details, exact
commands, and host limitations are recorded in the
[stabilization ledger](../../verification/pr-12-stabilization.md). Clean-
checkout CI on `a3c5982` (runs 33424905936/33424905907/33424905774) remains
the mandatory gate; do not treat this local evidence as green.

### UPDATE 2026-08-31 (third pass): newly exposed WTF-16 failure repaired at `a69f47c`

Hosted CI on `a3c5982` confirmed the repair: `end_to_end_v1` passed 10/10 on
Windows and Secret Scan plus Supabase contract runs were green. The verifier
then advanced exactly as the handoff predicted — with `context-mcp` no longer
stopping the run, later workspace binaries executed for the first time, and
one latent failure surfaced in the `contextd` lib suite:

`native_memory::tests::windows_wtf16_source_reaches_the_native_snapshot_boundary`
failed with `UnsupportedTopology`. This test has no passing Windows CI history
(it never ran at `435367d`; the failure reproduces on that baseline). Root
cause: `native-runner` `validate_name` rejected every non-scalar WTF-16 name
(isolated surrogates are legal NTFS filenames) via `String::from_utf16`.

PR #12 head advanced additively to `a69f47c` (“fix: accept WTF-16 non-scalar
component names in native path policy”). `validate_name` now applies the NFC
check only when the units are valid Unicode; a non-scalar name has no
alternative normalization form and cannot equal a pure-ASCII reserved stem or
internal recovery pattern. All unit-level gates are unchanged: control
characters, forbidden punctuation, embedded NUL, over-length names, trailing
dot/space, and traversal still reject. Local Windows runtime evidence: the
contextd lib suite passes **57/57** on this host (it failed 56+1 on CI at
`a3c5982`), and a focused regression pins both acceptance and the unchanged
ASCII gates. Ledger updated in the same commits. Subsequent clean-checkout CI
on `a69f47c` is the mandatory gate; further never-reached Windows suites may
still surface similar latent failures — same diagnose/fix/verify pattern
applies.

Prior run [33357305605](https://github.com/Skytuhua/Context-Relay/actions/runs/33357305605)
at `89d832b` had a six-hour Windows ordinary-test timeout and failed Windows
native-isolation. Those are the reasons for `435367d`; prior green native builds
do not verify the repaired runtime tests. CodeRabbit's draft-skip success is not
a substantive code-review approval.

### UPDATE 2026-09-02 (fourth pass): fixture isolation and SD canonicalization at `a9f8f0e` + `d09d113`

Hosted CI on `a9f8f0e`'s predecessor exposed the next class: all contextd and
native-runner suites now execute on Windows, and their first executions
surfaced four fixture-only defects plus one production defect. All are
repaired with additive commits; no security check was weakened.

**Fixture-only repairs (`a9f8f0e`, test code):**

1. Runtime suffixes derived from the leading characters of a UUIDv7 encode
   the millisecond timestamp, so parallel tests minted identical suffixes.
   Windows IPC singletons are named by per-user SID plus suffix alone (global
   mutex and named pipe), unlike macOS where the lock lives under each
   runtime root, so identical suffixes lost the `InstanceGuard` race
   (`AlreadyRunning`). Suffixes now use the random tail.
2. `native_hook_v1` gave every test the same literal suffix — only the first
   starters could ever bind. Each test now gets its own.
3. `native_memory_watch_v1` built roots under `/private/tmp`, which is not
   absolute on Windows (no drive prefix), so source paths failed
   `decode_path` absolute validation and previews never completed.
4. The same suite and `harness_setup_v1` hardcoded `NativePlatform::Macos`
   with cfg-branch bytes; the Windows branch's UTF-16LE encoding contains
   NUL high bytes that the macOS NUL check rejects (`InvalidSource("path")`).
   The platform is now cfg-branched to match the encoding.

**Production repair (`d09d113`, one file + regression):**

`native-isolation-windows-x64` failed on a single real test
(`private_creation_replaces_permissive_inherited_acl_with_owner_only_dacl`),
with 7 cascading `PoisonError`s from the shared serial mutex. The failure is
deterministic on every Windows environment: `compare_and_swap`'s staged
verify compares fingerprints, but the desired security descriptor is
serialized by `MakeSelfRelativeSD` while the staged read-back is serialized
by `GetSecurityInfo` — two producers lay out self-relative sections
differently, so semantically identical descriptors hashed differently and
the fail-closed recheck rejected every private creation.

`stable_security_descriptor` (Windows) now re-serializes canonically before
hashing (fixed section order, revision, control minus the auto-inherited
class, raw SID and ACE bytes in stored order). Access decisions, restorable
validation, and the `SetSecurityInfo` write path still use raw bytes; only
the fingerprint input is normalized. A regression test hashes two
byte-different but semantically identical descriptors and asserts equality.

**Windows x64 evidence:** all 7 contextd binaries pass (exit 0) including
`harness_setup_v1` 10/10 across three runs and `native_hook_v1` 6/6 twice;
`native-runner` lib passes **40/40 with zero skips** — the ACL test that
failed on every Windows host now passes, and the local `--skip` caveat is
obsolete. `cargo fmt --check` clean. Clean-checkout CI on `d09d113` is the
mandatory gate; the ledger will be updated with hosted results once the run
completes.

### PR #13, head `485886c`

[CI run 33385426512](https://github.com/Skytuhua/Context-Relay/actions/runs/33385426512)
had fast policy/frontend/generated-artifact checks, both native builds, both
Rust lint jobs and Secret Scan green, with ordinary Rust tests still running.
Its Semgrep/native-isolation jobs were
**skipped by changed-material conditions**, not passed. Those skips cannot
satisfy a release gate. Obtain an applicable exact-candidate qualification run
before claiming release verification; never equate a skipped job with green.

[Supabase run 33385426361](https://github.com/Skytuhua/Context-Relay/actions/runs/33385426361)
failed exactly where the pending integration predicted:

- Fresh CI-container reset applied the new migration successfully.
- pgTAP assertion **122** failed: the old test still expected legacy public
  lifecycle wrappers to be executable by `service_role`.
- SQL line **2703** aborted with permission denied for
  `service_begin_account_deletion`.
- **469 of 518** planned assertions ran: one failed assertion, 49 not run.
  The summary's “50/518” is not evidence of 50 independent bugs.
- Database lint was not reached. This is a disposable GitHub-runner database,
  **not** an applied hosted Supabase project or live OAuth test.

Read-only refresh commands:

```sh
gh pr checks 12 --repo Skytuhua/Context-Relay
gh pr checks 13 --repo Skytuhua/Context-Relay
gh run view 33384463445 --repo Skytuhua/Context-Relay
gh run view 33385426361 --repo Skytuhua/Context-Relay --log-failed
```

If `gh run view --log-failed` refuses logs while another job in the same run is
still active, a completed job's log can be read through
`gh api repos/Skytuhua/Context-Relay/actions/jobs/99463842162/logs`.

Record head SHA, run URL, job, timestamp, actual exit/result, and execution
plane in the evidence ledger. Do not keep reporting a capture-time run as live.

## 5. Windows repairs already made — do not rediscover or undo

`435367d` addressed three independent problems:

1. **Named-pipe concurrency.** A busy Windows pipe was mapped directly to an I/O
   failure. Connection establishment now retries only `ERROR_PIPE_BUSY`, at
   50 ms intervals with a five-second bound. It does not retry authenticated
   application requests or hide other errors. Portable retry tests and an actual
   Windows second-connection regression were added.
2. **64-call/cancellation test hang.** An unbounded wait could consume the whole
   CI timeout, and panic paths could strand a blocking worker. The test now
   bounds waits/completion and releases the worker through an RAII guard.
   This is not permission to skip concurrency/cancellation behavior.
3. **Windows fixtures.** Four Codex fixture helpers incorrectly placed native
   Windows path strings directly into TOML quoted keys. The complete key is now
   serialized/escaped; plain native-path text stays unchanged. Drive, UNC,
   extended, Unicode, quote, tab, and carriage-return cases have regressions.
   Separately, the native security test called `GetSecurityInfo` using a
   traversal-only parent handle without `READ_CONTROL`. A test-only ACL handle
   fixes this. The first failing call was `security_descriptor(held.parent())`,
   not `metadata_for_new_private_file`; seven poisoned-mutex failures cascaded
   from that first panic. Production ACLs were not loosened.

The stabilization ledger records **166 targeted local cases** passing: IPC
46 unit + 28 integration, Codex adapter 66, primary-memory setup 9, MCP end-to-end
10, daemon authoritative memory 4, native ACL source contracts 3. Windows-target
compile/lint and scoped macOS strict lint passed. An independent scoped review
reported no actionable issue for candidate CI, not approval to merge.

Important limits: those local runs had the pending Task 17 edits present; only
clean remote execution proves the committed PR #12 snapshot. Windows cross-
compilation does not exercise Win32. Some daemon tests needed real local-socket
access outside the restricted sandbox. The simulated Hermes commit panic is
intentional fault injection if the enclosing test passes. Do not count a
restricted-sandbox transport denial as a product regression without reproduction.

## 6. Architecture and trust-boundary map

| Area | Source location / responsibility |
| --- | --- |
| Protocol | `crates/protocol`: canonical domain/IPC/CBOR/sync/pairing contracts, bounds, Rust exports, vectors, schemas. |
| Core | `crates/core`: crypto, SQLCipher vault, search, adapters, native transactions, memory authority, sync engine and device coordinators. |
| Daemon | `crates/contextd`: single-writer vault queue, authenticated local API routing, ordered operations, startup recovery, trusted transport ownership. |
| IPC | `crates/local-ipc`: per-user endpoint security, peer proof/roles, version handshake, framing/limits, sockets and Windows named pipes. |
| MCP | `crates/context-mcp`: scoped product-memory/task/handoff interface, output contracts, daemon client and concurrency. |
| Native runner | `crates/native-runner`: constrained launcher/helper authority, sidecar verification, filesystem topology, native isolation. |
| Desktop | `apps/desktop/src`: React UI; `apps/desktop/src-tauri`: native host and narrow capabilities. Renderer is not key/session/filesystem authority. |
| Provider | `supabase/migrations`, `supabase/functions`, `supabase/tests`: ciphertext-only database/storage/realtime boundary and server-derived auth. |
| Evidence/policy | `scripts`, `.github/workflows`, `docs/verification`, `docs/security`, `docs/protocols`, schemas and lockfiles. |

Preserve these invariants across future work:

- Context data and keys remain daemon-owned. Never let React, ordinary local IPC,
  logs, crash diagnostics, or a generic Tauri capability transport recovery words.
- Signature/certificate/epoch verification precedes decryption and admission;
  untrusted provider success is not trust. Replay and substitution must fail closed.
- Native setup remains exact-plan/exact-file, approval-bound, re-attested,
  transactional, crash-recoverable, and rollback-safe across both platforms.
- Hosted identity is verified JWT/session-derived; caller account/device ownership
  and editable metadata never establish authority. Private Realtime carries only
  opaque hints. Storage and database rows remain ciphertext/opaque metadata.
- New protocol/schema changes require one amendment plus atomic regeneration of
  bindings, schemas, canonical vectors, hashes, and compatibility tests.
- Candidate-only native sidecar verification must stay confined to exact
  qualification smokes; it is not an ordinary production feature.

Current documented amendments: A-001 recovery-enrollment protocol 1.3 history;
A-002 operation schema **1** versus scope-bound checkpoint schema **2**;
A-003 50-bit pairing locator plus independent full **80-bit** safety confirmation;
A-004 ordinary-feature CI vs candidate-only confinement; A-005 current exact
local IPC protocol **1.4**, explicit Hermes profile binding. Old 1.3 peers must
fail negotiation, not be silently upgraded. Read the full amendment ledger.

## 7. Task 17 WIP — exact implementation and missing contracts

See [the checkpoint](../../verification/task-17-account-lifecycle-wip.md) for
the file list and test results. The new code is source preservation, not a
validated production lifecycle service.

### Core and daemon

- `crates/core/src/devices/account_lifecycle.rs` defines
  `AccountLifecycleTransport`, status/begin/cancel, sanitized failures, and
  strict deletion projections. Pending deletion is exactly seven days; active
  and purged states have no pending timestamps. Time values must fit signed
  64-bit milliseconds. Export remains available during the grace period.
- `supabase_account_lifecycle.rs` implements the existing abstraction behind
  the daemon boundary. Requests go to `/functions/v1/account-lifecycle` over
  HTTPS only, with redirects disabled, 15-second timeout, at most three
  attempts, bounded backoff, and strict 16 KiB logical response parsing.
- Every mutation call generates an opaque 32-byte lowercase-hex request ID and
  retains it across that call's retries. This is **not yet durable caller-level
  idempotency across a process crash**; define the next layer before claiming it.
- The shared sync HTTP implementation is now crate-private reusable plumbing;
  credential-observing test seams remain behind `test-support`.
- `crates/contextd/src/account_lifecycle.rs` routes through the ordered vault
  worker, checks the exact case-insensitive `delete` confirmation, revalidates
  returned projections, and emits sanitized client errors.
- Ordinary daemon construction still uses
  `UnavailableAccountLifecycleTransport`. There is no renderer-selected
  transport or environment-token shortcut. Test injection is not production
  authenticated-session provisioning.

### Edge admission

- Exact request shape is `{v: 1, action: "status", workspaceId}` for status;
  mutations also carry `requestId` (64 lowercase hexadecimal characters).
  POST JSON is bounded to 16 KiB; workspace identifiers are UUIDv7; unknown or
  caller ownership fields are rejected.
- `adapter.mjs` verifies claims with `getClaims`, derives `sub` and `session_id`,
  and uses separate unprivileged and service clients without persistent sessions.
- Mutations require the first signed AMR entry (currently assumed newest) to be `method: "oauth"` and
  no older than 300 seconds. JWT `iat` alone is not credential freshness.
  **Verify actual supported GitHub OAuth AMR shape and ordering before activation;
  the implementation selects `claims.amr[0]`, not a computed newest entry.**
- Environment-variable names are `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY`,
  and `CONTEXT_RELAY_SUPABASE_SECRET_KEY`. Only names are committed. No key
  should enter renderer config, logs, notes, or this handoff.
- `verify_jwt = false` at the Edge gateway is intentional manual-verification
  wiring, not permission to bypass JWT verification in the handler.

### Draft migration and exact SQL repair path

`supabase/migrations/20260831051540_account_lifecycle.sql` adds:

- Dedicated non-login `context_relay_rls_owner` boundary, checked for safe
  privileges; temporary migration grants are revoked afterwards.
- A private bridge to the live `auth.sessions` row, checking exact user/session
  and `not_after` with row locking. Signed stale JWTs alone are insufficient.
- Account-serialized authorization and state transitions, with post-lock
  revalidation of device/workspace/session/epoch and credential freshness.
- A private RLS-protected budget of 30 requests per account per 60 seconds.
- Private durable receipts bound to account, user, session, workspace, action,
  and projection. Draft bound: 10,000 per account, no eviction before purge,
  fail closed when full. Review denial-of-service and product implications.
- Server-computed time values using floored epoch milliseconds encoded as text.
- Service-only public status `(uuid, uuid, uuid)` and begin/cancel
  `(uuid, uuid, uuid, bigint, bytea)` wrappers; legacy begin/cancel `(uuid)`
  execution by `service_role` is deliberately revoked.

The existing `supabase/tests/0001_context_relay_ciphertext_boundary_test.sql`
still expects legacy grants around lines 686–687 and calls the legacy functions
as `service_role` in the deletion section around lines 2698–2855. These are now
confirmed CI failures, not merely suspected failures.

Next worker should:

1. Write failing executable pgTAP tests for the new session-bound wrapper
   contracts, including a real seeded/live Auth session rather than static text
   matching or client-supplied identity.
2. Update privilege assertions for the new public signatures and explicitly
   assert that old legacy signatures are denied to service/client roles.
3. Retain historical internal state-machine tests using the suite's bounded
   transaction-local owner inheritance, not a public service privilege. Do not
   place pgTAP assertions inside a role block that cannot access the extension.
4. Test revoked/expired sessions, expired binding, stale control/key epochs,
   foreign account/workspace, role denial, post-lock freshness, rate exhaustion,
   receipt collision/rebinding, replay after intervening begin/cancel, and
   concurrent lifecycle/authorization transitions.
5. If adding a second SQL suite, update the explicit `supabase:test` script and
   its workflow/static contracts. It currently names only `0001...sql`; fixture
   include files must not be accidentally discovered as standalone pgTAP suites.
6. Run a fresh disposable reset, the entire planned suite, database lint, and
   relevant advisor checks. Record exact counts and logs; update the audit row
   only for the scope actually proven. Preserve production privilege boundaries.

Do not fix these tests by regranting legacy authority, skipping assertions,
accepting partial plans, weakening freshness, or interpreting SQL source-text
tests as database execution. The migration now has CI reset execution evidence,
but no complete new-wrapper runtime coverage and no hosted deployment evidence.

Still missing beyond that slice: daemon-owned OAuth session lifecycle and
refresh/expiry handling; production pairing/recovery transports; native phrase
entry; reassociation; immediate device cutoff and epoch rotation; recovery after
revocation; final purge scheduling; product export and deletion UX.

## 8. Task-by-task completion map

The [audit matrix](../../verification/v1-master-plan-audit.md) is the maintained
source of truth. This is its capture-time summary, not a new acceptance decision.
“Verified” below means a scoped local requirement, not all release planes.

| Task | Status | Next substantial gate |
| --- | --- | --- |
| 1 — repository/history | partial | Live protection/history/branch reconciliation. |
| 2 — licensing/governance | partial | Live protection/fork-secret/license/name checks. |
| 3 — workspace/CI | partial | Every required supported-host check completes green. |
| 4 — protocol/threat model | amended | Ratify ledger and revalidate cross-platform frozen contracts. |
| 5 — cryptography | verified, scoped | Physical cross-platform vectors and secret-lifetime checks. |
| 6 — vault/search | verified, scoped | Key loss, crash/migration, 10,000-record P95 physical gates. |
| 7 — daemon/IPC | partial | Repaired Windows runtime plus physical identity/restart/size gates. |
| 8 — offline desktop | verified, scoped | Physical accessibility, renderer-plaintext and offline acceptance. |
| 9 — native isolation | partial | Deferred Task 9R and both-platform sidecar/filesystem/network qualification. |
| 10 — Claude adapter | verified, scoped | Real current/previous/unknown installs and rollback. |
| 11 — Codex adapter | partial | Real installs, wrapper/precedence/NTFS ACL/exact rollback. |
| 12 — Hermes adapter | partial | Real profiles/gateway/redaction/crash/rollback; unauthenticated runtime closures remain import-only. |
| 13 — MCP | partial | Physical three-harness/daemon matrix and offline hosted convergence. |
| 14 — native memory authority | verified, scoped | Physical harnesses and current clean CI. |
| 15 — hosted boundary | partial | Credentialed Storage, two-account private Realtime, JWT/OAuth behavior. |
| 16 — signed sync | partial | Approved hosted migration, daemon-owned session integration, real multi-device convergence. |
| 17 — devices/recovery/lifecycle | partial | Finish the detailed gaps above; PR #13 is WIP. |
| 18 — GitHub App | missing | Exact read-only permissions, selected repositories, memory-only short-lived tokens, reassociation. |
| 19 — packages | missing | Dependency closure, quarantine/scanning/provenance, exact approval, install/rollback and malicious fixtures. |
| 20 — onboarding/setup | missing | Accessible create/pair/recover/import/approve/smoke/resume/rollback on both platforms. |
| 21 — history/export/diagnostics | missing | Conflict presentation, compensating undo, safe export/import and redacted diagnostics. |
| 22 — releases/updates | missing | Signing/notarization, SBOM/provenance/licenses, verified updates and N-1 rollback. |
| 23 — final hardening | missing | Independent full audit, fuzz/fault/performance/dependency/privacy/license gates. |
| 24 — alpha/beta | missing | Full signed physical matrix twice from clean machines; every release blocker passes. |

The original master plan's detailed release-blocking cases still apply. The
matrix's category rows do not replace those individual cases. Do not declare
completion just because a task has many tests or a development report says done.

## 9. Toolchain, test commands, and reproducibility

Supported v1 product hosts: **macOS arm64 and Windows x64**. Linux CI is useful
for SQL/static policy, not a newly supported product target.

| Component | Repository pin / relevant observation |
| --- | --- |
| Rust | `rust-toolchain.toml`: 1.97.1, rustfmt and clippy; edition 2024. |
| Node | `.node-version`: 24.14.0. Originating bundled runtime now reports 24.19.0; do not misattribute local checks to the CI pin. |
| pnpm | `package.json`: 11.9.0; old local fallback launcher was 11.16.0. Use the repository pin and frozen lockfile. |
| Supabase CLI | 2.113.0 via development dependency. Do not downgrade to historical 2.110.0. |
| Supabase JS | 2.112.0, including the pinned Edge import. |
| Gitleaks | 8.30.1 used for preservation; verify downloaded binaries against published digests before execution. |
| Native build | Platform SDK/compiler prerequisites and exact workflow environment remain authoritative. Cross-compile is not native execution. |

Read the checked-in workflows before replicating native qualification. macOS CI
uses a canonical temporary root and a case-sensitive APFS fixture. The original
Codex checkout has host provenance/xattr behavior that can fail exact topology
tests; do not remove those protections or skip tests to make an arbitrary
filesystem look qualified. Use a clean appropriate test environment.

### Focused preservation checks (all ran, 26 cases total)

```sh
node --test scripts/tests/account-lifecycle-edge.test.mjs scripts/tests/account-lifecycle-cloud-admission.test.mjs scripts/tests/supabase-sync-rust-boundary.test.mjs scripts/supabase-workflow.test.mjs
node scripts/check-supabase-contract.mjs
cargo +1.97.1 test -p context-relay-core --features test-support --test account_lifecycle_transport_v1 --test supabase_account_lifecycle_v1
cargo +1.97.1 test -p context-relay-contextd --features test-support --lib account_lifecycle -- --nocapture
cargo +1.97.1 clippy -p context-relay-core -p context-relay-contextd --all-targets --features context-relay-core/test-support,context-relay-contextd/test-support -- -D warnings
cargo +1.97.1 fmt --all -- --check
git diff 435367d..485886c --check
```

Results: Node 21; core Rust 3; daemon Rust 2; static contract, scoped Clippy,
formatting and complete preservation-range whitespace passed. Gitleaks scanned
the pending implementation without findings; the public Secret Scan also passed.
These are not a full workspace/physical/hosted acceptance run.

### Ordinary workspace checks to reproduce

```sh
pnpm install --frozen-lockfile
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --features "context-relay-core/test-support,context-relay-local-ipc/test-support,context-relay-contextd/test-support,context-relay-context-mcp/test-support" -- -D warnings
cargo test --workspace --all-targets --features "context-relay-core/test-support,context-relay-local-ipc/test-support,context-relay-contextd/test-support,context-relay-context-mcp/test-support"
pnpm lint
pnpm typecheck
pnpm test
pnpm build
pnpm check:daemon-boundary
pnpm check:bindings
pnpm check:schemas
pnpm license:check
```

Do **not** substitute workspace-wide `--all-features`: that enables the
candidate-only sidecar acceptance feature. A-004 documents the exact ordinary
feature set. Individual historical core-only `--all-features` evidence has a
different scope; do not copy it blindly to the whole workspace.

For SQL, use an empty disposable local Supabase stack with Docker and the pinned
CLI. `supabase:start:ci` excludes Auth/Realtime/Storage services and is suitable
for the existing SQL contract suite, not live provider integration. The checked-
in workflow supplies deliberately synthetic local OAuth placeholders. After
confirming the local database is disposable, the existing sequence is
`pnpm supabase:start:ci`, `pnpm supabase:reset`, `pnpm supabase:test`,
`pnpm supabase:lint`, then `pnpm supabase:stop`. Reset/stop can discard local data;
never run them against a valuable developer database. Do not run hosted push,
link, deploy, or credentialed tests without the explicit approval below.

Historical SQL counts: the original hosted report says 502; later local CI
proved the 502-case compatibility repair; signed-sync expansion planned 518.
The current Task 17 branch runs 469/518 before the known failure. These counts
refer to different source snapshots and execution planes, not interchangeable
evidence. The upstream database crash/collation/pgTAP compatibility history is
already documented in Task 15; do not rediscover it by downgrading tools.

## 10. Security/dependency state and approval gates

The push banner currently reports **28 default-branch dependency alerts**
(2 critical, 13 high, 9 moderate, 4 low). This is not a triage of the draft
candidate: its dependency gates were green, while `main` is still old.
Read [dependency recovery evidence](../../verification/dependency-alerts-2026-08-10.md).
Verify live advisories and candidate reachability; do not claim all alerts closed.
Earlier alert-detail access lacked the required security permission. If still
blocked, request the minimum explicit access rather than silently expanding auth.

The full-history secret scanner retains **11 exact immutable fixture
fingerprints**, with one-to-one rationale in
[secret-scan exceptions](../../security/secret-scan-exceptions.md). Preserve
`.github/repository.gitleaksignore`; do not add broad regex/path exemptions or
disable history scanning. Archive documents and decoded graph payloads must be
scanned too; compression is not a secret-scan bypass.

Pause for explicit user approval before any of these:

- Applying a migration to a hosted Supabase project, changing production buckets,
  functions, policies, Realtime, or authentication settings.
- Creating GitHub App/OAuth credentials or changing external app permissions.
- Credentialed physical-device/multi-account tests, paid services, or external
  testers. An old approval for one historical project is not blanket authority.
- Signing/notarization, production deployment, publishing artifacts/installers,
  updater metadata, or release tags.
- Credential rotation if a real secret is found: stop exposure, identify exact
  scope and authority, and coordinate the approved rotation without printing it.

The historical report's Supabase project identifier is not a secret, but does
not select or authorize a production target. No provider credentials, GitHub
tokens, recovery phrases, signing identities, user vaults, or global harness
settings are part of this transfer. Reauthenticate on the other device using
normal secure product flows.

## 11. Portable archive, integrity, and limitations

Preservation validation: all **52** archived files passed stored/decoded SHA-256
and size checks (59,787,677 decoded bytes; about 3.49 MB stored). Every archived
JSON parsed, no originating Mac home path remained, and 19 local Markdown links
resolved. Gitleaks scanned the decoded archive and documentation (~59.88 MB)
without findings; the pre-handoff-commit full-history scan covered 353 commits
without findings using the unchanged exact historical exceptions. A separate
read-only review found three documentation inaccuracies; all were corrected and
re-reviewed. These checks validate preservation, not the product's release gates.

[artifact-manifest.json](artifact-manifest.json) identifies every newly archived
reference by logical source, original SHA-256, stored SHA-256, byte size, and
decoded hash for compressed files. Machine-local paths and trailing whitespace
were normalized; archive notices were added to historical Markdown. Original
hashes identify the original attachments, not byte-identical portable copies.

Included: both original user reference texts; all 14 local-only recovery
briefs/reports; Graphify's final graph, report, HTML, manifest, AST, extraction,
semantic chunks, labels, analysis, cost, and saved query/lesson records. Large
JSON artifacts are gzip-compressed to avoid unnecessary repository bulk. No
Git LFS service or external paid storage is required.

Ten review-diff scratch packages are also archived as compressed, scanned text
under `audit-notes/review-patches/`, with original/portable hashes. The manifest
additionally records public commit endpoints, paths and regeneration commands
for the nine actual diffs. Regenerated default-context diffs need not have the
same historical headers/context as those packages. One scratch file contains
only a 113-byte incomplete header and an invalid old starting ref, not a patch;
its exact logical content is preserved but it is not evidence of a valid commit.

Excluded: build outputs, dependency stores, duplicate extraction caches, local
runtime path settings, and credentials. These exclusions do not hide source
changes; all meaningful implementation changes are in the PR stack. Generated
tracked schemas/bindings and lockfiles remain version controlled. Read-only
ChatGPT project `sources/` mirrors were not edited or uploaded wholesale.

### Graphify caveats and use

The graph is a **2026-08-10 navigation snapshot**, not a fresh August 31 audit.
Recorded health: 453 supported files, 12,456 nodes, 39,200 directed edges,
427 communities, 1,792 dangling edges, 2,060 collapsed endpoint pairs. It can
identify where to look but cannot prove absence of vulnerabilities or coverage
of later code. Its saved August 31 query does not make the underlying graph new.

Read [GRAPH_REPORT.md](graphify/GRAPH_REPORT.md) directly. The HTML is an optional
interactive snapshot, not a required runtime. To inspect the full portable JSON
without installing Graphify, use Node's `zlib.gunzipSync` and `JSON.parse` on
`graphify/graph.json.gz`. To rebuild, use the current installed Graphify skill on
the new checkout; follow its corpus-size partition rules and keep source secrets
excluded. Recreate runtime root/interpreter settings for that device. Never
copy the originating host's interpreter or global harness configuration.

## 12. Prioritized continuation plan and stopping criteria

### First session on the new device

1. Fetch/check out the handoff branch, verify clean state and parent SHAs, read
   this handoff, master plan, matrix, amendments and Task 17 checkpoint.
2. Refresh PR #12's exact-head Windows/macOS test and native-isolation status.
   Its two remaining Windows MCP failures are recorded above; diagnose the
   primary topology/fixture rejection rather than its later symptom. Preserve
   `435367d` regressions and repair in an isolated focused change.
3. Reproduce PR #13's documented SQL failure in a disposable environment. Add
   executable new-boundary regression tests, reconcile the legacy harness, and
   obtain complete reset/test/lint evidence without widening production grants.
4. Review Task 17's unverified AMR/live-session/idempotency and daemon injection
   contracts against the master plan before enabling production transports.
   Ask for provider approval only when local implementation/evidence is ready.
5. Update the maintained audit matrix and ledger with actual new evidence, then
   request an independent scoped review. Do not promote a whole task from one
   test count or a source-only check.

### Following focused PRs

Complete hosted Tasks 15–17 in separable slices: authenticated provider boundary;
production `SyncTransport` push/pull/range/checkpoints/tombstones/retries/hints;
authenticated pairing/recovery with full independent safety confirmation;
native phrase-entry host; full account/device lifecycle and immediate cutoff.
Keep provider implementation behind existing daemon-owned traits rather than
adding parallel renderer-facing privileged APIs.

Then Tasks 18–24: read-only GitHub App; package quarantine/approval/install;
accessible onboarding; conflict/history/export/diagnostics; signed releases and
updates; final independent hardening; twice-clean physical alpha. Each has the
master plan's detailed checks and explicit external-action approval gates.

### Completion means all of the following, not just a successful build

- Every master-plan requirement has reproducible evidence or an explicitly
  approved strengthening amendment with synchronized contracts and tests.
- Every required CI/release gate is green on the applicable exact candidate;
  no hidden, failed, or skipped requirement is treated as satisfied.
- No unresolved critical/high vulnerabilities, real secrets, unknown licenses,
  or unreviewed dependency alerts. Actionable lower-severity issues are fixed;
  unavoidable no-fix dependencies require explicit approval, reachability proof,
  owner and expiry.
- Hosted tests cover at least two accounts and multiple devices, expired/stale
  auth, private Storage/Realtime, repair/convergence, recovery/revocation/rotation,
  export, deletion cancellation and final purge.
- Signed install/update/rollback, SBOM/provenance, outage behavior, accessibility,
  performance, and the full master-plan matrix pass twice on clean supported
  physical machines. Only then consider beta; a calendar date is not a gate.

If a new permission, credential, hardware target, or external service is needed,
state the exact blocker and ask. Do not infer authority from repeated “continue”
messages or fabricate successful evidence to complete the handoff.
