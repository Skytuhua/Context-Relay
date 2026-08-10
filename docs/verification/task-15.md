# Task 15 verification ledger

## Task 1 baseline — 2026-08-05

**Branch:** `codex/supabase-schema-rls`
**Starting commit:** `f147c712d6ef7e432022c3d789f8190f95e669d3` (`build: add pinned Supabase contract harness`)

| Gate | Result | Evidence / limitation |
| --- | --- | --- |
| Desktop tests | Green | Task 14 verified `vitest --run` in `apps/desktop`: 28 passed across 5 files, using the bundled Node runtime. |
| `cargo test --workspace` | Environment-unverified | `cargo` is not installed on this Mac. |
| `pnpm check:bindings` | Environment-unverified | Requires the unavailable Cargo toolchain. |
| `pnpm check:schemas` | Environment-unverified | Requires the unavailable Cargo toolchain. |
| Local Supabase start/reset/pgTAP/lint | Environment-unverified | Docker is not installed on this Mac; these remain mandatory CI and hosted checks. |

Task 1 uses only synthetic local/CI OAuth values and contains no credentials or
production secrets. The local Supabase Darwin binary could not be hydrated due
to registry error 23, so local CLI runtime commands remain unavailable; this
does not alter the pinned CI requirements.

## Task 7 Step 1 pre-remote ledger — 2026-08-05

This is the acceptance snapshot taken before any remote mutation.

| Field | Recorded value |
| --- | --- |
| Branch | `codex/supabase-schema-rls` |
| Pre-remote commit | `67c46f27f3c8f9c30c82f1853226e2485f71e1de` |
| Supabase CLI package | Exactly `2.110.0`, pinned in `package.json` and `pnpm-lock.yaml`; its executable cannot run on this host because the Darwin ARM64 package binary is unavailable. |
| Committed migration | `supabase/migrations/20260804000000_context_relay_ciphertext_boundary.sql`; migration version `20260804000000` |
| Committed migration SHA-256 | `4cdc8c6095e2971e1b6d69110e5309293da5cc75e4932bc4f0dedc9cfaa2175c` |

The checksum above is for the migration committed at the pre-remote commit, not
the intentionally dirty Task 5 worktree copy.

### Static evidence available before provisioning

| Check | Recorded result | Scope |
| --- | --- | --- |
| Task 4 contract controller | 73/73 contract tests passed against the clean committed migration. | Static contract evidence only. |
| Task 6 Realtime verifier | 14/14 unit tests passed. | Injected-client orchestration evidence only; no live WebSocket was exercised. |
| Syntax and diff checks | Syntax checks and `git diff --check` passed at the clean Task 4/Task 6 checkpoints. | Static evidence only. |

At this pre-remote snapshot, the dirty Task 5 tests and related worktree edits
were intentional RED work in progress. They were excluded from the historical
results above; the completed local implementation is recorded next.

## Post-local Task 5 and Task 6 checkpoint — 2026-08-05

No hosted project was selected, linked, created, or mutated while reaching this
checkpoint.

| Field | Recorded value |
| --- | --- |
| Branch head | `cd14ee38b92a64ae05409c8db69ed763296115cd` (`feat: authorize private Supabase sync hints`) |
| Task 5 commits | `1dba32d` through `40d3e93`; independent security review approved after upload-returning and finalization lifecycle hardening. |
| Task 6 commits | Realtime verifier `a995f86` through `67c46f2`; policy/checker `cd14ee3`; independent security review approved after adversarial SQL/JavaScript checker hardening. |
| Committed migration | `supabase/migrations/20260804000000_context_relay_ciphertext_boundary.sql`; migration version `20260804000000` |
| Current migration SHA-256 | `30e2055188a8b56d98de81c7422847a592f93ba46b3e4b4065c29d289b9fa093` |
| Toolchain visible on this host | Node `v24.14.0`; pnpm package `11.9.0`; Supabase CLI package remains pinned to `2.110.0`. |

### Locally executed evidence

| Check | Result | Scope / limitation |
| --- | --- | --- |
| Static Supabase contract suite | Green: 135/135 tests. | Includes Task 5 quota/Storage and Task 6 policy, payload, parser-bypass, provider-DDL, and verifier-dataflow regressions. |
| Repository contract checker | Green: direct checker CLI exited 0. | This is the exact command behind `check:supabase`. The workspace pnpm wrapper attempted a dependency-directory reinstall and aborted without a TTY, so the underlying pinned Node command was run directly without mutating dependencies. |
| Realtime verifier unit suite | Green: 14/14 tests. | Injected-client orchestration only; no live WebSocket was exercised. |
| JavaScript syntax checks | Green. | Checker, checker tests, Realtime verifier, and verifier tests all parsed successfully. |
| Patch hygiene | Green. | `git diff --check` passed before commit and the tracked worktree was clean after `cd14ee3`. |
| pgTAP inventory | Static-only: `plan(501)` with `finish()` and rollback present. | The 501 assertions were not executed because no PostgreSQL/Supabase runtime is available. |

The Task 6 checker is intentionally conservative around executable dynamic SQL:
DDL-looking strings inside a `DO` block can cause a false-positive review gate.
The independent security reviewer classified this as Minor CI friction, with no
remaining Critical or Important Task 6 finding.

## Task 7 hosted zero-cost checkpoint — 2026-08-05

This section supersedes the earlier pre-remote status while preserving it as a
historical checkpoint. The only hosted project used was the newly created free
Context Relay project; unrelated projects were not selected, linked, or changed.

| Field | Recorded value |
| --- | --- |
| Hosted project | `brvzuycnxoswdzzipgvx` (`Context Relay`) |
| Cost and region | Exactly `$0/month`; `us-west-1` |
| PostgreSQL | Hosted PostgreSQL 17.6 |
| Foundation source | Implementation commit `5dc1216`; SHA-256 `d5d113906e26f06a9e1c594996c25254122d19d3a860729acaf8b36b67e1406a` |
| Foundation hosted migration | Version `20260805153409`; name `context_relay_ciphertext_boundary` |
| Privilege-repair source | Implementation commit `4ad9f29`; SHA-256 `cc839506e9046906f12904bab2457ea75d13b8c661189edd27b8daf2d0d63a86` |
| Privilege-repair hosted migration | Version `20260805155753`; name `revoke_context_relay_internal_execute` |
| pgTAP source | `plan(502)`; SHA-256 `c9a67a10928412785c0ff540a5c33adf7bbcec09822a7ff428fc81910059f95c` |

The first foundation apply attempt failed on a hosted-only `ALTER ROLE`
permission boundary, and the next failed while assigning private-schema
objects. Both attempts were transactional and left no migration record, role,
table, or row behind. Rollback probes established the PostgreSQL 17
`INHERIT false, SET true` membership form, owner-context DDL, temporary public
schema creation, and the minimal hosted Auth claim bridge. The corrected
foundation then applied once. The original applied migration was not edited
afterward; a separate forward migration repaired the later runtime-discovered
function ACL issue.

### Hosted execution evidence

| Check | Result | Evidence / limitation |
| --- | --- | --- |
| Foundation catalog | Green | Eleven Context Relay relations exist, all eleven have RLS enabled, all contain zero persistent rows, and none is in the `supabase_realtime` Postgres Changes publication. |
| Ciphertext bucket | Green | Private bucket exists with an exact `33,554,432` byte object limit. |
| Dedicated owner boundary | Green | No login, inheritance, superuser, bypass-RLS, creation, replication, public-schema CREATE, or runtime `INHERIT`/`SET` membership remains. |
| Hosted Auth bridge | Green | The migration identity owns the minimal `auth.uid()`/JWT `session_id` bridge; only the dedicated owner can execute it, and clients cannot. |
| Internal function ACLs | Green after forward repair | All six internal validators/trigger helpers deny `PUBLIC`, `anon`, `authenticated`, and `service_role`; the dedicated owner retains execution. |
| Full hosted pgTAP | Green: 502/502 | The complete suite ran in one transaction. Connector-only adapters inlined the two `\ir` fixtures, normalized pgTAP 1.3 two-argument behavior/collation, and granted the hosted migration identity test-only access after structural assertions. The transaction rolled back. |
| Rollback hygiene | Green | Follow-up catalog checks found zero Context Relay rows, zero synthetic Auth users, zero synthetic Storage objects, zero adapter functions, and zero runtime owner memberships. |
| Static contract suite | Green: 140/140 | Includes the owner-scoped six-function revocation, ordered/balanced temporary-membership regression, and CI coverage for both Task 15 Node suites. |
| Realtime verifier unit suite | Green: 14/14 | Credential handling, cleanup, own/cross/service/fresh channel orchestration, revocation, redaction, and the hosted `rpc()` `{ data: null, error: null }` response contract remain covered. |
| Public Realtime transport warmup | Green | A real public-channel WebSocket subscribed and sent a Broadcast successfully, initializing the provider's daily partitions without persistent Context Relay data. |
| Private Realtime authorization verifier | Pending | Requires a service key to create and clean up ephemeral users; no such private credential was available or requested. |
| Storage database policy behavior | Green | The 502 hosted assertions exercised private bucket metadata, upload/read policy predicates, path/part validation, finalization, quota, revocation, and cross-account denial at the database policy layer. |
| Storage HTTP API behavior | Pending | No service credential was available for an end-to-end object upload/read/delete exercise. |
| GitHub OAuth | Pending | Provider client ID/secret and the required hosted dashboard action were unavailable. No credential was requested or recorded. |

### Hosted advisors

Both current advisor scans contain no `WARN` or `ERROR` release blocker.

- Security: five `INFO` notices for RLS-enabled tables without policies. These
  are the intentionally grant-private reservation, pairing, recovery, GitHub
  installation, and deletion-request relations; denial by absence is required.
  See the [advisor description](https://supabase.com/docs/guides/database/database-linter?lint=0008_rls_enabled_no_policy).
- Performance: eight `INFO` unused-index notices. The database is new and empty,
  so usage statistics do not justify removing required access-path indexes.
  See the [advisor description](https://supabase.com/docs/guides/database/database-linter?lint=0005_unused_index).

### Review disposition

The hosted compatibility and forward privilege-repair delta received an
independent security review. The final disposition is approved with zero
Critical, Important, or Minor findings. The reviewer specifically verified the
transactional temporary-role lifecycle, all six exact function signatures,
effective privilege checks, and the static checker's ordered closure regression.

The independent full-diff correctness review found two actionable issues. The
Realtime verifier incorrectly expected a custom `success` field instead of the
Supabase client RPC result shape, and the two standalone Task 15 Node suites
were not explicit CI gates. Commit `b9a4b8c` added failing regressions first,
then accepted only the exact void-RPC success shape and added both suites and
their source paths to `.github/workflows/supabase.yml`. The reviewer re-ran the
review and approved the fixes. A concern about database identity seeding was
withdrawn because the Task 6 plan intentionally places privileged account and
binding seeding between `prepare` and `verify`; the verifier prints the safe
identifiers needed for that operator-owned step.

The independent full-diff security review approved `f147c712..b9a4b8c` with no
validated exploitable finding. It rechecked session-derived identity, scoped
foreign keys and RLS, empty-search-path definer functions, the non-login owner
boundary, service-only transition RPCs, transactional ACL repair, account-row
quota serialization, exact Storage paths and object metadata, receive-only
private Realtime topics, and the verifier/CI follow-up. The focused Node suites
were 154/154, the checker exited 0, and patch hygiene passed for the reviewed
head. Remaining private-transport, OAuth, and local-toolchain gaps are execution
limitations rather than accepted source findings.

### Task 8 regression checkpoint

| Gate | Result | Evidence / limitation |
| --- | --- | --- |
| Static Supabase contract suite | Green: 140/140 | Direct Node suite passed at commit `b9a4b8c`. |
| Repository contract checker | Green | Direct checker CLI exited 0. |
| Realtime verifier suite | Green: 14/14 | Includes table-driven malformed and non-void RPC response rejection. |
| Desktop lint | Green | ESLint passed from `apps/desktop`. |
| Desktop typecheck | Green | TypeScript `--noEmit` passed from `apps/desktop`. |
| Desktop tests | Green: 28/28 | Vitest passed across five files from `apps/desktop`. |
| Desktop build | Green | Vite built 33 modules from `apps/desktop`; generated output remains ignored. |
| Complete repository Node test discovery | Partial: 282/288 | Six sidecar-installer tests fail with `write EPIPE` because their child process cannot spawn the absent Cargo executable. All six are in unchanged Task 14-era sidecar files; a diff against starting commit `f147c712` is empty. |
| Cargo format/check/test/clippy | Environment-unverified | Cargo is not installed, so no Rust workspace gate can execute. |
| Binding, schema, license, and daemon checks | Environment-unverified | Each reaches the same missing-Cargo boundary (`ENOENT` or null child status). No unrelated sidecar or Task 14 behavior was modified. |
| Fresh local Supabase start/reset/pgTAP/lint | Environment-unverified | Docker, `psql`, and a runnable local Supabase CLI are unavailable. Hosted pgTAP and advisors remain the available database evidence. |
| Patch hygiene | Green | `git diff --check` passed at the review checkpoint. |

### Execution availability

| Surface | Status | Blocker |
| --- | --- | --- |
| Local Supabase/database | `unverified` | Docker, `psql`, and a runnable local Supabase CLI are unavailable. |
| pgTAP and database lint | `unverified` | No local Supabase database can be started or reset. |
| Cargo/workspace gates | `unverified` | Cargo is unavailable. |
| Hosted database | `verified` | Foundation and forward migrations applied; 502/502 pgTAP assertions passed transactionally. |
| Storage API | `database-policy verified / HTTP pending` | Hosted policy behavior passed; an API-level run needs a private service credential. |
| Realtime WebSockets | `public transport verified / private verifier pending` | Public Broadcast transport passed; the private two-user verifier needs a service credential. |
| GitHub OAuth | `pending` | Private provider credentials and dashboard configuration are unavailable. |
| Cost, region, and project | `verified` | Project `brvzuycnxoswdzzipgvx`, exactly `$0/month`, `us-west-1`. |
| Security/performance advisors | `verified` | No warning or error; informational notices are dispositioned above. |

### Task 8 acceptance assertions

| Acceptance assertion | Status | Execution plane | Evidence | Timestamp or blocker |
| --- | --- | --- | --- | --- |
| User A cannot select, insert, or blob-access user B. | `hosted database/runtime verified; HTTP/WebSocket pending` | Hosted database, Storage policy, and Realtime policy | 502/502 pgTAP assertions exercised two users, cross-account SQL denial, Storage policy denial, and exact private Realtime topic authorization. | 2026-08-05: private API/WebSocket verifier needs a service credential. |
| Revoked sessions fail the next sensitive authorization, and Realtime refresh is bounded by the 900-second JWT lifetime. | `hosted database verified; private WebSocket and hosted Auth setting pending` | Hosted database and Realtime | Fresh policy evaluation denied the revoked session across all six read relations; verifier logic is 14/14. Repository configuration fixes JWT expiry at 900 seconds, but the hosted Auth setting was not independently inspected. | 2026-08-05: live private-channel revocation needs a service credential; hosted JWT expiry remains unverified. |
| A client device ID cannot affect authorization. | `hosted runtime verified` | Hosted database | Identity derives from hosted Auth claims and the bound session/device chain; caller-selected device identity is rejected in the 502-test matrix. | 2026-08-05. |
| Anonymous access is absent. | `hosted database/policy verified; HTTP/WebSocket pending` | Hosted database, Storage policy, and Realtime policy | Effective grants and role-switched runtime assertions deny anonymous access. | 2026-08-05: API transport remains credential-blocked. |
| Operation-log mutation is service-only. | `hosted runtime verified` | Hosted database | Effective privilege and negative mutation assertions passed. | 2026-08-05. |
| Quota and Storage part invariants are atomic and exact. | `hosted database verified; HTTP pending` | Hosted database and Storage policy | Reservation, finalization, replay, release, exact size/digest/part checks, and quota boundaries passed transactionally. | 2026-08-05: Storage HTTP transport remains credential-blocked. |
| Pending deletion is read/export-only. | `hosted database verified; private WebSocket pending` | Hosted database, Storage policy, and Realtime policy | Hosted lifecycle and policy assertions retain reads while denying writes and reservations. | 2026-08-05. |
| Security and performance advisors contain no release blocker. | `verified` | Hosted advisors | Zero warning/error lints; expected informational notices dispositioned above. | 2026-08-05. |

### Task 17 fresh-auth contract

| Contract | Status | Owner | Evidence / blocker |
| --- | --- | --- | --- |
| Deletion begin/cancel must require the most recent credential-bearing `amr` timestamp to be no older than 300 seconds; a refreshed JWT `iat` is insufficient, and the gate must pass before the service-only RPC is invoked. | `unverified` | Downstream Task 17 | Task 15 can test the database transition state machine; Task 17 owns fresh-auth application tests. |

### Completion Evidence

| Required evidence | Status | Execution plane | Evidence | Timestamp or blocker |
| --- | --- | --- | --- | --- |
| Exact committed migrations and CLI version | `repository and hosted verified` | Repository plus hosted migration ledger | Both source checksums and hosted versions are recorded above; CLI remains pinned to `2.110.0`. | 2026-08-05. |
| Green static contract tests | `verified-local` | Repository/Node | 140/140 contract tests, checker CLI, 14/14 Realtime verifier tests, syntax checks, and diff hygiene passed at review-fix commit `b9a4b8c`. | 2026-08-05. |
| Green pgTAP and database lint on a fresh Supabase stack | `hosted pgTAP verified / local lint unavailable` | Hosted database and local tooling | 502/502 hosted pgTAP passed; advisor scans have no warning/error. Local CLI lint remains unavailable without Docker/CLI. | 2026-08-05. |
| Zero-cost project reference and `us-west-1` region | `verified` | Hosted control plane | Project, exact zero cost, and region are recorded above. | 2026-08-05. |
| Hosted two-user/session/deletion isolation queries | `verified` | Hosted database | Full transactional pgTAP matrix passed and rolled back cleanly. | 2026-08-05. |
| Hosted Storage upload/read/revocation behavior | `database-policy verified / HTTP pending` | Hosted database and Storage API | Database policy/object-metadata behavior passed; HTTP transport needs a private service credential. | 2026-08-05. |
| Absence from Postgres Changes publication | `hosted runtime verified` | Hosted database | Catalog query and pgTAP both confirm all Context Relay relations are absent. | 2026-08-05. |
| GitHub OAuth callback/provider status without secret material | `pending` | Hosted Auth configuration | Private provider credentials/dashboard action unavailable; nothing sensitive was requested or logged. | 2026-08-05. |
| Current security and performance advisor results | `verified` | Hosted advisors | Zero warning/error; informational notices are recorded above. | 2026-08-05. |
| Independent security and correctness review dispositions | `verified` | Full Task 15 diff | Correctness is approved after the `b9a4b8c` RPC/CI fixes. Independent security review of `f147c712..b9a4b8c` found no validated exploitable issue; all earlier focused security reviews also remain approved. | 2026-08-05. |
| Full workspace regression-gate results | `partial / environment-blocked` | Local workspace and CI-capable runners | Task 15 Node gates and all four desktop gates are green. The full Node discovery is 282/288 with six unchanged Cargo-dependent sidecar failures; Cargo-backed and fresh local-database gates cannot run on this host. | 2026-08-05: Cargo, Docker, `psql`, and runnable local Supabase CLI unavailable. |

### PR #12 recovery addendum (2026-08-10)

The `2.110.0` references above are retained as the exact historical Task 15
execution record. They are not the current repository toolchain. PR recovery
run [31352707006](https://github.com/Skytuhua/Context-Relay/actions/runs/31352707006),
job [93346355675](https://github.com/Skytuhua/Context-Relay/actions/runs/31352707006/job/93346355675),
reproduced a database backend connection loss at
`grant context_relay_rls_owner to current_user with inherit false, set true`
while starting the local PostgreSQL 17 stack from Supabase CLI `2.110.0`.

Upstream confirmed that the `supautils` version in the corresponding
`supabase/postgres:17.6.1.143` image dereferences a null special-role name and
crashes the backend for `GRANT` or `REVOKE ... current_user`. The fix is
[supabase/supautils#205](https://github.com/supabase/supautils/pull/205),
released in
[`supautils` 3.2.3](https://github.com/supabase/supautils/releases/tag/v3.2.3).
The repository now pins Supabase CLI `2.113.0`; the official embedded manifest
for that release uses `supabase/postgres:17.6.1.158`, after the fixed
`supautils` release. A repository regression rejects the vulnerable `2.110.0`
CLI package family in the lockfile. The migration and its temporary-owner
security boundary are unchanged.

| Recovery gate | Result |
| --- | --- |
| Dependency/lock contract RED | `3/4` Supabase workflow tests; exact expected mismatch `2.110.0` versus `2.113.0`. |
| Dependency/lock contract GREEN | `4/4`; package and all platform CLI packages resolve to `2.113.0`, with no `2.110.0` CLI entry. |
| Local executable identity | `supabase --version` reports exactly `2.113.0`. |
| Fresh local database start/reset | Green in recovery run [31353437071](https://github.com/Skytuhua/Context-Relay/actions/runs/31353437071), job [93348456664](https://github.com/Skytuhua/Context-Relay/actions/runs/31353437071/job/93348456664); the prior backend crash no longer occurs. |
| First pgTAP execution on the fixed image | Reached 119/502 before PostgreSQL rejected an indeterminate catalog-text collation. CLI `2.113.0` also discovered two included fixture files as standalone suites with no TAP plan. |
| First pgTAP compatibility repair | The runner now names only the planned suite. The first affected catalog-text and expected-text fields use the same explicit `C` collation. Recovery runs [31353663192](https://github.com/Skytuhua/Context-Relay/actions/runs/31353663192) and [31353661559](https://github.com/Skytuhua/Context-Relay/actions/runs/31353661559) proved fixture discovery was fixed and advanced the suite from 119 to 123 assertions before exposing the next unpinned catalog-text comparison at test line 823. |
| Complete pgTAP collation repair | Every text cast compared by `results_eq` now pins the same deterministic `C` collation; direct text and JSON-text projections in those comparisons are pinned explicitly too. A repository regression scans every multiline `results_eq` block and rejects an unpinned text cast. Recovery runs [31354328629](https://github.com/Skytuhua/Context-Relay/actions/runs/31354328629) and [31354326691](https://github.com/Skytuhua/Context-Relay/actions/runs/31354326691) proved the complete collation repair and advanced the suite to 125 assertions. |
| CLI 2.113 pg_prove fixture authority | Recovery runs [31354328629](https://github.com/Skytuhua/Context-Relay/actions/runs/31354328629) and [31354326691](https://github.com/Skytuhua/Context-Relay/actions/runs/31354326691) proved the collation repair and advanced to 125/502 before the newer pg_prove runner denied fixture insertion into the dedicated-owner tables. The suite now adds transaction-local inherited/SET membership only after the no-runtime-membership assertions, uses exact role switching for client/service checks, explicitly revokes the harness grant before `finish()`, and rolls the transaction back. A static order contract prevents that fixture authority from preceding the production-membership assertion or surviving to test completion. Fresh GitHub-hosted execution is pending. |
| Fixture-authority hosted proof | Recovery run [31354624195](https://github.com/Skytuhua/Context-Relay/actions/runs/31354624195) proved that the transaction-local grant preserves the production-membership assertion and authorizes the dedicated-owner fixture seed. The suite advanced from 125 to 235 assertions before exposing pgTAP call-signature incompatibility; rollback and cleanup completed. |
| pgTAP 1.3 `throws_ok` compatibility | The failing calls used the two-argument `throws_ok(sql, text)` form as though the second value were a test description. Under the [pgTAP 1.3 `throws_ok` contract](https://pgtap.org/documentation.html#throws_ok) that value is the expected error message, so valid exceptions failed whenever their real messages differed. All description-only calls now use `throws_ok(sql, null, null, description)`, which accepts any exception while retaining the description. A SQL-aware repository regression rejects any remaining ambiguous two-argument call. The bulk sync-envelope validation block no longer switches the session away from the migration identity solely to reach owner authority; it relies on the bounded transaction-local membership. Recovery run [31355156608](https://github.com/Skytuhua/Context-Relay/actions/runs/31355156608) proved every converted exception assertion through this block and advanced the suite to 282 assertions with zero failed subtests. |
| pgTAP visibility inside privileged quota/deletion assertions | Run `31355156608` then stopped when a narrower quota assertion explicitly assumed the dedicated owner role: that role intentionally cannot resolve the pgTAP extension functions. The quota-boundary and pending-deletion assertions now retain the migration session identity and receive the same owner authority only through the transaction-local inherited grant. A regression scans every explicit owner-role block and rejects any embedded pgTAP assertion, preventing the test harness from hiding its own assertion functions again. Static Supabase contracts are green at 161/161 and `pnpm check:supabase` exits successfully; fresh GitHub-hosted execution is pending. |

No paid action was performed. No secret, private key, service key, OAuth secret,
database password, access token, or refresh token is recorded in this ledger.
