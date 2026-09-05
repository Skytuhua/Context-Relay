# Supabase Ciphertext Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development to implement this plan task-by-task.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish and prove a zero-cost West US Supabase boundary that stores
only Context Relay ciphertext and minimum routing metadata, isolates accounts
by authenticated device session, and supports free-tier-safe encrypted blobs.

**Architecture:** Six public relations form an authenticated read-only model.
Private `SECURITY DEFINER` helpers derive account and device identity from
`auth.uid()` plus the Auth-issued JWT `session_id`; service-only functions own
authoritative writes and atomic quota transitions. A private Storage bucket
holds ordered ciphertext parts behind reservations and finalized manifests.
Private Realtime Broadcast sends only account-scoped pull hints. Postgres
Changes is not used.

**Tech Stack:** PostgreSQL 17, Supabase CLI 2.110.0,
`@supabase/supabase-js` 2.112.0, Supabase Auth/Storage/Realtime, pgTAP, SQL,
Node.js 24, pnpm 11.9.0, GitHub Actions, existing Rust 1.97 and TypeScript
workspace gates.

**Normative design:**
`docs/superpowers/specs/2026-08-04-supabase-schema-rls-design.md`

## Global Constraints

- Use test-driven development for every behavior: add one focused failing
  static or pgTAP assertion, observe the expected failure, implement the
  minimum SQL/configuration, and rerun the focused gate before broader gates.
- Use only a Supabase project whose confirmed recurring project cost is zero.
  Stop hosted provisioning if any non-zero cost appears; local work continues.
- Do not purchase or require Apple Developer membership, paid Supabase capacity,
  custom domains, or another paid product.
- Never commit Supabase service keys, database passwords, GitHub OAuth secrets,
  access tokens, `.env` files, or generated local state.
- Supply synthetic non-production GitHub client values in the environment when
  starting the local stack and in CI. Hosted provider values are configured
  only in the provider dashboard/API; local commands never reuse them.
- The stable Context Relay account UUID is separate from `auth.users.id`.
- Identity helpers accept no account, device, user, or session arguments. They
  derive identity only from `auth.uid()` and `auth.jwt().session_id`. Storage
  policy predicates may accept candidate object attributes, never identity.
- A binding must match user, session, account, and device; be `active`; be
  unrevoked; and be unexpired.
- Read authorization permits account states `active` and `pending_delete`.
  Write authorization permits only `active`.
- `anon` receives no Context Relay table/function/Storage/Realtime access.
- Authenticated clients receive `SELECT` only on the six read relations.
  They never receive direct operation, checkpoint, certificate, manifest,
  pairing, recovery, installation, deletion, or quota mutation privileges.
- `service_role` receives no direct privilege on Context Relay relations. It
  executes only narrow definer-owned `public.service_*` wrappers.
- Every table in an exposed schema enables RLS and has explicit grants.
- Private helpers use a dedicated `NOLOGIN NOINHERIT` owner, empty search path,
  fully-qualified objects, no dynamic SQL, and revoked default execution.
- `sync_operations` and `sync_checkpoints` are immutable to clients and absent
  from the `supabase_realtime` Postgres Changes publication.
- Realtime payloads are minimal private Broadcast hints, never sync rows.
- The account ciphertext limit is exactly 524,288,000 bytes across used plus
  reserved bytes. Transitions lock the account row.
- A logical blob is at most 524,288,000 bytes and each Storage part is at most
  33,554,432 bytes. Part paths are server-derived and exact. No client upsert,
  update, delete, or signed URL is permitted.
- Supabase is an untrusted ciphertext store. Client-side encryption, signature
  verification, issuer validation, replay detection, and causal reconciliation
  remain authoritative.
- Existing active sessions may read/export during `pending_delete`, but cannot
  write, reserve, upload, pair, recover, ingest, or create sessions.
- A deletion grace deadline is exactly seven days after the pending-delete
  request. Cancellation is accepted only before that deadline.
- Revocation denies the next Database, Storage, Edge, or fresh Realtime policy
  authorization. Do not claim recall of already-authorized in-flight traffic.
- A service revocation transition must atomically store signed cutoff evidence
  and advance account control/key epochs with the binding state change.
- Account `used_bytes` counts retained inline operation ciphertext plus
  finalized logical blob ciphertext. Operation insert and blob finalization
  each lock the account and charge bytes in the committing transaction.
- Deletion begin/cancel requires credential-bearing authentication at most five
  minutes old. JWT issuance/refresh time alone is not reauthentication.
- Forward migrations only after hosted application. Do not edit an applied
  migration or use destructive database reset against the hosted project.

---

### Task 1: Pin the Supabase toolchain and add the fast contract harness

**Files:**

- Modify: `package.json`
- Modify: `pnpm-lock.yaml`
- Modify: `.gitignore`
- Create: `supabase/config.toml`
- Create: `scripts/check-supabase-contract.mjs`
- Create: `scripts/tests/check-supabase-contract.test.mjs`
- Create: `.github/workflows/supabase.yml`

**Configuration contract:**

```text
CLI version: 2.110.0
local project id: context-relay
API schemas: public, graphql_public
private schema excluded: context_relay_private
Auth JWT lifetime: 900 seconds
GitHub OAuth secret source: environment only
ciphertext bucket: private, 33,554,432-byte per-object limit
```

- [ ] **Step 1: Record a clean baseline**

```bash
git status --short
pnpm install --frozen-lockfile
cargo test --workspace
pnpm test --run
pnpm check:bindings
pnpm check:schemas
```

Expected: the Task 14 checkout is green before Supabase files are introduced.
Record failures proven unrelated to Task 15 in `docs/verification/task-15.md`
instead of weakening their assertions.

- [ ] **Step 2: Write RED Node tests for the static contract checker**

Create table-driven temporary fixtures proving the checker rejects:

- an exposed `context_relay_private` schema;
- JWT expiry greater than 900 seconds;
- a literal GitHub OAuth secret;
- a public ciphertext bucket or part limit above 33,554,432;
- a migration without RLS, explicit revoke/grant sections, or session helpers;
- an identity helper with arguments or a Storage predicate accepting user,
  account, device, or session identity;
- authenticated mutation grants on immutable tables;
- any direct Context Relay relation grant to `service_role`;
- Context Relay tables added to `supabase_realtime` publication;
- a signed-URL SQL or application contract; and
- a CI workflow missing reset, pgTAP, lint, or cleanup commands.

```bash
node --test scripts/tests/check-supabase-contract.test.mjs
```

Expected RED: the checker module does not exist.

- [ ] **Step 3: Implement the smallest fixture-driven checker**

Export pure validation functions from `scripts/check-supabase-contract.mjs` and
run them against the repository only when the module is the entry point. Use
bounded exact-path reads. Report every violation in one run with relative paths
and stable rule IDs. Do not parse or print environment values.

```bash
node --test scripts/tests/check-supabase-contract.test.mjs
```

Expected GREEN: every intentionally unsafe fixture fails for its target rule;
the minimal safe fixture passes.

- [ ] **Step 4: Add the pinned CLI and generate local configuration**

```bash
pnpm add --save-dev --save-exact supabase@2.110.0 @supabase/supabase-js@2.112.0
pnpm exec supabase init
pnpm exec supabase --version
```

Expected: `2.110.0`. Keep generated configuration only after reviewing every
setting. Set PostgreSQL major version 17, JWT expiry 900 seconds, and GitHub
provider values exactly as the normative design specifies. The config uses
`env(SUPABASE_AUTH_GITHUB_CLIENT_ID)` and
`env(SUPABASE_AUTH_GITHUB_SECRET)`; no fallback secret is present.

Add package scripts:

```json
"check:supabase": "node scripts/check-supabase-contract.mjs",
"supabase:start": "supabase start",
"supabase:reset": "supabase db reset --local",
"supabase:test": "supabase test db",
"supabase:lint": "supabase db lint --local --level warning --fail-on error",
"supabase:stop": "supabase stop --no-backup"
```

Ignore only local Supabase runtime state and environment files recommended by
the generated config. Do not ignore migrations, tests, or configuration.

- [ ] **Step 5: Add the deterministic database workflow**

Create `.github/workflows/supabase.yml` for pull requests and pushes affecting
`supabase/**`, the checker, package manifests, or the workflow. Use Ubuntu,
checkout, pnpm 11.9.0, Node 24, exact frozen install, and the pinned local CLI.
Set job-only synthetic values for `SUPABASE_AUTH_GITHUB_CLIENT_ID` and
`SUPABASE_AUTH_GITHUB_SECRET` so config expansion is deterministic without a
production OAuth secret. Run:
Run:

```bash
pnpm check:supabase
pnpm supabase:start
pnpm supabase:reset
pnpm supabase:test
pnpm supabase:lint
pnpm supabase:stop
```

Put `supabase:stop` in an `if: always()` step. Do not use hosted credentials.

- [ ] **Step 6: Turn the configuration contract GREEN and commit**

At this checkpoint, validate every present Supabase artifact but do not require
a migration yet. Add the exact migration-surface requirement in Task 2 as a new
RED test; do not add a phase flag or bypass to repository configuration.

```bash
node --test scripts/tests/check-supabase-contract.test.mjs
pnpm check:supabase
git diff --check
git commit -m "build: add pinned Supabase contract harness"
```

---

### Task 2: Create the schema foundation and session-bound identity helpers

**Files:**

- Create: `supabase/migrations/20260804000000_context_relay_ciphertext_boundary.sql`
- Create: `supabase/tests/0001_context_relay_ciphertext_boundary_test.sql`
- Modify: `scripts/tests/check-supabase-contract.test.mjs`
- Modify: `scripts/check-supabase-contract.mjs`

**Relations created by this task:**

```text
public.accounts
public.device_bindings
public.device_certificates
public.sync_operations
public.sync_checkpoints
public.blob_manifests
public.pairing_requests
public.recovery_roots
public.github_installations
public.deletion_requests
context_relay_private.blob_upload_reservations
```

- [ ] **Step 1: Extend RED static tests to require the full surface**

Assert exact relation names, foreign-key account scoping, enum/check constants,
RLS enablement, indexes on every foreign key and policy column, owner role,
private schema, explicit privilege reset, and the five zero-argument identity
helpers.

```bash
node --test scripts/tests/check-supabase-contract.test.mjs
```

Expected RED: the migration does not exist.

- [ ] **Step 2: Add pgTAP structural RED assertions**

Start the local stack when available and create a test transaction with
`select plan(...)`. Assert:

- schemas, enum types, tables, primary keys, foreign keys, unique constraints,
  quota/ciphertext/crypto-width checks, seven-day deletion deadlines, and
  all-or-none signed revocation cutoff fields exist;
- all eleven relations have RLS enabled;
- all account foreign keys and helper hot-path columns are indexed;
- the exact five identity helpers have zero arguments, are stable security
  definers, use empty search paths, and are owned by
  `context_relay_rls_owner`;
- the private schema is not one of the API schemas; and
- no Context Relay relation appears in `pg_publication_tables` for
  `supabase_realtime`.

```bash
pnpm supabase:start
pnpm supabase:reset
pnpm supabase:test
```

Expected RED: migration objects are absent. If Docker is unavailable on the
developer machine, preserve the test as RED-by-inspection, run the static test,
and use the GitHub/local-stack gate before declaring Task 15 complete.

- [ ] **Step 3: Implement schemas, owner, enums, tables, and constraints**

Create objects in dependency order. Use `uuid` wire identifiers, `bytea` fixed-
width checks, `bigint` for unsigned bounded values, `jsonb` for frozen signed
arrays/clock payloads, and `timestamptz` audit columns. Set the account quota
default and check to exactly 524,288,000. Set operation ciphertext maximum to
4,194,304. Set blob-part maximum to 33,554,432.

Use compound unique keys and foreign keys that include `account_id` for device,
workspace, operation, checkpoint, manifest, and reservation relationships.
Every foreign-key column gets a supporting btree index in the same migration.

- [ ] **Step 4: Add the private current-session helpers**

Implement these zero-argument functions:

```sql
context_relay_private.current_session_id() returns uuid
context_relay_private.current_read_account_id() returns uuid
context_relay_private.current_write_account_id() returns uuid
context_relay_private.current_read_device_id() returns uuid
context_relay_private.current_write_device_id() returns uuid
```

`current_session_id` catches a malformed/missing claim and returns `NULL`.
Account/device helpers match both `auth.uid()` and the session ID, require an
active/unrevoked/unexpired binding, and distinguish read versus write account
state. Use `SECURITY DEFINER SET search_path = ''` with fully-qualified
references. Revoke all default function execution before exact grants.

- [ ] **Step 5: Add behavioral helper tests**

Seed deterministic UUIDs for:

```text
user A / account A / active, pending, revoked, expired devices
user B / account B / active device
user D / account D / active device on pending_delete account
```

Set `request.jwt.claims` and `ROLE authenticated` exactly as PostgREST does.
Assert correct read/write account/device results for active sessions and `NULL`
for pending, revoked, expired, absent, malformed, user/session mismatch, and
pending-delete write contexts. Change unrelated caller fields and prove helper
results do not change.

- [ ] **Step 6: Run focused gates and commit**

```bash
pnpm check:supabase
pnpm supabase:reset
pnpm supabase:test
pnpm supabase:lint
git diff --check
git commit -m "feat: add session-bound Supabase schema foundation"
```

Expected: all structural and identity-helper assertions pass. If the host lacks
Docker, static gates must pass and the database commands remain mandatory in CI
and hosted verification.

---

### Task 3: Lock down grants and account-scoped read policies

**Files:**

- Modify: `supabase/migrations/20260804000000_context_relay_ciphertext_boundary.sql`
- Modify: `supabase/tests/0001_context_relay_ciphertext_boundary_test.sql`
- Modify: `scripts/check-supabase-contract.mjs`
- Modify: `scripts/tests/check-supabase-contract.test.mjs`
- Create: `scripts/verify-supabase-realtime.mjs`
- Create: `scripts/tests/verify-supabase-realtime.test.mjs`
- Modify: `package.json`

**Authenticated read surface:**

```text
accounts
device_bindings
device_certificates
sync_operations
sync_checkpoints
blob_manifests (finalized only)
```

**Service-only lifecycle transitions:**

```sql
public.service_revoke_device_binding(
  p_account_id uuid,
  p_device_id uuid,
  p_cutoff_sequence bigint,
  p_cutoff_hash bytea,
  p_cutoff_signature bytea
) returns void

public.service_begin_account_deletion(p_account_id uuid) returns uuid

public.service_cancel_account_deletion(p_account_id uuid) returns void
```

The later Edge layer supplies account/device and signed evidence only after JWT,
binding, issuer, and signature validation. These functions are public-schema
RPCs only so PostgREST can route them; only `service_role` may execute them.

- [ ] **Step 1: Write RED privilege assertions**

Use `has_table_privilege`, `has_schema_privilege`, and
`has_function_privilege` to prove:

- `anon` has no privilege on any Context Relay relation or function;
- `authenticated` has only `SELECT` on the six read relations;
- `authenticated` has no relation privilege on pairing, recovery, installation,
  deletion, or reservation data;
- `service_role` has no direct select, insert, update, delete, or truncate
  privilege on any Context Relay relation;
- neither client role can truncate any relation; and
- default/public execution is absent from private functions.

Expected RED: no explicit grants exist.

- [ ] **Step 2: Implement the deny-first privilege block**

Revoke all relation, sequence, and function privileges from `PUBLIC`, `anon`,
`authenticated`, and `service_role` on Context Relay-owned objects. Grant only
schema usage and six table `SELECT` privileges
to `authenticated`, plus the exact zero-argument policy helper execution needed
by its policies. Preserve required Supabase platform privileges on `storage`
and `realtime`; do not issue broad revokes against provider-owned schemas.
Every public `service_*` wrapper introduced in this and later tasks revokes
execution from `PUBLIC`, `anon`, and `authenticated`, then grants it only to
`service_role`.

- [ ] **Step 3: Write RED two-user RLS tests**

As active user A, assert the visible primary-key sets for all six relations are
exactly A’s finalized/account-scoped fixtures, even when filters name B’s
account/device/workspace/storage IDs. Assert symmetric results for B. Assert
pending/revoked/expired sessions and `anon` see zero rows.

As user D in `pending_delete`, assert existing rows and finalized manifests are
still visible. Use `throws_ok` to prove every client mutation and truncate
attempt fails by privilege or RLS.

- [ ] **Step 4: Add exact read policies**

Create one `FOR SELECT TO authenticated` policy per read relation. Compare the
row’s `account_id` or `accounts.id` to a scalar subquery of
`current_read_account_id()`. `blob_manifests` additionally requires
`finalized_at IS NOT NULL`. Do not add policies to the four private-by-grant
relations or reservations.

- [ ] **Step 5: Prove spoofing and deletion behavior**

Add regression cases where A supplies B’s account/device values in filters and
synthetic payload JSON, and where the JWT subject/session combination is split
between A and B. Results remain empty or A-scoped. Transition D between active,
pending-delete, and active within one privileged test and prove only write
helper availability changes.

Implement the three service-only lifecycle transitions with account/binding row
locks. Revocation atomically stores all cutoff fields, changes binding state,
and increments both account epochs. Beginning deletion records exactly one
pending request with `statement_timestamp() + interval '7 days'` and changes
account state. Cancellation succeeds only before that deadline and returns the
account to active. Grant execution only to `service_role`; test idempotent
replays and invalid terminal transitions.

- [ ] **Step 6: Run focused gates and commit**

```bash
pnpm check:supabase
pnpm supabase:reset
pnpm supabase:test
pnpm supabase:lint
git diff --check
git commit -m "feat: enforce account-scoped Supabase reads"
```

---

### Task 4: Freeze immutable sync-operation and checkpoint storage

**Files:**

- Modify: `supabase/migrations/20260804000000_context_relay_ciphertext_boundary.sql`
- Modify: `supabase/tests/0001_context_relay_ciphertext_boundary_test.sql`
- Create: `supabase/tests/fixtures/sync_envelopes.sql`
- Modify: `scripts/check-supabase-contract.mjs`

- [ ] **Step 1: Add RED wire-shape tests**

Insert valid fixtures as the migration owner and assert every
`SyncOperationV1` and `CheckpointV1` routing/signature field round-trips without
numeric truncation or JSON shape changes. Use maximum legal ciphertext and
boundary numeric values in focused cases without printing ciphertext.

Add `throws_ok` cases for:

- ciphertext above 4,194,304 bytes;
- hashes, nonces, keys, or signatures with wrong byte lengths;
- negative sequence/epoch/size values;
- duplicate operation IDs and duplicate `(account, device, sequence)` tuples;
- cross-account compound references; and
- arrays beyond the SQL-enforced 10,000-item limit;
- operation insert on a pending-delete or quota-exhausted account; and
- an operation whose inline ciphertext exceeds the exact remaining quota by
  one byte.

Assert a valid privileged operation insert increments `accounts.used_bytes` by
exactly `octet_length(ciphertext)`. A duplicate/constraint-failing insert rolls
the increment back. Finalized blob bytes seeded for the fixture remain part of
the same `used + reserved <= limit` calculation.

Expected RED: incomplete checks or fixture columns fail.

- [ ] **Step 2: Complete exact envelope constraints and indexes**

Add only deterministic storage-level validation. Do not attempt to reimplement
canonical CBOR, Ed25519, X25519, XChaCha20-Poly1305, causal validation, or issuer
trust in SQL. Add a definer-owned before-insert trigger that locks the account,
requires `active`, checks the combined inline-operation/blob/reservation quota,
and increments used bytes in the same transaction. Unique/constraint failures
roll the trigger update back automatically. There is no standalone operation
delete/refund path; purge removes the account and its children together. Add
pagination indexes for account/workspace/receipt ordering, device sequence
lookup, checkpoint creator/frontier lookup, and manifest storage lookup.

- [ ] **Step 3: Prove client immutability exhaustively**

For both A and B, assert `INSERT`, `UPDATE`, `DELETE`, `TRUNCATE`, and conflict
upsert attempts fail on operations and checkpoints even when rows carry the
caller’s legitimate account/device IDs. Confirm read-only pagination continues
to work.

- [ ] **Step 4: Prove Realtime publication exclusion**

Assert no Context Relay table appears in `pg_publication_tables` for
`supabase_realtime`. Extend the static checker to reject any future
`ALTER PUBLICATION ... ADD TABLE` targeting those relations.

- [ ] **Step 5: Run focused gates and commit**

```bash
pnpm check:supabase
pnpm supabase:reset
pnpm supabase:test
pnpm supabase:lint
git diff --check
git commit -m "feat: add immutable ciphertext sync records"
```

---

### Task 5: Add atomic quota reservations and chunked private Storage

**Files:**

- Modify: `supabase/migrations/20260804000000_context_relay_ciphertext_boundary.sql`
- Modify: `supabase/tests/0001_context_relay_ciphertext_boundary_test.sql`
- Create: `supabase/tests/fixtures/storage_objects.sql`
- Modify: `scripts/check-supabase-contract.mjs`
- Modify: `scripts/tests/check-supabase-contract.test.mjs`

**Service-only function contracts:**

```sql
public.service_reserve_blob_upload(
  p_account_id uuid,
  p_device_id uuid,
  p_storage_id uuid,
  p_ciphertext_sha256 bytea,
  p_part_sizes bigint[],
  p_expires_at timestamptz
) returns void

public.service_finalize_blob_upload(p_storage_id uuid) returns void

public.service_release_blob_upload(
  p_storage_id uuid,
  p_terminal_state context_relay_private.upload_reservation_state
) returns void

context_relay_private.can_upload_ciphertext_object(
  p_bucket_id text,
  p_name text,
  p_metadata jsonb
) returns boolean

context_relay_private.can_read_ciphertext_object(
  p_bucket_id text,
  p_name text
) returns boolean
```

Only `service_role` executes these transitions. Task 16 must pass account/device
values derived from a verified JWT, not request fields. `authenticated` may
execute only the two boolean policy predicates. Their arguments are candidate
Storage row attributes, never identity; direct reservation reads remain denied.

- [ ] **Step 1: Write RED quota state-machine tests**

Assert reservation:

- locks and increments `reserved_bytes` in the same transaction;
- rejects inactive accounts, non-active/revoked devices, expired reservations,
  zero/negative/oversized parts, more than sixteen parts, invalid digest size,
  duplicate storage IDs, and totals above 524,288,000;
- permits the exact remaining quota byte and rejects one byte beyond it; and
- preserves `used + reserved <= limit` after every failure.

Use two transactions where the local runner supports concurrency to prove row
locking prevents over-reservation. The deterministic single-session boundary
test remains mandatory everywhere.

- [ ] **Step 2: Implement reservation with an account row lock**

Validate input before mutation, then `SELECT ... FOR UPDATE` the account. Check
account/device service invariants, counters, and uniqueness. Insert the private
reservation and increment the account counter atomically. Generate no signed
URL and perform no Storage write from SQL.

- [ ] **Step 3: Write RED finalize/refund tests**

Seed provider-owned `storage.objects` metadata as the database owner. Assert
finalization rejects missing, extra, duplicate, wrong-path, wrong-index, and
wrong-sized objects. A valid set creates one finalized manifest, moves exact
bytes from reserved to used, and is idempotent only in the already-finalized
terminal state. Expiry/cancel releases reserved bytes exactly once and never
reduces used bytes.

- [ ] **Step 4: Implement exact manifest finalization and release**

Lock reservation and account in stable order. Derive every expected path from
account/storage/index and compare exact Storage metadata sizes. Insert the
manifest and transition counters in one transaction. Reject terminal-state
changes other than the explicitly idempotent replay. Grant execution to
`service_role` only.

- [ ] **Step 5: Write RED Storage policy tests**

Assert:

- bucket `ciphertext` is private and limited to 33,554,432 bytes per object;
- A can insert only a reserved A path at the exact part index and size;
- A cannot insert B paths, extra indices, traversal-shaped names, wrong sizes,
  duplicate/upsert objects, or objects for pending-delete accounts;
- incomplete/reserved objects are unreadable to clients;
- finalized A parts are readable by A but not B;
- pending-delete D can read finalized D parts but cannot upload; and
- revoked/pending/expired sessions cannot read or upload.

Also assert `authenticated` cannot select
`context_relay_private.blob_upload_reservations` even though its policy
predicate can authorize one exact object.

Use policy evaluation with realistic `storage.objects.name`, bucket, owner, and
metadata. Test actual Storage HTTP calls during hosted verification.

- [ ] **Step 6: Add bucket and exact object policies**

Insert/update the bucket configuration in the migration. Create authenticated
`INSERT` and `SELECT` policies on `storage.objects` restricted to the
`ciphertext` bucket. Each policy calls the matching hardened definer predicate,
which derives current write/read identity, validates a canonical three-component
path, and performs the private live-reservation/finalized-manifest lookup with
exact part index and metadata size. Both predicates use empty search paths,
fully-qualified objects, no dynamic SQL, and a non-login owner. Add no
authenticated `UPDATE` or `DELETE` policy and no reservation table grant.

- [ ] **Step 7: Run focused gates and commit**

```bash
pnpm check:supabase
pnpm supabase:reset
pnpm supabase:test
pnpm supabase:lint
git diff --check
git commit -m "feat: add quota-safe ciphertext blob storage"
```

---

### Task 6: Add private Realtime pull-hint authorization

**Files:**

- Modify: `supabase/migrations/20260804000000_context_relay_ciphertext_boundary.sql`
- Modify: `supabase/tests/0001_context_relay_ciphertext_boundary_test.sql`
- Modify: `scripts/check-supabase-contract.mjs`
- Modify: `scripts/tests/check-supabase-contract.test.mjs`

**Topic and payload contract:**

```json
{
  "topic": "account:<account_uuid>:sync",
  "event": "sync_hint",
  "payload": { "version": 1, "kind": "pull_now" },
  "private": true
}
```

- [ ] **Step 1: Write RED policy and topic tests**

Assert A can authorize `SELECT` on `realtime.messages` only for A’s exact sync
topic. A cannot receive B, malformed, prefix/suffix-expanded, broadcast-send,
or presence topics. Pending/revoked/expired/anonymous sessions fail. Existing
active pending-delete sessions may receive the pull hint for export.

- [ ] **Step 2: Add the minimal private Broadcast policy**

Create a named `FOR SELECT TO authenticated` policy using `realtime.topic()`
and the scalar read-account helper. Require the exact
`account:<uuid>:sync` construction. Add no authenticated insert policy, and do
not change provider-wide grants on `realtime.messages`.

- [ ] **Step 3: Freeze the payload contract statically**

Add the JSON shape to the checker as an allowlist used by later Edge work. The
checker rejects operation IDs, device IDs, record IDs, project IDs, ciphertext,
titles, deletion state, or arbitrary payload fields in the contract. Confirm
again that Postgres Changes publication is empty for Context Relay.

- [ ] **Step 4: Write RED orchestration tests for real channels**

Build the verifier as an importable state machine with injected Supabase
clients/channels. Unit tests prove it:

- subscribes A and B to their own exact private topics;
- attempts and rejects A-to-B and B-to-A subscriptions;
- sends the frozen hint with a service client and accepts delivery only on the
  intended account channel;
- invokes `service_revoke_device_binding`, closes A’s existing channel, and
  proves a fresh A authorization fails with the same session;
- cleans up channels and ephemeral Auth users on success or failure; and
- never logs access, refresh, service, anon, OAuth, or password values.

```bash
node --test scripts/tests/verify-supabase-realtime.test.mjs
```

Expected RED: the verifier does not exist.

- [ ] **Step 5: Implement the local/hosted WebSocket verifier**

Use pinned `@supabase/supabase-js` clients. The executable has `prepare`,
`verify`, and `cleanup` modes. `prepare` creates two uniquely named ephemeral
Auth users, signs them in, writes tokens only to an explicitly supplied file
under `/private/tmp`, and prints only user/session UUIDs needed for privileged
SQL fixture seeding. `verify` reads that private file, performs the real channel
matrix, sends service hints, invokes the service-only revocation RPC, forces
disconnect/re-subscribe, and emits pass/fail assertions without secrets.
`cleanup` removes channels/users and the caller removes the temporary file.

The verifier requires URL/keys/test credentials through environment variables;
it has no defaults for hosted credentials. Add:

```json
"verify:supabase-realtime": "node scripts/verify-supabase-realtime.mjs"
```

Run it against the local stack after seeding matching account/binding rows from
the printed safe identifiers. Record that an already-authorized channel is
forcibly closed and that a fresh authorization fails; the configured 900-second
JWT expiry remains the upper bound if a client does not force reauthorization.

- [ ] **Step 6: Run focused gates and commit**

```bash
pnpm check:supabase
node --test scripts/tests/verify-supabase-realtime.test.mjs
pnpm supabase:reset
pnpm supabase:test
pnpm supabase:lint
git diff --check
git commit -m "feat: authorize private Supabase sync hints"
```

---

### Task 7: Provision and verify the zero-cost hosted project

**Files:**

- Create: `docs/verification/task-15.md`
- Modify: `.gitignore` only if the official link command produces an unignored
  local state path
- Do not commit: `.env*`, `supabase/.temp/**`, passwords, access tokens, anon
  keys, service keys, OAuth values

- [ ] **Step 1: Create the acceptance ledger before remote mutation**

Record branch/commit, exact CLI version, static test results, local-stack
availability, migration checksum, and every acceptance row with status
`unverified`. Include no secret values.

- [ ] **Step 2: Reconfirm zero recurring cost and create West US project**

Use the authenticated Supabase organization already connected to this task.
Request the current creation cost. Continue only when it reports exactly
`$0/month`. Confirm that zero amount, then create one project named
`Context Relay` in `us-west-1`. Record the project reference and region, not its
database password.

- [ ] **Step 3: Wait for health and inspect the untouched project**

Poll project state until active. List migrations, public tables, and extensions
without mutation. Confirm there is no pre-existing Context Relay schema/data
that would be overwritten.

- [ ] **Step 4: Apply the reviewed migration once**

Apply the exact committed migration through the Supabase migration API. Verify
the recorded migration version and checksum-equivalent file content. Do not run
`db reset`, destructive DDL, or ad hoc schema edits against the hosted project.

- [ ] **Step 5: Configure free GitHub OAuth**

Create or reuse a GitHub OAuth App dedicated to Context Relay with the project
homepage and callback:

```text
https://<project-ref>.supabase.co/auth/v1/callback
```

Store client ID/secret only in the Supabase Auth provider configuration. Set
the site/redirect allowlist to the local desktop callback contract already
owned by the app and set hosted JWT expiry to exactly 900 seconds. This task
configures the provider and callback; Task 17 owns the application sign-in and
account lifecycle flow. If an account interstitial requires the user’s private
credential entry, leave only that UI action unresolved and continue every
database verification step; do not expose or request the credential in chat.

- [ ] **Step 6: Run hosted SQL isolation tests**

Execute a transaction that seeds synthetic Auth/account/device/ciphertext
fixtures, sets realistic JWT claims, and repeats the representative pgTAP
matrix. Roll the transaction back. At minimum prove:

- A cannot select B under filters or joins;
- pending/revoked/expired/malformed sessions see no data;
- `anon` sees no Context Relay row;
- authenticated direct operation mutation fails;
- pending deletion is read-only;
- A cannot authorize B Storage or Broadcast access; and
- revocation denies the next policy evaluation.

Do not create real users or upload user data for this test.

- [ ] **Step 7: Exercise hosted Storage APIs**

With synthetic short-lived test JWTs or a reversible test identity, reserve a
small two-part blob through the privileged test boundary. Prove exact upload
paths work, wrong account/size/upsert fails, incomplete parts are unreadable,
finalization makes only the owner’s parts readable, and revocation blocks the
next download. Remove all test objects and rows afterward using service-only
cleanup.

- [ ] **Step 8: Exercise hosted Realtime WebSockets**

Run the committed verifier’s `prepare` mode with an ephemeral file under
`/private/tmp`, seed matching account/device bindings through one privileged SQL
transaction, then run `verify`. Prove A and B receive only their own service
hints, cross-topic subscription is rejected, revocation plus forced
reauthorization rejects A’s same session, and the private payload contains only
`version` and `kind`. Run `cleanup`, delete the temporary token file, and remove
all synthetic database rows. Record assertions and timestamps, never values of
keys/tokens/passwords.

- [ ] **Step 9: Prove fresh-auth lifecycle ownership**

Record the Task 17 contract that deletion begin/cancel must check the most
recent credential-bearing `amr` timestamp is no older than 300 seconds. A
refreshed JWT `iat` is insufficient. Task 15 database transition tests prove the
seven-day state machine; Task 17 application tests will prove the reauthentication
gate before invoking its service-only RPC.

- [ ] **Step 10: Run security and performance advisors**

Capture current Supabase advisor results. Fix every release-blocking warning
with a new forward migration and regression test. Document informational
findings with exact rationale; do not suppress or ignore them silently.

- [ ] **Step 11: Complete the ledger and commit**

```bash
pnpm check:supabase
git diff --check
git commit -m "docs: verify the Supabase ciphertext boundary"
```

The ledger separates locally executed, CI-capable, and hosted proof. It does
not mark a Docker-only command as locally executed when this Mac lacks Docker.

---

### Task 8: Full review, regression gates, and Task 15 checkpoint

**Files:**

- Modify only files required by validated review findings
- Modify: `docs/verification/task-15.md`

- [ ] **Step 1: Run an independent security review**

Review the complete Task 15 diff for account confusion, JWT/session parsing,
RLS recursion, privilege escalation, unsafe definer ownership/search paths,
cross-account foreign keys, Storage prefix bypass, quota races, counter drift,
Realtime metadata leaks, and deletion/revocation gaps. Every validated finding
gets a failing regression test before its fix.

- [ ] **Step 2: Run an independent correctness review**

Review migration reset determinism, forward migration safety, pgTAP quality,
CI cleanup, config/lockfile consistency, protocol field fidelity, index coverage,
and documentation truthfulness. Fix and re-review until no actionable findings
remain.

- [ ] **Step 3: Run Task 15 focused gates from a clean database**

```bash
pnpm install --frozen-lockfile
pnpm check:supabase
node --test scripts/tests/check-supabase-contract.test.mjs
pnpm supabase:start
pnpm supabase:reset
pnpm supabase:test
pnpm supabase:lint
pnpm supabase:stop
```

Expected: all pass. The hosted migration and advisors must also remain green.

- [ ] **Step 4: Run workspace regression gates**

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
pnpm lint
pnpm typecheck
pnpm test --run
pnpm build
pnpm check:bindings
pnpm check:schemas
pnpm license:check
git diff --check
git status --short
```

Do not modify unrelated Task 14 behavior to make an environment-specific gate
pass. Record a precisely reproduced pre-existing failure instead.

- [ ] **Step 5: Reconcile every acceptance assertion**

The Task 15 ledger must contain direct evidence that:

- user A cannot select, insert, subscribe to, or blob-access user B;
- revoked sessions fail the next sensitive authorization and Realtime refresh
  is bounded by the 900-second JWT lifetime;
- a client device ID cannot affect authorization;
- anonymous access is absent;
- operation-log mutation is service-only;
- quota and Storage part invariants are atomic and exact;
- pending deletion is read/export-only; and
- security/performance advisors contain no release blocker.

- [ ] **Step 6: Create the final implementation checkpoint**

```bash
git status --short
git log --oneline --decorate -10
git commit -m "feat: add ciphertext-only Supabase schema and RLS"
```

Create the final commit only if review fixes or ledger reconciliation leave
tracked changes; otherwise the already-reviewed task commits constitute the
checkpoint and the branch head is recorded unchanged. Do not push or merge
without a separate explicit publication request.

## Completion Evidence

Task 15 is complete only when `docs/verification/task-15.md` records:

- exact committed migration and CLI versions;
- green static contract tests;
- green pgTAP and database lint on a fresh Supabase stack;
- the zero-cost project reference and `us-west-1` region;
- hosted two-user/session/deletion isolation queries;
- hosted Storage upload/read/revocation behavior;
- absence from Postgres Changes publication;
- GitHub OAuth callback/provider status without secret material;
- current security and performance advisor results;
- independent security and correctness review dispositions; and
- full workspace regression-gate results.
