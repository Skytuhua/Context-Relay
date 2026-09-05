# Supabase Ciphertext Boundary Design

**Date:** 2026-08-04

**Status:** Approved through the explicit instruction to continue without further questions

**Roadmap task:** Task 15 — Supabase project, ciphertext schema, and row-level security

## Summary

Context Relay will add a free-tier Supabase backend that stores encrypted sync
material and the minimum routing metadata needed to move it between authorized
devices. Supabase is not a trusted source of plaintext, device identity, causal
truth, or authorization assertions supplied by a client. Clients continue to
encrypt, sign, verify, and reconcile locally.

The database boundary derives the current Context Relay account from both
`auth.uid()` and the standard Supabase JWT `session_id` claim. That session must
map to an active, unexpired device binding. Callers never select an account or
device by passing identifiers to an authorization helper. Existing active
sessions may read and export while an account is `pending_delete`; writes and
new bindings require an `active` account. Revocation is enforced on the next
Database, Storage, or Edge authorization check. An already-authorized Realtime
socket is bounded by short JWT lifetime and forced reauthentication.

The Data API exposes six read-only account-scoped relations. Operation-log
mutation, pairing, recovery material, GitHub installation state, deletion
requests, quota reservations, and authorization helpers remain private or
service-only. Realtime carries only a private account-scoped “pull now” hint;
it never publishes operation rows. Encrypted logical blobs are split into
ordered Storage objects of at most 32 MiB so the protocol’s 500 MiB logical
limit remains compatible with Supabase Free’s per-object limit.

## Goals

- Provision one West US Supabase project whose recurring project cost is zero.
- Configure local and hosted GitHub OAuth without committing client secrets.
- Store only signed ciphertext envelopes, encrypted blob parts, public device
  keys, signatures, and necessary routing/account metadata.
- Bind every user-facing authorization decision to the authenticated user and
  current active device session.
- Make cross-account reads, writes, subscriptions, and blob access impossible
  through normal Supabase roles.
- Deny anonymous access and direct operation-log mutation.
- Keep all explicit grants and RLS policies reviewable in one migration.
- Account atomically for at most 500 MiB of used plus reserved ciphertext per
  Context Relay account.
- Preserve read/export access during the deletion grace state while denying
  all writes and new sessions.
- Prove the boundary with pgTAP tests covering two users, pending, active, and
  revoked devices, spoofed identifiers, deletion state, grants, Storage, and
  Realtime.
- Run schema tests and database linting in continuous integration and record
  live-project advisor results in the Task 15 verification ledger.

## Non-goals

- Uploading plaintext, recovery phrases, private device keys, content keys, or
  GitHub access tokens to public relations or Storage.
- Trusting Supabase to validate signatures, causal history, checkpoints, or
  decryption results.
- Implementing signed-operation submission, pairing approval, recovery, blob
  ticket, GitHub ingestion, or deletion Edge Functions. Those APIs are Tasks
  16 and 17.
- Implementing desktop online-sync behavior. This task establishes and proves
  the hosted authorization and persistence boundary.
- Publishing sync rows through Postgres Changes.
- Purchasing an Apple Developer membership, a paid Supabase plan, a custom
  domain, or any other paid resource.
- Granting a browser or desktop client the Supabase `service_role` key.

## Options Considered

### 1. Public read model plus private write services — selected

Account-scoped read relations are available to the authenticated role through
RLS. Sensitive state and all authoritative writes are private or service-only.
This keeps client pulls simple while leaving signature verification, replay
checks, quota transitions, pairing decisions, and deletion orchestration behind
the later Edge Function boundary.

### 2. Edge Functions for every read and write

This would reduce the Data API surface, but it would duplicate account-scoped
pagination and make RLS less useful as a defense in depth. It also makes Task 15
dependent on Task 16 before the core isolation boundary can be tested.

### 3. Direct authenticated writes guarded only by RLS

RLS can isolate accounts, but it cannot establish that a submitted operation
has a valid device signature, correct sequence, trusted issuer, or acceptable
causal frontier. Direct writes would also let a caller choose security-sensitive
identity fields. This option is rejected.

### 4. One Storage object per logical blob

The protocol permits 500 MiB logical blobs while Supabase Free permits smaller
individual objects. A one-object design would make valid protocol values fail
on the selected free plan. Ordered 32 MiB parts preserve the protocol limit and
leave margin below the hosted object ceiling.

## Trust and Identity Model

### Stable account identity

`public.accounts.id` is the stable Context Relay `AccountId` UUIDv7. It is not
`auth.users.id`. `owner_user_id` references the Supabase Auth user and is unique
in Task 15, establishing one Context Relay account per hosted login while
leaving the wire identifier independent of the identity provider.

Every account-scoped table carries a non-null `account_id` foreign key. Every
compound relationship includes `account_id` so a valid row from one account
cannot be attached to another account’s object.

### Session-to-device binding

`public.device_bindings` binds this tuple:

```text
auth user id | JWT session_id | Context Relay account id | device id
```

The session identifier is unique. An `(account_id, device_id)` may have only
one live binding, and historical revoked rows remain auditable. A usable
binding has state `active`, no `revoked_at`, and either no expiry or an expiry
in the future. Pending bindings cannot read or write. Revoked bindings cannot
read, write, subscribe, or access Storage on the next policy evaluation.

The client-supplied `device_id`, `account_id`, issuer fields, JSON claims other
than the Auth-issued user/session claims, query filters, Storage object names,
and Realtime topics never establish identity.

### Read and write contexts

Two zero-argument private helpers define the entire RLS identity surface:

- `context_relay_private.current_read_account_id()` returns the single account
  for the current Auth user and active device session when the account is
  `active` or `pending_delete`.
- `context_relay_private.current_write_account_id()` returns the account only
  when the same binding is usable and the account is `active`.

Companion zero-argument helpers return the current bound device for policies
that need it. They read `auth.uid()` and `auth.jwt()->>'session_id'` internally,
return `NULL` for missing or malformed claims, and accept no caller-selected
identity arguments.

Storage policies use two additional hardened predicates,
`can_upload_ciphertext_object(bucket_id, name, metadata)` and
`can_read_ciphertext_object(bucket_id, name)`. Their arguments are only the
candidate Storage row attributes supplied by PostgreSQL policy evaluation;
they never accept user, account, device, or session identity. They derive the
current identity through the zero-argument helpers and perform the reservation
or finalized-manifest lookup as the definer. This preserves a private
reservation table while allowing policy evaluation. Authenticated callers can
execute the boolean predicates but cannot select reservations directly.

Helpers and predicates are `STABLE SECURITY DEFINER`, have `search_path = ''`,
fully qualify every object, contain no dynamic SQL, and are owned by a dedicated
`NOLOGIN` role. Default function execution is revoked. Only the exact execution
needed by `authenticated` policies is granted. The private schema is not added
to the Data API’s exposed schemas.

### Service boundary

The `service_role` remains an Edge Function secret. Later functions must derive
the user, session, account, and device from the verified incoming JWT before
calling service-only database operations. They must load the trusted device
certificate and issuer chain from the database, validate certificate admission
against that database-trusted chain, and verify the submitted operation against
the admitted certificate. Verifying a certificate against an issuer embedded
only in the same request is forbidden. Request fields with matching names are
payload claims to validate, never authorization inputs. Clients independently
revalidate the complete chain because a cloud operator remains untrusted.

## Database Layout

### Schemas and owner

- `public` contains the six authenticated read relations plus four private-by-
  grant service relations required by the roadmap.
- `context_relay_private` contains quota reservations, identity/policy helpers,
  and internal transition implementations. It is omitted from API exposed
  schemas.
- Narrow `public.service_*` wrapper functions expose only the transitions later
  Edge Functions must call through PostgREST. They are definer-owned, accept no
  JWT/service secret values, and grant execution only to `service_role`; client
  roles cannot invoke them.
- `storage` and `realtime` keep their Supabase-owned relations; this migration
  adds only the narrow bucket and policies required by Context Relay.
- `context_relay_rls_owner` is a `NOLOGIN NOINHERIT` owner for the Context
  Relay relations and definer functions. It has no dynamic login path.

All relations enable RLS. Public-schema placement does not imply access: table,
sequence, schema, and function privileges are revoked first, then granted
explicitly. No Context Relay table relies on Supabase’s historical default
grants.

`service_role` receives no direct `SELECT`, `INSERT`, `UPDATE`, `DELETE`, or
`TRUNCATE` privilege on Context Relay relations. Its `BYPASSRLS` attribute is
therefore insufficient to mutate them. It receives only exact execution on
reviewed `public.service_*` wrappers, which run as the non-login relation owner.
Future Edge work adds a wrapper when it needs a new read or transition; it does
not restore direct table access.

### Enumerations

Private enum types freeze the state machines:

- device: `pending`, `active`, `revoked`;
- account deletion: `active`, `pending_delete`, `purged`;
- pairing: `pending`, `approved`, `rejected`, `expired`, `cancelled`;
- upload reservation: `reserved`, `finalized`, `expired`, `cancelled`.

`purged` is a terminal audit value used during orchestration. The final deletion
worker removes user-readable rows and Storage objects before or as the account
becomes purged.

### `public.accounts`

Stores the stable account, Auth owner, deletion state/timestamps, control and
key epochs, quota limit, used bytes, reserved bytes, and timestamps. Checks
enforce non-negative counters and:

```text
used_bytes + reserved_bytes <= quota_limit_bytes = 524,288,000
```

`used_bytes` is the sum of `octet_length(sync_operations.ciphertext)` for
retained operations plus finalized logical blob ciphertext bytes. Routing
metadata, signatures, public keys, and private service bookkeeping are not
counted. A before-insert operation trigger locks the account, requires an active
account, enforces the invariant, and increments the inline-ciphertext portion in
the same transaction. A failed uniqueness or append transaction rolls the
counter change back.

Authenticated users may select only the row returned by the read helper. Only
service-only transition functions mutate accounts.

### `public.device_bindings`

Stores binding ID, account, Auth user, JWT session, device, state, expiry,
revocation reason/timestamps, signed cutoff sequence/hash/signature, and audit
timestamps. Fixed-width cutoff fields are all-null before revocation and
all-present after a signed revocation. Auth user and account owner must agree.
Authenticated users may select bindings only for their read account; they cannot
insert or mutate them directly. Account/session/device columns are indexed for
the helper hot path.

New bindings are denied when an account is `pending_delete`. Revocation updates
the row before subsequent service work so the next policy evaluation fails.

### `public.device_certificates`

Stores the signed `DeviceCertificateV1` wire fields: account, workspace,
control epoch, request nonce, device, issuer kind, issuer device or recovery
public key, issuer signing public key, device signing public key, device wrapping
public key, signature, and creation timestamp. Fixed-width cryptographic fields
have byte-length checks. Authenticated sessions may select certificates for
their read account; only the later pairing service may insert them.

The cloud stores and routes the certificate. The trusted Edge admission path
must validate a new certificate against an issuer already trusted in the
database before making it usable, but clients repeat certificate and issuer-
chain verification and never treat server admission as cryptographic truth.

### `public.sync_operations`

Stores the immutable signed `SyncOperationV1` envelope without decrypting it:
schema version, all UUID routing IDs, record/mutation kinds, device sequence,
causal frontier JSON, epochs, previous-device hash, nonce, ciphertext,
ciphertext hash, blob-reference JSON, hybrid logical clock, signature, and
server receipt time.

Checks enforce fixed widths, ciphertext at most 4 MiB, non-negative numeric
ranges, and bounded JSON array sizes where SQL can do so cheaply. Unique
constraints cover operation ID and `(account_id, device_id, device_sequence)`.
The service submission path later performs canonical encoding, trusted-issuer
and admitted-certificate lookup, signature, frontier, replay, and blob-reference
validation in one transaction. The database quota trigger then locks the account
and charges the inline ciphertext before insert can commit.

Authenticated users may select their read account’s rows. `anon` and
`authenticated` have no `INSERT`, `UPDATE`, `DELETE`, or `TRUNCATE` privileges.
No permissive write policy exists. The append service has only the narrow
privileges it needs.

### `public.sync_checkpoints`

Stores a server identifier plus account/workspace, schema version, prior
checkpoint hash, causal frontier JSON, state hash, key epoch, creator device,
hybrid logical clock, signature, and receipt time. It is immutable to clients
and readable only through the read-account helper. Clients validate the signed
checkpoint and distrust rollback or omission by the server.

### `public.blob_manifests`

Represents one logical encrypted blob. It stores account, opaque `storage_id`,
ciphertext digest, exact logical byte count, ordered part-size array, part
count, creating device, finalized timestamp, and audit timestamps. Each part is
greater than zero and at most 33,554,432 bytes; total parts equal the declared
logical ciphertext size and never exceed 524,288,000 bytes.

Only finalized manifests are visible through the authenticated read policy.
Reservations and incomplete uploads are private. Clients verify the assembled
logical digest from the signed operation’s `BlobRef` after download.

### Private-by-grant roadmap relations

These public-schema relations enable later service work but receive no
`anon`/`authenticated` table privileges or user RLS policies in Task 15:

- `pairing_requests`: opaque request payload/digest, requester public material,
  bounded code digest, state, expiry, and decision metadata;
- `recovery_roots`: account-scoped recovery signing/wrapping public keys and
  encrypted recovery metadata, never the phrase or derived private keys;
- `github_installations`: installation identity and encrypted token reference
  metadata, never a plaintext GitHub token;
- `deletion_requests`: grace deadline, request/cancel/purge audit timestamps,
  and state transition evidence.

Service policies are restrictive even though the service role normally bypasses
RLS. This keeps accidental lower-privilege grants from becoming sufficient.

Service-only definer functions own device revocation and deletion transitions.
Revocation locks account and binding rows, stores the complete signed cutoff,
changes device state, and advances control/key epochs atomically. Deletion begin
locks the account, creates exactly one request with a database-derived seven-day
deadline, and changes the account state. Cancellation succeeds only before the
deadline. Public `service_*` wrappers make these transitions callable by a later
Edge Function without exposing the private schema; they are not granted to
client roles.

### `context_relay_private.blob_upload_reservations`

Stores account, storage ID, expected total, exact part-size array, reservation
state, creating device, expiry, and audit timestamps. It is neither selectable
nor mutable by `anon` or `authenticated`.

The reservation service locks the account row, rejects a non-active account,
checks `used + reserved + requested <= 500 MiB`, adds to `reserved_bytes`, and
inserts the reservation in the same transaction. Storage paths are derived as:

```text
<account_uuid>/<storage_uuid>/<zero-padded-eight-digit-part>.bin
```

No upsert is allowed. Every part has a unique expected path and exact expected
size. Finalization locks the same account and reservation, reads actual Storage
metadata, rejects missing, extra, duplicate, or wrong-sized parts, creates the
manifest, subtracts expected bytes from reserved, and adds actual bytes to used
in one transaction. Cancellation, expiry, or failed finalization refunds the
reservation exactly once. Cleanup deletes orphaned objects with service
credentials after the database transition.

These transitions have narrow public `service_*` wrappers granted only to
`service_role` in Task 15. The Task 16 Edge Function will supply account and
device values derived from the verified JWT, not from request fields, and
return upload paths rather than signed URLs.

## Privilege and RLS Matrix

| Surface | `anon` | `authenticated` | Authorization |
|---|---|---|---|
| `accounts` | none | `SELECT` | row ID equals current read account |
| `device_bindings` | none | `SELECT` | account equals current read account |
| `device_certificates` | none | `SELECT` | account equals current read account |
| `sync_operations` | none | `SELECT` | account equals current read account |
| `sync_checkpoints` | none | `SELECT` | account equals current read account |
| `blob_manifests` | none | `SELECT` | finalized and account equals current read account |
| four private-by-grant relations | none | none | service-only |
| quota reservations/helpers | none | policy helpers only | private/service-only |
| public `service_*` wrappers | none | none | `service_role` execute only |
| `storage.objects` read | none | `SELECT` | finalized object for current read account |
| `storage.objects` upload | none | `INSERT` | active reservation for current write account and exact path/size |
| `storage.objects` update/delete | none | none | service cleanup/finalization only |
| `realtime.messages` receive | none | `SELECT` | private topic for current read account |
| operation/checkpoint Postgres Changes | none | none | not published |

Every policy names `TO authenticated`, wraps stable Auth/helper calls in scalar
`SELECT` expressions for planner caching, and has a supporting index on policy
and foreign-key columns. No policy uses caller-provided account/device fields to
choose an identity.

## Storage Boundary

The migration creates a private `ciphertext` bucket with a hosted per-object
limit compatible with 32 MiB parts. MIME type is an optional routing hint only;
content is opaque.

The upload policy requires:

1. the authenticated write helper returns the account in path component one;
2. component two identifies a live, unexpired reservation for that account;
3. the file name maps to an existing part index in the reservation;
4. the Storage metadata size equals the reserved size for that index; and
5. no object already exists at the path.

There is no authenticated update policy, so `upsert` cannot replace a part.
There is no client delete policy. The download policy joins the exact object
path to a finalized manifest belonging to the read account. A pending-deletion
account can download existing finalized ciphertext; it cannot reserve or upload
new data.

No signed upload or download URL is part of the design. A URL that outlives the
JWT authorization check would weaken revocation. Clients use JWT-authenticated
Storage requests, and later Edge APIs return exact upload contracts, not bearer
URLs. The Storage RLS policies call the hardened row-attribute predicates; the
client role never receives `SELECT` on the private reservation relation.

## Realtime Boundary

`sync_operations` and other Context Relay tables are not added to
`supabase_realtime` publication. In particular, Postgres Changes `DELETE`
events are unsuitable because old-row filtering can disclose metadata outside
the intended read policy.

The later submission service sends a private Broadcast event on:

```text
account:<account_uuid>:sync
```

The event contains only a version and `pull_now` kind. It contains no operation,
record, device, project, title, ciphertext, or deletion metadata. A
`realtime.messages` RLS policy accepts subscriptions only when the account topic
equals the caller’s current read account. Client broadcast sends are not
granted; the service sends after a committed append.

Existing WebSocket authorization can remain cached until the channel’s JWT is
refreshed. Clients therefore use a short Auth JWT lifetime, refresh before
expiry, and tear down the socket on refresh or authorization failure. Database,
Storage, and Edge requests check revocation anew. The system does not claim to
erase a request or message that was already authorized in flight.

## Deletion Semantics

The account state machine is:

```text
active -> pending_delete -> purged
              |
              +----------> active (cancel within grace period)
```

Entering `pending_delete` atomically records a deletion request with a deadline
exactly seven days after the request and changes the account state. Existing
active device sessions retain read/export access to existing rows and finalized
blobs. The write helper returns `NULL`, so operation submission, checkpoint
creation, upload reservation, upload, pairing, recovery mutation, GitHub
ingestion, and new device bindings fail.

Cancellation within the grace period restores `active` through the service
transition. Purge revokes bindings first, removes Storage objects and account
data idempotently, records terminal audit evidence where retention permits, and
then removes the Auth identity according to the Task 17 orchestration contract.

Beginning or cancelling deletion is a destructive account-lifecycle action and
requires fresh credential-bearing authentication no more than five minutes old.
The future Edge layer checks the most recent Supabase `amr` authentication
method timestamp, not JWT `iat`, because token refresh alone is not
reauthentication. If the Auth token lacks suitable AMR evidence, the user must
complete GitHub reauthentication before the transition is called.

## Revocation Semantics

Revocation changes the binding state, stores the client-signed cutoff evidence,
and advances the account control/key epochs in one transaction. The next RLS
helper call returns `NULL`, denying Data API reads, Storage operations, and new
Realtime subscription authorization. Sensitive Edge Functions must perform
their own current-binding check immediately before mutation even if they
verified the JWT earlier in the request.

Short JWT expiry bounds an already-authorized Realtime channel. Tests prove the
database-side immediate property and the policy that a fresh authorization with
the same JWT session fails. The product describes this boundary precisely; it
does not promise recall of already-delivered ciphertext.

## GitHub OAuth Configuration

Local configuration enables GitHub Auth with environment-backed values:

```toml
[auth.external.github]
enabled = true
client_id = "env(SUPABASE_AUTH_GITHUB_CLIENT_ID)"
secret = "env(SUPABASE_AUTH_GITHUB_SECRET)"
redirect_uri = "http://localhost:54321/auth/v1/callback"
```

The hosted GitHub OAuth App uses the repository/project homepage and callback:

```text
https://<project-ref>.supabase.co/auth/v1/callback
```

Hosted Auth JWT expiry is set to 900 seconds to match local configuration and
the documented Realtime residual bound.

The client ID and secret live only in GitHub/Supabase provider configuration or
local ignored environment files. Tests and CI use synthetic JWT claims and do
not need production OAuth credentials. Provider configuration is free; if the
provider or project reports a non-zero recurring cost, provisioning stops
without changing the local implementation.

## Migration and CI Layout

- `supabase/config.toml` pins local Auth, Storage, API, and database behavior.
- `supabase/migrations/20260804000000_context_relay_ciphertext_boundary.sql`
  creates all Task 15 database objects in dependency order.
- `supabase/tests/0001_context_relay_ciphertext_boundary_test.sql` contains
  pgTAP behavioral and privilege tests.
- `scripts/check-supabase-contract.mjs` performs fast static checks that catch
  accidentally exposed schemas, missing RLS/grants, publication drift, secrets,
  and configuration regressions without Docker.
- `.github/workflows/supabase.yml` pins Supabase CLI `2.110.0`, starts the local
  stack, runs reset, pgTAP, and database lint, then stops the stack.
- `docs/verification/task-15.md` records local, CI-capable, and live-project
  evidence separately.

The CLI is an exact development dependency so local scripts and CI run the same
version. No global installation is required.

## Verification Strategy

### Static contract tests

The repository-level checker fails on:

- missing RLS enablement for any Context Relay or relevant Supabase surface;
- wildcard/default grants or authenticated write grants on immutable tables;
- any direct Context Relay relation grant to `service_role`;
- an exposed private schema;
- Context Relay relations in Postgres Changes publication;
- a public bucket, object part limit above 32 MiB, or signed-URL contract;
- an OAuth secret literal;
- identity helpers with arguments, Storage predicates with identity arguments,
  mutable search paths, or caller-selected identity parameters; and
- missing CI commands for database reset, pgTAP, and lint.

### pgTAP fixture matrix

Tests create two Auth users and accounts with these bindings:

- user A: active current session, pending second device, revoked old session;
- user B: active current session;
- user D: active session on an account transitioned to `pending_delete`.

JWT claims are set exactly as PostgREST supplies them. Tests then prove:

- `anon` has no Context Relay relation, function, Storage, or Realtime access;
- A can read A and cannot read B under direct filters, joins, or spoofed IDs;
- B has the symmetric isolation;
- pending, missing, malformed-session, expired, and revoked bindings resolve no
  read or write account;
- changing submitted `account_id` or `device_id` cannot affect authorization;
- direct operation/checkpoint/certificate/manifest insert, update, delete, and
  truncate fail for authenticated users;
- A cannot receive B’s Broadcast topic or read B’s Storage object;
- a valid A reservation permits only exact A part paths and sizes;
- update/upsert, extra parts, traversal-shaped names, wrong sizes, and B’s
  reservation fail;
- quota reservation is atomic at the 500 MiB boundary and refund/finalize paths
  preserve the counter invariant;
- finalized parts become readable, incomplete parts do not;
- `pending_delete` retains reads/downloads but loses writes, reservations, and
  new bindings; and
- revoking the current binding denies the next Database/Storage/Realtime policy
  authorization using that session.

The Realtime assertion is also exercised over real WebSockets: ephemeral A and
B Auth sessions subscribe to their own and each other’s private topics, a
service client sends the frozen hint, and only the matching account receives
it. After A is revoked, the test closes the existing channel and proves a fresh
authorization with that session fails. This demonstrates the forced-
reauthorization path while the 900-second JWT lifetime documents the residual
upper bound for a client that does not reconnect promptly.

### Live free-project verification

After local/CI-capable tests pass, create the zero-cost West US project, apply
the migration once, configure GitHub OAuth, and run representative isolation
queries plus Storage HTTP and Realtime WebSocket tests against the hosted
services. Record Supabase security and performance advisor output. Task 15 is
complete only when there are no release-blocking findings; accepted
informational findings require written rationale.

## Failure Handling and Rollback

The migration is additive and is tested from an empty local database before
hosted application. A hosted failure is repaired with a forward migration;
production history is never edited in place. Initial rollout contains no user
data, so the free project can be recreated if provisioning itself is corrupt,
but database migrations still remain forward-only.

Quota transitions use row locks and idempotent terminal states. Reservation
cleanup may be retried. Orphaned ciphertext is unavailable without a live
reservation/finalized manifest and is removed by service cleanup. A database
counter is never decremented merely because a Storage delete was attempted; the
transition records the authoritative state and cleanup reports failures for
retry.

## Security Boundaries Preserved

- The cloud can observe account relationships, device metadata, ciphertext
  sizes, timing, and routing fields. It can withhold, replay, fork, or delete
  ciphertext. These are documented limits, not hidden assumptions.
- Encryption and signature verification remain client responsibilities.
- Supabase Auth proves a login session; it does not replace Context Relay’s
  signed device certificate or operation validation.
- The `service_role` key is never shipped to a client or committed.
- Private helpers cannot be parameterized to impersonate an account/device.
- Storage authorization is tied to a live database reservation and current
  device session, not an object-name prefix alone.
- Realtime is a hint channel, not a data or authorization channel.
- Deletion grace access is read-only and explicit.
- No paid Apple or cloud capability is required for Task 15.

## Deferred Work

Task 15 configures the hosted GitHub OAuth provider and callback. Task 16 will
implement signed operation submission, private Broadcast sends, checkpoint and
blob orchestration with verified-JWT identity derivation. Task 17 will implement
application account/device lifecycle, pairing, recovery, revocation, deletion,
fresh-auth enforcement, and purge workers on top of these service-only relations
and transitions. Desktop online sync and adversarial client reconciliation
remain later roadmap work.
