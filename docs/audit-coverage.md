# Audit coverage

Areas the July 2026 audit reviewed by hand, and what was checked in each. Recorded so
a later reader knows which surfaces have been looked at and which have not.

## Verified defects, fixed

| PR | Area | Defect |
|---|---|---|
| #31 | `context-mcp/src/server.rs` | Five `lock().unwrap()` on `std::sync::Mutex` with no `catch_unwind`: one panic poisoned the registry permanently and killed the stdio bridge. |
| #33 | `core/src/devices/memory_transport.rs` | Expired pairing invites were only dropped once a caller read them, so 120 invites over 120 hours all stayed resident. Anonymous join session ids were inserted unbounded. |

## Checked and found correct

**Local IPC** (`crates/local-ipc/`) — HMAC-SHA256 with domain separation for client and
server, `verify_slice` for constant-time comparison rather than `==`, `Zeroizing` on
token material, redacted `Debug` impls, and mutual authentication (the daemon proves
itself, not just the client). Frame length is bounded on both read and write, and the
daemon caps concurrent connections with a `Semaphore`.

**Pairing provider** (`core/src/devices/memory_transport.rs`) — codes are Crockford
base32 generated from `OsRng` via `try_fill_bytes` (no panic path), stored HMAC'd under
a pepper rather than in plaintext, compared with `verify_slice`, and de-duplicated
against existing invites before insertion. Code guessing is capped at five attempts per
session. Invite lifetime, terminal states and the cancel/approve/deny transitions are
each validated.

**MCP JSON-RPC** (`context-mcp/src/`) — unknown methods return `METHOD_NOT_FOUND`
rather than falling through, the `initialize` lifecycle is enforced so it cannot be
repeated, every handler parses and validates its own params, and frame size is bounded
with `checked_sub`/`saturating_add`. Tool calls are gated by a token-bucket rate limit
and a `MAX_IN_FLIGHT_TOOL_CALLS` semaphore; the bucket uses `saturating` arithmetic so
it cannot overflow.

**Credential storage** (`core/src/auth/`) — `StoredLogin` wraps the refresh token in
`Zeroizing` and redacts `Debug`. Records are version-pinned, bound to the project URL,
size-capped, and every UUID is canonicalised. Keyring entry names are SHA-256 digests
of project and profile, so credentials are not addressable by guessable name.
`valid_header_secret` rejects non-graphic characters and is applied to every value that
reaches an auth header, which blocks CRLF injection. `logout` invalidates local state
and clears the store *before* attempting the network call, so a network failure cannot
leave a credential behind. Refresh is generation-guarded with no lock held across the
network call.

**Vault durability** (`core/src/vault.rs`) — `journal_mode = DELETE` with
`synchronous = FULL`, plus `secure_delete`, `trusted_schema = false`,
`SQLITE_DBCONFIG_DEFENSIVE`, and `cipher_memory_security`. `verify_runtime` asserts at
open time that SQLite and SQLCipher are at or above the pinned minimums, that FTS5 is
compiled in, and that `synchronous` is genuinely FULL rather than trusting the pragma.
Both connection-open paths call it.

**Native memory watcher** (`contextd/src/native_memory.rs`) — pending and in-flight
sets are keyed by source id, the join set is drained each loop iteration, and a
`JoinSet` drain prevents duplicate submissions. Debounce is a bounded state machine.

**Command authorization** (`local-ipc/src/connection.rs`, `contextd/src/lib.rs`) —
every inbound frame is checked by `role_allows` in the connection read loop, before
the daemon sees it, and an unauthorized request gets `ScopeDenied` without being
dispatched. Verified that the narrower checks inside `route_request` are
defense-in-depth rather than the primary gate: a probe showed `route_request` does
not deny `ProjectUpsert`, `TasksList` or `AccessSet` for `McpBridge`/`Installer`
roles, but the IPC layer refuses them first. `role_allows` itself is exhaustive per
variant — `MemoryCreate`, `AccessSet`, `AccountDeletionBegin` and `Shutdown` are all
`Desktop`-only, `Health` is shared, and `Hello` is denied to everyone.

**Filesystem boundary** (`core/src/`) — `..` and `.` path components are rejected
explicitly in four separate boundary modules, wire paths are validated against the
declared platform and reject NUL bytes, containment checks compare
`canonicalize()`d paths rather than raw strings, and native-state writes are staged and
`fsync`ed before rename.

**Workspace parameter handling** (`contextd/src/lib.rs`, `core/src/service.rs`) —
the 37 workspace-queue handlers were walked for the request types that carry
attacker-influenced data. Registering a project validates both the identity and the
path before touching the database, and refuses to rebind an existing project to a
different path or name, so a repeated registration cannot redirect a bound project.
`WireNativeValue::validate` is called on *deserialization* as well as on use, so an
oversized path never reaches a handler. Memory search rejects an empty query,
resolves and authorizes the scope before searching, and caps results at 100. The
lexical half of the search goes through `quote_fts_query`, which wraps the query in
double quotes and doubles any embedded quote — the documented FTS5 escape — so the
`MATCH` clause is not injectable, and it is bound as a parameter rather than
interpolated.

**Recovery enrollment** (`contextd/src/recovery_enrollment*`, ~3.1k lines) — the
phrase is BIP39 with a checksum: `from_words` parses through
`Mnemonic::parse_in(Language::English)` and requires exactly 24 words, so a wrong
phrase fails the checksum before any key derivation runs. Entropy is 256-bit and
both the parsed and stored phrase live in `Zeroizing`, with an explicit `drop` of
the phrase immediately after derivation. `authenticate_recovery_root` verifies
entirely locally against the canonical record — digest, then derivation, then public
key match — so there is no online oracle to rate-limit. The membership walk is
fail-closed: a repeated `state_sha256` is rejected via a `BTreeSet` seen-set, and
the object count is capped by `BUDGET.max_events`.

**Ledger transaction integrity** (`vault/native_transactions.rs`,
`native_transaction/journal.rs`) — every state change runs inside a SQL
transaction, and the step transition uses a compare-and-swap `UPDATE` that fails if
`changed != 1`, so a concurrent writer is detected rather than overwritten. Step
entry is idempotent, which is what lets crash recovery re-enter a step it had
already entered. `commit_native_success` cross-checks the legacy and native
receipts against each other (target counts, per-target fingerprints, duplicate
targets) and is idempotent on replay. The journal releases its profile lock on
every error path and composes both the primary and the compensation error when a
rollback also fails. The gap found here was in the tests rather than the code, and
is now covered by #35.

## Not yet reviewed

- `hosted_auth` / `hosted_sync` state machines and retry backoff.
- `bridge_install` (2.1k lines).
