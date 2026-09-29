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

## Not yet reviewed

- Per-handler parameter validation inside `contextd`'s workspace queue. Command
  *authorization* is verified (see above); the individual handlers were not each
  walked for input validation.
- `contextd` shutdown and ledger transaction integrity, including crash-during-write
  behaviour.
- `hosted_auth` / `hosted_sync` state machines and retry backoff.
- `bridge_install` (2.1k lines) and `recovery_enrollment` (2.7k lines).
