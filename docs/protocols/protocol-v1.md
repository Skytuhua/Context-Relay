# Context Relay protocol version 1

Context Relay protocol version 1.6 is identified by `PROTOCOL_MAJOR = 1` and `PROTOCOL_MINOR = 6`. Sync operations use schema version 1; scope-bound signed checkpoints use the independent checkpoint schema version 2. Local IPC frames are limited to 8 MiB.

Harness discovery includes nullable `codexSavedHookApproval` with `sessionStart` and `stop` states. These describe saved user hook definitions and approvals, not effective runtime enablement or a verified connection. `null` means the check is unavailable, including unsupported versions or unreadable settings.

Version negotiation requires matching major versions and selects the greatest minor version present in both advertised ranges. A major mismatch or disjoint minor range returns `protocol_version_unsupported`. No caller may fall back to an unknown major.

All product identifiers are UUIDv7 values. JSON uses lowercase hyphenated text. Canonical CBOR uses exactly 16 bytes. JSON encodes wire `u64` values as canonical decimal strings. CBOR encodes them as unsigned integers.

The hybrid logical clock is `(physical_ms, logical, node)`. Protocol code accepts the current wall time as input and never reads or persists a clock. Tick and observe return `clock_exhausted` on logical overflow.

`SyncOperationV1` is immutable. The operation signing preimage contains integer keys 0 through 18. The complete signed operation adds key 19 for opaque Ed25519 signature bytes. Task 4 validates sizes and encodings only. It does not generate keys, sign, verify, encrypt, decrypt, or assign trust.

The encrypted record-mutation plaintext is a strict five-key CBOR map carrying
schema version, record kind, mutation kind, record ID, and either canonical
compact JSON bytes for the typed record or null for a tombstone. Its decoder
requires the typed record to validate, reserialize to byte-identical JSON, and
match the outer record ID and kind. The AEAD associated data is a 16-entry
canonical CBOR map of operation keys 0 through 13 plus 17 and 18. It excludes
the nonce, ciphertext, ciphertext hash, and signature so encryption can bind
the operation context without self-referencing ciphertext fields.

Later synchronization behavior must follow these rules:

- Wall-clock last-write-wins is prohibited.
- Concurrent body changes preserve both versions and create a conflict.
- A tombstone wins over causally older writes.
- A concurrent update and delete creates a conflict.
- Duplicate operation IDs are accepted only when canonical bytes match.
- Sequence conflicts and hash-chain breaks are quarantined.

Local JSON-RPC requests and success responses reject unknown fields and invalid nested domain content. MCP inputs reject unknown fields. The package manifest allows forward data only in an optional namespaced `extensions` field. Operation schema version 1 and checkpoint schema version 2 reject unknown top-level keys.

Checkpoint transport requests always carry the requested checkpoint schema
version for append, page pull, and exact-hash lookup. Providers partition logs
by that value and must never return legacy checkpoint bytes to a version 2
request. Legacy version 1 checkpoint logs did not bind account/workspace in the
signature. They must be retained in a separate partition or explicitly
retired; they cannot be decoded, upgraded, or joined to a version 2 chain.
Likewise, an old client cannot join a version 2 checkpoint chain. This is a
pre-release contract change, and no hosted checkpoint transport exists yet.
MCP callers never submit project UUID selectors. Memory search defaults to every caller-allowed scope and may narrow to `global` or the caller-relative `active_project`; memory writes use one of those two selectors. Task listing and upserts always resolve the active project, while ID-based reads and updates remain subject to later authorization. Returned records keep stable scope and project identifiers.


Rust enforces text limits in UTF-8 bytes. Every consumer of an exported JSON Schema must register the `x-utf8-maxBytes` keyword and reject a string whose UTF-8 encoding exceeds that value. JSON Schema `maxLength` remains a character-count portability hint and does not replace the byte check.

Native paths and arguments carry a platform tag, lossless bytes, and optional sanitized display text. Windows bytes are original UTF-16 code units in little-endian order. macOS bytes are the original `OsStr` bytes. Display text is never authoritative.

Task 4 defines DTOs and validation only. It does not implement storage, merging, transports, authorization, adapter behavior, an MCP server, or package installation.

## Setup and package contracts

A setup plan records the exact executable path bytes and digest, adapter and harness versions, the required-nullable selected Hermes profile, target scopes, expected native digests, semantic changes, CLI argument arrays, package artifacts, permission delta, typed network endpoint delta, scanner report hash, RuleSync version and hash, approval class, expiry, and batch hash. Hermes preview requests and plans require a nonempty explicit profile; Claude Code and Codex require null. The selected profile is sealed into the approval preimage and reused for apply, startup recovery, and rollback, so execution cannot silently fall back to another profile. A later task serializes the canonical approval preimage from every accepted plan field except `batchHash`, including the resolved dependency closure, permission and network delta, scanner result, and versions. `batchHash` is the SHA-256 digest of that canonical preimage. Task 4 does not compute or approve the hash.

An expected native digest may be absent, which means the approved precondition is that the target does not yet exist. Package artifact entries bind an immutable source reference and resolved commit, archive digest, installed artifact path and digest, and the transitive dependency closure.

Package dependency source and version fields are descriptive labels. The SHA-256 digest is the authoritative immutable identity. Core package fields do not designate secret or executable values. The optional `extensions` object is keyed by namespace, so namespace ordering is deterministic and duplicate namespaces are impossible after JSON parsing. Each namespace maps to a flat, deterministically ordered map of UTF-8 text. Extension maps are limited to 64 entries, keys to 128 UTF-8 bytes, and values to 16 KiB. Keys that normalize to secret-bearing or active-content roles, control-bearing values, and obvious PEM private-key blocks are rejected. Extension data remains untrusted input. Task 19 must still scan exact package bytes and reject executable content, credentials, secret values, transcripts, native trust state, and other unsafe payloads before installation.

JSON-RPC errors use numeric JSON-RPC codes. Context Relay stable snake-case error codes, safe field paths, and retryability are carried in typed error data. Standard parse, request, method, parameter, and internal codes are reserved alongside the documented Context Relay application range.

## Recovery enrollment boundary

Protocol 1.3 introduced five phase-specific enrollment
methods: begin, overview, confirm, status, and cancel. Enrollment and recovery-root identifiers are
distinct UUIDv7 types. Confirmation carries exactly four lowercase words at strictly increasing
one-based positions in 1 through 24; the request owns and zeroizes those strings and redacts them
from recursive Debug output.

Ordinary Desktop connections may request overview, status, and cancellation, but cannot begin an
enrollment or submit confirmation words. Those two operations require the distinct
`desktop_recovery_host` role, which is confined to begin, confirm, and cancellation. MCP and
installer roles cannot invoke any recovery-enrollment operation.

Only `recovery_enrollment_phrase` can carry all 24 words. The native-host begin and confirmation
result unions are closed, word-free projections, so phrase words cannot enter a Tauri command
result. Idle status requires every optional enrollment field to be null. Awaiting confirmation
requires an ID and creation time but no transition time; submitting, complete, and conflict also
require a transition time.

## Explicit Hermes profile boundary

Protocol 1.4 adds required-nullable `hermesProfile` to `HarnessParams` and `harnessProfile` to
`SetupPlan`. This is a deliberate pre-release strict-wire break: exact-version local handshakes
reject 1.3 peers before request decoding, and 1.4 decoders reject omitted profile fields. No
downgrade fallback is allowed. The change prevents previewing one Hermes profile and later applying
or recovering the transaction against `default` or another ambient profile.


## Atomic project registration

Protocol 1.5 adds the Desktop-only `project_register` request with required
`project` and `path` fields. The ordered daemon worker checks that the native
path names an existing accessible directory, then commits the project identity
and its local folder binding in one vault transaction. A failure during either
write commits neither new record. Exact same-ID/content replay succeeds;
conflicting content for an existing ID is rejected. A matching legacy identity
without a folder can be completed without replacing that identity.

The desktop retains the most recent uncertain registration identity for an
explicit retry of the same name and native path. It never retries the write
automatically or falls back to the legacy two-request creation sequence.
`project_upsert` and `project_path_set` remain available for their existing
independent operations. Their presence is not an atomic creation contract.

Ordinary local clients require exactly 1.6 and reject 1.5 before application
dispatch. The Windows updater always extracts its new authenticated shutdown
helper before replacing companions; it never runs an old daemon executable
that might ignore `--shutdown` and start a service. The helper has one private
compatibility path for protocols 1.4 and 1.5: verify both installation-token proofs,
send only the fixed shutdown request, require its matching empty acknowledgment,
and wait for the exact connected process to exit. It cannot return a reusable
client or dispatch other legacy requests. Other legacy versions are rejected.
An absent service succeeds without starting a daemon or reading credentials.
No vault schema migration is needed for project registration, and sync/checkpoint
schema versions are unchanged.
