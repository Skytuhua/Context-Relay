# Context Relay protocol version 1

Context Relay protocol version 1.0 is identified by `PROTOCOL_MAJOR = 1` and `PROTOCOL_MINOR = 0`. Sync operations use schema version 1. Local IPC frames are limited to 8 MiB.

Version negotiation requires matching major versions and selects the greatest minor version present in both advertised ranges. A major mismatch or disjoint minor range returns `protocol_version_unsupported`. No caller may fall back to an unknown major.

All product identifiers are UUIDv7 values. JSON uses lowercase hyphenated text. Canonical CBOR uses exactly 16 bytes. JSON encodes wire `u64` values as canonical decimal strings. CBOR encodes them as unsigned integers.

The hybrid logical clock is `(physical_ms, logical, node)`. Protocol code accepts the current wall time as input and never reads or persists a clock. Tick and observe return `clock_exhausted` on logical overflow.

`SyncOperationV1` is immutable. The operation signing preimage contains integer keys 0 through 18. The complete signed operation adds key 19 for opaque Ed25519 signature bytes. Task 4 validates sizes and encodings only. It does not generate keys, sign, verify, encrypt, decrypt, or assign trust.

Later synchronization behavior must follow these rules:

- Wall-clock last-write-wins is prohibited.
- Concurrent body changes preserve both versions and create a conflict.
- A tombstone wins over causally older writes.
- A concurrent update and delete creates a conflict.
- Duplicate operation IDs are accepted only when canonical bytes match.
- Sequence conflicts and hash-chain breaks are quarantined.

Local JSON-RPC and MCP inputs reject unknown fields. The package manifest allows forward data only in a namespaced `extensions` field. Sync schema version 1 rejects unknown top-level operation and checkpoint keys.
MCP callers never submit project UUID selectors. Memory search defaults to every caller-allowed scope and may narrow to `global` or the caller-relative `active_project`; memory writes use one of those two selectors. Task listing and upserts always resolve the active project, while ID-based reads and updates remain subject to later authorization. Returned records keep stable scope and project identifiers.


Rust enforces text limits in UTF-8 bytes. Every consumer of an exported JSON Schema must register the `x-utf8-maxBytes` keyword and reject a string whose UTF-8 encoding exceeds that value. JSON Schema `maxLength` remains a character-count portability hint and does not replace the byte check.

Native paths and arguments carry a platform tag, lossless bytes, and optional sanitized display text. Windows bytes are original UTF-16 code units in little-endian order. macOS bytes are the original `OsStr` bytes. Display text is never authoritative.

Task 4 defines DTOs and validation only. It does not implement storage, merging, transports, authorization, adapter behavior, an MCP server, or package installation.

## Setup and package contracts

A setup plan records the exact executable path bytes and digest, adapter and harness versions, target scopes, expected native digests, semantic changes, CLI argument arrays, package artifacts, permission delta, typed network endpoint delta, scanner report hash, RuleSync version and hash, approval class, expiry, and batch hash. A later task serializes the canonical approval preimage from every accepted plan field except `batchHash`, including the resolved dependency closure, permission and network delta, scanner result, and versions. `batchHash` is the SHA-256 digest of that canonical preimage. Task 4 does not compute or approve the hash.

An expected native digest may be absent, which means the approved precondition is that the target does not yet exist. Package artifact entries bind an immutable source reference and resolved commit, archive digest, installed artifact path and digest, and the transitive dependency closure.

Package dependency source and version fields are descriptive labels. The SHA-256 digest is the authoritative immutable identity. Core package fields do not designate secret or executable values. All package text and namespaced extension bytes remain untrusted input; Task 19 must scan and reject executable content, credentials, secret values, transcripts, native trust state, and other unsafe payloads before installation.

JSON-RPC errors use numeric JSON-RPC codes. Context Relay stable snake-case error codes, safe field paths, and retryability are carried in typed error data. Standard parse, request, method, parameter, and internal codes are reserved alongside the documented Context Relay application range.
