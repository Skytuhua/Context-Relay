# Context Relay canonical CBOR contracts

Sync operations (schema version 1) and checkpoints (checkpoint schema version 2) use RFC 8949 core deterministic encoding. Maps, arrays, text strings, and byte strings have definite lengths. Integer keys are written in ascending order with preferred encoding. Decoders reject floats, tags, indefinite lengths, duplicate or out-of-order keys, negative keys, trailing bytes, invalid UUID versions, oversized values, and unsupported schema versions. Canonical re-encoding must byte-match the input.

## Sync operation keys

| Key | Field | CBOR type |
| ---: | --- | --- |
| 0 | operation schema version | unsigned integer (1) |
| 1 | operation ID | 16-byte UUIDv7 |
| 2 | account ID | 16-byte UUIDv7 |
| 3 | workspace ID | 16-byte UUIDv7 |
| 4 | project ID | 16-byte UUIDv7 or null |
| 5 | record ID | 16-byte UUIDv7 |
| 6 | record kind | assigned unsigned integer |
| 7 | mutation kind | assigned unsigned integer |
| 8 | device ID | 16-byte UUIDv7 |
| 9 | device sequence | unsigned integer |
| 10 | causal frontier | array of `[device ID, sequence]` |
| 11 | control epoch | unsigned integer |
| 12 | key epoch | unsigned integer |
| 13 | previous device hash | 32-byte string |
| 14 | nonce | 24-byte string |
| 15 | ciphertext | bounded byte string |
| 16 | ciphertext hash | 32-byte string |
| 17 | blob references | array of fixed maps |
| 18 | creation HLC | fixed map |
| 19 | signature | 64-byte string |

The signing preimage uses the same assigned fields but omits signature key 19 and uses a 19-entry map. The complete signed operation uses a 20-entry map. These layouts do not use generic Serde maps.

### Sync operation AEAD associated data

The associated data for an encrypted sync mutation is a definite 16-entry map
containing operation keys 0 through 13, then 17 and 18, in that order. It
binds operation identity, tenancy, record and mutation identity, device
sequence and causal frontier, control and key epochs, the previous-device
hash, blob references, and creation HLC. It deliberately excludes nonce (14),
ciphertext (15), ciphertext hash (16), and signature (19).

## Encrypted mutation keys

Before encryption, a record mutation is encoded as a definite five-entry map.
Its typed record payload is compact JSON bytes; it is not a generic CBOR
serialization of the record.

| Key | Field | CBOR type |
| ---: | --- | --- |
| 0 | schema version | unsigned integer (1) |
| 1 | record kind | assigned unsigned integer |
| 2 | mutation kind | assigned unsigned integer |
| 3 | record ID | 16-byte UUIDv7 |
| 4 | record payload | canonical compact JSON byte string, or null for a tombstone |

An upsert payload must deserialize as the record type assigned by its record
kind, reject unknown fields through that record's DTO, validate, and serialize
back to exactly the same JSON bytes. The payload record ID must match key 3.
A tombstone requires null at key 4. Mutation decoding rejects noncanonical JSON
as well as noncanonical CBOR.

### Blob reference keys

| Key | Field | CBOR type |
| ---: | --- | --- |
| 0 | digest | 32-byte string |
| 1 | ciphertext byte length | unsigned integer |
| 2 | opaque storage ID | bounded text string |

### Hybrid logical clock keys

| Key | Field | CBOR type |
| ---: | --- | --- |
| 0 | physical milliseconds | unsigned integer |
| 1 | logical counter | unsigned integer |
| 2 | node | 16-byte UUIDv7 |

Record kinds are assigned as memory 0, memory candidate 1, task 2, secret reference 3, instruction 4, component 5, and project 6. Mutation kinds are upsert 0 and tombstone 1. All enum integer assignments are immutable within schema version 1; source declaration order cannot change them.

## Checkpoint keys

| Key | Field | CBOR type |
| ---: | --- | --- |
| 0 | checkpoint schema version | unsigned integer (2) |
| 1 | account ID | 16-byte UUIDv7 |
| 2 | workspace ID | 16-byte UUIDv7 |
| 3 | previous checkpoint hash | 32-byte string |
| 4 | causal frontier | array |
| 5 | state hash | 32-byte string |
| 6 | key epoch | unsigned integer |
| 7 | creator device | 16-byte UUIDv7 |
| 8 | creation HLC | fixed map |
| 9 | signature | 64-byte string |

The checkpoint signing preimage uses the same checkpoint map without signature key 9 and uses a 9-entry map. Account and workspace are therefore bound by the signature and cannot be supplied or relabelled out of band. The operation fixture identifier is the SHA-256 digest of the decoded hex bytes in `tests/fixtures/sync-operation-v1.hex`, recorded in the Task 4 report after generation. User Markdown bytes are not normalized or rewritten.

The earlier eight-entry signed checkpoint map did not bind account or workspace
and used checkpoint schema version 1. It is rejected with an explicit
unsupported-checkpoint-version result, not interpreted as the scoped format.
Local schema migration 18 retires every
pin and signed-checkpoint row created under that format, in foreign-key order,
and requests a fresh scoped checkpoint for each affected schedule. It never
decodes or upgrades unbound checkpoint bytes.

Checkpoint append, page-pull, and exact-hash lookup requests select checkpoint
schema version 2 explicitly. Provider logs are partitioned by that version.
Pre-contract remote version 1 logs must be retained separately or retired and
must never feed a version 2 client. Old clients cannot join version 2 chains.
This separation is a pre-release change; there is no hosted checkpoint
transport to migrate.
