# Context Relay canonical CBOR version 1

Sync operations and checkpoints use RFC 8949 core deterministic encoding. Maps, arrays, text strings, and byte strings have definite lengths. Integer keys are written in ascending order with preferred encoding. Decoders reject floats, tags, indefinite lengths, duplicate or out-of-order keys, negative keys, trailing bytes, invalid UUID versions, oversized values, and unsupported schema versions. Canonical re-encoding must byte-match the input.

## Sync operation keys

| Key | Field | CBOR type |
| ---: | --- | --- |
| 0 | schema version | unsigned integer |
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
| 0 | schema version | unsigned integer |
| 1 | previous checkpoint hash | 32-byte string |
| 2 | causal frontier | array |
| 3 | state hash | 32-byte string |
| 4 | key epoch | unsigned integer |
| 5 | creator device | 16-byte UUIDv7 |
| 6 | creation HLC | fixed map |
| 7 | signature | 64-byte string |

The checkpoint signing preimage uses the same checkpoint map without signature key 7 and uses a 7-entry map. The operation fixture identifier is the SHA-256 digest of the decoded hex bytes in `tests/fixtures/sync-operation-v1.hex`, recorded in the Task 4 report after generation. User Markdown bytes are not normalized or rewritten.
