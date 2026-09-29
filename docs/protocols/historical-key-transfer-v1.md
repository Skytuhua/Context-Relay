# Historical key transfer v1 — implementation candidate

This documents the isolated `devices::historical_crypto` codec. It is not yet a
production transfer protocol: durable acceptance, transport, current-key
activation and historical reconstruction remain required by the
[integration plan](../superpowers/plans/2026-09-13-membership-transfer-activation.md).
Existing pairing and checkpoint wire formats are unchanged.

## Authority and inventory

C is the exact recipient admission successor independently confirmed through
the V2 pairing transcript. D is the locally accepted control endpoint. Complete
verified membership replay must prove C is on D's branch. Reconstructing the
membership statement from the confirmed transcript and its signature must yield
exactly C, including its control/key epochs. A generic genesis or unrelated
membership anchor does not establish this admission.

Both exporter and recipient must be active at D. The recipient certificate and
admission ID must equal the original confirmed ones. An exporter admitted after
C is allowed. Exporter signing and recipient decryption operations require
their local signing/wrapping keys to match the respective active certificates.

The read-target checkpoint uses the existing canonical checkpoint codec, with
D's scope and key epoch and the exporter's creator identity and signature.
Authentication establishes an exporter assertion about the target; it does not
establish reconstructed state or a nonregressing replacement frontier.

Historical inventory is every epoch from 1 through D's key epoch minus one.
Current keys are authenticated and activated separately. Each transferred
bundle is canonical pinned bundle2 with exact scope, pin and epoch. Rotated
epochs must match their authenticated control epoch and exact signed plaintext
commitment, checking existing canonical bundle1 or same-pin bundle2 encoding.
Genesis has no public plaintext commitment: epoch 1 is explicitly trusted as an
active-exporter assertion, or compared with an already trusted local bundle.
Callers must supply the latter when a trusted value exists locally.

## Fixed header

Integers are unsigned big-endian. IDs use existing validated 16-byte UUIDv7
wrappers. Digests are 32 bytes. Every domain ends in one NUL byte.

The 250-byte context T is the concatenation below, in order:

| Field | Bytes |
| --- | ---: |
| schema version, value 1 | 2 |
| transfer ID | 16 |
| account ID | 16 |
| workspace ID | 16 |
| pairing membership successor digest C | 32 |
| authorizing control state digest D | 32 |
| recipient device ID | 16 |
| recipient certificate digest | 32 |
| enrollment record digest | 32 |
| exporter device ID | 16 |
| checkpoint digest | 32 |
| last historical key epoch | 4 |
| page count | 4 |

The signed preimage is `context-relay/historical-key-transfer/v1\0`, then T,
then the first-page digest. Appending the 64-byte Ed25519 signature produces
exactly 387 bytes. Reject other lengths, domains, versions, invalid IDs and
trailing bytes. All context digests are nonzero. Page count is the checked
ceiling of last historical epoch divided by 32. A zero first-page digest is
required exactly when there are no historical pages.

## Encrypted pages

Each page is at most 16 KiB and uses a canonical definite CBOR map with exactly
these ascending integer keys:

| Key | Value |
| --- | --- |
| 0 | zero-based page index, u32 |
| 1 | first key epoch, u32 |
| 2 | bundle count, u32 |
| 3 | next-page digest, bstr32 |
| 4 | existing embedded `WrappedKeyEnvelope` |

The first epoch is `1 + 32 * index`; the count is the remaining inventory
bounded to 32. Count must be positive. The final next-page digest is zero;
all earlier next-page digests are nonzero. The header or preceding page binds
SHA-256 of the exact canonical ciphertext page. Reject duplicate/unknown keys,
indefinite forms, nonminimal encodings, invalid envelopes and trailing bytes.

Page AAD is `context-relay/historical-key-page/v1\0`, T, index, first epoch,
count and next-page digest, in that order. Its fixed length is 331 bytes.
Use existing X25519 wrapping to the confirmed recipient certificate. Build
pages backward, then sign the header after preserving their exact bytes.

Plaintext is a canonical definite CBOR array with exactly the required number
of bstr entries. Each bstr contains one complete canonical pinned bundle2,
bounded to 160 bytes. Reject unpinned entries, wrong inventory positions and
scope/pin/commitment substitutions. Secret buffers use existing zeroization.

The in-memory verifier advances its expected page index/hash only after an
entire page decrypts and validates. A rejected page leaves progress unchanged.
No public restored cursor is provided by this codec. Verified inventory is
not durable installation, checkpoint reconstruction or current-write authority.

## Independent byte vectors

The fixed-header test uses UUIDs `018f22e2-79b0-7cc8-98c4-dc0c0c0739NN`:
transfer `0a`, account `01`, workspace `02`, recipient `04`, exporter `03`.
Context digests C, D, recipient certificate, enrollment and checkpoint are
respectively bytes `01`, `02`, `03`, `04`, `05` repeated 32 times. Last epoch is
33, page count is 2 and first-page digest is byte `06` repeated 32 times.
The test Ed25519 seed is byte `01` repeated 32 times.

Independently reconstructed using Python UUID/struct and Ed25519:

```text
context length: 250
header preimage length: 323
header length: 387
signature:
cf98b1313e6442399cbfa519eff2ba42436cc6711d543597789038dd0f75d8c47b5629af4aa46a2dfe445641c6c881c203b9572504aadb85cee9fe7f9f6fb804
header SHA-256:
d38a4d8766ad0606a5d9b2607c29234e95f58f19d1fa902448505b0b5122f011
```

The page wire vector uses the same T, index 1, first epoch 33, count 1 and a
zero next digest. Its envelope has X25519 public key derived from test private
bytes `02` repeated 32 times, nonce `07` repeated 24 times, and dummy ciphertext
`08` repeated 16 times. This is a wire/AAD vector, not valid encrypted material.

```text
ephemeral public key:
ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d59
page length: 125
page SHA-256:
584b087b9c652f86d55c0a34f44006607845f58c34fc342ed1705c0054977d16
AAD length: 331
AAD SHA-256:
32df2ea51153d23b251e9a48db1edb1718bf2ad9a6ef85acbefa0155f1c9df74
```

Before production use, enforce accepted-D agreement, immutable transfer
identity, target and page transaction CAS, nonregressing verified chain
frontiers, exact historical revocation cutoffs and complete reconstruction.
These are integration requirements, not properties supplied by this codec.
