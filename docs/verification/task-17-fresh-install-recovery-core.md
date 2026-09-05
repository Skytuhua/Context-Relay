# Task 17 fresh-install recovery core verification

Date: 2026-08-09

Status: the credential-free fresh-install recovery core is implemented and locally verified. A
fresh SQLCipher Vault can authenticate the saved 24-word recovery phrase against the exact
provider-retained recovery root, create one recovery-root-signed device claim, win one atomic
provider generation, install the exact root/recovered certificate graph, reopen the original
workspace material, and use the recovered device to pair a third encrypted Vault.

This slice deliberately does not add a renderer or local-IPC phrase-entry surface, a production
hosted provider, GitHub reassociation, device revocation, epoch rotation, or Apple packaging. No
Supabase project, GitHub OAuth setting, Apple Developer account, paid service, production
deployment, push, or merge was created or mutated.

## Verified repository range

| Commit | Subject |
| --- | --- |
| `ca05152` | `docs: design fresh-install recovery` |
| `ca4aa83` | `docs: plan fresh-install recovery` |
| `73e4802` | `feat: authenticate recovery device claims` |
| `149d4b0` | `feat: coordinate recovery device claims` |
| `34f15bb` | `feat: persist fresh-install recovery` |
| `a544cda` | `feat: restore devices from recovery phrase` |

The implementation baseline is `216dc82`. The evidence commit follows this range and cannot list
its own SHA without changing that SHA.

## Frozen vectors and boundaries

The hashes below cover decoded canonical bytes, not hexadecimal fixture text. No phrase, private
key, plaintext workspace key, raw envelope, or pairing safety number is reproduced here.

| Vector | Bytes | SHA-256 |
| --- | ---: | --- |
| `recovery-device-claim-v1.hex` | 699 | `86b78b1fc4633f33f826e5f0b27134a4670b4e28b95d4207c337504cbcf28e35` |
| `recovery-device-claim-signing-preimage-v1.hex` | 671 | `d82790c08aef156bb9cd61b41fc8364cad7b8ba454f41981c4c87f9d1dc2a436` |
| Referenced `recovery-enrollment-record-v1.hex` | 710 | `5a9a470d35924a44e599b9d9f753ad54e2dc8b967c22a88363e87daf2535e999` |

- This core slice originally left the local IPC protocol at 1.3. The later A-005 strengthening
  amendment advances the current boundary to 1.4 without changing these recovery bytes.
- The forward-only encrypted Vault schema advances from 22 to 23.
- The recovery-device claim schema is version 1 and is bounded at 32 KiB.
- Recovery IDs, certificate IDs, and device IDs are distinct strict UUIDv7 types.
- The claim signature covers every fixed-map field. The strict decoder rejects indefinite,
  reordered, duplicate, unknown, trailing, noncanonical, malformed, and oversized input.
- The recovered-device material envelope uses its own domain and binds root, restore, scope,
  generation, certificate digest, epochs, device ID, and both protected public keys.
- A phrase parse/checksum failure and a valid but wrong phrase return the same redacted
  `recovery_invalid` result and write no restore/provider state.

## Trust, compare-and-set, and restart behavior

- The phrase is consumed into a zeroizing recovery authority. The recovery private keys and opened
  workspace bundle are dropped before the prepared Vault transaction commits.
- A provider snapshot is strict-decoded and scope/hash-checked before phrase authentication. The
  phrase-derived keys must equal the enrolled recovery root keys and successfully open the exact
  encrypted recovery metadata.
- The provider accepts a claim only when its expected generation equals the current generation.
  Exact retries return the original receipt before the generation check; changed bytes, stale
  generations, or reused device/certificate identity conflict.
- A matching receipt alone is insufficient. The coordinator re-fetches the retained claim and
  requires exact canonical bytes, exact receipt, complete signature/certificate validation, and
  the prepared local pins before activation.
- A transient submit or exact-lookup failure leaves one resumable prepared row. A provider/local
  crash boundary reuses the same restore ID and canonical bytes without needing the phrase again.
- Provider contradictions durably transition the prepared row to Conflict without certificates.
  Conflict timestamps remain valid even if the local clock moved behind the prepare time.
- Schema 23 selects and validates every durable restore column, recomputes both canonical hashes,
  strict-decodes both signed objects, checks all duplicated metadata, and enforces exact prepared,
  active, and conflict nullability.
- Preparation requires an otherwise pristine Vault. Unexpected certificate appearance invalidates
  prepared replay and conflict transition rather than being treated as an exact replay.
- Activation inserts the root genesis certificate and recovered certificate and changes the
  restore state in one transaction. Trigger-aborted activation leaves no certificate and resumes
  after reopen.
- Active replay validates both exact active certificates and reopens the device-bound encrypted
  material without contacting the provider. Provider deletion cannot delete or downgrade the
  already verified local pin.
- `VaultPairingMaterialSource` accepts exactly one active enrollment or one active recovery
  restore. The recovered Vault successfully approves a normal third-device pairing with the full
  independent 80-bit safety-number comparison, and both resulting Vaults reopen equal material.

## Test-first RED evidence

1. Claim work began with missing `RecoveryRestoreId`, authentication authority, claim DTO/codec,
   builder, opener, and frozen vectors. Mutation REDs drove full signature/AAD coverage, canonical
   keys, weak-key rejection, size bounds, and redacted Debug behavior.
2. Transport work began with missing root snapshot, submit, exact lookup, and provider state.
   Focused failures drove one-lock generation CAS, exact replay-before-generation, caller scope,
   reused-identity rejection, forged/omitted projections, safe captures, and account deletion.
3. Persistence began with missing schema-23 types and methods. Raw-row, trigger, migration,
   plaintext, replay, and non-pristine REDs drove full-row validation and atomic activation. A
   later focused RED proved prepared replay had to reject an unexpectedly installed certificate.
4. Coordinator work began with a missing module, identity, outcomes, and phrase-consuming API.
   REDs then covered wrong phrases, crash/reopen, provider acceptance before local activation,
   generation races, forged/missing/substituted proof, identity mismatch, persisted tamper, offline
   replay, and third-device pairing.
5. Review found two additional edge cases before the coordinator commit: envelope-construction
   entropy failure was incorrectly classified as Invalid instead of Transient, and clock rollback
   could prevent a terminal Conflict from becoming durable. Both received focused failing tests
   before their fixes.

## End-to-end and plaintext evidence

The 13 coordinator tests use real SQLCipher Vault files, real recovery-root enrollment, stable
test protected identities, strict provider-like transports, canonical crypto, schema-23
persistence, and the existing pairing coordinator. They cover fresh recovery, prepared and
provider-accepted restart points, activation rollback, exact active replay, two-target generation
races, malicious root/scope/receipt/projection substitutions, provider deletion, and a real third
Vault pairing/reopen.

Canary checks scan target database files and WAL/SHM/journal companions, test-only plaintext-cell
projections, provider capture projections, errors, Debug output, and terminal coordinator state.
No scanned surface contains the full phrase, derived recovery secret, workspace root key, active
epoch key, or protected device private seed.

## Final local gate matrix

| Gate | Result |
| --- | --- |
| Sixteen focused core targets | Green: 176/176. Restore crypto 6, transport 6, Vault 9, e2e 13; enrollment crypto 6, transport 6, Vault 6, e2e 12; pairing crypto 11, transport 8, Vault 13, e2e 9; signed-sync e2e 16 across 256/256 seeds, backoff 4, checkpoint 8, engine 43. The clean-process convergence test took 199.43 s. |
| `cargo test -p context-relay-protocol --all-features` | Historical capture: green at 110/110 integration tests while the protocol was 1.3. Current 1.4 evidence is recorded in Task 13. |
| `cargo test -p context-relay-local-ipc` | Green outside the filesystem sandbox: 40 unit + 28 integration = 68/68. The first sandbox run passed all 40 unit and 24 integration tests; only four expected macOS socket operations failed with `Operation not permitted`. |
| `cargo test -p context-relay-contextd` | Green outside the filesystem sandbox: 86/86 — 53 lib, 1 main, 4 authoritative, 2 daemon, 10 harness, 6 hook, and 10 watcher tests. The first sandbox run failed only 17 socket-bearing lib cases. |
| `cargo check --workspace --all-targets --all-features` | Green. A separate normal-build core library check is also green. |
| Desktop | Green: 6 files / 54 tests; typecheck and lint green. |
| Bindings / schemas / licenses | Green after providing both bundled Node and pinned Rust paths to the scripts. The earlier launcher-only `node`/`cargo` not-found attempts changed no source or dependency. |
| Scoped core Clippy | Green with only the documented inherited allowances for `large_enum_variant` and `too_many_arguments`. |
| Formatting / diff / status | Green before evidence-file creation. |

## Final correctness and security inspection

The full `216dc82..a544cda` range was inspected for canonical signature and AAD coverage, phrase and
plaintext lifetime, snapshot/CAS/exact lookup ordering, generation race behavior, schema-23
SQL/Rust agreement, pristine-target enforcement, certificate graph activation/rollback, offline
active replay, normal-build/test-support visibility, pairing authority, and secret-free
diagnostics. No unresolved Critical or Important issue remains.

Review-driven findings were converted into focused RED/GREEN regressions before their commits.
The final accepted design does not trust a receipt without exact provider lookup, does not install
either certificate before atomic activation, and does not expose a normal-build constructor for
test-controlled cryptographic randomness or the in-memory provider.

## Residual boundary and handoff

The recovery phrase authenticates the root and every accepted device claim, so a provider cannot
substitute attacker trust without the phrase. A completely malicious provider can still hide or
delete the root, partition clients, or present stale availability/generation history; this causes
denial/conflict and remains an availability/transparency limitation until authenticated hosted
history and monitoring exist.

The next independent slice is a trusted native cross-platform 24-word entry surface that feeds
this core without exposing phrase data to an untrusted renderer. GitHub identity reassociation,
device revocation, epoch/key rotation, production provider retention/abuse controls, and
credential-backed multi-install tests remain later state machines. Apple Developer access is not
required for this verified local core.
