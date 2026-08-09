# Task 17 Fresh-Install Recovery Core Implementation Report

Date: 2026-08-09

## Status

The fresh-install recovery core is complete through implementation Tasks 1–4. Task 5 verification
is complete pending the evidence commit. The local slice authenticates a saved recovery phrase,
creates one root-signed recovered device, wins an exact provider generation, atomically installs
the root/recovered trust graph in schema 23, reopens the original workspace material without the
provider, and uses the recovered device to pair a third SQLCipher Vault.

No hosted provider, OAuth mutation, real account credential, paid Apple service, production
deployment, push, or merge was used. Native phrase entry and identity reassociation are separate.

## Delivered local slice

- A strict version-1 `RecoveryDeviceClaimV1`, type-distinct `RecoveryRestoreId`, canonical
  fixed-map codec/signing preimage, recovery-root-signed recovered certificate, complete
  device-material AAD, bounded ciphertext, and redacted secret-bearing types.
- Phrase-authenticated root authority that recomputes the exact enrolled-record digest, matches
  both derived recovery public keys, opens the root metadata, and consumes all plaintext authority
  before persistence.
- A scope-bound `RecoveryRestoreTransport` with strict root snapshots, generation compare-and-set,
  replay-before-generation semantics, stable receipts, retained exact lookup, duplicate device and
  certificate rejection, bounded safe captures, and malicious-test projection hooks.
- Forward-only schema 23 with full duplicated root/claim/certificate/scope/key/epoch/generation
  fields, exact state nullability, full-row loading, otherwise-pristine target enforcement,
  exact replay, atomic two-certificate activation, rollback, and offline material reopen.
- A phrase-consuming coordinator with OS clock/randomness in production, injected deterministic
  sources only under test support, stable protected identity matching, prepared/provider-accepted
  resume, exact provider proof, durable Conflict, redacted safe errors, and offline active replay.
- Real recovery-to-pairing proof: recovered material feeds `VaultPairingMaterialSource`; a third
  device completes the existing independent 80-bit safety comparison; both Vaults reopen the same
  scope, epochs, and plaintext key arrays.

## RED/GREEN evidence

All four implementation tasks began at a compile or behavior RED. The focused regressions drove
missing APIs, canonical vectors, all public mutation coverage, provider CAS/races, full-row SQL
tamper detection, migration preservation, non-pristine denial, activation rollback, crash resume,
provider substitution, identity mismatch, and plaintext canaries.

Controller self-review found and fixed three additional correctness gaps with RED-first tests:

1. Prepared restore replay and conflict transition now reject an unexpectedly present certificate
   instead of reporting exact replay.
2. Entropy failure during the envelope RNG path now maps to retryable `transient` and persists
   nothing instead of being flattened into `recovery_invalid`.
3. A backward local clock no longer prevents a proven terminal provider conflict from becoming
   durable; the conflict time is clamped to the prepared timestamp.

The public ledger at `docs/verification/task-17-fresh-install-recovery-core.md` contains the
secret-free vector hashes, commands/counts, sandbox reruns, and residual boundary.

## Final GREEN matrix

| Gate | Evidence |
| --- | --- |
| Core recovery/enrollment/pairing/sync matrix | 176/176 green; all 256 signed-sync convergence seeds green, 199.43 s for the convergence target |
| Protocol | 110/110 integration tests plus unit/bin/doc targets green; protocol stays 1.3 |
| Local IPC | 68/68 green outside the macOS socket sandbox after the expected first bind denial |
| contextd | 86/86 green outside the macOS socket sandbox after the expected first transport denial |
| Workspace | all targets/all features and normal core library checks green |
| Desktop | 54/54, typecheck and lint green |
| Metadata | bindings, schemas, and licenses green with bundled Node plus pinned Rust on PATH |
| Static hygiene | scoped library/e2e Clippy, formatting, diff, and clean implementation status green |

Scoped Clippy uses only the inherited Task 16 allowances for `large_enum_variant` and
`too_many_arguments`. Initial desktop/metadata launcher failures were environment-only (`node` or
`cargo` absent from PATH), then passed without source or dependency changes.

## Security inspection

- The phrase, derived recovery private keys, and opened bundle are zeroizing and are consumed
  before the prepared write. No secret enters provider captures, safe errors, Debug output, or
  plaintext persistence.
- The claim signature covers the complete canonical claim, while the material AEAD independently
  binds root, restore, scope, generation, certificate digest, epochs, device, and both public keys.
- Provider state alone cannot install trust. Receipt, retained exact claim, prepared pins, device
  envelope, and both certificate graphs are validated before one activation transaction.
- Root substitution, wrong scope, mutated signed root, forged receipt, missing/substituted claim,
  stale generation, stable-identity mismatch, row tamper, and activation abort all install no
  trust.
- Normal builds expose the OS-random coordinator and abstract transport only. Deterministic crypto
  builders, provider fault controls, and the in-memory provider remain test-support-only.

The final full-range correctness/security inspection found no unresolved Critical or Important
issue. The accepted residual is malicious-provider availability/transparency: a provider can hide,
delete, partition, or present stale history, causing unavailable/conflict, but cannot substitute a
valid root or claim without the recovery phrase.

## Handoff

The next local design is a trusted native Windows/macOS 24-word entry surface that invokes this
core without placing phrase data in renderer state, browser storage, logs, or telemetry. Production
hosted persistence, authenticated account reassociation, device revocation, control/key epoch
rotation, and Apple signing/notarization remain separate. No paid Apple action is needed for this
completed core.
