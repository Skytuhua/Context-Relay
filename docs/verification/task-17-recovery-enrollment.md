# Task 17 recovery-root enrollment verification

Date: 2026-08-09

Status: the credential-free recovery-root enrollment and first-device bootstrap slice is
implemented and locally verified. It creates one recoverable trust root, activates the first
device, survives restart, and uses the resulting material to pair and reopen a second SQLCipher
replica. Phrase-based recovery on a fresh installation, a hosted provider adapter, remote
credential-backed verification, and Apple packaging remain separate work.

No Supabase project, GitHub OAuth setting, Apple Developer account, paid service, production
deployment, push, or merge was created or mutated by this work.

## Verified repository range

| Commit | Subject |
| --- | --- |
| `97ac275` | `docs: design recovery-root enrollment` |
| `00a324e` | `docs: require trusted recovery enrollment` |
| `b37a8e8` | `docs: plan recovery-root enrollment` |
| `d151a74` | `feat: freeze recovery enrollment protocol` |
| `52c0c4e` | `feat: add signed recovery enrollment records` |
| `b26c8e7` | `feat: add recovery enrollment transport` |
| `f044eeb` | `feat: persist recovery enrollment` |
| `6186aa2` | `feat: bootstrap pairing from recovery enrollment` |
| `fbac003` | `feat: require native recovery approval` |
| `28ba134` | `feat: add recovery enrollment experience` |

The implementation baseline is `a74af6a`. The final documentation commit follows this range and
cannot include its own SHA without changing that SHA.

## Frozen vectors and boundaries

The SHA-256 values below hash decoded canonical bytes rather than hexadecimal fixture text. No
phrase, private key, workspace key, raw envelope, or safety number is reproduced here.

| Vector | Bytes | SHA-256 |
| --- | ---: | --- |
| `crates/core/tests/fixtures/recovery-enrollment-record-v1.hex` | 710 | `5a9a470d35924a44e599b9d9f753ad54e2dc8b967c22a88363e87daf2535e999` |
| `crates/core/tests/fixtures/recovery-enrollment-signing-preimage-v1.hex` | 687 | `79fd50d1a6ffcebdceb848b4a48a453107c368b732156eca3ebba6b738cd0dd0` |
| Frozen encrypted recovery-metadata envelope | 195 | `ed7eefc978b02ccd581f040138980d6cac5ae0db84be4ab95ed07bcfbf052bf0` |
| Frozen device-workspace-material envelope | 195 | `a27aaac830e16cf7cf605c15992e173e7943bd0c0252c4ebfa312252dc4d51cc` |

- The local IPC protocol boundary is exactly 1.3. Older exact-version peers fail before
  application dispatch.
- The forward-only encrypted Vault schema is version 22.
- The recovery record schema remains version 1 and is bounded at 32 KiB.
- The one-time phrase is BIP39 English with 24 words generated from 256 bits of OS randomness.
- An unconfirmed enrollment expires inclusively at 600,000 ms and challenges exactly four unique,
  sorted, one-based positions.
- Any wrong, missing, extra, duplicate, reordered, expired, or cross-enrollment confirmation
  consumes the memory-only session and installs no trust.
- Initial control and key epochs are exactly 1. Recovery metadata and device material use separate
  domains, complete associated-data layouts, and separate encrypted envelopes.

## Exact trust and restart behavior

- The recovery phrase and recovery private keys exist only during the unconfirmed in-memory
  session. They are not persisted in SQLCipher, the platform identity store, provider state,
  browser storage, logs, errors, or normal Debug output.
- The full phrase crosses authenticated local IPC only to the trusted Tauri Rust host. It appears
  in one native blocking dialog and never enters a Tauri result, JavaScript, React state, or the
  DOM. The renderer receives only the enrollment ID, four positions, and timestamps.
- Ordinary Desktop IPC can inspect/cancel status but cannot begin or confirm. Those two operations
  require the confined `DesktopRecoveryHost` role and dedicated native commands; the generic
  renderer request path rejects them before delegation.
- Provider registration is exact-byte compare-and-set. Provider-only state is Conflict, not trust.
  Complete requires a strictly validated local active pin and the identical provider projection.
- The provider receipt is checked against the exact canonical record before one Vault transaction
  activates the recovery root, genesis certificate, epochs, and sealed device material. A forced
  failure rolls the entire activation back.
- Prepared submission resumes after restart with the same canonical record and encrypted material.
  A crash before confirmation invalidates the memory-only phrase; a crash after activation reopens
  material through the stable protected device identity.
- The existing pairing coordinator reads the enrolled Vault material, issues the second-device
  grant, requires the independent 80-bit safety comparison, and reopens equivalent material in two
  separate SQLCipher Vaults.
- The React surface cleans challenge words on cancel, expiry, conflict, error, completion,
  unmount, and restart. Lost in-memory sessions are canceled before a replacement setup is
  offered; durable submitting state resumes by exact enrollment ID.

## Test-first and review-driven RED evidence

1. Protocol work began with absent IDs, request/result DTOs, role separation, and generated
   bindings. REDs also caught protocol 1.2 still being accepted and phrase-bearing Debug surfaces.
   Protocol 1.3 now has strict phase-specific messages and word-free host results.
2. Crypto work began with absent recovery record, codec, derivation, and envelope APIs. Frozen
   vectors and mutation tests then drove canonical map validation, record and certificate
   signatures, independent signing/wrapping derivations, complete AADs, weak-key rejection, and
   redacted secret-bearing types.
3. Transport work began with absent caller-bound recovery handles. REDs proved exact registration
   compare-and-set, account/workspace isolation, provider-time receipts, forged receipt/status
   rejection, bounded captures, and phrase-free diagnostics.
4. Persistence work began with absent schema-22 state. REDs covered full-row tampering, exact
   prepared/active replay, migration preservation, provider/local split failures, atomic rollback,
   sealed-material reopen, and plaintext-canary absence.
5. Coordinator integration began without a real enrolled material source. REDs drove one-time
   phrase challenge lifetime, invalid-answer consumption, restart resumption, provider-only
   Conflict, receipt revalidation, and the recovery-to-pairing two-Vault proof.
6. Native integration began without recovery routing or host commands. Tests drove role denial,
   ordered Vault-queue routing, identity/resume-before-ready ordering, zeroizing JSON frame buffers,
   native phrase/approval decline behavior, and word-free command results.
7. Desktop work began without a recovery UI. Further REDs caught a cancellation-result mismatch,
   unmount-after-begin cleanup, restart double-cancel races, and unsafe re-enablement before an
   authoritative Idle projection. The final UI is accessible, responsive, and fail-closed.

## End-to-end and plaintext evidence

The coordinator tests use real encrypted Vaults, protected stable device identities, and
provider-like in-memory transports. They cover phrase creation/confirmation, exact expiry,
invalid confirmations, cancellation, restart, provider-before-local activation, forged receipts
and statuses, persisted-row tampering, atomic rollback, fully provider-only state, enrollment to
pairing, two-replica reopen, and exact trusted-device graphs.

Canary checks scan raw SQLCipher database files plus WAL/SHM companions, test-only plaintext-cell
projections, provider captures, serialized safe results, errors, Debug output, renderer DOM,
browser storage, clipboard/download/analytics mocks, and post-terminal coordinator state. The
single authenticated phrase response/native prompt is the only intended plaintext occurrence.
No scanned persistent or untrusted surface contains a phrase, derived recovery secret, workspace
root key, or active epoch key.

## Final local gate matrix

| Gate | Result |
| --- | --- |
| Twelve focused core targets | Green: 142/142, 0 failed, 285.53 s wall. Includes recovery crypto 6, transport 6, Vault 6, e2e 12; pairing crypto 11, transport 8, Vault 13, e2e 9; signed-sync e2e 16 across 256/256 seeds; backoff 4, checkpoint 8, engine 43. |
| `cargo test -p context-relay-protocol --all-features` | Green: 110/110 integration tests; unit/bin/doc targets also green (24.25 s). |
| `cargo test -p context-relay-local-ipc` | Green outside the filesystem sandbox: 40 unit + 28 integration = 68/68 (1.16 s). The first sandbox run had only four expected macOS socket `Operation not permitted` failures after all 40 unit and 24 integration tests passed. |
| `cargo test -p context-relay-contextd` | Green outside the filesystem sandbox: 86/86 — 53 lib, 1 main, 4 authoritative, 2 daemon, 10 harness, 6 hook, and 10 watcher tests (34.89 s). The first sandbox run failed only socket-bearing cases. |
| `cargo check --workspace --all-targets --all-features` | Green (3.64 s). |
| Desktop test suite | Green: 54/54 (3.53 s); typecheck and lint also green. |
| Binding / schema / license checks | Green. The repository script is `pnpm license:check`; the plan's `pnpm check:licenses` spelling does not exist. An initial environment-only launcher failure was corrected with the pinned Rust environment, after which the real license gate passed. |
| Scoped core Clippy | Green (1.64 s) with only the two documented inherited Task 16 allowances: `large_enum_variant` and `too_many_arguments`. |
| Formatting / diff / status hygiene | Green; the implementation worktree was clean before evidence files were written. |

## Independent review

- The final full-range correctness review found no Critical, Important, or Minor issue and marked
  the slice Ready.
- Task-level correctness and security review findings were converted into focused RED/GREEN
  regressions before their commits. Those reviews covered provider reconciliation, signatures and
  AAD, schema activation rollback, startup ordering, role confinement, native-only phrase display,
  renderer cleanup, and the recovery-to-pairing trust graph.
- The final full-range security review found no Critical, Important, or Minor issue and marked the
  slice Ready. It independently validated canonical record/signature verification, both complete
  AAD layouts, provider CAS/projections, atomic Vault activation, provider-only/missing fail-closed
  behavior, pre-dispatch role enforcement, and word-free native/renderer projections.
- No review pass reported a Critical vulnerability in the accepted final slice.

## Residual boundary and handoff

Provider compare-and-set coordinates honest first-device races but is not an independent trust
anchor. A completely unpinned client cannot tell an empty account from a malicious provider that
hid an earlier root. This slice therefore preserves the first device's durable local pin but does
not claim account-wide continuity after every local pin is lost.

The next independent design is user-entered phrase recovery on a fresh installation. It must prove
the enrolled recovery root and exact provider record before installing any trust or key material.
A production provider adapter, authenticated hosted identities, retention/abuse controls,
credential-backed multi-install testing, revocation/rotation/reassociation, and macOS
signing/notarization remain separate work. Apple Developer access is not required for this verified
local slice.
