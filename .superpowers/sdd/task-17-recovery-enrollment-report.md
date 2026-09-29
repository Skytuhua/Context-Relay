# Task 17 Recovery-Root Enrollment Implementation Report

Date: 2026-08-09

## Status

Recovery-root enrollment and first-device bootstrap are implemented through Tasks 1–7. Task 8
verification is complete pending this report's evidence commit. The local slice generates and
confirms one 24-word recovery phrase, activates one recovery-root-signed genesis device, reopens
sealed workspace material after daemon restart, and uses that material to pair and reopen a second
SQLCipher replica.

No hosted service, OAuth setting, paid Apple service, production environment, push, or merge was
used. Phrase-based lost-device recovery and production provider deployment remain separate.

## Delivered local slice

- Exact protocol 1.3 recovery IDs, five phase-specific IPC requests, word-free native-host result
  unions, strict result-state validation, and the confined `DesktopRecoveryHost` role.
- BIP39 24-word generation, independent HKDF recovery signing/wrapping keys, canonical signed
  enrollment record, recovery-root-signed genesis certificate, and two fully bound encrypted
  material envelopes.
- Scope-bound exact provider compare-and-set with stable receipts, bounded phrase-free captures,
  provider-time identifiers, and fail-closed forged receipt/status handling.
- Forward-only schema 22 persistence for prepared/active/conflict enrollment, full-row hash and
  identity validation, exact replay, atomic trust activation, migration preservation, and sealed
  material reopen.
- A memory-only ten-minute challenge session with four unique positions, destructive invalid-answer
  behavior, exact cancellation/expiry, restart-safe prepared resumption, and provider-only Conflict.
- Real enrolled Vault material as the existing pairing flow's source, proven across two encrypted
  replica files, independent safety confirmation, and reopen.
- One ordered daemon Vault worker, shared protected device identity, resume-before-ready startup,
  authenticated local IPC, zeroizing JSON frames, and dedicated native phrase/approval prompts.
- A typed accessible Desktop recovery surface with no phrase result, browser persistence,
  clipboard, download, telemetry, or renderer-side cryptography.

## RED/GREEN and review evidence

Every task began with an absent API or behavior failure before production implementation. Focused
review-driven regressions closed protocol downgrade and Debug leakage; field/AAD mutation gaps;
provider receipt/status substitution; persisted-row corruption and rollback; provider/local split
recovery; role-confused begin/confirm; unsafe native-decline reporting; a renderer cancellation
result mismatch; challenge cleanup after unmount; and a restart double-cancel race that could have
re-enabled setup without authoritative Idle state.

The public ledger at `docs/verification/task-17-recovery-enrollment.md` records exact canonical
sizes/hashes, test counts, timings, sandbox reruns, inherited lint allowances, and residual trust
boundaries without reproducing secret vectors.

## Final GREEN matrix

| Gate | Evidence |
| --- | --- |
| Core recovery/pairing/sync matrix | 142/142 green in 285.53 s, including all 256 signed-sync convergence seeds |
| Protocol | 110/110 integration tests plus unit/bin/doc targets green |
| Local IPC | 68/68 green outside the macOS socket sandbox |
| contextd | 86/86 green outside the macOS socket sandbox |
| Workspace | all targets/all features check green |
| Desktop | 54/54; typecheck, lint, bindings, schemas, and licenses green |
| Static hygiene | scoped Clippy, formatting, diff, and clean implementation status green |

The initial local-IPC/contextd sandbox runs failed only macOS Unix-socket operations with
`Operation not permitted`; exact reruns outside that sandbox passed. Scoped Clippy uses only the
two inherited Task 16 allowances for `large_enum_variant` and `too_many_arguments`.

## Security boundaries

- Phrase and recovery private keys are memory-only, zeroizing application-owned buffers and are
  absent from the Vault, protected device store, provider, renderer, logs, and safe diagnostics.
- Both the recovery record and genesis certificate are independently signed; all identifiers,
  scope, keys, epochs, display metadata, certificate digest, and envelopes are bound before trust
  activation.
- The provider cannot establish trust by itself. Local activation requires the exact prepared pin,
  canonical record, verified receipt, and one atomic Vault transaction.
- The generic renderer request path cannot select the recovery-host role or invoke phrase-returning
  begin/final confirmation. React never receives the phrase.
- Plaintext canaries are scanned across encrypted-file companions, provider/test captures, safe
  formatting, browser/DOM surfaces, and reopened state.

The final full-range correctness and security reviews each reported no Critical, Important, or
Minor finding and marked the slice Ready. Security independently validated canonical
record/signature verification, both complete AADs, exact provider CAS, atomic Vault activation,
provider-only/missing fail-closed behavior, pre-dispatch role enforcement, and word-free
native/renderer projections.

## Handoff

The next local design is phrase-based recovery on a fresh installation. It must authenticate the
exact enrolled root/provider record and fail closed for a fully unpinned provider substitution.
Hosted provider deployment, real account credentials, abuse/retention controls, revocation and
epoch rotation, and Apple signing/notarization remain out of scope. No paid Apple action is needed
for the completed slice.
