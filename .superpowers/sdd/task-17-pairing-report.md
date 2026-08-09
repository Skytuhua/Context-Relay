# Task 17 Existing-Device Pairing Implementation Report

Date: 2026-08-09

## Status

The exact local existing-device pairing slice described by the Task 17 design and plan is
implemented through Tasks 1–8. Task 9 verification is complete pending this report's final local
commit. Task 17 as a hosted product capability is not complete: recovery-root enrollment, a
production hosted transport, credential-backed multi-install verification, revocation/recovery,
and Apple packaging remain separate work.

No Supabase project, OAuth setting, paid Apple service, or production environment was created or
mutated. The branch was not pushed or merged.

## Delivered local slice

- Canonical signed pairing requests and strict protocol 1.2 phase-specific IPC.
- Exact device certificates and a zeroizing X25519/XChaCha20-Poly1305 workspace-key grant.
- A caller-bound provider-like transport with 50-bit locators, HMAC-only lookup storage, exact
  600,000 ms expiry, five-attempt sessions, bounded payloads, and compare-and-set decisions.
- Protected, stable device identity storage with fail-closed load/create/reopen behavior.
- Forward-only schema 20/21 persistence for requests, decisions, certificates, awaiting
  confirmation, atomic completion, exact replay, and sealed-material reopen.
- A canonical outer approved payload and full 80-bit human-compared safety number. Provider
  acceptance alone installs no trust; the joining side cannot read or derive its expected number
  from normal APIs.
- One-transaction installation of the inviter genesis certificate, child certificate, key epochs,
  sealed material, and completion receipt after exact confirmation.
- Ordered contextd Vault-worker routing, restart resumption before ready, code-free invite status,
  durable terminal status, approver-only safety display, and direct trusted-device listing.
- An accessible React Devices screen with exact review, status/countdown announcements, focus
  restoration, terminal recovery, and truthful hosted-unavailable/local-stop behavior.

## Test-first and review evidence

Each plan task began with a focused compile or behavior failure. Review-driven regressions then
proved and fixed certificate-ID omission from AAD, unrelated certificate completion, incomplete
persisted-row validation, inconsistent exact replay timestamps, issuer-bootstrap substitution,
joiner access to safety inputs, invite/rejection restart regressions, provider/display digest
mismatch, terminal UI dead ends, role-confused joining cancellation, and unsafe debounce timing.

The detailed RED history, exact canonical hashes, retry/crash invariants, canary surfaces, and
residual handoff are recorded in `docs/verification/task-17-pairing.md`.

## Final GREEN matrix

| Gate | Evidence |
| --- | --- |
| Protocol all features | 100 integration tests plus unit/bin/doc targets, all green |
| Five focused core pairing targets | 47/47: identity 6, crypto 11, e2e 9, transport 8, Vault 13 |
| Signed replica convergence | 16/16, including all 256 deterministic randomized seeds |
| Local IPC | 66/66 outside the macOS filesystem sandbox |
| contextd | 79/79 outside the macOS filesystem sandbox |
| Workspace check | `--all-targets --all-features` green |
| Desktop | 40/40; lint, typecheck, build, bindings, schemas, and licenses green |
| Formatting and diff hygiene | green |
| Scoped core Clippy | green with only the two documented pre-existing Task 16 allowances |

The initial sandboxed local-IPC/contextd runs failed only macOS socket operations with
`Operation not permitted`; the exact commands passed outside that sandbox. The no-feature
all-target check still compiles integration harnesses that intentionally call `test-support`-only
APIs. Strict core/workspace Clippy still reports only the pre-existing Task 16
`large_enum_variant` and `too_many_arguments` lints. These results are recorded rather than hidden
or fixed by widening production APIs.

## Security and plaintext boundaries

- Canonical request, grant, approved-payload, certificate, receipt, and durable-row hashes are
  recomputed at trust transitions and exact replay boundaries.
- Weak/noncanonical Ed25519 and non-contributory X25519 keys fail closed; all request, scope,
  issuer, epoch, certificate, and envelope bindings are verified before key material is returned.
- Raw locator codes, device seeds, workspace root keys, epoch keys, opened grants, expected joiner
  safety values, and derivation inputs are absent from React and normal public APIs.
- Canaries are scanned across SQLCipher database/WAL/SHM files, provider captures, persisted
  plaintext projections, and safe Debug/error output after completion and reopen.
- Two authenticated daemon instances prove that only the approving side receives the expected
  safety number and the joining side remains opaque until user confirmation.

Independent correctness and security review findings were converted into focused regressions and
re-reviewed. Both final full-range reviews reported no Critical, Important, or Minor finding and
marked the approved local slice Ready. The correctness review's earlier artifact-only Minor is
closed by this report and the public verification ledger.

## Handoff

The next authorized implementation slice should enroll and protect a real recovery root and
provision the first active genesis certificate/workspace material without test fixtures. After
that, a production provider adapter needs authenticated caller identities, hosted persistence,
pepper custody, durable abuse controls, retention, and credential-backed cross-device tests.
Revocation, epoch rotation, recovery/reassociation, deletion/export, and macOS signing/notarization
remain separate reviewed state machines. Apple Developer access is not required for the completed
local slice and was not used.
