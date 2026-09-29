# Task 17 existing-device pairing verification

Date: 2026-08-09

Status: the exact local existing-device pairing slice is implemented and locally verified. Task 17
and hosted pairing are **not complete**. Recovery-root enrollment, a hosted provider adapter, and
credential-dependent cross-device verification remain in the handoff below. No Supabase project,
GitHub OAuth setting, Apple Developer account, paid service, or remote production system was
created or mutated by this work.

## Verified repository range

| Commit | Subject |
| --- | --- |
| `942ce3c` | `docs: design exact device pairing` |
| `ef3cf48` | `docs: plan exact device pairing` |
| `ad4e0ad` | `feat: freeze signed pairing requests` |
| `a613e67` | `fix: align pairing wire compatibility` |
| `3f1f81a` | `fix: update current protocol fixtures` |
| `8df798b` | `feat: issue exact encrypted pairing grants` |
| `a04cbed` | `fix: bind pairing certificate id into grant` |
| `112913b` | `feat: add bounded pairing transport` |
| `e3c839f` | `feat: persist protected device identity` |
| `cd03ecd` | `fix: keep pairing transport warning-free` |
| `95c4370` | `feat: persist exact pairing decisions` |
| `c9d1042` | `fix: validate persisted pairing replay rows` |
| `e6e2d62` | `fix: preserve pairing completion replay identity` |
| `bc8fb48` | `feat: pair trusted device replicas` |
| `4bf33b9` | `feat: expose exact device pairing over local IPC` |
| `e8ffe96` | `feat: add exact device pairing screen` |
| `691cb08` | `fix: keep pairing persistence lint-clean` |
| `b9dbcdd` | `test: stabilize native memory debounce gate` |

The final documentation commit follows this range and contains this ledger; its SHA cannot be
embedded in its own contents without changing that SHA.

## Frozen vectors and boundaries

The SHA-256 values hash the decoded canonical bytes, not the hexadecimal fixture text.

| Vector | Bytes | SHA-256 |
| --- | ---: | --- |
| `crates/protocol/tests/fixtures/pairing-request-v1.hex` | 225 | `10043c331e33f6c3f6aec76e346537a4a95966455e0f04125e7f49010b713163` |
| `crates/protocol/tests/fixtures/pairing-request-signing-preimage-v1.hex` | 191 | `896f3a685558203dcb79237fee5954ce2a8ca056a41d69219488b9e4c4016247` |
| `crates/core/tests/fixtures/pairing-grant-v1.hex` | 526 | `8b4bd329982b0dcb195e18720e35675967b989cb610ef4e5203e48e92843866f` |
| Canonical approved-payload fixture assembled in `device_pairing_crypto_v1.rs` | 828 | `d121600b4a148c2aa77b30e5623be2b4cca9141544bbe13700f4066a4982c591` |

- Pairing requests are capped at 8 KiB, grants at 16 KiB, and approved payloads at 32 KiB.
- A locator contains exactly 50 random bits rendered as two five-character Crockford groups. The
  raw code is returned once, never persisted by the coordinator/Vault, and the provider retains
  only a peppered HMAC lookup value.
- An invite expires at exactly `created_at + 600_000 ms`. The expiry comparison is inclusive.
- Five failed lookups exhaust the exact provider-authenticated joining session. Caller/session
  identity comes from a transport handle and cannot be supplied in pairing request JSON.
- The signed request covers pairing ID, nonce, device ID/name/platform, Ed25519 signing key, and
  X25519 wrapping key. Canonical Ed25519 and non-contributory X25519 checks fail closed.
- The safety transcript hashes the exact pairing ID, request digest, and outer approved-payload
  digest under `context-relay/pairing-safety/v1\0`. The first 80 bits are displayed as all five
  groups of four hexadecimal characters; partial, lowercase, truncated, and wrong values fail.
- Provider acceptance does not install trust. The fresh joiner decrypts or persists active trust
  only after the user enters the full safety number displayed by the approving device.

## Exact state, retry, and crash behavior

- Request submission is exact-byte idempotent for the same pairing and authenticated join session.
  Changed bytes, caller binding, nonce, identity, or request digest conflict.
- Decision submission is compare-and-set against the reviewed request digest. Exact prepared and
  accepted retries reuse the same canonical outer payload; a changed certificate, issuer, scope,
  epoch, encrypted envelope, or payload conflicts.
- Certificate, decision, join, and completion replay paths recompute canonical hashes and validate
  duplicated scope/device/state metadata before accepting an exact replay.
- A joining request is written to the encrypted Vault before provider submission. Reopen retries
  the same signed request after a transient submission failure.
- An approval is prepared locally before provider submission. Reopen reuses the exact signed
  certificate/grant rather than generating a second approval.
- Provider acceptance followed by a local failure resumes to one accepted local receipt after
  reopen. Rejection and cancellation remain terminal and install no trust.
- Awaiting confirmation persists the exact outer payload/transcript. Wrong or premature
  confirmation leaves the state unchanged; confirmation writes inviter certificate, child
  certificate, epochs, sealed material, and completion receipt in one transaction.
- A forced failure inside that confirmation transaction leaves no certificate or trust mutation.
  Completed material reopens by decrypting the canonical sealed grant with the protected stable
  device identity; plaintext workspace keys are never stored as separate database columns.
- Daemon startup loads the protected device identity and resumes pending decisions before the
  listener reports ready. All pairing operations use the ordered bounded Vault worker.

## TDD and review-driven RED evidence

1. Task 1 began with compile failures for the absent pairing request DTO, codec, constants, and IPC
   results. Follow-up REDs caught stale join fixtures, a still-advertised protocol 1.0 boundary,
   frozen HMAC vectors, and raw `PairingCode` Debug output. Protocol 1.2 now enforces the complete
   safety-confirmation IPC boundary and redacts codes recursively.
2. Task 2 began with compile failures for the absent pairing crypto module and domain-specific
   request sign/verify methods. The first implementation reached 4/6 before its fixture and exact
   invalid-key expectation were corrected. Review then proved that mutating `certificate_id` still
   opened a grant; the ID is now included in authenticated associated data and checked on open.
3. Task 3 began with missing role-separated transport modules. Tests proved exact code shape,
   ten-minute expiry, five-attempt budget, caller binding, request/decision CAS, stable receipts,
   payload bounds, and redacted provider captures before the in-memory provider was accepted.
4. Task 4 began with missing protected-identity interfaces. Malformed 64/65-byte records, storage
   errors, exact store-if-absent races, stable reopen, and redacted Debug paths were tested before
   the platform store and zeroizing versioned identity record were accepted.
5. Task 5 review reproduced an unrelated-certificate join completion and non-atomic certificate
   insertion. Further REDs caught omitted stored hashes/metadata and a pre-existing exact
   certificate whose first completion succeeded but identical replay conflicted. Schema 20/21 and
   shared strict row validation now preserve exact, atomic, crash-safe replay.
6. Task 6 security review blocked an untrusted caller-supplied issuer bootstrap. The design was
   amended to the exact outer payload plus a human-compared 80-bit safety transcript. Subsequent
   REDs closed direct joiner access to expected transcript/SAS inputs through crypto getters,
   provider handles, Vault transcript projections, and Debug output.
7. Task 7 caught an incomplete local-result validator, restart loss of invite status before a join,
   approving-side rejection later reported as pending, and display metadata not rebound to the
   durable accepted request. Provider-backed code-free status, durable terminal projections, and
   exact request-digest display checks fixed those paths.
8. Task 8 began with a missing Devices module. Later focused REDs caught approval/rejection focus
   loss, terminal states that hid all new-pairing controls, a joiner rendering an approver-only
   safety result, provider cancellation retaining the raw code, and a false joiner cancellation
   claim. The joiner can now only stop local checking with truthful residual-state text.
9. The final strict lint run found four mechanical tuple/nesting warnings in pairing persistence;
   type aliases and an equivalent let-chain removed them. The exact 47 pairing tests remained
   green. Two full contextd runs also exposed a 1 ms wall-clock debounce test margin; the exact
   749/750 ms boundary remains in deterministic unit tests, while the integration assertion now
   stays safely inside the window and the full 79-test contextd suite is green.

## End-to-end and plaintext evidence

The coordinator e2e uses two real SQLCipher Vault replicas and stable device identities sharing one
provider-like in-memory transport. It covers invite, join, exact display, approval, safety
confirmation, atomic trust installation, reopen, exact retry, expiry, attempt exhaustion,
cancel/reject, malicious self-consistent issuer substitution, provider/local failure splits, and
wrong/premature confirmation.

The authenticated contextd test crosses two daemon instances and proves the approving side alone
receives the expected safety number. The joining status remains opaque until the user supplies the
number, and completion returns the new trusted-device projection.

`TASK_17_PAIRING_KEY_CANARY_DO_NOT_LEAK` is split across the two plaintext keys. After completion
and reopen the tests scan both raw SQLCipher databases plus `-wal` and `-shm`, provider capture
bytes, persisted plaintext cells, and safe error/Debug strings. The transport-specific
`TASK17_PAIRING_CANARY` scan additionally covers provider captures and error output. No scanned
surface contains either plaintext canary, a raw locator code, a private device seed, or an opened
workspace key.

## Final local gate matrix

| Gate | Result |
| --- | --- |
| `cargo test -p context-relay-protocol --all-features` | Green: 100 integration tests; unit/bin/doc targets also green (14.06 s including shared build locks). |
| Five focused pairing core targets | Green: 47/47 — identity 6, crypto 11, e2e 9, transport 8, Vault 13 (23.57 s). |
| `cargo test -p context-relay-core --features test-support --test signed_sync_e2e_v1` | Green: 16/16, including 256/256 randomized convergence seeds (202.48 s test time). |
| `cargo test -p context-relay-local-ipc` | Green outside the filesystem sandbox: 39 unit + 27 integration = 66/66 (1.04 s). The first sandbox run failed only four macOS socket operations with `Operation not permitted`. |
| `cargo test -p context-relay-contextd` | Green outside the filesystem sandbox: 79/79 — 46 lib, 1 main, 4 authoritative, 2 daemon, 10 setup, 6 hook, 10 watcher tests (about 35 s). |
| `cargo check --workspace --all-targets --all-features` | Green (13.29 s final run). |
| `cargo fmt --all -- --check` | Green (1.56 s). |
| `cargo clippy -p context-relay-core --all-features --lib -- -D warnings` | Expected inherited Task 16 failure only: `AdmissionDecision` `large_enum_variant` and `OperationBuilder::build` `too_many_arguments` (7.65 s). |
| Same scoped Clippy with only those two documented allowances | Green (0.85 s). No Task 17 pairing lint remains. |
| `pnpm --dir apps/desktop test --run` | Green: 40/40 across 6 files (5.96 s reported by Vitest; 8.02 s command wall). |
| Desktop lint / typecheck / build | Green (7.71 / 8.24 / 7.00 s while run concurrently); Vite built 34 modules. |
| Binding / schema / license checks | Green (3.55 / 4.10 / 1.58 s while run concurrently). |
| `git diff --check` | Green. |

The no-feature `cargo check --workspace --all-targets` gate remains an inherited harness
configuration failure: integration targets directly use helpers deliberately private unless
`test-support` is enabled. Its final reproduction failed on private pairing inspect/confirm
capabilities and test-only Vault projections, which also positively demonstrates that normal builds
cannot obtain safety-transcript or opened-key material through those test APIs. Strict workspace
Clippy reproduces only the same two Task 16 lints. These failures are recorded, not concealed or
weakened with public production APIs.

## Independent review

- Task-level correctness reviews found and drove fixes for certificate/join identity binding,
  replay row validation, completion timestamp semantics, invite/rejection restart status, terminal
  UI recovery, approver/joiner cancellation semantics, and exact UI truthfulness.
- Task-level security reviews drove full certificate-ID AAD binding, the independent safety-number
  trust bootstrap, opaque joiner transcript boundaries, atomic inviter/child trust installation,
  protected identity handling, role-separated provider access, and SAS/raw-code redaction.
- The final full-range correctness review reported no Critical, Important, or Minor finding and
  marked the local slice Ready. Its earlier Minor was only the then-missing Task 9 evidence
  artifact and is closed by this ledger and the companion report.
- The final full-range security review reported no Critical, Important, or Minor finding and
  marked the approved local slice Ready.
- No review pass reported a Critical vulnerability in the accepted final slice.

## Remaining hosted and recovery handoff

Task 17 and hosted device pairing remain **not complete**. The following work requires a later
authorized slice and, where applicable, external credentials or account decisions:

- enroll and protect a real recovery root, then provision the first active genesis certificate and
  workspace material without test fixtures;
- implement the production `PairingTransport`/provider adapter with authenticated existing-device
  and joining-session identities, Edge Functions, the hosted `pairing_requests` storage contract,
  pepper custody, durable attempt/rate limits, retention, and abuse controls;
- deploy and exercise the hosted adapter with real Supabase Auth/RLS/Realtime/Edge Function
  credentials, multiple physical installations, disconnect/retry, expiry, revocation, and audit
  logs;
- add device revocation, control/key epoch rotation, recovery, reassociation, deletion, and export
  flows as separately reviewed state machines;
- package/sign/notarize the macOS application only when Apple Developer access is available. No
  paid Apple action is necessary for the local implementation and verification recorded here.

Until a production transport is injected, the daemon and desktop remain truthful: trusted devices
can be listed, but pairing returns/shows `Pairing needs the hosted device service and is not
available in this build.` No process-local invite is presented as a cross-device service.
