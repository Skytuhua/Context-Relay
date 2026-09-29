# Task 17 Fresh-Install Recovery Core Progress

Design: `docs/superpowers/specs/2026-08-09-fresh-install-recovery-core-design.md`

Plan: `docs/superpowers/plans/2026-08-09-fresh-install-recovery-core.md`

Implementation baseline: `216dc82`

Task 1: complete (`73e4802`; type-distinct restore ID, phrase-authenticated recovery authority,
canonical signed claim/preimage vectors, root-signed recovered certificate, complete material AAD,
strict mutation/weak-key/bound/redaction coverage)

Task 2: complete (`149d4b0`; scope-bound root snapshot and restore transport, one-lock generation
CAS, exact replay-before-generation, stable receipts and retained lookup, reused-identity rejection,
safe captures, forged/missing proof controls, account deletion)

Task 3: complete (`34f15bb`; forward-only schema 23, strict full-row loading, pristine target,
prepared/conflict/active exactness, atomic root+recovered certificate activation, rollback/reopen,
common recovered/enrolled pairing material source, migration and plaintext-canary coverage)

Task 4: complete (`a544cda`; phrase-consuming OS-random coordinator, exact stable identity,
prepared/provider-accepted resume, provider proof before activation, durable terminal conflict,
offline active replay, 13-case malicious/crash/race/canary e2e, real recovered-device pairing of a
third Vault)

Task 5: verification complete pending the evidence commit (core 176/176 including all 256 signed
sync seeds, protocol 110/110, local IPC 68/68, contextd 86/86, Desktop 54/54, workspace all-feature
and normal checks, bindings, schemas, licenses, formatting, diff, and scoped Clippy green; final
full-range correctness/security inspection found no unresolved Critical or Important issue)
