# Context Relay v1 contract amendments

Ledger version: **1.2.0**. This is a pre-release normative companion to the v1
master plan. The master plan remains product and security authority; this ledger
records later reviewed contract hardening that must be implemented, documented,
and tested as one synchronized change. Unlisted behavior is not amended.

## A-001 — Local protocol 1.3 recovery enrollment

- **Authority:** [recovery-enrollment design](../superpowers/specs/2026-08-09-recovery-root-enrollment-design.md), [implementation plan](../superpowers/plans/2026-08-09-recovery-root-enrollment.md), and the implemented [protocol contract](protocol-v1.md).
- **Amendment:** At adoption, the exact local IPC boundary advanced to protocol 1.3 from the earlier 1.0/1.2 fixtures. Five phase-specific recovery-enrollment methods replaced the unused generic recovery routes. A-005 later advances the current boundary to 1.4 while retaining these recovery shapes.
- **Security rationale:** Begin and confirmation are confined to the trusted native recovery host; ordinary renderer projections are word-free. Exact-version negotiation rejects 1.2 peers before application dispatch instead of silently accepting a phrase-bearing or under-authorized shape.
- **Compatibility and migration impact:** This was a deliberate pre-release wire break. Protocol 1.2 peers cannot interoperate with 1.3, and A-005 now makes 1.3 a legacy peer of 1.4. Generated TypeScript bindings, handshake vectors, runtime-contract hashes, and role allowlists must advance together; no downgrade fallback is allowed.
- **Required synchronized artifacts:** [protocol constants/DTOs](../../crates/protocol/src/ipc.rs), [generated bindings](../../apps/desktop/src/bindings.ts), [exact handshake vectors/tests](../../crates/local-ipc/src/handshake_tests.rs), [runtime-contract hashes](../../crates/protocol/tests/fixtures/runtime-contracts-v1.json), [Tauri native host](../../apps/desktop/src-tauri/src/main.rs), [daemon routing](../../crates/contextd/src/recovery_enrollment.rs), [protocol documentation](protocol-v1.md), and [recovery verification](../verification/task-17-recovery-enrollment.md).

## A-002 — Operation schema v1 and checkpoint schema v2

- **Authority:** [signed-sync design](../superpowers/specs/2026-08-05-signed-sync-design.md), [canonical CBOR contract](cbor-v1.md), and [Task 16 evidence](../verification/task-16.md).
- **Amendment:** `SyncOperationV1` remains operation schema version 1. Scope-bound signed checkpoints use an independent checkpoint schema version 2 even though the Rust continuity type remains `CheckpointV1`.
- **Security rationale:** The earlier checkpoint schema 1 signature omitted account and workspace. Version 2 binds both tenancy fields, and transport requests select/partition the checkpoint version so legacy bytes cannot be relabelled into a scoped chain.
- **Compatibility and migration impact:** Operation bytes do not change. Legacy checkpoint schema 1 is explicitly unsupported, never decoded or upgraded, and cannot join a version 2 chain. Local migration 18 retires old pins/checkpoint rows and requests fresh scoped checkpoints. No hosted checkpoint transport exists to migrate; any retained remote v1 log must remain separately partitioned or be retired.
- **Required synchronized artifacts:** [sync DTOs](../../crates/protocol/src/sync.rs), [CBOR codec](../../crates/protocol/src/canonical_cbor.rs), [checkpoint engine](../../crates/core/src/sync/checkpoint.rs), [migration 18](../../crates/core/migrations/0018_checkpoint_scans.sql), [runtime fixture](../../crates/protocol/tests/fixtures/runtime-contracts-v1.json), [protocol documentation](protocol-v1.md), and [CBOR documentation](cbor-v1.md).

## A-003 — 50-bit locator plus independent 80-bit safety confirmation

- **Authority:** [pairing design](../superpowers/specs/2026-08-09-device-pairing-design.md), [pairing implementation plan](../superpowers/plans/2026-08-09-device-pairing.md), and [pairing evidence](../verification/task-17-pairing.md).
- **Amendment:** The ten-character Crockford code is a 50-bit, one-time request locator only. Trust installation additionally requires the joining user to enter the complete independent 80-bit safety number displayed by the approving device.
- **Security rationale:** A fresh joiner has no issuer trust anchor. Provider acceptance, locator possession, or a provider-returned certificate therefore cannot install trust. The safety transcript binds the pairing ID, exact signed request, and canonical approved payload; substitution changes the value, and the joiner never receives its independently computed expected number.
- **Compatibility and migration impact:** The locator display remains `XXXXX-XXXXX`, with the existing ten-minute/five-attempt limits, but locator-only clients are incompatible and must fail closed. Pairing persistence, IPC, daemon state, and UI add an `awaiting_confirmation` phase and full five-group entry before atomic certificate/key installation.
- **Required synchronized artifacts:** [pairing protocol](../../crates/protocol/src/pairing.rs), [pairing cryptography](../../crates/core/src/devices/crypto.rs), [coordinator](../../crates/core/src/devices/pairing.rs), [desktop Devices screen](../../apps/desktop/src/devices.tsx), [pairing request fixture](../../crates/protocol/tests/fixtures/pairing-request-v1.hex), [threat model](../security/threat-model.md), and [pairing verification](../verification/task-17-pairing.md).

## A-004 — Ordinary-feature CI coverage and candidate-verifier confinement

- **Authority:** The v1 master plan's supported-host lint/test requirement, the [CI workflow](../../.github/workflows/ci.yml), and the [native CI contract](../../scripts/native-ci-workflow.test.mjs).
- **Amendment:** “All-feature” CI means every ordinary product and test-support surface, not every release-qualification-only feature. Both Windows x64 and macOS arm64 lint and test `context-relay-core/test-support`, `context-relay-local-ipc/test-support`, `context-relay-contextd/test-support`, and `context-relay-context-mcp/test-support`. `context-relay-native-runner/ci-candidate-sidecar-smoke` remains excluded from workspace-wide builds and is enabled only for the two exact registered, ignored Semgrep candidate smoke tests.
- **Security rationale:** The candidate verifier deliberately accepts a disabled, non-publishable Semgrep target whose final corresponding-source and native-build evidence is still pending. Broad Cargo `--all-features` would compile that exceptional boundary into ordinary workspace tests and production-like builds, weakening the evidence that it is reachable only inside the exact qualification smokes. Explicit ordinary features provide complete test-support coverage while keeping candidate acceptance fail-closed everywhere else.
- **Compatibility and evidence impact:** This changes no runtime protocol, schema, or production feature default. Existing `rust` check compatibility is retained while lint, tests, policy, generated-artifact, license, frontend, whitespace, and native-build evidence become independently visible. A real remote Windows/macOS run is still required before CI can be marked verified. The source lock's identical, nonzero `workflowGitBlob` values remain sealed historical evidence and are not rewritten for ordinary CI edits; current native authority remains bound by the exact source-lock digest and `native-ci-provenance` action, runner, and toolchain pins.
- **Required synchronized artifacts:** [CI workflow](../../.github/workflows/ci.yml), [independent-gate contract](../../scripts/ci-gates-workflow.test.mjs), [native candidate/provenance contract](../../scripts/native-ci-workflow.test.mjs), and [master-plan audit](../verification/v1-master-plan-audit.md).

## A-005 — Local protocol 1.4 explicit Hermes profile binding

- **Authority:** The v1 master plan's exact-file transaction, multi-profile Hermes, typed IPC, and fail-closed compatibility requirements; the [Task 13 verification](../verification/task-13.md); and the implemented [protocol contract](protocol-v1.md).
- **Amendment:** The exact local IPC boundary advances from protocol 1.3 to 1.4. `HarnessParams.hermesProfile` and `SetupPlan.harnessProfile` are required-nullable wire fields. Hermes requests and plans require a nonempty explicit profile; Claude Code and Codex require null. The chosen profile is carried through preview and the sealed production plan used by apply, recovery, and rollback.
- **Security rationale:** Ambient or hard-coded `default` profile selection could preview one native target and later mutate another. Binding the profile into typed input, validation, the approval hash, and persisted sealed bytes makes profile substitution and silent fallback fail closed.
- **Compatibility and migration impact:** This is a deliberate pre-release strict-wire break. Protocol 1.3 peers cannot interoperate with 1.4, omitted fields fail strict decoding, and exact-version handshake tests reject both downgrade directions before dispatch. There is no released plan migration. Any pre-release persisted 1.3 plan must be discarded and previewed again under 1.4; it must not be inferred or upgraded from ambient profile state.
- **Required synchronized artifacts:** [protocol version constant](../../crates/protocol/src/lib.rs), [IPC DTO and validation](../../crates/protocol/src/ipc.rs), [sealed setup-plan DTO](../../crates/protocol/src/adapters.rs), [current-protocol MCP status contract](../../crates/protocol/src/mcp.rs), [generated TypeScript bindings](../../apps/desktop/src/bindings.ts), [generated JSON Schemas](../../schemas), [desktop runtime validation](../../apps/desktop/src/protocol-validation.ts), [desktop protocol contract tests](../../apps/desktop/src/protocol-contracts.test.ts), [runtime-contract fixture and hashes](../../crates/protocol/tests/fixtures/runtime-contracts-v1.json), [MCP status fixture](../../crates/protocol/tests/fixtures/mcp-output-valid.json), [exact local-version compatibility tests](../../crates/protocol/tests/protocol_v1.rs), [MCP schema parity tests](../../crates/protocol/tests/mcp_schema_parity_v1.rs), [exact handshake vectors/tests](../../crates/local-ipc/src/handshake_tests.rs), [frozen HMAC vectors](../../crates/local-ipc/tests/ipc_v1.rs), [production daemon bridge routing](../../crates/contextd/src/bridge_install.rs), [profile compatibility tests](../../crates/protocol/tests/hermes_profile_v1.rs), [protocol documentation](protocol-v1.md), [Task 13 verification](../verification/task-13.md), and [master-plan audit](../verification/v1-master-plan-audit.md).

## Change control

Every future amendment must receive a stable `A-NNN` identifier and record the
same five fields. Every link in **Required synchronized artifacts** is mandatory;
the change that adopts an amendment must update or explicitly revalidate each
listed artifact, add compatibility/fail-closed tests, and update the
[master-plan audit](../verification/v1-master-plan-audit.md). Removing an
amendment requires a superseding ledger entry; history is not rewritten.

For every local wire-version amendment, change control must explicitly check off both the
[runtime-contract fixture and hashes](../../crates/protocol/tests/fixtures/runtime-contracts-v1.json)
and the [exact handshake vectors/tests](../../crates/local-ipc/src/handshake_tests.rs), including
any frozen proof vectors owned by those tests. This closes the A-001 checklist gap: DTOs or
bindings alone are never sufficient compatibility evidence.
