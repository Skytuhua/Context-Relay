# Context Relay v1 contract amendments

Ledger version: **1.0.0**. This is a pre-release normative companion to the v1
master plan. The master plan remains product and security authority; this ledger
records later reviewed contract hardening that must be implemented, documented,
and tested as one synchronized change. Unlisted behavior is not amended.

## A-001 — Local protocol 1.3 recovery enrollment

- **Authority:** [recovery-enrollment design](../superpowers/specs/2026-08-09-recovery-root-enrollment-design.md), [implementation plan](../superpowers/plans/2026-08-09-recovery-root-enrollment.md), and the implemented [protocol contract](protocol-v1.md).
- **Amendment:** The v1 product's exact local IPC boundary is protocol 1.3, not the earlier 1.0/1.2 fixtures. Five phase-specific recovery-enrollment methods replace the unused generic recovery routes.
- **Security rationale:** Begin and confirmation are confined to the trusted native recovery host; ordinary renderer projections are word-free. Exact-version negotiation rejects 1.2 peers before application dispatch instead of silently accepting a phrase-bearing or under-authorized shape.
- **Compatibility and migration impact:** This is a deliberate pre-release wire break. Protocol 1.2 peers cannot interoperate with 1.3. Generated TypeScript bindings, handshake vectors, runtime-contract hashes, and role allowlists must advance together; no downgrade fallback is allowed.
- **Required synchronized artifacts:** [protocol constants/DTOs](../../crates/protocol/src/ipc.rs), [generated bindings](../../apps/desktop/src/bindings.ts), [Tauri native host](../../apps/desktop/src-tauri/src/main.rs), [daemon routing](../../crates/contextd/src/recovery_enrollment.rs), [protocol documentation](protocol-v1.md), and [recovery verification](../verification/task-17-recovery-enrollment.md).

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

## Change control

Every future amendment must receive a stable `A-NNN` identifier and record the
same five fields. The change that adopts it must update every listed artifact,
add compatibility/fail-closed tests, and update the
[master-plan audit](../verification/v1-master-plan-audit.md). Removing an
amendment requires a superseding ledger entry; history is not rewritten.
