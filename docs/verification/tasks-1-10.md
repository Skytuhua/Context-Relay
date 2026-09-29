# Tasks 1-10 Verification Ledger

This ledger follows the task names in
`Context-Relay-v1-Implementation-Plan.md`. Local completion was verified at
`3fdb5489506398019a7f4fe0fbacd184d80e1795`; the final documentation-only tip
must additionally pass the hosted matrix and live GitHub governance audit
before Tasks 1-10 are declared complete.

| Task | Current evidence |
| --- | --- |
| 1. Align repositories | `main` and `codex/bootstrap-v1` were atomically aligned at `3fdb548`. |
| 2. Licensing and governance | Tracked license, security, dependency, and workflow policy checks pass. Live settings and protections are applied after the final hosted run. |
| 3. Pinned workspace and CI | Workspace, toolchain, lockfile, action-pinning, workflow, schema, and generated-binding checks pass. |
| 4. Protocol v1 and threat model | Protocol, schema, generated-binding, and daemon-boundary tests pass. |
| 5. Encryption, recovery, and device certificates | All-feature workspace tests and `cargo deny check` pass. |
| 6. Encrypted vault and search | Vault, storage, migration, and search tests pass. The release 10,000-record search gate measured 48.538 ms P95 against the 150 ms limit. |
| 7. Daemon and authenticated local IPC | Completed at `122ff4e`; every required local IPC family has a typed daemon route and encrypted Vault work remains on the single worker. |
| 8. Offline desktop workspace | Completed at `f59dc9e`; project, memory, candidate, task, evidence, accessibility, and networking-disabled workflows pass 28 desktop tests. |
| 9. Isolated RuleSync and scanner runner | V1 implementation remains complete at `2ef5acd`; 99 non-native material/workflow tests pass under the superseding single-build-per-platform rules. Task 9R remains deferred and was not run. |
| 10. Claude Code adapter | Completed at `3fdb548`; supported-version discovery, bounded validation, import, native planning/apply/rollback, unmanaged-content preservation, project MCP approval detection, and unknown-version import-only behavior pass. |

## Exact local gates

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace --all-features`
- release 10,000-record search performance test
- `pnpm lint`, `pnpm typecheck`, `pnpm test --run`, and `pnpm build`
- generated binding, schema, license metadata, and daemon-boundary checks
- `cargo deny check`
- Task 9's 99 non-native material/workflow tests
- `git diff --check`
- `graphify update .`

Task 9R release qualification and manual publication are outside this
completion pass.
