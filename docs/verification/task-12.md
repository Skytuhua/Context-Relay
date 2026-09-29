# Task 12 Hermes adapter verification ledger

This ledger records the focused recovery audit for the Hermes `0.18.2` and
`0.18.1` adapter. The master implementation plan remains authoritative; the
adapter fails closed when the installed executable or its complete runtime
closure cannot be authenticated.

## Authority and frozen upstream evidence

| Surface | Frozen authority | Local contract |
|---|---|---|
| Hermes `0.18.2` | Tag `v2026.7.7.2`, commit `9de9c25f620ff7f1ce0fd5457d596052d5159596` | `pyproject.toml` declares `hermes = "hermes_cli.main:main"`; the installer creates a Python console script and Bash shim. Those surface files do not authenticate the installed `hermes_cli` package or import closure, so they remain import-only. |
| Hermes `0.18.1` | Tag `v2026.7.7`, commit `f9eca7e15f1c2bfe5194aae5aa489af53c0a1a23` | The same unauthenticated Python launcher topology; it also remains import-only. |
| Permission surface | Both frozen releases | `approvals.mode`, `timeout`, `deny`, `cron_mode`, `mcp_reload_confirm`, `destructive_slash_confirm`, plus root `command_allowlist`; every mapping is lossy outside Context Relay's native model. |

## Finding-to-evidence matrix

| Confirmed finding | RED evidence | Implemented boundary | GREEN evidence |
|---|---|---|---|
| An attempted official-launcher exception authenticated only launcher shape and interpreter bytes, not `pyvenv.cfg`, installed package metadata, `hermes_cli`, or the transitive Python import closure. A malicious exact-shaped venv could claim `0.18.2` and execute code during version discovery or validation. | `malicious_official_shaped_python_venv_is_import_only_and_never_executed` initially discovered `0.18.2` and entered the injected execution sink; its malicious `hermes_cli.main` canary represented the unauthenticated package code. A bypass review then made `direct_wrapper_version_runner_rejects_before_process_creation` RED against the lower-level runner itself. | Only native executable images are runnable. Every script or wrapper—including the upstream Python console script and Bash shim—is import-only, never staged, version-probed, validated, or granted Full capability. Both staging and the lower-level version runner independently reject wrapper snapshots. Wrapper support requires a future immutable manifest for the complete package/import closure. | The malicious-venv regression now returns `unknown`, records zero discovery and validation executions, leaves the canary absent, and observes `HarnessUnsupported`; the direct-runner regression rejects before its shell canary is created. Exact official-shaped Python and Bash controls also remain import-only; native-executable staging/version/validation controls still pass. |
| A Windows `hermes.exe` was classified Native from its `MZ` header even though setuptools/distlib Python console launchers are PE files with the same outer format. A renamed PE file bypassed an initial suffix-only repair. | `windows_distlib_console_launcher_shape_is_not_a_native_hermes_binary` classified a portable distlib-shaped fixture Native; `windows_hermes_exe_launcher_is_import_only_and_never_version_probed` reached its version canary; `windows_pe_launcher_magic_remains_import_only_when_renamed` then proved that removing `.exe` restored Native classification. | Every PE/MZ candidate is conservatively classified Wrapper regardless of its path or suffix. Without an immutable artifact/package-closure manifest, the adapter does not guess whether a PE image is a standalone implementation or a Python launcher. | All three portable tests now classify Wrapper; discovery returns `unknown`, records zero execution calls, and leaves the canary absent. Actual Windows runtime behavior remains a CI/physical-host gate. |
| Native transactions checked receipt digests but did not run Hermes semantic validation after writing. | `invalid_effective_config_is_compensated_before_receipt_commit` initially committed a config mutation when its fake executable could not validate it. | `NativeAdapter::validate_effective` reimports every reviewed source after writes and runs the real isolated `config check` when `config.yaml` changed; errors are sanitized and enter ordinary compensation. | The same regression now observes the sanitized validation failure, a compensated journal, and exact restoration of the original config. `memory_only_write_revalidates_sources_without_starting_config_check` preserves non-config export behavior. |
| Child validation staged `{}` rather than the reviewed effective config. | `effective_validation_uses_only_isolated_nonsecret_home` initially expected `{}`. | Validation reimports live state and stages the exact non-secret reviewed projection. | The test compares parsed staged YAML to the exact reviewed projection and independently checks that provider, header, auth, environment, and operational canaries are absent. |
| Permission fidelity was accepted from caller metadata and unknown fields could appear exact. | `unsupported_permission_mappings_are_visible_in_probe_and_preview` accepted a forged exact target; `permission_fidelity_comes_from_the_supported_version_allowlist` imported an invented field as exact. | Import, preview, classification, and apply derive fidelity from the frozen version allowlist. Unknown fields are `lossy/unknown_permission_semantics`; forged fidelity/reason pairs are invalid. | Four focused permission tests plus the complete Hermes adapter suite pass. |
| Any change to a redacted MCP/hook declaration was rejected, even when only reviewed safe scalars changed. | Both `redacted_*_owned_scalars_can_change_without_reserializing_secret_containers` regressions failed with `Redacted Hermes configuration cannot be rendered`. | Redacted changes are diffed at reviewed scalar leaves. Mapping/sequence replacement and secret/credential paths fail closed; exact YAML leaf patches preserve omitted native containers. | Both regressions change `enabled`/`timeout` while proving native-only secret lines, quoting, comments, placeholders, and safe siblings remain byte-identical. |
| Redacted MCP/hook patching authorized a newly supplied scalar key merely because its path was non-secret-shaped; metadata proved component identity, not that the leaf had been imported and reviewed. | `redacted_mcp_cannot_add_an_unreviewed_scalar_leaf` and `redacted_hook_cannot_add_an_unreviewed_scalar_leaf` both produced native mutations that added `timeout` even though it was absent from the imported reviewed projection. | A redacted patch may replace or deliberately delete only scalar leaves present in the fresh imported reviewed projection. New scalar keys and all collection changes fail closed before YAML patching. | Both regressions now return `InvalidRequest`, leave native YAML unchanged, and do not expose hidden credentials. The positive MCP control deletes one existing reviewed scalar, changes two others, and preserves hidden headers byte-identically. |

## Reproduced verification

The focused Hermes library suite passed 38 tests. The complete
`hermes_adapter_v1` suite passed 77 tests with all features. Strict
all-target/all-feature Clippy passed for `context-relay-core`, and the complete
all-feature core library suite passed 87 tests. A fresh final broad sweep then
ran every all-feature Core integration-test binary except the separately
documented macOS native-topology fixture; every executed binary passed,
including the 197-second randomized signed-sync convergence gate.

An earlier broader `cargo test -p context-relay-core --all-features` run did not
complete in the shared audit worktree. It first found the unrelated Codex test
`codex::tests::effective_validation_selects_trusted_layers_in_exact_cli_order_without_starting_stdio`
failing at `crates/core/src/codex.rs:4774` with `Codex MCP configuration is
invalid`; after its Task 11 owner repaired that path, the then-current library
tests and the 10 apply/13 preview/11 rollback bridge tests passed. The run
subsequently advanced to the unrelated Task 13 test
`native_cli_transaction_v1::file_only_hermes_plan_recomputes_its_explicit_v2_approval`,
which had an empty required `harnessProfile` (13 other tests in that suite
passed). Both owners have since repaired their shared-subsystem failures. The
final broad sweep also exposed two stale synthetic capability assumptions: an
MCP bridge fixture lacked the now-required Codex trust record, and the primary
memory matrix bound a managed requirements file while claiming Full Codex
capability. Those fixtures were corrected without weakening the production
gate. The synthetic Hermes transaction wrapper now reimports and validates the
applied effective configuration while the dedicated adapter tests retain the
real isolated `config check` execution and compensation coverage.

The daemon-level managed Hermes memory-export reproducer also passes. Inside
the filesystem sandbox it advanced past the Hermes transaction and failed only
when the test daemon attempted to create its local Unix socket; the same exact
test passed outside that sandbox (1/1), proving the transaction integration and
the environmental nature of the intermediate `Transport` error.

## Remaining physical-host evidence

- The official macOS Python installation is intentionally import-only. Enabling
  apply requires an immutable reviewed manifest that binds `pyvenv.cfg`,
  package metadata, every imported `hermes_cli` file, and the complete
  transitive import closure; no such repository artifact currently exists.
- Every Windows x64 PE/MZ Hermes candidate remains intentionally import-only,
  even when renamed, because PE format alone cannot distinguish a standalone
  implementation from a setuptools/distlib Python launcher. Enabling apply
  requires an immutable reviewed native-artifact or complete
  package/import-closure manifest plus Windows CI and physical-host evidence.
- Real gateway processes, filesystem/AV interference, crash recovery, and exact
  rollback still require the master plan's two clean-machine runs on macOS
  arm64 and Windows x64.
