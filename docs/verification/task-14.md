# Task 14 Verification Ledger

Task 14 makes Context Relay the primary memory and shared task ledger for
Claude Code, Codex, and Hermes. This ledger records the acceptance evidence for
the implementation plan's Task 14 checkpoint.

## Acceptance evidence

| Requirement | Evidence |
| --- | --- |
| Applied setup survives desktop closure | `authoritative_memory_v1::applied_setup_keeps_primary_memory_and_task_contract_alive_without_a_desktop_client` starts a real daemon, registers a project, applies the frozen Codex `0.144.1` setup, drops the desktop client, waits at least 750 ms after an edit, reconnects, accepts the candidate, and confirms the instruction/task contract remains installed. |
| Setup, watcher, review, and typed MCP form one chain | `end_to_end_v1::production_setup_watcher_review_and_actual_mcp_form_one_chain` previews and applies a real frozen Codex adapter plan, verifies the sealed setup/native lifecycles and exact source registrations, waits for the production watcher, accepts through authenticated desktop IPC, drops that client, then performs typed `context_relay_search` through the actual MCP server and daemon. |
| Existing content is preview-only and exports do not loop | `authoritative_memory_v1::a_managed_self_export_completes_preview_without_creating_a_candidate` applies and crash-recovers a real Hermes managed export, proves the exact full-file digest suppresses the initial candidate while completing preview, then appends one unmanaged paragraph and proves exactly that paragraph becomes one candidate. |
| Unknown versions receive no guessed setting | `authoritative_memory_v1::unknown_exact_codex_binding_is_watch_only_and_never_synthesizes_disable_keys` proves exact `0.145.0` sources remain watch-only and the native config is byte-identical without either supported disable key. |
| Exact import-only bindings activate without native mutation | `authoritative_memory_v1::import_only_codex_setup_activates_exact_watchers_without_native_mutation` applies and rolls back the real `0.145.0` Codex registration-only setup through daemon IPC, observes an edit while active, and proves the raw config is byte-identical and no locator or native executor is reached. The core matrix repeats apply, crash recovery, and rollback for Claude Code `2.1.215`, Codex `0.145.0`, and Hermes `0.18.3`. |
| Full setup fails closed without an exact native-memory binding | `primary_memory_setup_v1::full_claude_setup_rejects_unavailable_native_memory_before_persisting_any_plan` covers malformed settings and an unsafe supported-version binding. It proves no bridge/instruction/hook plan, native write, CLI declaration, or ledger is persisted, while the import-only exact-binding matrix remains accepted. |
| Managed Hermes exports remain Passive and CAS-bound | `primary_memory_setup_v1::passive_hermes_export_rejects_concurrent_target_change_and_preserves_live_bytes` freezes the Passive approval class and proves a post-preview target edit is rejected, restored to a terminal lifecycle, and never overwritten or activated. |
| Applied export digests are monotonic across setup replay | `native_memory_vault_v1::setup_none_and_terminal_replays_preserve_the_newest_export_digest` proves registration-only setup cannot clear a prior export digest and terminal replay cannot overwrite a newer export digest. |
| Managed task completion is typed and needs no session identifier | `end_to_end_v1::claude_and_codex_primary_instructions_complete_tasks_through_typed_mcp` proves both generated instructions contain the typed `context_relay_complete_task` fallback and no hook command or session-ID placeholder, then creates, completes, and lists each task through the actual MCP server and daemon. The instruction requires the current Context Relay task ID and explicit bounded evidence and never substitutes a vendor task ID. |
| Native hook evidence remains explicit and session-bound | `offline_service_v1::native_hook_task_evidence_completes_only_the_explicit_current_project_task` rejects missing-session, wrong-project, before-start, and after-stop fresh evidence; permits an exact recorded replay after stop; and still requires the persisted session binding. `end_to_end_v1::native_hooks_persist_only_allowlisted_fields_across_every_output_boundary` exercises the fail-closed task-evidence bridge boundary independently of the managed task instruction. |
| Unreviewed vendor completion events are disabled, not guessed | The Claude `2.1.213`/`2.1.214` fixtures record native `TaskCompleted` availability separately from `contextRelayCompatibleLifecycleHookEvents`. They state only the evidence actually captured: payload compatibility is not proven because no reviewed bounded schema is frozen. `claude_code_adapter_v1::memory_hooks_render_only_frozen_context_relay_compatible_events_with_literal_arguments` proves setup renders only `SessionStart` and `Stop` and never maps `TaskCompleted` or a vendor task ID. |
| Adapter upgrades preserve one active logical source | `native_memory_vault_v1::adapter_upgrade_supersedes_one_active_source_and_rolls_back_with_ledger_continuity` proves an adapter-version source-ID change supersedes the prior active source while preserving preview completion plus every observed, unmanaged, imported, applied full-file, and applied managed-body ownership digest; rollback removes the successor and restores the predecessor ledger exactly. `native_memory_vault_v1::superseded_setup_cannot_roll_back_before_its_active_successor` rejects predecessor rollback at claim time before inverse sealing or execution, then proves successor-first rollback restores and permits the original rollback. |
| One native path has one logical project owner | `native_memory_vault_v1::different_projects_cannot_claim_the_same_logical_native_path` exercises Claude's lossy project-key collision case and proves a second project scope cannot claim the same native path. `windows_case_and_extended_prefix_aliases_cannot_cross_project_ownership` portably proves ASCII case-only and ordinary-equivalent `\\?\` Windows spellings cannot bypass that boundary. `plausible_non_ascii_windows_case_alias_is_denied_across_projects` proves a lossless comparison fails closed for plausible Unicode case aliases; `exact_non_ascii_windows_path_supersedes_and_rolls_back` proves exact Unicode wire units still retain upgrade continuity. `opaque_windows_wtf16_registers_and_does_not_block_an_unrelated_source` proves an isolated-surrogate filename remains lossless and cannot poison later setup. `exact_opaque_windows_wtf16_supersedes_and_rolls_back_losslessly` proves exact opaque code units retain upgrade continuity and rollback. `extended_trailing_dot_path_remains_distinct_across_projects` and `extended_trailing_space_path_does_not_supersede_same_project_ordinary_path` prove extended-only names are not collapsed into ordinary Win32 identities. `windows_alias_spelling_preserves_same_project_supersession_and_exact_rollback` separately proves normalized ASCII aliases carry ledger state and restore the exact predecessor. |
| Initial preview observes the full stability window | `contextd::native_memory::tests::initial_preview_waits_for_one_stable_window_and_keeps_the_latest_bytes` proves an unpreviewed source is not submitted at 0 ms or 749 ms, restarts its debounce when bytes change at 750 ms, and submits only the final bytes after they remain stable through 1,500 ms. |
| Managed-block drift is a durable conflict | `native_memory_engine_v1::reconcile_rejects_a_modified_managed_owned_block` and `reconcile_rejects_managed_fence_removal_before_the_owned_digest_is_bound` reject owned-body edits and the legacy/bootstrap race. `native_memory_owned_drift_v1::managed_owned_block_drift_is_a_durable_conflict_after_restart` proves the managed-body digest and redacted diagnostic survive encrypted-vault reopen without importing or acknowledging drift as user memory. `native_memory_watch_v1::managed_owned_block_drift_is_reported_after_restart` exercises the same boundary through the production watcher. |
| Unsafe source text remains redacted and retry-bounded | `native_memory_watch_v1::rejected_text_records_only_redacted_digest_diagnostics_and_recovers_after_correction` proves diagnostic persistence contains only class, source identity, and digest, acknowledges the rejected digest without hot retry, and clears the diagnostic after a corrected stable edit. |
| Documentation placeholders are not false-positive secrets | `mcp::secret_text::tests::empty_environment_and_redacted_sensitive_assignments_are_documentation` accepts empty/comment, environment-provided, environment-variable, and redacted placeholder assignments with either separator. `mcp::secret_text::tests::short_nonempty_sensitive_assignments_are_secret_like` proves every other nonempty sensitive-key assignment is rejected, including short and quoted values. |
| Hook input is allowlisted | `end_to_end_v1::native_hooks_persist_only_allowlisted_fields_across_every_output_boundary` delivers real start, task-evidence, and stop hooks containing unique sentinels in every excluded field. It scans every plaintext cell from every test-vault table/column, native file contents, captured stdout/stderr, serialized IPC fixtures, and typed MCP task output. No sentinel appears. The raw session fixture's SHA-256 and bytes remain unchanged. |
| Desktop is a client, not a runtime owner | `offline-workflow.test.tsx` unmounts the desktop and confirms daemon-gateway project, review, and completed-task state remains available without network activity. The real daemon acceptance above proves observation and MCP access continue without a desktop connection. |

## Contract covered

- Supported settings are closed over Claude Code `2.1.213`/`2.1.214`, Codex
  `0.144.0`/`0.144.1`, and Hermes `0.18.1`/`0.18.2`.
- Setup is one reviewed preview/apply transaction; existing native content
  enters the existing pending review queue once.
- The daemon observes only adapter-declared high-level Markdown. A digest must
  remain stable for 750 ms before reconciliation.
- Context Relay managed exports are identified by the transactional applied
  digest and never become candidates. Their managed-body ownership digest is
  durable; user edits to an owned block become a redacted conflict.
- Hook IPC contains only validated lifecycle/task fields. Conversation content,
  transcripts, and tool payloads are excluded.
- Managed instructions complete tasks through typed MCP without bridge-path or
  lifecycle-session placeholders. Frozen vendor completion events are rendered
  only when their payload is explicitly Context Relay-compatible.
- Active source registrations are superseded by logical adapter identity with
  ledger continuity, and a native path cannot be active under two project
  scopes.
- The daemon and MCP bridge continue independently of the desktop renderer.

## Verification commands

Fresh scoped acceptance for the 2026-08-10 strengthening amendment and adjacent
native-memory repairs:

```text
cargo test -p context-relay-core --test claude_code_adapter_v1 -- --test-threads=1
cargo test -p context-relay-core --test primary_memory_setup_v1
cargo test -p context-relay-core --test native_memory_vault_v1 -- --test-threads=1
cargo test -p context-relay-core --test native_memory_engine_v1
cargo test -p context-relay-core --test native_memory_owned_drift_v1
cargo test -p context-relay-contextd native_memory::tests --lib
cargo test -p context-relay-contextd --test native_memory_watch_v1 --features test-support
cargo test -p context-relay-context-mcp --test end_to_end_v1 --features test-support -- --test-threads=1
cargo clippy -p context-relay-core --test claude_code_adapter_v1 --test primary_memory_setup_v1 --all-features -- -D warnings
cargo clippy -p context-relay-context-mcp --test end_to_end_v1 --features test-support -- -D warnings
```

## Final gate results

These fresh results cover the scoped local repair at the current shared tree.
They do not restate historical package/workspace counts that were not rerun.

| Command | Result |
| --- | --- |
| `cargo test -p context-relay-core --test claude_code_adapter_v1 -- --test-threads=1` | 37 passed |
| `cargo test -p context-relay-core --test primary_memory_setup_v1` | 8 passed |
| `cargo test -p context-relay-core --test native_memory_vault_v1 -- --test-threads=1` | 28 passed |
| `cargo test -p context-relay-core --test native_memory_engine_v1` | 26 passed |
| `cargo test -p context-relay-core --test native_memory_owned_drift_v1` | 2 passed |
| `cargo test -p context-relay-contextd native_memory::tests --lib` | 9 passed |
| `cargo test -p context-relay-contextd --test native_memory_watch_v1 --features test-support -- --test-threads=1` | 11 passed |
| `cargo test -p context-relay-context-mcp --test end_to_end_v1 --features test-support -- --test-threads=1` | 10 passed |
| Focused core and context-MCP strict Clippy commands above | Passed with no warnings |
| `rustfmt --edition 2024 --check` on the four changed Rust files | Passed |
| `git diff --check` | Passed |

All results above are local macOS arm64 evidence using frozen/synthetic harness
fixtures and test-owned installations. They do not replace the master plan's
required physical validation against clean installed Claude Code, Codex, and
Hermes releases on macOS arm64 and Windows x64. A macOS-to-Windows strict
Clippy attempt was also not counted: the cross build stopped in `onig_sys` and
vendored OpenSSL before reaching repository code because this host lacks the
Windows C/OpenSSL build environment. Current public Windows CI or a physical
Windows host must run that gate.
