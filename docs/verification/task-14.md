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
| Task evidence is explicit and session-bound | `offline_service_v1::native_hook_task_evidence_completes_only_the_explicit_current_project_task` rejects missing-session, wrong-project, before-start, and after-stop fresh evidence; permits an exact recorded replay after stop; and still requires the persisted session binding. `end_to_end_v1::claude_and_codex_primary_instructions_reach_same_session_task_evidence` uses each generated instruction, a real daemon, actual typed MCP task creation/listing, and matching session IDs plus current Context Relay task IDs. Neither adapter invents a vendor task-completion hook or substitutes a vendor task ID. |
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
  digest and never become candidates.
- Hook IPC contains only validated lifecycle/task fields. Conversation content,
  transcripts, and tool payloads are excluded.
- The daemon and MCP bridge continue independently of the desktop renderer.

## Verification commands

Focused acceptance completed during TDD:

```text
cargo test -p context-relay-contextd --test authoritative_memory_v1 --features test-support
cargo test -p context-relay-core --test primary_memory_setup_v1
cargo test -p context-relay-contextd --test native_memory_watch_v1 --features test-support
cargo test -p context-relay-context-mcp --test end_to_end_v1 --features test-support production_setup_watcher_review_and_actual_mcp_form_one_chain -- --exact
cargo test -p context-relay-context-mcp --test end_to_end_v1 --features test-support native_hooks_persist_only_allowlisted_fields_across_every_output_boundary -- --exact
vitest --run src/offline-workflow.test.tsx
```

## Final gate results

Implementation, blocking review-finding remediation, and local verification are
complete. Independent ordinary specification and correctness reviews passed
after all validated findings were fixed.

| Command | Result |
| --- | --- |
| `cargo test -p context-relay-core --test primary_memory_setup_v1` | 8 passed |
| `cargo test -p context-relay-core --test native_memory_vault_v1` | 17 passed |
| `cargo test -p context-relay-core --test offline_service_v1` | 15 passed |
| `cargo test -p context-relay-core --lib mcp::secret_text::tests::` | 3 passed |
| `cargo test -p context-relay-contextd --test authoritative_memory_v1 --features test-support` | 4 passed |
| `cargo test -p context-relay-contextd --test native_memory_watch_v1 --features test-support` | 10 passed |
| `cargo test -p context-relay-context-mcp --test end_to_end_v1 --features test-support` | 9 passed |
| `cargo test -p context-relay-protocol` | 88 passed |
| `cargo test -p context-relay-local-ipc` | 64 passed |
| `cargo test -p context-relay-core -- --test-threads=1` | 544 passed, 1 release-only performance test ignored |
| `cargo test -p context-relay-context-mcp --features test-support -- --test-threads=1` | 63 passed |
| `cargo test -p context-relay-contextd --features test-support -- --test-threads=1` | 71 passed |
| `vitest --run` in `apps/desktop` | 28 passed across 5 files |
| `eslint .` in `apps/desktop` | Passed with no diagnostics |
| `tsc --noEmit` in `apps/desktop` | Passed with no diagnostics |
| `cargo check --workspace --all-targets` | Passed |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | Passed with no warnings |
| `cargo fmt --all -- --check` | Passed |
| `git diff --check` | Passed |

The core suite was serialized because its pre-existing native CLI journal
fixtures share a named temporary vault when tests start concurrently. `TMPDIR`
was pinned to `/private/tmp` so macOS topology validation does not traverse the
platform `/var` compatibility symlink. The isolated native filesystem target
passed 9/9 before the complete serialized package run; no Task 14 source
behavior was changed for either fixture condition.
