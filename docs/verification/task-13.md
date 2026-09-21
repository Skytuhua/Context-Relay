# Task 13 — MCP memory, tasks, and handoffs verification ledger

Status: **partial**. The scoped recovery audit closed six confirmed local
implementation defects and reproduced the complete MCP bridge suite on macOS
arm64. Windows x64 execution, real installed-harness qualification, and the
master plan's two clean-machine release repetitions remain release blockers.

The v1 master plan remains the product and security authority. Protocol 1.4 and
its explicit Hermes profile are the reviewed strengthening amendment recorded
as [A-005](../protocols/contract-amendments.md).

## Finding disposition

2026-09-06 native discovery amendment: the fixed eight-tool first page below
hid completion, handoff and status from actual Codex 0.144.6 sessions. The bridge
now returns all eleven tools in one bounded first response, retains the old
opaque cursor and rejects invalid cursors. The [native evidence](codex-mcp-roundtrip-2026-09-06.md)
records real CLI/app-server memory and task round trips and restart persistence.
This supersedes the fixed two-page implementation choice in T13-01; official
revision negotiation, metadata, argument defaults and cursor validation remain.
The updated test is `tools_list_keeps_the_legacy_cursor_and_call_arguments_default_to_empty_object`.

| ID | Severity | RED evidence | Implemented boundary | GREEN evidence | Status |
|---|---|---|---|---|---|
| T13-01 | Important | Official 2025-06-18/2025-11-25 initialize metadata was rejected, omitted `tools/call.arguments` failed, and `tools/list` returned one unpageable collection. | The bridge accepts the two frozen official revisions, defined `_meta`/progress metadata, `clientInfo.title` and standard optional client fields, defaults absent arguments to `{}`, and exposes an opaque two-page cursor contract. Unknown lifecycle methods, invalid metadata, and invalid cursors still fail closed. | `official_initialize_envelopes_accept_client_title_and_request_metadata`; `tools_list_uses_an_opaque_cursor_and_call_arguments_default_to_empty_object`; complete lifecycle suite 17/17. | verified locally |
| T13-02 | Important | A bridge could dispatch an unbounded sequence of completed calls despite the 64-call concurrency cap. | Each bridge owns a frozen integer token bucket: burst 64, refill 16 calls/second. Admission occurs before UUID parsing or daemon dispatch; the limiter neither shares authority across bridges nor exposes a renderer control. | `per_bridge_rate_limit_has_a_frozen_burst_and_deterministic_refill`; complete dispatcher suite 20/20. | verified locally |
| T13-03 | Important | The daemon failed startup when the key was unavailable, while MCP status used constructed constants rather than daemon-owned vault/sync state. | The authenticated endpoint now starts in a locked state, rejects non-unlock vault work with the frozen recoverable `vault_locked` error, and exposes service-owned vault/sync status. An authenticated Desktop `Unlock` retries the protected service key store and atomically installs the workspace; no key bytes cross ordinary IPC. Native-memory supervision begins empty and receives ledgers only after unlock. | `locked_vault_keeps_the_authenticated_endpoint_alive_until_desktop_unlocks_it`; contextd library 55/55; MCP `locked_and_unavailable_errors_are_structured_and_redacted`. | verified locally |
| T13-04 | Important | Hermes bridge requests and sealed plans selected an ambient/default profile, so preview and recovery could address different native trees. | Protocol 1.4 requires nullable `hermesProfile`/`harnessProfile` fields, nonempty for Hermes and null for Claude Code/Codex. The exact profile flows through production preview, approval hashing, sealed apply, recovery, and rollback. Protocol 1.3 and malformed 1.4 peers fail before dispatch. | `hermes_setup_requires_an_explicit_typed_profile`; `sealed_setup_plan_binds_the_selected_hermes_profile`; exact local-version and handshake tests; rollback 11/11; native CLI transaction 14/14; binding/schema drift checks. | amended and verified locally |
| T13-05 | Important | Handoff filtering initially missed obvious RSA/EC/DSA/encrypted/OpenSSH key headers and common bearer/token families. Independent follow-up then found missing ASCII-armored PGP private keys, bare Slack `xoxs-` session tokens, and a false positive for `Bearer ${CONTEXT_RELAY_ACCESS_TOKEN}`. Pre-commit Gitleaks hygiene also caught complete detector/self-test examples in source. | One centralized output-boundary scanner now rejects PEM/OpenPGP private-key headers, sensitive assignments, bearer credentials, JWTs, AWS access keys, and bounded common provider-token shapes without echoing the value. Slack session tokens are included. Environment/redacted placeholders are checked before punctuation normalization, including bearer-wrapped placeholders. Private-key detectors and the GitLab self-test compose exact values at runtime, preserving coverage without storing secret-shaped literals or adding an ignore. | `all_common_private_key_pem_headers_are_secret_like`; `common_bearer_and_provider_token_families_are_secret_like`; `bearer_environment_placeholder_is_documentation`; `handoff_rejects_an_ascii_armored_pgp_private_key_without_echoing_it`; `handoff_rejects_a_bare_slack_session_token_without_echoing_it`; `handoff_accepts_a_bearer_environment_placeholder`; scoped Gitleaks scan of `secret_text.rs` reports no leaks. | verified locally after follow-up review |
| T13-06 | Minor | Selected done/canceled tasks were rendered beneath “Open and blocked tasks,” misrepresenting terminal state. | Open/blocked and explicitly selected terminal tasks render in separate accurate sections; completion evidence remains attached and bounded. | `handoff_enriches_ordered_selections_recent_decisions_tasks_evidence_and_instructions`; complete tasks/handoffs suite 17/17. | verified locally |

## Master-plan requirement coverage

| Requirement | Evidence and disposition |
|---|---|
| All eleven frozen MCP v1 tools | Protocol schema/fixture parity plus `mcp_memory_tools_v1` (25/25) and `mcp_tasks_handoffs_v1` (17/17). |
| Harness binding, active-project scope, and cross-project denial | `mcp_binding_v1` policy matrix; `record_id_does_not_bypass_project_scope`; three-harness real-daemon flow; selected-project and ambiguous-root fail-closed tests. |
| Expected revisions, completion evidence, and replay safety | Memory update/archive conflict and immutable replay tests; task create/update pair, evidence, altered/global operation-ID reuse, daemon restart replay, and canceled queued-write tests. |
| Handoff content and secret/transcript exclusion | Ordered memories, recent decisions, accurately sectioned tasks, completion evidence, relevant instruction references, aggregate bounds, centralized secret rejection, and explicit transcript-absence assertions. |
| No native setup through MCP | The MCP role has no setup methods; the three-harness daemon flow asserts no bridge installation. Setup is authenticated Desktop/Installer IPC, and the managed-requirements negative test proves zero CLI/native authority. |
| Active bridge installation | Claude Code/Codex/Hermes exact bridge component and reversible transaction tests; production Codex setup/watcher/review/MCP full-chain test. Hermes profile selection is sealed by A-005. |
| Lifecycle, cancellation, timeout, backpressure, and stdout purity | Lifecycle 17/17, dispatcher 20/20, end-to-end 10/10, hooks 14/14, and stdout 5/5. |
| Locked/unavailable recoverability | Locked daemon starts an authenticated endpoint; MCP receives structured redacted `vault_locked`; Desktop unlock transitions the same service status to unlocked/offline. |

## Synchronized protocol 1.4 evidence

A-005 advances every compatibility-sensitive artifact together: Rust DTOs and
validators, TypeScript bindings, JSON Schemas, desktop runtime validators and
tests, runtime-contract fixture/hashes, MCP status fixture/schema, local
handshake tests, frozen HMAC proof vectors, production bridge routing, sealed
plan/profile tests, protocol documentation, this ledger, and the master-plan
audit. The global amendment checklist now also names the runtime-contract
fixture/hashes and exact handshake vectors/tests explicitly, closing the A-001
change-control omission.

Reproduced local gates:

- Complete protocol crate tests passed with all features.
- Generated Rust/TypeScript binding and JSON Schema drift checks passed.
- Desktop protocol contracts passed 18/18; desktop lint and typecheck passed.
- Strict all-target/all-feature Clippy passed for protocol, core, contextd, and
  context-mcp.
- The centralized scanner passed 6/6 unit regressions and the complete
  tasks/handoffs suite passed 17/17 after independent follow-up review.
- Gitleaks 8.30.1 reproduced four pre-fix findings in the centralized scanner
  source, then reported no leaks after runtime composition; no allowlist,
  fingerprint exception, or broad exclusion was added.
- Context-mcp passed dispatcher 20/20, end-to-end 10/10, lifecycle 17/17,
  hooks 14/14, stdout 5/5, and its library test.
- Contextd library tests passed 55/55, including the locked daemon transition.
- Local IPC passed 68/68, including exact-version handshake and proof vectors.

These counts are scoped execution evidence, not substitutes for current public
CI or physical release qualification.

## Remaining release evidence

- Run all MCP, daemon, local-IPC, adapter-install, and native transaction tests
  with all ordinary features on a Windows x64 runner; repeat the macOS arm64
  run from a clean release machine.
- Exercise current, previous, unknown, blocked, and offline Claude Code, Codex,
  and Hermes installations. Include exact Hermes multi-profile preview,
  apply, daemon restart/recovery, rollback, and zero-write reapply.
- Perform real stdout/stderr capture through each installed harness and verify
  no non-MCP stdout bytes, secret-bearing diagnostics, or transcript
  persistence.
- Exercise locked/unlock/relock, Credential Manager/Keychain loss, daemon crash,
  call floods, cancellation races, and filesystem/AV interference on both
  supported hosts.
- Offline writes are locally authoritative, but hosted convergence remains a
  Task 16/provider gate and is not claimed here. No credentialed hosted,
  signing, publishing, or production action was performed.
