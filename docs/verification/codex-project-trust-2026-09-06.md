# Codex project trust — 2026-09-06

Context Relay looked up project trust using the exact physical path it bound for
file operations. On Windows this commonly contains a `\\?\` prefix and mixed
case. Codex's native project lookup instead uses a compatible canonical path and
ASCII case normalization. The adapter therefore skipped configuration that Codex
loaded and accepted a verbatim-only trust entry that Codex ignored.

The adapter now normalizes the trust lookup key without changing the physical
paths used for reads, approvals or writes. It uses `dunce` 1.0.5, already locked
in the workspace, to simplify only paths that have an equivalent ordinary form.
Names that require a verbatim path remain unchanged. An exact normalized key
wins; remaining case aliases follow Codex's lexical precedence. Unset trust does
not mask another matching entry. Malformed trust is rejected, and non-ASCII
characters are not case-folded. Unix lookups retain their case sensitivity.

Review also found that root trust enabled every nested configuration layer.
Trust is now evaluated per bound directory: an explicit directory decision
overrides the project-root fallback. Imports and effective configuration skip
untrusted layers while preserving the trusted layers. Setup and mutation guards
require every selected layer to be trusted. No project or hook trust is written.

The matching reference is the pinned
[Codex configuration loader](https://github.com/openai/codex/blob/5d1fbf26c43abc65a203928b2e31561cb039e06d/codex-rs/config/src/loader/mod.rs).
The 0.144.0 and 0.144.1 source tags contain the same key-lookup functions. Older
synthetic fixtures wrote the physical Windows spelling as their trust key; the
fixture builders now use the native spelling while keeping their file bindings.

## Native comparison

The ignored Windows test
`codex::session_tests::pinned_codex_project_trust_matches_adapter_lookup` compares
the actual 0.144.6 app-server's `hooks/list` result with the adapter's selected
effective configuration layer in fourteen disposable profiles:

- Lowercase and uppercase aliases; conflicting normalized entries in both directions.
- Lexical alias precedence in both directions, with no normalized exact entry.
- Verbatim-only entries, including a verbatim request path, and a normalized denial.
- Unset trust and a non-ASCII case alias.
- Nested inheritance, an explicit child denial, and a trusted child under an untrusted root.

The nested mixed-trust cases also assert that overall setup remains blocked.
The comparison uses a single inert, untrusted project hook. It initializes the
app-server and lists hooks; it starts no thread, executes no hook and calls no
model. Each fresh home has a cleared environment. The pinned Codex executable
hash is checked before and after; configuration and hook bytes remain unchanged.
The existing stdin-gated Windows job contains descendants, with a 150-second
outer deadline, 15-second child deadlines and bounded output. Native path
comparison handles the verbatim request without stripping prefixes manually.

## Evidence

The original Windows normalization regression failed before the fix. The native
comparison also exposed the incorrect verbatim fallback. The nested-directory
regression failed before the per-layer correction.

Final native comparison: fourteen cases pass in 59.91 seconds. Source checks pass
111 core library tests, 68 Codex adapter tests, 17 primary-memory setup tests and
five bridge-installation tests. Six opt-in core tests remain ignored by the
ordinary suite. The setup matrix covers apply, crash recovery, changed settings,
exact Undo and source-registration privacy. Core, daemon and MCP all-target Clippy
with test support and warnings denied passes. Independent review approved the
normalization and nested-directory correction.

Local evidence under `.codex/context-relay-closeout-2026-09-05/`:
`codex-project-trust-red.log`, `codex-nested-trust-red.log`,
`codex-project-trust-native-layers.log`, `codex-project-trust-suites-final.log`,
and `codex-project-trust-clippy-complete.log`. Run the native test with the explicit
`CONTEXT_RELAY_TEST_CODEX_EXE` and `CONTEXT_RELAY_TEST_NODE_EXE` paths used by the
[lifecycle qualification](codex-native-hooks-2026-09-06.md):

```powershell
cargo test --config 'profile.dev.package.sha2.opt-level=3' -p context-relay-core --lib pinned_codex_project_trust_matches_adapter_lookup -- --ignored --nocapture
```

## Remaining acceptance

Project trust is distinct from a hook command's trust and from a verified bridge
connection. This corrects lookup and bound-directory behavior; it does not add a
live readiness endpoint or qualify custom project-root markers, linked-worktree
root fallback, managed configuration, launch overrides, installed credential
binding or full native setup/recovery. Codex 0.144.6 remains ImportOnly. Native
desktop control remains paused, and the local 11d6740 installer is unchanged.
