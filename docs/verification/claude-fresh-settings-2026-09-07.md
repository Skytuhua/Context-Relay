# Claude setup with missing settings files

Claude setup required a pre-existing user `settings.json` for lifecycle hooks,
and a sibling metadata template to create project settings. Both requirements
blocked first use even when the configuration directories already existed.
Two focused tests reproduced these errors before correction.

Missing settings now render from an empty JSON object and use the native
filesystem's private creation metadata. Existing-file metadata and unrelated
fields remain preserved. Preview creates no files. Undo restores prior absence;
archiving absent hooks does not create an empty settings file.

## Concurrent edits and restoration

Review exposed a read/render-before-snapshot race: if another process created
settings between rendering and fingerprint capture, the old empty-map output
could be approved against the new file. A deterministic per-adapter test hook
reproduced this. Planning now derives rendered bytes and metadata from the same
snapshot used for the expected fingerprint. The new foreign file is rejected
and preserved. The hook exists only in tests and defaults off.

The real Claude fresh-files fixture then found an Undo failure. After restoring
absence, the memory-state verifier compared against a hypothetical newly created
file, whose metadata used the parent directory's updated timestamps. This
misclassified the correct restored absence as a conflict. A focused regression
reproduced it by explicitly changing the parent's modification time.

The verifier now accepts the exact approved absent state for a matching payload
target. It requires the intended fingerprint to match both the current required
state and the decoded absent content. Existing live snapshot, dependency digest,
and source-binding checks remain required. The regression also confirms rejection
of a recreated target and a newly added local settings override.

## Evidence

- Missing-file reproductions: `.codex/claude-fresh-settings-red-valid.log`.
- Preview race reproduction: `.codex/claude-settings-race-red.log`.
- Undo reproduction: `.codex/claude-settings-undo-red.log`, plus the actual CLI
  failure in `.codex/claude-fresh-settings-native.log`.
- Broader suites: 193 core tests passed (17 opt-in tests ignored), 73 Claude
  adapter tests passed, and 17 primary-memory setup tests passed. Log:
  `.codex/claude-fresh-settings-suites.log`.
- Independent read-only review approved the final snapshot and absent-state
  checks with no remaining material findings in this change.

The opt-in `pinned_claude_fresh_settings_setup_restart_and_undo` fixture uses the
same pinned actual 2.1.202 image and contained child-process mechanism documented
in [native setup qualification](claude-native-setup-2026-09-07.md). Its selected
user and project settings, instruction files, and CLI state begin absent. It
exercises the actual CLI and native transaction engine with a synthetic vault
and inert bridge. Native files return to absence after Undo; the CLI-created
state file may retain its own metadata, with no configured MCP server.
The final actual-CLI rerun passes in 57.46 seconds; its contained child completes
in 56.93 seconds. Log: `.codex/claude-fresh-settings-native-final.log`.
Core all-target Clippy with test support and warnings denied passes (16.58
seconds), as do formatting, diff checks, the daemon boundary check, and the
code graph update.

## Remaining scope

The configuration and project `.claude` directories exist in these fixtures.
Creating missing parent directories transactionally remains open, as do the
remaining managed/interactive contexts, production bridge credential binding,
and installed application acceptance. No normal harness profile, credential
store, or daemon was changed. Native desktop control remains paused, and the
production version gates remain unchanged. This is not full first-use or release
acceptance; the latest delivered installer predates these source changes.
