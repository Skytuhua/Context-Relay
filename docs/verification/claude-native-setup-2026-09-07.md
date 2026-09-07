# Claude native setup and new project instructions

Real Claude 2.1.202 setup exposed a first-use failure: creating a project's
missing `CLAUDE.md` required an existing sibling `.mcp.json` as a metadata
template. A project without either file failed during preview.

The primary-instruction projection now uses the native filesystem's existing
private-file metadata helper, as Codex does. It validates the target's parent
without creating a preview-time file, preserves existing-file metadata, and
retains the original absent-state fingerprint for Undo. The ordinary Markdown
regression now removes `.mcp.json` before creation and restoration checks.

## Actual CLI qualification

The opt-in Windows unit test
`pinned_claude_native_setup_restart_reapply_undo_and_recovery` uses the actual
Claude 2.1.202 image with SHA-256
`7ff0787ebdc19fc509ccea8886ebf6a53ad8213407fa3a2b7c6d1446efc419f6`.
It verifies PATH discovery against the explicitly selected image and holds
verified executable state. A private `cfg(test, windows)` candidate override is
applied only after every fresh discovery asserts the production ImportOnly
result. No feature flag or production environment switch enables this version.

Four independent children use cleared environments, synthetic homes, a custom
configuration directory, project, temporary directory, and encrypted vault with
an in-memory key store. Each waits for admission to a kill-on-close Windows job
and has a 240-second deadline. The setup engine uses the actual Claude CLI for
MCP mutation and readback, the real native filesystem, and the production
approval-bound recovery implementation. The bridge itself is inert and never
executed; no model or normal credential store is used.

The cases cover ordinary save and injected panics after payload writes, after
CLI activation writes, and after ownership/receipt commit. They reopen the same
vault, recover the native files and CLI declaration, verify that reapplying a
committed setup performs no transaction, and Undo it. Recovery after the CLI
write removes the uncommitted managed declaration. Native mutation targets
return to their original restorable content/metadata fingerprints, including
prior absence; the unrelated MCP map and user state are retained. The unused
ambient settings/state files remain byte-identical. No native-memory ledger
remains active after restoration.

All four actual CLI cases pass: 59.47, 27.14, 56.56, and 72.85 seconds;
217.72 seconds overall. The first run reproduced the preview defect. A corrected
run reached Undo but could not stage another 252 MB CLI image while C: had only
204 MB free. The final passing run used a separate disposable NTFS temporary
directory. No existing user files were deleted to make room.

Independent read-only review approved the metadata fix and containment. It
identified the need for the after-CLI interruption case, which is included in
the passing run.

The broader core library suite passes 192 tests (16 opt-in fixtures ignored),
the Claude adapter suite passes 71, and the primary-memory setup suite passes
17. Their log is `.codex/claude-native-setup-suites.log`. The ordinary adapter
test confirms creation and restoration without `.mcp.json`.
Core all-target Clippy with test support and warnings denied passes, as do
formatting, diff checks, and the daemon boundary check. The graph update passes.

## Limits

These are panic-and-reopen fixtures, not abrupt daemon process crashes or
installed application acceptance. The selected user and project settings files
already exist in this matrix. Fully fresh settings directories, interactive
trust, remaining managed settings/launch contexts, production bridge credential
binding, and installed UI/clean-machine acceptance remain open. Claude 2.1.202
therefore remains ImportOnly. Native desktop control remains paused, and the
latest delivered installer predates this source correction.

Local logs: `.codex/claude-native-setup-first.log` (reproduction),
`.codex/claude-native-setup-create-fix.log` (scratch-space failure), and
`.codex/claude-native-setup-ntfs.log` (four passing native cases).
