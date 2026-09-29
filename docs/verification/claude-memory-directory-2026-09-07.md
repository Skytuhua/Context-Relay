# Claude settings environment memory directory — 2026-09-07

Context Relay previously ignored `env.CLAUDE_COWORK_MEMORY_PATH_OVERRIDE` in
Claude settings. It could therefore inspect the ordinary memory folder while
Claude used a different folder. The adapter now binds the settings-selected
directory before `autoMemoryDirectory`, retaining user < project < local
precedence and read-only handling of managed settings.

The environment override does not expand `~/`. Empty and invalid native values
fall through to the ordinary directory selection. Malformed settings values and
ambiguous Windows environment-name aliases are unavailable. A valid but unsafe
directory is rejected. Existing settings digests and source re-resolution reject
an approved plan if its selected directory changes before apply.

## Evidence

The pinned Windows Claude 2.1.202 executable has SHA-256
`7ff0787ebdc19fc509ccea8886ebf6a53ad8213407fa3a2b7c6d1446efc419f6`.
Its isolated native-session matrix now contains 25 cases. Five new cases verify
user/project environment overrides, invalid home shorthand, a remote memory base
and precedence of an explicit directory over that base. Each case made one
request to a loopback model with the expected memory marker and no wrong-folder
marker. Generated lifecycle hooks still delivered both events. All 25 passed in
37.00 seconds (`.codex/claude-memory-environment-native.log`). These sessions use
synthetic profiles and credentials; no ordinary harness configuration is changed.

The new adapter regression failed before the fix, selecting `regular memory`
instead of `environment memory 專案 O'Brien`, and passed after it. Additional
checks cover layer precedence, managed settings, native fallback rules, malformed
values, Windows aliases and changed-plan rejection.

- All 68 Claude adapter tests pass (1.05 seconds).
- All 30 selected Claude library tests pass; three native opt-in tests are excluded.
- All 17 primary memory setup integration tests pass (39.86 seconds).
- Core and daemon all-target Clippy passes with test support and warnings denied.
- Formatting and diff whitespace checks pass. Independent read-only review found
  no actionable issues in the three changed source/test files.

Logs use the `.codex/claude-memory-environment-` prefix: `red`, `green`,
`adapter`, `core`, `primary-memory` and `clippy`.

## Qualification boundary

The first production correction covers settings-provided cowork directory
overrides. The follow-up below handles qualified settings-provided remote bases.
Ambient directory overrides remain open.
Interactive trust, other managed settings sources, full native transaction/crash
recovery, production credentials and installed acceptance remain unqualified.
Claude 2.1.202 remains import-only. No version gate is expanded.

The unsigned Windows installer from source `357f4a2` predates this correction.
It has not been replaced or installed as part of this check.

## Settings-provided remote memory base

A second regression reproduced the adapter selecting the configuration directory
despite a nonempty `env.CLAUDE_CODE_REMOTE_MEMORY_DIR`. The pinned native binary
joins that base with `projects/<repository-key>/memory`, then normalizes the
result to NFC; its native session cases above confirm selection and priority.

The adapter now uses an absolute, safely bound remote base when neither the
cowork override nor `autoMemoryDirectory` selects a root. Empty values retain the
ordinary configuration base. The same user < project < local precedence,
managed read-only behavior, alias rejection and plan freshness rules apply.
Relative, drive-relative and UNC bases remain unavailable pending launch-context
qualification. An unqualified base never silently selects the ordinary folder.
Existing repository-key version gates remain in place; this does not enable a
default or remote-derived source for Claude 2.1.202.

The remote-base regression failed before the correction and passed afterward
(`.codex/claude-remote-memory-red.log` and `green.log`). All 71 Claude adapter
tests then passed in 1.80 seconds. New checks cover layered bases, explicit-root
priority, empty values, unqualified paths and malformed values; existing alias
and stale-plan checks now exercise both directory environment controls.
Independent review found no actionable issues in the two-file follow-up diff.
The affected library checks pass (30 tests, three opt-in cases excluded), as do
all 17 primary-memory integration tests (39.18 seconds) and core/daemon all-target
Clippy with test support and warnings denied (9.94 seconds). Formatting and diff
checks pass. These logs use the `.codex/claude-remote-memory-` prefix.
