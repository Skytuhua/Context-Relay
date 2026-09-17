# Retained Windows Hermes runtime verification

The retained-runtime API extends temporary capture with a private manifest,
durability barriers and reopening from a serialized expected identity. It does
not enable a harness version or authorize running Hermes management commands.

## Boundary checks

Eight retained-runtime tests cover fresh reopening after source removal, serialized
identity, payload changes/additions/deletions, missing empty directories, malformed
and oversized manifests, invalid storage keys, schema/path/alias validation,
junction substitution, public root/descendant/manifest permissions, and failures
at both final directory flushes before temporary ownership is relinquished.

The descendant-permissions regression first failed by accepting a public payload
file. The fix validates security descriptors through opened handles for files,
ancestors, empty directories and the manifest. Only the current user's ordinary
full-access ACE is accepted. Owners are limited to that user or the fixed Windows
Administrators group; this avoids binding reopen to the process's elevation state.
Actual elevated-to-normal process transition testing has not been performed.

Native tests additionally cover long descendant paths, alternate streams, hard
links, private root reopening, flushes and exclusion of a second root writer.
Independent review approved the final privacy policy and implementation.

## Validation status

Final Hermes unit suite: 60 passed, two opt-in tests ignored (includes eight retained
tests). Native-runner unit suite: 43 passed. Hermes adapter integration: 72 passed.
Core/native-runner all-target Clippy with test support and warnings denied: passed.
Formatting and whitespace checks passed. An attempted concurrent core relink failed
with Windows LNK1104 while the installed probe held its test executable; the queued
rerun after that process exited passed all 60 tests.

The explicit installed capture/retain/reopen/path probe passed in 1,110.79 seconds.
It captured 14,629 files, 2,452 directories and 342,033,097 bytes. Copy completed at
308.60 seconds, source recheck at 581.01, complete capture at 736.12, retention flush
at 872.11 and fresh reopening at 993.90. Copied CPython's fixed path probe confirmed
isolated/no-site execution, staged-only import paths, no user-startup canary and an
unchanged post-probe inventory. No Hermes management command ran. These are debug
timings, not release speed qualification.

The long probe started before the final owner-allowlist refinement, using the current
token's default owner for its elevated Administrators-owned descendants. The final
fixed user/Administrators policy was then covered by the final native and Hermes
unit suites; actual process elevation-transition testing remains unperformed.

The ordinary Hermes checkout remains dc5ef20d89f0fc787a97ebd05bb8c41fbce10ab7 with
the same seven pre-existing modifications. Configuration, credentials and daemon
were not changed. Graph refresh completed with 15,942 nodes and 45,332 edges.

The previously running seven migration/sync fixture suites have completed: all 103
tests passed, including 256 randomized signed-sync seeds. The fixture correction
changes no production migration behavior.

Logs are under .codex/context-relay-closeout-2026-09-05/hermes-retained-*.log;
the broad fixture run is migration-fixture-regression-green.log.

## Remaining connection work

Bind the distinct retained reference in sealed transaction approval and recovery,
reverify and lock bytes during contained execution, then qualify real connection,
restart and Undo. Runtime preparation also needs visible progress and cancellation.
No Full capability promotion or new local installer is claimed by this API.
