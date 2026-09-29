# Read-only memory registration verification

ImportOnly setup could publish the sources saved during preview without checking
whether the harness installation or memory settings had changed. Startup recovery
could also finish an interrupted registration without a live check. This correction
applies to read-only registration; it does not enable Full harness connection.

## Behavior

Preview now seals the file dependencies that select Claude's memory locations,
including absent user, project, local and configured managed settings files.
Apply and explicit resume require a live verifier. It compares the approved
project, profile, adapter/version, executable path and digest, exact dependencies
and source descriptors. Changed or expired plans require another preview.
Legacy Claude registration plans without the required settings dependencies fail
closed. Each adapter also rechecks its installation before returning sources.

Production rediscovery resolves the current candidate without running a version
command. Only matching approved executable bytes and path may reuse the saved
version. Codex and Hermes compare canonical executable paths, matching their
preview constructors. Claude preserves its discovered path spelling. This path
does not construct a native transaction, generator, CLI writer, bridge process
or Hermes gateway lease, and does not write harness configuration.

Registration publication and Applied status already share one vault transaction.
An Applying row therefore has no committed registration to recover. Startup now
ends that interrupted attempt as ApplyRestored instead of publishing stale
sources. A new preview is needed. A committed apply replay remains a no-op, and
Undo removes only the registration without requiring the harness to run.

## Evidence

The final core run passed 322 tests: 100 ordinary library, 12 bridge preview,
58 Claude adapter, 64 Codex adapter, 72 Hermes adapter and 16 primary-memory setup.
Two opt-in real-runtime library tests were not run. New cases cover missing live
verification, changed settings/sources/executables, explicit resume, expiry,
legacy dependencies, startup recovery, committed replay and Undo. The existing
three-harness matrix checks that the native filesystem remains unchanged.

The production daemon run passed 59 tests. Its new canary compiles a small
executable that writes a marker whenever launched, with a positive control to
prove the marker works. Twelve isolated child processes exercise the actual
production verifier across all three harnesses with unchanged candidates,
changed executable bytes, changed PATH entries and changed project bindings.
No verifier case launched the executable. The child test is ignored in ordinary
enumeration because the parent invokes it with a private environment and temporary
home/vault. All twelve cases ran through the parent test.

Ordinary Windows PATH spelling exposed a Hermes canonical-path mismatch. That
case failed before the correction and passed in the final daemon run. Review
also caught the original version-subprocess launch order and a POSIX-only unused
mutable binding; both were corrected. These are synthetic fixtures, not evidence
that the installed harness versions support full setup.

Core/daemon all-target test-support Clippy passes with warnings denied.
Independent review approved the final corrections. `graphify update .` completed
with 15,067 nodes and 43,434 edges. The preceding file-settings commit's macOS
Rust tests, lint and native build passed hosted CI33993325250; this registration
change has only been executed locally on Windows so far.

Local logs are under `.codex/context-relay-closeout-2026-09-05/`:
`watch-registration-red.log`, `watch-registration-final-core.log`,
`watch-registration-hermes-path-red.log`, `watch-registration-final-daemon.log`,
`watch-registration-clippy.log` and `watch-registration-graphify.log`.

## Remaining acceptance

The desktop still stops at the unavailable state when a harness lacks Full
capability. This backend correction does not present read-only registration as a
successful connection or qualify any additional version. Runtime settings/trust,
complete native setup/recovery, Codex isolation, Hermes launcher qualification
and installed acceptance remain open. The unsigned installer from source
`11d6740` is unchanged and does not include this or the two preceding memory
settings/path corrections. Native desktop control remains paused.

## Hosted watcher integration follow-up

CI33994948098 passed the production registration canary and all 60 macOS daemon
library tests, then failed the `authoritative_memory_v1` integration fixture.
That fixture still used a `NeverBridgeExecutor` with no live verifier. It now
calls the actual read-only Codex verifier while retaining a panic if any native
transaction is invoked. All four integration tests pass locally on Windows,
including registration, delivery of an edited source to the real daemon watcher
and Undo without configuration changes. The correction still needs the next
hosted run; the earlier overall CI result is not green.

Evidence: `ci-679-macos-rust-failure.log` and
`watch-registration-authoritative-memory.log` in the local closeout directory.
