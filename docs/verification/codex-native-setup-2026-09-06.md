# Codex native setup and plugin readback — 2026-09-06

The native Codex plugin-list schema permits metadata that Context Relay rejected:
a nullable version, optional marketplace source, Git sources without a ref,
Git subdirectories, npm sources, and installation policies beyond AVAILABLE.
This could reject an otherwise valid effective-configuration readback when
plugins were present. Empty-profile fixtures did not expose the mismatch.
The parser now accepts the exact required and optional fields from the
[pinned CLI source](https://raw.githubusercontent.com/openai/codex/5d1fbf26c43abc65a203928b2e31561cb039e06d/codex-rs/cli/src/plugin_cmd.rs).

The output still contains only installed plugin IDs and enabled flags. Source
metadata does not become a command, path to open or installation request.
Unknown fields, malformed optional fields, duplicate IDs, wrong list membership,
control characters and redacted source values remain rejected. The existing
64 KiB and 256-entry limits remain. Recursive duplicate-key rejection now also
prevents ambiguous enabled flags or source discriminators from being silently
overwritten during JSON parsing. Two regressions failed before the fix.

## Native transaction qualification

The ignored Windows unit test
pinned_codex_native_setup_restart_reapply_and_undo uses the real Codex 0.144.6
image with SHA-256
4b76ded066d0239115ca97473d010c92072bc5c5550a45dd7cbebe1e9eb956a7.
Its private candidate-version override exists only under cfg(test, windows).
It is not exposed through a feature, environment switch or production API.
Every freshly discovered adapter first asserts the unchanged ImportOnly result.

Three independent contained children cover normal save, an injected panic after
payload writes, and an injected panic after commit. Each has a cleared environment,
synthetic user home, custom CODEX_HOME, project, scratch directory and encrypted
vault. The explicit executable must equal the actual PATH discovery candidate;
its pinned image and path topology remain held open through the case. A stdin
gate assigns the child to a kill-on-close Windows job before any harness launch.
Each child has a 180-second deadline.

The fixture uses the production install service, native transaction engine,
filesystem and recovery implementation. It discovers Codex before preview,
reconstructs the project from the persisted plan and discovers again at executor
boundaries, then discovers anew after reopening the vault and after Undo.
Committed cases verify real Codex MCP declaration readback and saved hook state.
Reapply must execute no transaction. Undo must restore every mutation target's
restorable content and metadata fingerprint, including prior absence. NTFS
last-access time is intentionally excluded by the existing native fingerprint.
The native memory files and the unused default-profile config remain unchanged.

The restricted validator mirrors the daemon's in-process bridge validation;
no sidecar process is launched. Recovery cleanup accepts only the reserved
non-launch identity. The bridge file is inert and never executed. Recovery uses
an injected Rust panic and vault reopen, not an abrupt daemon process exit.
These distinctions limit the qualification claim.

## Evidence and remaining work

Local evidence is under .codex/context-relay-closeout-2026-09-05/.
The initial pinned-adapter fixture passed three cases; fresh discovery then
exposed noncanonical paths in the fixture setup, which were corrected before
the final run. The first broader core run hit a pre-existing 500 ms process-probe
timeout; its isolated recheck passed without changing that deadline.

Final pinned native qualification passed all three cases in 288.76 seconds
(ordinary 107.15, precommit recovery 70.82, committed recovery 110.53).
The core library suite passed 131 tests with nine opt-in tests ignored, using
one test thread; all-target core Clippy with test support and warnings denied
passed. Independent source review approved the fixture and parser boundaries.
Evidence: native-setup-rediscovery-canonical.log, codex-plugin-core-final.log,
codex-plugin-schema-red-final.log and codex-plugin-schema-clippy-final.log.

Hosted CI for the preceding commit exposed two stale authentication vectors
following the protocol 1.5-to-1.6 update. Windows reproduced both failures.
Independent .NET HMACSHA256 calculations matched both old and new vectors;
the expected values now explicitly bind protocol 1.6. No authentication code
changed; all 25 Windows IPC integration tests pass after the correction
(ci-native-setup-ipc-red.log and ci-native-setup-ipc-green.log).
The hosted Windows installer job passed, but that preceding CI run
contains the macOS test failure and is not a passing release check.

The production version allowlist is unchanged. This work does not establish
installed bridge process/credential binding, native UI acceptance, a clean-machine
installation, or the remaining harness/profile/platform matrix. Codex 0.144.6
therefore remains ImportOnly. No normal harness configuration, credential,
installed service or saved project record was modified. The existing installer
predates these changes.
