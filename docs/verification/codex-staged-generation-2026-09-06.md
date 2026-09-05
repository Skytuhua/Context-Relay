# Codex staged generation: Windows compatibility result

Status: the pinned Codex 0.144.6 executable cannot create its MCP configuration
inside the tested zero-capability AppContainer. Full connection remains
unqualified. This result supersedes the assumption that the existing Windows
sidecar sandbox can run this generation operation unchanged.

## Tested runtime and operation

- Native Windows x64 Codex 0.144.6, 341,225,264 bytes.
- SHA-256: `4b76ded066d0239115ca97473d010c92072bc5c5550a45dd7cbebe1e9eb956a7`.
- A fresh journaled AppContainer profile, copied and digest-locked helper/runtime,
  suspended creation, zero-capability token attestation, kill-on-close job and
  bounded protocol pipes. The candidate's dedicated job was also configured and
  queried with an active-process limit of two (helper plus one Codex process).
- Empty private stage. Environment cleared and replaced with private home,
  configuration, data, cache and temporary directories plus required Windows
  runtime environment. `CODEX_HOME` points to the private temporary directory.
- Only fixed `--version`, `mcp add context-relay -- <inert bridge path>
  --harness codex`, and `mcp get context-relay --json` operations were permitted.
  No real configuration, account credential, model request, hook or project
  content was supplied to the stage.

## Observed result

The optimized helper verified the copied runtime and prepared/sealed its stage.
The real `--version` process exited successfully. It emitted an optional PATH
alias warning because canonicalization of the private `CODEX_HOME` failed with
Windows error 5. Direct helper probes showed directory enumeration succeeding
while `std::fs::canonicalize` failed with error 5 for relative, absolute and
verbatim spellings of that same private directory.

After accepting only the exact observed alias warning, bound to the private
path and localized Windows error text, the real `mcp add` process exited with
code 1: configuration loading itself requires that canonicalization. Therefore
the failure is not merely optional alias initialization. No successful MCP
configuration generation or get readback occurred in this sandbox.

The final optimized reproduction completed in 7.12 seconds and cleaned up its
profile after recording the result. An initial test-journal implementation
incorrectly treated result durability as the end of the created lease state;
its cleanup failed. That synthetic profile was explicitly deleted through the
existing profile API, the fixture was corrected, and subsequent attempts
completed profile cleanup. This is not production crash-cleanup qualification.

The native-process ceiling and exact-warning checks each had failing regression
tests before correction. Querying a configured job proves the limit is installed;
this experiment did not separately prove third-process denial. It also does not
provide new real-home canary, loopback denial, inert-command execution tracing,
full transaction, or installed-app acceptance evidence.

## Alternative inspected

The same pinned executable exposes `codex sandbox [OPTIONS] [COMMAND]...` on
Windows. Its help describes a Windows restricted-token backend, explicit
sandbox-state input, readable roots and network disablement. A synthetic state
with an empty permission profile and a private file-URI working directory was
rejected with `Restricted read-only access requires the elevated Windows sandbox
backend`. No elevated backend was installed or configured for this test, and no
machine permission or normal Codex setting was changed.

This is insufficient evidence to select that backend: it still needs a reviewed
setup/lifecycle design and proof of denied real-home/network access, controlled
environment, bounded descendants and durable cleanup. It is not an approved
unsandboxed fallback.

## Disposition and reproducibility

The unsuccessful generator prototype was removed from release source. The
verified host-side validation and merge module from commit `489df8d` remains.
Codex 0.144.6 remains ImportOnly. No capability allowlist, live CLI transaction,
native CAS/provenance check, installer or normal installed app was changed.

After removing the prototype, the restored native runner passed all 12
`helper_protocol_v1` and both `native_helper_v1` tests. Its release helper build
also succeeded, replacing the temporary diagnostic binary with release source.

Local reproduction artifacts are retained under
`.codex/context-relay-closeout-2026-09-05/`:

- `codex-appcontainer-prototype.patch`, based on `489df8d`, 35,633 bytes,
  SHA-256 `ec3851903ec159bcff05cbd8f6f5cbb30abe0bd2b5546109b365309702622f36`.
  It includes temporary diagnostics and must not be packaged as release code.
- `codex-generation-commands-diagnostic.log`: real version/add results.
- `codex-generation-path-diagnostic.log`: private-directory enumeration and
  canonicalization probes.
- `codex-generation-job-red.log`, `codex-generation-job-green.log`,
  `codex-generation-warning-red.log`, `codex-generation-warning-green.log`:
  focused boundary regressions.
- `inspect-codex-sandbox-help.mjs`: isolated CLI help/state inspection. It uses a
  fresh synthetic home and records each result in a separate temporary folder.

To reproduce the AppContainer result in an isolated checkout at `489df8d`, apply
the saved patch, set `CONTEXT_RELAY_TEST_CODEX_EXE` to the exact pinned native
binary, and run:

```powershell
cargo test --release -p context-relay-native-runner --test codex_generation_windows_v1 real_codex -- --ignored --nocapture
```

The expected outcome is the documented configuration-loading failure, not a
passing generation test. Keep this qualification checkout separate from release
artifacts and retain its cleanup journal.

The generator requirement is superseded by the
[single native writer amendment](../superpowers/specs/2026-09-06-codex-native-bridge-design.md).
The failed sandbox experiment remains evidence. Ordinary synthetic CLI output
does not qualify a sandbox; the new setup path does not run a generator.

## Native writer follow-up

A committed test-only AppContainer probe now separates directory access from
volume-name resolution. Opening the private directory with FILE_READ_ATTRIBUTES
and enumerating it succeeds. GetFinalPathNameByHandleW with DOS or GUID names
fails with error 5, with both normalized and opened-name flags. NT and volume-free
queries succeed. A GLOBALROOT/NT input still fails Rust canonicalization. Host
queries on the same private directory all succeed. No machine ACL changes were
made. See `codex-path-query-final.log` in the local evidence directory.

Codex bridge adapter v2 now serializes the documented fixed command/args into a
single native mutation alongside global memory disable. Generic MCP/plugin CLI
editing and legacy sealed plans keep their existing behavior. The native path
preserves mixed configuration and metadata, rejects conflicting bridge options
and project overrides, binds read-only/absent config dependencies, and retains
the exact forward/inverse fingerprints. There are no live CLI mutations.

The real pinned 0.144.6 CLI reads this native output identically to a declaration
created by `mcp add` in a separate empty synthetic profile. Plain and paths with
spaces, Unicode, apostrophe and `$HOME` passed; get/list left the native config
unchanged and preserved the unrelated synthetic server. The parent used a
stdin-gated Node fixture inside a kill-on-close Windows job, explicit synthetic
homes and cleared environment, output/time bounds, and before/after CLI digest
checks. This is CLI configuration compatibility, not sandbox or full connection
qualification. Log: `codex-native-bridge-real-readback.log`.

The production native engine passed combined apply, simulated crash, restart
recovery and exact Undo with a frozen harness. Repeat preview has no file or CLI
mutations, correctly classifies implicit stdio, and binds no-op/absent files.
Concurrent configuration changes remain conflicts. Legacy adapter-v1 memory
fingerprint behavior is covered independently. No version was enabled; hook
trust/execution, production bridge round trips, supported platform qualification
and installed acceptance remain open. The unsigned installer is unchanged.
