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

The remaining design requirement is a compatible, pinned generator runtime or
a qualified equivalent Windows restriction mechanism. Preserve the
[staged-generation boundaries](../superpowers/specs/2026-09-05-codex-staged-mcp-design.md),
including nonsecret stage input, one native live writer, explicit approval
evidence and exact rollback. Successful CLI output in an ordinary synthetic
home does not satisfy those isolation requirements.
