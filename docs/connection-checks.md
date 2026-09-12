# Guided setup connection checks

The desktop explicitly saves a project note, then starts `connection_check_start`
with `selection: HarnessParams`, `memoryId`, and `expectedRevision`. The server
issues a new `checkId`; starting again replaces the previous check, including any
verified receipt. The desktop polls `connection_check_status {checkId}` and cancels
with `connection_check_cancel {checkId}`. These three methods are desktop-only.

`ConnectionCheckStatus` returns selection, note id/revision, `phase`, remaining
seconds, and nullable `verifiedAt` (decimal epoch milliseconds). Phases are
`waiting`, `verified`, `expired`, `canceled`, and `invalidated`. A waiting check
expires after five minutes using a monotonic clock. Changing or archiving its
note invalidates it. Checks are held only in daemon memory, with one current check;
daemon restart cannot restore an old successful receipt. Unknown/replaced check IDs
return not-found, so the UI must ask the user to start a fresh check.

Only a successful `context_relay_get` executed through the authenticated MCP bridge
route may verify. Existing dispatch admission, canonical project resolution, access
policy and record scope checks run first. Returned memory id, revision, project and
calling harness must all match. Desktop MCP calls, desktop `memory_get`, health,
status, failed calls and old reads cannot verify. No note content, paths, command
arguments, tokens or broad read history are retained in the receipt.

The current MCP binding carries a harness and working directory, but no Hermes
profile. Selection preserves the chosen profile for UI continuity; a receipt proves
the harness/project connection and must not be described as profile attestation.

`harness_launch_info` accepts only `HarnessParams` and is desktop-only. Its `info`
contains the original selection, discovered executable, and canonical registered
project root. The daemon verifies the project still exists, that its registered path
is an existing directory, and that the discovery result points to an existing absolute
file. It never accepts a caller-provided executable, working directory or arguments.
The native desktop revalidates these values and constructs the harness-specific launch.

These additive local interfaces ship in protocol 1.12. MCP status schema and generated
TypeScript version metadata are updated together; the existing exact-version boundary rejects older desktop/daemon pairs until both are upgraded.

## Verification on 2026-09-07

- Rust backend: five connection-check tests pass, including an authenticated temporary
  daemon/bridge read, expiry, revision/archive invalidation, identity mismatch, and
  constrained launch information. Existing daemon routing and scoped MCP tests pass.
- Protocol: 30 focused wire/schema/version tests pass. Local IPC: 26 tests pass,
  including desktop-only operations and independently recalculated 1.12 HMAC vectors.
- TypeScript: 19 validator and protocol-contract tests pass; bindings and schemas are
  regenerated from Rust.
- These checks use temporary fixtures. Installed application and real harness setup
  acceptance belong to the release verification, not this backend test evidence.
