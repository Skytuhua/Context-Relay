# Installed service version diagnosis — 2026-09-07

The ordinary Windows service was still running protocol 1.5 while the current
build requires 1.11. A bounded read of the server greeting established its
advertised protocol. `GetNamedPipeServerProcessId` independently identified the
pipe owner as the already-running installed `context-relay-contextd.exe` process.
Neither check authenticated, sent a service request, or changed the service.

Both a byte-identical copy of the installed bridge and the latest packaged bridge
returned only "The local service is unavailable" for read-only status calls.
The current source discarded `IpcError::ProtocolVersionUnsupported` in both the
MCP bridge and desktop transport. The desktop then recommended retrying or
checking the project folder, hiding the version mismatch.

The transport now preserves that error code with fixed update guidance. Other
IPC failures retain their existing redaction. Home startup and Harnesses review
select the guidance by the typed code, never by displaying native error text.
Retrying startup clears the previous diagnosis. Authentication, protocol matching,
automatic service startup, shutdown and harness version gates are unchanged.

## Verification

- Two frontend regressions failed before the change; all 230 frontend tests now
  pass, along with TypeScript and ESLint.
- Both MCP library tests and all ten native desktop binary tests pass, including
  typed mismatch mapping and unchanged redaction of other IPC errors.
- MCP and desktop all-target Clippy with warnings denied passes, as do formatting
  and diff checks.
- The rebuilt production bridge returns the update guidance for Codex, Claude Code
  and Hermes bindings against the existing protocol 1.5 service. Each invocation
  used normal HOME and environment and sent only MCP initialization followed by
  `context_relay_status`. No hooks or record mutations were requested.
- Each production bridge ran as a verified byte-identical copy in a fresh folder
  containing no sibling daemon executable. The current launcher uses only that
  exact sibling path, so this check could not start or replace a daemon if the
  connection failed. Credentials were read internally by production code, never
  extracted into the test script or logs. No credentials were written.
- Four actual-App browser views cover startup and Harnesses at 1166×800 and
  390×844 with a disposable in-memory gateway. Guidance is visible, native details
  remain hidden, and there is no horizontal overflow or browser runtime error.
- Independent read-only review found no actionable issues.

Local evidence: `.codex/installed-service-greeting.log`,
`.codex/installed-service-pipe-owner.log`,
`.codex/installed-bridge-latest-status.log`,
`.codex/installed-bridge-current-status.log`,
`.codex/installed-bridge-corrected-status.log`,
`.codex/service-version-ui-red.log`, `.codex/service-version-ui-green.log`,
`.codex/service-version-desktop-native-tests.log`,
`.codex/service-version-mcp-tests.log`, and
`.codex/service-version-ui/results.json`.

## Remaining work

These checks establish a real installed-version mismatch and improve its error
reporting. They do not establish a successful authenticated tool call against the
installed service or a working harness connection. The running service has not
been stopped, replaced or upgraded: native desktop control is still paused.
Installing the current build and restarting the service remain necessary before
installed connection acceptance. The installer already has a shutdown-only
compatibility path for protocol 1.5; that is not permission to run it while paused.
