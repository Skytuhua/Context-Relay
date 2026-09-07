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

## Approved installed update

The user explicitly authorized installing the verified update and restarting the
service. The `e09d206` NSIS installer ran with `/S /UPDATE` and exited successfully.
Its authenticated upgrade helper stopped the old protocol 1.5 process. All five
installed executables and thirteen search files match the candidate's manifest.
The existing encrypted workspace was retained.

The updated installed daemon started normally and now advertises protocol 1.11.
The production MCP executable, running directly from its installed path with the
normal environment and OS credential store, completed authenticated
`context_relay_status` calls for Codex, Claude Code and Hermes bindings. All three
returned protocol 1.11, an unlocked vault and no error. These are status calls
from the bridge, not sessions launched by the three harnesses; no context or
task mutations were requested. The daemon remained running after verification.

Installed candidate: 75,738,674 bytes, SHA-256
`4e43c2e6f0f8360b5e45bf4e219763e4b8e5c6b5b6d8bcbb5ab2e776d580bd9f`,
Authenticode `NotSigned`. Local evidence:
`.codex/e09d206-installed-update.log`, `.codex/e09d206-installed-files.json`,
`.codex/e09d206-installed-service-greeting.log` and
`.codex/e09d206-installed-path-bridge-success.log`.

## Remaining work

The installed service mismatch and production bridge credential/entry-point status
path are verified after the approved update. A subsequent
[actual Codex check](installed-codex-status-2026-09-07.md) also passes status-only
sessions through both exec and app-server against that installed service.
Full harness setup, interactive trust, installed Claude/Hermes client sessions, clean-machine
testing and the remaining version/platform matrix are still incomplete. Production
harness version gates are unchanged. Permission to install and restart the service
does not resume the earlier pause on general native desktop control.
