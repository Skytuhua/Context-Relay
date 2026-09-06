# Windows Hermes production setup qualification — 2026-09-07

Status: configured production setup qualification passed. The exact retained
0.17.0 gate is enabled in source; this is not installed release acceptance.
No replacement installer has been built or installed for this change.

## Candidate behavior

Discovery offers explicit runtime preparation for a Windows Python installation
reporting Hermes 0.17.0 with supported YAML. The ordinary launcher remains
ImportOnly. A retained adapter becomes Full only after reopening and validating
the runtime bound to its approved plan. The version and YAML checks still apply.
The test-only capability override has been removed.

Preparation copies and checks the installed runtime without changing harness
settings. Review is a separate action; Save uses the authenticated tracked
execution API. The UI distinguishes saved settings from a verified live connection.

## Qualification boundary

The opt-in `production_hermes` integration fixture uses the real
`ProductionBridgeInstallEngine`, prepared preview, persisted plan execution,
native transaction engine and filesystem. It selects the installed Hermes
launcher explicitly, inspects metadata passively, and runs management commands
only from the verified private runtime copy.

The profile, project, vault, installation token and IPC namespace are disposable.
The daemon uses its test-only runtime configuration and in-memory key store.
The first completed cycle registered an inert bridge file. The extended fixture
copies the explicitly built test-only bridge example to the production locator's
filename. It selects only a Hermes test IPC namespace and a fixed synthetic token.
The production dispatcher runs over real stdio; the installed production entry
point and credential store are not used. This is not an actual Hermes client or
model session.

The cycle checks preparation, unchanged settings before Save, tracked Save,
persisted history after opening a new daemon and vault instance, idempotent
reapply, and exact Undo. Native memory files and synthetic credentials are
canaries. Reopening the daemon occurs within the same contained child process;
the earlier core qualification separately covered a fresh process.

The parent owns a kill-on-close Windows job. The child must receive the exact
stdin startup gate before touching fixture data or starting the daemon. An outer
60-minute deadline covers RPC, startup and cleanup as well as phase polling.

## Evidence so far

- The gate regression failed against the old ImportOnly behavior, then passed
  with the candidate. Hermes core tests: 83 passed, 5 opt-in tests ignored.
- All 72 Hermes adapter integration tests passed, including rejection and
  transaction behavior for existing supported configurations.
- Authenticated setup integration tests: 19 passed, 2 opt-in tests ignored
  (47.82 seconds), including rejection of an absent startup gate before fixture
  access, incorrect configured bridge commands, and image replacement.
- A synthetic process-tree test passed after normal exit and timeout; it checks
  termination of the recorded sleeping descendant through a Win32 wait handle.
- Contextd and MCP all-target Clippy with test support and warnings denied passed.
- All 67 MCP tests passed, with one opt-in native test excluded. Two existing
  non-version-specific status fixtures were updated to use `PROTOCOL_VERSION`
  rather than an obsolete literal; production protocol validation is unchanged.
- The separate native Codex regression passed in 6.46 seconds with the extended
  shared bridge fixture. Actual Codex 0.144.6 exercised memory and task operations
  through both `exec` and `app-server`, using a loopback model and synthetic
  credentials. This does not enable Codex setup or qualify installed credentials.
- Independent review found one missing outer process-containment boundary in the
  fixture. The shared job helper and startup gate resolved it; no production
  gate defect was found in that review scope.
- The first real cycle prepared 14,629 files / 342,033,097 bytes, reaching Ready
  in 460.37 seconds. Prepared preview then rejected the fixture's incorrect bridge
  filename. The corrected fixture derives that path from the production locator
  and attests it before starting expensive preparation. This failure did not
  reach Save and does not establish a complete setup cycle.

The corrected run reached Ready in 451.30 seconds, sealed its prepared review,
and committed tracked Save in 464.97 seconds. A new daemon/vault instance loaded
the Applied history entry; reapply finished in 1.01 seconds with identical settings.
Undo passed in 467.53 seconds, restoring the original config and preserving the
memory/credential canaries. The complete test passed in 1394.75 seconds. This
qualifies the production settings composition with an inert bridge.

The first real stdio bridge cycle passed in 1081.53 seconds, including context
readback after Save and daemon restart. Review found that it identified the source
image before copying and used a fixed command for those readbacks. That run does
not establish that the actual saved declaration works.

The corrected fixture holds the copied image with Windows read sharing only,
preventing writes and replacement throughout identification and execution. Its
identification has a 128-byte output cap, discarded stderr and a five-second
deadline. Readback parses the actual saved YAML and launches its command and
arguments; mismatched paths, arguments, disabled entries and overrides fail before
launch. Independent focused review approved these corrections without remaining
blocking findings.

The configured cycle passed in `.codex/hermes-configured-production-cycle.log`.
It exercised real stdio tool discovery, project resolution and remember/get/search
before runtime preparation. Preparation reached Ready in 544.91 seconds for
14,629 files / 342,033,097 bytes. Tracked Save passed in 530.34 seconds, followed
by readback of the same context through the actual saved declaration. A restarted
daemon/vault instance returned that context again. Reapply passed in 1.01 seconds
with unchanged settings. Undo passed in 491.30 seconds, restoring the original
config and preserving the memory and credential canaries. The complete contained
test passed in 1575.45 seconds, and its parent exited successfully.

This covers the Python support design's production setup, configured bridge,
restart and Undo qualification for the retained 0.17.0 runtime. Actual Hermes
client/model validation, other harness versions, rebuilt installer and installed
acceptance remain separate work.
