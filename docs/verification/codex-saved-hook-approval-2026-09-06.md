# Saved Codex hook approval

Harness discovery can now report approval recorded for Context Relay's SessionStart
and Stop hooks in the selected Codex 0.144.6 user profile. Review setup shows the
result as saved settings evidence: missing, needs approval, approval saved, changed,
or disabled in saved settings. It explicitly does not establish effective runtime
enablement or a working connection.

The daemon reuses the adapter already identified by its compatibility check. The
new reader does not start a process, write approvals, change configuration, or scan
sessions. In particular, it does not invoke the test-only app-server hook probe,
whose startup can modify a profile. Existing discovery still performs its version
check. Only the installed adjacent bridge path is used to derive expected hooks;
the desktop cannot supply commands, paths or trusted hashes.

## Scope and matching

The reader verifies the selected native executable and canonical profile/project
context. It reads only the user hooks.json and config.toml, rereads both to reject
changes during the check, and revalidates the context and executable identity.
Strict JSON rejects duplicate keys. Multiple matching managed definitions cannot
inherit one saved approval. Malformed files and ambiguous normalized approval keys
produce unavailable evidence.

Hook comparison follows the pinned 0.144.6 command normalization: Windows command
overrides, default timeout, asynchronous exclusion, event-specific matcher behavior,
and recursively sorted normalized fingerprints. Saved trust must match both the
exact definition hash and its source/event/group/handler key. Project configuration
cannot grant approval to these user hooks. Individual saved disable preferences
are preserved. Global feature disable is a separate runtime question and does not
erase saved approval.

The protocol is now 1.6, with a required nullable codexSavedHookApproval field.
Null means unavailable, including versions outside this narrow qualification or
unreadable settings. Desktop validation rejects malformed states and reports for
another harness/version. Selection, navigation, refresh, Save settings and Undo
clear old approval evidence. This field is absent from sealed setup plans and does
not change their approval hashes.

The authenticated Windows upgrade helper accepts the frozen shutdown protocol of
both 1.4 and 1.5 previews, as well as current 1.6. Ordinary clients remain exact
version. The compatibility path can only authenticate, request shutdown and wait
for the connected process to exit; it does not yield a reusable legacy client.

## Verification

- Six core reader tests cover missing/approved/disabled/stale/changed definitions,
  duplicate candidates, positional changes, normalization, project isolation,
  malformed input, unsupported versions, and no startup marker or file writes.
- An isolated actual Codex 0.144.6 comparison matches the reader to native untrusted,
  trusted and modified metadata. With hooks globally disabled the reader correctly
  retains saved approval while native metadata is empty. Four native queries pass
  in 30.71 seconds; only disposable profiles are used.
- Core library: 129 passed, eight opt-in tests ignored.
- Protocol: 114 passed, including strict nullable nested approval data and rejection
  of previous protocol versions by ordinary clients. An outdated nullability
  fixture initially failed and was updated to include the required new null field.
- Desktop: 149 passed. All five saved states are rendered without a connected
  claim; malformed and mismatched evidence is rejected.
- Daemon production probe seam: one passed, with missing adjacent bridge,
  missing hooks, pending approval and malformed hooks. The selected executable is
  the inert test binary, not a launched Codex profile.
- Authenticated harness setup IPC: 12 passed, covering discovery, role checks,
  project registration, exact-plan apply/Undo, replay and startup recovery.
- Windows shutdown: 11 passed, one child-only test ignored. The added 1.5 regression
  first failed with ProtocolVersionUnsupported and passes after the compatibility
  correction, including waiting for actual process exit.
- Core, daemon and local IPC all-target Clippy with test support and warnings denied
  passes. Type checking, lint, generated bindings/schema checks and the daemon
  dependency boundary check pass.
- Ten headless Edge captures of the actual React app with an isolated gateway pass,
  including 1166- and 390-pixel widths without horizontal overflow or browser errors.
  Observed text/button contrast exceeds 4.5:1. These are not installed native UI tests.

Independent review approved the reader and integration after identifying and
correcting the protocol-upgrade regression. An interrupted lint/test attempt ran
out of disk space; Cargo's package-scoped cleanup recovered rebuildable core
outputs and the affected checks were rerun. No user project data was removed.

## Remaining acceptance

Codex 0.144.6 remains ImportOnly. This saved-settings report does not enable setup,
prove effective hooks or credential/process binding, or establish full native
setup/recovery. The existing unsigned local EXE predates this change and has not
been replaced or installed. Normal desktop control remains paused. Remaining
Codex, Claude, Hermes and wider first-use/release work is still open.
