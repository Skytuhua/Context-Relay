# Claude setup with no project configuration directory

The actual pinned Claude 2.1.202 CLI passes preview, native Save, vault reopen,
idempotent reapply, and Undo when the selected project has no `.claude` directory.
The directory remains absent throughout. This corrects the earlier investigation's
assumption that directory creation was a prerequisite for this setup path.

The existing Claude adapter returns `WatchOnly` native-memory capability with
exact registered source paths in this case. Full setup accepts that fallback:
it creates the project instruction and user hook settings and registers the MCP
declaration, without emitting a project memory-disable mutation. Claude's built-in
memory therefore remains enabled. This behavior already existed; this change
adds qualification coverage, not a new production capability or version gate.

## Native evidence

`pinned_claude_missing_project_directory_setup_restart_and_undo` extends the
existing disposable native setup fixture. The selected user configuration
directory exists, but user settings, CLI state, project instructions, and the
project `.claude` directory start absent. Assertions cover:

- Watch-only capability with exact sources before preview.
- No preview-time project directory creation or mutation below that directory.
- Actual CLI declaration creation and readback, persisted vault reopen, and
  idempotent reapply without executing the plan twice.
- Exact native file restoration, actual CLI declaration removal, empty memory
  ledgers after Undo, and the project directory still absent.
- Byte-preserved canaries in the unrelated synthetic ambient Claude profile.

The test passed in 57.06 seconds (owned child: 56.48 seconds). The log is
`.codex/claude-missing-project-directory-native.log`. Read-only review found no
material issue in the test or its containment.

All-target core Clippy with `test-support` and warnings denied passed in 16.07
seconds (`.codex/claude-missing-project-directory-clippy.log`). Formatting and
diff whitespace checks passed. Production source is unchanged by this test.

The executable is the previously pinned 2.1.202 image with SHA-256
`7ff0787ebdc19fc509ccea8886ebf6a53ad8213407fa3a2b7c6d1446efc419f6`.
Every discovery asserts production import-only status before the existing
test-only qualification override. The child receives a cleared environment,
synthetic profile paths, an owned Windows job and bounded deadline, and an inert
bridge that is never executed. Normal profiles and credentials are untouched.

This does not qualify an absent user configuration root, automatic directory
creation, built-in-memory suppression without project settings, live bridge
credentials, interactive trust, native desktop installation, or additional
production harness versions. Those remain distinct acceptance work.

## Updated Windows candidate

The new local installer was built from production source
`ba3d3323fc0e2de5570542cd1db8c56ec0823db0`, before this test-only delta. It includes
the missing Claude instruction/settings file fixes and exact-absence Undo fix,
along with the earlier bundled search and protocol 1.10 upgrade compatibility.

- File: `.codex/installer-candidates/ba3d332/Context Relay_0.1.0_x64-setup.exe`
- Size: 75,725,420 bytes.
- SHA-256: `fbc2f1447269885b57b6a02b1b79387ee31616202fed792faf4cd650c6131b51`.
- Authenticode status: `NotSigned`.
- Static extraction checks all five AMD64 executables, exact companion and
  service-control bytes, only the expected Tauri NSIS marker transformation,
  and all 13 search model/runtime/notice files against their manifests.

Logs: `.codex/ba3d332-package-windows.log` and
`.codex/ba3d332-installer-inspection.log`; manifest:
`.codex/installer-candidates/ba3d332/checksums.json`.
The candidate has not been installed or accepted through native UI testing.
