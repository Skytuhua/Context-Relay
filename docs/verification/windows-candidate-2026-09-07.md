# Windows installer candidate — 2026-09-07

Status: built and inspected; not installed or accepted through native UI.

## Artifact

- Source: `1d7b46da9d1eda371aa976cbc5f6159517fa45d7`.
- Command: `pnpm package:windows` completed successfully with locked Cargo
  dependencies and the Windows release configuration.
- Target: Windows x64, NSIS, current-user installation.
- Filename: `Context Relay_0.1.0_x64-setup.exe`.
- Size: 11,522,177 bytes.
- SHA-256: `4a7ab3f872a1e9357af9fa5a80316d50d294e0a953201edca8134dd6ef658051`.
- Authenticode status: `NotSigned`; no signing certificate or service is configured.
- Local archive: `.codex/installer-candidates/1d7b46d/` with the installer,
  `checksums.json`, extracted application files and dependency reports.

The preceding 357f4a2 installer is preserved under
`.codex/installer-candidates/357f4a2/`, with SHA-256
`b919653bd7ec50fb6befc33d9a4a9473cef67373a77aada98a79d53490a9e14b`.
The earlier 11d6740 installer is preserved separately under
`.codex/installer-candidates/11d6740/`, with its original SHA-256
`a18e2051f1fc30a9d7cf66dec71ac747f6f54facf03485fa826447d233d326bf`.
The installed application was not changed by this build.

## Package inspection

7-Zip identified a Unicode NSIS archive and successfully extracted the five
application executables and the installer service-control copy. All five
application images are AMD64 PE32+ files. The four companion executables match
their release build bytes exactly. The service-control copy matches the daemon.

The desktop differs from the bare release image by exactly Tauri's three-byte
bundle marker change, `UNK` to `NSS`, at the unique
`__TAURI_BUNDLE_TYPE_VAR_` marker. The installed Tauri utils source maps `NSS` to
NSIS. Applying only that expected marker change in memory gives an exact match
with the extracted desktop; no other bytes differ.

| Bundled file | Bytes | SHA-256 |
|---|---:|---|
| context-relay-desktop.exe | 13,744,128 | `fbec91113c521afb18661b999d987958b440091be2409e251512419b3a5f2878` |
| context-relay-contextd.exe | 20,568,576 | `03e9b932c95b5c93bc8a6a6e97f074e3a81f36fab65019313cf066d9998de0aa` |
| context-relay-context-mcp.exe | 5,625,856 | `341b2b3aa9fdc844cfc334d381ada93488c2c72cd37d7d6fc4412bdfac414de4` |
| context-relay-native-helper.exe | 1,082,880 | `17eb4d36fd3bae97a0b132e09c7d96ef1ebc9b577678f4423a1415599ecca2c3` |
| context-relay-sidecar-installer.exe | 440,320 | `e5c7c73b567b900af20acdd39aa1f7bdfaa2141be44ac5a4344c2e0d363c4922` |

`dumpbin /dependents` found no VCRUNTIME, MSVCP or MSVCR DLL import in these
images. The desktop does import seven Windows UCRT API sets; this is not an
entirely static CRT image. Microsoft documents that the UCRT is included in
[Windows 10 and later](https://learn.microsoft.com/en-us/cpp/windows/universal-crt-deployment?view=msvc-170),
which includes the declared Windows 11 target. The four companions have no CRT
DLL imports. This static inspection does not replace clean-machine testing.

## Included changes and remaining acceptance

The candidate includes the [first-use UI changes](first-use-ui-2026-09-06.md),
[qualified retained Hermes setup](hermes-production-setup-2026-09-07.md) and
[Claude memory-directory corrections](claude-memory-directory-2026-09-07.md).
The contained Hermes cycle passed preparation, tracked Save, configured bridge
readback, daemon/vault restart, reapply and exact Undo in 1575.45 seconds. Its
bridge uses test-only IPC and synthetic credentials. Separately, the
[actual Hermes client and CLI qualification](hermes-native-client-2026-09-07.md)
passes direct MCP operations and an eight-request conversation against a
scripted loopback model. These do not establish real provider or installed
production credential behavior.

The macOS workspace Rust test job for source `19044f6` passed after the two IPC
fixture corrections, including all nine desktop tests. The newer candidate's
native Hermes fixture is Windows-only. This is cross-platform source-test
evidence, not installed macOS or Windows release acceptance.

Native Computer Use remains paused. This candidate has not been installed,
launched from the installer, tested against the ordinary daemon/profile, or
accepted on a clean machine. Codex 0.144.6 and Claude Code 2.1.202 remain
import-only. Signing, remaining harness/profile/platform work and hosted product
functionality also remain open. This is an internal candidate, not a completed
release.
