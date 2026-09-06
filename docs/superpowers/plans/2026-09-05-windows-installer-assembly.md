# Windows installer assembly

This is the first implementation slice of [the full Windows app release objective](../../verification/windows-app-release.md). Completing this slice produces an internal installation candidate; it is not product-release completion.

## Design

Use the existing Tauri v2 NSIS bundler and IPC sibling-daemon launcher. Add a dedicated Windows release configuration and a deterministic build entry point. The entry point builds the four Rust companion binaries for `x86_64-pc-windows-msvc`, stages them using Tauri's target-suffixed `externalBin` convention, then invokes the existing Tauri CLI with the release configuration. The installer places companions adjacent to the desktop executable, as the current daemon and MCP locators require.

Keep ordinary CI builds and macOS configuration working. A package build must fail on missing/invalid/wrong-architecture companion output. Generated binaries are ignored by Git. Use per-user installation, the existing icon and product identifier, and supported WebView2 provisioning. Do not claim runtime sidecar qualification, signing, cloud connectivity or product readiness from this assembly step.

Package inspection follow-up: include the repository license and current third-party notice file as installed resources. This is not a complete dependency license inventory. Mark release desktop builds as the Windows GUI subsystem so opening the app does not leave an unintended console window; preserve debug console behavior. Verify the actual built PE subsystem and installed resource hashes.

Dependency inspection follow-up: the initial companion build imports `VCRUNTIME140.dll`. Enforce `-Ctarget-feature=+crt-static` through Cargo's encoded environment flags for both companion and desktop builds, preserving explicit environment arguments. The release policy overrides Cargo-config rustflags; the target directory still comes from Cargo metadata. Verify the resulting executables' actual DLL imports. This intentionally requires rebuilding native dependencies and is necessary to remove an undeclared end-user prerequisite.

## Task 1 — package assembly entry point

Files: `scripts/package-windows.mjs`, `scripts/package-windows.test.mjs`, `apps/desktop/src-tauri/tauri.windows-release.conf.json`, root `package.json`, `.gitignore`.

1. Test assembly behavior before implementation: missing binary fails, non-PE and non-AMD64 output fails, all four required binaries stage with correct target suffix, and a valid fixture set yields exactly the expected external binary files. Temporary fixture outputs must stay inside the test's own temporary directory.
2. Implement exports for the bounded staging function and the constant required binary list. Required names: `context-relay-contextd`, `context-relay-context-mcp`, `context-relay-native-helper`, `context-relay-sidecar-installer`. Validate the PE signature/machine field before copying. Do not search PATH for companion binaries or accept caller-supplied executable names.
3. Implement the CLI with structured spawn arguments and failure propagation: `cargo build --locked --release --target x86_64-pc-windows-msvc -p context-relay-contextd -p context-relay-context-mcp -p context-relay-native-runner --bins`, then stage from the corresponding target directory, then invoke the pinned workspace Tauri CLI to build with `--target x86_64-pc-windows-msvc --config src-tauri/tauri.windows-release.conf.json` from `apps/desktop`. Resolve repository paths from `import.meta.url`, not the caller's current directory. Respect an explicitly configured Cargo target directory or reject it clearly; never accidentally copy stale output from a different target directory.
4. Add a dedicated config overlay with `bundle.active: true`, `targets: ["nsis"]`, all four `externalBin` entries in `binaries/`, `icon: ["icons/icon.ico"]`, NSIS `installMode: "currentUser"`, and WebView2 provisioning. Add `package:windows` to root scripts and ignore only the generated staging directory.
5. Run `node --test scripts/package-windows.test.mjs`, schema/config validation through the installed Tauri tooling, and `git diff --check`. Do not start a long Cargo build concurrently with another agent's Cargo invocation.

## Task 2 — actual Windows build and package inspection

1. Run `pnpm package:windows` on the supported Windows toolchain. Ensure Strawberry Perl is available for vendored SQLCipher/OpenSSL.
2. Inspect the resulting NSIS `.exe`, its architecture, installed binary manifest, licenses and resource paths. Record the exact commit, command, hashes and unresolved runtime dependencies in the acceptance ledger.
3. Resolve build/package failures without weakening runtime integrity gates or removing required companions.

## Task 3 — independent review and integration

Review the scoped assembly diff against this plan; fix actionable findings and rerun affected tests. Commit the slice and maintain the full objective ledger. Public installer upload awaits the remaining product and clean-machine acceptance steps, not merely this plan's tests.

## Task 4 — repeatable hosted candidate build

Add a separate read-only Windows packaging workflow, triggered for relevant pull-request changes and manual runs. Run the staging tests and locked package command on Windows x64, record the source revision and hashes of the installer and all five application executables, and retain the unsigned internal candidate as a short-lived Actions artifact. Use pinned existing actions and no signing/publishing secrets. This is a hosted build check, not proof of clean-machine installation or public release readiness.
