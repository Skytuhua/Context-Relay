# Windows preview installer inspection — 2026-09-20

PR16 head `81dfbf8351bce573ee70c88bd59e257a74e41568` built successfully in
[run 35537739086](https://github.com/Skytuhua/Context-Relay/actions/runs/35537739086).
Artifact 10612939474 contains the installer, checksums, SBOM and provenance.
Its source is GitHub PR merge ref `2a1b622c04bca54b7a581871bff984134f7d9999`,
not a post-merge publication candidate. No publication approval is granted.

Installer `Context Relay_0.1.1_x64-setup.exe`: 78,099,041 bytes; SHA-256
`03eec6bcf9239760dab0e7f3c65f3330b30652e42e14d2d26033d64147a53a3c`.
All three downloaded artifact checksums match SHA256SUMS. Passive extraction
with 7-Zip 26.03 produced 29 files. The four companion executables and every
listed search/notices resource match their recorded bytes and hashes.
The SBOM contains 725 components and no glib component. This is fresh Windows
artifact evidence; it does not dismiss the Linux alert.
The configured hosted origin and fingerprint-verified publishable value were
found in the actual extracted context-relay-contextd.exe. No value is disclosed.

## Provenance defect and repair

The desktop payload differs from its recorded build-tree hash. Exact diagnosis:
replacing the extracted `__TAURI_BUNDLE_TYPE_VAR_NSS` marker with
`__TAURI_BUNDLE_TYPE_VAR_UNK` reproduces the recorded build-tree hash exactly.
[Tauri patches and restores the main binary during bundling](https://github.com/tauri-apps/tauri/blob/dev/crates/tauri-bundler/src/bundle.rs).
The CI log independently records NSIS patching. This is a provenance defect,
not evidence of an unexplained executable modification.

Auto-merge was disabled upon discovery. Evidence generation now extracts the
actual installer into an isolated temporary directory, hashes its five shipped
executables and declared resources, inventories every auxiliary payload file,
and removes extraction scratch data. Required missing files or extraction
errors fail the build. No build-tree executable hash is substituted for payload.

The new helper successfully inspected this actual installer. Its packaged desktop
SHA-256 is `a6be6c9891aa98f4da62b4b460b24daec53023dbf7f7fc4022f6790b1be285b9`.
Two regression tests failed before implementation and pass after the fix;
all eight preview tests pass. Resource-backed packaging/search/preview tests:
24 passed, 1 macOS skip, zero failures. Independent code review approved the fix.
A replacement CI artifact must verify the repaired provenance before auto-merge
is re-enabled. Current source and installed-product readiness are distinct.

Clean Windows installation, upgrade/interruption, fresh-profile and qualified
harness acceptance, authenticated hosted/two-device acceptance and four-hour
fuzzing remain open. Pairing still needs the dashboard secret. Full bundled
license/notice coverage, including auxiliary installer components, remains a
publication gate. No release or tag was created.
