# Replacing the native Semgrep sidecar

Context Relay invokes Semgrep 1.170.0 as a separate, unmodified executable named
exactly `osemgrep` (or `osemgrep.exe` on Windows). It does not link Semgrep
into Context Relay.

First verify and extract the complete source archive described by
`source-lock.v1.json`. Restore only its recorded Git symlinks:

```text
node scripts/semgrep-source-bundle.mjs --verify SOURCE_LOCK SOURCE_BUNDLE.tar
tar -xf SOURCE_BUNDLE.tar -C EXTRACTED_ROOT
node scripts/semgrep-source-bundle.mjs --materialize-links EXTRACTED_ROOT
```

The target build scripts perform these checks themselves, block network access,
create the same isolated working path twice, use only bundled Git pins and opam
archives, build the native OCaml executable, inventory its runtime closure,
reject Python dependencies, and smoke-test the literal closed scan template
with a restricted `PATH` against clean, one-finding, and invalid-rule cases.
The invalid rule must fail. The scripts then compare the two runtime outputs:

```text
sh third_party/sidecars/semgrep/build-public-source-macos.sh SOURCE_LOCK SOURCE_BUNDLE.tar ABSENT_WORK_ROOT ABSENT_OUTPUT_ROOT
powershell -File third_party/sidecars/semgrep/build-public-source-windows.ps1 -SourceLock SOURCE_LOCK -SourceBundle SOURCE_BUNDLE.tar -WorkRoot ABSENT_WORK_ROOT -OutputRoot ABSENT_OUTPUT_ROOT
```

The macOS route is pinned to the standard native-arm64 `macos-15` runner,
`actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020`, Node 24.14.0,
`semgrep/setup-ocaml@a739c5405d73c42ef15a9dc995efc0f87396cc36`,
and opam 2.5.0. The Windows route is pinned to `windows-2022`, Cygwin
3.6.10, the same setup-node action and Node version,
`semgrep/setup-ocaml@3e4c6ff8c9a04c9ec8f6f87701cd4b661b0f1f18`,
and opam 2.5.2. The Windows native run must emit the normalized evidence
specified by `builder-evidence.windows-x86_64.v1.schema.json`; its exact-byte
SHA-256 remains pending in the source lock until the first honest hosted build.
Each script writes runtime-only `build-a`, `build-b`, and verified `release`
directories. Their sibling `build-a-evidence`, `build-b-evidence`, and
`release-evidence` directories hold the flat canonical runtime manifest,
version, dependency inventory, and smoke reports. Build-time rule and target
fixtures remain under the disposable work root and never enter the runtime
closure.

A replacement becomes selectable only after its source-bundle digest,
executable and runtime-closure digests, command-template digest, two-build
evidence, and native sandbox smoke evidence are committed. Official PyPI wheels
and Pysemgrep are not substitutes for this public-source native build.

The immutable final corresponding-source location is predeclared as
`https://github.com/Skytuhua/Context-Relay/releases/download/sidecars-semgrep-1.170.0-source.1/semgrep-1.170.0-corresponding-source.tar`.
Its exact digest, size, entry count, and completion status live in the external
`bundle-evidence.v1.json`; the embedded source lock never contains the tar's
own digest, avoiding a circular rebuild.

This is an engineering compliance posture, not legal advice. Confirm the
release bundle with counsel before distribution.
