# Passive Windows Hermes Python discovery — 2026-09-06

Windows Python launcher discovery now reports the installed metadata version instead
of always returning unknown. The inspector describes the CPython base, venv,
site-packages, editable source and observed metadata digests without running Python.
The Harnesses result explains the outstanding Python runtime support and labels the
version source in Technical details. It does not request a setup plan or enable Apply.

## Actual installation evidence

An opt-in read-only core test inspected an existing Windows uv installation with
Hermes metadata version 0.17.0 and five metadata observations. The editable checkout
contains its venv. Its CPython minor-version junction resolves to the real 3.11.15
directory. The first actual inspection failed on these layouts; the corrected reader
passes against the same installation. The installed checkout's local modifications
were preserved. The test injects a panic if discovery attempts a version command.

The test reads installation metadata only. It does not import Python modules,
process .pth files, read profile credentials, run the harness, or modify settings.
This establishes passive discovery, not a complete or qualified Python runtime.

## Verification

- 40 Hermes core unit tests pass, with the opt-in installation test ignored by default.
- The explicit actual-installation test passes separately (0.17.0, five observations).
- All 72 Hermes adapter integration tests pass, preserving transaction and Full gates.
- 51 affected frontend tests pass; type checking and lint pass.
- Core all-target Clippy with test support and warnings denied passes.
- Independent source review approved the completed passive-inspection patch after
  the metadata substitution and remote-path findings were fixed.
- Failure-first regressions cover unknown metadata discovery, UI labeling, and a
  substituted metadata parent. Final tests reject the substituted junction and return
  no outside bytes or observation. UNC/device prefixes are rejected without I/O.
- Additional tests cover bounded metadata/directory reads, duplicate/mismatched
  distributions and console entries, unsupported Python metadata, external or
  ambiguous editable URLs, source version mismatch, and uv junction restrictions.

Logs are retained locally under the closeout directory with the hermes-python prefix.
The Windows linker emits the existing vendored OpenSSL missing-PDB warning; Clippy
passes without Rust warnings. No dependency or wire protocol change was needed.

## Remaining work

The description is not a runtime manifest, immutable staged closure, or execution
approval. Complete package/source/runtime capture, a separate sealed runtime binding,
controlled Python startup, and actual connection/recovery/Undo qualification remain
open under the [Python support design](../superpowers/specs/2026-09-06-hermes-python-installation.md).
Every Windows Python launcher remains ImportOnly. No replacement local EXE was built
or installed, native desktop control remains paused, and this is not release acceptance.
