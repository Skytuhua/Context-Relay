# Hermes Python installation discovery implementation plan

Use superpowers:executing-plans for this independently testable first deliverable.

**Goal:** Identify the actual Windows Python installation without executing it.

**Architecture:** A focused passive inspector returns resolved installation roots,
installed metadata version and observed metadata digests. Hermes discovery uses the
description for reporting only; executable classification and Full gates remain intact.

**Spec:** ../specs/2026-09-06-hermes-python-installation.md

**Files:** crates/core/src/hermes/python_installation.rs, crates/core/src/hermes.rs,
apps/desktop/src/harnesses.tsx and its discovery tests, adapters/hermes/capabilities.md.

- [x] Add a fixture shaped like the Windows uv editable installation. Assert that
  inspection returns 0.17.0 and resolved venv/base/source roots without processing
  a poisoned .pth file. Exercise the real discover-version seam with a callback
  that panics if invoked. Confirm the initial assertion fails on unknown version.
- [x] Implement bounded passive reads, strict metadata/entry-point consistency,
  canonical local roots, and rejection of symlinks/reparse points and ambiguous
  distributions. Return metadata observations explicitly separate from runtime authority.
- [x] Cover wheel and editable installs, unsupported Python implementation/version,
  duplicate and oversized metadata, missing interpreter, mismatched source version,
  external/direct URL schemes, source aliases, and unchanged ImportOnly behavior.
- [x] Report the installed metadata version and explain the Python runtime gate in
  the existing Harness availability result. Keep setup/approval unavailable.
- [x] Inspect the actual installed Windows metadata using an opt-in read-only test;
  run focused Hermes and frontend suites plus lint/type checks and reviewer gate.
- [x] Update capabilities, verification evidence, graph, handoff and draft PR.

Subsequent work is complete immutable runtime capture and staged execution under
the spec's remaining contract. This plan does not close the full connection goal.
