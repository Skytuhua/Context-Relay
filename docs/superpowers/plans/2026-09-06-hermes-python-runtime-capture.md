# Hermes Python runtime capture implementation plan

Use superpowers:executing-plans for the capture and controlled startup deliverable.

**Goal:** Retain a complete bounded runtime projection for actual Hermes execution.
**Spec:** ../specs/2026-09-06-hermes-python-runtime-capture.md
**Files:** crates/core/src/hermes/python_runtime.rs and focused projection/literal/
test helpers beneath python_runtime/, with minimal shared passive-reader visibility.

- [x] Write failing deterministic capture and source-change retention tests using
  a synthetic installation; inspect the actual Windows package shapes as evidence.
- [x] Implement bounded tree copy and exact inventory verification, using existing
  no-follow file/identity and stage-path primitives. Reject aliases and collisions.
- [x] Implement declared editable source projection, safe literal mapping parsing,
  reviewed finder recognition and explicit sibling data without executing Python.
- [x] Generate the staged import/DLL bootstrap and bind it into capture identity.
  Unknown executable startup lines fail instead of being silently ignored.
- [x] Verify capture of the actual installed runtime and a fixed isolated CPython
  path probe from retained bytes. Test source mutation, staged additions/deletions,
  startup code canaries, bounds, link substitution and path collisions.
- [x] Run affected tests/lint/review, refresh the graph and record precise evidence.

Sealed transaction runtime binding, management-command containment and actual harness
connection qualification are subsequent work under the complete connection objective.
