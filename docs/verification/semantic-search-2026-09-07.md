# Semantic search qualification — 2026-09-07

Status: production integration in progress. The current installer still uses the
legacy search path. This document is not installed-app acceptance.

## Evidence

- The existing workspace search returned no result for `automobile maintenance`
  when the saved note described servicing a car and replacing its oil. The new
  regression failed before model injection and passed with the actual BGE model.
- Real-model tests also passed for changed text, another project's exclusion,
  archived-record exclusion, and reopening the disposable encrypted vault.
- Native-model tests now show as ignored in ordinary test runs. Explicit runs
  require the model directory instead of silently returning a passing result when
  assets are absent.
- Model loading now consumes retained verified bytes, rather than reopening paths
  after their integrity check. Generic manifest verification remains streaming.
- The initial release-mode 10,000-record measurement failed: cold search took
  **155.244 seconds**, and warm P95 was **245.286 ms** against the 150 ms gate.
  That warm measurement includes actual query inference, current-document reads,
  cached passage validation, and hybrid ranking. It does not use an injected query
  vector as a substitute for model inference.
- The initial runtime used its default of every available CPU thread (28 on this
  machine). With one inference thread, cold search took **360.321 seconds** and
  warm P95 was **216.225 ms**: still a failure. Lower CPU usage did not solve the
  repeated full-document scan.
- The subsequent cache holds the most recent scope's eligible IDs against the
  connection change count and SQLite data version. Matching queries avoid reading
  every document again. Local writes and commits through another connection force
  a scoped refresh; record text digests determine which vectors need replacement.
  This version passed the local release-mode warm gate: **142.998 ms P95** over
  100 measured queries after warmup, with **349.051 seconds** for the first cold
  search. Total test time was 381.86 seconds. This is one Windows x64 machine,
  a short-text 10,000-record fixture, and a repeated query; the margin below
  150 ms is small. It is not a general latency guarantee or a cold-start pass.
- Focused search/model-input checks pass (seven tests, four explicit opt-ins
  excluded). The two real-model checks pass separately, including pending-candidate
  exclusion, instruction retrieval, and scope invalidation after a second
  connection moves a warmed global memory into a project. Three search unit tests
  pass. Core/daemon all-target Clippy passes with test support and warnings denied.
- Independent read-only review approved retained-byte loading and scope snapshot
  invalidation. It does not substitute for runtime or installed acceptance.

## Assets used locally

The five files exactly match the committed BGE manifest at
`crates/core/models/bge-small-en-v1.5/manifest.json`. They were downloaded from
the pinned Qdrant model revision `52398278842ec682c6f32300af41344b1c0b0bb2`.

The Windows x64 CPU runtime is Microsoft's ONNX Runtime 1.24.2 release archive:
`onnxruntime-win-x64-1.24.2.zip`, 74,075,355 bytes, SHA-256
`8e3e9c826375352e29cb2614fe44f3d7a4b0ff7b8028ad7a456af9d949a7e8b0`.
The hash matches the upstream release API's asset digest. The test process uses
an explicit local `ORT_DYLIB_PATH`; this is not yet the packaged runtime loader.
Model initialization disables runtime telemetry before creating a session.

## Open acceptance work

Cold indexing must fit an explicit application workflow. A synchronous first
search over 10,000 uncached passages exceeds the daemon's 29-second response
deadline. Warm performance alone does not resolve this.

The Windows installer still needs verified model/runtime resources and production
startup wiring. Current model-backed vaults are explicitly configured by tests.
Model vectors are derived in memory from current scoped documents; existing
stored legacy vectors are preserved and never compared with BGE query vectors in
this configured path. Model cache persistence and indexing progress remain open.

Semantic ranking currently uses document titles and bodies. Existing memory tag
search behavior must also be preserved before production activation.

The follow-up review recommends cooperative indexing batches on the existing
vault thread, persisted model-qualified vectors in the encrypted database, and
explicit progress while lexical results remain available. The current timeout
only abandons the response; it does not interrupt inference. This workflow is
planned, not implemented.

The code graph was refreshed after the source changes: 16,717 nodes and 47,337
edges. Optional SQL/OCaml parsers were unavailable and Cargo.toml produced no AST
nodes; graph navigation does not replace the source/tests above.
