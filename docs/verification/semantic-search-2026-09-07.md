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

The responsive-index follow-up separates passage inference from search requests.
Schema 27 persists model/input-qualified vectors and a pending queue inside the
encrypted vault, outside sync. It adds scoped progress and explicit resumable
batches; current searches use only ready vectors plus keyword matches. Title,
tags, and body determine the input digest, and tags also enter keyword search.
Vector publication and queue removal recheck current record state. Restart and
metadata-only changes reuse matching persisted vectors.

Read-only review found repeated full scans in the initial migration and batch
selection. Migration now clears FTS once and pages source records; batches visit
the pending queue. Progress counts still scan the eligible corpus and should be
polled at a controlled frequency, not after every slice.

The first cold-request regression failed at 1.399 seconds for 40 records and then
passed after removing passage inference from search. The storage/migration suite
passes 36 tests, and a focused SQL race-boundary test rejects publication after
edits, archival, loss of approval, or deletion. The real-model lifecycle covers
fingerprint mismatch, tag-only edits, restart reuse, scope changes through another
connection, pending candidates, and unchanged sync outbox contents.

A release maximum-record test initially failed at 2.443 seconds for a 1,048,572-byte
body: the tokenizer processed the whole input before applying 512-token truncation.
The model now receives at most a 16 KiB UTF-8 prefix, and this preprocessing is part
of its fingerprint. The record and full keyword index are preserved. The corrected
test passed at 1.062 seconds, with 10 focused checks passing in 9.75 seconds. This is
an observed single-record batch, not a hard preemption guarantee.
The final focused rerun passed all 10 checks in 8.50 seconds and measured that batch
at 752.714 ms.

The subsequent actual-model 10k run passed all local gates. Metadata upgrade/open
took **2.831 seconds** and a query before passage indexing took **136.369 ms**.
Resumable indexing took **313.769 seconds**. The first query over the completed
persisted index took **331 ms**, and warm P95 over 100 queries after five warmups
was **84.450 ms**, including BGE query inference. Total test time was 365.23 seconds.
The upgrade had first failed at 6.247 seconds, then 5.053 seconds; reusing prepared
statements and rebuilding FTS with one bulk SQL insert resolved the repeated work.
This remains a short-document fixture and repeated query on one Windows x64 host.
It does not establish daemon request fairness, macOS performance, or installed
first-use acceptance.

A separate 16,401-record cache-capacity check passed in 91.54 seconds. It computes
one real BGE vector, reuses it for records with identical model input, and checks
global/project switching above the 16,384-entry memory-cache bound, followed by
restart. Matching persisted vectors require no inference. This validates storage
and cache behavior, not the cost or retrieval quality of embedding 16,401 distinct
documents.

Final validation for this core checkpoint totals 53 selected passing tests:
10 focused search/model/lifecycle checks, the 10k gate, the cache-capacity check,
36 storage/migration regressions, and five search/publication unit tests.
Core and daemon all-target Clippy passes with test support and warnings denied;
format and diff checks pass. Final independent read-only review approved the core
patch, explicitly excluding service/UI scheduling and packaging.

The Windows installer still needs verified model/runtime resources and production
startup wiring. Current model-backed vaults are explicitly configured by tests.
Existing stored legacy vectors are preserved and never compared with BGE query
vectors in this configured path. Service scheduling, authenticated desktop
progress, and failure/retry composition still need qualification before production
activation. The cache-capacity test above does not establish latency for diverse
larger collections across supported platforms.

The service must schedule the new batches cooperatively and yield to requests.
Its current timeout only abandons the response; it cannot interrupt an inference.
Core batch/progress APIs alone do not constitute the complete application workflow.

The code graph was refreshed after the source changes: 16,758 nodes and 47,422
edges across 768 communities. Optional SQL/OCaml parsers were unavailable and Cargo.toml produced no AST
nodes; graph navigation does not replace the source/tests above.
