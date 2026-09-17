# Production semantic search

This implements the existing semantic-search requirement in the Windows release
acceptance map. The user has authorized finishing the intended product behavior.

## Design

`Vault` owns an optional pinned BGE search engine. Configured searches embed the
query with the BGE query instruction and rank current approved documents within
the resolved access scope. The existing lexical ranking remains in the hybrid
result. Legacy caller-supplied vectors must never be compared with BGE vectors.

The model engine caches passage vectors by record ID and SHA-256 of the exact
title/body input. The last scope's eligible IDs are cached against the connection's
total change count and SQLite data version. A local write, another connection's
commit, scope change, or passage eviction forces a fresh filtered document read.
This catches edits, sync materialization, candidate acceptance, and scope/archive
changes without adding invalidation hooks to every writer. Only one scope snapshot
is retained. The cache holds at most 16,384 vectors;
it is derived in memory and rebuilt after restart. Existing stored vectors and
records are preserved. Cold indexing cost must be reported separately from warm
query performance. Disk-persistent model caches can follow only if evidence calls
for them.

Model loading must consume the same bytes that passed the pinned manifest check.
Windows packaging must include pinned model assets and a qualified ONNX Runtime;
production activation depends on those assets, rather than a developer's ambient
model cache. Test-only vaults can retain explicit injected vectors.

## Steps

1. Run the existing real model smoke check with pinned, verified local assets.
2. Add a regression that misses a paraphrase using the current workspace search.
   Add the model-backed vault search and remove the legacy post-filter for it.
3. Exercise edits, archived/project-hidden records, instructions, and restart
   using the real model and a disposable encrypted vault. Make native-model tests
   explicitly ignored by default and fail if opted into without assets.
4. Make the loader verify retained bytes and cover damaged/missing artifacts.
5. Wire verified Windows model/runtime resources into packaging and production
   startup. Verify this path through a disposable daemon, never the normal vault.
6. Measure warm 10,000-record query latency separately from cold indexing. Run
   focused regressions, Clippy, formatting, independent read-only review, and
   graphify update. Record exact evidence and rebuild the installer when ready.

Native UI acceptance remains subject to the existing Computer Use pause. This
work does not qualify Codex or Claude Full setup, signing, or hosted features.

Measurement exposed two rollout prerequisites: preserve tag search and implement
a cold-indexing workflow that cannot block a request past the daemon deadline.
Production activation and packaging remain gated on those fixes. The independent
review approved loader retention and snapshot invalidation; measurements, not that
review, determine performance acceptance.

## Cold-indexing review follow-up

Read-only architecture review identified `run_vault_worker`, `ServiceStatus`,
`workspace.searchMemories`, and `App.searchMemory` as the integration points.
The current response timeout does not interrupt the synchronous inference loop.

Keep one resumable indexing job and the model on the existing vault thread. Yield
between small document/time batches, release statements/transactions between
batches, and service queued work before continuing. Persist a separate encrypted,
local-only derived-vector table with record ID, model/preprocessing fingerprint,
exact input digest, and validated vector. Reuse successful entries across restart,
retry, and memory-cache eviction. Do not mix this with the unqualified legacy
embedding table or sync its contents.

Search must return promptly with useful lexical results and an explicit semantic
index state while preparation runs. Carry compact progress through the existing
immediate/control routing pattern and gateway; refresh only the latest query and
project using the desktop's read-generation guard. A retry reuses the same job.
Stop scheduling batches on shutdown. Measure individual maximum-size inference,
since a batch deadline cannot preempt one ONNX call.

Revalidate content/scope before accepting work. Cache persistence changes SQLite's
total-change count, so indexing completion cannot use that count alone as its
generation. Verify concurrent reads/writes, edits and scope changes mid-index,
restart reuse, inference failure/retry, model-fingerprint changes, tag search, and
collections/scope switches that exceed the in-memory cache. This is a reviewed
follow-up direction. Core persistence and cooperative service/desktop integration
are now implemented and qualified in disposable tests; see the responsive-index
plan and semantic-search verification ledger for results.

Next: verify and stage pinned Windows model/runtime resources, initialize the
model as background work after worker readiness, preserve keyword access on
initialization failure, and make Retry repeat verification/initialization without
deleting completed vectors. Production resource paths must derive from the
installed executable, not ambient ORT_DYLIB_PATH. Use the runtime's explicit
`ort::init_from` path before any default runtime initialization, retaining verified
runtime file handles as needed to prevent replacement between checking/loading.
Qualify missing/tampered resources, interrupted/retried loading, and actual search
through an authenticated disposable daemon before enabling production or rebuilding
the installer. Also check how harness search reports a still-preparing index.
