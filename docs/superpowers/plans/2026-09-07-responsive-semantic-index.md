# Responsive semantic indexing

This follows the reviewed cold-indexing direction in the production semantic
search plan and the user's existing authorization to finish the product.

1. Add an actual-model regression proving a cold search does not embed the whole
   collection synchronously. Observe the failure on the current implementation.
2. Add schema27: tags/input digest on search documents and a separate encrypted
   `semantic_embeddings` table keyed by record ID, with model fingerprint, input
   digest, and normalized384-vector bytes. Backfill only metadata/FTS in migration,
   never run model inference in migration. The cache is local and outside sync.
3. Centralize title/tags/body input formatting and fingerprint its model,
   preprocessing, and pooling. Update the existing searchable-record projection
   so every memory/instruction write invalidates changed inputs transactionally.
   Include tags in keyword indexing and before the body in model input.
4. Add `Vault::index_semantic_batch` and scoped index progress. Bound batch size
   and elapsed work; recheck the current input digest and eligibility when saving
   a generated vector. Reuse persisted matching vectors after restart and edits.
5. Configured `Vault::search` reads only matching persisted vectors; it never
   performs passage inference. It can combine partial ready vectors with current
   lexical matches. The existing snapshot optimization must invalidate on writes.
6. Schedule small batches in `run_vault_worker`, yielding to queued requests.
   Add explicit index state/progress to the authenticated protocol and desktop
   gateway; keep control status responsive and discard obsolete UI completions.
   Retry preserves completed vectors, and shutdown stops scheduling batches.
7. Test cold responsiveness, persistence/restart, tags, stale vector rejection,
   edits/archive/scope changes, fingerprints, and collections beyond memory-cache
   capacity. Measure maximum-document inference and warm query latency. Review,
   update graph/evidence, then integrate verified packaged runtime/model assets.

Production activation remains off until the complete workflow and asset loading
are verified. No normal user vault, harness configuration, or native app input is
part of these disposable source tests.

## Implementation checkpoint

Steps 1–5 are implemented in the core vault. Schema 27 also has a durable pending
queue maintained by document/vector triggers and a model-identity singleton.
This replaces repeated full joins over completed records with queue slices.
The queue and vectors are derived local state, outside sync. Matching vectors
survive restart and metadata-only edits; changed text/tags invalidate readiness.
Migration clears FTS once and rebuilds it in 32-record pages.

The first actual-model cold-request regression failed at 1.399 seconds for 40
records; it passes after passage inference moved to the explicit batch API.
The 9-test search/lifecycle suite and 36 storage/migration tests pass. The initial
migration suite invocation omitted the repository's required `test-support`
feature and failed to compile; the corrected invocation passed.

The maximum-record test found that tokenization still processed a 1 MB body
before the 512-token limit, taking 2.443 seconds in a release test. Pre-tokenizer
input is now capped to a 16 KiB UTF-8 prefix, included in the model fingerprint.
Full records remain in encrypted storage and keyword search. The corrected test
passed at 1.062 seconds; all 10 focused release checks passed. The 10k metadata
upgrade then failed its 5-second gate at 6.247 seconds. Reusing prepared statements
and eliminating redundant queue writes reduced it to 5.053 seconds, still failing.
A single bulk FTS rebuild then passed: upgrade/open 2.831 seconds, first keyword
query before indexing 136.369 ms, resumable indexing 313.769 seconds, first indexed
query 331 ms, and warm query P95 84.450 ms. The real 10k test passed in 365.23 seconds
on the local Windows x64 host. These are core measurements, not installed UI proof.

Read-only review approved the revised queue/migration implementation. Scoped
progress still counts the eligible corpus; do not poll it after every slice.
The 16,401-record cache-capacity check passed in 91.54 seconds, using a real BGE
vector reused for identical inputs to qualify scope switching and restart beyond
the memory-cache limit. The final focused release rerun passed 10 tests in 8.50
seconds, with the maximum-record batch at 752.714 ms.
Step 6 now schedules one record per idle worker turn, with a second queue check
under the shared admission lock. Authenticated desktop-only status bypasses the
worker queue; it exposes a phase and revision without project/record counts.
The desktop polls only on Saved context, keeps existing results visible, refreshes
the submitted search when the revision changes, and offers an idempotent retry.
The wire contract is now 1.11, so older binaries cannot negotiate as compatible.
Verified model/runtime packaging and production initialization remain open.

Final core checkpoint: 53 selected tests pass, core/daemon all-target Clippy passes
with test support and warnings denied, and format/diff checks pass. Final read-only
review approved the core patch. The graph was updated to 16,758 nodes and 47,422
edges. Service/UI and installed acceptance remain open.

The service regression initially failed because no indexing work was scheduled.
It now passes with the actual BGE model. A second real-model fixture checks the
enqueue/admission race, request priority between records, status responses during
a gated inference, and no further admission after shutdown. Five focused service
checks pass. The desktop progress/retry/stale-result tests and the full 222-test
suite pass; lint and the production web build pass. Failure/retry state tests
preserve the completed revision; combined runtime failure/reinitialization and
packaged installed acceptance still need qualification.
