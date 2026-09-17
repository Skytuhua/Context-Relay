# Packaged Windows search — 2026-09-07

Windows production configuration now selects `search/` beside the daemon
executable. The installer supplies the model and its native runtime; the user
does not need Python, a model download, or an environment variable. Model loading
runs as one background worker turn after opening the vault. The worker returns
to its request queue before indexing the first record.

Until the model is available, search uses scoped keyword matches. Missing or
damaged assets stop background preparation and expose Retry. Query inference
errors preserve keyword results, discard the failed session, and publish the
same stopped state. Retry verifies the package again and creates a new session;
persisted records and derived vectors remain intact. Indexing model errors also
discard the session. Database errors remain errors, rather than being presented
as successful searches.

## Package inputs and native loading

`scripts/search-resources.mjs` verifies all 13 files before writing staged output:
five BGE model/tokenizer files, ONNX Runtime and its provider DLL, four Microsoft
C++ runtime DLLs, and two runtime notice files. It retains the verified bytes.
The Tauri release resource map enumerates each file explicitly. No unrelated
cache files enter the package. Provenance, sizes, and SHA-256 digests are recorded
in the manifests and README under `crates/core/models/`.

The Windows loader verifies model bytes before constructing a session. It opens
and retains native files against modification/deletion, and directory handles
against rename/deletion. Before native loading it checks reparse attributes and
compares every retained file/directory's normalized physical handle path with its
fixed expected path. This rejects a transient junction even when it is removed
before the final check. Expected paths are not resolved again through the changed
namespace. Directory guards request directory-list access as well as attributes.

Runtime dependencies load in manifest order from explicit paths, with only
System32 available for unresolved imports. The loader attests the selected ORT
API table against the explicitly loaded packaged module before configuring the
environment. It retains all native guards for the process lifetime. Telemetry is
disabled. A prior unrelated runtime selection is rejected.

## Regression evidence

- Packaging: 15 tests passed, including actual byte-for-byte staging and a
  same-size damaged C++ dependency. Missing/damaged input preserved prior output.
- Loader: four focused tests passed. The transient-junction and redirect/restore
  cases first reproduced failures. The latter uses only attribute-write access.
  Empty guarded directories cannot be renamed/deleted. A fresh child process
  rejects an ORT API previously selected from a differently named library.
- Packaged model: two isolated child-process checks passed. Missing/damaged
  runtime inputs are rejected, unrelated `ORT_DYLIB_PATH` is ignored, loaded
  native files remain pinned, and real BGE embeddings rank automobile maintenance
  closer to a car-service passage than a cake recipe.
- Core: seven regular search checks passed. An additional real-model test first
  reproduced loss of keyword results after inference failure, then passed with
  keyword fallback and recovery through a new model session.
- Service: authenticated private-IPC qualification uses a disposable vault,
  synthetic credential stores, and copied assets. It covers missing inputs,
  damaged inputs, keyword access, Retry, and real semantic results. With daemon
  test support, it restarts the same disposable vault, injects a query inference
  failure, observes Failed through authenticated IPC, retains keyword access,
  and recovers semantic results through Retry. The three packaged service tests
  passed in 2.85 seconds; the broader daemon suite passed 76 tests in 70.62 seconds.
- Desktop: the three progress/retry tests passed after clarifying that keyword
  search remains available when preparation stops.

The CI fetch step was exercised against a fresh independent cache. It downloaded
and verified the pinned BGE/ORT files and Microsoft redistributable, passively
extracted the exact four C++ DLLs, and passed all 15 packaging tests using those
fresh inputs. Neither the redistributable EXE nor any MSI was executed. CI itself
has not yet run this updated packaging workflow.

The loader and service changes received independent read-only review, with no
remaining material findings in their reviewed scope. Core/daemon all-target
Clippy passed with test support and warnings denied. These checks do not replace
installed application or clean-machine acceptance. Native desktop control remains
paused; no normal daemon, harness configuration, or user record was changed by
these fixtures. The installer remains unsigned. Non-Windows production semantic
activation and the broader harness/hosted acceptance items remain open.
