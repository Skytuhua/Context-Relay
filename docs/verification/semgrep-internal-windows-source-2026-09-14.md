# Semgrep internal Windows source checkpoint — 2026-09-14

This checkpoint qualifies two matching bootstrap source bundles and the tested
JavaScript verification components. It does not qualify a native Semgrep build,
the application license bundle, a Windows installer, installed behavior, or a
public release. Windows Semgrep remains disabled in the repository manifest.
Apple native qualification remains deferred.

## Actual source generation

Two separate fresh Git checkouts and archive caches under
`E:/Context Relay Releases/qualification-tools/pr16-semgrep-source-inputs/a` and
`b` were populated from the exact source-lock revisions. No earlier source tar
was copied or resealed to produce this pair. Each slot ran the existing source
inventory check, archive fetch, full bundle builder, and bundle verifier.
All eight commands completed with exit code zero. A streaming comparison then
compared every byte of the independently generated tar files.

| Input or result | Identity |
| --- | --- |
| Source lock SHA-256 | `0d85427b09343615126fde5ad9bd8ad7f157908692a69fea846b4d033f6cb3c0` |
| Generator SHA-256 | `199b18ff2bac412ded23b036cdef86ba1ea0402f55152b2743250be39d8ab9af` |
| Both tar SHA-256 values | `e098187c665f00d5864d3b734e17f7d19f4c4077567bf49813e1691615f0f549` |
| Each tar size | 1,149,654,016 bytes |
| Each tar inventory | 39,543 payload entries; 222 recorded links |
| Node version | 24.14.0 |
| Node executable SHA-256 | `63c259c81e5d472b5f11c8d506070130cb04a1ecf84b80377a34ed6ec9048088` |
| Git version observed | 2.55.0.windows.3 |
| Producer receipt SHA-256 | `1b8d9c6185d982420e9c8ba3394ba5c48282267716707f9e68f8c067dd659edf` |
| Production completed | 2026-09-14 11:30:31 UTC |

The receipt and all per-command logs are retained in that input directory's
`production-v2/` subdirectory. The receipt records the exact command arguments,
working directory, timestamps, terminal exit codes, log hashes, pinned Node
identity, Git version, each checkout's commit/tree, output metrics, and a hashed
source/support/provenance/workflow inventory checked before and after each command.
Both output files remain there as `source-a.tar` and `source-b.tar`.
An earlier equal build pair remains in `production/`. Independent review found
missing provenance fields in its receipt, so both full builds and verifications
were rerun with those fields captured; no historical fields were invented.

The repository evidence now records
`source_bundle_reproducible_native_builds_pending`, two independent source
builds, and equal bytes. Only the observed bundle identity and changed generator,
relinking, and evidence hashes were refreshed. This pending state is not a native
runtime qualification or a claim that the historical public source URL serves
these new bytes.

## Implemented verification components

The internal Windows finalizer preserves the actual qualification commit,
workflow, run, attempt, two builder identities, and Windows isolation evidence.
It requires complete corresponding source while preserving Apple deferral.
Public release and earlier incomplete CI-candidate verification remain separate.

The descriptor producer binds exact material bytes. Staged input verification
compares the installed descriptor with those producer bytes before parsing, then
checks the referenced materials, full corresponding-source tar, native evidence,
and runtime archive through the existing validators. Descriptor and manifest
archive inventories must agree exactly. Material reads reject linked paths and
hardlinks. The verifier explicitly returns `complianceVerified: false`; the
separate application compliance inventory and readable license files still need
their complete verification.

The final five-file Node suite completed with 86 passes, zero failures, and exit
code zero in 12,839.3719 ms. It includes source generation and tampering,
finalization, descriptor/material changes, runtime archive checks, and the
archive-inventory review regression. Its raw log is retained at
`.superpowers/sdd/2026-09-14-pr16-windows-shared-acceptance/task-7-internal-windows-final-suite.log`,
SHA-256 `d27412af53755ed93a13da0e6be82ee7410aa271b5d9eab28c96861c4a3c6a5b`.
Earlier failing checks and independent review records remain in the same audit
directory; they were not replaced with passing claims.

## Remaining gates

The exact reviewed source/evidence must be committed and both retained source
bundles checked against that committed evidence. The existing Windows-only
qualification workflow must then independently reproduce the source and native
runtime builds and supply its actual isolation results. Production package and
native descriptor integration, the complete license/SBOM/source-obligation tree,
installer inspection, and physical-PC installed acceptance remain required.
This checkpoint closes no hosted, installed, public-beta, or full release row.
