# PR16 Apple CI deferral — 2026-09-14

The approved Apple CI deferral is recorded in local source commit `a96e441456f5369c43ce805aaa615e933a252916`, parent `aa241cf59057c55d3466e5496e8c4f9a1959f7ea`. Main ruleset19760487 was updated with the separately reviewed exact PUT and independently checked against its saved fresh baseline, response and readback. Apple qualification is **deferred, not passed**. This work performed no source push, merge or public publication.

## Preserved repository protections

Exactly four required contexts were removed: `Rust lint (macos-arm64)`, `Rust tests (macos-arm64)`, `Native build (macos-arm64)` and `native-isolation-macos-arm64`.

All18 remaining contexts retain their original integration_id15368 and order: `rust`; `Secret Scan`; `Rust lint (windows-x64)`; `Rust tests (windows-x64)`; `daemon-boundary`; `bindings`; `schemas`; `licenses`; `dependency-policy`; `node-dependency-policy`; `whitespace`; `Frontend (lint)`; `Frontend (typecheck)`; `Frontend (tests)`; `Frontend (build)`; `Native build (windows-x64)`; `semgrep-materials`; `native-isolation-windows-x64`.

Strict required-status enforcement and enforcement on creation remain unchanged. The active main ref scope, deletion/non-fast-forward/linear-history protection, full pull-request rules including resolved review threads and squash-only merge methods, and existing bypass configuration are unchanged. No bypass was added or used. Release-tag ruleset19760490 remains byte-identical, including its update/deletion protections and existing bypass configuration.

Immediately preceding the PUT, saved fresh main/tag responses matched the reviewed baselines exactly. The saved PR16 state was OPEN/BLOCKED, autoMergeRequest null, remote head `30589c010af29b1bd0caf543eaab539baedd044c`. The PUT response and subsequent main readback are identical and match every writable proposed field; tag readback is unchanged. These are bounded saved observations, not a claim that future remote state cannot change.

## Source and local verification

The exact reviewed three-file v2 proposal is committed: `.github/workflows/ci.yml`, `scripts/ci-gates-workflow.test.mjs` and `scripts/native-ci-workflow.test.mjs`. The three host matrices now contain only their existing Windows rows. The two Mac Semgrep/native-isolation jobs explicitly skip; their definitions and Apple-specific steps remain for later requalification. Windows jobs, builder counts, permissions, artifact/reuse gates and public-publication dependencies/condition are preserved. Public publication still requires its complete protected qualification path; deferred Apple jobs do not supply successful outputs.

Independent byte/hash comparison matched all committed files to the reviewed v2 archive. The meaningful matrix assertion failed on original source (Node exit1,1.03s) and passed on the changed source (exit0,0.16s). The selected Windows Node workflow suites passed34/34, exit0,0.66s. Their command explicitly excluded `^whitespace gate` Linux `/bin/bash` integration cases; those remain required in Linux CI. Local tests establish workflow-contract behavior, not execution of hosted checks or installed qualification. A console encoding error occurred only after child receipts were saved; their terminal exit codes and logs were independently read.

## Evidence identities

Detailed immutable inputs and reviews are under `.superpowers/sdd/2026-09-14-pr16-windows-shared-acceptance/`.

| Evidence | SHA256 |
|---|---|
| Main captured/fresh-before response | `d22a3b3848847217f3cef66295cb29bab511bc1de9876a4da3822ab30dcced89` |
| Exact proposed main PUT | `15c4495e0bec3da0812ef3d2cdbac8ac2d170ccaf12090fe40b1b678a7080a7e` |
| Main PUT response/after readback | `6e45f350640f6764d6298deb54776b03f68d72a7f634e40a19584a54ccc6a3d8` |
| Tags captured/fresh-before/after | `0eda33eb5103d2e2525d9038a6a544fe00588bbda012827dc6c92194fc662675` |
| PR fresh-before | `f373389a8d382a2d3102bcb9bf4cb7b968553c8a913e1feda7e3ebe0e26514a2` |
| Source v2 manifest | `7b5881a495ba8f482f68141abf50e22c493d82341b09d9b4bf775ebba4cd6c6c` |
| Source v2 archive | `85e3e2a518172c5b95b4d6c6a7e410b96bfb89580b33ccfb25826bd60c05f54c` |

Ruleset evidence files are `finalization-main-fresh-before.json`, `finalization-tags-fresh-before.json`, `finalization-main-ruleset-proposed-put.json`, `finalization-main-ruleset-put-response.json`, `finalization-main-after.json`, `finalization-tags-after.json` and `finalization-pr-fresh-before.json`. Actual local receipts are `finalization-apple-deferral-{red,green,workflow-tests}.log` with matching `.result.json` files. Independent findings and their v2 resolution remain in `finalization-apple-deferral-preflight-review.md` and `finalization-apple-deferral-source-review.md`.

The18 Windows/shared gates, Linux whitespace execution, full installed physical-PC acceptance and later protected publication remain separate requirements. Deferral does not qualify Apple or close those requirements.
