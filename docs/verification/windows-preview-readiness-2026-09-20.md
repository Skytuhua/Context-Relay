# Windows preview readiness — 2026-09-20

**NO-GO: no PR revision is approved for release yet.** Target: Windows x64
0.1.1, unsigned public prerelease v0.1.1-alpha.1. This supersedes earlier
internal-only/signing/updater scope statements; it does not waive acceptance.
No merge, tag creation or publication was performed. This report ends at a recommendation.

| Release identity | Result |
|---|---|
| Approved PR revision | None; release approval withheld |
| Candidate installer SHA-256 | None; candidate build and inspection pending |
| Source-preview tag retained | v0.1.0-alpha.1 at b357b29ad4379fae191a288fb653dd55e69f340c |
| Publication environment | windows-preview-publication; Skytuhua reviewer; protected branches only |

## Implemented repair

Version-aligned Cargo, lockfile, package and Tauri manifests. Candidate workflow
records installer SHA-256, binary/resource hashes, toolchains, hosted fingerprint,
SBOM and provenance. Publication requires a successful main workflow, exact source
and digest, existing matching protected tag and reviewer-protected environment.
Existing builder action revisions and protocol 1.17 are retained.

Fixed hosted authority after revocation: immutable certificate issuance epochs
may precede the current epoch only under exact active membership and matching
account/head epochs. Operation epochs remain current. Added live-session sync
validation. Pending-delete cancellation remains available to surviving members.
New legacy recovery V1 admissions are rejected because they lack signed public
history; exact historical receipt lookup remains read-only. V2 is retained.

## Hosted deployment

Project `brvzuycnxoswdzzipgvx`. Repository build variables name
`https://brvzuycnxoswdzzipgvx.supabase.co`; the publishable-key SHA-256 is
`c9223f50e6484578bc1ff030210e4539ecedd52f4afd70c874769cbb59c47db9`.
This is configuration evidence, not proof of bytes inside an installer. All 17 historical migration contents matched source
(normalized line endings), despite differing timestamp identities. No accounts
existed immediately before the additive deployment.

| Source migration | Deployed identity | Normalized SHA-256 |
|---|---|---|
| 20260913210523_membership_public_history_v2 | 20260920200501 | 75e7cd2f8c164152eb80fa750abff312b2d3f2f1f8bc484c52cbf15912df6912 |
| 20260920195022_membership_authority_release_cutover | 20260920200510 | ac43b4b679815e6fc9bd2395121610055ca54197ec5626c1ba1f53f10a649950 |

Readback migration content digests match. Function deployments:

| Function | Version | Bundle SHA-256 |
|---|---|---|
| sync | 2 | fc6a06a2950fe0345fdb91921f0b6b5e72553b1483e0df4b8bb673429852e6f7 |
| enrollment | 2 | 66c8edc6af2b43732308c4787df6bd5de980182267d63aab22372c15e83b0b7a |
| account-lifecycle | 2 | d65cc293cfbd85aa2a6370d5be4f1d6525b21a443016054393a46d08328a84b4 |
| pairing | 1 | 1fcfd62b90e8a28340cbfb13527c2242f6634f97bb62c64d32caad931effde3a |

Functions perform explicit authentication; existing custom-auth deployment mode
is retained. Pairing currently fails startup without CONTEXT_RELAY_PAIRING_PEPPER.
The dashboard handoff remains mandatory; no secret was generated or disclosed.
OAuth configuration was recorded complete on September 14. Installed login,
refresh, logout and authenticated two-device behavior remain unverified.
Do not roll back membership schema destructively or deploy the old epoch checks
against rotated accounts. Preserve history, secrets and receipts; repair forward.

## Verification checkpoint

Fresh local lint, typecheck, 389 frontend tests, production frontend build,
Supabase contract and license metadata checks pass. Release/packaging tests:
18 pass. Edge sync tests: 20 pass, including observed failure-before-fix for
older signed certificate issuance. PostgreSQL 17.6 disposable fixture tests:
26 membership, 38 lifecycle, 2 revocation pass. The fixture supplies minimal
Supabase auth/storage/realtime schemas; it is not installed or live Auth proof.
A restricted non-superuser run exposed missing fixture-owner grants in the
membership/revocation scripts. Temporary grant/restore hooks were added, matching
the existing lifecycle harness; all restricted-role suites pass: membership 26, lifecycle 38 and revocation 2. This corrects test
administration without changing runtime RPC permissions.
The revocation fixture explicitly verifies post-self-revocation denial, rather than
assuming the revoked device retains receipt-query authority. Live lost-response
recovery and a surviving device's receipt flow remain mandatory acceptance cases.
Independent security and code reviews found no outstanding critical/high issue
within the changed boundaries and the inspected native IPC, authentication, encryption, transaction, recovery and migration paths. These were bounded source reviews, not an exhaustive certification. An SBOM license-expression finding was fixed
with a failing-then-passing regression; upstream declarations use named licenses.
Actual Windows dependency inventory generates 725 SBOM components, no unknown
licenses. cargo-deny 0.20.2 passes advisories, bans, licenses and sources; the
Node audit reports no known vulnerabilities. Clippy with all four CI test-support
features and -D warnings, formatting, bindings, schemas and daemon-boundary checks
pass. The broader applicable Node run passes 439 tests with 5 skips: three real
search-resource cases and two symlink cases. The POSIX-only Realtime verifier
and Bash whitespace execution remain unqualified locally; Linux CI is required.
The first broad run caught the missing publication checkout credential setting
and stale workflow assertions; both were repaired and independently reviewed.
Command results and log hashes are captured in
[component evidence](windows-preview-component-evidence-2026-09-20.json).
Complete Rust workspace/all-target verification with all four CI test-support
features exited 0. The fresh log contains 160 passing summaries totaling 1,793
passes and 54 ignored cases (including any nested child summaries); no failures.
Ignored cases are not acceptance passes. The disposable PostgreSQL server was
stopped after verification.

## Source and access checkpoint

Implementation commits `59b5ee8`, `42178ba` and
`ef2b657f97496a38f4b1347df748bcbfab9e18ab` are preserved locally on
`codex/windows-preview-readiness`. The last commit is the reviewed code revision;
the subsequent report commit changes evidence documents only.
GitHub rejected its push because the OAuth login lacks workflow scope; remote
PR #16 remains `889197041d16465235bdea091affc326478f1d24`. No final-candidate CI or
installer hash exists yet. User action requested: gh auth refresh -h github.com
-s workflow. After authorization, push the reviewed branch to codex/windows-app-release
without force, then verify the remote head and all required contexts.

This host reports Claude Code 2.1.198, Codex CLI 0.142.4 and Hermes 0.21.3. These are
outside the source's selected managed-setup versions; no actual harness acceptance
was credited and no user harness was upgraded or reconfigured. Frozen version
eligibility is listed in the prepared release notes, separately from qualification.

The new sync, enrollment and lifecycle deployments return `401 / auth_required` for missing
and invalid credentials on structurally valid routes before operation admission. This is denial-only smoke evidence.
Pairing startup still returns `500 / WORKER_ERROR` without its required dashboard secret.

## Mandatory unresolved gates

- Candidate installer hash and final CI: pending build/inspection.
- Two fresh-profile passes, clean Windows without developer prerequisites,
  upgrade/interruption from `1468327` and encrypted-data preservation: unverified.
- Real qualified harness retrieval/task updates, approval/Undo, restart/offline:
  unverified on the candidate. No harness version receives release approval yet.
- Hosted login/refresh/logout, enrollment, pairing, two-device sync, explicit
  recovery-history selection, revocation/deletion, cross-account denial and
  lost/cancelled response recovery: mandatory and open.
- Four-hour exposed CBOR/JSON-RPC/native configuration fuzz qualification:
  unperformed; dedicated fuzz qualification remains work to complete. This host has only stable 1.97.1; the previously recorded E: tooling
  and N-1 artifact are unavailable here. Crash tests do not replace fuzzing.
- Linux-only glib alert: absent from current Windows Cargo resolve inventory,
  but actual final installer evidence remains required. No alert was dismissed.
- No plaintext-canary/installed secret-leak acceptance has been established.
- Debug links emitted the known OpenSSL ossl_static.pdb warning; final release
  artifact disposition remains open. Metadata license checks do not replace
  inspecting the complete bundled notices and resource inventory.

The 333-row acceptance CSV preserves historical Status and evidence, adding
PreviewDisposition/PreviewEvidence. Package functionality, macOS and automatic
updates are excluded; mixed installer/updater rows retain manual installer gates.
Product hosted-availability copy remains unchanged until hosted qualification.

## PR disposition and merge sequence

#1 and #2 closed with provenance/supersession explanations. #14 closed while
preserving branch codex/cross-device-handoff-2026-08-31 and its archive at
0fdcf04a9310ab525f2f0a8afed37f50f6b9bfd4 (remote readback confirmed).
#19 documentation is incorporated with the OAuth correction into the candidate.
#8/#9/#11/#13/#17/#18 remain open until replacement #16 is merged; then close
with: “Superseded by the merged PR #16 Windows preview implementation; this
branch is not separately approved for merge.”
#3/#4/#5/#6 remain deferred. Repair #4's React/ReactDOM mismatch before reconsidering.

1. Finish every mandatory gate and review the exact final #16 revision/CI.
2. Recommend merge only after evidence supports it; merge is a separate action.
3. After merge, run all required contexts and dispatch Windows installer candidate
   on main. If source or artifact changes, qualify that exact candidate again.
4. Inspect payload, notices, resources, versions, hosted fingerprint and hashes;
   finish installed/hosted acceptance and record candidate run and installer SHA.
5. Recommend publication separately. Preserve v0.1.0-alpha.1. A later authorized
   action creates protected v0.1.1-alpha.1 at the accepted main commit and dispatches
   the protected publication workflow with its run/source/installer digest.

Unavailable environments and missing credentials remain blockers, never passes.
