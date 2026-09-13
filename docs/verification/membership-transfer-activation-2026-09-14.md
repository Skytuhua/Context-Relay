# Membership transfer and activation component evidence

Task4 of the membership-transfer plan is complete at
`d43aced5381d681bc79cb8f451d8e5d0b1fe1d4d`, after independent review and two
fix rounds. This is component acceptance, not full product-release acceptance.
Task5 hosted/daemon/UI integration remains incomplete, and PR16 is unmerged.
Apple work and anything requiring payment remain deferred, not passed.

## Requirements and coverage

| Requirement | Implementation and behavioral evidence |
|---|---|
| Historical authority with current-write guards retained | Historical admission and the private representative validator verify accepted certificates, epochs, complete device/causal prefixes and exact signed cutoffs. Real signed alternate-branch, metadata, receipt and off-prefix-head regressions reject invalid authority. |
| Consistent replacement domination | Selection requires reconstructed prior evidence and consistent verified prefixes over the actual target. Tests reject scalar-only and checkpoint-link-only replacement and preserve the selected target on missing proof. |
| Exact target reconstruction and repair | Bounded isolated replay reproduces the selected state hash; inventory completion alone is insufficient. Tests cover missing encrypted operations, withheld cutoff/causal proof, restart, alternate exporters and both public dependency-pressure repair paths. |
| Independent ordinary activation | `retained_root_stages_rotation_without_pairing_c_and_preserves_epoch_one` verifies exact accepted authority and privately opened material without pairing C or a historical transfer. Activation failure/restart and old-material fallback are exercised. |
| Atomic installation and completion | One immediate transaction rechecks target, D, inventory, reconstruction, current material and local provenance. Tests check rejection without activation/completion, rollback of materialization/cache effects, valid retry, and preservation of newer operations and conflicting heads. |
| No stale authority after interruption/revocation | The membership integration fixture injects activation failure, reopens the vault and rejects old sync/enrollment/pairing material and stale incoming/outgoing capabilities. After accepted local revocation and reopen, an owned admitted operation and pairing material reader remain unusable. |
| Offline/rotation/fork/restart scenarios | Historical and membership fixtures cover retained children, forks, withheld history, replacement exporters, exact revocation cutoffs and interruption before/after activation. The earlier unchanged 33-rotation inventory fixture has the bounded evidence noted below. |

## Current revision checks

All commands used the locked dependency graph, the existing qualification target,
and one Cargo build job on Windows. No production source changed after the
historical test run.

```powershell
cargo test --locked -p context-relay-core --features test-support --lib historical_ -- --skip historical_durable_pages_restart_conflicts_cas_and_supersession
cargo test --locked -p context-relay-core --features test-support --test membership_vault_v1
cargo test --locked -p context-relay-core --features test-support --doc
cargo fmt --all -- --check
cargo clippy --locked -p context-relay-core --features test-support --all-targets -- -D warnings
git diff --check
```

Results: 21 historical tests passed in164.36s; four membership tests passed
in44.68s; five compile-fail documentation tests passed in0.30s. Formatting and
whitespace checks passed. All-target Clippy completed cleanly in53.53s.
Linked tests still emit the separately tracked OpenSSL LNK4099 warning.

The two new second-round tests first failed at their intended installation and
completion assertions (0passed/2failed,29.71s), then passed in the covering run.
They use a valid signed sequence-2 record head with a wrong predecessor while
the verified device tip remains sequence1. The completion test establishes a
valid installed receipt before injecting corruption; both require valid repair.

The unchanged empty-target 33-rotation page/inventory fixture was explicitly
filtered in the fix runs. It passed in the original 11-test historical run at
`7d736642caeec1e4d71cc3d0421df6a471247486` (357.85s). The earlier 146-caller
batch, including all256 randomized seeds, also predates these fixes. Neither is
represented as a complete test run of the final fix revision. Final release
verification must use the eventual release revision.

## Review and remaining boundaries

The initial review found three Important issues: unauthenticated existing
representatives, incomplete canonical replay reporting success, and persistent
dependency-budget cache poisoning. Fix1 (`d577036`) addressed all three; its
review found an additional superseding-head chain-inclusion gap. Fix2
(`d43aced`) requires record heads to belong to the already verified closure
before causal comparison. Fresh scoped review found that issue addressed and
no new Critical/Important breakage.

Historical reconstruction uses the caller's explicit candidate/target/proof
budgets. Local-provenance checks separately reuse the bounded private reader
limits:100,000 rows,64MiB,1,000,000 dependencies and CURRENT_BUDGET membership
history. This permits a bounded older target beside larger newer local work.
The combined cost and fixed live-read ceiling remain performance obligations;
the implementation can reject a large vault rather than read without bounds.

Still open: schema40 legacy-root provenance, actual dependency-symbol placement,
full hosted authorization and transport, installed login/pair/sync/restart/recovery,
clean Windows acceptance, package and harness workflows, and every other
nondeferred release gate. No provider roster is promoted to membership authority,
and no hosted workflow is considered verified by these component tests.

Detailed local reports, immutable review packages and terminal logs are retained
under `.superpowers/sdd/2026-09-13-membership-transfer-activation/`. The graph
update was AST-only (19,024 nodes/53,839 edges/771 communities); known missing
SQL/OCaml parsers and unrelated cached-file parse limitations remain documented.
