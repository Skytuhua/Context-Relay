# Dependency license inventory — 2026-09-14

This inventory records dependency declarations, not a legal clearance or a claim
that every required license/source file is bundled. No dependencies or lockfiles
were changed, no Cargo command was run, and no package code was executed by the
Rust archive inspection.

| Input | SHA-256 | Result |
|---|---|---|
| Cargo.lock | `662dbdd4ee548881674c5353000fd9fe180770db587324fede694f3a206cf41d` | 632 entries: 623 registry packages, two pinned Git packages and seven workspace packages. |
| pnpm-lock.yaml | `63ce656df29e8a015553d76d5eaccfa47f68c88c032c41a29266a8cd54237184` | 363 package keys; installed license inventory covers 297 exact name/version pairs. |

For each registry crate, the local .crate archive's SHA-256 was compared with the
lock checksum before reading its bounded Cargo.toml member in memory. All 623
matched and declared a license; none had missing archive metadata or a checksum
mismatch. Names and versions were also checked against the lock entry. The two
Git dependencies, rusqlite 0.40.1 and libsqlite3-sys 0.38.1, declare MIT in the exact
Git objects at 62648175c23f84b45238f4a1fbb0133b75ce68f1. No working-copy metadata was
substituted for the pinned objects. Workspace packages remain covered separately
by the existing workspace metadata check; that check was not rerun here.

`pnpm licenses list --json` completed successfully using installed pnpm 11.9.0.
Its reported exact versions have no extras outside the lockfile. The 66 missing
lock keys all carry os/cpu constraints excluding Windows x64; none is an eligible
Windows x64 package omitted by this comparison. They remain absent from this
local license inventory, rather than being assigned assumed licenses. Apple
qualification remains deferred. This comparison inspects the existing lockfile's
package-key/constraint layout with explicit assertions; it is not a general YAML
parser and does not verify Node archive integrity.

Reproducible local evidence is retained under .codex/:

- pr16-rust-license-inventory.py and pr16-rust-license-inventory-2026-09-14.json;
- pr16-node-license-inventory-2026-09-14.json (raw pnpm output);
- pr16-node-license-coverage.py and pr16-node-license-coverage-2026-09-14.json.

The existing scripts/check-license-metadata.mjs uses Cargo metadata --no-deps and
workspace package manifests, plus sidecar material/hash inventory. It does not
replace this transitive lockfile inventory. Conversely, the declaration inventory
does not replace actual bundled license/source/relinking materials, model/runtime
obligations, distribution-specific review, dependency security disposition, or
Terms of Service/Privacy Policy review. T23 and RB-REP remain incomplete. These
artifacts must be regenerated if either lockfile changes before final acceptance.
