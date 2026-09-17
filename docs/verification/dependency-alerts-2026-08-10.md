# Dependency Alert Recovery — 2026-08-10

This ledger records the PR #12 dependency-alert recovery at the repository
head under review. GitHub still reports alerts against the default branch until
the reviewed repair is merged and Dependabot rescans it; no alert was dismissed
or marked accepted by this work.

## September 14 Rust follow-up

Read-only GitHub API verification still reports alert `#23` open for
`glib >=0.15.0,<0.20.0`, first patched at `0.20.0`. Local `Cargo.lock` at
`1bc7d53` contains `glib 0.18.5`, `gtk 0.18.2`, `tauri 2.11.5`,
`tao 0.35.3`, `webkit2gtk 2.0.2` and `wry 0.55.1`.

The [upstream advisory](https://github.com/advisories/GHSA-wrw7-89jp-8q8g)
identifies an invalid immutable out-pointer in `VariantStrIter`; its fix uses
a mutable pointer. The current upstream
[Tauri manifest](https://github.com/tauri-apps/tauri/blob/dev/crates/tauri/Cargo.toml)
still declares Linux `gtk 0.18`, as does the
[Tao manifest](https://github.com/tauri-apps/tao/blob/dev/Cargo.toml)
whose observed development version is `0.37.0`. These moving-branch observations
do not establish a tested compatible upgrade or rule out a reviewed backport.
They show why simply selecting a newer Tao version is not a verified repair.

The September12 saved target-tree evidence was inspected, not rerun during the
exclusive membership test batch. No Apple qualification was performed. No
dependency, alert state or exception approval changed. The older September10
proposed expiry below has elapsed; a later local proposal through October9 is
also unapproved. Neither proposal authorizes release acceptance. Require a
verified remediation or explicit disposition with fresh applicable-target and
artifact evidence at the final release boundary.

## Node repair

The 22 open npm alerts reported by Dependabot collapse to five packages. The
PR updates every resolved occurrence past the highest published fixed version:

| Package | Repaired resolution | Covered Dependabot alerts |
| --- | --- | --- |
| `ajv` | `8.18.0` | `#14` |
| `brace-expansion` | `1.1.18` and `2.1.4` | `#24` and the newer live-audit advisories for both major lines |
| `fast-uri` | `3.1.5` | `#21`, `#25` |
| `vite` | `7.3.5` | `#1`–`#3`, `#5`–`#7`, `#9`–`#13`, `#15`–`#17`, `#19`, `#20` where applicable to the package manifest or lockfile |
| `vitest` | `3.2.6` | `#8`, `#18` |

During verification, the live npm advisory service reported newer patched
transitive advisories not yet present in the GitHub list. Exact workspace
overrides therefore also advance `esbuild` to `0.28.1`, `js-yaml` to `4.3.1`,
`nanoid` to `3.3.17`, and `postcss` to `8.5.23`. The dependency-policy test
rejects every superseded resolved version, and the independently visible CI job
runs both that test and `pnpm audit --audit-level low` after a frozen install.

Verification at the candidate repair boundary:

- exact pnpm `11.9.0` frozen install: green;
- dependency-policy and CI-workflow contracts: 8/8 green;
- live `pnpm audit --audit-level low`: `No known vulnerabilities found`;
- desktop lint, typecheck, and production build: green;
- complete desktop suite: 54/54 green, including the concurrent protocol 1.4
  contract fixtures.

## Rust alert requiring an approval decision

Dependabot alert `#23` reports `glib 0.18.5` with first patched version `0.20.0`.
The locked dependency is introduced only by Tauri's Linux GTK/WebKit graph.
Exact target-specific `cargo tree --locked -i glib@0.18.5` queries print no
dependency for the supported macOS arm64 or Windows x64 release targets and
print the GTK/Tauri chain only for Linux.

This is not silently accepted and the alert remains open. Linux is outside the
v1 release target set, but the master plan requires explicit approval before an
unavoidable no-fix dependency can be dispositioned. Proposed owner: release
security maintainer. Proposed decision expiry: 2026-09-10. Until approval or a
compatible Tauri graph removes the dependency, repository/release dependency
acceptance remains `partial` and Linux artifacts remain forbidden.

## Completion boundary

This ledger proves a candidate repair, not product completion. The npm alerts
must disappear after the reviewed merge and a fresh Dependabot scan. The Rust
alert needs either a compatible dependency update or the explicit,
time-bounded, reachability-backed approval described above. Tasks 22–24 remain
blocked on their full release matrices.
