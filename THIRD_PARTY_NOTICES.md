# Third-Party Notices

The repository can hydrate the following separately executed sidecars into the
ignored `target/sidecars/` cache. Hydration verifies the committed source,
license, archive, executable, closure, and command-template records before
publication. Distribution packaging is a separate release gate.

| Sidecar | Version / source | License | Packaging state |
| --- | --- | --- | --- |
| RuleSync | 14.0.1 / `4c5574fd2a2633f99c879c4a3cc386c4933d1caf` | MIT; copyright (c) 2024 dyoshikawa | Windows x64 and macOS arm64 provenance pinned |
| Gitleaks | 8.30.1 / `83d9cd684c87d95d656c1458ef04895a7f1cbd8e` | MIT; copyright (c) 2019 Zachary Rice | Windows x64 and macOS arm64 provenance pinned |
| Semgrep native `osemgrep` | 1.170.0 / `bd614accba811b407ae5c9ec6f1eecd3bdc29911` | LGPL-2.1-or-later | Disabled on every target pending complete corresponding source, two matching public-source builds, and native sandbox smoke tests |

Exact license texts are under `third_party/sidecars/licenses/`. Source locks,
release evidence, deterministic build/manifest rules, and the Semgrep
replacement instructions are under `third_party/sidecars/`. Official Semgrep
PyPI wheels and the macOS bootstrap artifact are research evidence only and
cannot be hydrated or packaged.

The protocol crate directly uses the following third-party source packages:

| Package | Resolved version | SPDX license | Source |
| --- | --- | --- | --- |
| base64 | 0.22.1 | MIT OR Apache-2.0 | https://github.com/marshallpierce/rust-base64 |
| minicbor | 0.26.5 | BlueOak-1.0.0 | https://github.com/twittner/minicbor |
| serde | 1.0.228 | MIT OR Apache-2.0 | https://github.com/serde-rs/serde |
| serde_json | 1.0.150 | MIT OR Apache-2.0 | https://github.com/serde-rs/json |
| thiserror | 2.0.18 | MIT OR Apache-2.0 | https://github.com/dtolnay/thiserror |
| ts-rs | 11.1.0 | MIT | https://github.com/Aleph-Alpha/ts-rs |
| uuid | 1.24.0 | Apache-2.0 OR MIT | https://github.com/uuid-rs/uuid |

The repository lockfile records the exact resolved source-package versions.
