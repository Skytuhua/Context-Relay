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

Windows search resources are staged separately from the Rust executables. The
installer includes only the pinned files listed in the manifests under
`crates/core/models/`:

| Resource | Version / source | License / notice |
| --- | --- | --- |
| BGE small English embedding model (Qdrant ONNX quantization) | `Qdrant/bge-small-en-v1.5-onnx-Q`, revision `52398278842ec682c6f32300af41344b1c0b0bb2` | Apache-2.0; see the Apache license included with the application |
| ONNX Runtime Windows x64 | Microsoft ONNX Runtime 1.24.2 | MIT; bundled `search/runtime/LICENSE` and `search/runtime/ThirdPartyNotices.txt` |
| Microsoft Visual C++ runtime DLLs | 14.44.35211.0, x64 release redistributables from Visual Studio 2022 | Microsoft Software License Terms; copyright Microsoft Corporation. Distributed as application-local supporting libraries, not as standalone developer tools. |

The Visual C++ files are `vcruntime140.dll`, `vcruntime140_1.dll`, `msvcp140.dll`,
and `msvcp140_1.dll`. Build-time staging verifies their pinned hashes; the selected
source copies have valid Microsoft signatures. Redistribution is subject to the
[Visual Studio license terms](https://visualstudio.microsoft.com/license-terms/)
and [Microsoft's redistributable-file guidance](https://learn.microsoft.com/en-us/cpp/windows/redistributing-visual-cpp-files).
Application-local copies are serviced through Context Relay releases.
