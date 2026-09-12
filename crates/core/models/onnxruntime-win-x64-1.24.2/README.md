# Windows search runtime resources

`manifest.json` pins the complete application-local x64 runtime file set. These
binary files are build inputs, not Git-tracked source. Search resources are staged
by `scripts/search-resources.mjs` before Windows packaging starts its Cargo build.

ONNX Runtime comes from the official
[1.24.2 release](https://github.com/microsoft/onnxruntime/releases/tag/v1.24.2),
`onnxruntime-win-x64-1.24.2.zip`: 74,075,355 bytes, SHA-256
`8e3e9c826375352e29cb2614fe44f3d7a4b0ff7b8028ad7a456af9d949a7e8b0`.
The archive digest was checked against the release API. Its runtime DLL,
providers DLL, MIT license, and third-party notices are included unchanged.

The runtime PE imports also require `vcruntime140.dll`, `vcruntime140_1.dll`,
`msvcp140.dll`, and `msvcp140_1.dll`. The pinned copies have file version
14.44.35211.0 and valid Microsoft signatures. Their source is Visual Studio 2022's
release redistributable directory:
`VC/Redist/MSVC/14.44.35112/x64/Microsoft.VC143.CRT`.
No debug or OneCore DLL is selected. Their import closure needs only these four
DLLs and Windows system/API-set libraries. The application retains responsibility
for updating its app-local runtime copies; see
[Microsoft's deployment guidance](https://learn.microsoft.com/en-us/cpp/windows/redistributing-visual-cpp-files).

`scripts/fetch-search-resources.ps1` also obtains byte-identical copies by passive
extraction of Microsoft's 14.44.35211 x64 redistributable. The EXE is never run.
Its immutable URL and SHA-256 are recorded in Microsoft's
[WinGet manifest](https://github.com/microsoft/winget-pkgs/blob/master/manifests/m/Microsoft/VCRedist/2015%2B/x64/14.44.35211.0/Microsoft.VCRedist.2015%2B.x64.installer.yaml):
25,635,768 bytes, SHA-256
`cc0ff0eb1dc3f5188ae6300faef32bf5beeba4bdd6e8e445a9184072096b713b`.
For these exact bytes, the attached cabinet starts at offset 686,152 and has
length 24,939,223. Its Burn manifest maps `a12` to the x64 minimum-runtime
cabinet. Extracted DLLs must still match every committed runtime-file digest.

For a Windows package build, provide this cache layout through the build-only
`CONTEXT_RELAY_SEARCH_ASSETS` environment variable (default: Cargo target directory
plus `search-assets`):

```text
search-assets/
  bge-small-en-v1.5/  # five files in the adjacent BGE manifest
  runtime/           # eight files in this manifest
```

To create the default cache on Windows, run
`./scripts/fetch-search-resources.ps1` in PowerShell before `pnpm package:windows`.
The Windows candidate workflow runs this step automatically. A fresh independent
cache download and passive extraction were verified locally; the four C++ DLLs
match the original Visual Studio copies byte-for-byte.

Missing, wrong-size, or wrong-hash inputs stop packaging before any prior staged
search output changes. Only the explicit files in the Tauri resource map enter
the installer; unrelated cache files are excluded. All runtime selection and
asset verification must also happen in the production loader before native code
is loaded. Build-time staging alone is not installed-runtime qualification.
