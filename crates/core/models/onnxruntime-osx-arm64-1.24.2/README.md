# macOS arm64 ONNX Runtime inputs

The manifest pins unmodified input files from Microsoft's
[ONNX Runtime 1.24.2 arm64 archive](https://github.com/microsoft/onnxruntime/releases/download/v1.24.2/onnxruntime-osx-arm64-1.24.2.tgz).
The release API reports 31,604,221 bytes and SHA-256
`0af4fa503e8ea285245b47ee42d0a7461b8156a81270857da0c1d4ecf858abde`;
the downloaded archive matched both on 2026-09-09.

Select only these regular members under `onnxruntime-osx-arm64-1.24.2/`,
verify their bytes against `manifest.json`, and stage them using their basenames:

- `lib/libonnxruntime.1.24.2.dylib`
- `LICENSE`
- `ThirdPartyNotices.txt`

The dylib is a 64-bit arm64 Mach-O library. Its recorded dependencies point to
system frameworks and `/usr/lib`; its install name is
`@rpath/libonnxruntime.1.24.2.dylib` and it records `@loader_path` as an rpath.
This is static inspection of the pinned input, not a macOS execution or code-signing check.

`scripts/search-resources.mjs` accepts target `aarch64-apple-darwin` to stage
these three files alongside the five shared BGE model/tokenizer files. It verifies
the complete set before changing existing output and copies the bytes it verified.
An unsupported target or a Windows runtime directory is rejected.

To acquire and stage these inputs with Node, curl and tar installed, run:

```sh
node scripts/fetch-macos-search-resources.mjs target/macos-search-resources
```

The command downloads the five pinned model files and the pinned Microsoft
archive over HTTPS. It extracts only the three required members to bounded
memory, verifies their size and SHA-256, and stages `model/` and `runtime/`
only after the complete set validates. Temporary downloads are removed on
success or failure. It does not install or execute the runtime.

On an arm64 macOS 14+ host, select a signing identity explicitly:

```sh
# Internal CI candidate, not distribution signing:
CONTEXT_RELAY_MACOS_SIGNING_IDENTITY=- pnpm package:macos
# With the enrolled identity already available in the keychain:
CONTEXT_RELAY_MACOS_SIGNING_IDENTITY='Developer ID Application: Your Name (TEAMID)' pnpm package:macos
```

The command reads `target/macos-search-resources` by default; set
`CONTEXT_RELAY_SEARCH_ASSETS` for another acquisition directory. It verifies
upstream inputs, signs the staged dylib once, and derives both its final byte
pins and a CDHash-only library constraint. It compiles those pins into the
consumers, builds all four companions, and assembles Tauri with `--no-sign`.
It then signs the final companions and outer app, checks the final runtime
bytes and executable constraints, and invokes `--verify-packaged-search` on
the bundled daemon. This explicit mode runs real embedding inference without
starting a vault or IPC service. A disposable copied app with a changed runtime
must be rejected. The CI identity `-` uses an internal library-validation
exception; Developer ID mode keeps normal validation and never falls back.

The complete native signing/inference run remains pending. Production resource
discovery, Developer ID enrollment/notarization and installed acceptance remain
required. These manifest hashes describe upstream input bytes; the signing
pipeline separately binds the resulting signed bytes. No distributed release
or installed search acceptance is claimed by this manifest.
