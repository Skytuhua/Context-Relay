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

The macOS native loader, application resource map/build command, signing and
installed acceptance are still required. These hashes describe the upstream
input bytes; if signing changes the dylib, release verification must bind the
resulting signed bytes rather than reuse these input hashes. No packaged macOS
search capability is claimed by this manifest.
