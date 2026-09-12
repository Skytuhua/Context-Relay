"""Sign verified macOS runtime inputs and final app executables in dependency order."""
import hashlib
import json
from pathlib import Path
import platform
import plistlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile


def constraint_digest(image):
    def word(data, offset, endian):
        if offset < 0 or offset + 4 > len(data):
            raise ValueError("truncated signature")
        return struct.unpack_from(endian + "I", data, offset)[0]
    le = lambda offset: word(image, offset, "<")
    if len(image) > 256 * 1024 * 1024 or le(0) != 0xfeedfacf or le(4) != 0x0100000c or le(12) != 2:
        raise ValueError("expected thin arm64 executable")
    count, end = le(16), 32 + le(20)
    if not count or end > len(image) or count > (end - 32) // 8:
        raise ValueError("invalid load commands")
    offset, signature = 32, None
    for _ in range(count):
        if offset + 8 > end:
            raise ValueError("truncated load command")
        command, size = le(offset), le(offset + 4)
        if size < 8 or size % 8 or offset + size > end:
            raise ValueError("invalid load command")
        if command == 0x1d:
            if signature is not None or size != 16:
                raise ValueError("invalid signature command")
            start, length = le(offset + 8), le(offset + 12)
            if start < end or length > 16 * 1024 * 1024 or start + length > len(image):
                raise ValueError("invalid signature bounds")
            signature = image[start:start + length]
        offset += size
    if offset != end or signature is None:
        raise ValueError("missing signature")
    be = lambda offset: word(signature, offset, ">")
    length, count = be(4), be(8)
    if be(0) != 0xfade0cc0 or not 1 <= count <= 64 or not 12 + count * 8 <= length <= len(signature):
        raise ValueError("invalid signature table")
    entries, digest = [], None
    for index in range(count):
        slot, start = be(12 + index * 8), be(16 + index * 8)
        size = be(start + 4)
        if start < 12 + count * 8 or size < 8 or start + size > length:
            raise ValueError("invalid signature blob")
        if any(slot == prior or (start < b and start + size > a) for prior, a, b in entries):
            raise ValueError("overlapping signature blobs")
        entries.append((slot, start, start + size))
        if slot == 11:
            digest = hashlib.sha256(signature[start:start + size]).hexdigest()
    if digest is None:
        raise ValueError("missing library constraint")
    return digest


def run(args):
    result = subprocess.run(args, capture_output=True, timeout=120)
    if result.returncode:
        raise RuntimeError(f"{Path(args[0]).name} failed: {result.stderr.decode('utf-8', errors='replace')}")
    return result


def sign(path, identity, constraint=None, entitlements=None):
    args = ["/usr/bin/codesign", "--force", "--sign", identity]
    args += ["--timestamp=none"] if identity == "-" else ["--timestamp"]
    if constraint is not None:
        args += ["--options", "runtime", "--library-constraint", str(constraint)]
        if entitlements is not None:
            args += ["--entitlements", str(entitlements)]
    run(args + [str(path)])
    run(["/usr/bin/codesign", "--verify", "--strict", str(path)])


def prepare(runtime, metadata, identity):
    manifest = json.loads((Path(__file__).resolve().parent.parent / "crates/core/models/onnxruntime-osx-arm64-1.24.2/manifest.json").read_text())
    for artifact in manifest["artifacts"]:
        path = runtime / artifact["file"]
        if path.is_symlink() or not path.is_file():
            raise ValueError("runtime input must be a regular file")
        data = path.read_bytes()
        if len(data) != artifact["bytes"] or hashlib.sha256(data).hexdigest() != artifact["sha256"]:
            raise ValueError(f"upstream runtime input mismatch: {path.name}")
    library = runtime / "libonnxruntime.1.24.2.dylib"
    sign(library, identity)
    details = run(["/usr/bin/codesign", "-d", "--verbose=4", str(library)])
    match = re.search(rb"^CDHash=([0-9a-f]{40})$", details.stderr, re.MULTILINE)
    if not match:
        raise ValueError("missing signed runtime CDHash")
    metadata.parent.mkdir(parents=True, exist_ok=True)
    constraint = metadata.parent / "library.coderequirement"
    constraint.write_bytes(plistlib.dumps({"cdhash": bytes.fromhex(match[1].decode("ascii"))}))
    entitlements = None
    if identity == "-":
        # Internal CI candidate only; Developer ID keeps normal library validation.
        entitlements = metadata.parent / "candidate-entitlements.plist"
        entitlements.write_bytes(plistlib.dumps({"com.apple.security.cs.disable-library-validation": True}))
    with tempfile.TemporaryDirectory(prefix="context-relay-signing-") as temporary:
        source, seed = Path(temporary) / "seed.c", Path(temporary) / "seed"
        source.write_text("int main(void) { return 0; }", encoding="utf-8")
        run(["/usr/bin/clang", "-arch", "arm64", str(source), "-o", str(seed)])
        sign(seed, identity, constraint, entitlements)
        digest = constraint_digest(seed.read_bytes())
    data = library.read_bytes()
    value = {"identity": identity, "buildTrust": {
        "signedRuntimeSha256": hashlib.sha256(data).hexdigest(),
        "signedRuntimeBytes": len(data), "libraryConstraintSha256": digest,
    }}
    metadata.write_text(json.dumps(value), encoding="utf-8")


def finish(app, metadata, identity):
    value = json.loads(metadata.read_text(encoding="utf-8"))
    if value["identity"] != identity:
        raise ValueError("signing identity changed after runtime preparation")
    trust = value["buildTrust"]
    library = app / "Contents/Resources/search/runtime/libonnxruntime.1.24.2.dylib"
    def verify_runtime():
        data = library.read_bytes()
        if len(data) != trust["signedRuntimeBytes"] or hashlib.sha256(data).hexdigest() != trust["signedRuntimeSha256"]:
            raise ValueError("bundled runtime changed after build trust was compiled")
        run(["/usr/bin/codesign", "--verify", "--strict", str(library)])
    verify_runtime()
    constraint = metadata.parent / "library.coderequirement"
    entitlements = metadata.parent / "candidate-entitlements.plist" if identity == "-" else None
    info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
    names = ["context-relay-contextd", "context-relay-context-mcp", "context-relay-native-helper", "context-relay-sidecar-installer"]
    for name in names:
        executable = app / "Contents/MacOS" / name
        sign(executable, identity, constraint, entitlements)
        if constraint_digest(executable.read_bytes()) != trust["libraryConstraintSha256"]:
            raise ValueError(f"compiled constraint differs from signed executable: {name}")
    # Sign the outer app last. Never recursively re-sign the already pinned dylib.
    sign(app, identity, constraint, entitlements)
    if constraint_digest((app / "Contents/MacOS" / info["CFBundleExecutable"]).read_bytes()) != trust["libraryConstraintSha256"]:
        raise ValueError("outer app constraint mismatch")
    verify_runtime()
    result = run([str(app / "Contents/MacOS/context-relay-contextd"), "--verify-packaged-search"])
    if result.stdout != b"verified packaged search\n":
        raise ValueError("packaged daemon did not confirm real inference")
    with tempfile.TemporaryDirectory(prefix="context-relay-signed-tamper-") as temporary:
        damaged = Path(temporary) / app.name
        shutil.copytree(app, damaged)
        control = run([str(damaged / "Contents/MacOS/context-relay-contextd"), "--verify-packaged-search"])
        if control.stdout != b"verified packaged search\n":
            raise ValueError("copied packaged daemon did not confirm real inference")
        print("Verified copied app inference before runtime tampering", flush=True)
        runtime = damaged / "Contents/Resources/search/runtime/libonnxruntime.1.24.2.dylib"
        data = bytearray(runtime.read_bytes())
        data[-1] ^= 1
        runtime.write_bytes(data)
        rejected = subprocess.run([str(damaged / "Contents/MacOS/context-relay-contextd"), "--verify-packaged-search"], capture_output=True, timeout=120)
        if rejected.returncode == 0 or rejected.stdout:
            raise ValueError("packaged daemon accepted a changed runtime")
    print("Verified assembled macOS app signing constraints and real packaged inference", flush=True)


def main():
    if platform.system() != "Darwin" or platform.machine() != "arm64" or int(platform.mac_ver()[0].split(".")[0]) < 14:
        raise RuntimeError("requires native arm64 macOS 14+")
    if len(sys.argv) != 5 or sys.argv[1] not in ("prepare", "finish"):
        raise ValueError("expected prepare|finish runtime-or-app metadata signing-identity")
    mode, source, metadata, identity = sys.argv[1:]
    if identity != "-" and not identity.startswith("Developer ID Application:"):
        raise ValueError("choose explicit internal candidate '-' or Developer ID Application identity")
    (prepare if mode == "prepare" else finish)(Path(source).resolve(strict=True), Path(metadata).resolve(), identity)


if __name__ == "__main__":
    main()
