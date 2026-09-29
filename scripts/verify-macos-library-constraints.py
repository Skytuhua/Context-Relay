"""Native prerequisite for packaged ORT loading; never touches installed apps.

Run on macOS 14+ arm64. This tests OS enforcement with disposable ad-hoc code,
not Developer ID signing, notarization, or the production ONNX loader.
"""
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
from macos_signing import constraint_digest


def run(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, timeout=60, **kwargs)


def main():
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise RuntimeError("requires native arm64 macOS")
    if int(platform.mac_ver()[0].split(".")[0]) < 14:
        raise RuntimeError("library constraints require macOS 14+")
    with tempfile.TemporaryDirectory(prefix="context-relay-library-constraint-") as temporary:
        root = Path(temporary)
        library = root / "library.c"
        library.write_text(r'''
#include <stdio.h>
#include <stdlib.h>
__attribute__((constructor)) static void initialized(void) {
    const char *path = getenv("CONTEXT_RELAY_TEST_MARKER");
    if (!path) abort();
    FILE *output = fopen(path, "wb");
    if (!output) abort();
    fputs(MARKER, output);
    fclose(output);
}
''', encoding="utf-8")
        for name in ("good", "evil"):
            output = root / f"{name}.dylib"
            run(["/usr/bin/clang", "-arch", "arm64", "-dynamiclib", f'-DMARKER="{name}"', str(library), "-o", str(output)])
            # Same identifier and signing mode; the cdhash must distinguish them.
            run(["/usr/bin/codesign", "--force", "--sign", "-", "--identifier", "com.skytuhua.constraint.fixture", str(output)])
        details = run(["/usr/bin/codesign", "-d", "--verbose=4", str(root / "good.dylib")])
        match = re.search(rb"^CDHash=([0-9a-f]{40})$", details.stderr, re.MULTILINE)
        if not match:
            raise RuntimeError("missing canonical good-library CDHash")
        constraint = root / "library.coderequirement"
        constraint.write_bytes(plistlib.dumps({"cdhash": bytes.fromhex(match[1].decode("ascii"))}))
        entitlements = root / "entitlements.plist"
        # Isolate constraint enforcement from same-Team library validation.
        # This exception belongs only to the disposable test executables.
        entitlements.write_bytes(plistlib.dumps({"com.apple.security.cs.disable-library-validation": True}))
        source = root / "loader.c"
        source.write_text(r'''
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 2 && argc != 3) return 40;
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) return 41;
    // Hold the original inode while atomically substituting the load pathname.
    if (argc == 3 && rename(argv[2], argv[1]) != 0) return 42;
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL | RTLD_FIRST);
    close(fd);
    if (!library) { fprintf(stderr, "%s\n", dlerror()); return 20; }
    dlclose(library);
    return 0;
}
''', encoding="utf-8")
        for name in ("control", "constrained"):
            output = root / name
            run(["/usr/bin/clang", "-arch", "arm64", str(source), "-o", str(output)])
            args = ["/usr/bin/codesign", "--force", "--sign", "-", "--options", "runtime", "--entitlements", str(entitlements)]
            if name == "constrained":
                args += ["--library-constraint", str(constraint)]
            run(args + [str(output)])
            run(["/usr/bin/codesign", "--verify", "--strict", str(output)])
        marker = root / "marker"
        env = {**os.environ, "CONTEXT_RELAY_TEST_MARKER": str(marker)}
        for loader, target, expected_code, expected_marker in (
            ("control", "evil", 0, b"evil"),
            ("control", "replacement", 0, b"evil"),
            ("constrained", "good", 0, b"good"),
            ("constrained", "evil", 20, None),
            ("constrained", "replacement", 20, None),
        ):
            marker.unlink(missing_ok=True)
            if target == "replacement":
                shutil.copyfile(root / "good.dylib", root / "candidate.dylib")
                shutil.copyfile(root / "evil.dylib", root / "replacement.dylib")
                args = [str(root / loader), str(root / "candidate.dylib"), str(root / "replacement.dylib")]
            else:
                args = [str(root / loader), str(root / f"{target}.dylib")]
            result = subprocess.run(args, env=env, capture_output=True, timeout=30)
            actual_marker = marker.read_bytes() if marker.exists() else None
            if result.returncode != expected_code or actual_marker != expected_marker:
                raise RuntimeError(f"{loader}/{target}: exit={result.returncode}, marker={actual_marker!r}, stderr={result.stderr!r}")
            print(f"PASS {loader}/{target}: exit={result.returncode}, marker={actual_marker!r}", flush=True)

        if len(sys.argv) != 2:
            raise RuntimeError("provide the compiled Rust qualification executable")
        probe = Path(sys.argv[1]).resolve(strict=True)
        for name in ("rust-control", "rust-constrained"):
            output = root / name
            shutil.copyfile(probe, output)
            output.chmod(0o755)
            args = ["/usr/bin/codesign", "--force", "--sign", "-", "--options", "runtime", "--entitlements", str(entitlements)]
            if name == "rust-constrained":
                args += ["--library-constraint", str(constraint)]
            run(args + [str(output)])
            run(["/usr/bin/codesign", "--verify", "--strict", str(output)])
        expected = constraint_digest((root / "rust-constrained").read_bytes())
        for name, digest, code in (("rust-constrained", expected, 0),
                                  ("rust-control", expected, 20),
                                  ("rust-constrained", "00" * 32, 20)):
            result = subprocess.run([str(root / name), digest], capture_output=True, timeout=30)
            if result.returncode != code or result.stdout != (b"verified running constraint\n" if code == 0 else b""):
                raise RuntimeError(f"{name}: exit={result.returncode}, stdout={result.stdout!r}, stderr={result.stderr!r}")
            print(f"PASS {name}/digest-{digest[:8]}: exit={code}", flush=True)
        # Positive control for the identical rename path, followed by the attack.
        for name, code in (("rust-constrained", 0), ("rust-control", 20)):
            running = root / "running"
            replacement = root / "replacement"
            shutil.copyfile(root / name, running)
            running.chmod(0o755)
            shutil.copyfile(root / "rust-constrained", replacement)
            replacement.chmod(0o755)
            result = subprocess.run([str(running), expected, str(replacement)], capture_output=True, timeout=30)
            if result.returncode != code or result.stdout != (b"verified running constraint\n" if code == 0 else b""):
                raise RuntimeError(f"{name}/path-replacement: exit={result.returncode}, stdout={result.stdout!r}, stderr={result.stderr!r}")
            print(f"PASS {name}/path-replacement: exit={code}", flush=True)


if __name__ == "__main__":
    main()
