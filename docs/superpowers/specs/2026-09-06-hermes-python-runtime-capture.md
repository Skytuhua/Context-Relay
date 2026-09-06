# Hermes Python runtime capture

This implements the capture requirement of the Python installation design. The end
state remains an actual qualified harness connection with sealed setup and recovery.

Capture a deterministic local execution projection into a private temporary tree.
Use the real CPython base image and runtime library layout, the complete selected
site-packages tree, and a projected Hermes source checkout. Never copy the original
venv redirector as the execution entry point or use live installation import paths.

The editable source projection includes declared standalone modules, package roots
with all package data, declared data-file directories, and the shipped skills and
optional-skills trees identified by MANIFEST.in. Validate the installed editable
finder's literal mapping and namespaces against this projection without running the
finder or build backend. Accept only the reviewed generated finder template. Preserve
relative checkout layout for Hermes resource lookups. Exclude the checkout's .env,
.envrc, .git, venv, node_modules and unrelated files; reject declared required roots
that intersect those exclusions. Do not copy bytecode caches into the source-first
projection. Bytecode-only modules are unsupported by this projection policy.

Copy with bounded no-follow reads and verify source and destination inventories.
Limit capture to 32,768 entries, depth 32, 64 MiB per file and 1 GiB total. Bind
relative paths, file lengths, SHA256 bytes, directories, source roots, metadata and
the generated startup policy into the manifest. Rechecking a retained tree detects
added, deleted, changed or aliased entries, not just changed files already listed.
The snapshot remains valid after the mutable source installation changes; launch
must use the retained bytes. Keep metadata identity separate from executable hash.

This temporary capture is deleted when its owner is dropped. Verification establishes
readable bytes, not crash durability. Durable transaction promotion must flush file
contents and publish directories and the manifest durably before sealing approval;
retention/reopen is part of that later integration.

The fixed startup projection uses Windows ._pth without import site and Python
-I -S -B. It lists only staged stdlib, extensions, packages, source and recognized
relative .pth data paths. Do not run .pth lines. Replace the recognized pywin32 DLL
bootstrap with a retained os.add_dll_directory handle for the staged DLL directory.
Reject unknown executable .pth forms. The controlled bootstrap and path policy are
part of runtime identity. They do not provide a filesystem or network sandbox.

Capture never starts a harness command. Qualification may run a fixed CPython path
probe from the retained copy in a disposable environment. Actual Hermes management
commands still require execution containment, sealed runtime approval, and full
connection/restart/Undo qualification before enabling Full. Normal installed
configuration, credentials and native Computer Use remain untouched.
