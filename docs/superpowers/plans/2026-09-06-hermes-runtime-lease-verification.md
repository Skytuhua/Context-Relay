# Retained Hermes runtime lease verification

The execution prerequisite now consumes a retained Windows runtime into an owned
LockedRuntime. An opaque NativeReadLease hashes through the same read handle it
retains, excludes write/delete sharing and keeps relative ancestors open. The
runtime owner holds the manifest, all directories (including empty ones), every
manifest file, and both existing private root pins. Final verification runs while
all leases are live. Acquisition failure releases earlier leases.

New core tests initially failed to compile because RetainedRuntime::lock did not
exist. After implementation, all three pass. They exercise actual Windows write,
delete and rename failures, compatible reads, an existing writer, release after
failure/drop, changed bytes since retention and inserted-name detection. A new
native test verifies that a file lease still prevents replacement and ancestor
renaming after the original directory/creation pins have been dropped.

Final focused checks on Windows:

- cargo test -p context-relay-core --lib hermes::python_runtime --features
  test-support: 23 passed, 1 opt-in installed capture probe ignored.
- cargo test -p context-relay-native-runner --lib native_fs::windows:: --
  --test-threads=1: 33 passed, including both Windows test modules and the new
  native lease regression. The initial narrower ::tests filter selected only
  three older tests and was corrected; it is not the claimed native coverage.
- cargo clippy -p context-relay-core -p context-relay-native-runner --all-targets
  --features context-relay-core/test-support -- -D warnings: passed in 34 seconds.
- cargo fmt --all -- --check and git diff --check: passed.
- Independent reviewer approved ownership, sharing and failure cleanup with no
  actionable findings.

Logs are in .codex/context-relay-closeout-2026-09-05/hermes-runtime-lease-*.log.
The existing OpenSSL missing-PDB debug linker warning remains; tests exited zero.

These checks do not prove process-tree containment or a working harness connection.
There is no new production command caller, support promotion, installed-config
write, local EXE build or native UI test. New filenames can still be created while
existing files are held. Inventory checks detect such additions but do not prevent
their use by a process; this remains outside an OS sandbox claim. The upcoming
process guard must own LockedRuntime through proven descendant termination,
including exceptional cleanup paths.
