# Retained Hermes Runtime Execution Plan

Continue the approved retained-runtime design into real Windows management checks.
The immediate prerequisite is an owned lease over the approved runtime bytes.
Normal harness configuration, credentials, installed service and native UI remain
untouched. Harness support stays ImportOnly until actual connection qualification.

## Runtime lease

Implemented and reviewed; evidence: 2026-09-06-hermes-runtime-lease-verification.md.

- Add opaque Windows native read leases. Hash the same read handle that the lease
  retains, excluding write/delete sharing. Retain no-reparse ancestor handles too.
- Consume RetainedRuntime into LockedRuntime; lock the manifest, every directory
  (including empty ones) and every inventoried file. Compare hashes and exact
  inventory while all leases remain live. Partial failure drops acquired leases.
- Expose only read-only runtime metadata and verification. No clone or raw handles.
  The eventual process guard must own the complete LockedRuntime.
- Test write/delete/rename denial, existing writer conflicts, changed bytes before
  acquisition, late acquisition failure releasing earlier leases, and successful
  release. Explicitly test detection of newly inserted filenames.

These leases freeze existing file contents and keep their ancestry held. They do
not freeze directory namespaces or prevent an inserted module from being imported.
Before/after inventory detects additions; it is not an OS sandbox or protection
from privileged actors changing access controls.

## Process runner and integration

The Windows process runner is implemented and independently reviewed; synthetic
verification is recorded in 2026-09-06-hermes-management-runner-verification.md.
Actual retained Version/ConfigCheck commands passed with an isolated profile and
unchanged runtime inventory. Production integration and connection qualification
remain open.

- Own an unnamed kill-on-close Windows job; create the child suspended, assign and
  verify membership before resuming. Disable breakaway and bound process count.
- Explicit executable, fixed bootstrap/closed arguments, isolated profile, cleared
  environment, trusted Windows system paths and restricted handle inheritance.
- Bound stdout/stderr, time and cancellation without unbounded reader-thread joins.
  Use overlapped pipe I/O for a hard deadline; synchronous PeekNamedPipe does not
  provide an unconditional nonblocking guarantee in a multithreaded process.
- Terminate remaining descendants and query ActiveProcesses == 0 before releasing
  runtime leases. A cleanup failure must retain job plus runtime ownership until
  emptiness is proven; an ordinary error must not silently release the leases.
- Synthetic regressions cover orphaned pipes, children with closed pipes, floods,
  cancellation, launch failure, cleanup failure, and full-tree lock lifetime.
- Qualify real retained Hermes version/config checks with a synthetic profile.
  Installed source currently shows --version uses update checking on Windows;
  account for subprocess/network behavior, do not assume it is metadata-only.
  Its no-update fast path is Termux-only. Source inspection also shows startup
  repair uses PROJECT_ROOT/.update-incomplete and launcher cleanup uses
  PROJECT_ROOT/venv/Scripts; those must remain absent from the projected runtime.
- Consume the exact approved reference in the adapter and daemon setup/recovery
  paths before removing their temporary unconsumed-binding guards. Qualify actual
  setup, restart and Undo before enabling Full and producing another installer.

## Verification

The owned core management facade is implemented and independently reviewed. It
derives the executable root from LockedRuntime, validates bounded YAML before
creating a private profile, and transfers both owners to the process runner.
Runtime inventory is verified before and after execution; nonzero exits and
stderr fail. Hermes's version banner is parsed separately from Python/SDK versions.
Evidence: 2026-09-07-hermes-management-facade-verification.md.

Run focused Windows filesystem/runtime regressions and affected Rust Clippy/fmt
checks. Refresh graphify after code changes. Request review of ownership and
failure paths before recording the slice as verified.

Windows process-lifetime references:
[job termination](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-terminatejobobject)
and [job accounting](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_accounting_information).
Termination requests apply to the job hierarchy; inspect the active-process count
and finish outstanding I/O before releasing the owned runtime.
