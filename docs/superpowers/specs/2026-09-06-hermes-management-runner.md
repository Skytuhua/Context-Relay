# Windows retained Hermes management runner

Hermes's captured Python runtime needs real version and configuration checks before
setup can consume its approved identity. Run only the fixed retained interpreter,
bootstrap and Version/ConfigCheck arguments. This runner is process lifetime control,
not an OS sandbox or authority to use an unapproved runtime.

The caller supplies an owned runtime lease and any profile/temporary-directory
owners needed during execution. The native layer erases this owner only while it
holds the process state, returning the exact original type on success. It does not
clone leases or expose process/file handles. Core integration must bind the root
to LockedRuntime and preserve profile ownership, then verify inventory again.

Launch uses an explicit application, argument quoting, CWD and environment block.
HOME, USERPROFILE, APPDATA, LOCALAPPDATA, HERMES_HOME, TEMP and TMP point to the
caller-prepared isolated home. SystemRoot comes from the Windows API and PATH is
its System32 directory. Normal environment variables and credentials are absent.
The three standard handles are the only inherited handles. The child starts
suspended, joins an unnamed kill-on-close job, has membership verified and resumes
exactly once. The job limits active processes to 16 and permits no breakaway.

Independent overlapped stdout/stderr reads use stable boxed buffers and events.
Each stream has a 256 KiB cumulative cap. Polling alternates streams and checks
cancellation and a 15-second runtime limit. No pipe-reader thread is joined.
Successful zero-byte reads remain readable; only broken-pipe completion means EOF.
See [Windows ReadFile pipe semantics](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile#pipes).

After normal parent exit, terminate any descendants and finish draining output.
On failure, terminate the job and cancel outstanding reads. Allow three seconds
for cleanup; require ActiveProcesses == 0, direct-parent exit and both pipe reads
settled before releasing runtime ownership or kernel-referenced buffers. Report
output errors discovered during the final drain as failures.

An owned static cleanup slot is installed before CreateProcess. It serializes
checks and holds every process/job/pipe handle, boxed buffer and caller owner.
Cleanup timeout or uncertain queries leave that slot intact. A subsequent check
must reap it first or refuse another launch. A panic unwinds the mutex guard but
leaves the state in the slot; the next call recovers the poisoned mutex and reaps
before clearing poison. This bounds retained cleanup state to one command and
avoids background-thread creation or early unlocking on exceptional paths.

Synthetic tests cover both output streams, flooding, timeout, cancellation,
descendants retaining or closing their pipes, assignment/resume failures, final-
drain errors, real file-lock retention through uncertain cleanup, blocked reentry,
successful reap, unwind recovery and zero-byte read completion. The opt-in real
installation test captures/retains/reopens/locks once, runs both closed commands
with a private synthetic home, and checks inventory after each. Passing these
checks does not qualify actual setup, persisted recovery, Undo or Full support.
