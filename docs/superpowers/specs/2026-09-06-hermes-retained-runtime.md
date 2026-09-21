# Retained Windows Hermes runtime

Setup and recovery must reuse the exact approved Python runtime after restart,
even when the installed venv or editable checkout changes. A temporary capture
cannot supply that guarantee. This extends the runtime-capture design with durable
local retention and explicit reopening; it does not itself authorize a command.

Use the existing random temporary holder as the eventual storage key, beneath a
caller-selected local runtime store. Its protected private container holds a
private payload directory and a manifest beside it. The manifest is outside the
payload inventory so its hash is not recursive. Both private directories retain
their Windows handles and ancestor topology while open.

Retention consumes a successful capture. Synchronize all payload files and
directories, verify their exact inventory against the captured manifest, create
the manifest without overwriting anything, synchronize it and its directory
ancestry, then relinquish automatic temporary cleanup. Any error leaves the
capture unretained and returns no reference. Publication does not rename over or
replace an existing runtime. Crash leftovers without a completed trusted reference
do not acquire approval and must never be discovered as executable authority.

A versioned RetainedRuntimeReference contains one bounded storage-key component
and the expected manifest identity. It contains no arbitrary filesystem root.
Reopen takes a local store root and this reference from trusted persisted state,
checks the private directories, reads a bounded manifest, validates its schema,
projection, limits and canonical identity, then verifies the entire payload.
It never inspects or executes the source installation. Wrong/missing manifests,
changed/deleted/added files, symlinks/junctions, aliases and invalid keys fail.

The manifest limit is 48 MiB, with the capture's existing 32,768 entries, 32-level
tree depth, 64 MiB per file and 1 GiB total limits retained. Runtime files stay
private local files. The reference and manifest are identity, not launch permission;
sealed transaction approval must bind the reference before management commands
consume it. Durable promotion must complete before that approval is stored.

Reopen checks every descendant's security descriptor, including empty directories
and the manifest. The sole ordinary full-access ACE must name the current user;
legitimate inheritance flags are allowed. Protected roots remain user-owned.
Descendants may be owned by that user or the fixed privileged Administrators group,
as Windows assigns the latter during elevated creation. This fixed allowance also
works after the same user restarts without elevation; it does not accept arbitrary
token-owner groups. Administrative ownership carries the ability to change access,
so this is local file privacy, not isolation from Windows administrators.

Implement Windows retention first, matching the installed Python layout. Existing
native harness behavior and other platforms' temporary capture tests stay intact.
No native UI, ordinary configuration, credentials or installed daemon is touched.
No Full support promotion is implied. Tests use synthetic runtimes and directories.

Qualification must include fresh-handle reopen after dropping the original owner,
source removal, serialized reference round trip, altered manifest/payload, missing
publication, private-directory tampering and failure before manifest publication.
Filesystem flush success demonstrates the requested durability barrier; it is not
a simulation of storage hardware failure. Contained management commands and actual
setup/restart/Undo qualification remain part of the full connection objective.
