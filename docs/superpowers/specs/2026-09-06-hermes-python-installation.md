# Hermes Python installation support

The Windows Hermes installer creates a Python console launcher. Treating every PE
image as an unsupported standalone executable makes the installed harness unusable.
Support will use a separate local Python runtime identity; a launcher hash cannot
stand for its interpreter, packages, editable source, or startup policy.

This extends the native-only design in the July 29 Hermes spec. Local snapshots
identify the user's installation, as native executable snapshots already do. They
do not authenticate a publisher or prove compatibility. The existing Full version
matrix remains unchanged until actual runtime qualification passes.

## First deliverable: passive installation discovery

Inspect a Windows Scripts/hermes.exe installation without running Python, importing
modules, processing .pth code, or reading the selected profile's credentials. Read
bounded pyvenv.cfg, distribution METADATA, entry_points.txt and optional direct_url.json.
Require a single consistent Hermes distribution and its documented console entry.
Resolve the venv interpreter, CPython base, package directory and editable source
when present. Reject links/reparse points, ambiguous metadata and external URLs.
The one supported alias is uv's same-parent minor-version CPython junction: read
its link target first, reject remote/device paths, and inspect its real versioned
directory. An editable checkout may contain its venv, as the Windows installer does.
Metadata reads use no-follow handles, bounds, and post-read topology/file identity
checks. Path validation rejects UNC/device namespaces before filesystem access.
The reported version is installed metadata, not an executed or qualified version.

Return the observed metadata hashes and resolved roots for subsequent capture. This
is explicitly an installation description, not a complete runtime closure or launch
authority. Discovery remains ImportOnly and must never make a child process runnable.

## Remaining execution contract

Capture complete bounded runtime/package/source directory inventories, including
native extensions and package data. Parse recognized editable mappings statically.
Retain immutable approved bytes; do not substitute a later mutable installation.
Use a typed, versioned runtime binding in sealed preview/apply/recovery, separate
from the existing native executable hash and shipped sidecar provenance.

A fixed bootstrap must suppress ambient registry/environment/user-site/project
imports and arbitrary .pth startup. Reattest the retained closure before each launch;
bound output and descendants. A snapshot is not a filesystem/network sandbox.
Qualification must exercise the actual staged runtime, config validation, bridge
round trip, restart and Undo before enabling Full for that runtime/version.

The user's modified Hermes 0.17.0 is a qualification target, not an installation
to overwrite. Normal harness configuration and native Computer Use remain paused.
