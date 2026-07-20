# Deterministic corresponding-source manifest

Build the Semgrep 1.170.0 source bundle from exact Git revisions and the
checksum-addressed archive cache with:

```text
node scripts/semgrep-source-bundle.mjs --build SOURCE_LOCK SEMGREP_GIT_DIR OPAM_REPOSITORY_GIT_DIR PINS_ROOT ARCHIVE_CACHE_ROOT OUTPUT.tar SUPPORT_ROOT
```

`PINS_ROOT` contains one recursively initialized Git checkout per exact pin
revision. The fetch command populates `ARCHIVE_CACHE_ROOT/<algorithm>/<digest>`
and verifies every declared strong checksum before atomically persisting it:

```text
node scripts/semgrep-source-bundle.mjs --fetch SOURCE_LOCK ARCHIVE_CACHE_ROOT
```

The output is an uncompressed USTAR archive containing regular files only.
Paths are NFC UTF-8, use `/` separators, and are sorted by unsigned UTF-8
bytes. Case-fold collisions, traversal, links in inputs, devices, duplicate
paths, and unrecorded objects are rejected. Git symlinks are represented in
`SYMLINKS.v1.json` and may be restored only after verification. Modes are
normalized to 0644 or 0755; uid, gid, and mtime are zero; reserved header fields
and both trailing zero blocks are canonical.

Opam archive mirrors address an archive by its first declared checksum. The
bundle stores each archive once at a verified canonical strong-checksum path
and records every other declared checksum address in `SYMLINKS.v1.json`.
`--materialize-links` restores those cache addresses as hard links, including
MD5-first records, without duplicating archive bytes. SHA-512-only archives
also have 128-hex filenames that cannot fit USTAR's 100-byte name field, so
their canonical bytes are stored as two 64-hex path components and the same
command restores opam's official `sha512/<first-two>/<full-digest>` hard link.
Every cache name therefore addresses the same verified bytes. Source paths
that cannot fit any USTAR name/prefix split are stored below
`LONG_PATHS/<sha256-of-original-path>`. Canonical `LONG_PATHS.v1.json`
maps them back, and the same materialization command restores the original
path with a hard link before restoring Git symlinks.

`MANIFEST.sha256` covers every payload member except itself and `MODES.v1`.
Each line is `<lowercase SHA-256><two spaces><relative path><LF>`.
`MODES.v1` records `path<TAB>0|1<LF>`, where `1` means executable.
`metadata/git-repositories.v1.json` records every recursively collected Git
revision, tree, and gitlink. Verify the complete archive before extraction:

```text
node scripts/semgrep-source-bundle.mjs --verify SOURCE_LOCK OUTPUT.tar
```

Generate two archives independently and require identical size and SHA-256.
The source inventory is complete enough to assemble this bundle, but
`completeCorrespondingSource` and both distribution targets remain disabled
until two native builds, runtime-closure inventories, and target sandbox smoke
checks have been captured.
