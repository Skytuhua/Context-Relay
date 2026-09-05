# Codex managed MCP configuration generation

## Status

Implementation direction for the remaining Windows connection and rollback
failure. This is not release qualification. Codex 0.144.6 remains ImportOnly
until this path and native hook trust/execution pass real-install acceptance.

2026-09-06 qualification update: the pinned Windows 0.144.6 CLI fails to load
configuration inside the tested zero-capability AppContainer because it cannot
canonicalize the private CODEX_HOME. Directory access itself succeeds. The
unsuccessful prototype was removed from release source; see the
[observed compatibility result](../../verification/codex-staged-generation-2026-09-06.md).
A compatible pinned runtime or qualified equivalent restriction mechanism is
still required. The host-side validated merge exists; this does not make the
full staged setup available.

## Reproduced failure

The existing full setup writes native memory settings into global config.toml,
then invokes the official Codex MCP CLI against that same file. The native
receipt records the intermediate file, while Codex replaces it with a file
containing the MCP declaration. The inverse transaction expects the
intermediate fingerprint and object provenance, so it cannot safely restore
the original file. Removing the MCP declaration can restore identical bytes,
but that alone does not establish the approved native object identity or
metadata.

An isolated Windows Codex 0.144.6 add/get/remove run reproduced the byte
mismatch. Existing MatrixCli fixtures change semantic declarations in memory;
they do not model this file replacement. Native file comparisons and recovery
provenance must remain intact.

## Decision

Keep official CLI authorship of the managed declaration and make the native
transaction the sole writer of the live configuration. Generate only the
canonical global context-relay MCP declaration inside an empty, restricted
stage. Import the validated CLI-authored TOML item into the captured live
document alongside the reviewed memory-setting edits. Seal one complete native
mutation using the original live metadata. Apply and rollback use the existing
native transaction and exact before-image machinery.

This narrowly amends the preview mechanics and live CLI subphase described in
[the transactional MCP design](2026-07-31-transactional-mcp-adapter-install-design.md):
Codex managed-bridge preview may invoke the pinned official MCP CLI only inside
the restricted stage. It may not mutate the live harness. This path has no
live CLI operations or CLI WAL; its native mutation and generation evidence
must be approval-bound. Claude Code's live CLI path, Hermes YAML handling,
plugins, packages and arbitrary CLI operations are outside this amendment.

## Input and execution boundary

- Capture the live config once through OsNativeFileSystem. Do not copy that
  whole mixed document or any home, auth, plugin, session, history, approval or
  memory files into staging.
- Stage input contains only the canonical managed bridge command and the two
  fixed arguments `--harness`, `codex`. No environment overrides, credentials,
  URLs, projects, working-directory fields or arbitrary server names are
  permitted. The command path is inert configuration data, never launched.
- Use a dedicated closed operation and an OS-enforced restricted runner. The
  current CodexCommandRunner inherits the daemon environment and is not this
  runner. CODEX_HOME reassignment alone is insufficient.
- Start from an empty stage with controlled HOME, USERPROFILE, application,
  configuration, cache, temporary and CODEX_HOME roots. Strip inherited
  credentials, proxies, provider variables and real-home discovery paths.
- Bind the exact native Codex executable/version/digest and validate its
  copied runtime immediately before launch. No wrapper, mutable alias,
  unverified executable or unsandboxed fallback is accepted.
- Deny real-home/project access and networking; bound process lifetime,
  children, stdout, stderr, stage file count and bytes. Preserve existing
  sandbox attestation, private-stage ownership and durable cleanup rules.

## Output and approval boundary

The official CLI must produce exactly the canonical managed declaration on
readback. Reject unknown settings, additional servers, executable stage output,
links/reparse points, unexpected files and malformed or excessive output. Any
version-required incidental files need an explicit narrow allowlist and may
not be imported into the live document.

Merge only the validated CLI-authored managed item into the original parsed
TOML. Retain comments and unrelated values, including secret-bearing sections,
in the host's native snapshot. Combine global memory booleans in that same
mutation. Active project memory overrides remain their own reviewed native
mutations. Preserve original live metadata; stage ACLs and timestamps must
never become the intended live metadata.

Record generation evidence explicitly: operation/template version, sandbox
policy version, generator identity and digest, canonical input digest,
accepted output digest and structural merge policy. Add a new approval/sealed
plan version if existing fields cannot represent these bindings without
misstating their meaning. Recompute approval on open/apply; tampering with any
binding invalidates the plan. Do not retain fake live cli_operations to make
an existing validator pass.

The adapter's imported semantic declaration, generated item, reviewed native
document and final live configuration must agree. Apply rejects executable,
source-home, project, policy, input or target drift. Reapply is idempotent;
rollback restores exact original bytes/metadata through the ordinary native
before-image path. No general fingerprint or object-token rebasing is added.

## Qualification required before enabling Full

1. Reproduce the live shared-file failure with a file-writing CLI fixture,
   including replacement identity and a concurrent unrelated edit.
2. Prove typed stage inputs reject extra argv, environment, server names,
   invalid/ambiguous native paths and oversized payloads.
3. Execute the real pinned Codex CLI inside the real Windows sandbox. Prove
   real-home canary denial, loopback denial, environment stripping, inert
   hook/MCP commands, child termination, output limits and crash cleanup.
   An unsandboxed synthetic CODEX_HOME run proves only CLI output behavior.
4. Generate from empty stages for paths with spaces, Unicode and quoting
   characters; validate exact JSON readback and the accepted TOML item.
5. Verify merge preservation using mixed config canaries, unrelated MCP
   servers, comments, trusted projects and native memory overrides. No mixed
   config or credential canary may appear in stage files or logs.
6. Exercise preview, approval invalidation, actual native apply, restart,
   reapply, inverse rollback and crashes at each durable file boundary.
   Confirm a concurrent foreign replacement produces Conflict without
   adopting it or overwriting it.
7. Qualify the corresponding macOS runner and preserve version-qualified
   behavior; absence of a required sandbox returns unavailable.
8. Complete native hook trust, hook execution, MCP memory/task round trips and
   the installed-app user workflow before changing capability allowlists or
   declaring the release ready.
