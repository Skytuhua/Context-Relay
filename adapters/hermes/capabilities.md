# Hermes adapter capabilities

| Surface | Import | Apply | Gateway rule | Secret treatment |
|---|---:|---:|---|---|
| `SOUL.md` | Yes | Managed fence | Passive; existing sessions remain frozen | Bounded text secret scan |
| `.hermes.md` / `HERMES.md` | Active nearest file | Managed fence | Passive; existing sessions remain frozen | Bounded text secret scan |
| `memories/MEMORY.md` | Typed agent memory | Managed fence | Passive; existing sessions remain frozen | Bounded text secret scan |
| `memories/USER.md` | Typed user memory | Managed fence | Passive; existing sessions remain frozen | Bounded text secret scan |
| `config.yaml` reviewed paths | Yes | Exact owned paths | Block while live or unverifiable | Recursive structural redaction |
| Skills | `SKILL.md` only | Existing managed file only | Passive | Bounded text secret scan |
| Plugin state | Manifest and enabled/disabled state | State only | Block while live or unverifiable | Never import code/env values |
| Shell hooks | Declaration | Exact reviewed scalar leaves | Block while live or unverifiable | Redact native secret containers; patch only non-secret leaves |
| Gateway hooks | Manifest and scanned handler | Reviewed files only | Block while live or unverifiable | Handler scan; never execute |
| MCP | Safe declaration and filters | Exact reviewed scalar leaves | Block while live or unverifiable | Secret values excluded; native secret containers remain byte-identical |
| Permissions | Version-allowlisted native declaration | Lossy changes conflict | Block while live or unverifiable | Caller-supplied fidelity is never trusted |
| `.env`, auth, providers, channels, sessions, databases, logs, gateway records | No | No | Read gateway records only for interlock | Always excluded |

## Authoritative memory contract

Hermes `0.18.1` and `0.18.2` receive the shared Context Relay memory and task
ledger contract in the project-root `.hermes.md`. The reviewed setup writes
only `memory.memory_enabled: false` and
`memory.user_profile_enabled: false`. The daemon continues watching the exact
bound profile files `memories/MEMORY.md` and `memories/USER.md`; an existing
nonempty body is previewed once and later edits become eligible after the same
digest is stable for 750 ms.

Accepted records remain authoritative in the encrypted vault and are available
through the local MCP bridge while the desktop is closed. Managed Hermes
exports record their intended digest transactionally so they cannot re-import
themselves. Unknown versions never receive guessed disable settings: an exact,
safely bound source remains watch-only and any ambiguous source is unavailable.

Hermes renders only lifecycle hooks present in its frozen fixture; it does not
invent missing hook keys. Explicit task completion uses the typed
`context_relay_complete_task` MCP tool from the managed instruction and never
requires a lifecycle-session identifier. Hook projection forwards session ID,
project binding, locally generated event time, and explicit task evidence only.
Prompts, responses, transcript paths, last assistant messages, tool
input/output, and unknown fields are never forwarded or persisted.

## Supported installations and profile binding

Hermes `0.18.2` and `0.18.1` native executable images are supported for import
and apply. Every script or wrapper is import-only, including the upstream Unix
four-line Bash shim and its `venv/bin/hermes` Python console script. Matching a
launcher body, `pyvenv.cfg`, sibling interpreter path, native interpreter bytes,
or a claimed version does not authenticate the installed `hermes_cli` package,
package metadata, dependencies, or transitive Python import closure. Context
Relay therefore never stages, version-probes, or validates through those
launchers and never grants them Full capability.

Upstream tags `v2026.7.7.2` (`0.18.2`, commit
`9de9c25f620ff7f1ce0fd5457d596052d5159596`) and `v2026.7.7` (`0.18.1`,
commit `f9eca7e15f1c2bfe5194aae5aa489af53c0a1a23`) establish source history, not
the identity of a mutable local venv. Python launcher apply support remains
disabled until the repository contains an immutable reviewed manifest for the
complete installed package and import closure and the adapter binds and
reattests every manifest entry.

Windows PE/MZ candidates are also import-only, including a `hermes.exe` renamed
to omit its suffix. A setuptools/distlib Python console launcher is itself a PE
executable, so neither an `MZ` header nor the path can prove that the file is a
standalone Hermes implementation. Until an immutable reviewed Windows artifact
or complete package/import-closure manifest exists, every PE/MZ candidate is
classified as a wrapper and never executed.

The adapter binds one explicitly named profile to its canonical profile root;
it never falls back to another profile or creates a missing profile. The
native executable wire path and digest, supported version, selected profile,
canonical project root, and working directory are rechecked at the native
transaction boundary.

## Effective validation

Internal validation reimports live state and constructs the exact effective
reviewed projection: version-allowlisted permissions, plugin state, safe MCP
fields, and sanitized hook fields. Effective child validation then runs only
the staged, locally attested native executable image with the exact arguments
`config check`. It uses a unique owner-only staged `HERMES_HOME` containing that
non-secret projection plus empty safe `memories/` and `home/` scaffolding. It
never copies native secret containers, secret values, identity, extension code,
sessions, channels, gateway state, provider state, databases, or logs.

The child environment is cleared and rebuilt with only `HERMES_HOME`, `HOME`, `NO_COLOR=1`, `TERM=dumb`, and the minimal platform system `PATH`. Standard input is null; stdout and stderr are separately bounded; timeout, non-zero exit, stderr, invalid UTF-8, oversized output, and output-contract drift fail closed. Missing credentials in the frozen `0.18.2` or `0.18.1` `Configuration Status` contract are reported as `isolated_credential_missing` findings and do not make the reviewed structural configuration invalid.

After any approved write, the native transaction reimports and validates every
reviewed source before ownership or receipt commit. When the transaction
changes `config.yaml`, it additionally runs the isolated child `config check`;
memory or managed-markdown-only writes do not launch a checker for unchanged
configuration. Any invalid changed effective configuration enters the
transaction's ordinary compare-and-swap compensation path and restores matching
before-images.

## Redacted native configuration

Imported MCP and hook components contain only their reviewed, non-secret
projection. When the native declaration also has redacted children, apply may
replace or deliberately delete only scalar leaves already present in the fresh
imported reviewed projection. New scalar keys, mapping/sequence changes,
secret-named paths, and credential-container paths are rejected. The YAML
patcher edits exact leaf spans so omitted native secret containers are not
reconstructed or reserialized. Redaction and placeholder-name metadata must
continue to match the fresh native import.

## Stable lossy mapping reasons

Hermes permission changes remain conflicts when their native meaning cannot be represented exactly. The stable reasons are:

- `approval_mode_not_portable`
- `approval_timeout_not_portable`
- `deny_pattern_not_portable`
- `permanent_allowlist_not_portable`
- `cron_permission_not_portable`
- `confirmation_switch_not_portable`
- `unknown_permission_semantics`

For both supported versions, the frozen allowlist is exactly
`approvals.mode`, `approvals.timeout`, `approvals.deny`,
`approvals.cron_mode`, `approvals.mcp_reload_confirm`,
`approvals.destructive_slash_confirm`, and `command_allowlist`. Unknown
`approvals.*` fields are visible but lossy. Classification recomputes fidelity
and reason from this allowlist; a caller cannot relabel a lossy or unknown path
as exact.

## Import-only rules

All wrappers, unknown Hermes versions, and configurations whose reviewed YAML
paths cannot be patched without ambiguity remain import-only. Import-only
installations are never allowed to start the version or validation command or
enter native apply. Unsupported YAML includes unsafe or non-block topology,
repeated or conflicting plugin state, redacted collection changes, and other
layouts that cannot preserve unowned bytes while changing only the approved
paths.
