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
| Shell hooks | Declaration | Exact owned path | Block while live or unverifiable | Reject secret-bearing declarations |
| Gateway hooks | Manifest and scanned handler | Reviewed files only | Block while live or unverifiable | Handler scan; never execute |
| MCP | Safe declaration and filters | Exact owned paths | Block while live or unverifiable | Values excluded; placeholder names only |
| Permissions | Exact native declaration | Exact Hermes mapping only | Block while live or unverifiable | Lossy mappings conflict |
| `.env`, auth, providers, channels, sessions, databases, logs, gateway records | No | No | Read gateway records only for interlock | Always excluded |

## Supported installations and profile binding

Hermes `0.18.2` and `0.18.1` native executables are supported for import and apply. The adapter binds one explicitly named profile to its canonical profile root; it never falls back to another profile or creates a missing profile. The executable wire path, native classification, SHA-256 digest, supported version, selected profile, canonical project root, and working directory are rechecked at the native transaction boundary.

## Effective validation

Internal validation performs the reviewed semantic and configuration checks. Effective child validation then runs only the attested executable with the exact arguments `config check`. It uses a unique owner-only staged `HERMES_HOME` containing a shape-only `{}` `config.yaml` plus empty safe `memories/` and `home/` scaffolding. It never copies the reviewed semantic projection or the real profile's secrets, identity, extension code, sessions, channels, gateway state, provider state, databases, or logs.

The child environment is cleared and rebuilt with only `HERMES_HOME`, `HOME`, `NO_COLOR=1`, `TERM=dumb`, and the minimal platform system `PATH`. Standard input is null; stdout and stderr are separately bounded; timeout, non-zero exit, stderr, invalid UTF-8, oversized output, and output-contract drift fail closed. Missing credentials in the frozen `0.18.2` or `0.18.1` `Configuration Status` contract are reported as `isolated_credential_missing` findings and do not make the reviewed structural configuration invalid.

## Stable lossy mapping reasons

Hermes permission changes remain conflicts when their native meaning cannot be represented exactly. The stable reasons are:

- `approval_mode_not_portable`
- `deny_pattern_not_portable`
- `permanent_allowlist_not_portable`
- `cron_permission_not_portable`
- `confirmation_switch_not_portable`

## Import-only rules

Wrappers, unknown Hermes versions, and configurations whose reviewed YAML paths cannot be patched without ambiguity remain import-only. Import-only installations are never allowed to start the validation command or enter native apply. Unsupported YAML includes unsafe or non-block topology, repeated or conflicting plugin state, and other layouts that cannot preserve unowned bytes while changing only the approved paths.
