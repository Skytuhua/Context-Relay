# Codex adapter capabilities

## Capability and policy states

Native Codex `0.144.0` and `0.144.1` installations are eligible for full setup.
Unknown versions, wrapper scripts, and unknown executable formats are
import-only. A supported native installation is reported as blocked for setup
when an administrator requirements file is active or the selected project is
not explicitly trusted. Missing installations are represented by discovery
failure rather than by constructing an adapter for an unbound executable.

Full setup is transactional. Every file/CLI mutation planner and native/CLI
apply recheck requires the effective setup capability to remain `Full`, in
addition to rechecking the executable path, native identity, digest, version,
project root, and exact expected state. A requirements or trust-policy change
therefore invalidates an already approved mutation before file or CLI
authority is exercised. CLI authority is rechecked after the command runner's
prelaunch hook and before every mutation launch; native authority is rechecked
after transaction preflight and immediately before every file mutation.
Import-only and blocked states receive no generic filesystem or CLI authority.

Policy-blocked installations do not expose a setup-time watch-only memory
registration. Version/format import-only installations may still expose the
exact frozen high-level memory files as watch-only sources when they are safely
bindable.

## Authoritative memory contract

The shared Context Relay memory and task-ledger contract is projected into the
effective project-root instruction file. A nonempty `AGENTS.override.md` is the
effective target; otherwise the target is `AGENTS.md`. A clean project may
create that target as a daemon-owned private file, and rollback restores exact
absence. Existing unmanaged Markdown and newline style are preserved.

Supported setup writes only `[memories] generate_memories = false` and
`use_memories = false`. Prior values and unmanaged TOML remain in the
transaction before-image. Once the project has an explicit trust record, setup
may create an absent project `config.toml`, `hooks.json`, or effective
instruction file with platform-native private metadata; rollback restores its
prior absence exactly. An absent global config cannot bootstrap its own project
trust and remains blocked.

The adapter watches exactly `$CODEX_HOME/memories/MEMORY.md` and
`$CODEX_HOME/memories/memory_summary.md`, where `$CODEX_HOME` is the resolved
custom directory or, by default, `$HOME/.codex`. Raw memories, rollout
summaries, sessions, history, databases, auth material, and approval records
are excluded. Existing reviewed content enters the ordinary pending-candidate
queue. Later edits become eligible after the same digest is stable for 750 ms.
Context Relay managed exports are suppressed by the source ledger.

Unknown versions never receive guessed memory keys. Their exact high-level
sources remain watch-only when safely bindable and are otherwise unavailable.

## Reviewed inputs and native boundary

`CODEX_HOME`, project, working-directory, executable, and custom user-skill
roots are canonicalized before binding. Reviewed reads use the native snapshot
boundary, reject symlinks/reparse points, hardlinks, unsafe topology, oversized
files, and concurrent identity changes, and never rely on a later pathname
read. New private-file metadata is derived while the parent is held and
revalidated; the helper rejects redirected parents and unsupported platforms.
On Windows, the file security descriptor is derived from the current process
token and contains a protected DACL with one owner-only full-access ACE, so
permissive or inherited parent `Users`/`Everyone` entries are not copied.
Security-descriptor capture and restore use the NTFS file-object APIs against
the held file handle; they do not reopen an ACL target by path or pass a file
handle through the generic kernel-object security API. Captured owner, group,
and DACL presence must be exactly reproducible; an omitted component is
rejected before approval, while a present null DACL remains distinct from an
absent DACL. New managed files always use the protected owner-only DACL.

Instruction, rule, skill, hook, permission, plugin, and MCP imports redact or
reject secret-like text. Credential-bearing URLs are redacted on import and
rejected on render. Environment and header maps are never exported literally.

## Plugins, MCP, and hooks

Global plugin and MCP changes use only bounded Codex JSON CLI operations.
Project-scoped plugin and MCP writes remain import-only. Effective validation
compares the complete enabled plugin set, the complete enabled MCP name set,
and normalized MCP transport declarations; an extra, missing, disabled, or
drifted declaration fails validation. Validation never starts configured MCP
servers.

Supported frozen versions use managed `SessionStart` and `Stop` commands.
Explicit task evidence uses the managed task instruction until Codex exposes a
stable task-completion hook. The bridge projects vendor JSON onto session ID,
project binding, locally generated event time, and explicit task ID/evidence
only. Prompt/response text, transcript paths, assistant messages, and tool
input/output are ignored and never opened or forwarded.

## Discovery classification

Known ChatGPT application resource layouts are classified as bundled. Exact
Homebrew, npm `node_modules`, and WinGet path shapes are package-managed. The
documented `$HOME/.local/bin/codex` and Windows OpenAI standalone layouts are
manual. Arbitrary PATH results are unknown rather than inferred from a
substring.

## Remaining qualification

The frozen/synthetic adapter and macOS native boundary are covered in CI. A
release still requires the master plan's credentialed real-install matrix on
clean macOS arm64 and Windows x64 machines, including Windows execution of the
reparse/identity/metadata/rollback cases and current/previous/unknown Codex
installations.
