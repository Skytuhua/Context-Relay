# Authoritative Product Memory Design

**Date:** 2026-08-01

**Status:** Approved through the standing recommendation-first instruction

**Roadmap task:** Task 14 — Make product memory authoritative

## Summary

Context Relay will become the primary product-memory layer for Claude Code,
Codex, and Hermes without making the desktop application part of the runtime
path. The daemon will own a small native-memory reconciliation service. Each
supported adapter will render a managed instruction block, turn off the
harness's own memory generation only through a version-supported setting,
observe a narrow allowlist of native memory Markdown files, and submit new
unmanaged content to the existing review queue.

The service will poll only adapter-declared files, debounce changes for 750 ms,
and persist a source identity plus last-observed, last-imported, and
last-applied digests. These digests make Context Relay exports idempotent and
prevent a managed write from returning as a new candidate. Initial native
content is presented once as pending candidates; it is never silently accepted.

Hook commands will report session start, session stop, and explicit task
evidence through the existing authenticated local bridge. The hook bridge will
project vendor input into a small allowlisted DTO before sending it. Prompt,
response, transcript, and raw session fields are neither read nor persisted.

## Goals

- Render the same product-memory contract into each harness's native project
  instruction file.
- Make Context Relay the primary place for explicit decisions, inferred
  knowledge, and the shared task ledger.
- Prevent a supported harness from generating a competing memory store.
- Preserve native memory as an import/recovery surface, including when the
  desktop UI is closed.
- Detect native edits automatically and queue unmarked content for review.
- Import pre-existing native memory through a one-time preview rather than a
  silent write.
- Suppress export/import loops deterministically.
- Handle lifecycle and task-evidence hooks without collecting conversation
  content.
- Preserve the current adapter rules: bounded file sets, no directory-wide
  state scans, no raw sessions/history, reversible setup mutations, and
  import-only behavior for unknown versions.

## Non-goals

- Importing prompts, assistant messages, transcripts, rollout JSONL, history,
  state databases, logs, or browser context.
- Replacing the existing MCP memory and task tools.
- Automatically accepting inferred or native memory.
- Inventing settings for unknown harness versions.
- Running a model to summarize native files or hook payloads.
- Requiring the desktop process to remain open.
- Adding hosted synchronization behavior in this task.

## Product Contract Rendered to Harnesses

The adapter renders this semantic block inside the existing Context Relay
fence in the project instruction file (`CLAUDE.md`, `AGENTS.md`, or
`.hermes.md`):

```markdown
## Context Relay memory

- At the start of every session, query Context Relay with
  `context_relay_search` for the active project before relying on recalled
  context.
- Treat Context Relay results as the primary memory for decisions, project
  knowledge, and ongoing work. Native harness memory is only an import and
  recovery surface.
- Save explicit user or project decisions with `context_relay_remember`.
- Submit inferred knowledge with `context_relay_propose_memory` so it enters
  review instead of becoming authoritative immediately.
- Keep the shared task ledger current with `context_relay_list_tasks`,
  `context_relay_upsert_task`, and `context_relay_complete_task`.
```

The wording is a shared constant owned by `core::native_memory`; adapters
select only the native target and newline style. This prevents the three
renderers from drifting.

## Options Considered

### 1. Daemon-owned polling reconciliation — selected

The daemon polls the small adapter-declared allowlist and passes observations
to a pure reconciliation engine. Polling every 250 ms gives the 750 ms
debouncer at least three observation opportunities, is deterministic in tests,
needs no new platform dependency, and keeps working without the desktop UI.

### 2. Operating-system file notifications

An event library would reduce idle stat calls, but macOS, Linux, and Windows
emit different rename/write sequences. The service would still need the same
debouncer, rescan path, and loop ledger, while adding another native dependency
and more nondeterministic tests. The watched set is too small for that tradeoff
to pay off in Task 14.

### 3. Harness hooks only

Hooks are useful for lifecycle signals but do not reliably observe a user or
another tool editing a memory file. Hermes also has a different hook surface.
Hook-only integration cannot satisfy the automatic native-edit acceptance
criterion.

## Architecture

```text
adapter capability + source descriptors
                  |
                  v
       contextd polling supervisor
       (250 ms metadata/digest probe)
                  |
                  v
       core::native_memory engine
       - 750 ms stable debounce
       - managed fence extraction
       - source/digest loop checks
       - initial/live classification
          |                 |
          |                 +--> self-export: ledger update only
          v
   pending MemoryCandidate
   (existing review queue)

harness command hook --> context-mcp hook mode --> authenticated local request
                                               --> sanitized lifecycle record
```

The core engine is synchronous and independent of Tokio and the filesystem.
The daemon owns clocks, polling, adapter instances, filesystem reads, and vault
writes. This keeps debounce and loop behavior testable with table-driven unit
tests.

## Core Native-Memory Model

Create `crates/core/src/native_memory/` with the following concepts.

### Source identity

`NativeMemorySourceId` is a SHA-256 digest of a canonical tuple:

```text
contract-version | harness | adapter-version | scope | document-kind | wire-path
```

The wire path is already bound by the adapter and is never accepted directly
from hook input. The digest is the persisted key, while the path remains in the
adapter-owned runtime descriptor.

`NativeMemorySource` contains:

- source ID;
- harness and project/global scope;
- document kind (`agent`, `user_profile`, `summary`, or `topic`);
- exact bound native path;
- maximum byte and character limits;
- whether a Context Relay managed fence is valid in that file;
- observation mode (`initial_preview` then `live`);
- disable capability for the bound harness version.

### Persisted reconciliation ledger

Migration `0010_native_memory_reconciliation.sql` adds:

```sql
CREATE TABLE native_memory_sources (
    source_id TEXT PRIMARY KEY,
    harness TEXT NOT NULL CHECK (harness IN ('claude_code', 'codex', 'hermes')),
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('global', 'project')),
    project_id TEXT,
    document_kind TEXT NOT NULL,
    last_observed_digest TEXT,
    last_unmanaged_digest TEXT,
    last_imported_digest TEXT,
    last_applied_digest TEXT,
    initial_preview_complete INTEGER NOT NULL DEFAULT 0,
    payload_json BLOB NOT NULL,
    CHECK (
        (scope_kind = 'global' AND project_id IS NULL)
        OR (scope_kind = 'project' AND project_id IS NOT NULL)
    )
);
```

The JSON snapshot carries the validated model so later schema additions remain
explicit. Indexed columns support the hot comparisons. No native file body is
stored in this table.

### Observation and debounce

The daemon probes each exact source path every 250 ms. A probe returns only one
of `absent`, `regular_file(bytes, metadata)`, or `unsupported_topology`. Existing
native filesystem constraints reject links, devices, path escapes, oversized
files, and changing identity.

The engine tracks a pending observation per source:

- A new digest starts or resets the 750 ms timer.
- Repeated observations of the same digest retain the original start time.
- The observation becomes ready only after the same digest has remained stable
  for at least 750 ms.
- Absence is debounced too, but never produces a memory candidate.
- Unsupported topology is reported and retried; it never broadens the path set.

The polling loop is independent of the vault worker. Ready observations are
submitted through the existing bounded worker queue, so all ledger and
candidate writes remain serialized with other vault mutations.

### Managed content and loop suppression

The parser recognizes exactly one complete Context Relay fence. It returns:

- `managed_body`, if present;
- `unmanaged_body`, preserving all bytes outside the fence;
- full-file digest;
- normalized unmanaged digest.

Duplicate, nested, or partial markers are conflicts and never imported.

For each stable observation:

1. If the full digest equals `last_applied_digest`, record it as observed and
   stop. This is a Context Relay export.
2. Remove the managed block and normalize only newline-at-end differences.
3. If the unmanaged body is empty, update the ledger and stop.
4. If its digest equals `last_imported_digest`, update the ledger and stop.
5. Otherwise create one pending candidate and atomically record the imported
   digest.

An export records `last_applied_digest` in the same vault transaction that
records the approved native transaction plan. A process failure can therefore
leave a harmless extra observation, but cannot silently import a body that was
not actually written. Startup native-transaction recovery runs before watcher
activation, preserving existing ordering.

### Candidate construction

Native content uses the existing `MemoryCandidate` review queue with:

- `MemoryOrigin::NativeImport`;
- a deterministic candidate and operation ID derived from
  `(source_id, unmanaged_digest)`;
- source harness and bound scope from the adapter;
- a title derived from harness plus document kind, never from arbitrary file
  content;
- the unmanaged Markdown as the candidate body;
- tags `native-import` and the harness name;
- evidence text that distinguishes `initial native-memory preview` from
  `native-memory edit`.

Candidate insertion and ledger advancement occur in one SQLite transaction.
Restarting or receiving duplicate events cannot create another candidate.
Acceptance continues through the existing candidate-review path and is the
only way native content becomes authoritative memory.

## One-Time Existing-Memory Preview

After adapter setup is applied and startup transaction recovery completes, the
daemon registers source descriptors and performs an initial scan.

- Every nonempty unmanaged native document not previously previewed becomes a
  pending `MemoryCandidate`.
- `initial_preview_complete` advances atomically with candidate creation.
- Empty, missing, managed-only, and already-previewed sources produce no
  candidate.
- Initial content is never inserted directly into the memory records table.
- Later edits use the same pipeline with `native-memory edit` evidence.

The existing desktop review queue is the preview UI. No second review model or
parallel candidate type is introduced.

## Adapter Capability Matrix

Capabilities are closed over the existing frozen full-apply versions. Unknown
versions remain import-only and receive no guessed config mutation.

| Harness | Full versions | Supported native-generation disable | Project instruction target | Native memory sources |
|---|---|---|---|---|
| Claude Code | 2.1.213, 2.1.214 | project setting `autoMemoryEnabled: false` | project-root `CLAUDE.md` | bound project memory `MEMORY.md` and bounded topic Markdown files |
| Codex | 0.144.0, 0.144.1 | `[memories] generate_memories = false` and `use_memories = false` | project-root `AGENTS.md` | `~/.codex/memories/MEMORY.md` and `memory_summary.md`; raw memories, rollout summaries, sessions, history, and databases are excluded |
| Hermes | 0.18.1, 0.18.2 | `memory.memory_enabled: false` and `memory.user_profile_enabled: false` | project-root `.hermes.md` | profile `memories/MEMORY.md` and `memories/USER.md` |

For Claude's default project-memory directory, the adapter uses its frozen
version contract and fixture-defined project-key mapping. An explicit supported
`autoMemoryDirectory` setting takes precedence. If the bound directory cannot
be resolved exactly, the adapter reports `watch_only_unavailable`; it does not
scan sibling project directories.

For a supported config write, the adapter preserves the user's prior value in
the native transaction before-image. Managed policy conflicts remain visible
and block apply. For an import-only or otherwise unsupported version, setup
does not emit a disable mutation. If an exact native source path can still be
bound safely, the daemon uses watch-only fallback; otherwise it reports the
source unavailable.

All adapters watch their declared sources even after native generation is
disabled. This captures deliberate hand edits and also provides the required
fallback if policy or version constraints prevent a disable mutation.

## Exports and Desktop Independence

Accepted Context Relay memory remains in the vault and is queried through the
local MCP bridge. The project instruction file and bridge declaration are
ordinary native files, so the harness can discover the contract while the
desktop UI is closed. The daemon and MCP bridge, not the desktop renderer, are
the runtime components.

Hermes additionally retains its existing managed `MEMORY.md`/`USER.md` export
path. Any Task 14 export through that path must call the native-memory ledger
API with the intended digest before commit. Claude and Codex do not receive
direct writes into vendor-generated memory artifacts in Task 14; their managed
project instruction block points at the authoritative MCP tools.

This distinction avoids treating Codex-generated artifacts as a supported
write API while still observing reviewed high-level Markdown files.

## Hook Event Handling

### Invocation

Extend the installed `context-relay-mcp` executable with a hook mode while
preserving the existing strict MCP invocation:

```text
context-relay-mcp --hook-event session-start --harness <harness>
context-relay-mcp --hook-event session-stop --harness <harness>
context-relay-mcp --hook-event task-evidence --harness <harness>
```

The hook reads at most the existing bounded arbitrary-input limit from stdin,
projects supported vendor fields into `NativeHookEvent`, and sends
`LocalRequest::NativeHookEvent` as `ClientRole::McpBridge` over authenticated
local IPC. The command is best effort and produces no conversation text for
stop/evidence events. Session start returns only a fixed, bounded reminder to
query Context Relay; it does not inject memory bodies.

### Allowlisted event DTO

`NativeHookEvent` contains only:

- harness;
- event kind (`session_start`, `session_stop`, `task_evidence`);
- source/session identifier after length validation;
- bound working directory encoded as `WireNativeValue`;
- optional task ID, task status, and explicit evidence references;
- event timestamp generated locally by the bridge.

The vendor JSON adapter may inspect only the scalar keys needed to populate
that DTO. It must never open or forward `transcript_path`, and must ignore
fields such as `prompt`, `message`, `last_assistant_message`, tool input/output,
or conversation content. The daemon persists only the validated DTO.

Task evidence updates only an existing task and only when a validated task ID
is supplied. It uses the existing completion-evidence limits and does not infer
evidence from a stop message. A lifecycle event without an active project path
is acknowledged but not persisted.

### Rendered hooks by harness

- Claude Code: managed command hooks for `SessionStart`, `Stop`, and
  `TaskCompleted` where the frozen version supports them.
- Codex: managed command hooks for `SessionStart` and `Stop`; explicit task
  evidence uses the hook command invoked by the managed task instruction until
  Codex exposes a stable task-completion hook.
- Hermes: render only lifecycle hooks present in the frozen 0.18.x fixture. If
  no equivalent event exists, the instruction/MCP path remains active and no
  hook key is invented.

Hook mutations use the existing adapter-native transaction planner and preserve
unmanaged hooks. Reapplying setup is byte-stable.

## Protocol and Vault Changes

- Add validated protocol DTOs for `NativeHookEventParams` and its small enums.
- Add `LocalRequest::NativeHookEvent` and route it only for `McpBridge` and
  desktop test clients.
- Return `LocalResult::Empty`; session-start context is constructed by the hook
  executable from a fixed constant after successful acknowledgement.
- Export regenerated TypeScript bindings.
- Add vault APIs for source-ledger load/upsert and atomic
  candidate-plus-ledger insertion.
- Extend startup and setup recovery tests so watchers start only after native
  recovery and bridge reconciliation.

No network protocol or hosted record kind changes in Task 14. Source-ledger and
hook-lifecycle rows are local operational state, not synchronized records.

## Failure Behavior

- Unsupported disable key: do not write it; report watch-only or unavailable.
- Policy-owned config: surface a conflict and leave it untouched.
- Missing source: retain the descriptor and continue polling.
- Link, special file, path escape, oversized file, or identity race: reject the
  observation and retain the last safe ledger state.
- Partial/duplicate managed markers: report a source conflict; do not import.
- Invalid UTF-8 or secret-like adapter-rejected content: do not create a
  candidate; record a redacted diagnostic only.
- Busy vault worker: retain the ready observation and retry with bounded
  backoff; do not advance its digest.
- Hook daemon unavailable: exit nonzero without printing input or storing it.
- Unknown hook fields: ignored by the vendor projector and never forwarded.
- Restart: rebuild runtime descriptors, load persisted digests, perform an
  initial probe, and resume idempotently.

## Verification Strategy

### Core unit tests

- 749 ms is not ready; 750 ms is ready.
- Digest changes restart the debounce window.
- Absence never creates a candidate.
- Initial nonempty unmanaged content creates exactly one pending candidate.
- A later unmanaged edit creates exactly one new pending candidate.
- Repeated events and restart replay do not duplicate candidates.
- `last_applied_digest` suppresses a Context Relay export.
- Managed content plus a new unmanaged section imports only the unmanaged
  section.
- Partial, duplicate, or nested fences are rejected.

### Adapter contract tests

- Each full version renders the exact shared instruction semantics.
- Claude writes only `autoMemoryEnabled: false`.
- Codex writes only documented memory keys.
- Hermes writes only the frozen `memory.*_enabled` keys.
- Unknown versions emit no disable mutation.
- Prior values and unmanaged config/hooks survive apply and rollback.
- Raw session/history/state paths never appear in any source descriptor.

### Hook tests

- Session start/stop and task evidence produce the allowlisted DTO.
- Payloads containing transcript, prompt, response, or last-message fields do
  not place those values in IPC bytes, vault rows, logs, or command output.
- Oversized and malformed input fails closed.
- Unsupported vendor events are not rendered.

### Daemon acceptance tests

- Editing a watched native Markdown file creates a pending candidate
  automatically after 750 ms.
- A Context Relay managed export is observed but never re-imported.
- An unsupported version never receives a guessed setting.
- Existing native content appears once in the review queue.
- Closing the desktop frontend does not stop daemon observation or MCP access.
- Raw session files remain byte-identical through setup, observation, hook
  delivery, export, rollback, and restart.

## Documentation Sources

- [Claude Code memory](https://code.claude.com/docs/en/memory) documents
  `autoMemoryEnabled`, the project memory directory, and the supported disable
  behavior.
- [Claude Code hooks](https://code.claude.com/docs/en/hooks) documents
  `SessionStart`, `Stop`, and task lifecycle events; its transcript and last
  message fields are intentionally excluded here.
- [Codex memories](https://learn.chatgpt.com/docs/customization/memories) and the
  [Codex config reference](https://learn.chatgpt.com/docs/config-file/config-reference)
  document `memories.generate_memories` and `memories.use_memories`.
- [Codex hooks](https://learn.chatgpt.com/docs/hooks) documents `SessionStart`,
  `Stop`, the common hook fields, and the unstable nature of transcript paths.
- [Codex memory pipeline](https://github.com/openai/codex/blob/main/codex-rs/core/src/memories/README.md)
  documents the generated high-level Markdown and raw/rollout artifacts.
- [Hermes 0.18.2 configuration](https://raw.githubusercontent.com/NousResearch/hermes-agent/v2026.7.7.2/website/docs/user-guide/configuration.md)
  documents `memory.memory_enabled` and `memory.user_profile_enabled` for the
  frozen adapter release.

## Acceptance Criteria

Task 14 is complete when all of the following are demonstrated by tests and a
clean repository verification run:

1. Every harness receives the managed primary-memory and task-ledger contract.
2. Supported versions use only their documented native-memory disable keys.
3. Unknown or unsupported versions receive no guessed config.
4. Existing native memory is previewed once as pending candidates.
5. A stable native edit appears automatically after the 750 ms debounce.
6. A Context Relay export cannot re-import itself.
7. Hook lifecycle/task evidence is handled without prompt, response, transcript,
   or raw-session capture.
8. Observation and MCP access continue while the desktop UI is closed.
9. All modified adapter, protocol, core, daemon, MCP bridge, binding, and desktop
   regression suites pass.
