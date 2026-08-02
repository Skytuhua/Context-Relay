# Codex adapter capabilities

## Authoritative memory contract

Codex `0.144.0` and `0.144.1` receive the shared Context Relay memory and
task-ledger contract in the project-root `AGENTS.md`. The reviewed setup writes
only `[memories] generate_memories = false` and `use_memories = false`; prior
values and unmanaged TOML remain in the transaction before-image.

The adapter watches exactly `~/.codex/memories/MEMORY.md` and
`memory_summary.md`. Raw memories, rollout summaries, sessions, history, and
databases are excluded. Existing high-level content is previewed once through
the ordinary pending candidate queue. Later edits become eligible after the
same digest is stable for 750 ms. Context Relay managed exports are suppressed
by the source ledger, and accepted records are queried through the local MCP
bridge while the desktop is closed.

Unknown versions never receive guessed memory keys. Their exact high-level
sources remain watch-only when safely bindable and are otherwise unavailable.

## Managed hooks and privacy

Supported frozen versions use managed `SessionStart` and `Stop` commands.
Explicit task evidence uses the managed task instruction until Codex exposes a
stable task-completion hook. The bridge projects vendor JSON onto session ID,
project binding, locally generated event time, and explicit task ID/evidence
only. Prompt and response text, transcript paths, last assistant messages,
tool input/output, and unknown fields are ignored and never opened or
forwarded.

Session start emits only a fixed reminder to query Context Relay. Stop and task
evidence emit no conversation text and never store raw session content.
