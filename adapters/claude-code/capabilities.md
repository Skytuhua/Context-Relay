# Claude Code adapter capabilities

## Authoritative memory contract

Claude Code `2.1.213` and `2.1.214` receive the shared Context Relay memory and
task-ledger contract in the project-root `CLAUDE.md`. The reviewed setup writes
only the supported project setting `autoMemoryEnabled: false`; prior values and
unmanaged configuration remain in the transaction before-image.

The adapter watches the exactly bound project memory `MEMORY.md` and its
bounded topic Markdown files. An explicit supported `autoMemoryDirectory`
takes precedence over the frozen default project-key mapping. Existing content
is previewed once through the ordinary pending candidate queue. Later stable
edits are observed by the daemon after 750 ms, including while the desktop is
closed. Accepted records remain authoritative in the encrypted vault and are
retrieved through the local MCP bridge.

Unknown versions never receive a guessed disable setting. If the exact source
directory can still be bound safely, the capability is watch-only; otherwise
the source is unavailable. Sibling project-memory directories are never
scanned.

## Managed hooks and privacy

Supported frozen versions use managed `SessionStart` and `Stop` commands.
Explicit task evidence uses the managed task instruction until Claude Code
exposes a stable task-completion hook. The bridge projects vendor JSON onto
session ID, project binding, locally generated event time, and explicit task
ID/evidence only. Prompt and response text, transcript paths, last assistant
messages, tool input/output, and unknown fields are ignored and never opened
or forwarded.

Session start emits only a fixed reminder to query Context Relay. Stop and task
evidence emit no conversation text. Hook delivery updates local operational
state or an existing task; it never stores raw session content.
