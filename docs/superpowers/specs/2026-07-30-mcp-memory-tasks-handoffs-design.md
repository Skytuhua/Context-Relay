# Scoped MCP Memory, Tasks, and Handoffs Design

**Status:** Approved for implementation planning on 2026-07-30 under the
standing instruction to adopt the recommended design and continue.

## Objective

Add a production-safe stdio MCP bridge that exposes all eleven frozen Context
Relay v1 tools to Claude Code, Codex, and Hermes. The bridge resolves the
calling harness and active project without accepting a project identifier from
tool input, delegates all vault operations to the single-writer daemon, and
installs through the existing adapter transaction flow as an active setup
change.

The bridge must work offline, preserve idempotent write replay, enforce
expected revisions, require task-completion evidence, produce complete
structured handoffs, and never write transcripts, credentials, or non-MCP
bytes to stdout.

## Protocol Baseline

The stdio server follows the official Model Context Protocol:

- Primary revision: `2025-11-25`.
- Compatibility revision: `2025-06-18`.
- Transport: newline-delimited UTF-8 JSON-RPC 2.0 on stdin/stdout.
- Supported client lifecycle: `initialize`, `notifications/initialized`,
  `ping`, `tools/list`, `tools/call`, and `notifications/cancelled`.
- Declared server capability: stable tools only, with
  `tools.listChanged = false`.
- MCP task augmentation is not declared. Context Relay task records are domain
  data and are not MCP deferred-execution tasks.
- Unknown methods return JSON-RPC `-32601`; malformed parameters return
  `-32602`; malformed JSON returns `-32700`.
- Each input and output line is bounded by the existing 8 MiB IPC frame limit.
- Stdout contains only one compact JSON-RPC message per line. Diagnostics may
  use stderr after redaction.

References:

- <https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle>
- <https://modelcontextprotocol.io/specification/2025-11-25/basic/transports>
- <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>
- <https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/cancellation>

## Scope

### Included

- All eleven frozen tools in `context_relay_protocol::MCP_TOOL_NAMES`.
- Typed schema validation before and after daemon execution.
- Harness binding for Claude Code, Codex, and Hermes.
- Active-project resolution from the bridge working directory and registered
  project paths.
- Harness access policies for reads, writes, proposals, and tasks.
- Idempotent explicit memories, proposals, updates, archives, task upserts,
  task completion, and handoff creation.
- Expected-revision enforcement through existing workspace operations.
- Handoffs with project identity, selected memories, recent decisions,
  open/blocked tasks, completion evidence, and relevant instruction
  references.
- Bounded concurrency, cancellation, timeout, overload, vault-locked, and
  daemon-unavailable errors.
- Active adapter setup for one stable server named `context-relay`.
- macOS and Windows command/argument rendering without shell command strings.

### Excluded

- HTTP or SSE MCP transports.
- Prompts, resources, sampling, elicitation, logging capabilities, and MCP
  task augmentation.
- Raw SQL, arbitrary paths, shell execution, package operations, native setup,
  device management, sync control, or vault unlock through MCP.
- A project ID, access policy, adapter path, or native setup action in any MCP
  tool input.
- Transcript, session, history, credential, environment-secret, or native
  approval storage.
- Automatic approval of bridge installation. Installation remains an active
  adapter change with the existing exact yes/no approval boundary.
- Retrying a write whose local IPC outcome is unknown. The caller may safely
  replay the same operation ID.

## Architecture

The implementation adds four focused boundaries:

```text
crates/context-mcp/src/
├── main.rs              # CLI binding and process entry point
├── protocol.rs          # bounded MCP JSON-RPC parsing and response shapes
├── server.rs            # lifecycle, dispatcher, cancellation, stdout writer
└── daemon.rs            # one scoped local-IPC call per tool invocation

crates/core/src/mcp/
├── mod.rs               # public bridge binding and workspace facade
├── binding.rs           # harness policy and canonical active-project resolution
├── tools.rs             # all eleven typed tool mappings
├── handoff.rs           # bounded handoff selection and Markdown projection
├── secret_text.rs       # conservative secret-like-text rejection
└── install.rs           # stable adapter-owned MCP component declarations
```

`context-mcp` owns only MCP transport and lifecycle concerns. It does not open
the vault, resolve project policy, mutate native configuration, or contain
database logic.

`core::mcp` owns the scoped semantic operation. It receives one validated
bridge binding and one frozen tool call, resolves policy and project against
daemon-owned vault state, performs the operation through the existing
`OfflineWorkspace` and vault APIs, and returns a validated frozen MCP output.

`contextd` remains the single writer. It accepts one new local request,
`McpCall`, and one new local result, `McpOutput`. The MCP bridge role loses
direct authorization for raw memory, task, handoff, access, and status
requests; it may use only `Health`, `Cancel`, and `McpCall`. This prevents the
bridge from bypassing scoped mapping with a hand-constructed project ID.

## Frozen Local IPC Extension

The protocol crate adds:

```rust
pub struct McpBinding {
    pub harness: HarnessId,
    pub working_directory: WireNativeValue,
}

pub struct McpCallParams {
    pub binding: McpBinding,
    pub name: String,
    pub arguments: serde_json::Value,
}

pub enum LocalRequest {
    // existing variants
    McpCall(McpCallParams),
}

pub enum LocalResult {
    // existing variants
    McpOutput {
        name: String,
        output: serde_json::Value,
    },
}
```

`McpCallParams::validate` requires a known tool name, validates the native
working-directory representation, and runs the existing frozen input
validator. `LocalResult::validate` runs the matching frozen output validator.
The surrounding local request ID remains the cancellation identity. Write
idempotency remains the explicit `operationId` inside the tool arguments.

The bridge supplies `harness` from its adapter-installed argument
and obtains `working_directory` from `std::env::current_dir`. Tools never
accept either field. Same-user malware is already outside the v1 guarantee;
the design nevertheless keeps project and policy enforcement inside the
daemon so an ordinary MCP caller cannot widen scope through tool arguments.

## Binding and Active-Project Resolution

`McpWorkspace::resolve_binding` performs these steps for every tool call:

1. Decode the platform-native working-directory value.
2. Require an absolute existing directory.
3. Canonicalize it without following a caller-provided project identifier.
4. Load all registered project identities and their stored native paths.
5. Canonicalize each usable registered project root.
6. Keep roots that contain the working directory.
7. Select the longest containing root.
8. If equally specific roots map to different project IDs, return a
   non-retryable `scope_denied` ambiguity error.
9. Load the calling harness's access policy.
10. Resolve the allowed global/project grant with
    `AllowedSearchScope::resolve`.

If no project matches, the resolved project is `None`; the default policy then
allows only global memory. Project task operations and an explicit
`active_project` selector fail with `scope_denied`.

Registered roots that are missing, non-directories, unrepresentable, or unsafe
are ignored for resolution but are never rewritten. A selected-project policy
must match the active project. No policy grants arbitrary access to another
project.

The resolver is deterministic across nested monorepo roots and Windows
case-insensitive path forms. It uses the existing native-path codec rather than
lossy UTF-8 conversion.

## Access Rules

The daemon applies one permission matrix before executing a tool:

| Policy | Global read | Project read | Global write | Project write | Tasks |
|---|---:|---:|---:|---:|---:|
| `default` | yes | active | yes | active | active |
| `read_only` | yes | active | no | no | read only |
| `active_project_only` | no | active | no when read-only, otherwise no global | active when writable | active |
| `global_only` | yes | no | yes when writable | no | no |
| `selected_project` | no | selected only when active | no | selected when writable | selected |
| `disabled` | no | no | no | no | no |

`context_relay_get`, update, archive, selected handoff records, and returned
search records are checked against this grant after loading. Record IDs never
act as authorization.

`context_relay_propose_memory` is a write for access purposes. Ordinary
approved memory/task writes operate only on the encrypted vault and never
construct or apply a native setup plan.

## Tool Mapping

Each tool is parsed into its existing typed DTO and mapped as follows:

- `context_relay_search`: resolve the requested global or active-project
  selector, run bounded hybrid search, and return allowed memories plus
  allowed matching instructions.
- `context_relay_get`: load either a memory or instruction by record ID and
  return it only when its scope is granted.
- `context_relay_remember`: map the selector to a granted `ScopeRef`, create an
  explicit memory, and preserve operation-ID replay semantics.
- `context_relay_propose_memory`: create an inferred candidate attributed to
  the calling harness and keep it pending for desktop review. The candidate
  and proposed-memory IDs derive from `operationId`, so replay returns the
  existing candidate.
- `context_relay_update_memory`: require write access to the existing record,
  preserve its title/tags/scope, update Markdown only, and enforce
  `expectedRevision`.
- `context_relay_archive_memory`: require write access and enforce
  `expectedRevision`.
- `context_relay_list_tasks`: require an active granted project, list only
  that project, and apply the optional status filter.
- `context_relay_upsert_task`: require a writable active project; create when
  both task ID and expected revision are absent, otherwise require both and
  enforce the revision.
- `context_relay_complete_task`: require a writable active project, nonempty
  validated evidence, and the expected revision.
- `context_relay_create_handoff`: require a resolved active project and build
  the bounded structured payload described below.
- `context_relay_status`: return the negotiated local protocol range, vault
  state, resolved project, offline/sync state, and the calling harness's
  actual access policy.

Every output is validated before it leaves the daemon and again before the MCP
bridge serializes it.

## Handoff Construction

The caller selects at least one memory, decision, or task. The daemon then:

1. Resolves the active project and requires read access.
2. Loads selected records in caller order.
3. Rejects missing, archived, duplicate, wrong-kind, ungranted, or
   other-project records.
4. Adds recent non-archived project decisions not already selected, newest
   first, within `MAX_EVIDENCE_ITEMS`.
5. Adds all open and blocked active-project tasks not already selected within
   the same bound.
6. Preserves completion evidence on selected done tasks.
7. Selects relevant non-archived instruction IDs from the global and active
   project scopes using the handoff summary and selected-record text, bounded
   and deduplicated.
8. Includes the exact active `ProjectIdentity`.
9. Renders deterministic Markdown from the structured payload.

The Markdown sections are:

```text
# Handoff
## Project
## Summary
## Selected memories
## Recent decisions
## Open and blocked tasks
## Completion evidence
## Relevant instructions
```

Before rendering or returning a handoff, `secret_text` scans the summary,
selected record titles and bodies, task evidence, and project display fields.
It rejects credential assignments, sensitive structured keys, private-key
markers, authorization headers, and bounded token-shaped values. The failure
reports only that secret-like text was found; it never echoes the match. This
is deliberately conservative because a caller can remove the sensitive record
and retry.

The handoff returns record data already admitted to the encrypted vault. It
does not read native configuration, environment variables, logs, sessions,
transcripts, or adapter before-images. Text is bounded by existing protocol
limits, and instruction references are record IDs rather than copied
instruction bodies.

Handoff creation is a read projection: `operationId` becomes `handoffId`, but
no handoff row is persisted. Replaying it cannot create a duplicate write; the
projection reflects the current revisions of its selected records.

## MCP Server Lifecycle and Concurrency

`context-mcp` accepts exactly:

- `--harness claude-code`
- `--harness codex`
- `--harness hermes`

Missing, repeated, or unknown arguments fail before any stdout write and may
emit one redacted stderr diagnostic.

The server state machine is `AwaitInitialize -> AwaitInitialized -> Ready`.
`ping` is allowed after the initialize response. Tool methods before Ready
return an invalid-request error.

The stdin reader parses bounded lines and sends accepted calls to a dispatcher.
A semaphore admits at most 64 in-flight tool calls. A full dispatcher returns
a structured retryable `busy` tool error immediately; it never blocks stdin
indefinitely. A single writer task owns stdout and serializes complete compact
responses, preventing byte interleaving.

Each accepted tool call:

1. Receives a fresh UUIDv7 local request ID.
2. Is entered in an active map keyed by the original MCP JSON-RPC ID.
3. Opens an authenticated `McpBridge` local IPC connection.
4. sends one `McpCall`.
5. Returns a success tool result containing the canonical JSON output as text
   plus `structuredContent` with the same object. `tools/list` publishes the
   existing frozen output schema as `outputSchema`.
6. Removes the active-map entry and releases capacity.

`notifications/cancelled` resolves the active local request ID and sends
`LocalRequest::Cancel` on a separate authenticated connection. Unknown,
completed, initialize, or malformed cancellation targets are ignored as
required by MCP. A queued daemon operation is removed before execution; an
already committed operation remains committed and its late response is
discarded.

EOF closes the reader. The server waits only for already admitted calls up to
the fixed shutdown bound, then exits without emitting non-protocol stdout.

## Error Mapping

Protocol errors use normal JSON-RPC errors. Tool execution failures use an MCP
tool result with `isError = true`, a short redacted text message, no
output-schema-bearing `structuredContent`, and machine-readable `_meta`:

```json
{
  "contextRelay": {
    "code": "vault_locked",
    "retryable": true,
    "fieldPath": null
  }
}
```

Mappings preserve `ClientError.code`, `retryable`, and `fieldPath`. Messages
never include native paths, command lines, environment values, configuration
values, SQL, or token material.

- Locked vault: `vault_locked`, retryable.
- Daemon absent during startup or restart: `internal`, retryable.
- Local request timeout: `timeout`, retryable, with “outcome unknown.”
- Queue saturation: `busy`, retryable.
- Revision mismatch: `revision_conflict`, non-retryable until reread.
- Cross-project or policy failure: `scope_denied`, non-retryable.
- Cancellation: no tool response after a valid cancellation notification.

The bridge never automatically retries a write. Callers may safely replay the
same `operationId`; existing vault operations return the previously committed
record rather than duplicating it.

## Adapter Installation

`core::mcp::install` produces one canonical `ComponentRecord`:

- Name: `context-relay`.
- Kind: `McpServer`.
- Scope: global.
- Command: the absolute attested sibling path to
  `context-relay-context-mcp`.
- Arguments: `["--harness", "<adapter-specific-id>"]`.
- Environment: empty.
- Network endpoints: none.
- No credentials, project IDs, working directories, or secret references.

The existing adapters render that component through their supported MCP
surfaces:

- Claude Code: official `claude mcp add-json ... --scope user`.
- Codex: official `codex mcp add ...`.
- Hermes: reviewed `mcp_servers.context-relay` YAML projection.

Adding, changing, enabling, disabling, or removing this executable declaration
is classified `ApprovalClass::Active`. It flows through the existing semantic
preview, exact approval hash, native transaction, validation, and rollback
mechanisms. The executable digest is attested before planning and rechecked at
apply.

Effective validation inspects configuration through each adapter's existing
non-starting validation path. It must never start the MCP server merely to
validate registration.

## Testing

### Core and daemon

- Resolve no project, one project, nested roots, ambiguous roots, missing
  roots, and platform-native paths.
- Enforce every `HarnessAccessPolicy` for reads, writes, proposals, and tasks.
- Deny direct MCP-bridge memory/task/handoff/status requests.
- Deny record-ID scope bypass and cross-project handoff selections.
- Exercise all eleven typed tool mappings.
- Enforce update/archive/task revisions and completion evidence.
- Replay every write operation ID without duplicate state.
- Build deterministic complete handoffs and retain completion evidence.
- Prove handoffs contain no transcript or adapter-secret sources.
- Return structured locked, busy, canceled, timeout, and unavailable errors.

### MCP process

- Initialize with both supported revisions and reject unsupported negotiation.
- Require `notifications/initialized` before tool use.
- List exactly the eleven frozen schemas.
- Call every tool and validate structured output.
- Reject unknown tools, invalid parameters, oversized lines, embedded
  newlines, and malformed JSON.
- Cancel a queued call and discard a late active-call response.
- Saturate 64 calls and receive retryable `busy`.
- Exercise daemon timeout and daemon restart/reconnect.
- Assert every stdout line is a valid MCP JSON-RPC message.
- Assert null stdin exits successfully with empty stdout.
- Assert diagnostics and failures do not leak binding paths or arguments.

### Adapters

- Render the exact `context-relay` declaration for Claude Code, Codex, and
  Hermes.
- Classify install/remove/enable/disable as active.
- Confirm no environment or secret field is present.
- Confirm validation inspects without starting the bridge.
- Confirm rejected setup performs no write and failed apply rolls back.

## Acceptance Criteria

Task 13 is complete when:

- All eleven frozen tools execute through the daemon with validated inputs and
  outputs.
- Calling harness and active project are daemon-resolved and cross-project
  access is denied.
- Expected revisions and nonempty completion evidence are enforced.
- Handoffs contain every required section and no transcript or secret source.
- Initialize, list, call, cancellation, timeout, overload, and stdout-purity
  tests pass.
- Write replay is idempotent and ordinary memory/task calls never enter native
  approval code.
- Locked and unavailable vault failures are structured and recoverable.
- Each supported adapter can preview, apply, validate, and roll back the
  active bridge registration.
- Workspace formatting, tests, linting, and fresh review pass, apart from
  explicitly documented pre-existing platform-only failures.
