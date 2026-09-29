# Claude tool discovery and native MCP round trip

The actual pinned Claude 2.1.202 client omitted two Context Relay tools from its
model request: `context_relay_upsert_task` and `context_relay_create_handoff`.
The other nine tools were present. Both missing tools uniquely used a top-level
`anyOf` in their input schemas. This was an actual-client failure that the
existing protocol and native setup tests did not expose.

The shared schemas now express the same cross-field rules with `if`/`then`/`else`.
The task schema accepts absent/null task ID and revision together, or requires
both UUIDs for an update. The handoff schema requires at least one selected
record across its three arrays. Types, required fields, unknown-field rejection,
array limits, UUID patterns, and semantic request validation are unchanged.
The two generated input-schema artifacts are updated with the source.

## Reproduction and verification

- The first real-Claude run failed before any tool call: its model request
  advertised only nine of the eleven tools. The log is
  `.codex/claude-native-client-run.log` (4.62 seconds).
- A focused regression requiring object tool inputs without root
  `anyOf`/`oneOf`/`allOf` failed against the original schema, then passed after
  the fix. Semantic matrices cover all nine absent/null/UUID task pairs and all
  eight empty/nonempty handoff selections. Logs:
  `.codex/claude-mcp-schema-red.log` and `.codex/claude-mcp-schema-green.log`.
- Independent Ajv 8.18.0 Draft 2020-12 validation compared the original and
  corrected schemas over 100 task cases and 1,331 handoff cases, including
  missing values, nulls, invalid types/UUIDs, and duplicate arrays. Acceptance
  was identical in every case. Local reproducer and result:
  `.codex/verify-claude-mcp-schema-equivalence.mjs` and
  `.codex/claude-mcp-schema-equivalence.log`.
- The corrected actual-Claude test passed in 6.53 seconds (owned child: 6.49).
  Claude advertised all eleven tools and completed eight real MCP calls through
  the production dispatcher: status, remember, get, search, task creation, task
  completion, task listing, and handoff creation. Nine scripted model responses
  drove the sequence. The final task was done with the expected evidence.
- A new daemon instance reopened the encrypted vault and read back the memory
  and completed task written by the actual Claude client. The test also verified
  the generated SessionStart reminder reached the model, settings bytes stayed
  unchanged, the selected saved MCP declaration stayed exact during the session,
  and the actual CLI removed that declaration afterward.
- Read-only review approved the fixture containment and the schema equivalence.
- The combined protocol/MCP suites passed 191 tests; the two explicit native
  client tests are ignored in ordinary runs and were run separately. The shared
  fixture's closed namespace test passes. Log:
  `.codex/claude-mcp-schema-suites.log`.
- The existing actual Codex 0.144.6 regression passed in 7.46 seconds, exercising
  both `exec` and `app-server` with all eleven advertised tools and memory/task
  round trips. Log: `.codex/claude-mcp-schema-codex-regression.log`.
- All-target protocol/MCP Clippy with test support and warnings denied passed in
  29.77 seconds. Formatting, schema export, and daemon-boundary checks pass.
  `graphify update .` completed with 17,089 nodes and 48,026 edges.

## Containment and scope

`actual_claude_exchanges_memory_and_tasks_with_the_production_dispatcher` lives in
`crates/context-mcp/tests/native_claude_v1.rs`. Its stdin-gated child is assigned to
an owned kill-on-close Windows job before any native fixture executable runs.
The Node driver has an additional owned job, time limits and output bounds.
The test holds writer/delete-excluding image leases. Claude's image is pinned
to SHA-256
`7ff0787ebdc19fc509ccea8886ebf6a53ad8213407fa3a2b7c6d1446efc419f6`.

The selected user configuration is synthetic and separate from the ambient
synthetic home. Byte canaries prove the ambient settings and state remain
untouched. The actual CLI saves its own user MCP declaration in the selected
configuration. Built-in tools are disabled and only the fixture MCP tools are
allowed; tool search is disabled so all tool declarations can be inspected.
The environment is cleared, provider credentials are dummy values, and model
requests go to a bounded loopback server. Nonessential traffic and automatic
updates are disabled.

The bridge example extends its closed test namespace with a fixed synthetic
Claude token. It cannot select the production `main` endpoint or read installed
credentials. It runs the production stdio dispatcher and hook handler against
`TestDaemonConfig`, including normal authorization and project binding. The
example and all test hooks are outside the shipped production entry point.
Tokio's process feature is added only to this crate's dev-dependencies to reuse
the existing bounded bridge-identification helper.

This qualifies the actual Claude MCP client and fixes tool-schema compatibility.
It does not establish installed credential binding, native desktop installation,
real-provider acceptance, interactive trust, or the entire native setup
transaction in the same fixture. Production Full-version gates remain unchanged.
The previous local installer from `ba3d332` predates this schema correction.
