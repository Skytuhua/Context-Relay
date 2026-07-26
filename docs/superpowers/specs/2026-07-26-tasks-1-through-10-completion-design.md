# Tasks 1 Through 10 Completion Design

**Status:** Approved

**Goal:** Make every requirement in Tasks 1 through 10 of
`Context-Relay-v1-Implementation-Plan.md` true, prove it with authoritative
local, hosted, and live-repository evidence, and keep `main` and
`codex/bootstrap-v1` aligned on GitHub for cross-machine work.

## Scope

This completion pass implements the exact Tasks 1 through 10 boundary.

- Tasks 1 and 3 through 6 are retained and reverified.
- Task 2 live GitHub governance is configured and tested.
- Task 7 gains functional local daemon services for every listed IPC family.
- Task 8 gains the complete networking-disabled memory and task workspace.
- Task 9 retains the revised V1 scope and exact-artifact hosted proof.
- Task 10 gains every missing Claude Code discovery, validation, preservation,
  and approval behavior.

Online synchronization, remote pairing semantics, authoritative product-memory
promotion, and one-click multi-harness onboarding remain assigned to Tasks 13
through 20. Task 7 IPC endpoints for those later systems must still be real,
typed local endpoints: they may report an explicit offline, unconfigured, or
empty local state, but they may not fall through to the generic
`This service is not available in this build` response.

## Completion Tracks

### 1. GitHub Governance

Repository files remain the source-controlled policy record. Live GitHub
configuration becomes the enforcement layer.

After the final source commit is on both branches and required check names are
stable:

- Enable secret scanning, push protection, non-provider patterns, and validity
  checks.
- Enable Dependabot alerts and security updates.
- Enable private vulnerability reporting.
- Keep Actions' default token read-only and unable to approve pull requests.
- Permit squash merges only.
- Protect `main` with pull requests, zero required approvals, required checks,
  conversation resolution, linear history, blocked force pushes and deletion,
  and owner-only emergency bypass.
- Protect `v*` tags from update and deletion.
- Verify push protection with a disposable branch containing a synthetic test
  pattern, then remove the local disposable branch after GitHub rejects it.

Repository protections are applied last so they cannot interrupt the required
final atomic update of `main` and `codex/bootstrap-v1`.

### 2. Functional Single-Writer Daemon

The existing authenticated local IPC transport, framing, installation-token
authentication, request limits, cancellation, backpressure, and vault worker
remain the shared boundary.

Required request families route through explicit service commands:

- health and unlock;
- projects and local path mappings;
- memory CRUD, archive, search, and candidate decisions;
- task CRUD and evidence reads;
- harness, package, sync, device, pairing, recovery, export, and deletion
  status or operations.

Database-backed operations execute only on the vault worker. No desktop or MCP
code opens SQLCipher directly. Local-only implementations preserve the public
IPC shapes intended for later online services. An endpoint that is valid but
not configured returns a typed domain state; malformed, unauthorized,
oversized, timed-out, canceled, or unavailable storage operations return the
existing typed error envelope.

Graceful shutdown stops acceptance, drains or cancels bounded work according
to the existing deadline policy, flushes committed operations, and leaves no
new unowned worker.

### 3. Complete Offline Desktop Workspace

The Tauri desktop remains a thin, typed IPC client. React state contains only
the minimum rendered view model and never becomes a second persistence layer.

The navigation exposes Home, Projects, Memory, Review queue, Tasks, Harnesses,
Packages, Activity, Devices, and Settings. The complete networking-disabled
workflow supports:

1. unlock the local vault;
2. create or select a project and map a local path;
3. create, read, update, archive, and search memories;
4. accept or reject memory candidates;
5. create, read, update, and complete tasks;
6. display task evidence and local harness/package/device status;
7. show locked, offline, syncing, conflict, quota, and revoked states through
   typed status data rather than fabricated records.

Dialogs restore focus to their triggering control. Every action is keyboard
reachable, form controls and errors have screen-reader labels, and destructive
operations require an explicit confirmation. No token, key, or bulk plaintext
record set is stored in browser storage or exposed through an unbounded React
store.

### 4. Complete Claude Code Adapter

The adapter extends the existing import/render/native-transaction design rather
than introducing a second adapter framework.

Discovery covers standalone and package-manager installations, respects
`CLAUDE_CONFIG_DIR`, records the exact supported version, and runs
`claude doctor` through a bounded command invocation.

Import covers global and project `CLAUDE.md`, rules, skills, plugins, MCP,
hooks, declarative permissions, and the reviewed structural allowlist from
mixed-sensitive `~/.claude.json`. OAuth, trust, sessions, caches, and project
history remain local and untouched.

Validation obtains:

- `claude doctor` health;
- official plugin JSON output;
- `claude mcp list` and `claude mcp get` output without starting servers.

Plugin and MCP mutations continue to use official CLI commands. Native project
MCP approvals are detected and represented without modifying native trust
state.

Markdown mutations replace only Context Relay-managed blocks. JSON mutations
replace only allowlisted managed fields. Plans contain restorable before-state
fingerprints, fail on concurrent edits, and rollback to the exact unmanaged
Markdown and JSON content that preceded apply.

Golden fixtures cover Claude Code 2.1.213 and 2.1.214. Unknown versions remain
import-only.

## Data Flow

Desktop actions use generated protocol bindings to call authenticated local
IPC. The daemon validates the request and submits database work to the bounded
single-writer vault queue. The response is normalized into a bounded desktop
view model.

Claude import reads reviewed native files and bounded official CLI output into
managed component records. Rendering produces a native transaction plan.
Apply rechecks fingerprints, performs only the approved file or CLI mutations,
journals before-images, and commits. Rollback consumes that journal and
restores exact prior unmanaged content.

## Testing and Evidence

Each behavior change follows RED/GREEN TDD with the narrowest test that proves
the missing requirement.

Required evidence includes:

- live GitHub API responses for every Task 2 setting and protection;
- clean-clone license, README, action pinning, and workflow checks;
- all-feature Rust formatting, Clippy, and workspace tests;
- protocol, crypto, vault, search, local IPC, daemon, native runner, and Claude
  adapter focused tests;
- the ignored release-mode 10,000-record search performance gate;
- desktop lint, typecheck, component tests, keyboard/focus/accessibility
  workflow tests, bindings, schemas, and production builds;
- hosted Windows and macOS native jobs;
- Task 9 exact-artifact-reuse isolation jobs;
- `cargo deny`, license metadata, and `git diff --check`;
- an exact Tasks 1 through 10 requirement ledger that points every requirement
  to current authoritative evidence.

The final hosted run must target the exact final commit. A green parent commit
does not prove the final source.

## GitHub Handoff Sequence

1. Commit approved design and implementation plan.
2. Implement and locally verify focused tracks.
3. Run `graphify update .`.
4. Commit production changes with scoped messages.
5. Atomically push identical tips to `main` and `codex/bootstrap-v1`.
6. Run and retain hosted Windows/macOS CI at that exact tip.
7. Apply and verify live repository protections.
8. Confirm both remote branches resolve to the verified commit.
9. Audit every Tasks 1 through 10 requirement before declaring completion.

The untracked `.codex/`, `AGENTS.md`, and `graphify-out/` paths remain
preserved and are never staged.
