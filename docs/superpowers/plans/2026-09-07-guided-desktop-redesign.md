# Context Relay guided setup and compact desktop redesign

User-approved implementation plan, 2026-09-07. The full user message is authoritative.

## Product requirements

Redesign the entire existing React/Tauri app for first-time users familiar with their
harness but unfamiliar with configuration files, MCP or hooks. Use compact charcoal
surfaces and restrained orange accents, with Dark default and Light/System options.
Support existing Codex, Claude Code and Hermes integrations. Preserve all existing
records, encryption, setup transactions, Save/retry/recovery and exact Undo.

First launch shows a dedicated five-step guide with progress rail, Back, Continue,
Finish later. Persist versioned non-secret preferences and progress identifiers;
never replay writes on resume. Returning users can resume or replay from Help.

1. Choose multiple harnesses, detect installations, distinguish installed/missing/
unsupported, official installation guide and Check again. Explain what harness means.
2. Deliberately select an existing project or choose a folder with native picker;
derive editable name. Never auto-select the old Installer verification project.
3. Connect selected harnesses individually through existing setup logic. Present
plain-language change review and explicit Save approval. Provide constrained Open
harness for project, Copy command, Check again with instructions for external trust
and hook approval. Keep preparation, progress, cancel, retry and Undo. Distinguish
Settings saved, Approval needed, Connection verified.
4. User explicitly saves an editable test note: Use clear, plain language and explain
unfamiliar terms. Open harness and copy a test prompt. Only a fresh successful read
by the matching authenticated MCP harness/project of this note confirms connection.
Offer Keep note or Archive test note; support additional harnesses or finishing later.
5. Replayable/skip-able five-part tour: project, context, suggestions, tasks, harnesses.

Shell: 200px labeled sidebar Dashboard/Context/Tasks/Harnesses/Projects; Help and
Settings at bottom; Devices inside Settings. 52px toolbar with persistent project
selector and page actions. Context has Saved/Suggestions tabs. Dashboard real data:
harness status/next action, recent context, tasks to continue, suggestions, Resume setup.
Use compact lists and detail/editor panes, explicit Add context/New task actions,
preserved drafts and selection, consistent confirmations and row actions.

Every feature explains what it is, why it matters and next action. Brief inline help,
examples, expandable How this works; essential instructions never only in tooltips.
Errors state problem and specific next action. Advanced paths/hooks behind disclosure.

Visuals: Impeccable product/onboard/clarify rules. System sans, 14px body, 20–24px
headings, 36–40px desktop controls, 4/8px spacing, mostly 6–8px radii, consistent labeled
icons, charcoal layered surfaces, subtle separators, orange actions. Adapt to small
windows and text zoom, keyboard focus, reduced motion, accessible contrast/targets.

## Implementation units and ownership

1. Shared tokens/styles and design documentation. Existing CSS must be migrated,
not a pile of contradictory overrides. Add classes for onboarding rail, toolbar,
dashboard columns, work list/detail panes, help/tour and semantic status rows.
2. Root integration: preferences, guided setup, dashboard, tour, working screens.
Keep existing operations shared rather than copy their recovery logic.
3. Backend: short-lived connection-check start/status interfaces, matching successful
authenticated MCP note-read receipts, selected harness/project/note and expiry.
Old receipts and service health checks cannot verify. Update schema/bindings/protocol.
4. Native constrained launch/helper interfaces: resolve discovered harness and
registered project; never accept arbitrary shell commands from frontend.
5. Integration, review and real Windows installer acceptance.

## Acceptance

Test first launch/existing install/defer/restart/tour replay, multiple harnesses,
missing/unsupported/trust/policy/approvals/interrupted preparation; note-read success
and wrong harness/project/expiry/service failures; existing Save/retry/recovery/Undo;
keyboard, focus, screen-reader names, themes, reduced motion and contrast; 1180x760,
900x600 and enlarged text/responsive coverage. Inspect actual rendered interfaces.
Build one complete redesigned installer; verify install/launch/service compatibility
and actual selected harness reading an explicitly approved note. User comprehension
acceptance requires finding and explaining Context/Suggestions/Tasks unaided.

## Constraints and rulings

- Continue existing authorized feature branch codex/windows-app-release; retain caches.
- C disk nearly full. Use recorded E TEMP/TMP. Only one Cargo job at a time.
- Never invoke bare Python (it resolves to the user's Hermes runtime).
- No ordinary project/record writes or hidden trust approval during development tests.
- Existing installed daemon is PID41992; do not stop as cleanup.
- Latest installed build6a612e8; its installation approval is already fulfilled.
- A finished UI with mocked data alone does not satisfy delivery; receipt and launch
  interfaces and installed verification are required before claiming completion.
