# Context Relay desktop design system

The desktop app helps people who know their coding harness save useful context and resume work across sessions. A first-time user should understand each step without knowing what MCP, hooks, or configuration files mean. The approved design uses charcoal surfaces and restrained orange actions, alongside Light and System options.

## Theme and tokens

`src/styles.css` is the single visual source of truth. Dark is the default. Set `document.documentElement.dataset.theme` to `dark` or `light`; application code resolves the System preference and listens for system changes. Native controls use the matching `color-scheme`.

| Role | Dark | Light |
| --- | --- | --- |
| Canvas | `#1c1c1f` | `#fafafa` |
| Sidebar / secondary surface | `#242427` | `#f0f0f2` |
| Hover / stronger surface | `#303034` | `#e6e6e9` |
| Text | `#f3f3f4` | `#202024` |
| Supporting text / placeholders | `#b9b9c0` | `#5a5a64` |
| Primary action | `#ed8a48` | `#a6470a` |
| Primary action text | `#21150e` | `#ffffff` |
| Selected background | `#3e3028` | `#f7e6da` |

Use `--color-border` for quiet separators and `--color-control-border` for input/button boundaries. Orange identifies actions, selection, or focus; it does not decorate every section. Semantic success, warning, danger, and information tokens include their own background surfaces. Always show state text as well as color.

## Typography and dimensions

Use the system sans family throughout. Body text is 14px (`0.875rem`); h1 is 24px, h2 is 20px, and subsection headings are 16px. Prose has a maximum line length of 72 characters. Text must wrap, and paths/identifiers may wrap anywhere on technical or recovery surfaces.

The desktop sidebar is 200px. The toolbar has a 52px minimum height and grows when content wraps. Controls have a 36px minimum height, 6px corners, and 8–12px padding. Panels use 8px corners. Layout spacing follows 4/8px increments. Coarse-pointer controls expand to 44px. Keep headings at fixed rem sizes rather than shrinking them with the viewport.

## Shared layout API

- `.app-shell` contains `.sidebar` and the workspace. Sidebar buttons use `aria-current="page"`; `.nav-icon` supports an 18px labeled icon. The last `.nav-group` moves to the bottom.
- `#workspace-main` supports legacy content directly. When it directly contains `.app-toolbar`, it loses its outer padding so the toolbar reaches the content edges. Put the rest of that page in `.workspace-content`.
- `.app-toolbar` holds `.project-switcher` and `.toolbar-actions`. The switcher can contain its label and select. `.form-actions` and `.row-actions` share wrapping horizontal action spacing.
- `.context-tabs` contains labeled buttons with `aria-pressed="true"` for the active view; application code owns the associated panels.
- `.workbench` contains `.work-list` and `.work-detail`. At desktop width these are list/editor columns; below 1024px they stack. `.record-card` remains a compatible compact list row; `data-selected="true"` highlights a selected row. `.record-button[aria-pressed="true"]` supports a selected row button.
- `.dashboard-grid` arranges `.dashboard-section` elements in two columns. Each section can have a header with a title and action. Use real records and status lists; no illustrative graphs or invented metrics.
- `.onboarding-shell` fits the window and contains `.onboarding-rail` and `.onboarding-content`. Put the five progress items in the rail's ordered list and mark the current item with `aria-current="step"`. The step body and rail scroll independently; the heading and `.onboarding-footer` keep their own visible rows. Long details must never push Back, Continue, or Finish later outside the window. Project names sit beside their radio buttons.
- `.harness-choices` contains `.harness-choice` labels with checkboxes. Checked inputs or `data-selected="true"` show selection. Include installation state and guidance in visible text.
- `.status-row` contains status content and actions. `.status-label` accepts `data-status="success|warning|error|info"`. Row aliases `data-status="verified|approval|missing"` affect a child status label.
- `.tour-panel` is an inline, bordered guide rather than an overlay that blocks the workspace. `.help-content` groups readable help sections with separators.

Existing connection, device, pairing, encryption/recovery, and write-recovery class names remain supported. Use disclosures for technical detail; never hide the required next action in one. Recovery words and pairing codes retain their readable monospace presentation.

## Interaction and accessibility

Every control has a visible keyboard outline. Selected, hover, active, disabled, busy, invalid, and semantic feedback states use consistent tokens. Native inputs remain native. Form errors use readable text, a full border, and a semantic background. Dialogs use the native top layer. Sticky navigation and inline tours use named stacking tokens rather than arbitrary large indices.

At 1024px, editor columns stack. At 736px, labeled sidebar navigation becomes a wrapping top region; dashboard and device/pairing columns stack, and setup progress moves above its content. Workspace pages grow with text enlargement and scroll normally. Setup uses a viewport-height layout with scrollable step content and visible navigation; its stacked progress rail uses at most 30% of the viewport. Do not clip overflowing content to conceal layout problems.

Reduced-motion preference removes transitions and animations. Forced-colors mode gives selected navigation and choices an explicit system-color outline. Semantics, accessible names, focus movement after navigation, and live-region behavior remain application responsibilities.

## Verification

Check dark and light text against canvas, secondary, and stronger surfaces; check primary action text and semantic message backgrounds. Body/supporting/placeholder text must reach 4.5:1. Visible control boundaries and focus indicators must reach 3:1 against the adjacent surface. Test actual integrated pages at 1180×760 and 900×600, enlarged text, keyboard-only navigation, and reduced motion. CSS syntax/contrast checks alone do not replace rendered application acceptance.

## Implemented setup and wording contracts

First launch uses a separate five-step guide. Finish later preserves its step, selected harnesses, deliberate project ID and test identifiers; it does not write harness settings. Help can replay the tour without changing unfinished setup. Locally stored appearance, tour and setup state is versioned; a last verified-read timestamp is historical display metadata only and never completes a connection check.

Connection language distinguishes Settings saved, Approval needed and Connection verified. A verified result requires the current daemon's authenticated note-read check for the selected harness, project, note and revision. The Hermes profile is retained for setup/launch and check selection, but the bridge cannot attest which Hermes profile performed a read; the test screen states that limitation. Keep note or Archive test note after a successful check advances to the tour.

Context uses Saved/Suggestions buttons with aria-pressed states. Dashboard Add context and New task open their editor directly; record actions open the corresponding record. Forms and selected editors retain their drafts in memory across navigation. No plaintext note drafts or configuration commands are stored in appearance/setup preferences.

Production browser validation includes 1180x760, 900x600, 600px responsive width, 200% text, Light and System appearance, explicit project choice and draft preservation. These fixtures do not replace installed native/harness acceptance.
