# Harness setup status — 2026-09-06

The desktop previously displayed `Connected` immediately after `harness_apply`
acknowledged its configuration transaction. That response does not verify a
harness session or Codex hook trust. An ordinary first connection can save its
settings successfully while Codex skips the newly added hooks.

The preview action now says `Review setup`, with retry and expiry instructions
that name the same action. Apply says `Save settings`, followed by `Settings saved`. Its history
is labeled `Recent setup changes` and preserves each original plan for Undo.
Each saved result states that the connection has not been verified. Codex results
explain how to open the CLI in the saved project's folder, review the Context
Relay SessionStart and Stop commands through `/hooks`, and start a new session.
The review screen explains this additional step before approval. Other harnesses
receive new-session guidance without Codex-specific instructions.

These instructions follow [Codex's documented review flow](https://learn.chatgpt.com/docs/hooks).
The pinned 0.144.6 runtime's [feature declaration](https://github.com/openai/codex/blob/5d1fbf26c43abc65a203928b2e31561cb039e06d/codex-rs/features/src/lib.rs)
enables hooks by default. The [native lifecycle fixture](codex-native-hooks-2026-09-06.md)
now verifies that default and explicitly disabled hooks across 32 actual CLI and
app-server sessions. The product does not write hook trust or feature overrides.

## Validation

- The original UI failed two targeted regressions because it reported a
  connection instead of saved settings and omitted the native approval step.
- All 143 frontend tests pass. The revised tests cover acknowledgment timing,
  the correct saved project after selection changes, harness-specific guidance,
  unverified status, failed apply and exact-plan Undo.
- Frontend lint, type checking and production build pass.
- Independent source review found no actionable correctness issues and confirmed
  that the preview action should be named for setup rather than live verification.
- A fresh headless Edge context renders the actual React app with a synthetic
  in-memory gateway. Ten desktop/narrow screenshots include the saved Codex
  instructions; apply and Undo pass, with no page errors or horizontal overflow.
  No installed application, normal service, user configuration or account is used.
- The actual pinned Codex fixture passes all 32 local-model sessions in 20.15
  seconds. Default-enabled, exact trusted hooks run; untrusted, modified and
  explicitly disabled hooks remain inactive.

Local evidence is under `.codex/context-relay-closeout-2026-09-05/`:
`harness-setup-status-{red,green,suite,lint,typecheck,build,native,browser}.log`
and `harness-setup-status-ui/`. Screenshots verify layout using a synthetic Full
response; they are not evidence that the real runtime's Full gate is enabled.

## Remaining acceptance

Live connection verification is still required: read back the effective native
hook state and complete production bridge memory/task round trips. The UI does
not infer verification from a manual step, restart, or checkbox. Setup history
remains session-local. Existing version gates remain unchanged, and Codex
0.144.6 is still ImportOnly. The existing 11d6740 installer is unchanged and has
not received these later source fixes. Native desktop testing remains paused.
