# Harness setup failure feedback — 2026-09-07

Setup errors could remain below the viewport, and changing projects left the old
project's error visible. An independently reviewed related path allowed a late
saved-setup read failure to restore that error after navigation.

The active Harnesses screen now focuses and scrolls setup errors into view,
including repeated failed attempts. Changing projects or leaving the screen clears
the error. Both successful and failed saved-setup reads respect the original
request generation, so an obsolete failure cannot focus another screen or project.
Known error guidance and the rule against displaying raw native errors are unchanged.

The existing full desktop suite also exposed a regression in the preceding Claude
tool-discovery change: strict Ajv rejected handoff conditional `maxItems`/`minItems`
without explicit array types. The schema generator now includes those types and
the checked-in schema was regenerated. Base constraints already require the same
array types, so this does not change accepted handoff inputs or version gates.

## Verification

- Two initial focus/project-error regressions failed before the fix. Two additional
  actual-App tests reproduced late saved-setup failures after project changes and
  leaving/returning. All pass, along with a late probe failure and repeated retry.
- All 228 desktop tests pass, including strict Draft 2020-12 schema compilation.
  TypeScript and ESLint pass.
- All 124 protocol tests pass. Independent Ajv validation preserves acceptance
  across 100 task-input and 1,331 handoff-input combinations.
- The pinned Claude 2.1.202 executable again advertises all eleven tools and
  completes eight production-dispatcher memory/task/handoff calls, generated
  SessionStart delivery and persisted readback after restart in 6.67 seconds.
  This uses the existing disposable-profile, synthetic-credential, loopback-model
  fixture; it does not widen production version qualification.
- Actual App and styles ran in a fresh headless Edge context with an in-memory
  gateway and loopback-only network access. Six Codex/Claude/Hermes failure views
  at 1166×800 and 390×844 passed focus, full-error visibility, overflow and retry
  checks (12 attempts). There were no browser runtime errors. Screenshots were
  inspected. No ordinary daemon, harness profile, credentials or native desktop
  were accessed by this frontend fixture.
- Read-only review approved the final patch after the late saved-setup fix.

Local evidence: `.codex/harness-error-focus-red.log`,
`.codex/harness-error-history-red.log`, `.codex/harness-error-final-suite.log`,
`.codex/harness-error-protocol-tests.log`,
`.codex/verify-harness-error-focus-ui.mjs` and
`.codex/harness-error-focus-ui/results.json`.

This is scoped failure-feedback and schema validation evidence, not installed
connection acceptance. Native desktop control remains paused; signing and full
installed-harness verification remain incomplete.
