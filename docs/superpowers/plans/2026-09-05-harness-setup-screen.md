# Harness setup screen

This bounded slice advances the full Windows app release objective. It does not claim native runtime qualification, full onboarding, or completion of the release acceptance map.

## Design

Replace the Harnesses placeholder with a screen for selecting a registered project, choosing Claude Code, Codex or Hermes, entering an explicit Hermes profile, and requesting a native setup preview. The existing daemon preview performs discovery and durably stores its approved-input plan; do not add a fake probe or repair operation (those daemon routes currently return unsupported). Use the existing typed local client, and preserve all native approval and runtime integrity requirements.

Show the selected harness/profile and project, executable identity/version, semantic changes and targets, target scopes, permission/network changes, CLI operations, package artifacts and expiry. Keep identity/digest details in an expandable review section. Render all content as text, never executable HTML. A missing native display string must still have an honest platform/byte representation rather than a fabricated decoded path. Block approval on mismatched selection/profile, expired plan or semantic conflicts; use the existing protocol plan validator before trusting a returned plan.

Apply requires an explicit review checkbox and action; transmit only the exact stored plan ID to the daemon. No automatic apply after preview or error retry. Clear approval when preview/selection changes. Ignore late preview responses after selection change/unmount. Busy actions must not duplicate or overlap. An applied plan retains its own labeled rollback action independent of the current selection, with explicit confirmation. The daemon remains authoritative for drift and expiry; show a safe retry/refresh error without echoing arbitrary error objects or plaintext. Do not claim rollback or setup succeeded until the daemon acknowledges the operation.

## Implementation and tests

1. Add a narrow HarnessGateway interface and LocalWorkspaceGateway methods for preview/apply/rollback; extend WorkspaceGateway. Keep the existing Windows native-path fix intact. No backend or protocol generation changes in this slice.
2. Add `harnesses.tsx`, its focused tests, and replace only the Harnesses screen branch/import in App.tsx. Reuse existing form/card styles and accessibility patterns. Avoid global redesign or unrelated cleanup.
3. First add failing behavioral tests for explicit approval, exact-plan application, failed apply not claiming success, selection changes and late responses, expiry, Hermes profile, conflicts, and explicit rollback of the acknowledged plan. Gateway tests verify the actual local-request envelopes and reject unexpected/malformed/mismatched responses.
4. Run focused tests, then the full frontend tests/typecheck/lint. Report boundaries honestly: fixture tests do not verify real harness installations.
5. Independent review and install testing follow before release acceptance. Do not commit, publish, invoke Cargo, edit packaging files or update graphify concurrently with root work.

Ruling: this uses the existing preview route for discovery because standalone probe and repair routes are not implemented. This is a useful truthful setup slice; standalone status/repair and full onboarding remain outstanding.
