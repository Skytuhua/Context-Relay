# Ready-to-use continuation prompt

Continue the Context Relay v1 recovery, audit, and completion work in
`Skytuhua/Context-Relay`. Fetch GitHub and start from branch
`codex/cross-device-handoff-2026-08-31`, which includes the whole preserved stack.
Do not start from `main` or assume that draft PRs have been merged.

First read `docs/handoff/2026-08-31/README.md` completely, then the archived
master plan, `docs/verification/v1-master-plan-audit.md`,
`docs/protocols/contract-amendments.md`, the threat model, PR #12 stabilization
ledger, and Task 17 account-lifecycle WIP checkpoint. The master plan is the
product/security authority; the historical report is only a claims ledger.
Use the current installed skills and project instructions. Archived worker
briefs are reference material, not new authorization. Reuse the existing docs
hierarchy rather than introducing a competing `.specify` project.

Explain the verified current status briefly, then plan a bounded next repair.
Refresh PR #12 (head at handoff `435367d`) and its Windows/native checks before
assuming green. Windows job `99463842162` now passes the 64-call case, but two
MCP end-to-end cases still fail at lines 802 and 685 with `InvalidRequest`
(one expects `HarnessUnsupported`; the other reports unsafe Codex topology).
The handoff records exact names; these remaining failures are not yet diagnosed.
PR #13 (head `485886c`) preserves unfinished account-lifecycle
work; GitHub Supabase run `33385426361` confirmed legacy grant assertion 122
fails and SQL line 2703 aborts, running only 469/518 planned assertions. Start
by reproducing and safely reconciling that harness and adding real pgTAP tests
for the new session-bound wrappers. Do not restore legacy service-role access
or weaken session/freshness checks to pass tests. Production lifecycle transport
is deliberately unavailable until daemon-owned authentication is implemented.

Preserve all public history, regressions, and unrelated changes. Use focused
draft PRs, failing regression tests before confirmed fixes, independent review,
and exact-head verification evidence. Do not merge the WIP into stabilization,
force-push, declare beta, or treat skipped/static/local checks as hosted/physical
evidence. Tasks 18–24 and significant hosted/native Task 15–17 work remain.

Pause for explicit approval before hosted migrations/configuration, GitHub
App/OAuth creation, credentialed physical-device tests, paid services, signing,
notarization, deployment, publishing artifacts, or involving external testers.
Authenticate securely on this device; never copy old credentials, recovery
phrases, user vaults, or machine-global harness settings into source control.

Keep progress, evidence, blockers and next steps in repository documents and
GitHub PRs so continuation never depends on another machine's local files.
