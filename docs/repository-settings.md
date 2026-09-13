# Repository Settings Checklist

Task 3 must apply and verify available settings after CI exists and GitHub authentication is restored.

- Enable GitHub secret scanning and provider-pattern push protection.
- Until organization-only non-provider patterns and validity checks are
  licensed, require the `Secret Scan` status check. It scans every Git ref with
  the hash-pinned Gitleaks release and permits only the reviewed synthetic test
  fixture fingerprints.
- Treat every finding as active and revoke and rotate it at the issuer.
- Enable Dependabot alerts and security updates.
- Enable private vulnerability reporting.
- Set the GitHub Actions token to read-only.
- Require squash-only merges.
- After CI exists, configure rulesets for `main` and `v*`.

## Live verification — 2026-09-14

### Canonical remote and preserved history

The active release checkout is `E:\Context Relay Releases\workspaces\pr16-release`
on `codex/windows-app-release`. Fetch and push remotes both resolve to
`https://github.com/Skytuhua/Context-Relay.git`. Its existing upstream tracks
`origin/codex/windows-app-release`; this single-branch clone had no `origin/main`
ref. A non-forced `git fetch --no-tags origin refs/heads/main:refs/remotes/origin/main`
created that tracking ref without changing the checkout or working files.

GitHub PR16 and `git ls-remote` agreed on:

| Reference | Commit |
| --- | --- |
| Public `main` | `b3d487e0965a87f69a0d7acf07066daa6a29f132` |
| Pushed release branch / PR head | `30589c010af29b1bd0caf543eaab539baedd044c` |
| Local head at this check | `c56c173ce3ff63902bf8fb9e4af54cac282394a1` |

All five explicit `git merge-base --is-ancestor` checks exited zero: original
root `ab914cc4be6776c3f0d844fd9a19928bc58119e8` to public main and local head;
bootstrap `3fdb5489506398019a7f4fe0fbacd184d80e1795` to public main;
public main to local head; and pushed release head to local head.
`git rev-list --left-right --count origin/codex/windows-app-release...HEAD`
reported `0 15`: local commits extend the pushed branch without divergence.
This verifies current canonical alignment and preservation of the original
history. It does not reconstruct every historical push event. PR16 remained
open and unmerged, with membership source changes still uncommitted; no push,
reset, checkout switch or force update was performed. Recheck exact refs before
the final authorized merge.

### Hosted protection settings

Read-only GitHub REST checks against `Skytuhua/Context-Relay` verified:

- Public repository, default branch `main`, and GitHub license detection `Apache-2.0`.
- Secret scanning, provider-pattern push protection, Dependabot security updates,
  and private vulnerability reporting enabled. Non-provider patterns and validity
  checks remain disabled; the required `Secret Scan` check remains the recorded
  compensating gate, not evidence that those GitHub features are enabled.
- Actions default token permissions are `read`, and Actions cannot approve pull
  request reviews. Squash merging is enabled; merge commits and rebase merging
  are disabled.
- [Protect main](https://github.com/Skytuhua/Context-Relay/rules/19760487)
  is active for exactly `refs/heads/main`: deletion and force updates are blocked,
  linear history and a pull request are required, review threads must be resolved,
  and 22 strict status checks are required. Required approving review count is zero.
- [Protect release tags](https://github.com/Skytuhua/Context-Relay/rules/19760490)
  is active for `refs/tags/v*`, blocking update and deletion. It does not restrict
  tag creation. Both rulesets retain an explicit user bypass actor with `always`
  mode; this audit neither used nor removed that bypass.

The main ruleset still includes macOS checks. The user's Apple deferral has not
changed remote protection configuration or authorized bypassing a failed check.
Reconcile applicable merge requirements before the final merge audit. No remote
settings were changed during this verification.

The live open Dependabot set is #23 (`glib`), #37–39 (`@vitest/mocker`/`vitest`),
and #40 (`js-yaml`). The latter four advisories report patched versions 4.1.11
and 4.3.2 respectively, already present in PR16's manifest/lockfile at pushed
head `30589c010af29b1bd0caf543eaab539baedd044c`; those files match the current
worktree. This does not close the default-branch alerts. Alert #23 remains open
without an approved disposition. No alert was dismissed.

Evidence was retrieved using `gh api` for the repository, both ruleset IDs,
`actions/permissions/workflow`, `private-vulnerability-reporting`, and the open
Dependabot alerts. The local response snapshot is
`.codex/pr16-repository-settings-2026-09-14.json`. These are configuration and
advisory observations, not fork-secret attack tests, name clearance, license
closure, protected-tag publication, or full T01/T02/RB-REP acceptance.
