# Windows x64 setup for Codex 0.144.6 and Claude Code 2.1.202

Context Relay now permits automatic settings setup for these exact native
Windows x64 versions. Previously, both installed versions stopped at the
availability screen despite their accumulated native qualification. The normal
flow can now advance through Review setup, explicit approval and Save settings.

This is settings setup support. Saving settings still does not claim a verified
harness connection or approve Codex hooks. The user reviews those commands in
Codex through `/hooks`. If the selected project is not trusted, Context Relay
explains that Codex needs folder-trust review and names Review setup as the retry
action. Managed requirements retain their policy guidance and blocking behavior.

## Qualification decision

The independent review considered the cumulative evidence for safe settings
setup separately from the remaining release and ordinary-profile acceptance:

| Boundary | Evidence |
| --- | --- |
| Actual Codex configuration transactions | [Native preview, Save, reopen, reapply, Undo and recovery](codex-native-setup-2026-09-06.md) |
| Actual Claude configuration transactions | [Native setup/recovery](claude-native-setup-2026-09-07.md), [fresh settings](claude-fresh-settings-2026-09-07.md), [missing project directory](claude-missing-project-directory-2026-09-07.md) |
| Native hook semantics and explicit approval | [Codex hook matrix](codex-native-hooks-2026-09-06.md), [saved approval readback](codex-saved-hook-approval-2026-09-06.md) |
| Harness memory and task calls | [Actual Codex MCP sessions](codex-mcp-roundtrip-2026-09-06.md), [actual Claude MCP session](claude-native-client-2026-09-07.md) |
| Claude memory directory selection | [Native directory/repository/environment qualification](claude-memory-directory-2026-09-07.md) |
| Installed service and credential path | [Actual Codex](installed-codex-status-2026-09-07.md) and [actual Claude](installed-claude-status-2026-09-07.md) status sessions |

These checks collectively justify the exact Windows x64 setup promotion. They
do not qualify another platform or version. The shared cross-platform allowlists
are unchanged; both new gates require Windows and x86_64 explicitly.

Codex retains native-image classification, project-trust and managed-requirement
checks. Claude retains settings/environment precedence, WatchOnly behavior for
managed settings and safely missing project settings, and rejection of unsafe
memory roots. Both retain executable binding, preview expiry, freshness checks,
encrypted before-images, idempotent apply and exact-plan Undo/recovery.

The private unit-test version overrides were removed. Native setup fixtures now
must pass through the same production version gates as the shipped service.

## Verification

Both new positive gate regressions first failed with ImportOnly rather than
Full. The final adapter suites pass 145 tests, including neighboring-version
exclusion, Codex native/wrapper and trust/policy distinctions, and Claude default
and remote memory roots for 2.1.202. One historical negative used 2.1.202 as an
unsupported version; it now uses 2.1.201. Fixture-only corrections use valid
neighboring versions and actual wrapper bytes rather than an ignored kind hint.

The folder-trust UI regression first failed because only generic policy guidance
was shown. All 232 frontend tests, TypeScript and ESLint then pass. Four actual
React App browser views cover trust and managed-policy responses at 1166×800 and
390×844, with visible guidance, no horizontal overflow and no browser errors.
The narrow trust screenshot was inspected. These views use a disposable gateway.

The actual native setup fixtures pass all four root tests and nine contained
cases in 596.06 seconds through the production gates. Claude covers fresh
settings, missing project settings directory, ordinary Save/Undo and recovery
after payload writes, CLI activation and commit. Codex covers ordinary Save/Undo
and recovery after payload writes and commit. Each case reopens the encrypted
vault and verifies idempotent reapply, exact Undo or restoration, and unchanged
ambient-profile canaries. The bridge within these transaction fixtures is inert;
the separate actual-client/installed-service evidence above covers communication.

The exact opt-in selector is `native_setup_tests::pinned_`. An initial broader
selector was stopped after identifying unrelated ignored Hermes tests in its
selection; it is not the final run. Only the verified owned test parent was
stopped, and its child jobs closed with it. The ordinary installed daemon remained
running throughout. No Hermes runtime was invoked.

Local evidence: `.codex/windows-setup-promotion-{adapters,native,frontend}.log`,
`.codex/windows-setup-trust-ui-{red,green,typecheck,lint}.log` and
`.codex/windows-setup-promotion-ui/results.json`.

Final library checks pass: 193 core tests (18 opt-in tests ignored) and seven
daemon bridge-install tests (one child-only entry ignored). Release Clippy for
both crates and all targets passes with warnings denied. Independent review of
the production and UI changes found no issues. Rust formatting and diff checks
pass; the source knowledge graph was updated.

The installed application still uses candidate e09d206. Packaging and installation
of this setup promotion are not yet claimed.

## Remaining acceptance

Ordinary-profile Save/Undo, native GUI acceptance, clean-machine installation,
signing, installed Hermes client sessions and wider platform/product work remain
open. Existing evidence documents retain their historical test scope; their
statements that these two versions must remain ImportOnly are superseded by this
Windows x64 setup decision. No automatic hook trust or universal live-connection
claim is introduced.
