# Windows preview readiness implementation

Approved target: Windows x64 0.1.1, tag v0.1.1-alpha.1, unsigned public preview.
Core memory, tasks, qualified harnesses and hosted login/pairing/sync/recovery are
in scope. macOS, package installation, automatic updates and optional dependency
upgrades are deferred. Do not merge or publish during this implementation.

1. Correct PR19 OAuth history and reconcile evidence and PR dispositions.
2. Add version-checked candidate evidence and a protected publication workflow.
3. Compare deployed migration contents; deploy reviewed additive membership and
   matching functions; never recreate or print existing credentials.
4. Qualify final source, artifact contents and installed/hosted workflows.
5. Independently review, fix confirmed issues, report exact remaining blockers,
   and capture the final report in Mission Control.

Required checks: workspace Rust tests/Clippy with CI test-support features;
frontend lint/typecheck/tests/build; schemas/bindings/boundaries; dependency and
license checks; current Windows CI; NSIS payload/version/hash verification;
two fresh-profile and clean-OS acceptance; N-1 migration; actual harness and
two-device hosted acceptance; crash boundaries and four-hour exposed parser fuzzing.
Unavailable environments remain open. Preserve protocol 1.17 and published tags.

Public publication must consume a successful main-branch candidate with an
explicit source SHA and installer digest through a reviewer-protected environment.
An unsigned preview is not a waiver of installed or hosted acceptance.
