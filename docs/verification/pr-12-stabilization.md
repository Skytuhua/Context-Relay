# PR #12 stabilization ledger

This ledger records the locally reproduced stabilization evidence for the preserved draft PR #12
stack before it is pushed for authoritative hosted execution. The v1 master implementation plan is
the product and security authority; this document narrows every claim to its actual execution plane.

## Immutable baseline and repair range

| Item | Exact value |
| --- | --- |
| PR base and merge base | `367b32e15d06a7d46b6b8d04676d38dc368ae235` |
| Original PR head | `3c2a371aef74f4962af64d0fe71545557244f21a` |
| Original PR-head tree | `b1f20f83f6a6f89f7f433b01dc29127b4c823216` |
| Baseline tree | `f83ff99d9a522aec3e3705daccf412d3f93a5249` |
| Recorded repair range | `3c2a371aef74f4962af64d0fe71545557244f21a..f8376450892aed6395268645c7f791f8ebe2b47f` |
| Publication state at capture | On 2026-08-10 at `f8376450892aed6395268645c7f791f8ebe2b47f`, the repair range was local only and had not been pushed. This is capture-time evidence, not a promise about later publication. |

The range is additive. It preserves the original PR head and contains no force-push, reset, history
rewrite, credentialed provider mutation, or release action.

## Exact repair sequence

| Commit | Purpose / disposition |
| --- | --- |
| `224ba8df8c270644f24198fa551fd6485fb949f9` | Establish the v1 audit baseline, threat model, and amendment ledger. |
| `61babf07cbce29393e4971e749bf4135b9f14d04` | Complete evidence links required by the first independent review. |
| `593c9d2f8965a26f59790a61821007c0acea99e0` | Record the reviewed baseline progress without promoting release status. |
| `fc0f262220b95687f5ad89eee02fe40a4d7a65b9` | Pin and minimize the Supabase workflow and add five exact reviewed historical fingerprints. |
| `ab7b3b2417d7a2b66f073fed0c695e9f55e688d5` | Record the approved workflow/secret-scan repair. |
| `4b57cbc9a176bea55a8212b9aff286a49269fbc3` | Restore strict Rust contracts, fixtures, and parallel temporary-vault safety. |
| `38331da30bdf935cf5c09afc9cc517c819b3c7b9` | Record the approved Rust stabilization and its native-host limits. |
| `f5f0eee49c12aaf140bc74b8d7f0473b2a3fa3f4` | Repair Windows path ownership, native encoding, runtime-target parity, and target-only lints. |
| `a1c1db7f2d24a9fabddaeac5def3256e623033a1` | Close the independently found opaque-WTF-16 capability rejection. |
| `2daee6dffb719e959935955b22987d2aceb5b84b` | Record the reviewed Windows parity repair and pending execution plane. |
| `8261053475431a304f2177935d7a5ed4d027a60e` | Derive Windows helper deadlines from the sealed command limits. |
| `981fa58deec0e49520f25728c8e245e8726d62d7` | Remove the independently found raw/default-deadline exchange bypass. |
| `3599b7b4b60d0da700f15608d124fb4c4b348780` | Record the reviewed timeout repair and pending Win32 execution. |
| `85a59ed519b5bd24b78e9af384c347626a2e4d5b` | Split required CI gates by responsibility and supported host. |
| `db55e76aeb7f3b2e0ea42fe2caf64f7987f1bcad` | Make the independently visible whitespace gate inspect exact committed event ranges. |
| `f8376450892aed6395268645c7f791f8ebe2b47f` | Record the approved independent-gate repair without claiming a remote run. |

## Graphify navigation snapshot

The local 2026-08-10 Graphify snapshot is a non-committed host artifact identified by visualization
`019fe7de-353d-76b2-9e16-530e93962e39`, beneath
`context-relay-graph/graphify-out/GRAPH_REPORT.md` in the Codex visualization store. Its report
covers 453 supported files, 12,456 nodes, 39,200 post-build directed edges, and 427 communities.
Integrity accounting recorded 1,792 dangling edges and 2,060 collapsed directed endpoint pairs.
The generated report exposes the corpus/node/edge/community counts but does not print those two
integrity counters. The graph is therefore a navigation aid only; source review, tests, and
execution ledgers remain the evidence authority.

## Local execution environment

| Component | Locally verified value |
| --- | --- |
| Host | macOS `26.5.2`, arm64 |
| Rust compiler | `rustc 1.97.1 (8bab26f4f 2026-07-14)` |
| Cargo | `cargo 1.97.1 (c980f4866 2026-06-30)` |
| Isolated Rust homes | `CARGO_HOME=/private/tmp/context-relay-v1-cargo-20260810`; `RUSTUP_HOME=/private/tmp/context-relay-v1-rustup-20260810` |
| Canonical local temporary root | `/private/var/folders/zf/_0sgs1550fn4l5mmv9gf3j540000gn/T/` |
| Bundled Node | `v24.14.0` |
| Bundled local pnpm launcher | `11.16.0`; workflows independently install the pinned `pnpm@11.9.0` |
| Gitleaks | `8.30.1` at `/private/tmp/context-relay-gitleaks-8.30.1/gitleaks` |
| Cargo Deny | `0.20.2` |

Windows checks described as cross-target compile/lint used `x86_64-pc-windows-msvc`; they did not
execute Win32 process, job-object, filesystem, or IPC behavior.

## Reproduced original blockers

| Blocker at the original head | Evidence plane and observed failure |
| --- | --- |
| Mutable Supabase workflow provenance and secret findings | The test-first workflow contracts failed four of six assertions before repair. A Gitleaks 8.30.1 full-history run reproduced five not-yet-reviewed findings in addition to the six pre-existing exact exceptions. |
| Strict Rust lint and stale fixtures | Local Rust 1.97.1 strict Clippy reproduced the two overlong builders and 744-byte `AdmissionDecision`; focused runs also reproduced the stale protocol status, colliding temporary vault names, and invalid schema-v10 migration fixture. |
| Windows `contextd` path/runtime failures | Immutable GitHub run `31328633774`, job `93283104812`, at the original head reported 41 passed and 7 failed. One failure used a mixed Unix/Windows temporary path; six decoded Windows bytes as the macOS platform. This is public Windows evidence, not a local Windows reproduction. |
| Windows Osemgrep outer timeout | The same immutable run, job `93292663233`, built the candidate and then returned `Failed(TimedOut)`: the outer 30-second launcher deadline could terminate the helper before its sealed 90-second Osemgrep limit. The portable source contract reproduced the 30-second mismatch locally. |
| Lint-masked required gates | The CI topology contract failed all six initial assertions because lint, tests, daemon policy, generated artifacts, licenses, dependency policy, and whitespace were serialized, while frontend/native visibility and supported-host matrices were incomplete. |
| No-op committed-whitespace check | Independent review added an executable range contract. It first failed two assertions for missing full history and event-range selection, then one assertion for accepting a malformed current SHA. |

## Repaired gates and local evidence

| Gate | Repair and evidence available before remote execution |
| --- | --- |
| Workflow provenance | Every third-party action is full-SHA pinned; ordinary checkouts do not persist credentials; permissions are least privilege. Supabase and workflow contract suites passed locally. |
| Secret scan | The ignore file remains exactly 1,103 bytes with SHA-256 `651da29e101f61580d789284520431ca8aaf944f933394b86130149b865d6032`. All eleven entries are immutable fingerprints with a tracked one-to-one rationale. The exact Gitleaks full-history command below returns a JSON array with zero findings. |
| Strict Rust contracts | Typed request objects replace overlong signatures, the admitted payload is boxed, target/test `cfg` defects are corrected, and fixture regressions have focused tests. Strict workspace Clippy, formatting, focused suites, and the maximum locally runnable workspace remainder passed. |
| Windows path and runtime parity | Tests own platform-aware temporary directories; lossless Windows path fixtures cover drive, UNC, extended, reserved, Unicode, malformed UTF-16, and opaque WTF-16 cases. Runtime target selection is fail-closed and remains approval-bound. Focused core/contextd behavior, strict local workspace Clippy, and formatting passed on macOS. The attempted MSVC core/contextd cross-check stopped in vendored OpenSSL and `onig_sys` host prerequisites before project crates compiled; Windows compilation and execution remain pending. |
| Windows helper timeout | The only public exchange accepts the same sealed `HelperRunRequest` used for staging and serialization. RuleSync/Gitleaks receive 35 seconds and Osemgrep 95 seconds including bounded shutdown grace; invalid bounds fail closed. Portable and Windows-target compile/lint contracts passed. |
| Independent CI visibility | Formatting, supported-host lint/tests, daemon ownership, bindings, schemas, licensing, dependency policy, exact committed whitespace, four frontend gates, and native builds are separately visible with no lint dependency. Thirty-eight workflow contracts and strict YAML parsing passed locally. |
| Ordinary feature scope | Both supported-host Rust matrices select all four ordinary `test-support` features. The candidate-only Semgrep feature remains confined to its two exact ignored qualification tests; no workspace-wide `--all-features` claim is made. |

The reproducible full-history command is:

```text
/private/tmp/context-relay-gitleaks-8.30.1/gitleaks --no-banner --no-color --log-level=error --redact=100 --exit-code=10 --report-format=json --report-path=/private/tmp/context-relay-gitleaks-report-after-task6.json --gitleaks-ignore-path=.github/repository.gitleaksignore --ignore-gitleaks-allow --max-target-megabytes=0 --max-archive-depth=0 --max-decode-depth=1 --timeout=30 '--diagnostics=' git '--log-opts=--all' .
```

Success requires exit 0 and a parsed JSON top-level array containing zero findings. The exact
ignore-file byte count and digest above remain independently locked by workflow and static tests.

## Independent review and fix history

- The baseline review required protocol-handshake/runtime-contract and Task 17 evidence links;
  `61babf07cbce29393e4971e749bf4135b9f14d04` supplied them, and re-review approved the slice.
- The workflow/secret repair and strict Rust repair were independently approved without actionable
  findings. A sandboxed MCP rerun limitation was resolved by an equivalent controller execution,
  which passed all nine real-socket cases; this did not resolve native-host gates.
- The Windows parity reviewer found premature strict UTF-16 conversion. A failing full-capability
  regression preceded `a1c1db7f2d24a9fabddaeac5def3256e623033a1`; fresh review found no issue.
- The timeout reviewer found a reachable raw/default-deadline API. A failing reachability contract
  preceded `981fa58deec0e49520f25728c8e245e8726d62d7`; fresh review found no issue.
- The CI reviewer found that a clean-checkout whitespace command inspected no committed range.
  Failing range and SHA-validation regressions preceded
  `db55e76aeb7f3b2e0ea42fe2caf64f7987f1bcad`; fresh review approved the full range.

## Initial execution-plane limits (2026-08-10)

- The repaired stack has not yet run on GitHub-hosted Windows x64 or macOS arm64. Workflow
  expansion, actual Win32 behavior, hydrated Osemgrep timing/cleanup, the canonical APFS fixture,
  and every new required check remain pending the draft-PR run. T03 remains `partial`.
- The Codex-managed macOS tree adds `com.apple.provenance`, so the unmodified full workspace is not
  claimed green locally. The fail-closed native topology tests and launcher descriptor-census gate
  remain authoritative and are not skipped or weakened in CI.
- Cross-target compilation is not Windows execution. A prior successful macOS native-isolation job
  at the original head does not verify the repaired stack.
- No credentialed Supabase project, hosted RLS/Storage/Realtime transport, OAuth or GitHub App,
  physical-device matrix, signing/notarization, deployment, publication, external testing, or
  release evidence was created by this stabilization work.
- This ledger establishes local pre-publication evidence only. It does not complete Tasks 15–24,
  clear any release blocker, authorize a push/merge, or replace two clean physical release runs.

## Windows follow-up (2026-08-31)

The initial remote-execution gap above is superseded by
[run 33357305605](https://github.com/Skytuhua/Context-Relay/actions/runs/33357305605)
at `89d832b`. Both native builds, both strict Rust lint jobs, macOS Rust tests,
macOS native isolation, and both candidate native Semgrep builds passed. Windows
Rust tests and Windows native isolation failed; downstream native publication
was skipped. This is not an all-green run, and PR #12 must remain draft.

### Root causes and focused repairs

| Boundary | Reproduction | Repair |
| --- | --- | --- |
| Windows IPC under concurrent connection load | The transport called `ClientOptions::open` once and mapped `ERROR_PIPE_BUSY` to permanent `Io`. The real 64-call test then waited without a deadline for calls that never reached the worker. Two portable regressions failed before the retry implementation. | Retry only busy opens at 50 ms intervals under one five-second deadline; preserve missing/denied errors and never replay an authenticated request. Add a Windows test that occupies one pipe instance and connects the next client while accept publishes the replacement. Bound the 64-call test's enqueue/completion waits and release its worker on panic. |
| Codex setup fixtures | Both Windows setup-chain tests failed in the incomplete Rust run. Independently, parsing the frozen fixture after inserting `C:\Users\runner\project with spaces` failed with an invalid Unicode escape. | Serialize the complete quoted TOML project key rather than inserting unescaped path bytes. Preserve plain-text substitution. Regressions cover drive, verbatim, UNC, Unicode, spaces, quoted paths, and silently misdecoded escape sequences in both core fixture helpers. |
| Windows ACL inspection fixture | Job `99395540076` first failed at `windows.rs:2546`: `security_descriptor(held.parent().unwrap())`, before private-file creation. Seven later failures were mutex-poison cascades. | Open a separate test-only parent handle with `READ_CONTROL` for `GetSecurityInfo`. Keep production traversal handles and owner-only creation checks unchanged. A source-contract regression failed before this repair. |

The pipe behavior is documented by
[Tokio's client options](https://docs.rs/tokio/latest/tokio/net/windows/named_pipe/struct.ClientOptions.html#method.open).
The ACL handle requirement is documented by
[Microsoft's GetSecurityInfo contract](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo).
Context7 returned the same Tokio busy-pipe guidance; no authentication configuration was changed.

Local verification is macOS execution plus Windows cross-compilation, not Win32
runtime evidence. The first post-repair macOS MCP end-to-end run passed all ten
tests, including real sockets, setup/watch/review, cancellation, and the 64-call
case. Both local IPC and native-runner Windows all-target checks passed. The
three native ACL source contracts passed. The full candidate's clean Windows
runtime checks remain a mandatory next gate; no tests or security checks were
disabled to obtain these results.

The complete local IPC suite subsequently passed 46 unit tests and 28 integration
tests on macOS, including six portable retry/cancellation regressions. Strict
Windows-target Clippy passed for local IPC and native-runner; macOS all-target
Clippy passed for MCP/native-runner with the ordinary MCP test-support feature.
An independent scoped review found no actionable issues and approved the changes
for candidate CI only, explicitly not for merge. T07 is returned to `partial`
until the Windows runtime repair has authoritative evidence.

Final targeted results (Rust 1.97.1, macOS arm64):

| Command after `cargo +1.97.1` | Passed |
| --- | ---: |
| `test -p context-relay-local-ipc --all-targets --features test-support` | 46 unit + 28 integration |
| `test -p context-relay-core --features test-support --test codex_adapter_v1 --test primary_memory_setup_v1` | 66 + 9 |
| `test -p context-relay-context-mcp --features test-support --test end_to_end_v1 -- --nocapture` | 10 |
| `test -p context-relay-contextd --features test-support --test authoritative_memory_v1 -- --nocapture` | 4 |
| `test -p context-relay-native-runner --test native_fs_windows_security_api_v1` | 3 |

These are 166 distinct targeted cases, not a clean full-workspace or release
claim. The daemon memory suite initially had three `Transport` failures inside
the restricted sandbox; its unchanged rerun with real local-socket access
passed all four cases. Its printed simulated Hermes-commit panic is intentional
fault injection and the test passes. The MCP suite was repeated after all four
fixture helpers were repaired and again passed all ten cases. Scoped formatting
and whitespace checks passed. Pending local Task 17 edits were present during
these runs but will not be included in this repair commit; clean-checkout CI
must verify the committed candidate independently.

The unfinished Task 17 hosted account-lifecycle implementation is deliberately
excluded from these stabilization changes. No hosted migration, production
configuration, signing, publication, or release action is authorized by this
evidence.
