# PR 16 unfinished-work status — 2026-09-19

Scope of this session: verify and close what is closable autonomously on
branch `codex/windows-app-release` (PR #16) without merging, publishing, or
touching hosted state. Evidence gathered at revision `8891970` ("Bind package
approval to bytes, closure and scanner results"). All work performed on local
branch `plan/pr16-finish`.

## Closed this session

### The three Windows daemon integration failures — fixed upstream, verified

The continuation ledger (`pr16-release-continuation-2026-09-08.md`) records
three contextd library failures at revision `30589c0` (2026-09-14, CI run
`34765079727`). At current head `8891970` all three pass locally on Windows:

| Test | Result at `8891970` |
|---|---|
| `device_pairing_crosses_two_authenticated_daemons_without_exposing_joiner_safety` | ok, 12.41s |
| `hosted_pairing_crosses_two_daemons_and_resumes_lost_approval` | ok, 23.54s |
| `hosted_sync_receives_searchable_remote_memory_and_recovers_checkpoint_after_restart` | ok, 43.76s |

No source change was required; the intervening ~50 upstream commits resolved
them. No fix commits were produced by this session (nothing to fix).

### One-revision verification at `8891970`

- `cargo fmt --all -- --check`: pass.
- `cargo clippy --workspace --all-targets` with the four test-support
  features, `-D warnings`: pass (49.95s, clean).
- `cargo test --workspace --all-targets --locked` with the same features:
  **`TEST_EXIT=0` — 160/160 suites ok, 0 failed, 1,793 tests passed**
  (`CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 -j 6`).
- Frontend: lint pass, typecheck pass; `vitest --run` **45/45 files,
  389/389 tests pass** when run in isolation. An earlier 6-test failure
  window (timeout assertions) reproduced only while the full Rust suite ran
  concurrently on this machine — a local resource-contention artifact, not
  a source issue; CI's isolated job is green at the same revision.
- Sidecars re-hydrated for the branch: `target/sidecars/windows-x86_64/f7039e4d…`.

### Local build-environment facts (this machine)

- Full-suite runs require `export PATH="/c/Users/user/.cargo/bin:/c/Strawberry/perl/bin:$PATH"`
  (native Strawberry Perl; the Git Bash Perl breaks vendored OpenSSL — see repo `SETUP.md`).
- This drive filled to 100% during test linking (debug PDBs); `cargo clean`
  and `CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0` with `-j 6`
  are the sustainable local invocation.

## Awaiting user action (cannot be automated)

1. **Pairing pepper** — set `CONTEXT_RELAY_PAIRING_PEPPER` (64 hex chars,
   e.g. `openssl rand -hex 32`) as an Edge Function secret for project
   `brvzuycnxoswdzzipgvx` via the Supabase dashboard. The previous automated
   attempt was policy-rejected; do not retry automation. This unblocks
   deploying `supabase/functions/pairing` (adapter validates the secret at
   `adapter.mjs:17`) and finishing hosted V2 pairing acceptance.
2. **OAuth consent** — per the ledger, GitHub sign-in remained disabled in
   regular Chrome on 2026-09-14 and the prepared OAuth registration is
   unsubmitted. Submit it to unblock installed sign-in acceptance.
3. **Installer acceptance** — build/qualify candidate N (`0.1.1`), qualify
   N−1 (`1468327`) as internal predecessor, and run the two fresh-profile
   passes on this physical PC. Native installer UI steps are user-only.

## Explicitly open upstream (not attempted here)

- Five 4-hour fuzz targets; crash injection at durable boundaries.
- Dependency alert 23 (`glib` RUSTSEC) disposition; alerts 37–40 (js-yaml,
  vitest) pending triage.
- OpenSSL `ossl_static.pdb` packaging disposition — repo docs
  (`docs/verification/pr16-handoff-2026-09-14.md`) say keep open; observed
  again locally, mitigated locally by building without debuginfo.
- Apple/macOS requalification (approved deferral; four CI contexts skip).
- Hosted V2 pairing/public-history transport acceptance and installed
  login/sync/recovery acceptance (blocked by user actions above).

## Delimitation

No merge, publish, hosted-state change, secret creation, or production-daemon
run was performed. Local verification establishes component behavior at one
revision; it does not close hosted or installed acceptance rows.
