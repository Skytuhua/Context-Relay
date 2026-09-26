# Contributing

By intentionally submitting a contribution to this repository, you license it under Apache-2.0.

You must have the right to submit a contribution. Never commit credentials or test secrets. Pull requests must include relevant tests and pass the repository checks.

## Setup

Install Rust 1.97.1 through rustup and Node 24.14.0, then install the pinned JavaScript package manager and dependencies:

```sh
corepack enable
corepack prepare pnpm@11.9.0 --activate
pnpm install --frozen-lockfile
```

### Rust build memory

Limit cargo's parallelism on machines with less than about 16 GB of free memory:

```sh
cargo build --workspace --all-targets -j 2
```

The workspace pulls in SQLCipher and OpenSSL through the Tauri dependency graph. Building every target at default job counts can exhaust memory and kill a `rustc` process partway through, which then surfaces as unrelated `E0463: can't find crate for context_relay_core` errors on the next run rather than as an out-of-memory message. A killed compile leaves a partial `target/debug/deps`, so clear it if the follow-on errors do not go away. See [Debugging](#debugging) for the full symptom list.

## Verification

Run the same checks as CI:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
pnpm lint
pnpm typecheck
pnpm test --run
pnpm build
pnpm check:bindings
cargo deny check
node --test scripts/check-license-metadata.test.mjs
```

Use `pnpm generate:bindings` after changing exported Rust protocol types, and commit the updated `apps/desktop/src/bindings.ts`.

## Debugging

### A Rust build dies with `E0463: can't find crate`

This is almost always a killed compile, not a broken dependency graph. The sequence is:

1. `cargo build` stops with `error: could not compile '<crate>'` and a `rustc` line ending in `exit code 15`, with no preceding error in that crate
2. the next run fails with `E0463` for `context_relay_core` or `context_relay_contextd`, in files you did not touch

Rebuild with limited parallelism (`-j 2`, see [Rust build memory](#rust-build-memory)). If the `E0463` errors persist, the previous run left a partial artifact behind: remove `target/debug/deps` and rebuild. Do not "fix" this by changing dependency versions.

### The frontend test suite cannot find a package

A module resolves as `undefined` or `Cannot find package` after switching branches usually means a stale workspace symlink rather than a real dependency problem. `pnpm install --frozen-lockfile` in the repository root restores it; `--lockfile-only` does not, because it never links anything into `node_modules`.

### A dialog test throws `showModal is not a function`

The test environment implements neither `HTMLDialogElement.showModal` nor `close`. Stub both in `beforeEach` before rendering a component that opens a dialog.
