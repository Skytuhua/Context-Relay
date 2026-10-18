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

On machines with limited free memory, reduce Cargo's parallelism:

```sh
cargo build --workspace --all-targets -j 2
```

The workspace builds native dependencies including SQLCipher and OpenSSL. Compiling many targets at once can exhaust available memory. If a compiler process terminates without a Rust diagnostic, inspect the earlier build output and the operating system's resource reports, then retry with fewer jobs. See [Debugging](#debugging) for follow-on errors.

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

`E0463` means the compiler could not find a required crate. Start with the first error in the build log: a missing dependency, a toolchain or target mismatch, and an interrupted compilation require different fixes.

If the previous build shows a compiler process was terminated, retry with limited parallelism (`-j 2`, see [Rust build memory](#rust-build-memory)). If the error persists and the log points to a stale artifact, use `cargo clean -p <affected-package>` with the same target directory, then rebuild that package. Check the diagnosis before cleaning a shared build directory or changing dependency versions.

### The frontend test suite cannot find a package

A `Cannot find package` error after switching branches can mean the installed dependency links no longer match the branch's lockfile. Run `pnpm install --frozen-lockfile` in the repository root to reconcile them, then retry the failing command. `--lockfile-only` updates the lockfile without installing packages into `node_modules`.

### A dialog test throws `showModal is not a function`

Check which dialog methods the installed test environment provides. When `HTMLDialogElement.showModal` or `close` is missing, stub the missing methods before rendering a component that opens a dialog, and restore them after the test. Keep assertions for opening, closing, and focus behavior so the stub does not hide a regression.
