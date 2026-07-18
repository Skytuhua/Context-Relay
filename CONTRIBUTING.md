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
