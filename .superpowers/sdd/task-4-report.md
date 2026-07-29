# Task 4 Report: Hermes Isolated Validation and Native Boundary

## Status

Implemented and committed as a separate Task 4 change. The Hermes adapter now validates a reviewed,
redacted configuration projection inside a unique adapter-owned home and implements the complete
native transaction boundary. Focused Hermes, Claude Code, Codex, core-library, lint, formatting, and
frontend verification passed. The full workspace run remains blocked only by the repository's
pre-existing macOS native-filesystem topology gate, described under **Verification exception**.

## Files

- Created `adapters/hermes/capabilities.md`.
- Modified `crates/core/src/hermes.rs`.
- Modified `crates/core/src/hermes/import.rs`.
- Modified `crates/core/src/hermes/render.rs`.
- Modified `crates/core/tests/hermes_adapter_v1.rs`.
- No Claude Code or Codex fixture/test correction was required.
- No direct `gateway.rs` edit was required; Task 4 uses the existing bounded gateway inspection API.

## TDD evidence

The required focused tests were introduced before the implementation.

```text
cargo test -p context-relay-core --test hermes_adapter_v1 \
  effective_validation_uses_only_isolated_nonsecret_home
```

RED: failed with `HarnessUnsupported: Hermes adapter phase is not available`.

```text
cargo test -p context-relay-core --test hermes_adapter_v1 \
  native_adapter_rechecks_gateway_profile_executable_and_digests
```

RED: failed at the baseline `reprobe_live_state` assertion because the complete native adapter
boundary was not implemented.

The injection-specific validation tests live in the private `hermes.rs` test module, keeping
`HermesValidationRequest` and `validate_effective_with` private. Public integration coverage
exercises `HarnessAdapter` and `NativeAdapter`.

## Implementation

### Isolated validation

- Validates the receipt, requires full capability, and rechecks profile, executable, project, and
  working-directory bindings before reading effective files.
- Reimports only safe Hermes surfaces, validates managed Markdown markers and YAML topology, and
  renders a deterministic block-style YAML document from the reviewed redacted projection.
- Creates the stage below the canonical system temporary directory using 16 OS-random bytes. The
  stage and config are owner-only on Unix. An RAII guard validates the generated child path and
  removes only that exact directory on success or failure.
- Populates only `config.yaml`, `memories/`, and an empty adapter-owned `home/`.
- Executes exactly `hermes config check` with null stdin and bounded stdout/stderr.
- Clears the inherited environment and supplies only `HERMES_HOME`, `HOME`, `NO_COLOR=1`,
  `TERM=dumb`, and the minimal platform `PATH`.
- Rechecks the attested executable digest immediately before process creation.
- Enforces a 30-second timeout and 65,536-byte stream caps.
- Strips ANSI sequences and parses only the frozen 0.18.2/0.18.1 output contracts. Structural
  deviations, invalid UTF-8, stderr, timeout, oversized output, and nonzero status fail closed.
  Missing credentials become the non-secret `isolated_credential_missing` finding.

### Native boundary

- Implements `NativeAdapter` for Hermes with exact harness, adapter version, executable path/hash,
  profile binding, canonical root, project binding, and approval-class checks.
- Rejects a live or unverifiable gateway only for active transactions.
- Rechecks every approved target digest or approved absence.
- Requires the staged semantic hash and scanner hash.
- Requires receipt plan ID and resulting digests to equal intended mutations in order.
- Maps boundary failures to stable messages that omit native operational/credential paths and
  contents.
- The rollback regression mutates config, managed Markdown, memory, and hook targets, injects a
  later failure, and verifies restoration of bytes and repository-supported restorable metadata.

### Capability matrix

`adapters/hermes/capabilities.md` contains the required exact surface table, supported versions
0.18.2 and 0.18.1, explicit profile binding, validation command/environment, five stable lossy
mapping reasons, and import-only behavior for wrappers, unknown versions, and unpatchable YAML.

## Verification

Passed:

```text
cargo test -p context-relay-core --test hermes_adapter_v1
  43 passed
cargo test -p context-relay-core hermes::tests
  16 passed
cargo test -p context-relay-core --test claude_code_adapter_v1
  7 passed
cargo test -p context-relay-core --test codex_adapter_v1
  33 passed
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
pnpm test --run
  5 files, 28 tests passed
git diff --check
```

The security scans found:

- sensitive-name matches only in denylist logic, safe labels/documentation, and test canaries;
- process execution only in isolated `config check`, version discovery, and bounded gateway
  inspection;
- one pre-existing `serde_yaml_ng::to_string` in `hermes/yaml.rs`, limited to a reviewed replacement
  subtree rather than full-document serialization;
- only the owned Task 4 files changed.

## Verification exception

`cargo test --workspace --all-features` did not become fully green:

- `contextd` produced ten transport failures inside the restricted sandbox, then passed 20/20 when
  rerun outside it, confirming a sandbox-only failure.
- Nine `native_filesystem_macos_v1` tests fail at the repository's existing `UnsafeTopology` native
  filesystem gate, including when run outside the sandbox. They fail before entering the Hermes
  paths changed by Task 4 and are therefore recorded as pre-existing/out of scope.

No unsupported test was weakened or bypassed.

## Review

Self-review covered profile isolation, secret flow, deterministic YAML projection, gateway PID
reuse/active-state handling, receipt and digest freshness, stage cleanup, rollback, and stable
non-secret errors. An independent focused code review was requested before commit; its actionable
findings and resolutions, if any, are recorded in the final handoff.
