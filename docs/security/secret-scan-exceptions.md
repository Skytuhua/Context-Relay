# Secret-scan exception rationale

This ledger is the review authority for the exact immutable fingerprints in
`.github/repository.gitleaksignore`. It contains no matched payloads. An entry means only that the
specific historical object was inspected and found to be non-credential data serving a documented
security purpose; it is not a general allowlist.

## Exception policy

- Only an exact commit/path/rule/line fingerprint may be recorded. A changed fingerprint is a new
  active finding and must be investigated from the beginning.
- If a finding contains a real credential, revoke and rotate it at the issuer, remove it from the
  repository and Git history, and require a clean full-history scan before closing the incident.
- Broad regular-expression, path, or rule exclusions are forbidden. Scanner coverage, full-history
  traversal, redaction, and detector behavior must not be weakened to admit a fixture.
- `detector-literal` means non-secret source text used by a detector to recognize forbidden input.
  `synthetic-negative-test` means deliberately fabricated non-secret input used to prove rejection,
  redaction, or scanner behavior.
- Reviewers must inspect the exact historical Git object. Similar-looking current source or an older
  review statement is not sufficient evidence.

## Reviewed immutable fingerprints

### `7e5089dd4e433ddd552e91a9abb184225618079d:crates/native-runner/tests/real_sidecars_windows_v1.rs:aws-access-token:123`

- Historical commit: `7e5089dd4e433ddd552e91a9abb184225618079d`
- Historical path: `crates/native-runner/tests/real_sidecars_windows_v1.rs`
- Rule: `aws-access-token`
- Line: `123`
- Classification: `synthetic-negative-test`
- Non-credential basis: The historical line creates a deliberately fabricated access-key-shaped sentinel inside an isolated test fixture; it has no issuer, account, authority, or usable companion credential.
- Security purpose: The Windows real-sidecar test proves pinned Gitleaks returns the findings disposition for hostile input and does not honor an attacker-controlled ignore file in the scanned package.

### `7e5089dd4e433ddd552e91a9abb184225618079d:crates/native-runner/tests/macos-launcher-harness/tests/adapter_native.rs:aws-access-token:452`

- Historical commit: `7e5089dd4e433ddd552e91a9abb184225618079d`
- Historical path: `crates/native-runner/tests/macos-launcher-harness/tests/adapter_native.rs`
- Rule: `aws-access-token`
- Line: `452`
- Classification: `synthetic-negative-test`
- Non-credential basis: The historical line creates the macOS launcher harness counterpart of the deliberately fabricated access-key-shaped sentinel; it is test data with no issuer, account, authority, or companion credential.
- Security purpose: The native launcher harness proves the real scanner distinguishes clean input from findings while preserving the closed scanner configuration across the macOS process boundary.

### `d7855f58669beb6f6814d6450253761448edd5b5:apps/desktop/src/schema-parity.test.ts:private-key:77`

- Historical commit: `d7855f58669beb6f6814d6450253761448edd5b5`
- Historical path: `apps/desktop/src/schema-parity.test.ts`
- Rule: `private-key`
- Line: `77`
- Classification: `synthetic-negative-test`
- Non-credential basis: The historical value is deliberately fabricated key-shaped text in a TypeScript invalid-package fixture; it is not imported, parsed, issued, or usable as private key material.
- Security purpose: The desktop schema-parity test proves namespaced package extension data rejects secret-shaped active content instead of accepting opaque strings at the renderer boundary.

### `d7855f58669beb6f6814d6450253761448edd5b5:apps/desktop/src/schema-parity.test.ts:private-key:79`

- Historical commit: `d7855f58669beb6f6814d6450253761448edd5b5`
- Historical path: `apps/desktop/src/schema-parity.test.ts`
- Rule: `private-key`
- Line: `79`
- Classification: `synthetic-negative-test`
- Non-credential basis: The historical value is a second deliberately malformed key-shaped string in the bounded-extension negative fixture; it has no corresponding key object, issuer, or cryptographic use.
- Security purpose: This case keeps the TypeScript validator aligned with the protocol boundary for multiple key-like encodings rather than proving only one conveniently formatted rejection.

### `d7855f58669beb6f6814d6450253761448edd5b5:crates/protocol/tests/packages_v1.rs:private-key:85`

- Historical commit: `d7855f58669beb6f6814d6450253761448edd5b5`
- Historical path: `crates/protocol/tests/packages_v1.rs`
- Rule: `private-key`
- Line: `85`
- Classification: `synthetic-negative-test`
- Non-credential basis: The historical Rust fixture contains deliberately fabricated key-shaped extension text with no valid key object, issuer, account, or signing/decryption role.
- Security purpose: The protocol test proves `PackageManifestV1` rejects opaque secret-shaped values in namespaced extensions at deserialization before package data can cross the trust boundary.

### `d7855f58669beb6f6814d6450253761448edd5b5:crates/protocol/tests/packages_v1.rs:private-key:87`

- Historical commit: `d7855f58669beb6f6814d6450253761448edd5b5`
- Historical path: `crates/protocol/tests/packages_v1.rs`
- Rule: `private-key`
- Line: `87`
- Classification: `synthetic-negative-test`
- Non-credential basis: The historical value is the second deliberately malformed key-shaped string in the Rust package rejection fixture and is neither valid nor connected to any credential lifecycle.
- Security purpose: This companion case keeps Rust and TypeScript package-schema enforcement in parity across multiple key-like encodings and prevents a single-format validation blind spot.

### `3c2a371aef74f4962af64d0fe71545557244f21a:crates/core/src/hermes/yaml.rs:private-key:456`

- Historical commit: `3c2a371aef74f4962af64d0fe71545557244f21a`
- Historical path: `crates/core/src/hermes/yaml.rs`
- Rule: `private-key`
- Line: `456`
- Classification: `detector-literal`
- Non-credential basis: The historical line is a static textual marker inside `scan_text_secret`; it contains no key body, issuer data, account binding, or usable private key material.
- Security purpose: The marker lets the Hermes importer recognize and reject private-key-shaped content before imported YAML text can enter normalized context records.

### `6b144104d8a315038785dfdeaccdb13cdbca730d:crates/core/tests/hermes_adapter_v1.rs:private-key:406`

- Historical commit: `6b144104d8a315038785dfdeaccdb13cdbca730d`
- Historical path: `crates/core/tests/hermes_adapter_v1.rs`
- Rule: `private-key`
- Line: `406`
- Classification: `synthetic-negative-test`
- Non-credential basis: The historical Hermes YAML fixture uses deliberately fabricated key-shaped text with no valid key body, issuer, account, or cryptographic function.
- Security purpose: The adapter regression proves embedded secret text is removed from imported MCP and hook components rather than serialized into the normalized result.

### `6b144104d8a315038785dfdeaccdb13cdbca730d:crates/core/tests/hermes_adapter_v1.rs:curl-auth-header:399`

- Historical commit: `6b144104d8a315038785dfdeaccdb13cdbca730d`
- Historical path: `crates/core/tests/hermes_adapter_v1.rs`
- Rule: `curl-auth-header`
- Line: `399`
- Classification: `synthetic-negative-test`
- Non-credential basis: The historical YAML value is a deliberately fabricated bearer-header-shaped sentinel; it is not an issued token and has no provider, subject, scope, or usable authorization context.
- Security purpose: The adapter regression proves embedded command/header secrets are stripped from imported MCP and hook components before normalized serialization.

### `f98444a51754f5deaba2da9aa86f4463129a3380:crates/core/src/hermes/yaml.rs:private-key:94`

- Historical commit: `f98444a51754f5deaba2da9aa86f4463129a3380`
- Historical path: `crates/core/src/hermes/yaml.rs`
- Rule: `private-key`
- Line: `94`
- Classification: `detector-literal`
- Non-credential basis: The historical line is the earlier location of a static textual marker in `scan_text_secret`; it has no key body, issuer data, account binding, or private-key capability.
- Security purpose: The detector literal rejects private-key-shaped text during reviewed Hermes-state import, preventing secret-bearing YAML from becoming normalized context.

### `3c2a371aef74f4962af64d0fe71545557244f21a:crates/core/tests/hermes_adapter_v1.rs:curl-auth-header:2480`

- Historical commit: `3c2a371aef74f4962af64d0fe71545557244f21a`
- Historical path: `crates/core/tests/hermes_adapter_v1.rs`
- Rule: `curl-auth-header`
- Line: `2480`
- Classification: `synthetic-negative-test`
- Non-credential basis: The historical current-head fixture retains deliberately fabricated bearer-header-shaped text that has no provider, subject, scope, issuance record, or authorization value.
- Security purpose: The expanded Hermes adapter suite continues to prove the importer removes embedded header secrets from MCP and hook components after later adapter changes.
