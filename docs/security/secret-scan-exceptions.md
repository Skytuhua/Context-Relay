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
- `synthetic-public-test-vector` means a fixed non-secret identifier or public cryptographic
  verification value used for deterministic cross-language equality, binding, and hostile-input tests.
- `non-secret-source-or-metadata` means exact source syntax or content-identity metadata that carries no
  authentication, signing, decryption, bearer, account-access, or issuer authority.
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

### `b357b29ad4379fae191a288fb653dd55e69f340c:crates/core/src/hermes/yaml.rs:private-key:464`

- Historical commit: `b357b29ad4379fae191a288fb653dd55e69f340c`
- Historical path: `crates/core/src/hermes/yaml.rs`
- Rule: `private-key`
- Line: `464`
- Classification: `detector-literal`
- Non-credential basis: The exact squash-merge object was inspected at lines 464–466. These are static string comparisons in `scan_text_secret`, with no key body, issuer, account, or private-key capability. They match the detector logic independently inspected in the earlier historical object at `3c2a371aef74f4962af64d0fe71545557244f21a`.
- Security purpose: The comparisons reject private-key-shaped content before Hermes YAML enters normalized context. Squashing PR #12 gave the same detector a new immutable commit and line fingerprint; this entry admits only that inspected object and leaves every detector and full-history scanning enabled.

### `770a39d5754f22039cc9267932aa43bb7260d99c:crates/core/tests/fixtures/hosted-enrollment-proof-v1.json:generic-api-key:3`

- Historical commit: `770a39d5754f22039cc9267932aa43bb7260d99c`
- Historical path: `crates/core/tests/fixtures/hosted-enrollment-proof-v1.json`
- Rule: `generic-api-key`
- Line: `3`
- Classification: `synthetic-negative-test`
- Non-credential basis: The exact historical Git object contains deterministic fixture identifiers and public cryptographic material. Its companion Rust test uses fixed synthetic device seeds. The JSON contains neither a private key nor a provider-issued credential; read-only review confirmed the exact object.
- Security purpose: The fixture verifies cross-language enrollment-proof parity and rejection of substituted reservation, user, session, nonce, record, key or signature.

### `5bd19cfc2125ddaa1e101ef4bd80d8923a114955:crates/core/tests/fixtures/hosted-pairing-approval-v1.json:generic-api-key:14`

- Historical commit: `5bd19cfc2125ddaa1e101ef4bd80d8923a114955`
- Historical path: `crates/core/tests/fixtures/hosted-pairing-approval-v1.json`
- Rule: `generic-api-key`
- Line: `14`
- Classification: `synthetic-negative-test`
- Non-credential basis: The exact historical JSON object was inspected. The matched issuer signing key is public Ed25519 verification material in a synthetic pairing vector, not a private seed, bearer token or provider-issued credential. The canonical certificate embeds this public key; companion Rust and Edge tests verify the signatures and reject substituted authority. No credential exists to revoke.
- Security purpose: Frozen cross-language pairing fixtures test canonical approval verification and rejection of altered requests, issuer keys and session-bound proofs. Only this immutable historical fingerprint is admitted; full-history scanning and all detector rules remain enabled.

### `1d1ee66c443e50d824ea10224e9f1e517582592d:crates/core/tests/fixtures/hosted-pairing-approval-v1.json:generic-api-key:8`

- Historical commit: `1d1ee66c443e50d824ea10224e9f1e517582592d`
- Historical path: `crates/core/tests/fixtures/hosted-pairing-approval-v1.json`
- Rule: `generic-api-key`
- Line: `8`
- Classification: `synthetic-negative-test`
- Non-credential basis: The exact historical JSON object was inspected. The matched issuer signing key is public Ed25519 verification material in a synthetic pairing vector, not a private seed, bearer token or provider-issued credential. The canonical certificate embeds this public key; companion Rust and Edge tests verify the signatures and reject substituted authority. No credential exists to revoke.
- Security purpose: Frozen cross-language pairing fixtures test canonical approval verification and rejection of altered requests, issuer keys and session-bound proofs. Only this immutable historical fingerprint is admitted; full-history scanning and all detector rules remain enabled.

### `1d1ee66c443e50d824ea10224e9f1e517582592d:crates/core/tests/fixtures/hosted-pairing-approval-v1.json:generic-api-key:10`

- Historical commit: `1d1ee66c443e50d824ea10224e9f1e517582592d`
- Historical path: `crates/core/tests/fixtures/hosted-pairing-approval-v1.json`
- Rule: `generic-api-key`
- Line: `10`
- Classification: `synthetic-negative-test`
- Non-credential basis: The exact historical JSON object was inspected. The matched recovery-root signing key is public Ed25519 verification material in a synthetic pairing vector, not a private seed, bearer token or provider-issued credential. The canonical certificate embeds this public key; companion Rust and Edge tests verify the signatures and reject substituted authority. No credential exists to revoke.
- Security purpose: Frozen cross-language pairing fixtures test canonical approval verification and rejection of altered requests, issuer keys and session-bound proofs. Only this immutable historical fingerprint is admitted; full-history scanning and all detector rules remain enabled.

### `f4ab27c7edb4d5402d96ea21d62cf51a4c25f46e:docs/protocols/historical-key-transfer-v1.md:generic-api-key:128`

- Historical commit: `f4ab27c7edb4d5402d96ea21d62cf51a4c25f46e`
- Historical path: `docs/protocols/historical-key-transfer-v1.md`
- Rule: `generic-api-key`
- Line: `128`
- Classification: `synthetic-negative-test`
- Non-credential basis: The exact historical Git blob was inspected. The matched label introduces an X25519 public value independently reproduced from fixed synthetic test input. It is public verification data, not a private key, bearer token or provider-issued credential. The adjacent envelope contains dummy ciphertext, not usable encrypted material. Independent read-only review confirmed the derivation; no credential exists to revoke.
- Security purpose: The frozen page and authenticated-data vectors support canonical encoding verification and hostile-input rejection in historical key transfer. This exception admits only the inspected historical fingerprint; all detector rules, redaction and full-history scanning remain enabled.

### `924348a36900e89df6bc8b41fa6162127c24b8b3:crates/core/tests/fixtures/hosted-recovery-claim-v2.json:generic-api-key:2`

- Historical commit: `924348a36900e89df6bc8b41fa6162127c24b8b3`
- Historical path: `crates/core/tests/fixtures/hosted-recovery-claim-v2.json`
- Rule: `generic-api-key`
- Line: `2`
- Classification: `synthetic-public-test-vector`
- Non-credential basis: The exact historical field is a fixed UUID subject identifier, not a bearer token, private key, session credential or provider secret. Its bytes match the repository deterministic fixture-ID family at fixed index 33, and the static JSON is read directly by the Rust and Edge tests rather than populated at test runtime. Its companion session UUID is separate, and the Edge verifier explicitly rejects substituting the user UUID for that session binding.
- Security purpose: The public/encrypted cross-language recovery vector proves exact V2 claim and possession-proof binding to the synthetic user/session pair, and drives truncation, signed-field mutation, wrong-session and publication-error rejection cases.

### `924348a36900e89df6bc8b41fa6162127c24b8b3:crates/core/tests/fixtures/hosted-pairing-approval-v2.json:generic-api-key:19`

- Historical commit: `924348a36900e89df6bc8b41fa6162127c24b8b3`
- Historical path: `crates/core/tests/fixtures/hosted-pairing-approval-v2.json`
- Rule: `generic-api-key`
- Line: `19`
- Classification: `synthetic-public-test-vector`
- Non-credential basis: The exact historical field is a 32-byte Ed25519 public verification key in the deterministic V2 pairing fixture, not a private seed, bearer token or provider-issued credential. The retained PostgreSQL/Edge test constructs its test-only private key from a fixed repeated-byte seed, derives the public SPKI key and requires exact equality with this fixture field before signing. Only the public key is stored in the JSON.
- Security purpose: Cross-language pairing tests use this public value to verify the canonical approval and hosted possession proof, then reject every changed trusted field, changed request digest, changed membership signature, malformed signature and truncated canonical payload.

### `7d736642caeec1e4d71cc3d0421df6a471247486:crates/core/src/vault/membership/activation.rs:generic-api-key:92`

- Historical commit: `7d736642caeec1e4d71cc3d0421df6a471247486`
- Historical path: `crates/core/src/vault/membership/activation.rs`
- Rule: `generic-api-key`
- Line: `92`
- Classification: `non-secret-source-or-metadata`
- Non-credential basis: The exact historical match is part of a static parameterized SQLite INSERT/ON-CONFLICT statement. The detector joined the SQL `excluded.key_epoch` identifier and adjacent assignment text; runtime device, source-hash, epoch and signature values enter through numbered bound parameters. The line contains no credential literal or authority-bearing value.
- Security purpose: The query atomically records the already verified current membership activation and its signature. This exception admits only the detector's exact historical false-positive fingerprint; SQL source, scanner rules and full-history traversal remain enabled.

### `6c3bd9807dce57eecf8335da9730048c8f156942:docs/verification/pr16-windows-shared-acceptance.csv:generic-api-key:322`

- Historical commit: `6c3bd9807dce57eecf8335da9730048c8f156942`
- Historical path: `docs/verification/pr16-windows-shared-acceptance.csv`
- Rule: `generic-api-key`
- Line: `322`
- Classification: `non-secret-source-or-metadata`
- Non-credential basis: The exact historical match crosses the end of updater/Authenticode procedure prose into the next CSV field, `SourceFileSha256`. That 64-character lowercase hexadecimal field independently equals the SHA256 of the row's pinned `docs/context-relay-v1-implementation-plan.md` Git object at source revision `86f5f37343978351f1d0cb1e13e28ce9c91a8ffd`. It is a public content digest with no authentication, signing or account authority.
- Security purpose: The `RB-RELEASE-15-UPDATER` execution child retains exact original-source provenance for later updater qualification. This exception admits only that immutable CSV fingerprint and does not suppress Authenticode material, signing keys, other hashes, paths or detector results.
