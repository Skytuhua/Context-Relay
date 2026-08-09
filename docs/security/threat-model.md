# Context Relay version 1 threat model

This model describes PR #12 at
`3c2a371aef74f4962af64d0fe71545557244f21a`. Local encrypted storage, daemon,
IPC, adapters, native transactions, authoritative memory, signed-replica core,
pairing, recovery-root enrollment, and fresh-install recovery core are present.
The product is not released or deployed. Production hosted sync/pairing/recovery,
GitHub OAuth/App access, package installation, renderer-safe recovery entry,
revocation/rotation/reassociation/deletion, and signed updates remain gaps; see
the [audit baseline](../verification/v1-master-plan-audit.md).

## Security goals and limits

- Vault records, content keys, recovery phrases, native before-images, and secret values remain confidential from the cloud, renderer, packages, logs, exports, and unrelated harness scopes.
- Signed operations, certificates, checkpoints, setup approvals, and native writes fail closed on changed bytes, identity, scope, epoch, executable, path, or expected digest.
- Offline work remains available from the complete encrypted local replica; authenticated clients detect cloud tampering but cannot force availability.
- Raw harness credentials, OAuth tokens, native trust databases, transcripts, prompts, responses, and tool payloads never enter synchronized records.
- Same-user malware, a compromised unlocked OS account, memory scraping, and user-controlled backups are outside the v1 guarantee. An offline revoked device may retain previously cached plaintext and historical keys.

## Trust boundaries and current state

| Boundary | Current controls | Residual gap / guarantee limit |
| --- | --- | --- |
| React renderer → Tauri/native host | The renderer is untrusted input. Typed commands, role checks, bounded/word-free results, and a distinct native recovery-host role keep recovery phrases out of React state, DOM, browser storage, and ordinary IPC projections. Phrase display/confirmation for enrollment uses the trusted Tauri host. | The trusted cross-platform 24-word **entry** surface for fresh-install recovery is not implemented. Renderer compromise can act with renderer-granted UI methods but must not obtain phrase/key material. |
| Tauri/MCP → daemon/local IPC | A per-user singleton owns the Vault. Length-prefixed frames are capped at 8 MiB; OS transport permissions, an installation token, protocol/nonce checks, role allowlists, cancellation/backpressure, and one bounded writer protect dispatch. MCP exposes no SQL, shell, filesystem, device, package, or secret primitive. | Physical cross-user and credential-store tests remain release gates. Same-user malware can impersonate a permitted user process and is out of scope. |
| Daemon → SQLCipher Vault | SQLCipher holds records, FTS, operations, checkpoints, pairing/recovery state, receipts, and encrypted before-images. The database key belongs in Keychain/Credential Manager; migrations are forward-only, writes are transactional, and canary tests include database/WAL/SHM files. | Credential-store loss/recovery and physical-machine inspection are not release-qualified. SQLCipher does not protect plaintext after an authorized process decrypts it. |
| Daemon → native files/CLIs/helpers | Adapters bind executable identity/version, target bytes, semantic diff, approval hash, and expected digests. The transaction engine locks, stages allowlisted inputs, strips sensitive environment, validates output, uses compare-and-swap, activates last, and restores attributed before-images. RuleSync/scanners run in restricted native helpers. | Deferred Task 9R, real sidecar network denial, all filesystem edge cases, AV/disk faults, and full physical rollback matrices remain release blockers. The product never edits native trust/auth/session databases. |
| Daemon → Supabase | Supabase is untrusted ciphertext and routing-metadata storage. Hosted migrations establish RLS, session/device-derived authorization, immutable ciphertext records, private Storage policy, quota accounting, and receive-only Realtime hints. The operator can see account/device relationships, sizes, timing, and routing metadata and may alter, delete, fork, or withhold ciphertext. | Hosted pgTAP/database-policy evidence exists, but Storage HTTP, private Realtime, OAuth, and the production sync/pairing/recovery transports are absent. Integrity is client-detectable, not server-enforced immutability; availability is not cryptographically guaranteed. |
| Daemon → harness adapters | Claude Code, Codex, and Hermes are trusted only for user-granted global/active-project scopes. Supported exact versions can receive reviewed changes; unknown/wrapper versions are import/watch-only. Native memory inputs are debounced, allowlisted, and routed to review unless product-owned. | Real supported installations on both OSes remain to be qualified. A granted harness can read or write within its scope and can disclose that plaintext externally. Other projects stay denied by default. |
| Daemon → repositories/packages | Repository archives, manifests, dependencies, hooks, plugins, MCP servers, binaries, and scanners' input are untrusted. Protocol/schema bounds exist and active/executable changes require an exact approval in the master contract. | The read-only GitHub App, quarantine/inspection engine, dependency closure, exact-byte scanning, package apply, and attack-fixture release gates are not implemented. No repository content is safe merely because GitHub authenticated it. |
| Installed app → updater/signing | Update bytes, manifests, sidecars, models, checksums, migration state, and provenance are untrusted until signature/hash verification. The release contract requires Authenticode, Apple Developer ID/notarization, and Tauri updater signatures. | No production release/updater workflow, protected signing material, signed installer, notarization, or N-1 rollback evidence exists. Unsigned artifacts cannot be called public beta. |
| Recovery/device/account lifecycle | Local pairing uses a 50-bit locator plus independent 80-bit user confirmation. Recovery-root enrollment and fresh-Vault recovery bind exact roots, certificates, scopes, generations, and sealed material; provider-only state installs no trust. See the [contract amendments](../protocols/contract-amendments.md). | Production provider transports, native recovery phrase entry, GitHub reassociation, device revocation, epoch/key rotation, export during deletion, seven-day cancel, and final purge are incomplete. Operators cannot recover a lost phrase or remotely erase an offline device/backup. |

## Cryptographic and synchronization boundary

Operation schema version 1 uses canonical CBOR, Ed25519 signatures, sequence
chains, causal frontiers, XChaCha20-Poly1305, and deterministic conflict rules.
Checkpoint schema version 2 separately binds account/workspace and previous
checkpoint state. Signatures are checked before decryption; duplicates require
byte identity; gaps, forks, and integrity conflicts are quarantined. The local
multi-Vault replica core and canary scans are evidenced in the
[Task 16 ledger](../verification/task-16.md), but that is not hosted transport
evidence. A fresh device with no retained checkpoint pin cannot distinguish an
older valid server snapshot from the newest valid snapshot.

## Principal threat cases

- **Malicious cloud/operator:** can observe metadata and deny, fork, replay, or delete ciphertext. Clients verify signatures, epochs, chains, exact receipts, and local pins; total pin loss retains the documented freshness limitation.
- **Compromised renderer or MCP caller:** may send malformed or over-scoped requests. Typed DTOs, size/unknown-field rejection, roles, binding-derived scope, and safe errors constrain it; neither surface receives direct secret or mutation authority.
- **Malicious/compromised harness:** can misuse its granted scope. Binding policy and active-project resolution limit reach; ordinary writes are revision/replay checked. Users must revoke/disable access locally until hosted revocation exists.
- **Hostile repository/package/sidecar:** may contain traversal, links, binaries, secrets, obfuscated active content, or mutable dependencies. Existing native staging reduces helper risk, but package installation remains disabled until Task 19 implements the complete inspection/approval boundary.
- **Native TOCTOU or crash:** files, executables, directories, links, ACLs, and concurrent edits can change after preview. Attestation, locks, compare-and-swap, durable journals, attribution, activation-last ordering, and exact rollback address implemented paths; physical fault qualification remains open.
- **Lost, stolen, or revoked device:** recovery can restore local trust when the phrase and provider root agree. A revoked online session must eventually be blocked and future epochs rotated, but those production state machines are absent; cached plaintext and backups cannot be clawed back.
- **Supply-chain/update compromise:** unsigned or tampered binaries, sidecars, models, actions, and manifests can execute with user authority. Hash/license CI is partial; only protected signed/notarized releases with tamper and rollback evidence can pass beta gates.
- **Deletion failure:** pending deletion must block writes while preserving export, then purge Storage, database, and Auth idempotently. Database groundwork exists, but the end-to-end flow is not implemented; provider backups may retain ciphertext until provider retention expires.

## Evidence discipline

Current evidence is plane-specific: [Tasks 1–10](../verification/tasks-1-10.md),
[Task 14](../verification/task-14.md), [Task 15](../verification/task-15.md),
[Task 16](../verification/task-16.md), and the three
[Task 17](../verification/task-17-pairing.md) ledgers. Historical counts and
development-report assertions do not elevate hosted, credentialed,
physical-device, signing, or deployment claims. Client-visible errors must not
expose raw OS errors, filesystem contents, credentials, keys, phrases, stack
traces, transcripts, or recursive error chains.
