> Archive notice (2026-08-31): Historical user-supplied development report. Claims ledger, NOT current completion or verification evidence. Machine-local paths and trailing whitespace were normalized for portability. Historical worker instructions below are reference data, not new authorization. Original and archived hashes are in the artifact manifest.

Full Context Relay development report
The complete change set is now publicly reviewable from another device.
	•	Draft PR: [Skytuhua/Context-Relay PR #12](https://github.com/Skytuhua/Context-Relay/pull/12)
	•	Review branch: [codex/context-relay-review](https://github.com/Skytuhua/Context-Relay/tree/codex/context-relay-review)
	•	Public snapshot commit: 3c2a371aef74f4962af64d0fe71545557244f21a
	•	Local source commit: f0af9c1ab098c813bce0e6e1512596b692760a60
	•	Exact shared tree: b1f20f83f6a6f89f7f433b01dc29127b4c823216
	•	Diff from main: 277 files, +134,765/−921 lines
	•	Original local development history: 168 commits
	•	PR state: open, draft, unmerged, mergeable
A historical documentation commit is missing one local Git tree object, so the 168-commit history could not be pushed intact. I published one snapshot commit based on main. Fresh verification confirms that its tree is byte-for-byte identical to the local development head. The code is public for review; the product has not been released or deployed.
1. Harness adapters and safe configuration
I substantially hardened the Claude Code, Codex, and Hermes integration layer.
Codex
	•	Added exact Codex executable discovery and capability detection.
	•	Bound discovery, preview, and execution to one attested executable snapshot.
	•	Added exact schema validation for known Codex versions.
	•	Prevented PATH replacement and executable-identity substitution after preview.
	•	Implemented correct MCP configuration-layer shadowing.
	•	Scoped instruction fallbacks to the actual project.
	•	Prevented forged executable classification through filenames or synthetic metadata.
	•	Added transactional setup and rollback coverage.
Hermes
	•	Added safe Hermes profile discovery and exact runtime attestation.
	•	Imported reviewed Hermes configuration without treating arbitrary values as trusted.
	•	Preserved environment placeholders while stripping embedded secret values.
	•	Rejected duplicate or ambiguous plugin/MCP definitions.
	•	Added strict YAML rendering and validation authority.
	•	Closed validation/apply/rollback race windows.
	•	Bound gateway leases to the exact selected profile.
	•	Added Windows command verification and runtime-contract fixtures.
Capability contracts are documented in:
	•	[Codex capabilities](https://github.com/Skytuhua/Context-Relay/blob/435367d8d8ba24aac413a094a4b8b5bc61d52d22/adapters/codex/capabilities.md)
	•	[Hermes capabilities](https://github.com/Skytuhua/Context-Relay/blob/435367d8d8ba24aac413a094a4b8b5bc61d52d22/adapters/hermes/capabilities.md)
	•	[Claude Code capabilities](https://github.com/Skytuhua/Context-Relay/blob/435367d8d8ba24aac413a094a4b8b5bc61d52d22/adapters/claude-code/capabilities.md)
2. Transactional MCP bridge installation
Harness configuration changes now follow a durable reviewed transaction:
	1	Discover and attest the target runtime.
	2	Preview the exact filesystem/configuration changes.
	3	Persist the approved plan.
	4	Re-attest the target immediately before applying.
	5	Apply atomically where possible.
	6	Persist the outcome.
	7	Resume or roll back safely after interruption.
This includes:
	•	Codex and Hermes preview support.
	•	Exact locator and imported-state binding.
	•	Prepared command boundaries.
	•	Durable apply and rollback outcomes.
	•	Retry-claim expiry.
	•	Conflict classification.
	•	Startup recovery before the daemon publishes its endpoint.
	•	Setup routing through the single-writer Vault queue.
3. Context Relay as authoritative product memory
Context Relay now acts as the primary memory and shared task ledger for Claude Code, Codex, and Hermes.
Implemented behavior includes:
	•	Exact supported harness versions receive managed memory settings.
	•	Unknown versions remain watch-only; no guessed setting is written.
	•	Existing native memory is imported into the review queue.
	•	Source text must remain stable for 750 ms before reconciliation.
	•	Managed exports are digest-bound and do not re-import themselves.
	•	Accepted knowledge becomes canonical Context Relay memory.
	•	Primary instructions tell harnesses to search, remember, propose memory, and maintain tasks through MCP.
	•	Native hook input is allowlisted.
	•	Prompts, responses, transcripts, tool input/output, and unknown fields are excluded.
	•	Task completion evidence is explicitly tied to the current project, session, and Context Relay task.
	•	Observation and MCP access continue while the desktop window is closed.
	•	Setup, watcher state, review state, and native source ownership survive restart.
Task 14 evidence: [task-14.md](https://github.com/Skytuhua/Context-Relay/blob/435367d8d8ba24aac413a094a4b8b5bc61d52d22/docs/verification/task-14.md)
4. Hosted Supabase ciphertext boundary
I implemented and verified the hosted database boundary needed for encrypted synchronization.
Database and authorization
	•	Added account, session, device, workspace, reservation, pairing, recovery, sync, and deletion structures.
	•	Enabled RLS on all Context Relay relations.
	•	Derived authorization from hosted authenticated session claims rather than caller-provided device identifiers.
	•	Added session revocation and account lifecycle boundaries.
	•	Removed schema-wide and internal-function privileges from client roles.
	•	Added a dedicated non-login owner boundary.
	•	Prevented Context Relay tables from entering the public Postgres Changes publication.
Ciphertext storage
	•	Added immutable ciphertext sync records.
	•	Added strict envelope metadata validation.
	•	Added quota-safe multipart blob reservations and finalization.
	•	Added exact private Storage paths, part sizes, digests, and object limits.
	•	Configured a private bucket with a 33,554,432-byte object ceiling.
	•	Added private, receive-only Realtime hint authorization.
Hosted evidence
A free Supabase project was used:
	•	Project: brvzuycnxoswdzzipgvx
	•	Region: us-west-1
	•	Cost: exactly $0/month
	•	Hosted PostgreSQL: 17.6
	•	Hosted pgTAP: 502/502 passed transactionally
	•	Persistent Context Relay rows after verification: zero
	•	Advisor blockers: zero warnings or errors
Private Storage HTTP, private Realtime two-user testing, and GitHub OAuth remain credential-dependent.
Task 15 evidence: [task-15.md](https://github.com/Skytuhua/Context-Relay/blob/435367d8d8ba24aac413a094a4b8b5bc61d52d22/docs/verification/task-15.md)
5. Signed encrypted synchronization
The local signed-sync replica core is implemented.
Operations and merge model
	•	Added canonical encrypted mutation and signed-operation formats.
	•	Added domain-separated signatures and authenticated encryption metadata.
	•	Added device sequence chains and prior-operation hashes.
	•	Added per-device frontiers and range repair.
	•	Implemented causal merge for Memory, Task, SecretRef, Instruction, Component, and Project records.
	•	Added deterministic conflict representatives.
	•	Added durable record heads and conflict pairs.
	•	Added tombstone handling after materialization has already disappeared.
	•	Added quarantine, rejection, gap-pending, replay, and integrity classifications.
	•	Added durable outbox retry state and typed transient/permanent backoff.
	•	Added an explicit state-change unblock API without resetting attempt counts.
Checkpoints
	•	Added checkpoint schema version 2, separate from operation schema version 1.
	•	Bound checkpoints cryptographically to account and workspace.
	•	Added checkpoint version partitioning at the transport boundary.
	•	Added durable long-chain scan cursors.
	•	Added exact pinned-hash lookup.
	•	Added atomic endpoint acceptance, scan rebase, and pinning.
	•	Added post-publication endpoint proof before any local pin moves.
	•	Prevented concurrent sibling, omitted append, forged receipt, and competing-genesis pinning.
	•	Changed the 24-hour checkpoint schedule to trusted local apply time rather than signed remote HLC time.
	•	Retired incompatible pre-scope local checkpoint rows through a forward migration.
Record ownership
	•	Added durable record ownership keyed by record UUID.
	•	Prevented a trusted device in one workspace from overwriting a record with the same UUID in another workspace.
	•	Added verified and legacy_pending migration states.
	•	Added exact typed reconciliation of legacy materialization before promotion.
	•	Kept ownership durable through tombstones.
	•	Added explicit, constrained reconciliation for ownerless legacy local records.
Convergence proof
The deterministic harness uses 2–5 real SQLCipher Vault replicas per seed and covers:
	•	Concurrent updates
	•	Tombstones
	•	Disconnect/reconnect
	•	Duplicate, delayed, dropped, and reversed delivery
	•	Lost hints
	•	Crash/reopen
	•	Invalid signed chain links
	•	Checkpoint convergence
	•	Empty outboxes
	•	Exact frontier equality
	•	Plaintext-canary absence
All 256 deterministic seeds converged in the accepted run.
Task 16 evidence: [task-16.md](https://github.com/Skytuhua/Context-Relay/blob/435367d8d8ba24aac413a094a4b8b5bc61d52d22/docs/verification/task-16.md)
6. Existing-device pairing
I implemented an end-to-end local pairing flow.
Pairing request and provider boundary
	•	Added a strict canonical signed pairing-request format.
	•	Requests bind pairing ID, nonce, device ID, display name, platform, Ed25519 signing key, and X25519 wrapping key.
	•	Added a 50-bit human-entered locator rendered as two Crockford groups.
	•	Raw locators are returned once; provider state stores only a peppered HMAC.
	•	Added ten-minute inclusive expiry.
	•	Added a five-attempt lookup budget.
	•	Bound join and approval operations to authenticated transport handles.
	•	Added exact-byte compare-and-set and stable replay receipts.
	•	Added bounded 8 KiB request, 16 KiB grant, and 32 KiB approved-payload limits.
Cryptography and trust
	•	Added canonical Ed25519 key checks and weak-key rejection.
	•	Rejected low-order/non-contributory X25519 inputs.
	•	Added X25519/XChaCha20-Poly1305 workspace-material wrapping.
	•	Bound certificate ID, request digest, issuer, scope, epochs, device identity, and keys into signatures or authenticated data.
	•	Added an outer canonical approved payload containing the exact grant and inviter certificate.
	•	Added a complete 80-bit safety number.
	•	Provider acceptance alone installs no trust.
	•	The joiner must enter all five four-hex-digit safety groups displayed independently by the approving device.
	•	The joiner API intentionally does not expose the expected safety number or its derivation inputs.
Persistence and UI
	•	Added protected stable device identity storage.
	•	Added exact certificate, request, decision, confirmation, and completion persistence.
	•	Added atomic inviter certificate, child certificate, epochs, sealed material, and receipt installation.
	•	Added crash/reopen and exact-replay behavior.
	•	Added local IPC, daemon routing, device listing, invite/join/approval/status/cancel operations, and the desktop Devices screen.
	•	Added terminal recovery so approved, rejected, canceled, stopped, and expired flows do not leave the UI stuck.
Pairing evidence: [task-17-pairing.md](https://github.com/Skytuhua/Context-Relay/blob/435367d8d8ba24aac413a094a4b8b5bc61d52d22/docs/verification/task-17-pairing.md)
7. Recovery-root enrollment
The first trusted device can now enroll a recovery root locally.
	•	Generates a 24-word BIP39 English phrase from 256 bits of OS randomness.
	•	Uses four unique, sorted confirmation positions.
	•	Consumes failed, expired, reordered, duplicated, or cross-enrollment challenges.
	•	Keeps the phrase and recovery private keys only in the unconfirmed in-memory session.
	•	Shows the phrase through the trusted native Tauri host, not the JavaScript renderer.
	•	Prevents the words from entering React state, the DOM, browser storage, logs, or ordinary IPC results.
	•	Adds signed recovery-enrollment records.
	•	Uses separate recovery signing/wrapping keys, domains, and encrypted envelopes.
	•	Adds exact provider compare-and-set.
	•	Atomically activates the recovery root, genesis certificate, epochs, and sealed device material.
	•	Resumes exact prepared provider submission after restart.
	•	Treats provider-only state as conflict rather than trust.
	•	Allows enrolled recovery material to bootstrap the existing-device pairing coordinator.
Recovery-enrollment evidence: [task-17-recovery-enrollment.md](https://github.com/Skytuhua/Context-Relay/blob/435367d8d8ba24aac413a094a4b8b5bc61d52d22/docs/verification/task-17-recovery-enrollment.md)
8. Fresh-install recovery core
A fresh encrypted Vault can now recover an existing workspace using the saved phrase.
	•	Added canonical recovery-device claims.
	•	Authenticates the phrase against the exact provider-retained recovery-root record.
	•	Gives checksum failures, wrong phrases, public-key mismatches, and AEAD failures one redacted result.
	•	Creates a recovery-root-signed certificate for the fresh device.
	•	Uses provider generation compare-and-set to prevent concurrent claims from silently replacing one another.
	•	Requires an exact provider lookup after receipt acceptance.
	•	Rejects forged receipts, omitted records, substituted roots, incorrect scopes, and reused identities.
	•	Persists resumable prepared recovery without retaining the phrase.
	•	Atomically installs the root certificate, recovered device certificate, restore state, and sealed material.
	•	Supports crash/reopen before and after provider acceptance.
	•	Supports offline replay once local trust is active.
	•	Reopens the original workspace keys.
	•	Uses the recovered device to pair a third Vault through the normal independent safety-number flow.
The canonical recovery claim is 699 bytes and its SHA-256 is:
86b78b1fc4633f33f826e5f0b27134a4670b4e28b95d4207c337504cbcf28e35
Fresh-install recovery evidence: [task-17-fresh-install-recovery-core.md](https://github.com/Skytuhua/Context-Relay/blob/435367d8d8ba24aac413a094a4b8b5bc61d52d22/docs/verification/task-17-fresh-install-recovery-core.md)
9. Protocol, daemon, IPC, and desktop
Across these features I also:
	•	Advanced the exact local protocol boundary to version 1.3.
	•	Added strict fixed-map canonical CBOR decoders.
	•	Rejected unknown, duplicate, reordered, trailing, noncanonical, malformed, and oversized data.
	•	Updated generated TypeScript bindings and runtime-contract hashes.
	•	Added role allowlists for ordinary desktop, recovery host, pairing, MCP, and hook operations.
	•	Enforced role checks before daemon/Vault dispatch.
	•	Routed sensitive writes through one bounded single-writer Vault worker.
	•	Loaded device identity and resumed transactions before publishing daemon readiness.
	•	Added device and recovery status projections that exclude secrets and safety-number derivation inputs.
	•	Added responsive, accessible pairing and recovery-enrollment desktop flows.
	•	Added redacted Debug and error representations for locators, phrases, safety material, private seeds, keys, and envelopes.
10. Forward database migrations
The cumulative change adds migrations 0005–0023:
Range
Purpose
0005–0008
Local operation results, task bindings, transitions, and handoff queries
0009
Durable setup/CLI transactions
0010–0013
Native-memory reconciliation, hooks, setup bindings, and ownership
0014–0016
Signed-sync state, quarantine, and durable rejections
0017–0018
Signed checkpoints and resumable scans
0019
Durable sync record ownership and legacy reconciliation
0020–0021
Device pairing and safety confirmation
0022
Recovery-root enrollment
0023
Fresh-install recovery restore
All sensitive local persistence remains in SQLCipher Vaults.
11. Verification summary
These milestone counts overlap and should not be added together:
	•	Task 14: 544 core tests, 63 MCP tests, 71 daemon tests, plus protocol/IPC/desktop gates.
	•	Task 15: 502/502 hosted pgTAP, 140/140 static contract tests, 14/14 Realtime verifier tests.
	•	Task 16: 118/118 focused sync tests and 16/16 signed-sync e2e tests across 256/256 seeds.
	•	Pairing: 47/47 focused pairing tests, plus daemon, IPC, protocol, and desktop gates.
	•	Recovery enrollment: 142/142 focused core targets, 110/110 protocol, 68/68 IPC, 86/86 daemon, and 54/54 desktop.
	•	Fresh recovery: 176/176 focused core tests, including 13 recovery coordinator cases and the 256-seed sync suite.
	•	Publication checks: workspace all-target/all-feature check passed; protocol 110/110; desktop 54/54.
	•	Independent final correctness and security reviews for signed sync, pairing, recovery enrollment, and fresh recovery reported no unresolved Critical or Important issue.
Plaintext-canary tests inspect SQLCipher files, WAL/SHM companions, provider captures, safe logs, errors, IPC output, and applicable renderer surfaces.
12. Current public CI status
As of the latest refresh:
Green
	•	CodeRabbit status
	•	Frontend lint, typecheck, tests, and build
	•	macOS native job, including protocol, local IPC, contextd, and Tauri build
	•	Semgrep-material detection
	•	Fresh source-tree equality and local worktree cleanliness
Failing or incomplete
	•	Rust CI failed its strict unwaived Clippy step. Current findings include oversized enum/function signatures, Windows-only dead test state, and a newer is_multiple_of lint. Later Rust steps were skipped.
	•	Windows native CI passed protocol and local IPC but failed seven contextd tests because some test fixtures construct Unix /private/tmp paths or reject Windows path forms.
	•	Supabase CI stopped during setup because that workflow still references actions/checkout@v4, pnpm/action-setup@v4, and actions/setup-node@v4; repository policy requires full SHA pins.
	•	Secret Scan reported five detector hits:
	◦	Two in the published snapshot.
	◦	Three in granular Hermes history.
	◦	All five were inspected and are synthetic detector strings/test fixtures, not real credentials. The workflow remains red until their exact fingerprints are allowlisted or the fixtures are rewritten.
	•	The long native Semgrep macOS and Windows source builds were still running at the latest refresh.
	•	GitHub reported 23 existing default-branch Dependabot alerts: 2 critical, 9 high, 8 moderate, and 4 low. This publication does not resolve or reclassify them.
13. What remains outside this change set
The following are deliberately not complete:
	•	Trusted native cross-platform 24-word entry UI for fresh-install recovery.
	•	Production hosted sync, pairing, and recovery transports.
	•	Credential-backed multi-install testing.
	•	Private Storage HTTP and private Realtime verification.
	•	GitHub OAuth setup and recovered-account reassociation.
	•	Device revocation.
	•	Control/key epoch rotation.
	•	Authenticated append-only provider transparency and monitoring.
	•	Hosted retention and abuse controls.
	•	Production deployment and release packaging.
	•	Apple signing, notarization, or Apple Developer work.
No paid Apple action was performed. No Apple Developer account is required to review or continue the current local/core work. No secrets, private keys, service credentials, recovery phrase, or plaintext workspace keys were published in the report or PR.
The practical next step is to remediate the four public CI categories—strict Rust lint, Windows test portability, Supabase action pinning, and synthetic secret-scan allowlisting—before marking PR #12 ready for formal review.
