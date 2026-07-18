# Context Relay version 1 threat model

Supabase is untrusted ciphertext storage. A cloud operator may alter, delete, fork, or withhold ciphertext. Cloud routing metadata, account relationships, device metadata, ciphertext sizes, and timing remain visible. Clients aim to detect integrity failures. They do not guarantee availability.

Harnesses are trusted only for scopes the user grants. Other projects are denied by default. GitHub repositories and packages are untrusted until exact bytes are inspected, scanned, approved when required, and transactionally applied.

The React UI, MCP clients, native harness files, archives, sidecars, cloud responses, adapter discovery results, local IPC fields, package manifests, and repository archives are untrusted inputs. Version 1 requires typed deserialization, unknown-field rejection at local boundaries, size limits, stable safe errors, canonical CBOR checks, and explicit approval classes.

Same-user malware can read process memory and decrypted local data and is outside the version 1 security guarantee. An offline revoked device may retain plaintext and historical keys it already cached. A fresh device with no checkpoint pin cannot distinguish an older valid server snapshot from the newest valid snapshot. Operators cannot recover a lost recovery phrase.

Task 4 does not provide encryption, signature verification, server integrity, native rollback, authorization, package safety, or replay prevention. Signature, nonce, hash, ciphertext, and public-key fields are opaque validated bytes until later crypto and storage tasks define their behavior.

Client-visible errors must not expose raw OS errors, filesystem contents, credentials, keys, stack traces, transcripts, or error chains. MCP DTOs must not expose raw SQL, shell execution, device management, package installation, native writes, credentials, secret values, or arbitrary cross-project access.
