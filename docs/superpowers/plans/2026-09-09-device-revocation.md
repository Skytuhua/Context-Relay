# Authenticated device revocation implementation plan

Goal: finish the v1 release requirement for device revocation, signed cutoffs and
key rotation. A valid signature alone is not authorization to revoke a device.

Architecture: native code signs a fixed-width statement; the authenticated hosted
transaction verifies current device authority and atomically publishes the cutoff,
new epochs and encrypted key envelopes. Receiving devices verify the control
transition before changing trust or keys. Reuse existing Ed25519, X25519, SQLCipher,
Supabase Edge and PostgreSQL components; no new dependencies.

Basis: the frozen Task 17 lifecycle requirements, recovery-root enrollment design
and `../specs/2026-08-04-supabase-schema-rls-design.md`. Preserve one workspace per
account, original authenticated session intent, durable retries and historical
operation verification. Never export signing keys or send plaintext workspace keys.

1. Add a native signed statement binding operation ID, account, workspace, issuer,
   target, current control/key epochs, cutoff sequence/hash and SHA-256 of the full
   canonical rotation transition. Write failing signature/bounds/key-mismatch tests
   first, implement with existing crypto, then run the focused test and Clippy.
   Freeze independently generated cross-language vectors before hosted integration.
2. Define and verify the complete transition: previous control-state hash, exact
   remaining-device roster, incremented epochs, per-device key envelopes and recovery
   envelope. Recompute its digest; exclude the revoked target. Test missing/extra
   recipients, rollback, concurrent rotations and mismatched envelopes.
3. Persist revocation intent and historical epoch keys atomically. Implement signed
   cutoff admission for old operations and authenticated current-roster admission for
   new operations, including descendants of an issuer revoked after enrollment.
4. Add authenticated Edge/SQL lifecycle handling with current trusted certificate,
   fresh session/binding checks and epoch compare-and-swap. Exact retries reuse the
   stored transition; reject altered replay. Exercise real PostgreSQL grants/RLS.
5. Wire daemon DeviceRevoke, status and sync control propagation; reject successful
   responses queued across logout/account changes. Prove two-device revocation,
   recovery, offline/restart and simultaneous revocation behavior.
6. Run installed live-provider Windows/macOS acceptance, current-head CI and final
   review before marking this release requirement complete or merging PR16.

The statement verifier only checks cryptographic binding to the supplied certificate.
Its caller must authenticate that certificate against the current roster/control
chain. Immutable older certificates remain usable when explicitly authorized by that
chain; reject zero or future certificate epochs. Both installed public keys must
match before signing. Zero cutoff sequence requires zero hash and vice versa;
sequences must fit PostgreSQL bigint and both epochs must admit an increment.
