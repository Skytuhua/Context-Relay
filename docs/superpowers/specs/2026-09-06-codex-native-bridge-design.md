# Codex managed bridge: one native configuration write

This supersedes the generator and CLI-authorship requirements in
[the staged MCP proposal](2026-09-05-codex-staged-mcp-design.md) for the fixed
Context Relay bridge only. Codex documents direct `config.toml` configuration:
https://learn.chatgpt.com/docs/extend/mcp?surface=cli . Arbitrary MCP servers,
plugins and other CLI operations retain their existing paths.

The Windows probe establishes that private-directory access succeeds while
DOS/GUID final-path queries fail inside the zero-capability AppContainer. NT
queries succeed, but an NT-prefixed input does not fix Rust canonicalization.
Do not change machine-wide ACLs or substitute an unrestricted generator.

Instead, construct the two documented fields (`command`, fixed `args`) using
the TOML serializer and the already validated canonical bridge declaration.
Compose this with the global memory changes in one native mutation. Preserve
unrelated fields, comments and original metadata. Existing file snapshots,
approval hashes, encrypted before-images, compare-and-swap, crash recovery and
Undo remain authoritative. No generator runs and no fake CLI evidence is kept.

Setup must classify the native declaration, reject conflicting or overriding
declarations, and bind the revised adapter behavior. Keep the generic Codex CLI
adapter unchanged. Coalescing must verify the memory projection's original
fingerprint; memory-state revalidation must understand the composed write
without accepting arbitrary differences or rebasing foreign file identities.

Verification: exercise real native preview/apply/restart/reapply/Undo, creation,
mixed-file preservation, tampered inputs, concurrent edits and recovery with no
CLI mutation. Qualify serializer output using pinned official CLI readback in
synthetic profiles. Preserve the existing version gates until hook trust,
production MCP memory/tasks and installed workflow acceptance are complete.
