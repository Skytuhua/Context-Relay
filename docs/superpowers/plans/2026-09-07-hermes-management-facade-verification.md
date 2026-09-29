# Owned Hermes management facade verification

The core facade consumes a LockedRuntime and derives its own executable root.
Each command gets a new bounded YAML configuration inside a private Windows
directory. Runtime and profile owners remain in the native runner until process
and I/O cleanup completes, including retained uncertain-cleanup state. Success
returns the still-locked runtime after inventory verification. Failed commands
and nonempty stderr are rejected without including command output in errors.

The actual retained Hermes 0.17.0 banner includes Python and OpenAI SDK versions.
The previous general parser rejected it as ambiguous. A regression first failed
with None instead of 0.17.0; the retained parser now recognizes the exact Hermes
banner and rejects malformed or duplicate headers. Captured real config-check
stdout passes the existing configuration parser with isolated credentials absent.

Validation on Windows:

- Five facade tests pass: private directory ownership/cleanup, invalid and
  oversized YAML, banner parsing, actual config output parsing, and both command
  paths through a compiled inert native executable. The latter checks arguments,
  environment, projected configuration, retained identity and profile cleanup.
- The complete focused Python runtime group passes 28 tests, with two explicitly
  opt-in installed-runtime tests ignored in this synthetic run.
- Core and native-runner all-target Clippy with test support and warnings denied
  passes. Independent review approved the facade and subsequent process fixture.

The earlier opt-in direct runner test separately passed both commands against
14,629 retained files from the selected real Hermes installation. Both exited 0,
wrote no stderr and preserved runtime inventory; details are in
2026-09-06-hermes-management-runner-verification.md. The new facade itself was
exercised with an inert native fixture, not another full real-installation capture.

Adapter/daemon setup, approved-runtime recovery and actual connection/restart/Undo
qualification remain open. No Full version, installed application or local EXE is
changed by this slice.
