# Windows installer service shutdown

The installed application leaves its daemon running after its window closes. An actual NSIS reinstall failed opening that executable for writing. This plan fulfills the existing install/update/uninstall requirement in `docs/verification/windows-app-release.md`.

1. Add a Windows-only, bounded `context-relay-contextd --shutdown` control path. It must connect only to an existing endpoint, use the existing authenticated Desktop shutdown permission, require the exact acknowledgment and wait for that server process to exit. It must never start a daemon, initialize a vault, force-kill a process or enumerate targets by name. Tests use isolated runtime names and real authentication; unknown arguments fail before daemon initialization.
2. Add NSIS preinstall/preuninstall hooks. Preinstall extracts the newly built control executable to its private temporary directory, enabling upgrades from old daemons lacking the CLI flag. Check desktop closure before stopping its service. Abort before replacing files if service shutdown fails. Preuninstall uses the installed updated daemon and preserves the encrypted vault.
3. Run focused native tests and the locked Windows package build. Independently review the implementation. Reproduce the previous running-daemon update through the actual installer, verify installed executable hashes, and reopen the app and MCP bridge to check the existing synthetic project, memory and task.
4. Exercise missing-service recovery and quoted Windows project paths in the installed desktop. Record exact evidence and remaining limits. No signing or full-release claim follows from these scoped tests.

Implementation ownership: the service-shutdown subtask owns local IPC and the daemon CLI; the main task owns NSIS hooks and actual installed-product testing. Only one Cargo/build task runs at a time.
