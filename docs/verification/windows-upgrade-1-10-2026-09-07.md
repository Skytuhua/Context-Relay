# Windows protocol 1.10 installer upgrade

The previous installer source, `1d7b46da9d1eda371aa976cbc5f6159517fa45d7`,
uses IPC protocol 1.10. The current installer uses 1.11. Its shutdown helper
accepted earlier qualified versions through 1.9 but omitted 1.10, so updating
while the previous daemon was running could stop with
`ProtocolVersionUnsupported` before authentication.

The shutdown-only compatibility list now includes 1.10. The frozen hello,
authentication, and shutdown message shapes match the previous installer.
Ordinary client version matching is unchanged. Shutdown still requires mutual
authentication, a successful empty acknowledgment, and exit of the connected
process; acknowledgment alone does not let the installer proceed.

The new private-IPC fixture first reproduced the rejection against a frozen
1.10 server. After the fix, all 59 local-IPC library tests passed (three child
fixtures ignored as standalone tests). This includes invalid authentication,
invalid acknowledgments, unsupported versions, bounded timeouts, and waiting
for process exit. The fixture uses synthetic credentials and a unique endpoint.
An independent read-only review found no material regression or security issue.

This is source-level upgrade qualification. The installer has not been run
against the ordinary installed application: native desktop control remains
paused. No normal daemon, credential store, harness profile, or user record was
changed by these tests.
