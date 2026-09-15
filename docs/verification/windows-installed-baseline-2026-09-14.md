# Installed Windows baseline — 2026-09-14

Read-only file verification identifies the currently installed application as
source `14683270b98f391d9e9bce71792f9ace8620ea04` (Clarify setup review and resolve
packaged search resource paths). All 18 files in that candidate's saved manifest
match the installed byte lengths and SHA-256 hashes: five application executables
and thirteen search model/runtime/license resources.

The installation is registered as Context Relay 0.1.0 at
`C:\Users\User\AppData\Local\Context Relay`. Version 0.1.0 alone does not identify
the source revision. This observation supersedes the older e09d206 installed-file
baseline where it is described as current; its earlier runtime tests remain dated
evidence and are not reattributed to this build.

The matching installer is preserved at
`E:\Context Relay Releases\1468327\Context Relay_0.1.0_x64-setup.exe`,
75,852,732 bytes, SHA-256
`3a0dacf88661628de535a4d46ecf17d968227fea3dc3856673b7c53f93bc8b45`.
Its freshly computed hash matches `E:\Context Relay Releases\1468327\checksums.json`.
Seven archived E: candidate installers were checked against their saved manifests;
all seven installer hashes match. The five executable hashes distinguish 1468327
from the other six candidate manifests.

Older protocol-upgrade fixtures remain available in the original workspace:
`C:\Users\User\Documents\AI Cloud Sync\.codex\installer-candidates\`.
Fresh hashes for 11d6740, 1d7b46d and 357f4a2 match their documented hashes. In particular,
1d7b46d remains the documented protocol 1.10 installer fixture. Select the actual
N-1 release separately when executing release acceptance; an arbitrary archived
candidate is not automatically N-1.

The current host reports Windows 11 Home, 10.0.26200, 64-bit. WindowsSandbox.exe,
VBoxManage.exe, vmrun.exe, qemu-system-x86_64.exe and Get-VM were not available through
command discovery. This bounded check does not prove no virtualization software
exists elsewhere. No clean test machine has been qualified by this observation.

Local detailed evidence is retained at
`.codex/pr16-installed-baseline-2026-09-14.json`, including all 18 file hashes and
observation time. No installer, desktop, bridge or daemon was executed, stopped,
restarted or changed. No credential or vault content was read. This is file-identity
evidence only: current-source runtime behavior, real hosted workflows, upgrade,
interrupted rollback, clean-machine testing and the full acceptance matrix remain
open. Apple-related work and anything requiring payment remain deferred.
