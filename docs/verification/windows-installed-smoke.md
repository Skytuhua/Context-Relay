# Windows installed first-launch smoke

The `Installed Windows first launch` job in `windows-package.yml` exercises the
installer produced by the same workflow run on a second, disposable
`windows-2025` hosted runner. The existing installer build job and its packaging
checks remain required. This is additional installed-product evidence; it does
not turn an unsigned candidate into a qualified release.

## What the job verifies

The job downloads the exact `context-relay-windows-x64-${github.sha}` artifact
from its own workflow run. Before execution, the driver checks the source
commit, workflow identity, build run, target, installer name, recorded byte
length and SHA-256, and all three `SHA256SUMS` entries. Installed bytes must then
match the provenance of the five shipped executables and fifteen declared
model, runtime and notice files. Provenance describes extracted installer
payload bytes, including Tauri's packaged desktop marker.

The driver refuses an existing Context Relay installation, uninstall
registration, product process, or `%LOCALAPPDATA%\Context Relay` directory. That
directory is also the normal production vault location. Existing parent paths
are checked for reparse points before the first write. Candidate paths reject
absolute paths, traversal, alternate streams and ambiguous Windows components.

The installer runs with its ordinary `/S` option and configured current-user
destination. No destination override, upgrade switch, application test mode,
synthetic credential, fake profile, or daemon readiness shortcut is used. The
installed uninstall command is captured from the one expected HKCU entry,
restricted to an executable directly inside the installed directory, and
hashed before later execution.

The test then follows these real entry points:

1. Load each installed native helper with closed input and require its ordinary
   missing-request refusal. This checks that both executables can load; it does
   not qualify a hydrated scanner or a native mutation.
2. Launch `context-relay-desktop.exe` visibly without arguments. Windows UI
   Automation must observe `Choose harnesses`, invoke the normal `Finish later`
   button, and observe `Ready on this computer`. A process or window alone does
   not pass the test.
3. Open the normal `Context` screen and wait for visible `Search is ready.`.
   This reflects the connected daemon's search-index state. Even an empty vault
   exercises packaged model validation, ONNX runtime initialization, and model
   session creation. It does not exercise passage embedding or search quality.
4. Launch the installed MCP bridge with its supported `--harness codex` identity
   in an unregistered working directory. Send newline-framed MCP initialization,
   tool discovery, and `context_relay_status` through standard input. Require
   correlated numeric reply IDs, the expected server version, and the normal
   authenticated daemon status showing an unlocked vault and default scope.
   No Codex installation is needed; this is bridge connectivity evidence, not
   a real coding-harness qualification.
5. Close the desktop normally, execute the installed daemon's authenticated
   `--shutdown`, and repeat MCP status to exercise bridge-initiated cold start.
   Shut the resulting daemon down normally again.
6. Run the captured uninstaller with `/S`. Require removal of the product
   registration and shipped executable files, while preserving the exact vault
   file bytes recorded after shutdown. The temporary runner is later discarded;
   the smoke never recursively deletes the production data directory.

## Deadlines and process ownership

Every process launched directly by the driver starts suspended, is assigned to
a driver-owned Windows Job Object before its first instruction, and then resumes
with only three explicit standard-I/O handles. Descendants inherit job membership
through ordinary production launches, including the
daemon and NSIS's temporary uninstaller. The application does not receive a new
flag or authority. The job does not allow breakaway and remains open until after
uninstall. Authenticated shutdown and normal window close are the primary
cleanup paths. Any forced job cleanup makes the run fail; kill-on-close also
limits leftovers if the driver is interrupted.

The installer has a ten-minute budget. UI steps have explicit 10–120 second
budgets, and each UI Automation provider call has a separate five-second bound.
Every MCP reply has a 75-second bound with bounded frame and diagnostic output.
Shutdown has a 60-second budget. Uninstall has a two-minute process/output
budget and a further one-minute removal check. Final job cleanup has two
ten-second bounds. A forty-minute job limit leaves room for those failure
paths. Desktop connection and search/model initialization are asserted as
separate stages; model loading is not counted as synchronous daemon startup.

## Evidence and remaining limits

An always-run upload retains only `installed-smoke.json`: exact candidate and
installed identities, completed stages, UI readiness text, MCP status summary,
runner/WebView observations, cleanup outcome and any bounded failure message.
It does not upload the vault, profile, credentials, raw protocol streams or
application logs. A failing stage cannot be converted into a passing process
check. Partial installation without a validated uninstaller uses job teardown
and reports failure instead of guessing an uninstall command.

The child environment keeps the real Windows user/profile values and restricts
`PATH` to Windows system directories. The test job does not set up Node, pnpm,
Rust or Python. The hosted image still contains machine-installed developer
tools and runtimes, so this does not prove behavior on a clean operating system.
The runner's elevation, interactive session, image version and WebView2 registry
versions are recorded. Registry absence is not treated as proof that WebView2
is absent. A preinstalled WebView2 runtime means this run cannot establish that
the bundled offline installer provisions a machine without WebView2, nor does
it establish disconnected installation or standard-user integrity behavior.

The hosted runner must expose an interactive desktop and the rendered WebView
accessibility tree to UI Automation. If it does not, this required assertion
fails with a concrete readiness error. The workflow does not enable a debugger,
headless test route, fake readiness text, or an application bypass to make it
pass. Such a hosted-runner failure needs separate runner qualification before
claiming installed UI coverage.

Fresh-OS/offline runtime provisioning, upgrade and interrupted installation,
real coding harnesses, account/hosted operations, and inference quality remain
separate qualification work. An actual hosted run of this new job is required
before its installed-product claims can be reported as passed.

## Safe source validation

Run `node --test scripts/windows-installed-smoke.test.mjs` to check the workflow
contract. On Windows it also parses the whole PowerShell driver, extracts only
named helper function definitions, compiles the driver-side C# helpers, and
checks temporary path/hash fixtures including junction refusal. It does not
construct a process job or invoke any native process entry point. On other
platforms the Windows-only test reports an explicit skip.

The full driver refuses execution outside the dedicated GitHub-hosted
`installed-smoke` job. Do not run it on a developer's workstation. The safe
source test is the local validation path; normal installer execution belongs
only in the disposable workflow job.
