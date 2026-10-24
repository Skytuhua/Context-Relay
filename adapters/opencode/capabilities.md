# OpenCode MCP support

Context Relay supports an **explicit, project-bound MCP setup export** for OpenCode.
OpenCode can search and read saved context, save explicit decisions, submit
suggestions for review, and use the shared task tools through the installed local
MCP bridge. The existing Context Relay access policy still controls each request.

This is a manual connection with an authenticated saved-note read test. It is not
a qualified managed harness adapter: Context Relay does not detect or run
OpenCode, edit its configuration, import its native memory, change native-memory
settings, install lifecycle hooks, or create an automatic setup/Undo receipt.
No OpenCode executable version is claimed as qualified by this integration.

## Set up a native Windows project

1. Install the OpenCode CLI using an [official installation method](https://opencode.ai/docs/).
   OpenCode documents native Windows installation and also recommends WSL for its
   own environment. Use native Windows OpenCode with a Windows Context Relay
   installation; a Windows executable/path export does not configure a WSL
   bridge or cross that filesystem boundary.
2. Add the project folder to Context Relay under **Projects**. If the initial
   wizard is open, choose **Finish later** first. Automatic wizard choices remain
   limited to Claude Code, Codex, and Hermes, because that wizard requires a saved
   managed setup.
3. In **Harnesses**, select the project and use **OpenCode · manual MCP setup →
   Prepare OpenCode configuration**. The daemon resolves the registered folder,
   checks that its working directory uniquely identifies the selected project,
   and attests the installed bridge next to the daemon. The caller cannot supply
   a command, executable path, or replacement project path.
4. Review the returned fragment and merge it into the indicated project config.
   If no config exists, the fragment is a complete initial configuration.
   Otherwise, add only `mcp.context-relay`, and append the dedicated instruction
   filename to the existing `instructions` array once. Preserve unrelated
   servers, settings, comments, and instruction paths. Save the displayed
   instruction text to `.context-relay-opencode.md` in that project. Keep existing
   `AGENTS.md` and `CLAUDE.md` files.
5. Open OpenCode in that folder, inspect `opencode mcp list`, and complete any
   sign-in, project trust, or tool approvals OpenCode requests. Keep Context Relay
   running. Restart OpenCode after changing its configuration.
6. Return to the OpenCode panel, choose **Test OpenCode with saved context**, and
   explicitly save a test note. Send its generated test prompt in OpenCode.
   Context Relay reports success only after an MCP read of the exact note and
   revision under the matching OpenCode/project binding. Copying configuration
   or seeing the server in a list does not produce that receipt. The manual
   panel's test does not satisfy the wizard's managed setup gate.

The generated fragment uses actual absolute paths from the installed bridge and
registered project. This illustration uses placeholders; use the panel's export
instead of copying these paths:

```json
{
  "mcp": {
    "context-relay": {
      "type": "local",
      "command": [
        "C:\\Program Files\\Context Relay\\context-relay-context-mcp.exe",
        "--harness",
        "opencode"
      ],
      "enabled": true,
      "cwd": "C:\\Projects\\my-project",
      "timeout": 60000
    }
  },
  "instructions": [".context-relay-opencode.md"]
}
```

OpenCode documents the local MCP `command` array, `cwd`, `enabled`, and `timeout`
fields. `timeout` is in milliseconds and defaults to 5,000. This export requests
60,000 milliseconds for MCP initialization/tool discovery so the local service
has room for synchronous startup and vault recovery. It does not claim that
model loading runs during synchronous daemon startup or impose a timeout on
every model or tool operation. See the [official MCP configuration reference](https://docs.opencode.ai/docs/mcp-servers/).

## Configuration preservation and limits

The export reads only `opencode.json` / `opencode.jsonc` and the dedicated
instruction file in the registered project. Both config extensions accept
comments and trailing commas, matching OpenCode's JSONC parser. The export never
rewrites those files or returns unrelated existing configuration values. It rejects:

- Both project config filenames existing at once, duplicate object keys at any
  depth, malformed JSON/JSONC, and malformed `mcp` / `instructions` shapes.
- A pre-existing `context-relay` entry that differs from the exact export, or
  duplicate references to the dedicated instruction file.
- An existing `mcp.servers.context-relay` entry in OpenCode's newer configuration
  layout. This export uses the documented flat `mcp.context-relay` local entry;
  review and resolve the same-name entry before merging the fragment.
- Different content in the dedicated instruction file. Matching Windows CRLF
  line endings and an optional UTF-8 BOM are accepted without rewriting the file.
- Linked/reparse project config or instruction files, non-files, files exceeding
  the supported size, changed bridge attestation, and paths that contain OpenCode
  `{env:...}` / `{file:...}` expansion tokens.

The project config read limit is 256 KiB; the dedicated instruction file limit is
8 KiB. Fix a reported conflict in your editor and prepare a fresh export. This is
structural validation of the project surfaces used by this connection, not a
claim that every OpenCode setting, provider, remote config, or plugin is valid.

OpenCode also loads global and other configuration layers. Its documented native
Windows global location is `%USERPROFILE%\.config\opencode\opencode.json` or
`opencode.jsonc`. `OPENCODE_CONFIG`, `OPENCODE_CONFIG_CONTENT`, custom config
directories, and managed organization settings can affect the effective config.
This project-only export does not inspect or override those layers. Review
OpenCode's effective MCP status and the [config documentation](https://opencode.ai/docs/config/)
if a correctly saved project fragment is not active.

To disconnect, review and remove only the `context-relay` MCP entry, the dedicated
instruction-array entry, and `.context-relay-opencode.md`. Preserve anything you
subsequently added to those surfaces. There is no managed transaction receipt or
automatic Undo for this manual connection.

## Implementation and verification contract

The stdio bridge accepts `--harness opencode`; its lifecycle-hook invocation mode
explicitly refuses OpenCode. Managed `SetupPlan` validation, bridge transaction
construction, native-memory source qualification, and native CLI recovery do not
gain an OpenCode authority path. MCP access gets a separate `opencode` policy row;
vault migration 49 preserves all existing policies while allowing that identity.

Local protocol 1.19 requires a coordinated desktop, daemon, and bridge upgrade.
The normal handshake continues to require the exact current version; only the
existing authenticated shutdown path recognizes prior local versions, including
1.18, for an upgrade. Update other
Context Relay devices before expecting them to consume records with OpenCode
provenance.

Focused fixtures cover export shape, canonical binding, comments/unrelated file
preservation, conflicts and limits, access policy isolation, protocol/role gates,
CLI hook refusal, stale UI replies, and the real saved-note test flow. These
fixtures do not launch an installed OpenCode CLI and do not constitute an
installed-version qualification.

Additional official references: [Windows and WSL](https://opencode.ai/docs/windows-wsl/),
[CLI and MCP status commands](https://opencode.ai/docs/cli/),
[instruction files](https://opencode.ai/docs/rules/), and
[native config locations](https://opencode.ai/docs/troubleshooting/).
The [official config schema](https://opencode.ai/config.json) describes both MCP
layouts; the [official config loader](https://github.com/anomalyco/opencode/blob/dev/packages/core/src/config.ts)
uses JSONC parsing with trailing commas for both project file extensions.
