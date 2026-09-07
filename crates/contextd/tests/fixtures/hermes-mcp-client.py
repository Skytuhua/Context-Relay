"""Opt-in native Hermes MCP client qualification; no model or ordinary profile."""
import sys

assert sys.stdin.buffer.read() == b"run", "fixture requires the parent's owned job"

import contextlib
import io
import json
import os
from pathlib import Path

fixture = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
runtime = Path(fixture["runtime"]).resolve()
home = Path(fixture["home"]).resolve()
assert Path(os.environ["HERMES_HOME"]).resolve() == home
assert Path.cwd().resolve() == Path(fixture["project"]).resolve()
assert sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode

def within_runtime(path):
    resolved = Path(path).resolve(strict=True)
    # CPython's _pth entries may use ordinary drive paths while Rust supplies
    # a verbatim \\?\ path. Compare filesystem identity, not those spellings.
    return any(parent.samefile(runtime) for parent in (resolved, *resolved.parents))

assert all(within_runtime(path) for path in sys.path), {"paths": sys.path, "runtime": str(runtime)}

# Execute the verified projection's existing path-probe initialization while
# retaining its namespace (and DLL-directory handles) for the client lifetime.
bootstrap = runtime / "bootstrap.py"
namespace = {"__file__": str(bootstrap), "__name__": "__main__"}
sys.argv = [str(bootstrap), "path-probe"]
with contextlib.redirect_stdout(io.StringIO()):
    try:
        exec(compile(bootstrap.read_bytes(), str(bootstrap), "exec"), namespace)
    except SystemExit as outcome:
        assert outcome.code == 0

# Qualification permits only local transports. This audit hook is a test guard,
# not an OS sandbox; the actual bridge uses a closed synthetic named-pipe target.
def local_network_only(event, args):
    if event == "socket.connect":
        address = args[1]
        if isinstance(address, tuple):
            assert address[0] in ("127.0.0.1", "::1"), "nonlocal network attempt"
    if event == "socket.getaddrinfo":
        assert args[0] in ("localhost", "127.0.0.1", "::1"), "nonlocal DNS attempt"

sys.addaudithook(local_network_only)
import hermes_cli
from tools import mcp_tool
from tools.registry import registry

assert hermes_cli.__version__ == "0.17.0"
prefix = "mcp_context_relay_"

def call(name, arguments):
    result = json.loads(registry.dispatch(prefix + name, arguments))
    assert "error" not in result, result
    result = result.get("structuredContent", result.get("result"))
    assert isinstance(result, dict), result
    return result

try:
    names = mcp_tool.discover_mcp_tools()
    expected = sorted(prefix + name for name in fixture["toolNames"])
    assert sorted(names) == expected, {"names": names, "status": mcp_tool.get_mcp_status()}
    status = call("context_relay_status", {})
    assert status["resolvedProject"] == fixture["projectId"], status
    scope = {"scope": "active_project"}
    memory = call("context_relay_remember", {
        "operationId": fixture["operations"][0], "kind": "note",
        "title": "Actual Hermes client canary", "markdown": "Retain project context. 專案",
        "tags": ["fixture"], "scope": scope,
    })["memory"]
    assert memory["scope"]["projectId"] == fixture["projectId"]
    read = call("context_relay_get", {"recordId": memory["id"]})["record"]["record"]
    assert read["bodyMarkdown"] == "Retain project context. 專案"
    found = call("context_relay_search", {
        "query": "Actual Hermes client canary", "scope": scope, "limit": 10,
    })
    assert any(item["id"] == memory["id"] for item in found["memories"])
    task = call("context_relay_upsert_task", {
        "operationId": fixture["operations"][1], "taskId": None,
        "expectedRevision": None, "title": "Actual Hermes task",
        "bodyMarkdown": "Complete the client fixture.", "status": "open",
    })["task"]
    completed = call("context_relay_complete_task", {
        "operationId": fixture["operations"][2], "taskId": task["id"],
        "expectedRevision": task["revision"],
        "evidence": [{"kind": "result", "summary": "Completed through the actual Hermes client."}],
    })["task"]
    assert completed["status"] == "done"
    assert completed["evidence"][0]["summary"] == "Completed through the actual Hermes client."
    tasks = call("context_relay_list_tasks", {"status": "done"})["tasks"]
    assert any(item["id"] == task["id"] for item in tasks)
    print(json.dumps({"harness": hermes_cli.__version__, "tools": len(names),
                      "projectBound": True, "rememberGetSearch": True, "taskCompletion": True}))
finally:
    mcp_tool.shutdown_mcp_servers()
