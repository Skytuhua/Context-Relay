"""Executed after the contained copied-runtime bootstrap; no ordinary profile."""
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import yaml
import hermes_cli

assert hermes_cli.__version__ == "0.17.0"

PREFIX = "mcp_context_relay_"
FINAL = "HERMES_CONTEXT_RELAY_CONVERSATION_PASSED"
MODEL = "context-relay-fixture"
state = {"step": 0, "errors": [], "memory": None, "task": None}


class BoundedOutput(io.StringIO):
    def __init__(self):
        super().__init__()
        self.byte_count = 0

    def write(self, value):
        self.byte_count += len(value.encode("utf-8"))
        assert self.byte_count <= 65536, "CLI output size limit"
        return super().write(value)


def tool_result(messages, step):
    matches = [m for m in messages if m.get("role") == "tool"
               and m.get("tool_call_id") == f"relay-{step}"]
    assert len(matches) == 1, "missing or duplicate tool result"
    content = matches[0]["content"]
    name = matches[0]["name"]
    assert name in [PREFIX + tool for tool in fixture["toolNames"]]
    # Hermes labels MCP output as untrusted data before passing it to a model.
    # Preserve that native behavior; inspect only the enclosed JSON payload.
    assert content.startswith(f'<untrusted_tool_result source="{name}">\n')
    assert content.endswith("\n</untrusted_tool_result>")
    _warning, separator, payload = content.partition("\n\n")
    assert separator, "missing native untrusted-content delimiter"
    try:
        result = json.loads(payload.removesuffix("\n</untrusted_tool_result>"))
    except json.JSONDecodeError as error:
        raise AssertionError(f"tool payload JSON: {payload[:80]!r}") from error
    assert "error" not in result, result
    result = result.get("structuredContent", result.get("result"))
    assert isinstance(result, dict), result
    return result


def next_message(body):
    step = state["step"]
    assert body["model"] == MODEL
    tools = body.get("tools", [])
    assert sorted(t["function"]["name"] for t in tools) == sorted(
        PREFIX + name for name in fixture["toolNames"]
    ), "CLI must expose precisely the configured Context Relay tools"
    if step:
        result = tool_result(body["messages"], step - 1)
        if step == 1:
            assert result["resolvedProject"] == fixture["projectId"]
        elif step == 2:
            state["memory"] = result["memory"]
            assert state["memory"]["scope"]["projectId"] == fixture["projectId"]
        elif step == 3:
            assert result["record"]["record"]["bodyMarkdown"] == "CLI conversation context. 專案"
        elif step == 4:
            assert any(m["id"] == state["memory"]["id"] for m in result["memories"])
        elif step == 5:
            state["task"] = result["task"]
        elif step == 6:
            assert result["task"]["status"] == "done"
            assert result["task"]["evidence"][0]["summary"] == "Completed by the Hermes CLI conversation."
        elif step == 7:
            assert any(t["id"] == state["task"]["id"] for t in result["tasks"])
        else:
            raise AssertionError("unexpected extra model request")
    scope = {"scope": "active_project"}
    requests = [
        ("context_relay_status", {}),
        ("context_relay_remember", {"operationId": fixture["operations"][0], "kind": "note",
         "title": "Hermes CLI conversation canary", "markdown": "CLI conversation context. 專案",
         "tags": ["fixture"], "scope": scope}),
        ("context_relay_get", {"recordId": (state["memory"] or {}).get("id")}),
        ("context_relay_search", {"query": "Hermes CLI conversation canary", "scope": scope, "limit": 10}),
        ("context_relay_upsert_task", {"operationId": fixture["operations"][1], "taskId": None,
         "expectedRevision": None, "title": "Hermes CLI conversation task",
         "bodyMarkdown": "Complete the conversation fixture.", "status": "open"}),
        ("context_relay_complete_task", {"operationId": fixture["operations"][2],
         "taskId": (state["task"] or {}).get("id"), "expectedRevision": (state["task"] or {}).get("revision"),
         "evidence": [{"kind": "result", "summary": "Completed by the Hermes CLI conversation."}]}),
        ("context_relay_list_tasks", {"status": "done"}),
    ]
    state["step"] += 1
    if step == len(requests):
        return {"role": "assistant", "content": FINAL}, "stop"
    name, arguments = requests[step]
    return {"role": "assistant", "content": None, "tool_calls": [{
        "id": f"relay-{step}", "type": "function",
        "function": {"name": PREFIX + name, "arguments": json.dumps(arguments)},
    }]}, "tool_calls"


class ModelHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_POST(self):
        stage = "headers"
        try:
            # Hermes probes custom providers for Ollama metadata. This fixture
            # serves the chat API only; a normal 404 declines that optional probe.
            if self.path == "/api/show":
                self.send_error(404, "Ollama metadata is not provided")
                return
            assert self.path == "/v1/chat/completions", f"unexpected API path: {self.path[:120]}"
            assert self.headers.get("Authorization") == "Bearer relay-synthetic-only"
            size = int(self.headers.get("Content-Length", "0"))
            assert 0 < size <= 2 * 1024 * 1024, "model request size limit"
            stage = "request JSON"
            body = json.loads(self.rfile.read(size))
            stage = "conversation"
            message, finish = next_message(body)
            response = {"id": "relay-model", "object": "chat.completion", "created": 1,
                        "model": MODEL, "choices": [{"index": 0, "message": message, "finish_reason": finish}],
                        "usage": {"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20}}
            if body.get("stream"):
                delta = dict(message)
                if "tool_calls" in delta:
                    delta["tool_calls"] = [dict(call, index=i) for i, call in enumerate(delta["tool_calls"])]
                response["object"] = "chat.completion.chunk"
                response["choices"] = [{"index": 0, "delta": delta, "finish_reason": None}]
                stop = dict(response, choices=[{"index": 0, "delta": {}, "finish_reason": finish}])
                payload = ("data: " + json.dumps(response) + "\n\ndata: " + json.dumps(stop) + "\n\ndata: [DONE]\n\n").encode()
                content_type = "text/event-stream"
            else:
                payload = json.dumps(response).encode()
                content_type = "application/json"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except Exception as error:
            state["errors"].append({"step": state["step"], "path": self.path[:120], "stage": stage,
                                    "encoding": self.headers.get("Content-Encoding", "identity")[:40],
                                    "error": repr(error)[:500]})
            self.send_error(400, "synthetic conversation assertion failed")


server = HTTPServer(("127.0.0.1", 0), ModelHandler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
config_path = home / "config.yaml"
original_settings = config_path.read_bytes()
settings = yaml.safe_load(original_settings)
settings["model"] = {"default": MODEL, "provider": "custom", "api_mode": "chat_completions",
                     "base_url": f"http://127.0.0.1:{server.server_port}/v1", "api_key": "relay-synthetic-only"}
output = BoundedOutput()
try:
    config_path.write_text(yaml.safe_dump(settings), encoding="utf-8")
    from hermes_cli.main import main
    sys.argv = ["hermes", "-z", "Save and retrieve project context, then create and complete a task.",
                "--toolsets", "context-relay"]
    with contextlib.redirect_stdout(output):
        try:
            main()
        except SystemExit as outcome:
            assert outcome.code in (None, 0), {"exit": outcome.code, "errors": state["errors"]}
    assert not state["errors"], state["errors"]
    assert state["step"] == 8, state["step"]
    assert FINAL in output.getvalue(), output.getvalue()
finally:
    try:
        from tools import mcp_tool
        mcp_tool.shutdown_mcp_servers()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        config_path.write_bytes(original_settings)
        assert not thread.is_alive()
print(json.dumps({"harness": hermes_cli.__version__, "cliConversation": True, "modelRequests": state["step"],
                  "projectBound": True, "rememberGetSearch": True, "taskCompletion": True}))
