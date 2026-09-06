//! Real stdio bridge process, fixed test-only IPC/credentials, production dispatcher.
use context_relay_protocol::ProjectIdentity;
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use uuid::Uuid;

pub(super) fn hold_fixture_image(path: &Path) -> std::fs::File {
    use std::os::windows::fs::OpenOptionsExt as _;
    // Read sharing permits execution; deny write/delete until all round trips finish.
    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(path)
        .unwrap()
}

pub(super) async fn identify_fixture(path: &Path) {
    let mut child = tokio::process::Command::new(path)
        .arg("--fixture-info")
        .env_clear()
        .creation_flags(0x0800_0000)
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut bytes = Vec::new();
        child
            .stdout
            .take()
            .unwrap()
            .take(128)
            .read_to_end(&mut bytes)
            .await
            .unwrap();
        assert_eq!(bytes, b"context-relay-isolated-codex-bridge-fixture-v1\n");
        assert!(child.wait().await.unwrap().success());
    })
    .await
    .expect("test-only bridge identification deadline");
}

fn configured_bridge(
    configuration: &str,
    expected: &Path,
) -> Result<(PathBuf, Vec<String>), &'static str> {
    let config: Value = serde_yaml_ng::from_str(configuration).map_err(|_| "invalid saved YAML")?;
    let entry = config["mcp_servers"]["context-relay"]
        .as_object()
        .ok_or("missing managed bridge")?;
    if entry
        .keys()
        .any(|key| !matches!(key.as_str(), "command" | "args" | "enabled"))
        || entry.get("enabled").is_some_and(|value| value != true)
    {
        return Err("unexpected managed bridge settings");
    }
    let command = entry
        .get("command")
        .and_then(Value::as_str)
        .ok_or("missing managed command")?;
    let args = entry
        .get("args")
        .and_then(Value::as_array)
        .ok_or("missing managed arguments")?;
    if Path::new(command) != expected || args != &[json!("--harness"), json!("hermes")] {
        return Err("saved managed command or arguments do not match the approved bridge");
    }
    Ok((
        PathBuf::from(command),
        args.iter()
            .map(|arg| arg.as_str().unwrap().to_owned())
            .collect(),
    ))
}

pub(super) async fn roundtrip(
    bridge: &Path,
    project_root: &Path,
    project: &ProjectIdentity,
    remembered: Option<&Value>,
    configuration: Option<&str>,
) -> Value {
    assert!(
        remembered.is_none() || configuration.is_some(),
        "readback must use saved harness configuration"
    );
    let (command, args) = configuration
        .map(|config| configured_bridge(config, bridge).unwrap())
        .unwrap_or_else(|| (bridge.to_owned(), vec!["--harness".into(), "hermes".into()]));
    // The containing qualification owns this process tree in a kill-on-close job.
    let mut child = tokio::process::Command::new(command)
        .args(args)
        .current_dir(project_root)
        .env_clear()
        .creation_flags(0x0800_0000)
        .kill_on_drop(true)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut sequence = 0_u32;
    async fn rpc(
        input: &mut tokio::process::ChildStdin,
        output: &mut BufReader<tokio::process::ChildStdout>,
        sequence: &mut u32,
        method: &str,
        params: Value,
    ) -> Value {
        *sequence += 1;
        let mut request = serde_json::to_vec(
            &json!({"jsonrpc":"2.0","id":*sequence,"method":method,"params":params}),
        )
        .unwrap();
        request.push(b'\n');
        let result = tokio::time::timeout(Duration::from_secs(10), async {
            input.write_all(&request).await.unwrap();
            let mut line = Vec::new();
            (&mut *output)
                .take(65_537)
                .read_until(b'\n', &mut line)
                .await
                .unwrap();
            assert!(
                line.len() <= 65_536 && line.last() == Some(&b'\n'),
                "bounded MCP response"
            );
            serde_json::from_slice::<Value>(&line).unwrap()
        })
        .await
        .expect("bridge RPC deadline");
        assert_eq!(result["id"], *sequence);
        assert!(result.get("error").is_none(), "{result}");
        assert_ne!(result["result"]["isError"], true, "{result}");
        result["result"].clone()
    }
    let initialized = rpc(&mut input, &mut output, &mut sequence, "initialize", json!({"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"isolated-hermes-qualification","version":"1"}})).await;
    assert_eq!(initialized["protocolVersion"], "2025-11-25");
    input
        .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
        .await
        .unwrap();
    let tools = rpc(
        &mut input,
        &mut output,
        &mut sequence,
        "tools/list",
        json!({}),
    )
    .await;
    let mut names = tools["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect::<Vec<_>>();
    let mut expected_names = context_relay_protocol::MCP_TOOL_NAMES.to_vec();
    names.sort_unstable();
    expected_names.sort_unstable();
    assert_eq!(names, expected_names);
    let status = rpc(
        &mut input,
        &mut output,
        &mut sequence,
        "tools/call",
        json!({"name":"context_relay_status","arguments":{}}),
    )
    .await;
    assert_eq!(
        status["structuredContent"]["resolvedProject"],
        project.project_id.to_string()
    );
    let memory = if let Some(memory) = remembered {
        memory.clone()
    } else {
        let saved = rpc(&mut input, &mut output, &mut sequence, "tools/call", json!({"name":"context_relay_remember","arguments":{"operationId":Uuid::now_v7().to_string(),"kind":"note","title":"Hermes production bridge canary","markdown":"Keep this project context across daemon restart. 專案","tags":["fixture"],"scope":{"scope":"active_project"}}})).await;
        saved["structuredContent"]["memory"].clone()
    };
    assert_eq!(memory["scope"]["projectId"], project.project_id.to_string());
    assert_eq!(
        memory["bodyMarkdown"],
        "Keep this project context across daemon restart. 專案"
    );
    let read = rpc(
        &mut input,
        &mut output,
        &mut sequence,
        "tools/call",
        json!({"name":"context_relay_get","arguments":{"recordId":memory["id"]}}),
    )
    .await;
    assert_eq!(
        read["structuredContent"]["record"]["record"]["id"],
        memory["id"]
    );
    assert_eq!(
        read["structuredContent"]["record"]["record"]["bodyMarkdown"],
        memory["bodyMarkdown"]
    );
    let search = rpc(&mut input, &mut output, &mut sequence, "tools/call", json!({"name":"context_relay_search","arguments":{"query":"Hermes production bridge canary","scope":{"scope":"active_project"},"limit":10}})).await;
    assert!(
        search["structuredContent"]["memories"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["id"] == memory["id"])
    );
    drop(input);
    assert!(
        tokio::time::timeout(Duration::from_secs(10), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
    memory
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saved_bridge_readback_rejects_wrong_command_arguments_and_overrides() {
        let expected = Path::new(r"C:\fixture\context-relay-context-mcp.exe");
        let entry = json!({"command":expected.to_str().unwrap(),"args":["--harness","hermes"]});
        let configuration =
            |entry| serde_json::to_string(&json!({"mcp_servers":{"context-relay":entry}})).unwrap();
        assert_eq!(
            configured_bridge(&configuration(entry.clone()), expected).unwrap(),
            (
                expected.to_owned(),
                vec!["--harness".to_owned(), "hermes".to_owned()]
            )
        );
        for (key, wrong) in [
            ("command", json!(r"C:\wrong.exe")),
            ("args", json!(["--harness", "codex"])),
            ("args", json!(["--harness", "hermes", "--extra"])),
            ("enabled", json!(false)),
            ("env", json!({"PRIVATE":"unexpected"})),
        ] {
            let mut changed = entry.clone();
            changed[key] = wrong;
            assert!(configured_bridge(&configuration(changed), expected).is_err());
        }
        assert!(configured_bridge("mcp_servers: {}", expected).is_err());
    }

    #[test]
    fn copied_bridge_image_cannot_be_written_or_replaced_while_identified() {
        let fixture = tempfile::tempdir().unwrap();
        let path = fixture.path().join("bridge.exe");
        std::fs::write(&path, b"identified bytes").unwrap();
        let image = hold_fixture_image(&path);
        assert!(std::fs::write(&path, b"replacement").is_err());
        assert!(std::fs::rename(&path, fixture.path().join("moved.exe")).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"identified bytes");
        drop(image);
        std::fs::write(&path, b"replacement").unwrap();
    }
}
