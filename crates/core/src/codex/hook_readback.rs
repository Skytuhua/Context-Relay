//! Isolated hook-readback qualification, never compiled into the product.
//!
//! The RPC requests do not approve or run hooks, but app-server startup can
//! migrate its profile and refresh plugins. Use only disposable fixture homes.

use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    path::Path,
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use context_relay_protocol::ClientError;
use process_wrap::std::{ChildWrapper, CommandWrap};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{CodexAdapter, CodexCommandContext, invalid, open_verified_codex_executable};

const OUTPUT_LIMIT: u64 = 256 * 1024;
const TIMEOUT: Duration = Duration::from_secs(30);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

#[cfg(all(test, windows))]
mod native_tests;

/// Native metadata at the time of the check, not evidence of a working bridge.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CodexHookMetadata {
    pub event_name: String,
    pub handler_type: String,
    pub command: Option<String>,
    pub matcher: Option<String>,
    pub timeout_sec: u64,
    pub source: String,
    pub source_path: String,
    pub plugin_id: Option<String>,
    pub is_managed: bool,
    pub enabled: bool,
    pub trust_status: String,
    pub current_hash: String,
    pub key: String,
    pub status_message: Option<String>,
}

impl CodexAdapter {
    /// Query only `hooks/list` in this adapter's selected profile and directory.
    /// This neither grants native trust nor changes the adapter's capability.
    pub fn read_native_hooks(&self) -> Result<Vec<CodexHookMetadata>, ClientError> {
        if self.layout.executable_kind != super::CodexExecutableKind::Native {
            return Err(invalid("Hook readback requires a native Codex executable"));
        }
        let executable =
            open_verified_codex_executable(&self.layout.executable, self.executable_hash)
                .map_err(|_| invalid("Codex executable changed before the hook check"))?;
        let context = CodexCommandContext::new(&self.layout)?;
        let launch = executable.prepare_launch()?;
        let mut command = Command::new(&launch.program);
        command.args(["app-server", "--listen", "stdio://"]);
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;
            command.arg0(&executable.path);
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            use std::os::unix::process::CommandExt as _;
            // SAFETY: no work is performed after fork. Match the CLI runner:
            // force fork/exec so the sealed memfd survives pathname resolution.
            unsafe {
                command.pre_exec(|| Ok(()));
            }
        }
        context.configure(&mut command)?;
        executable
            .revalidate_before_launch()
            .map_err(|_| invalid("Codex executable changed before the hook check"))?;
        let cwd = context
            .working_directory
            .to_str()
            .ok_or_else(|| invalid("Codex working directory cannot be represented"))?;
        let result = run_probe(command, cwd.to_owned(), TIMEOUT).map_err(invalid)?;
        context.validate()?;
        executable
            .revalidate_before_launch()
            .map_err(|_| invalid("Codex executable changed during the hook check"))?;
        parse_hooks(result, &context.working_directory).map_err(invalid)
    }
}

fn parse_hooks(value: Value, cwd: &Path) -> Result<Vec<CodexHookMetadata>, &'static str> {
    #[derive(Deserialize)]
    struct Response {
        data: Vec<Entry>,
    }
    #[derive(Deserialize)]
    struct Entry {
        cwd: String,
        hooks: Vec<CodexHookMetadata>,
        errors: Vec<Value>,
        warnings: Vec<String>,
    }
    let mut response: Response =
        serde_json::from_value(value).map_err(|_| "Codex returned invalid hook metadata")?;
    if response.data.len() != 1 {
        return Err("Codex returned hooks for an unexpected directory");
    }
    let entry = response.data.remove(0);
    if !Path::new(&entry.cwd).is_absolute()
        || fs::canonicalize(&entry.cwd).ok().as_deref() != Some(cwd)
    {
        return Err("Codex returned hooks for an unexpected directory");
    }
    if !entry.errors.is_empty() || !entry.warnings.is_empty() {
        return Err("Codex could not load hook settings without errors or warnings");
    }
    Ok(entry.hooks)
}

fn exchange(
    mut reader: impl BufRead,
    mut writer: impl Write,
    cwd: &str,
) -> Result<Value, &'static str> {
    let mut remaining = OUTPUT_LIMIT;
    send(
        &mut writer,
        &json!({"id":1,"method":"initialize","params":{
            "clientInfo":{"name":"context_relay_hook_check","version":env!("CARGO_PKG_VERSION")},
            "capabilities":{"experimentalApi":true}
        }}),
    )?;
    response(&mut reader, 1, &mut remaining)?;
    send(&mut writer, &json!({"method":"initialized"}))?;
    send(
        &mut writer,
        &json!({"id":2,"method":"hooks/list","params":{"cwds":[cwd]}}),
    )?;
    response(&mut reader, 2, &mut remaining)
}

fn send(writer: &mut impl Write, value: &Value) -> Result<(), &'static str> {
    let mut bytes =
        serde_json::to_vec(value).map_err(|_| "Codex hook request cannot be encoded")?;
    bytes.push(b'\n');
    if bytes.len() > OUTPUT_LIMIT as usize {
        return Err("Codex hook request is too large");
    }
    writer
        .write_all(&bytes)
        .and_then(|()| writer.flush())
        .map_err(|_| "Codex hook request could not be sent")
}

fn response(
    reader: &mut impl BufRead,
    id: u64,
    remaining: &mut u64,
) -> Result<Value, &'static str> {
    loop {
        let mut line = Vec::new();
        let read = reader
            .by_ref()
            .take(*remaining + 1)
            .read_until(b'\n', &mut line)
            .map_err(|_| "Codex hook response could not be read")? as u64;
        if read == 0 {
            return Err("Codex exited before completing the hook check");
        }
        if read > *remaining {
            return Err("Codex hook response exceeded its output limit");
        }
        *remaining -= read;
        let message = crate::claude_code::parse_unique_json(&line)
            .map_err(|_| "Codex returned an invalid hook response")?;
        if !message.is_object() {
            return Err("Codex returned an invalid hook response");
        }
        // The pinned app-server announces disabled remote control at startup.
        // Do not discard warnings, unknown notices, or evidence of remote activity.
        if id == 2 && disabled_remote_status(&message) {
            continue;
        }
        if message.get("id").and_then(Value::as_u64) != Some(id)
            || message.get("method").is_some()
            || message.get("error").is_some()
            || !message.get("result").is_some_and(Value::is_object)
        {
            return Err("Codex rejected the hook check or returned an unexpected response");
        }
        return Ok(message["result"].clone());
    }
}

fn disabled_remote_status(message: &Value) -> bool {
    message.as_object().is_some_and(|object| object.len() == 2)
        && message.get("id").is_none()
        && message.get("error").is_none()
        && message.get("result").is_none()
        && message.get("method").and_then(Value::as_str) == Some("remoteControl/status/changed")
        && message
            .get("params")
            .and_then(Value::as_object)
            .is_some_and(|params| {
                params.len() == 4
                    && params.get("status").and_then(Value::as_str) == Some("disabled")
                    && params.get("serverName").is_some_and(Value::is_string)
                    && params.get("installationId").is_some_and(Value::is_string)
                    && params.get("environmentId") == Some(&Value::Null)
            })
}

struct ProbeChild(Box<dyn ChildWrapper>);

impl Drop for ProbeChild {
    fn drop(&mut self) {
        let _ = self.0.start_kill();
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        while Instant::now() < deadline {
            if !matches!(self.0.try_wait(), Ok(None)) {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

fn run_probe(mut command: Command, cwd: String, timeout: Duration) -> Result<Value, &'static str> {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut wrapped = CommandWrap::from(command);
    #[cfg(windows)]
    {
        use process_wrap::std::{CreationFlags, JobObject};
        let mut flags = CreationFlags(Default::default());
        flags.0.0 = 0x0800_0000; // CREATE_NO_WINDOW, preserved alongside suspension for job assignment.
        wrapped.wrap(flags).wrap(JobObject);
    }
    #[cfg(unix)]
    wrapped.wrap(process_wrap::std::ProcessGroup::leader());
    let mut child = ProbeChild(
        wrapped
            .spawn()
            .map_err(|_| "Codex hook check could not start in a contained process")?,
    );
    let stdin = child
        .0
        .stdin()
        .take()
        .ok_or("Codex hook input is unavailable")?;
    let stdout = child
        .0
        .stdout()
        .take()
        .ok_or("Codex hook output is unavailable")?;
    let stderr = child
        .0
        .stderr()
        .take()
        .ok_or("Codex hook diagnostics are unavailable")?;
    let (tx, rx) = mpsc::channel();
    let rpc = thread::Builder::new()
        .name("codex-hook-readback".into())
        .spawn(move || {
            let _ = tx.send(exchange(BufReader::new(stdout), stdin, &cwd));
        })
        .map_err(|_| "Codex hook reader could not start")?;
    let diagnostics = thread::Builder::new()
        .name("codex-hook-diagnostics".into())
        .spawn(move || {
            let mut bytes = Vec::new();
            stderr
                .take(OUTPUT_LIMIT + 1)
                .read_to_end(&mut bytes)
                .map(|_| bytes)
        })
        .map_err(|_| "Codex hook diagnostics reader could not start")?;
    let result = rx
        .recv_timeout(timeout)
        .map_err(|_| "Codex hook check timed out")
        .and_then(|result| result);
    // Always end the process tree, including children left after a successful response.
    drop(child);
    let deadline = Instant::now() + CLEANUP_TIMEOUT;
    while !(rpc.is_finished() && diagnostics.is_finished()) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    if !(rpc.is_finished() && diagnostics.is_finished()) {
        return Err("Codex hook check did not finish shutting down");
    }
    rpc.join().map_err(|_| "Codex hook reader failed")?;
    let stderr = diagnostics
        .join()
        .map_err(|_| "Codex hook diagnostics reader failed")?
        .map_err(|_| "Codex hook diagnostics could not be read")?;
    if !stderr.is_empty() {
        return Err("Codex reported diagnostics during the hook check");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn reads_only_hooks_after_initialization() {
        let input = b"{\"id\":1,\"result\":{\"userAgent\":\"codex\"}}\n{\"id\":2,\"result\":{\"data\":[]}}\n";
        let mut sent = Vec::new();
        assert_eq!(
            exchange(Cursor::new(input), &mut sent, "C:/project").unwrap(),
            json!({"data":[]})
        );
        let messages: Vec<Value> = sent
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect();
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0]["method"], "initialize");
        assert_eq!(messages[1]["method"], "initialized");
        assert_eq!(
            messages[2],
            json!({"id":2,"method":"hooks/list","params":{"cwds":["C:/project"]}})
        );
    }

    #[test]
    fn rejects_failed_or_invalid_initialization_before_sending_hook_request() {
        for input in [
            "{\"id\":1,\"error\":{\"code\":-1}}\n",
            "{\"id\":2,\"result\":{}}\n",
            "{\"id\":1,\"result\":{},\"error\":{}}\n",
            "not JSON\n",
            "",
        ] {
            let mut sent = Vec::new();
            assert!(exchange(Cursor::new(input), &mut sent, "C:/project").is_err());
            assert!(!String::from_utf8(sent).unwrap().contains("hooks/list"));
        }
    }

    #[test]
    fn rejects_unbounded_output_and_server_requests() {
        for input in [
            "x".repeat(256 * 1024 + 1),
            "{\"id\":44,\"method\":\"approve\"}\n".into(),
            "{\"method\":\"notice\"}\n".repeat(20_000),
        ] {
            assert!(exchange(Cursor::new(input), Vec::new(), "C:/project").is_err());
        }
    }

    #[test]
    fn rejects_diagnostic_notifications_before_and_after_initialization() {
        for method in [
            "configWarning",
            "warning",
            "error",
            "unknownFutureNotification",
        ] {
            for initialized in [false, true] {
                let initialization = "{\"id\":1,\"result\":{}}\n";
                let notification = format!("{{\"method\":\"{method}\",\"params\":{{}}}}\n");
                let input = if initialized {
                    format!(
                        "{initialization}{notification}{{\"id\":2,\"result\":{{\"data\":[]}}}}\n"
                    )
                } else {
                    format!(
                        "{notification}{initialization}{{\"id\":2,\"result\":{{\"data\":[]}}}}\n"
                    )
                };
                let mut sent = Vec::new();
                assert!(
                    exchange(Cursor::new(input), &mut sent, "C:/project").is_err(),
                    "accepted {method} with initialized={initialized}"
                );
                if !initialized {
                    assert!(!String::from_utf8(sent).unwrap().contains("hooks/list"));
                }
            }
        }
    }

    #[test]
    fn duplicate_keys_cannot_hide_wrong_directories_or_load_failures() {
        for entry in [
            r#"{"cwd":"wrong","cwd":"C:/project","hooks":[],"errors":[],"warnings":[]}"#,
            r#"{"cwd":"C:/project","hooks":[],"errors":[{}],"errors":[],"warnings":[]}"#,
            r#"{"cwd":"C:/project","hooks":[],"errors":[],"warnings":["bad"],"warnings":[]}"#,
        ] {
            let input = format!(
                "{{\"id\":1,\"result\":{{}}}}\n{{\"id\":2,\"result\":{{\"data\":[{entry}]}}}}\n"
            );
            assert!(exchange(Cursor::new(input), Vec::new(), "C:/project").is_err());
        }
    }

    #[test]
    fn only_inactive_remote_status_notifications_are_ignored_within_the_output_budget() {
        let notification = json!({"method":"remoteControl/status/changed","params":{
            "status":"disabled","serverName":"fixture","installationId":"fixture-id","environmentId":null
        }});
        let prefix = "{\"id\":1,\"result\":{}}\n";
        let suffix = "{\"id\":2,\"result\":{\"data\":[]}}\n";
        let good = format!("{prefix}{notification}\n{suffix}");
        assert!(exchange(Cursor::new(good), Vec::new(), "C:/project").is_ok());
        assert!(
            exchange(
                Cursor::new(format!("{notification}\n{prefix}{suffix}")),
                Vec::new(),
                "C:/project"
            )
            .is_err()
        );
        let mut invalid = Vec::new();
        for status in ["connecting", "connected", "errored"] {
            let mut notice = notification.clone();
            notice["params"]["status"] = json!(status);
            invalid.push(notice);
        }
        let mut active = notification.clone();
        active["params"]["environmentId"] = json!("remote");
        invalid.push(active);
        let mut missing = notification.clone();
        missing["params"]
            .as_object_mut()
            .unwrap()
            .remove("installationId");
        invalid.push(missing);
        let mut request = notification.clone();
        request["id"] = json!(9);
        invalid.push(request);
        let mut extra = notification.clone();
        extra["warning"] = json!("must not be hidden");
        invalid.push(extra);
        for notice in invalid {
            assert!(
                exchange(
                    Cursor::new(format!("{prefix}{notice}\n{suffix}")),
                    Vec::new(),
                    "C:/project"
                )
                .is_err()
            );
        }
        assert!(
            exchange(
                Cursor::new(format!(
                    "{prefix}{}",
                    format!("{notification}\n").repeat(3000)
                )),
                Vec::new(),
                "C:/project"
            )
            .is_err()
        );
    }

    #[test]
    fn hook_metadata_must_belong_to_exactly_the_selected_directory() {
        let root = tempfile::tempdir().unwrap();
        let cwd = fs::canonicalize(root.path()).unwrap();
        let entry = json!({"cwd":cwd,"hooks":[],"errors":[],"warnings":[]});
        assert!(
            parse_hooks(json!({"data":[entry.clone()]}), &cwd)
                .unwrap()
                .is_empty()
        );
        for value in [
            json!({"data":[]}),
            json!({"data":[entry.clone(), entry.clone()]}),
            json!({"data":[{"cwd":".","hooks":[],"errors":[],"warnings":[]}]}),
            json!({"data":[{"cwd":cwd,"hooks":[],"errors":[{}],"warnings":[]}]}),
            json!({"data":[{"cwd":cwd,"hooks":[],"errors":[],"warnings":["incomplete"]}]}),
            json!({"data":[{"cwd":cwd,"hooks":[{}],"errors":[],"warnings":[]}]}),
        ] {
            assert!(parse_hooks(value, &cwd).is_err());
        }
    }

    pub(super) fn compile_probe(directory: &Path) -> std::path::PathBuf {
        let executable = directory.join(if cfg!(windows) { "probe.exe" } else { "probe" });
        let mut compiler = Command::new("rustc");
        compiler
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/codex-hook-readback.rs"),
            )
            .args(["--crate-name", "codex_hook_probe", "-o"])
            .arg(&executable);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt as _;
            compiler.creation_flags(0x0800_0000);
        }
        let compiled = compiler.output().unwrap();
        assert!(
            compiled.status.success(),
            "{}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        executable
    }

    #[test]
    fn verified_adapter_reads_metadata_through_its_prepared_image() {
        use super::super::{CodexExecutableKind, CodexLayout};
        use context_relay_protocol::{DeviceId, HybridLogicalClock, InstallationMethod};
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let executable = compile_probe(&root);
        let home = root.join("home");
        let config = root.join("config");
        let project = root.join("project");
        for path in [&home, &config, &project] {
            fs::create_dir(path).unwrap();
        }
        fs::write(project.join("mode"), "metadata").unwrap();
        fs::write(project.join("response"), serde_json::to_vec(&json!({"id":2,"result":{"data":[{"cwd":project,"hooks":[],"errors":[],"warnings":[]}]}})).unwrap()).unwrap();
        let device: DeviceId = "018f22e2-79b0-7cc8-98c4-dc0c0c073982".parse().unwrap();
        let adapter = CodexAdapter::from_layout(
            CodexLayout {
                executable,
                executable_kind: CodexExecutableKind::Native,
                version: "0.144.6".into(),
                installation_method: InstallationMethod::Manual,
                codex_home: config,
                user_home: home.clone(),
                user_skills_dir: home.join(".agents/skills"),
                project_root: project.clone(),
                working_directory: project.clone(),
                requirements_paths: vec![],
            },
            "018f22e2-79b0-7cc8-98c4-dc0c0c073981".parse().unwrap(),
            device,
            HybridLogicalClock::new(1, 0, device),
        )
        .unwrap();
        assert!(adapter.read_native_hooks().unwrap().is_empty());
        let mut wrapper = adapter.clone();
        wrapper.layout.executable_kind = CodexExecutableKind::Wrapper;
        assert!(wrapper.read_native_hooks().is_err());
        assert_eq!(
            fs::read_to_string(project.join("requests"))
                .unwrap()
                .lines()
                .count(),
            3
        );
    }

    #[test]
    fn process_probe_stops_descendants_on_success_failure_and_timeout() {
        let temp = tempfile::tempdir().unwrap();
        let executable = compile_probe(temp.path());
        let mut cases = Vec::new();
        for mode in ["valid", "malformed", "hang", "stdout", "stderr"] {
            let case = temp.path().join(mode);
            fs::create_dir(&case).unwrap();
            fs::write(case.join("mode"), mode).unwrap();
            fs::write(case.join("response"), r#"{"id":2,"result":{"data":[]}}"#).unwrap();
            let mut command = Command::new(&executable);
            command.current_dir(&case);
            let start = Instant::now();
            let result = run_probe(
                command,
                case.to_str().unwrap().to_owned(),
                Duration::from_millis(500),
            );
            assert_eq!(result.is_ok(), mode == "valid", "{mode}: {result:?}");
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "{mode} exceeded deadline"
            );
            assert!(
                case.join("descendant-started").exists(),
                "{mode} did not exercise a descendant"
            );
            if mode == "valid" {
                assert_eq!(
                    fs::read_to_string(case.join("requests"))
                        .unwrap()
                        .lines()
                        .count(),
                    3
                );
            }
            cases.push(case);
        }
        thread::sleep(Duration::from_millis(1700));
        for case in cases {
            assert!(
                !case.join("escaped").exists(),
                "descendant survived: {}",
                case.display()
            );
        }
    }
}
