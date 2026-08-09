use std::{
    ffi::OsString,
    path::Path,
    str::FromStr as _,
    time::{SystemTime, UNIX_EPOCH},
};

use context_relay_protocol::{
    CompletionEvidenceInput, HarnessId, LocalRequest, LocalResult, MAX_ARBITRARY_BYTES, McpBinding,
    NativeHookEvent, NativeHookEventParams, TaskId,
};
use serde_json::{Map, Value};
use tokio::io::{AsyncRead, AsyncReadExt as _};

use crate::{BridgeError, LocalDaemon, NativeHookDaemon, daemon::invalid_daemon_result};

pub const MAX_HOOK_INPUT_BYTES: usize = MAX_ARBITRARY_BYTES;
pub const SESSION_START_REMINDER: &str =
    "Query Context Relay for the active project before relying on recalled context.\n";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HookInvocationKind {
    SessionStart,
    SessionStop,
    TaskEvidence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Invocation {
    Mcp {
        harness: HarnessId,
    },
    Hook {
        harness: HarnessId,
        event: HookInvocationKind,
    },
}

pub fn parse_invocation(arguments: impl IntoIterator<Item = OsString>) -> Option<Invocation> {
    let mut arguments = arguments.into_iter();
    arguments.next()?;
    match arguments.next()?.to_str()? {
        "--harness" => {
            let harness = parse_harness_name(arguments.next()?)?;
            arguments
                .next()
                .is_none()
                .then_some(Invocation::Mcp { harness })
        }
        "--hook-event" => {
            let event = parse_event_name(arguments.next()?)?;
            if arguments.next()?.to_str()? != "--harness" {
                return None;
            }
            let harness = parse_harness_name(arguments.next()?)?;
            if arguments.next().is_some() || !supported_hook(harness, event) {
                return None;
            }
            Some(Invocation::Hook { harness, event })
        }
        _ => None,
    }
}

fn parse_harness_name(value: OsString) -> Option<HarnessId> {
    match value.to_str()? {
        "claude-code" => Some(HarnessId::ClaudeCode),
        "codex" => Some(HarnessId::Codex),
        "hermes" => Some(HarnessId::Hermes),
        _ => None,
    }
}

fn parse_event_name(value: OsString) -> Option<HookInvocationKind> {
    match value.to_str()? {
        "session-start" => Some(HookInvocationKind::SessionStart),
        "session-stop" => Some(HookInvocationKind::SessionStop),
        "task-evidence" => Some(HookInvocationKind::TaskEvidence),
        _ => None,
    }
}

fn supported_hook(harness: HarnessId, event: HookInvocationKind) -> bool {
    matches!(
        (harness, event),
        (
            HarnessId::ClaudeCode | HarnessId::Codex,
            HookInvocationKind::SessionStart
                | HookInvocationKind::SessionStop
                | HookInvocationKind::TaskEvidence
        )
    )
}

pub fn project_hook_input(
    harness: HarnessId,
    event: HookInvocationKind,
    bytes: &[u8],
    cwd: &Path,
    now_ms: u64,
) -> Result<NativeHookEventParams, BridgeError> {
    if bytes.len() > MAX_HOOK_INPUT_BYTES {
        return Err(BridgeError::HookInputTooLarge);
    }
    if !supported_hook(harness, event) {
        return Err(BridgeError::InvalidHookInput);
    }
    let value =
        serde_json::from_slice::<Value>(bytes).map_err(|_| BridgeError::InvalidHookInput)?;
    let object = value.as_object().ok_or(BridgeError::InvalidHookInput)?;
    let session_id = required_string(object, "session_id")?.to_owned();
    let event = match event {
        HookInvocationKind::SessionStart => NativeHookEvent::SessionStart { session_id },
        HookInvocationKind::SessionStop => NativeHookEvent::SessionStop { session_id },
        HookInvocationKind::TaskEvidence => NativeHookEvent::TaskEvidence {
            session_id,
            task_id: TaskId::from_str(required_string(object, "task_id")?)
                .map_err(|_| BridgeError::InvalidHookInput)?,
            evidence: project_evidence(object)?,
        },
    };
    let params = NativeHookEventParams {
        binding: McpBinding {
            harness,
            working_directory: crate::encode_native_path(cwd),
        },
        event,
        occurred_at_ms: now_ms,
    };
    LocalRequest::NativeHookEvent(params.clone())
        .validate()
        .map_err(|_| BridgeError::InvalidHookInput)?;
    Ok(params)
}

fn project_evidence(
    object: &Map<String, Value>,
) -> Result<Vec<CompletionEvidenceInput>, BridgeError> {
    object
        .get("evidence")
        .and_then(Value::as_array)
        .ok_or(BridgeError::InvalidHookInput)?
        .iter()
        .map(|item| {
            let item = item.as_object().ok_or(BridgeError::InvalidHookInput)?;
            let reference = match item.get("reference") {
                None | Some(Value::Null) => None,
                Some(Value::String(reference)) => Some(reference.clone()),
                Some(_) => return Err(BridgeError::InvalidHookInput),
            };
            Ok(CompletionEvidenceInput {
                summary: required_string(item, "summary")?.to_owned(),
                kind: required_string(item, "kind")?.to_owned(),
                reference,
            })
        })
        .collect()
}

fn required_string<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str, BridgeError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(BridgeError::InvalidHookInput)
}

pub async fn read_hook_input(reader: impl AsyncRead + Unpin) -> Result<Vec<u8>, BridgeError> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_HOOK_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .await
        .map_err(BridgeError::from)?;
    if bytes.len() > MAX_HOOK_INPUT_BYTES {
        return Err(BridgeError::HookInputTooLarge);
    }
    Ok(bytes)
}

pub async fn execute_hook<D: NativeHookDaemon>(
    daemon: D,
    harness: HarnessId,
    event: HookInvocationKind,
    bytes: &[u8],
    cwd: &Path,
    now_ms: u64,
) -> Result<&'static str, BridgeError> {
    let params = project_hook_input(harness, event, bytes, cwd, now_ms)?;
    match daemon.native_hook(params).await? {
        LocalResult::Empty => match event {
            HookInvocationKind::SessionStart => Ok(SESSION_START_REMINDER),
            HookInvocationKind::SessionStop | HookInvocationKind::TaskEvidence => Ok(""),
        },
        _ => Err(invalid_daemon_result()),
    }
}

pub async fn run_hook_stdio(
    harness: HarnessId,
    event: HookInvocationKind,
) -> Result<&'static str, BridgeError> {
    let bytes = read_hook_input(tokio::io::stdin()).await?;
    let cwd = std::env::current_dir().map_err(|_| BridgeError::Unavailable)?;
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BridgeError::Unavailable)?
        .as_millis()
        .try_into()
        .map_err(|_| BridgeError::Unavailable)?;
    execute_hook(LocalDaemon::default(), harness, event, &bytes, &cwd, now_ms).await
}
