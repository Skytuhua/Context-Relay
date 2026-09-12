use std::{path::Path, str::FromStr as _};

use context_relay_protocol::{
    ClientError, ComponentKind, ComponentRecord, DeviceId, ErrorCode, HarnessId,
    HybridLogicalClock, NativePlatform, Provenance, RecordId, ScopeRef, WireNativeValue,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::mcp::install::harness_cli_name;

const DRAFT_DEVICE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073982";
const MEMORY_HOOK_STATUS_MESSAGE: &str = "Context Relay memory lifecycle";
const CLAUDE_EVENTS: [(&str, &str); 2] =
    [("SessionStart", "session-start"), ("Stop", "session-stop")];
const CODEX_EVENTS: [(&str, &str); 2] =
    [("SessionStart", "session-start"), ("Stop", "session-stop")];

pub fn managed_memory_hooks(
    harness: HarnessId,
    bridge_executable: &WireNativeValue,
) -> Result<Vec<ComponentRecord>, ClientError> {
    bridge_executable
        .validate()
        .map_err(|_| invalid("Product memory hook executable is invalid"))?;
    if harness == HarnessId::Hermes {
        return Ok(Vec::new());
    }
    let executable = literal_executable(harness, bridge_executable)?;
    let events = managed_events(harness);
    let harness_name = harness_cli_name(harness);
    let mut hooks = serde_json::Map::new();
    for (native_event, hook_event) in events {
        let command = format!("{executable} --hook-event {hook_event} --harness {harness_name}");
        hooks.insert(
            (*native_event).to_owned(),
            json!([{"hooks": [{
                "command": command,
                "statusMessage": MEMORY_HOOK_STATUS_MESSAGE,
                "type": "command"
            }]}]),
        );
    }
    let (name, location) = match harness {
        HarnessId::ClaudeCode => ("hooks", "settings.json#hooks"),
        HarnessId::Codex => ("hooks.json", "hooks.json#hooks"),
        HarnessId::Hermes => unreachable!("Hermes has no frozen lifecycle hooks"),
    };
    let device = DeviceId::from_str(DRAFT_DEVICE_ID)
        .map_err(|_| invalid("Product memory hook provenance cannot be derived"))?;
    let component = ComponentRecord {
        id: managed_hook_record_id(harness)?,
        scope: ScopeRef::Global,
        kind: ComponentKind::Hook,
        name: name.to_owned(),
        body_markdown: serde_json::to_string(&Value::Object(hooks))
            .map_err(|_| invalid("Product memory hooks cannot be rendered"))?,
        metadata: vec![("structuralLocation".to_owned(), location.to_owned())],
        provenance: Provenance {
            origin_device: device,
            harness: Some(harness),
            source: None,
            created_hlc: HybridLogicalClock::new(0, 0, device),
        },
        archived: false,
    };
    component
        .validate()
        .map_err(|_| invalid("Product memory hook component is invalid"))?;
    Ok(vec![component])
}

pub(crate) fn is_managed_memory_hook_component(
    harness: HarnessId,
    component: &ComponentRecord,
) -> bool {
    has_managed_memory_hook_identity(harness, component)
        && valid_managed_hook_body(harness, &component.body_markdown)
}

pub(crate) fn has_managed_memory_hook_identity(
    harness: HarnessId,
    component: &ComponentRecord,
) -> bool {
    let Ok(expected_id) = managed_hook_record_id(harness) else {
        return false;
    };
    component.id == expected_id
        && component.scope == ScopeRef::Global
        && component.kind == ComponentKind::Hook
        && component.provenance.harness == Some(harness)
        && component.provenance.source.is_none()
        && match harness {
            HarnessId::ClaudeCode => {
                component.name == "hooks"
                    && component.metadata
                        == [(
                            "structuralLocation".to_owned(),
                            "settings.json#hooks".to_owned(),
                        )]
            }
            HarnessId::Codex => {
                component.name == "hooks.json"
                    && component.metadata
                        == [(
                            "structuralLocation".to_owned(),
                            "hooks.json#hooks".to_owned(),
                        )]
            }
            HarnessId::Hermes => false,
        }
}

fn valid_managed_hook_body(harness: HarnessId, body: &str) -> bool {
    if harness == HarnessId::Hermes {
        return false;
    }
    let events = managed_events(harness);
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return false;
    };
    if serde_json::to_string(&value).ok().as_deref() != Some(body) {
        return false;
    }
    let Some(object) = value
        .as_object()
        .filter(|object| object.len() == events.len())
    else {
        return false;
    };
    events.iter().all(|(native_event, _)| {
        let Some(entries) = object.get(*native_event).and_then(Value::as_array) else {
            return false;
        };
        let [entry] = entries.as_slice() else {
            return false;
        };
        is_managed_hook_entry(harness, native_event, entry, false)
    })
}

fn is_managed_hook_entry(
    harness: HarnessId,
    native_event: &str,
    entry: &Value,
    allow_legacy: bool,
) -> bool {
    let Some((_, hook_event)) = managed_events(harness)
        .iter()
        .find(|(candidate, _)| *candidate == native_event)
    else {
        return false;
    };
    let Some(entry) = entry.as_object().filter(|entry| entry.len() == 1) else {
        return false;
    };
    let Some(hooks) = entry.get("hooks").and_then(Value::as_array) else {
        return false;
    };
    let [hook] = hooks.as_slice() else {
        return false;
    };
    let Some(hook) = hook.as_object().filter(|hook| hook.len() == 3) else {
        return false;
    };
    let Some(command) = hook.get("command").and_then(Value::as_str) else {
        return false;
    };
    let suffix = format!(
        " --hook-event {hook_event} --harness {}",
        harness_cli_name(harness)
    );
    hook.get("type").and_then(Value::as_str) == Some("command")
        && hook.get("statusMessage").and_then(Value::as_str) == Some(MEMORY_HOOK_STATUS_MESSAGE)
        && !command.contains(['\n', '\r'])
        && command
            .strip_suffix(&suffix)
            .is_some_and(|literal| canonical_literal_executable(harness, literal, allow_legacy))
}

fn bash_literal_path(literal: &str) -> Option<String> {
    let inner = literal
        .strip_prefix('\'')
        .and_then(|literal| literal.strip_suffix('\''))?;
    let segments = inner.split("'\\''").collect::<Vec<_>>();
    if segments.iter().any(|segment| segment.contains('\'')) {
        return None;
    }
    Some(segments.join("'"))
}

fn bash_quote(path: &str) -> String {
    format!("'{}'", path.replace('\'', "'\\''"))
}

#[cfg(windows)]
fn powershell_quote(path: &str) -> String {
    let mut literal = String::from("& '");
    for character in path.chars() {
        literal.push(character);
        if powershell_single_quote(character) {
            literal.push(character);
        }
    }
    literal.push('\'');
    literal
}

#[cfg(windows)]
fn powershell_single_quote(character: char) -> bool {
    // PowerShell's IsSingleQuote also recognizes the four smart single quotes.
    matches!(character, '\'' | '\u{2018}'..='\u{201b}')
}

#[cfg(windows)]
fn powershell_literal_path(literal: &str) -> Option<String> {
    let inner = literal.strip_prefix("& '")?.strip_suffix('\'')?;
    let mut characters = inner.chars();
    let mut path = String::new();
    while let Some(character) = characters.next() {
        if powershell_single_quote(character) && characters.next() != Some(character) {
            return None;
        }
        path.push(character);
    }
    Some(path)
}

#[cfg(not(windows))]
fn canonical_literal_executable(_: HarnessId, literal: &str, _: bool) -> bool {
    bash_literal_path(literal)
        .is_some_and(|path| Path::new(&path).is_absolute() && bash_quote(&path) == literal)
}

#[cfg(windows)]
fn canonical_literal_executable(harness: HarnessId, literal: &str, allow_legacy: bool) -> bool {
    let path = match harness {
        HarnessId::ClaudeCode => bash_literal_path(literal),
        HarnessId::Codex => powershell_literal_path(literal),
        HarnessId::Hermes => None,
    };
    if let Some(path) = path {
        let bytes = path
            .replace('/', "\\")
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        return crate::native_transaction::approval::windows_target_key(&bytes).is_ok_and(|path| {
            match harness {
                HarnessId::ClaudeCode => bash_quote(&path.replace('\\', "/")) == literal,
                HarnessId::Codex => powershell_quote(&path) == literal,
                HarnessId::Hermes => false,
            }
        });
    }
    // Old Context Relay entries remain recognizable for replacement and
    // archival, but cannot be approved as newly generated commands.
    if !allow_legacy {
        return false;
    }
    let Some(path) = literal
        .strip_prefix('"')
        .and_then(|literal| literal.strip_suffix('"'))
    else {
        return false;
    };
    Path::new(path).is_absolute()
        && !path
            .chars()
            .any(|character| matches!(character, '"' | '%' | '!' | '^' | '&' | '|' | '<' | '>'))
        && format!("\"{path}\"") == literal
}

pub(crate) fn merge_managed_memory_hooks(
    harness: HarnessId,
    current: Option<&Value>,
    component: &ComponentRecord,
) -> Result<Value, ClientError> {
    if !is_managed_memory_hook_component(harness, component) {
        return Err(invalid("Product memory hook component is invalid"));
    }
    let desired = serde_json::from_str::<Value>(&component.body_markdown)
        .map_err(|_| invalid("Product memory hook component is invalid"))?;
    let desired = desired
        .as_object()
        .ok_or_else(|| invalid("Product memory hook component is invalid"))?;
    let mut merged = match current {
        Some(Value::Object(current)) => current.clone(),
        None => serde_json::Map::new(),
        Some(_) => return Err(invalid("Native product memory hooks are invalid")),
    };
    let mut remove_empty_events = Vec::new();
    for (event, managed_entries) in desired {
        let managed_entries = managed_entries
            .as_array()
            .filter(|entries| entries.len() == 1)
            .ok_or_else(|| invalid("Product memory hook component is invalid"))?;
        let managed_entry = &managed_entries[0];
        let entries = match merged.get_mut(event) {
            Some(entries) => entries
                .as_array_mut()
                .ok_or_else(|| invalid("Native product memory hooks are invalid"))?,
            None if component.archived => continue,
            None => {
                merged.insert(event.clone(), Value::Array(Vec::new()));
                merged
                    .get_mut(event)
                    .and_then(Value::as_array_mut)
                    .ok_or_else(|| invalid("Native product memory hooks are invalid"))?
            }
        };
        let before = entries.len();
        entries.retain(|entry| !is_managed_hook_entry(harness, event, entry, true));
        let removed = entries.len() != before;
        if component.archived {
            if removed && entries.is_empty() {
                remove_empty_events.push(event.clone());
            }
        } else {
            entries.push(managed_entry.clone());
        }
    }
    for event in remove_empty_events {
        merged.remove(&event);
    }
    Ok(Value::Object(merged))
}

fn managed_events(harness: HarnessId) -> &'static [(&'static str, &'static str)] {
    match harness {
        HarnessId::ClaudeCode => CLAUDE_EVENTS.as_slice(),
        HarnessId::Codex => CODEX_EVENTS.as_slice(),
        HarnessId::Hermes => &[],
    }
}

fn managed_hook_record_id(harness: HarnessId) -> Result<RecordId, ClientError> {
    let mut bytes: [u8; 32] = Sha256::digest(format!(
        "context-relay|primary-memory-hooks|{}",
        harness_cli_name(harness)
    ))
    .into();
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    RecordId::from_str(&format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    ))
    .map_err(|_| invalid("Product memory hook identifier cannot be derived"))
}

#[cfg(not(windows))]
fn literal_executable(_: HarnessId, value: &WireNativeValue) -> Result<String, ClientError> {
    if value.platform != NativePlatform::Macos || value.bytes.contains(&0) {
        return Err(invalid("Product memory hook executable is invalid"));
    }
    let path = std::str::from_utf8(&value.bytes)
        .map_err(|_| invalid("Product memory hook executable is not UTF-8"))?;
    if !Path::new(path).is_absolute() {
        return Err(invalid("Product memory hook executable must be absolute"));
    }
    Ok(bash_quote(path))
}

#[cfg(windows)]
fn literal_executable(harness: HarnessId, value: &WireNativeValue) -> Result<String, ClientError> {
    if value.platform != NativePlatform::Windows || !value.bytes.len().is_multiple_of(2) {
        return Err(invalid("Product memory hook executable is invalid"));
    }
    // Validate before removing a verbatim prefix so Win32 aliases cannot
    // change the executable. Each harness uses a different Windows shell.
    let path = crate::native_transaction::approval::windows_target_key(&value.bytes)
        .map_err(|_| invalid("Product memory hook executable is unsafe"))?;
    match harness {
        HarnessId::ClaudeCode => Ok(bash_quote(&path.replace('\\', "/"))),
        HarnessId::Codex => Ok(powershell_quote(&path)),
        HarnessId::Hermes => Err(invalid("Hermes has no lifecycle hook command")),
    }
}

fn invalid(message: &'static str) -> ClientError {
    ClientError {
        code: ErrorCode::InvalidRequest,
        message: message.to_owned(),
        field_path: None,
        retryable: false,
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    fn wire(path: &str) -> WireNativeValue {
        WireNativeValue {
            platform: NativePlatform::Windows,
            bytes: path.encode_utf16().flat_map(u16::to_le_bytes).collect(),
            display: None,
        }
    }

    #[test]
    fn claude_hooks_use_bash_literals_for_canonical_windows_paths() {
        let component = managed_memory_hooks(
            HarnessId::ClaudeCode,
            &wire(r"\\?\C:\Users\A $HOME\O'Brien\bridge.exe"),
        )
        .unwrap()
        .remove(0);
        let body: Value = serde_json::from_str(&component.body_markdown).unwrap();
        assert_eq!(
            body["SessionStart"][0]["hooks"][0]["command"],
            "'C:/Users/A $HOME/O'\\''Brien/bridge.exe' --hook-event session-start --harness claude-code"
        );
        assert!(is_managed_memory_hook_component(
            HarnessId::ClaudeCode,
            &component
        ));
    }

    #[test]
    fn codex_hooks_use_powershell_literals_for_canonical_windows_paths() {
        let component = managed_memory_hooks(
            HarnessId::Codex,
            &wire(r"\\?\C:\Users\A $HOME\O'Brien\bridge.exe"),
        )
        .unwrap()
        .remove(0);
        let body: Value = serde_json::from_str(&component.body_markdown).unwrap();
        assert_eq!(
            body["SessionStart"][0]["hooks"][0]["command"],
            "& 'C:\\Users\\A $HOME\\O''Brien\\bridge.exe' --hook-event session-start --harness codex"
        );
        assert!(is_managed_memory_hook_component(
            HarnessId::Codex,
            &component
        ));
    }

    #[test]
    fn legacy_codex_windows_quotes_are_only_accepted_for_cleanup() {
        let component = managed_memory_hooks(HarnessId::Codex, &wire(r"\\?\C:\Fixture\bridge.exe"))
            .unwrap()
            .remove(0);
        let mut old_body: Value = serde_json::from_str(&component.body_markdown).unwrap();
        for (event, kind) in CODEX_EVENTS {
            old_body[event][0]["hooks"][0]["command"] = json!(format!(
                r#""\\?\C:\Fixture\old.exe" --hook-event {kind} --harness codex"#
            ));
        }
        let mut old_component = component.clone();
        old_component.body_markdown = serde_json::to_string(&old_body).unwrap();
        assert!(!is_managed_memory_hook_component(
            HarnessId::Codex,
            &old_component
        ));
        assert_eq!(
            merge_managed_memory_hooks(HarnessId::Codex, Some(&old_body), &component).unwrap(),
            serde_json::from_str::<Value>(&component.body_markdown).unwrap()
        );
        let injected = "& 'C:\\Fixture\\bridge.exe'; Write-Output 'extra'";
        assert!(!canonical_literal_executable(
            HarnessId::Codex,
            injected,
            true
        ));
    }

    #[test]
    fn powershell_smart_quote_delimiters_are_escaped_and_only_exact_pairs_are_recognized() {
        let path = r"C:\O‘Brien O’Brien O‚Brien O‛Brien O'Brien “double”\bridge.exe";
        let literal = r"& 'C:\O‘‘Brien O’’Brien O‚‚Brien O‛‛Brien O''Brien “double”\bridge.exe'";
        assert_eq!(powershell_quote(path), literal);
        assert_eq!(powershell_literal_path(literal).as_deref(), Some(path));
        assert!(canonical_literal_executable(
            HarnessId::Codex,
            literal,
            false
        ));
        for character in ['\'', '\u{2018}', '\u{2019}', '\u{201a}', '\u{201b}'] {
            let unescaped =
                format!("& 'C:\\Fixture\\A{character} ; Write-Output synthetic ; #.exe'");
            assert!(powershell_literal_path(&unescaped).is_none());
            assert!(!canonical_literal_executable(
                HarnessId::Codex,
                &unescaped,
                true
            ));
        }
    }

    #[test]
    fn legacy_claude_windows_quotes_are_only_accepted_for_cleanup() {
        let component =
            managed_memory_hooks(HarnessId::ClaudeCode, &wire(r"\\?\C:\Fixture\bridge.exe"))
                .unwrap()
                .remove(0);
        let mut old_body: Value = serde_json::from_str(&component.body_markdown).unwrap();
        old_body["SessionStart"][0]["hooks"][0]["command"] =
            json!(r#""\\?\C:\Fixture\old.exe" --hook-event session-start --harness claude-code"#);
        let mut old_component = component.clone();
        old_component.body_markdown = serde_json::to_string(&old_body).unwrap();
        assert!(!is_managed_memory_hook_component(
            HarnessId::ClaudeCode,
            &old_component
        ));
        let merged =
            merge_managed_memory_hooks(HarnessId::ClaudeCode, Some(&old_body), &component).unwrap();
        let desired: Value = serde_json::from_str(&component.body_markdown).unwrap();
        assert_eq!(merged, desired);
    }

    #[test]
    fn hook_paths_reject_windows_aliases_before_removing_verbatim_prefix() {
        for path in [
            r"\\?\C:\Fixture\bridge.exe.",
            r"\\?\C:\Fixture\bridge.exe ",
            r"\\?\C:\Fixture\NUL.exe",
            r"\\?\C:\Fixture\..\bridge.exe",
            r"\\?\UNC\server\share\bridge.exe",
        ] {
            for harness in [HarnessId::ClaudeCode, HarnessId::Codex] {
                assert!(
                    managed_memory_hooks(harness, &wire(path)).is_err(),
                    "{path}"
                );
            }
        }
    }
}
