//! Approval recorded for Context Relay's saved user hooks, without launching Codex.
//!
//! This is settings evidence, not proof of a running connection or runtime policy.

use super::*;
use serde::Deserialize;
use serde_json::json;

pub use context_relay_protocol::{SavedHookApproval, SavedMemoryHookApproval};

impl CodexAdapter {
    /// Inspect only the saved user definitions and approval records. No process
    /// starts and no approval is granted. Runtime overrides remain separate.
    pub fn saved_memory_hook_approval(
        &self,
        bridge: &WireNativeValue,
    ) -> Result<SavedMemoryHookApproval, ClientError> {
        if self.layout.version != "0.144.6"
            || self.layout.executable_kind != CodexExecutableKind::Native
        {
            return Err(unsupported(
                "Saved hook approval is not supported for this Codex version",
            ));
        }
        let context = CodexCommandContext::new(&self.layout)?;
        let executable =
            open_verified_codex_executable(&self.layout.executable, self.executable_hash)
                .map_err(|_| invalid("Codex executable changed before the approval check"))?;
        let hook_path = self.layout.codex_home.join("hooks.json");
        let config_path = self.layout.codex_home.join("config.toml");
        let hook_bytes = read_optional_file(&hook_path)?;
        let config_bytes = read_optional_file(&config_path)?;
        let result = assess_saved_hooks(
            &hook_path,
            hook_bytes.as_deref(),
            config_bytes.as_deref(),
            bridge,
        )?;
        if read_optional_file(&hook_path)? != hook_bytes
            || read_optional_file(&config_path)? != config_bytes
        {
            return Err(invalid("Codex settings changed during the approval check"));
        }
        context.validate()?;
        executable
            .revalidate_before_launch()
            .map_err(|_| invalid("Codex executable changed during the approval check"))?;
        Ok(result)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HookFile {
    #[serde(default, rename = "description")]
    _description: Option<String>,
    #[serde(default)]
    hooks: BTreeMap<String, Vec<Group>>,
}

#[derive(Deserialize)]
struct Group {
    #[serde(default)]
    matcher: Option<String>,
    #[serde(default)]
    hooks: Vec<Handler>,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum Handler {
    #[serde(rename = "command")]
    Command {
        command: String,
        #[serde(default, rename = "commandWindows", alias = "command_windows")]
        command_windows: Option<String>,
        #[serde(default, rename = "timeout")]
        timeout: Option<u64>,
        #[serde(default, rename = "async")]
        asynchronous: bool,
        #[serde(default, rename = "statusMessage")]
        status_message: Option<String>,
    },
    #[serde(rename = "prompt")]
    Prompt {},
    #[serde(rename = "agent")]
    Agent {},
}

#[derive(Default, Deserialize)]
struct HookState {
    enabled: Option<bool>,
    trusted_hash: Option<String>,
}

fn assess_saved_hooks(
    path: &Path,
    hooks: Option<&[u8]>,
    config: Option<&[u8]>,
    bridge: &WireNativeValue,
) -> Result<SavedMemoryHookApproval, ClientError> {
    let components = crate::native_memory::managed_memory_hooks(HarnessId::Codex, bridge)?;
    let expected: BTreeMap<String, Vec<Group>> = serde_json::from_str(&components[0].body_markdown)
        .map_err(|_| invalid("Context Relay hook definitions are invalid"))?;
    let hooks = hooks
        .map(|bytes| {
            let value = crate::claude_code::parse_unique_json(bytes)
                .map_err(|_| invalid("Saved Codex hooks are invalid"))?;
            serde_json::from_value::<HookFile>(value)
                .map_err(|_| invalid("Saved Codex hooks are invalid"))
        })
        .transpose()?;
    let states = saved_states(config)?;
    #[cfg(windows)]
    let source = dunce::simplified(path);
    #[cfg(not(windows))]
    let source = path;
    let source = source
        .to_str()
        .ok_or_else(|| invalid("Codex hook source cannot be represented"))?;
    let read = |event: &str, key_event: &str| -> Result<SavedHookApproval, ClientError> {
        let expected_group = &expected[event][0];
        let expected_handler = &expected_group.hooks[0];
        let expected_hash = handler_hash(key_event, expected_group, expected_handler)?
            .ok_or_else(|| invalid("Context Relay hook definition is invalid"))?;
        let Some(groups) = hooks.as_ref().and_then(|file| file.hooks.get(event)) else {
            return Ok(SavedHookApproval::Missing);
        };
        let mut candidates = Vec::new();
        for (group_index, group) in groups.iter().enumerate() {
            for (handler_index, handler) in group.hooks.iter().enumerate() {
                if managed_candidate(handler, expected_handler) {
                    candidates.push((
                        group_index,
                        handler_index,
                        handler_hash(key_event, group, handler)?,
                    ));
                }
            }
        }
        let [(group_index, handler_index, hash)] = candidates.as_slice() else {
            return Ok(if candidates.is_empty() {
                SavedHookApproval::Missing
            } else {
                SavedHookApproval::Changed
            });
        };
        if hash.as_ref() != Some(&expected_hash) {
            return Ok(SavedHookApproval::Changed);
        }
        let key = format!("{source}:{key_event}:{group_index}:{handler_index}");
        let state = states.get(&key);
        if state.is_some_and(|state| state.enabled == Some(false)) {
            return Ok(SavedHookApproval::Disabled);
        }
        Ok(
            match state.and_then(|state| state.trusted_hash.as_deref()) {
                Some(hash) if hash == expected_hash => SavedHookApproval::Approved,
                Some(_) => SavedHookApproval::Changed,
                None => SavedHookApproval::NeedsApproval,
            },
        )
    };
    Ok(SavedMemoryHookApproval {
        session_start: read("SessionStart", "session_start")?,
        stop: read("Stop", "stop")?,
    })
}

fn saved_states(bytes: Option<&[u8]>) -> Result<BTreeMap<String, HookState>, ClientError> {
    let mut states = BTreeMap::new();
    let Some(bytes) = bytes else {
        return Ok(states);
    };
    let document = bytes_to_document(bytes)?;
    let Some(hooks) = document.get("hooks") else {
        return Ok(states);
    };
    let Some(raw) = hooks.get("state") else {
        return Ok(states);
    };
    let raw = raw
        .as_table_like()
        .ok_or_else(|| invalid("Saved Codex hook approval is invalid"))?;
    for (key, value) in raw.iter() {
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        let Ok(state) = serde_json::from_value::<HookState>(toml_item_json(value)) else {
            continue;
        };
        if states.insert(key.to_owned(), state).is_some() {
            return Err(invalid("Saved Codex hook approval keys are ambiguous"));
        }
    }
    Ok(states)
}

fn effective_command(handler: &Handler) -> Option<&str> {
    if let Handler::Command {
        command,
        command_windows,
        ..
    } = handler
    {
        Some(if cfg!(windows) {
            command_windows.as_deref().unwrap_or(command)
        } else {
            command
        })
    } else {
        None
    }
}

fn managed_candidate(actual: &Handler, expected: &Handler) -> bool {
    if effective_command(actual).is_some()
        && effective_command(actual) == effective_command(expected)
    {
        return true;
    }
    matches!((actual, expected),
        (Handler::Command { status_message: Some(actual), .. }, Handler::Command { status_message: Some(expected), .. }) if actual == expected)
}

fn handler_hash(
    event: &str,
    group: &Group,
    handler: &Handler,
) -> Result<Option<String>, ClientError> {
    let Handler::Command {
        timeout,
        asynchronous,
        status_message,
        ..
    } = handler
    else {
        return Ok(None);
    };
    let command =
        effective_command(handler).ok_or_else(|| invalid("Codex command hook is invalid"))?;
    if *asynchronous || command.trim().is_empty() {
        return Ok(None);
    }
    let mut handler = json!({"type":"command", "command":command, "timeout":timeout.unwrap_or(600).max(1), "async":false});
    if let Some(status) = status_message {
        handler["statusMessage"] = json!(status);
    }
    let mut identity = json!({"event_name":event, "hooks":[handler]});
    if event != "stop"
        && let Some(matcher) = &group.matcher
    {
        identity["matcher"] = json!(matcher);
    }
    Ok(Some(format!(
        "sha256:{:x}",
        Sha256::digest(
            serde_json::to_vec(&sorted_json(identity))
                .map_err(|_| invalid("Codex hook fingerprint cannot be encoded"))?
        )
    )))
}

fn sorted_json(value: Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .into_iter()
                .map(|(key, value)| (key, sorted_json(value)))
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.into_iter().map(sorted_json).collect()),
        value => value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> (tempfile::TempDir, CodexAdapter, WireNativeValue) {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let home = root.join("home");
        let config = home.join(".codex");
        let project = root.join("project");
        fs::create_dir_all(&config).unwrap();
        fs::create_dir(&project).unwrap();
        let device = DeviceId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073982").unwrap();
        let adapter = CodexAdapter::from_layout(
            CodexLayout {
                executable: env::current_exe().unwrap(),
                executable_kind: CodexExecutableKind::Native,
                version: "0.144.6".into(),
                installation_method: InstallationMethod::Manual,
                codex_home: config,
                user_home: home.clone(),
                user_skills_dir: home.join(".agents/skills"),
                project_root: project.clone(),
                working_directory: project,
                requirements_paths: vec![],
            },
            ProjectId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073981").unwrap(),
            device,
            HybridLogicalClock::new(1, 0, device),
        )
        .unwrap();
        let bridge = wire_path(&root.join("context-relay bridge.exe"));
        (temp, adapter, bridge)
    }

    #[test]
    fn saved_hooks_require_explicit_approval_and_reading_never_starts_codex() {
        let (_temp, adapter, bridge) = fixture();
        // The selected executable is this test binary, not Codex. A reader
        // that starts it cannot obtain native hook metadata.
        assert_eq!(
            adapter.saved_memory_hook_approval(&bridge).unwrap(),
            SavedMemoryHookApproval {
                session_start: SavedHookApproval::Missing,
                stop: SavedHookApproval::Missing,
            }
        );
        let component = crate::native_memory::managed_memory_hooks(HarnessId::Codex, &bridge)
            .unwrap()
            .remove(0);
        let hooks: Value = serde_json::from_str(&component.body_markdown).unwrap();
        let bytes = serde_json::to_vec(&json!({"hooks":hooks})).unwrap();
        let path = adapter.layout.codex_home.join("hooks.json");
        fs::write(&path, &bytes).unwrap();
        assert_eq!(
            adapter.saved_memory_hook_approval(&bridge).unwrap(),
            SavedMemoryHookApproval {
                session_start: SavedHookApproval::NeedsApproval,
                stop: SavedHookApproval::NeedsApproval,
            }
        );
        assert_eq!(fs::read(path).unwrap(), bytes);
        assert!(!adapter.layout.codex_home.join("config.toml").exists());
        assert!(
            !adapter
                .layout
                .codex_home
                .join(".personality_migration")
                .exists()
        );
    }

    fn approved_fixture() -> (
        tempfile::TempDir,
        CodexAdapter,
        WireNativeValue,
        Value,
        String,
    ) {
        let (temp, adapter, bridge) = fixture();
        let component = crate::native_memory::managed_memory_hooks(HarnessId::Codex, &bridge)
            .unwrap()
            .remove(0);
        let hooks: Value = serde_json::from_str(&component.body_markdown).unwrap();
        let groups: BTreeMap<String, Vec<Group>> = serde_json::from_value(hooks.clone()).unwrap();
        let path = adapter.layout.codex_home.join("hooks.json");
        #[cfg(windows)]
        let source = dunce::simplified(&path);
        #[cfg(not(windows))]
        let source = &path;
        let mut config = String::new();
        for (event, key_event) in [("SessionStart", "session_start"), ("Stop", "stop")] {
            let hash = handler_hash(key_event, &groups[event][0], &groups[event][0].hooks[0])
                .unwrap()
                .unwrap();
            let key = format!("{}:{key_event}:0:0", source.display());
            config.push_str(&format!(
                "\n[hooks.state.{}]\ntrusted_hash = {}\n",
                serde_json::to_string(&key).unwrap(),
                serde_json::to_string(&hash).unwrap()
            ));
        }
        fs::write(&path, serde_json::to_vec(&json!({"hooks":hooks})).unwrap()).unwrap();
        fs::write(adapter.layout.codex_home.join("config.toml"), &config).unwrap();
        (temp, adapter, bridge, hooks, config)
    }

    #[test]
    fn approval_is_exact_and_preserves_the_individual_disable_preference() {
        let (_temp, adapter, bridge, _hooks, config) = approved_fixture();
        assert_eq!(
            adapter.saved_memory_hook_approval(&bridge).unwrap(),
            SavedMemoryHookApproval {
                session_start: SavedHookApproval::Approved,
                stop: SavedHookApproval::Approved
            }
        );
        let path = adapter.layout.codex_home.join("config.toml");
        fs::write(
            &path,
            config.replace("trusted_hash =", "enabled = false\ntrusted_hash ="),
        )
        .unwrap();
        assert_eq!(
            adapter.saved_memory_hook_approval(&bridge).unwrap(),
            SavedMemoryHookApproval {
                session_start: SavedHookApproval::Disabled,
                stop: SavedHookApproval::Disabled
            }
        );
        fs::write(&path, config.replace("sha256:", "changed:")).unwrap();
        assert_eq!(
            adapter
                .saved_memory_hook_approval(&bridge)
                .unwrap()
                .session_start,
            SavedHookApproval::Changed
        );
        fs::write(&path, config.replace(":0:0", ":1:0")).unwrap();
        assert_eq!(
            adapter
                .saved_memory_hook_approval(&bridge)
                .unwrap()
                .session_start,
            SavedHookApproval::NeedsApproval
        );
    }

    #[test]
    fn edited_or_duplicate_managed_definitions_do_not_inherit_approval() {
        let (_temp, adapter, bridge, hooks, _config) = approved_fixture();
        let path = adapter.layout.codex_home.join("hooks.json");
        for (field, value) in [
            ("command", json!("other executable")),
            ("statusMessage", json!("changed")),
            ("timeout", json!(5)),
            ("async", json!(true)),
        ] {
            let mut changed = hooks.clone();
            changed["SessionStart"][0]["hooks"][0][field] = value;
            fs::write(
                &path,
                serde_json::to_vec(&json!({"hooks":changed})).unwrap(),
            )
            .unwrap();
            assert_eq!(
                adapter
                    .saved_memory_hook_approval(&bridge)
                    .unwrap()
                    .session_start,
                SavedHookApproval::Changed,
                "{field}"
            );
        }
        let mut duplicate = hooks.clone();
        let original = duplicate["SessionStart"][0].clone();
        duplicate["SessionStart"]
            .as_array_mut()
            .unwrap()
            .push(original);
        fs::write(
            &path,
            serde_json::to_vec(&json!({"hooks":duplicate})).unwrap(),
        )
        .unwrap();
        assert_eq!(
            adapter
                .saved_memory_hook_approval(&bridge)
                .unwrap()
                .session_start,
            SavedHookApproval::Changed
        );
        let mut shifted = hooks;
        shifted["SessionStart"].as_array_mut().unwrap().insert(
            0,
            json!({"hooks":[{"type":"command","command":"unrelated"}]}),
        );
        fs::write(
            &path,
            serde_json::to_vec(&json!({"hooks":shifted})).unwrap(),
        )
        .unwrap();
        assert_eq!(
            adapter
                .saved_memory_hook_approval(&bridge)
                .unwrap()
                .session_start,
            SavedHookApproval::NeedsApproval
        );
    }

    #[test]
    fn normalization_matches_native_defaults_and_event_matcher_semantics() {
        let (_temp, adapter, bridge, mut hooks, _config) = approved_fixture();
        for event in ["SessionStart", "Stop"] {
            hooks[event][0]["hooks"][0]["timeout"] = json!(600);
            hooks[event][0]["hooks"][0]["async"] = json!(false);
        }
        hooks["Stop"][0]["matcher"] = json!("ignored by this event");
        let path = adapter.layout.codex_home.join("hooks.json");
        fs::write(&path, serde_json::to_vec(&json!({"hooks":hooks})).unwrap()).unwrap();
        assert_eq!(
            adapter.saved_memory_hook_approval(&bridge).unwrap(),
            SavedMemoryHookApproval {
                session_start: SavedHookApproval::Approved,
                stop: SavedHookApproval::Approved
            }
        );
        hooks["SessionStart"][0]["matcher"] = json!("startup");
        fs::write(&path, serde_json::to_vec(&json!({"hooks":hooks})).unwrap()).unwrap();
        assert_eq!(
            adapter
                .saved_memory_hook_approval(&bridge)
                .unwrap()
                .session_start,
            SavedHookApproval::Changed
        );
    }

    #[test]
    fn project_hook_state_cannot_grant_user_approval() {
        let (_temp, adapter, bridge, _hooks, config) = approved_fixture();
        fs::write(adapter.layout.codex_home.join("config.toml"), "").unwrap();
        let directory = adapter.layout.project_root.join(".codex");
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("config.toml"), config).unwrap();
        assert_eq!(
            adapter
                .saved_memory_hook_approval(&bridge)
                .unwrap()
                .session_start,
            SavedHookApproval::NeedsApproval
        );
    }

    #[test]
    fn malformed_or_ambiguous_inputs_never_produce_approved_state() {
        let (_temp, mut adapter, bridge, _hooks, config) = approved_fixture();
        let path = adapter.layout.codex_home.join("hooks.json");
        for bytes in [
            r#"{"hooks":{},"hooks":{}}"#,
            r#"{"hooks":{},"unexpected":true}"#,
            r#"{"hooks":{"Stop":"wrong type"}}"#,
        ] {
            fs::write(&path, bytes).unwrap();
            assert!(adapter.saved_memory_hook_approval(&bridge).is_err());
        }
        fs::write(&path, r#"{"hooks":{}}"#).unwrap();
        let invalid = format!(
            "{config}\n[hooks.state.'same']\nenabled=true\n[hooks.state.' same ']\nenabled=false\n"
        );
        fs::write(adapter.layout.codex_home.join("config.toml"), invalid).unwrap();
        assert!(adapter.saved_memory_hook_approval(&bridge).is_err());
        adapter.layout.version = "unknown".into();
        assert!(adapter.saved_memory_hook_approval(&bridge).is_err());
    }
}
