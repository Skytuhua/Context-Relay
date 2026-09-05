use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(unix)]
use context_relay_core::claude_code::{ClaudeCodeCommandRunner, VerifiedClaudeCommand};
use context_relay_core::{
    claude_code::{ClaudeCodeAdapter, ClaudeCodeLayout},
    mcp::install::bridge_component,
    native_memory::{
        NativeMemoryAdapter, NativeMemoryDisable, NativeMemoryDocumentKind,
        PRIMARY_MEMORY_INSTRUCTIONS, managed_memory_hooks, primary_memory_instruction_component,
    },
    native_transaction::{
        NativeTransactionPlan,
        cli::NativeCliExecutor,
        engine::{BoundaryError, NativeAdapter, NativeFileSystem},
        filesystem::OsNativeTransactionFileSystem,
    },
    setup::BridgePreviewHarness,
};
use context_relay_native_runner::NativeState;
use context_relay_protocol::{
    ApprovalClass, CapabilityLevel, ComponentKind, ComponentRecord, DesiredState, DeviceId,
    ErrorCode, ExpectedNativeDigest, HarnessAdapter, HarnessId, HybridLogicalClock, ImportRequest,
    InstallationMethod, NativePlatform, NativeScope, NetworkDelta, PermissionDelta, PlanId,
    ProbeContext, ProjectId, Provenance, ScopeRef, SetupPlan, Sha256Digest, WireNativeValue,
};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};

const PROJECT_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073981";
const DEVICE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073982";
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    adapter: ClaudeCodeAdapter,
    project_id: ProjectId,
    state_path: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn fixture(source: &str) -> Fixture {
    let fixture: Value = serde_json::from_str(source).unwrap();
    let root = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!(
            "context-relay-claude-code-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
    let config_dir = root.join("custom claude config");
    let project_root = root.join("project with spaces");
    materialize(&config_dir, fixture["config"].as_object().unwrap());
    materialize(&project_root, fixture["project"].as_object().unwrap());

    let state_path = config_dir.join(".claude.json");
    let mut state = fixture["state"].clone();
    let project = state["projects"]
        .as_object_mut()
        .unwrap()
        .remove("$PROJECT")
        .unwrap();
    let mut project = project;
    for (key, value) in fixture["projectMcpApprovals"].as_object().unwrap() {
        project
            .as_object_mut()
            .unwrap()
            .insert(key.clone(), value.clone());
    }
    state["projects"]
        .as_object_mut()
        .unwrap()
        .insert(project_root.to_string_lossy().into_owned(), project);
    fs::write(&state_path, serde_json::to_vec(&state).unwrap()).unwrap();
    let managed_settings_path = root.join("managed-settings.json");
    fs::write(
        &managed_settings_path,
        serde_json::to_vec(&fixture["managedSettings"]).unwrap(),
    )
    .unwrap();
    let executable = root.join(if cfg!(windows) {
        "claude.exe"
    } else {
        "claude"
    });
    // `VerifiedClaudeExecutable::open` verifies the executable is a native
    // PE image on Windows, so the fixture carries a minimal MZ/PE stub
    // there; other platforms accept placeholder bytes.
    let executable_bytes = if cfg!(windows) {
        let mut bytes = vec![0_u8; 0x44];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        let pe_offset: u32 = 0x40;
        bytes[0x3c..0x40].copy_from_slice(&pe_offset.to_le_bytes());
        bytes[0x40..0x44].copy_from_slice(b"PE\0\0");
        bytes
    } else {
        b"fixture executable".to_vec()
    };
    fs::write(&executable, executable_bytes).unwrap();

    let project_id = ProjectId::from_str(PROJECT_ID).unwrap();
    let device_id = DeviceId::from_str(DEVICE_ID).unwrap();
    let adapter = ClaudeCodeAdapter::from_layout(
        ClaudeCodeLayout {
            executable,
            version: fixture["version"].as_str().unwrap().to_owned(),
            installation_method: InstallationMethod::PackageManager,
            user_home: PathBuf::from(root.to_str().unwrap().trim_start_matches(r"\\?\")),
            config_dir,
            state_path: state_path.clone(),
            project_root,
            managed_settings_paths: vec![managed_settings_path],
        },
        project_id,
        device_id,
        HybridLogicalClock::new(1_900_000_000_000, 0, device_id),
    )
    .unwrap();

    Fixture {
        root,
        adapter,
        project_id,
        state_path,
    }
}

fn materialize(root: &Path, files: &Map<String, Value>) {
    for (relative, body) in files {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, body.as_str().unwrap()).unwrap();
    }
}

fn import_everything(fixture: &Fixture) -> context_relay_protocol::ImportedState {
    fixture
        .adapter
        .import(&ImportRequest {
            scopes: vec![
                NativeScope::Global,
                NativeScope::Project {
                    project_id: fixture.project_id,
                    root: fixture.adapter.project_root_wire(),
                },
            ],
            include_disabled: true,
        })
        .unwrap()
}

#[test]
fn supported_release_fixtures_import_the_reviewed_surfaces_without_secrets() {
    for source in [
        include_str!("fixtures/claude-code-2.1.214.json"),
        include_str!("fixtures/claude-code-2.1.213.json"),
    ] {
        let fixture = fixture(source);
        let report = fixture
            .adapter
            .probe(&ProbeContext {
                harness: HarnessId::ClaudeCode,
                requested_profile: None,
            })
            .unwrap();
        assert_eq!(report.capability, CapabilityLevel::Full);
        assert_eq!(
            report.policy_conflicts,
            vec![
                "managed_settings_active".to_owned(),
                "project_mcp_approvals_configured".to_owned(),
            ]
        );

        let imported = import_everything(&fixture);
        let kinds = imported
            .components
            .iter()
            .map(|component| component.kind)
            .collect::<Vec<_>>();
        for kind in [
            ComponentKind::Instruction,
            ComponentKind::Rule,
            ComponentKind::Skill,
            ComponentKind::Plugin,
            ComponentKind::McpServer,
            ComponentKind::Hook,
            ComponentKind::PermissionDeclaration,
        ] {
            assert!(kinds.contains(&kind), "missing {kind:?}");
        }
        let serialized = serde_json::to_string(&imported).unwrap();
        assert!(!serialized.contains("secret"));
        assert!(!serialized.contains("must-survive"));
        assert!(serialized.contains("<redacted>"));
    }
}

#[test]
fn memory_hooks_render_only_frozen_context_relay_compatible_events_with_literal_arguments() {
    for source in [
        include_str!("fixtures/claude-code-2.1.214.json"),
        include_str!("fixtures/claude-code-2.1.213.json"),
    ] {
        let contract: Value = serde_json::from_str(source).unwrap();
        let fixture = fixture(source);
        let bridge = executable_bridge(
            &fixture,
            "context-relay context-mcp",
            b"fixture bridge executable",
        );
        let mut bridge_wire = test_wire_path(&bridge);
        bridge_wire.display = Some("/must-not-use-display".to_owned());
        let components = managed_memory_hooks(HarnessId::ClaudeCode, &bridge_wire).unwrap();
        assert_eq!(components.len(), 1);
        let hooks: Value = serde_json::from_str(&components[0].body_markdown).unwrap();
        let expected = contract["contextRelayCompatibleLifecycleHookEvents"]
            .as_array()
            .unwrap()
            .iter()
            .map(|event| event.as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(hooks.as_object().unwrap().len(), expected.len());
        for native_event in expected {
            let event = match native_event {
                "SessionStart" => "session-start",
                "Stop" => "session-stop",
                _ => panic!("unsupported frozen Claude hook event"),
            };
            let command = hooks[native_event][0]["hooks"][0]["command"]
                .as_str()
                .unwrap();
            let bridge_path = bridge.to_str().unwrap();
            #[cfg(windows)]
            let bridge_path = bridge_path
                .strip_prefix(r"\\?\")
                .unwrap_or(bridge_path)
                .replace('\\', "/");
            #[cfg(windows)]
            assert!(command.contains(&bridge_path));
            #[cfg(not(windows))]
            assert!(command.contains(bridge_path));
            assert!(command.ends_with(&format!(" --hook-event {event} --harness claude-code")));
            assert_eq!(hooks[native_event][0]["hooks"][0]["type"], "command");
            assert_eq!(
                hooks[native_event][0]["hooks"][0]["statusMessage"],
                "Context Relay memory lifecycle"
            );
        }
        let unreviewed = contract["contextRelayUnreviewedLifecycleHookEvents"]
            .as_object()
            .unwrap();
        assert_eq!(
            unreviewed["TaskCompleted"],
            "Payload compatibility is not captured or proven; disabled until a reviewed bounded schema is frozen."
        );
        assert!(
            contract["lifecycleHookEvents"]
                .as_array()
                .unwrap()
                .contains(&json!("TaskCompleted"))
        );
        assert!(hooks.get("TaskCompleted").is_none());
        let serialized = serde_json::to_string(&hooks).unwrap();
        assert!(!serialized.contains("TaskCompleted"));
        assert!(!serialized.contains("task-evidence"));
        assert!(!serialized.contains("must-not-use-display"));
        for forbidden in [
            "transcript_path",
            "prompt",
            "response",
            "last_assistant_message",
            "${",
        ] {
            assert!(!serialized.contains(forbidden));
        }
    }
}

#[test]
fn memory_hooks_install_preserves_exact_unmarked_and_differently_marked_user_commands() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let bridge = executable_bridge(
        &fixture,
        "context-relay-context-mcp",
        b"fixture bridge executable",
    );
    let managed = managed_memory_hooks(HarnessId::ClaudeCode, &test_wire_path(&bridge))
        .unwrap()
        .remove(0);
    let managed_hooks: Value = serde_json::from_str(&managed.body_markdown).unwrap();
    let mut unmarked_user = managed_hooks["SessionStart"][0].clone();
    unmarked_user["hooks"][0]
        .as_object_mut()
        .unwrap()
        .remove("statusMessage");
    let mut differently_marked_user = managed_hooks["SessionStart"][0].clone();
    differently_marked_user["hooks"][0]["statusMessage"] =
        Value::String("User lifecycle hook".into());
    let path = fixture.root.join("custom claude config/settings.json");
    let mut prior: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    prior["hooks"]["SessionStart"] =
        Value::Array(vec![unmarked_user.clone(), differently_marked_user.clone()]);
    fs::write(path, serde_json::to_vec(&prior).unwrap()).unwrap();

    let mutation = fixture
        .adapter
        .plan_native_global_settings(&DesiredState {
            components: vec![managed],
            scopes: vec![NativeScope::Global],
        })
        .unwrap();
    let NativeState::RegularFile { bytes, .. } = NativeState::decode_v1(&mutation.content).unwrap()
    else {
        panic!("Claude settings remain a regular file")
    };
    let rendered: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        rendered["hooks"]["SessionStart"],
        Value::Array(vec![
            unmarked_user,
            differently_marked_user,
            managed_hooks["SessionStart"][0].clone(),
        ])
    );
}

#[test]
fn memory_hooks_merge_deduplicate_reapply_and_rollback_exactly() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let bridge = executable_bridge(
        &fixture,
        "context-relay context-mcp",
        b"fixture bridge executable",
    );
    let managed = managed_memory_hooks(HarnessId::ClaudeCode, &test_wire_path(&bridge))
        .unwrap()
        .remove(0);
    let managed_hooks: Value = serde_json::from_str(&managed.body_markdown).unwrap();
    let path = fixture.root.join("custom claude config/settings.json");
    let mut prior: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    for (event, entry) in managed_hooks.as_object().unwrap() {
        let entry = entry.as_array().unwrap()[0].clone();
        prior["hooks"][event] = Value::Array(vec![entry.clone(), entry]);
    }
    let mut before = serde_json::to_vec(&prior).unwrap();
    before.push(b'\n');
    fs::write(&path, &before).unwrap();

    let desired = DesiredState {
        components: vec![managed],
        scopes: vec![NativeScope::Global],
    };
    let mutation = fixture
        .adapter
        .plan_native_global_settings(&desired)
        .unwrap();
    let NativeState::RegularFile { bytes, .. } = NativeState::decode_v1(&mutation.content).unwrap()
    else {
        panic!("Claude settings remain a regular file")
    };
    let rendered: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(rendered["theme"], "dark");
    assert_eq!(rendered["hooks"]["PostToolUse"], serde_json::json!([]));
    for event in ["SessionStart", "Stop"] {
        assert_eq!(rendered["hooks"][event].as_array().unwrap().len(), 1);
    }
    assert!(rendered["hooks"].get("TaskCompleted").is_none());

    let nonce = [41; 16];
    let mut native = OsNativeTransactionFileSystem::new(nonce);
    let images = native
        .create_before_images(std::slice::from_ref(&mutation))
        .unwrap();
    native.record_native_metadata(&images).unwrap();
    native
        .compare_and_swap_targets(std::slice::from_ref(&mutation))
        .unwrap();
    native.apply_mutation(&nonce, &mutation).unwrap();
    assert_eq!(fs::read(&path).unwrap(), bytes);

    let reapplied = fixture
        .adapter
        .plan_native_global_settings(&desired)
        .unwrap();
    let NativeState::RegularFile {
        bytes: reapplied_bytes,
        ..
    } = NativeState::decode_v1(&reapplied.content).unwrap()
    else {
        panic!("Claude settings remain a regular file")
    };
    assert_eq!(reapplied_bytes, bytes);

    native.restore_matching_applied_targets(&nonce).unwrap();
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn memory_hooks_reject_a_managed_identity_with_user_controlled_argv() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let bridge = executable_bridge(
        &fixture,
        "context-relay-context-mcp",
        b"fixture bridge executable",
    );
    let mut managed = managed_memory_hooks(HarnessId::ClaudeCode, &test_wire_path(&bridge))
        .unwrap()
        .remove(0);
    let mut body: Value = serde_json::from_str(&managed.body_markdown).unwrap();
    let command = body["Stop"][0]["hooks"][0]["command"].as_str().unwrap();
    body["Stop"][0]["hooks"][0]["command"] =
        Value::String(format!("{command} --prompt must-not-enter-hook-argv"));
    managed.body_markdown = serde_json::to_string(&body).unwrap();
    let desired = DesiredState {
        components: vec![managed],
        scopes: vec![NativeScope::Global],
    };
    let error = fixture
        .adapter
        .plan_native_global_settings(&desired)
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidRequest);

    for marker in [None, Some("Not Context Relay")] {
        let mut claimed = managed_memory_hooks(HarnessId::ClaudeCode, &test_wire_path(&bridge))
            .unwrap()
            .remove(0);
        let mut body: Value = serde_json::from_str(&claimed.body_markdown).unwrap();
        match marker {
            Some(marker) => {
                body["Stop"][0]["hooks"][0]["statusMessage"] = Value::String(marker.to_owned());
            }
            None => {
                body["Stop"][0]["hooks"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("statusMessage");
            }
        }
        claimed.body_markdown = serde_json::to_string(&body).unwrap();
        let error = fixture
            .adapter
            .plan_native_global_settings(&DesiredState {
                components: vec![claimed],
                scopes: vec![NativeScope::Global],
            })
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidRequest);
    }
}

#[test]
fn memory_hooks_archive_removes_only_managed_entries_and_rolls_back_exactly() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let bridge = executable_bridge(
        &fixture,
        "context-relay-context-mcp",
        b"fixture bridge executable",
    );
    let mut managed = managed_memory_hooks(HarnessId::ClaudeCode, &test_wire_path(&bridge))
        .unwrap()
        .remove(0);
    let mut managed_hooks: Value = serde_json::from_str(&managed.body_markdown).unwrap();
    let path = fixture.root.join("custom claude config/settings.json");
    let mut prior: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    prior["hooks"]["FutureEvent"] = serde_json::json!([{
        "matcher": "user",
        "hooks": [],
        "unknown": {"keep": true}
    }]);
    for entries in managed_hooks.as_object_mut().unwrap().values_mut() {
        entries[0]["hooks"][0]["statusMessage"] =
            Value::String("Context Relay memory lifecycle".into());
    }
    for (event, entries) in managed_hooks.as_object().unwrap() {
        prior["hooks"][event] = entries.clone();
    }
    let mut unmarked_user = managed_hooks["SessionStart"][0].clone();
    unmarked_user["hooks"][0]
        .as_object_mut()
        .unwrap()
        .remove("statusMessage");
    let mut differently_marked_user = managed_hooks["SessionStart"][0].clone();
    differently_marked_user["hooks"][0]["statusMessage"] =
        Value::String("User lifecycle hook".into());
    prior["hooks"]["SessionStart"] = Value::Array(vec![
        unmarked_user.clone(),
        differently_marked_user.clone(),
        managed_hooks["SessionStart"][0].clone(),
    ]);
    let user_stop = serde_json::json!({
        "matcher": "user-stop",
        "hooks": [{"type": "command", "command": "user-stop-command"}]
    });
    prior["hooks"]["Stop"]
        .as_array_mut()
        .unwrap()
        .insert(0, user_stop.clone());
    let mut before = serde_json::to_vec(&prior).unwrap();
    before.push(b'\n');
    fs::write(&path, &before).unwrap();

    managed.archived = true;
    let desired = DesiredState {
        components: vec![managed],
        scopes: vec![NativeScope::Global],
    };
    let mutation = fixture
        .adapter
        .plan_native_global_settings(&desired)
        .unwrap();
    let NativeState::RegularFile { bytes, .. } = NativeState::decode_v1(&mutation.content).unwrap()
    else {
        panic!("Claude settings remain a regular file")
    };
    let rendered: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(rendered["theme"], prior["theme"]);
    assert_eq!(rendered["oauthAccount"], prior["oauthAccount"]);
    assert_eq!(
        rendered["hooks"]["PostToolUse"],
        prior["hooks"]["PostToolUse"]
    );
    assert_eq!(
        rendered["hooks"]["FutureEvent"],
        prior["hooks"]["FutureEvent"]
    );
    assert_eq!(rendered["hooks"]["Stop"], Value::Array(vec![user_stop]));
    assert_eq!(
        rendered["hooks"]["SessionStart"],
        Value::Array(vec![unmarked_user, differently_marked_user])
    );
    assert!(rendered["hooks"].get("TaskCompleted").is_none());

    let nonce = [43; 16];
    let mut native = OsNativeTransactionFileSystem::new(nonce);
    let images = native
        .create_before_images(std::slice::from_ref(&mutation))
        .unwrap();
    native.record_native_metadata(&images).unwrap();
    native
        .compare_and_swap_targets(std::slice::from_ref(&mutation))
        .unwrap();
    native.apply_mutation(&nonce, &mutation).unwrap();
    let reapplied = fixture
        .adapter
        .plan_native_global_settings(&desired)
        .unwrap();
    let NativeState::RegularFile {
        bytes: reapplied_bytes,
        ..
    } = NativeState::decode_v1(&reapplied.content).unwrap()
    else {
        panic!("Claude settings remain a regular file")
    };
    assert_eq!(reapplied_bytes, bytes);
    native.restore_matching_applied_targets(&nonce).unwrap();
    assert_eq!(fs::read(path).unwrap(), before);
}

#[test]
fn memory_hooks_rotate_executable_without_removing_user_lookalikes() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let old_bridge = executable_bridge(&fixture, "old bridge", b"old bridge executable");
    let new_bridge = executable_bridge(&fixture, "new bridge", b"new bridge executable");
    let old = managed_memory_hooks(HarnessId::ClaudeCode, &test_wire_path(&old_bridge))
        .unwrap()
        .remove(0);
    let new = managed_memory_hooks(HarnessId::ClaudeCode, &test_wire_path(&new_bridge))
        .unwrap()
        .remove(0);
    let mut old_hooks: Value = serde_json::from_str(&old.body_markdown).unwrap();
    let new_hooks: Value = serde_json::from_str(&new.body_markdown).unwrap();
    for entries in old_hooks.as_object_mut().unwrap().values_mut() {
        entries[0]["hooks"][0]["statusMessage"] =
            Value::String("Context Relay memory lifecycle".into());
    }
    let old_entry = old_hooks["SessionStart"][0].clone();
    let mut unmarked_user = old_entry.clone();
    unmarked_user["hooks"][0]
        .as_object_mut()
        .unwrap()
        .remove("statusMessage");
    let mut differently_marked_user = old_entry.clone();
    differently_marked_user["hooks"][0]["statusMessage"] =
        Value::String("User lifecycle hook".into());
    let mut schema_lookalike = old_entry.clone();
    schema_lookalike["matcher"] = Value::String("user-owned".into());
    let mut argv_lookalike = old_entry.clone();
    let command = argv_lookalike["hooks"][0]["command"].as_str().unwrap();
    argv_lookalike["hooks"][0]["command"] = Value::String(format!("{command} --user-owned"));
    let path = fixture.root.join("custom claude config/settings.json");
    let mut prior: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    for (event, entries) in old_hooks.as_object().unwrap() {
        prior["hooks"][event] = entries.clone();
    }
    prior["hooks"]["SessionStart"] = Value::Array(vec![
        old_entry.clone(),
        unmarked_user.clone(),
        differently_marked_user.clone(),
        schema_lookalike.clone(),
        old_entry,
        argv_lookalike.clone(),
    ]);
    prior["hooks"]["FutureEvent"] = serde_json::json!([]);
    fs::write(&path, serde_json::to_vec(&prior).unwrap()).unwrap();

    let mutation = fixture
        .adapter
        .plan_native_global_settings(&DesiredState {
            components: vec![new],
            scopes: vec![NativeScope::Global],
        })
        .unwrap();
    let NativeState::RegularFile { bytes, .. } = NativeState::decode_v1(&mutation.content).unwrap()
    else {
        panic!("Claude settings remain a regular file")
    };
    let rendered: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        rendered["hooks"]["SessionStart"],
        Value::Array(vec![
            unmarked_user,
            differently_marked_user,
            schema_lookalike,
            argv_lookalike,
            new_hooks["SessionStart"][0].clone(),
        ])
    );
    assert_eq!(rendered["hooks"]["Stop"], new_hooks["Stop"]);
    assert_eq!(
        rendered["hooks"]["TaskCompleted"],
        new_hooks["TaskCompleted"]
    );
    assert_eq!(rendered["hooks"]["FutureEvent"], serde_json::json!([]));
}

#[test]
fn unknown_versions_are_import_only() {
    let mut source: Value =
        serde_json::from_str(include_str!("fixtures/claude-code-2.1.214.json")).unwrap();
    source["version"] = json!("9.9.9");
    let fixture = fixture(&source.to_string());
    assert_eq!(
        fixture
            .adapter
            .probe(&ProbeContext {
                harness: HarnessId::ClaudeCode,
                requested_profile: None,
            })
            .unwrap()
            .capability,
        CapabilityLevel::ImportOnly
    );
    assert!(!import_everything(&fixture).components.is_empty());
    assert!(
        fixture
            .adapter
            .render(&DesiredState {
                components: vec![],
                scopes: vec![],
            })
            .is_err()
    );
}

#[test]
fn mixed_settings_preserve_unmanaged_and_trust_state_through_apply_and_rollback() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let settings_path = fixture.adapter.project_settings_path();
    let before_settings = fs::read(&settings_path).unwrap();
    let before_state = fs::read(&fixture.state_path).unwrap();
    let desired = DesiredState {
        components: vec![
            component(
                fixture.project_id,
                ComponentKind::PermissionDeclaration,
                "permissions",
                r#"{"allow":["Bash(cargo test)"],"deny":["Read(.env)"]}"#,
            ),
            component(
                fixture.project_id,
                ComponentKind::Hook,
                "hooks",
                r#"{"PostToolUse":[{"matcher":"Write","hooks":[]}]}"#,
            ),
        ],
        scopes: vec![NativeScope::Project {
            project_id: fixture.project_id,
            root: fixture.adapter.project_root_wire(),
        }],
    };
    let mutation = fixture.adapter.plan_native_settings(&desired).unwrap();
    let intended = NativeState::decode_v1(&mutation.content).unwrap();
    let NativeState::RegularFile { bytes, .. } = intended else {
        panic!("settings remain a regular file");
    };
    let rendered: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(rendered["unmanaged"]["keep"], true);
    assert_eq!(rendered["permissions"]["allow"][0], "Bash(cargo test)");
    assert!(rendered.get("oauthAccount").is_none());

    let nonce = [7; 16];
    let mut native = OsNativeTransactionFileSystem::new(nonce);
    let images = native
        .create_before_images(std::slice::from_ref(&mutation))
        .unwrap();
    native.record_native_metadata(&images).unwrap();
    native
        .compare_and_swap_targets(std::slice::from_ref(&mutation))
        .unwrap();
    native.apply_mutation(&nonce, &mutation).unwrap();
    assert_eq!(fs::read(&fixture.state_path).unwrap(), before_state);
    assert!(
        fs::read_to_string(&settings_path)
            .unwrap()
            .contains("\"keep\":true")
    );

    native.restore_matching_applied_targets(&nonce).unwrap();
    assert_eq!(fs::read(&settings_path).unwrap(), before_settings);
    assert_eq!(fs::read(&fixture.state_path).unwrap(), before_state);
}

#[test]
fn concurrent_native_edit_invalidates_the_planned_settings_mutation() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let desired = DesiredState {
        components: vec![component(
            fixture.project_id,
            ComponentKind::PermissionDeclaration,
            "permissions",
            r#"{"allow":["Read"],"deny":[]}"#,
        )],
        scopes: vec![NativeScope::Project {
            project_id: fixture.project_id,
            root: fixture.adapter.project_root_wire(),
        }],
    };
    let mutation = fixture.adapter.plan_native_settings(&desired).unwrap();
    fs::write(
        fixture.adapter.project_settings_path(),
        br#"{"concurrent":true}"#,
    )
    .unwrap();
    assert!(
        OsNativeTransactionFileSystem::new([8; 16])
            .create_before_images(&[mutation])
            .is_err()
    );
}

#[test]
fn managed_markdown_blocks_preserve_unmanaged_bytes_and_rollback() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let components = [
        component(
            fixture.project_id,
            ComponentKind::Instruction,
            "CLAUDE.md",
            "Managed project instructions.",
        ),
        component(
            fixture.project_id,
            ComponentKind::Rule,
            "project.md",
            "Managed project rule.",
        ),
        component(
            fixture.project_id,
            ComponentKind::Skill,
            "release",
            "Managed release skill.",
        ),
    ];
    let paths = [
        fixture.root.join("project with spaces").join("CLAUDE.md"),
        fixture
            .root
            .join("project with spaces/.claude/rules/project.md"),
        fixture
            .root
            .join("project with spaces/.claude/skills/release/SKILL.md"),
    ];
    fs::write(
        &paths[0],
        "# User preface\n\n<!-- context-relay:start -->\nold managed text\n<!-- context-relay:end -->\n\nUser footer\n",
    )
    .unwrap();
    let before = paths
        .iter()
        .map(fs::read)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mutations = components
        .iter()
        .map(|component| fixture.adapter.plan_native_file(component).unwrap())
        .collect::<Vec<_>>();

    let nonce = [9; 16];
    let mut native = OsNativeTransactionFileSystem::new(nonce);
    let images = native.create_before_images(&mutations).unwrap();
    native.record_native_metadata(&images).unwrap();
    native.compare_and_swap_targets(&mutations).unwrap();
    for mutation in &mutations {
        native.apply_mutation(&nonce, mutation).unwrap();
    }
    for (index, ((path, original), component)) in
        paths.iter().zip(&before).zip(&components).enumerate()
    {
        let applied = fs::read(path).unwrap();
        if index == 0 {
            let applied_text = String::from_utf8(applied.clone()).unwrap();
            assert!(applied_text.starts_with("# User preface\n"));
            assert!(applied_text.ends_with("\nUser footer\n"));
            assert!(!applied_text.contains("old managed text"));
        } else {
            assert!(applied.starts_with(original));
        }
        let applied = String::from_utf8(applied).unwrap();
        assert!(applied.contains("<!-- context-relay:start -->"));
        assert!(applied.contains(&component.body_markdown));
        assert!(applied.contains("<!-- context-relay:end -->"));
    }

    native.restore_matching_applied_targets(&nonce).unwrap();
    for (path, original) in paths.iter().zip(before) {
        assert_eq!(fs::read(path).unwrap(), original);
    }
}

#[test]
fn managed_markdown_plan_rejects_malformed_markers_and_concurrent_edits() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let path = fixture.root.join("project with spaces").join("CLAUDE.md");
    let managed = component(
        fixture.project_id,
        ComponentKind::Instruction,
        "CLAUDE.md",
        "Managed instructions.",
    );
    for malformed in [
        "<!-- context-relay:start -->\nmissing end\n",
        "<!-- context-relay:end -->\n<!-- context-relay:start -->\n",
        "<!-- context-relay:start -->\na\n<!-- context-relay:end -->\n<!-- context-relay:start -->\nb\n<!-- context-relay:end -->\n",
    ] {
        fs::write(&path, malformed).unwrap();
        assert!(fixture.adapter.plan_native_file(&managed).is_err());
    }

    fs::write(&path, "# User preface\n").unwrap();
    let mutation = fixture.adapter.plan_native_file(&managed).unwrap();
    fs::write(&path, "# Concurrent edit\n").unwrap();
    assert!(
        OsNativeTransactionFileSystem::new([10; 16])
            .create_before_images(&[mutation])
            .is_err()
    );
}

#[test]
fn primary_memory_semantic_contract_is_shared_byte_for_byte() {
    let project_id = ProjectId::from_str(PROJECT_ID).unwrap();
    let device_id = DeviceId::from_str(DEVICE_ID).unwrap();
    let clock = HybridLogicalClock::new(1_900_000_000_000, 0, device_id);
    let components = [HarnessId::ClaudeCode, HarnessId::Codex, HarnessId::Hermes].map(|harness| {
        primary_memory_instruction_component(harness, project_id, device_id, clock).unwrap()
    });
    let expected = "## Context Relay memory\n\n\
- At the start of every session, query Context Relay with `context_relay_search` for the active project before relying on recalled context.\n\
- Treat Context Relay results as the primary memory for decisions, project knowledge, and ongoing work. Native harness memory is only an import and recovery surface.\n\
- Save explicit user or project decisions with `context_relay_remember`.\n\
- Submit inferred knowledge with `context_relay_propose_memory` so it enters review instead of becoming authoritative immediately.\n\
- Keep the shared task ledger current with `context_relay_list_tasks`, `context_relay_upsert_task`, and `context_relay_complete_task`.\n\
- When completing the current Context Relay task, use the typed `context_relay_complete_task` tool with the current Context Relay task ID returned by `context_relay_list_tasks` and explicit bounded evidence; never infer or substitute a vendor task identifier.\n";

    assert_eq!(PRIMARY_MEMORY_INSTRUCTIONS, expected);
    assert!(components.iter().all(|component| {
        component.kind == ComponentKind::Instruction
            && component.scope == ScopeRef::Project { project_id }
            && component.body_markdown == expected
    }));
    for component in &components {
        assert!(!component.body_markdown.contains("--hook-event"));
        assert!(!component.body_markdown.contains("session_id"));
        assert!(
            component
                .body_markdown
                .contains("typed `context_relay_complete_task` tool")
        );
        assert!(
            component
                .body_markdown
                .contains("explicit bounded evidence")
        );
        assert!(
            component
                .body_markdown
                .contains("current Context Relay task ID")
        );
        assert!(
            component
                .body_markdown
                .contains("never infer or substitute a vendor task identifier")
        );
    }
    assert_eq!(components[0].name, "CLAUDE.md");
    assert_eq!(components[1].name, "AGENTS.md");
    assert_eq!(components[2].name, ".hermes.md");

    let other_project = ProjectId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073999").unwrap();
    let other = primary_memory_instruction_component(
        HarnessId::ClaudeCode,
        other_project,
        device_id,
        clock,
    )
    .unwrap();
    assert_ne!(components[0].id, other.id);
}

#[test]
fn native_memory_capability_matrix_is_exact_for_frozen_claude_releases() {
    for source in [
        include_str!("fixtures/claude-code-2.1.214.json"),
        include_str!("fixtures/claude-code-2.1.213.json"),
    ] {
        let expected_version = serde_json::from_str::<Value>(source).unwrap()["version"]
            .as_str()
            .unwrap()
            .to_owned();
        let fixture = fixture(source);
        let project_root = fixture.root.join("project with spaces");
        let memory_root = project_root.join(".claude/native-memory");
        fs::create_dir_all(memory_root.join("nested")).unwrap();
        fs::write(memory_root.join("raw_memories.md"), "excluded\n").unwrap();
        fs::write(memory_root.join("nested/topic.md"), "excluded\n").unwrap();

        let capabilities = fixture.adapter.native_memory_capabilities().unwrap();
        let NativeMemoryDisable::Supported(mutations) = capabilities.disable else {
            panic!("frozen Claude release must support native-memory disable");
        };
        assert_eq!(mutations.len(), 1);
        let NativeState::RegularFile { bytes, .. } =
            NativeState::decode_v1(&mutations[0].content).unwrap()
        else {
            panic!("Claude settings remain a regular file");
        };
        let rendered: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(rendered["autoMemoryEnabled"], false);
        assert_eq!(
            rendered["autoMemoryDirectory"],
            "~/project with spaces/.claude/native-memory"
        );
        assert_eq!(rendered["unmanaged"]["keep"], true);
        assert_eq!(rendered.as_object().unwrap().len(), 6);

        let paths = capabilities
            .sources
            .iter()
            .map(|source| source.path.display.clone().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            paths,
            vec![
                memory_root.join("MEMORY.md").display().to_string(),
                memory_root.join("decisions.md").display().to_string(),
            ]
        );
        assert_eq!(
            capabilities.sources[0].document_kind,
            NativeMemoryDocumentKind::Agent
        );
        assert_eq!(
            capabilities.sources[1].document_kind,
            NativeMemoryDocumentKind::Topic
        );
        assert!(capabilities.sources.iter().all(|source| {
            source.adapter_version == expected_version
                && source.scope
                    == ScopeRef::Project {
                        project_id: fixture.project_id,
                    }
                && source.managed_fence
        }));
    }
}

#[test]
fn unknown_claude_versions_never_guess_a_default_native_memory_binding() {
    let mut source: Value =
        serde_json::from_str(include_str!("fixtures/claude-code-2.1.214.json")).unwrap();
    source["version"] = json!("9.9.9");
    let fixture = fixture(&source.to_string());
    let settings_path = fixture.adapter.project_settings_path();
    let mut settings: Value = serde_json::from_slice(&fs::read(&settings_path).unwrap()).unwrap();
    settings
        .as_object_mut()
        .unwrap()
        .remove("autoMemoryDirectory");
    fs::write(&settings_path, serde_json::to_vec(&settings).unwrap()).unwrap();
    let capabilities = fixture.adapter.native_memory_capabilities().unwrap();
    assert!(matches!(
        capabilities.disable,
        NativeMemoryDisable::Unavailable
    ));
    assert!(capabilities.sources.is_empty());

    settings["autoMemoryDirectory"] = json!(".claude/native-memory");
    fs::write(&settings_path, serde_json::to_vec(&settings).unwrap()).unwrap();
    let capabilities = fixture.adapter.native_memory_capabilities().unwrap();
    assert!(matches!(
        capabilities.disable,
        NativeMemoryDisable::Unavailable
    ));
    assert!(capabilities.sources.is_empty());

    settings["autoMemoryDirectory"] = json!("~/project with spaces/.claude/native-memory");
    fs::write(&settings_path, serde_json::to_vec(&settings).unwrap()).unwrap();
    let capabilities = fixture.adapter.native_memory_capabilities().unwrap();
    assert!(matches!(
        capabilities.disable,
        NativeMemoryDisable::WatchOnly
    ));
    assert!(!capabilities.sources.is_empty());
}

#[test]
fn frozen_claude_default_binding_is_exact_when_an_explicit_path_is_ignored() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let settings_path = fixture.adapter.project_settings_path();
    let mut settings: Value = serde_json::from_slice(&fs::read(&settings_path).unwrap()).unwrap();
    settings
        .as_object_mut()
        .unwrap()
        .remove("autoMemoryDirectory");
    fs::write(&settings_path, serde_json::to_vec(&settings).unwrap()).unwrap();

    let project_root = fixture.root.join("project with spaces");
    let project_key = project_root
        .to_string_lossy()
        .trim_start_matches(r"\\?\")
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' {
                character
            } else {
                '-'
            }
        })
        .collect::<String>();
    let expected = fixture
        .root
        .join("custom claude config/projects")
        .join(project_key)
        .join("memory/MEMORY.md");
    let capabilities = fixture.adapter.native_memory_capabilities().unwrap();
    assert_eq!(
        capabilities.sources[0].path.display.as_deref(),
        Some(expected.to_string_lossy().as_ref())
    );

    settings["autoMemoryDirectory"] = json!("../sibling-project/memory");
    fs::write(&settings_path, serde_json::to_vec(&settings).unwrap()).unwrap();
    let capabilities = fixture.adapter.native_memory_capabilities().unwrap();
    assert_eq!(capabilities.sources[0].path, test_wire_path(&expected));
}

#[test]
fn native_memory_disable_rolls_back_true_false_and_absent_claude_values_exactly() {
    for (index, prior) in [Some(true), Some(false), None].into_iter().enumerate() {
        let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
        let settings_path = fixture.adapter.project_settings_path();
        let mut settings: Value =
            serde_json::from_slice(&fs::read(&settings_path).unwrap()).unwrap();
        match prior {
            Some(value) => settings["autoMemoryEnabled"] = json!(value),
            None => {
                settings
                    .as_object_mut()
                    .unwrap()
                    .remove("autoMemoryEnabled");
            }
        }
        fs::write(&settings_path, serde_json::to_vec(&settings).unwrap()).unwrap();
        let before = fs::read(&settings_path).unwrap();
        let capabilities = fixture.adapter.native_memory_capabilities().unwrap();
        let NativeMemoryDisable::Supported(mutations) = capabilities.disable else {
            panic!("supported Claude release must remain writable");
        };
        if prior == Some(false) {
            assert!(mutations.is_empty());
            assert_eq!(fs::read(&settings_path).unwrap(), before);
            continue;
        }
        let nonce = [40 + index as u8; 16];
        let mut native = OsNativeTransactionFileSystem::new(nonce);
        let images = native.create_before_images(&mutations).unwrap();
        native.record_native_metadata(&images).unwrap();
        native.compare_and_swap_targets(&mutations).unwrap();
        for mutation in &mutations {
            native.apply_mutation(&nonce, mutation).unwrap();
        }
        assert_eq!(
            fixture
                .adapter
                .native_memory_capabilities()
                .unwrap()
                .sources,
            capabilities.sources
        );
        native.restore_matching_applied_targets(&nonce).unwrap();
        assert_eq!(fs::read(&settings_path).unwrap(), before);
    }
}

fn use_default_memory(fixture: &Fixture) {
    let path = fixture.adapter.project_settings_path();
    let mut settings: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    settings
        .as_object_mut()
        .unwrap()
        .remove("autoMemoryDirectory");
    fs::write(path, serde_json::to_vec(&settings).unwrap()).unwrap();
}

fn expected_default_memory(fixture: &Fixture, repository: &Path) -> WireNativeValue {
    let key = repository
        .to_str()
        .unwrap()
        .trim_start_matches(r"\\?\")
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '-'
            }
        })
        .collect::<String>();
    test_wire_path(
        &fixture
            .root
            .join("custom claude config/projects")
            .join(key)
            .join("memory/MEMORY.md"),
    )
}

#[test]
fn native_memory_claude_default_uses_repository_ancestor_and_rechecks_new_nested_repository() {
    let mut fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    use_default_memory(&fixture);
    fs::create_dir(fixture.root.join(".git")).unwrap();
    let capabilities = fixture.adapter.native_memory_capabilities().unwrap();
    assert_eq!(
        capabilities.sources[0].path,
        expected_default_memory(&fixture, &fixture.root)
    );
    let plan = claude_memory_plan(&fixture);
    NativeAdapter::reprobe_live_state(&mut fixture.adapter, &plan).unwrap();
    fs::create_dir(fixture.root.join("project with spaces/.git")).unwrap();
    assert!(NativeAdapter::reprobe_live_state(&mut fixture.adapter, &plan).is_err());
    assert!(NativeAdapter::verify_live_state_reservation(&mut fixture.adapter, &plan).is_err());
}

#[test]
fn native_memory_claude_default_shares_linked_worktree_memory_and_rechecks_backlink() {
    let mut fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    use_default_memory(&fixture);
    let main = fixture.root.join("main");
    let gitdir = main.join(".git/worktrees/topic");
    fs::create_dir_all(&gitdir).unwrap();
    fs::write(
        fixture.root.join("project with spaces/.git"),
        b"gitdir: ../main/.git/worktrees/topic\n",
    )
    .unwrap();
    fs::write(gitdir.join("commondir"), b"../..\n").unwrap();
    fs::write(
        gitdir.join("gitdir"),
        b"../../../../project with spaces/.git\n",
    )
    .unwrap();
    let capabilities = fixture.adapter.native_memory_capabilities().unwrap();
    assert_eq!(
        capabilities.sources[0].path,
        expected_default_memory(&fixture, &main)
    );
    let plan = claude_memory_plan(&fixture);
    NativeAdapter::reprobe_live_state(&mut fixture.adapter, &plan).unwrap();
    fs::write(gitdir.join("gitdir"), b"../../../../missing/.git\n").unwrap();
    assert!(NativeAdapter::reprobe_live_state(&mut fixture.adapter, &plan).is_err());
    assert!(NativeAdapter::verify_live_state_reservation(&mut fixture.adapter, &plan).is_err());
}

#[test]
fn native_memory_claude_reads_user_project_and_local_directory_precedence() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let user = fixture.root.join("custom claude config/settings.json");
    let project = fixture.adapter.project_settings_path();
    let local = project.with_file_name("settings.local.json");
    fs::write(&user, br#"{"autoMemoryDirectory":"~/user memory"}"#).unwrap();
    fs::write(&project, b"{}").unwrap();
    for (path, body, expected) in [
        (&project, "{}", "user memory"),
        (
            &project,
            r#"{"autoMemoryDirectory":"~/project memory"}"#,
            "project memory",
        ),
        (
            &local,
            r#"{"autoMemoryDirectory":"~/local memory"}"#,
            "local memory",
        ),
    ] {
        fs::write(path, body).unwrap();
        let capabilities = fixture.adapter.native_memory_capabilities().unwrap();
        let expected = fixture.root.join(expected).join("MEMORY.md");
        assert_eq!(capabilities.sources[0].path, test_wire_path(&expected));
    }
}

#[test]
fn native_memory_claude_disables_the_local_override_and_rolls_it_back_exactly() {
    for enabled in [true, false] {
        let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
        let project = fixture.adapter.project_settings_path();
        let project_before = fs::read(&project).unwrap();
        let local = project.with_file_name("settings.local.json");
        let before = format!("{{\n  \"autoMemoryEnabled\": {enabled}, \"unmanaged\": [1, 2]\n}}\n");
        fs::write(&local, &before).unwrap();
        let capabilities = fixture.adapter.native_memory_capabilities().unwrap();
        let NativeMemoryDisable::Supported(mutations) = capabilities.disable else {
            panic!("local override must be supported");
        };
        assert_eq!(mutations.len(), usize::from(enabled));
        if enabled {
            assert_eq!(mutations[0].target, test_wire_path(&local));
            let nonce = [86; 16];
            let mut native = OsNativeTransactionFileSystem::new(nonce);
            let images = native.create_before_images(&mutations).unwrap();
            native.record_native_metadata(&images).unwrap();
            native.compare_and_swap_targets(&mutations).unwrap();
            native.apply_mutation(&nonce, &mutations[0]).unwrap();
            let after: Value = serde_json::from_slice(&fs::read(&local).unwrap()).unwrap();
            assert_eq!(
                after,
                json!({"autoMemoryEnabled": false, "unmanaged": [1, 2]})
            );
            native.restore_matching_applied_targets(&nonce).unwrap();
        }
        assert_eq!(fs::read(&local).unwrap(), before.as_bytes());
        assert_eq!(fs::read(&project).unwrap(), project_before);
    }
}

#[test]
fn native_memory_claude_rejects_ambiguous_or_non_file_settings_layers() {
    for layer in [
        "custom claude config/settings.json",
        "project with spaces/.claude/settings.local.json",
        "managed-settings.json",
    ] {
        for body in [
            r#"{"autoMemoryEnabled":true,"autoMemoryEnabled":false}"#,
            "[]",
        ] {
            let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
            let path = fixture.root.join(layer);
            fs::write(&path, body).unwrap();
            let capabilities = fixture.adapter.native_memory_capabilities().unwrap();
            assert!(
                matches!(capabilities.disable, NativeMemoryDisable::Unavailable),
                "{layer}: {body}"
            );
            assert!(capabilities.sources.is_empty());
        }
        let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
        let path = fixture.root.join(layer);
        if path.is_file() {
            fs::remove_file(&path).unwrap();
        }
        fs::create_dir(&path).unwrap();
        let capabilities = fixture.adapter.native_memory_capabilities().unwrap();
        assert!(
            matches!(capabilities.disable, NativeMemoryDisable::Unavailable),
            "{layer}"
        );
    }
}

fn claude_memory_plan(fixture: &Fixture) -> NativeTransactionPlan {
    let executable = fixture.root.join(if cfg!(windows) {
        "claude.exe"
    } else {
        "claude"
    });
    let mut plan = native_digest_plan(
        &executable,
        Sha256Digest(Sha256::digest(fs::read(&executable).unwrap()).into()),
    );
    plan.setup
        .expected_native_digests
        .extend(fixture.adapter.bridge_operational_digests().unwrap());
    let capabilities = fixture.adapter.native_memory_capabilities().unwrap();
    plan.native_memory_registrations = capabilities
        .sources
        .into_iter()
        .map(
            |source| context_relay_core::native_memory::NativeMemoryRegistration {
                source,
                last_applied_digest: None,
            },
        )
        .collect();
    if let NativeMemoryDisable::Supported(mutations) = capabilities.disable {
        plan.mutations = mutations;
    }
    plan
}

#[test]
fn native_memory_claude_rechecks_new_local_overrides_and_managed_changes() {
    for (layer, body) in [
        (
            "project with spaces/.claude/settings.local.json",
            r#"{"autoMemoryEnabled":true}"#,
        ),
        (
            "custom claude config/settings.json",
            r#"{"autoMemoryDirectory":"~/changed memory"}"#,
        ),
        ("managed-settings.json", r#"{"autoMemoryEnabled":true}"#),
    ] {
        let mut fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
        let plan = claude_memory_plan(&fixture);
        NativeAdapter::reprobe_live_state(&mut fixture.adapter, &plan).unwrap();
        let before = fs::read(fixture.adapter.project_settings_path()).unwrap();
        fs::write(fixture.root.join(layer), body).unwrap();
        assert!(
            NativeAdapter::reprobe_live_state(&mut fixture.adapter, &plan).is_err(),
            "{layer}"
        );
        assert!(
            NativeAdapter::verify_live_state_reservation(&mut fixture.adapter, &plan).is_err(),
            "{layer}"
        );
        assert_eq!(
            fs::read(fixture.adapter.project_settings_path()).unwrap(),
            before
        );
    }
}

fn memory_receipt(plan: &NativeTransactionPlan) -> context_relay_protocol::ApplyReceipt {
    context_relay_protocol::ApplyReceipt {
        plan_id: plan.setup.plan_id,
        applied_hlc: HybridLogicalClock::new(
            1_900_000_000_001,
            0,
            DeviceId::from_str(DEVICE_ID).unwrap(),
        ),
        resulting_digests: plan
            .mutations
            .iter()
            .map(|mutation| mutation.intended.0)
            .collect(),
    }
}

#[test]
fn native_memory_claude_verifies_intermediate_forward_and_inverse_settings() {
    for local_override in [false, true] {
        let mut fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
        if local_override {
            fs::write(
                fixture
                    .adapter
                    .project_settings_path()
                    .with_file_name("settings.local.json"),
                br#"{"autoMemoryEnabled":true}"#,
            )
            .unwrap();
        }
        let mut plan = claude_memory_plan(&fixture);
        let bridge = executable_bridge(&fixture, "memory bridge", b"fixture bridge");
        let hooks = fixture
            .adapter
            .plan_native_global_settings(&DesiredState {
                components: managed_memory_hooks(HarnessId::ClaudeCode, &test_wire_path(&bridge))
                    .unwrap(),
                scopes: vec![NativeScope::Global],
            })
            .unwrap();
        plan.mutations.insert(0, hooks);
        let before: Vec<_> = plan
            .mutations
            .iter()
            .map(|mutation| {
                // Fixture paths all have display strings; production uses wire bytes.
                let path = Path::new(mutation.target.display.as_ref().unwrap());
                context_relay_native_runner::OsNativeFileSystem::new()
                    .snapshot(path)
                    .unwrap()
                    .state()
                    .encode_v1()
                    .unwrap()
            })
            .collect();
        let receipt = memory_receipt(&plan);
        NativeAdapter::compare_approved_digests(&mut fixture.adapter, &plan).unwrap();
        assert!(NativeAdapter::validate_effective(&mut fixture.adapter, &plan, &receipt).is_err());
        let nonce = [88; 16];
        let mut native = OsNativeTransactionFileSystem::new(nonce);
        let images = native.create_before_images(&plan.mutations).unwrap();
        native.record_native_metadata(&images).unwrap();
        native.compare_and_swap_targets(&plan.mutations).unwrap();
        for mutation in &plan.mutations {
            NativeAdapter::verify_live_state_reservation(&mut fixture.adapter, &plan).unwrap();
            native.apply_mutation(&nonce, mutation).unwrap();
        }
        NativeAdapter::validate_effective(&mut fixture.adapter, &plan, &receipt).unwrap();
        let mut inverse = plan.clone();
        for (mutation, prior) in inverse.mutations.iter_mut().zip(&before) {
            std::mem::swap(&mut mutation.expected, &mut mutation.intended);
            mutation.content.clone_from(prior);
        }
        NativeAdapter::reprobe_live_state(&mut fixture.adapter, &inverse).unwrap();
        NativeAdapter::compare_approved_digests(&mut fixture.adapter, &inverse).unwrap();
        native.restore_matching_applied_targets(&nonce).unwrap();
        assert!(NativeAdapter::validate_effective(&mut fixture.adapter, &plan, &receipt).is_err());
        NativeAdapter::verify_live_state_reservation(&mut fixture.adapter, &inverse).unwrap();
        NativeAdapter::validate_effective(
            &mut fixture.adapter,
            &inverse,
            &memory_receipt(&inverse),
        )
        .unwrap();
    }
}

#[test]
fn native_memory_claude_preserves_watch_only_and_rejects_unbound_legacy_plans() {
    let mut fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    fs::write(
        fixture.root.join("managed-settings.json"),
        br#"{"autoMemoryEnabled":true}"#,
    )
    .unwrap();
    let plan = claude_memory_plan(&fixture);
    assert!(plan.mutations.is_empty());
    NativeAdapter::reprobe_live_state(&mut fixture.adapter, &plan).unwrap();
    NativeAdapter::validate_effective(&mut fixture.adapter, &plan, &memory_receipt(&plan)).unwrap();
    let mut unbound = plan.clone();
    unbound.setup.expected_native_digests.truncate(1);
    assert!(NativeAdapter::reprobe_live_state(&mut fixture.adapter, &unbound).is_err());
    fs::write(fixture.root.join("managed-settings.json"), b"{}").unwrap();
    assert!(
        NativeAdapter::validate_effective(&mut fixture.adapter, &plan, &memory_receipt(&plan))
            .is_err()
    );
}

#[test]
fn native_memory_claude_keeps_the_same_binding_when_the_directory_is_created() {
    let mut fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    fs::write(
        fixture.adapter.project_settings_path(),
        br#"{"autoMemoryDirectory":"~/new memory/topics"}"#,
    )
    .unwrap();
    let plan = claude_memory_plan(&fixture);
    fs::create_dir_all(fixture.root.join("new memory/topics")).unwrap();
    NativeAdapter::reprobe_live_state(&mut fixture.adapter, &plan).unwrap();
    let current = fixture.adapter.native_memory_capabilities().unwrap();
    assert_eq!(
        current.sources[0],
        plan.native_memory_registrations[0].source
    );
}

#[test]
fn native_memory_claude_policy_conflicts_and_unsupported_values_never_write() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    fs::write(
        fixture.root.join("managed-settings.json"),
        br#"{"autoMemoryEnabled":true}"#,
    )
    .unwrap();
    assert!(matches!(
        fixture
            .adapter
            .native_memory_capabilities()
            .unwrap()
            .disable,
        NativeMemoryDisable::WatchOnly
    ));

    fs::write(
        fixture.root.join("managed-settings.json"),
        br#"{"permissions":{}}"#,
    )
    .unwrap();
    let settings_path = fixture.adapter.project_settings_path();
    let mut settings: Value = serde_json::from_slice(&fs::read(&settings_path).unwrap()).unwrap();
    settings["autoMemoryEnabled"] = json!("unsupported");
    fs::write(&settings_path, serde_json::to_vec(&settings).unwrap()).unwrap();
    let before = fs::read(&settings_path).unwrap();
    assert!(matches!(
        fixture
            .adapter
            .native_memory_capabilities()
            .unwrap()
            .disable,
        NativeMemoryDisable::WatchOnly
    ));
    assert_eq!(fs::read(settings_path).unwrap(), before);
}

#[test]
fn missing_claude_managed_policy_file_does_not_create_a_false_conflict() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    fs::remove_file(fixture.root.join("managed-settings.json")).unwrap();
    assert!(matches!(
        fixture
            .adapter
            .native_memory_capabilities()
            .unwrap()
            .disable,
        NativeMemoryDisable::Supported(_)
    ));
}

#[test]
fn native_memory_claude_accepts_an_exact_absolute_explicit_directory() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let memory_root = fixture.root.join("explicit memory directory");
    fs::create_dir_all(&memory_root).unwrap();
    let settings_path = fixture.adapter.project_settings_path();
    let mut settings: Value = serde_json::from_slice(&fs::read(&settings_path).unwrap()).unwrap();
    settings["autoMemoryDirectory"] =
        json!(memory_root.to_string_lossy().trim_start_matches(r"\\?\"));
    fs::write(settings_path, serde_json::to_vec(&settings).unwrap()).unwrap();

    let capabilities = fixture.adapter.native_memory_capabilities().unwrap();
    assert!(matches!(
        capabilities.disable,
        NativeMemoryDisable::Supported(_)
    ));
    assert_eq!(
        capabilities.sources[0].path.display.as_deref(),
        Some(memory_root.join("MEMORY.md").to_string_lossy().as_ref())
    );
}

#[test]
fn native_memory_claude_expands_home_and_normalizes_the_configured_directory() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let memory_root = fixture.root.join("explicit memory directory");
    fs::create_dir_all(&memory_root).unwrap();
    fs::write(memory_root.join("topic.md"), "# Selected home\n").unwrap();
    let settings_path = fixture.adapter.project_settings_path();
    let mut settings: Value = serde_json::from_slice(&fs::read(&settings_path).unwrap()).unwrap();
    for configured in [
        "~/unused/../explicit memory directory",
        "~\\explicit memory directory",
    ] {
        settings["autoMemoryDirectory"] = json!(configured);
        fs::write(&settings_path, serde_json::to_vec(&settings).unwrap()).unwrap();
        let capabilities = fixture.adapter.native_memory_capabilities().unwrap();
        assert_eq!(capabilities.sources.len(), 2, "{configured}");
        assert_eq!(
            capabilities.sources[0].path,
            test_wire_path(&memory_root.join("MEMORY.md"))
        );
        assert_eq!(
            capabilities.sources[1].path,
            test_wire_path(&memory_root.join("topic.md"))
        );
    }
}

#[test]
fn native_memory_claude_ignores_relative_directory_like_the_native_runtime() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let settings_path = fixture.adapter.project_settings_path();
    let mut settings: Value = serde_json::from_slice(&fs::read(&settings_path).unwrap()).unwrap();
    settings
        .as_object_mut()
        .unwrap()
        .remove("autoMemoryDirectory");
    fs::write(&settings_path, serde_json::to_vec(&settings).unwrap()).unwrap();
    let default = fixture
        .adapter
        .native_memory_capabilities()
        .unwrap()
        .sources;
    for configured in [
        ".claude/native-memory",
        "../other-project/memory",
        "~/../memory",
    ] {
        settings["autoMemoryDirectory"] = json!(configured);
        fs::write(&settings_path, serde_json::to_vec(&settings).unwrap()).unwrap();
        assert_eq!(
            fixture
                .adapter
                .native_memory_capabilities()
                .unwrap()
                .sources,
            default,
            "{configured}"
        );
    }
}

#[cfg(unix)]
#[test]
fn native_memory_claude_rejects_linked_directories_even_with_a_trailing_separator() {
    use std::os::unix::fs::symlink;
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let target = fixture.root.join("real memory");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("MEMORY.md"), "# Not selected\n").unwrap();
    let linked = fixture.root.join("linked memory");
    symlink(&target, &linked).unwrap();
    let settings_path = fixture.adapter.project_settings_path();
    for configured in ["~/linked memory/", "~/linked memory/missing/"] {
        fs::write(
            &settings_path,
            serde_json::to_vec(&json!({"autoMemoryDirectory": configured})).unwrap(),
        )
        .unwrap();
        let capabilities = fixture.adapter.native_memory_capabilities().unwrap();
        assert!(matches!(
            capabilities.disable,
            NativeMemoryDisable::Unavailable
        ));
        assert!(capabilities.sources.is_empty());
    }
    fs::remove_file(target.join("MEMORY.md")).unwrap();
    fs::remove_dir(&target).unwrap();
    fs::write(
        &settings_path,
        br#"{"autoMemoryDirectory":"~/linked memory/"}"#,
    )
    .unwrap();
    let capabilities = fixture.adapter.native_memory_capabilities().unwrap();
    assert!(matches!(
        capabilities.disable,
        NativeMemoryDisable::Unavailable
    ));
    assert!(capabilities.sources.is_empty());
}

#[test]
fn native_memory_claude_normalizes_long_input_before_bounding_the_binding() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let memory_root = fixture.root.join("short memory");
    fs::create_dir(&memory_root).unwrap();
    let configured = format!(
        "{}/{}/short memory",
        fixture.root.to_str().unwrap().trim_start_matches(r"\\?\"),
        "segment/../".repeat(500)
    );
    assert!(configured.len() > 4096);
    fs::write(
        fixture.adapter.project_settings_path(),
        serde_json::to_vec(&json!({"autoMemoryDirectory": configured})).unwrap(),
    )
    .unwrap();
    let capabilities = fixture.adapter.native_memory_capabilities().unwrap();
    assert_eq!(
        capabilities.sources[0].path,
        test_wire_path(&memory_root.join("MEMORY.md"))
    );
    let configured = format!(
        "{}/discard\0/../short memory",
        fixture.root.to_str().unwrap().trim_start_matches(r"\\?\")
    );
    fs::write(
        fixture.adapter.project_settings_path(),
        serde_json::to_vec(&json!({"autoMemoryDirectory": configured})).unwrap(),
    )
    .unwrap();
    let capabilities = fixture.adapter.native_memory_capabilities().unwrap();
    assert_eq!(
        capabilities.sources[0].path,
        test_wire_path(&memory_root.join("MEMORY.md"))
    );

    let configured = format!(
        "{}{}",
        fixture.root.to_str().unwrap().trim_start_matches(r"\\?\"),
        "/leaf".repeat(1000)
    );
    fs::write(
        fixture.adapter.project_settings_path(),
        serde_json::to_vec(&json!({"autoMemoryDirectory": configured})).unwrap(),
    )
    .unwrap();
    let capabilities = fixture.adapter.native_memory_capabilities().unwrap();
    assert!(matches!(
        capabilities.disable,
        NativeMemoryDisable::Unavailable
    ));
    assert!(capabilities.sources.is_empty());
}

#[test]
fn native_memory_claude_supported_absent_project_settings_plans_exact_creation_and_rollback() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    fs::remove_file(fixture.adapter.project_settings_path()).unwrap();
    let project_root = fixture.root.join("project with spaces");
    let project_key = project_root
        .to_string_lossy()
        .trim_start_matches(r"\\?\")
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' {
                character
            } else {
                '-'
            }
        })
        .collect::<String>();
    let memory_root = fixture
        .root
        .join("custom claude config/projects")
        .join(project_key)
        .join("memory");
    fs::create_dir_all(&memory_root).unwrap();
    fs::write(memory_root.join("topic.md"), "# Topic\n").unwrap();

    let capabilities = fixture.adapter.native_memory_capabilities().unwrap();
    let NativeMemoryDisable::Supported(mutations) = capabilities.disable else {
        panic!("supported Claude must create its exact missing project settings file")
    };
    assert_eq!(mutations.len(), 1);
    let mutation = &mutations[0];
    assert_eq!(
        mutation.target,
        test_wire_path(&fixture.adapter.project_settings_path())
    );
    let intended = NativeState::decode_v1(&mutation.content).unwrap();
    let NativeState::RegularFile { bytes, .. } = intended else {
        panic!("missing project settings must become a regular file")
    };
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap(),
        json!({"autoMemoryEnabled": false})
    );
    assert_eq!(
        capabilities
            .sources
            .iter()
            .map(|source| source.path.display.clone().unwrap())
            .collect::<Vec<_>>(),
        vec![
            memory_root.join("MEMORY.md").display().to_string(),
            memory_root.join("topic.md").display().to_string(),
        ]
    );
    assert!(!fixture.adapter.project_settings_path().exists());

    let nonce = [0x91; 16];
    let mut native = OsNativeTransactionFileSystem::new(nonce);
    let images = native
        .create_before_images(std::slice::from_ref(mutation))
        .unwrap();
    native.record_native_metadata(&images).unwrap();
    native
        .compare_and_swap_targets(std::slice::from_ref(mutation))
        .unwrap();
    native.apply_mutation(&nonce, mutation).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(
            &fs::read(fixture.adapter.project_settings_path()).unwrap()
        )
        .unwrap(),
        json!({"autoMemoryEnabled": false})
    );
    native.restore_matching_applied_targets(&nonce).unwrap();
    assert!(!fixture.adapter.project_settings_path().exists());
}

#[test]
fn native_memory_claude_absent_project_settings_parent_watches_without_creating_it() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let settings_path = fixture.adapter.project_settings_path();
    let settings_parent = settings_path.parent().unwrap();
    fs::remove_dir_all(settings_parent).unwrap();
    let project_root = fixture.root.join("project with spaces");
    let project_key = project_root
        .to_string_lossy()
        .trim_start_matches(r"\\?\")
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' {
                character
            } else {
                '-'
            }
        })
        .collect::<String>();
    let memory_root = fixture
        .root
        .join("custom claude config/projects")
        .join(project_key)
        .join("memory");
    fs::create_dir_all(&memory_root).unwrap();
    fs::write(memory_root.join("topic.md"), "# Topic\n").unwrap();

    let capabilities = fixture.adapter.native_memory_capabilities().unwrap();
    assert!(matches!(
        capabilities.disable,
        NativeMemoryDisable::WatchOnly
    ));
    assert_eq!(
        capabilities
            .sources
            .iter()
            .map(|source| source.path.display.clone().unwrap())
            .collect::<Vec<_>>(),
        vec![
            memory_root.join("MEMORY.md").display().to_string(),
            memory_root.join("topic.md").display().to_string(),
        ]
    );
    assert!(!settings_parent.exists());
    assert!(!settings_path.exists());
}

#[test]
fn native_memory_claude_managed_directory_is_the_only_effective_watch_binding() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let managed_root = fixture.root.join("managed memory directory");
    fs::create_dir_all(&managed_root).unwrap();
    fs::write(managed_root.join("MEMORY.md"), "# Managed memory\n").unwrap();
    fs::write(
        fixture.root.join("managed-settings.json"),
        serde_json::to_vec(&json!({
            "autoMemoryEnabled": true,
            "autoMemoryDirectory": managed_root.to_string_lossy().trim_start_matches(r"\\?\"),
        }))
        .unwrap(),
    )
    .unwrap();

    let capabilities = fixture.adapter.native_memory_capabilities().unwrap();
    assert!(matches!(
        capabilities.disable,
        NativeMemoryDisable::WatchOnly
    ));
    assert_eq!(
        capabilities.sources[0].path.display.as_deref(),
        Some(managed_root.join("MEMORY.md").to_string_lossy().as_ref())
    );
    assert!(capabilities.sources.iter().all(|source| {
        !source
            .path
            .display
            .as_deref()
            .unwrap()
            .contains(".claude/native-memory")
    }));

    let settings_path = fixture.adapter.project_settings_path();
    let mut settings: Value = serde_json::from_slice(&fs::read(&settings_path).unwrap()).unwrap();
    settings
        .as_object_mut()
        .unwrap()
        .remove("autoMemoryDirectory");
    fs::write(&settings_path, serde_json::to_vec(&settings).unwrap()).unwrap();
    fs::write(fixture.root.join("managed-settings.json"), b"{}").unwrap();
    let default = fixture
        .adapter
        .native_memory_capabilities()
        .unwrap()
        .sources;
    fs::write(
        fixture.root.join("managed-settings.json"),
        br#"{"autoMemoryEnabled":true,"autoMemoryDirectory":"../sibling-project/memory"}"#,
    )
    .unwrap();
    let capabilities = fixture.adapter.native_memory_capabilities().unwrap();
    assert!(matches!(
        capabilities.disable,
        NativeMemoryDisable::WatchOnly
    ));
    assert_eq!(capabilities.sources, default);
}

#[test]
fn primary_memory_claude_markdown_handles_crlf_replacement_archive_and_absence() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let device_id = DeviceId::from_str(DEVICE_ID).unwrap();
    let mut managed = primary_memory_instruction_component(
        HarnessId::ClaudeCode,
        fixture.project_id,
        device_id,
        HybridLogicalClock::new(1_900_000_000_000, 0, device_id),
    )
    .unwrap();
    let path = fixture.root.join("project with spaces/CLAUDE.md");
    fs::write(
        &path,
        b"user prefix\r\n<!-- context-relay:start -->\r\nold\r\n<!-- context-relay:end -->\r\nuser suffix\r\n",
    )
    .unwrap();

    let mutation = fixture.adapter.plan_native_file(&managed).unwrap();
    let NativeState::RegularFile { bytes, .. } = NativeState::decode_v1(&mutation.content).unwrap()
    else {
        panic!("primary instructions remain a regular file")
    };
    let expected = format!(
        "user prefix\r\n<!-- context-relay:start -->\r\n{}<!-- context-relay:end -->\r\nuser suffix\r\n",
        managed.body_markdown.replace('\n', "\r\n")
    );
    assert_eq!(bytes, expected.as_bytes());

    fs::write(&path, &bytes).unwrap();
    let reapplied = fixture.adapter.plan_native_file(&managed).unwrap();
    let NativeState::RegularFile {
        bytes: reapplied, ..
    } = NativeState::decode_v1(&reapplied.content).unwrap()
    else {
        panic!("reapplied primary instructions remain a regular file")
    };
    assert_eq!(reapplied, bytes);

    managed.archived = true;
    let archived = fixture.adapter.plan_native_file(&managed).unwrap();
    let NativeState::RegularFile {
        bytes: archived, ..
    } = NativeState::decode_v1(&archived.content).unwrap()
    else {
        panic!("archiving preserves the unmanaged file")
    };
    assert_eq!(archived, b"user prefix\r\nuser suffix\r\n");

    fs::remove_file(&path).unwrap();
    managed.archived = false;
    let created = fixture.adapter.plan_native_file(&managed).unwrap();
    let NativeState::RegularFile {
        bytes: created_bytes,
        ..
    } = NativeState::decode_v1(&created.content).unwrap()
    else {
        panic!("absent primary instruction is created from a metadata template")
    };
    assert!(
        String::from_utf8(created_bytes.clone())
            .unwrap()
            .contains(PRIMARY_MEMORY_INSTRUCTIONS)
    );

    let desired = DesiredState {
        components: vec![managed.clone()],
        scopes: vec![NativeScope::Project {
            project_id: fixture.project_id,
            root: fixture.adapter.project_root_wire(),
        }],
    };
    let preview = fixture.adapter.render(&desired).unwrap();
    assert_eq!(preview.files.len(), 1);
    assert_eq!(
        preview.files[0].bytes_sha256,
        Sha256Digest(Sha256::digest(&created_bytes).into())
    );
    assert_eq!(preview.files[0].byte_length, created_bytes.len() as u64);

    let nonce = [41; 16];
    let mut native = OsNativeTransactionFileSystem::new(nonce);
    let images = native
        .create_before_images(std::slice::from_ref(&created))
        .unwrap();
    native.record_native_metadata(&images).unwrap();
    native
        .compare_and_swap_targets(std::slice::from_ref(&created))
        .unwrap();
    native.apply_mutation(&nonce, &created).unwrap();
    assert_eq!(fs::read(&path).unwrap(), created_bytes);
    assert!(fixture.adapter.render(&desired).unwrap().files.is_empty());

    managed.archived = true;
    let archived = fixture.adapter.plan_native_file(&managed).unwrap();
    let NativeState::RegularFile {
        bytes: archived_bytes,
        ..
    } = NativeState::decode_v1(&archived.content).unwrap()
    else {
        panic!("archived primary instructions preserve the unmanaged target")
    };
    let archived_preview = fixture
        .adapter
        .render(&DesiredState {
            components: vec![managed.clone()],
            scopes: desired.scopes.clone(),
        })
        .unwrap();
    assert_eq!(archived_preview.files.len(), 1);
    assert_eq!(
        archived_preview.files[0].bytes_sha256,
        Sha256Digest(Sha256::digest(&archived_bytes).into())
    );
    assert_eq!(
        archived_preview.files[0].byte_length,
        archived_bytes.len() as u64
    );

    native.restore_matching_applied_targets(&nonce).unwrap();
    assert!(!path.exists());
    assert!(
        fixture
            .adapter
            .render(&DesiredState {
                components: vec![managed.clone()],
                scopes: desired.scopes,
            })
            .unwrap()
            .files
            .is_empty()
    );

    fs::write(&path, "<!-- context-relay:start -->\nmissing end\n").unwrap();
    assert!(fixture.adapter.plan_native_file(&managed).is_err());
}

#[test]
fn primary_memory_absent_creation_applies_and_restores_transactionally() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let path = fixture.root.join("project with spaces/CLAUDE.md");
    fs::remove_file(&path).unwrap();
    let device_id = DeviceId::from_str(DEVICE_ID).unwrap();
    let managed = primary_memory_instruction_component(
        HarnessId::ClaudeCode,
        fixture.project_id,
        device_id,
        HybridLogicalClock::new(1_900_000_000_000, 0, device_id),
    )
    .unwrap();
    let mutation = fixture.adapter.plan_native_file(&managed).unwrap();
    let nonce = [44; 16];
    let mut native = OsNativeTransactionFileSystem::new(nonce);
    let images = native
        .create_before_images(std::slice::from_ref(&mutation))
        .unwrap();
    native.record_native_metadata(&images).unwrap();
    native
        .compare_and_swap_targets(std::slice::from_ref(&mutation))
        .unwrap();
    native.apply_mutation(&nonce, &mutation).unwrap();
    assert!(
        fs::read_to_string(&path)
            .unwrap()
            .contains(PRIMARY_MEMORY_INSTRUCTIONS)
    );
    native.restore_matching_applied_targets(&nonce).unwrap();
    assert!(!path.exists());
}

#[test]
fn plugin_and_mcp_changes_use_only_official_cli_argv() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let rendered = fixture
        .adapter
        .render(&DesiredState {
            components: vec![
                component(
                    fixture.project_id,
                    ComponentKind::Plugin,
                    "formatter@team",
                    "true",
                ),
                component(
                    fixture.project_id,
                    ComponentKind::McpServer,
                    "docs",
                    r#"{"type":"http","url":"https://example.com/mcp"}"#,
                ),
            ],
            scopes: vec![NativeScope::Project {
                project_id: fixture.project_id,
                root: fixture.adapter.project_root_wire(),
            }],
        })
        .unwrap();
    let argv = rendered
        .cli_operations
        .iter()
        .map(|operation| {
            operation
                .arguments
                .iter()
                .map(|argument| argument.display.clone().unwrap())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        argv,
        vec![
            vec!["plugin", "install", "formatter@team", "--scope", "project"],
            vec![
                "mcp",
                "add-json",
                "docs",
                r#"{"type":"http","url":"https://example.com/mcp"}"#,
                "--scope",
                "project"
            ],
        ]
    );
}

fn executable_bridge(fixture: &Fixture, name: &str, bytes: &[u8]) -> PathBuf {
    let path = fixture.root.join(name);
    fs::write(&path, bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    path
}

fn bridge(_fixture: &Fixture, path: &Path) -> ComponentRecord {
    let device = DeviceId::from_str(DEVICE_ID).unwrap();
    bridge_component(
        HarnessId::ClaudeCode,
        path,
        device,
        HybridLogicalClock::new(1_900_000_000_000, 0, device),
    )
    .unwrap()
}

fn displays(operation: &context_relay_protocol::CliOperation) -> Vec<String> {
    operation
        .arguments
        .iter()
        .map(|argument| argument.display.clone().unwrap())
        .collect()
}

fn test_wire_path(path: &Path) -> WireNativeValue {
    #[cfg(windows)]
    let bytes = {
        use std::os::windows::ffi::OsStrExt as _;

        path.as_os_str()
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect()
    };
    #[cfg(not(windows))]
    let bytes = {
        use std::os::unix::ffi::OsStrExt as _;

        path.as_os_str().as_bytes().to_vec()
    };
    WireNativeValue {
        platform: if cfg!(windows) {
            NativePlatform::Windows
        } else {
            NativePlatform::Macos
        },
        bytes,
        display: path.to_str().map(str::to_owned),
    }
}

fn native_digest_plan(target: &Path, digest: Sha256Digest) -> NativeTransactionPlan {
    NativeTransactionPlan {
        setup: SetupPlan {
            plan_id: PlanId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073984").unwrap(),
            harness: HarnessId::ClaudeCode,
            harness_profile: None,
            adapter_version: 1,
            executable_path: test_wire_path(target),
            executable_hash: digest,
            harness_version: "2.1.214".to_owned(),
            target_scopes: vec![NativeScope::Global],
            expected_native_digests: vec![ExpectedNativeDigest {
                target: test_wire_path(target),
                expected_digest: Some(digest),
            }],
            semantic_changes: vec![],
            cli_operations: vec![],
            package_artifacts: vec![],
            permission_delta: PermissionDelta {
                added: vec![],
                removed: vec![],
            },
            network_delta: NetworkDelta {
                added: vec![],
                removed: vec![],
            },
            scanner_report_hash: Sha256Digest([1; 32]),
            rulesync_version: "fixture".to_owned(),
            rulesync_hash: Sha256Digest([2; 32]),
            approval_class: ApprovalClass::Active,
            expires_at: 2_000_000_000_000,
            batch_hash: Sha256Digest([3; 32]),
        },
        approval_version: 2,
        helper_policy_version: 1,
        manifest_schema_version: 1,
        manifest_digest: Sha256Digest([4; 32]),
        helper_hash: Sha256Digest([5; 32]),
        sidecars: vec![],
        structural_allowlist_hash: Sha256Digest([6; 32]),
        staged_inputs: vec![],
        expected_semantic_output_hash: Sha256Digest([7; 32]),
        scanner_result_hash: Sha256Digest([8; 32]),
        mutations: vec![],
        cli_mutations: vec![],
        native_memory_registrations: vec![],
        ownership_changes: vec![],
    }
}

#[test]
fn bridge_preview_reads_saved_configuration_without_launching_a_harness() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let bridge_path = executable_bridge(&fixture, "context relay bridge", b"bridge v1");
    let intended = bridge(&fixture, &bridge_path);
    let before = fs::read(&fixture.state_path).unwrap();

    // The fixture executable is intentionally not runnable. Preview needs no
    // subprocess: Claude's real mcp list/get commands start configured servers.
    let mutation = fixture.adapter.plan_bridge_cli_mutation(&intended).unwrap();

    assert_eq!(mutation.expected, None);
    assert_eq!(fs::read(&fixture.state_path).unwrap(), before);
}

#[test]
fn bridge_preview_preserves_exact_saved_argument_boundaries() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let old_path = executable_bridge(&fixture, "old bridge 專案", b"old bridge");
    let new_path = executable_bridge(&fixture, "new bridge", b"new bridge");
    let prior = bridge(&fixture, &old_path).body_markdown;
    let intended = bridge(&fixture, &new_path);
    let mut state: Value = serde_json::from_slice(&fs::read(&fixture.state_path).unwrap()).unwrap();
    state["mcpServers"] = json!({"context-relay": serde_json::from_str::<Value>(&prior).unwrap()});
    fs::write(&fixture.state_path, serde_json::to_vec(&state).unwrap()).unwrap();

    let mutation = fixture.adapter.plan_bridge_cli_mutation(&intended).unwrap();
    assert_eq!(mutation.expected.unwrap().canonical_body, prior);

    state["mcpServers"]["context-relay"]["args"] = json!(["--harness claude-code"]);
    fs::write(&fixture.state_path, serde_json::to_vec(&state).unwrap()).unwrap();
    let error = fixture
        .adapter
        .plan_bridge_cli_mutation(&intended)
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
}

fn set_saved_bridge(fixture: &Fixture, body: Option<&str>) {
    let mut state: Value = serde_json::from_slice(&fs::read(&fixture.state_path).unwrap()).unwrap();
    let servers = state
        .as_object_mut()
        .unwrap()
        .entry("mcpServers")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .unwrap();
    match body {
        Some(body) => {
            servers.insert(
                "context-relay".to_owned(),
                serde_json::from_str(body).unwrap(),
            );
        }
        None => {
            servers.remove("context-relay");
        }
    }
    fs::write(&fixture.state_path, serde_json::to_vec(&state).unwrap()).unwrap();
}

#[test]
fn bridge_cli_plan_binds_exact_declarations_fingerprints_and_user_scope_argv() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let bridge_path = executable_bridge(&fixture, "context relay bridge", b"bridge v1");
    let intended = bridge(&fixture, &bridge_path);
    let mutation = fixture.adapter.plan_bridge_cli_mutation(&intended).unwrap();
    assert_eq!(mutation.stable_id, intended.id.to_string());
    assert_eq!(mutation.expected, None);
    let declaration = mutation.intended.unwrap();
    assert_eq!(declaration.harness, HarnessId::ClaudeCode);
    assert_eq!(declaration.server_name, "context-relay");
    assert_eq!(declaration.canonical_body, intended.body_markdown);
    assert_eq!(
        declaration.fingerprint,
        Sha256Digest(Sha256::digest(declaration.canonical_body.as_bytes()).into())
    );
    assert_eq!(
        displays(&mutation.forward[0]),
        vec![
            "mcp",
            "add-json",
            "context-relay",
            intended.body_markdown.as_str(),
            "--scope",
            "user",
        ]
    );
    assert_eq!(
        displays(&mutation.rollback[0]),
        vec!["mcp", "remove", "context-relay", "--scope", "user"]
    );
}

#[test]
fn bridge_cli_plan_restores_the_exact_secret_free_managed_prior_declaration() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let old_path = executable_bridge(&fixture, "old bridge", b"old bridge");
    let new_path = executable_bridge(&fixture, "new bridge", b"new bridge");
    let prior = bridge(&fixture, &old_path).body_markdown;
    let intended = bridge(&fixture, &new_path);
    set_saved_bridge(&fixture, Some(&prior));
    let mutation = fixture.adapter.plan_bridge_cli_mutation(&intended).unwrap();
    let expected = mutation.expected.unwrap();
    assert_eq!(expected.canonical_body, prior);
    assert_eq!(
        expected.fingerprint,
        Sha256Digest(Sha256::digest(prior.as_bytes()).into())
    );
    assert_eq!(
        displays(&mutation.rollback[0]),
        vec![
            "mcp",
            "add-json",
            "context-relay",
            prior.as_str(),
            "--scope",
            "user",
        ]
    );
}

#[test]
fn bridge_cli_plan_rejects_disabled_secret_bearing_and_unmanaged_saved_declarations() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let bridge_path = executable_bridge(&fixture, "bridge", b"bridge");
    let intended = bridge(&fixture, &bridge_path);
    for (key, value) in [
        ("args", json!(["--harness", "codex"])),
        ("args", json!(["--harness claude-code"])),
        ("enabled", json!(false)),
        ("env", json!({"TOKEN": "synthetic-secret"})),
        ("env", json!({})),
        ("type", json!("http")),
        ("command", json!("<redacted>")),
        ("command", json!("relative-bridge")),
        ("cwd", json!("elsewhere")),
    ] {
        let mut prior: Value = serde_json::from_str(&intended.body_markdown).unwrap();
        prior[key] = value;
        set_saved_bridge(&fixture, Some(&serde_json::to_string(&prior).unwrap()));
        let before = fs::read(&fixture.state_path).unwrap();
        let error = fixture
            .adapter
            .plan_bridge_cli_mutation(&intended)
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::Conflict, "{key}");
        assert_eq!(fs::read(&fixture.state_path).unwrap(), before);
    }
}

#[test]
fn bridge_cli_plan_rejects_malformed_or_duplicate_native_json() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let bridge_path = executable_bridge(&fixture, "bridge", b"bridge");
    let intended = bridge(&fixture, &bridge_path);
    for state in [
        "not-json",
        "[]",
        r#"{"mcpServers":null}"#,
        r#"{"projects":[]}"#,
        r#"{"mcpServers":{},"mcpServers":{}}"#,
        r#"{"mcpServers":{"context-relay":{},"context-relay":{}}}"#,
        r#"{"mcpServers":{"context-relay":{"command":"first","command":"second"}}}"#,
    ] {
        fs::write(&fixture.state_path, state).unwrap();
        let error = fixture
            .adapter
            .plan_bridge_cli_mutation(&intended)
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidRequest, "{state}");
        assert!(!error.retryable);
    }
}

#[test]
fn bridge_cli_plan_rejects_project_and_local_shadowing_without_modifying_them() {
    for project_file in [false, true] {
        let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
        let bridge_path = executable_bridge(&fixture, "bridge", b"bridge");
        let intended = bridge(&fixture, &bridge_path);
        set_saved_bridge(&fixture, Some(&intended.body_markdown));
        let declaration: Value = serde_json::from_str(&intended.body_markdown).unwrap();
        let path = if project_file {
            let path = fixture.root.join("project with spaces/.mcp.json");
            fs::write(
                &path,
                serde_json::to_vec(&json!({"mcpServers":{"context-relay":declaration}})).unwrap(),
            )
            .unwrap();
            path
        } else {
            let mut state: Value =
                serde_json::from_slice(&fs::read(&fixture.state_path).unwrap()).unwrap();
            let project = state["projects"]
                .as_object_mut()
                .unwrap()
                .values_mut()
                .next()
                .unwrap();
            project["mcpServers"]["context-relay"] = declaration;
            fs::write(&fixture.state_path, serde_json::to_vec(&state).unwrap()).unwrap();
            fixture.state_path.clone()
        };
        let before = fs::read(&path).unwrap();
        assert_eq!(
            fixture
                .adapter
                .plan_bridge_cli_mutation(&intended)
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
        assert_eq!(fs::read(&path).unwrap(), before);
    }
}

#[test]
fn bridge_cli_plan_bounds_native_configuration_and_rejects_non_files() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let bridge_path = executable_bridge(&fixture, "bridge", b"bridge");
    let intended = bridge(&fixture, &bridge_path);
    fs::write(&fixture.state_path, vec![b' '; 1024 * 1024 + 1]).unwrap();
    assert!(fixture.adapter.plan_bridge_cli_mutation(&intended).is_err());
    fs::remove_file(&fixture.state_path).unwrap();
    // Absent state is a valid first connection, not an inspection error.
    assert_eq!(
        fixture
            .adapter
            .plan_bridge_cli_mutation(&intended)
            .unwrap()
            .expected,
        None
    );
    fs::create_dir(&fixture.state_path).unwrap();
    assert!(fixture.adapter.plan_bridge_cli_mutation(&intended).is_err());
}

#[test]
fn bridge_preview_does_not_mistake_ignored_user_settings_for_managed_mcp_state() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let bridge_path = executable_bridge(&fixture, "bridge", b"bridge");
    let intended = bridge(&fixture, &bridge_path);
    set_saved_bridge(&fixture, Some(&intended.body_markdown));
    let policy = fixture.root.join("managed-mcp.json");
    fs::write(&policy, br#"{"mcpServers":{}}"#).unwrap();
    assert!(fixture.adapter.plan_bridge_cli_mutation(&intended).is_err());
    fs::remove_file(&policy).unwrap();
    fs::create_dir(&policy).unwrap();
    assert!(fixture.adapter.plan_bridge_cli_mutation(&intended).is_err());
}

#[cfg(windows)]
#[test]
fn bridge_preview_detects_the_local_scope_key_written_by_windows_claude() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let bridge_path = executable_bridge(&fixture, "bridge", b"bridge");
    let intended = bridge(&fixture, &bridge_path);
    let mut state: Value = serde_json::from_slice(&fs::read(&fixture.state_path).unwrap()).unwrap();
    let projects = state["projects"].as_object_mut().unwrap();
    let native_key = projects.keys().next().unwrap().clone();
    let mut project = projects.remove(&native_key).unwrap();
    project["mcpServers"]["context-relay"] = serde_json::from_str(&intended.body_markdown).unwrap();
    // Captured from actual Claude 2.1.202 local-scope add-json on Windows.
    let cli_key = native_key
        .strip_prefix(r"\\?\")
        .unwrap_or(&native_key)
        .replace('\\', "/");
    projects.insert(cli_key, project);
    fs::write(&fixture.state_path, serde_json::to_vec(&state).unwrap()).unwrap();
    assert_eq!(
        fixture
            .adapter
            .plan_bridge_cli_mutation(&intended)
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
}

#[cfg(windows)]
fn use_claude_project_key(fixture: &Fixture, conflict: bool) {
    let mut state: Value = serde_json::from_slice(&fs::read(&fixture.state_path).unwrap()).unwrap();
    let projects = state["projects"].as_object_mut().unwrap();
    let key = projects.keys().next().unwrap().clone();
    let mut project = projects.remove(&key).unwrap();
    if conflict {
        project["enabledMcpjsonServers"] = json!(["docs"]);
        project["disabledMcpjsonServers"] = json!(["docs"]);
    }
    let cli_key = key.strip_prefix(r"\\?\").unwrap_or(&key).replace('\\', "/");
    projects.insert(cli_key, project);
    fs::write(&fixture.state_path, serde_json::to_vec(&state).unwrap()).unwrap();
}

#[cfg(windows)]
#[test]
fn windows_probe_recognizes_existing_claude_project_trust() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    use_claude_project_key(&fixture, false);
    let report = fixture
        .adapter
        .probe(&ProbeContext {
            harness: HarnessId::ClaudeCode,
            requested_profile: None,
        })
        .unwrap();
    assert!(
        !report
            .policy_conflicts
            .iter()
            .any(|value| value == "project_unapproved")
    );
}

#[cfg(windows)]
#[test]
fn windows_probe_does_not_skip_claude_project_approval_conflicts() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    use_claude_project_key(&fixture, true);
    let report = fixture
        .adapter
        .probe(&ProbeContext {
            harness: HarnessId::ClaudeCode,
            requested_profile: None,
        })
        .unwrap();
    assert!(
        report
            .policy_conflicts
            .iter()
            .any(|value| value == "project_mcp_approval_conflict")
    );
}

#[cfg(windows)]
#[test]
fn windows_import_includes_claude_local_project_servers() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    use_claude_project_key(&fixture, false);
    let imported = fixture
        .adapter
        .import(&ImportRequest {
            scopes: vec![NativeScope::Project {
                project_id: fixture.project_id,
                root: fixture.adapter.project_root_wire(),
            }],
            include_disabled: true,
        })
        .unwrap();
    assert!(
        imported
            .components
            .iter()
            .any(|component| component.name == "local-only")
    );
}

#[test]
fn cli_executor_runs_only_approved_mutations_and_reads_back_the_saved_declaration() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let bridge_path = executable_bridge(&fixture, "configured bridge", b"bridge");
    let intended = bridge(&fixture, &bridge_path);
    let mutation = fixture.adapter.plan_bridge_cli_mutation(&intended).unwrap();
    let before: Value = serde_json::from_slice(&fs::read(&fixture.state_path).unwrap()).unwrap();
    let mut operations = Vec::new();
    let (probed, outcome) = {
        let mut executor = fixture.adapter.cli_executor_with_runner(|argv: &[String]| {
            operations.push(argv.to_vec());
            set_saved_bridge(&fixture, Some(&argv[3]));
            Ok::<Vec<u8>, BoundaryError>(Vec::new())
        });
        (
            executor.probe_cli_mutation(&mutation).unwrap(),
            executor.apply_cli_mutation(&mutation).unwrap(),
        )
    };
    assert_eq!(probed, None);
    assert_eq!(outcome.command_error, None);
    assert_eq!(
        outcome.resulting_fingerprint,
        mutation.intended.as_ref().map(|value| value.fingerprint)
    );
    assert_eq!(
        operations,
        vec![vec![
            "mcp",
            "add-json",
            "context-relay",
            intended.body_markdown.as_str(),
            "--scope",
            "user"
        ]]
    );
    let saved: Value = serde_json::from_slice(&fs::read(&fixture.state_path).unwrap()).unwrap();
    assert_eq!(saved["oauthAccount"], before["oauthAccount"]);
    assert_eq!(saved["projects"], before["projects"]);
}

#[test]
fn cli_executor_detects_a_command_that_did_not_write_the_intended_declaration() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let bridge_path = executable_bridge(&fixture, "configured bridge", b"bridge");
    let intended = bridge(&fixture, &bridge_path);
    let mutation = fixture.adapter.plan_bridge_cli_mutation(&intended).unwrap();
    let mut executor = fixture.adapter.cli_executor_with_runner(|_: &[String]| {
        Ok::<_, BoundaryError>(b"Added stdio MCP server context-relay to user config\n".to_vec())
    });
    let outcome = executor.apply_cli_mutation(&mutation).unwrap();
    assert_eq!(outcome.resulting_fingerprint, None);
}

#[test]
fn cli_executor_rejects_a_different_configuration_project_or_home_after_preview() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let bridge_path = executable_bridge(&fixture, "bridge", b"bridge");
    let intended = bridge(&fixture, &bridge_path);
    let mutation = fixture.adapter.plan_bridge_cli_mutation(&intended).unwrap();
    for change in 0..3 {
        let config = fixture.root.join(if change == 0 {
            "other config"
        } else {
            "custom claude config"
        });
        let project = fixture.root.join(if change == 1 {
            "other project"
        } else {
            "project with spaces"
        });
        let home = if change == 2 {
            fixture.root.join("other home")
        } else {
            fixture.root.clone()
        };
        fs::create_dir_all(&config).unwrap();
        fs::create_dir_all(&project).unwrap();
        fs::create_dir_all(&home).unwrap();
        let device = DeviceId::from_str(DEVICE_ID).unwrap();
        let adapter = ClaudeCodeAdapter::from_layout(
            ClaudeCodeLayout {
                executable: fixture.root.join(if cfg!(windows) {
                    "claude.exe"
                } else {
                    "claude"
                }),
                version: "2.1.214".into(),
                installation_method: InstallationMethod::PackageManager,
                user_home: home,
                state_path: config.join(".claude.json"),
                config_dir: config,
                project_root: project,
                managed_settings_paths: vec![fixture.root.join("managed-settings.json")],
            },
            fixture.project_id,
            device,
            HybridLogicalClock::new(1_900_000_000_000, 0, device),
        )
        .unwrap();
        let mut executor =
            adapter.cli_executor_with_runner(|_: &[String]| -> Result<Vec<u8>, BoundaryError> {
                panic!("a different command context must not launch the CLI")
            });
        assert!(
            executor
                .compare_cli_targets(std::slice::from_ref(&mutation))
                .is_err()
        );
        assert!(executor.apply_cli_mutation(&mutation).is_err());
        assert!(executor.restore_cli_mutation_if_matches(&mutation).is_err());
    }
}

#[test]
fn claude_reprobe_and_executor_reject_legacy_unbound_cli_mutations() {
    let mut fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let bridge_path = executable_bridge(&fixture, "bridge", b"bridge");
    let intended = bridge(&fixture, &bridge_path);
    let mut mutation = fixture.adapter.plan_bridge_cli_mutation(&intended).unwrap();
    let executable = fixture.root.join(if cfg!(windows) {
        "claude.exe"
    } else {
        "claude"
    });
    let hash = Sha256Digest(Sha256::digest(fs::read(&executable).unwrap()).into());
    let mut plan = native_digest_plan(&executable, hash);
    plan.cli_mutations = vec![mutation.clone()];
    fixture.adapter.reprobe_live_state(&plan).unwrap();
    mutation.execution_context = None;
    plan.cli_mutations = vec![mutation.clone()];
    assert!(fixture.adapter.reprobe_live_state(&plan).is_err());
    let mut executor = fixture.adapter.cli_executor_with_runner(
        |_: &[String]| -> Result<Vec<u8>, BoundaryError> {
            panic!("legacy unbound mutation must not launch the CLI")
        },
    );
    assert!(executor.probe_cli_mutation(&mutation).is_err());
    assert!(
        executor
            .compare_cli_targets(std::slice::from_ref(&mutation))
            .is_err()
    );
    assert!(executor.apply_cli_mutation(&mutation).is_err());
    assert!(executor.restore_cli_mutation_if_matches(&mutation).is_err());
    assert!(
        executor
            .finish_committed_cli_mutations(&[mutation])
            .is_err()
    );
}

#[test]
fn claude_executor_rejects_legacy_inferred_home_context_before_launch() {
    use context_relay_core::native_transaction::CliExecutionContext;
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let bridge_path = executable_bridge(&fixture, "bridge", b"bridge");
    let intended = bridge(&fixture, &bridge_path);
    let mut mutation = fixture.adapter.plan_bridge_cli_mutation(&intended).unwrap();
    let Some(CliExecutionContext::ClaudeCodeV2 {
        config_dir,
        state_path,
        project_root,
        ..
    }) = mutation.execution_context.take()
    else {
        panic!("new preview must bind home")
    };
    mutation.execution_context = Some(CliExecutionContext::ClaudeCodeV1 {
        config_dir,
        state_path,
        project_root,
    });
    let mut executor = fixture.adapter.cli_executor_with_runner(
        |_: &[String]| -> Result<Vec<u8>, BoundaryError> {
            panic!("legacy inferred home must not launch")
        },
    );
    assert!(executor.probe_cli_mutation(&mutation).is_err());
    assert!(executor.apply_cli_mutation(&mutation).is_err());
    assert!(executor.restore_cli_mutation_if_matches(&mutation).is_err());
}

#[test]
fn cli_executor_restores_only_while_live_declaration_equals_intended() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let bridge_path = executable_bridge(&fixture, "configured bridge", b"bridge");
    let divergent_path = executable_bridge(&fixture, "divergent bridge", b"divergent");
    let intended = bridge(&fixture, &bridge_path);
    let mutation = fixture.adapter.plan_bridge_cli_mutation(&intended).unwrap();
    let divergent = bridge(&fixture, &divergent_path).body_markdown;
    set_saved_bridge(&fixture, Some(&divergent));
    let mut executor = fixture.adapter.cli_executor_with_runner(
        |_: &[String]| -> Result<Vec<u8>, BoundaryError> {
            panic!("divergent state must not execute a command")
        },
    );
    let outcome = executor.restore_cli_mutation_if_matches(&mutation).unwrap();
    assert!(!outcome.restored);
    assert_eq!(
        outcome.resulting_fingerprint,
        Some(Sha256Digest(Sha256::digest(divergent.as_bytes()).into()))
    );
}

#[test]
fn cli_executor_runs_the_exact_rollback_after_intended_state_matches() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let bridge_path = executable_bridge(&fixture, "configured bridge", b"bridge");
    let intended = bridge(&fixture, &bridge_path);
    let mutation = fixture.adapter.plan_bridge_cli_mutation(&intended).unwrap();
    set_saved_bridge(&fixture, Some(&intended.body_markdown));
    let mut operations = Vec::new();
    let outcome = {
        let mut executor = fixture.adapter.cli_executor_with_runner(|argv: &[String]| {
            operations.push(argv.to_vec());
            set_saved_bridge(&fixture, None);
            Ok::<Vec<u8>, BoundaryError>(Vec::new())
        });
        executor.restore_cli_mutation_if_matches(&mutation).unwrap()
    };
    assert!(outcome.restored);
    assert_eq!(outcome.resulting_fingerprint, None);
    assert_eq!(
        operations,
        vec![vec!["mcp", "remove", "context-relay", "--scope", "user"]]
    );
}

#[test]
fn cli_executor_rechecks_harness_executable_before_any_mutation() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let bridge_path = executable_bridge(&fixture, "configured bridge", b"bridge");
    let intended = bridge(&fixture, &bridge_path);
    let mutation = fixture.adapter.plan_bridge_cli_mutation(&intended).unwrap();
    fs::write(
        fixture.root.join(if cfg!(windows) {
            "claude.exe"
        } else {
            "claude"
        }),
        b"changed executable",
    )
    .unwrap();
    let mut executor = fixture.adapter.cli_executor_with_runner(
        |_: &[String]| -> Result<Vec<u8>, BoundaryError> {
            panic!("changed executable reached mutation")
        },
    );
    assert!(
        executor
            .compare_cli_targets(std::slice::from_ref(&mutation))
            .is_err()
    );
    assert!(executor.apply_cli_mutation(&mutation).is_err());
}

#[cfg(unix)]
#[test]
fn verified_runner_rejects_path_substitution_before_execution() {
    struct SubstitutingRunner {
        executable: PathBuf,
        original: PathBuf,
        replacement: PathBuf,
    }
    impl ClaudeCodeCommandRunner for SubstitutingRunner {
        fn before_launch(&mut self, _: &[String]) -> Result<(), BoundaryError> {
            fs::rename(&self.executable, &self.original).unwrap();
            fs::rename(&self.replacement, &self.executable).unwrap();
            Ok(())
        }
        fn run(&mut self, _: VerifiedClaudeCommand<'_>) -> Result<Vec<u8>, BoundaryError> {
            panic!("substituted executable reached launch")
        }
    }
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let bridge_path = executable_bridge(&fixture, "configured bridge", b"bridge");
    let intended = bridge(&fixture, &bridge_path);
    let mutation = fixture.adapter.plan_bridge_cli_mutation(&intended).unwrap();
    let executable = fixture.root.join("claude");
    let replacement = fixture.root.join("replacement claude");
    fs::write(&replacement, fs::read(&executable).unwrap()).unwrap();
    let runner = SubstitutingRunner {
        executable,
        original: fixture.root.join("original claude"),
        replacement,
    };
    let outcome = fixture
        .adapter
        .cli_executor_with_runner(runner)
        .apply_cli_mutation(&mutation)
        .unwrap();
    assert!(outcome.command_error.is_some());
    assert_eq!(outcome.resulting_fingerprint, None);
}

#[cfg(unix)]
#[test]
fn passive_preview_rejects_a_link_instead_of_treating_it_as_absence() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let bridge_path = executable_bridge(&fixture, "bridge", b"bridge");
    let intended = bridge(&fixture, &bridge_path);
    fs::remove_file(&fixture.state_path).unwrap();
    std::os::unix::fs::symlink(fixture.root.join("missing"), &fixture.state_path).unwrap();
    assert!(fixture.adapter.plan_bridge_cli_mutation(&intended).is_err());
}

#[test]
fn native_digest_comparison_rejects_bridge_executable_content_changes() {
    let mut fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let bridge_path = executable_bridge(&fixture, "configured bridge", b"bridge v1");
    let expected = Sha256Digest(Sha256::digest(b"bridge v1").into());
    let plan = native_digest_plan(&bridge_path, expected);
    fs::write(&bridge_path, b"bridge v2").unwrap();

    assert!(fixture.adapter.compare_approved_digests(&plan).is_err());
}

fn component(
    project_id: ProjectId,
    kind: ComponentKind,
    name: &str,
    body: &str,
) -> ComponentRecord {
    let device_id = DeviceId::from_str(DEVICE_ID).unwrap();
    ComponentRecord {
        id: context_relay_protocol::RecordId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073983")
            .unwrap(),
        scope: ScopeRef::Project { project_id },
        kind,
        name: name.to_owned(),
        body_markdown: body.to_owned(),
        metadata: vec![],
        provenance: Provenance {
            origin_device: device_id,
            harness: Some(HarnessId::ClaudeCode),
            source: None,
            created_hlc: HybridLogicalClock::new(1_900_000_000_000, 0, device_id),
        },
        archived: false,
    }
}
