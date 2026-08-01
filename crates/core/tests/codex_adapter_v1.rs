use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
};

use context_relay_core::{
    codex::{
        CodexAdapter, CodexCommandRunner, CodexExecutableKind, CodexLayout, VerifiedCodexCommand,
    },
    mcp::install::bridge_component,
    native_memory::{
        NativeMemoryAdapter, NativeMemoryDisable, NativeMemoryDocumentKind,
        PRIMARY_MEMORY_INSTRUCTIONS, managed_memory_hooks, primary_memory_instruction_component,
    },
    native_transaction::{
        approval_hash_v1,
        cli::NativeCliExecutor,
        engine::{NativeAdapter, NativeFileSystem, RestrictedRun},
        filesystem::OsNativeTransactionFileSystem,
        model::{CanonicalCliDeclaration, NativeTransactionPlan, SidecarBinding},
    },
};
use context_relay_native_runner::{
    NativeState, RuleSyncFeature, RuleSyncFeatures, RuleSyncTarget, RuntimeTarget, SidecarCommand,
    SidecarId,
};
use context_relay_protocol::{
    ApplyReceipt, ApprovalClass, CapabilityLevel, ComponentKind, ComponentRecord, DesiredState,
    DeviceId, ErrorCode, ExpectedNativeDigest, HarnessAdapter, HarnessId, HybridLogicalClock,
    ImportRequest, InstallationMethod, NativePlatform, NativeScope, NetworkDelta, PermissionDelta,
    PlanId, ProbeContext, ProjectId, Provenance, ScopeRef, SetupPlan, Sha256Digest,
    WireNativeValue,
};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};

const PROJECT_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073981";
const DEVICE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073982";
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct Fixture {
    root: PathBuf,
    adapter: CodexAdapter,
    layout: CodexLayout,
    project_id: ProjectId,
    codex_home: PathBuf,
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
            "context-relay-codex-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
    let codex_home = root.join("codex home");
    let home = root.join("home");
    let project_root = root.join("project with spaces");
    let working_directory = project_root.join("service");
    materialize_substituting(
        &codex_home,
        fixture["codexHome"].as_object().unwrap(),
        &project_root,
    );
    if let Some(extra) = fixture["nativeMemoryConfigToml"].as_str() {
        let config_path = codex_home.join("config.toml");
        let mut config = fs::read_to_string(&config_path).unwrap();
        config.push_str(extra);
        fs::write(config_path, config).unwrap();
    }
    if let Some(files) = fixture["nativeMemoryFiles"].as_object() {
        materialize(&codex_home.join("memories"), files);
    }
    materialize(
        &home.join(".agents/skills"),
        fixture["userSkills"].as_object().unwrap(),
    );
    materialize(&project_root, fixture["project"].as_object().unwrap());
    fs::create_dir_all(&working_directory).unwrap();
    let requirements = root.join("requirements.toml");
    fs::write(&requirements, fixture["requirements"].as_str().unwrap()).unwrap();
    let executable = root.join("codex");
    fs::write(&executable, b"\x7fELFfixture executable").unwrap();
    let project_id = ProjectId::from_str(PROJECT_ID).unwrap();
    let device_id = DeviceId::from_str(DEVICE_ID).unwrap();
    let layout = CodexLayout {
        executable,
        executable_kind: CodexExecutableKind::Native,
        version: fixture["version"].as_str().unwrap().to_owned(),
        installation_method: InstallationMethod::PackageManager,
        codex_home: codex_home.clone(),
        user_skills_dir: home.join(".agents/skills"),
        project_root: project_root.clone(),
        working_directory,
        requirements_paths: vec![requirements],
    };
    let adapter = CodexAdapter::from_layout(
        layout.clone(),
        project_id,
        device_id,
        HybridLogicalClock::new(1_900_000_000_000, 0, device_id),
    )
    .unwrap();
    Fixture {
        root,
        adapter,
        layout,
        project_id,
        codex_home,
    }
}

fn materialize(root: &Path, files: &Map<String, Value>) {
    for (relative, body) in files {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, body.as_str().unwrap()).unwrap();
    }
}

fn materialize_substituting(root: &Path, files: &Map<String, Value>, project: &Path) {
    for (relative, body) in files {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            path,
            body.as_str()
                .unwrap()
                .replace("$PROJECT", &project.to_string_lossy()),
        )
        .unwrap();
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

fn import_project(
    fixture: &Fixture,
) -> Result<context_relay_protocol::ImportedState, context_relay_protocol::ClientError> {
    fixture.adapter.import(&ImportRequest {
        scopes: vec![NativeScope::Project {
            project_id: fixture.project_id,
            root: fixture.adapter.project_root_wire(),
        }],
        include_disabled: true,
    })
}

fn assert_excludes_sensitive_values(serialized: &str, sensitive_values: &[&str]) {
    let leaked = sensitive_values
        .iter()
        .any(|value| serialized.contains(value));
    assert!(!leaked, "Codex import contained a sensitive value");
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

fn test_digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest(Sha256::digest(bytes).into())
}

fn test_file_digest(path: &Path) -> Sha256Digest {
    test_digest(&fs::read(path).unwrap())
}

fn executable_bridge(fixture: &Fixture, name: &str) -> ComponentRecord {
    let path = fixture.root.join(name);
    fs::write(&path, b"fixture bridge executable").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).unwrap();
    }
    let device = DeviceId::from_str(DEVICE_ID).unwrap();
    bridge_component(
        HarnessId::Codex,
        &path,
        device,
        HybridLogicalClock::new(1_900_000_000_000, 0, device),
    )
    .unwrap()
}

fn declaration(body: &str) -> CanonicalCliDeclaration {
    CanonicalCliDeclaration {
        harness: HarnessId::Codex,
        server_name: "context-relay".to_owned(),
        canonical_body: body.to_owned(),
        fingerprint: test_digest(body.as_bytes()),
    }
}

fn codex_native_plan(
    fixture: &Fixture,
    expected_native_digests: Vec<ExpectedNativeDigest>,
) -> NativeTransactionPlan {
    let mutation = fixture
        .adapter
        .plan_native_markdown(&component(
            fixture.project_id,
            ScopeRef::Global,
            ComponentKind::Instruction,
            "AGENTS.override.md",
            "approved global instructions",
        ))
        .unwrap();
    let setup = SetupPlan {
        plan_id: PlanId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073984").unwrap(),
        harness: HarnessId::Codex,
        adapter_version: 1,
        executable_path: test_wire_path(&fixture.layout.executable),
        executable_hash: test_file_digest(&fixture.layout.executable),
        harness_version: fixture.layout.version.clone(),
        target_scopes: vec![NativeScope::Global],
        expected_native_digests,
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
        scanner_report_hash: Sha256Digest([21; 32]),
        rulesync_version: "0.2.0".to_owned(),
        rulesync_hash: Sha256Digest([22; 32]),
        approval_class: ApprovalClass::Passive,
        expires_at: 2_000_000_000_000,
        batch_hash: Sha256Digest([0; 32]),
    };
    let mut plan = NativeTransactionPlan {
        setup,
        approval_version: 1,
        helper_policy_version: 1,
        manifest_schema_version: 1,
        manifest_digest: Sha256Digest([23; 32]),
        helper_hash: Sha256Digest([24; 32]),
        sidecars: vec![SidecarBinding {
            id: SidecarId::RuleSync,
            target: RuntimeTarget::MacosArm64,
            version: "0.2.0".to_owned(),
            closure_hash: Sha256Digest([25; 32]),
            source_bundle_hash: Sha256Digest([26; 32]),
            build_toolchain_hash: Sha256Digest([27; 32]),
            command_template_digest: Sha256Digest([28; 32]),
            command: SidecarCommand::RuleSyncGenerate {
                target: RuleSyncTarget::CodexCli,
                features: RuleSyncFeatures::new(&[RuleSyncFeature::Rules]).unwrap(),
            },
        }],
        structural_allowlist_hash: Sha256Digest([29; 32]),
        staged_inputs: vec![],
        expected_semantic_output_hash: Sha256Digest([30; 32]),
        scanner_result_hash: Sha256Digest([31; 32]),
        mutations: vec![mutation],
        cli_mutations: vec![],
        native_memory_registrations: vec![],
        ownership_changes: vec![],
    };
    plan.setup.batch_hash = approval_hash_v1(&plan).unwrap();
    plan
}

#[test]
fn supported_release_fixtures_import_reviewed_surfaces_without_secrets() {
    for source in [
        include_str!("fixtures/codex-0.144.1.json"),
        include_str!("fixtures/codex-0.144.0.json"),
    ] {
        let fixture = fixture(source);
        assert_eq!(
            fixture
                .adapter
                .probe(&ProbeContext {
                    harness: HarnessId::Codex,
                    requested_profile: None
                })
                .unwrap()
                .capability,
            CapabilityLevel::Full
        );
        let imported = import_everything(&fixture);
        for kind in [
            ComponentKind::Instruction,
            ComponentKind::Rule,
            ComponentKind::Skill,
            ComponentKind::Plugin,
            ComponentKind::McpServer,
            ComponentKind::Hook,
            ComponentKind::PermissionDeclaration,
        ] {
            assert!(
                imported
                    .components
                    .iter()
                    .any(|component| component.kind == kind),
                "missing {kind:?}"
            );
        }
        assert!(
            imported
                .components
                .iter()
                .any(|component| component.name == "formatter@team")
        );
        assert!(
            imported
                .components
                .iter()
                .any(|component| component.name == "docs")
        );
        let serialized = serde_json::to_string(&imported).unwrap();
        for forbidden in [
            "must-not-import",
            "OPENAI_API_KEY",
            "auth.json",
            "sessions",
            "history.jsonl",
            "state_5.sqlite",
            "native-approvals",
        ] {
            assert!(!serialized.contains(forbidden));
        }
    }
}

#[test]
fn memory_hooks_render_only_the_frozen_lifecycle_events_with_literal_arguments() {
    for source in [
        include_str!("fixtures/codex-0.144.1.json"),
        include_str!("fixtures/codex-0.144.0.json"),
    ] {
        let contract: Value = serde_json::from_str(source).unwrap();
        let fixture = fixture(source);
        let bridge = fixture.root.join("context-relay context-mcp");
        fs::write(&bridge, b"fixture bridge executable").unwrap();
        let mut bridge_wire = test_wire_path(&bridge);
        bridge_wire.display = Some("/must-not-use-display".to_owned());
        let components = managed_memory_hooks(HarnessId::Codex, &bridge_wire).unwrap();
        assert_eq!(components.len(), 1);
        let hooks: Value = serde_json::from_str(&components[0].body_markdown).unwrap();
        let expected = contract["lifecycleHookEvents"].as_array().unwrap();
        assert_eq!(hooks.as_object().unwrap().len(), expected.len());
        for native_event in expected {
            let native_event = native_event.as_str().unwrap();
            let event = match native_event {
                "SessionStart" => "session-start",
                "Stop" => "session-stop",
                _ => panic!("unsupported frozen Codex hook event"),
            };
            let command = hooks[native_event][0]["hooks"][0]["command"]
                .as_str()
                .unwrap();
            assert!(command.contains(bridge.to_string_lossy().as_ref()));
            assert!(command.ends_with(&format!(" --hook-event {event} --harness codex")));
            assert_eq!(hooks[native_event][0]["hooks"][0]["type"], "command");
            assert_eq!(
                hooks[native_event][0]["hooks"][0]["statusMessage"],
                "Context Relay memory lifecycle"
            );
        }
        let serialized = serde_json::to_string(&hooks).unwrap();
        assert!(!serialized.contains("must-not-use-display"));
        for forbidden in [
            "TaskCompleted",
            "task-evidence",
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
    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let bridge = fixture.root.join("context-relay-context-mcp");
    fs::write(&bridge, b"fixture bridge executable").unwrap();
    let managed = managed_memory_hooks(HarnessId::Codex, &test_wire_path(&bridge))
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
    let path = fixture.codex_home.join("hooks.json");
    let mut prior: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    prior["hooks"]["SessionStart"] =
        Value::Array(vec![unmarked_user.clone(), differently_marked_user.clone()]);
    fs::write(path, serde_json::to_vec(&prior).unwrap()).unwrap();

    let mutation = fixture.adapter.plan_native_hooks_json(&managed).unwrap();
    let NativeState::RegularFile { bytes, .. } = NativeState::decode_v1(&mutation.content).unwrap()
    else {
        panic!("Codex hooks remain a regular file")
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
    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let bridge = fixture.root.join("context-relay context-mcp");
    fs::write(&bridge, b"fixture bridge executable").unwrap();
    let managed = managed_memory_hooks(HarnessId::Codex, &test_wire_path(&bridge))
        .unwrap()
        .remove(0);
    let managed_hooks: Value = serde_json::from_str(&managed.body_markdown).unwrap();
    let path = fixture.codex_home.join("hooks.json");
    let mut prior: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    for (event, entry) in managed_hooks.as_object().unwrap() {
        let entry = entry.as_array().unwrap()[0].clone();
        prior["hooks"][event] = Value::Array(vec![entry.clone(), entry]);
    }
    let mut before = serde_json::to_vec(&prior).unwrap();
    before.push(b'\n');
    fs::write(&path, &before).unwrap();

    let mutation = fixture.adapter.plan_native_hooks_json(&managed).unwrap();
    let NativeState::RegularFile { bytes, .. } = NativeState::decode_v1(&mutation.content).unwrap()
    else {
        panic!("Codex hooks remain a regular file")
    };
    let rendered: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(rendered["description"], "global hooks");
    assert_eq!(rendered["unknown"]["keep"], true);
    assert_eq!(rendered["hooks"]["PreToolUse"], serde_json::json!([]));
    for event in ["SessionStart", "Stop"] {
        assert_eq!(rendered["hooks"][event].as_array().unwrap().len(), 1);
    }

    let nonce = [42; 16];
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

    let reapplied = fixture.adapter.plan_native_hooks_json(&managed).unwrap();
    let NativeState::RegularFile {
        bytes: reapplied_bytes,
        ..
    } = NativeState::decode_v1(&reapplied.content).unwrap()
    else {
        panic!("Codex hooks remain a regular file")
    };
    assert_eq!(reapplied_bytes, bytes);

    native.restore_matching_applied_targets(&nonce).unwrap();
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn memory_hooks_retain_codex_project_trust_restrictions() {
    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let bridge = fixture.root.join("context-relay-context-mcp");
    fs::write(&bridge, b"fixture bridge executable").unwrap();
    let mut managed = managed_memory_hooks(HarnessId::Codex, &test_wire_path(&bridge))
        .unwrap()
        .remove(0);
    managed.scope = ScopeRef::Project {
        project_id: fixture.project_id,
    };
    managed.metadata = vec![(
        "structuralLocation".into(),
        "project/.codex/hooks.json#hooks".into(),
    )];
    let config_path = fixture.codex_home.join("config.toml");
    let config = fs::read_to_string(&config_path)
        .unwrap()
        .replace("trust_level = \"trusted\"", "trust_level = \"untrusted\"");
    fs::write(config_path, config).unwrap();
    let error = fixture
        .adapter
        .plan_native_hooks_json(&managed)
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::HarnessUnsupported);
}

#[test]
fn memory_hooks_reject_a_managed_identity_with_user_controlled_argv() {
    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let bridge = fixture.root.join("context-relay-context-mcp");
    fs::write(&bridge, b"fixture bridge executable").unwrap();
    let mut managed = managed_memory_hooks(HarnessId::Codex, &test_wire_path(&bridge))
        .unwrap()
        .remove(0);
    let mut body: Value = serde_json::from_str(&managed.body_markdown).unwrap();
    let command = body["Stop"][0]["hooks"][0]["command"].as_str().unwrap();
    body["Stop"][0]["hooks"][0]["command"] =
        Value::String(format!("{command} --prompt must-not-enter-hook-argv"));
    managed.body_markdown = serde_json::to_string(&body).unwrap();
    let error = fixture
        .adapter
        .plan_native_hooks_json(&managed)
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidRequest);

    for marker in [None, Some("Not Context Relay")] {
        let mut claimed = managed_memory_hooks(HarnessId::Codex, &test_wire_path(&bridge))
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
            .plan_native_hooks_json(&claimed)
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidRequest);
    }
}

#[test]
fn memory_hooks_archive_preserves_user_state_in_planning_render_and_rollback() {
    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let bridge = fixture.root.join("context-relay-context-mcp");
    fs::write(&bridge, b"fixture bridge executable").unwrap();
    let mut managed = managed_memory_hooks(HarnessId::Codex, &test_wire_path(&bridge))
        .unwrap()
        .remove(0);
    let mut managed_hooks: Value = serde_json::from_str(&managed.body_markdown).unwrap();
    let path = fixture.codex_home.join("hooks.json");
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
        .plan_native_hooks_json(&desired.components[0])
        .unwrap();
    let NativeState::RegularFile { bytes, .. } = NativeState::decode_v1(&mutation.content).unwrap()
    else {
        panic!("Codex hooks remain a regular file")
    };
    let rendered: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(rendered["description"], prior["description"]);
    assert_eq!(rendered["unknown"], prior["unknown"]);
    assert_eq!(
        rendered["hooks"]["PreToolUse"],
        prior["hooks"]["PreToolUse"]
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
    let preview = fixture.adapter.render(&desired).unwrap();
    assert_eq!(preview.files.len(), 1);
    assert_eq!(preview.files[0].bytes_sha256, test_digest(&bytes));
    assert_eq!(preview.files[0].byte_length, bytes.len() as u64);

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
    let reapplied = fixture
        .adapter
        .plan_native_hooks_json(&desired.components[0])
        .unwrap();
    let NativeState::RegularFile {
        bytes: reapplied_bytes,
        ..
    } = NativeState::decode_v1(&reapplied.content).unwrap()
    else {
        panic!("Codex hooks remain a regular file")
    };
    assert_eq!(reapplied_bytes, bytes);
    assert_eq!(
        fixture.adapter.render(&desired).unwrap().files[0].bytes_sha256,
        test_digest(&bytes)
    );
    native.restore_matching_applied_targets(&nonce).unwrap();
    assert_eq!(fs::read(path).unwrap(), before);
}

#[test]
fn memory_hooks_rotate_executable_in_planning_and_render_without_removing_user_lookalikes() {
    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let old_bridge = fixture.root.join("old bridge");
    let new_bridge = fixture.root.join("new bridge");
    fs::write(&old_bridge, b"old bridge executable").unwrap();
    fs::write(&new_bridge, b"new bridge executable").unwrap();
    let old = managed_memory_hooks(HarnessId::Codex, &test_wire_path(&old_bridge))
        .unwrap()
        .remove(0);
    let new = managed_memory_hooks(HarnessId::Codex, &test_wire_path(&new_bridge))
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
    let path = fixture.codex_home.join("hooks.json");
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

    let mutation = fixture.adapter.plan_native_hooks_json(&new).unwrap();
    let NativeState::RegularFile { bytes, .. } = NativeState::decode_v1(&mutation.content).unwrap()
    else {
        panic!("Codex hooks remain a regular file")
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
    assert_eq!(rendered["hooks"]["FutureEvent"], serde_json::json!([]));
    let preview = fixture
        .adapter
        .render(&DesiredState {
            components: vec![new],
            scopes: vec![NativeScope::Global],
        })
        .unwrap();
    assert_eq!(preview.files.len(), 1);
    assert_eq!(preview.files[0].bytes_sha256, test_digest(&bytes));
    assert_eq!(preview.files[0].byte_length, bytes.len() as u64);
}

#[test]
fn native_memory_capability_matrix_is_exact_for_frozen_codex_releases() {
    for source in [
        include_str!("fixtures/codex-0.144.1.json"),
        include_str!("fixtures/codex-0.144.0.json"),
    ] {
        let fixture = fixture(source);
        let capabilities = fixture.adapter.native_memory_capabilities().unwrap();
        let NativeMemoryDisable::Supported(mutations) = capabilities.disable else {
            panic!("frozen native Codex release must support native-memory disable");
        };
        assert_eq!(mutations.len(), 1);
        let NativeState::RegularFile { bytes, .. } =
            NativeState::decode_v1(&mutations[0].content).unwrap()
        else {
            panic!("Codex config remains a regular file");
        };
        let rendered = String::from_utf8(bytes).unwrap();
        assert!(rendered.contains("[memories]\n"));
        assert!(rendered.contains("generate_memories = false\n"));
        assert!(rendered.contains("use_memories = false\n"));
        assert!(rendered.contains("# user heading"));
        assert!(rendered.contains("unknown_user_key = \"preserve-me\""));

        assert_eq!(capabilities.sources.len(), 2);
        assert_eq!(
            capabilities.sources[0].document_kind,
            NativeMemoryDocumentKind::Agent
        );
        assert_eq!(
            capabilities.sources[1].document_kind,
            NativeMemoryDocumentKind::Summary
        );
        assert_eq!(
            capabilities
                .sources
                .iter()
                .map(|source| source.path.display.clone().unwrap())
                .collect::<Vec<_>>(),
            vec![
                fixture
                    .codex_home
                    .join("memories/MEMORY.md")
                    .display()
                    .to_string(),
                fixture
                    .codex_home
                    .join("memories/memory_summary.md")
                    .display()
                    .to_string(),
            ]
        );
        assert!(capabilities.sources.iter().all(|source| {
            source.scope == ScopeRef::Global
                && source.adapter_version == fixture.layout.version
                && source.managed_fence
        }));
    }
}

#[test]
fn unknown_and_wrapper_codex_installations_are_watch_only_without_guessed_settings() {
    for (version, wrapper) in [("9.9.9", false), ("0.144.1", true)] {
        let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
        let mut layout = fixture.layout.clone();
        layout.version = version.to_owned();
        if wrapper {
            fs::write(&layout.executable, b"#!/bin/sh\nexit 0\n").unwrap();
        }
        let device = DeviceId::from_str(DEVICE_ID).unwrap();
        let adapter = CodexAdapter::from_layout(
            layout,
            fixture.project_id,
            device,
            HybridLogicalClock::new(1_900_000_000_000, 0, device),
        )
        .unwrap();
        let capabilities = adapter.native_memory_capabilities().unwrap();
        assert!(matches!(
            capabilities.disable,
            NativeMemoryDisable::WatchOnly
        ));
        assert_eq!(capabilities.sources.len(), 2);
    }
}

#[test]
fn native_memory_disable_rolls_back_true_false_and_absent_codex_values_exactly() {
    for (index, prior) in [Some(true), Some(false), None].into_iter().enumerate() {
        let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
        let config_path = fixture.codex_home.join("config.toml");
        let config = fs::read_to_string(&config_path).unwrap();
        let memory_table = "[memories]\ngenerate_memories = true\nuse_memories = true\n\n";
        let config = match prior {
            Some(true) => config,
            Some(false) => config.replace(
                memory_table,
                "[memories]\ngenerate_memories = false\nuse_memories = false\n\n",
            ),
            None => config.replace(memory_table, ""),
        };
        fs::write(&config_path, config).unwrap();
        let before = fs::read(&config_path).unwrap();
        let capabilities = fixture.adapter.native_memory_capabilities().unwrap();
        let NativeMemoryDisable::Supported(mutations) = capabilities.disable else {
            panic!("supported Codex release must remain writable");
        };
        if prior == Some(false) {
            assert!(mutations.is_empty());
            assert_eq!(fs::read(&config_path).unwrap(), before);
            continue;
        }
        let nonce = [50 + index as u8; 16];
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
        assert_eq!(fs::read(&config_path).unwrap(), before);
    }
}

#[test]
fn native_memory_codex_policy_conflicts_and_unsupported_values_never_write() {
    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    fs::write(
        &fixture.layout.requirements_paths[0],
        "[memories]\ngenerate_memories = true\n",
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
        &fixture.layout.requirements_paths[0],
        "allowed_approval_policies = [\"on-request\"]\n",
    )
    .unwrap();
    let config_path = fixture.codex_home.join("config.toml");
    let config = fs::read_to_string(&config_path).unwrap().replace(
        "[memories]\ngenerate_memories = true\nuse_memories = true\n\n",
        "memories = \"unsupported\"\n\n",
    );
    fs::write(&config_path, config).unwrap();
    let before = fs::read(&config_path).unwrap();
    assert!(matches!(
        fixture
            .adapter
            .native_memory_capabilities()
            .unwrap()
            .disable,
        NativeMemoryDisable::WatchOnly
    ));
    assert_eq!(fs::read(config_path).unwrap(), before);
}

#[test]
fn native_memory_codex_disable_preserves_comments_on_owned_boolean_values() {
    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let config_path = fixture.codex_home.join("config.toml");
    let config = fs::read_to_string(&config_path)
        .unwrap()
        .replace(
            "generate_memories = true\nuse_memories = true\n",
            "generate_memories = true # keep generation rationale\n# keep usage rationale\nuse_memories = true # keep usage suffix\n",
        );
    fs::write(config_path, config).unwrap();
    let capabilities = fixture.adapter.native_memory_capabilities().unwrap();
    let NativeMemoryDisable::Supported(mutations) = capabilities.disable else {
        panic!("supported Codex memory booleans must remain writable");
    };
    let NativeState::RegularFile { bytes, .. } =
        NativeState::decode_v1(&mutations[0].content).unwrap()
    else {
        panic!("Codex config remains a regular file");
    };
    let rendered = String::from_utf8(bytes).unwrap();
    assert!(rendered.contains("generate_memories = false # keep generation rationale"));
    assert!(rendered.contains("# keep usage rationale\nuse_memories = false # keep usage suffix"));
}

#[test]
fn toml_mcp_secrets_are_recursively_redacted_before_import() {
    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let config = fixture.codex_home.join("config.toml");
    fs::write(
        &config,
        format!(
            "{}\n[mcp_servers.secret]\nurl = \"https://safe.example/mcp\"\napi_token = \"sensitive-mcp-token\"\nauthorization = \"Bearer sensitive-auth\"\nbearer = \"sensitive-bearer\"\ncookie = \"sensitive-cookie\"\ncredential = \"sensitive-credential\"\n[mcp_servers.secret.env]\nOPENAI_API_KEY = \"sensitive-openai\"\nAWS_ACCESS_KEY_ID = \"sensitive-aws-id\"\nAWS_SECRET_ACCESS_KEY = \"sensitive-aws-secret\"\nPRIVATE_KEY = \"sensitive-private-key\"\nPUBLIC_SETTING = \"sensitive-env-fallback\"\n[mcp_servers.secret.http_headers]\nX_CUSTOM_HEADER = \"sensitive-custom-header\"\nACCEPT = \"sensitive-standard-header\"\n",
            fs::read_to_string(&config).unwrap()
        ),
    )
    .unwrap();
    let serialized = serde_json::to_string(&import_everything(&fixture)).unwrap();
    assert_excludes_sensitive_values(
        &serialized,
        &[
            "sensitive-mcp-token",
            "sensitive-auth",
            "sensitive-bearer",
            "sensitive-cookie",
            "sensitive-credential",
            "sensitive-openai",
            "sensitive-aws-id",
            "sensitive-aws-secret",
            "sensitive-private-key",
            "sensitive-env-fallback",
            "sensitive-custom-header",
            "sensitive-standard-header",
        ],
    );
    assert!(serialized.contains("<redacted>"));
    assert!(serialized.contains("https://safe.example/mcp"));
}

#[test]
fn toml_plugin_secrets_are_recursively_redacted_before_import() {
    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let config = fixture.codex_home.join("config.toml");
    let existing = fs::read_to_string(&config).unwrap();
    let configured = existing.replace(
        "[plugins.\"formatter@team\"]\nenabled = true",
        "[plugins]\n\"formatter@team\" = { enabled = true }\n\"secret-plugin\" = { enabled = true, description = \"safe plugin description\", settings = { apiKey = \"sensitive-plugin-api-key\", token = \"sensitive-plugin-token\", passphrase = \"sensitive-plugin-passphrase\", pwd = \"sensitive-plugin-pwd\", auth = \"sensitive-plugin-auth\", endpoint = \"https://safe.example/plugin\" } }",
    );
    assert_ne!(configured, existing);
    fs::write(&config, configured).unwrap();

    let serialized = serde_json::to_string(&import_everything(&fixture)).unwrap();
    assert_excludes_sensitive_values(
        &serialized,
        &[
            "sensitive-plugin-api-key",
            "sensitive-plugin-token",
            "sensitive-plugin-passphrase",
            "sensitive-plugin-pwd",
            "sensitive-plugin-auth",
        ],
    );
    assert!(serialized.contains("<redacted>"));
    assert!(serialized.contains("safe plugin description"));
    assert!(serialized.contains("https://safe.example/plugin"));
}

#[test]
fn discovery_never_executes_wrapper_candidates() {
    let _guard = ENV_LOCK.lock().unwrap();
    let root = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!(
            "context-relay-codex-discover-{}",
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
    let bin = root.join("bin");
    let home = root.join("home");
    let project = root.join("project");
    let marker = root.join("executed");
    fs::create_dir_all(&bin).unwrap();
    fs::create_dir_all(home.join(".codex")).unwrap();
    fs::create_dir_all(&project).unwrap();
    let wrapper = bin.join(if cfg!(windows) { "codex.exe" } else { "codex" });
    fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\necho executed > {}\necho 'codex 0.144.1'\n",
            marker.display()
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let old_path = std::env::var_os("PATH");
    let old_home = std::env::var_os("HOME");
    let old_codex_home = std::env::var_os("CODEX_HOME");
    unsafe {
        std::env::set_var("PATH", &bin);
        std::env::set_var("HOME", &home);
        std::env::set_var("CODEX_HOME", home.join(".codex"));
    }
    let device = DeviceId::from_str(DEVICE_ID).unwrap();
    let result = CodexAdapter::discover(
        &project,
        &project,
        ProjectId::from_str(PROJECT_ID).unwrap(),
        device,
        HybridLogicalClock::new(1, 0, device),
    );
    unsafe {
        match old_path {
            Some(value) => std::env::set_var("PATH", value),
            None => std::env::remove_var("PATH"),
        };
        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        };
        match old_codex_home {
            Some(value) => std::env::set_var("CODEX_HOME", value),
            None => std::env::remove_var("CODEX_HOME"),
        };
    }
    let adapter = result.unwrap();
    assert_eq!(
        adapter
            .probe(&ProbeContext {
                harness: HarnessId::Codex,
                requested_profile: None
            })
            .unwrap()
            .capability,
        CapabilityLevel::ImportOnly
    );
    assert!(!marker.exists());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn codex_home_and_user_skill_roots_are_distinct() {
    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let report = fixture
        .adapter
        .probe(&ProbeContext {
            harness: HarnessId::Codex,
            requested_profile: None,
        })
        .unwrap();
    assert_eq!(
        report.config_roots[0].display.as_deref(),
        fixture.codex_home.to_str()
    );
    assert_ne!(report.config_roots[0], report.config_roots[1]);
    let imported = import_everything(&fixture);
    assert!(
        imported
            .components
            .iter()
            .any(|component| component.kind == ComponentKind::Skill && component.name == "review")
    );
    assert!(!imported.components.iter().any(|component| {
        component
            .metadata
            .iter()
            .any(|(_, value)| value.contains("codex home/skills"))
    }));
}

#[test]
fn instructions_follow_global_root_to_cwd_precedence() {
    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let instructions = import_everything(&fixture)
        .components
        .into_iter()
        .filter(|component| component.kind == ComponentKind::Instruction)
        .collect::<Vec<_>>();
    assert!(instructions.iter().any(|component| {
        component
            .metadata
            .iter()
            .any(|(key, value)| key == "structuralLocation" && value == "AGENTS.override.md")
            && component
                .metadata
                .iter()
                .any(|(key, value)| key == "precedenceIndex" && value == "0")
    }));
    assert!(instructions.iter().any(|component| {
        component.body_markdown.contains("Repository instructions")
            && component
                .metadata
                .iter()
                .any(|(key, value)| key == "precedenceIndex" && value == "1")
    }));
    assert!(instructions.iter().any(|component| {
        component.body_markdown.contains("Service override")
            && component
                .metadata
                .iter()
                .any(|(key, value)| key == "precedenceIndex" && value == "2")
    }));
    assert!(!instructions.iter().any(|component| {
        component.body_markdown.contains("Global instructions")
            || component.body_markdown.contains("Service instructions")
    }));
}

#[test]
fn shadowed_instructions_and_managed_requirements_are_reported() {
    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    assert_eq!(
        fixture
            .adapter
            .probe(&ProbeContext {
                harness: HarnessId::Codex,
                requested_profile: None
            })
            .unwrap()
            .policy_conflicts,
        vec![
            "global_instructions_shadowed",
            "managed_requirements_active",
            "project_instructions_shadowed"
        ]
    );
}

#[test]
fn untrusted_projects_skip_project_config_hooks_and_rules() {
    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let config = fixture.codex_home.join("config.toml");
    let contents = fs::read_to_string(&config)
        .unwrap()
        .replace("trust_level = \"trusted\"", "trust_level = \"untrusted\"");
    fs::write(config, contents).unwrap();
    let report = fixture
        .adapter
        .probe(&ProbeContext {
            harness: HarnessId::Codex,
            requested_profile: None,
        })
        .unwrap();
    assert!(
        report
            .policy_conflicts
            .contains(&"project_untrusted".to_owned())
    );
    let imported = import_everything(&fixture);
    assert!(!imported.components.iter().any(|component| {
        component
            .metadata
            .iter()
            .any(|(_, value)| value.contains(".codex/"))
    }));
    assert!(
        imported
            .components
            .iter()
            .any(|component| component.body_markdown.contains("Repository instructions"))
    );
    assert!(
        imported
            .components
            .iter()
            .any(|component| component.name == "release")
    );
}

#[test]
fn unknown_versions_are_import_only() {
    let mut source: Value =
        serde_json::from_str(include_str!("fixtures/codex-0.144.1.json")).unwrap();
    source["version"] = json!("9.9.9");
    let fixture = fixture(&source.to_string());
    assert_eq!(
        fixture
            .adapter
            .probe(&ProbeContext {
                harness: HarnessId::Codex,
                requested_profile: None
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
                scopes: vec![]
            })
            .is_err()
    );
}

#[test]
fn forged_native_classification_cannot_execute_a_wrapper() {
    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let sentinel = fixture.root.join("forged-wrapper-ran");
    fs::write(
        &fixture.layout.executable,
        format!(
            "#!/bin/sh\n/usr/bin/touch '{}'\nexit 9\n",
            sentinel.display()
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let mut permissions = fs::metadata(&fixture.layout.executable)
            .unwrap()
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&fixture.layout.executable, permissions).unwrap();
    }

    let forged = CodexAdapter::from_layout(
        CodexLayout {
            executable_kind: CodexExecutableKind::Native,
            ..fixture.layout.clone()
        },
        fixture.project_id,
        DeviceId::from_str(DEVICE_ID).unwrap(),
        HybridLogicalClock::new(1_900_000_000_000, 0, DeviceId::from_str(DEVICE_ID).unwrap()),
    )
    .unwrap();
    let receipt = ApplyReceipt {
        plan_id: PlanId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073984").unwrap(),
        applied_hlc: HybridLogicalClock::new(
            1_900_000_000_001,
            0,
            DeviceId::from_str(DEVICE_ID).unwrap(),
        ),
        resulting_digests: vec![],
    };

    assert!(forged.validate_effective(&receipt).is_err());
    assert!(
        !sentinel.exists(),
        "forged native classification executed a wrapper"
    );
    assert_eq!(
        forged
            .probe(&ProbeContext {
                harness: HarnessId::Codex,
                requested_profile: None,
            })
            .unwrap()
            .capability,
        CapabilityLevel::ImportOnly
    );
    assert!(
        forged
            .render(&DesiredState {
                components: vec![],
                scopes: vec![],
            })
            .is_err()
    );
    assert!(
        forged
            .plan_native_markdown(&component(
                fixture.project_id,
                ScopeRef::Global,
                ComponentKind::Instruction,
                "AGENTS.override.md",
                "managed",
            ))
            .is_err()
    );

    fs::write(&fixture.layout.executable, b"unknown executable format").unwrap();
    let unknown = CodexAdapter::from_layout(
        CodexLayout {
            executable_kind: CodexExecutableKind::Native,
            ..fixture.layout.clone()
        },
        fixture.project_id,
        DeviceId::from_str(DEVICE_ID).unwrap(),
        HybridLogicalClock::new(1_900_000_000_000, 0, DeviceId::from_str(DEVICE_ID).unwrap()),
    )
    .unwrap();
    assert_eq!(
        unknown
            .probe(&ProbeContext {
                harness: HarnessId::Codex,
                requested_profile: None,
            })
            .unwrap()
            .capability,
        CapabilityLevel::ImportOnly
    );
    assert!(unknown.validate_effective(&receipt).is_err());
    assert!(!sentinel.exists());
}

#[test]
fn native_reprobe_rejects_changed_codex_installation_identity() {
    let mut fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let plan = codex_native_plan(&fixture, vec![]);
    NativeAdapter::reprobe_live_state(&mut fixture.adapter, &plan).unwrap();

    let original_executable = fs::read(&fixture.layout.executable).unwrap();
    fs::write(&fixture.layout.executable, b"concurrently replaced").unwrap();
    assert_eq!(
        NativeAdapter::reprobe_live_state(&mut fixture.adapter, &plan)
            .unwrap_err()
            .to_string(),
        "Codex installation changed"
    );
    fs::write(&fixture.layout.executable, original_executable).unwrap();

    for changed in [
        {
            let mut changed = plan.clone();
            changed.setup.harness = HarnessId::ClaudeCode;
            changed
        },
        {
            let mut changed = plan.clone();
            changed.setup.harness_version = "0.143.0".to_owned();
            changed
        },
        {
            let mut changed = plan.clone();
            changed.setup.executable_path = test_wire_path(&fixture.root.join("other-codex"));
            changed
        },
    ] {
        assert_eq!(
            NativeAdapter::reprobe_live_state(&mut fixture.adapter, &changed)
                .unwrap_err()
                .to_string(),
            "Codex installation changed"
        );
    }

    fs::write(&fixture.layout.executable, b"#!/bin/sh\nexit 9\n").unwrap();
    let mut import_only = CodexAdapter::from_layout(
        CodexLayout {
            executable_kind: CodexExecutableKind::Native,
            ..fixture.layout.clone()
        },
        fixture.project_id,
        DeviceId::from_str(DEVICE_ID).unwrap(),
        HybridLogicalClock::new(1_900_000_000_000, 0, DeviceId::from_str(DEVICE_ID).unwrap()),
    )
    .unwrap();
    assert_eq!(
        NativeAdapter::reprobe_live_state(&mut import_only, &plan)
            .unwrap_err()
            .to_string(),
        "Codex installation changed"
    );
}

#[cfg(unix)]
#[test]
fn native_reprobe_rejects_a_symlinked_harness_even_with_identical_bytes() {
    use std::os::unix::fs::symlink;

    let mut fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let plan = codex_native_plan(&fixture, vec![]);
    let replacement = fixture.root.join("same-codex-bytes");
    fs::write(&replacement, fs::read(&fixture.layout.executable).unwrap()).unwrap();
    fs::remove_file(&fixture.layout.executable).unwrap();
    symlink(&replacement, &fixture.layout.executable).unwrap();

    assert_eq!(
        NativeAdapter::reprobe_live_state(&mut fixture.adapter, &plan)
            .unwrap_err()
            .to_string(),
        "Codex installation changed"
    );
}

#[cfg(unix)]
#[test]
fn verified_runner_rejects_path_substitution_before_execution() {
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };

    use context_relay_core::native_transaction::engine::BoundaryError;

    struct SubstitutingRunner {
        executable: PathBuf,
        original: PathBuf,
        replacement: PathBuf,
        executions: Arc<AtomicU64>,
    }

    impl CodexCommandRunner for SubstitutingRunner {
        fn before_launch(&mut self, _: &[String]) -> Result<(), BoundaryError> {
            fs::rename(&self.executable, &self.original)
                .map_err(|_| BoundaryError::new("fixture rename failed"))?;
            fs::rename(&self.replacement, &self.executable)
                .map_err(|_| BoundaryError::new("fixture substitution failed"))
        }

        fn run(&mut self, _: VerifiedCodexCommand<'_>) -> Result<Vec<u8>, BoundaryError> {
            self.executions.fetch_add(1, Ordering::Relaxed);
            Ok(br#"{"installed":[],"available":[]}"#.to_vec())
        }
    }

    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let bridge = executable_bridge(&fixture, "bridge executable");
    let replacement = fixture.root.join("replacement-codex");
    fs::write(&replacement, fs::read(&fixture.layout.executable).unwrap()).unwrap();
    let executions = Arc::new(AtomicU64::new(0));
    let runner = SubstitutingRunner {
        executable: fixture.layout.executable.clone(),
        original: fixture.root.join("original-codex"),
        replacement,
        executions: Arc::clone(&executions),
    };

    assert!(
        fixture
            .adapter
            .plan_bridge_cli_mutation_with_runner(&bridge, runner)
            .is_err()
    );
    assert_eq!(
        executions.load(Ordering::Relaxed),
        0,
        "substituted executable reached the runner launch boundary"
    );
}

#[cfg(unix)]
#[test]
fn verified_runner_executes_prepared_identity_after_late_path_substitution() {
    use std::{
        os::unix::fs::PermissionsExt as _,
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
    };

    use context_relay_core::native_transaction::engine::BoundaryError;

    struct LateSubstitutingRunner {
        executable: PathBuf,
        original: PathBuf,
        replacement: PathBuf,
        working_directory: PathBuf,
        successful_launches: Arc<AtomicU64>,
        substituted: bool,
    }

    impl CodexCommandRunner for LateSubstitutingRunner {
        fn run(&mut self, command: VerifiedCodexCommand<'_>) -> Result<Vec<u8>, BoundaryError> {
            let arguments = command.arguments().to_vec();
            if !self.substituted {
                fs::rename(&self.executable, &self.original)
                    .map_err(|_| BoundaryError::new("fixture rename failed"))?;
                fs::rename(&self.replacement, &self.executable)
                    .map_err(|_| BoundaryError::new("fixture substitution failed"))?;
                self.substituted = true;
            }
            command.execute(&self.working_directory)?;
            self.successful_launches.fetch_add(1, Ordering::Relaxed);
            Ok(match arguments.as_slice() {
                [plugin, list, json]
                    if (plugin.as_str(), list.as_str(), json.as_str())
                        == ("plugin", "list", "--json") =>
                {
                    br#"{"installed":[],"available":[]}"#.to_vec()
                }
                _ => b"[]".to_vec(),
            })
        }
    }

    let mut fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let true_source = ["/usr/bin/true", "/bin/true"]
        .into_iter()
        .map(Path::new)
        .find(|path| path.is_file())
        .unwrap();
    let false_source = ["/usr/bin/false", "/bin/false"]
        .into_iter()
        .map(Path::new)
        .find(|path| path.is_file())
        .unwrap();
    fs::copy(true_source, &fixture.layout.executable).unwrap();
    fs::set_permissions(
        &fixture.layout.executable,
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let device_id = DeviceId::from_str(DEVICE_ID).unwrap();
    fixture.adapter = CodexAdapter::from_layout(
        fixture.layout.clone(),
        fixture.project_id,
        device_id,
        HybridLogicalClock::new(1_900_000_000_000, 0, device_id),
    )
    .unwrap();
    let replacement = fixture.root.join("replacement-codex");
    fs::copy(false_source, &replacement).unwrap();
    let successful_launches = Arc::new(AtomicU64::new(0));
    let runner = LateSubstitutingRunner {
        executable: fixture.layout.executable.clone(),
        original: fixture.root.join("original-codex"),
        replacement,
        working_directory: fixture.layout.working_directory.clone(),
        successful_launches: Arc::clone(&successful_launches),
        substituted: false,
    };
    let bridge = executable_bridge(&fixture, "bridge executable");

    assert!(
        fixture
            .adapter
            .plan_bridge_cli_mutation_with_runner(&bridge, runner)
            .is_err(),
        "the next probe must reject the substituted executable"
    );
    assert_eq!(
        successful_launches.load(Ordering::Relaxed),
        1,
        "the prepared verified identity did not execute successfully"
    );
}

#[test]
fn native_digest_comparison_rejects_concurrent_mutation_and_absence() {
    let mut fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let target = fixture.root.join("approved-bridge-executable");
    let approved_bytes = b"approved native bytes";
    fs::write(&target, approved_bytes).unwrap();
    let plan = codex_native_plan(
        &fixture,
        vec![ExpectedNativeDigest {
            target: test_wire_path(&target),
            expected_digest: Some(test_digest(approved_bytes)),
        }],
    );
    NativeAdapter::compare_approved_digests(&mut fixture.adapter, &plan).unwrap();

    fs::write(&target, b"concurrent mutation").unwrap();
    assert_eq!(
        NativeAdapter::compare_approved_digests(&mut fixture.adapter, &plan)
            .unwrap_err()
            .to_string(),
        "Codex native state changed"
    );

    fs::remove_file(&target).unwrap();
    assert_eq!(
        NativeAdapter::compare_approved_digests(&mut fixture.adapter, &plan)
            .unwrap_err()
            .to_string(),
        "Codex native state changed"
    );
}

#[test]
fn native_staged_output_validation_rejects_either_changed_hash() {
    let mut fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let plan = codex_native_plan(&fixture, vec![]);
    let approved = RestrictedRun {
        staged_output_hash: plan.expected_semantic_output_hash,
        scanner_result_hash: plan.scanner_result_hash,
    };
    let frozen =
        NativeAdapter::validate_staged_output(&mut fixture.adapter, &plan, &approved).unwrap();
    assert_eq!(
        frozen.staged_output_hash,
        plan.expected_semantic_output_hash
    );
    assert_eq!(frozen.scanner_result_hash, plan.scanner_result_hash);

    for changed in [
        RestrictedRun {
            staged_output_hash: Sha256Digest([41; 32]),
            ..approved.clone()
        },
        RestrictedRun {
            scanner_result_hash: Sha256Digest([42; 32]),
            ..approved
        },
    ] {
        assert_eq!(
            NativeAdapter::validate_staged_output(&mut fixture.adapter, &plan, &changed)
                .unwrap_err()
                .to_string(),
            "Codex staged output changed"
        );
    }
}

#[test]
fn native_effective_validation_rejects_receipts_outside_the_plan() {
    let mut fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let plan = codex_native_plan(&fixture, vec![]);
    let receipt = ApplyReceipt {
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
    };
    NativeAdapter::validate_effective(&mut fixture.adapter, &plan, &receipt).unwrap();

    let wrong_plan = ApplyReceipt {
        plan_id: PlanId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073985").unwrap(),
        ..receipt.clone()
    };
    assert_eq!(
        NativeAdapter::validate_effective(&mut fixture.adapter, &plan, &wrong_plan)
            .unwrap_err()
            .to_string(),
        "Codex effective state differs from the plan"
    );

    let wrong_digests = ApplyReceipt {
        resulting_digests: vec![Sha256Digest([43; 32])],
        ..receipt
    };
    assert_eq!(
        NativeAdapter::validate_effective(&mut fixture.adapter, &plan, &wrong_digests)
            .unwrap_err()
            .to_string(),
        "Codex effective state differs from the plan"
    );
}

#[test]
fn mixed_toml_preserves_comments_unknown_fields_trust_and_rolls_back() {
    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let before = fs::read(fixture.codex_home.join("config.toml")).unwrap();
    let desired = DesiredState {
        components: vec![component(
            fixture.project_id,
            ScopeRef::Global,
            ComponentKind::PermissionDeclaration,
            "permissions",
            "\"full\"",
        )],
        scopes: vec![NativeScope::Global],
    };
    let mutation = fixture
        .adapter
        .plan_native_config(&desired, ScopeRef::Global)
        .unwrap();
    let NativeState::RegularFile { bytes, .. } = NativeState::decode_v1(&mutation.content).unwrap()
    else {
        panic!("regular file")
    };
    let rendered = String::from_utf8(bytes).unwrap();
    for preserved in [
        "# user heading",
        "unknown_user_key",
        "[projects",
        "[plugins",
        "[mcp_servers.docs]",
    ] {
        assert!(rendered.contains(preserved));
    }
    let mut native = OsNativeTransactionFileSystem::new([1; 16]);
    let images = native
        .create_before_images(std::slice::from_ref(&mutation))
        .unwrap();
    native.record_native_metadata(&images).unwrap();
    native
        .compare_and_swap_targets(std::slice::from_ref(&mutation))
        .unwrap();
    native.apply_mutation(&[1; 16], &mutation).unwrap();
    native.restore_matching_applied_targets(&[1; 16]).unwrap();
    assert_eq!(
        fs::read(fixture.codex_home.join("config.toml")).unwrap(),
        before
    );
}

#[test]
fn plugin_and_global_mcp_changes_use_only_official_cli_argv() {
    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let mut removed_plugin = component(
        fixture.project_id,
        ScopeRef::Global,
        ComponentKind::Plugin,
        "old@team",
        "true",
    );
    removed_plugin.archived = true;
    let mut removed_mcp = component(
        fixture.project_id,
        ScopeRef::Global,
        ComponentKind::McpServer,
        "old-tools",
        "{}",
    );
    removed_mcp.archived = true;
    let rendered = fixture
        .adapter
        .render(&DesiredState {
            components: vec![
                component(
                    fixture.project_id,
                    ScopeRef::Global,
                    ComponentKind::Plugin,
                    "formatter@team",
                    "true",
                ),
                component(
                    fixture.project_id,
                    ScopeRef::Global,
                    ComponentKind::McpServer,
                    "docs",
                    r#"{"url":"https://example.com/mcp","bearer_token_env_var":"DOCS_TOKEN"}"#,
                ),
                removed_plugin,
                removed_mcp,
                component(
                    fixture.project_id,
                    ScopeRef::Global,
                    ComponentKind::McpServer,
                    "public-docs",
                    r#"{"url":"https://example.com/public"}"#,
                ),
                component(
                    fixture.project_id,
                    ScopeRef::Global,
                    ComponentKind::McpServer,
                    "local-tools",
                    r#"{"type":"stdio","command":"local-server","args":["--safe"],"env":{"ZETA":"last","ALPHA":"first"}}"#,
                ),
            ],
            scopes: vec![NativeScope::Global],
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
            vec!["plugin", "add", "formatter@team", "--json"],
            vec![
                "mcp",
                "add",
                "docs",
                "--url",
                "https://example.com/mcp",
                "--bearer-token-env-var",
                "DOCS_TOKEN"
            ],
            vec!["plugin", "remove", "old@team", "--json"],
            vec!["mcp", "remove", "old-tools"],
            vec![
                "mcp",
                "add",
                "public-docs",
                "--url",
                "https://example.com/public"
            ],
            vec![
                "mcp",
                "add",
                "local-tools",
                "--env",
                "ALPHA=first",
                "--env",
                "ZETA=last",
                "--",
                "local-server",
                "--safe"
            ],
        ]
    );
}

fn codex_mcp_get(body: &str) -> Vec<u8> {
    let body: Value = serde_json::from_str(body).unwrap();
    serde_json::to_vec(&json!({
        "name": "context-relay",
        "enabled": true,
        "disabled_reason": null,
        "transport": {
            "type": "stdio",
            "command": body["command"],
            "args": body["args"],
            "env": {},
            "env_vars": [],
            "cwd": null
        },
        "enabled_tools": null,
        "disabled_tools": null,
        "startup_timeout_sec": null,
        "tool_timeout_sec": null
    }))
    .unwrap()
}

fn codex_mcp_list(body: &str) -> Vec<u8> {
    let body: Value = serde_json::from_str(body).unwrap();
    serde_json::to_vec(&json!([{
        "name": "context-relay",
        "enabled": true,
        "disabled_reason": null,
        "transport": {
            "type": "stdio",
            "command": body["command"],
            "args": body["args"],
            "env": {},
            "env_vars": [],
            "cwd": null
        },
        "startup_timeout_sec": null,
        "tool_timeout_sec": null,
        "auth_status": "unsupported"
    }]))
    .unwrap()
}

#[test]
fn bridge_cli_plan_binds_exact_declarations_and_preserves_argv_boundaries() {
    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let bridge = executable_bridge(&fixture, "bridge executable with spaces");
    let mut commands = Vec::new();
    let mut validation = |argv: &[String]| {
        commands.push(argv.to_vec());
        Ok(match argv {
            [plugin, list, json]
                if (plugin.as_str(), list.as_str(), json.as_str())
                    == ("plugin", "list", "--json") =>
            {
                br#"{"installed":[],"available":[]}"#.to_vec()
            }
            [mcp, list, json]
                if (mcp.as_str(), list.as_str(), json.as_str()) == ("mcp", "list", "--json") =>
            {
                b"[]".to_vec()
            }
            _ => panic!("unexpected validation argv: {argv:?}"),
        })
    };

    let mutation = fixture
        .adapter
        .plan_bridge_cli_mutation_with_runner(&bridge, &mut validation)
        .unwrap();

    assert_eq!(mutation.stable_id, bridge.id.to_string());
    assert_eq!(mutation.expected, None);
    assert_eq!(mutation.intended, Some(declaration(&bridge.body_markdown)));
    assert_eq!(
        mutation
            .forward
            .iter()
            .map(|operation| {
                operation
                    .arguments
                    .iter()
                    .map(|argument| argument.display.clone().unwrap())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>(),
        vec![vec![
            "mcp",
            "add",
            "context-relay",
            "--",
            bridge.body_markdown.parse::<Value>().unwrap()["command"]
                .as_str()
                .unwrap(),
            "--harness",
            "codex",
        ]]
    );
    assert_eq!(
        mutation.rollback[0]
            .arguments
            .iter()
            .map(|argument| argument.display.as_deref().unwrap())
            .collect::<Vec<_>>(),
        ["mcp", "remove", "context-relay"]
    );
    assert_eq!(
        commands,
        vec![
            vec!["plugin", "list", "--json"],
            vec!["mcp", "list", "--json"],
        ]
    );
}

#[test]
fn bridge_cli_plan_restores_the_exact_managed_prior_declaration() {
    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let prior = executable_bridge(&fixture, "prior bridge executable");
    let intended = executable_bridge(&fixture, "next bridge executable");
    let prior_body = prior.body_markdown.clone();
    let prior_list = codex_mcp_list(&prior_body);
    let prior_get = codex_mcp_get(&prior_body);
    let mut validation = move |argv: &[String]| {
        Ok(match argv {
            [plugin, list, json]
                if (plugin.as_str(), list.as_str(), json.as_str())
                    == ("plugin", "list", "--json") =>
            {
                br#"{"installed":[],"available":[]}"#.to_vec()
            }
            [mcp, list, json]
                if (mcp.as_str(), list.as_str(), json.as_str()) == ("mcp", "list", "--json") =>
            {
                prior_list.clone()
            }
            [mcp, get, name, json]
                if (mcp.as_str(), get.as_str(), name.as_str(), json.as_str())
                    == ("mcp", "get", "context-relay", "--json") =>
            {
                prior_get.clone()
            }
            _ => panic!("unexpected validation argv: {argv:?}"),
        })
    };

    let mutation = fixture
        .adapter
        .plan_bridge_cli_mutation_with_runner(&intended, &mut validation)
        .unwrap();

    assert_eq!(mutation.expected, Some(declaration(&prior.body_markdown)));
    assert_eq!(
        mutation.rollback[0]
            .arguments
            .iter()
            .map(|argument| argument.display.as_deref().unwrap())
            .collect::<Vec<_>>(),
        [
            "mcp",
            "add",
            "context-relay",
            "--",
            serde_json::from_str::<Value>(&prior.body_markdown).unwrap()["command"]
                .as_str()
                .unwrap(),
            "--harness",
            "codex",
        ]
    );
}

#[test]
fn bridge_cli_plan_treats_a_mismatched_get_name_as_invalid_inspection_output() {
    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let intended = executable_bridge(&fixture, "intended bridge executable");
    let listed = codex_mcp_list(&intended.body_markdown);
    let mut mismatched_get: Value =
        serde_json::from_slice(&codex_mcp_get(&intended.body_markdown)).unwrap();
    mismatched_get["name"] = Value::String("different-server".to_owned());
    let mismatched_get = serde_json::to_vec(&mismatched_get).unwrap();
    let mut validation = |argv: &[String]| {
        Ok(match argv {
            [plugin, list, json]
                if (plugin.as_str(), list.as_str(), json.as_str())
                    == ("plugin", "list", "--json") =>
            {
                br#"{"installed":[],"available":[]}"#.to_vec()
            }
            [mcp, list, json]
                if (mcp.as_str(), list.as_str(), json.as_str()) == ("mcp", "list", "--json") =>
            {
                listed.clone()
            }
            [mcp, get, name, json]
                if (mcp.as_str(), get.as_str(), name.as_str(), json.as_str())
                    == ("mcp", "get", "context-relay", "--json") =>
            {
                mismatched_get.clone()
            }
            _ => panic!("unexpected validation argv: {argv:?}"),
        })
    };

    let error = fixture
        .adapter
        .plan_bridge_cli_mutation_with_runner(&intended, &mut validation)
        .unwrap_err();

    assert_eq!(error.code, ErrorCode::InvalidRequest);
}

#[test]
fn bridge_cli_plan_reports_disabled_and_unmanaged_prior_declarations_as_conflicts() {
    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let intended = executable_bridge(&fixture, "intended bridge executable");
    let prior = executable_bridge(&fixture, "prior unmanaged bridge executable");
    let mut unmanaged_body: Value = serde_json::from_str(&prior.body_markdown).unwrap();
    unmanaged_body["args"][1] = Value::String("claude-code".to_owned());
    let unmanaged = codex_mcp_get(&serde_json::to_string(&unmanaged_body).unwrap());
    let listed = codex_mcp_list(&intended.body_markdown);
    let mut unmanaged_validation = |argv: &[String]| {
        Ok(match argv {
            [plugin, list, json]
                if (plugin.as_str(), list.as_str(), json.as_str())
                    == ("plugin", "list", "--json") =>
            {
                br#"{"installed":[],"available":[]}"#.to_vec()
            }
            [mcp, list, json]
                if (mcp.as_str(), list.as_str(), json.as_str()) == ("mcp", "list", "--json") =>
            {
                listed.clone()
            }
            [mcp, get, name, json]
                if (mcp.as_str(), get.as_str(), name.as_str(), json.as_str())
                    == ("mcp", "get", "context-relay", "--json") =>
            {
                unmanaged.clone()
            }
            _ => panic!("unexpected validation argv: {argv:?}"),
        })
    };
    let unmanaged_error = fixture
        .adapter
        .plan_bridge_cli_mutation_with_runner(&intended, &mut unmanaged_validation)
        .unwrap_err();
    assert_eq!(unmanaged_error.code, ErrorCode::Conflict);

    let mut disabled_list: Value = serde_json::from_slice(&listed).unwrap();
    disabled_list[0]["enabled"] = Value::Bool(false);
    let disabled_list = serde_json::to_vec(&disabled_list).unwrap();
    let mut disabled_validation = |argv: &[String]| {
        Ok(match argv {
            [plugin, list, json]
                if (plugin.as_str(), list.as_str(), json.as_str())
                    == ("plugin", "list", "--json") =>
            {
                br#"{"installed":[],"available":[]}"#.to_vec()
            }
            [mcp, list, json]
                if (mcp.as_str(), list.as_str(), json.as_str()) == ("mcp", "list", "--json") =>
            {
                disabled_list.clone()
            }
            _ => panic!("disabled declaration must be rejected before mcp get"),
        })
    };
    let disabled_error = fixture
        .adapter
        .plan_bridge_cli_mutation_with_runner(&intended, &mut disabled_validation)
        .unwrap_err();
    assert_eq!(disabled_error.code, ErrorCode::Conflict);
}

#[test]
fn bridge_cli_plan_rejects_malformed_redacted_secret_bearing_and_unmanaged_prior_state() {
    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let intended = executable_bridge(&fixture, "intended bridge");
    let malformed = b"not-json".to_vec();
    let redacted =
        codex_mcp_get(r#"{"args":["--harness","codex"],"command":"<redacted>","type":"stdio"}"#);
    let secret_bearing = serde_json::to_vec(&json!({
        "name": "context-relay",
        "enabled": true,
        "disabled_reason": null,
        "transport": {
            "type": "stdio",
            "command": "/managed/bridge",
            "args": ["--harness", "codex"],
            "env": {"TOKEN": "secret"},
            "env_vars": [],
            "cwd": null
        },
        "enabled_tools": null,
        "disabled_tools": null,
        "startup_timeout_sec": null,
        "tool_timeout_sec": null
    }))
    .unwrap();
    let unmanaged = codex_mcp_get(
        r#"{"args":["--harness","claude-code"],"command":"/managed/bridge","type":"stdio"}"#,
    );

    for (rejected, expected_code) in [
        (malformed, ErrorCode::InvalidRequest),
        (redacted, ErrorCode::InvalidRequest),
        (secret_bearing, ErrorCode::Conflict),
        (unmanaged, ErrorCode::Conflict),
    ] {
        let list = codex_mcp_list(&intended.body_markdown);
        let mut validation = |argv: &[String]| {
            Ok(match argv {
                [plugin, list, json]
                    if (plugin.as_str(), list.as_str(), json.as_str())
                        == ("plugin", "list", "--json") =>
                {
                    br#"{"installed":[],"available":[]}"#.to_vec()
                }
                [mcp, list_command, json]
                    if (mcp.as_str(), list_command.as_str(), json.as_str())
                        == ("mcp", "list", "--json") =>
                {
                    list.clone()
                }
                [mcp, get, name, json]
                    if (mcp.as_str(), get.as_str(), name.as_str(), json.as_str())
                        == ("mcp", "get", "context-relay", "--json") =>
                {
                    rejected.clone()
                }
                _ => panic!("unexpected validation argv: {argv:?}"),
            })
        };
        let error = fixture
            .adapter
            .plan_bridge_cli_mutation_with_runner(&intended, &mut validation)
            .unwrap_err();
        assert_eq!(error.code, expected_code);
    }

    let mut disabled_list: Value =
        serde_json::from_slice(&codex_mcp_list(&intended.body_markdown)).unwrap();
    disabled_list[0]["enabled"] = Value::Bool(false);
    let disabled_list = serde_json::to_vec(&disabled_list).unwrap();
    let mut validation = |argv: &[String]| {
        Ok(match argv {
            [plugin, list, json]
                if (plugin.as_str(), list.as_str(), json.as_str())
                    == ("plugin", "list", "--json") =>
            {
                br#"{"installed":[],"available":[]}"#.to_vec()
            }
            [mcp, list, json]
                if (mcp.as_str(), list.as_str(), json.as_str()) == ("mcp", "list", "--json") =>
            {
                disabled_list.clone()
            }
            _ => panic!("disabled declaration must be rejected before mcp get"),
        })
    };
    let error = fixture
        .adapter
        .plan_bridge_cli_mutation_with_runner(&intended, &mut validation)
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
}

#[test]
fn cli_executor_reprobes_intended_state_without_starting_the_bridge() {
    use std::sync::{Arc, Mutex};

    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let bridge = executable_bridge(&fixture, "bridge executable");
    let intended_body = bridge.body_markdown.clone();
    let mutation = {
        let mut validation = |argv: &[String]| {
            Ok(match argv {
                [plugin, list, json]
                    if (plugin.as_str(), list.as_str(), json.as_str())
                        == ("plugin", "list", "--json") =>
                {
                    br#"{"installed":[],"available":[]}"#.to_vec()
                }
                [mcp, list, json]
                    if (mcp.as_str(), list.as_str(), json.as_str())
                        == ("mcp", "list", "--json") =>
                {
                    b"[]".to_vec()
                }
                _ => panic!("unexpected validation argv: {argv:?}"),
            })
        };
        fixture
            .adapter
            .plan_bridge_cli_mutation_with_runner(&bridge, &mut validation)
            .unwrap()
    };
    let live = Arc::new(Mutex::new(None::<String>));
    let operations = Arc::new(Mutex::new(Vec::<Vec<String>>::new()));
    let operation_live = Arc::clone(&live);
    let operation_log = Arc::clone(&operations);
    let operation = move |argv: &[String]| {
        operation_log.lock().unwrap().push(argv.to_vec());
        *operation_live.lock().unwrap() = Some(intended_body.clone());
        Ok(Vec::new())
    };
    let validation_live = Arc::clone(&live);
    let validation = move |argv: &[String]| {
        let live = validation_live.lock().unwrap().clone();
        Ok(match argv {
            [plugin, list, json]
                if (plugin.as_str(), list.as_str(), json.as_str())
                    == ("plugin", "list", "--json") =>
            {
                br#"{"installed":[],"available":[]}"#.to_vec()
            }
            [mcp, list, json]
                if (mcp.as_str(), list.as_str(), json.as_str()) == ("mcp", "list", "--json") =>
            {
                live.as_deref()
                    .map(codex_mcp_list)
                    .unwrap_or_else(|| b"[]".to_vec())
            }
            [mcp, get, name, json]
                if (mcp.as_str(), get.as_str(), name.as_str(), json.as_str())
                    == ("mcp", "get", "context-relay", "--json") =>
            {
                codex_mcp_get(live.as_deref().unwrap())
            }
            _ => panic!("unexpected validation argv: {argv:?}"),
        })
    };
    let mut executor = fixture
        .adapter
        .cli_executor_with_runners(operation, validation);

    executor
        .compare_cli_targets(std::slice::from_ref(&mutation))
        .unwrap();
    assert!(operations.lock().unwrap().is_empty());
    assert_eq!(executor.probe_cli_mutation(&mutation).unwrap(), None);
    assert!(operations.lock().unwrap().is_empty());
    let outcome = executor.apply_cli_mutation(&mutation).unwrap();
    assert_eq!(outcome.command_error, None);
    assert_eq!(
        outcome.resulting_fingerprint,
        mutation
            .intended
            .as_ref()
            .map(|declaration| declaration.fingerprint)
    );
    assert_eq!(operations.lock().unwrap().len(), 1);
}

#[test]
fn cli_executor_restores_only_while_live_declaration_equals_intended() {
    use std::sync::{Arc, Mutex};

    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let bridge = executable_bridge(&fixture, "bridge executable");
    let mutation = {
        let mut validation = |argv: &[String]| {
            Ok(match argv {
                [plugin, list, json]
                    if (plugin.as_str(), list.as_str(), json.as_str())
                        == ("plugin", "list", "--json") =>
                {
                    br#"{"installed":[],"available":[]}"#.to_vec()
                }
                [mcp, list, json]
                    if (mcp.as_str(), list.as_str(), json.as_str())
                        == ("mcp", "list", "--json") =>
                {
                    b"[]".to_vec()
                }
                _ => panic!("unexpected validation argv: {argv:?}"),
            })
        };
        fixture
            .adapter
            .plan_bridge_cli_mutation_with_runner(&bridge, &mut validation)
            .unwrap()
    };
    let divergent = executable_bridge(&fixture, "divergent bridge").body_markdown;
    let live = Arc::new(Mutex::new(Some(divergent)));
    let operations = Arc::new(Mutex::new(0_u64));
    let operation_live = Arc::clone(&live);
    let operation_count = Arc::clone(&operations);
    let operation = move |_: &[String]| {
        *operation_count.lock().unwrap() += 1;
        *operation_live.lock().unwrap() = None;
        Ok(Vec::new())
    };
    let validation_live = Arc::clone(&live);
    let validation = move |argv: &[String]| {
        let live = validation_live.lock().unwrap().clone();
        Ok(match argv {
            [plugin, list, json]
                if (plugin.as_str(), list.as_str(), json.as_str())
                    == ("plugin", "list", "--json") =>
            {
                br#"{"installed":[],"available":[]}"#.to_vec()
            }
            [mcp, list, json]
                if (mcp.as_str(), list.as_str(), json.as_str()) == ("mcp", "list", "--json") =>
            {
                live.as_deref()
                    .map(codex_mcp_list)
                    .unwrap_or_else(|| b"[]".to_vec())
            }
            [mcp, get, name, json]
                if (mcp.as_str(), get.as_str(), name.as_str(), json.as_str())
                    == ("mcp", "get", "context-relay", "--json") =>
            {
                codex_mcp_get(live.as_deref().unwrap())
            }
            _ => panic!("unexpected validation argv: {argv:?}"),
        })
    };
    let mut executor = fixture
        .adapter
        .cli_executor_with_runners(operation, validation);

    let divergent = executor.restore_cli_mutation_if_matches(&mutation).unwrap();
    assert!(!divergent.restored);
    assert_eq!(*operations.lock().unwrap(), 0);

    *live.lock().unwrap() = Some(bridge.body_markdown.clone());
    let restored = executor.restore_cli_mutation_if_matches(&mutation).unwrap();
    assert!(restored.restored);
    assert_eq!(restored.resulting_fingerprint, None);
    assert_eq!(*operations.lock().unwrap(), 1);
}

#[test]
fn managed_markdown_preserves_unmanaged_bytes_and_rejects_malformed_markers() {
    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let path = fixture.codex_home.join("AGENTS.override.md");
    let before = b"# User preface\n<!-- context-relay:start -->\nold\n<!-- context-relay:end -->\nUser footer\n".to_vec();
    fs::write(&path, &before).unwrap();
    let component = component(
        fixture.project_id,
        ScopeRef::Global,
        ComponentKind::Instruction,
        "AGENTS.override.md",
        "new managed text",
    );
    let mutation = fixture.adapter.plan_native_markdown(&component).unwrap();
    let NativeState::RegularFile { bytes, .. } = NativeState::decode_v1(&mutation.content).unwrap()
    else {
        panic!("regular file")
    };
    let rendered = String::from_utf8(bytes).unwrap();
    assert!(rendered.starts_with("# User preface\n"));
    assert!(rendered.ends_with("User footer\n"));
    assert!(rendered.contains("new managed text"));
    let mut native = OsNativeTransactionFileSystem::new([2; 16]);
    let images = native
        .create_before_images(std::slice::from_ref(&mutation))
        .unwrap();
    native.record_native_metadata(&images).unwrap();
    native
        .compare_and_swap_targets(std::slice::from_ref(&mutation))
        .unwrap();
    native.apply_mutation(&[2; 16], &mutation).unwrap();
    native.restore_matching_applied_targets(&[2; 16]).unwrap();
    assert_eq!(fs::read(&path).unwrap(), before);
    for malformed in [
        "<!-- context-relay:start -->\n",
        "<!-- context-relay:end -->\n<!-- context-relay:start -->\n",
        "<!-- context-relay:start -->\na\n<!-- context-relay:end -->\n<!-- context-relay:start -->\nb\n<!-- context-relay:end -->\n",
    ] {
        fs::write(&path, malformed).unwrap();
        assert!(fixture.adapter.plan_native_markdown(&component).is_err());
    }
}

#[test]
fn primary_memory_codex_markdown_handles_crlf_replacement_archive_and_absence() {
    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let device_id = DeviceId::from_str(DEVICE_ID).unwrap();
    let mut managed = primary_memory_instruction_component(
        HarnessId::Codex,
        fixture.project_id,
        device_id,
        HybridLogicalClock::new(1_900_000_000_000, 0, device_id),
    )
    .unwrap();
    let path = fixture.layout.project_root.join("AGENTS.md");
    fs::write(
        &path,
        b"user prefix\r\n<!-- context-relay:start -->\r\nold\r\n<!-- context-relay:end -->\r\nuser suffix\r\n",
    )
    .unwrap();

    let mutation = fixture.adapter.plan_native_markdown(&managed).unwrap();
    let NativeState::RegularFile { bytes, .. } = NativeState::decode_v1(&mutation.content).unwrap()
    else {
        panic!("primary instructions remain a regular file")
    };
    let expected = format!(
        "user prefix\r\n<!-- context-relay:start -->\r\n{}<!-- context-relay:end -->\r\nuser suffix\r\n",
        PRIMARY_MEMORY_INSTRUCTIONS.replace('\n', "\r\n")
    );
    assert_eq!(bytes, expected.as_bytes());

    fs::write(&path, &bytes).unwrap();
    let reapplied = fixture.adapter.plan_native_markdown(&managed).unwrap();
    let NativeState::RegularFile {
        bytes: reapplied, ..
    } = NativeState::decode_v1(&reapplied.content).unwrap()
    else {
        panic!("reapplied primary instructions remain a regular file")
    };
    assert_eq!(reapplied, bytes);

    managed.archived = true;
    let archived = fixture.adapter.plan_native_markdown(&managed).unwrap();
    let NativeState::RegularFile {
        bytes: archived, ..
    } = NativeState::decode_v1(&archived.content).unwrap()
    else {
        panic!("archiving preserves the unmanaged file")
    };
    assert_eq!(archived, b"user prefix\r\nuser suffix\r\n");

    fs::remove_file(&path).unwrap();
    let template_name = "PRIMARY.template.md";
    fs::write(
        fixture.layout.project_root.join(template_name),
        "# Metadata template\n",
    )
    .unwrap();
    let config_path = fixture.codex_home.join("config.toml");
    let config = fs::read_to_string(&config_path).unwrap();
    fs::write(
        &config_path,
        format!("project_doc_fallback_filenames = [\"{template_name}\"]\n{config}"),
    )
    .unwrap();
    managed.archived = false;
    let created = fixture.adapter.plan_native_markdown(&managed).unwrap();
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
    assert_eq!(preview.files[0].bytes_sha256, test_digest(&created_bytes));
    assert_eq!(preview.files[0].byte_length, created_bytes.len() as u64);

    let nonce = [42; 16];
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
    let archived = fixture.adapter.plan_native_markdown(&managed).unwrap();
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
        test_digest(&archived_bytes)
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
    assert!(fixture.adapter.plan_native_markdown(&managed).is_err());
}

#[test]
fn hooks_json_preserves_unknown_fields_and_rolls_back() {
    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let path = fixture.codex_home.join("hooks.json");
    let before = fs::read(&path).unwrap();
    let component = component(
        fixture.project_id,
        ScopeRef::Global,
        ComponentKind::Hook,
        "hooks.json",
        r#"{"Stop":[]}"#,
    );
    let mutation = fixture.adapter.plan_native_hooks_json(&component).unwrap();
    let NativeState::RegularFile { bytes, .. } = NativeState::decode_v1(&mutation.content).unwrap()
    else {
        panic!("regular file")
    };
    let rendered: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(rendered["description"], "global hooks");
    assert_eq!(rendered["unknown"]["keep"], true);
    assert!(rendered["hooks"].get("Stop").is_some());
    let mut native = OsNativeTransactionFileSystem::new([3; 16]);
    let images = native
        .create_before_images(std::slice::from_ref(&mutation))
        .unwrap();
    native.record_native_metadata(&images).unwrap();
    native
        .compare_and_swap_targets(std::slice::from_ref(&mutation))
        .unwrap();
    native.apply_mutation(&[3; 16], &mutation).unwrap();
    native.restore_matching_applied_targets(&[3; 16]).unwrap();
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn project_mcp_changes_are_import_only_and_redacted_mcp_cannot_be_applied() {
    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let project = component(
        fixture.project_id,
        ScopeRef::Project {
            project_id: fixture.project_id,
        },
        ComponentKind::McpServer,
        "docs",
        r#"{"url":"https://example.com/mcp","bearer_token_env_var":"DOCS_TOKEN"}"#,
    );
    assert!(
        fixture
            .adapter
            .render(&DesiredState {
                components: vec![project],
                scopes: vec![]
            })
            .is_err()
    );
    let redacted = component(
        fixture.project_id,
        ScopeRef::Global,
        ComponentKind::McpServer,
        "docs",
        r#"{"url":"<redacted>","bearer_token_env_var":"DOCS_TOKEN"}"#,
    );
    assert!(
        fixture
            .adapter
            .render(&DesiredState {
                components: vec![redacted],
                scopes: vec![]
            })
            .is_err()
    );
    let unsupported_headers = component(
        fixture.project_id,
        ScopeRef::Global,
        ComponentKind::McpServer,
        "docs",
        r#"{"url":"https://example.com/mcp","http_headers":{"X-Test":"value"}}"#,
    );
    assert!(
        fixture
            .adapter
            .render(&DesiredState {
                components: vec![unsupported_headers],
                scopes: vec![]
            })
            .is_err()
    );
}

#[test]
fn concurrent_native_edit_invalidates_the_planned_config_mutation() {
    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let desired = DesiredState {
        components: vec![component(
            fixture.project_id,
            ScopeRef::Global,
            ComponentKind::PermissionDeclaration,
            "permissions",
            "\"full\"",
        )],
        scopes: vec![NativeScope::Global],
    };
    let mutation = fixture
        .adapter
        .plan_native_config(&desired, ScopeRef::Global)
        .unwrap();
    fs::write(
        fixture.codex_home.join("config.toml"),
        "concurrent = true\n",
    )
    .unwrap();
    assert!(
        OsNativeTransactionFileSystem::new([4; 16])
            .create_before_images(&[mutation])
            .is_err()
    );
}

#[test]
fn table_valued_permissions_and_inline_hooks_round_trip_as_toml_items() {
    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let path = fixture.codex_home.join("config.toml");
    let existing = fs::read_to_string(&path).unwrap();
    fs::write(
        &path,
        format!(
            "{existing}\n[permissions]\n# permissions comment\nmode = \"strict\"\n\n[permissions.nested]\nkeep = true\n"
        ),
    )
    .unwrap();

    let imported = import_everything(&fixture);
    let permission = imported
        .components
        .iter()
        .find(|component| {
            component.scope == ScopeRef::Global
                && component.kind == ComponentKind::PermissionDeclaration
                && component.name == "permissions"
        })
        .unwrap()
        .clone();
    let inline_hooks = imported
        .components
        .iter()
        .find(|component| {
            component.scope == ScopeRef::Global
                && component.kind == ComponentKind::Hook
                && metadata(component, "structuralLocation") == Some("config.toml#hooks")
        })
        .unwrap()
        .clone();
    assert_eq!(metadata(&permission, "tomlItemKind"), Some("table"));
    assert_eq!(metadata(&inline_hooks, "tomlItemKind"), Some("table"));

    let desired = DesiredState {
        components: vec![permission, inline_hooks],
        scopes: vec![NativeScope::Global],
    };
    let rendered = fixture.adapter.render(&desired).unwrap();
    assert_eq!(rendered.files.len(), 1);
    assert_eq!(rendered.files[0].path.display.as_deref(), path.to_str());
    let mutation = fixture
        .adapter
        .plan_native_config(&desired, ScopeRef::Global)
        .unwrap();
    let NativeState::RegularFile { bytes, .. } = NativeState::decode_v1(&mutation.content).unwrap()
    else {
        panic!("regular file")
    };
    let rendered = String::from_utf8(bytes).unwrap();
    for expected in [
        "# user heading",
        "unknown_user_key",
        "[projects",
        "[plugins",
        "[mcp_servers.docs]",
        "[permissions]",
        "# permissions comment",
        "[permissions.nested]",
        "keep = true",
        "[hooks]",
        "# inline hook comment",
        "[[hooks.PostToolUse]]",
        "[[hooks.PostToolUse.hooks]]",
        "command = \"check-write\"",
    ] {
        assert!(rendered.contains(expected), "missing {expected}");
    }
}

#[test]
fn array_of_tables_managed_items_round_trip_without_scalar_coercion() {
    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let path = fixture.codex_home.join("config.toml");
    let existing = fs::read_to_string(&path).unwrap();
    fs::write(
        &path,
        format!(
            "{existing}\n[[permissions]]\nname = \"first\"\n\n[[permissions]]\nname = \"second\"\n"
        ),
    )
    .unwrap();
    let permission = import_everything(&fixture)
        .components
        .into_iter()
        .find(|component| {
            component.scope == ScopeRef::Global
                && component.kind == ComponentKind::PermissionDeclaration
                && component.name == "permissions"
        })
        .unwrap();
    assert_eq!(
        metadata(&permission, "tomlItemKind"),
        Some("array-of-tables")
    );
    let desired = DesiredState {
        components: vec![permission],
        scopes: vec![NativeScope::Global],
    };
    let mutation = fixture
        .adapter
        .plan_native_config(&desired, ScopeRef::Global)
        .unwrap();
    let NativeState::RegularFile { bytes, .. } = NativeState::decode_v1(&mutation.content).unwrap()
    else {
        panic!("regular file")
    };
    let rendered = String::from_utf8(bytes).unwrap();
    assert_eq!(rendered.matches("[[permissions]]").count(), 2);
    assert!(rendered.contains("name = \"first\""));
    assert!(rendered.contains("name = \"second\""));
}

#[test]
fn nested_project_configs_keep_layer_identity_and_exact_mutation_targets() {
    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let nested_path = fixture
        .layout
        .project_root
        .join("service/.codex/config.toml");
    let nested = fs::read_to_string(&nested_path).unwrap();
    fs::write(
        &nested_path,
        format!("approval_policy = \"on-request\"\n{nested}"),
    )
    .unwrap();

    let imported = import_everything(&fixture);
    let root = imported
        .components
        .iter()
        .find(|component| {
            component.kind == ComponentKind::PermissionDeclaration
                && component.name == "approval_policy"
                && metadata(component, "structuralLocation")
                    == Some("project/.codex/config.toml#approval_policy")
        })
        .unwrap()
        .clone();
    let nested = imported
        .components
        .iter()
        .find(|component| {
            component.kind == ComponentKind::PermissionDeclaration
                && component.name == "approval_policy"
                && metadata(component, "structuralLocation")
                    == Some("project/service/.codex/config.toml#approval_policy")
        })
        .unwrap()
        .clone();
    assert_ne!(root.id, nested.id);

    let scope = ScopeRef::Project {
        project_id: fixture.project_id,
    };
    let desired = DesiredState {
        components: vec![root, nested.clone()],
        scopes: vec![NativeScope::Project {
            project_id: fixture.project_id,
            root: fixture.adapter.project_root_wire(),
        }],
    };
    let mut targets = fixture
        .adapter
        .render(&desired)
        .unwrap()
        .files
        .into_iter()
        .map(|file| file.path.display.unwrap())
        .collect::<Vec<_>>();
    targets.sort();
    let mut expected = vec![
        fixture
            .layout
            .project_root
            .join(".codex/config.toml")
            .to_string_lossy()
            .into_owned(),
        nested_path.to_string_lossy().into_owned(),
    ];
    expected.sort();
    assert_eq!(targets, expected);

    let mutation = fixture
        .adapter
        .plan_native_config_at(
            &desired,
            scope.clone(),
            "project/service/.codex/config.toml#approval_policy",
        )
        .unwrap();
    assert_eq!(mutation.target.display.as_deref(), nested_path.to_str());

    let mut escaped = nested;
    set_metadata(
        &mut escaped,
        "structuralLocation",
        "project/../escape/.codex/config.toml#approval_policy",
    );
    let escaped = DesiredState {
        components: vec![escaped],
        scopes: vec![],
    };
    assert!(fixture.adapter.render(&escaped).is_err());
    assert!(
        fixture
            .adapter
            .plan_native_config_at(
                &escaped,
                scope,
                "project/../escape/.codex/config.toml#approval_policy",
            )
            .is_err()
    );
}

#[test]
fn fallback_instructions_select_the_first_nonempty_name_only_when_standard_files_are_absent() {
    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let config = fixture.codex_home.join("config.toml");
    let existing = fs::read_to_string(&config).unwrap();
    fs::write(
        &config,
        format!("project_doc_fallback_filenames = [\"FIRST.md\", \"SECOND.md\"]\n{existing}"),
    )
    .unwrap();
    fs::write(fixture.layout.project_root.join("FIRST.md"), "").unwrap();
    fs::write(
        fixture.layout.project_root.join("SECOND.md"),
        "# Selected fallback\n",
    )
    .unwrap();
    fs::write(
        fixture.layout.working_directory.join("SECOND.md"),
        "# Shadowed fallback\n",
    )
    .unwrap();
    fs::remove_file(fixture.layout.project_root.join("AGENTS.md")).unwrap();

    let instructions = import_project(&fixture)
        .unwrap()
        .components
        .into_iter()
        .filter(|component| component.kind == ComponentKind::Instruction)
        .collect::<Vec<_>>();
    assert!(instructions.iter().any(|component| {
        component.body_markdown.contains("Selected fallback")
            && metadata(component, "structuralLocation") == Some("project/SECOND.md")
    }));
    assert!(
        !instructions
            .iter()
            .any(|component| { component.body_markdown.contains("Shadowed fallback") })
    );
    assert!(
        instructions
            .iter()
            .any(|component| { component.body_markdown.contains("Service override") })
    );
}

#[test]
fn fallback_instruction_names_apply_to_project_layers_but_not_codex_home() {
    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let config = fixture.codex_home.join("config.toml");
    let existing = fs::read_to_string(&config).unwrap();
    fs::write(
        &config,
        format!("project_doc_fallback_filenames = [\"README.md\"]\n{existing}"),
    )
    .unwrap();
    fs::remove_file(fixture.codex_home.join("AGENTS.override.md")).unwrap();
    fs::remove_file(fixture.codex_home.join("AGENTS.md")).unwrap();
    fs::write(
        fixture.codex_home.join("README.md"),
        "# Must not become global instructions\n",
    )
    .unwrap();
    fs::remove_file(fixture.layout.project_root.join("AGENTS.md")).unwrap();
    fs::write(
        fixture.layout.project_root.join("README.md"),
        "# Repository fallback instructions\n",
    )
    .unwrap();

    let instructions = import_everything(&fixture)
        .components
        .into_iter()
        .filter(|component| component.kind == ComponentKind::Instruction)
        .collect::<Vec<_>>();
    assert!(instructions.iter().any(|component| {
        component
            .body_markdown
            .contains("Repository fallback instructions")
            && metadata(component, "structuralLocation") == Some("project/README.md")
    }));
    assert!(
        !instructions
            .iter()
            .any(|component| component.body_markdown.contains("Must not become global"))
    );
}

#[test]
fn malformed_fallback_names_are_rejected() {
    for setting in [
        r#"project_doc_fallback_filenames = ["bad/name.md"]"#,
        r#"project_doc_fallback_filenames = ["bad\\name.md"]"#,
        r#"project_doc_fallback_filenames = ["."]"#,
        r#"project_doc_fallback_filenames = [".."]"#,
        r#"project_doc_fallback_filenames = ["bad\u0007.md"]"#,
        r#"project_doc_fallback_filenames = [42]"#,
        r#"project_doc_fallback_filenames = "FALLBACK.md""#,
    ] {
        let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
        let config = fixture.codex_home.join("config.toml");
        let existing = fs::read_to_string(&config).unwrap();
        fs::write(&config, format!("{setting}\n{existing}")).unwrap();
        fs::remove_file(fixture.layout.project_root.join("AGENTS.md")).unwrap();
        assert!(
            import_project(&fixture).is_err(),
            "accepted malformed setting {setting}"
        );
    }
}

#[cfg(unix)]
#[test]
fn fallback_instruction_topology_errors_are_propagated() {
    use std::os::unix::fs::symlink;

    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let config = fixture.codex_home.join("config.toml");
    let existing = fs::read_to_string(&config).unwrap();
    fs::write(
        &config,
        format!("project_doc_fallback_filenames = [\"FALLBACK.md\"]\n{existing}"),
    )
    .unwrap();
    fs::remove_file(fixture.layout.project_root.join("AGENTS.md")).unwrap();
    let target = fixture.root.join("fallback-target.md");
    fs::write(&target, "# unsafe fallback\n").unwrap();
    symlink(&target, fixture.layout.project_root.join("FALLBACK.md")).unwrap();
    assert!(import_project(&fixture).is_err());
}

#[cfg(unix)]
#[test]
fn physical_working_directory_must_remain_inside_the_project() {
    use std::os::unix::fs::symlink;

    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let outside = fixture.root.join("outside-working-directory");
    fs::create_dir_all(outside.join(".codex")).unwrap();
    fs::create_dir_all(outside.join(".agents/skills/outside")).unwrap();
    fs::write(outside.join("AGENTS.md"), "# outside instruction\n").unwrap();
    fs::write(
        outside.join(".codex/config.toml"),
        "approval_policy = \"never\"\n",
    )
    .unwrap();
    fs::write(
        outside.join(".agents/skills/outside/SKILL.md"),
        "# outside skill\n",
    )
    .unwrap();
    fs::remove_dir_all(&fixture.layout.working_directory).unwrap();
    symlink(&outside, &fixture.layout.working_directory).unwrap();

    let device_id = DeviceId::from_str(DEVICE_ID).unwrap();
    assert!(
        CodexAdapter::from_layout(
            fixture.layout.clone(),
            fixture.project_id,
            device_id,
            HybridLogicalClock::new(1_900_000_000_000, 0, device_id),
        )
        .is_err()
    );
    assert!(import_project(&fixture).is_err());
}

#[cfg(unix)]
#[test]
fn project_codex_root_symlink_cannot_import_outside_configuration() {
    use std::os::unix::fs::symlink;

    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let project_codex = fixture.layout.project_root.join(".codex");
    let outside = fixture.root.join("outside-codex");
    fs::create_dir_all(outside.join("rules")).unwrap();
    fs::write(outside.join("config.toml"), "approval_policy = \"never\"\n").unwrap();
    fs::write(outside.join("rules/outside.rules"), "outside-rule\n").unwrap();
    fs::remove_dir_all(&project_codex).unwrap();
    symlink(&outside, &project_codex).unwrap();

    assert!(import_project(&fixture).is_err());
}

#[cfg(unix)]
#[test]
fn untrusted_project_agents_root_symlink_cannot_import_outside_skills() {
    use std::os::unix::fs::symlink;

    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let config = fixture.codex_home.join("config.toml");
    fs::write(
        &config,
        fs::read_to_string(&config)
            .unwrap()
            .replace("trust_level = \"trusted\"", "trust_level = \"untrusted\""),
    )
    .unwrap();
    let project_agents = fixture.layout.project_root.join(".agents");
    let outside = fixture.root.join("outside-agents");
    fs::create_dir_all(outside.join("skills/outside")).unwrap();
    fs::write(
        outside.join("skills/outside/SKILL.md"),
        "# outside untrusted skill\n",
    )
    .unwrap();
    fs::remove_dir_all(&project_agents).unwrap();
    symlink(&outside, &project_agents).unwrap();

    assert!(import_project(&fixture).is_err());
}

#[test]
fn skill_discovery_stops_after_one_directory_level() {
    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let nested_user = fixture
        .layout
        .user_skills_dir
        .join("review/descendant/hidden/SKILL.md");
    let nested_project = fixture
        .layout
        .project_root
        .join(".agents/skills/release/descendant/hidden/SKILL.md");
    fs::create_dir_all(nested_user.parent().unwrap()).unwrap();
    fs::create_dir_all(nested_project.parent().unwrap()).unwrap();
    fs::write(&nested_user, "# hidden user skill\n").unwrap();
    fs::write(&nested_project, "# hidden project skill\n").unwrap();

    let imported = import_everything(&fixture);
    assert!(
        imported.components.iter().any(|component| {
            component.kind == ComponentKind::Skill && component.name == "review"
        })
    );
    assert!(imported.components.iter().any(|component| {
        component.kind == ComponentKind::Skill && component.name == "release"
    }));
    assert!(!imported.components.iter().any(|component| {
        component.kind == ComponentKind::Skill
            && (component.name == "hidden" || component.body_markdown.contains("hidden"))
    }));
}

#[test]
fn markdown_components_round_trip_to_exact_global_and_nested_paths() {
    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let nested_rule_path = fixture
        .layout
        .working_directory
        .join(".codex/rules/nested.rules");
    fs::create_dir_all(nested_rule_path.parent().unwrap()).unwrap();
    fs::write(&nested_rule_path, "prefix_rule(pattern=[\"cargo\"])\n").unwrap();

    let imported = import_everything(&fixture);
    let cases = [
        (
            ComponentKind::Rule,
            "rules/default.rules",
            fixture.codex_home.join("rules/default.rules"),
        ),
        (
            ComponentKind::Skill,
            "user skills/review/SKILL.md",
            fixture.layout.user_skills_dir.join("review/SKILL.md"),
        ),
        (
            ComponentKind::Instruction,
            "project/service/AGENTS.override.md",
            fixture.layout.working_directory.join("AGENTS.override.md"),
        ),
        (
            ComponentKind::Rule,
            "project/service/.codex/rules/nested.rules",
            nested_rule_path,
        ),
        (
            ComponentKind::Skill,
            "project/service/.agents/skills/audit/SKILL.md",
            fixture
                .layout
                .working_directory
                .join(".agents/skills/audit/SKILL.md"),
        ),
    ];
    let mut selected = Vec::new();
    for (kind, location, expected) in cases {
        let component = imported
            .components
            .iter()
            .find(|component| {
                component.kind == kind
                    && metadata(component, "structuralLocation") == Some(location)
            })
            .unwrap()
            .clone();
        let mutation = fixture.adapter.plan_native_markdown(&component).unwrap();
        assert_eq!(mutation.target.display.as_deref(), expected.to_str());
        selected.push(component);
    }

    let global_rule_path = fixture.codex_home.join("rules/constructed.rules");
    fs::write(&global_rule_path, "# constructed rule\n").unwrap();
    let global_skill_path = fixture.layout.user_skills_dir.join("constructed/SKILL.md");
    fs::create_dir_all(global_skill_path.parent().unwrap()).unwrap();
    fs::write(&global_skill_path, "# constructed skill\n").unwrap();
    for (component, expected) in [
        (
            component(
                fixture.project_id,
                ScopeRef::Global,
                ComponentKind::Rule,
                "constructed.rules",
                "managed",
            ),
            global_rule_path,
        ),
        (
            component(
                fixture.project_id,
                ScopeRef::Global,
                ComponentKind::Skill,
                "constructed",
                "managed",
            ),
            global_skill_path,
        ),
    ] {
        let mutation = fixture.adapter.plan_native_markdown(&component).unwrap();
        assert_eq!(mutation.target.display.as_deref(), expected.to_str());
    }

    let config = fixture.codex_home.join("config.toml");
    let untrusted = fs::read_to_string(&config)
        .unwrap()
        .replace("trust_level = \"trusted\"", "trust_level = \"untrusted\"");
    fs::write(config, untrusted).unwrap();
    let project_instruction = selected
        .iter()
        .find(|component| component.kind == ComponentKind::Instruction)
        .unwrap();
    let project_rule = selected
        .iter()
        .find(|component| {
            component.kind == ComponentKind::Rule
                && metadata(component, "structuralLocation")
                    == Some("project/service/.codex/rules/nested.rules")
        })
        .unwrap();
    let project_skill = selected
        .iter()
        .find(|component| {
            component.kind == ComponentKind::Skill
                && matches!(component.scope, ScopeRef::Project { .. })
        })
        .unwrap();
    assert!(
        fixture
            .adapter
            .plan_native_markdown(project_instruction)
            .is_ok()
    );
    assert!(fixture.adapter.plan_native_markdown(project_skill).is_ok());
    assert!(fixture.adapter.plan_native_markdown(project_rule).is_err());
}

#[test]
fn unsafe_markdown_structural_locations_are_rejected() {
    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    for (kind, scope, name, location) in [
        (
            ComponentKind::Rule,
            ScopeRef::Global,
            "default.rules",
            "rules/../escape.rules",
        ),
        (
            ComponentKind::Skill,
            ScopeRef::Global,
            "review",
            "user skills/review/nested/SKILL.md",
        ),
        (
            ComponentKind::Instruction,
            ScopeRef::Project {
                project_id: fixture.project_id,
            },
            "AGENTS.md",
            "project/other/AGENTS.md",
        ),
        (
            ComponentKind::Skill,
            ScopeRef::Project {
                project_id: fixture.project_id,
            },
            "audit",
            "project/service/.agents/skills/audit/../escape/SKILL.md",
        ),
    ] {
        let mut component = component(fixture.project_id, scope, kind, name, "managed");
        set_metadata(&mut component, "structuralLocation", location);
        assert!(
            fixture.adapter.plan_native_markdown(&component).is_err(),
            "accepted unsafe location {location}"
        );
    }
}

fn metadata<'a>(component: &'a ComponentRecord, key: &str) -> Option<&'a str> {
    component
        .metadata
        .iter()
        .find_map(|(candidate, value)| (candidate == key).then_some(value.as_str()))
}

fn set_metadata(component: &mut ComponentRecord, key: &str, value: &str) {
    component.metadata.retain(|(candidate, _)| candidate != key);
    component.metadata.push((key.to_owned(), value.to_owned()));
}

fn component(
    _project_id: ProjectId,
    scope: ScopeRef,
    kind: ComponentKind,
    name: &str,
    body: &str,
) -> ComponentRecord {
    let device_id = DeviceId::from_str(DEVICE_ID).unwrap();
    ComponentRecord {
        id: context_relay_protocol::RecordId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073983")
            .unwrap(),
        scope,
        kind,
        name: name.to_owned(),
        body_markdown: body.to_owned(),
        metadata: vec![],
        provenance: Provenance {
            origin_device: device_id,
            harness: Some(HarnessId::Codex),
            source: None,
            created_hlc: HybridLogicalClock::new(1_900_000_000_000, 0, device_id),
        },
        archived: false,
    }
}
