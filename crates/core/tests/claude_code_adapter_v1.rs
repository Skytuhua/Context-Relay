use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
};

use context_relay_core::{
    claude_code::{ClaudeCodeAdapter, ClaudeCodeLayout},
    native_transaction::{engine::NativeFileSystem, filesystem::OsNativeTransactionFileSystem},
};
use context_relay_native_runner::NativeState;
use context_relay_protocol::{
    CapabilityLevel, ComponentKind, ComponentRecord, DesiredState, DeviceId, HarnessAdapter,
    HarnessId, HybridLogicalClock, ImportRequest, InstallationMethod, NativeScope, ProbeContext,
    ProjectId, Provenance, ScopeRef,
};
use serde_json::{Map, Value, json};

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
    let root = std::env::temp_dir().join(format!(
        "context-relay-claude-code-{}-{}",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    let config_dir = root.join("custom claude config");
    let project_root = root.join("project with spaces");
    materialize(&config_dir, fixture["config"].as_object().unwrap());
    materialize(&project_root, fixture["project"].as_object().unwrap());

    let state_path = root.join(".claude.json");
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
    fs::write(&executable, b"fixture executable").unwrap();

    let project_id = ProjectId::from_str(PROJECT_ID).unwrap();
    let device_id = DeviceId::from_str(DEVICE_ID).unwrap();
    let adapter = ClaudeCodeAdapter::from_layout(
        ClaudeCodeLayout {
            executable,
            version: fixture["version"].as_str().unwrap().to_owned(),
            installation_method: InstallationMethod::PackageManager,
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
