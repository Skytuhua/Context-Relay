use std::{
    cell::Cell,
    fs,
    path::{Path, PathBuf},
    rc::Rc,
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
};

use context_relay_core::{
    claude_code::{
        ClaudeCodeAdapter, ClaudeCodeCommandRunner, ClaudeCodeLayout, VerifiedClaudeCommand,
    },
    mcp::install::bridge_component,
    native_memory::{
        NativeMemoryAdapter, NativeMemoryDisable, NativeMemoryDocumentKind,
        PRIMARY_MEMORY_INSTRUCTIONS, primary_memory_instruction_component,
    },
    native_transaction::{
        NativeTransactionPlan,
        cli::NativeCliExecutor,
        engine::{BoundaryError, NativeAdapter, NativeFileSystem},
        filesystem::OsNativeTransactionFileSystem,
    },
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
- Keep the shared task ledger current with `context_relay_list_tasks`, `context_relay_upsert_task`, and `context_relay_complete_task`.\n";

    assert_eq!(PRIMARY_MEMORY_INSTRUCTIONS, expected);
    assert!(components.iter().all(|component| {
        component.kind == ComponentKind::Instruction
            && component.scope == ScopeRef::Project { project_id }
            && component.body_markdown.as_bytes() == expected.as_bytes()
    }));
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
        assert_eq!(rendered["autoMemoryDirectory"], ".claude/native-memory");
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
        NativeMemoryDisable::WatchOnly
    ));
    assert!(!capabilities.sources.is_empty());
}

#[test]
fn frozen_claude_default_binding_is_exact_and_invalid_explicit_paths_are_unavailable() {
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
    assert!(matches!(
        capabilities.disable,
        NativeMemoryDisable::Unavailable
    ));
    assert!(capabilities.sources.is_empty());
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
    settings["autoMemoryDirectory"] = json!(memory_root.to_string_lossy());
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
fn native_memory_claude_absent_project_settings_watches_the_frozen_default_without_writing() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    fs::remove_file(fixture.adapter.project_settings_path()).unwrap();
    let project_root = fixture.root.join("project with spaces");
    let project_key = project_root
        .to_string_lossy()
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
    assert!(!fixture.adapter.project_settings_path().exists());
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
            "autoMemoryDirectory": managed_root.to_string_lossy(),
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

    fs::write(
        fixture.root.join("managed-settings.json"),
        br#"{"autoMemoryEnabled":true,"autoMemoryDirectory":"../sibling-project/memory"}"#,
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
        PRIMARY_MEMORY_INSTRUCTIONS.replace('\n', "\r\n")
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

fn validation_output(argv: &[String], declaration: Option<&str>) -> Result<Vec<u8>, BoundaryError> {
    match argv {
        [mcp, list] if mcp == "mcp" && list == "list" => Ok(declaration
            .map(|_| b"context-relay: local (stdio)\n".to_vec())
            .unwrap_or_default()),
        [mcp, get, name] if mcp == "mcp" && get == "get" && name == "context-relay" => {
            let body: Value = serde_json::from_str(
                declaration.ok_or_else(|| BoundaryError::new("missing declaration"))?,
            )
            .unwrap();
            Ok(serde_json::to_vec(&json!({
                "name": "context-relay",
                "scope": "user",
                "type": body["type"],
                "command": body["command"],
                "args": body["args"],
            }))
            .unwrap())
        }
        _ => Err(BoundaryError::new("unexpected validation argv")),
    }
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
        ownership_changes: vec![],
    }
}

#[test]
fn bridge_cli_plan_binds_exact_declarations_fingerprints_and_user_scope_argv() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let bridge_path = executable_bridge(&fixture, "context relay bridge", b"bridge v1");
    let intended = bridge(&fixture, &bridge_path);
    let mut validation_argv = Vec::new();

    let mutation = fixture
        .adapter
        .plan_bridge_cli_mutation_with_runner(&intended, |argv: &[String]| {
            validation_argv.push(argv.to_vec());
            validation_output(argv, None)
        })
        .unwrap();

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
    assert_eq!(validation_argv, vec![vec!["mcp", "list"]]);
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
    let mut validation_argv = Vec::new();

    let mutation = fixture
        .adapter
        .plan_bridge_cli_mutation_with_runner(&intended, |argv: &[String]| {
            validation_argv.push(argv.to_vec());
            validation_output(argv, Some(&prior))
        })
        .unwrap();

    let expected = mutation.expected.unwrap();
    assert_eq!(expected.canonical_body, prior);
    assert_eq!(
        expected.fingerprint,
        Sha256Digest(Sha256::digest(expected.canonical_body.as_bytes()).into())
    );
    assert_eq!(
        validation_argv,
        vec![vec!["mcp", "list"], vec!["mcp", "get", "context-relay"]]
    );
    assert_eq!(
        displays(&mutation.rollback[0]),
        vec![
            "mcp",
            "add-json",
            "context-relay",
            expected.canonical_body.as_str(),
            "--scope",
            "user",
        ]
    );
}

#[test]
fn bridge_cli_plan_reports_disabled_and_unmanaged_prior_declarations_as_conflicts() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let old_path = executable_bridge(&fixture, "old bridge", b"old bridge");
    let intended_path = executable_bridge(&fixture, "intended bridge", b"intended bridge");
    let old: Value = serde_json::from_str(&bridge(&fixture, &old_path).body_markdown).unwrap();
    let intended = bridge(&fixture, &intended_path);
    let rejected = [
        json!({
            "name": "context-relay",
            "scope": "user",
            "type": "stdio",
            "command": old["command"],
            "args": ["--harness", "codex"],
        }),
        json!({
            "name": "context-relay",
            "scope": "user",
            "type": "stdio",
            "command": old["command"],
            "args": ["--harness", "claude-code"],
            "enabled": false,
        }),
    ];

    for prior in rejected {
        let error = fixture
            .adapter
            .plan_bridge_cli_mutation_with_runner(&intended, |argv: &[String]| match argv {
                [mcp, list] if (mcp.as_str(), list.as_str()) == ("mcp", "list") => {
                    Ok(b"context-relay: local (stdio)\n".to_vec())
                }
                [mcp, get, name]
                    if (mcp.as_str(), get.as_str(), name.as_str())
                        == ("mcp", "get", "context-relay") =>
                {
                    Ok(serde_json::to_vec(&prior).unwrap())
                }
                _ => panic!("unexpected validation argv: {argv:?}"),
            })
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::Conflict);
    }
}

#[test]
fn bridge_cli_plan_rejects_malformed_redacted_secret_bearing_and_unmanaged_prior_state() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let bridge_path = executable_bridge(&fixture, "intended bridge", b"bridge");
    let intended = bridge(&fixture, &bridge_path);
    let invalid_get_outputs = [
        (b"not-json".to_vec(), ErrorCode::InvalidRequest),
        (
            serde_json::to_vec(&json!({
                "name": "context-relay",
                "scope": "user",
                "type": "stdio",
                "command": "<redacted>",
                "args": ["--harness", "claude-code"],
            }))
            .unwrap(),
            ErrorCode::InvalidRequest,
        ),
        (
            serde_json::to_vec(&json!({
                "name": "context-relay",
                "scope": "user",
                "type": "stdio",
                "command": "/old/bridge",
                "args": ["--harness", "claude-code"],
                "env": {"TOKEN": "secret"},
            }))
            .unwrap(),
            ErrorCode::Conflict,
        ),
        (
            serde_json::to_vec(&json!({
                "name": "context-relay",
                "scope": "user",
                "type": "http",
                "command": "/old/bridge",
                "args": ["--harness", "claude-code"],
            }))
            .unwrap(),
            ErrorCode::Conflict,
        ),
    ];

    for (get_output, expected_code) in invalid_get_outputs {
        let mut calls = 0;
        let error = fixture
            .adapter
            .plan_bridge_cli_mutation_with_runner(&intended, |argv: &[String]| {
                calls += 1;
                match argv {
                    [mcp, list] if mcp == "mcp" && list == "list" => {
                        Ok(b"context-relay: local (stdio)\n".to_vec())
                    }
                    [mcp, get, name] if mcp == "mcp" && get == "get" && name == "context-relay" => {
                        Ok(get_output.clone())
                    }
                    _ => Err(BoundaryError::new("unexpected validation argv")),
                }
            })
            .unwrap_err();

        assert_eq!(calls, 2);
        assert_eq!(error.code, expected_code);
        assert!(!error.retryable);
    }
}

#[test]
fn cli_executor_runs_only_exact_approved_argv_and_read_only_validation() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let bridge_path = executable_bridge(&fixture, "configured bridge", b"bridge");
    let intended = bridge(&fixture, &bridge_path);
    let mut planning_runner = |argv: &[String]| validation_output(argv, None);
    let mutation = fixture
        .adapter
        .plan_bridge_cli_mutation_with_runner(&intended, &mut planning_runner)
        .unwrap();
    let mut operation_argv = Vec::new();
    let mut validation_argv = Vec::new();
    let body = intended.body_markdown.clone();
    let applied = Rc::new(Cell::new(false));
    let operation_applied = Rc::clone(&applied);
    let validation_applied = Rc::clone(&applied);
    let (probed, outcome) = {
        let mut executor = fixture.adapter.cli_executor_with_runners(
            |argv: &[String]| {
                operation_argv.push(argv.to_vec());
                operation_applied.set(true);
                Ok::<Vec<u8>, BoundaryError>(Vec::new())
            },
            |argv: &[String]| {
                validation_argv.push(argv.to_vec());
                validation_output(argv, validation_applied.get().then_some(body.as_str()))
            },
        );
        let probed = executor.probe_cli_mutation(&mutation).unwrap();
        let outcome = executor.apply_cli_mutation(&mutation).unwrap();
        (probed, outcome)
    };

    assert_eq!(probed, None);
    assert_eq!(outcome.command_error, None);
    assert_eq!(
        outcome.resulting_fingerprint,
        mutation.intended.as_ref().map(|value| value.fingerprint)
    );
    assert_eq!(
        operation_argv,
        vec![vec![
            "mcp",
            "add-json",
            "context-relay",
            intended.body_markdown.as_str(),
            "--scope",
            "user",
        ]]
    );
    assert!(
        validation_argv
            .iter()
            .all(|argv| { argv == &["mcp", "list"] || argv == &["mcp", "get", "context-relay"] })
    );
    assert!(operation_argv.iter().chain(&validation_argv).all(|argv| {
        argv.first()
            .is_some_and(|program| program != bridge_path.to_str().unwrap())
    }));
}

#[test]
fn cli_executor_restores_only_while_live_declaration_equals_intended() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let bridge_path = executable_bridge(&fixture, "configured bridge", b"bridge");
    let divergent_path = executable_bridge(&fixture, "divergent bridge", b"divergent");
    let intended = bridge(&fixture, &bridge_path);
    let divergent = bridge(&fixture, &divergent_path).body_markdown;
    let mut planning_runner = |argv: &[String]| validation_output(argv, None);
    let mutation = fixture
        .adapter
        .plan_bridge_cli_mutation_with_runner(&intended, &mut planning_runner)
        .unwrap();
    let mut operation_calls = 0;
    let outcome = {
        let mut executor = fixture.adapter.cli_executor_with_runners(
            |_: &[String]| {
                operation_calls += 1;
                Ok::<Vec<u8>, BoundaryError>(Vec::new())
            },
            |argv: &[String]| validation_output(argv, Some(&divergent)),
        );
        executor.restore_cli_mutation_if_matches(&mutation).unwrap()
    };

    assert!(!outcome.restored);
    assert_eq!(operation_calls, 0);
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
    let mut planning_runner = |argv: &[String]| validation_output(argv, None);
    let mutation = fixture
        .adapter
        .plan_bridge_cli_mutation_with_runner(&intended, &mut planning_runner)
        .unwrap();
    let present = Rc::new(Cell::new(true));
    let operation_present = Rc::clone(&present);
    let validation_present = Rc::clone(&present);
    let rollback_argv = Rc::new(std::cell::RefCell::new(Vec::new()));
    let recorded_argv = Rc::clone(&rollback_argv);
    let body = intended.body_markdown.clone();
    let mut executor = fixture.adapter.cli_executor_with_runners(
        |argv: &[String]| {
            recorded_argv.borrow_mut().push(argv.to_vec());
            operation_present.set(false);
            Ok::<Vec<u8>, BoundaryError>(Vec::new())
        },
        |argv: &[String]| {
            validation_output(argv, validation_present.get().then_some(body.as_str()))
        },
    );

    let outcome = executor.restore_cli_mutation_if_matches(&mutation).unwrap();

    assert!(outcome.restored);
    assert_eq!(outcome.resulting_fingerprint, None);
    assert_eq!(
        rollback_argv.borrow().as_slice(),
        &[vec!["mcp", "remove", "context-relay", "--scope", "user"]]
    );
}

#[test]
fn cli_executor_rechecks_non_link_harness_executable_before_any_runner() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let bridge_path = executable_bridge(&fixture, "configured bridge", b"bridge");
    let intended = bridge(&fixture, &bridge_path);
    let mut planning_runner = |argv: &[String]| validation_output(argv, None);
    let mutation = fixture
        .adapter
        .plan_bridge_cli_mutation_with_runner(&intended, &mut planning_runner)
        .unwrap();
    fs::write(
        fixture.root.join("replacement claude"),
        b"replacement executable",
    )
    .unwrap();
    fs::remove_file(fixture.root.join("claude")).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        fixture.root.join("replacement claude"),
        fixture.root.join("claude"),
    )
    .unwrap();
    #[cfg(windows)]
    fs::write(fixture.root.join("claude"), b"changed executable").unwrap();
    let runner_calls = Rc::new(Cell::new(0));
    let operation_calls = Rc::clone(&runner_calls);
    let validation_calls = Rc::clone(&runner_calls);
    let comparison = {
        let mut executor = fixture.adapter.cli_executor_with_runners(
            |_: &[String]| {
                operation_calls.set(operation_calls.get() + 1);
                Ok::<Vec<u8>, BoundaryError>(Vec::new())
            },
            |_: &[String]| {
                validation_calls.set(validation_calls.get() + 1);
                Ok::<Vec<u8>, BoundaryError>(Vec::new())
            },
        );
        executor.compare_cli_targets(std::slice::from_ref(&mutation))
    };
    assert!(comparison.is_err());
    assert_eq!(runner_calls.get(), 0);
}

#[test]
fn cli_executor_rechecks_harness_executable_digest_before_any_runner() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let bridge_path = executable_bridge(&fixture, "configured bridge", b"bridge");
    let intended = bridge(&fixture, &bridge_path);
    let mut planning_runner = |argv: &[String]| validation_output(argv, None);
    let mutation = fixture
        .adapter
        .plan_bridge_cli_mutation_with_runner(&intended, &mut planning_runner)
        .unwrap();
    fs::write(fixture.root.join("claude"), b"changed executable").unwrap();
    let runner_calls = Rc::new(Cell::new(0));
    let operation_calls = Rc::clone(&runner_calls);
    let validation_calls = Rc::clone(&runner_calls);
    let comparison = {
        let mut executor = fixture.adapter.cli_executor_with_runners(
            |_: &[String]| {
                operation_calls.set(operation_calls.get() + 1);
                Ok::<Vec<u8>, BoundaryError>(Vec::new())
            },
            |_: &[String]| {
                validation_calls.set(validation_calls.get() + 1);
                Ok::<Vec<u8>, BoundaryError>(Vec::new())
            },
        );
        executor.compare_cli_targets(std::slice::from_ref(&mutation))
    };
    assert!(comparison.is_err());
    assert_eq!(runner_calls.get(), 0);
}

#[cfg(unix)]
#[test]
fn verified_runner_rejects_path_substitution_before_execution() {
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };

    struct SubstitutingRunner {
        executable: PathBuf,
        original: PathBuf,
        replacement: PathBuf,
        executions: Arc<AtomicU64>,
    }

    impl ClaudeCodeCommandRunner for SubstitutingRunner {
        fn before_launch(&mut self, _: &[String]) -> Result<(), BoundaryError> {
            fs::rename(&self.executable, &self.original)
                .map_err(|_| BoundaryError::new("fixture rename failed"))?;
            fs::rename(&self.replacement, &self.executable)
                .map_err(|_| BoundaryError::new("fixture substitution failed"))
        }

        fn run(&mut self, _: VerifiedClaudeCommand<'_>) -> Result<Vec<u8>, BoundaryError> {
            self.executions.fetch_add(1, Ordering::Relaxed);
            Ok(Vec::new())
        }
    }

    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let bridge_path = executable_bridge(&fixture, "configured bridge", b"bridge");
    let intended = bridge(&fixture, &bridge_path);
    let executable = fixture.root.join("claude");
    let replacement = fixture.root.join("replacement claude");
    fs::write(&replacement, fs::read(&executable).unwrap()).unwrap();
    let executions = Arc::new(AtomicU64::new(0));
    let runner = SubstitutingRunner {
        executable: executable.clone(),
        original: fixture.root.join("original claude"),
        replacement,
        executions: Arc::clone(&executions),
    };

    assert!(
        fixture
            .adapter
            .plan_bridge_cli_mutation_with_runner(&intended, runner)
            .is_err()
    );
    assert_eq!(
        executions.load(Ordering::Relaxed),
        0,
        "substituted executable reached the runner launch boundary"
    );
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
