use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
};

use context_relay_core::{
    codex::{CodexAdapter, CodexExecutableKind, CodexLayout},
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
fn toml_mcp_secrets_are_recursively_redacted_before_import() {
    let fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let config = fixture.codex_home.join("config.toml");
    fs::write(&config, format!("{}\n[mcp_servers.secret]\nurl = \"https://example.com\"\napi_token = \"literal-token\"\nauthorization = \"Bearer literal-auth\"\n[mcp_servers.secret.env]\nSECRET_VALUE = \"literal-env\"\n", fs::read_to_string(&config).unwrap())).unwrap();
    let serialized = serde_json::to_string(&import_everything(&fixture)).unwrap();
    for secret in ["literal-token", "literal-auth", "literal-env"] {
        assert!(!serialized.contains(secret));
    }
    assert!(serialized.contains("<redacted>"));
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
    let wrapper = bin.join("codex");
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
fn unknown_versions_and_wrapper_executables_are_import_only() {
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
    let wrapped = CodexAdapter::from_layout(
        CodexLayout {
            executable_kind: CodexExecutableKind::Wrapper,
            ..fixture.layout.clone()
        },
        fixture.project_id,
        DeviceId::from_str(DEVICE_ID).unwrap(),
        HybridLogicalClock::new(1_900_000_000_000, 0, DeviceId::from_str(DEVICE_ID).unwrap()),
    )
    .unwrap();
    assert_eq!(
        wrapped
            .probe(&ProbeContext {
                harness: HarnessId::Codex,
                requested_profile: None
            })
            .unwrap()
            .capability,
        CapabilityLevel::ImportOnly
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
            ]
        ]
    );
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
