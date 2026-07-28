use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
};

use context_relay_core::{
    codex::{CodexAdapter, CodexExecutableKind, CodexLayout},
    native_transaction::{
        approval_hash_v1,
        engine::{NativeAdapter, NativeFileSystem, RestrictedRun},
        filesystem::OsNativeTransactionFileSystem,
        model::{NativeTransactionPlan, SidecarBinding},
    },
};
use context_relay_native_runner::{
    NativeState, RuleSyncFeature, RuleSyncFeatures, RuleSyncTarget, RuntimeTarget, SidecarCommand,
    SidecarId,
};
use context_relay_protocol::{
    ApplyReceipt, ApprovalClass, CapabilityLevel, ComponentKind, ComponentRecord, DesiredState,
    DeviceId, ExpectedNativeDigest, HarnessAdapter, HarnessId, HybridLogicalClock, ImportRequest,
    InstallationMethod, NativePlatform, NativeScope, NetworkDelta, PermissionDelta, PlanId,
    ProbeContext, ProjectId, Provenance, ScopeRef, SetupPlan, Sha256Digest, WireNativeValue,
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
    assert!(
        wrapped
            .render(&DesiredState {
                components: vec![],
                scopes: vec![],
            })
            .is_err()
    );
    assert!(
        wrapped
            .plan_native_markdown(&component(
                fixture.project_id,
                ScopeRef::Global,
                ComponentKind::Instruction,
                "AGENTS.override.md",
                "managed",
            ))
            .is_err()
    );
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

    let mut import_only = CodexAdapter::from_layout(
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
        NativeAdapter::reprobe_live_state(&mut import_only, &plan)
            .unwrap_err()
            .to_string(),
        "Codex installation changed"
    );
}

#[test]
fn native_digest_comparison_rejects_concurrent_mutation_and_absence() {
    let mut fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let target = fixture.root.join("approved-native-target");
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

#[cfg(unix)]
#[test]
fn effective_validation_uses_enabled_global_and_trusted_layered_mcp_servers_only() {
    use std::os::unix::fs::PermissionsExt as _;

    let mut fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let sentinel = fixture.root.join("configured-server-ran");
    let root_config = fixture.layout.project_root.join(".codex/config.toml");
    fs::write(
        &root_config,
        format!(
            "{}\n[mcp_servers.root]\ncommand = \"/usr/bin/touch\"\nargs = [\"{}\"]\n\n[mcp_servers.root_disabled]\nenabled = false\ncommand = \"/usr/bin/touch\"\nargs = [\"{}\"]\n",
            fs::read_to_string(&root_config).unwrap(),
            sentinel.display(),
            sentinel.display()
        ),
    )
    .unwrap();
    let nested_config = fixture
        .layout
        .project_root
        .join("service/.codex/config.toml");
    fs::write(
        &nested_config,
        format!(
            "{}\n[mcp_servers.nested]\ncommand = \"/usr/bin/touch\"\nargs = [\"{}\"]\n\n[mcp_servers.nested_disabled]\nenabled = false\ncommand = \"/usr/bin/touch\"\nargs = [\"{}\"]\n",
            fs::read_to_string(&nested_config).unwrap(),
            sentinel.display(),
            sentinel.display()
        ),
    )
    .unwrap();
    let global_config = fixture.codex_home.join("config.toml");
    fs::write(
        &global_config,
        format!(
            "{}\n[mcp_servers.global_disabled]\nenabled = false\ncommand = \"/usr/bin/touch\"\nargs = [\"{}\"]\n",
            fs::read_to_string(&global_config).unwrap(),
            sentinel.display()
        ),
    )
    .unwrap();

    let script = r#"#!/bin/sh
printf '%s\n' "$*" >> ../../codex-argv.log
case "$1 $2" in
  "plugin list")
    printf '%s' '{"installed":[],"available":[]}'
    ;;
  "mcp list")
    cat ../../mcp-list.json
    ;;
  "mcp get")
    printf '{"name":"%s","enabled":true,"disabled_reason":null,"transport":{"type":"stdio","command":"never-run","args":[],"env":{},"env_vars":[],"cwd":null},"enabled_tools":null,"disabled_tools":null,"startup_timeout_sec":null,"tool_timeout_sec":null}' "$3"
    ;;
  *)
    exit 9
    ;;
esac
"#;
    fs::write(&fixture.layout.executable, script).unwrap();
    let mut permissions = fs::metadata(&fixture.layout.executable)
        .unwrap()
        .permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&fixture.layout.executable, permissions).unwrap();
    fixture.adapter = CodexAdapter::from_layout(
        fixture.layout.clone(),
        fixture.project_id,
        DeviceId::from_str(DEVICE_ID).unwrap(),
        HybridLogicalClock::new(1_900_000_000_000, 0, DeviceId::from_str(DEVICE_ID).unwrap()),
    )
    .unwrap();
    let list_path = fixture.root.join("mcp-list.json");
    let write_list = |enabled: &[&str]| {
        let mut servers = enabled
            .iter()
            .map(|name| {
                json!({
                    "name": name,
                    "enabled": true,
                    "disabled_reason": null,
                    "transport": {
                        "type": "stdio",
                        "command": "never-run",
                        "args": [],
                        "env": {},
                        "env_vars": [],
                        "cwd": null
                    },
                    "startup_timeout_sec": null,
                    "tool_timeout_sec": null,
                    "auth_status": "unsupported"
                })
            })
            .collect::<Vec<_>>();
        servers.push(json!({
            "name": "listed-disabled",
            "enabled": false,
            "disabled_reason": "disabled by config",
            "transport": {
                "type": "stdio",
                "command": "never-run",
                "args": [],
                "env": {},
                "env_vars": [],
                "cwd": null
            },
            "startup_timeout_sec": null,
            "tool_timeout_sec": null,
            "auth_status": "unsupported"
        }));
        fs::write(&list_path, serde_json::to_vec(&servers).unwrap()).unwrap();
    };
    let receipt = ApplyReceipt {
        plan_id: PlanId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073984").unwrap(),
        applied_hlc: HybridLogicalClock::new(
            1_900_000_000_001,
            0,
            DeviceId::from_str(DEVICE_ID).unwrap(),
        ),
        resulting_digests: vec![],
    };

    write_list(&["docs", "nested", "root"]);
    let trusted = fixture.adapter.validate_effective(&receipt).unwrap();
    assert!(trusted.valid);
    assert_eq!(
        fs::read_to_string(fixture.root.join("codex-argv.log")).unwrap(),
        "plugin list --json\nmcp list --json\nmcp get docs --json\nmcp get nested --json\nmcp get root --json\n"
    );

    fs::remove_file(fixture.root.join("codex-argv.log")).unwrap();
    fs::write(
        &global_config,
        fs::read_to_string(&global_config)
            .unwrap()
            .replace("trust_level = \"trusted\"", "trust_level = \"untrusted\""),
    )
    .unwrap();
    let untrusted = fixture.adapter.validate_effective(&receipt).unwrap();
    assert!(untrusted.valid);
    assert_eq!(
        fs::read_to_string(fixture.root.join("codex-argv.log")).unwrap(),
        "plugin list --json\nmcp list --json\nmcp get docs --json\n"
    );

    fs::write(
        &global_config,
        fs::read_to_string(&global_config)
            .unwrap()
            .replace("trust_level = \"untrusted\"", "trust_level = \"trusted\""),
    )
    .unwrap();
    write_list(&["docs", "root"]);
    let missing = fixture.adapter.validate_effective(&receipt).unwrap();
    assert!(!missing.valid);
    assert_eq!(missing.findings, vec!["configured_mcp_server_missing"]);
    assert!(!sentinel.exists());

    fs::write(
        &global_config,
        format!(
            "mcp_servers = \"not-a-table\"\n\n[projects.\"{}\"]\ntrust_level = \"trusted\"\n",
            fixture.layout.project_root.display()
        ),
    )
    .unwrap();
    assert!(fixture.adapter.validate_effective(&receipt).is_err());
}

#[cfg(unix)]
#[test]
fn effective_validation_honors_same_name_mcp_shadowing_across_layers() {
    use std::os::unix::fs::PermissionsExt as _;

    let mut fixture = fixture(include_str!("fixtures/codex-0.144.1.json"));
    let global_config = fixture.codex_home.join("config.toml");
    fs::write(
        &global_config,
        format!(
            "{}\n[mcp_servers.shadowed]\ncommand = \"global-shadowed\"\n\n[mcp_servers.reenabled]\nenabled = false\ncommand = \"global-disabled\"\n",
            fs::read_to_string(&global_config).unwrap()
        ),
    )
    .unwrap();
    let root_config = fixture.layout.project_root.join(".codex/config.toml");
    fs::write(
        &root_config,
        format!(
            "{}\n[mcp_servers.shadowed]\nenabled = true\ncommand = \"root-shadowed\"\n",
            fs::read_to_string(&root_config).unwrap()
        ),
    )
    .unwrap();
    let nested_config = fixture
        .layout
        .project_root
        .join("service/.codex/config.toml");
    fs::write(
        &nested_config,
        format!(
            "{}\n[mcp_servers.shadowed]\nenabled = false\ncommand = \"nested-disabled\"\n\n[mcp_servers.reenabled]\nenabled = true\ncommand = \"nested-reenabled\"\n",
            fs::read_to_string(&nested_config).unwrap()
        ),
    )
    .unwrap();

    let script = r#"#!/bin/sh
printf '%s\n' "$*" >> ../../codex-argv.log
case "$1 $2" in
  "plugin list")
    printf '%s' '{"installed":[],"available":[]}'
    ;;
  "mcp list")
    printf '%s' '[{"name":"docs","enabled":true,"disabled_reason":null,"transport":{"type":"stdio","command":"never-run","args":[],"env":{},"env_vars":[],"cwd":null},"startup_timeout_sec":null,"tool_timeout_sec":null,"auth_status":"unsupported"},{"name":"reenabled","enabled":true,"disabled_reason":null,"transport":{"type":"stdio","command":"never-run","args":[],"env":{},"env_vars":[],"cwd":null},"startup_timeout_sec":null,"tool_timeout_sec":null,"auth_status":"unsupported"}]'
    ;;
  "mcp get")
    [ "$3" != "shadowed" ] || exit 8
    printf '{"name":"%s","enabled":true,"disabled_reason":null,"transport":{"type":"stdio","command":"never-run","args":[],"env":{},"env_vars":[],"cwd":null},"enabled_tools":null,"disabled_tools":null,"startup_timeout_sec":null,"tool_timeout_sec":null}' "$3"
    ;;
  *)
    exit 9
    ;;
esac
"#;
    fs::write(&fixture.layout.executable, script).unwrap();
    let mut permissions = fs::metadata(&fixture.layout.executable)
        .unwrap()
        .permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&fixture.layout.executable, permissions).unwrap();
    fixture.adapter = CodexAdapter::from_layout(
        fixture.layout.clone(),
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
    let report = fixture.adapter.validate_effective(&receipt).unwrap();

    assert!(report.valid);
    assert_eq!(
        fs::read_to_string(fixture.root.join("codex-argv.log")).unwrap(),
        "plugin list --json\nmcp list --json\nmcp get docs --json\nmcp get reenabled --json\n"
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
