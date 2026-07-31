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
    ExpectedNativeDigest, HarnessAdapter, HarnessId, HybridLogicalClock, ImportRequest,
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
fn bridge_cli_plan_rejects_malformed_redacted_secret_bearing_and_unmanaged_prior_state() {
    let fixture = fixture(include_str!("fixtures/claude-code-2.1.214.json"));
    let bridge_path = executable_bridge(&fixture, "intended bridge", b"bridge");
    let intended = bridge(&fixture, &bridge_path);
    let invalid_get_outputs = [
        b"not-json".to_vec(),
        serde_json::to_vec(&json!({
            "name": "context-relay",
            "scope": "user",
            "type": "stdio",
            "command": "<redacted>",
            "args": ["--harness", "claude-code"],
        }))
        .unwrap(),
        serde_json::to_vec(&json!({
            "name": "context-relay",
            "scope": "user",
            "type": "stdio",
            "command": "/old/bridge",
            "args": ["--harness", "claude-code"],
            "env": {"TOKEN": "secret"},
        }))
        .unwrap(),
        serde_json::to_vec(&json!({
            "name": "context-relay",
            "scope": "user",
            "type": "http",
            "command": "/old/bridge",
            "args": ["--harness", "claude-code"],
        }))
        .unwrap(),
    ];

    for get_output in invalid_get_outputs {
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
    let outcome = {
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
        executor.apply_cli_mutation(&mutation).unwrap()
    };

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
