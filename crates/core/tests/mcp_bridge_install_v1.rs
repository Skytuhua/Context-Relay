use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
};

use context_relay_core::{
    claude_code::{ClaudeCodeAdapter, ClaudeCodeLayout},
    codex::{CodexAdapter, CodexExecutableKind, CodexLayout},
    hermes::{HermesAdapter, HermesExecutableKind, HermesLayout, HermesProfile},
    mcp::install::{
        BRIDGE_SERVER_NAME, bridge_component, harness_cli_name, is_managed_bridge_component,
    },
    native_transaction::{engine::NativeFileSystem, filesystem::OsNativeTransactionFileSystem},
};
use context_relay_native_runner::NativeState;
use context_relay_protocol::{
    ComponentKind, DesiredState, DeviceId, HarnessAdapter, HarnessId, HybridLogicalClock,
    InstallationMethod, NativeScope, ProjectId, ScopeRef,
};
use serde_json::{Value, json};

const DEVICE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073982";

fn clock() -> HybridLogicalClock {
    let device = DeviceId::from_str(DEVICE_ID).unwrap();
    HybridLogicalClock::new(1_900_000_000_000, 0, device)
}

fn write_executable(path: &Path) {
    fs::write(path, b"attested bridge fixture").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
}

fn argv(rendered: &context_relay_protocol::RenderedState) -> Vec<Vec<String>> {
    rendered
        .cli_operations
        .iter()
        .map(|operation| {
            operation
                .arguments
                .iter()
                .map(|argument| argument.display.clone().unwrap())
                .collect()
        })
        .collect()
}

fn desired(component: context_relay_protocol::ComponentRecord) -> DesiredState {
    DesiredState {
        components: vec![component],
        scopes: vec![NativeScope::Global],
    }
}

struct AdapterFixture {
    _root: tempfile::TempDir,
    bridge: PathBuf,
    claude: ClaudeCodeAdapter,
    codex: CodexAdapter,
    hermes: HermesAdapter,
    hermes_config: PathBuf,
}

fn adapter_fixture() -> AdapterFixture {
    let root = tempfile::tempdir().unwrap();
    let bridge = root.path().join("context-relay-context-mcp");
    write_executable(&bridge);
    let project_root = root.path().join("project");
    let working_directory = project_root.join("service");
    fs::create_dir_all(&working_directory).unwrap();
    let device = DeviceId::from_str(DEVICE_ID).unwrap();
    let project = ProjectId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073981").unwrap();

    let claude_config = root.path().join("claude");
    fs::create_dir_all(&claude_config).unwrap();
    let claude_state = claude_config.join(".claude.json");
    fs::write(&claude_state, b"{}").unwrap();
    let claude_executable = root
        .path()
        .join(format!("claude-bin{}", std::env::consts::EXE_SUFFIX));
    // `VerifiedClaudeExecutable::open` verifies the executable is a native
    // PE image on Windows, so the fixture carries a minimal MZ header with
    // a PE\0\0 signature there; other platforms accept placeholder bytes.
    let mut claude_bytes = vec![0_u8; 0x44];
    if cfg!(windows) {
        claude_bytes[0] = b'M';
        claude_bytes[1] = b'Z';
        let pe_offset: u32 = 0x40;
        claude_bytes[0x3c..0x40].copy_from_slice(&pe_offset.to_le_bytes());
        claude_bytes[0x40..0x44].copy_from_slice(b"PE\0\0");
    }
    fs::write(&claude_executable, &claude_bytes).unwrap();
    let claude = ClaudeCodeAdapter::from_layout(
        ClaudeCodeLayout {
            user_home: root.path().to_path_buf(),
            executable: claude_executable,
            version: "2.1.214".to_owned(),
            installation_method: InstallationMethod::Manual,
            config_dir: claude_config,
            state_path: claude_state,
            project_root: project_root.clone(),
            managed_settings_paths: vec![],
        },
        project,
        device,
        clock(),
    )
    .unwrap();

    let codex_home = root.path().join("codex");
    let user_skills_dir = root.path().join("home/.agents/skills");
    fs::create_dir_all(&codex_home).unwrap();
    fs::create_dir_all(&user_skills_dir).unwrap();
    let physical_project = fs::canonicalize(&project_root).unwrap();
    let project_key = physical_project.as_path();
    #[cfg(windows)]
    let project_key = dunce::simplified(project_key);
    let quoted_project = serde_json::to_string(project_key.to_str().unwrap()).unwrap();
    fs::write(
        codex_home.join("config.toml"),
        format!("[projects.{quoted_project}]\ntrust_level = \"trusted\"\n"),
    )
    .unwrap();
    let codex_executable = root.path().join("codex-bin");
    fs::write(&codex_executable, b"\x7fELFfixture codex executable").unwrap();
    let codex = CodexAdapter::from_layout(
        CodexLayout {
            executable: codex_executable,
            executable_kind: CodexExecutableKind::Native,
            version: "0.144.1".to_owned(),
            installation_method: InstallationMethod::Manual,
            codex_home,
            user_home: root.path().join("home"),
            user_skills_dir,
            project_root: project_root.clone(),
            working_directory: working_directory.clone(),
            requirements_paths: vec![],
        },
        project,
        device,
        clock(),
    )
    .unwrap();

    let hermes_home = root.path().join("hermes");
    fs::create_dir_all(&hermes_home).unwrap();
    let hermes_config = hermes_home.join("config.yaml");
    fs::write(
        &hermes_config,
        b"# user-owned prefix\nunknown_root: preserve-me\n",
    )
    .unwrap();
    let hermes_executable = root.path().join("hermes-bin");
    fs::write(&hermes_executable, b"\x7fELFfixture hermes executable").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        fs::set_permissions(&hermes_executable, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let hermes = HermesAdapter::from_layout(
        HermesLayout {
            executable: hermes_executable,
            executable_kind: HermesExecutableKind::Native,
            version: "0.18.2".to_owned(),
            installation_method: InstallationMethod::Manual,
            default_hermes_home: hermes_home.clone(),
            profile: HermesProfile {
                name: "default".to_owned(),
                hermes_home,
            },
            project_root,
            working_directory,
        },
        project,
        device,
        clock(),
    )
    .unwrap();

    AdapterFixture {
        _root: root,
        bridge,
        claude,
        codex,
        hermes,
        hermes_config,
    }
}

#[test]
fn bridge_components_are_stable_global_harness_specific_and_secret_free() {
    let root = tempfile::tempdir().unwrap();
    let executable = root.path().join("context-relay-context-mcp");
    write_executable(&executable);
    let canonical_executable = fs::canonicalize(&executable).unwrap();
    let device = DeviceId::from_str(DEVICE_ID).unwrap();
    let mut ids = Vec::new();

    for harness in [HarnessId::ClaudeCode, HarnessId::Codex, HarnessId::Hermes] {
        let component = bridge_component(harness, &executable, device, clock()).unwrap();
        let repeated = bridge_component(harness, &executable, device, clock()).unwrap();

        assert_eq!(component.id, repeated.id);
        assert_eq!(
            component.id.to_string(),
            match harness {
                HarnessId::ClaudeCode => "f4a4f9a2-0e8d-720e-8df4-a5a68da3e9c7",
                HarnessId::Codex => "b5be495e-d4ee-7a2e-a29e-b589ebc5d7fd",
                HarnessId::Hermes => "92cb3173-a859-79e2-97e1-3ef3633fcb3a",
            }
        );
        assert_eq!(component.name, BRIDGE_SERVER_NAME);
        assert_eq!(component.kind, ComponentKind::McpServer);
        assert_eq!(component.scope, ScopeRef::Global);
        assert_eq!(component.provenance.harness, None);
        assert_eq!(component.provenance.source, None);
        assert!(is_managed_bridge_component(harness, &component));

        let expected = if harness == HarnessId::Hermes {
            json!({
                "args": ["--harness", harness_cli_name(harness)],
                "command": canonical_executable.to_str().unwrap(),
            })
        } else {
            json!({
                "args": ["--harness", harness_cli_name(harness)],
                "command": canonical_executable.to_str().unwrap(),
                "type": "stdio",
            })
        };
        assert_eq!(
            component.body_markdown,
            serde_json::to_string(&expected).unwrap()
        );
        let value: Value = serde_json::from_str(&component.body_markdown).unwrap();
        assert_eq!(value, expected);
        for forbidden in [
            "env",
            "credentials",
            "project",
            "projectId",
            "cwd",
            "workingDirectory",
            "url",
            "network",
            "headers",
            "token",
            "secret",
        ] {
            assert!(
                value.get(forbidden).is_none(),
                "bridge declaration contained {forbidden}"
            );
        }
        assert_eq!(
            component.metadata,
            if harness == HarnessId::Hermes {
                vec![(
                    "structuralLocation".to_owned(),
                    "config:mcp_servers.context-relay".to_owned(),
                )]
            } else {
                vec![]
            }
        );
        ids.push(component.id);
    }

    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 3);
}

#[test]
fn managed_bridge_predicate_is_narrow_but_accepts_the_archived_remove_form() {
    let root = tempfile::tempdir().unwrap();
    let executable = root.path().join("context-relay-context-mcp");
    write_executable(&executable);
    let device = DeviceId::from_str(DEVICE_ID).unwrap();
    let component = bridge_component(HarnessId::Hermes, &executable, device, clock()).unwrap();

    let mut archived = component.clone();
    archived.archived = true;
    assert!(is_managed_bridge_component(HarnessId::Hermes, &archived));

    let mut changed = component.clone();
    changed.name = "context-relay-copy".to_owned();
    assert!(!is_managed_bridge_component(HarnessId::Hermes, &changed));

    let mut changed = component.clone();
    changed.body_markdown.push(' ');
    assert!(!is_managed_bridge_component(HarnessId::Hermes, &changed));

    let mut changed = component.clone();
    changed
        .metadata
        .push(("profile".to_owned(), "default".to_owned()));
    assert!(!is_managed_bridge_component(HarnessId::Hermes, &changed));

    let mut changed = component.clone();
    changed.provenance.harness = Some(HarnessId::Hermes);
    assert!(!is_managed_bridge_component(HarnessId::Hermes, &changed));

    assert!(!is_managed_bridge_component(HarnessId::Codex, &component));
}

#[test]
fn bridge_executable_must_be_absolute_existing_regular_non_link_and_lossless() {
    let root = tempfile::tempdir().unwrap();
    let executable = root.path().join("context-relay-context-mcp");
    write_executable(&executable);
    let device = DeviceId::from_str(DEVICE_ID).unwrap();

    assert!(
        bridge_component(
            HarnessId::Codex,
            Path::new("context-relay-context-mcp"),
            device,
            clock(),
        )
        .is_err()
    );
    assert!(
        bridge_component(
            HarnessId::Codex,
            &root.path().join("missing"),
            device,
            clock(),
        )
        .is_err()
    );
    assert!(bridge_component(HarnessId::Codex, root.path(), device, clock()).is_err());

    #[cfg(unix)]
    {
        use std::{
            ffi::OsStr,
            os::unix::{
                ffi::OsStrExt as _,
                fs::{PermissionsExt as _, symlink},
            },
        };

        let link = root.path().join("bridge-link");
        symlink(&executable, &link).unwrap();
        assert!(bridge_component(HarnessId::Codex, &link, device, clock()).is_err());

        fs::set_permissions(&executable, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(bridge_component(HarnessId::Codex, &executable, device, clock()).is_err());

        let control = root.path().join("bridge\ncontrol");
        assert!(bridge_component(HarnessId::Codex, &control, device, clock()).is_err());

        let non_utf8 = root.path().join(OsStr::from_bytes(b"bridge-\xff"));
        assert!(bridge_component(HarnessId::Codex, &non_utf8, device, clock()).is_err());
    }
}

#[test]
fn claude_and_codex_render_exact_official_global_add_and_remove_argv() {
    let fixture = adapter_fixture();
    let device = DeviceId::from_str(DEVICE_ID).unwrap();

    let claude = bridge_component(HarnessId::ClaudeCode, &fixture.bridge, device, clock()).unwrap();
    let mut claude_remove = claude.clone();
    claude_remove.archived = true;
    assert_eq!(
        argv(&fixture.claude.render(&desired(claude.clone())).unwrap()),
        vec![vec![
            "mcp",
            "add-json",
            BRIDGE_SERVER_NAME,
            claude.body_markdown.as_str(),
            "--scope",
            "user",
        ]]
    );
    assert_eq!(
        argv(&fixture.claude.render(&desired(claude_remove)).unwrap()),
        vec![vec!["mcp", "remove", BRIDGE_SERVER_NAME, "--scope", "user",]]
    );

    let codex = bridge_component(HarnessId::Codex, &fixture.bridge, device, clock()).unwrap();
    let mut codex_remove = codex.clone();
    codex_remove.archived = true;
    assert_eq!(
        argv(&fixture.codex.render(&desired(codex)).unwrap()),
        vec![vec![
            "mcp",
            "add",
            BRIDGE_SERVER_NAME,
            "--",
            fs::canonicalize(&fixture.bridge).unwrap().to_str().unwrap(),
            "--harness",
            "codex",
        ]]
    );
    assert_eq!(
        argv(&fixture.codex.render(&desired(codex_remove)).unwrap()),
        vec![vec!["mcp", "remove", BRIDGE_SERVER_NAME]]
    );
}

#[test]
fn hermes_bridge_plan_is_structural_idempotent_gated_and_byte_exactly_reversible() {
    let fixture = adapter_fixture();
    let device = DeviceId::from_str(DEVICE_ID).unwrap();
    let component = bridge_component(HarnessId::Hermes, &fixture.bridge, device, clock()).unwrap();
    let desired = desired(component);
    let before = fs::read(&fixture.hermes_config).unwrap();

    let rendered = fixture.hermes.render(&desired).unwrap();
    assert_eq!(rendered.cli_operations, vec![]);
    assert_eq!(fs::read(&fixture.hermes_config).unwrap(), before);

    let mutation = fixture
        .hermes
        .plan_native_config(&desired)
        .unwrap()
        .unwrap();
    assert_eq!(fs::read(&fixture.hermes_config).unwrap(), before);
    let NativeState::RegularFile { bytes, .. } = NativeState::decode_v1(&mutation.content).unwrap()
    else {
        panic!("Hermes bridge plan must target config.yaml");
    };
    let yaml: serde_yaml_ng::Value = serde_yaml_ng::from_slice(&bytes).unwrap();
    let bridge = &yaml["mcp_servers"][BRIDGE_SERVER_NAME];
    assert_eq!(
        bridge["command"].as_str(),
        fs::canonicalize(&fixture.bridge).unwrap().to_str()
    );
    assert_eq!(
        bridge["args"],
        serde_yaml_ng::from_str::<serde_yaml_ng::Value>("[--harness, hermes]").unwrap()
    );
    assert!(bridge.get("type").is_none());
    assert!(bridge.get("env").is_none());

    let gateway_lock = fixture.hermes_config.parent().unwrap().join("gateway.lock");
    assert!(
        !gateway_lock.exists(),
        "preview must not create gateway.lock"
    );
    fs::write(&gateway_lock, []).unwrap();

    let mut native = OsNativeTransactionFileSystem::new([19; 16]);
    let images = native
        .create_before_images(std::slice::from_ref(&mutation))
        .unwrap();
    native.record_native_metadata(&images).unwrap();
    native
        .compare_and_swap_targets(std::slice::from_ref(&mutation))
        .unwrap();
    native.apply_mutation(&[19; 16], &mutation).unwrap();
    assert!(
        fixture
            .hermes
            .plan_native_config(&desired)
            .unwrap()
            .is_none()
    );
    native.restore_matching_applied_targets(&[19; 16]).unwrap();
    assert_eq!(fs::read(&fixture.hermes_config).unwrap(), before);

    fs::write(
        fixture.hermes_config.parent().unwrap().join("gateway.pid"),
        b"invalid-live-gateway-record",
    )
    .unwrap();
    let error = fixture.hermes.plan_native_config(&desired).unwrap_err();
    assert_eq!(error.code, context_relay_protocol::ErrorCode::Conflict);
    assert_eq!(fs::read(&fixture.hermes_config).unwrap(), before);
}
