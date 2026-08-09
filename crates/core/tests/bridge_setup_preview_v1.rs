mod support;

use std::{
    cell::{Cell, RefCell},
    fs,
    path::Path,
    rc::Rc,
    str::FromStr,
};

#[cfg(feature = "test-support")]
use context_relay_core::native_transaction::{approval_hash_v2, open_plan};
use context_relay_core::{
    hermes::{HermesAdapter, HermesExecutableKind, HermesLayout, HermesProfile},
    mcp::install::{
        BRIDGE_SERVER_NAME, BridgeExecutable, attest_bridge_executable, bridge_component,
    },
    native_transaction::{ApprovedCliMutation, CanonicalCliDeclaration},
    setup::{BridgeInstallService, BridgeLocator, BridgeMutationPlan, BridgePreviewHarness},
    vault::{SetupPlanAction, SetupPlanLifecycle, Vault},
};
#[cfg(feature = "test-support")]
use context_relay_native_runner::RuntimeTarget;
use context_relay_protocol::{
    ApprovalClass, CapabilityLevel, ChangeClass, ClassifiedChanges, CliOperation, CliOperations,
    ClientError, ComponentRecord, DesiredState, DeviceId, DiscoveredScopes, HarnessAdapter,
    HarnessId, ImportRequest, ImportedState, InstallationMethod, NativePlatform, NativeScope,
    PlanId, ProbeContext, ProbeReport, RenderedState, SemanticDiff, Sha256Digest, ValidationReport,
    WireNativeValue,
};
use sha2::{Digest as _, Sha256};

use support::{ID_1, ID_2, MemoryKeyStore, TempVault, clock};

const NOW_MS: u64 = 1_900_000_000_000;

#[derive(Default)]
struct Calls {
    probe: usize,
    import: usize,
    render: usize,
    classify: usize,
    cli: usize,
    config_writes: usize,
}

struct Harness {
    calls: Rc<RefCell<Calls>>,
    executable: WireNativeValue,
    existing: Option<ComponentRecord>,
    prior_declaration: Option<CanonicalCliDeclaration>,
    reject_prior_declaration: bool,
}

#[derive(Clone)]
struct FixtureBridgeLocator {
    bridge: BridgeExecutable,
    resolutions: Rc<Cell<usize>>,
}

impl BridgeLocator for FixtureBridgeLocator {
    fn locate(&self) -> Result<BridgeExecutable, ClientError> {
        self.resolutions.set(self.resolutions.get() + 1);
        Ok(self.bridge.clone())
    }
}

impl Harness {
    fn bridge_mutation(&self, intended: &ComponentRecord) -> ApprovedCliMutation {
        let body = intended.body_markdown.clone();
        let declaration = CanonicalCliDeclaration {
            harness: HarnessId::Codex,
            server_name: BRIDGE_SERVER_NAME.to_owned(),
            fingerprint: Sha256Digest(Sha256::digest(body.as_bytes()).into()),
            canonical_body: body,
        };
        let operation = CliOperation {
            executable: self.executable.clone(),
            arguments: ["mcp", "add", BRIDGE_SERVER_NAME]
                .into_iter()
                .map(native_text)
                .collect(),
            timeout_ms: 30_000,
        };
        ApprovedCliMutation {
            stable_id: intended.id.to_string(),
            expected: self.prior_declaration.clone(),
            intended: Some(declaration),
            forward: vec![operation.clone()],
            rollback: vec![match &self.prior_declaration {
                Some(declaration) => CliOperation {
                    executable: self.executable.clone(),
                    arguments: [
                        "mcp",
                        "add",
                        BRIDGE_SERVER_NAME,
                        &declaration.canonical_body,
                    ]
                    .into_iter()
                    .map(native_text)
                    .collect(),
                    timeout_ms: 30_000,
                },
                None => CliOperation {
                    executable: self.executable.clone(),
                    arguments: ["mcp", "remove", BRIDGE_SERVER_NAME]
                        .into_iter()
                        .map(native_text)
                        .collect(),
                    timeout_ms: 30_000,
                },
            }],
        }
    }
}

fn declaration(body: String) -> CanonicalCliDeclaration {
    CanonicalCliDeclaration {
        harness: HarnessId::Codex,
        server_name: BRIDGE_SERVER_NAME.to_owned(),
        fingerprint: Sha256Digest(Sha256::digest(body.as_bytes()).into()),
        canonical_body: body,
    }
}

impl HarnessAdapter for Harness {
    fn probe(&self, context: &ProbeContext) -> Result<ProbeReport, ClientError> {
        assert_eq!(context.harness, HarnessId::Codex);
        self.calls.borrow_mut().probe += 1;
        Ok(ProbeReport {
            executable: Some(self.executable.clone()),
            executable_sha256: Some(Sha256Digest([3; 32])),
            harness_version: Some("0.144.1".to_owned()),
            installation_method: InstallationMethod::Manual,
            config_roots: vec![],
            active_profile: None,
            policy_conflicts: vec![],
            capability: CapabilityLevel::Full,
        })
    }

    fn discover_scopes(&self, _: &ProbeReport) -> Result<DiscoveredScopes, ClientError> {
        Ok(DiscoveredScopes(vec![NativeScope::Global]))
    }

    fn import(&self, request: &ImportRequest) -> Result<ImportedState, ClientError> {
        assert_eq!(request.scopes, vec![NativeScope::Global]);
        assert!(request.include_disabled);
        self.calls.borrow_mut().import += 1;
        Ok(ImportedState {
            components: self.existing.clone().into_iter().collect(),
            source_digests: vec![],
        })
    }

    fn render(&self, desired: &DesiredState) -> Result<RenderedState, ClientError> {
        assert_eq!(desired.components.len(), 1);
        self.calls.borrow_mut().render += 1;
        Ok(RenderedState {
            files: vec![],
            cli_operations: vec![],
        })
    }

    fn classify(&self, diff: &SemanticDiff) -> Result<ClassifiedChanges, ClientError> {
        assert_eq!(diff.conflicts, Vec::<String>::new());
        self.calls.borrow_mut().classify += 1;
        Ok(ClassifiedChanges(diff.changes.clone()))
    }

    fn plan_cli_ops(&self, classified: &ClassifiedChanges) -> Result<CliOperations, ClientError> {
        self.calls.borrow_mut().cli += 1;
        Ok(CliOperations(
            (!classified.0.is_empty())
                .then(|| CliOperation {
                    executable: self.executable.clone(),
                    arguments: ["mcp", "add", BRIDGE_SERVER_NAME]
                        .into_iter()
                        .map(native_text)
                        .collect(),
                    timeout_ms: 30_000,
                })
                .into_iter()
                .collect(),
        ))
    }

    fn validate_effective(
        &self,
        _: &context_relay_protocol::ApplyReceipt,
    ) -> Result<ValidationReport, ClientError> {
        unreachable!("preview never validates effective state")
    }
}

impl BridgePreviewHarness for Harness {
    fn bridge_harness(&self) -> HarnessId {
        HarnessId::Codex
    }

    fn bridge_mutations(
        &self,
        _: &DesiredState,
        intended: &ComponentRecord,
    ) -> Result<BridgeMutationPlan, ClientError> {
        if self.reject_prior_declaration {
            return Err(ClientError {
                code: context_relay_protocol::ErrorCode::Conflict,
                message: "Codex prior MCP declaration is unmanaged".to_owned(),
                field_path: None,
                retryable: false,
            });
        }
        Ok(BridgeMutationPlan {
            cli: Some(self.bridge_mutation(intended)),
            native: vec![],
        })
    }
}

fn native_text(value: &str) -> WireNativeValue {
    #[cfg(not(windows))]
    use std::os::unix::ffi::OsStrExt as _;
    #[cfg(windows)]
    use std::os::windows::ffi::OsStrExt as _;

    let value = std::ffi::OsStr::new(value);
    WireNativeValue {
        platform: if cfg!(windows) {
            NativePlatform::Windows
        } else {
            NativePlatform::Macos
        },
        #[cfg(not(windows))]
        bytes: value.as_bytes().to_vec(),
        #[cfg(windows)]
        bytes: value.encode_wide().flat_map(u16::to_le_bytes).collect(),
        display: value.to_str().map(str::to_owned),
    }
}

fn bridge(path: &Path) {
    fs::write(path, b"bridge-preview-v1").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
}

fn hermes_adapter(root: &Path, config: &[u8]) -> (HermesAdapter, std::path::PathBuf) {
    let project_root = root.join("project");
    let working_directory = project_root.join("service");
    fs::create_dir_all(&working_directory).unwrap();
    fs::write(
        project_root.join("HERMES.md"),
        b"user project instructions\n",
    )
    .unwrap();
    let profile_home = root.join("hermes");
    fs::create_dir_all(&profile_home).unwrap();
    let config_path = profile_home.join("config.yaml");
    fs::write(&config_path, config).unwrap();
    let executable = root.join("hermes-bin");
    fs::write(&executable, b"\x7fELFfixture hermes executable").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    }
    (
        HermesAdapter::from_layout(
            HermesLayout {
                executable,
                executable_kind: HermesExecutableKind::Native,
                version: "0.18.2".to_owned(),
                installation_method: InstallationMethod::Manual,
                default_hermes_home: profile_home.clone(),
                profile: HermesProfile {
                    name: "default".to_owned(),
                    hermes_home: profile_home,
                },
                project_root,
                working_directory,
            },
            ID_1.parse().unwrap(),
            ID_2.parse().unwrap(),
            clock(NOW_MS),
        )
        .unwrap(),
        config_path,
    )
}

fn locator(path: &Path) -> FixtureBridgeLocator {
    FixtureBridgeLocator {
        bridge: attest_bridge_executable(path).unwrap(),
        resolutions: Rc::new(Cell::new(0)),
    }
}

fn service<'a>(
    vault: &'a mut Vault,
    harness: Harness,
    locator: FixtureBridgeLocator,
) -> BridgeInstallService<'a, Harness, FixtureBridgeLocator> {
    BridgeInstallService::new(
        vault,
        harness,
        locator,
        DeviceId::from_str(ID_1).unwrap(),
        clock(NOW_MS),
    )
}

#[cfg(feature = "test-support")]
#[test]
fn bridge_preview_seals_the_selected_supported_runtime_target() {
    for target in [RuntimeTarget::MacosArm64, RuntimeTarget::WindowsX86_64] {
        let root = tempfile::tempdir().unwrap();
        let bridge_path = root.path().join("context-relay-context-mcp");
        bridge(&bridge_path);
        let vault_path = TempVault::new(target.stable_name());
        let keys = MemoryKeyStore::default();
        let mut vault = Vault::open(vault_path.path(), "bridge-target-v1", &keys).unwrap();
        let harness = Harness {
            calls: Rc::new(RefCell::new(Calls::default())),
            executable: native_text("fixture-codex"),
            existing: None,
            prior_declaration: None,
            reject_prior_declaration: false,
        };

        let setup = BridgeInstallService::new_for_runtime_target(
            &mut vault,
            harness,
            locator(&bridge_path),
            DeviceId::from_str(ID_1).unwrap(),
            clock(NOW_MS),
            target,
        )
        .preview(None, NOW_MS)
        .unwrap();
        let stored = vault.setup_plan(&setup.plan_id).unwrap().unwrap();
        let mut opened = open_plan(&stored.payload).unwrap().plan;

        assert_eq!(opened.sidecars.len(), 1);
        assert_eq!(opened.sidecars[0].target, target);
        opened.sidecars[0].target = match target {
            RuntimeTarget::MacosArm64 => RuntimeTarget::WindowsX86_64,
            RuntimeTarget::WindowsX86_64 => RuntimeTarget::MacosArm64,
        };
        assert_ne!(approval_hash_v2(&opened).unwrap(), setup.batch_hash);
    }
}

#[test]
fn preview_runs_the_adapter_path_derives_active_and_persists_the_sealed_v2_plan() {
    let root = tempfile::tempdir().unwrap();
    let bridge_path = root.path().join("context-relay-context-mcp");
    bridge(&bridge_path);
    let vault_path = TempVault::new("bridge-preview");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(vault_path.path(), "bridge-preview-v1", &keys).unwrap();
    let calls = Rc::new(RefCell::new(Calls::default()));
    let harness = Harness {
        calls: calls.clone(),
        executable: native_text("/fixture/codex"),
        existing: None,
        prior_declaration: None,
        reject_prior_declaration: false,
    };

    let bridge_locator = locator(&bridge_path);
    let resolutions = bridge_locator.resolutions.clone();
    let setup = service(&mut vault, harness, bridge_locator)
        .preview(None, NOW_MS)
        .unwrap();

    assert_eq!(setup.harness, HarnessId::Codex);
    assert_eq!(setup.approval_class, ApprovalClass::Active);
    assert_eq!(
        setup.expires_at,
        NOW_MS + BridgeInstallService::<Harness, FixtureBridgeLocator>::PREVIEW_TTL_MS
    );
    assert_eq!(calls.borrow().probe, 1);
    assert_eq!(calls.borrow().import, 1);
    assert_eq!(calls.borrow().render, 1);
    assert_eq!(calls.borrow().classify, 1);
    assert_eq!(calls.borrow().cli, 1);
    assert_eq!(calls.borrow().config_writes, 0);
    assert_eq!(resolutions.get(), 1);

    let stored = vault.setup_plan(&setup.plan_id).unwrap().unwrap();
    assert_eq!(stored.lifecycle, SetupPlanLifecycle::Previewed);
    assert_eq!(stored.approval_version, 2);
    assert_eq!(stored.approval_hash, setup.batch_hash);
    assert_eq!(stored.expires_ms, setup.expires_at);
    let sealed: serde_json::Value = serde_json::from_slice(&stored.payload).unwrap();
    assert_eq!(sealed["schemaVersion"], 1);
    assert_eq!(sealed["approvalVersion"], 2);
    assert_eq!(
        sealed["nativePlan"]["setup"]["planId"],
        setup.plan_id.to_string()
    );
    assert_eq!(
        setup.expected_native_digests[0].expected_digest,
        Some(Sha256Digest(Sha256::digest(b"bridge-preview-v1").into()))
    );
}

#[test]
fn preview_rejects_a_forged_locator_digest_before_probing_or_persisting() {
    let root = tempfile::tempdir().unwrap();
    let bridge_path = root.path().join("context-relay-context-mcp");
    bridge(&bridge_path);
    let vault_path = TempVault::new("bridge-preview-forged-locator");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(vault_path.path(), "bridge-preview-v1", &keys).unwrap();
    let calls = Rc::new(RefCell::new(Calls::default()));
    let forged_locator = FixtureBridgeLocator {
        bridge: BridgeExecutable {
            path: bridge_path,
            digest: Sha256Digest([0; 32]),
        },
        resolutions: Rc::new(Cell::new(0)),
    };
    let harness = Harness {
        calls: calls.clone(),
        executable: native_text("/fixture/codex"),
        existing: None,
        prior_declaration: None,
        reject_prior_declaration: false,
    };

    let error = service(&mut vault, harness, forged_locator)
        .preview(None, NOW_MS)
        .unwrap_err();

    assert_eq!(error.code, context_relay_protocol::ErrorCode::Conflict);
    let calls = calls.borrow();
    assert_eq!(calls.probe, 0);
    assert_eq!(calls.import, 0);
    assert_eq!(calls.render, 0);
    assert_eq!(calls.classify, 0);
    assert_eq!(calls.cli, 0);
    assert_eq!(calls.config_writes, 0);
    assert!(
        vault
            .setup_plan(&PlanId::from_str(ID_1).unwrap())
            .unwrap()
            .is_none()
    );
}

#[test]
fn preview_rejects_a_conflicting_prior_declaration_without_persisting_or_writing() {
    let root = tempfile::tempdir().unwrap();
    let bridge_path = root.path().join("context-relay-context-mcp");
    bridge(&bridge_path);
    let vault_path = TempVault::new("bridge-preview-conflict");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(vault_path.path(), "bridge-preview-v1", &keys).unwrap();
    let calls = Rc::new(RefCell::new(Calls::default()));
    let conflicting = bridge_component(
        HarnessId::Codex,
        &bridge_path,
        ID_2.parse().unwrap(),
        clock(NOW_MS),
    )
    .unwrap();
    let mut conflicting = conflicting;
    conflicting.body_markdown = "{\"command\":\"/unmanaged\"}".to_owned();
    let harness = Harness {
        calls: calls.clone(),
        executable: native_text("/fixture/codex"),
        existing: Some(conflicting),
        prior_declaration: None,
        reject_prior_declaration: true,
    };

    let error = service(&mut vault, harness, locator(&bridge_path))
        .preview(None, NOW_MS)
        .unwrap_err();

    assert_eq!(error.code, context_relay_protocol::ErrorCode::Conflict);
    assert_eq!(calls.borrow().config_writes, 0);
    assert!(
        vault
            .setup_plan(&PlanId::from_str(ID_1).unwrap())
            .unwrap()
            .is_none()
    );
}

#[test]
fn preview_uses_the_authoritative_cli_absence_over_an_imported_exact_bridge() {
    let root = tempfile::tempdir().unwrap();
    let bridge_path = root.path().join("context-relay-context-mcp");
    bridge(&bridge_path);
    let vault_path = TempVault::new("bridge-preview-authoritative-absence");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(vault_path.path(), "bridge-preview-v1", &keys).unwrap();
    let calls = Rc::new(RefCell::new(Calls::default()));
    let imported_exact = bridge_component(
        HarnessId::Codex,
        &bridge_path,
        ID_1.parse().unwrap(),
        clock(NOW_MS),
    )
    .unwrap();

    let setup = service(
        &mut vault,
        Harness {
            calls,
            executable: native_text("/fixture/codex"),
            existing: Some(imported_exact),
            prior_declaration: None,
            reject_prior_declaration: false,
        },
        locator(&bridge_path),
    )
    .preview(None, NOW_MS)
    .unwrap();

    assert_eq!(setup.approval_class, ApprovalClass::Active);
    assert_eq!(setup.semantic_changes[0].class, ChangeClass::Create);
}

#[test]
fn preview_keeps_an_authoritatively_exact_cli_bridge_passive_without_mutations() {
    let root = tempfile::tempdir().unwrap();
    let bridge_path = root.path().join("context-relay-context-mcp");
    bridge(&bridge_path);
    let vault_path = TempVault::new("bridge-preview-authoritative-exact");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(vault_path.path(), "bridge-preview-v1", &keys).unwrap();
    let exact = bridge_component(
        HarnessId::Codex,
        &bridge_path,
        ID_1.parse().unwrap(),
        clock(NOW_MS),
    )
    .unwrap();

    let setup = service(
        &mut vault,
        Harness {
            calls: Rc::new(RefCell::new(Calls::default())),
            executable: native_text("/fixture/codex"),
            existing: None,
            prior_declaration: Some(declaration(exact.body_markdown)),
            reject_prior_declaration: false,
        },
        locator(&bridge_path),
    )
    .preview(None, NOW_MS)
    .unwrap();

    assert_eq!(setup.approval_class, ApprovalClass::Passive);
    assert!(setup.semantic_changes.is_empty());
    assert!(setup.cli_operations.is_empty());
    let stored = vault.setup_plan(&setup.plan_id).unwrap().unwrap();
    let sealed: serde_json::Value = serde_json::from_slice(&stored.payload).unwrap();
    assert_eq!(sealed["nativePlan"]["cliMutations"], serde_json::json!([]));
}

#[test]
fn preview_binds_an_authoritatively_changed_cli_bridge_to_update_and_exact_rollback() {
    let root = tempfile::tempdir().unwrap();
    let bridge_path = root.path().join("context-relay-context-mcp");
    let previous_bridge_path = root.path().join("previous-context-mcp");
    bridge(&bridge_path);
    bridge(&previous_bridge_path);
    let vault_path = TempVault::new("bridge-preview-authoritative-update");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(vault_path.path(), "bridge-preview-v1", &keys).unwrap();
    let previous = bridge_component(
        HarnessId::Codex,
        &previous_bridge_path,
        ID_1.parse().unwrap(),
        clock(NOW_MS),
    )
    .unwrap();

    let setup = service(
        &mut vault,
        Harness {
            calls: Rc::new(RefCell::new(Calls::default())),
            executable: native_text("/fixture/codex"),
            existing: None,
            prior_declaration: Some(declaration(previous.body_markdown.clone())),
            reject_prior_declaration: false,
        },
        locator(&bridge_path),
    )
    .preview(None, NOW_MS)
    .unwrap();

    assert_eq!(setup.approval_class, ApprovalClass::Active);
    assert_eq!(setup.semantic_changes[0].class, ChangeClass::Update);
    let stored = vault.setup_plan(&setup.plan_id).unwrap().unwrap();
    let sealed: serde_json::Value = serde_json::from_slice(&stored.payload).unwrap();
    assert_eq!(
        sealed["nativePlan"]["cliMutations"][0]["expected"]["canonicalBody"],
        previous.body_markdown
    );
    assert_eq!(
        sealed["nativePlan"]["cliMutations"][0]["rollback"][0]["arguments"][3]["display"],
        previous.body_markdown
    );
}

#[test]
fn preview_replays_identical_sealed_bytes_and_the_persisted_plan_expires() {
    let root = tempfile::tempdir().unwrap();
    let bridge_path = root.path().join("context-relay-context-mcp");
    bridge(&bridge_path);
    let vault_path = TempVault::new("bridge-preview-replay");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(vault_path.path(), "bridge-preview-v1", &keys).unwrap();

    let first = service(
        &mut vault,
        Harness {
            calls: Rc::new(RefCell::new(Calls::default())),
            executable: native_text("/fixture/codex"),
            existing: None,
            prior_declaration: None,
            reject_prior_declaration: false,
        },
        locator(&bridge_path),
    )
    .preview(None, NOW_MS)
    .unwrap();
    let first_payload = vault.setup_plan(&first.plan_id).unwrap().unwrap().payload;

    let replay = service(
        &mut vault,
        Harness {
            calls: Rc::new(RefCell::new(Calls::default())),
            executable: native_text("/fixture/codex"),
            existing: None,
            prior_declaration: None,
            reject_prior_declaration: false,
        },
        locator(&bridge_path),
    )
    .preview(None, NOW_MS)
    .unwrap();
    assert_eq!(replay.plan_id, first.plan_id);
    assert_eq!(
        vault.setup_plan(&replay.plan_id).unwrap().unwrap().payload,
        first_payload
    );

    assert!(
        vault
            .claim_setup_plan(&first.plan_id, SetupPlanAction::Apply, first.expires_at)
            .is_err()
    );
    assert_eq!(
        vault.setup_plan(&first.plan_id).unwrap().unwrap().lifecycle,
        SetupPlanLifecycle::Expired
    );
}

#[test]
fn preview_uses_the_reviewed_hermes_native_path_without_cli_or_config_writes() {
    let root = tempfile::tempdir().unwrap();
    let bridge_path = root.path().join("context-relay-context-mcp");
    bridge(&bridge_path);
    let config_before = b"unknown_root: preserve-me\n";
    let (adapter, config_path) = hermes_adapter(root.path(), config_before);
    let vault_path = TempVault::new("bridge-preview-hermes");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(vault_path.path(), "bridge-preview-v1", &keys).unwrap();

    let setup = BridgeInstallService::new(
        &mut vault,
        adapter,
        locator(&bridge_path),
        ID_1.parse().unwrap(),
        clock(NOW_MS),
    )
    .preview(None, NOW_MS)
    .unwrap();

    assert_eq!(setup.harness, HarnessId::Hermes);
    assert!(setup.cli_operations.is_empty());
    assert_eq!(setup.approval_class, ApprovalClass::Active);
    assert_eq!(fs::read(config_path).unwrap(), config_before);
    let stored = vault.setup_plan(&setup.plan_id).unwrap().unwrap();
    let sealed: serde_json::Value = serde_json::from_slice(&stored.payload).unwrap();
    assert_eq!(sealed["nativePlan"]["cliMutations"], serde_json::json!([]));
    assert_eq!(
        sealed["nativePlan"]["mutations"].as_array().unwrap().len(),
        2
    );
}

#[test]
fn preview_accepts_an_existing_exact_hermes_bridge_projection() {
    let root = tempfile::tempdir().unwrap();
    let bridge_path = root.path().join("context-relay-context-mcp");
    bridge(&bridge_path);
    let bridge = bridge_component(
        HarnessId::Hermes,
        &bridge_path,
        ID_1.parse().unwrap(),
        clock(NOW_MS),
    )
    .unwrap();
    let body: serde_json::Value = serde_json::from_str(&bridge.body_markdown).unwrap();
    let command = body["command"].as_str().unwrap();
    let config = format!(
        "mcp_servers:\n  context-relay:\n    args:\n      - --harness\n      - hermes\n    command: {command}\n"
    );
    let (adapter, config_path) = hermes_adapter(root.path(), config.as_bytes());
    let vault_path = TempVault::new("bridge-preview-hermes-existing");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(vault_path.path(), "bridge-preview-v1", &keys).unwrap();

    let setup = BridgeInstallService::new(
        &mut vault,
        adapter,
        locator(&bridge_path),
        ID_1.parse().unwrap(),
        clock(NOW_MS),
    )
    .preview(None, NOW_MS)
    .unwrap();

    assert_eq!(setup.harness, HarnessId::Hermes);
    assert_eq!(setup.approval_class, ApprovalClass::Active);
    assert!(setup.cli_operations.is_empty());
    assert_eq!(fs::read(config_path).unwrap(), config.as_bytes());
}

#[test]
fn preview_enables_an_existing_exact_disabled_hermes_bridge_projection() {
    let root = tempfile::tempdir().unwrap();
    let bridge_path = root.path().join("context-relay-context-mcp");
    bridge(&bridge_path);
    let bridge = bridge_component(
        HarnessId::Hermes,
        &bridge_path,
        ID_1.parse().unwrap(),
        clock(NOW_MS),
    )
    .unwrap();
    let body: serde_json::Value = serde_json::from_str(&bridge.body_markdown).unwrap();
    let command = body["command"].as_str().unwrap();
    let config = format!(
        "mcp_servers:\n  context-relay:\n    args:\n      - --harness\n      - hermes\n    command: {command}\n    enabled: false\n"
    );
    let (adapter, config_path) = hermes_adapter(root.path(), config.as_bytes());
    let vault_path = TempVault::new("bridge-preview-hermes-disabled");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(vault_path.path(), "bridge-preview-v1", &keys).unwrap();

    let setup = BridgeInstallService::new(
        &mut vault,
        adapter,
        locator(&bridge_path),
        ID_1.parse().unwrap(),
        clock(NOW_MS),
    )
    .preview(None, NOW_MS)
    .unwrap();

    assert_eq!(setup.approval_class, ApprovalClass::Active);
    assert_eq!(setup.semantic_changes[0].class, ChangeClass::Enable);
    assert!(setup.cli_operations.is_empty());
    assert_eq!(fs::read(config_path).unwrap(), config.as_bytes());
}

#[test]
fn preview_updates_a_changed_managed_active_hermes_bridge_projection() {
    let root = tempfile::tempdir().unwrap();
    let bridge_path = root.path().join("context-relay-context-mcp");
    let previous_bridge_path = root.path().join("previous-context-mcp");
    bridge(&bridge_path);
    bridge(&previous_bridge_path);
    let bridge = bridge_component(
        HarnessId::Hermes,
        &previous_bridge_path,
        ID_1.parse().unwrap(),
        clock(NOW_MS),
    )
    .unwrap();
    let body: serde_json::Value = serde_json::from_str(&bridge.body_markdown).unwrap();
    let command = body["command"].as_str().unwrap();
    let config = format!(
        "mcp_servers:\n  context-relay:\n    args:\n      - --harness\n      - hermes\n    command: {command}\n"
    );
    let (adapter, config_path) = hermes_adapter(root.path(), config.as_bytes());
    let vault_path = TempVault::new("bridge-preview-hermes-update");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(vault_path.path(), "bridge-preview-v1", &keys).unwrap();

    let setup = BridgeInstallService::new(
        &mut vault,
        adapter,
        locator(&bridge_path),
        ID_1.parse().unwrap(),
        clock(NOW_MS),
    )
    .preview(None, NOW_MS)
    .unwrap();

    assert_eq!(setup.approval_class, ApprovalClass::Active);
    assert_eq!(setup.semantic_changes[0].class, ChangeClass::Update);
    assert!(setup.cli_operations.is_empty());
    assert_eq!(fs::read(config_path).unwrap(), config.as_bytes());
}

#[test]
fn preview_rejects_an_unmanaged_hermes_same_name_projection() {
    let root = tempfile::tempdir().unwrap();
    let bridge_path = root.path().join("context-relay-context-mcp");
    bridge(&bridge_path);
    let config = b"mcp_servers:\n  context-relay:\n    command: /unmanaged\n";
    let (adapter, _) = hermes_adapter(root.path(), config);
    let vault_path = TempVault::new("bridge-preview-hermes-conflict");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(vault_path.path(), "bridge-preview-v1", &keys).unwrap();

    let error = BridgeInstallService::new(
        &mut vault,
        adapter,
        locator(&bridge_path),
        ID_1.parse().unwrap(),
        clock(NOW_MS),
    )
    .preview(None, NOW_MS)
    .unwrap_err();

    assert_eq!(error.code, context_relay_protocol::ErrorCode::Conflict);
}
