use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
};

use context_relay_core::{
    hermes::{HermesAdapter, HermesExecutableKind, HermesLayout, HermesMemoryKind, HermesProfile},
    mcp::install::bridge_component,
    native_memory::{
        NativeMemoryAdapter, NativeMemoryDisable, NativeMemoryDocumentKind,
        PRIMARY_MEMORY_INSTRUCTIONS, primary_memory_instruction_component,
    },
    native_transaction::{
        approval_hash_v1,
        engine::{
            BeforeImage, BoundaryError, FaultHook, MutationOutcome, NativeAdapter,
            NativeFileSystem, NativeJournal, NativeTransactionEngine, RestrictedExecutor,
            RestrictedRun,
        },
        filesystem::OsNativeTransactionFileSystem,
        model::{
            ApprovedCliMutation, ApprovedInput, ApprovedMutation, NativeApplyReceipt,
            NativeObjectToken, NativeTransactionPlan, SidecarBinding, TransactionStep,
        },
    },
};
use context_relay_native_runner::{
    NativeState, OsNativeFileSystem, RuleSyncFeature, RuleSyncFeatures, RuleSyncTarget,
    RuntimeTarget, SidecarCommand, SidecarId,
};
use context_relay_protocol::{
    ApplyReceipt, ApprovalClass, CapabilityLevel, ChangeClass, ClassifiedChange, CliOperation,
    ComponentKind, ComponentRecord, DesiredState, DeviceId, ErrorCode, ExpectedNativeDigest,
    HarnessAdapter, HarnessId, HybridLogicalClock, ImportRequest, InstallationMethod,
    NativePlatform, NativeScope, NetworkDelta, PermissionDelta, PlanId, ProbeContext, ProjectId,
    SemanticDiff, SetupPlan, Sha256Digest, WireNativeValue,
};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};

const PROJECT_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073981";
const DEVICE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073982";
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct Fixture {
    root: PathBuf,
    adapter: HermesAdapter,
    layout: HermesLayout,
    project_id: ProjectId,
    default_home: PathBuf,
    profiles_root: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn fixture(source: &str) -> Fixture {
    let source: Value = serde_json::from_str(source).unwrap();
    let root = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!(
            "context-relay-hermes-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
    let default_home = root.join("hermes home");
    let profiles_root = default_home.join("profiles");
    let project_root = root.join("project with spaces");
    let working_directory = project_root.join("service");
    let profile = source["profile"].as_object().unwrap();
    let files = profile["files"].as_object().unwrap();
    let native_memory_config = source["nativeMemoryConfigYaml"]
        .as_str()
        .unwrap_or_default();
    materialize_profile(&default_home, profile, files, native_memory_config);
    materialize_profile(
        &profiles_root.join("coder"),
        profile,
        files,
        native_memory_config,
    );
    materialize_profile(
        &profiles_root.join("writer"),
        profile,
        files,
        native_memory_config,
    );
    materialize(&project_root, source["project"].as_object().unwrap());
    fs::create_dir_all(&working_directory).unwrap();

    // Keep the operational canaries in place so import tests prove they are excluded.
    for profile_root in [
        &default_home,
        &profiles_root.join("coder"),
        &profiles_root.join("writer"),
    ] {
        assert!(profile_root.join("gateway.pid").is_file());
        assert!(profile_root.join("gateway_state.json").is_file());
    }

    let executable = root.join("hermes");
    fs::write(&executable, b"\x7fELFfixture hermes executable").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let project_id = ProjectId::from_str(PROJECT_ID).unwrap();
    let device_id = DeviceId::from_str(DEVICE_ID).unwrap();
    let layout = HermesLayout {
        executable,
        executable_kind: HermesExecutableKind::Native,
        version: source["version"].as_str().unwrap().to_owned(),
        installation_method: InstallationMethod::PackageManager,
        default_hermes_home: default_home.clone(),
        profile: HermesProfile {
            name: "coder".to_owned(),
            hermes_home: profiles_root.join("coder"),
        },
        project_root,
        working_directory,
    };
    let adapter = HermesAdapter::from_layout(
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
        default_home,
        profiles_root,
    }
}

fn materialize_profile(
    root: &Path,
    profile: &Map<String, Value>,
    files: &Map<String, Value>,
    native_memory_config: &str,
) {
    materialize(root, files);
    let mut config = profile["configYaml"].as_str().unwrap().to_owned();
    config.push_str(native_memory_config);
    fs::write(root.join("config.yaml"), config).unwrap();
}

fn materialize(root: &Path, files: &Map<String, Value>) {
    for (relative, body) in files {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, body.as_str().unwrap()).unwrap();
    }
}

fn profile_layout(
    fixture: &Fixture,
    name: &str,
    version: &str,
    kind: HermesExecutableKind,
) -> HermesLayout {
    HermesLayout {
        executable: fixture.layout.executable.clone(),
        executable_kind: kind,
        version: version.to_owned(),
        installation_method: fixture.layout.installation_method,
        default_hermes_home: fixture.default_home.clone(),
        profile: HermesProfile {
            name: name.to_owned(),
            hermes_home: if name == "default" {
                fixture.default_home.clone()
            } else {
                fixture.profiles_root.join(name)
            },
        },
        project_root: fixture.layout.project_root.clone(),
        working_directory: fixture.layout.working_directory.clone(),
    }
}

fn probe(
    adapter: &HermesAdapter,
    requested_profile: Option<&str>,
) -> context_relay_protocol::ProbeReport {
    adapter
        .probe(&ProbeContext {
            harness: HarnessId::Hermes,
            requested_profile: requested_profile.map(str::to_owned),
        })
        .unwrap()
}

fn import_everything(
    fixture: &Fixture,
    include_disabled: bool,
) -> context_relay_protocol::ImportedState {
    match fixture.adapter.import(&ImportRequest {
        scopes: vec![
            NativeScope::Global,
            NativeScope::Project {
                project_id: fixture.project_id,
                root: fixture.adapter.project_root_wire(),
            },
        ],
        include_disabled,
    }) {
        Ok(imported) => imported,
        Err(error) => {
            let diagnostic = format!("{error:?}");
            assert!(
                !diagnostic.contains("must-not-import"),
                "Hermes import error exposed a secret canary"
            );
            panic!("Hermes import unexpectedly failed with {:?}", error.code);
        }
    }
}

fn import_global(fixture: &Fixture) -> context_relay_protocol::ImportedState {
    fixture
        .adapter
        .import(&ImportRequest {
            scopes: vec![NativeScope::Global],
            include_disabled: true,
        })
        .unwrap()
}

fn desired_global(_fixture: &Fixture, components: Vec<ComponentRecord>) -> DesiredState {
    DesiredState {
        components,
        scopes: vec![NativeScope::Global],
    }
}

fn clear_gateway_records(fixture: &Fixture) {
    for name in ["gateway.pid", "gateway_state.json", "gateway.lock"] {
        let path = fixture.layout.profile.hermes_home.join(name);
        if path.exists() {
            fs::remove_file(path).unwrap();
        }
    }
}

fn managed_bridge_desired(fixture: &Fixture) -> (PathBuf, DesiredState) {
    let executable = fixture.root.join("context-relay-context-mcp");
    fs::write(&executable, b"attested Hermes bridge executable").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let device_id = DeviceId::from_str(DEVICE_ID).unwrap();
    let component = bridge_component(
        HarnessId::Hermes,
        &executable,
        device_id,
        HybridLogicalClock::new(1_900_000_000_000, 0, device_id),
    )
    .unwrap();
    (executable, desired_global(fixture, vec![component]))
}

fn intended_bytes(
    mutation: &context_relay_core::native_transaction::model::ApprovedMutation,
) -> Vec<u8> {
    match NativeState::decode_v1(&mutation.content).unwrap() {
        NativeState::RegularFile { bytes, .. } => bytes,
        NativeState::Absent { .. } => panic!("Hermes planned an unexpected absence"),
    }
}

fn component_at(
    components: &[ComponentRecord],
    kind: ComponentKind,
    location: &str,
) -> ComponentRecord {
    components
        .iter()
        .find(|component| {
            component.kind == kind && metadata(component, "structuralLocation") == Some(location)
        })
        .unwrap()
        .clone()
}

fn metadata<'a>(component: &'a ComponentRecord, key: &str) -> Option<&'a str> {
    component
        .metadata
        .iter()
        .find_map(|(candidate, value)| (candidate == key).then_some(value.as_str()))
}

fn metadata_mut<'a>(component: &'a mut ComponentRecord, key: &str) -> &'a mut String {
    component
        .metadata
        .iter_mut()
        .find_map(|(candidate, value)| (candidate == key).then_some(value))
        .unwrap()
}

fn test_digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest(Sha256::digest(bytes).into())
}

fn test_file_digest(path: &Path) -> Sha256Digest {
    test_digest(&fs::read(path).unwrap())
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

fn validation_receipt() -> ApplyReceipt {
    let device_id = DeviceId::from_str(DEVICE_ID).unwrap();
    ApplyReceipt {
        plan_id: PlanId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073984").unwrap(),
        applied_hlc: HybridLogicalClock::new(1_900_000_000_001, 0, device_id),
        resulting_digests: vec![],
    }
}

fn hermes_native_plan(
    fixture: &Fixture,
    approval_class: ApprovalClass,
    expected_native_digests: Vec<ExpectedNativeDigest>,
) -> NativeTransactionPlan {
    clear_gateway_records(fixture);
    let imported = import_global(fixture);
    let mut plugin = component_at(
        &imported.components,
        ComponentKind::Plugin,
        "config:plugins.enabled.reviewer",
    );
    plugin.archived = true;
    let mutation = fixture
        .adapter
        .plan_native_config(&desired_global(fixture, vec![plugin]))
        .unwrap()
        .unwrap();
    NativeTransactionPlan {
        setup: SetupPlan {
            plan_id: validation_receipt().plan_id,
            harness: HarnessId::Hermes,
            adapter_version: 1,
            executable_path: test_wire_path(&fixture.layout.executable),
            executable_hash: test_file_digest(&fixture.layout.executable),
            harness_version: fixture.layout.version.clone(),
            target_scopes: vec![
                NativeScope::Global,
                NativeScope::Project {
                    project_id: fixture.project_id,
                    root: fixture.adapter.project_root_wire(),
                },
            ],
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
            approval_class,
            expires_at: 2_000_000_000_000,
            batch_hash: Sha256Digest([23; 32]),
        },
        approval_version: 1,
        helper_policy_version: 1,
        manifest_schema_version: 1,
        manifest_digest: Sha256Digest([24; 32]),
        helper_hash: Sha256Digest([25; 32]),
        sidecars: Vec::<SidecarBinding>::new(),
        structural_allowlist_hash: Sha256Digest([26; 32]),
        staged_inputs: vec![],
        expected_semantic_output_hash: Sha256Digest([27; 32]),
        scanner_result_hash: Sha256Digest([28; 32]),
        mutations: vec![mutation],
        cli_mutations: vec![],
        ownership_changes: vec![],
    }
}

struct RollbackExecutor {
    run: RestrictedRun,
}

impl RestrictedExecutor for RollbackExecutor {
    fn copy_allowlisted_inputs(&mut self, _inputs: &[ApprovedInput]) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn create_fake_roots(&mut self) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn build_restricted_environment(&mut self) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn run_restricted_tools(
        &mut self,
        _sidecars: &[SidecarBinding],
    ) -> Result<RestrictedRun, BoundaryError> {
        Ok(self.run.clone())
    }

    fn reject_unsafe_topology(&mut self) -> Result<(), BoundaryError> {
        Ok(())
    }
}

#[derive(Default)]
struct RollbackJournal {
    compensated: bool,
    restored_candidates: usize,
}

impl NativeJournal for RollbackJournal {
    fn acquire_lock_and_begin(
        &mut self,
        _plan: &NativeTransactionPlan,
    ) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn enter_step(&mut self, _step: TransactionStep) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn complete_step(&mut self, _step: TransactionStep) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn put_before_images(&mut self, _images: &[BeforeImage]) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn prepare_mutation(
        &mut self,
        _index: usize,
        _mutation: &ApprovedMutation,
    ) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn mark_mutation_applied(
        &mut self,
        _index: usize,
        _mutation: &ApprovedMutation,
        _outcome: &MutationOutcome,
        _applied_token: Option<&NativeObjectToken>,
    ) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn record_mutation_candidate(
        &mut self,
        _index: usize,
        _mutation: &ApprovedMutation,
        _candidate_token: &NativeObjectToken,
    ) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn mark_mutation_conflict(
        &mut self,
        _index: usize,
        _applied_token: &NativeObjectToken,
    ) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn mark_mutation_applied_for_recovery(
        &mut self,
        _index: usize,
        _mutation: &ApprovedMutation,
        _applied_token: &NativeObjectToken,
    ) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn record_mutation_restored_candidate(
        &mut self,
        _index: usize,
        _candidate_token: &NativeObjectToken,
    ) -> Result<(), BoundaryError> {
        self.restored_candidates += 1;
        Ok(())
    }

    fn checkpoint_mutation_applied_absence(
        &mut self,
        _index: usize,
        _later_index: usize,
        _expected_old_token: &NativeObjectToken,
        _new_token: &NativeObjectToken,
    ) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn rebind_mutation_applied_absence(
        &mut self,
        _index: usize,
        _later_index: usize,
        _expected_old_token: &NativeObjectToken,
        _new_token: &NativeObjectToken,
    ) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn prepare_compensation(&mut self) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn commit_native_transaction(
        &mut self,
        _plan: &NativeTransactionPlan,
        _receipt: &NativeApplyReceipt,
    ) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn finish_committed(&mut self) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn finish_compensated(
        &mut self,
        _conflict_target_sequences: &[u32],
    ) -> Result<(), BoundaryError> {
        self.compensated = true;
        Ok(())
    }
}

#[derive(Default)]
struct FailAfterPayloadWrites {
    injected: bool,
}

impl FaultHook for FailAfterPayloadWrites {
    fn after_step(&mut self, step: TransactionStep) -> Result<(), BoundaryError> {
        if step == TransactionStep::WritePayloads {
            self.injected = true;
            Err(BoundaryError::new("injected after Hermes payload writes"))
        } else {
            Ok(())
        }
    }
}

#[cfg(unix)]
fn gateway_lock_available(path: &Path) -> bool {
    use std::{fs::OpenOptions, os::fd::AsRawFd as _};

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .unwrap();
    let acquired = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0;
    if acquired {
        assert_eq!(unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) }, 0);
    }
    acquired
}

#[cfg(unix)]
struct GatewayReservationHook {
    lock_path: PathBuf,
    fail_after: Option<TransactionStep>,
    blocked_after_reprobe: bool,
}

#[cfg(unix)]
impl FaultHook for GatewayReservationHook {
    fn after_step(&mut self, step: TransactionStep) -> Result<(), BoundaryError> {
        if step == TransactionStep::ReprobeLiveState {
            self.blocked_after_reprobe = !gateway_lock_available(&self.lock_path);
        }
        if self.fail_after == Some(step) {
            Err(BoundaryError::new("injected after gateway reservation"))
        } else {
            Ok(())
        }
    }
}

#[cfg(unix)]
#[test]
fn active_transaction_holds_gateway_lock_until_commit_or_compensation_finishes() {
    for fail_after in [None, Some(TransactionStep::CompareApprovedDigests)] {
        let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
        let mut plan = hermes_native_plan(&fixture, ApprovalClass::Active, vec![]);
        plan.mutations.clear();
        plan.sidecars = vec![SidecarBinding {
            id: SidecarId::RuleSync,
            target: RuntimeTarget::MacosArm64,
            version: plan.setup.rulesync_version.clone(),
            closure_hash: Sha256Digest([45; 32]),
            source_bundle_hash: Sha256Digest([46; 32]),
            build_toolchain_hash: Sha256Digest([47; 32]),
            command_template_digest: Sha256Digest([48; 32]),
            command: SidecarCommand::RuleSyncGenerate {
                target: RuleSyncTarget::CodexCli,
                features: RuleSyncFeatures::new(&[RuleSyncFeature::Rules]).unwrap(),
            },
        }];
        plan.setup.batch_hash = approval_hash_v1(&plan).unwrap();
        let nonce = *plan.setup.plan_id.as_bytes();
        let lock_path = fixture.layout.profile.hermes_home.join("gateway.lock");
        let mut adapter = fixture.adapter.clone();
        let mut executor = RollbackExecutor {
            run: RestrictedRun {
                staged_output_hash: plan.expected_semantic_output_hash,
                scanner_result_hash: plan.scanner_result_hash,
            },
        };
        let mut native = OsNativeTransactionFileSystem::new(nonce);
        let mut journal = RollbackJournal::default();
        let mut hook = GatewayReservationHook {
            lock_path: lock_path.clone(),
            fail_after,
            blocked_after_reprobe: false,
        };

        let result = NativeTransactionEngine::new(
            &mut adapter,
            &mut executor,
            &mut native,
            &mut journal,
            &mut hook,
        )
        .apply(&plan, 1_900_000_000_000, validation_receipt().applied_hlc);

        assert_eq!(
            result.is_err(),
            fail_after.is_some(),
            "unexpected transaction result: {result:?}"
        );
        assert!(hook.blocked_after_reprobe);
        assert!(gateway_lock_available(&lock_path));
    }
}

#[test]
fn yaml_patch_preserves_unowned_bytes_comments_order_and_scalar_style() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    clear_gateway_records(&fixture);
    let source = concat!(
        "# root comment\r\n",
        "unknown_root: 'preserve-single-quotes'\r\n",
        "approvals:\r\n",
        "  timeout: 1\r\n",
        "plugins:\r\n",
        "  unknown_child: preserve-me\r\n",
        "  enabled:\r\n",
        "    - reviewer\r\n",
        "  disabled:\r\n",
        "    - legacy\r\n",
        "mcp_servers:\r\n",
        "  docs:\r\n",
        "    url: https://example.com/mcp\r\n",
        "    sibling: 'keep-style'\r\n",
        "hooks:\r\n",
        "  shell:\r\n",
        "    enabled: true\r\n",
    );
    fs::write(
        fixture.layout.profile.hermes_home.join("config.yaml"),
        source,
    )
    .unwrap();
    let imported = import_global(&fixture);
    let mut permission = component_at(
        &imported.components,
        ComponentKind::PermissionDeclaration,
        "config:approvals.timeout",
    );
    permission.body_markdown = "2".into();
    let mut plugin = component_at(
        &imported.components,
        ComponentKind::Plugin,
        "config:plugins.enabled.reviewer",
    );
    plugin.archived = true;
    let desired = desired_global(&fixture, vec![permission, plugin]);
    let mutation = fixture
        .adapter
        .plan_native_config(&desired)
        .unwrap()
        .unwrap();
    let rendered = String::from_utf8(intended_bytes(&mutation)).unwrap();

    for unchanged in [
        "# root comment\r\n",
        "unknown_root: 'preserve-single-quotes'\r\n",
        "  unknown_child: preserve-me\r\n",
        "    url: https://example.com/mcp\r\n",
        "    sibling: 'keep-style'\r\n",
    ] {
        assert!(
            rendered.contains(unchanged),
            "lost exact bytes: {unchanged:?}"
        );
    }
    assert!(rendered.contains("  timeout: 2\r\n"));
    assert!(!rendered.replace("\r\n", "").contains('\n'));
    assert!(rendered.contains("  disabled:\r\n    - legacy\r\n    - reviewer\r\n"));
}

#[test]
fn semantic_noop_produces_no_rendered_file_or_mutation() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    clear_gateway_records(&fixture);
    let imported = import_global(&fixture);
    let desired = desired_global(&fixture, imported.components.clone());
    assert!(fixture.adapter.render(&desired).unwrap().files.is_empty());
    assert!(
        fixture
            .adapter
            .plan_native_config(&desired)
            .unwrap()
            .is_none()
    );

    let soul = component_at(&imported.components, ComponentKind::Rule, "profile:SOUL.md");
    assert!(
        fixture
            .adapter
            .plan_native_markdown(&soul)
            .unwrap()
            .is_none()
    );
    for memory in fixture.adapter.import_native_memory().unwrap() {
        assert!(
            fixture
                .adapter
                .plan_native_memory(memory.kind, &memory.body_markdown)
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn managed_markdown_and_memory_preserve_unmanaged_bytes() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    clear_gateway_records(&fixture);
    let imported = import_global(&fixture);
    let mut soul = component_at(&imported.components, ComponentKind::Rule, "profile:SOUL.md");
    let soul_path = fixture.layout.profile.hermes_home.join("SOUL.md");
    fs::write(
        &soul_path,
        "user prefix\r\n<!-- context-relay:start -->\r\nold\r\n<!-- context-relay:end -->\r\nuser suffix\r\n",
    )
    .unwrap();
    soul.body_markdown = "new managed".into();
    let mutation = fixture
        .adapter
        .plan_native_markdown(&soul)
        .unwrap()
        .unwrap();
    assert_eq!(
        String::from_utf8(intended_bytes(&mutation)).unwrap(),
        "user prefix\r\n<!-- context-relay:start -->\r\nnew managed\r\n<!-- context-relay:end -->\r\nuser suffix\r\n"
    );

    soul.archived = true;
    let mutation = fixture
        .adapter
        .plan_native_markdown(&soul)
        .unwrap()
        .unwrap();
    assert_eq!(
        String::from_utf8(intended_bytes(&mutation)).unwrap(),
        "user prefix\r\nuser suffix\r\n"
    );

    let memory_path = fixture
        .layout
        .profile
        .hermes_home
        .join("memories/MEMORY.md");
    fs::write(
        &memory_path,
        "memory prefix\n<!-- context-relay:start -->\nold\n<!-- context-relay:end -->\nmemory suffix\n",
    )
    .unwrap();
    let mutation = fixture
        .adapter
        .plan_native_memory(HermesMemoryKind::Agent, "new memory")
        .unwrap()
        .unwrap();
    assert_eq!(
        String::from_utf8(intended_bytes(&mutation)).unwrap(),
        "memory prefix\n<!-- context-relay:start -->\nnew memory\n<!-- context-relay:end -->\nmemory suffix\n"
    );

    for malformed in [
        "<!-- context-relay:start -->\na\n<!-- context-relay:start -->\nb\n<!-- context-relay:end -->\n",
        "<!-- context-relay:start -->\na\n<!-- context-relay:end -->\n<!-- context-relay:end -->\n",
        "<!-- context-relay:start -->\na\n",
        "a\n<!-- context-relay:end -->\n",
        "<!-- context-relay:end -->\na\n<!-- context-relay:start -->\n",
    ] {
        fs::write(&soul_path, malformed).unwrap();
        let error = fixture.adapter.plan_native_markdown(&soul).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidRequest);
    }
}

#[test]
fn primary_memory_hermes_markdown_handles_crlf_replacement_archive_and_absence() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    clear_gateway_records(&fixture);
    let device_id = DeviceId::from_str(DEVICE_ID).unwrap();
    let mut managed = primary_memory_instruction_component(
        HarnessId::Hermes,
        fixture.project_id,
        device_id,
        HybridLogicalClock::new(1_900_000_000_000, 0, device_id),
    )
    .unwrap();
    let path = fixture.layout.project_root.join(".hermes.md");
    fs::write(
        &path,
        b"user prefix\r\n<!-- context-relay:start -->\r\nold\r\n<!-- context-relay:end -->\r\nuser suffix\r\n",
    )
    .unwrap();

    let mutation = fixture
        .adapter
        .plan_native_markdown(&managed)
        .unwrap()
        .unwrap();
    let expected = format!(
        "user prefix\r\n<!-- context-relay:start -->\r\n{}<!-- context-relay:end -->\r\nuser suffix\r\n",
        PRIMARY_MEMORY_INSTRUCTIONS.replace('\n', "\r\n")
    );
    assert_eq!(intended_bytes(&mutation), expected.as_bytes());

    fs::write(&path, expected.as_bytes()).unwrap();
    assert!(
        fixture
            .adapter
            .plan_native_markdown(&managed)
            .unwrap()
            .is_none()
    );

    managed.archived = true;
    let archived = fixture
        .adapter
        .plan_native_markdown(&managed)
        .unwrap()
        .unwrap();
    assert_eq!(intended_bytes(&archived), b"user prefix\r\nuser suffix\r\n");

    fs::remove_file(&path).unwrap();
    managed.archived = false;
    let created = fixture
        .adapter
        .plan_native_markdown(&managed)
        .unwrap()
        .unwrap();
    let created_bytes = intended_bytes(&created);
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

    let nonce = [43; 16];
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
    let archived = fixture
        .adapter
        .plan_native_markdown(&managed)
        .unwrap()
        .unwrap();
    let archived_bytes = intended_bytes(&archived);
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
fn redacted_or_secret_bearing_desired_state_cannot_render() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    clear_gateway_records(&fixture);
    let imported = import_global(&fixture);
    let template = component_at(
        &imported.components,
        ComponentKind::McpServer,
        "config:mcp_servers.docs",
    );
    for rejected in [
        "<redacted>",
        "ghp_must-not-render-token",
        "-----BEGIN PRIVATE KEY----- must-not-render-private",
        "Authorization: Bearer must-not-render-authorization",
        "https://user:must-not-render-password@example.com/mcp",
    ] {
        let mut component = template.clone();
        component.body_markdown = serde_json::to_string(&serde_json::json!({
            "command": rejected,
            "enabled": true
        }))
        .unwrap();
        let desired = desired_global(&fixture, vec![component]);
        let error = fixture.adapter.render(&desired).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidRequest);
        assert!(!format!("{error:?}").contains(rejected));
    }
}

#[test]
fn unsupported_permission_mappings_are_visible_in_probe_and_preview() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let report = probe(&fixture.adapter, Some("coder"));
    assert_eq!(
        report.policy_conflicts,
        vec![
            "approval_mode_not_portable".to_owned(),
            "deny_pattern_not_portable".to_owned(),
            "gateway_state_stale".to_owned(),
            "permanent_allowlist_not_portable".to_owned(),
        ]
    );
    let classified = fixture
        .adapter
        .classify(&SemanticDiff {
            changes: vec![
                ClassifiedChange {
                    class: ChangeClass::Update,
                    target:
                        "hermes-permission|coder|lossy|approvals.mode|approval_mode_not_portable"
                            .into(),
                    summary: "must-not-preview-native-value".into(),
                },
                ClassifiedChange {
                    class: ChangeClass::Update,
                    target: "hermes-permission|coder|exact|approvals.mode|-".into(),
                    summary: "exact native change".into(),
                },
            ],
            conflicts: vec![],
        })
        .unwrap();
    assert_eq!(classified.0[0].class, ChangeClass::Conflict);
    assert_eq!(
        classified.0[0].summary,
        "lossy Hermes permission mapping: approval_mode_not_portable"
    );
    assert!(
        !classified.0[0]
            .summary
            .contains("must-not-preview-native-value")
    );
    assert_eq!(classified.0[1].class, ChangeClass::Update);
}

#[test]
fn unresolved_lossy_permission_change_cannot_render_or_plan() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    clear_gateway_records(&fixture);
    let before = fs::read(fixture.layout.profile.hermes_home.join("config.yaml")).unwrap();
    let imported = import_global(&fixture);
    let mut lossy = component_at(
        &imported.components,
        ComponentKind::PermissionDeclaration,
        "config:approvals.mode",
    );
    lossy.body_markdown = "\"manual\"".into();
    let desired = desired_global(&fixture, vec![lossy]);
    assert_eq!(
        fixture.adapter.render(&desired).unwrap_err().code,
        ErrorCode::Conflict
    );
    assert_eq!(
        fixture
            .adapter
            .plan_native_config(&desired)
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert_eq!(
        fs::read(fixture.layout.profile.hermes_home.join("config.yaml")).unwrap(),
        before
    );
}

#[test]
fn caller_cannot_downgrade_native_lossy_permission_metadata() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    clear_gateway_records(&fixture);
    let imported = import_global(&fixture);
    let mut permission = component_at(
        &imported.components,
        ComponentKind::PermissionDeclaration,
        "config:approvals.mode",
    );
    permission.body_markdown = "\"manual\"".into();
    *metadata_mut(&mut permission, "mappingFidelity") = "exact".into();
    let desired = desired_global(&fixture, vec![permission]);

    for error in [
        fixture.adapter.render(&desired).unwrap_err(),
        fixture.adapter.plan_native_config(&desired).unwrap_err(),
    ] {
        assert_eq!(error.code, ErrorCode::Conflict);
        let diagnostic = format!("{error:?}");
        assert!(!diagnostic.contains("smart"));
        assert!(!diagnostic.contains("manual"));
    }
}

#[test]
fn caller_cannot_remove_native_redaction_metadata() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    clear_gateway_records(&fixture);
    let config_path = fixture.layout.profile.hermes_home.join("config.yaml");
    let config = fs::read_to_string(&config_path).unwrap().replace(
        "    post_tool:\n      command: check-write\n",
        "    token: must-not-import-hook-token\n    post_tool:\n      command: check-write\n",
    );
    fs::write(config_path, config).unwrap();
    let imported = import_global(&fixture);

    for (kind, location) in [
        (ComponentKind::McpServer, "config:mcp_servers.docs"),
        (ComponentKind::Hook, "config:hooks.shell"),
    ] {
        let mut component = component_at(&imported.components, kind, location);
        assert_eq!(metadata(&component, "redacted"), Some("true"));
        component
            .metadata
            .retain(|(key, _)| key.as_str() != "redacted");
        let mut body: Value = serde_json::from_str(&component.body_markdown).unwrap();
        body.as_object_mut()
            .unwrap()
            .insert("enabled".into(), Value::Bool(false));
        component.body_markdown = serde_json::to_string(&body).unwrap();
        let desired = desired_global(&fixture, vec![component]);

        for error in [
            fixture.adapter.render(&desired).unwrap_err(),
            fixture.adapter.plan_native_config(&desired).unwrap_err(),
        ] {
            assert!(matches!(
                error.code,
                ErrorCode::InvalidRequest | ErrorCode::Conflict
            ));
            let diagnostic = format!("{error:?}");
            assert!(!diagnostic.contains("must-not-import"));
            assert!(!diagnostic.contains("must-not-render"));
        }
    }
}

#[test]
fn caller_security_metadata_mismatches_fail_closed_without_native_values() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    clear_gateway_records(&fixture);
    let imported = import_global(&fixture);
    let template = component_at(
        &imported.components,
        ComponentKind::PermissionDeclaration,
        "config:approvals.mode",
    );

    for (key, value) in [
        ("mappingFidelity", "exact"),
        ("mappingReason", "must-not-render-reason"),
        ("nativePermissionPath", "approvals.deny"),
        ("profile", "writer"),
        ("structuralLocation", "config:approvals.deny"),
    ] {
        let mut permission = template.clone();
        *metadata_mut(&mut permission, key) = value.into();
        permission.body_markdown = "\"manual\"".into();
        let desired = desired_global(&fixture, vec![permission]);

        for error in [
            fixture.adapter.render(&desired).unwrap_err(),
            fixture.adapter.plan_native_config(&desired).unwrap_err(),
        ] {
            assert!(matches!(
                error.code,
                ErrorCode::InvalidRequest | ErrorCode::Conflict
            ));
            let diagnostic = format!("{error:?}");
            assert!(!diagnostic.contains("smart"));
            assert!(!diagnostic.contains("manual"));
            assert!(!diagnostic.contains("must-not-render-reason"));
        }
    }
}

#[test]
fn plugin_semantic_noop_preserves_native_sequence_order() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    clear_gateway_records(&fixture);
    let config_path = fixture.layout.profile.hermes_home.join("config.yaml");
    let source = "plugins:\n  enabled:\n    - zeta\n    - alpha\n";
    fs::write(&config_path, source).unwrap();
    let imported = import_global(&fixture);
    let plugins = imported
        .components
        .into_iter()
        .filter(|component| component.kind == ComponentKind::Plugin)
        .collect();
    let desired = desired_global(&fixture, plugins);

    assert!(fixture.adapter.render(&desired).unwrap().files.is_empty());
    assert!(
        fixture
            .adapter
            .plan_native_config(&desired)
            .unwrap()
            .is_none()
    );
    assert_eq!(fs::read_to_string(config_path).unwrap(), source);
}

#[test]
fn conflicting_plugin_membership_is_importable_but_unpatchable() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    clear_gateway_records(&fixture);
    let config_path = fixture.layout.profile.hermes_home.join("config.yaml");
    fs::write(
        config_path,
        "plugins:\n  enabled:\n    - ambiguous-plugin\n  disabled:\n    - ambiguous-plugin\n",
    )
    .unwrap();

    let imported = import_global(&fixture);
    let conflicting = imported
        .components
        .iter()
        .filter(|component| {
            component.kind == ComponentKind::Plugin && component.name == "ambiguous-plugin"
        })
        .collect::<Vec<_>>();
    assert_eq!(conflicting.len(), 2);
    assert!(conflicting.iter().any(|component| {
        metadata(component, "structuralLocation") == Some("config:plugins.enabled.ambiguous-plugin")
            && !component.archived
    }));
    assert!(conflicting.iter().any(|component| {
        metadata(component, "structuralLocation")
            == Some("config:plugins.disabled.ambiguous-plugin")
            && component.archived
    }));

    let desired = desired_global(&fixture, imported.components);
    let report = probe(&fixture.adapter, Some("coder"));
    let render_error = fixture.adapter.render(&desired).unwrap_err();
    let plan_error = fixture.adapter.plan_native_config(&desired).unwrap_err();

    assert_eq!(report.capability, CapabilityLevel::ImportOnly);
    for error in [render_error, plan_error] {
        assert_eq!(error.code, ErrorCode::HarnessUnsupported);
        assert!(!format!("{error:?}").contains("ambiguous-plugin"));
    }
}

#[test]
fn duplicate_enabled_plugin_membership_is_importable_but_unpatchable() {
    assert_same_list_duplicate_is_unpatchable("enabled", false);
}

#[test]
fn duplicate_disabled_plugin_membership_is_importable_but_unpatchable() {
    assert_same_list_duplicate_is_unpatchable("disabled", true);
}

fn assert_same_list_duplicate_is_unpatchable(state: &str, archived: bool) {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    clear_gateway_records(&fixture);
    let plugin_name = format!("{state}-duplicate");
    let config_path = fixture.layout.profile.hermes_home.join("config.yaml");
    fs::write(
        config_path,
        format!("plugins:\n  {state}:\n    - {plugin_name}\n    - {plugin_name}\n"),
    )
    .unwrap();

    let imported = import_global(&fixture);
    let location = format!("config:plugins.{state}.{plugin_name}");
    let duplicates = imported
        .components
        .iter()
        .filter(|component| {
            component.kind == ComponentKind::Plugin
                && component.name == plugin_name
                && metadata(component, "structuralLocation") == Some(location.as_str())
                && component.archived == archived
        })
        .count();
    assert_eq!(duplicates, 2);

    let desired = desired_global(&fixture, imported.components);
    let report = probe(&fixture.adapter, Some("coder"));
    let render_error = fixture.adapter.render(&desired).unwrap_err();
    let plan_error = fixture.adapter.plan_native_config(&desired).unwrap_err();

    assert_eq!(report.capability, CapabilityLevel::ImportOnly);
    for error in [render_error, plan_error] {
        assert_eq!(error.code, ErrorCode::HarnessUnsupported);
        assert!(!format!("{error:?}").contains(&plugin_name));
    }
}

#[test]
fn plugin_toggle_preserves_retained_order_and_appends_deterministically() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    clear_gateway_records(&fixture);
    let config_path = fixture.layout.profile.hermes_home.join("config.yaml");
    fs::write(
        &config_path,
        "plugins:\n  enabled:\n    - zeta\n    - alpha\n    - middle\n    - beta\n  disabled:\n    - omega\n    - old\n",
    )
    .unwrap();
    let imported = import_global(&fixture);
    let mut zeta = component_at(
        &imported.components,
        ComponentKind::Plugin,
        "config:plugins.enabled.zeta",
    );
    zeta.archived = true;
    let mut alpha = component_at(
        &imported.components,
        ComponentKind::Plugin,
        "config:plugins.enabled.alpha",
    );
    alpha.archived = true;
    let mut old = component_at(
        &imported.components,
        ComponentKind::Plugin,
        "config:plugins.disabled.old",
    );
    old.archived = false;
    let mutation = fixture
        .adapter
        .plan_native_config(&desired_global(&fixture, vec![zeta, old, alpha]))
        .unwrap()
        .unwrap();
    let rendered = String::from_utf8(intended_bytes(&mutation)).unwrap();

    assert!(rendered.contains("  enabled:\n    - middle\n    - beta\n    - old\n"));
    assert!(rendered.contains("  disabled:\n    - omega\n    - alpha\n    - zeta\n"));
}

#[test]
fn plugin_enabled_inserts_under_existing_parent_without_replacing_unknown_children() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    clear_gateway_records(&fixture);
    let config_path = fixture.layout.profile.hermes_home.join("config.yaml");
    fs::write(
        &config_path,
        "plugins:\n  # keep this comment\n  unknown_child: preserve-me\n",
    )
    .unwrap();
    let imported = import_global(&fixture);
    let mut plugin = component_at(
        &imported.components,
        ComponentKind::Plugin,
        "profile:plugins/reviewer/plugin.yaml",
    );
    plugin.metadata.retain(|(key, _)| {
        !matches!(
            key.as_str(),
            "structuralLocation" | "nativeFormat" | "enabled"
        )
    });
    plugin.metadata.extend([
        (
            "structuralLocation".into(),
            "config:plugins.enabled.reviewer".into(),
        ),
        ("nativeFormat".into(), "json".into()),
        ("enabled".into(), "true".into()),
    ]);
    plugin.metadata.sort();
    plugin.archived = false;
    let desired = desired_global(&fixture, vec![plugin]);
    let mutation = fixture
        .adapter
        .plan_native_config(&desired)
        .unwrap()
        .unwrap();
    let rendered = String::from_utf8(intended_bytes(&mutation)).unwrap();

    assert!(rendered.contains("  # keep this comment\n  unknown_child: preserve-me\n"));
    assert!(rendered.contains("  enabled:\n    - reviewer\n"));
}

#[test]
fn plugin_manifests_preserve_enabled_disabled_and_discovered_states() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    clear_gateway_records(&fixture);
    let plugins = fixture.layout.profile.hermes_home.join("plugins");
    for (name, body) in [
        (
            "legacy",
            "name: legacy\nversion: 0.9.0\ndescription: Disabled plugin.\n",
        ),
        (
            "observer",
            "name: observer\nversion: 1.0.0\ndescription: Discovered plugin.\n",
        ),
    ] {
        fs::create_dir_all(plugins.join(name)).unwrap();
        fs::write(plugins.join(name).join("plugin.yaml"), body).unwrap();
    }

    let imported = import_global(&fixture);
    let manifest = |name: &str| {
        imported
            .components
            .iter()
            .find(|component| {
                component.kind == ComponentKind::Plugin
                    && component.name == name
                    && metadata(component, "manifest") == Some("true")
            })
            .unwrap()
    };
    let enabled = manifest("reviewer");
    let disabled = manifest("legacy");
    let discovered = manifest("observer");

    assert_eq!(metadata(enabled, "pluginState"), Some("enabled"));
    assert_eq!(metadata(enabled, "enabled"), Some("true"));
    assert!(!enabled.archived);
    assert_eq!(metadata(disabled, "pluginState"), Some("disabled"));
    assert_eq!(metadata(disabled, "enabled"), Some("false"));
    assert!(disabled.archived);
    assert_eq!(metadata(discovered, "pluginState"), Some("discovered"));
    assert_eq!(metadata(discovered, "enabled"), Some("false"));
    assert!(discovered.archived);
    assert!(enabled.body_markdown.contains("name: reviewer"));
    assert!(disabled.body_markdown.contains("name: legacy"));
    assert!(discovered.body_markdown.contains("name: observer"));

    let desired = desired_global(&fixture, vec![discovered.clone()]);
    assert!(fixture.adapter.render(&desired).unwrap().files.is_empty());
    assert!(
        fixture
            .adapter
            .plan_native_config(&desired)
            .unwrap()
            .is_none()
    );
}

#[test]
fn live_selected_profile_gateway_blocks_every_active_change() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let profile = &fixture.layout.profile.hermes_home;
    fs::write(profile.join("gateway.pid"), b"{malformed").unwrap();
    fs::remove_file(profile.join("gateway_state.json")).unwrap();
    assert!(
        probe(&fixture.adapter, Some("coder"))
            .policy_conflicts
            .contains(&"gateway_state_unverifiable".to_owned())
    );
    let imported = import_global(&fixture);
    let config_components = imported
        .components
        .iter()
        .filter(|component| {
            metadata(component, "structuralLocation")
                .is_some_and(|location| location.starts_with("config:"))
        })
        .cloned()
        .collect::<Vec<_>>();
    let desired = desired_global(&fixture, config_components);
    assert_eq!(
        fixture.adapter.render(&desired).unwrap_err().code,
        ErrorCode::Conflict
    );
    assert_eq!(
        fixture
            .adapter
            .plan_native_config(&desired)
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );

    let manifest = component_at(
        &imported.components,
        ComponentKind::Hook,
        "profile:hooks/audit/HOOK.yaml",
    );
    let handler = component_at(
        &imported.components,
        ComponentKind::Hook,
        "profile:hooks/audit/handler.py",
    );
    assert_eq!(
        fixture
            .adapter
            .plan_native_gateway_hook(&manifest, Some(&handler))
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );

    let mut soul = component_at(&imported.components, ComponentKind::Rule, "profile:SOUL.md");
    soul.body_markdown.push_str("\nPassive update.");
    assert!(
        fixture
            .adapter
            .plan_native_markdown(&soul)
            .unwrap()
            .is_some()
    );
    assert!(
        fixture
            .adapter
            .plan_native_memory(HermesMemoryKind::Agent, "Passive memory update.")
            .unwrap()
            .is_some()
    );
    let passive = fixture
        .adapter
        .classify(&SemanticDiff {
            changes: vec![ClassifiedChange {
                class: ChangeClass::Update,
                target: "hermes-markdown|coder|profile:SOUL.md".into(),
                summary: "passive Markdown update".into(),
            }],
            conflicts: vec![],
        })
        .unwrap();
    assert_eq!(passive.0[0].class, ChangeClass::Update);
    assert!(passive.0[0].summary.contains("frozen_session_snapshot"));
    assert!(
        probe(&fixture.adapter, Some("coder"))
            .policy_conflicts
            .contains(&"frozen_session_snapshot".to_owned())
    );
}

#[test]
fn other_profile_gateway_does_not_block_selected_profile() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    clear_gateway_records(&fixture);
    fs::write(
        fixture.profiles_root.join("writer/gateway.pid"),
        b"{malformed",
    )
    .unwrap();
    let imported = import_global(&fixture);
    let mut permission = component_at(
        &imported.components,
        ComponentKind::PermissionDeclaration,
        "config:approvals.mode",
    );
    permission.body_markdown = permission.body_markdown.clone();
    let desired = desired_global(&fixture, vec![permission]);
    assert!(
        fixture
            .adapter
            .plan_native_config(&desired)
            .unwrap()
            .is_none()
    );
}

#[test]
fn stale_dead_gateway_is_nonblocking_and_reported() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let profile = &fixture.layout.profile.hermes_home;
    let stale = r#"{"pid":999999,"kind":"hermes-gateway","argv":["hermes","gateway","run","--profile","coder"],"start_time":1}"#;
    let stale_runtime = r#"{"pid":999999,"kind":"hermes-gateway","argv":["hermes","gateway","run","--profile","coder"],"start_time":1,"gateway_state":"running","exit_reason":null,"restart_requested":false,"active_agents":0,"platforms":{},"updated_at":"2026-07-07T12:00:00+00:00"}"#;
    fs::write(profile.join("gateway.pid"), stale).unwrap();
    fs::write(profile.join("gateway_state.json"), stale_runtime).unwrap();
    let imported = import_global(&fixture);
    let mut exact = component_at(
        &imported.components,
        ComponentKind::PermissionDeclaration,
        "config:approvals.deny",
    );
    exact.body_markdown = exact.body_markdown.clone();
    let desired = desired_global(&fixture, vec![exact]);
    assert!(
        fixture
            .adapter
            .plan_native_config(&desired)
            .unwrap()
            .is_none()
    );
    assert!(
        probe(&fixture.adapter, Some("coder"))
            .policy_conflicts
            .contains(&"gateway_state_stale".to_owned())
    );
}

#[test]
fn malformed_recycled_or_foreign_gateway_state_blocks_active_apply() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let profile = &fixture.layout.profile.hermes_home;
    let imported = import_global(&fixture);
    let desired = desired_global(
        &fixture,
        vec![component_at(
            &imported.components,
            ComponentKind::PermissionDeclaration,
            "config:approvals.mode",
        )],
    );
    for record in [
        "{malformed".to_owned(),
        format!(
            r#"{{"pid":{},"kind":"hermes-gateway","argv":["hermes","gateway","run","--profile","coder"],"start_time":1}}"#,
            std::process::id()
        ),
        format!(
            r#"{{"pid":{},"kind":"hermes-gateway","argv":["not-hermes","gateway","run","--profile","coder"],"start_time":1}}"#,
            std::process::id()
        ),
        format!(
            r#"{{"pid":{},"kind":"hermes-gateway","argv":["hermes","gateway","run","--profile","writer"],"start_time":1}}"#,
            std::process::id()
        ),
    ] {
        fs::write(profile.join("gateway.pid"), record).unwrap();
        if profile.join("gateway_state.json").exists() {
            fs::remove_file(profile.join("gateway_state.json")).unwrap();
        }
        assert_eq!(
            fixture
                .adapter
                .plan_native_config(&desired)
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
    }
}

#[test]
fn concurrent_native_edit_invalidates_planned_config_and_memory() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    clear_gateway_records(&fixture);
    let imported = import_global(&fixture);
    let mut plugin = component_at(
        &imported.components,
        ComponentKind::Plugin,
        "config:plugins.enabled.reviewer",
    );
    plugin.archived = true;
    let config = fixture
        .adapter
        .plan_native_config(&desired_global(&fixture, vec![plugin]))
        .unwrap()
        .unwrap();
    let memory = fixture
        .adapter
        .plan_native_memory(HermesMemoryKind::Agent, "changed memory")
        .unwrap()
        .unwrap();
    let config_path = fixture.layout.profile.hermes_home.join("config.yaml");
    let memory_path = fixture
        .layout
        .profile
        .hermes_home
        .join("memories/MEMORY.md");
    let config_before = fs::read(&config_path).unwrap();
    let memory_before = fs::read(&memory_path).unwrap();
    fs::write(&config_path, b"concurrent config").unwrap();
    fs::write(&memory_path, b"concurrent memory").unwrap();
    let mut native = OsNativeTransactionFileSystem::new([13; 16]);
    assert!(native.create_before_images(&[config]).is_err());
    let mut native = OsNativeTransactionFileSystem::new([14; 16]);
    assert!(native.create_before_images(&[memory]).is_err());
    fs::write(&config_path, &config_before).unwrap();
    fs::write(&memory_path, &memory_before).unwrap();
    assert_eq!(fs::read(&config_path).unwrap(), config_before);
    assert_eq!(fs::read(&memory_path).unwrap(), memory_before);

    let before_snapshot = OsNativeFileSystem::new().snapshot(&memory_path).unwrap();
    let rollback_mutation = fixture
        .adapter
        .plan_native_memory(HermesMemoryKind::Agent, "rollback verification memory")
        .unwrap()
        .unwrap();
    let nonce = [16; 16];
    let mut native = OsNativeTransactionFileSystem::new(nonce);
    let images = native
        .create_before_images(std::slice::from_ref(&rollback_mutation))
        .unwrap();
    native.record_native_metadata(&images).unwrap();
    native
        .compare_and_swap_targets(std::slice::from_ref(&rollback_mutation))
        .unwrap();
    native.apply_mutation(&nonce, &rollback_mutation).unwrap();
    native.restore_matching_applied_targets(&nonce).unwrap();
    let restored = OsNativeFileSystem::new().snapshot(&memory_path).unwrap();
    let (
        NativeState::RegularFile {
            bytes: before_bytes,
            metadata: before_metadata,
        },
        NativeState::RegularFile {
            bytes: restored_bytes,
            metadata: restored_metadata,
        },
    ) = (before_snapshot.state(), restored.state())
    else {
        panic!("Hermes memory remained a regular file");
    };
    assert_eq!(restored_bytes, before_bytes);
    assert_eq!(
        restored_metadata.file_attributes(),
        before_metadata.file_attributes()
    );
    assert_eq!(
        restored_metadata.creation_time(),
        before_metadata.creation_time()
    );
    assert_eq!(
        restored_metadata.last_write_time(),
        before_metadata.last_write_time()
    );
    assert_eq!(
        restored_metadata.security_descriptor(),
        before_metadata.security_descriptor()
    );
    assert_eq!(
        restored_metadata.alternate_streams(),
        before_metadata.alternate_streams()
    );
}

#[test]
fn absent_gateway_hook_files_use_a_safe_template_and_reject_concurrent_creation() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    clear_gateway_records(&fixture);
    let imported = import_global(&fixture);
    let manifest = component_at(
        &imported.components,
        ComponentKind::Hook,
        "profile:hooks/audit/HOOK.yaml",
    );
    let handler = component_at(
        &imported.components,
        ComponentKind::Hook,
        "profile:hooks/audit/handler.py",
    );
    let manifest_path = fixture
        .layout
        .profile
        .hermes_home
        .join("hooks/audit/HOOK.yaml");
    let handler_path = fixture
        .layout
        .profile
        .hermes_home
        .join("hooks/audit/handler.py");
    fs::remove_file(&manifest_path).unwrap();
    fs::remove_file(&handler_path).unwrap();
    let mutations = fixture
        .adapter
        .plan_native_gateway_hook(&manifest, Some(&handler))
        .unwrap();
    assert_eq!(mutations.len(), 2);
    assert!(mutations.iter().all(|mutation| matches!(
        NativeState::decode_v1(&mutation.content).unwrap(),
        NativeState::RegularFile { .. }
    )));
    fs::write(&manifest_path, "concurrent hook creation").unwrap();
    let manifest_mutation = mutations
        .into_iter()
        .find(|mutation| mutation.target.display.as_deref() == manifest_path.to_str())
        .unwrap();
    assert!(
        OsNativeTransactionFileSystem::new([15; 16])
            .create_before_images(&[manifest_mutation])
            .is_err()
    );
}

fn global_import_error(fixture: &Fixture) -> context_relay_protocol::ClientError {
    fixture
        .adapter
        .import(&ImportRequest {
            scopes: vec![NativeScope::Global],
            include_disabled: true,
        })
        .unwrap_err()
}

fn install_non_execution_sentinels(fixture: &Fixture) -> Vec<PathBuf> {
    let profile = &fixture.layout.profile.hermes_home;
    let mcp = fixture.root.join("mcp-ran");
    let plugin = fixture.root.join("plugin-ran");
    let hook = fixture.root.join("hook-ran");
    let config = fs::read_to_string(profile.join("config.yaml"))
        .unwrap()
        .replace(
            "command: node",
            &format!("command: \"touch {}\"", mcp.display()),
        );
    fs::write(profile.join("config.yaml"), config).unwrap();
    fs::write(
        profile.join("plugins/reviewer/plugin.py"),
        format!(
            "from pathlib import Path\nPath({:?}).touch()\n",
            plugin.to_string_lossy()
        ),
    )
    .unwrap();
    fs::write(
        profile.join("hooks/audit/handler.py"),
        format!(
            "from pathlib import Path\nPath({:?}).touch()\n",
            hook.to_string_lossy()
        ),
    )
    .unwrap();
    vec![mcp, plugin, hook]
}

#[test]
fn supported_release_fixtures_bind_one_named_profile() {
    for source in [
        include_str!("fixtures/hermes-0.18.2.json"),
        include_str!("fixtures/hermes-0.18.1.json"),
    ] {
        let fixture = fixture(source);
        let report = probe(&fixture.adapter, Some("coder"));
        assert_eq!(report.capability, CapabilityLevel::Full);
        assert_eq!(report.active_profile.as_deref(), Some("coder"));
        assert_eq!(
            report.policy_conflicts,
            vec![
                "approval_mode_not_portable".to_owned(),
                "deny_pattern_not_portable".to_owned(),
                "gateway_state_stale".to_owned(),
                "permanent_allowlist_not_portable".to_owned(),
            ]
        );
        assert_eq!(
            report.config_roots,
            vec![
                fixture.adapter.profile_home_wire(),
                fixture.adapter.project_root_wire()
            ]
        );
    }
}

#[test]
fn native_memory_capability_matrix_is_exact_for_frozen_hermes_releases() {
    for source in [
        include_str!("fixtures/hermes-0.18.2.json"),
        include_str!("fixtures/hermes-0.18.1.json"),
    ] {
        let fixture = fixture(source);
        let capabilities = fixture.adapter.native_memory_capabilities().unwrap();
        let NativeMemoryDisable::Supported(mutations) = capabilities.disable else {
            panic!("frozen native Hermes release must support native-memory disable");
        };
        assert_eq!(mutations.len(), 1);
        let rendered = String::from_utf8(intended_bytes(&mutations[0])).unwrap();
        assert!(rendered.contains("memory:\n"));
        assert!(rendered.contains("  memory_enabled: false\n"));
        assert!(rendered.contains("  user_profile_enabled: false\n"));
        assert!(rendered.contains("# profile heading"));
        assert!(rendered.contains("unknown_root: 'preserve-single-quotes'"));

        assert_eq!(capabilities.sources.len(), 2);
        assert_eq!(
            capabilities.sources[0].document_kind,
            NativeMemoryDocumentKind::Agent
        );
        assert_eq!(
            capabilities.sources[1].document_kind,
            NativeMemoryDocumentKind::UserProfile
        );
        assert_eq!(
            capabilities
                .sources
                .iter()
                .map(|source| source.path.display.clone().unwrap())
                .collect::<Vec<_>>(),
            vec![
                fixture
                    .layout
                    .profile
                    .hermes_home
                    .join("memories/MEMORY.md")
                    .display()
                    .to_string(),
                fixture
                    .layout
                    .profile
                    .hermes_home
                    .join("memories/USER.md")
                    .display()
                    .to_string(),
            ]
        );
        assert!(capabilities.sources.iter().all(|source| {
            source.scope == context_relay_protocol::ScopeRef::Global
                && source.adapter_version == fixture.layout.version
                && source.managed_fence
        }));
    }
}

#[test]
fn native_memory_disable_rolls_back_true_false_and_absent_hermes_values_exactly() {
    for (index, prior) in [Some(true), Some(false), None].into_iter().enumerate() {
        let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
        let config_path = fixture.layout.profile.hermes_home.join("config.yaml");
        let config = fs::read_to_string(&config_path).unwrap();
        let memory_block = "memory:\n  memory_enabled: true\n  user_profile_enabled: true\n";
        let config = match prior {
            Some(true) => config,
            Some(false) => config.replace(
                memory_block,
                "memory:\n  memory_enabled: false\n  user_profile_enabled: false\n",
            ),
            None => config.replace(memory_block, ""),
        };
        fs::write(&config_path, config).unwrap();
        let before = fs::read(&config_path).unwrap();
        let capabilities = fixture.adapter.native_memory_capabilities().unwrap();
        let NativeMemoryDisable::Supported(mutations) = capabilities.disable else {
            panic!("supported Hermes release must remain writable");
        };
        if prior == Some(false) {
            assert!(mutations.is_empty());
            assert_eq!(fs::read(&config_path).unwrap(), before);
            continue;
        }
        let nonce = [60 + index as u8; 16];
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
fn native_memory_hermes_unsupported_setting_is_never_synthesized() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let config_path = fixture.layout.profile.hermes_home.join("config.yaml");
    let config = fs::read_to_string(&config_path).unwrap().replace(
        "memory:\n  memory_enabled: true\n  user_profile_enabled: true\n",
        "memory:\n  memory_enabled: unsupported\n  user_profile_enabled: true\n",
    );
    fs::write(&config_path, config).unwrap();
    let before = fs::read(&config_path).unwrap();
    let capabilities = fixture.adapter.native_memory_capabilities().unwrap();
    assert!(matches!(
        capabilities.disable,
        NativeMemoryDisable::WatchOnly
    ));
    assert_eq!(capabilities.sources.len(), 2);
    assert_eq!(fs::read(config_path).unwrap(), before);
}

#[test]
fn supported_releases_import_every_reviewed_component_kind() {
    for source in [
        include_str!("fixtures/hermes-0.18.2.json"),
        include_str!("fixtures/hermes-0.18.1.json"),
    ] {
        let fixture = fixture(source);
        let imported = import_everything(&fixture, true);
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
        for name in ["reviewer", "legacy"] {
            assert!(imported.components.iter().any(|component| {
                component.kind == ComponentKind::Plugin && component.name == name
            }));
        }
        for name in ["docs", "local"] {
            assert!(imported.components.iter().any(|component| {
                component.kind == ComponentKind::McpServer && component.name == name
            }));
        }
        for (kind, name, location) in [
            (ComponentKind::Hook, "shell", "config:hooks.shell"),
            (
                ComponentKind::Hook,
                "audit",
                "profile:hooks/audit/HOOK.yaml",
            ),
            (
                ComponentKind::Hook,
                "audit/handler.py",
                "profile:hooks/audit/handler.py",
            ),
            (
                ComponentKind::Skill,
                "review",
                "profile:skills/review/SKILL.md",
            ),
        ] {
            assert!(imported.components.iter().any(|component| {
                component.kind == kind
                    && component.name == name
                    && metadata(component, "structuralLocation") == Some(location)
            }));
        }
        let permission_reasons = imported
            .components
            .iter()
            .filter(|component| component.kind == ComponentKind::PermissionDeclaration)
            .filter_map(|component| metadata(component, "mappingReason"))
            .collect::<std::collections::BTreeSet<_>>();
        assert!(permission_reasons.contains("approval_mode_not_portable"));
        assert!(permission_reasons.contains("deny_pattern_not_portable"));
        assert!(permission_reasons.contains("permanent_allowlist_not_portable"));
        for component in &imported.components {
            assert_eq!(metadata(component, "profile"), Some("coder"));
            assert!(metadata(component, "structuralLocation").is_some());
            assert!(metadata(component, "nativeFormat").is_some());
        }
    }
}

#[test]
fn import_serialization_contains_no_secret_or_operational_canary() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let imported = import_everything(&fixture, true);
    let memories = fixture.adapter.import_native_memory().unwrap();
    let serialized =
        format!("{}|{memories:?}", serde_json::to_string(&imported).unwrap()).to_ascii_lowercase();
    for excluded in [
        "must-not-import",
        "openrouter_api_key",
        "authorization",
        ".env",
        "auth.json",
        "sessions",
        "state.db",
        "gateway.pid",
        "gateway_state.json",
        "channels",
        "logs",
    ] {
        assert!(
            !serialized.contains(excluded),
            "serialized Hermes import exposed {excluded}"
        );
    }
}

#[test]
fn secret_bearing_yaml_fields_are_removed_before_component_creation() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let imported = import_everything(&fixture, true);
    let serialized = serde_json::to_string(&imported).unwrap();
    for secret in [
        "must-not-import-yaml-header",
        "must-not-import-yaml-env",
        "must-not-import-provider-key",
    ] {
        assert!(!serialized.contains(secret));
    }
    let docs = imported
        .components
        .iter()
        .find(|component| component.kind == ComponentKind::McpServer && component.name == "docs")
        .unwrap();
    assert_eq!(metadata(docs, "redacted"), Some("true"));
    assert_eq!(metadata(docs, "secretReferenceNames"), Some("HEADER_TOKEN"));
    assert!(!docs.body_markdown.contains("headers"));
    let local = imported
        .components
        .iter()
        .find(|component| component.kind == ComponentKind::McpServer && component.name == "local")
        .unwrap();
    assert_eq!(metadata(local, "redacted"), Some("true"));
    assert_eq!(metadata(local, "secretReferenceNames"), Some("DOCS_TOKEN"));
    assert!(!local.body_markdown.contains("env"));
}

#[test]
fn embedded_secret_text_is_removed_from_mcp_and_hook_components() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    fs::write(
        fixture.layout.profile.hermes_home.join("config.yaml"),
        r#"mcp_servers:
  authorization:
    command: "curl -H 'Authorization: Bearer must-not-import-mcp-authorization'"
    enabled: true
  basic:
    args:
      - "--header Basic must-not-import-mcp-basic"
    enabled: true
  private_key:
    command: "loader --value prefix-----BEGIN PRIVATE KEY-----must-not-import-mcp-private"
    enabled: true
  token:
    args:
      - "--token=prefix:ghp_must-not-import-mcp-token"
    enabled: true
  credential_url:
    url: "proxy=https://must-not-import-user:must-not-import-password@example.com/mcp"
    enabled: true
hooks:
  scalar_guard:
    enabled: true
    preflight: "runner --header 'Authorization: Bearer must-not-import-hook-authorization'"
    fallback: "runner --header Basic must-not-import-hook-basic"
    loader: "loader prefix-----BEGIN OPENSSH PRIVATE KEY-----must-not-import-hook-private"
    notifier: "runner --token=prefix:github_pat_must-not-import-hook-token"
    callback: "proxy=https://must-not-import-hook-user:must-not-import-hook-password@example.com/callback"
"#,
    )
    .unwrap();

    let imported = import_everything(&fixture, true);
    let serialized = serde_json::to_string(&imported).unwrap();
    assert!(
        !serialized.contains("must-not-import"),
        "serialized Hermes import exposed an embedded scalar canary"
    );

    for name in [
        "authorization",
        "basic",
        "private_key",
        "token",
        "credential_url",
    ] {
        let component = imported
            .components
            .iter()
            .find(|component| component.kind == ComponentKind::McpServer && component.name == name)
            .unwrap();
        assert_eq!(metadata(component, "redacted"), Some("true"));
        assert!(
            !component.body_markdown.contains("Authorization")
                && !component.body_markdown.contains("Bearer")
                && !component.body_markdown.contains("Basic")
                && !component.body_markdown.contains("PRIVATE KEY")
                && !component.body_markdown.contains("ghp_")
                && !component.body_markdown.contains('@'),
            "MCP component retained secret-like scalar text"
        );
    }

    let hook = imported
        .components
        .iter()
        .find(|component| component.kind == ComponentKind::Hook && component.name == "scalar_guard")
        .unwrap();
    assert_eq!(metadata(hook, "redacted"), Some("true"));
    assert_eq!(hook.body_markdown, r#"{"enabled":true}"#);
}

#[test]
fn mcp_credential_option_args_are_omitted_and_marked_redacted() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    fs::write(
        fixture.layout.profile.hermes_home.join("config.yaml"),
        r#"mcp_servers:
  guarded:
    command: safe-runner
    args:
      - --api-key
      - opaque-mcp-value
      - --mode
      - safe
      - "${MCP_API_KEY}"
    enabled: false
    timeout: 30
    tools:
      include:
        - safe-tool
"#,
    )
    .unwrap();

    let imported = import_everything(&fixture, true);
    let serialized = serde_json::to_string(&imported).unwrap();
    assert!(!serialized.contains("opaque-mcp-value"));
    let component = imported
        .components
        .iter()
        .find(|component| component.kind == ComponentKind::McpServer && component.name == "guarded")
        .unwrap();
    assert_eq!(metadata(component, "redacted"), Some("true"));
    assert_eq!(
        metadata(component, "secretReferenceNames"),
        Some("MCP_API_KEY")
    );
    assert_eq!(metadata(component, "enabled"), Some("false"));
    assert_eq!(
        component.body_markdown,
        r#"{"command":"safe-runner","enabled":false,"timeout":30,"tools":{"include":["safe-tool"]}}"#
    );
}

#[test]
fn hook_credential_option_command_is_omitted_and_marked_redacted() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    fs::write(
        fixture.layout.profile.hermes_home.join("config.yaml"),
        r#"hooks:
  guarded:
    command: "helper --token opaque-hook-value"
    enabled: true
    timeout: 45
    tools:
      - safe-tool
"#,
    )
    .unwrap();

    let imported = import_everything(&fixture, true);
    let serialized = serde_json::to_string(&imported).unwrap();
    assert!(!serialized.contains("opaque-hook-value"));
    let component = imported
        .components
        .iter()
        .find(|component| component.kind == ComponentKind::Hook && component.name == "guarded")
        .unwrap();
    assert_eq!(metadata(component, "redacted"), Some("true"));
    assert_eq!(
        component.body_markdown,
        r#"{"enabled":true,"timeout":45,"tools":["safe-tool"]}"#
    );
}

#[test]
fn mcp_context_redaction_preserves_embedded_placeholder_names_without_command_or_args() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    fs::write(
        fixture.layout.profile.hermes_home.join("config.yaml"),
        r#"mcp_servers:
  guarded:
    command: "helper --token ${MCP_SHARED} --secret=${MCP_COMMAND_SECRET}"
    args:
      - "--api-key=${MCP_ARGS_KEY}"
      - --client-key
      - "prefix-${MCP_CLIENT_KEY}-suffix"
      - --password
      - "${MCP_SHARED}"
    enabled: true
    timeout: 30
"#,
    )
    .unwrap();

    let imported = import_everything(&fixture, true);
    let component = imported
        .components
        .iter()
        .find(|component| component.kind == ComponentKind::McpServer && component.name == "guarded")
        .unwrap();
    assert_eq!(metadata(component, "redacted"), Some("true"));
    assert_eq!(
        metadata(component, "secretReferenceNames"),
        Some("MCP_ARGS_KEY,MCP_CLIENT_KEY,MCP_COMMAND_SECRET,MCP_SHARED")
    );
    assert_eq!(component.body_markdown, r#"{"enabled":true,"timeout":30}"#);
    assert!(!component.body_markdown.contains("helper"));
    assert!(!component.body_markdown.contains("--api-key"));
}

#[test]
fn hook_context_redaction_preserves_embedded_placeholder_names_without_command() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    fs::write(
        fixture.layout.profile.hermes_home.join("config.yaml"),
        r#"hooks:
  guarded:
    command: "helper --token ${HOOK_TOKEN} --client-key=${HOOK_CLIENT_KEY} --secret prefix-${HOOK_SECRET}-suffix --password ${HOOK_TOKEN}"
    enabled: false
    timeout: 45
"#,
    )
    .unwrap();

    let imported = import_everything(&fixture, true);
    let component = imported
        .components
        .iter()
        .find(|component| component.kind == ComponentKind::Hook && component.name == "guarded")
        .unwrap();
    assert_eq!(metadata(component, "redacted"), Some("true"));
    assert_eq!(
        metadata(component, "secretReferenceNames"),
        Some("HOOK_CLIENT_KEY,HOOK_SECRET,HOOK_TOKEN")
    );
    assert_eq!(component.body_markdown, r#"{"enabled":false,"timeout":45}"#);
    assert!(!component.body_markdown.contains("helper"));
    assert!(!component.body_markdown.contains("--token"));
}

#[test]
fn ignored_nested_mcp_command_cannot_influence_placeholder_metadata() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    fs::write(
        fixture.layout.profile.hermes_home.join("config.yaml"),
        r#"mcp_servers:
  guarded:
    command: "helper --token ${SUPPORTED_KEY}"
    enabled: true
    experimental:
      command: "ignored --api-key=${IGNORED_KEY}"
"#,
    )
    .unwrap();

    let imported = import_everything(&fixture, true);
    let component = imported
        .components
        .iter()
        .find(|component| component.kind == ComponentKind::McpServer && component.name == "guarded")
        .unwrap();
    assert_eq!(metadata(component, "redacted"), Some("true"));
    assert_eq!(
        metadata(component, "secretReferenceNames"),
        Some("SUPPORTED_KEY")
    );
    assert_eq!(component.body_markdown, r#"{"enabled":true}"#);
    assert!(
        !serde_json::to_string(&imported)
            .unwrap()
            .contains("IGNORED_KEY")
    );
}

#[test]
fn ignored_nested_mcp_args_over_context_limit_do_not_fail_import() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let ignored_arguments = (0..129)
        .map(|index| format!("        - ignored-{index}\n"))
        .collect::<String>();
    let config = format!(
        "mcp_servers:\n  guarded:\n    command: safe-runner\n    enabled: true\n    experimental:\n      args:\n{ignored_arguments}"
    );
    fs::write(
        fixture.layout.profile.hermes_home.join("config.yaml"),
        config,
    )
    .unwrap();

    let imported = import_everything(&fixture, true);
    let component = imported
        .components
        .iter()
        .find(|component| component.kind == ComponentKind::McpServer && component.name == "guarded")
        .unwrap();
    assert_eq!(metadata(component, "redacted"), None);
    assert_eq!(metadata(component, "secretReferenceNames"), None);
    assert_eq!(
        component.body_markdown,
        r#"{"command":"safe-runner","enabled":true}"#
    );
}

#[test]
fn nested_auth_structures_are_removed_from_mcp_and_hook_components() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    fs::write(
        fixture.layout.profile.hermes_home.join("config.yaml"),
        r#"mcp_servers:
  nested_auth:
    command: safe-runner
    tools:
      prompts:
        safe: safe-prompt
        oauth:
          access_token: must-not-import-mcp-access
          refresh_token: must-not-import-mcp-refresh
          client_secret: must-not-import-mcp-client
        authorization_code:
          code: must-not-import-mcp-code
        credentials:
          value: must-not-import-mcp-credential
        access_token: must-not-import-mcp-leaf-access
        refresh_token: must-not-import-mcp-leaf-refresh
        client_secret: must-not-import-mcp-leaf-client
    enabled: true
hooks:
  nested_auth:
    enabled: true
    settings:
      mode: audited
      oauth:
        access_token: must-not-import-hook-access
        refresh_token: must-not-import-hook-refresh
        client_secret: must-not-import-hook-client
      auth:
        code: must-not-import-hook-auth
      authorization_code:
        code: must-not-import-hook-code
      credentials:
        value: must-not-import-hook-credential
      access_token: must-not-import-hook-leaf-access
      refresh_token: must-not-import-hook-leaf-refresh
      client_secret: must-not-import-hook-leaf-client
"#,
    )
    .unwrap();

    let imported = import_everything(&fixture, true);
    let serialized = serde_json::to_string(&imported).unwrap();
    assert!(
        !serialized.contains("must-not-import"),
        "serialized Hermes import exposed a nested credential canary"
    );

    let mcp = imported
        .components
        .iter()
        .find(|component| {
            component.kind == ComponentKind::McpServer && component.name == "nested_auth"
        })
        .unwrap();
    assert_eq!(metadata(mcp, "redacted"), Some("true"));
    assert_eq!(
        mcp.body_markdown,
        r#"{"command":"safe-runner","enabled":true,"tools":{"prompts":{"safe":"safe-prompt"}}}"#
    );

    let hook = imported
        .components
        .iter()
        .find(|component| component.kind == ComponentKind::Hook && component.name == "nested_auth")
        .unwrap();
    assert_eq!(metadata(hook, "redacted"), Some("true"));
    assert_eq!(
        hook.body_markdown,
        r#"{"enabled":true,"settings":{"mode":"audited"}}"#
    );
}

#[test]
fn nested_exact_mcp_placeholders_are_sorted_deduplicated_and_propagated() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    fs::write(
        fixture.layout.profile.hermes_home.join("config.yaml"),
        r#"mcp_servers:
  nested_placeholders:
    command:
      oauth:
        access_token: ${COMMAND_TOKEN}
        duplicate: ${SHARED_TOKEN}
        prefixed: prefix-${PREFIXED_TOKEN}
    args:
      credentials:
        value: ${ARGS_TOKEN}
        duplicate: ${SHARED_TOKEN}
        lowercase: ${lowercase_token}
    url:
      auth:
        value: ${URL_TOKEN}
    timeout:
      authorization_code:
        value: ${TIMEOUT_TOKEN}
    connect_timeout:
      oauth2:
        value: ${CONNECT_TIMEOUT_TOKEN}
    idle_timeout_seconds:
      authentication:
        value: ${IDLE_TIMEOUT_TOKEN}
    max_lifetime_seconds:
      credential:
        value: ${MAX_LIFETIME_TOKEN}
    enabled:
      authorization:
        value: ${ENABLED_TOKEN}
    supports_parallel_tool_calls:
      credentials:
        value: ${PARALLEL_TOKEN}
    tools:
      include:
        oauth:
          access_token: ${TOOLS_INCLUDE_TOKEN}
      exclude:
        auth:
          value: ${TOOLS_EXCLUDE_TOKEN}
      prompts:
        authorization_code:
          value: ${TOOLS_PROMPTS_TOKEN}
      resources:
        credentials:
          value: ${TOOLS_RESOURCES_TOKEN}
"#,
    )
    .unwrap();

    let imported = import_everything(&fixture, true);
    let component = imported
        .components
        .iter()
        .find(|component| {
            component.kind == ComponentKind::McpServer && component.name == "nested_placeholders"
        })
        .unwrap();

    assert_eq!(metadata(component, "redacted"), Some("true"));
    assert_eq!(
        metadata(component, "secretReferenceNames"),
        Some(
            "ARGS_TOKEN,COMMAND_TOKEN,CONNECT_TIMEOUT_TOKEN,ENABLED_TOKEN,IDLE_TIMEOUT_TOKEN,\
MAX_LIFETIME_TOKEN,PARALLEL_TOKEN,SHARED_TOKEN,TIMEOUT_TOKEN,TOOLS_EXCLUDE_TOKEN,\
TOOLS_INCLUDE_TOKEN,TOOLS_PROMPTS_TOKEN,TOOLS_RESOURCES_TOKEN,URL_TOKEN"
        )
    );
    assert!(
        !component.body_markdown.contains("${")
            && !component.body_markdown.contains("oauth")
            && !component.body_markdown.contains("auth")
            && !component.body_markdown.contains("credential")
            && !component.body_markdown.contains("authorization")
    );
    assert!(
        !metadata(component, "secretReferenceNames")
            .unwrap()
            .contains("PREFIXED_TOKEN")
            && !metadata(component, "secretReferenceNames")
                .unwrap()
                .contains("lowercase_token"),
        "non-exact placeholder forms entered MCP metadata"
    );
}

#[test]
fn soul_and_nearest_project_context_have_exact_precedence() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let imported = import_everything(&fixture, true);
    let soul = imported
        .components
        .iter()
        .find(|component| metadata(component, "contextRole") == Some("soul"))
        .unwrap();
    assert_eq!(soul.name, "SOUL.md");
    assert_eq!(metadata(soul, "precedenceIndex"), Some("0"));
    assert_eq!(
        metadata(soul, "structuralLocation"),
        Some("profile:SOUL.md")
    );
    assert_eq!(metadata(soul, "profile"), Some("coder"));

    let project = imported
        .components
        .iter()
        .filter(|component| metadata(component, "contextRole") == Some("project"))
        .collect::<Vec<_>>();
    assert_eq!(project.len(), 1);
    assert_eq!(project[0].name, ".hermes.md");
    assert_eq!(metadata(project[0], "precedenceIndex"), Some("1"));
    assert_eq!(
        metadata(project[0], "structuralLocation"),
        Some("project:service/.hermes.md")
    );
    assert_eq!(metadata(project[0], "profile"), Some("coder"));
    assert!(
        project[0]
            .body_markdown
            .contains("Preserve wire contracts.")
    );
    assert!(!project[0].body_markdown.contains("Fallback context."));
    assert!(!project[0].body_markdown.contains("Root context."));
}

#[test]
fn root_project_context_round_trips_without_a_curdir_segment() {
    for (remove_preferred, name) in [(false, ".hermes.md"), (true, "HERMES.md")] {
        let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
        for service_name in [".hermes.md", "HERMES.md"] {
            fs::remove_file(fixture.layout.working_directory.join(service_name)).unwrap();
        }
        if remove_preferred {
            fs::remove_file(fixture.layout.project_root.join(".hermes.md")).unwrap();
        }
        let imported = import_everything(&fixture, true);
        let context = imported
            .components
            .iter()
            .find(|component| metadata(component, "contextRole") == Some("project"))
            .unwrap();

        assert_eq!(context.name, name);
        assert_eq!(
            metadata(context, "structuralLocation"),
            Some(format!("project:{name}").as_str())
        );
        let desired = DesiredState {
            components: vec![context.clone()],
            scopes: vec![NativeScope::Project {
                project_id: fixture.project_id,
                root: fixture.adapter.project_root_wire(),
            }],
        };
        assert!(fixture.adapter.render(&desired).unwrap().files.is_empty());
        assert!(
            fixture
                .adapter
                .plan_native_markdown(context)
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn memory_documents_remain_typed_and_separate() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let memories = fixture.adapter.import_native_memory().unwrap();
    assert_eq!(memories.len(), 2);
    assert_eq!(memories[0].kind, HermesMemoryKind::Agent);
    assert_eq!(memories[1].kind, HermesMemoryKind::User);
    assert_ne!(memories[0].body_markdown, memories[1].body_markdown);
    assert_ne!(memories[0].source_digest, memories[1].source_digest);
    let imported = import_everything(&fixture, true);
    assert!(imported.components.iter().all(|component| {
        !component.body_markdown.contains("Hermes-owned prefix.")
            && !component
                .body_markdown
                .contains("User prefers concise output.")
    }));
}

#[test]
fn skills_plugins_and_hooks_are_allowlist_walks() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let sentinels = install_non_execution_sentinels(&fixture);
    let imported = import_everything(&fixture, true);
    let serialized = serde_json::to_string(&imported).unwrap();
    assert!(serialized.contains("Review the diff."));
    assert!(serialized.contains("Nested review guidance."));
    assert!(serialized.contains("Review changes."));
    assert!(serialized.contains("profile:hooks/audit/handler.py"));
    assert!(serialized.contains("Path("));
    assert!(!serialized.contains("plugin.py"));
    assert!(!serialized.contains("requirements.txt"));
    assert!(!serialized.contains("ignored-hook.txt"));
    assert!(!serialized.contains("REVIEW_TOKEN"));
    for sentinel in sentinels {
        assert!(!sentinel.exists(), "{} was executed", sentinel.display());
    }
}

#[test]
fn plugin_manifest_import_is_a_deterministic_reviewed_projection() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let imported = import_global(&fixture);
    let manifest = imported
        .components
        .iter()
        .find(|component| {
            component.kind == ComponentKind::Plugin
                && component.name == "reviewer"
                && metadata(component, "manifest") == Some("true")
        })
        .unwrap();

    assert_eq!(
        manifest.body_markdown,
        "name: reviewer\nversion: 1.2.3\ndescription: Review changes.\n"
    );
    assert!(!manifest.body_markdown.contains("requires_env"));
    assert!(!manifest.body_markdown.contains("REVIEW_TOKEN"));
}

#[test]
fn malformed_yaml_and_unsafe_topology_fail_closed_without_values() {
    let cases = [
        "approvals:\n  mode: smart\n  mode: must-not-import-duplicate\n",
        "approvals: !must-not-import-tag\n  mode: smart\n",
        "unknown: &outside\n  mode: must-not-import-alias\napprovals: *outside\n",
        "approvals:\n  <<: {mode: must-not-import-merge}\n",
        "approvals:\n  ? [not, string]\n  : must-not-import-key\n",
        "approvals:\n  nested:\n    a:\n      b:\n        c:\n          d:\n            e:\n              f:\n                g:\n                  h:\n                    i:\n                      j:\n                        k:\n                          l:\n                            m:\n                              n:\n                                o:\n                                  p:\n                                    q:\n                                      r:\n                                        s:\n                                          t:\n                                            u:\n                                              v:\n                                                w:\n                                                  x:\n                                                    y:\n                                                      z:\n                                                        aa:\n                                                          bb:\n                                                            cc:\n                                                              dd:\n                                                                ee:\n                                                                  ff: must-not-import-depth\n",
    ];
    for yaml in cases {
        let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
        fs::write(fixture.layout.profile.hermes_home.join("config.yaml"), yaml).unwrap();
        let rendered = format!("{:?}", global_import_error(&fixture));
        assert!(!rendered.contains("must-not-import"));
    }

    let collection_fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let collection = (0..257)
        .map(|index| format!("  key{index}: value\n"))
        .collect::<String>();
    fs::write(
        collection_fixture
            .layout
            .profile
            .hermes_home
            .join("config.yaml"),
        format!("approvals:\n{collection}"),
    )
    .unwrap();
    assert!(!format!("{:?}", global_import_error(&collection_fixture)).contains("value"));

    let markdown_fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    fs::write(
        markdown_fixture.layout.profile.hermes_home.join("SOUL.md"),
        "-----BEGIN PRIVATE KEY-----\nmust-not-import-markdown\n",
    )
    .unwrap();
    assert!(!format!("{:?}", global_import_error(&markdown_fixture)).contains("must-not-import"));

    #[cfg(unix)]
    {
        let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
        let outside = fixture.root.join("outside-skill");
        fs::write(&outside, "must-not-import-symlink").unwrap();
        let target = fixture
            .layout
            .profile
            .hermes_home
            .join("skills/review/SKILL.md");
        fs::remove_file(&target).unwrap();
        std::os::unix::fs::symlink(outside, target).unwrap();
        assert!(!format!("{:?}", global_import_error(&fixture)).contains("must-not-import"));
    }
}

#[test]
fn disabled_components_respect_include_disabled() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let enabled = import_everything(&fixture, false);
    assert!(!enabled.components.iter().any(|component| {
        (component.kind == ComponentKind::Plugin && component.name == "legacy")
            || (component.kind == ComponentKind::McpServer && component.name == "old")
            || (component.kind == ComponentKind::Hook && component.name == "disabled")
    }));
    let all = import_everything(&fixture, true);
    for (kind, name) in [
        (ComponentKind::Plugin, "legacy"),
        (ComponentKind::McpServer, "old"),
        (ComponentKind::Hook, "disabled"),
    ] {
        let component = all
            .components
            .iter()
            .find(|component| component.kind == kind && component.name == name)
            .unwrap();
        assert!(
            component.archived || metadata(component, "enabled") == Some("false"),
            "{kind:?} {name} was not marked disabled"
        );
    }
}

#[test]
fn default_and_named_profiles_are_distinct_explicit_targets() {
    let _env = ENV_LOCK.lock().unwrap();
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let discovered = HermesAdapter::discover_profiles(&fixture.default_home).unwrap();
    assert_eq!(
        discovered
            .iter()
            .map(|profile| profile.name.as_str())
            .collect::<Vec<_>>(),
        vec!["default", "coder", "writer"]
    );
    assert_ne!(discovered[0].hermes_home, discovered[1].hermes_home);
    assert_ne!(discovered[1].hermes_home, discovered[2].hermes_home);
    assert_ne!(discovered[0].hermes_home, discovered[2].hermes_home);
    for profile in discovered {
        let adapter = HermesAdapter::from_layout(
            profile_layout(
                &fixture,
                &profile.name,
                &fixture.layout.version,
                HermesExecutableKind::Native,
            ),
            fixture.project_id,
            DeviceId::from_str(DEVICE_ID).unwrap(),
            HybridLogicalClock::new(1_900_000_000_000, 0, DeviceId::from_str(DEVICE_ID).unwrap()),
        )
        .unwrap();
        assert_eq!(
            adapter.profile_home_wire().display.as_deref(),
            profile.hermes_home.to_str()
        );
    }
}

#[test]
fn unknown_profile_is_rejected_without_fallback_or_creation() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let default_before = fs::read(fixture.default_home.join("config.yaml")).unwrap();
    let coder_before = fs::read(fixture.profiles_root.join("coder/config.yaml")).unwrap();
    let error = HermesAdapter::from_layout(
        profile_layout(
            &fixture,
            "missing",
            &fixture.layout.version,
            HermesExecutableKind::Native,
        ),
        fixture.project_id,
        DeviceId::from_str(DEVICE_ID).unwrap(),
        HybridLogicalClock::new(1_900_000_000_000, 0, DeviceId::from_str(DEVICE_ID).unwrap()),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::NotFound);
    assert!(!fixture.profiles_root.join("missing").exists());
    assert_eq!(
        fs::read(fixture.default_home.join("config.yaml")).unwrap(),
        default_before
    );
    assert_eq!(
        fs::read(fixture.profiles_root.join("coder/config.yaml")).unwrap(),
        coder_before
    );
}

#[test]
fn invalid_nested_symlinked_and_case_colliding_profiles_are_ignored() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    for name in [
        "-invalid",
        "UPPER",
        "too.long.profile",
        "a".repeat(65).as_str(),
    ] {
        fs::create_dir_all(fixture.profiles_root.join(name)).unwrap();
    }
    fs::create_dir_all(fixture.profiles_root.join("coder/child")).unwrap();
    fs::create_dir_all(fixture.profiles_root.join("Coder")).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        fixture.profiles_root.join("writer"),
        fixture.profiles_root.join("linked"),
    )
    .unwrap();
    #[cfg(windows)]
    let _ = std::os::windows::fs::symlink_dir(
        &fixture.profiles_root.join("writer"),
        fixture.profiles_root.join("linked"),
    );
    let discovered = HermesAdapter::discover_profiles(&fixture.default_home).unwrap();
    let has_distinct_case_collision = fs::read_dir(&fixture.profiles_root)
        .unwrap()
        .filter_map(Result::ok)
        .any(|entry| entry.file_name() == "Coder");
    assert_eq!(
        discovered
            .iter()
            .map(|profile| profile.name.as_str())
            .collect::<Vec<_>>(),
        if has_distinct_case_collision {
            vec!["default", "writer"]
        } else {
            vec!["default", "coder", "writer"]
        }
    );
}

#[test]
fn adapter_cannot_be_redirected_after_construction() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let default_canary = fixture.default_home.join("do-not-read");
    let writer_canary = fixture.profiles_root.join("writer/do-not-read");
    fs::write(&default_canary, "default canary").unwrap();
    fs::write(&writer_canary, "writer canary").unwrap();
    for requested in ["writer", "default"] {
        let error = fixture
            .adapter
            .probe(&ProbeContext {
                harness: HarnessId::Hermes,
                requested_profile: Some(requested.to_owned()),
            })
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidRequest);
    }
    assert_eq!(
        fs::read_to_string(default_canary).unwrap(),
        "default canary"
    );
    assert_eq!(fs::read_to_string(writer_canary).unwrap(), "writer canary");
}

#[test]
fn working_directory_must_stay_inside_project_root() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let mut outside = fixture.layout.clone();
    outside.working_directory = fixture.root.clone();
    assert_eq!(
        HermesAdapter::from_layout(
            outside,
            fixture.project_id,
            DeviceId::from_str(DEVICE_ID).unwrap(),
            HybridLogicalClock::new(1_900_000_000_000, 0, DeviceId::from_str(DEVICE_ID).unwrap()),
        )
        .unwrap_err()
        .code,
        ErrorCode::InvalidRequest
    );
    let mut unresolved = fixture.layout.clone();
    unresolved.project_root = fixture.root.join("does-not-exist");
    assert_eq!(
        HermesAdapter::from_layout(
            unresolved,
            fixture.project_id,
            DeviceId::from_str(DEVICE_ID).unwrap(),
            HybridLogicalClock::new(1_900_000_000_000, 0, DeviceId::from_str(DEVICE_ID).unwrap()),
        )
        .unwrap_err()
        .code,
        ErrorCode::NotFound
    );
}

#[test]
fn unknown_versions_and_wrappers_are_import_only() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let mut variants = vec![
        ("9.9.9", HermesExecutableKind::Native, "hermes"),
        ("0.18.2", HermesExecutableKind::Wrapper, "hermes-script"),
        ("0.18.2", HermesExecutableKind::Wrapper, "hermes.cmd"),
        ("0.18.2", HermesExecutableKind::Wrapper, "hermes.bat"),
        ("0.18.2", HermesExecutableKind::Wrapper, "hermes.ps1"),
    ];
    for (version, kind, executable_name) in variants.drain(..) {
        let mut layout = profile_layout(&fixture, "coder", version, kind);
        layout.executable = fixture.root.join(executable_name);
        fs::write(
            &layout.executable,
            if executable_name == "hermes-script" {
                &b"#!/bin/sh\necho 0.18.2\n"[..]
            } else {
                &b"wrapper"[..]
            },
        )
        .unwrap();
        let adapter = HermesAdapter::from_layout(
            layout,
            fixture.project_id,
            DeviceId::from_str(DEVICE_ID).unwrap(),
            HybridLogicalClock::new(1_900_000_000_000, 0, DeviceId::from_str(DEVICE_ID).unwrap()),
        )
        .unwrap();
        assert_eq!(
            probe(&adapter, Some("coder")).capability,
            CapabilityLevel::ImportOnly
        );
        let capabilities = adapter.native_memory_capabilities().unwrap();
        assert!(matches!(
            capabilities.disable,
            NativeMemoryDisable::WatchOnly
        ));
        assert_eq!(capabilities.sources.len(), 2);
        assert_eq!(
            adapter
                .render(&context_relay_protocol::DesiredState {
                    components: vec![],
                    scopes: vec![]
                })
                .unwrap_err()
                .code,
            ErrorCode::HarnessUnsupported
        );
    }
}

#[test]
fn from_layout_reclassifies_wrapper_bytes_claimed_as_native() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let mut layout = profile_layout(
        &fixture,
        "coder",
        &fixture.layout.version,
        HermesExecutableKind::Native,
    );
    layout.executable = fixture.root.join("claimed-native-wrapper");
    fs::write(&layout.executable, b"#!/bin/sh\necho 0.18.2\n").unwrap();

    let adapter = HermesAdapter::from_layout(
        layout,
        fixture.project_id,
        DeviceId::from_str(DEVICE_ID).unwrap(),
        HybridLogicalClock::new(1_900_000_000_000, 0, DeviceId::from_str(DEVICE_ID).unwrap()),
    )
    .unwrap();

    assert_eq!(
        probe(&adapter, Some("coder")).capability,
        CapabilityLevel::ImportOnly
    );
}

#[test]
fn native_adapter_rechecks_gateway_profile_executable_and_digests() {
    let digest_fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let config_path = digest_fixture
        .layout
        .profile
        .hermes_home
        .join("config.yaml");
    let expected = ExpectedNativeDigest {
        target: test_wire_path(&config_path),
        expected_digest: Some(test_file_digest(&config_path)),
    };
    let mut plan = hermes_native_plan(&digest_fixture, ApprovalClass::Passive, vec![expected]);
    let mut adapter = digest_fixture.adapter.clone();
    assert!(adapter.reprobe_live_state(&plan).is_ok());
    assert!(adapter.compare_approved_digests(&plan).is_ok());

    fs::write(&config_path, b"changed native bytes").unwrap();
    assert!(adapter.compare_approved_digests(&plan).is_err());

    let bridge_fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let (bridge, _) = managed_bridge_desired(&bridge_fixture);
    let expected = ExpectedNativeDigest {
        target: test_wire_path(&bridge),
        expected_digest: Some(test_file_digest(&bridge)),
    };
    let bridge_plan = hermes_native_plan(&bridge_fixture, ApprovalClass::Passive, vec![expected]);
    let mut adapter = bridge_fixture.adapter.clone();
    assert!(adapter.compare_approved_digests(&bridge_plan).is_ok());
    fs::write(&bridge, b"changed Hermes bridge executable").unwrap();
    assert!(adapter.compare_approved_digests(&bridge_plan).is_err());

    let live_fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    plan = hermes_native_plan(&live_fixture, ApprovalClass::Active, vec![]);
    fs::write(
        live_fixture
            .layout
            .profile
            .hermes_home
            .join("gateway.pid"),
        format!(
            r#"{{"pid":{},"kind":"hermes-gateway","argv":["hermes","gateway","run","--profile","coder"],"start_time":1}}"#,
            std::process::id()
        ),
    )
    .unwrap();
    let mut adapter = live_fixture.adapter.clone();
    assert!(adapter.reprobe_live_state(&plan).is_err());

    for drift in ["version", "path", "hash"] {
        let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
        let mut plan = hermes_native_plan(&fixture, ApprovalClass::Passive, vec![]);
        match drift {
            "version" => plan.setup.harness_version = "0.18.1".into(),
            "path" => plan.setup.executable_path = test_wire_path(&fixture.root.join("other")),
            "hash" => fs::write(&fixture.layout.executable, b"\x7fELFchanged executable").unwrap(),
            _ => unreachable!(),
        }
        assert!(fixture.adapter.clone().reprobe_live_state(&plan).is_err());
    }

    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let plan = hermes_native_plan(&fixture, ApprovalClass::Passive, vec![]);
    let original = fixture.layout.profile.hermes_home.clone();
    let moved = fixture.root.join("moved profile");
    fs::rename(&original, &moved).unwrap();
    fs::create_dir_all(&original).unwrap();
    assert!(fixture.adapter.clone().reprobe_live_state(&plan).is_err());
}

#[test]
fn managed_bridge_native_plan_binds_before_and_intended_fingerprints() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    clear_gateway_records(&fixture);
    let (_, desired) = managed_bridge_desired(&fixture);
    let config_path = fixture.layout.profile.hermes_home.join("config.yaml");
    let before = OsNativeFileSystem::new().snapshot(&config_path).unwrap();
    let before_bytes = fs::read(&config_path).unwrap();

    let rendered = fixture.adapter.render(&desired).unwrap();
    assert!(rendered.cli_operations.is_empty());
    let mutation = fixture
        .adapter
        .plan_native_config(&desired)
        .unwrap()
        .unwrap();
    assert_eq!(mutation.target, test_wire_path(&config_path));
    assert_eq!(mutation.expected.0.0, *before.fingerprint());
    let intended = NativeState::decode_v1(&mutation.content).unwrap();
    assert_eq!(mutation.intended.0.0, intended.fingerprint());

    let nonce = [29; 16];
    let mut native = OsNativeTransactionFileSystem::new(nonce);
    let images = native
        .create_before_images(std::slice::from_ref(&mutation))
        .unwrap();
    assert_eq!(images.len(), 1);
    assert_eq!(images[0].fingerprint, mutation.expected);
    let NativeState::RegularFile {
        bytes: captured_before,
        ..
    } = NativeState::decode_v1(&images[0].encrypted_state).unwrap()
    else {
        panic!("Hermes before-image did not capture config.yaml");
    };
    assert_eq!(captured_before, before_bytes);
    native.record_native_metadata(&images).unwrap();
    native
        .compare_and_swap_targets(std::slice::from_ref(&mutation))
        .unwrap();
    native.apply_mutation(&nonce, &mutation).unwrap();
    assert_eq!(
        *OsNativeFileSystem::new()
            .snapshot(&config_path)
            .unwrap()
            .fingerprint(),
        intended.fingerprint()
    );
    let restored = native.restore_matching_applied_targets(&nonce).unwrap();
    assert!(restored.conflict_target_sequences().is_empty());
    assert_eq!(fs::read(&config_path).unwrap(), before_bytes);
}

#[test]
fn managed_bridge_restore_preserves_divergent_live_yaml() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    clear_gateway_records(&fixture);
    let (_, desired) = managed_bridge_desired(&fixture);
    let config_path = fixture.layout.profile.hermes_home.join("config.yaml");
    let mutation = fixture
        .adapter
        .plan_native_config(&desired)
        .unwrap()
        .unwrap();
    let nonce = [30; 16];
    let mut native = OsNativeTransactionFileSystem::new(nonce);
    let images = native
        .create_before_images(std::slice::from_ref(&mutation))
        .unwrap();
    native.record_native_metadata(&images).unwrap();
    native
        .compare_and_swap_targets(std::slice::from_ref(&mutation))
        .unwrap();
    native.apply_mutation(&nonce, &mutation).unwrap();

    let divergent = b"mcp_servers:\n  context-relay:\n    command: external-change\n";
    fs::write(&config_path, divergent).unwrap();
    assert!(native.restore_matching_applied_targets(&nonce).is_err());
    assert_eq!(fs::read(&config_path).unwrap(), divergent);
}

#[test]
fn managed_bridge_authority_rejects_near_misses_and_unsafe_prior_state() {
    let exact_fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    clear_gateway_records(&exact_fixture);
    let (_, desired) = managed_bridge_desired(&exact_fixture);
    assert!(exact_fixture.adapter.plan_native_config(&desired).is_ok());
    let exact = desired.components[0].clone();

    let mut near_misses = Vec::new();
    let mut changed = exact.clone();
    changed.body_markdown.push(' ');
    near_misses.push(changed);
    let mut changed = exact.clone();
    changed
        .metadata
        .push(("profile".into(), exact_fixture.layout.profile.name.clone()));
    near_misses.push(changed);
    let mut changed = exact.clone();
    changed.name = "context-relay-copy".into();
    near_misses.push(changed);
    let mut changed = exact;
    changed.provenance.harness = Some(HarnessId::Hermes);
    near_misses.push(changed);
    for changed in near_misses {
        assert!(
            exact_fixture
                .adapter
                .plan_native_config(&desired_global(&exact_fixture, vec![changed]))
                .is_err()
        );
    }

    for prior in [
        "mcp_servers:\n  context-relay: []\n",
        "mcp_servers:\n  context-relay:\n    command: <redacted>\n",
        "mcp_servers:\n  context-relay:\n    command: ghp_must-not-take-over\n",
        "mcp_servers:\n  context-relay:\n    command: unmanaged-command\n    args: [--other]\n",
    ] {
        let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
        clear_gateway_records(&fixture);
        let (_, desired) = managed_bridge_desired(&fixture);
        let config_path = fixture.layout.profile.hermes_home.join("config.yaml");
        fs::write(&config_path, prior).unwrap();
        let error = fixture.adapter.plan_native_config(&desired).unwrap_err();
        assert_eq!(fs::read_to_string(config_path).unwrap(), prior);
        assert!(!format!("{error:?}").contains("ghp_must-not-take-over"));
    }
}

#[test]
fn native_adapter_rejects_every_cli_mutation_surface() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let mut plan = hermes_native_plan(&fixture, ApprovalClass::Passive, vec![]);
    plan.cli_mutations.push(ApprovedCliMutation {
        stable_id: "must-not-run-through-hermes-cli".into(),
        expected: None,
        intended: None,
        forward: vec![],
        rollback: vec![],
    });

    assert!(fixture.adapter.clone().reprobe_live_state(&plan).is_err());

    plan.cli_mutations.clear();
    plan.setup.cli_operations.push(CliOperation {
        executable: plan.setup.executable_path.clone(),
        arguments: vec![plan.setup.executable_path.clone()],
        timeout_ms: 30_000,
    });
    assert!(fixture.adapter.clone().reprobe_live_state(&plan).is_err());
}

#[test]
fn native_adapter_rejects_staged_hash_and_receipt_changes() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let plan = hermes_native_plan(&fixture, ApprovalClass::Passive, vec![]);
    let mut adapter = fixture.adapter.clone();
    let valid = RestrictedRun {
        staged_output_hash: plan.expected_semantic_output_hash,
        scanner_result_hash: plan.scanner_result_hash,
    };
    assert!(adapter.validate_staged_output(&plan, &valid).is_ok());
    for invalid in [
        RestrictedRun {
            staged_output_hash: Sha256Digest([90; 32]),
            ..valid.clone()
        },
        RestrictedRun {
            scanner_result_hash: Sha256Digest([91; 32]),
            ..valid.clone()
        },
    ] {
        assert!(adapter.validate_staged_output(&plan, &invalid).is_err());
    }

    let intended = plan
        .mutations
        .iter()
        .map(|mutation| mutation.intended.0)
        .collect::<Vec<_>>();
    let mut receipt = validation_receipt();
    receipt.resulting_digests = intended;
    assert!(NativeAdapter::validate_effective(&mut adapter, &plan, &receipt).is_ok());
    receipt.plan_id = PlanId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073985").unwrap();
    assert!(NativeAdapter::validate_effective(&mut adapter, &plan, &receipt).is_err());
    receipt.plan_id = plan.setup.plan_id;
    receipt.resulting_digests = vec![Sha256Digest([92; 32])];
    assert!(NativeAdapter::validate_effective(&mut adapter, &plan, &receipt).is_err());
}

#[test]
fn rollback_restores_all_hermes_targets_and_metadata() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    clear_gateway_records(&fixture);
    let imported = import_global(&fixture);
    let mut plugin = component_at(
        &imported.components,
        ComponentKind::Plugin,
        "config:plugins.enabled.reviewer",
    );
    plugin.archived = true;
    let config = fixture
        .adapter
        .plan_native_config(&desired_global(&fixture, vec![plugin]))
        .unwrap()
        .unwrap();
    let mut soul = component_at(&imported.components, ComponentKind::Rule, "profile:SOUL.md");
    soul.body_markdown = "rollback changed soul".into();
    let markdown = fixture
        .adapter
        .plan_native_markdown(&soul)
        .unwrap()
        .unwrap();
    let memory = fixture
        .adapter
        .plan_native_memory(HermesMemoryKind::Agent, "rollback changed memory")
        .unwrap()
        .unwrap();
    let mut manifest = component_at(
        &imported.components,
        ComponentKind::Hook,
        "profile:hooks/audit/HOOK.yaml",
    );
    manifest.body_markdown = "name: audit\nevents: [post_tool, pre_tool]\n".into();
    let mut handler = component_at(
        &imported.components,
        ComponentKind::Hook,
        "profile:hooks/audit/handler.py",
    );
    handler.body_markdown = "print('changed safe handler')\n".into();
    let hooks = fixture
        .adapter
        .plan_native_gateway_hook(&manifest, Some(&handler))
        .unwrap();
    let mutations = [vec![config, markdown, memory], hooks].concat();
    let before = mutations
        .iter()
        .map(|mutation| {
            let path = PathBuf::from(mutation.target.display.as_ref().unwrap());
            (
                path.clone(),
                OsNativeFileSystem::new()
                    .snapshot(&path)
                    .unwrap()
                    .state()
                    .clone(),
            )
        })
        .collect::<Vec<_>>();
    let mut plan = hermes_native_plan(&fixture, ApprovalClass::Passive, vec![]);
    plan.mutations = mutations;
    plan.sidecars = vec![SidecarBinding {
        id: SidecarId::RuleSync,
        target: RuntimeTarget::MacosArm64,
        version: plan.setup.rulesync_version.clone(),
        closure_hash: Sha256Digest([45; 32]),
        source_bundle_hash: Sha256Digest([46; 32]),
        build_toolchain_hash: Sha256Digest([47; 32]),
        command_template_digest: Sha256Digest([48; 32]),
        command: SidecarCommand::RuleSyncGenerate {
            target: RuleSyncTarget::CodexCli,
            features: RuleSyncFeatures::new(&[RuleSyncFeature::Rules]).unwrap(),
        },
    }];
    plan.setup.batch_hash = approval_hash_v1(&plan).unwrap();
    let nonce = *plan.setup.plan_id.as_bytes();
    let mut adapter = fixture.adapter.clone();
    let mut executor = RollbackExecutor {
        run: RestrictedRun {
            staged_output_hash: plan.expected_semantic_output_hash,
            scanner_result_hash: plan.scanner_result_hash,
        },
    };
    let mut native = OsNativeTransactionFileSystem::new(nonce);
    let mut journal = RollbackJournal::default();
    let mut fault = FailAfterPayloadWrites::default();
    let result = NativeTransactionEngine::new(
        &mut adapter,
        &mut executor,
        &mut native,
        &mut journal,
        &mut fault,
    )
    .apply(&plan, 1_900_000_000_000, validation_receipt().applied_hlc);
    assert!(result.is_err());
    assert!(fault.injected);
    assert!(journal.compensated);
    assert_eq!(journal.restored_candidates, plan.mutations.len());

    for (path, expected) in before {
        let restored = OsNativeFileSystem::new().snapshot(&path).unwrap();
        let (
            NativeState::RegularFile {
                bytes: expected_bytes,
                metadata: expected_metadata,
            },
            NativeState::RegularFile {
                bytes: restored_bytes,
                metadata: restored_metadata,
            },
        ) = (&expected, restored.state())
        else {
            panic!("Hermes rollback target remained a regular file");
        };
        assert_eq!(restored_bytes, expected_bytes);
        assert_eq!(
            restored_metadata.file_attributes(),
            expected_metadata.file_attributes()
        );
        assert_eq!(
            restored_metadata.creation_time(),
            expected_metadata.creation_time()
        );
        assert_eq!(
            restored_metadata.last_access_time(),
            expected_metadata.last_access_time()
        );
        assert_eq!(
            restored_metadata.last_write_time(),
            expected_metadata.last_write_time()
        );
        #[cfg(windows)]
        assert_eq!(
            restored_metadata.change_time(),
            expected_metadata.change_time()
        );
        assert_eq!(
            restored_metadata.security_descriptor(),
            expected_metadata.security_descriptor()
        );
        assert_eq!(
            restored_metadata.alternate_streams(),
            expected_metadata.alternate_streams()
        );
    }
}

#[cfg(windows)]
#[test]
fn windows_junction_profile_paths_are_rejected() {
    fn junction(link: &Path, target: &Path) {
        let status = std::process::Command::new("cmd")
            .arg("/C")
            .arg(format!(
                "mklink /J \"{}\" \"{}\"",
                link.display(),
                target.display()
            ))
            .status()
            .unwrap();
        assert!(status.success());
    }

    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let default_junction = fixture.root.join("default-junction");
    junction(&default_junction, &fixture.default_home);
    assert_eq!(
        HermesAdapter::discover_profiles(&default_junction)
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
    fs::remove_dir(&default_junction).unwrap();

    let profiles_target = fixture.root.join("profiles-target");
    fs::rename(&fixture.profiles_root, &profiles_target).unwrap();
    junction(&fixture.profiles_root, &profiles_target);
    assert_eq!(
        HermesAdapter::discover_profiles(&fixture.default_home)
            .unwrap()
            .iter()
            .map(|profile| profile.name.as_str())
            .collect::<Vec<_>>(),
        vec!["default"]
    );
    fs::remove_dir(&fixture.profiles_root).unwrap();
    fs::rename(&profiles_target, &fixture.profiles_root).unwrap();

    let candidate_junction = fixture.profiles_root.join("fake");
    junction(&candidate_junction, &fixture.profiles_root.join("writer"));
    assert_eq!(
        HermesAdapter::discover_profiles(&fixture.default_home)
            .unwrap()
            .iter()
            .map(|profile| profile.name.as_str())
            .collect::<Vec<_>>(),
        vec!["default", "coder", "writer"]
    );
}
