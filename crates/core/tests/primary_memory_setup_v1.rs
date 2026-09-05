mod support;

use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    fs,
    panic::AssertUnwindSafe,
    path::{Path, PathBuf},
    rc::Rc,
    str::FromStr as _,
};

use context_relay_core::{
    claude_code::{ClaudeCodeAdapter, ClaudeCodeLayout},
    codex::{CodexAdapter, CodexExecutableKind, CodexLayout},
    hermes::{HermesAdapter, HermesExecutableKind, HermesLayout, HermesMemoryKind, HermesProfile},
    mcp::install::{BRIDGE_SERVER_NAME, BridgeExecutable, attest_bridge_executable},
    native_memory::{
        NativeMemoryDocumentKind, NativeMemoryLimits, NativeMemoryRegistration, NativeMemorySource,
        PRIMARY_MEMORY_INSTRUCTIONS,
    },
    native_transaction::{
        ApprovedCliMutation, ApprovedInput, ApprovedMutation, CanonicalCliDeclaration,
        MutationKind, NativeTransactionPlan, RestorableStateFingerprint, SidecarBinding,
        TransactionStep,
        cli::{CliMutationOutcome, CliRestoreOutcome, NativeCliExecutor},
        engine::{
            BoundaryError, FaultHook, FrozenOutput, NativeAdapter, NoFault, RestrictedExecutor,
            RestrictedRun,
        },
        filesystem::OsNativeTransactionFileSystem,
        open_plan,
        recovery::{
            CliRecoveryRestore, NativeCliRecoveryIo, OsNativeRecoveryIo, bind_cli_recovery_plan,
            recover_native_transactions_with_cli,
        },
    },
    setup::{
        BridgeExecutionError, BridgeInstallService, BridgeLocator, BridgeMutationPlan,
        BridgePlanExecutor, BridgePreviewHarness, HermesMemoryExportService,
        NativeEngineBridgePlanExecutor, PrimaryMemoryMutationPlan, RegisteredProject,
    },
    vault::{
        BeforeImagePolicy, NativeCliWalRecord, NativeSandboxIdentity, SetupPlanAction,
        SetupPlanLifecycle, Vault,
    },
};
use context_relay_native_runner::{NativeState, OsNativeFileSystem, RuntimeTarget};
use context_relay_protocol::{
    ApplyReceipt, CapabilityLevel, ChangeClass, ClassifiedChange, ClassifiedChanges, CliOperation,
    CliOperations, ClientError, ComponentKind, ComponentRecord, DesiredState, DeviceId,
    DiscoveredScopes, ExpectedNativeDigest, HarnessAdapter, HarnessId, HybridLogicalClock,
    ImportRequest, ImportedState, InstallationMethod, NativePlatform, NativeScope, ProbeContext,
    ProbeReport, ProjectId, RenderedState, ScopeRef, SemanticDiff, Sha256Digest, ValidationReport,
    WireNativeValue,
};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};

use support::{ID_1, ID_2, MemoryKeyStore, TempVault, clock};

const NOW_MS: u64 = 1_900_000_000_000;

struct Locator {
    bridge: BridgeExecutable,
    calls: Rc<Cell<usize>>,
}

impl BridgeLocator for Locator {
    fn locate(&self) -> Result<BridgeExecutable, ClientError> {
        self.calls.set(self.calls.get() + 1);
        Ok(self.bridge.clone())
    }
}

struct Harness {
    executable: WireNativeValue,
    project_id: ProjectId,
    primary: PathBuf,
    hooks: PathBuf,
    settings: PathBuf,
    memory: PathBuf,
}

impl Harness {
    fn cli_mutation(&self, intended: &ComponentRecord) -> ApprovedCliMutation {
        let declaration = CanonicalCliDeclaration {
            harness: HarnessId::Codex,
            server_name: BRIDGE_SERVER_NAME.to_owned(),
            canonical_body: intended.body_markdown.clone(),
            fingerprint: digest(intended.body_markdown.as_bytes()),
        };
        let forward = CliOperation {
            executable: self.executable.clone(),
            arguments: ["mcp", "add", BRIDGE_SERVER_NAME]
                .into_iter()
                .map(native_text)
                .collect(),
            timeout_ms: 30_000,
        };
        let rollback = CliOperation {
            executable: self.executable.clone(),
            arguments: ["mcp", "remove", BRIDGE_SERVER_NAME]
                .into_iter()
                .map(native_text)
                .collect(),
            timeout_ms: 30_000,
        };
        ApprovedCliMutation {
            execution_context: None,
            stable_id: intended.id.to_string(),
            expected: None,
            intended: Some(declaration),
            forward: vec![forward],
            rollback: vec![rollback],
        }
    }
}

impl HarnessAdapter for Harness {
    fn probe(&self, context: &ProbeContext) -> Result<ProbeReport, ClientError> {
        assert_eq!(context.harness, HarnessId::Codex);
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
        assert_eq!(request.scopes.len(), 2);
        assert!(request.include_disabled);
        Ok(ImportedState {
            components: vec![],
            source_digests: vec![],
        })
    }

    fn render(&self, desired: &DesiredState) -> Result<RenderedState, ClientError> {
        assert_eq!(desired.components[0].kind, ComponentKind::McpServer);
        assert!(desired.components.iter().any(|component| {
            component.kind == ComponentKind::Instruction
                && component
                    .body_markdown
                    .starts_with(PRIMARY_MEMORY_INSTRUCTIONS)
        }));
        assert!(
            desired
                .components
                .iter()
                .any(|component| component.kind == ComponentKind::Hook)
        );
        Ok(RenderedState {
            files: vec![],
            cli_operations: vec![],
        })
    }

    fn classify(&self, diff: &SemanticDiff) -> Result<ClassifiedChanges, ClientError> {
        Ok(ClassifiedChanges(diff.changes.clone()))
    }

    fn plan_cli_ops(&self, changes: &ClassifiedChanges) -> Result<CliOperations, ClientError> {
        Ok(CliOperations(
            (!changes.0.is_empty())
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
        unreachable!("preview performs no effective validation")
    }
}

impl BridgePreviewHarness for Harness {
    fn bridge_harness(&self) -> HarnessId {
        HarnessId::Codex
    }

    fn bridge_project_id(&self) -> Option<ProjectId> {
        Some(self.project_id)
    }

    fn bridge_mutations(
        &self,
        _: &DesiredState,
        intended: &ComponentRecord,
    ) -> Result<BridgeMutationPlan, ClientError> {
        Ok(BridgeMutationPlan {
            cli: Some(self.cli_mutation(intended)),
            native: vec![],
        })
    }

    fn primary_memory_mutations(
        &self,
        desired: &DesiredState,
    ) -> Result<PrimaryMemoryMutationPlan, ClientError> {
        let instruction = desired
            .components
            .iter()
            .find(|component| component.kind == ComponentKind::Instruction)
            .unwrap();
        let hook = desired
            .components
            .iter()
            .find(|component| component.kind == ComponentKind::Hook)
            .unwrap();
        let native = vec![
            mutation(&self.primary, instruction.body_markdown.as_bytes()),
            mutation(&self.hooks, hook.body_markdown.as_bytes()),
            mutation(
                &self.settings,
                b"[memories]\ngenerate_memories = false\nuse_memories = false\n",
            ),
        ];
        let source = NativeMemorySource::new(
            HarnessId::Codex,
            "0.144.1",
            ScopeRef::Global,
            NativeMemoryDocumentKind::Agent,
            wire_path(&self.memory),
            NativeMemoryLimits {
                max_bytes: 16 * 1024,
                max_characters: 16 * 1024,
            },
            true,
        )
        .unwrap();
        Ok(PrimaryMemoryMutationPlan {
            native,
            registrations: vec![NativeMemoryRegistration {
                source,
                last_applied_digest: None,
            }],
            semantic_changes: [
                "primary-memory-instruction",
                "primary-memory-hooks",
                "native-memory-disable",
                "native-memory-source",
            ]
            .into_iter()
            .map(|target| ClassifiedChange {
                class: ChangeClass::Update,
                target: target.to_owned(),
                summary: target.to_owned(),
            })
            .collect(),
        })
    }
}

#[test]
fn preview_seals_bridge_instruction_disable_hooks_and_sources_without_mutating_native_state() {
    let root = tempfile::tempdir().unwrap();
    let root_path = fs::canonicalize(root.path()).unwrap();
    let bridge_path = root_path.join("context-relay-context-mcp");
    fs::write(&bridge_path, b"bridge").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&bridge_path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let primary = seed(root_path.join("AGENTS.md"), b"user primary\n");
    let hooks = seed(root_path.join("hooks.json"), b"{\"hooks\":{}}\n");
    let settings = seed(root_path.join("config.toml"), b"model = \"fixture\"\n");
    let memory = seed(root_path.join("memories/MEMORY.md"), b"native memory\n");
    let before = [
        fs::read(&primary).unwrap(),
        fs::read(&hooks).unwrap(),
        fs::read(&settings).unwrap(),
        fs::read(&memory).unwrap(),
    ];
    let project_id = ProjectId::from_str(ID_2).unwrap();
    let vault_path = TempVault::new("primary-memory-setup");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(vault_path.path(), "primary-memory-setup-v1", &keys).unwrap();
    let bridge = attest_bridge_executable(&bridge_path).unwrap();
    let calls = Rc::new(Cell::new(0));
    let setup = BridgeInstallService::new(
        &mut vault,
        Harness {
            executable: native_text("/fixture/codex"),
            project_id,
            primary: primary.clone(),
            hooks: hooks.clone(),
            settings: settings.clone(),
            memory: memory.clone(),
        },
        Locator {
            bridge,
            calls: calls.clone(),
        },
        DeviceId::from_str(ID_1).unwrap(),
        clock(NOW_MS),
    )
    .preview(
        Some(&RegisteredProject {
            project_id,
            root: wire_path(&root_path),
        }),
        NOW_MS,
    )
    .unwrap();

    assert_eq!(calls.get(), 1);
    assert_eq!(
        [
            fs::read(&primary).unwrap(),
            fs::read(&hooks).unwrap(),
            fs::read(&settings).unwrap(),
            fs::read(&memory).unwrap(),
        ],
        before
    );
    let stored = vault.setup_plan(&setup.plan_id).unwrap().unwrap();
    let opened = open_plan(&stored.payload).unwrap();
    assert_eq!(opened.plan.cli_mutations.len(), 1);
    assert_eq!(opened.plan.mutations.len(), 3);
    assert_eq!(opened.plan.native_memory_registrations.len(), 1);
    assert_eq!(opened.plan.setup.semantic_changes.len(), 5);
    assert!(
        opened
            .plan
            .mutations
            .iter()
            .all(|mutation| { NativeState::decode_v1(&mutation.content).is_ok() })
    );
}

#[derive(Clone)]
enum FrozenHarness {
    Claude {
        adapter: ClaudeCodeAdapter,
        cli: Rc<RefCell<Option<CanonicalCliDeclaration>>>,
    },
    Codex {
        adapter: CodexAdapter,
        cli: Rc<RefCell<Option<CanonicalCliDeclaration>>>,
    },
    Hermes(HermesAdapter),
}

impl FrozenHarness {
    fn id(&self) -> HarnessId {
        match self {
            Self::Claude { .. } => HarnessId::ClaudeCode,
            Self::Codex { .. } => HarnessId::Codex,
            Self::Hermes(_) => HarnessId::Hermes,
        }
    }

    fn cli_state(&self) -> Rc<RefCell<Option<CanonicalCliDeclaration>>> {
        match self {
            Self::Claude { cli, .. } | Self::Codex { cli, .. } => cli.clone(),
            Self::Hermes(_) => Rc::new(RefCell::new(None)),
        }
    }
}

impl HarnessAdapter for FrozenHarness {
    fn probe(&self, context: &ProbeContext) -> Result<ProbeReport, ClientError> {
        match self {
            Self::Claude { adapter, .. } => adapter.probe(context),
            Self::Codex { adapter, .. } => adapter.probe(context),
            Self::Hermes(adapter) => adapter.probe(context),
        }
    }

    fn discover_scopes(&self, report: &ProbeReport) -> Result<DiscoveredScopes, ClientError> {
        match self {
            Self::Claude { adapter, .. } => adapter.discover_scopes(report),
            Self::Codex { adapter, .. } => adapter.discover_scopes(report),
            Self::Hermes(adapter) => adapter.discover_scopes(report),
        }
    }

    fn import(&self, request: &ImportRequest) -> Result<ImportedState, ClientError> {
        match self {
            Self::Claude { adapter, .. } => adapter.import(request),
            Self::Codex { adapter, .. } => adapter.import(request),
            Self::Hermes(adapter) => adapter.import(request),
        }
    }

    fn render(&self, desired: &DesiredState) -> Result<RenderedState, ClientError> {
        match self {
            Self::Claude { adapter, .. } => adapter.render(desired),
            Self::Codex { adapter, .. } => adapter.render(desired),
            Self::Hermes(adapter) => adapter.render(desired),
        }
    }

    fn classify(&self, diff: &SemanticDiff) -> Result<ClassifiedChanges, ClientError> {
        match self {
            Self::Claude { adapter, .. } => adapter.classify(diff),
            Self::Codex { adapter, .. } => adapter.classify(diff),
            Self::Hermes(adapter) => adapter.classify(diff),
        }
    }

    fn plan_cli_ops(&self, changes: &ClassifiedChanges) -> Result<CliOperations, ClientError> {
        match self {
            Self::Claude { adapter, .. } => adapter.plan_cli_ops(changes),
            Self::Codex { adapter, .. } => adapter.plan_cli_ops(changes),
            Self::Hermes(adapter) => adapter.plan_cli_ops(changes),
        }
    }

    fn validate_effective(&self, receipt: &ApplyReceipt) -> Result<ValidationReport, ClientError> {
        match self {
            Self::Claude { adapter, .. } => adapter.validate_effective(receipt),
            Self::Codex { adapter, .. } => adapter.validate_effective(receipt),
            Self::Hermes(adapter) => adapter.validate_effective(receipt),
        }
    }
}

impl BridgePreviewHarness for FrozenHarness {
    fn bridge_harness(&self) -> HarnessId {
        self.id()
    }

    fn bridge_setup_capability(&self) -> CapabilityLevel {
        match self {
            Self::Claude { adapter, .. } => BridgePreviewHarness::bridge_setup_capability(adapter),
            Self::Codex { adapter, .. } => BridgePreviewHarness::bridge_setup_capability(adapter),
            Self::Hermes(adapter) => BridgePreviewHarness::bridge_setup_capability(adapter),
        }
    }

    fn bridge_project_id(&self) -> Option<ProjectId> {
        Some(match self {
            Self::Claude { adapter, .. } => adapter.project_id(),
            Self::Codex { adapter, .. } => adapter.project_id(),
            Self::Hermes(adapter) => adapter.project_id(),
        })
    }

    fn bridge_project_root(&self) -> Option<WireNativeValue> {
        Some(match self {
            Self::Claude { adapter, .. } => adapter.project_root_wire(),
            Self::Codex { adapter, .. } => adapter.project_root_wire(),
            Self::Hermes(adapter) => adapter.project_root_wire(),
        })
    }

    fn bridge_requested_profile(&self) -> Option<String> {
        match self {
            Self::Hermes(adapter) => Some(adapter.profile_name().to_owned()),
            _ => None,
        }
    }

    fn bridge_operational_digests(&self) -> Result<Vec<ExpectedNativeDigest>, ClientError> {
        match self {
            Self::Hermes(adapter) => BridgePreviewHarness::bridge_operational_digests(adapter),
            _ => Ok(vec![]),
        }
    }

    fn bridge_mutations(
        &self,
        _: &DesiredState,
        intended: &ComponentRecord,
    ) -> Result<BridgeMutationPlan, ClientError> {
        let cli = match self {
            Self::Claude { adapter, .. } => Some(adapter.plan_bridge_cli_mutation(intended)?),
            Self::Codex { adapter, cli } => {
                let cli = cli.clone();
                Some(adapter.plan_bridge_cli_mutation_with_runner(
                    intended,
                    move |arguments: &[String]| codex_cli_output(arguments, cli.borrow().as_ref()),
                )?)
            }
            Self::Hermes(_) => None,
        };
        Ok(BridgeMutationPlan {
            cli,
            native: vec![],
        })
    }

    fn primary_memory_mutations(
        &self,
        desired: &DesiredState,
    ) -> Result<PrimaryMemoryMutationPlan, ClientError> {
        match self {
            Self::Claude { adapter, .. } => {
                BridgePreviewHarness::primary_memory_mutations(adapter, desired)
            }
            Self::Codex { adapter, .. } => {
                BridgePreviewHarness::primary_memory_mutations(adapter, desired)
            }
            Self::Hermes(adapter) => {
                BridgePreviewHarness::primary_memory_mutations(adapter, desired)
            }
        }
    }

    fn watch_only_memory_registrations(
        &self,
    ) -> Result<Option<Vec<NativeMemoryRegistration>>, ClientError> {
        match self {
            Self::Claude { adapter, .. } => {
                BridgePreviewHarness::watch_only_memory_registrations(adapter)
            }
            Self::Codex { adapter, .. } => {
                BridgePreviewHarness::watch_only_memory_registrations(adapter)
            }
            Self::Hermes(adapter) => BridgePreviewHarness::watch_only_memory_registrations(adapter),
        }
    }
}

impl NativeAdapter for FrozenHarness {
    fn reprobe_live_state(&mut self, plan: &NativeTransactionPlan) -> Result<(), BoundaryError> {
        match self {
            Self::Claude { adapter, .. } => NativeAdapter::reprobe_live_state(adapter, plan),
            Self::Codex { adapter, .. } => NativeAdapter::reprobe_live_state(adapter, plan),
            Self::Hermes(adapter) => NativeAdapter::reprobe_live_state(adapter, plan),
        }
    }

    fn compare_approved_digests(
        &mut self,
        plan: &NativeTransactionPlan,
    ) -> Result<(), BoundaryError> {
        match self {
            Self::Claude { adapter, .. } => NativeAdapter::compare_approved_digests(adapter, plan),
            Self::Codex { adapter, .. } => NativeAdapter::compare_approved_digests(adapter, plan),
            Self::Hermes(adapter) => NativeAdapter::compare_approved_digests(adapter, plan),
        }
    }

    fn validate_staged_output(
        &mut self,
        plan: &NativeTransactionPlan,
        run: &RestrictedRun,
    ) -> Result<FrozenOutput, BoundaryError> {
        match self {
            Self::Claude { adapter, .. } => {
                NativeAdapter::validate_staged_output(adapter, plan, run)
            }
            Self::Codex { adapter, .. } => {
                NativeAdapter::validate_staged_output(adapter, plan, run)
            }
            Self::Hermes(adapter) => NativeAdapter::validate_staged_output(adapter, plan, run),
        }
    }

    fn validate_effective(
        &mut self,
        plan: &NativeTransactionPlan,
        receipt: &ApplyReceipt,
    ) -> Result<(), BoundaryError> {
        match self {
            Self::Claude { adapter, .. } => {
                NativeAdapter::validate_effective(adapter, plan, receipt)
            }
            Self::Codex { adapter, .. } => {
                NativeAdapter::validate_effective(adapter, plan, receipt)
            }
            Self::Hermes(adapter) => {
                receipt
                    .validate()
                    .map_err(|_| BoundaryError::new("Hermes effective receipt is invalid"))?;
                adapter
                    .import(&ImportRequest {
                        scopes: vec![
                            NativeScope::Global,
                            NativeScope::Project {
                                project_id: adapter.project_id(),
                                root: adapter.project_root_wire(),
                            },
                        ],
                        include_disabled: true,
                    })
                    .map_err(|_| BoundaryError::new("Hermes effective configuration is invalid"))?;
                Ok(())
            }
        }
    }

    fn release_live_state_reservation(&mut self) -> Result<(), BoundaryError> {
        match self {
            Self::Claude { adapter, .. } => NativeAdapter::release_live_state_reservation(adapter),
            Self::Codex { adapter, .. } => NativeAdapter::release_live_state_reservation(adapter),
            Self::Hermes(adapter) => NativeAdapter::release_live_state_reservation(adapter),
        }
    }
}

fn codex_cli_output(
    arguments: &[String],
    live: Option<&CanonicalCliDeclaration>,
) -> Result<Vec<u8>, BoundaryError> {
    match arguments {
        [plugin, list, format]
            if (plugin.as_str(), list.as_str(), format.as_str())
                == ("plugin", "list", "--json") =>
        {
            Ok(br#"{"installed":[],"available":[]}"#.to_vec())
        }
        [mcp, list, format]
            if (mcp.as_str(), list.as_str(), format.as_str()) == ("mcp", "list", "--json") =>
        {
            Ok(match live {
                Some(declaration) => codex_mcp_list(&declaration.canonical_body),
                None => b"[]".to_vec(),
            })
        }
        [mcp, get, name, format]
            if (mcp.as_str(), get.as_str(), name.as_str(), format.as_str())
                == ("mcp", "get", BRIDGE_SERVER_NAME, "--json") =>
        {
            Ok(codex_mcp_get(
                &live
                    .ok_or_else(|| BoundaryError::new("missing declaration"))?
                    .canonical_body,
            ))
        }
        _ => Err(BoundaryError::new("unexpected Codex CLI inspection")),
    }
}

fn codex_mcp_list(body: &str) -> Vec<u8> {
    let body: Value = serde_json::from_str(body).unwrap();
    serde_json::to_vec(&json!([{
        "name": BRIDGE_SERVER_NAME,
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

fn codex_mcp_get(body: &str) -> Vec<u8> {
    let body: Value = serde_json::from_str(body).unwrap();
    serde_json::to_vec(&json!({
        "name": BRIDGE_SERVER_NAME,
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

struct MatrixCli {
    live: Rc<RefCell<Option<CanonicalCliDeclaration>>>,
}

impl NativeCliExecutor for MatrixCli {
    fn probe_cli_mutation(
        &mut self,
        _: &ApprovedCliMutation,
    ) -> Result<Option<Sha256Digest>, BoundaryError> {
        Ok(self.live.borrow().as_ref().map(|value| value.fingerprint))
    }

    fn compare_cli_targets(
        &mut self,
        mutations: &[ApprovedCliMutation],
    ) -> Result<(), BoundaryError> {
        for mutation in mutations {
            if self.live.borrow().as_ref().map(|value| value.fingerprint)
                != mutation.expected.as_ref().map(|value| value.fingerprint)
            {
                return Err(BoundaryError::new("managed CLI declaration changed"));
            }
        }
        Ok(())
    }

    fn apply_cli_mutation(
        &mut self,
        mutation: &ApprovedCliMutation,
    ) -> Result<CliMutationOutcome, BoundaryError> {
        let live = self.live.borrow().as_ref().map(|value| value.fingerprint);
        if live == mutation.expected.as_ref().map(|value| value.fingerprint) {
            self.live.borrow_mut().clone_from(&mutation.intended);
        }
        Ok(CliMutationOutcome {
            resulting_fingerprint: self.live.borrow().as_ref().map(|value| value.fingerprint),
            command_error: None,
        })
    }

    fn restore_cli_mutation_if_matches(
        &mut self,
        mutation: &ApprovedCliMutation,
    ) -> Result<CliRestoreOutcome, BoundaryError> {
        let intended = mutation.intended.as_ref().map(|value| value.fingerprint);
        if self.live.borrow().as_ref().map(|value| value.fingerprint) != intended {
            return Ok(CliRestoreOutcome {
                restored: false,
                resulting_fingerprint: self.live.borrow().as_ref().map(|value| value.fingerprint),
            });
        }
        self.live.borrow_mut().clone_from(&mutation.expected);
        Ok(CliRestoreOutcome {
            restored: true,
            resulting_fingerprint: self.live.borrow().as_ref().map(|value| value.fingerprint),
        })
    }

    fn finish_committed_cli_mutations(
        &mut self,
        mutations: &[ApprovedCliMutation],
    ) -> Result<(), BoundaryError> {
        for mutation in mutations {
            if self.live.borrow().as_ref().map(|value| value.fingerprint)
                != mutation.intended.as_ref().map(|value| value.fingerprint)
            {
                return Err(BoundaryError::new("committed CLI declaration changed"));
            }
        }
        Ok(())
    }
}

struct MatrixRestricted {
    inputs: Vec<ApprovedInput>,
    sidecars: Vec<SidecarBinding>,
    run: RestrictedRun,
}

impl RestrictedExecutor for MatrixRestricted {
    fn copy_allowlisted_inputs(&mut self, inputs: &[ApprovedInput]) -> Result<(), BoundaryError> {
        (inputs == self.inputs)
            .then_some(())
            .ok_or_else(|| BoundaryError::new("staged inputs changed"))
    }

    fn create_fake_roots(&mut self) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn build_restricted_environment(&mut self) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn run_restricted_tools(
        &mut self,
        sidecars: &[SidecarBinding],
    ) -> Result<RestrictedRun, BoundaryError> {
        (sidecars == self.sidecars)
            .then(|| self.run.clone())
            .ok_or_else(|| BoundaryError::new("sidecars changed"))
    }

    fn reject_unsafe_topology(&mut self) -> Result<(), BoundaryError> {
        Ok(())
    }
}

struct MatrixExecutor<'a> {
    harness: &'a mut FrozenHarness,
    live: Rc<RefCell<Option<CanonicalCliDeclaration>>>,
    lock_root: PathBuf,
}

impl BridgePlanExecutor for MatrixExecutor<'_> {
    fn execute(
        &mut self,
        vault: &mut Vault,
        plan: &NativeTransactionPlan,
        sealed_plan: &[u8],
        created_ms: u64,
        now_ms: u64,
    ) -> Result<(), BridgeExecutionError> {
        self.execute_with_hook(vault, plan, sealed_plan, created_ms, now_ms, &mut NoFault)
    }
}

impl MatrixExecutor<'_> {
    fn execute_with_hook(
        &mut self,
        vault: &mut Vault,
        plan: &NativeTransactionPlan,
        sealed_plan: &[u8],
        created_ms: u64,
        now_ms: u64,
        hook: &mut impl FaultHook,
    ) -> Result<(), BridgeExecutionError> {
        let mut restricted = MatrixRestricted {
            inputs: plan.staged_inputs.clone(),
            sidecars: plan.sidecars.clone(),
            run: RestrictedRun {
                staged_output_hash: plan.expected_semantic_output_hash,
                scanner_result_hash: plan.scanner_result_hash,
            },
        };
        let mut filesystem = OsNativeTransactionFileSystem::new(*plan.setup.plan_id.as_bytes());
        let mut cli = MatrixCli {
            live: self.live.clone(),
        };
        NativeEngineBridgePlanExecutor::new(
            &mut *self.harness,
            &mut restricted,
            &mut filesystem,
            hook,
            &mut cli,
            &self.lock_root,
            NativeSandboxIdentity::Windows {
                moniker: "context-relay.native.0123456789abcdef0123456789abcdef".to_owned(),
                sid: b"S-1-15-2-3872518810-2985098273-1912316193-2655983105-1250049442-371239648-1157085541".to_vec(),
            },
            BeforeImagePolicy::default(),
            HybridLogicalClock::new(now_ms, 0, DeviceId::from_str(ID_1).unwrap()),
        )
        .execute(vault, plan, sealed_plan, created_ms, now_ms)
    }
}

struct CrashBeforeNativeCleanup<'a>(MatrixExecutor<'a>);

struct CommitCrash;

impl FaultHook for CommitCrash {
    fn after_step(&mut self, step: TransactionStep) -> Result<(), BoundaryError> {
        if step == TransactionStep::CommitOwnershipAndReceipt {
            panic!("simulated exit with committed native and CLI WAL still present");
        }
        Ok(())
    }
}

impl BridgePlanExecutor for CrashBeforeNativeCleanup<'_> {
    fn execute(
        &mut self,
        vault: &mut Vault,
        plan: &NativeTransactionPlan,
        sealed_plan: &[u8],
        created_ms: u64,
        now_ms: u64,
    ) -> Result<(), BridgeExecutionError> {
        self.0.execute_with_hook(
            vault,
            plan,
            sealed_plan,
            created_ms,
            now_ms,
            &mut CommitCrash,
        )
    }
}

struct BoundMatrixCliRecovery<'a> {
    harness: &'a mut FrozenHarness,
    cli: MatrixCli,
}

impl NativeCliRecoveryIo for BoundMatrixCliRecovery<'_> {
    fn probe_cli_declaration(
        &mut self,
        sealed: &[u8],
        row: &NativeCliWalRecord,
    ) -> Result<Option<Sha256Digest>, BoundaryError> {
        let bound = bind_cli_recovery_plan(sealed, std::slice::from_ref(row))?;
        NativeAdapter::reprobe_live_state(self.harness, &bound.plan)?;
        self.cli.probe_cli_mutation(&bound.mutations[0])
    }

    fn restore_cli_mutation_if_matches(
        &mut self,
        sealed: &[u8],
        row: &NativeCliWalRecord,
    ) -> Result<CliRecoveryRestore, BoundaryError> {
        let bound = bind_cli_recovery_plan(sealed, std::slice::from_ref(row))?;
        NativeAdapter::reprobe_live_state(self.harness, &bound.plan)?;
        self.cli
            .restore_cli_mutation_if_matches(&bound.mutations[0])
            .map(|outcome| {
                if outcome.restored {
                    CliRecoveryRestore::Restored
                } else {
                    CliRecoveryRestore::Conflict
                }
            })
    }

    fn finish_committed_cli_mutations(
        &mut self,
        sealed: &[u8],
        rows: &[NativeCliWalRecord],
    ) -> Result<(), BoundaryError> {
        let bound = bind_cli_recovery_plan(sealed, rows)?;
        NativeAdapter::reprobe_live_state(self.harness, &bound.plan)?;
        self.cli.finish_committed_cli_mutations(&bound.mutations)
    }
}

struct CrashAfterCommit<'a>(MatrixExecutor<'a>);

impl BridgePlanExecutor for CrashAfterCommit<'_> {
    fn execute(
        &mut self,
        vault: &mut Vault,
        plan: &NativeTransactionPlan,
        sealed_plan: &[u8],
        created_ms: u64,
        now_ms: u64,
    ) -> Result<(), BridgeExecutionError> {
        self.0
            .execute(vault, plan, sealed_plan, created_ms, now_ms)
            .unwrap();
        panic!("simulated exit after the native transaction committed")
    }
}

struct MustNotExecute;

impl BridgePlanExecutor for MustNotExecute {
    fn execute(
        &mut self,
        _: &mut Vault,
        _: &NativeTransactionPlan,
        _: &[u8],
        _: u64,
        _: u64,
    ) -> Result<(), BridgeExecutionError> {
        panic!("terminal setup replay executed again")
    }
}

struct MatrixFixture {
    _temp: tempfile::TempDir,
    harness: FrozenHarness,
    project_id: ProjectId,
    project_root: PathBuf,
    lock_root: PathBuf,
    bridge: BridgeExecutable,
    raw_files: Vec<(PathBuf, Vec<u8>)>,
}

fn matrix_fixture(harness: HarnessId) -> MatrixFixture {
    match harness {
        HarnessId::ClaudeCode => claude_matrix_fixture(),
        HarnessId::Codex => codex_matrix_fixture(),
        HarnessId::Hermes => hermes_matrix_fixture(),
    }
}

fn claude_matrix_fixture() -> MatrixFixture {
    claude_matrix_fixture_with_version("2.1.214")
}

fn claude_matrix_fixture_with_version(version: &str) -> MatrixFixture {
    let source: Value =
        serde_json::from_str(include_str!("fixtures/claude-code-2.1.214.json")).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let config_dir = root.join("claude");
    let lock_root = root.join("locks");
    fs::create_dir(&lock_root).unwrap();
    let project_root = root.join("project with spaces");
    materialize_json(&config_dir, source["config"].as_object().unwrap());
    materialize_json(&project_root, source["project"].as_object().unwrap());
    let state_path = config_dir.join(".claude.json");
    let mut state = source["state"].clone();
    let project = state["projects"]
        .as_object_mut()
        .unwrap()
        .remove("$PROJECT")
        .unwrap();
    state["projects"]
        .as_object_mut()
        .unwrap()
        .insert(project_root.display().to_string(), project);
    fs::write(&state_path, serde_json::to_vec(&state).unwrap()).unwrap();
    let managed = root.join("managed-settings.json");
    fs::write(
        &managed,
        serde_json::to_vec(&source["managedSettings"]).unwrap(),
    )
    .unwrap();
    // `VerifiedClaudeExecutable::open` verifies the executable is a native
    // PE image on Windows, so the fixture carries the `.exe` suffix and a
    // minimal MZ header with a PE signature there. The path derives from
    // the plain tempdir (not the verbatim canonical root): the transaction
    // engine requires the canonical lock root, while the Claude topology
    // validator rejects verbatim `\\?\` components — both paths denote the
    // same directory.
    let claude_path = temp
        .path()
        .join(format!("claude-bin{}", std::env::consts::EXE_SUFFIX));
    let mut claude_bytes = b"fixture claude executable".to_vec();
    if cfg!(windows) {
        claude_bytes = vec![0_u8; 0x44];
        claude_bytes[0] = b'M';
        claude_bytes[1] = b'Z';
        let pe_offset: u32 = 0x40;
        claude_bytes[0x3c..0x40].copy_from_slice(&pe_offset.to_le_bytes());
        claude_bytes[0x40..0x44].copy_from_slice(b"PE\0\0");
    }
    let executable = executable(&claude_path, &claude_bytes);
    let raw_files = raw_sentinels(&config_dir);
    let project_id = ProjectId::from_str(ID_2).unwrap();
    let device_id = DeviceId::from_str(ID_1).unwrap();
    let adapter = ClaudeCodeAdapter::from_layout(
        ClaudeCodeLayout {
            user_home: PathBuf::from(root.to_str().unwrap().trim_start_matches(r"\\?\")),
            executable,
            version: version.to_owned(),
            installation_method: InstallationMethod::PackageManager,
            config_dir,
            state_path,
            project_root: project_root.clone(),
            managed_settings_paths: vec![managed],
        },
        project_id,
        device_id,
        HybridLogicalClock::new(NOW_MS, 0, device_id),
    )
    .unwrap();
    MatrixFixture {
        _temp: temp,
        harness: FrozenHarness::Claude {
            adapter,
            cli: Rc::new(RefCell::new(None)),
        },
        project_id,
        project_root,
        lock_root,
        bridge: matrix_bridge(&root),
        raw_files,
    }
}

fn codex_matrix_fixture() -> MatrixFixture {
    codex_matrix_fixture_with_version("0.144.1")
}

fn codex_matrix_fixture_with_version(version: &str) -> MatrixFixture {
    let source: Value = serde_json::from_str(include_str!("fixtures/codex-0.144.1.json")).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let codex_home = root.join("codex");
    let lock_root = root.join("locks");
    fs::create_dir(&lock_root).unwrap();
    let home = root.join("home");
    let project_root = root.join("project");
    let working_directory = project_root.join("service");
    materialize_json_substituting(
        &codex_home,
        source["codexHome"].as_object().unwrap(),
        &project_root,
    );
    materialize_json(
        &home.join(".agents/skills"),
        source["userSkills"].as_object().unwrap(),
    );
    materialize_json(&project_root, source["project"].as_object().unwrap());
    fs::create_dir_all(&working_directory).unwrap();
    let executable = executable(&root.join("codex-bin"), b"\x7fELFfixture codex executable");
    let raw_files = [
        codex_home.join("sessions/2026/session.jsonl"),
        codex_home.join("history.jsonl"),
        codex_home.join("state_5.sqlite"),
    ]
    .into_iter()
    .map(|path| {
        let bytes = fs::read(&path).unwrap();
        (path, bytes)
    })
    .collect();
    let project_id = ProjectId::from_str(ID_2).unwrap();
    let device_id = DeviceId::from_str(ID_1).unwrap();
    let adapter = CodexAdapter::from_layout(
        CodexLayout {
            executable,
            executable_kind: CodexExecutableKind::Native,
            version: version.to_owned(),
            installation_method: InstallationMethod::PackageManager,
            codex_home,
            user_skills_dir: home.join(".agents/skills"),
            project_root: project_root.clone(),
            working_directory,
            requirements_paths: vec![],
        },
        project_id,
        device_id,
        HybridLogicalClock::new(NOW_MS, 0, device_id),
    )
    .unwrap();
    MatrixFixture {
        _temp: temp,
        harness: FrozenHarness::Codex {
            adapter,
            cli: Rc::new(RefCell::new(None)),
        },
        project_id,
        project_root,
        lock_root,
        bridge: matrix_bridge(&root),
        raw_files,
    }
}

fn hermes_matrix_fixture() -> MatrixFixture {
    hermes_matrix_fixture_with_version("0.18.2")
}

fn hermes_matrix_fixture_with_version(version: &str) -> MatrixFixture {
    let source: Value = serde_json::from_str(include_str!("fixtures/hermes-0.18.2.json")).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let profile = source["profile"].as_object().unwrap();
    let default_hermes_home = root.join("hermes");
    let lock_root = root.join("locks");
    fs::create_dir(&lock_root).unwrap();
    let hermes_home = default_hermes_home.join("profiles/coder");
    let mut profile_files = profile["files"].as_object().unwrap().clone();
    profile_files.remove("gateway.pid");
    profile_files.remove("gateway_state.json");
    materialize_json(&hermes_home, &profile_files);
    let mut config = profile["configYaml"].as_str().unwrap().to_owned();
    config.push_str(source["nativeMemoryConfigYaml"].as_str().unwrap());
    fs::write(hermes_home.join("config.yaml"), config).unwrap();
    let project_root = root.join("project");
    let working_directory = project_root.join("service");
    materialize_json(&project_root, source["project"].as_object().unwrap());
    fs::create_dir_all(&working_directory).unwrap();
    let executable = executable(
        &root.join("hermes-bin"),
        b"\x7fELFfixture hermes executable",
    );
    let mut raw_files = vec![hermes_home.join("sessions/session.jsonl")];
    let history = hermes_home.join("history.jsonl");
    fs::write(&history, b"HERMES_HISTORY_RAW_SENTINEL\n").unwrap();
    raw_files.push(history);
    let raw_files = raw_files
        .into_iter()
        .map(|path| {
            let bytes = fs::read(&path).unwrap();
            (path, bytes)
        })
        .collect();
    let project_id = ProjectId::from_str(ID_2).unwrap();
    let device_id = DeviceId::from_str(ID_1).unwrap();
    let adapter = HermesAdapter::from_layout(
        HermesLayout {
            executable,
            executable_kind: HermesExecutableKind::Native,
            version: version.to_owned(),
            installation_method: InstallationMethod::PackageManager,
            default_hermes_home,
            profile: HermesProfile {
                name: "coder".to_owned(),
                hermes_home,
            },
            project_root: project_root.clone(),
            working_directory,
        },
        project_id,
        device_id,
        HybridLogicalClock::new(NOW_MS, 0, device_id),
    )
    .unwrap();
    MatrixFixture {
        _temp: temp,
        harness: FrozenHarness::Hermes(adapter),
        project_id,
        project_root,
        lock_root,
        bridge: matrix_bridge(&root),
        raw_files,
    }
}

fn materialize_json(root: &Path, files: &Map<String, Value>) {
    for (relative, body) in files {
        seed(root.join(relative), body.as_str().unwrap().as_bytes());
    }
}

fn materialize_json_substituting(root: &Path, files: &Map<String, Value>, project: &Path) {
    let project = project.to_string_lossy();
    for (relative, body) in files {
        let body = body.as_str().unwrap();
        let body = if relative.ends_with(".toml") {
            // The quoted TOML key needs string escaping, unlike plain-text paths.
            body.replace(
                "\"$PROJECT\"",
                &serde_json::to_string(project.as_ref()).unwrap(),
            )
        } else {
            body.replace("$PROJECT", project.as_ref())
        };
        seed(root.join(relative), body.as_bytes());
    }
}

#[test]
fn fixture_project_substitution_preserves_windows_paths_in_toml() {
    let frozen: Value = serde_json::from_str(include_str!("fixtures/codex-0.144.1.json")).unwrap();
    let mut files = frozen["codexHome"].as_object().unwrap().clone();
    files.insert("project.txt".to_owned(), json!("Project: \"$PROJECT\"\n"));
    for project in [
        r"C:\Users\runner\project with spaces",
        r"C:\temp\repo",
        r"\\?\C:\Users\runner\project with spaces",
        r"\\server\share\project",
        r"\\?\UNC\server\share\專案",
        r"C:\使用者\專案 α",
        "/tmp/project with \"quotes\"",
    ] {
        let temp = tempfile::tempdir().unwrap();
        materialize_json_substituting(temp.path(), &files, Path::new(project));
        let config = fs::read_to_string(temp.path().join("config.toml")).unwrap();
        let document = config
            .parse::<toml_edit::DocumentMut>()
            .unwrap_or_else(|error| panic!("fixture TOML must parse for {project:?}: {error}"));
        let projects = document["projects"].as_table().unwrap();
        assert_eq!(projects.len(), 1);
        assert_eq!(
            projects
                .get(project)
                .and_then(|entry| entry["trust_level"].as_str()),
            Some("trusted"),
            "project key must round-trip exactly for {project:?}"
        );
        assert_eq!(
            fs::read_to_string(temp.path().join("project.txt")).unwrap(),
            format!("Project: \"{project}\"\n")
        );
    }
}

fn executable(path: &Path, bytes: &[u8]) -> PathBuf {
    seed(path.to_path_buf(), bytes);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    path.to_path_buf()
}

fn matrix_bridge(root: &Path) -> BridgeExecutable {
    let path = executable(
        &root.join("context-relay-context-mcp"),
        b"matrix bridge executable",
    );
    attest_bridge_executable(&path).unwrap()
}

fn raw_sentinels(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    [
        (
            "sessions/session.jsonl",
            b"RAW_SESSION_PROMPT_RESPONSE_SENTINEL\n".as_slice(),
        ),
        ("history.jsonl", b"RAW_HISTORY_SENTINEL\n".as_slice()),
    ]
    .into_iter()
    .map(|(relative, bytes)| {
        let path = seed(root.join(relative), bytes);
        (path, bytes.to_vec())
    })
    .collect()
}

fn assert_raw_unchanged(fixture: &MatrixFixture) {
    for (path, before) in &fixture.raw_files {
        assert_eq!(
            fs::read(path).unwrap(),
            *before,
            "{} changed",
            path.display()
        );
    }
}

fn snapshot_tree(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, path: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
        let mut entries = fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        entries.sort();
        for entry in entries {
            let metadata = fs::symlink_metadata(&entry).unwrap();
            if metadata.is_dir() {
                visit(root, &entry, files);
            } else if metadata.is_file() {
                files.insert(
                    entry.strip_prefix(root).unwrap().to_path_buf(),
                    fs::read(entry).unwrap(),
                );
            }
        }
    }

    let mut files = BTreeMap::new();
    visit(root, root, &mut files);
    files
}

fn mutation_path(value: &WireNativeValue) -> PathBuf {
    #[cfg(unix)]
    {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt as _};
        PathBuf::from(OsString::from_vec(value.bytes.clone()))
    }
    #[cfg(windows)]
    {
        use std::{ffi::OsString, os::windows::ffi::OsStringExt as _};
        PathBuf::from(OsString::from_wide(
            &value
                .bytes
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect::<Vec<_>>(),
        ))
    }
}

fn intended_bytes(mutation: &ApprovedMutation) -> Vec<u8> {
    match NativeState::decode_v1(&mutation.content).unwrap() {
        NativeState::RegularFile { bytes, .. } => bytes,
        NativeState::Absent { .. } => panic!("memory setup unexpectedly removes a target"),
    }
}

#[test]
fn frozen_harnesses_transact_authoritative_memory_with_recovery_and_raw_privacy() {
    for harness_id in [HarnessId::ClaudeCode, HarnessId::Codex, HarnessId::Hermes] {
        let mut fixture = matrix_fixture(harness_id);
        if harness_id == HarnessId::Codex {
            fs::write(
                fixture.project_root.join(".codex/config.toml"),
                "# project memory override\n[memories]\nuse_memories = true\n",
            )
            .unwrap();
            fs::write(
                fixture.project_root.join("service/.codex/config.toml"),
                "# nested memory override\n[memories]\ngenerate_memories = true\n",
            )
            .unwrap();
        }
        let vault_path = TempVault::new(&format!("primary-memory-matrix-{harness_id:?}"));
        let keys = MemoryKeyStore::default();
        let mut vault = Vault::open(vault_path.path(), "primary-memory-setup-v1", &keys).unwrap();
        let calls = Rc::new(Cell::new(0));
        let setup = BridgeInstallService::new(
            &mut vault,
            fixture.harness.clone(),
            Locator {
                bridge: fixture.bridge.clone(),
                calls,
            },
            DeviceId::from_str(ID_1).unwrap(),
            clock(NOW_MS),
        )
        .preview(
            Some(&RegisteredProject {
                project_id: fixture.project_id,
                root: wire_path(&fixture.project_root),
            }),
            NOW_MS,
        )
        .unwrap();
        let stored = vault.setup_plan(&setup.plan_id).unwrap().unwrap();
        let opened = open_plan(&stored.payload).unwrap();
        assert_eq!(
            opened.plan.sidecars[0].target,
            RuntimeTarget::current().unwrap()
        );
        assert_eq!(opened.plan.setup.harness, harness_id);
        assert_eq!(opened.plan.native_memory_registrations.len(), 2);
        assert_eq!(
            opened.plan.cli_mutations.is_empty(),
            harness_id == HarnessId::Hermes
        );
        assert!(opened.plan.mutations.len() >= 2);
        let original = opened
            .plan
            .mutations
            .iter()
            .map(|mutation| {
                let path = mutation_path(&mutation.target);
                let bytes = fs::read(&path).unwrap();
                (path, bytes)
            })
            .collect::<Vec<_>>();
        let intended = opened
            .plan
            .mutations
            .iter()
            .map(|mutation| (mutation_path(&mutation.target), intended_bytes(mutation)))
            .collect::<Vec<_>>();
        for mutation in &opened.plan.mutations {
            let path = mutation_path(&mutation.target);
            let snapshot = OsNativeFileSystem::new().snapshot(&path).unwrap();
            let live = RestorableStateFingerprint(Sha256Digest(*snapshot.fingerprint()));
            if harness_id == HarnessId::Hermes && live != mutation.expected {
                let lock = opened
                    .plan
                    .setup
                    .expected_native_digests
                    .iter()
                    .find(|expected| {
                        expected.expected_digest.is_none()
                            && mutation_path(&expected.target).file_name()
                                == Some(std::ffi::OsStr::new("gateway.lock"))
                    })
                    .expect("Hermes post-reservation fingerprint needs an approved absent lock");
                assert!(!mutation_path(&lock.target).exists());
            } else {
                assert_eq!(
                    live,
                    mutation.expected,
                    "{harness_id:?}: preview changed {}",
                    path.display()
                );
            }
        }
        assert!(intended.iter().any(|(_, bytes)| {
            String::from_utf8_lossy(bytes).contains(PRIMARY_MEMORY_INSTRUCTIONS)
        }));
        assert!(intended.iter().any(|(_, bytes)| {
            String::from_utf8_lossy(bytes).contains("typed `context_relay_complete_task` tool")
        }));
        assert!(intended.iter().all(|(_, bytes)| {
            let text = String::from_utf8_lossy(bytes);
            !text.contains("--hook-event task-evidence") && !text.contains("session_id")
        }));
        match harness_id {
            HarnessId::ClaudeCode => {
                assert_eq!(intended.len(), 3);
                assert!(intended.iter().any(|(_, bytes)| {
                    let text = String::from_utf8_lossy(bytes);
                    text.contains("\"autoMemoryEnabled\":false")
                        && text.contains("\"autoMemoryDirectory\":\"~/project with spaces/.claude/native-memory\"")
                }));
                assert!(intended.iter().any(|(_, bytes)| {
                    let text = String::from_utf8_lossy(bytes);
                    text.contains("--hook-event session-start --harness claude-code")
                        && text.contains("--hook-event session-stop --harness claude-code")
                }));
            }
            HarnessId::Codex => {
                assert_eq!(intended.len(), 5);
                assert!(intended.iter().any(|(path, bytes)| path
                    == &fixture.project_root.join(".codex/config.toml")
                    && String::from_utf8_lossy(bytes).contains("use_memories = false")));
                assert!(intended.iter().any(|(_, bytes)| {
                    let text = String::from_utf8_lossy(bytes);
                    text.contains("generate_memories = false")
                        && text.contains("use_memories = false")
                }));
                assert!(intended.iter().any(|(_, bytes)| {
                    let text = String::from_utf8_lossy(bytes);
                    text.contains("--hook-event session-start --harness codex")
                        && text.contains("--hook-event session-stop --harness codex")
                        && !text.contains("task-evidence")
                }));
            }
            HarnessId::Hermes => {
                assert_eq!(intended.len(), 2);
                assert!(intended.iter().any(|(_, bytes)| {
                    let text = String::from_utf8_lossy(bytes);
                    text.contains("memory_enabled: false")
                        && text.contains("user_profile_enabled: false")
                        && text.contains("mcp_servers:")
                }));
                assert!(intended.iter().all(|(_, bytes)| {
                    !String::from_utf8_lossy(bytes).contains("--hook-event")
                }));
            }
        }
        for registration in &opened.plan.native_memory_registrations {
            assert!(
                vault
                    .native_memory_ledger(&registration.source.id)
                    .unwrap()
                    .is_none(),
                "{harness_id:?}: preview activated a source"
            );
        }
        assert_raw_unchanged(&fixture);

        let live = fixture.harness.cli_state();
        let crashed = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let mut executor = CrashBeforeNativeCleanup(MatrixExecutor {
                harness: &mut fixture.harness,
                live: live.clone(),
                lock_root: fixture.lock_root.clone(),
            });
            let _ = BridgeInstallService::persisted(&mut vault).apply(
                &setup.plan_id,
                NOW_MS + 1,
                &mut executor,
            );
        }));
        assert!(crashed.is_err());
        assert_eq!(
            vault.setup_plan(&setup.plan_id).unwrap().unwrap().lifecycle,
            SetupPlanLifecycle::Applying
        );
        if !opened.plan.cli_mutations.is_empty() {
            let wal = vault
                .native_cli_wal(&format!("bridge-setup-{}", setup.plan_id))
                .unwrap();
            assert!(!wal.is_empty());
            let bound = context_relay_core::native_transaction::recovery::bind_cli_recovery_plan(
                &stored.payload,
                &wal,
            )
            .unwrap();
            assert_eq!(bound.plan, opened.plan);
            assert_eq!(bound.mutations, opened.plan.cli_mutations);
        }
        for (path, bytes) in &intended {
            assert_eq!(fs::read(path).unwrap(), *bytes, "{}", path.display());
        }
        for registration in &opened.plan.native_memory_registrations {
            assert!(
                vault
                    .native_memory_ledger(&registration.source.id)
                    .unwrap()
                    .is_none(),
                "{harness_id:?}: source activated before recovery"
            );
        }
        assert_raw_unchanged(&fixture);

        let mut recovery_io = OsNativeRecoveryIo::new(|_, _| Ok(()));
        let mut cli_recovery = BoundMatrixCliRecovery {
            harness: &mut fixture.harness,
            cli: MatrixCli { live: live.clone() },
        };
        recover_native_transactions_with_cli(&mut vault, &mut recovery_io, &mut cli_recovery)
            .unwrap();
        assert!(
            vault
                .native_cli_wal(&format!("bridge-setup-{}", setup.plan_id))
                .unwrap()
                .is_empty()
        );
        BridgeInstallService::persisted(&mut vault)
            .reconcile_after_native_recovery()
            .unwrap();
        for registration in &opened.plan.native_memory_registrations {
            assert_eq!(
                vault
                    .native_memory_ledger(&registration.source.id)
                    .unwrap()
                    .unwrap()
                    .source,
                Some(registration.source.clone())
            );
        }
        BridgeInstallService::persisted(&mut vault)
            .apply(&setup.plan_id, NOW_MS + 2, &mut MustNotExecute)
            .unwrap();
        for (path, bytes) in &intended {
            assert_eq!(fs::read(path).unwrap(), *bytes, "{}", path.display());
        }

        let mut executor = MatrixExecutor {
            harness: &mut fixture.harness,
            live,
            lock_root: fixture.lock_root.clone(),
        };
        BridgeInstallService::persisted(&mut vault)
            .rollback(&setup.plan_id, NOW_MS + 3, &mut executor)
            .unwrap();
        for (path, bytes) in &original {
            assert_eq!(fs::read(path).unwrap(), *bytes, "{}", path.display());
        }
        for registration in &opened.plan.native_memory_registrations {
            assert!(
                vault
                    .native_memory_ledger(&registration.source.id)
                    .unwrap()
                    .is_none(),
                "{harness_id:?}: rollback retained a plan-owned source"
            );
        }
        BridgeInstallService::persisted(&mut vault)
            .rollback(&setup.plan_id, NOW_MS + 4, &mut MustNotExecute)
            .unwrap();
        assert_raw_unchanged(&fixture);
    }
}

#[test]
fn hermes_managed_export_seals_the_full_file_digest_and_recovers_before_activation() {
    let mut fixture = hermes_matrix_fixture();
    let FrozenHarness::Hermes(adapter) = fixture.harness.clone() else {
        panic!("Hermes export fixture changed")
    };
    let vault_path = TempVault::new("primary-memory-hermes-export");
    let keys = MemoryKeyStore::default();
    let mut vault =
        Vault::open(vault_path.path(), "primary-memory-hermes-export-v1", &keys).unwrap();

    let setup = HermesMemoryExportService::new(&mut vault)
        .preview(
            &adapter,
            HermesMemoryKind::Agent,
            "Context Relay owns this exported Hermes memory.",
            NOW_MS,
        )
        .unwrap();
    let stored = vault.setup_plan(&setup.plan_id).unwrap().unwrap();
    let opened = open_plan(&stored.payload).unwrap();
    assert_eq!(
        opened.plan.sidecars[0].target,
        RuntimeTarget::current().unwrap()
    );
    assert_eq!(opened.plan.mutations.len(), 1);
    assert_eq!(opened.plan.native_memory_registrations.len(), 1);
    let mutation = &opened.plan.mutations[0];
    let intended = intended_bytes(mutation);
    let registration = &opened.plan.native_memory_registrations[0];
    assert_eq!(mutation.target, registration.source.path);
    assert_eq!(
        registration.last_applied_digest,
        Some(Sha256Digest(Sha256::digest(&intended).into()))
    );
    assert!(
        vault
            .native_memory_ledger(&registration.source.id)
            .unwrap()
            .is_none()
    );

    let live = fixture.harness.cli_state();
    let crashed = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let mut executor = CrashAfterCommit(MatrixExecutor {
            harness: &mut fixture.harness,
            live,
            lock_root: fixture.lock_root.clone(),
        });
        let _ = BridgeInstallService::persisted(&mut vault).apply(
            &setup.plan_id,
            NOW_MS + 1,
            &mut executor,
        );
    }));
    assert!(crashed.is_err());
    assert_eq!(fs::read(mutation_path(&mutation.target)).unwrap(), intended);
    assert_eq!(
        vault.setup_plan(&setup.plan_id).unwrap().unwrap().lifecycle,
        SetupPlanLifecycle::Applying
    );
    assert!(
        vault
            .native_memory_ledger(&registration.source.id)
            .unwrap()
            .is_none()
    );

    BridgeInstallService::persisted(&mut vault)
        .reconcile_after_native_recovery()
        .unwrap();
    let ledger = vault
        .native_memory_ledger(&registration.source.id)
        .unwrap()
        .unwrap();
    assert_eq!(ledger.source, Some(registration.source.clone()));
    assert_eq!(ledger.last_applied_digest, registration.last_applied_digest);
    assert!(!ledger.initial_preview_complete);
    assert_raw_unchanged(&fixture);
}

#[test]
fn passive_hermes_export_rejects_concurrent_target_change_and_preserves_live_bytes() {
    let mut fixture = hermes_matrix_fixture();
    let FrozenHarness::Hermes(adapter) = fixture.harness.clone() else {
        panic!("Hermes export fixture changed")
    };
    let vault_path = TempVault::new("primary-memory-hermes-export-concurrent-change");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(
        vault_path.path(),
        "primary-memory-hermes-export-concurrent-change-v1",
        &keys,
    )
    .unwrap();

    let setup = HermesMemoryExportService::new(&mut vault)
        .preview(
            &adapter,
            HermesMemoryKind::Agent,
            "Context Relay reviewed this export before a concurrent edit.",
            NOW_MS,
        )
        .unwrap();
    assert_eq!(
        setup.approval_class,
        context_relay_protocol::ApprovalClass::Passive
    );
    let opened = open_plan(&vault.setup_plan(&setup.plan_id).unwrap().unwrap().payload).unwrap();
    let mutation = &opened.plan.mutations[0];
    let target = mutation_path(&mutation.target);
    let concurrent = b"Hermes changed this memory after preview.\n";
    fs::write(&target, concurrent).unwrap();
    let mut executor = MatrixExecutor {
        live: fixture.harness.cli_state(),
        harness: &mut fixture.harness,
        lock_root: fixture.lock_root.clone(),
    };

    let error = HermesMemoryExportService::new(&mut vault)
        .apply(&setup.plan_id, NOW_MS + 1, &mut executor)
        .unwrap_err();

    assert_eq!(error.code, context_relay_protocol::ErrorCode::Conflict);
    assert_eq!(fs::read(&target).unwrap(), concurrent);
    assert_eq!(
        vault.setup_plan(&setup.plan_id).unwrap().unwrap().lifecycle,
        SetupPlanLifecycle::ApplyRestored
    );
    for registration in &opened.plan.native_memory_registrations {
        assert!(
            vault
                .native_memory_ledger(&registration.source.id)
                .unwrap()
                .is_none()
        );
    }
    assert_raw_unchanged(&fixture);
}

#[test]
fn supported_claude_missing_project_settings_recovers_creation_and_rolls_back_to_absent() {
    let mut fixture = claude_matrix_fixture();
    let settings_path = fixture.project_root.join(".claude/settings.json");
    fs::remove_file(&settings_path).unwrap();
    assert!(!settings_path.exists());
    let vault_path = TempVault::new("primary-memory-claude-missing-settings");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(vault_path.path(), "primary-memory-setup-v1", &keys).unwrap();
    let setup = BridgeInstallService::new(
        &mut vault,
        fixture.harness.clone(),
        Locator {
            bridge: fixture.bridge.clone(),
            calls: Rc::new(Cell::new(0)),
        },
        DeviceId::from_str(ID_1).unwrap(),
        clock(NOW_MS),
    )
    .preview(
        Some(&RegisteredProject {
            project_id: fixture.project_id,
            root: wire_path(&fixture.project_root),
        }),
        NOW_MS,
    )
    .unwrap();
    let opened = open_plan(&vault.setup_plan(&setup.plan_id).unwrap().unwrap().payload).unwrap();
    let settings = opened
        .plan
        .mutations
        .iter()
        .find(|mutation| mutation_path(&mutation.target) == settings_path)
        .expect("missing supported settings must be sealed as an exact native mutation");
    let NativeState::RegularFile { bytes, .. } = NativeState::decode_v1(&settings.content).unwrap()
    else {
        panic!("missing settings must be created as a regular file")
    };
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap()["autoMemoryEnabled"],
        false
    );

    let live = fixture.harness.cli_state();
    let crashed = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let mut executor = CrashAfterCommit(MatrixExecutor {
            harness: &mut fixture.harness,
            live: live.clone(),
            lock_root: fixture.lock_root.clone(),
        });
        let _ = BridgeInstallService::persisted(&mut vault).apply(
            &setup.plan_id,
            NOW_MS + 1,
            &mut executor,
        );
    }));
    assert!(crashed.is_err());
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(&settings_path).unwrap()).unwrap()["autoMemoryEnabled"],
        false
    );
    BridgeInstallService::persisted(&mut vault)
        .reconcile_after_native_recovery()
        .unwrap();

    let mut executor = MatrixExecutor {
        harness: &mut fixture.harness,
        live,
        lock_root: fixture.lock_root.clone(),
    };
    BridgeInstallService::persisted(&mut vault)
        .rollback(&setup.plan_id, NOW_MS + 2, &mut executor)
        .unwrap();
    assert!(!settings_path.exists());
}

#[test]
fn full_claude_setup_rejects_unavailable_native_memory_before_persisting_any_plan() {
    for (case, settings, expected_code) in [
        (
            "malformed",
            b"{malformed".as_slice(),
            context_relay_protocol::ErrorCode::InvalidRequest,
        ),
        (
            "invalid-directory-type",
            br#"{"autoMemoryDirectory":123}"#.as_slice(),
            context_relay_protocol::ErrorCode::HarnessUnsupported,
        ),
    ] {
        let fixture = claude_matrix_fixture();
        let settings_path = match &fixture.harness {
            FrozenHarness::Claude { adapter, .. } => adapter.project_settings_path(),
            _ => panic!("Claude fixture changed"),
        };
        fs::write(&settings_path, settings).unwrap();
        let before_tree = snapshot_tree(fixture._temp.path());
        let vault_path = TempVault::new(&format!("full-claude-unavailable-memory-{case}"));
        let keys = MemoryKeyStore::default();
        let mut vault = Vault::open(vault_path.path(), "primary-memory-setup-v1", &keys).unwrap();
        let before_vault = fs::read(vault_path.path()).unwrap();
        let cli = fixture.harness.cli_state();

        let error = BridgeInstallService::new(
            &mut vault,
            fixture.harness.clone(),
            Locator {
                bridge: fixture.bridge.clone(),
                calls: Rc::new(Cell::new(0)),
            },
            DeviceId::from_str(ID_1).unwrap(),
            clock(NOW_MS),
        )
        .preview(
            Some(&RegisteredProject {
                project_id: fixture.project_id,
                root: wire_path(&fixture.project_root),
            }),
            NOW_MS,
        )
        .unwrap_err();

        assert_eq!(error.code, expected_code, "{case}");
        assert_eq!(snapshot_tree(fixture._temp.path()), before_tree, "{case}");
        assert_eq!(fs::read(vault_path.path()).unwrap(), before_vault, "{case}");
        assert!(vault.native_memory_ledgers().unwrap().is_empty(), "{case}");
        assert!(vault.incomplete_setup_plans().unwrap().is_empty(), "{case}");
        assert!(cli.borrow().is_none(), "{case}");
    }
}

#[test]
fn import_only_exact_memory_bindings_apply_and_rollback_as_registration_only_plans() {
    for (harness_id, fixture) in [
        (
            HarnessId::ClaudeCode,
            claude_matrix_fixture_with_version("2.1.215"),
        ),
        (
            HarnessId::Codex,
            codex_matrix_fixture_with_version("0.145.0"),
        ),
        (
            HarnessId::Hermes,
            hermes_matrix_fixture_with_version("0.18.3"),
        ),
    ] {
        let vault_path = TempVault::new(&format!("watch-only-registration-{harness_id:?}"));
        let keys = MemoryKeyStore::default();
        let mut vault = Vault::open(vault_path.path(), "primary-memory-setup-v1", &keys).unwrap();
        let setup = BridgeInstallService::new(
            &mut vault,
            fixture.harness.clone(),
            Locator {
                bridge: fixture.bridge.clone(),
                calls: Rc::new(Cell::new(0)),
            },
            DeviceId::from_str(ID_1).unwrap(),
            clock(NOW_MS),
        )
        .preview(
            Some(&RegisteredProject {
                project_id: fixture.project_id,
                root: wire_path(&fixture.project_root),
            }),
            NOW_MS,
        )
        .unwrap();
        assert_eq!(setup.rulesync_version, "native-memory-watch-only-v1");
        assert!(setup.cli_operations.is_empty());
        let opened =
            open_plan(&vault.setup_plan(&setup.plan_id).unwrap().unwrap().payload).unwrap();
        assert_eq!(
            opened.plan.sidecars[0].target,
            RuntimeTarget::current().unwrap()
        );
        assert!(opened.plan.mutations.is_empty());
        assert!(opened.plan.cli_mutations.is_empty());
        assert_eq!(opened.plan.native_memory_registrations.len(), 2);
        assert!(
            opened
                .plan
                .native_memory_registrations
                .iter()
                .all(|registration| registration.source.harness == harness_id
                    && registration.last_applied_digest.is_none())
        );
        assert_eq!(
            opened.plan.setup.semantic_changes.len(),
            opened.plan.native_memory_registrations.len()
        );
        for registration in &opened.plan.native_memory_registrations {
            assert!(
                vault
                    .native_memory_ledger(&registration.source.id)
                    .unwrap()
                    .is_none()
            );
        }

        BridgeInstallService::persisted(&mut vault)
            .apply(&setup.plan_id, NOW_MS + 1, &mut MustNotExecute)
            .unwrap();
        for registration in &opened.plan.native_memory_registrations {
            assert_eq!(
                vault
                    .native_memory_ledger(&registration.source.id)
                    .unwrap()
                    .unwrap()
                    .source,
                Some(registration.source.clone())
            );
        }
        BridgeInstallService::persisted(&mut vault)
            .rollback(&setup.plan_id, NOW_MS + 2, &mut MustNotExecute)
            .unwrap();
        for registration in &opened.plan.native_memory_registrations {
            assert!(
                vault
                    .native_memory_ledger(&registration.source.id)
                    .unwrap()
                    .is_none()
            );
        }
        assert_raw_unchanged(&fixture);

        let recovery_setup = BridgeInstallService::new(
            &mut vault,
            fixture.harness.clone(),
            Locator {
                bridge: fixture.bridge.clone(),
                calls: Rc::new(Cell::new(0)),
            },
            DeviceId::from_str(ID_1).unwrap(),
            clock(NOW_MS + 10),
        )
        .preview(
            Some(&RegisteredProject {
                project_id: fixture.project_id,
                root: wire_path(&fixture.project_root),
            }),
            NOW_MS + 10,
        )
        .unwrap();
        let recovery_opened = open_plan(
            &vault
                .setup_plan(&recovery_setup.plan_id)
                .unwrap()
                .unwrap()
                .payload,
        )
        .unwrap();
        vault
            .claim_setup_plan(&recovery_setup.plan_id, SetupPlanAction::Apply, NOW_MS + 11)
            .unwrap();
        BridgeInstallService::persisted(&mut vault)
            .reconcile_after_native_recovery()
            .unwrap();
        assert_eq!(
            vault
                .setup_plan(&recovery_setup.plan_id)
                .unwrap()
                .unwrap()
                .lifecycle,
            SetupPlanLifecycle::Applied
        );
        for registration in &recovery_opened.plan.native_memory_registrations {
            assert_eq!(
                vault
                    .native_memory_ledger(&registration.source.id)
                    .unwrap()
                    .unwrap()
                    .source,
                Some(registration.source.clone())
            );
        }
        BridgeInstallService::persisted(&mut vault)
            .rollback(&recovery_setup.plan_id, NOW_MS + 12, &mut MustNotExecute)
            .unwrap();
        assert_raw_unchanged(&fixture);
    }
}

#[test]
fn codex_full_preview_rejects_uninspectable_memory_settings_without_writing() {
    for relative in [".codex/config.toml", "service/.codex/config.toml"] {
        let fixture = codex_matrix_fixture();
        let path = fixture.project_root.join(relative);
        fs::write(&path, "[memories]\nuse_memories = 'unsupported'\n").unwrap();
        let global = fixture
            .project_root
            .parent()
            .unwrap()
            .join("codex/config.toml");
        let before = fs::read(&global).unwrap();
        let vault_path = TempVault::new("codex-memory-invalid-preview");
        let keys = MemoryKeyStore::default();
        let mut vault = Vault::open(vault_path.path(), "primary-memory-setup-v1", &keys).unwrap();
        let error = BridgeInstallService::new(
            &mut vault,
            fixture.harness.clone(),
            Locator {
                bridge: fixture.bridge.clone(),
                calls: Rc::new(Cell::new(0)),
            },
            DeviceId::from_str(ID_1).unwrap(),
            clock(NOW_MS),
        )
        .preview(
            Some(&RegisteredProject {
                project_id: fixture.project_id,
                root: wire_path(&fixture.project_root),
            }),
            NOW_MS,
        )
        .unwrap_err();
        assert_eq!(
            error.code,
            context_relay_protocol::ErrorCode::HarnessUnsupported
        );
        assert!(error.message.contains("Codex memory settings"));
        assert_eq!(fs::read(&global).unwrap(), before);
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "[memories]\nuse_memories = 'unsupported'\n"
        );
        assert_raw_unchanged(&fixture);
    }
}

#[test]
fn codex_setup_rejects_new_memory_overrides_after_preview_without_writing() {
    for (global, prior, changed_value) in [
        (false, None, "true"),
        (false, Some("# inherits global memory settings\n"), "true"),
        (false, Some("[memories]\nuse_memories = false\n"), "true"),
        (false, None, "'invalid boolean'"),
        (true, None, "true"),
        (true, None, "'invalid boolean'"),
    ] {
        let mut fixture = codex_matrix_fixture();
        let config_path = if global {
            fixture
                .project_root
                .parent()
                .unwrap()
                .join("codex/config.toml")
        } else {
            fixture.project_root.join(".codex/config.toml")
        };
        let changed = if global {
            let disabled = fs::read_to_string(&config_path)
                .unwrap()
                .replace("generate_memories = true", "generate_memories = false")
                .replace("use_memories = true", "use_memories = false");
            fs::write(&config_path, &disabled).unwrap();
            disabled.replace(
                "use_memories = false",
                &format!("use_memories = {changed_value}"),
            )
        } else {
            match prior {
                None => fs::remove_file(&config_path).unwrap(),
                Some(value) => fs::write(&config_path, value).unwrap(),
            }
            format!("[memories]\nuse_memories = {changed_value}\n")
        };
        let vault_path = TempVault::new("codex-memory-override-after-preview");
        let keys = MemoryKeyStore::default();
        let mut vault = Vault::open(vault_path.path(), "primary-memory-setup-v1", &keys).unwrap();
        let setup = BridgeInstallService::new(
            &mut vault,
            fixture.harness.clone(),
            Locator {
                bridge: fixture.bridge.clone(),
                calls: Rc::new(Cell::new(0)),
            },
            DeviceId::from_str(ID_1).unwrap(),
            clock(NOW_MS),
        )
        .preview(
            Some(&RegisteredProject {
                project_id: fixture.project_id,
                root: wire_path(&fixture.project_root),
            }),
            NOW_MS,
        )
        .unwrap();
        let opened =
            open_plan(&vault.setup_plan(&setup.plan_id).unwrap().unwrap().payload).unwrap();
        let original = opened
            .plan
            .mutations
            .iter()
            .map(|mutation| {
                let path = mutation_path(&mutation.target);
                let bytes = fs::read(&path).unwrap();
                (path, bytes)
            })
            .collect::<Vec<_>>();
        fs::write(&config_path, &changed).unwrap();
        let mut executor = MatrixExecutor {
            live: fixture.harness.cli_state(),
            harness: &mut fixture.harness,
            lock_root: fixture.lock_root.clone(),
        };
        let result = BridgeInstallService::persisted(&mut vault).apply(
            &setup.plan_id,
            NOW_MS + 1,
            &mut executor,
        );
        assert!(
            result.is_err(),
            "new memory setting was not in the reviewed plan: global={global}, prior={prior:?}, value={changed_value}"
        );
        for (path, bytes) in original {
            assert_eq!(fs::read(path).unwrap(), bytes);
        }
        assert_eq!(fs::read_to_string(config_path).unwrap(), changed);
        for registration in &opened.plan.native_memory_registrations {
            assert!(
                vault
                    .native_memory_ledger(&registration.source.id)
                    .unwrap()
                    .is_none()
            );
        }
        assert_raw_unchanged(&fixture);
    }
}

#[test]
fn frozen_harnesses_reject_live_divergence_without_activation_or_raw_writes() {
    for harness_id in [HarnessId::ClaudeCode, HarnessId::Codex, HarnessId::Hermes] {
        let mut fixture = matrix_fixture(harness_id);
        let vault_path = TempVault::new(&format!("primary-memory-divergence-{harness_id:?}"));
        let keys = MemoryKeyStore::default();
        let mut vault = Vault::open(vault_path.path(), "primary-memory-setup-v1", &keys).unwrap();
        let setup = BridgeInstallService::new(
            &mut vault,
            fixture.harness.clone(),
            Locator {
                bridge: fixture.bridge.clone(),
                calls: Rc::new(Cell::new(0)),
            },
            DeviceId::from_str(ID_1).unwrap(),
            clock(NOW_MS),
        )
        .preview(
            Some(&RegisteredProject {
                project_id: fixture.project_id,
                root: wire_path(&fixture.project_root),
            }),
            NOW_MS,
        )
        .unwrap();
        let opened =
            open_plan(&vault.setup_plan(&setup.plan_id).unwrap().unwrap().payload).unwrap();
        let divergent = mutation_path(&opened.plan.mutations[0].target);
        fs::write(&divergent, b"concurrent live divergence\n").unwrap();
        let mut executor = MatrixExecutor {
            live: fixture.harness.cli_state(),
            harness: &mut fixture.harness,
            lock_root: fixture.lock_root.clone(),
        };

        let error = BridgeInstallService::persisted(&mut vault)
            .apply(&setup.plan_id, NOW_MS + 1, &mut executor)
            .unwrap_err();

        assert_eq!(error.code, context_relay_protocol::ErrorCode::Conflict);
        assert_eq!(
            fs::read(&divergent).unwrap(),
            b"concurrent live divergence\n"
        );
        for registration in &opened.plan.native_memory_registrations {
            assert!(
                vault
                    .native_memory_ledger(&registration.source.id)
                    .unwrap()
                    .is_none()
            );
        }
        assert_raw_unchanged(&fixture);
    }
}

fn seed(path: PathBuf, bytes: &[u8]) -> PathBuf {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, bytes).unwrap();
    path
}

fn mutation(path: &Path, intended_bytes: &[u8]) -> ApprovedMutation {
    let snapshot = OsNativeFileSystem::new().snapshot(path).unwrap();
    let NativeState::RegularFile { metadata, .. } = snapshot.state() else {
        unreachable!()
    };
    let intended = NativeState::regular_file(intended_bytes.to_vec(), metadata.clone());
    ApprovedMutation {
        target: wire_path(path),
        kind: MutationKind::Payload,
        content: intended.encode_v1().unwrap(),
        expected: RestorableStateFingerprint(Sha256Digest(*snapshot.fingerprint())),
        intended: RestorableStateFingerprint(Sha256Digest(intended.fingerprint())),
    }
}

fn native_text(value: &str) -> WireNativeValue {
    WireNativeValue {
        platform: NativePlatform::Macos,
        bytes: value.as_bytes().to_vec(),
        display: Some(value.to_owned()),
    }
}

fn wire_path(path: &Path) -> WireNativeValue {
    #[cfg(unix)]
    let bytes = {
        use std::os::unix::ffi::OsStrExt as _;
        path.as_os_str().as_bytes().to_vec()
    };
    #[cfg(windows)]
    let bytes = {
        use std::os::windows::ffi::OsStrExt as _;
        path.as_os_str()
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect()
    };
    WireNativeValue {
        platform: if cfg!(windows) {
            NativePlatform::Windows
        } else {
            NativePlatform::Macos
        },
        bytes,
        display: Some(path.display().to_string()),
    }
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest(Sha256::digest(bytes).into())
}
