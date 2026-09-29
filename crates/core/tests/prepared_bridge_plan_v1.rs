#![cfg(windows)]
mod support;

use context_relay_core::{
    mcp::install::{BridgeExecutable, attest_bridge_executable},
    native_memory::{
        NativeMemoryDocumentKind, NativeMemoryLimits, NativeMemoryRegistration, NativeMemorySource,
    },
    native_transaction::{InstalledRuntimeBinding, approval_hash_v2, open_plan},
    setup::{BridgeInstallService, BridgeLocator, BridgeMutationPlan, BridgePreviewHarness},
    vault::Vault,
};
use context_relay_protocol::*;
use std::{cell::RefCell, fs, rc::Rc};
use support::{ID_1, MemoryKeyStore, TempVault, clock};

const NOW: u64 = 1_900_000_000_000;

fn binding(byte: u8) -> InstalledRuntimeBinding {
    serde_json::from_value(serde_json::json!({"kind":"hermesPythonV1", "runtime": {
        "schemaVersion":1, "storageKey":"context-relay-hermes-runtime-fixture",
        "manifestIdentity": Sha256Digest([byte;32])
    }}))
    .unwrap()
}

struct Locator(BridgeExecutable);
impl BridgeLocator for Locator {
    fn locate(&self) -> Result<BridgeExecutable, ClientError> {
        Ok(self.0.clone())
    }
}

#[derive(Default)]
struct Executor {
    seen: Vec<context_relay_core::native_transaction::NativeTransactionPlan>,
}
impl context_relay_core::setup::BridgePlanExecutor for Executor {
    fn execute(
        &mut self,
        _: &mut Vault,
        plan: &context_relay_core::native_transaction::NativeTransactionPlan,
        sealed: &[u8],
        _: u64,
        _: u64,
    ) -> Result<(), context_relay_core::setup::BridgeExecutionError> {
        assert_eq!(open_plan(sealed).unwrap().plan, *plan);
        self.seen.push(plan.clone());
        Ok(())
    }
}

struct Harness {
    binding: Rc<RefCell<Option<InstalledRuntimeBinding>>>,
    change_during_render: bool,
    capability: CapabilityLevel,
    change_during_watch: Option<WatchStage>,
}
#[derive(Clone, Copy, PartialEq)]
enum WatchStage {
    Probe,
    Registrations,
    Digests,
}
impl Harness {
    fn change_at(&self, stage: WatchStage) {
        if self.change_during_watch == Some(stage) {
            *self.binding.borrow_mut() = Some(binding(8));
        }
    }
}
impl HarnessAdapter for Harness {
    fn probe(&self, _: &ProbeContext) -> Result<ProbeReport, ClientError> {
        self.change_at(WatchStage::Probe);
        Ok(ProbeReport {
            codex_saved_hook_approval: None,
            executable: Some(WireNativeValue {
                platform: NativePlatform::Windows,
                bytes: "C:\\fixture\\hermes.exe"
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect(),
                display: None,
            }),
            executable_sha256: Some(Sha256Digest([1; 32])),
            harness_version: Some("0.17.0".into()),
            installation_method: InstallationMethod::Manual,
            config_roots: vec![],
            active_profile: Some("default".into()),
            policy_conflicts: vec![],
            capability: self.capability,
        })
    }
    fn discover_scopes(&self, _: &ProbeReport) -> Result<DiscoveredScopes, ClientError> {
        Ok(DiscoveredScopes(vec![NativeScope::Global]))
    }
    fn import(&self, _: &ImportRequest) -> Result<ImportedState, ClientError> {
        Ok(ImportedState {
            components: vec![],
            source_digests: vec![],
        })
    }
    fn render(&self, _: &DesiredState) -> Result<RenderedState, ClientError> {
        if self.change_during_render {
            *self.binding.borrow_mut() = Some(binding(8));
        }
        Ok(RenderedState {
            files: vec![],
            cli_operations: vec![],
        })
    }
    fn classify(&self, diff: &SemanticDiff) -> Result<ClassifiedChanges, ClientError> {
        Ok(ClassifiedChanges(diff.changes.clone()))
    }
    fn plan_cli_ops(&self, _: &ClassifiedChanges) -> Result<CliOperations, ClientError> {
        Ok(CliOperations(vec![]))
    }
    fn validate_effective(&self, _: &ApplyReceipt) -> Result<ValidationReport, ClientError> {
        panic!("preview cannot execute a runtime")
    }
}
impl BridgePreviewHarness for Harness {
    fn watch_only_memory_registrations(
        &self,
    ) -> Result<Option<Vec<NativeMemoryRegistration>>, ClientError> {
        self.change_at(WatchStage::Registrations);
        let source = NativeMemorySource::new(
            HarnessId::Hermes,
            "0.17.0",
            ScopeRef::Global,
            NativeMemoryDocumentKind::Agent,
            WireNativeValue {
                platform: NativePlatform::Windows,
                bytes: "C:\\fixture\\MEMORY.md"
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect(),
                display: None,
            },
            NativeMemoryLimits {
                max_bytes: 16384,
                max_characters: 16384,
            },
            true,
        )
        .unwrap();
        Ok(Some(vec![NativeMemoryRegistration {
            source,
            last_applied_digest: None,
        }]))
    }
    fn watch_only_memory_digests(&self) -> Result<Vec<ExpectedNativeDigest>, ClientError> {
        self.change_at(WatchStage::Digests);
        Ok(vec![])
    }
    fn bridge_harness(&self) -> HarnessId {
        HarnessId::Hermes
    }
    fn bridge_setup_capability(&self) -> CapabilityLevel {
        self.capability
    }
    fn bridge_requested_profile(&self) -> Option<String> {
        Some("default".into())
    }
    fn bridge_installed_runtime(&self) -> Option<InstalledRuntimeBinding> {
        self.binding.borrow().clone()
    }
    fn bridge_mutations(
        &self,
        _: &DesiredState,
        _: &ComponentRecord,
    ) -> Result<BridgeMutationPlan, ClientError> {
        Ok(BridgeMutationPlan {
            cli: None,
            native: vec![],
        })
    }
}

#[test]
fn preview_seals_the_runtime_binding_and_its_approval_hash() {
    let temp = TempVault::new("prepared-bridge-plan");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(temp.path(), "prepared-bridge-plan", &keys).unwrap();
    let files = tempfile::tempdir().unwrap();
    let bridge_path = files.path().join("context-mcp.exe");
    fs::write(&bridge_path, b"inert bridge fixture").unwrap();
    let selected = binding(7);
    let harness = Harness {
        binding: Rc::new(RefCell::new(Some(selected.clone()))),
        change_during_render: false,
        capability: CapabilityLevel::Full,
        change_during_watch: None,
    };
    let setup = BridgeInstallService::new(
        &mut vault,
        harness,
        Locator(attest_bridge_executable(&bridge_path).unwrap()),
        ID_1.parse().unwrap(),
        clock(NOW),
    )
    .preview(None, NOW)
    .unwrap();
    let stored = vault.setup_plan(&setup.plan_id).unwrap().unwrap();
    let mut opened = open_plan(&stored.payload).unwrap().plan;
    assert_eq!(opened.installed_runtime, Some(selected.clone()));
    assert_eq!(approval_hash_v2(&opened).unwrap(), setup.batch_hash);
    opened.installed_runtime = Some(binding(8));
    assert_ne!(approval_hash_v2(&opened).unwrap(), setup.batch_hash);
    drop(vault);
    let mut vault = Vault::open(temp.path(), "prepared-bridge-plan", &keys).unwrap();
    let mut executor = Executor::default();
    BridgeInstallService::persisted(&mut vault)
        .apply(&setup.plan_id, NOW + 1, &mut executor)
        .unwrap();
    BridgeInstallService::persisted(&mut vault)
        .rollback(&setup.plan_id, NOW + 2, &mut executor)
        .unwrap();
    BridgeInstallService::persisted(&mut vault)
        .rollback(&setup.plan_id, NOW + 3, &mut executor)
        .unwrap();
    assert_eq!(
        executor.seen.len(),
        2,
        "Undo replay must reuse the saved inverse"
    );
    for plan in &executor.seen {
        assert_eq!(plan.installed_runtime, Some(selected.clone()));
    }
    assert_ne!(
        executor.seen[0].setup.plan_id,
        executor.seen[1].setup.plan_id
    );
}

#[test]
fn preview_rejects_a_changed_binding_or_import_only_binding() {
    for (change_during_render, capability) in [
        (true, CapabilityLevel::Full),
        (false, CapabilityLevel::ImportOnly),
    ] {
        let temp = TempVault::new("prepared-bridge-conflict");
        let keys = MemoryKeyStore::default();
        let mut vault = Vault::open(temp.path(), "prepared-bridge-conflict", &keys).unwrap();
        let files = tempfile::tempdir().unwrap();
        let bridge_path = files.path().join("context-mcp.exe");
        fs::write(&bridge_path, b"inert bridge fixture").unwrap();
        let harness = Harness {
            binding: Rc::new(RefCell::new(Some(binding(7)))),
            change_during_render,
            capability,
            change_during_watch: None,
        };
        let result = BridgeInstallService::new(
            &mut vault,
            harness,
            Locator(attest_bridge_executable(&bridge_path).unwrap()),
            ID_1.parse().unwrap(),
            clock(NOW),
        )
        .preview(None, NOW);
        assert!(result.is_err());
    }
}

#[test]
fn watch_only_preview_rejects_a_runtime_acquired_during_any_callback() {
    for stage in [
        None,
        Some(WatchStage::Probe),
        Some(WatchStage::Registrations),
        Some(WatchStage::Digests),
    ] {
        let temp = TempVault::new("watch-runtime-conflict");
        let keys = MemoryKeyStore::default();
        let mut vault = Vault::open(temp.path(), "watch-runtime-conflict", &keys).unwrap();
        let files = tempfile::tempdir().unwrap();
        let bridge_path = files.path().join("context-mcp.exe");
        fs::write(&bridge_path, b"inert bridge fixture").unwrap();
        let harness = Harness {
            binding: Rc::new(RefCell::new(None)),
            change_during_render: false,
            capability: CapabilityLevel::ImportOnly,
            change_during_watch: stage,
        };
        let result = BridgeInstallService::new(
            &mut vault,
            harness,
            Locator(attest_bridge_executable(&bridge_path).unwrap()),
            ID_1.parse().unwrap(),
            clock(NOW),
        )
        .preview(None, NOW);
        if stage.is_none() {
            let setup = result.expect("unchanged watch-only binding remains supported");
            let stored = vault.setup_plan(&setup.plan_id).unwrap().unwrap();
            assert!(
                open_plan(&stored.payload)
                    .unwrap()
                    .plan
                    .installed_runtime
                    .is_none()
            );
        } else {
            let error = result.expect_err("watch-only plan must not discard an acquired runtime");
            assert_eq!(error.code, ErrorCode::Conflict);
        }
    }
}
