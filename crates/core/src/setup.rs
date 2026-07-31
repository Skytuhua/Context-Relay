//! Mutation-free preview and persistence of managed bridge installation plans.

use std::{path::PathBuf, str::FromStr};

use context_relay_native_runner::{
    RuleSyncFeature, RuleSyncFeatures, RuleSyncTarget, RuntimeTarget, SidecarCommand, SidecarId,
};
use context_relay_protocol::{
    ApprovalClass, CapabilityLevel, ChangeClass, ClassifiedChange, ClientError, ComponentKind,
    ComponentRecord, DesiredState, DeviceId, ErrorCode, ExpectedNativeDigest, HarnessAdapter,
    HarnessId, HybridLogicalClock, ImportRequest, NativePlatform, NativeScope, PlanId,
    ProbeContext, ScopeRef, SemanticDiff, SetupPlan, Sha256Digest, WireNativeValue,
};
use sha2::{Digest as _, Sha256};

use crate::{
    claude_code::ClaudeCodeAdapter,
    codex::CodexAdapter,
    hermes::HermesAdapter,
    mcp::install::{
        BRIDGE_SERVER_NAME, attest_bridge_executable, bridge_component_for_attested,
        is_managed_bridge_component,
    },
    native_transaction::{
        ApprovedCliMutation, ApprovedMutation, NativeTransactionPlan, SidecarBinding,
        approval_hash_v2, seal_plan,
    },
    vault::{SetupPlanWrite, Vault},
};

pub const PREVIEW_TTL_MS: u64 = 15 * 60 * 1_000;

/// A registered project is imported for conflict detection, but the managed
/// bridge is always installed in global scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisteredProject {
    pub project_id: context_relay_protocol::ProjectId,
    pub root: WireNativeValue,
}

pub struct BridgeMutationPlan {
    pub cli: Option<ApprovedCliMutation>,
    pub native: Vec<ApprovedMutation>,
}

/// The narrow capability preview needs in addition to the protocol adapter.
///
/// The specific adapter owns expected-state inspection and creation of both
/// forward and rollback argv; this service never accepts either from callers.
pub trait BridgePreviewHarness: HarnessAdapter {
    fn bridge_harness(&self) -> HarnessId;

    fn bridge_requested_profile(&self) -> Option<String> {
        None
    }

    fn bridge_mutations(
        &self,
        desired: &DesiredState,
        intended: &ComponentRecord,
    ) -> Result<BridgeMutationPlan, ClientError>;

    fn bridge_adapter_version(&self) -> u32 {
        1
    }
}

impl BridgePreviewHarness for ClaudeCodeAdapter {
    fn bridge_harness(&self) -> HarnessId {
        HarnessId::ClaudeCode
    }

    fn bridge_mutations(
        &self,
        _: &DesiredState,
        intended: &ComponentRecord,
    ) -> Result<BridgeMutationPlan, ClientError> {
        Ok(BridgeMutationPlan {
            cli: Some(self.plan_bridge_cli_mutation(intended)?),
            native: vec![],
        })
    }
}

impl BridgePreviewHarness for CodexAdapter {
    fn bridge_harness(&self) -> HarnessId {
        HarnessId::Codex
    }

    fn bridge_mutations(
        &self,
        _: &DesiredState,
        intended: &ComponentRecord,
    ) -> Result<BridgeMutationPlan, ClientError> {
        Ok(BridgeMutationPlan {
            cli: Some(self.plan_bridge_cli_mutation(intended)?),
            native: vec![],
        })
    }
}

impl BridgePreviewHarness for HermesAdapter {
    fn bridge_harness(&self) -> HarnessId {
        HarnessId::Hermes
    }

    fn bridge_requested_profile(&self) -> Option<String> {
        Some(self.profile_name().to_owned())
    }

    fn bridge_mutations(
        &self,
        desired: &DesiredState,
        _: &ComponentRecord,
    ) -> Result<BridgeMutationPlan, ClientError> {
        Ok(BridgeMutationPlan {
            cli: None,
            native: self.plan_native_config(desired)?.into_iter().collect(),
        })
    }
}

pub struct BridgeInstallService<'a, H> {
    vault: &'a mut Vault,
    harness: H,
    bridge_path: PathBuf,
    origin_device: DeviceId,
    observed_hlc: HybridLogicalClock,
}

impl<'a, H> BridgeInstallService<'a, H>
where
    H: BridgePreviewHarness,
{
    pub const PREVIEW_TTL_MS: u64 = PREVIEW_TTL_MS;

    pub fn new(
        vault: &'a mut Vault,
        harness: H,
        bridge_path: PathBuf,
        origin_device: DeviceId,
        observed_hlc: HybridLogicalClock,
    ) -> Self {
        Self {
            vault,
            harness,
            bridge_path,
            origin_device,
            observed_hlc,
        }
    }

    /// Builds and durably records a preview. It does not invoke any harness
    /// mutation or write its configuration.
    pub fn preview(
        &mut self,
        registered_project: Option<&RegisteredProject>,
        now_ms: u64,
    ) -> Result<SetupPlan, ClientError> {
        let bridge = attest_bridge_executable(&self.bridge_path)?;
        let harness = self.harness.bridge_harness();
        let report = self.harness.probe(&ProbeContext {
            harness,
            requested_profile: self.harness.bridge_requested_profile(),
        })?;
        if report.capability != CapabilityLevel::Full {
            return Err(unsupported("The selected harness is import-only"));
        }
        let executable_path = report
            .executable
            .clone()
            .ok_or_else(|| unsupported("The selected harness executable is unavailable"))?;
        let executable_hash = report
            .executable_sha256
            .ok_or_else(|| unsupported("The selected harness cannot be attested"))?;
        let harness_version = report
            .harness_version
            .clone()
            .ok_or_else(|| unsupported("The selected harness version is unavailable"))?;

        let mut import_scopes = vec![NativeScope::Global];
        if let Some(project) = registered_project {
            project
                .root
                .validate()
                .map_err(|_| invalid("The registered project path is invalid"))?;
            import_scopes.push(NativeScope::Project {
                project_id: project.project_id,
                root: project.root.clone(),
            });
        }
        let imported = self.harness.import(&ImportRequest {
            scopes: import_scopes,
            include_disabled: true,
        })?;
        let intended =
            bridge_component_for_attested(harness, &bridge, self.origin_device, self.observed_hlc)?;
        let change = bridge_change(
            harness,
            report.active_profile.as_deref(),
            &imported.components,
            &intended,
        )?;
        let semantic_diff = SemanticDiff {
            changes: change.into_iter().collect(),
            conflicts: vec![],
        };

        // These calls are intentionally kept in preview even though the exact
        // CLI mutation below is the authority for rollback argv.
        let desired = DesiredState {
            components: vec![intended.clone()],
            scopes: vec![NativeScope::Global],
        };
        let _rendered = self.harness.render(&desired)?;
        let classified = self.harness.classify(&semantic_diff)?;
        let adapter_operations = self.harness.plan_cli_ops(&classified)?.0;
        let mutations = if classified.0.is_empty() {
            BridgeMutationPlan {
                cli: None,
                native: vec![],
            }
        } else {
            self.harness.bridge_mutations(&desired, &intended)?
        };
        let cli_mutation = mutations.cli;
        if adapter_operations
            != cli_mutation
                .as_ref()
                .map(|mutation| mutation.forward.clone())
                .unwrap_or_default()
        {
            return Err(conflict(
                "Harness CLI preview differs from its approved bridge declaration",
            ));
        }
        if harness == HarnessId::Hermes && cli_mutation.is_some() {
            return Err(conflict(
                "Hermes bridge previews cannot contain CLI mutations",
            ));
        }
        if harness != HarnessId::Hermes && !mutations.native.is_empty() {
            return Err(conflict(
                "CLI bridge previews cannot contain native mutations",
            ));
        }

        let expires_at = now_ms
            .checked_add(PREVIEW_TTL_MS)
            .ok_or_else(|| invalid("Preview expiry is outside the supported range"))?;
        let plan_id = preview_plan_id(harness, &bridge.digest, now_ms)?;
        let mut setup = SetupPlan {
            plan_id,
            harness,
            adapter_version: self.harness.bridge_adapter_version(),
            executable_path,
            executable_hash,
            harness_version,
            target_scopes: vec![NativeScope::Global],
            expected_native_digests: vec![ExpectedNativeDigest {
                target: wire_path(&bridge.path),
                expected_digest: Some(bridge.digest),
            }],
            approval_class: approval_class(&classified.0),
            semantic_changes: classified.0,
            cli_operations: cli_mutation
                .as_ref()
                .map(|mutation| mutation.forward.clone())
                .unwrap_or_default(),
            package_artifacts: vec![],
            permission_delta: context_relay_protocol::PermissionDelta {
                added: vec![],
                removed: vec![],
            },
            network_delta: context_relay_protocol::NetworkDelta {
                added: vec![],
                removed: vec![],
            },
            scanner_report_hash: digest(b"bridge-preview-scanner-v1"),
            rulesync_version: "bridge-preview-v1".to_owned(),
            rulesync_hash: digest(b"bridge-preview-rulesync-v1"),
            expires_at,
            batch_hash: Sha256Digest([0; 32]),
        };
        let mut plan = NativeTransactionPlan {
            setup: setup.clone(),
            approval_version: 2,
            helper_policy_version: 1,
            manifest_schema_version: 1,
            manifest_digest: digest(b"bridge-preview-manifest-v1"),
            helper_hash: digest(b"bridge-preview-helper-v1"),
            sidecars: vec![SidecarBinding {
                id: SidecarId::RuleSync,
                target: RuntimeTarget::MacosArm64,
                version: "bridge-preview-v1".to_owned(),
                closure_hash: digest(b"bridge-preview-sidecar-closure-v1"),
                source_bundle_hash: digest(b"bridge-preview-sidecar-source-v1"),
                build_toolchain_hash: digest(b"bridge-preview-sidecar-toolchain-v1"),
                command_template_digest: digest(b"bridge-preview-sidecar-command-v1"),
                command: SidecarCommand::RuleSyncGenerate {
                    target: match harness {
                        HarnessId::ClaudeCode => RuleSyncTarget::ClaudeCode,
                        HarnessId::Codex => RuleSyncTarget::CodexCli,
                        HarnessId::Hermes => RuleSyncTarget::ClaudeCode,
                    },
                    features: RuleSyncFeatures::new(&[RuleSyncFeature::Mcp])
                        .map_err(|_| invalid("Bridge preview sidecar is invalid"))?,
                },
            }],
            structural_allowlist_hash: digest(b"bridge-preview-allowlist-v1"),
            staged_inputs: vec![],
            expected_semantic_output_hash: digest(b"bridge-preview-output-v1"),
            scanner_result_hash: digest(b"bridge-preview-scanner-v1"),
            mutations: mutations.native,
            cli_mutations: cli_mutation.into_iter().collect(),
            ownership_changes: vec![],
        };
        let approval_hash =
            approval_hash_v2(&plan).map_err(|_| invalid("Bridge preview plan is invalid"))?;
        setup.batch_hash = approval_hash;
        plan.setup = setup.clone();
        let sealed = seal_plan(&plan, approval_hash)
            .map_err(|_| invalid("Bridge preview plan cannot be sealed"))?;
        self.vault
            .put_setup_plan(SetupPlanWrite {
                plan_id: &setup.plan_id,
                schema_version: crate::native_transaction::SEALED_PLAN_SCHEMA_VERSION,
                approval_version: 2,
                approval_hash: &approval_hash,
                payload: &sealed,
                created_ms: now_ms,
                expires_ms: expires_at,
            })
            .map_err(|_| invalid("Bridge preview plan cannot be persisted"))?;
        Ok(setup)
    }
}

fn bridge_change(
    harness: HarnessId,
    profile: Option<&str>,
    imported: &[ComponentRecord],
    intended: &ComponentRecord,
) -> Result<Option<ClassifiedChange>, ClientError> {
    let same_name = imported.iter().find(|component| {
        component.kind == ComponentKind::McpServer
            && component.scope == ScopeRef::Global
            && component.name == BRIDGE_SERVER_NAME
    });
    let class = match same_name {
        None => ChangeClass::Create,
        Some(component) if !is_managed_bridge_component(harness, component) => {
            return Err(conflict(
                "An unmanaged context-relay MCP declaration already exists",
            ));
        }
        Some(component) if component.body_markdown == intended.body_markdown => return Ok(None),
        Some(_) => ChangeClass::Update,
    };
    Ok(Some(ClassifiedChange {
        class,
        target: match harness {
            HarnessId::ClaudeCode => format!("claude-mcp:global:{BRIDGE_SERVER_NAME}"),
            HarnessId::Codex => format!("codex-mcp|global|{BRIDGE_SERVER_NAME}"),
            HarnessId::Hermes => format!(
                "hermes-config|{}|mcp_servers.{BRIDGE_SERVER_NAME}",
                profile.ok_or_else(|| invalid("Hermes profile is unavailable"))?
            ),
        },
        summary: intended.body_markdown.clone(),
    }))
}

fn approval_class(changes: &[ClassifiedChange]) -> ApprovalClass {
    if changes.iter().any(|change| {
        matches!(
            change.class,
            ChangeClass::Create
                | ChangeClass::Update
                | ChangeClass::Enable
                | ChangeClass::Disable
                | ChangeClass::Remove
        )
    }) {
        ApprovalClass::Active
    } else {
        ApprovalClass::Passive
    }
}

fn preview_plan_id(
    harness: HarnessId,
    bridge_digest: &Sha256Digest,
    now_ms: u64,
) -> Result<PlanId, ClientError> {
    let mut bytes: [u8; 32] = Sha256::digest(
        [
            harness_cli_name(harness).as_bytes(),
            &bridge_digest.0,
            &now_ms.to_le_bytes(),
        ]
        .concat(),
    )
    .into();
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    PlanId::from_str(&format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    ))
    .map_err(|_| invalid("Bridge preview identifier cannot be derived"))
}

fn wire_path(path: &std::path::Path) -> WireNativeValue {
    let display = path.to_string_lossy().into_owned();
    WireNativeValue {
        platform: NativePlatform::Macos,
        bytes: display.as_bytes().to_vec(),
        display: Some(display),
    }
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest(Sha256::digest(bytes).into())
}

fn harness_cli_name(harness: HarnessId) -> &'static str {
    match harness {
        HarnessId::ClaudeCode => "claude-code",
        HarnessId::Codex => "codex",
        HarnessId::Hermes => "hermes",
    }
}

fn invalid(message: &'static str) -> ClientError {
    ClientError {
        code: ErrorCode::InvalidRequest,
        message: message.to_owned(),
        field_path: None,
        retryable: false,
    }
}

fn conflict(message: &'static str) -> ClientError {
    ClientError {
        code: ErrorCode::Conflict,
        message: message.to_owned(),
        field_path: None,
        retryable: false,
    }
}

fn unsupported(message: &'static str) -> ClientError {
    ClientError {
        code: ErrorCode::HarnessUnsupported,
        message: message.to_owned(),
        field_path: None,
        retryable: false,
    }
}
