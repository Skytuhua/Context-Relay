//! Hermes adapter identity and profile binding.
//!
//! The adapter attests one explicit profile before importing only reviewed
//! configuration and file surfaces. Native rendering remains closed.

mod gateway;
mod import;
mod profile;
mod render;
mod yaml;

use std::{
    collections::BTreeSet,
    env, fs,
    fs::OpenOptions,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use context_relay_native_runner::OsNativeFileSystem;
use context_relay_protocol::{
    ApplyReceipt, ApprovalClass, CapabilityLevel, ClassifiedChanges, CliOperations, ClientError,
    ComponentKind, DesiredState, DeviceId, DiscoveredScopes, ErrorCode, ExpectedNativeDigest,
    HarnessAdapter, HarnessId, HybridLogicalClock, ImportRequest, ImportedState,
    InstallationMethod, NativePlatform, NativeScope, ProbeContext, ProbeReport, ProjectId,
    RenderedState, SemanticDiff, Sha256Digest, ValidationReport, WireNativeValue,
};
use rand_core::{OsRng, RngCore as _};
use serde_json::Value as JsonValue;
use sha2::{Digest as _, Sha256};

use crate::native_transaction::{
    engine::{BoundaryError, FrozenOutput, NativeAdapter, RestrictedRun},
    model::NativeTransactionPlan,
};

const SUPPORTED_VERSIONS: [&str; 2] = ["0.18.2", "0.18.1"];
const HERMES_ADAPTER_VERSION: u32 = 1;
const CLI_TIMEOUT_MS: u32 = 30_000;
const CLI_OUTPUT_LIMIT: u64 = 64 * 1024;
#[allow(dead_code)]
const MANAGED_START: &str = "<!-- context-relay:start -->";
#[allow(dead_code)]
const MANAGED_END: &str = "<!-- context-relay:end -->";
const DEFAULT_PROFILE: &str = "default";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HermesExecutableKind {
    Native,
    Wrapper,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExecutableSnapshot {
    kind: HermesExecutableKind,
    digest: Sha256Digest,
}

impl ExecutableSnapshot {
    fn runnable(&self) -> bool {
        self.kind == HermesExecutableKind::Native
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AttestedExecutable {
    snapshot: ExecutableSnapshot,
    bytes: Vec<u8>,
}

#[derive(Debug)]
struct StagedExecutable {
    _directory: tempfile::TempDir,
    path: PathBuf,
    snapshot: ExecutableSnapshot,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HermesProfile {
    pub name: String,
    pub hermes_home: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HermesMemoryKind {
    Agent,
    User,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HermesMemoryDocument {
    pub kind: HermesMemoryKind,
    pub body_markdown: String,
    pub source_digest: Sha256Digest,
}

#[derive(Clone, Debug)]
pub struct HermesLayout {
    pub executable: PathBuf,
    pub executable_kind: HermesExecutableKind,
    pub version: String,
    pub installation_method: InstallationMethod,
    pub default_hermes_home: PathBuf,
    pub profile: HermesProfile,
    pub project_root: PathBuf,
    pub working_directory: PathBuf,
}

#[derive(Debug)]
pub struct HermesAdapter {
    layout: HermesLayout,
    project_id: ProjectId,
    #[allow(dead_code)]
    origin_device: DeviceId,
    #[allow(dead_code)]
    observed_hlc: HybridLogicalClock,
    executable_hash: Sha256Digest,
    executable_snapshot: Box<ExecutableSnapshot>,
    gateway_profile: Option<gateway::GatewayProfileReservation>,
    gateway_lease: Option<gateway::GatewayLease>,
}

impl Clone for HermesAdapter {
    fn clone(&self) -> Self {
        Self {
            layout: self.layout.clone(),
            project_id: self.project_id,
            origin_device: self.origin_device,
            observed_hlc: self.observed_hlc,
            executable_hash: self.executable_hash,
            executable_snapshot: self.executable_snapshot.clone(),
            gateway_profile: None,
            gateway_lease: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HermesValidationRequest {
    executable: PathBuf,
    argv: Vec<String>,
    working_directory: PathBuf,
    staged_hermes_home: PathBuf,
    executable_hash: Sha256Digest,
}

#[derive(Debug)]
struct HermesValidationStage {
    path: PathBuf,
    temp_root: PathBuf,
}

impl Drop for HermesValidationStage {
    fn drop(&mut self) {
        let removable = self.path.parent() == Some(self.temp_root.as_path())
            && self
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.starts_with("context-relay-hermes-validation-")
                        && name.len() == "context-relay-hermes-validation-".len() + 32
                })
            && fs::symlink_metadata(&self.path)
                .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
            && fs::canonicalize(&self.path).is_ok_and(|canonical| canonical == self.path);
        if removable {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

impl HermesAdapter {
    pub(crate) fn gateway_lock_expected_digest(&self) -> Result<ExpectedNativeDigest, ClientError> {
        let path = self.layout.profile.hermes_home.join("gateway.lock");
        let snapshot = OsNativeFileSystem::new()
            .snapshot(&path)
            .map_err(|_| invalid("Hermes gateway lock cannot be safely inspected"))?;
        Ok(ExpectedNativeDigest {
            target: wire_path(&path),
            expected_digest: snapshot
                .bytes()
                .map(|bytes| Sha256Digest(Sha256::digest(bytes).into())),
        })
    }

    pub fn project_id(&self) -> ProjectId {
        self.project_id
    }

    pub fn discover(
        project_root: impl Into<PathBuf>,
        working_directory: impl Into<PathBuf>,
        requested_profile: &str,
        project_id: ProjectId,
        origin_device: DeviceId,
        observed_hlc: HybridLogicalClock,
    ) -> Result<Self, ClientError> {
        Self::discover_inner(
            project_root.into(),
            working_directory.into(),
            requested_profile,
            project_id,
            origin_device,
            observed_hlc,
            None,
        )
    }

    /// Rechecks the selected profile and executable without launching Hermes.
    pub fn discover_for_registration(
        project_root: impl Into<PathBuf>,
        working_directory: impl Into<PathBuf>,
        requested_profile: &str,
        project_id: ProjectId,
        origin_device: DeviceId,
        observed_hlc: HybridLogicalClock,
        approved: &context_relay_protocol::SetupPlan,
    ) -> Result<Self, ClientError> {
        Self::discover_inner(
            project_root.into(),
            working_directory.into(),
            requested_profile,
            project_id,
            origin_device,
            observed_hlc,
            Some(approved),
        )
    }

    fn discover_inner(
        project_root: PathBuf,
        working_directory: PathBuf,
        requested_profile: &str,
        project_id: ProjectId,
        origin_device: DeviceId,
        observed_hlc: HybridLogicalClock,
        approved: Option<&context_relay_protocol::SetupPlan>,
    ) -> Result<Self, ClientError> {
        let default_hermes_home = default_hermes_home()?;
        let profile = profile::select_profile(&default_hermes_home, requested_profile)?;
        let executable =
            find_executable().ok_or_else(|| not_found("Hermes executable was not found"))?;
        let (snapshot, version) = match approved {
            Some(approved) => {
                let snapshot = snapshot_executable(&executable)?;
                let approved_path = fs::canonicalize(&executable)
                    .map_err(|_| invalid("Hermes executable cannot be safely resolved"))?;
                let version = crate::setup::approved_registration_version(
                    approved,
                    HarnessId::Hermes,
                    &wire_path(&approved_path),
                    snapshot.digest,
                )?;
                (snapshot, version)
            }
            None => discover_executable_version(&executable)?,
        };
        let installation_method = installation_method(&executable);
        Self::from_attested_layout(
            HermesLayout {
                executable,
                executable_kind: snapshot.kind,
                version,
                installation_method,
                default_hermes_home,
                profile,
                project_root,
                working_directory,
            },
            project_id,
            origin_device,
            observed_hlc,
            snapshot,
        )
    }

    pub fn from_layout(
        layout: HermesLayout,
        project_id: ProjectId,
        origin_device: DeviceId,
        observed_hlc: HybridLogicalClock,
    ) -> Result<Self, ClientError> {
        Self::from_layout_with_expected_snapshot(
            layout,
            project_id,
            origin_device,
            observed_hlc,
            None,
        )
    }

    fn from_attested_layout(
        layout: HermesLayout,
        project_id: ProjectId,
        origin_device: DeviceId,
        observed_hlc: HybridLogicalClock,
        expected_snapshot: ExecutableSnapshot,
    ) -> Result<Self, ClientError> {
        Self::from_layout_with_expected_snapshot(
            layout,
            project_id,
            origin_device,
            observed_hlc,
            Some(expected_snapshot),
        )
    }

    fn from_layout_with_expected_snapshot(
        mut layout: HermesLayout,
        project_id: ProjectId,
        origin_device: DeviceId,
        observed_hlc: HybridLogicalClock,
        expected_snapshot: Option<ExecutableSnapshot>,
    ) -> Result<Self, ClientError> {
        if !valid_version(&layout.version) && layout.version != "unknown" {
            return Err(invalid("Hermes version is invalid"));
        }
        require_file(&layout.executable, "Hermes executable was not found")?;
        layout.executable = fs::canonicalize(&layout.executable)
            .map_err(|_| invalid("Hermes executable cannot be safely resolved"))?;
        let executable = snapshot_executable(&layout.executable)?;
        if expected_snapshot
            .as_ref()
            .is_some_and(|expected| &executable != expected)
        {
            return Err(conflict("Hermes executable changed"));
        }
        require_directory(&layout.project_root, "Hermes project root was not found")?;
        require_directory(
            &layout.working_directory,
            "Hermes working directory was not found",
        )?;
        layout.default_hermes_home = profile::canonical_real_directory(
            &layout.default_hermes_home,
            "Hermes default profile was not found",
        )?;
        layout.project_root = fs::canonicalize(&layout.project_root)
            .map_err(|_| invalid("Hermes project root cannot be safely resolved"))?;
        layout.working_directory = fs::canonicalize(&layout.working_directory)
            .map_err(|_| invalid("Hermes working directory cannot be safely resolved"))?;
        if !layout.working_directory.starts_with(&layout.project_root) {
            return Err(invalid(
                "Hermes working directory is outside the project root",
            ));
        }
        profile::validate_profile_binding(&layout.default_hermes_home, &layout.profile)?;
        layout.profile =
            profile::select_profile(&layout.default_hermes_home, &layout.profile.name)?;
        layout.executable_kind = executable.kind;
        Ok(Self {
            layout,
            project_id,
            origin_device,
            observed_hlc,
            executable_hash: executable.digest,
            executable_snapshot: Box::new(executable),
            gateway_profile: None,
            gateway_lease: None,
        })
    }

    pub fn discover_profiles(
        default_hermes_home: impl AsRef<Path>,
    ) -> Result<Vec<HermesProfile>, ClientError> {
        profile::enumerate_profiles(default_hermes_home.as_ref())
    }

    pub fn profile_home_wire(&self) -> WireNativeValue {
        wire_path(&self.layout.profile.hermes_home)
    }

    pub fn profile_name(&self) -> &str {
        &self.layout.profile.name
    }

    pub fn project_root_wire(&self) -> WireNativeValue {
        wire_path(&self.layout.project_root)
    }

    pub fn import_native_memory(&self) -> Result<Vec<HermesMemoryDocument>, ClientError> {
        self.import_memory_documents()
    }

    fn validate_effective_with(
        &self,
        receipt: &ApplyReceipt,
        mut execute: impl FnMut(&HermesValidationRequest) -> Result<Vec<u8>, ClientError>,
    ) -> Result<ValidationReport, ClientError> {
        receipt
            .validate()
            .map_err(|_| invalid("Hermes receipt is invalid"))?;
        self.require_apply_supported()?;
        self.revalidate_bound_installation()?;
        let projection = self.revalidate_effective_sources()?;
        let staged_config = render_projection_yaml(&projection)?;
        let parsed_staged = yaml::parse_config(&staged_config)?;
        if !yaml::topology_supported(&parsed_staged) {
            return Err(invalid("Hermes staged config topology is unsupported"));
        }
        let attested = attest_executable(&self.layout.executable)?;
        if attested.snapshot != *self.executable_snapshot {
            return Err(conflict("Hermes executable changed"));
        }
        let executable_stage = stage_executable(&attested)?;
        let stage = create_validation_stage(&staged_config)?;
        let request = HermesValidationRequest {
            executable: executable_stage.path.clone(),
            argv: vec!["config".into(), "check".into()],
            working_directory: self.layout.working_directory.clone(),
            staged_hermes_home: stage.path.clone(),
            executable_hash: executable_stage.snapshot.digest,
        };
        let output = execute(&request)?;
        parse_config_check_output(&output, &self.layout.version)
    }

    pub(crate) fn capability(&self) -> CapabilityLevel {
        if SUPPORTED_VERSIONS.contains(&self.layout.version.as_str())
            && self.executable_snapshot.runnable()
            && self.yaml_topology_supported()
        {
            CapabilityLevel::Full
        } else {
            CapabilityLevel::ImportOnly
        }
    }

    fn yaml_topology_supported(&self) -> bool {
        let path = self.layout.profile.hermes_home.join("config.yaml");
        fs::read(path)
            .ok()
            .and_then(|bytes| yaml::parse_config(&bytes).ok())
            .is_some_and(|parsed| yaml::topology_supported(&parsed))
    }

    pub(crate) fn revalidate_bound_installation(&self) -> Result<(), ClientError> {
        profile::validate_profile_binding(&self.layout.default_hermes_home, &self.layout.profile)?;
        let selected =
            profile::select_profile(&self.layout.default_hermes_home, &self.layout.profile.name)?;
        if selected != self.layout.profile {
            return Err(conflict("Hermes profile binding changed"));
        }
        let executable = snapshot_executable(&self.layout.executable)?;
        if executable != *self.executable_snapshot {
            return Err(conflict("Hermes executable changed"));
        }
        let project_root = fs::canonicalize(&self.layout.project_root)
            .map_err(|_| conflict("Hermes project root changed"))?;
        let working_directory = fs::canonicalize(&self.layout.working_directory)
            .map_err(|_| conflict("Hermes working directory changed"))?;
        if project_root != self.layout.project_root
            || working_directory != self.layout.working_directory
            || !working_directory.starts_with(&project_root)
        {
            return Err(conflict("Hermes project binding changed"));
        }
        Ok(())
    }

    fn revalidate_effective_sources(&self) -> Result<JsonValue, ClientError> {
        let imported = self.import(&ImportRequest {
            scopes: vec![
                NativeScope::Global,
                NativeScope::Project {
                    project_id: self.project_id,
                    root: self.project_root_wire(),
                },
            ],
            include_disabled: true,
        })?;
        for component in &imported.components {
            if matches!(
                component.kind,
                ComponentKind::Instruction | ComponentKind::Rule | ComponentKind::Skill
            ) {
                render::validate_managed_markdown(component.body_markdown.as_bytes())?;
            }
        }
        for memory in self.import_memory_documents()? {
            render::validate_managed_markdown(memory.body_markdown.as_bytes())?;
        }
        let config = fs::read(self.layout.profile.hermes_home.join("config.yaml"))
            .map_err(|_| invalid("Hermes config cannot be read"))?;
        let parsed = yaml::parse_config(&config)?;
        if !yaml::topology_supported(&parsed) {
            return Err(invalid("Hermes config topology is unsupported"));
        }
        import::validation_config_projection(
            &parsed,
            &self.layout.profile.name,
            &self.layout.version,
        )
    }
}

impl NativeAdapter for HermesAdapter {
    fn reprobe_live_state(&mut self, plan: &NativeTransactionPlan) -> Result<(), BoundaryError> {
        self.gateway_profile.take();
        self.gateway_lease.take();
        if !plan.cli_mutations.is_empty() || !plan.setup.cli_operations.is_empty() {
            return Err(BoundaryError::new(
                "Hermes native plans cannot contain CLI mutations",
            ));
        }
        let gateway_profile = (plan.setup.approval_class == ApprovalClass::Active)
            .then(|| gateway::GatewayProfileReservation::observe(&self.layout.profile))
            .transpose()
            .map_err(|_| BoundaryError::new("Hermes profile binding changed"))?;
        self.revalidate_bound_installation()
            .map_err(|_| BoundaryError::new("Hermes installation changed"))?;
        if self.capability() != CapabilityLevel::Full
            || plan.setup.harness != HarnessId::Hermes
            || plan.setup.adapter_version != HERMES_ADAPTER_VERSION
            || plan.setup.harness_version != self.layout.version
            || plan.setup.executable_path != wire_path(&self.layout.executable)
            || plan.setup.executable_hash != self.executable_hash
        {
            return Err(BoundaryError::new("Hermes installation changed"));
        }
        if plan.setup.target_scopes.iter().any(|scope| match scope {
            NativeScope::Global => false,
            NativeScope::Project { project_id, root } => {
                *project_id != self.project_id || *root != self.project_root_wire()
            }
        }) {
            return Err(BoundaryError::new("Hermes project binding changed"));
        }
        if let Some(profile) = gateway_profile.as_ref() {
            profile
                .verify()
                .map_err(|_| BoundaryError::new("Hermes profile binding changed"))?;
        }
        self.gateway_profile = gateway_profile;
        Ok(())
    }

    fn compare_approved_digests(
        &mut self,
        plan: &NativeTransactionPlan,
    ) -> Result<(), BoundaryError> {
        if let Some(profile) = self.gateway_profile.as_ref() {
            profile
                .verify()
                .map_err(|_| BoundaryError::new("Hermes profile binding changed"))?;
        }
        for expected in &plan.setup.expected_native_digests {
            let path = decode_wire_path(&expected.target)?;
            let actual = match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                    return Err(BoundaryError::new("Hermes native state changed"));
                }
                Ok(_) => Some(digest_file_boundary(&path)?),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(_) => return Err(BoundaryError::new("Hermes native state cannot be read")),
            };
            if actual != expected.expected_digest {
                return Err(BoundaryError::new("Hermes native state changed"));
            }
        }
        if plan.setup.approval_class == ApprovalClass::Active && self.gateway_lease.is_none() {
            let profile = self
                .gateway_profile
                .take()
                .ok_or_else(|| BoundaryError::new("Hermes profile binding changed"))?;
            let lease = gateway::acquire_gateway_idle(&self.layout.profile, profile)
                .map_err(|_| BoundaryError::new("Hermes gateway blocks active changes"))?;
            self.gateway_lease = Some(lease);
        }
        Ok(())
    }

    fn verify_live_state_reservation(
        &mut self,
        plan: &NativeTransactionPlan,
    ) -> Result<(), BoundaryError> {
        if plan.setup.approval_class == ApprovalClass::Active {
            self.gateway_lease
                .as_ref()
                .ok_or_else(|| BoundaryError::new("Hermes gateway reservation is missing"))?
                .verify()
                .map_err(|_| BoundaryError::new("Hermes profile binding changed"))?;
        }
        Ok(())
    }

    fn validate_staged_output(
        &mut self,
        plan: &NativeTransactionPlan,
        run: &RestrictedRun,
    ) -> Result<FrozenOutput, BoundaryError> {
        if run.staged_output_hash != plan.expected_semantic_output_hash
            || run.scanner_result_hash != plan.scanner_result_hash
        {
            return Err(BoundaryError::new("Hermes staged output changed"));
        }
        Ok(FrozenOutput {
            staged_output_hash: run.staged_output_hash,
            scanner_result_hash: run.scanner_result_hash,
        })
    }

    fn validate_effective(
        &mut self,
        plan: &NativeTransactionPlan,
        receipt: &ApplyReceipt,
    ) -> Result<(), BoundaryError> {
        receipt
            .validate()
            .map_err(|_| BoundaryError::new("Hermes effective receipt is invalid"))?;
        let intended = plan
            .mutations
            .iter()
            .map(|mutation| mutation.intended.0)
            .collect::<Vec<_>>();
        if receipt.plan_id != plan.setup.plan_id || receipt.resulting_digests != intended {
            return Err(BoundaryError::new(
                "Hermes effective state differs from the plan",
            ));
        }
        if plan.mutations.is_empty() && plan.cli_mutations.is_empty() {
            return Ok(());
        }
        let config_target = wire_path(&self.layout.profile.hermes_home.join("config.yaml"));
        if !plan
            .mutations
            .iter()
            .any(|mutation| mutation.target == config_target)
        {
            self.revalidate_effective_sources()
                .map_err(|_| BoundaryError::new("Hermes effective configuration is invalid"))?;
            return Ok(());
        }
        let report = self
            .validate_effective_with(receipt, run_validation)
            .map_err(|_| BoundaryError::new("Hermes effective configuration is invalid"))?;
        if !report.valid {
            return Err(BoundaryError::new(
                "Hermes effective configuration is invalid",
            ));
        }
        Ok(())
    }

    fn release_live_state_reservation(&mut self) -> Result<(), BoundaryError> {
        self.gateway_lease.take();
        self.gateway_profile.take();
        Ok(())
    }
}

impl HarnessAdapter for HermesAdapter {
    fn probe(&self, context: &ProbeContext) -> Result<ProbeReport, ClientError> {
        context
            .validate()
            .map_err(|_| invalid("Hermes probe context is invalid"))?;
        if context.harness != HarnessId::Hermes {
            return Err(invalid("Hermes adapter received another harness"));
        }
        let requested = context
            .requested_profile
            .as_deref()
            .ok_or_else(|| invalid("Hermes probe requires an explicit profile"))?;
        if ascii_lowercase(requested) != self.layout.profile.name {
            return Err(invalid("Hermes probe profile does not match the adapter"));
        }
        let mut policy_conflicts = self.import_policy_conflicts();
        match gateway::inspect_gateway(&self.layout.profile)? {
            gateway::GatewayStatus::Idle => {}
            gateway::GatewayStatus::Stale => policy_conflicts.push("gateway_state_stale".into()),
            gateway::GatewayStatus::Live => {
                policy_conflicts.push("frozen_session_snapshot".into());
                policy_conflicts.push("gateway_state_live".into());
            }
            gateway::GatewayStatus::Unverifiable => {
                policy_conflicts.push("frozen_session_snapshot".into());
                policy_conflicts.push("gateway_state_unverifiable".into());
            }
        }
        policy_conflicts.sort();
        policy_conflicts.dedup();
        Ok(ProbeReport {
            codex_saved_hook_approval: None,
            executable: Some(wire_path(&self.layout.executable)),
            executable_sha256: Some(self.executable_hash),
            harness_version: Some(self.layout.version.clone()),
            installation_method: self.layout.installation_method,
            config_roots: vec![self.profile_home_wire(), self.project_root_wire()],
            active_profile: Some(self.layout.profile.name.clone()),
            policy_conflicts,
            capability: self.capability(),
        })
    }

    fn discover_scopes(&self, report: &ProbeReport) -> Result<DiscoveredScopes, ClientError> {
        report
            .validate()
            .map_err(|_| invalid("Hermes probe report is invalid"))?;
        Ok(DiscoveredScopes(vec![
            NativeScope::Global,
            NativeScope::Project {
                project_id: self.project_id,
                root: self.project_root_wire(),
            },
        ]))
    }

    fn import(&self, request: &ImportRequest) -> Result<ImportedState, ClientError> {
        request
            .validate()
            .map_err(|_| invalid("Hermes import request is invalid"))?;
        let mut components = Vec::new();
        let mut digests = BTreeSet::new();
        let mut seen = BTreeSet::new();
        for native_scope in &request.scopes {
            let scope = import::validate_bound_scope(self, native_scope)?;
            let key = match scope {
                context_relay_protocol::ScopeRef::Global => "global".to_owned(),
                context_relay_protocol::ScopeRef::Project { project_id } => {
                    format!("project:{project_id}")
                }
            };
            if !seen.insert(key) {
                return Err(invalid("Hermes import repeated a scope"));
            }
            self.import_scope(
                scope,
                request.include_disabled,
                &mut components,
                &mut digests,
            )?;
        }
        components.sort_by_key(|component| component.id);
        let imported = ImportedState {
            components,
            source_digests: digests.into_iter().collect(),
        };
        imported
            .validate()
            .map_err(|_| invalid("Hermes imported state exceeds protocol limits"))?;
        Ok(imported)
    }

    fn render(&self, desired: &DesiredState) -> Result<RenderedState, ClientError> {
        self.render_desired(desired)
    }

    fn classify(&self, diff: &SemanticDiff) -> Result<ClassifiedChanges, ClientError> {
        self.classify_changes(diff)
    }

    fn plan_cli_ops(&self, changes: &ClassifiedChanges) -> Result<CliOperations, ClientError> {
        self.require_apply_supported()?;
        changes
            .validate()
            .map_err(|_| invalid("Hermes changes are invalid"))?;
        Ok(CliOperations(vec![]))
    }

    fn validate_effective(&self, receipt: &ApplyReceipt) -> Result<ValidationReport, ClientError> {
        self.validate_effective_with(receipt, run_validation)
    }
}

fn create_validation_stage(config: &[u8]) -> Result<HermesValidationStage, ClientError> {
    let temp_root = fs::canonicalize(env::temp_dir())
        .map_err(|_| invalid("Hermes validation root is unavailable"))?;
    for _ in 0..16 {
        let mut random = [0u8; 16];
        OsRng
            .try_fill_bytes(&mut random)
            .map_err(|_| invalid("Hermes validation randomness is unavailable"))?;
        let name = format!(
            "context-relay-hermes-validation-{}",
            random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        let candidate = temp_root.join(name);
        #[cfg(unix)]
        let mut builder = fs::DirBuilder::new();
        #[cfg(not(unix))]
        let builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        match builder.create(&candidate) {
            Ok(()) => {
                let path = fs::canonicalize(&candidate)
                    .map_err(|_| invalid("Hermes validation stage is unavailable"))?;
                if path.parent() != Some(temp_root.as_path()) {
                    let _ = fs::remove_dir_all(&candidate);
                    return Err(invalid("Hermes validation stage escaped its root"));
                }
                let stage = HermesValidationStage { path, temp_root };
                create_private_directory(&stage.path.join("memories"))?;
                create_private_directory(&stage.path.join("home"))?;
                write_private_file(&stage.path.join("config.yaml"), config)?;
                return Ok(stage);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(invalid("Hermes validation stage cannot be created")),
        }
    }
    Err(invalid("Hermes validation stage cannot be allocated"))
}

fn create_private_directory(path: &Path) -> Result<(), ClientError> {
    #[cfg(unix)]
    let mut builder = fs::DirBuilder::new();
    #[cfg(not(unix))]
    let builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .map_err(|_| invalid("Hermes validation directory cannot be created"))
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), ClientError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| invalid("Hermes validation config cannot be created"))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| invalid("Hermes validation config cannot be written"))
}

fn render_projection_yaml(value: &JsonValue) -> Result<Vec<u8>, ClientError> {
    let mut rendered = String::new();
    let JsonValue::Object(mapping) = value else {
        return Err(invalid("Hermes reviewed config projection is invalid"));
    };
    write_yaml_mapping(mapping, 0, &mut rendered)?;
    if rendered.is_empty() {
        rendered.push_str("{}\n");
    }
    Ok(rendered.into_bytes())
}

fn write_yaml_mapping(
    mapping: &serde_json::Map<String, JsonValue>,
    indent: usize,
    rendered: &mut String,
) -> Result<(), ClientError> {
    for (key, value) in mapping {
        if !safe_yaml_key(key) {
            return Err(invalid("Hermes reviewed config key is invalid"));
        }
        rendered.push_str(&" ".repeat(indent));
        rendered.push_str(key);
        match value {
            JsonValue::Object(object) if object.is_empty() => rendered.push_str(": {}\n"),
            JsonValue::Array(array) if array.is_empty() => rendered.push_str(": []\n"),
            JsonValue::Object(object) => {
                rendered.push_str(":\n");
                write_yaml_mapping(object, indent + 2, rendered)?;
            }
            JsonValue::Array(array) => {
                rendered.push_str(":\n");
                write_yaml_sequence(array, indent + 2, rendered)?;
            }
            scalar => {
                rendered.push_str(": ");
                write_yaml_scalar(scalar, rendered)?;
                rendered.push('\n');
            }
        }
    }
    Ok(())
}

fn write_yaml_sequence(
    values: &[JsonValue],
    indent: usize,
    rendered: &mut String,
) -> Result<(), ClientError> {
    for value in values {
        rendered.push_str(&" ".repeat(indent));
        match value {
            JsonValue::Object(object) if object.is_empty() => rendered.push_str("- {}\n"),
            JsonValue::Array(array) if array.is_empty() => rendered.push_str("- []\n"),
            JsonValue::Object(object) => {
                rendered.push_str("-\n");
                write_yaml_mapping(object, indent + 2, rendered)?;
            }
            JsonValue::Array(array) => {
                rendered.push_str("-\n");
                write_yaml_sequence(array, indent + 2, rendered)?;
            }
            scalar => {
                rendered.push_str("- ");
                write_yaml_scalar(scalar, rendered)?;
                rendered.push('\n');
            }
        }
    }
    Ok(())
}

fn write_yaml_scalar(value: &JsonValue, rendered: &mut String) -> Result<(), ClientError> {
    match value {
        JsonValue::Null => rendered.push_str("null"),
        JsonValue::Bool(value) => rendered.push_str(if *value { "true" } else { "false" }),
        JsonValue::Number(value) => rendered.push_str(&value.to_string()),
        JsonValue::String(value) => rendered.push_str(
            &serde_json::to_string(value)
                .map_err(|_| invalid("Hermes reviewed config scalar is invalid"))?,
        ),
        JsonValue::Array(_) | JsonValue::Object(_) => {
            return Err(invalid("Hermes reviewed config scalar is invalid"));
        }
    }
    Ok(())
}

fn safe_yaml_key(key: &str) -> bool {
    let bytes = key.as_bytes();
    (1..=128).contains(&bytes.len())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn run_validation(request: &HermesValidationRequest) -> Result<Vec<u8>, ClientError> {
    if request.argv != ["config", "check"] {
        return Err(invalid("Hermes validation command is invalid"));
    }
    let path = minimal_system_path();
    let mut child = Command::new(&request.executable);
    child
        .args(&request.argv)
        .current_dir(&request.working_directory)
        .env_clear()
        .env("HERMES_HOME", &request.staged_hermes_home)
        .env("HOME", request.staged_hermes_home.join("home"))
        .env("NO_COLOR", "1")
        .env("TERM", "dumb")
        .env("PATH", path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if snapshot_executable(&request.executable)?.digest != request.executable_hash {
        return Err(conflict("Hermes validation executable changed"));
    }
    let mut child = child
        .spawn()
        .map_err(|_| not_found("Hermes validation command could not be started"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| invalid("Hermes validation output is unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| invalid("Hermes validation output is unavailable"))?;
    let stdout_thread = thread::spawn(move || read_capped(stdout));
    let stderr_thread = thread::spawn(move || read_capped(stderr));
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|_| invalid("Hermes validation command failed"))?
        {
            break status;
        }
        if started.elapsed() > Duration::from_millis(CLI_TIMEOUT_MS.into()) {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_thread.join();
            let _ = stderr_thread.join();
            return Err(ClientError {
                code: ErrorCode::Timeout,
                message: "Hermes validation timed out".into(),
                field_path: None,
                retryable: false,
            });
        }
        thread::sleep(Duration::from_millis(10));
    };
    let stdout = stdout_thread
        .join()
        .map_err(|_| invalid("Hermes validation output is invalid"))?
        .map_err(|_| invalid("Hermes validation output is invalid"))?;
    let stderr = stderr_thread
        .join()
        .map_err(|_| invalid("Hermes validation output is invalid"))?
        .map_err(|_| invalid("Hermes validation output is invalid"))?;
    if !status.success() {
        return Err(invalid("Hermes validation command failed"));
    }
    if !stderr.is_empty() {
        return Err(invalid("Hermes validation wrote to stderr"));
    }
    Ok(stdout)
}

fn minimal_system_path() -> &'static str {
    #[cfg(windows)]
    {
        r"C:\Windows\System32"
    }
    #[cfg(not(windows))]
    {
        "/usr/bin:/bin"
    }
}

fn parse_config_check_output(bytes: &[u8], version: &str) -> Result<ValidationReport, ClientError> {
    if bytes.len() as u64 > CLI_OUTPUT_LIMIT {
        return Err(invalid("Hermes validation output exceeds the limit"));
    }
    let output =
        std::str::from_utf8(bytes).map_err(|_| invalid("Hermes validation output is invalid"))?;
    let output = strip_ansi(output).replace("\r\n", "\n");
    if output
        .chars()
        .any(|character| character.is_control() && character != '\n')
    {
        return Err(invalid("Hermes validation output is invalid"));
    }
    let lines = output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect::<Vec<_>>();
    let mut state = 0u8;
    let mut missing = false;
    let mut notice = false;
    for line in lines {
        let trimmed = line.trim();
        match state {
            0 if matches!(trimmed, "Configuration Status" | "📋 Configuration Status") => {
                state = 1
            }
            1 if valid_config_version_line(trimmed) => state = 2,
            2 if trimmed == "Required:" => state = 3,
            3 if trimmed == "Optional:" => state = 4,
            3 | 4 if valid_credential_status_line(line) => {
                missing |= trimmed.starts_with('✗') || trimmed.starts_with('○');
            }
            4 if valid_config_notice(trimmed, version) && !notice => {
                notice = true;
                state = 5;
            }
            5 if notice && trimmed == "Run 'hermes config migrate' to add them" => state = 6,
            _ => return Err(invalid("Hermes validation output is unexpected")),
        }
    }
    if state < 4 {
        return Err(invalid("Hermes validation output is incomplete"));
    }
    Ok(ValidationReport {
        valid: true,
        findings: missing
            .then(|| "isolated_credential_missing".to_owned())
            .into_iter()
            .collect(),
    })
}

fn valid_config_version_line(line: &str) -> bool {
    let Some(value) = line.strip_prefix("Config version: ") else {
        return false;
    };
    let parts = value.split_whitespace().collect::<Vec<_>>();
    matches!(
        parts.as_slice(),
        [current, "✓"] if current.bytes().all(|byte| byte.is_ascii_digit())
    ) || matches!(
        parts.as_slice(),
        [current, "→", latest, "(update", "available)"]
            if current.bytes().all(|byte| byte.is_ascii_digit())
                && latest.bytes().all(|byte| byte.is_ascii_digit())
    )
}

fn valid_credential_status_line(line: &str) -> bool {
    let indentation = line.len() - line.trim_start_matches(' ').len();
    if indentation < 4 {
        return false;
    }
    let trimmed = line.trim();
    let Some((status, rest)) = [("present", "✓ "), ("missing", "✗ "), ("optional", "○ ")]
        .into_iter()
        .find_map(|(status, prefix)| trimmed.strip_prefix(prefix).map(|rest| (status, rest)))
    else {
        return false;
    };
    let (name, suffix) = rest.split_once(' ').unwrap_or((rest, ""));
    let valid_name = (1..=128).contains(&name.len())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_');
    if !valid_name {
        return false;
    }
    match status {
        "present" => suffix.is_empty(),
        "missing" => suffix == "(missing)",
        "optional" if suffix.is_empty() => true,
        "optional" => suffix.strip_prefix("→ ").is_some_and(|tools| {
            !tools.is_empty()
                && tools.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b',' | b' ')
                })
                && tools.split(", ").all(|tool| !tool.is_empty())
        }),
        _ => false,
    }
}

fn valid_config_notice(line: &str, version: &str) -> bool {
    if !SUPPORTED_VERSIONS.contains(&version) {
        return false;
    }
    let Some((count, suffix)) = line.split_once(' ') else {
        return false;
    };
    count.bytes().all(|byte| byte.is_ascii_digit()) && suffix == "new config option(s) available"
}

fn digest_file_boundary(path: &Path) -> Result<Sha256Digest, BoundaryError> {
    fs::read(path)
        .map(|bytes| Sha256Digest(Sha256::digest(bytes).into()))
        .map_err(|_| BoundaryError::new("Hermes native state cannot be read"))
}

fn decode_wire_path(value: &WireNativeValue) -> Result<PathBuf, BoundaryError> {
    #[cfg(windows)]
    {
        use std::{ffi::OsString, os::windows::ffi::OsStringExt as _};
        if value.platform != NativePlatform::Windows || !value.bytes.len().is_multiple_of(2) {
            return Err(BoundaryError::new("Hermes native target is invalid"));
        }
        let wide = value
            .bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        Ok(PathBuf::from(OsString::from_wide(&wide)))
    }
    #[cfg(not(windows))]
    {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt as _};
        if value.platform != NativePlatform::Macos {
            return Err(BoundaryError::new("Hermes native target is invalid"));
        }
        Ok(PathBuf::from(OsString::from_vec(value.bytes.clone())))
    }
}

fn default_hermes_home() -> Result<PathBuf, ClientError> {
    default_hermes_home_from(
        env::var_os("HERMES_HOME").map(PathBuf::from),
        env::var_os("LOCALAPPDATA").map(PathBuf::from),
        platform_home_dir(),
        cfg!(target_os = "windows"),
    )
    .ok_or_else(|| not_found("Hermes home directory was not found"))
}

fn default_hermes_home_from(
    explicit: Option<PathBuf>,
    local_app_data: Option<PathBuf>,
    home: Option<PathBuf>,
    windows: bool,
) -> Option<PathBuf> {
    explicit.or_else(|| {
        if windows {
            local_app_data
                .map(|local| local.join("hermes"))
                .or_else(|| home.map(|home| home.join("AppData/Local/hermes")))
        } else {
            home.map(|home| home.join(".hermes"))
        }
    })
}

fn platform_home_dir() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        env::var_os("USERPROFILE")
            .or_else(|| env::var_os("HOME"))
            .map(PathBuf::from)
            .or_else(|| {
                let drive = env::var_os("HOMEDRIVE")?;
                let path = env::var_os("HOMEPATH")?;
                Some(PathBuf::from(drive).join(path))
            })
    }
    #[cfg(not(target_os = "windows"))]
    {
        home_dir()
    }
}

fn find_executable() -> Option<PathBuf> {
    let executable = if cfg!(windows) {
        "hermes.exe"
    } else {
        "hermes"
    };
    env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| env::split_paths(&paths).collect::<Vec<_>>())
        .map(|directory| directory.join(executable))
        .find(|candidate| candidate.is_file())
        .or_else(|| {
            cfg!(target_os = "macos")
                .then(home_dir)
                .flatten()
                .map(|home| home.join(".local/bin/hermes"))
                .filter(|candidate| candidate.is_file())
        })
}

fn snapshot_executable(path: &Path) -> Result<ExecutableSnapshot, ClientError> {
    Ok(attest_executable(path)?.snapshot)
}

fn attest_executable(path: &Path) -> Result<AttestedExecutable, ClientError> {
    attest_regular_executable(path)
}

fn attest_regular_executable(path: &Path) -> Result<AttestedExecutable, ClientError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .map_err(|_| not_found("Hermes executable was not found"))?;
    let metadata = file
        .metadata()
        .map_err(|_| invalid("Hermes executable cannot be inspected"))?;
    if !metadata.is_file() {
        return Err(invalid("Hermes executable cannot be inspected"));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|_| invalid("Hermes executable cannot be read"))?;
    let kind = classify_executable_bytes(path, &bytes);
    #[cfg(unix)]
    let kind = {
        use std::os::unix::fs::PermissionsExt as _;
        if kind == HermesExecutableKind::Native && metadata.permissions().mode() & 0o111 == 0 {
            HermesExecutableKind::Unknown
        } else {
            kind
        }
    };
    Ok(AttestedExecutable {
        snapshot: ExecutableSnapshot {
            kind,
            digest: Sha256Digest(Sha256::digest(&bytes).into()),
        },
        bytes,
    })
}

fn stage_executable(attested: &AttestedExecutable) -> Result<StagedExecutable, ClientError> {
    if !attested.snapshot.runnable() {
        return Err(invalid("Hermes wrapper execution is unsupported"));
    }
    let mut builder = tempfile::Builder::new();
    builder.prefix("context-relay-hermes-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        builder.permissions(fs::Permissions::from_mode(0o700));
    }
    let directory = builder
        .tempdir()
        .map_err(|_| invalid("Hermes executable could not be staged"))?;
    let path = directory.path().join(if cfg!(windows) {
        "hermes.exe"
    } else {
        "hermes"
    });
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o700);
    }
    let mut file = options
        .open(&path)
        .map_err(|_| invalid("Hermes executable could not be staged"))?;
    file.write_all(&attested.bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| invalid("Hermes executable could not be staged"))?;
    drop(file);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .map_err(|_| invalid("Hermes executable could not be staged"))?;
    }
    let staged_snapshot = snapshot_executable(&path)?;
    if staged_snapshot != attested.snapshot {
        return Err(conflict("Hermes staged executable changed"));
    }
    Ok(StagedExecutable {
        _directory: directory,
        path,
        snapshot: staged_snapshot,
    })
}

fn classify_executable_bytes(path: &Path, bytes: &[u8]) -> HermesExecutableKind {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase);
    if matches!(extension.as_deref(), Some("cmd" | "bat" | "ps1")) {
        return HermesExecutableKind::Wrapper;
    }
    // A setuptools/distlib Python console launcher is itself a PE image. Without
    // an immutable reviewed Windows artifact manifest, PE magic cannot prove
    // that this is a standalone Hermes implementation. Keep every PE candidate
    // import-only, including one renamed to omit the `.exe` suffix.
    if bytes.starts_with(b"MZ") {
        return HermesExecutableKind::Wrapper;
    }
    if bytes.starts_with(b"\x7fELF")
        || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xce])
        || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
        || bytes.starts_with(&[0xce, 0xfa, 0xed, 0xfe])
        || bytes.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
        || bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
        || bytes.starts_with(&[0xbe, 0xba, 0xfe, 0xca])
        || bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbf])
        || bytes.starts_with(&[0xbf, 0xba, 0xfe, 0xca])
    {
        return HermesExecutableKind::Native;
    }
    if bytes.starts_with(b"#!") {
        return HermesExecutableKind::Wrapper;
    }
    HermesExecutableKind::Unknown
}

fn discover_executable_version(
    executable: &Path,
) -> Result<(ExecutableSnapshot, String), ClientError> {
    discover_executable_version_after_snapshot(executable, || {}, run_version)
}

fn discover_executable_version_after_snapshot(
    executable: &Path,
    after_snapshot: impl FnOnce(),
    execute: impl FnMut(&Path, ExecutableSnapshot) -> Result<Vec<u8>, ClientError>,
) -> Result<(ExecutableSnapshot, String), ClientError> {
    discover_executable_version_with_boundaries(executable, after_snapshot, |_, _| {}, execute)
}

fn discover_executable_version_with_boundaries(
    executable: &Path,
    after_snapshot: impl FnOnce(),
    after_staging: impl FnOnce(&Path, &Path),
    mut execute: impl FnMut(&Path, ExecutableSnapshot) -> Result<Vec<u8>, ClientError>,
) -> Result<(ExecutableSnapshot, String), ClientError> {
    let attested = attest_executable(executable)?;
    let version = if attested.snapshot.runnable() {
        after_snapshot();
        if snapshot_executable(executable)? != attested.snapshot {
            return Err(conflict("Hermes executable changed"));
        }
        let staged = stage_executable(&attested)?;
        after_staging(executable, &staged.path);
        let output = execute(&staged.path, staged.snapshot.clone())?;
        if snapshot_executable(&staged.path)? != staged.snapshot {
            return Err(conflict("Hermes staged executable changed"));
        }
        parse_version(&output).ok_or_else(|| invalid("Hermes returned an invalid version"))?
    } else {
        "unknown".to_owned()
    };
    Ok((attested.snapshot, version))
}

fn run_version(
    executable: &Path,
    expected_snapshot: ExecutableSnapshot,
) -> Result<Vec<u8>, ClientError> {
    if !expected_snapshot.runnable() {
        return Err(invalid("Hermes wrapper execution is unsupported"));
    }
    if snapshot_executable(executable)? != expected_snapshot {
        return Err(conflict("Hermes executable changed"));
    }
    let stage_directory = executable
        .parent()
        .ok_or_else(|| invalid("Hermes executable stage is invalid"))?;
    let mut child = Command::new(executable);
    child
        .arg("--version")
        .current_dir(stage_directory)
        .env_clear()
        .env("HOME", stage_directory)
        .env("HERMES_HOME", stage_directory)
        .env("NO_COLOR", "1")
        .env("TERM", "dumb")
        .env("PATH", minimal_system_path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = child
        .spawn()
        .map_err(|_| not_found("Hermes executable could not be started"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| invalid("Hermes version output is unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| invalid("Hermes version output is unavailable"))?;
    let stdout_thread = thread::spawn(move || read_capped(stdout));
    let stderr_thread = thread::spawn(move || read_capped(stderr));
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|_| invalid("Hermes version probe failed"))?
        {
            break status;
        }
        if started.elapsed() > Duration::from_millis(CLI_TIMEOUT_MS.into()) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ClientError {
                code: ErrorCode::Timeout,
                message: "Hermes version probe timed out".into(),
                field_path: None,
                retryable: false,
            });
        }
        thread::sleep(Duration::from_millis(10));
    };
    let stdout = stdout_thread
        .join()
        .map_err(|_| invalid("Hermes version output is invalid"))?
        .map_err(|_| invalid("Hermes version output is invalid"))?;
    let stderr = stderr_thread
        .join()
        .map_err(|_| invalid("Hermes version output is invalid"))?
        .map_err(|_| invalid("Hermes version output is invalid"))?;
    if !status.success() || !stderr.is_empty() {
        return Err(invalid("Hermes version probe failed"));
    }
    Ok(stdout)
}

fn read_capped(reader: impl Read) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(CLI_OUTPUT_LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > CLI_OUTPUT_LIMIT {
        return Err(std::io::Error::other("output limit exceeded"));
    }
    Ok(bytes)
}

fn parse_version(bytes: &[u8]) -> Option<String> {
    let output = std::str::from_utf8(bytes).ok()?;
    let output = strip_ansi(output).replace("\r\n", "\n");
    if output
        .chars()
        .any(|character| character.is_control() && character != '\n')
    {
        return None;
    }
    let versions = output
        .split(|character: char| !(character.is_ascii_alphanumeric() || character == '.'))
        .filter(|token| valid_version(token))
        .collect::<Vec<_>>();
    (versions.len() == 1).then(|| versions[0].to_owned())
}

fn strip_ansi(value: &str) -> String {
    let mut result = String::new();
    let mut characters = value.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '\u{1b}' && characters.peek() == Some(&'[') {
            characters.next();
            for next in characters.by_ref() {
                if ('@'..='~').contains(&next) {
                    break;
                }
            }
        } else {
            result.push(character);
        }
    }
    result
}

fn valid_version(version: &str) -> bool {
    let mut parts = version.split('.');
    let valid = |part: Option<&str>| {
        part.is_some_and(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    };
    valid(parts.next()) && valid(parts.next()) && valid(parts.next()) && parts.next().is_none()
}

fn installation_method(path: &Path) -> InstallationMethod {
    let rendered = path.to_string_lossy();
    if rendered.contains("/bin/") || rendered.contains("\\bin\\") {
        InstallationMethod::PackageManager
    } else {
        InstallationMethod::Unknown
    }
}

fn require_file(path: &Path, message: &'static str) -> Result<(), ClientError> {
    path.is_file()
        .then_some(())
        .ok_or_else(|| not_found(message))
}

fn require_directory(path: &Path, message: &'static str) -> Result<(), ClientError> {
    path.is_dir()
        .then_some(())
        .ok_or_else(|| not_found(message))
}

fn home_dir() -> Option<PathBuf> {
    env::var_os("HOME").map(PathBuf::from)
}

fn ascii_lowercase(value: &str) -> String {
    value
        .bytes()
        .map(|byte| byte.to_ascii_lowercase() as char)
        .collect()
}

fn wire_path(path: &Path) -> WireNativeValue {
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

pub(super) fn invalid(message: &'static str) -> ClientError {
    ClientError {
        code: ErrorCode::InvalidRequest,
        message: message.into(),
        field_path: None,
        retryable: false,
    }
}

pub(super) fn not_found(message: &'static str) -> ClientError {
    ClientError {
        code: ErrorCode::NotFound,
        message: message.into(),
        field_path: None,
        retryable: false,
    }
}

pub(super) fn conflict(message: &'static str) -> ClientError {
    ClientError {
        code: ErrorCode::Conflict,
        message: message.into(),
        field_path: None,
        retryable: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::{Cell, RefCell},
        str::FromStr,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn default_home_resolution_matches_windows_priority_and_fallback() {
        let explicit = PathBuf::from("explicit");
        let local = PathBuf::from("local");
        let home = PathBuf::from("home");

        assert_eq!(
            default_hermes_home_from(
                Some(explicit.clone()),
                Some(local.clone()),
                Some(home.clone()),
                true,
            ),
            Some(explicit)
        );
        assert_eq!(
            default_hermes_home_from(None, Some(local.clone()), None, true),
            Some(local.join("hermes"))
        );
        assert_eq!(
            default_hermes_home_from(None, None, Some(home.clone()), true),
            Some(home.join("AppData/Local/hermes"))
        );
        assert_eq!(
            default_hermes_home_from(None, Some(local), Some(home.clone()), false),
            Some(home.join(".hermes"))
        );
    }

    struct ValidationFixture {
        root: PathBuf,
        adapter: HermesAdapter,
        layout: HermesLayout,
        project_id: ProjectId,
    }

    impl Drop for ValidationFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn validation_fixture(version: &str) -> ValidationFixture {
        let root = fs::canonicalize(env::temp_dir()).unwrap().join(format!(
            "context-relay-hermes-validation-fixture-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        let default_home = root.join("hermes home");
        let profile_home = default_home.join("profiles/coder");
        let project_root = root.join("project");
        let working_directory = project_root.join("service");
        let config = concat!(
            "approvals:\n",
            "  mode: smart\n",
            "  extension:\n",
            "    command: approval-command\n",
            "    args:\n",
            "      - --approval-arg\n",
            "    url: https://example.com/approval\n",
            "    placeholder: \"${APPROVAL_TOKEN}\"\n",
            "    nested:\n",
            "      arbitrary: approval-extension-value\n",
            "command_allowlist:\n",
            "  - cargo test\n",
            "plugins:\n",
            "  enabled:\n",
            "    - reviewer\n",
            "mcp_servers:\n",
            "  docs:\n",
            "    url: https://example.com/mcp\n",
            "    command: safe-command\n",
            "    args:\n",
            "      - --serve\n",
            "      - \"${MCP_TOKEN}\"\n",
            "    headers:\n",
            "      Authorization: must-not-stage-header\n",
            "hooks:\n",
            "  shell:\n",
            "    enabled: true\n",
            "    command: configured-hook-command\n",
            "    args:\n",
            "      - --audit\n",
            "    extension_scalar: arbitrary-extension-value\n",
            "provider:\n",
            "  api_key: must-not-stage-provider\n",
        );
        for home in [&default_home, &profile_home] {
            fs::create_dir_all(home.join("memories")).unwrap();
            fs::create_dir_all(home.join("plugins/reviewer")).unwrap();
            fs::create_dir_all(home.join("hooks/audit")).unwrap();
            fs::write(home.join("config.yaml"), config).unwrap();
            fs::write(home.join("memories/MEMORY.md"), "safe memory\n").unwrap();
            fs::write(
                home.join("plugins/reviewer/plugin.yaml"),
                "name: reviewer\nversion: 1\n",
            )
            .unwrap();
            fs::write(
                home.join("plugins/reviewer/plugin.py"),
                "raise RuntimeError('must-not-execute-plugin')\n",
            )
            .unwrap();
            fs::write(home.join("hooks/audit/HOOK.yaml"), "name: audit\n").unwrap();
            fs::write(
                home.join("hooks/audit/handler.py"),
                "print('must-not-execute-hook')\n",
            )
            .unwrap();
            fs::write(home.join(".env"), "TOKEN=must-not-stage-env\n").unwrap();
            fs::write(
                home.join("auth.json"),
                "{\"token\":\"must-not-stage-auth\"}",
            )
            .unwrap();
        }
        fs::create_dir_all(&working_directory).unwrap();
        fs::write(project_root.join(".hermes.md"), "safe project context\n").unwrap();
        let executable = root.join("hermes");
        fs::write(&executable, b"\x7fELFfixture hermes executable").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let project_id = ProjectId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073981").unwrap();
        let device_id = DeviceId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073982").unwrap();
        let layout = HermesLayout {
            executable,
            executable_kind: HermesExecutableKind::Native,
            version: version.to_owned(),
            installation_method: InstallationMethod::PackageManager,
            default_hermes_home: default_home,
            profile: HermesProfile {
                name: "coder".to_owned(),
                hermes_home: profile_home,
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
        ValidationFixture {
            root,
            adapter,
            layout,
            project_id,
        }
    }

    fn validation_receipt() -> ApplyReceipt {
        let device_id = DeviceId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073982").unwrap();
        ApplyReceipt {
            plan_id: context_relay_protocol::PlanId::from_str(
                "018f22e2-79b0-7cc8-98c4-dc0c0c073984",
            )
            .unwrap(),
            applied_hlc: HybridLogicalClock::new(1_900_000_000_001, 0, device_id),
            resulting_digests: vec![],
        }
    }

    fn config_check_output(version: &str) -> Vec<u8> {
        match version {
            "0.18.2" => concat!(
                "\x1b[36;1m📋 Configuration Status\x1b[0m\n",
                "\n",
                "  Config version: 33 ✓\n",
                "\n",
                "\x1b[1m  Required:\x1b[0m\n",
                "    \x1b[31m✗ MODEL_PROVIDER_KEY (missing)\x1b[0m\n",
                "\n",
                "\x1b[1m  Optional:\x1b[0m\n",
                "    \x1b[2m○ OPENROUTER_API_KEY → vision_analyze, web_search\x1b[0m\n",
                "    ✓ SAFE_OPTIONAL_KEY\n",
                "\n",
                "  2 new config option(s) available\n",
                "    Run 'hermes config migrate' to add them\n",
            )
            .as_bytes()
            .to_vec(),
            "0.18.1" => concat!(
                "📋 Configuration Status\r\n",
                "\r\n",
                "  Config version: 32 → 33 (update available)\r\n",
                "\r\n",
                "  Required:\r\n",
                "    ✗ MODEL_PROVIDER_KEY (missing)\r\n",
                "\r\n",
                "  Optional:\r\n",
                "    ○ OPENROUTER_API_KEY → vision_analyze\r\n",
            )
            .as_bytes()
            .to_vec(),
            _ => panic!("unsupported validation fixture version"),
        }
    }

    #[cfg(unix)]
    fn write_official_launcher_chain(root: &Path) -> (PathBuf, PathBuf, Vec<u8>) {
        use std::os::unix::fs::PermissionsExt as _;

        let bin = root.join("hermes-agent/venv/bin");
        let command_bin = root.join("command-bin");
        fs::create_dir_all(&bin).unwrap();
        fs::create_dir_all(&command_bin).unwrap();
        fs::write(root.join("hermes-agent/venv/pyvenv.cfg"), "home = pinned\n").unwrap();
        let interpreter = bin.join("python");
        fs::write(&interpreter, b"\xcf\xfa\xed\xfeofficial python").unwrap();
        fs::set_permissions(&interpreter, fs::Permissions::from_mode(0o700)).unwrap();
        let python_launcher = bin.join("hermes");
        let launcher = format!(
            "#!{}\n# -*- coding: utf-8 -*-\nimport sys\nfrom hermes_cli.main import main\nif __name__ == \"__main__\":\n    if sys.argv[0].endswith(\"-script.pyw\"):\n        sys.argv[0] = sys.argv[0][:-11]\n    elif sys.argv[0].endswith(\".exe\"):\n        sys.argv[0] = sys.argv[0][:-4]\n    sys.exit(main())\n",
            interpreter.display()
        )
        .into_bytes();
        fs::write(&python_launcher, &launcher).unwrap();
        fs::set_permissions(&python_launcher, fs::Permissions::from_mode(0o700)).unwrap();
        let shim = command_bin.join("hermes");
        fs::write(
            &shim,
            format!(
                "#!/usr/bin/env bash\nunset PYTHONPATH\nunset PYTHONHOME\nexec \"{}\" \"$@\"\n",
                python_launcher.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&shim, fs::Permissions::from_mode(0o700)).unwrap();
        (shim, interpreter, launcher)
    }

    #[test]
    fn effective_validation_uses_only_isolated_nonsecret_home() {
        let fixture = validation_fixture("0.18.2");
        let imported = fixture
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
            .unwrap();
        let imported_mcp = imported
            .components
            .iter()
            .find(|component| component.kind == ComponentKind::McpServer)
            .unwrap();
        assert!(imported_mcp.body_markdown.contains("safe-command"));
        assert!(imported_mcp.body_markdown.contains("--serve"));
        assert!(imported_mcp.body_markdown.contains("${MCP_TOKEN}"));
        assert!(
            imported_mcp
                .body_markdown
                .contains("https://example.com/mcp")
        );
        let imported_hook = imported
            .components
            .iter()
            .find(|component| {
                component.kind == ComponentKind::Hook
                    && component.metadata.iter().any(|(key, value)| {
                        key == "structuralLocation" && value == "config:hooks.shell"
                    })
            })
            .unwrap();
        assert!(
            imported_hook
                .body_markdown
                .contains("arbitrary-extension-value")
        );
        assert!(
            imported_hook
                .body_markdown
                .contains("configured-hook-command")
        );
        assert!(imported_hook.body_markdown.contains("--audit"));
        let imported_approval = imported
            .components
            .iter()
            .find(|component| {
                component.kind == ComponentKind::PermissionDeclaration
                    && component.metadata.iter().any(|(key, value)| {
                        key == "structuralLocation" && value == "config:approvals.extension"
                    })
            })
            .unwrap();
        for preserved in [
            "approval-command",
            "--approval-arg",
            "https://example.com/approval",
            "${APPROVAL_TOKEN}",
            "approval-extension-value",
        ] {
            assert!(imported_approval.body_markdown.contains(preserved));
        }
        let live_config = fs::read(fixture.layout.profile.hermes_home.join("config.yaml")).unwrap();
        let live_config = yaml::parse_config(&live_config).unwrap();
        let expected_projection = import::validation_config_projection(
            &live_config,
            &fixture.layout.profile.name,
            &fixture.layout.version,
        )
        .unwrap();
        let expected_projection = serde_yaml_ng::to_value(expected_projection).unwrap();
        let stages = RefCell::new(Vec::new());
        for _ in 0..2 {
            let report = fixture
                .adapter
                .validate_effective_with(&validation_receipt(), |request| {
                    assert_eq!(request.argv, ["config", "check"]);
                    assert_ne!(request.executable, fixture.layout.executable);
                    assert_eq!(
                        fs::read(&request.executable).unwrap(),
                        fs::read(&fixture.layout.executable).unwrap()
                    );
                    assert_eq!(request.working_directory, fixture.layout.working_directory);
                    assert_eq!(
                        request.executable_hash,
                        snapshot_executable(&request.executable).unwrap().digest
                    );
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt as _;
                        assert_eq!(
                            fs::metadata(&request.staged_hermes_home)
                                .unwrap()
                                .permissions()
                                .mode()
                                & 0o777,
                            0o700
                        );
                        assert_eq!(
                            fs::metadata(request.staged_hermes_home.join("config.yaml"))
                                .unwrap()
                                .permissions()
                                .mode()
                                & 0o777,
                            0o600
                        );
                    }
                    stages.borrow_mut().push(request.staged_hermes_home.clone());
                    let staged =
                        fs::read_to_string(request.staged_hermes_home.join("config.yaml")).unwrap();
                    assert!(staged.contains("approvals:"));
                    assert!(staged.contains("mode: \"smart\""));
                    assert!(staged.contains("command_allowlist:"));
                    assert!(staged.contains("plugins:"));
                    assert!(staged.contains("mcp_servers:"));
                    assert!(staged.contains("safe-command"));
                    assert!(staged.contains("https://example.com/mcp"));
                    assert!(staged.contains("hooks:"));
                    assert!(staged.contains("configured-hook-command"));
                    let parsed = yaml::parse_config(staged.as_bytes()).unwrap();
                    assert_eq!(parsed.value, expected_projection);
                    for excluded in [
                        "must-not-stage",
                        "provider:",
                        "api_key",
                        "authorization",
                        "headers:",
                        "env:",
                    ] {
                        assert!(
                            !staged.to_ascii_lowercase().contains(excluded),
                            "staged projection exposed excluded marker {excluded}: {staged}"
                        );
                    }
                    assert!(request.staged_hermes_home.join("memories").is_dir());
                    for forbidden in [
                        ".env",
                        "auth.json",
                        "SOUL.md",
                        "skills",
                        "plugins",
                        "hooks",
                        "mcp",
                        "sessions",
                        "channels",
                        "gateway.pid",
                        "gateway_state.json",
                        "provider",
                        "state.db",
                        "logs",
                        "canary",
                    ] {
                        assert!(!request.staged_hermes_home.join(forbidden).exists());
                    }
                    Ok(config_check_output("0.18.2"))
                })
                .unwrap();
            assert!(report.valid);
            assert_eq!(report.findings, ["isolated_credential_missing"]);
        }
        let stages = stages.into_inner();
        assert_ne!(stages[0], stages[1]);
        assert!(stages.iter().all(|stage| !stage.exists()));
    }

    #[test]
    fn effective_validation_executes_staged_attested_bytes_after_source_replacement() {
        let fixture = validation_fixture("0.18.2");
        let source = fixture.layout.executable.clone();
        let attested_bytes = fs::read(&source).unwrap();
        let expected_digest = Sha256Digest(Sha256::digest(&attested_bytes).into());
        let executed = RefCell::new(None);

        fixture
            .adapter
            .validate_effective_with(&validation_receipt(), |request| {
                fs::write(&source, b"\x7fELFreplacement hermes executable").unwrap();
                assert_ne!(request.executable, source);
                assert_eq!(fs::read(&request.executable).unwrap(), attested_bytes);
                assert_eq!(request.executable_hash, expected_digest);
                assert_eq!(
                    snapshot_executable(&request.executable).unwrap().digest,
                    request.executable_hash
                );
                executed.replace(Some(request.executable.clone()));
                Ok(config_check_output("0.18.2"))
            })
            .unwrap();

        assert!(!executed.into_inner().unwrap().exists());
    }

    #[test]
    fn validation_never_starts_gateway_plugins_hooks_mcp_or_provider() {
        let fixture = validation_fixture("0.18.2");
        let sentinels = [
            fixture.root.join("configured-command-ran"),
            fixture.root.join("plugin-ran"),
            fixture.root.join("hook-ran"),
            fixture.root.join("provider-ran"),
        ];
        fixture
            .adapter
            .validate_effective_with(&validation_receipt(), |request| {
                assert_eq!(request.argv, ["config", "check"]);
                for forbidden in [
                    "gateway",
                    "doctor",
                    "migrate",
                    "setup",
                    "plugin",
                    "hook",
                    "mcp",
                    "chat",
                    "provider",
                    "safe-command",
                    "https://example.com/mcp",
                ] {
                    assert!(
                        request
                            .argv
                            .iter()
                            .all(|argument| !argument.contains(forbidden))
                    );
                }
                assert!(sentinels.iter().all(|sentinel| !sentinel.exists()));
                Ok(config_check_output("0.18.2"))
            })
            .unwrap();
        assert!(sentinels.iter().all(|sentinel| !sentinel.exists()));
    }

    #[test]
    fn config_check_output_parser_accepts_both_frozen_release_contracts() {
        for version in SUPPORTED_VERSIONS {
            let fixture = validation_fixture(version);
            let report = fixture
                .adapter
                .validate_effective_with(&validation_receipt(), |_| {
                    Ok(config_check_output(version))
                })
                .unwrap();
            assert!(report.valid);
            assert_eq!(report.findings, ["isolated_credential_missing"]);
        }
    }

    #[test]
    fn unexpected_oversized_stderr_or_nonzero_validation_fails_closed() {
        let fixture = validation_fixture("0.18.2");
        let duplicate = [
            config_check_output("0.18.2"),
            b"\n  Required:\n    \xe2\x9c\x97 DUPLICATE_KEY (missing)\n".to_vec(),
        ]
        .concat();
        let unknown = [
            config_check_output("0.18.2"),
            b"\n  Gateway: running\n".to_vec(),
        ]
        .concat();
        let mut oversized = config_check_output("0.18.2");
        oversized.resize(65_537, b' ');
        for bytes in [duplicate, unknown, oversized, vec![0xff, 0xfe, 0xfd]] {
            assert_eq!(
                fixture
                    .adapter
                    .validate_effective_with(&validation_receipt(), |_| Ok(bytes.clone()))
                    .unwrap_err()
                    .code,
                ErrorCode::InvalidRequest
            );
        }
        for error in [
            invalid("Hermes validation wrote to stderr"),
            ClientError {
                code: ErrorCode::Timeout,
                message: "Hermes validation timed out".into(),
                field_path: None,
                retryable: false,
            },
            invalid("Hermes validation command failed"),
        ] {
            let actual = fixture
                .adapter
                .validate_effective_with(&validation_receipt(), |_| Err(error.clone()))
                .unwrap_err();
            assert_eq!(actual.code, error.code);
        }
    }

    #[test]
    fn unknown_version_or_wrapper_never_runs_validation_command() {
        for (version, wrapper) in [("9.9.9", false), ("0.18.2", true)] {
            let fixture = validation_fixture("0.18.2");
            if wrapper {
                fs::write(&fixture.layout.executable, b"#!/bin/sh\nexit 99\n").unwrap();
            }
            let mut layout = fixture.layout.clone();
            layout.version = version.into();
            layout.executable_kind = if wrapper {
                HermesExecutableKind::Wrapper
            } else {
                HermesExecutableKind::Native
            };
            let device_id = DeviceId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073982").unwrap();
            let adapter = HermesAdapter::from_layout(
                layout,
                fixture.project_id,
                device_id,
                HybridLogicalClock::new(1_900_000_000_000, 0, device_id),
            )
            .unwrap();
            let calls = Cell::new(0);
            let error = adapter
                .validate_effective_with(&validation_receipt(), |_| {
                    calls.set(calls.get() + 1);
                    Ok(config_check_output("0.18.2"))
                })
                .unwrap_err();
            assert_eq!(error.code, ErrorCode::HarnessUnsupported);
            assert_eq!(calls.get(), 0);
        }
    }

    #[test]
    fn validation_stage_is_removed_on_success_and_failure() {
        let fixture = validation_fixture("0.18.2");
        let success = RefCell::new(None);
        fixture
            .adapter
            .validate_effective_with(&validation_receipt(), |request| {
                success.replace(Some(request.staged_hermes_home.clone()));
                Ok(config_check_output("0.18.2"))
            })
            .unwrap();
        assert!(!success.into_inner().unwrap().exists());

        let failure = RefCell::new(None);
        fixture
            .adapter
            .validate_effective_with(&validation_receipt(), |request| {
                failure.replace(Some(request.staged_hermes_home.clone()));
                Err(ClientError {
                    code: ErrorCode::Timeout,
                    message: "Hermes validation timed out".into(),
                    field_path: None,
                    retryable: false,
                })
            })
            .unwrap_err();
        assert!(!failure.into_inner().unwrap().exists());
    }

    #[test]
    fn parse_version_accepts_a_single_version_with_a_trailing_newline() {
        assert_eq!(parse_version(b"hermes 0.18.2\n"), Some("0.18.2".to_owned()));
    }

    #[test]
    fn parse_version_accepts_a_single_ansi_decorated_version() {
        assert_eq!(
            parse_version(b"\x1b[32mhermes 0.18.2\x1b[0m\r\n"),
            Some("0.18.2".to_owned())
        );
    }

    #[test]
    fn parse_version_rejects_malformed_or_multiple_versions() {
        assert_eq!(parse_version(b"hermes 9.9\n"), None);
        assert_eq!(parse_version(b"hermes 9.9.9.9\n"), None);
        assert_eq!(parse_version(b"hermes 9.9.9 runtime 0.18.2\n"), None);
    }

    #[cfg(unix)]
    #[test]
    fn direct_wrapper_version_runner_rejects_before_process_creation() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = fs::canonicalize(env::temp_dir()).unwrap().join(format!(
            "context-relay-hermes-direct-wrapper-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let executable = root.join("hermes");
        let canary = root.join("wrapper-ran");
        fs::write(
            &executable,
            format!(
                "#!/bin/sh\n/usr/bin/touch '{}'\nprintf 'hermes 0.18.2\\n'\n",
                canary.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let snapshot = snapshot_executable(&executable).unwrap();

        assert_eq!(
            run_version(&executable, snapshot).unwrap_err().code,
            ErrorCode::InvalidRequest
        );
        assert!(!canary.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn nonexecutable_native_source_is_not_staged_or_version_probed() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = fs::canonicalize(env::temp_dir()).unwrap().join(format!(
            "context-relay-hermes-version-nonexec-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let executable = root.join("hermes");
        fs::write(&executable, b"\x7fELFnonexecutable native").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o600)).unwrap();
        let calls = Cell::new(0);

        let (snapshot, version) = discover_executable_version_after_snapshot(
            &executable,
            || {},
            |_, _| {
                calls.set(calls.get() + 1);
                Ok(b"hermes 0.18.2\n".to_vec())
            },
        )
        .unwrap();

        assert_eq!(snapshot.kind, HermesExecutableKind::Unknown);
        assert_eq!(version, "unknown");
        assert_eq!(calls.get(), 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn malicious_official_shaped_python_venv_is_import_only_and_never_executed() {
        let fixture = validation_fixture("0.18.2");
        let venv_root = fixture.root.join("malicious-official-shape");
        let (executable, _, _) = write_official_launcher_chain(&venv_root);
        let package =
            venv_root.join("hermes-agent/venv/lib/python3.13/site-packages/hermes_cli/main.py");
        fs::create_dir_all(package.parent().unwrap()).unwrap();
        let package_canary = fixture.root.join("malicious-hermes-package-ran");
        fs::write(
            &package,
            format!(
                "from pathlib import Path\nPath({:?}).write_text('executed')\ndef main(): return 0\n",
                package_canary
            ),
        )
        .unwrap();

        let version_calls = Cell::new(0);
        let (_, version) = discover_executable_version_after_snapshot(
            &executable,
            || {},
            |_, _| {
                version_calls.set(version_calls.get() + 1);
                fs::write(&package_canary, b"version probe executed malicious package").unwrap();
                Ok(b"hermes 0.18.2\n".to_vec())
            },
        )
        .unwrap();
        assert_eq!(version, "unknown");
        assert_eq!(version_calls.get(), 0);
        assert!(!package_canary.exists());

        let mut layout = fixture.layout.clone();
        layout.executable = executable;
        layout.executable_kind = HermesExecutableKind::Wrapper;
        let device_id = DeviceId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073982").unwrap();
        let adapter = HermesAdapter::from_layout(
            layout,
            fixture.project_id,
            device_id,
            HybridLogicalClock::new(1_900_000_000_000, 0, device_id),
        )
        .unwrap();
        assert_eq!(adapter.capability(), CapabilityLevel::ImportOnly);
        let validation_calls = Cell::new(0);
        let error = adapter
            .validate_effective_with(&validation_receipt(), |_| {
                validation_calls.set(validation_calls.get() + 1);
                fs::write(&package_canary, b"validation executed malicious package").unwrap();
                Ok(config_check_output("0.18.2"))
            })
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::HarnessUnsupported);
        assert_eq!(validation_calls.get(), 0);
        assert!(!package_canary.exists());
    }

    #[cfg(unix)]
    #[test]
    fn official_python_launcher_is_import_only_without_a_pinned_package_closure() {
        use std::os::unix::fs::PermissionsExt as _;

        for version in SUPPORTED_VERSIONS {
            let root = fs::canonicalize(env::temp_dir()).unwrap().join(format!(
                "context-relay-hermes-official-python-{}-{}",
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
            ));
            let bin = root.join("hermes-agent/venv/bin");
            fs::create_dir_all(&bin).unwrap();
            fs::write(root.join("hermes-agent/venv/pyvenv.cfg"), "home = pinned\n").unwrap();
            let interpreter = bin.join("python");
            fs::write(&interpreter, b"\xcf\xfa\xed\xfeofficial python").unwrap();
            fs::set_permissions(&interpreter, fs::Permissions::from_mode(0o700)).unwrap();
            let executable = bin.join("hermes");
            let launcher = format!(
                "#!{}\n# -*- coding: utf-8 -*-\nimport sys\nfrom hermes_cli.main import main\nif __name__ == \"__main__\":\n    if sys.argv[0].endswith(\"-script.pyw\"):\n        sys.argv[0] = sys.argv[0][:-11]\n    elif sys.argv[0].endswith(\".exe\"):\n        sys.argv[0] = sys.argv[0][:-4]\n    sys.exit(main())\n",
                interpreter.display()
            );
            fs::write(&executable, launcher.as_bytes()).unwrap();
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
            let calls = Cell::new(0);

            let (snapshot, discovered) = discover_executable_version_after_snapshot(
                &executable,
                || {},
                |_, _| {
                    calls.set(calls.get() + 1);
                    Ok(format!("hermes {version}\n").into_bytes())
                },
            )
            .unwrap();

            assert_eq!(snapshot.kind, HermesExecutableKind::Wrapper);
            assert_eq!(discovered, "unknown");
            assert_eq!(calls.get(), 0);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn official_bash_shim_is_import_only_without_a_pinned_package_closure() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = fs::canonicalize(env::temp_dir()).unwrap().join(format!(
            "context-relay-hermes-official-shim-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        let bin = root.join("hermes-agent/venv/bin");
        let command_bin = root.join("command-bin");
        fs::create_dir_all(&bin).unwrap();
        fs::create_dir_all(&command_bin).unwrap();
        fs::write(root.join("hermes-agent/venv/pyvenv.cfg"), "home = pinned\n").unwrap();
        let interpreter = bin.join("python");
        fs::write(&interpreter, b"\xcf\xfa\xed\xfeofficial python").unwrap();
        fs::set_permissions(&interpreter, fs::Permissions::from_mode(0o700)).unwrap();
        let python_launcher = bin.join("hermes");
        let launcher = format!(
            "#!{}\n# -*- coding: utf-8 -*-\nimport sys\nfrom hermes_cli.main import main\nif __name__ == \"__main__\":\n    if sys.argv[0].endswith(\"-script.pyw\"):\n        sys.argv[0] = sys.argv[0][:-11]\n    elif sys.argv[0].endswith(\".exe\"):\n        sys.argv[0] = sys.argv[0][:-4]\n    sys.exit(main())\n",
            interpreter.display()
        );
        fs::write(&python_launcher, launcher.as_bytes()).unwrap();
        fs::set_permissions(&python_launcher, fs::Permissions::from_mode(0o700)).unwrap();
        let executable = command_bin.join("hermes");
        let shim = format!(
            "#!/usr/bin/env bash\nunset PYTHONPATH\nunset PYTHONHOME\nexec \"{}\" \"$@\"\n",
            python_launcher.display()
        );
        fs::write(&executable, shim.as_bytes()).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let calls = Cell::new(0);

        let (snapshot, version) = discover_executable_version_after_snapshot(
            &executable,
            || {},
            |_, _| {
                calls.set(calls.get() + 1);
                Ok(b"hermes 0.18.2\n".to_vec())
            },
        )
        .unwrap();

        assert_eq!(snapshot.kind, HermesExecutableKind::Wrapper);
        assert_eq!(version, "unknown");
        assert_eq!(calls.get(), 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn official_launcher_shape_never_reaches_full_or_validation() {
        let fixture = validation_fixture("0.18.2");
        let (executable, _, _) = write_official_launcher_chain(&fixture.root.join("official"));
        let mut layout = fixture.layout.clone();
        layout.executable = executable;
        layout.executable_kind = HermesExecutableKind::Wrapper;
        let device_id = DeviceId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073982").unwrap();
        let adapter = HermesAdapter::from_layout(
            layout,
            fixture.project_id,
            device_id,
            HybridLogicalClock::new(1_900_000_000_000, 0, device_id),
        )
        .unwrap();

        assert_eq!(adapter.capability(), CapabilityLevel::ImportOnly);
        let calls = Cell::new(0);
        let error = adapter
            .validate_effective_with(&validation_receipt(), |_| {
                calls.set(calls.get() + 1);
                Ok(config_check_output("0.18.2"))
            })
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::HarnessUnsupported);
        assert_eq!(calls.get(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn official_wrapper_never_reaches_the_staging_boundary() {
        let root = fs::canonicalize(env::temp_dir()).unwrap().join(format!(
            "context-relay-hermes-official-staging-race-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let (executable, _, _) = write_official_launcher_chain(&root);
        let staged = Cell::new(0);
        let calls = Cell::new(0);

        let (_, version) = discover_executable_version_with_boundaries(
            &executable,
            || {},
            |_, _| {
                staged.set(staged.get() + 1);
            },
            |_, _| {
                calls.set(calls.get() + 1);
                Ok(b"hermes 0.18.2\n".to_vec())
            },
        )
        .unwrap();

        assert_eq!(version, "unknown");
        assert_eq!(staged.get(), 0);
        assert_eq!(calls.get(), 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn arbitrary_shebangs_and_modified_python_launchers_are_never_executed() {
        use std::os::unix::fs::PermissionsExt as _;

        for variant in [
            "shell",
            "wrong-topology",
            "wrong-interpreter",
            "modified-body",
        ] {
            let root = fs::canonicalize(env::temp_dir()).unwrap().join(format!(
                "context-relay-hermes-untrusted-wrapper-{}-{}",
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
            ));
            let bin = if variant == "wrong-topology" {
                root.join("bin")
            } else {
                root.join("hermes-agent/venv/bin")
            };
            fs::create_dir_all(&bin).unwrap();
            if let Some(venv) = bin.parent().filter(|parent| parent.ends_with("venv")) {
                fs::write(venv.join("pyvenv.cfg"), "home = pinned\n").unwrap();
            }
            let sibling_interpreter = bin.join("python");
            fs::write(&sibling_interpreter, b"\xcf\xfa\xed\xfeofficial python").unwrap();
            fs::set_permissions(&sibling_interpreter, fs::Permissions::from_mode(0o700)).unwrap();
            let outside_interpreter = root.join("outside-python");
            fs::write(&outside_interpreter, b"\xcf\xfa\xed\xfeoutside python").unwrap();
            fs::set_permissions(&outside_interpreter, fs::Permissions::from_mode(0o700)).unwrap();
            let executable = bin.join("hermes");
            let bytes = match variant {
                "shell" => b"#!/bin/sh\nprintf 'hermes 0.18.2\\n'\n".to_vec(),
                _ => {
                    let interpreter = if variant == "wrong-interpreter" {
                        &outside_interpreter
                    } else {
                        &sibling_interpreter
                    };
                    let extra = if variant == "modified-body" {
                        "print('unreviewed')\n"
                    } else {
                        ""
                    };
                    format!(
                        "#!{}\n# -*- coding: utf-8 -*-\nimport sys\nfrom hermes_cli.main import main\nif __name__ == \"__main__\":\n    if sys.argv[0].endswith(\"-script.pyw\"):\n        sys.argv[0] = sys.argv[0][:-11]\n    elif sys.argv[0].endswith(\".exe\"):\n        sys.argv[0] = sys.argv[0][:-4]\n    sys.exit(main())\n{extra}",
                        interpreter.display()
                    )
                    .into_bytes()
                }
            };
            fs::write(&executable, bytes).unwrap();
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
            let calls = Cell::new(0);

            let (snapshot, version) = discover_executable_version_after_snapshot(
                &executable,
                || {},
                |_, _| {
                    calls.set(calls.get() + 1);
                    Ok(b"hermes 0.18.2\n".to_vec())
                },
            )
            .unwrap();

            assert_eq!(snapshot.kind, HermesExecutableKind::Wrapper, "{variant}");
            assert_eq!(version, "unknown", "{variant}");
            assert_eq!(calls.get(), 0, "{variant}");
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn windows_distlib_console_launcher_shape_is_not_a_native_hermes_binary() {
        let launcher =
            b"MZ\x90\0distlib.exe\0#!python.exe\r\nfrom hermes_cli.main import main\r\nPK\x03\x04";
        assert_eq!(
            classify_executable_bytes(Path::new("hermes.exe"), launcher),
            HermesExecutableKind::Wrapper
        );
    }

    #[test]
    fn windows_pe_launcher_magic_remains_import_only_when_renamed() {
        let launcher =
            b"MZ\x90\0distlib.exe\0#!python.exe\r\nfrom hermes_cli.main import main\r\nPK\x03\x04";
        assert_eq!(
            classify_executable_bytes(Path::new("hermes"), launcher),
            HermesExecutableKind::Wrapper
        );
    }

    #[test]
    fn windows_hermes_exe_launcher_is_import_only_and_never_version_probed() {
        let root = fs::canonicalize(env::temp_dir()).unwrap().join(format!(
            "context-relay-hermes-windows-launcher-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let executable = root.join("hermes.exe");
        fs::write(
            &executable,
            b"MZ\x90\0distlib.exe\0#!python.exe\r\nfrom hermes_cli.main import main\r\nPK\x03\x04",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let canary = root.join("windows-python-launcher-ran");
        let calls = Cell::new(0);

        let (snapshot, version) = discover_executable_version_after_snapshot(
            &executable,
            || {},
            |_, _| {
                calls.set(calls.get() + 1);
                fs::write(&canary, b"executed").unwrap();
                Ok(b"hermes 0.18.2\n".to_vec())
            },
        )
        .unwrap();

        assert_eq!(snapshot.kind, HermesExecutableKind::Wrapper);
        assert_eq!(version, "unknown");
        assert_eq!(calls.get(), 0);
        assert!(!canary.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn classify_executable_recognizes_universal_mach_o_headers() {
        let root = fs::canonicalize(env::temp_dir()).unwrap().join(format!(
            "context-relay-hermes-classifier-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let executable = root.join("hermes");
        for header in [
            [0xca, 0xfe, 0xba, 0xbe],
            [0xbe, 0xba, 0xfe, 0xca],
            [0xca, 0xfe, 0xba, 0xbf],
            [0xbf, 0xba, 0xfe, 0xca],
        ] {
            fs::write(&executable, header).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
            }
            assert_eq!(
                snapshot_executable(&executable).unwrap().kind,
                HermesExecutableKind::Native
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn wrapper_extension_overrides_native_magic() {
        let root = fs::canonicalize(env::temp_dir()).unwrap().join(format!(
            "context-relay-hermes-wrapper-precedence-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let executable = root.join("hermes.cmd");
        fs::write(&executable, b"MZnative-looking wrapper").unwrap();

        assert_eq!(
            snapshot_executable(&executable).unwrap().kind,
            HermesExecutableKind::Wrapper
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn native_discovery_rejects_replacement_after_snapshot_without_executing_wrapper() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = fs::canonicalize(env::temp_dir()).unwrap().join(format!(
            "context-relay-hermes-discovery-race-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let executable = root.join("hermes");
        let sentinel = root.join("wrapper-ran");
        fs::write(&executable, b"\x7fELFnative executable").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();

        let result = discover_executable_version_after_snapshot(
            &executable,
            || {
                fs::write(
                    &executable,
                    format!(
                        "#!/bin/sh\n/usr/bin/touch '{}'\nprintf 'hermes 0.18.2\\n'\n",
                        sentinel.display()
                    ),
                )
                .unwrap();
                fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
            },
            run_version,
        );
        let sentinel_exists = sentinel.exists();
        let _ = fs::remove_dir_all(root);

        assert!(matches!(
            result,
            Err(ClientError {
                code: ErrorCode::Conflict,
                ..
            })
        ));
        assert!(!sentinel_exists);
    }

    #[cfg(unix)]
    #[test]
    fn native_discovery_executes_staged_attested_bytes_when_source_changes_after_staging() {
        use std::{cell::RefCell, os::unix::fs::PermissionsExt as _};

        let root = fs::canonicalize(env::temp_dir()).unwrap().join(format!(
            "context-relay-hermes-staged-race-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let executable = root.join("hermes");
        let sentinel = root.join("wrapper-ran");
        fs::write(&executable, b"\x7fELFattested native executable").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let executed_path = RefCell::new(None);

        let (snapshot, version) = discover_executable_version_with_boundaries(
            &executable,
            || {},
            |source, staged| {
                assert_ne!(staged, source);
                fs::write(
                    source,
                    format!(
                        "#!/bin/sh\n/usr/bin/touch '{}'\nprintf 'hermes 0.18.2\\n'\n",
                        sentinel.display()
                    ),
                )
                .unwrap();
                fs::set_permissions(source, fs::Permissions::from_mode(0o700)).unwrap();
            },
            |staged, expected_snapshot| {
                assert_eq!(snapshot_executable(staged).unwrap(), expected_snapshot);
                assert_eq!(
                    fs::metadata(staged).unwrap().permissions().mode() & 0o777,
                    0o700
                );
                assert_eq!(
                    fs::metadata(staged.parent().unwrap())
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o700
                );
                executed_path.replace(Some(staged.to_owned()));
                Ok(b"hermes 0.18.2\n".to_vec())
            },
        )
        .unwrap();

        assert_eq!(snapshot.kind, HermesExecutableKind::Native);
        assert_eq!(version, "0.18.2");
        assert_ne!(
            executed_path.borrow().as_deref(),
            Some(executable.as_path())
        );
        assert!(!executed_path.borrow().as_ref().unwrap().exists());
        assert!(!sentinel.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn attested_constructor_rejects_different_native_binary_replaced_after_version_probe() {
        use std::str::FromStr as _;

        let root = fs::canonicalize(env::temp_dir()).unwrap().join(format!(
            "context-relay-hermes-constructor-race-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        let default_home = root.join("home");
        let profile_home = default_home.join("profiles/coder");
        let project_root = root.join("project");
        let working_directory = project_root.join("service");
        fs::create_dir_all(&profile_home).unwrap();
        fs::create_dir_all(&working_directory).unwrap();
        fs::write(profile_home.join("config.yaml"), "approvals: {}\n").unwrap();
        let executable = root.join("hermes");
        fs::write(&executable, b"\x7fELForiginal native executable").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        }

        let (snapshot, version) = discover_executable_version_after_snapshot(
            &executable,
            || {},
            |_, _| Ok(b"hermes 0.18.2\n".to_vec()),
        )
        .unwrap();
        fs::write(&executable, b"\x7fELFdifferent native executable").unwrap();

        let project_id = ProjectId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073981").unwrap();
        let device_id = DeviceId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073982").unwrap();
        let result = HermesAdapter::from_attested_layout(
            HermesLayout {
                executable,
                executable_kind: snapshot.kind,
                version,
                installation_method: InstallationMethod::PackageManager,
                default_hermes_home: default_home,
                profile: HermesProfile {
                    name: "coder".to_owned(),
                    hermes_home: profile_home,
                },
                project_root,
                working_directory,
            },
            project_id,
            device_id,
            HybridLogicalClock::new(1_900_000_000_000, 0, device_id),
            snapshot,
        );

        assert!(matches!(
            result,
            Err(ClientError {
                code: ErrorCode::Conflict,
                ..
            })
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn native_discovery_accepts_newline_and_ansi_version_output() {
        let root = fs::canonicalize(env::temp_dir()).unwrap().join(format!(
            "context-relay-hermes-version-output-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let executable = root.join("hermes");
        fs::write(&executable, b"\x7fELFnative executable").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        }
        for output in [
            b"hermes 0.18.2\n".as_slice(),
            b"\x1b[32mhermes 0.18.2\x1b[0m\r\n",
        ] {
            let (_, version) = discover_executable_version_after_snapshot(
                &executable,
                || {},
                |_, _| Ok(output.to_vec()),
            )
            .unwrap();
            assert_eq!(version, "0.18.2");
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn native_discovery_accepts_one_unknown_semantic_version() {
        use std::str::FromStr as _;

        let root = fs::canonicalize(env::temp_dir()).unwrap().join(format!(
            "context-relay-hermes-unknown-version-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        let default_home = root.join("home");
        let profile_home = default_home.join("profiles/coder");
        let project_root = root.join("project");
        let working_directory = project_root.join("service");
        fs::create_dir_all(&profile_home).unwrap();
        fs::create_dir_all(&working_directory).unwrap();
        fs::write(profile_home.join("config.yaml"), "approvals: {}\n").unwrap();
        let executable = root.join("hermes");
        fs::write(&executable, b"\x7fELFnative executable").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        }

        let (snapshot, version) = discover_executable_version_after_snapshot(
            &executable,
            || {},
            |_, _| Ok(b"hermes 9.9.9\n".to_vec()),
        )
        .unwrap();

        assert_eq!(snapshot.kind, HermesExecutableKind::Native);
        assert_eq!(version, "9.9.9");
        let project_id = ProjectId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073981").unwrap();
        let device_id = DeviceId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073982").unwrap();
        let adapter = HermesAdapter::from_attested_layout(
            HermesLayout {
                executable,
                executable_kind: snapshot.kind,
                version,
                installation_method: InstallationMethod::PackageManager,
                default_hermes_home: default_home,
                profile: HermesProfile {
                    name: "coder".to_owned(),
                    hermes_home: profile_home,
                },
                project_root,
                working_directory,
            },
            project_id,
            device_id,
            HybridLogicalClock::new(1_900_000_000_000, 0, device_id),
            snapshot,
        )
        .unwrap();
        assert_eq!(
            adapter
                .probe(&ProbeContext {
                    harness: HarnessId::Hermes,
                    requested_profile: Some("coder".to_owned()),
                })
                .unwrap()
                .capability,
            CapabilityLevel::ImportOnly
        );
        fs::remove_dir_all(root).unwrap();
    }
}
