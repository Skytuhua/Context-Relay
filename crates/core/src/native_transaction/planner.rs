//! Canonical persistence for previewed native transaction plans.

use context_relay_native_runner::{
    NativeState, OsNativeFileSystem, RuleSyncFeature, RuleSyncFeatures, RuleSyncTarget,
    RuntimeTarget, SidecarCommand, SidecarId, StagePath,
};
use context_relay_protocol::{
    ApprovalClass, CliOperation, HarnessId, PlanId, SetupPlan, Sha256Digest, WireNativeValue,
};
use serde::Deserialize;
use serde_json::{Value, json};
use thiserror::Error;

use super::NativeTransactionPlan;

pub const SEALED_PLAN_SCHEMA_VERSION: u32 = 1;
pub const REVERSIBLE_PLAN_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Error)]
pub enum PlanSealError {
    #[error("preview plans must use approval v2")]
    ApprovalVersion,
    #[error("the setup approval hash does not match the sealed plan")]
    ApprovalHash,
    #[error("cannot serialize the sealed native plan: {0}")]
    Serialization(String),
    #[error("cannot open the sealed native plan: {0}")]
    Deserialization(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenedPlan {
    pub schema_version: u32,
    pub plan: NativeTransactionPlan,
    pub native_rollback_states: Vec<Vec<u8>>,
    pub rollback_of_plan_id: Option<PlanId>,
}

/// Returns the stable, complete plan envelope persisted for a preview.
///
/// The envelope deliberately carries the public plan and each internal binding
/// rather than accepting a caller-provided serialized payload.
pub fn seal_plan(
    plan: &NativeTransactionPlan,
    approval_hash: Sha256Digest,
) -> Result<Vec<u8>, PlanSealError> {
    if plan.approval_version != 2 {
        return Err(PlanSealError::ApprovalVersion);
    }
    if plan.setup.batch_hash != approval_hash {
        return Err(PlanSealError::ApprovalHash);
    }

    let native_plan = json!({
        "setup": plan.setup,
        "approvalVersion": plan.approval_version,
        "helperPolicyVersion": plan.helper_policy_version,
        "manifestSchemaVersion": plan.manifest_schema_version,
        "manifestDigest": digest(plan.manifest_digest),
        "helperHash": digest(plan.helper_hash),
        "sidecars": plan.sidecars.iter().map(|sidecar| json!({
            "id": sidecar.id.stable_name(),
            "target": sidecar.target.stable_name(),
            "version": sidecar.version,
            "closureHash": digest(sidecar.closure_hash),
            "sourceBundleHash": digest(sidecar.source_bundle_hash),
            "buildToolchainHash": digest(sidecar.build_toolchain_hash),
            "commandTemplateDigest": digest(sidecar.command_template_digest),
            "command": {
                "templateId": sidecar.command.template_id(),
                "normalizedArguments": sidecar.command.normalized_arguments(),
            },
        })).collect::<Vec<_>>(),
        "structuralAllowlistHash": digest(plan.structural_allowlist_hash),
        "stagedInputs": plan.staged_inputs.iter().map(|input| json!({
            "path": input.path.as_str(),
            "length": input.length,
            "digest": digest(input.digest),
        })).collect::<Vec<_>>(),
        "expectedSemanticOutputHash": digest(plan.expected_semantic_output_hash),
        "scannerResultHash": digest(plan.scanner_result_hash),
        "mutations": plan.mutations.iter().map(|mutation| json!({
            "target": mutation.target,
            "kind": mutation.kind.canonical_name(),
            "content": hex(&mutation.content),
            "expectedFingerprint": digest(mutation.expected.0),
            "intendedFingerprint": digest(mutation.intended.0),
        })).collect::<Vec<_>>(),
        "cliMutations": plan.cli_mutations.iter().map(|mutation| json!({
            "stableId": mutation.stable_id,
            "expected": mutation.expected.as_ref().map(cli_declaration),
            "intended": mutation.intended.as_ref().map(cli_declaration),
            "forward": mutation.forward,
            "rollback": mutation.rollback,
        })).collect::<Vec<_>>(),
        "nativeMemoryRegistrations": plan.native_memory_registrations,
        "ownershipChanges": plan.ownership_changes.iter().map(|change| json!({
            "stableId": change.stable_id,
            "structuralLocation": change.structural_location,
            "semanticDigest": digest(change.semantic_digest),
            "nativeDigest": digest(change.native_digest),
        })).collect::<Vec<_>>(),
    });
    serde_json::to_vec(&json!({
        "schemaVersion": SEALED_PLAN_SCHEMA_VERSION,
        "approvalVersion": 2,
        "approvalHash": digest(approval_hash),
        "nativePlan": native_plan,
    }))
    .map_err(|error| PlanSealError::Serialization(error.to_string()))
}

/// Seals a v2 reversible envelope. Each rollback state is the exact canonical
/// NativeState-v1 image corresponding to the native mutation at the same
/// index. Its fingerprint is already approval-bound as `mutation.expected`.
pub fn seal_reversible_plan(
    plan: &NativeTransactionPlan,
    approval_hash: Sha256Digest,
    native_rollback_states: &[Vec<u8>],
    rollback_of_plan_id: Option<PlanId>,
) -> Result<Vec<u8>, PlanSealError> {
    validate_native_rollback_states(plan, native_rollback_states)?;
    let mut envelope: Value = serde_json::from_slice(&seal_plan(plan, approval_hash)?)
        .map_err(|error| PlanSealError::Serialization(error.to_string()))?;
    let object = envelope
        .as_object_mut()
        .ok_or_else(|| PlanSealError::Serialization("sealed envelope is not an object".into()))?;
    object.insert(
        "schemaVersion".to_owned(),
        Value::from(REVERSIBLE_PLAN_SCHEMA_VERSION),
    );
    object.insert(
        "nativeRollbackStates".to_owned(),
        Value::Array(
            plan.mutations
                .iter()
                .zip(native_rollback_states)
                .map(|(mutation, content)| {
                    json!({
                        "target": mutation.target,
                        "expectedFingerprint": digest(mutation.expected.0),
                        "content": hex(content),
                    })
                })
                .collect(),
        ),
    );
    object.insert(
        "rollbackOfPlanId".to_owned(),
        rollback_of_plan_id
            .map(|plan_id| Value::String(plan_id.to_string()))
            .unwrap_or(Value::Null),
    );
    serde_json::to_vec(&envelope).map_err(|error| PlanSealError::Serialization(error.to_string()))
}

pub(crate) fn capture_native_rollback_states(
    plan: &NativeTransactionPlan,
) -> Result<Vec<Vec<u8>>, PlanSealError> {
    plan.mutations
        .iter()
        .map(|mutation| {
            let path = decode_native_path(&mutation.target)?;
            let snapshot = OsNativeFileSystem::new()
                .snapshot(&path)
                .map_err(|_| invalid_envelope("native rollback state cannot be inspected"))?;
            let state = predicted_hermes_gateway_reserved_state(plan, &path, snapshot.state())?;
            if Sha256Digest(state.fingerprint()) != mutation.expected.0 {
                return Err(invalid_envelope(
                    "native rollback state changed during preview",
                ));
            }
            state
                .encode_v1()
                .map_err(|_| invalid_envelope("native rollback state is not representable"))
        })
        .collect()
}

fn predicted_hermes_gateway_reserved_state(
    plan: &NativeTransactionPlan,
    path: &std::path::Path,
    state: &NativeState,
) -> Result<NativeState, PlanSealError> {
    if plan.setup.harness != HarnessId::Hermes || plan.setup.approval_class != ApprovalClass::Active
    {
        return Ok(state.clone());
    }
    let Some(lock_path) = plan
        .setup
        .expected_native_digests
        .iter()
        .filter(|expected| expected.expected_digest.is_none())
        .filter_map(|expected| decode_native_path(&expected.target).ok())
        .find(|candidate| {
            candidate
                .file_name()
                .is_some_and(|name| name == "gateway.lock")
                && candidate.parent() == path.parent()
        })
    else {
        return Ok(state.clone());
    };
    let lock = OsNativeFileSystem::new()
        .snapshot(&lock_path)
        .map_err(|_| invalid_envelope("Hermes gateway lock cannot be inspected"))?;
    if !matches!(lock.state(), NativeState::Absent { .. }) {
        return Err(invalid_envelope(
            "Hermes gateway lock changed during preview",
        ));
    }
    let NativeState::RegularFile { bytes, metadata } = state else {
        return Err(invalid_envelope(
            "Hermes profile-root creation requires an existing gateway lock",
        ));
    };
    let metadata = metadata
        .for_absent_sibling_creation(lock.state())
        .map_err(|_| invalid_envelope("Hermes gateway reservation changed"))?;
    Ok(NativeState::regular_file(bytes.clone(), metadata))
}

#[cfg(windows)]
fn decode_native_path(target: &WireNativeValue) -> Result<std::path::PathBuf, PlanSealError> {
    use std::{ffi::OsString, os::windows::ffi::OsStringExt as _};

    if target.platform != context_relay_protocol::NativePlatform::Windows
        || target.bytes.len() % 2 != 0
    {
        return Err(invalid_envelope("native rollback target path is invalid"));
    }
    let wide = target
        .bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    if wide.is_empty() || wide.contains(&0) {
        return Err(invalid_envelope("native rollback target path is invalid"));
    }
    Ok(std::path::PathBuf::from(OsString::from_wide(&wide)))
}

#[cfg(unix)]
fn decode_native_path(target: &WireNativeValue) -> Result<std::path::PathBuf, PlanSealError> {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt as _};

    if target.platform == context_relay_protocol::NativePlatform::Windows
        || target.bytes.is_empty()
        || target.bytes.contains(&0)
    {
        return Err(invalid_envelope("native rollback target path is invalid"));
    }
    Ok(std::path::PathBuf::from(OsString::from_vec(
        target.bytes.clone(),
    )))
}

/// Opens the complete persisted envelope and reconstructs only the plan bytes
/// that were sealed by [`seal_plan`]. Approval is recomputed after parsing so
/// the caller never relies on envelope metadata alone.
pub fn open_plan(payload: &[u8]) -> Result<OpenedPlan, PlanSealError> {
    let envelope: SealedEnvelope = serde_json::from_slice(payload)
        .map_err(|error| PlanSealError::Deserialization(error.to_string()))?;
    if !matches!(
        envelope.schema_version,
        SEALED_PLAN_SCHEMA_VERSION | REVERSIBLE_PLAN_SCHEMA_VERSION
    ) || envelope.approval_version != 2
    {
        return Err(PlanSealError::Deserialization(
            "unsupported sealed plan envelope version".to_owned(),
        ));
    }
    let approval_hash = parse_digest(&envelope.approval_hash)?;
    let native: SealedNativePlan = serde_json::from_value(envelope.native_plan)
        .map_err(|error| PlanSealError::Deserialization(error.to_string()))?;
    let plan = native.open()?;
    if plan.approval_version != 2
        || plan.setup.batch_hash != approval_hash
        || approval_hash_v2_for_open(&plan)? != approval_hash
    {
        return Err(PlanSealError::ApprovalHash);
    }
    let native_rollback_states = match envelope.schema_version {
        SEALED_PLAN_SCHEMA_VERSION => {
            if !plan.mutations.is_empty()
                || envelope.native_rollback_states.is_some()
                || envelope.rollback_of_plan_id.is_some()
            {
                return Err(invalid_envelope(
                    "schema v1 cannot carry reversible native state or rollback linkage",
                ));
            }
            vec![]
        }
        REVERSIBLE_PLAN_SCHEMA_VERSION => {
            let states = envelope
                .native_rollback_states
                .ok_or_else(|| invalid_envelope("reversible native states are missing"))?
                .into_iter()
                .map(SealedNativeRollback::open)
                .collect::<Result<Vec<_>, _>>()?;
            if states.len() != plan.mutations.len() {
                return Err(invalid_envelope(
                    "reversible native state cardinality differs from mutations",
                ));
            }
            let mut content = Vec::with_capacity(states.len());
            for (mutation, state) in plan.mutations.iter().zip(states) {
                if state.target != mutation.target || state.expected != mutation.expected.0 {
                    return Err(invalid_envelope(
                        "reversible native state binding differs from its mutation",
                    ));
                }
                content.push(state.content);
            }
            validate_native_rollback_states(&plan, &content)?;
            content
        }
        _ => unreachable!(),
    };
    Ok(OpenedPlan {
        schema_version: envelope.schema_version,
        plan,
        native_rollback_states,
        rollback_of_plan_id: envelope.rollback_of_plan_id,
    })
}

fn approval_hash_v2_for_open(plan: &NativeTransactionPlan) -> Result<Sha256Digest, PlanSealError> {
    super::approval_hash_v2(plan).map_err(|error| PlanSealError::Deserialization(error.to_string()))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SealedEnvelope {
    schema_version: u32,
    approval_version: u32,
    approval_hash: String,
    native_plan: Value,
    #[serde(default)]
    native_rollback_states: Option<Vec<SealedNativeRollback>>,
    #[serde(default)]
    rollback_of_plan_id: Option<PlanId>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SealedNativeRollback {
    target: WireNativeValue,
    expected_fingerprint: String,
    content: String,
}

struct OpenedNativeRollback {
    target: WireNativeValue,
    expected: Sha256Digest,
    content: Vec<u8>,
}

impl SealedNativeRollback {
    fn open(self) -> Result<OpenedNativeRollback, PlanSealError> {
        Ok(OpenedNativeRollback {
            target: self.target,
            expected: parse_digest(&self.expected_fingerprint)?,
            content: parse_hex(&self.content)?,
        })
    }
}

fn validate_native_rollback_states(
    plan: &NativeTransactionPlan,
    states: &[Vec<u8>],
) -> Result<(), PlanSealError> {
    if states.len() != plan.mutations.len() {
        return Err(invalid_envelope(
            "reversible native state cardinality differs from mutations",
        ));
    }
    for (mutation, encoded) in plan.mutations.iter().zip(states) {
        let state = NativeState::decode_v1(encoded)
            .map_err(|_| invalid_envelope("reversible native state is not canonical"))?;
        if state
            .encode_v1()
            .map_err(|_| invalid_envelope("reversible native state is invalid"))?
            != *encoded
            || Sha256Digest(state.fingerprint()) != mutation.expected.0
        {
            return Err(invalid_envelope(
                "reversible native state fingerprint differs from its mutation",
            ));
        }
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SealedNativePlan {
    setup: SetupPlan,
    approval_version: u32,
    helper_policy_version: u32,
    manifest_schema_version: u32,
    manifest_digest: String,
    helper_hash: String,
    sidecars: Vec<SealedSidecar>,
    structural_allowlist_hash: String,
    staged_inputs: Vec<SealedInput>,
    expected_semantic_output_hash: String,
    scanner_result_hash: String,
    mutations: Vec<SealedMutation>,
    cli_mutations: Vec<SealedCliMutation>,
    #[serde(default)]
    native_memory_registrations: Vec<crate::native_memory::NativeMemoryRegistration>,
    ownership_changes: Vec<SealedOwnershipChange>,
}

impl SealedNativePlan {
    fn open(self) -> Result<NativeTransactionPlan, PlanSealError> {
        Ok(NativeTransactionPlan {
            setup: self.setup,
            approval_version: self.approval_version,
            helper_policy_version: self.helper_policy_version,
            manifest_schema_version: self.manifest_schema_version,
            manifest_digest: parse_digest(&self.manifest_digest)?,
            helper_hash: parse_digest(&self.helper_hash)?,
            sidecars: self
                .sidecars
                .into_iter()
                .map(SealedSidecar::open)
                .collect::<Result<_, _>>()?,
            structural_allowlist_hash: parse_digest(&self.structural_allowlist_hash)?,
            staged_inputs: self
                .staged_inputs
                .into_iter()
                .map(SealedInput::open)
                .collect::<Result<_, _>>()?,
            expected_semantic_output_hash: parse_digest(&self.expected_semantic_output_hash)?,
            scanner_result_hash: parse_digest(&self.scanner_result_hash)?,
            mutations: self
                .mutations
                .into_iter()
                .map(SealedMutation::open)
                .collect::<Result<_, _>>()?,
            cli_mutations: self
                .cli_mutations
                .into_iter()
                .map(SealedCliMutation::open)
                .collect::<Result<_, _>>()?,
            native_memory_registrations: self.native_memory_registrations,
            ownership_changes: self
                .ownership_changes
                .into_iter()
                .map(SealedOwnershipChange::open)
                .collect::<Result<_, _>>()?,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SealedSidecar {
    id: String,
    target: String,
    version: String,
    closure_hash: String,
    source_bundle_hash: String,
    build_toolchain_hash: String,
    command_template_digest: String,
    command: SealedCommand,
}

impl SealedSidecar {
    fn open(self) -> Result<super::SidecarBinding, PlanSealError> {
        let id = match self.id.as_str() {
            "rulesync" => SidecarId::RuleSync,
            "gitleaks" => SidecarId::Gitleaks,
            "semgrep" => SidecarId::Osemgrep,
            _ => return Err(invalid_envelope("unknown sidecar id")),
        };
        let target = match self.target.as_str() {
            "windows-x86_64" => RuntimeTarget::WindowsX86_64,
            "macos-aarch64" => RuntimeTarget::MacosArm64,
            _ => return Err(invalid_envelope("unknown runtime target")),
        };
        let command = self.command.open()?;
        if command.sidecar() != id {
            return Err(invalid_envelope("sidecar command binding differs"));
        }
        Ok(super::SidecarBinding {
            id,
            target,
            version: self.version,
            closure_hash: parse_digest(&self.closure_hash)?,
            source_bundle_hash: parse_digest(&self.source_bundle_hash)?,
            build_toolchain_hash: parse_digest(&self.build_toolchain_hash)?,
            command_template_digest: parse_digest(&self.command_template_digest)?,
            command,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SealedCommand {
    template_id: String,
    normalized_arguments: Vec<String>,
}

impl SealedCommand {
    fn open(self) -> Result<SidecarCommand, PlanSealError> {
        let command = match self.template_id.as_str() {
            "rulesync-generate-v1" => parse_rulesync_command(&self.normalized_arguments)?,
            "gitleaks-dir-v1" => SidecarCommand::GitleaksScanPackage,
            "osemgrep-scan-v1" => SidecarCommand::OsemgrepScanPackage,
            _ => return Err(invalid_envelope("unknown command template")),
        };
        if command.template_id() != self.template_id
            || command.normalized_arguments() != self.normalized_arguments
        {
            return Err(invalid_envelope("sidecar command arguments differ"));
        }
        command
            .validate()
            .map_err(|_| invalid_envelope("sidecar command is invalid"))?;
        Ok(command)
    }
}

fn parse_rulesync_command(arguments: &[String]) -> Result<SidecarCommand, PlanSealError> {
    if arguments.len() != 12
        || arguments[0] != "generate"
        || arguments[1] != "--targets"
        || arguments[3] != "--features"
        || arguments[5] != "--output-roots"
        || arguments[6] != "output"
        || arguments[7] != "--config"
        || arguments[8] != "rulesync.jsonc"
        || arguments[9] != "--input-root"
        || arguments[10] != "input"
        || arguments[11] != "--silent"
    {
        return Err(invalid_envelope("RuleSync command arguments are invalid"));
    }
    let target = match arguments[2].as_str() {
        "claudecode" => RuleSyncTarget::ClaudeCode,
        "codexcli" => RuleSyncTarget::CodexCli,
        _ => return Err(invalid_envelope("RuleSync target is invalid")),
    };
    let features = arguments[4]
        .split(',')
        .map(|feature| match feature {
            "rules" => Ok(RuleSyncFeature::Rules),
            "ignore" => Ok(RuleSyncFeature::Ignore),
            "mcp" => Ok(RuleSyncFeature::Mcp),
            "subagents" => Ok(RuleSyncFeature::Subagents),
            "commands" => Ok(RuleSyncFeature::Commands),
            "skills" => Ok(RuleSyncFeature::Skills),
            "hooks" => Ok(RuleSyncFeature::Hooks),
            "permissions" => Ok(RuleSyncFeature::Permissions),
            "checks" => Ok(RuleSyncFeature::Checks),
            _ => Err(invalid_envelope("RuleSync feature is invalid")),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let features = RuleSyncFeatures::new(&features)
        .map_err(|_| invalid_envelope("RuleSync features are invalid"))?;
    Ok(SidecarCommand::RuleSyncGenerate { target, features })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SealedInput {
    path: String,
    length: u64,
    digest: String,
}

impl SealedInput {
    fn open(self) -> Result<super::ApprovedInput, PlanSealError> {
        Ok(super::ApprovedInput {
            path: StagePath::try_from(self.path)
                .map_err(|_| invalid_envelope("staged input path is invalid"))?,
            length: self.length,
            digest: parse_digest(&self.digest)?,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SealedMutation {
    target: WireNativeValue,
    kind: String,
    content: String,
    expected_fingerprint: String,
    intended_fingerprint: String,
}

impl SealedMutation {
    fn open(self) -> Result<super::ApprovedMutation, PlanSealError> {
        let kind = match self.kind.as_str() {
            "payload" => super::MutationKind::Payload,
            "executable_disabled" => super::MutationKind::ExecutableDisabled,
            "activation_reference" => super::MutationKind::ActivationReference,
            _ => return Err(invalid_envelope("native mutation kind is invalid")),
        };
        Ok(super::ApprovedMutation {
            target: self.target,
            kind,
            content: parse_hex(&self.content)?,
            expected: super::RestorableStateFingerprint(parse_digest(&self.expected_fingerprint)?),
            intended: super::RestorableStateFingerprint(parse_digest(&self.intended_fingerprint)?),
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SealedCliMutation {
    stable_id: String,
    expected: Option<SealedCliDeclaration>,
    intended: Option<SealedCliDeclaration>,
    forward: Vec<CliOperation>,
    rollback: Vec<CliOperation>,
}

impl SealedCliMutation {
    fn open(self) -> Result<super::ApprovedCliMutation, PlanSealError> {
        Ok(super::ApprovedCliMutation {
            stable_id: self.stable_id,
            expected: self.expected.map(SealedCliDeclaration::open).transpose()?,
            intended: self.intended.map(SealedCliDeclaration::open).transpose()?,
            forward: self.forward,
            rollback: self.rollback,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SealedCliDeclaration {
    harness: HarnessId,
    server_name: String,
    canonical_body: String,
    fingerprint: String,
}

impl SealedCliDeclaration {
    fn open(self) -> Result<super::CanonicalCliDeclaration, PlanSealError> {
        Ok(super::CanonicalCliDeclaration {
            harness: self.harness,
            server_name: self.server_name,
            canonical_body: self.canonical_body,
            fingerprint: parse_digest(&self.fingerprint)?,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SealedOwnershipChange {
    stable_id: String,
    structural_location: String,
    semantic_digest: String,
    native_digest: String,
}

impl SealedOwnershipChange {
    fn open(self) -> Result<super::OwnershipChange, PlanSealError> {
        Ok(super::OwnershipChange {
            stable_id: self.stable_id,
            structural_location: self.structural_location,
            semantic_digest: parse_digest(&self.semantic_digest)?,
            native_digest: parse_digest(&self.native_digest)?,
        })
    }
}

fn parse_digest(value: &str) -> Result<Sha256Digest, PlanSealError> {
    let bytes = parse_hex(value)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| invalid_envelope("digest length is invalid"))?;
    Ok(Sha256Digest(bytes))
}

fn parse_hex(value: &str) -> Result<Vec<u8>, PlanSealError> {
    if !value.len().is_multiple_of(2)
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(invalid_envelope("hex value is invalid"));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]);
            let low = hex_nibble(pair[1]);
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("parse_hex validates lowercase hexadecimal"),
    }
}

fn invalid_envelope(message: &str) -> PlanSealError {
    PlanSealError::Deserialization(message.to_owned())
}

fn cli_declaration(declaration: &super::CanonicalCliDeclaration) -> serde_json::Value {
    json!({
        "harness": declaration.harness,
        "serverName": declaration.server_name,
        "canonicalBody": declaration.canonical_body,
        "fingerprint": digest(declaration.fingerprint),
    })
}

fn digest(value: Sha256Digest) -> String {
    hex(&value.0)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
