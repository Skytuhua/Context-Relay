//! Canonical persistence for previewed native transaction plans.

use context_relay_protocol::Sha256Digest;
use serde_json::json;
use thiserror::Error;

use super::NativeTransactionPlan;

pub const SEALED_PLAN_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Error)]
pub enum PlanSealError {
    #[error("preview plans must use approval v2")]
    ApprovalVersion,
    #[error("the setup approval hash does not match the sealed plan")]
    ApprovalHash,
    #[error("cannot serialize the sealed native plan: {0}")]
    Serialization(String),
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
