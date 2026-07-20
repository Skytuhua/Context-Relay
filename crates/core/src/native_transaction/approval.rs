use std::{cmp::Ordering, collections::BTreeSet};

use context_relay_native_runner::NativeState;
use context_relay_protocol::{NativePlatform, Sha256Digest, WireNativeValue};
use minicbor::Encoder;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use unicode_casefold::UnicodeCaseFold;
use unicode_normalization::UnicodeNormalization;

use super::model::{ApprovedInput, NativeTransactionPlan, OwnershipChange, SidecarBinding};

pub const APPROVAL_DOMAIN_V1: &[u8] = b"context-relay/native-plan/v1\0";

#[derive(Debug, Error)]
pub enum ApprovalError {
    #[error("invalid native plan: {0}")]
    Invalid(String),
    #[error("duplicate native plan member: {0}")]
    Duplicate(String),
    #[error("cannot serialize native approval: {0}")]
    Serialization(String),
}

pub fn approval_hash_v1(plan: &NativeTransactionPlan) -> Result<Sha256Digest, ApprovalError> {
    plan.setup
        .validate()
        .map_err(|error| ApprovalError::Invalid(error.to_string()))?;
    validate(plan)?;

    let value = approval_value(plan)?;
    let mut encoder = Encoder::new(Vec::new());
    encode_value(&mut encoder, &value)?;
    let encoded = encoder.into_writer();

    let mut hasher = Sha256::new();
    hasher.update(APPROVAL_DOMAIN_V1);
    hasher.update(encoded);
    Ok(Sha256Digest(hasher.finalize().into()))
}

fn validate(plan: &NativeTransactionPlan) -> Result<(), ApprovalError> {
    if plan.sidecars.is_empty() {
        return Err(ApprovalError::Invalid("sidecars cannot be empty".into()));
    }
    unique(
        plan.sidecars.iter().map(|sidecar| {
            format!(
                "{}\0{}",
                sidecar.id.stable_name(),
                sidecar.target.stable_name()
            )
        }),
        "sidecar",
    )?;
    for sidecar in &plan.sidecars {
        if sidecar.version.is_empty() {
            return Err(ApprovalError::Invalid(
                "sidecar fields cannot be empty".into(),
            ));
        }
        if sidecar.command.sidecar() != sidecar.id {
            return Err(ApprovalError::Invalid(
                "sidecar command does not match sidecar id".into(),
            ));
        }
    }

    unique(
        plan.staged_inputs
            .iter()
            .map(|input| input.path.as_str().to_owned()),
        "input",
    )?;

    unique_targets(plan.mutations.iter().map(|mutation| &mutation.target))?;
    let mut last_role = 0_u8;
    for mutation in &plan.mutations {
        let intended = NativeState::decode_v1(&mutation.content).map_err(|_| {
            ApprovalError::Invalid(
                "mutation content is not a canonical complete native state".into(),
            )
        })?;
        if intended
            .encode_v1()
            .map_err(|_| ApprovalError::Invalid("mutation native state cannot be encoded".into()))?
            != mutation.content
        {
            return Err(ApprovalError::Invalid(
                "mutation content is not the canonical native-state encoding".into(),
            ));
        }
        if intended.fingerprint() != mutation.intended.0.0 {
            return Err(ApprovalError::Invalid(
                "mutation native state does not match its intended fingerprint".into(),
            ));
        }
        let role = match mutation.kind {
            super::model::MutationKind::Payload => 1,
            super::model::MutationKind::ExecutableDisabled => 2,
            super::model::MutationKind::ActivationReference => 3,
        };
        if role < last_role {
            return Err(ApprovalError::Invalid(
                "mutations must order payloads before disabled executables before activation references"
                    .into(),
            ));
        }
        last_role = role;
    }
    unique(
        plan.ownership_changes
            .iter()
            .map(|change| change.stable_id.clone()),
        "ownership stable id",
    )?;
    Ok(())
}

fn unique(
    values: impl IntoIterator<Item = String>,
    label: &'static str,
) -> Result<(), ApprovalError> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value.clone()) {
            return Err(ApprovalError::Duplicate(format!("{label}: {value}")));
        }
    }
    Ok(())
}

fn approval_value(plan: &NativeTransactionPlan) -> Result<Value, ApprovalError> {
    let mut setup = serde_json::to_value(&plan.setup)
        .map_err(|error| ApprovalError::Serialization(error.to_string()))?;
    setup
        .as_object_mut()
        .ok_or_else(|| ApprovalError::Serialization("SetupPlan is not an object".into()))?
        .remove("batchHash")
        .ok_or_else(|| ApprovalError::Serialization("SetupPlan.batchHash is missing".into()))?;
    canonicalize_setup_sets(&mut setup)?;

    let mut sidecars: Vec<&SidecarBinding> = plan.sidecars.iter().collect();
    sidecars.sort_by(|left, right| {
        left.id
            .stable_name()
            .cmp(right.id.stable_name())
            .then_with(|| left.target.stable_name().cmp(right.target.stable_name()))
    });

    let mut inputs: Vec<&ApprovedInput> = plan.staged_inputs.iter().collect();
    inputs.sort_by(|left, right| left.path.as_str().cmp(right.path.as_str()));

    let mut ownership: Vec<&OwnershipChange> = plan.ownership_changes.iter().collect();
    ownership.sort_by(|left, right| left.stable_id.cmp(&right.stable_id));

    let sidecars = sidecars
        .into_iter()
        .map(|sidecar| {
            json!({
                "id": sidecar.id.stable_name(),
                "target": sidecar.target.stable_name(),
                "version": sidecar.version,
                "closureHash": digest(&sidecar.closure_hash),
                "sourceBundleHash": digest(&sidecar.source_bundle_hash),
                "buildToolchainHash": digest(&sidecar.build_toolchain_hash),
                "commandTemplateDigest": digest(&sidecar.command_template_digest),
                "command": {
                    "templateId": sidecar.command.template_id(),
                    "normalizedArguments": sidecar.command.normalized_arguments(),
                },
            })
        })
        .collect::<Vec<_>>();

    let inputs = inputs
        .into_iter()
        .map(|input| {
            json!({
                "path": input.path.as_str(),
                "length": input.length,
                "digest": digest(&input.digest),
            })
        })
        .collect::<Vec<_>>();

    let mutations = plan
        .mutations
        .iter()
        .map(|mutation| {
            Ok(json!({
                "target": serde_json::to_value(&mutation.target)
                    .map_err(|error| ApprovalError::Serialization(error.to_string()))?,
                "kind": mutation.kind.canonical_name(),
                "content": hex(&mutation.content),
                "expectedFingerprint": digest(&mutation.expected.0),
                "intendedFingerprint": digest(&mutation.intended.0),
            }))
        })
        .collect::<Result<Vec<_>, ApprovalError>>()?;

    let ownership = ownership
        .into_iter()
        .map(|change| {
            json!({
                "stableId": change.stable_id,
                "structuralLocation": change.structural_location,
                "semanticDigest": digest(&change.semantic_digest),
                "nativeDigest": digest(&change.native_digest),
            })
        })
        .collect::<Vec<_>>();

    Ok(json!([
        1,
        setup,
        {
            "helperPolicyVersion": plan.helper_policy_version,
            "manifestSchemaVersion": plan.manifest_schema_version,
            "manifestDigest": digest(&plan.manifest_digest),
            "helperHash": digest(&plan.helper_hash),
            "sidecars": sidecars,
            "structuralAllowlistHash": digest(&plan.structural_allowlist_hash),
            "stagedInputs": inputs,
            "expectedSemanticOutputHash": digest(&plan.expected_semantic_output_hash),
            "scannerResultHash": digest(&plan.scanner_result_hash),
            "mutations": mutations,
            "ownershipChanges": ownership,
        }
    ]))
}

fn canonicalize_setup_sets(setup: &mut Value) -> Result<(), ApprovalError> {
    let setup = setup
        .as_object_mut()
        .ok_or_else(|| ApprovalError::Serialization("SetupPlan is not an object".into()))?;

    canonicalize_array_field(setup, "targetScopes", "setup target scope")?;
    canonicalize_array_field(
        setup,
        "expectedNativeDigests",
        "setup expected native digest",
    )?;
    canonicalize_array_field(setup, "semanticChanges", "setup semantic change")?;

    let artifacts = setup
        .get_mut("packageArtifacts")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| {
            ApprovalError::Serialization("SetupPlan.packageArtifacts is not an array".into())
        })?;
    for artifact in artifacts.iter_mut() {
        let artifact = artifact.as_object_mut().ok_or_else(|| {
            ApprovalError::Serialization("SetupPlan package artifact is not an object".into())
        })?;
        canonicalize_array_field(
            artifact,
            "dependencies",
            "setup package artifact dependency",
        )?;
    }
    canonicalize_set(artifacts, "setup package artifact")?;

    for (field, label) in [
        ("permissionDelta", "setup permission"),
        ("networkDelta", "setup network endpoint"),
    ] {
        let delta = setup
            .get_mut(field)
            .and_then(Value::as_object_mut)
            .ok_or_else(|| {
                ApprovalError::Serialization(format!("SetupPlan.{field} is not an object"))
            })?;
        canonicalize_array_field(delta, "added", label)?;
        canonicalize_array_field(delta, "removed", label)?;
    }

    Ok(())
}

fn canonicalize_array_field(
    object: &mut Map<String, Value>,
    field: &'static str,
    label: &'static str,
) -> Result<(), ApprovalError> {
    let values = object
        .get_mut(field)
        .and_then(Value::as_array_mut)
        .ok_or_else(|| ApprovalError::Serialization(format!("{field} is not an array")))?;
    canonicalize_set(values, label)
}

fn canonicalize_set(values: &mut Vec<Value>, label: &'static str) -> Result<(), ApprovalError> {
    let mut keyed = values
        .drain(..)
        .map(|value| Ok((canonical_value_key(&value)?, value)))
        .collect::<Result<Vec<_>, ApprovalError>>()?;
    keyed.sort_by(|(left, _), (right, _)| left.cmp(right));
    if keyed.windows(2).any(|members| members[0].0 == members[1].0) {
        return Err(ApprovalError::Duplicate(label.into()));
    }
    values.extend(keyed.into_iter().map(|(_, value)| value));
    Ok(())
}

fn canonical_value_key(value: &Value) -> Result<Vec<u8>, ApprovalError> {
    let mut encoder = Encoder::new(Vec::new());
    encode_value(&mut encoder, value)?;
    Ok(encoder.into_writer())
}

enum TargetKey {
    Windows(String),
    Macos(Vec<u8>),
}

fn unique_targets<'a>(
    targets: impl IntoIterator<Item = &'a WireNativeValue>,
) -> Result<(), ApprovalError> {
    let mut seen = Vec::new();
    for target in targets {
        let key = target_key(target)?;
        for existing in &seen {
            let collides = match (existing, &key) {
                (TargetKey::Windows(left), TargetKey::Windows(right)) => {
                    context_relay_native_runner::windows_ordinal_ignore_case_eq(left, right)
                        .map_err(|error| ApprovalError::Invalid(error.to_string()))?
                }
                (TargetKey::Macos(left), TargetKey::Macos(right)) => left == right,
                _ => false,
            };
            if collides {
                return Err(ApprovalError::Duplicate("mutation target".into()));
            }
        }
        seen.push(key);
    }
    Ok(())
}

fn target_key(target: &WireNativeValue) -> Result<TargetKey, ApprovalError> {
    target
        .validate()
        .map_err(|error| ApprovalError::Invalid(error.to_string()))?;
    match target.platform {
        NativePlatform::Windows => windows_target_key(&target.bytes).map(TargetKey::Windows),
        NativePlatform::Macos => macos_target_key(&target.bytes).map(TargetKey::Macos),
    }
}

fn windows_target_key(bytes: &[u8]) -> Result<String, ApprovalError> {
    let units = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    if units.len() < 4
        || units.len() > 259
        || !(u16::from(b'A')..=u16::from(b'Z')).contains(&units[0])
        || units[1] != u16::from(b':')
        || units[2] != u16::from(b'\\')
        || units.contains(&0)
        || units.contains(&u16::from(b'/'))
    {
        return Err(invalid_target());
    }

    let mut key = String::new();
    key.push(char::from(
        u8::try_from(units[0]).map_err(|_| invalid_target())?,
    ));
    key.push_str(":\\");
    let components = units[3..].split(|unit| *unit == u16::from(b'\\'));
    for (index, component) in components.enumerate() {
        let text = validate_windows_component(component)?;
        if index > 0 {
            key.push('\\');
        }
        key.push_str(&text);
    }
    Ok(key)
}

fn validate_windows_component(units: &[u16]) -> Result<String, ApprovalError> {
    let text = String::from_utf16(units).map_err(|_| invalid_target())?;
    if units.is_empty()
        || units.len() > 255
        || units.iter().any(|unit| {
            *unit <= 0x1f
                || *unit == 0x7f
                || matches!(
                    *unit,
                    value if value == u16::from(b'<')
                        || value == u16::from(b'>')
                        || value == u16::from(b':')
                        || value == u16::from(b'"')
                        || value == u16::from(b'/')
                        || value == u16::from(b'\\')
                        || value == u16::from(b'|')
                        || value == u16::from(b'?')
                        || value == u16::from(b'*')
                )
        })
        || matches!(units.last(), Some(unit) if *unit == u16::from(b'.') || *unit == u16::from(b' '))
        || text == "."
        || text == ".."
        || text.nfc().ne(text.chars())
        || reserved_windows_name(&text)
        || internal_backup_name(&text)
        || internal_staging_name(&text)
    {
        return Err(invalid_target());
    }
    Ok(text)
}

fn internal_backup_name(name: &str) -> bool {
    const PREFIX: &str = ".context-relay-";
    const SUFFIX: &str = ".backup";
    name.len() == PREFIX.len() + 64 + SUFFIX.len()
        && name
            .get(..PREFIX.len())
            .is_some_and(|value| value.eq_ignore_ascii_case(PREFIX))
        && name
            .get(name.len() - SUFFIX.len()..)
            .is_some_and(|value| value.eq_ignore_ascii_case(SUFFIX))
        && name
            .get(PREFIX.len()..name.len() - SUFFIX.len())
            .is_some_and(|value| value.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn internal_staging_name(name: &str) -> bool {
    const PREFIX: &str = ".context-relay-";
    const SUFFIX: &str = ".tmp";
    const TARGET_HASH_LEN: usize = 64;
    const NONCE_LEN: usize = 32;
    let expected_len = PREFIX.len() + TARGET_HASH_LEN + 1 + NONCE_LEN + SUFFIX.len();
    if name.len() != expected_len
        || !name
            .get(..PREFIX.len())
            .is_some_and(|value| value.eq_ignore_ascii_case(PREFIX))
        || !name
            .get(name.len() - SUFFIX.len()..)
            .is_some_and(|value| value.eq_ignore_ascii_case(SUFFIX))
    {
        return false;
    }
    let Some(body) = name.get(PREFIX.len()..name.len() - SUFFIX.len()) else {
        return false;
    };
    let Some((target_hash, nonce)) = body.split_once('-') else {
        return false;
    };
    target_hash.len() == TARGET_HASH_LEN
        && nonce.len() == NONCE_LEN
        && target_hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        && nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn reserved_windows_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or_default().to_uppercase();
    if matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$"
    ) {
        return true;
    }
    for prefix in ["COM", "LPT"] {
        if let Some(suffix) = stem.strip_prefix(prefix) {
            return matches!(
                suffix,
                "1" | "2"
                    | "3"
                    | "4"
                    | "5"
                    | "6"
                    | "7"
                    | "8"
                    | "9"
                    | "\u{00b9}"
                    | "\u{00b2}"
                    | "\u{00b3}"
            );
        }
    }
    false
}

fn macos_target_key(bytes: &[u8]) -> Result<Vec<u8>, ApprovalError> {
    let path = std::str::from_utf8(bytes).map_err(|_| invalid_target())?;
    if !path.starts_with('/') || path.len() == 1 || path.contains('\0') {
        return Err(invalid_target());
    }

    let mut key = String::new();
    for component in path[1..].split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(invalid_target());
        }
        let folded = component.nfd().case_fold().nfd().collect::<String>();
        if internal_backup_name(&folded) || internal_staging_name(&folded) {
            return Err(invalid_target());
        }
        key.push('/');
        key.push_str(&folded);
    }
    Ok(key.into_bytes())
}

fn invalid_target() -> ApprovalError {
    ApprovalError::Invalid("mutation target is not a canonical absolute path".into())
}

fn digest(value: &Sha256Digest) -> String {
    hex(&value.0)
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn encode_value(encoder: &mut Encoder<Vec<u8>>, value: &Value) -> Result<(), ApprovalError> {
    match value {
        Value::Null => {
            encoder
                .null()
                .map_err(|error| ApprovalError::Serialization(error.to_string()))?;
        }
        Value::Bool(value) => {
            encoder
                .bool(*value)
                .map_err(|error| ApprovalError::Serialization(error.to_string()))?;
        }
        Value::Number(value) => {
            if let Some(value) = value.as_u64() {
                encoder
                    .u64(value)
                    .map_err(|error| ApprovalError::Serialization(error.to_string()))?;
            } else if let Some(value) = value.as_i64() {
                encoder
                    .i64(value)
                    .map_err(|error| ApprovalError::Serialization(error.to_string()))?;
            } else {
                return Err(ApprovalError::Serialization(
                    "floating-point approval values are forbidden".into(),
                ));
            }
        }
        Value::String(value) => {
            encoder
                .str(value)
                .map_err(|error| ApprovalError::Serialization(error.to_string()))?;
        }
        Value::Array(values) => {
            encoder
                .array(values.len() as u64)
                .map_err(|error| ApprovalError::Serialization(error.to_string()))?;
            for value in values {
                encode_value(encoder, value)?;
            }
        }
        Value::Object(values) => encode_map(encoder, values)?,
    }
    Ok(())
}

fn encode_map(
    encoder: &mut Encoder<Vec<u8>>,
    values: &Map<String, Value>,
) -> Result<(), ApprovalError> {
    let mut entries: Vec<_> = values.iter().collect();
    entries.sort_by(|(left, _), (right, _)| canonical_text_order(left, right));
    encoder
        .map(entries.len() as u64)
        .map_err(|error| ApprovalError::Serialization(error.to_string()))?;
    for (key, value) in entries {
        encoder
            .str(key)
            .map_err(|error| ApprovalError::Serialization(error.to_string()))?;
        encode_value(encoder, value)?;
    }
    Ok(())
}

fn canonical_text_order(left: &str, right: &str) -> Ordering {
    left.len()
        .cmp(&right.len())
        .then_with(|| left.as_bytes().cmp(right.as_bytes()))
}
