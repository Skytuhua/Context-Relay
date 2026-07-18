mod support;

use context_relay_protocol::{
    CapabilityLevel, ComponentKind, ComponentRecord, DesiredState, ImportRequest, ImportedState,
    InstallationMethod, MAX_ADAPTER_COLLECTION_ITEMS, MAX_ADAPTER_TEXT_BYTES, NativePlatform,
    NativeScope, ProbeContext, ProbeReport, ProjectId, Provenance, RecordId, ScopeRef,
    Sha256Digest, ValidationError, WireNativeValue,
};
use std::str::FromStr;

fn native_value() -> WireNativeValue {
    WireNativeValue {
        platform: NativePlatform::Macos,
        bytes: vec![b'/'],
        display: Some("/".into()),
    }
}

fn component() -> ComponentRecord {
    ComponentRecord {
        id: RecordId::from_str(support::ID).unwrap(),
        scope: ScopeRef::Global,
        kind: ComponentKind::Instruction,
        name: "instruction".into(),
        body_markdown: "body".into(),
        metadata: vec![],
        provenance: Provenance {
            origin_device: support::device(),
            harness: None,
            source: None,
            created_hlc: support::hlc(),
        },
        archived: false,
    }
}

fn probe_report() -> ProbeReport {
    ProbeReport {
        executable: Some(native_value()),
        executable_sha256: Some(Sha256Digest([0; 32])),
        harness_version: Some("1.0".into()),
        installation_method: InstallationMethod::Bundled,
        config_roots: vec![native_value()],
        active_profile: Some("default".into()),
        policy_conflicts: vec!["conflict".into()],
        capability: CapabilityLevel::Full,
    }
}

#[test]
fn probe_report_bounds_capability_collections() {
    let mut report = probe_report();
    report.config_roots = vec![native_value(); MAX_ADAPTER_COLLECTION_ITEMS];
    report.policy_conflicts = vec!["conflict".into(); MAX_ADAPTER_COLLECTION_ITEMS];
    report.validate().unwrap();

    report.config_roots.push(native_value());
    assert_eq!(
        report.validate(),
        Err(ValidationError::TooLarge {
            field: "probeReport.configRoots",
            limit: MAX_ADAPTER_COLLECTION_ITEMS,
        })
    );

    report.config_roots.pop();
    report.policy_conflicts.push("conflict".into());
    assert_eq!(
        report.validate(),
        Err(ValidationError::TooLarge {
            field: "probeReport.policyConflicts",
            limit: MAX_ADAPTER_COLLECTION_ITEMS,
        })
    );
}

#[test]
fn probe_report_bounds_text_and_validates_native_values() {
    let mut report = probe_report();
    report.harness_version = Some("v".repeat(MAX_ADAPTER_TEXT_BYTES));
    report.active_profile = Some("p".repeat(MAX_ADAPTER_TEXT_BYTES));
    report.policy_conflicts = vec!["c".repeat(MAX_ADAPTER_TEXT_BYTES)];
    report.validate().unwrap();

    report.policy_conflicts[0].push('c');
    assert_eq!(
        report.validate(),
        Err(ValidationError::TooLarge {
            field: "probeReport.policyConflicts.text",
            limit: MAX_ADAPTER_TEXT_BYTES,
        })
    );

    report.policy_conflicts[0].pop();
    report.config_roots[0].bytes = vec![0; context_relay_protocol::MAX_ARBITRARY_BYTES + 1];
    assert!(report.validate().is_err());
}

#[test]
fn import_request_bounds_and_validates_scopes() {
    let mut request = ImportRequest {
        scopes: vec![NativeScope::Global; MAX_ADAPTER_COLLECTION_ITEMS],
        include_disabled: false,
    };
    request.validate().unwrap();

    request.scopes.push(NativeScope::Global);
    assert_eq!(
        request.validate(),
        Err(ValidationError::TooLarge {
            field: "importRequest.scopes",
            limit: MAX_ADAPTER_COLLECTION_ITEMS,
        })
    );

    request.scopes = vec![NativeScope::Project {
        project_id: ProjectId::from_str(support::ID).unwrap(),
        root: WireNativeValue {
            platform: NativePlatform::Windows,
            bytes: vec![0],
            display: None,
        },
    }];
    assert!(request.validate().is_err());
}

#[test]
fn imported_state_bounds_and_validates_components() {
    let mut state = ImportedState {
        components: vec![component(); MAX_ADAPTER_COLLECTION_ITEMS],
        source_digests: vec![Sha256Digest([0; 32]); MAX_ADAPTER_COLLECTION_ITEMS],
    };
    state.validate().unwrap();

    state.source_digests.push(Sha256Digest([0; 32]));
    assert_eq!(
        state.validate(),
        Err(ValidationError::TooLarge {
            field: "importedState.sourceDigests",
            limit: MAX_ADAPTER_COLLECTION_ITEMS,
        })
    );

    state.source_digests.pop();
    state.components[0].name.clear();
    assert!(state.validate().is_err());
}

#[test]
fn desired_state_bounds_and_validates_nested_values() {
    let mut state = DesiredState {
        components: vec![component(); MAX_ADAPTER_COLLECTION_ITEMS],
        scopes: vec![NativeScope::Global; MAX_ADAPTER_COLLECTION_ITEMS],
    };
    state.validate().unwrap();

    state.components.push(component());
    assert_eq!(
        state.validate(),
        Err(ValidationError::TooLarge {
            field: "desiredState.components",
            limit: MAX_ADAPTER_COLLECTION_ITEMS,
        })
    );

    state.components.pop();
    state.scopes = vec![NativeScope::Project {
        project_id: ProjectId::from_str(support::ID).unwrap(),
        root: WireNativeValue {
            platform: NativePlatform::Windows,
            bytes: vec![0],
            display: None,
        },
    }];
    assert!(state.validate().is_err());
}

#[test]
fn adapter_dtos_reject_oversized_serde_boundaries() {
    let mut report = probe_report();
    report.config_roots = vec![native_value(); MAX_ADAPTER_COLLECTION_ITEMS + 1];
    assert!(serde_json::to_value(&report).is_err());

    let mut request = ImportRequest {
        scopes: vec![NativeScope::Global],
        include_disabled: false,
    };
    request.scopes = vec![NativeScope::Global; MAX_ADAPTER_COLLECTION_ITEMS + 1];
    assert!(serde_json::to_value(&request).is_err());

    let mut imported = ImportedState {
        components: vec![component()],
        source_digests: vec![],
    };
    imported.source_digests = vec![Sha256Digest([0; 32]); MAX_ADAPTER_COLLECTION_ITEMS + 1];
    assert!(serde_json::to_value(&imported).is_err());

    let mut desired = DesiredState {
        components: vec![component()],
        scopes: vec![],
    };
    desired.scopes = vec![NativeScope::Global; MAX_ADAPTER_COLLECTION_ITEMS + 1];
    assert!(serde_json::to_value(&desired).is_err());

    let mut report_json = serde_json::to_value(probe_report()).unwrap();
    report_json["configRoots"] = serde_json::Value::Array(vec![
        serde_json::to_value(native_value())
            .unwrap();
        MAX_ADAPTER_COLLECTION_ITEMS + 1
    ]);
    assert!(serde_json::from_value::<ProbeReport>(report_json).is_err());

    let mut request_json = serde_json::to_value(ImportRequest {
        scopes: vec![],
        include_disabled: false,
    })
    .unwrap();
    request_json["scopes"] = serde_json::Value::Array(vec![
        serde_json::json!({ "scope": "global" });
        MAX_ADAPTER_COLLECTION_ITEMS + 1
    ]);
    assert!(serde_json::from_value::<ImportRequest>(request_json).is_err());

    let digest_json = serde_json::to_value(Sha256Digest([0; 32])).unwrap();
    let mut imported_json = serde_json::to_value(ImportedState {
        components: vec![],
        source_digests: vec![],
    })
    .unwrap();
    imported_json["sourceDigests"] =
        serde_json::Value::Array(vec![digest_json; MAX_ADAPTER_COLLECTION_ITEMS + 1]);
    assert!(serde_json::from_value::<ImportedState>(imported_json).is_err());

    let mut desired_json = serde_json::to_value(DesiredState {
        components: vec![],
        scopes: vec![],
    })
    .unwrap();
    desired_json["scopes"] = serde_json::Value::Array(vec![
        serde_json::json!({ "scope": "global" });
        MAX_ADAPTER_COLLECTION_ITEMS + 1
    ]);
    assert!(serde_json::from_value::<DesiredState>(desired_json).is_err());
}

#[test]
fn probe_context_rejects_oversized_profile_at_serde_boundary() {
    let context = ProbeContext {
        harness: context_relay_protocol::HarnessId::Codex,
        requested_profile: Some("p".repeat(MAX_ADAPTER_TEXT_BYTES + 1)),
    };
    assert!(serde_json::to_value(&context).is_err());

    let json = serde_json::json!({
        "harness": "codex",
        "requestedProfile": "p".repeat(MAX_ADAPTER_TEXT_BYTES + 1),
    });
    assert!(serde_json::from_value::<ProbeContext>(json).is_err());
}
