use std::str::FromStr;

use context_relay_protocol::{
    ApprovalClass, ExportEnvelopeV1, ImmutableDependency, MAX_BATCH_OPERATIONS, PackageComponent,
    PackageManifestV1, RecordId, ScopeRef, Sha256Digest, ValidationError,
};

fn manifest() -> PackageManifestV1 {
    serde_json::from_str(include_str!("fixtures/package-v1-valid.json")).unwrap()
}

fn dependency() -> ImmutableDependency {
    ImmutableDependency {
        name: "dependency".into(),
        version: "1.0.0".into(),
        digest: Sha256Digest([1; 32]),
        immutable_source_ref: "registry:dependency@1.0.0".into(),
    }
}

#[test]
fn component_dependency_and_permission_limits_reject_max_plus_one() {
    let id = RecordId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c07398f").unwrap();
    let mut package = manifest();
    package.components = vec![PackageComponent::Plugin {
        id,
        scope: ScopeRef::Global,
        name: "plugin".into(),
        dependencies: vec![dependency(); MAX_BATCH_OPERATIONS + 1],
    }];
    assert_eq!(
        package.validate(),
        Err(ValidationError::TooLarge {
            field: "component.dependencies",
            limit: MAX_BATCH_OPERATIONS
        })
    );

    package.components = vec![PackageComponent::PermissionDeclaration {
        id,
        scope: ScopeRef::Global,
        permissions: vec!["same".into(); MAX_BATCH_OPERATIONS + 1],
        approval_class: ApprovalClass::Active,
    }];
    assert_eq!(
        package.validate(),
        Err(ValidationError::TooLarge {
            field: "component.permissions",
            limit: MAX_BATCH_OPERATIONS
        })
    );
}

#[test]
fn export_collection_limits_reject_max_plus_one() {
    let mut export: ExportEnvelopeV1 =
        serde_json::from_str(include_str!("fixtures/export-v1-valid.json")).unwrap();
    export.records = vec![export.records[0].clone(); MAX_BATCH_OPERATIONS + 1];
    assert_eq!(
        export.validate(),
        Err(ValidationError::TooLarge {
            field: "records",
            limit: MAX_BATCH_OPERATIONS
        })
    );

    let mut export: ExportEnvelopeV1 =
        serde_json::from_str(include_str!("fixtures/export-v1-valid.json")).unwrap();
    export.operation_order = vec![export.operation_order[0]; MAX_BATCH_OPERATIONS + 1];
    assert_eq!(
        export.validate(),
        Err(ValidationError::TooLarge {
            field: "operationOrder",
            limit: MAX_BATCH_OPERATIONS
        })
    );
}
