use context_relay_protocol::{ExportEnvelopeV1, PackageManifestV1};

#[test]
fn package_and_export_fixtures_cross_serde_and_semantic_validation() {
    let package: PackageManifestV1 =
        serde_json::from_str(include_str!("fixtures/package-v1-valid.json")).unwrap();
    package.validate().unwrap();
    assert!(
        serde_json::from_str::<PackageManifestV1>(include_str!("fixtures/package-v1-invalid.json"))
            .is_err()
    );

    let export: ExportEnvelopeV1 =
        serde_json::from_str(include_str!("fixtures/export-v1-valid.json")).unwrap();
    export.validate().unwrap();
    assert!(
        serde_json::from_str::<ExportEnvelopeV1>(include_str!("fixtures/export-v1-invalid.json"))
            .is_err()
    );
}

#[test]
fn export_validation_rejects_duplicate_operation_order() {
    let mut export: ExportEnvelopeV1 =
        serde_json::from_str(include_str!("fixtures/export-v1-valid.json")).unwrap();
    export.operation_order.push(export.operation_order[0]);
    assert!(export.validate().is_err());
}
