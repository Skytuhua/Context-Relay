use context_relay_protocol::{ExportEnvelopeV1, PackageManifestV1};

const EXTENSION_NAMESPACE: &str = "dev.context-relay.fixture";

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

fn valid_package_json() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures/package-v1-valid.json")).unwrap()
}

#[test]
fn namespaced_extensions_are_optional_flat_deterministic_metadata() {
    let package: PackageManifestV1 = serde_json::from_value(valid_package_json()).unwrap();
    package.validate().unwrap();
    assert_eq!(
        serde_json::to_value(&package).unwrap(),
        valid_package_json()
    );

    let mut absent = valid_package_json();
    absent.as_object_mut().unwrap().remove("extensions");
    let package: PackageManifestV1 = serde_json::from_value(absent.clone()).unwrap();
    assert_eq!(serde_json::to_value(package).unwrap(), absent);
}

#[test]
fn namespaced_extensions_reject_opaque_active_or_unbounded_content() {
    let valid = valid_package_json();

    let mut raw_bytes = valid.clone();
    raw_bytes["extensions"][EXTENSION_NAMESPACE] = serde_json::json!({"value": "AQ"});
    assert!(serde_json::from_value::<PackageManifestV1>(raw_bytes).is_err());

    for key in [
        "password",
        "Client_Secret",
        "api-token",
        "session.cookie",
        "Private-Key",
        "credential",
        "executable",
        "binary",
        "Script",
        "shell",
        "run-command",
        "pre_hook",
        "sourceCode",
    ] {
        let mut invalid = valid.clone();
        invalid["extensions"][EXTENSION_NAMESPACE]["data"] =
            serde_json::json!({key: "not allowed"});
        assert!(
            serde_json::from_value::<PackageManifestV1>(invalid).is_err(),
            "{key}"
        );
    }

    for value in [
        "text\0with control",
        "-----BEGIN PRIVATE KEY-----not-a-real-key-----END PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----not-a-real-key-----END RSA PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----not-a-real-key-----END OPENSSH PRIVATE KEY-----",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----not-a-real-key-----END ENCRYPTED PRIVATE KEY-----",
    ] {
        let mut invalid = valid.clone();
        invalid["extensions"][EXTENSION_NAMESPACE]["data"] = serde_json::json!({"note": value});
        assert!(serde_json::from_value::<PackageManifestV1>(invalid).is_err());
    }

    let mut nested = valid.clone();
    nested["extensions"][EXTENSION_NAMESPACE]["data"] =
        serde_json::json!({"nested": {"value": "no"}});
    assert!(serde_json::from_value::<PackageManifestV1>(nested).is_err());

    let mut too_many = valid.clone();
    too_many["extensions"][EXTENSION_NAMESPACE]["data"] = serde_json::Value::Object(
        (0..65)
            .map(|index| (format!("item{index}"), serde_json::json!("value")))
            .collect(),
    );
    assert!(serde_json::from_value::<PackageManifestV1>(too_many).is_err());

    let mut long_key = valid.clone();
    long_key["extensions"][EXTENSION_NAMESPACE]["data"] =
        serde_json::json!({"k".repeat(129): "value"});
    assert!(serde_json::from_value::<PackageManifestV1>(long_key).is_err());

    let mut long_text = valid.clone();
    long_text["extensions"][EXTENSION_NAMESPACE]["data"] =
        serde_json::json!({"note": "v".repeat(16 * 1024 + 1)});
    assert!(serde_json::from_value::<PackageManifestV1>(long_text).is_err());

    let mut unknown = valid.clone();
    unknown["extensions"][EXTENSION_NAMESPACE]["ignored"] = true.into();
    assert!(serde_json::from_value::<PackageManifestV1>(unknown).is_err());

    let mut invalid_namespace = valid.clone();
    let extension = invalid_namespace["extensions"]
        .as_object_mut()
        .unwrap()
        .remove(EXTENSION_NAMESPACE)
        .unwrap();
    invalid_namespace["extensions"]
        .as_object_mut()
        .unwrap()
        .insert("Invalid.Namespace".into(), extension);
    assert!(serde_json::from_value::<PackageManifestV1>(invalid_namespace).is_err());

    let mut duplicate = valid;
    duplicate["extensions"] = serde_json::json!([
        {"namespace": EXTENSION_NAMESPACE, "data": {"first": "value"}},
        {"namespace": EXTENSION_NAMESPACE, "data": {"other": "value"}}
    ]);
    assert!(serde_json::from_value::<PackageManifestV1>(duplicate).is_err());
}
