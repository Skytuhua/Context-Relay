mod support;

use std::str::FromStr;

use context_relay_protocol::{
    ChangeClass, ExpectedNativeDigest, ImmutableDependency, NativePlatform, PackageArtifact,
    PackageId, Sha256Digest, WireNativeValue,
};

fn path(bytes: &[u8]) -> WireNativeValue {
    WireNativeValue {
        platform: NativePlatform::Macos,
        bytes: bytes.to_vec(),
        display: None,
    }
}

fn artifact() -> PackageArtifact {
    PackageArtifact {
        package_id: PackageId::from_str(support::ID).unwrap(),
        immutable_source_ref: "https://example.invalid/repository.git".into(),
        resolved_commit: "01".repeat(20),
        archive_digest: Sha256Digest([2; 32]),
        artifact_path: path(b"skill/SKILL.md"),
        artifact_digest: Sha256Digest([3; 32]),
        dependencies: vec![ImmutableDependency {
            name: "dependency".into(),
            version: "1.0.0".into(),
            digest: Sha256Digest([4; 32]),
            immutable_source_ref: "registry:dependency@sha256:04".into(),
        }],
    }
}

#[test]
fn expected_native_digest_round_trips_present_and_absent_states() {
    for expected_digest in [None, Some(Sha256Digest([1; 32]))] {
        let expected = ExpectedNativeDigest {
            target: path(b"config.json"),
            expected_digest,
        };
        let value = serde_json::to_value(&expected).unwrap();
        assert_eq!(
            serde_json::from_value::<ExpectedNativeDigest>(value).unwrap(),
            expected
        );
    }
}

#[test]
fn every_package_artifact_field_changes_the_plan_representation() {
    let mut plan = support::setup_plan();
    plan.package_artifacts = vec![artifact()];
    let baseline = serde_json::to_value(&plan).unwrap();
    let mut variants = Vec::new();

    let mut value = plan.clone();
    value.package_artifacts[0]
        .immutable_source_ref
        .push_str("?mirror=1");
    variants.push(value);
    let mut value = plan.clone();
    value.package_artifacts[0].resolved_commit = "02".repeat(20);
    variants.push(value);
    let mut value = plan.clone();
    value.package_artifacts[0].archive_digest = Sha256Digest([5; 32]);
    variants.push(value);
    let mut value = plan.clone();
    value.package_artifacts[0].artifact_path = path(b"skill/OTHER.md");
    variants.push(value);
    let mut value = plan.clone();
    value.package_artifacts[0].artifact_digest = Sha256Digest([6; 32]);
    variants.push(value);
    let mut value = plan.clone();
    value.package_artifacts[0].dependencies[0].digest = Sha256Digest([7; 32]);
    variants.push(value);

    for variant in variants {
        assert_ne!(serde_json::to_value(variant).unwrap(), baseline);
    }
}

#[test]
fn change_class_includes_enable_and_disable() {
    assert_eq!(serde_json::to_value(ChangeClass::Enable).unwrap(), "enable");
    assert_eq!(
        serde_json::to_value(ChangeClass::Disable).unwrap(),
        "disable"
    );
}

#[test]
fn native_values_preserve_platform_specific_bytes_and_cli_arguments() {
    let windows = WireNativeValue {
        platform: NativePlatform::Windows,
        bytes: vec![b' ', 0, 0xe9, 0, 0x00, 0xd8],
        display: Some("sanitized display".into()),
    };
    let macos = path(&[b' ', 0xff, 0x80, b'x']);
    for value in [&windows, &macos] {
        let json = serde_json::to_value(value).unwrap();
        assert_eq!(
            serde_json::from_value::<WireNativeValue>(json).unwrap(),
            *value
        );
    }
    let mut plan = support::setup_plan();
    plan.cli_operations
        .push(context_relay_protocol::CliOperation {
            executable: windows.clone(),
            arguments: vec![macos.clone(), windows],
            timeout_ms: 1_000,
        });
    let decoded = serde_json::from_value::<context_relay_protocol::SetupPlan>(
        serde_json::to_value(&plan).unwrap(),
    )
    .unwrap();
    assert_eq!(
        decoded.cli_operations[0].arguments,
        vec![macos, decoded.cli_operations[0].executable.clone()]
    );
}
