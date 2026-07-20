use std::str::FromStr;

use context_relay_core::native_transaction::{
    approval::{APPROVAL_DOMAIN_V1, approval_hash_v1},
    model::{
        ApprovedInput, ApprovedMutation, MutationKind, NativeTransactionPlan,
        RestorableStateFingerprint, SidecarBinding,
    },
};
use context_relay_native_runner::{
    NativeState, RuleSyncFeature, RuleSyncFeatures, RuleSyncTarget, RuntimeTarget, SidecarCommand,
    SidecarId, StagePath,
};
use context_relay_protocol::{
    ApprovalClass, ChangeClass, ClassifiedChange, CliOperation, ExpectedNativeDigest, HarnessId,
    ImmutableDependency, NativePlatform, NativeScope, NetworkDelta, NetworkEndpoint, NetworkScheme,
    PackageArtifact, PackageId, PermissionDelta, PlanId, ProjectId, SetupPlan, Sha256Digest,
    WireNativeValue,
};

const PLAN_ID: &str = "01890f3e-1c2b-7a4d-8e5f-123456789abc";
type PlanMutation = Box<dyn Fn(&mut NativeTransactionPlan)>;

fn native_value(bytes: &[u8]) -> WireNativeValue {
    WireNativeValue {
        platform: NativePlatform::Windows,
        bytes: bytes.to_vec(),
        display: None,
    }
}

fn native_text(value: &str) -> WireNativeValue {
    native_value(
        &value
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>(),
    )
}

fn macos_native_text(value: &str) -> WireNativeValue {
    WireNativeValue {
        platform: NativePlatform::Macos,
        bytes: value.as_bytes().to_vec(),
        display: None,
    }
}

fn setup_plan() -> SetupPlan {
    SetupPlan {
        plan_id: PlanId::from_str(PLAN_ID).unwrap(),
        harness: HarnessId::Codex,
        adapter_version: 7,
        executable_path: native_value(br"C:\Program Files\Codex\codex.exe"),
        executable_hash: Sha256Digest([1; 32]),
        harness_version: "1.2.3".into(),
        target_scopes: vec![NativeScope::Global],
        expected_native_digests: vec![],
        semantic_changes: vec![],
        cli_operations: vec![],
        package_artifacts: vec![],
        permission_delta: PermissionDelta {
            added: vec![],
            removed: vec![],
        },
        network_delta: NetworkDelta {
            added: vec![],
            removed: vec![],
        },
        scanner_report_hash: Sha256Digest([2; 32]),
        rulesync_version: "14.0.1".into(),
        rulesync_hash: Sha256Digest([3; 32]),
        approval_class: ApprovalClass::Passive,
        expires_at: 1_900_000_000_000,
        batch_hash: Sha256Digest([4; 32]),
    }
}

fn approved_state(state: NativeState) -> (Vec<u8>, RestorableStateFingerprint) {
    let fingerprint = RestorableStateFingerprint(Sha256Digest(state.fingerprint()));
    (state.encode_v1().unwrap(), fingerprint)
}

fn plan() -> NativeTransactionPlan {
    let payload = approved_state(NativeState::absent(0x0e, 2));
    let activation = approved_state(NativeState::absent(0x10, 2));
    NativeTransactionPlan {
        setup: setup_plan(),
        helper_policy_version: 1,
        manifest_schema_version: 1,
        manifest_digest: Sha256Digest([54; 32]),
        helper_hash: Sha256Digest([5; 32]),
        sidecars: vec![SidecarBinding {
            id: SidecarId::RuleSync,
            target: RuntimeTarget::WindowsX86_64,
            version: "14.0.1".into(),
            closure_hash: Sha256Digest([6; 32]),
            source_bundle_hash: Sha256Digest([7; 32]),
            build_toolchain_hash: Sha256Digest([8; 32]),
            command_template_digest: Sha256Digest([55; 32]),
            command: SidecarCommand::RuleSyncGenerate {
                target: RuleSyncTarget::CodexCli,
                features: RuleSyncFeatures::new(&[RuleSyncFeature::Rules]).unwrap(),
            },
        }],
        structural_allowlist_hash: Sha256Digest([9; 32]),
        staged_inputs: vec![
            ApprovedInput {
                path: StagePath::try_from("input/z.md").unwrap(),
                length: 1,
                digest: Sha256Digest([10; 32]),
            },
            ApprovedInput {
                path: StagePath::try_from("input/a.md").unwrap(),
                length: 2,
                digest: Sha256Digest([11; 32]),
            },
        ],
        expected_semantic_output_hash: Sha256Digest([12; 32]),
        scanner_result_hash: Sha256Digest([13; 32]),
        mutations: vec![
            ApprovedMutation {
                target: native_text(r"C:\Users\test\.codex\AGENTS.md"),
                kind: MutationKind::Payload,
                content: payload.0,
                expected: RestorableStateFingerprint(Sha256Digest([14; 32])),
                intended: payload.1,
            },
            ApprovedMutation {
                target: native_text(r"C:\Users\test\.codex\config.toml"),
                kind: MutationKind::ActivationReference,
                content: activation.0,
                expected: RestorableStateFingerprint(Sha256Digest([16; 32])),
                intended: activation.1,
            },
        ],
        ownership_changes: vec![],
    }
}

fn package_artifact(id: &str, byte: u8) -> PackageArtifact {
    PackageArtifact {
        package_id: PackageId::from_str(id).unwrap(),
        immutable_source_ref: format!("https://example.invalid/{byte}.git"),
        resolved_commit: format!("{byte:02x}").repeat(20),
        archive_digest: Sha256Digest([byte; 32]),
        artifact_path: native_text(&format!("artifact/{byte}")),
        artifact_digest: Sha256Digest([byte + 1; 32]),
        dependencies: vec![
            ImmutableDependency {
                name: format!("dependency-z-{byte}"),
                version: "1.0.0".into(),
                digest: Sha256Digest([byte + 2; 32]),
                immutable_source_ref: format!("registry:z-{byte}"),
            },
            ImmutableDependency {
                name: format!("dependency-a-{byte}"),
                version: "1.0.0".into(),
                digest: Sha256Digest([byte + 3; 32]),
                immutable_source_ref: format!("registry:a-{byte}"),
            },
        ],
    }
}

fn plan_with_setup_sets() -> NativeTransactionPlan {
    let mut value = plan();
    value.setup.target_scopes = vec![
        NativeScope::Project {
            project_id: ProjectId::from_str("01890f3e-1c2b-7a4d-8e5f-123456789abd").unwrap(),
            root: native_text("project"),
        },
        NativeScope::Global,
    ];
    value.setup.expected_native_digests = vec![
        ExpectedNativeDigest {
            target: native_text("z-target"),
            expected_digest: Some(Sha256Digest([60; 32])),
        },
        ExpectedNativeDigest {
            target: native_text("a-target"),
            expected_digest: None,
        },
    ];
    value.setup.semantic_changes = vec![
        ClassifiedChange {
            class: ChangeClass::Update,
            target: "z-target".into(),
            summary: "z-summary".into(),
        },
        ClassifiedChange {
            class: ChangeClass::Create,
            target: "a-target".into(),
            summary: "a-summary".into(),
        },
    ];
    value.setup.cli_operations = vec![
        CliOperation {
            executable: native_text("z-tool"),
            arguments: vec![native_text("z-arg")],
            timeout_ms: 2,
        },
        CliOperation {
            executable: native_text("a-tool"),
            arguments: vec![native_text("a-arg")],
            timeout_ms: 1,
        },
    ];
    value.setup.package_artifacts = vec![
        package_artifact("01890f3e-1c2b-7a4d-8e5f-123456789abe", 70),
        package_artifact("01890f3e-1c2b-7a4d-8e5f-123456789abf", 80),
    ];
    value.setup.permission_delta = PermissionDelta {
        added: vec!["z-added".into(), "a-added".into()],
        removed: vec!["z-removed".into(), "a-removed".into()],
    };
    value.setup.network_delta = NetworkDelta {
        added: vec![
            NetworkEndpoint {
                scheme: NetworkScheme::Wss,
                host: "z.example.invalid".into(),
                port: 443,
            },
            NetworkEndpoint {
                scheme: NetworkScheme::Https,
                host: "a.example.invalid".into(),
                port: 443,
            },
        ],
        removed: vec![
            NetworkEndpoint {
                scheme: NetworkScheme::Wss,
                host: "y.example.invalid".into(),
                port: 443,
            },
            NetworkEndpoint {
                scheme: NetworkScheme::Https,
                host: "b.example.invalid".into(),
                port: 443,
            },
        ],
    };
    value
}

#[test]
fn freezes_the_domain_separator_and_golden_hash() {
    assert_eq!(APPROVAL_DOMAIN_V1, b"context-relay/native-plan/v1\0");
    assert_eq!(
        approval_hash_v1(&plan()).unwrap(),
        Sha256Digest([
            255, 230, 229, 47, 129, 201, 245, 241, 53, 168, 68, 198, 251, 90, 131, 110, 85, 210,
            157, 232, 235, 166, 234, 51, 161, 212, 189, 137, 72, 188, 15, 227,
        ])
    );
}

#[test]
fn mutation_content_is_the_canonical_complete_intended_native_state() {
    let mut valid = plan();
    for (index, marker) in [0x0e_u32, 0x10].into_iter().enumerate() {
        let state = NativeState::absent(marker, 2);
        valid.mutations[index].content = state.encode_v1().unwrap();
        valid.mutations[index].intended =
            RestorableStateFingerprint(Sha256Digest(state.fingerprint()));
    }
    assert!(approval_hash_v1(&valid).is_ok());

    let mut raw_bytes = valid.clone();
    raw_bytes.mutations[0].content = b"payload".to_vec();
    assert!(approval_hash_v1(&raw_bytes).is_err());

    let mut noncanonical = valid.clone();
    noncanonical.mutations[0].content = vec![0x84, 0x01, 0x00, 0x18, 0x0e, 0x02];
    assert_eq!(
        NativeState::decode_v1(&noncanonical.mutations[0].content).unwrap(),
        NativeState::absent(0x0e, 2)
    );
    assert!(approval_hash_v1(&noncanonical).is_err());

    let mut mismatched = valid;
    mismatched.mutations[0].intended = RestorableStateFingerprint(Sha256Digest([0xff; 32]));
    assert!(approval_hash_v1(&mismatched).is_err());
}

#[test]
fn batch_hash_is_output_but_every_other_setup_field_is_bound() {
    let baseline = approval_hash_v1(&plan()).unwrap();

    let mut changed = plan();
    changed.setup.batch_hash = Sha256Digest([99; 32]);
    assert_eq!(approval_hash_v1(&changed).unwrap(), baseline);

    let mutations: Vec<PlanMutation> = vec![
        Box::new(|p| p.setup.adapter_version += 1),
        Box::new(|p| p.setup.executable_hash = Sha256Digest([41; 32])),
        Box::new(|p| p.setup.harness_version.push('x')),
        Box::new(|p| p.setup.expires_at += 1),
        Box::new(|p| p.setup.scanner_report_hash = Sha256Digest([42; 32])),
        Box::new(|p| p.setup.rulesync_hash = Sha256Digest([43; 32])),
        Box::new(|p| p.helper_policy_version += 1),
        Box::new(|p| p.manifest_schema_version += 1),
        Box::new(|p| p.manifest_digest = Sha256Digest([56; 32])),
        Box::new(|p| p.helper_hash = Sha256Digest([44; 32])),
        Box::new(|p| p.sidecars[0].closure_hash = Sha256Digest([45; 32])),
        Box::new(|p| p.sidecars[0].source_bundle_hash = Sha256Digest([46; 32])),
        Box::new(|p| p.sidecars[0].build_toolchain_hash = Sha256Digest([47; 32])),
        Box::new(|p| p.sidecars[0].command_template_digest = Sha256Digest([57; 32])),
        Box::new(|p| {
            p.sidecars[0].command = SidecarCommand::RuleSyncGenerate {
                target: RuleSyncTarget::ClaudeCode,
                features: RuleSyncFeatures::new(&[RuleSyncFeature::Rules]).unwrap(),
            };
        }),
        Box::new(|p| p.structural_allowlist_hash = Sha256Digest([48; 32])),
        Box::new(|p| p.staged_inputs[0].digest = Sha256Digest([49; 32])),
        Box::new(|p| p.expected_semantic_output_hash = Sha256Digest([50; 32])),
        Box::new(|p| p.scanner_result_hash = Sha256Digest([51; 32])),
        Box::new(|p| {
            let changed = approved_state(NativeState::absent(0x0f, 2));
            p.mutations[0].content = changed.0;
            p.mutations[0].intended = changed.1;
        }),
        Box::new(|p| p.mutations[0].expected.0 = Sha256Digest([52; 32])),
    ];

    for mutate in mutations {
        let mut candidate = plan();
        mutate(&mut candidate);
        assert_ne!(approval_hash_v1(&candidate).unwrap(), baseline);
    }
}

#[test]
fn closed_sidecar_and_stage_path_types_fail_closed() {
    assert!(StagePath::try_from("../live-home/secret").is_err());

    let mut mismatched = plan();
    mismatched.sidecars[0].id = SidecarId::Gitleaks;
    assert!(approval_hash_v1(&mismatched).is_err());
}

#[test]
fn canonical_sets_are_order_independent_but_mutation_order_is_bound() {
    let baseline = approval_hash_v1(&plan()).unwrap();

    let mut reordered_set = plan();
    reordered_set.staged_inputs.reverse();
    assert_eq!(approval_hash_v1(&reordered_set).unwrap(), baseline);

    let mut reordered_operations = plan();
    reordered_operations.mutations.reverse();
    assert!(approval_hash_v1(&reordered_operations).is_err());
}

#[test]
fn every_setup_set_is_canonical_but_cli_operation_order_is_bound() {
    let populated = plan_with_setup_sets();
    let baseline = approval_hash_v1(&populated).unwrap();

    let reorder_sets: Vec<PlanMutation> = vec![
        Box::new(|p| p.setup.target_scopes.reverse()),
        Box::new(|p| p.setup.expected_native_digests.reverse()),
        Box::new(|p| p.setup.semantic_changes.reverse()),
        Box::new(|p| p.setup.package_artifacts.reverse()),
        Box::new(|p| p.setup.package_artifacts[0].dependencies.reverse()),
        Box::new(|p| p.setup.permission_delta.added.reverse()),
        Box::new(|p| p.setup.permission_delta.removed.reverse()),
        Box::new(|p| p.setup.network_delta.added.reverse()),
        Box::new(|p| p.setup.network_delta.removed.reverse()),
    ];
    for reorder in reorder_sets {
        let mut candidate = populated.clone();
        reorder(&mut candidate);
        assert_eq!(approval_hash_v1(&candidate).unwrap(), baseline);
    }

    let mut reordered_operations = populated;
    reordered_operations.setup.cli_operations.reverse();
    assert_ne!(approval_hash_v1(&reordered_operations).unwrap(), baseline);
}

#[test]
fn duplicate_setup_set_members_fail_closed() {
    let populated = plan_with_setup_sets();
    let duplicate_sets: Vec<PlanMutation> = vec![
        Box::new(|p| p.setup.target_scopes.push(p.setup.target_scopes[0].clone())),
        Box::new(|p| {
            p.setup
                .expected_native_digests
                .push(p.setup.expected_native_digests[0].clone());
        }),
        Box::new(|p| {
            p.setup
                .semantic_changes
                .push(p.setup.semantic_changes[0].clone());
        }),
        Box::new(|p| {
            p.setup
                .package_artifacts
                .push(p.setup.package_artifacts[0].clone());
        }),
        Box::new(|p| {
            let duplicate = p.setup.package_artifacts[0].dependencies[0].clone();
            p.setup.package_artifacts[0].dependencies.push(duplicate);
        }),
        Box::new(|p| {
            p.setup
                .permission_delta
                .added
                .push(p.setup.permission_delta.added[0].clone());
        }),
        Box::new(|p| {
            p.setup
                .network_delta
                .removed
                .push(p.setup.network_delta.removed[0].clone());
        }),
    ];
    for duplicate in duplicate_sets {
        let mut candidate = populated.clone();
        duplicate(&mut candidate);
        assert!(approval_hash_v1(&candidate).is_err());
    }
}

#[test]
fn duplicate_set_members_and_targets_fail_closed() {
    let mut duplicate_input = plan();
    duplicate_input
        .staged_inputs
        .push(duplicate_input.staged_inputs[0].clone());
    assert!(approval_hash_v1(&duplicate_input).is_err());

    let mut duplicate_target = plan();
    duplicate_target
        .mutations
        .push(duplicate_target.mutations[0].clone());
    assert!(approval_hash_v1(&duplicate_target).is_err());
}

#[test]
fn windows_mutation_targets_reject_noncanonical_case_separator_and_dot_aliases() {
    let mut candidate = plan();
    candidate.mutations[0].target = native_text(r"C:\x\Rules.md");
    let mut alias = candidate.mutations[0].clone();
    alias.target = native_text("c:/x/./rules.md");
    candidate.mutations.insert(1, alias);

    assert!(approval_hash_v1(&candidate).is_err());
}

#[test]
fn windows_mutation_targets_reject_the_internal_recovery_backup_namespace() {
    for name in [
        format!(".context-relay-{}.backup", "a".repeat(64)),
        format!(".CONTEXT-RELAY-{}.BACKUP", "A5".repeat(32)),
    ] {
        let mut candidate = plan();
        candidate.mutations[0].target = native_text(&format!(r"C:\x\{name}"));
        assert!(approval_hash_v1(&candidate).is_err(), "{name}");
    }
}

#[test]
fn windows_mutation_targets_reject_the_transaction_staging_namespace() {
    for name in [
        format!(".context-relay-{}-{}.tmp", "a".repeat(64), "b".repeat(32)),
        format!(".CONTEXT-RELAY-{}-{}.TMP", "A5".repeat(32), "B6".repeat(16)),
    ] {
        let mut candidate = plan();
        candidate.mutations[0].target = native_text(&format!(r"C:\x\{name}"));
        assert!(approval_hash_v1(&candidate).is_err(), "{name}");
    }
}

#[test]
fn windows_transaction_staging_namespace_match_is_exact() {
    for name in [
        format!(".context-relay-{}-{}.tmp", "a".repeat(63), "b".repeat(32)),
        format!(".context-relay-{}-{}.tmp", "a".repeat(64), "b".repeat(31)),
        format!(".context-relay-{}{}.tmp", "a".repeat(64), "b".repeat(32)),
        format!(".context-relay-{}-{}.tmpx", "a".repeat(64), "b".repeat(32)),
    ] {
        let mut candidate = plan();
        candidate.mutations[0].target = native_text(&format!(r"C:\x\{name}"));
        candidate.setup.batch_hash = approval_hash_v1(&candidate).unwrap();
        assert!(approval_hash_v1(&candidate).is_ok(), "{name}");
    }
}

#[test]
fn windows_mutation_targets_reject_canonical_case_aliases() {
    let mut candidate = plan();
    candidate.mutations[0].target = native_text(r"C:\x\Rules.md");
    let mut alias = candidate.mutations[0].clone();
    alias.target = native_text(r"C:\x\rules.md");
    candidate.mutations.insert(1, alias);

    assert!(approval_hash_v1(&candidate).is_err());
}

#[test]
fn windows_mutation_targets_use_uppercase_ordinal_aliases() {
    let mut candidate = plan();
    candidate.mutations[0].target = native_text("C:\\x\\Σ.md");
    let mut alias = candidate.mutations[0].clone();
    alias.target = native_text("C:\\x\\σ.md");
    candidate.mutations.insert(1, alias);

    assert!(approval_hash_v1(&candidate).is_err());
}

#[test]
fn macos_mutation_targets_reject_case_and_normalization_aliases() {
    for (first, second) in [
        ("/Users/test/Rules.md", "/users/test/rules.md"),
        ("/Users/test/\u{00e9}.md", "/Users/test/e\u{0301}.md"),
        ("/Users/test/stra\u{00df}e.md", "/Users/test/STRASSE.md"),
    ] {
        let mut candidate = plan();
        candidate.mutations[0].target = macos_native_text(first);
        let mut alias = candidate.mutations[0].clone();
        alias.target = macos_native_text(second);
        candidate.mutations.insert(1, alias);

        assert!(approval_hash_v1(&candidate).is_err(), "{first} vs {second}");
    }
}

#[test]
fn macos_mutation_targets_reject_internal_transaction_names_and_aliases() {
    for name in [
        format!(".context-relay-{}.backup", "a".repeat(64)),
        format!(".CONTEXT-RELAY-{}.BACKUP", "A5".repeat(32)),
        format!(".context-relay-{}-{}.tmp", "a".repeat(64), "b".repeat(32)),
        format!(".CONTEXT-RELAY-{}-{}.TMP", "A5".repeat(32), "B6".repeat(16)),
    ] {
        let mut candidate = plan();
        candidate.mutations[0].target = macos_native_text(&format!("/Users/test/{name}"));
        assert!(approval_hash_v1(&candidate).is_err(), "{name}");
    }
}

#[test]
fn macos_mutation_targets_require_utf8_for_collision_safe_approval() {
    let mut candidate = plan();
    candidate.mutations[0].target = WireNativeValue {
        platform: NativePlatform::Macos,
        bytes: b"/Users/test/\xff".to_vec(),
        display: None,
    };

    assert!(approval_hash_v1(&candidate).is_err());
}

#[cfg(windows)]
#[test]
fn windows_mutation_targets_do_not_apply_full_unicode_case_expansion() {
    let mut distinct_sharp_s = plan();
    distinct_sharp_s.mutations[0].target = native_text("C:\\x\\ß.md");
    let mut capital_sharp_s = distinct_sharp_s.mutations[0].clone();
    capital_sharp_s.target = native_text("C:\\x\\ẞ.md");
    distinct_sharp_s.mutations.insert(1, capital_sharp_s);
    assert!(approval_hash_v1(&distinct_sharp_s).is_ok());

    let mut distinct = plan();
    distinct.mutations[0].target = native_text("C:\\x\\ß.md");
    let mut double_s = distinct.mutations[0].clone();
    double_s.target = native_text("C:\\x\\ss.md");
    distinct.mutations.insert(1, double_s);
    assert!(approval_hash_v1(&distinct).is_ok());
}
