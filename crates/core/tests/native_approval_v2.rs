use std::str::FromStr;

use context_relay_core::{
    native_memory::{
        NativeMemoryDocumentKind, NativeMemoryLimits, NativeMemoryRegistration, NativeMemorySource,
    },
    native_transaction::{
        APPROVAL_DOMAIN_V2, ApprovedCliMutation, CanonicalCliDeclaration, CliExecutionContext,
        NativeTransactionPlan, SidecarBinding, approval_hash_v2, open_plan, seal_plan,
    },
};
use context_relay_native_runner::{
    RuleSyncFeature, RuleSyncFeatures, RuleSyncTarget, RuntimeTarget, SidecarCommand, SidecarId,
};
use context_relay_protocol::{
    ApprovalClass, CliOperation, HarnessId, NativePlatform, NativeScope, NetworkDelta,
    PermissionDelta, PlanId, ProjectId, ScopeRef, SetupPlan, Sha256Digest, WireNativeValue,
};
use sha2::{Digest as _, Sha256};

const PLAN_ID: &str = "01890f3e-1c2b-7a4d-8e5f-123456789abc";
const CLI_TIMEOUT_MS: u32 = 30_000;

fn native_text(value: &str) -> WireNativeValue {
    WireNativeValue {
        platform: NativePlatform::Macos,
        bytes: value.as_bytes().to_vec(),
        display: None,
    }
}

fn declaration(harness: HarnessId, server_name: &str, command: &str) -> CanonicalCliDeclaration {
    let harness_name = match harness {
        HarnessId::ClaudeCode => "claude-code",
        HarnessId::Codex => "codex",
        HarnessId::Hermes => "hermes",
    };
    let canonical_body = serde_json::to_string(&serde_json::json!({
        "args": ["--harness", harness_name],
        "command": command,
        "type": "stdio",
    }))
    .unwrap();
    CanonicalCliDeclaration {
        harness,
        server_name: server_name.to_owned(),
        fingerprint: Sha256Digest(Sha256::digest(canonical_body.as_bytes()).into()),
        canonical_body,
    }
}

fn operation(executable: &str, arguments: &[&str]) -> CliOperation {
    CliOperation {
        executable: native_text(executable),
        arguments: arguments
            .iter()
            .map(|argument| native_text(argument))
            .collect(),
        timeout_ms: CLI_TIMEOUT_MS,
    }
}

fn mutation() -> ApprovedCliMutation {
    ApprovedCliMutation {
        execution_context: None,
        stable_id: "b5be495e-d4ee-7a2e-a29e-b589ebc5d7fd".to_owned(),
        expected: Some(declaration(
            HarnessId::Codex,
            "context-relay",
            "/opt/context-relay-old",
        )),
        intended: Some(declaration(
            HarnessId::Codex,
            "context-relay",
            "/opt/context-relay",
        )),
        forward: vec![operation(
            "/fixture/codex",
            &[
                "mcp",
                "add",
                "context-relay",
                "--",
                "/opt/context-relay",
                "--harness",
                "codex",
            ],
        )],
        rollback: vec![operation(
            "/fixture/codex",
            &[
                "mcp",
                "add",
                "context-relay",
                "--",
                "/opt/context-relay-old",
                "--harness",
                "codex",
            ],
        )],
    }
}

fn memory_registration() -> NativeMemoryRegistration {
    NativeMemoryRegistration {
        source: NativeMemorySource::new(
            HarnessId::Codex,
            "0.144.1",
            ScopeRef::Global,
            NativeMemoryDocumentKind::Agent,
            WireNativeValue {
                platform: NativePlatform::Macos,
                bytes: b"/fixture/codex/memories/MEMORY.md".to_vec(),
                display: Some("Codex MEMORY.md".to_owned()),
            },
            NativeMemoryLimits {
                max_bytes: 16 * 1024,
                max_characters: 8 * 1024,
            },
            true,
        )
        .unwrap(),
        last_applied_digest: None,
    }
}

fn rebuild_source(source: &mut NativeMemorySource) {
    *source = NativeMemorySource::new(
        source.harness,
        &source.adapter_version,
        source.scope.clone(),
        source.document_kind,
        source.path.clone(),
        source.limits,
        source.managed_fence,
    )
    .unwrap();
}

fn plan() -> NativeTransactionPlan {
    let cli_mutation = mutation();
    NativeTransactionPlan {
        setup: SetupPlan {
            plan_id: PlanId::from_str(PLAN_ID).unwrap(),
            harness: HarnessId::Codex,
            harness_profile: None,
            adapter_version: 7,
            executable_path: native_text("/fixture/codex"),
            executable_hash: Sha256Digest([1; 32]),
            harness_version: "1.2.3".to_owned(),
            target_scopes: vec![NativeScope::Global],
            expected_native_digests: vec![],
            semantic_changes: vec![],
            cli_operations: cli_mutation.forward.clone(),
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
            rulesync_version: "14.0.1".to_owned(),
            rulesync_hash: Sha256Digest([3; 32]),
            approval_class: ApprovalClass::Active,
            expires_at: 1_900_000_000_000,
            batch_hash: Sha256Digest([0; 32]),
        },
        approval_version: 2,
        helper_policy_version: 1,
        manifest_schema_version: 1,
        manifest_digest: Sha256Digest([4; 32]),
        helper_hash: Sha256Digest([5; 32]),
        sidecars: vec![SidecarBinding {
            id: SidecarId::RuleSync,
            target: RuntimeTarget::MacosArm64,
            version: "14.0.1".to_owned(),
            closure_hash: Sha256Digest([6; 32]),
            source_bundle_hash: Sha256Digest([7; 32]),
            build_toolchain_hash: Sha256Digest([8; 32]),
            command_template_digest: Sha256Digest([9; 32]),
            command: SidecarCommand::RuleSyncGenerate {
                target: RuleSyncTarget::CodexCli,
                features: RuleSyncFeatures::new(&[RuleSyncFeature::Rules]).unwrap(),
            },
        }],
        structural_allowlist_hash: Sha256Digest([10; 32]),
        staged_inputs: vec![],
        expected_semantic_output_hash: Sha256Digest([11; 32]),
        scanner_result_hash: Sha256Digest([12; 32]),
        mutations: vec![],
        cli_mutations: vec![cli_mutation],
        native_memory_registrations: vec![memory_registration()],
        ownership_changes: vec![],
    }
}

fn assert_rejects(plan: &NativeTransactionPlan, expected: &str) {
    let error = approval_hash_v2(plan).unwrap_err().to_string();
    assert!(
        error.contains(expected),
        "expected {error:?} to contain {expected:?}"
    );
}

#[test]
fn freezes_the_v2_domain_separator() {
    assert_eq!(APPROVAL_DOMAIN_V2, b"context-relay/native-plan/v2\0");
}

fn claude_context_plan() -> NativeTransactionPlan {
    let mut candidate = plan();
    candidate.setup.harness = HarnessId::ClaudeCode;
    candidate.setup.executable_path = native_text("/fixture/claude");
    candidate.native_memory_registrations.clear();
    let mutation = &mut candidate.cli_mutations[0];
    mutation.stable_id = "f4a4f9a2-0e8d-720e-8df4-a5a68da3e9c7".into();
    mutation.expected = None;
    mutation.intended = Some(declaration(
        HarnessId::ClaudeCode,
        "context-relay",
        "/opt/context-relay",
    ));
    mutation.forward = vec![operation(
        "/fixture/claude",
        &[
            "mcp",
            "add-json",
            "context-relay",
            &mutation.intended.as_ref().unwrap().canonical_body,
            "--scope",
            "user",
        ],
    )];
    mutation.rollback = vec![operation(
        "/fixture/claude",
        &["mcp", "remove", "context-relay", "--scope", "user"],
    )];
    mutation.execution_context = Some(CliExecutionContext::ClaudeCodeV1 {
        config_dir: native_text("/fixture/home/.claude"),
        state_path: native_text("/fixture/home/.claude.json"),
        project_root: native_text("/fixture/project"),
    });
    candidate.setup.cli_operations = mutation.forward.clone();
    candidate
}

#[test]
fn claude_execution_context_is_approval_bound_and_survives_sealing() {
    let mut candidate = claude_context_plan();
    let approved = approval_hash_v2(&candidate).unwrap();
    candidate.setup.batch_hash = approved;
    let sealed = seal_plan(&candidate, approved).unwrap();
    assert_eq!(
        open_plan(&sealed).unwrap().plan.cli_mutations,
        candidate.cli_mutations
    );

    for field in 0..3 {
        let mut changed = candidate.clone();
        let Some(CliExecutionContext::ClaudeCodeV1 {
            config_dir,
            state_path,
            project_root,
        }) = &mut changed.cli_mutations[0].execution_context
        else {
            unreachable!()
        };
        match field {
            0 => {
                *config_dir = native_text("/fixture/other/.claude");
                *state_path = native_text("/fixture/other/.claude.json");
            }
            1 => *state_path = native_text("/fixture/home/.claude/.claude.json"),
            _ => *project_root = native_text("/fixture/other-project"),
        }
        assert_ne!(approval_hash_v2(&changed).unwrap(), approved);
    }
    let mut missing = candidate.clone();
    missing.cli_mutations[0].execution_context = None;
    assert_ne!(approval_hash_v2(&missing).unwrap(), approved);

    let mut tampered: serde_json::Value = serde_json::from_slice(&sealed).unwrap();
    tampered["nativePlan"]["cliMutations"][0]["executionContext"]["statePath"] =
        serde_json::to_value(native_text("/fixture/home/.claude/.claude.json")).unwrap();
    assert!(open_plan(&serde_json::to_vec(&tampered).unwrap()).is_err());
}

#[test]
fn claude_execution_context_rejects_wrong_harness_and_invalid_paths() {
    let mut wrong_harness = plan();
    wrong_harness.cli_mutations[0].execution_context = claude_context_plan().cli_mutations[0]
        .execution_context
        .clone();
    assert!(approval_hash_v2(&wrong_harness).is_err());
    let mut bad_path = claude_context_plan();
    let Some(CliExecutionContext::ClaudeCodeV1 { project_root, .. }) =
        &mut bad_path.cli_mutations[0].execution_context
    else {
        unreachable!()
    };
    *project_root = native_text("../other");
    assert!(approval_hash_v2(&bad_path).is_err());
}

#[test]
fn legacy_cli_envelopes_remain_readable_without_an_execution_context_field() {
    let mut candidate = claude_context_plan();
    candidate.cli_mutations[0].execution_context = None;
    let approved = approval_hash_v2(&candidate).unwrap();
    candidate.setup.batch_hash = approved;
    let sealed = seal_plan(&candidate, approved).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&sealed).unwrap();
    assert!(
        value["nativePlan"]["cliMutations"][0]
            .get("executionContext")
            .is_none()
    );
    assert_eq!(open_plan(&sealed).unwrap().plan, candidate);
}

#[test]
fn expected_and_intended_declaration_bytes_affect_the_hash() {
    let baseline = approval_hash_v2(&plan()).unwrap();

    let mut changed_expected = plan();
    changed_expected.cli_mutations[0].expected = Some(declaration(
        HarnessId::Codex,
        "context-relay",
        "/opt/context-relay-earlier",
    ));
    assert_ne!(approval_hash_v2(&changed_expected).unwrap(), baseline);

    let mut changed_intended = plan();
    changed_intended.cli_mutations[0].intended = Some(declaration(
        HarnessId::Codex,
        "context-relay",
        "/opt/context-relay-new",
    ));
    assert_ne!(approval_hash_v2(&changed_intended).unwrap(), baseline);
}

#[test]
fn every_native_memory_descriptor_field_affects_the_v2_hash() {
    let baseline = approval_hash_v2(&plan()).unwrap();

    let mut changed_path = plan();
    changed_path.native_memory_registrations[0]
        .source
        .path
        .bytes
        .extend_from_slice(b".other");
    rebuild_source(&mut changed_path.native_memory_registrations[0].source);
    assert_ne!(approval_hash_v2(&changed_path).unwrap(), baseline);

    let mut changed_display = plan();
    changed_display.native_memory_registrations[0]
        .source
        .path
        .display = Some("Different display semantics".to_owned());
    assert_ne!(approval_hash_v2(&changed_display).unwrap(), baseline);

    for mutate in [
        |source: &mut NativeMemorySource| source.limits.max_bytes -= 1,
        |source: &mut NativeMemorySource| source.limits.max_characters -= 1,
    ] {
        let mut changed = plan();
        mutate(&mut changed.native_memory_registrations[0].source);
        rebuild_source(&mut changed.native_memory_registrations[0].source);
        assert_ne!(approval_hash_v2(&changed).unwrap(), baseline);
    }

    let mut changed_scope = plan();
    changed_scope.native_memory_registrations[0].source.scope = ScopeRef::Project {
        project_id: ProjectId::from_str(PLAN_ID).unwrap(),
    };
    rebuild_source(&mut changed_scope.native_memory_registrations[0].source);
    assert_ne!(approval_hash_v2(&changed_scope).unwrap(), baseline);

    let mut changed_kind = plan();
    changed_kind.native_memory_registrations[0]
        .source
        .document_kind = NativeMemoryDocumentKind::Summary;
    rebuild_source(&mut changed_kind.native_memory_registrations[0].source);
    assert_ne!(approval_hash_v2(&changed_kind).unwrap(), baseline);

    let mut changed_version = plan();
    changed_version.native_memory_registrations[0]
        .source
        .adapter_version = "0.144.0".to_owned();
    rebuild_source(&mut changed_version.native_memory_registrations[0].source);
    assert_ne!(approval_hash_v2(&changed_version).unwrap(), baseline);

    let mut changed_fence = plan();
    changed_fence.native_memory_registrations[0]
        .source
        .managed_fence = false;
    rebuild_source(&mut changed_fence.native_memory_registrations[0].source);
    assert_ne!(approval_hash_v2(&changed_fence).unwrap(), baseline);

    let mut changed_digest = plan();
    changed_digest.native_memory_registrations[0].last_applied_digest =
        Some(Sha256Digest([0x44; 32]));
    assert_ne!(approval_hash_v2(&changed_digest).unwrap(), baseline);
}

#[test]
fn native_memory_descriptor_identity_and_metadata_must_validate_exactly() {
    let mut changed_path_bytes = plan();
    changed_path_bytes.native_memory_registrations[0]
        .source
        .path
        .bytes
        .push(b'x');
    assert_rejects(&changed_path_bytes, "native memory source");

    let mut changed_scope = plan();
    changed_scope.native_memory_registrations[0].source.scope = ScopeRef::Project {
        project_id: ProjectId::from_str(PLAN_ID).unwrap(),
    };
    assert_rejects(&changed_scope, "native memory source");

    let mut changed_kind = plan();
    changed_kind.native_memory_registrations[0]
        .source
        .document_kind = NativeMemoryDocumentKind::Summary;
    assert_rejects(&changed_kind, "native memory source");

    let mut changed_version = plan();
    changed_version.native_memory_registrations[0]
        .source
        .adapter_version = "0.144.0".to_owned();
    assert_rejects(&changed_version, "native memory source");
}

#[test]
fn forward_and_rollback_operation_bytes_affect_the_hash() {
    let baseline = approval_hash_v2(&plan()).unwrap();

    let mut changed_forward = plan();
    changed_forward.cli_mutations[0].forward[0].arguments[4] =
        native_text("/opt/context-relay-new");
    changed_forward.setup.cli_operations = changed_forward.cli_mutations[0].forward.clone();
    assert_ne!(approval_hash_v2(&changed_forward).unwrap(), baseline);

    let mut changed_rollback = plan();
    changed_rollback.cli_mutations[0].rollback[0].arguments[4] =
        native_text("/opt/context-relay-earlier");
    assert_ne!(approval_hash_v2(&changed_rollback).unwrap(), baseline);
}

#[test]
fn forward_and_rollback_operation_order_affects_the_hash() {
    let mut ordered = plan();
    ordered.cli_mutations[0].forward.push(operation(
        "/fixture/codex",
        &["mcp", "get", "context-relay"],
    ));
    ordered.cli_mutations[0].rollback.push(operation(
        "/fixture/codex",
        &["mcp", "get", "context-relay"],
    ));
    ordered.setup.cli_operations = ordered.cli_mutations[0].forward.clone();
    let baseline = approval_hash_v2(&ordered).unwrap();

    let mut forward_reordered = ordered.clone();
    forward_reordered.cli_mutations[0].forward.reverse();
    forward_reordered.setup.cli_operations = forward_reordered.cli_mutations[0].forward.clone();
    assert_ne!(approval_hash_v2(&forward_reordered).unwrap(), baseline);

    let mut rollback_reordered = ordered;
    rollback_reordered.cli_mutations[0].rollback.reverse();
    assert_ne!(approval_hash_v2(&rollback_reordered).unwrap(), baseline);
}

#[test]
fn duplicate_stable_ids_and_harness_server_targets_reject() {
    let mut duplicate_stable_id = plan();
    let mut duplicate = duplicate_stable_id.cli_mutations[0].clone();
    duplicate.expected = Some(declaration(
        HarnessId::Codex,
        "another-target",
        "/opt/context-relay-old",
    ));
    duplicate.intended = Some(declaration(
        HarnessId::Codex,
        "another-target",
        "/opt/context-relay",
    ));
    duplicate_stable_id.cli_mutations.push(duplicate);
    assert_rejects(&duplicate_stable_id, "cli stable id");

    let mut duplicate_target = plan();
    let mut duplicate = duplicate_target.cli_mutations[0].clone();
    duplicate.stable_id = "another-stable-id".to_owned();
    duplicate_target.cli_mutations.push(duplicate);
    assert_rejects(&duplicate_target, "cli target");
}

#[test]
fn declaration_fingerprint_mismatch_rejects() {
    let mut expected = plan();
    expected.cli_mutations[0]
        .expected
        .as_mut()
        .unwrap()
        .fingerprint = Sha256Digest([0xff; 32]);
    assert_rejects(&expected, "declaration fingerprint");

    let mut intended = plan();
    intended.cli_mutations[0]
        .intended
        .as_mut()
        .unwrap()
        .fingerprint = Sha256Digest([0xff; 32]);
    assert_rejects(&intended, "declaration fingerprint");
}

#[test]
fn declarations_must_be_canonical_bounded_and_secret_free() {
    let mut noncanonical = plan();
    let declaration = noncanonical.cli_mutations[0].intended.as_mut().unwrap();
    declaration.canonical_body = format!(" {} ", declaration.canonical_body);
    declaration.fingerprint =
        Sha256Digest(Sha256::digest(declaration.canonical_body.as_bytes()).into());
    assert_rejects(&noncanonical, "canonical managed bridge");

    let mut secret_bearing = plan();
    let declaration = secret_bearing.cli_mutations[0].intended.as_mut().unwrap();
    declaration.canonical_body = serde_json::to_string(&serde_json::json!({
        "args": ["--harness", "codex"],
        "command": "/opt/context-relay",
        "env": {"TOKEN": "secret"},
        "type": "stdio",
    }))
    .unwrap();
    declaration.fingerprint =
        Sha256Digest(Sha256::digest(declaration.canonical_body.as_bytes()).into());
    assert_rejects(&secret_bearing, "canonical managed bridge");

    let mut oversized = plan();
    let declaration = oversized.cli_mutations[0].intended.as_mut().unwrap();
    declaration.canonical_body = "x".repeat(16 * 1024 + 1);
    declaration.fingerprint =
        Sha256Digest(Sha256::digest(declaration.canonical_body.as_bytes()).into());
    assert_rejects(&oversized, "declaration body");
}

#[test]
fn managed_declarations_accept_canonical_absolute_command_families() {
    for command in [
        "/opt/context-relay/bin/context-relay",
        r"C:\Program Files\Context Relay\context-relay.exe",
        r"\\server\share\bin\context-relay.exe",
        r"\\?\C:\Program Files\Context Relay\context-relay.exe",
        r"\\?\UNC\server\share\bin\context-relay.exe",
    ] {
        let mut candidate = plan();
        candidate.cli_mutations[0].intended =
            Some(declaration(HarnessId::Codex, "context-relay", command));
        assert!(
            approval_hash_v2(&candidate).is_ok(),
            "canonical command rejected: {command:?}"
        );
    }
}

#[test]
fn managed_declarations_reject_relative_traversing_and_device_command_paths() {
    for command in [
        "",
        "relative/context-relay",
        r"C:context-relay.exe",
        r"C:/bin/context-relay.exe",
        r"C:\bin\..\context-relay.exe",
        r"C:\bin\\context-relay.exe",
        r"\bin\context-relay.exe",
        r"\\server",
        r"\\server\share",
        r"\\server\share\bin/context-relay.exe",
        r"\\?\C:",
        r"\\?\C:\",
        r"\\?\C:\bin\..\context-relay.exe",
        r"\\?\UNC\server\share",
        r"\\?\UNC\server\share\bin/context-relay.exe",
        r"\\?\GLOBALROOT\Device\HarddiskVolume1\context-relay.exe",
        r"\\?\Volume{12345678-1234-1234-1234-123456789abc}\context-relay.exe",
        r"\\?\PIPE\context-relay",
        r"\\.\PhysicalDrive0",
        r"\??\C:\bin\context-relay.exe",
        "C:\\bin\\context\u{0000}-relay.exe",
        "C:\\bin\\context\u{000a}-relay.exe",
    ] {
        let mut candidate = plan();
        candidate.cli_mutations[0].intended =
            Some(declaration(HarnessId::Codex, "context-relay", command));
        assert_rejects(&candidate, "canonical managed bridge");
    }
}

#[test]
fn managed_declarations_reject_dos_device_aliases_in_every_windows_component() {
    let aliases = [
        "CON",
        "con.exe",
        "PRN",
        "prn.txt",
        "AUX",
        "aux.json",
        "NUL",
        "nul.bin",
        "CLOCK$",
        "clock$.log",
        "CONIN$",
        "conin$.txt",
        "CONOUT$",
        "conout$.txt",
        "COM1",
        "com9.exe",
        "COM\u{00b9}",
        "com\u{00b2}.txt",
        "COM\u{00b3}",
        "LPT1",
        "lpt9.exe",
        "LPT\u{00b9}",
        "lpt\u{00b2}.txt",
        "LPT\u{00b3}",
        "NUL .exe",
        "COM1 .cmd",
        "com\u{00b9} .txt",
        "LPT\u{00b2} .bin",
        "CON.",
        "NUL ",
    ];
    for alias in aliases {
        let commands = [
            format!(r"C:\{alias}\context-relay.exe"),
            format!(r"C:\bin\{alias}"),
            format!(r"\\?\C:\{alias}\context-relay.exe"),
            format!(r"\\?\C:\bin\{alias}"),
            format!(r"\\{alias}\share\bin\context-relay.exe"),
            format!(r"\\server\{alias}\bin\context-relay.exe"),
            format!(r"\\server\share\{alias}\context-relay.exe"),
            format!(r"\\server\share\bin\{alias}"),
            format!(r"\\?\UNC\{alias}\share\bin\context-relay.exe"),
            format!(r"\\?\UNC\server\{alias}\bin\context-relay.exe"),
            format!(r"\\?\UNC\server\share\{alias}\context-relay.exe"),
            format!(r"\\?\UNC\server\share\bin\{alias}"),
        ];
        for command in commands {
            let mut candidate = plan();
            candidate.cli_mutations[0].intended =
                Some(declaration(HarnessId::Codex, "context-relay", &command));
            assert_rejects(&candidate, "canonical managed bridge");
        }
    }
}

#[test]
fn managed_declarations_accept_non_device_windows_names_containing_alias_text() {
    for command in [
        r"C:\CONTEXT\AUXILIARY\COM10\LPT0\NUL-safe\context-relay.exe",
        r"C:\xCOM1\LPT1x\CONSOLE\context-relay.exe",
        "C:\\NUL safe.exe\\COM1-safe.cmd\\COM\u{00b9}-safe\\context-relay.exe",
        r"\\?\C:\PRINTER\COM01\LPT10\context-relay.exe",
        r"\\connection\auxiliary\com10\context-relay.exe",
        r"\\?\UNC\connection\auxiliary\lpt0\context-relay.exe",
    ] {
        let mut candidate = plan();
        candidate.cli_mutations[0].intended =
            Some(declaration(HarnessId::Codex, "context-relay", command));
        assert!(
            approval_hash_v2(&candidate).is_ok(),
            "legitimate command rejected: {command:?}"
        );
    }
}

#[cfg(windows)]
#[test]
fn windows_bridge_component_canonical_path_is_accepted_by_approval_v2() {
    use std::fs;

    use context_relay_core::mcp::install::bridge_component;
    use context_relay_protocol::{DeviceId, HybridLogicalClock};

    let root = tempfile::tempdir().unwrap();
    let executable = root.path().join("context-relay.exe");
    fs::write(&executable, b"fixture").unwrap();
    let device = DeviceId::from_str(PLAN_ID).unwrap();
    let component = bridge_component(
        HarnessId::Codex,
        &executable,
        device,
        HybridLogicalClock::new(1_900_000_000_000, 0, device),
    )
    .unwrap();
    let mut candidate = plan();
    candidate.cli_mutations[0].expected = None;
    candidate.cli_mutations[0].intended = Some(CanonicalCliDeclaration {
        harness: HarnessId::Codex,
        server_name: "context-relay".to_owned(),
        fingerprint: Sha256Digest(Sha256::digest(component.body_markdown.as_bytes()).into()),
        canonical_body: component.body_markdown,
    });

    approval_hash_v2(&candidate).unwrap();
}

#[test]
fn flattened_forward_operations_must_equal_setup_operations() {
    let mut missing = plan();
    missing.setup.cli_operations.clear();
    assert_rejects(&missing, "flattened cli forward operations");

    let mut reordered = plan();
    reordered.cli_mutations[0].forward.push(operation(
        "/fixture/codex",
        &["mcp", "get", "context-relay"],
    ));
    reordered.setup.cli_operations = reordered.cli_mutations[0].forward.clone();
    reordered.setup.cli_operations.reverse();
    assert_rejects(&reordered, "flattened cli forward operations");
}

#[test]
fn every_operation_must_use_the_attested_harness_executable() {
    let mut forward = plan();
    forward.cli_mutations[0].forward[0].executable = native_text("/fixture/other");
    forward.setup.cli_operations = forward.cli_mutations[0].forward.clone();
    assert_rejects(&forward, "attested harness executable");

    let mut rollback = plan();
    rollback.cli_mutations[0].rollback[0].executable = native_text("/fixture/other");
    assert_rejects(&rollback, "attested harness executable");
}

#[test]
fn operation_timeouts_are_exactly_bounded() {
    for timeout_ms in [0, CLI_TIMEOUT_MS - 1, CLI_TIMEOUT_MS + 1, u32::MAX] {
        let mut candidate = plan();
        candidate.cli_mutations[0].forward[0].timeout_ms = timeout_ms;
        candidate.setup.cli_operations = candidate.cli_mutations[0].forward.clone();
        assert_rejects(&candidate, "timeout");
    }
}

#[test]
fn hermes_and_non_managed_targets_reject() {
    let mut hermes = plan();
    hermes.setup.harness = HarnessId::Hermes;
    hermes.setup.harness_profile = Some("coder".to_owned());
    assert_rejects(&hermes, "Hermes");

    let mut wrong_harness = plan();
    wrong_harness.cli_mutations[0].expected = Some(declaration(
        HarnessId::ClaudeCode,
        "context-relay",
        "/opt/context-relay-old",
    ));
    wrong_harness.cli_mutations[0].intended = Some(declaration(
        HarnessId::ClaudeCode,
        "context-relay",
        "/opt/context-relay",
    ));
    assert_rejects(&wrong_harness, "plan harness");

    let mut wrong_server = plan();
    wrong_server.cli_mutations[0].expected = Some(declaration(
        HarnessId::Codex,
        "unmanaged",
        "/opt/context-relay-old",
    ));
    wrong_server.cli_mutations[0].intended = Some(declaration(
        HarnessId::Codex,
        "unmanaged",
        "/opt/context-relay",
    ));
    assert_rejects(&wrong_server, "managed context-relay");

    let mut wrong_stable_id = plan();
    wrong_stable_id.cli_mutations[0].stable_id = "unmanaged".to_owned();
    assert_rejects(&wrong_stable_id, "managed bridge stable id");
}
