#[cfg(feature = "ci-candidate-sidecar-smoke")]
use context_relay_native_runner::RunnerError;
use context_relay_native_runner::{
    ContentFrame, RuleSyncFeature, RuleSyncFeatures, RuleSyncTarget, RunDisposition,
    SidecarCommand, StagePath, validate_gitleaks_report, validate_rulesync_outputs,
    validate_semgrep_report,
};
use serde_json::{Value, json};

fn frame(path: &str, bytes: &[u8]) -> ContentFrame {
    ContentFrame::new(StagePath::try_from(path).unwrap(), bytes.to_vec()).unwrap()
}

fn gitleaks_finding() -> Value {
    json!({
        "RuleID": "generic-api-key",
        "Description": "Generic API Key",
        "StartLine": 1,
        "EndLine": 1,
        "StartColumn": 1,
        "EndColumn": 11,
        "Match": "token = REDACTED",
        "Secret": "REDACTED",
        "File": "payload/a.txt",
        "SymlinkFile": "",
        "Commit": "",
        "Entropy": 3.2,
        "Author": "",
        "Email": "",
        "Date": "",
        "Message": "",
        "Tags": ["key"],
        "Fingerprint": "payload/a.txt:generic-api-key:1"
    })
}

fn semgrep_report(results: Vec<Value>, scanned: Vec<&str>) -> Value {
    let targets = scanned
        .iter()
        .map(|path| {
            json!({
                "path": path,
                "num_bytes": 11,
                "match_times": [0.0],
                "parse_times": [0.0],
                "run_time": 0.0
            })
        })
        .collect::<Vec<_>>();
    let total_bytes = scanned.len() * 11;
    json!({
        "version": "1.170.0",
        "results": results,
        "errors": [],
        "paths": { "scanned": scanned },
        "time": {
            "rules": ["config.semgrep.context-relay-no-python-runtime"],
            "rules_parse_time": 0.0,
            "profiling_times": {},
            "parsing_time": {
                "total_time": 0.0,
                "per_file_time": { "mean": 0.0, "std_dev": 0.0 },
                "very_slow_stats": { "time_ratio": 0.0, "count_ratio": 0.0 },
                "very_slow_files": []
            },
            "scanning_time": {
                "total_time": 0.001,
                "per_file_time": { "mean": 0.001, "std_dev": 0.0 },
                "very_slow_stats": { "time_ratio": 0.0, "count_ratio": 0.0 },
                "very_slow_files": []
            },
            "matching_time": {
                "total_time": 0.0,
                "per_file_and_rule_time": { "mean": 0.0, "std_dev": 0.0 },
                "very_slow_stats": { "time_ratio": 0.0, "count_ratio": 0.0 },
                "very_slow_rules_on_files": []
            },
            "tainting_time": {
                "total_time": 0.0,
                "per_def_and_rule_time": { "mean": 0.0, "std_dev": 0.0 },
                "very_slow_stats": { "time_ratio": 0.0, "count_ratio": 0.0 },
                "very_slow_rules_on_defs": []
            },
            "prefiltering": {
                "project_level_time": 0.0,
                "file_level_time": 0.0,
                "rules_with_project_prefilters_ratio": 0.0,
                "rules_with_file_prefilters_ratio": 1.0,
                "rules_selected_ratio": 1.0,
                "rules_matched_ratio": 0.0
            },
            "targets": targets,
            "total_bytes": total_bytes,
            "max_memory_bytes": 0,
            "fixpoint_timeouts": []
        },
        "engine_requested": "OSS",
        "skipped_rules": [],
        "profiling_results": []
    })
}

fn semgrep_warning() -> &'static [u8] {
    b"[00.10][WARNING]: !!! You're using one or more options starting with '--x-'. These options are not part of the semgrep API. They will change or will be removed without notice !!! \n"
}

#[test]
fn gitleaks_requires_exact_reviewed_fields_paths_fingerprints_and_diagnostics() {
    let inputs = vec![frame("input/gitleaks-scan/payload/a.txt", b"hello world")];
    let stdout = serde_json::to_vec(&vec![gitleaks_finding()]).unwrap();
    let stderr = b"9:59AM INF scanned ~11 bytes (11 bytes) in 3.5ms\n9:59AM WRN leaks found: 1\n";
    let (disposition, report) = validate_gitleaks_report(10, &stdout, stderr, &inputs).unwrap();
    assert_eq!(disposition, RunDisposition::Findings(1));
    let persisted: Value = serde_json::from_slice(&report).unwrap();
    let finding = persisted.as_array().unwrap()[0].as_object().unwrap();
    assert!(!finding.contains_key("Secret"));
    assert!(!finding.contains_key("Match"));

    let clean_stderr =
        b"9:59AM INF scanned ~11 bytes (11 bytes) in 3.5ms\n9:59AM INF no leaks found\n";
    assert_eq!(
        validate_gitleaks_report(0, b"[]", clean_stderr, &inputs)
            .unwrap()
            .0,
        RunDisposition::Clean
    );

    let mut poisoned = gitleaks_finding();
    poisoned
        .as_object_mut()
        .unwrap()
        .insert("Link".into(), json!("https://example.invalid/secret"));
    let encoded = serde_json::to_vec(&vec![poisoned]).unwrap();
    assert!(validate_gitleaks_report(10, &encoded, stderr, &inputs).is_err());
    assert!(
        validate_gitleaks_report(
            10,
            &stdout,
            b"9:59AM INF scanned ~10 bytes (10 bytes) in 3.5ms\n9:59AM WRN leaks found: 1\n",
            &inputs,
        )
        .is_err()
    );
    assert!(
        validate_gitleaks_report(
            10,
            &stdout,
            b"9:59AM INF scanned ~11 bytes (11 bytes) in 3.5ms\n9:59AM WRN leaks found: 2\n",
            &inputs,
        )
        .is_err()
    );
}

#[test]
fn gitleaks_normalizes_only_the_exact_scan_root_prefix() {
    let inputs = vec![frame("input/gitleaks-scan/payload/a.txt", b"hello world")];
    let stderr = b"9:59AM INF scanned ~11 bytes (11 bytes) in 3.5ms\n9:59AM WRN leaks found: 1\n";
    let mut prefixed = gitleaks_finding();
    let object = prefixed.as_object_mut().unwrap();
    object.insert("File".into(), json!("input/gitleaks-scan/payload/a.txt"));
    object.insert(
        "Fingerprint".into(),
        json!("input/gitleaks-scan/payload/a.txt:generic-api-key:1"),
    );
    let stdout = serde_json::to_vec(&vec![prefixed]).unwrap();

    let (_, report) = validate_gitleaks_report(10, &stdout, stderr, &inputs).unwrap();
    let persisted: Value = serde_json::from_slice(&report).unwrap();
    let finding = persisted.as_array().unwrap()[0].as_object().unwrap();
    assert_eq!(finding["File"], "payload/a.txt");
    assert_eq!(finding["Fingerprint"], "payload/a.txt:generic-api-key:1");

    let mut lookalike = gitleaks_finding();
    let object = lookalike.as_object_mut().unwrap();
    object.insert(
        "File".into(),
        json!("input/gitleaks-scan-extra/payload/a.txt"),
    );
    object.insert(
        "Fingerprint".into(),
        json!("input/gitleaks-scan-extra/payload/a.txt:generic-api-key:1"),
    );
    let stdout = serde_json::to_vec(&vec![lookalike]).unwrap();
    assert!(validate_gitleaks_report(10, &stdout, stderr, &inputs).is_err());
}

#[test]
fn semgrep_requires_exact_schema_unique_paths_and_source_free_results() {
    let inputs = vec![frame("input/semgrep-target/METADATA", b"hello world")];
    let clean = serde_json::to_vec(&semgrep_report(
        vec![],
        vec!["input\\semgrep-target\\METADATA"],
    ))
    .unwrap();
    assert_eq!(
        validate_semgrep_report(0, &clean, semgrep_warning(), &inputs)
            .unwrap()
            .0,
        RunDisposition::Clean
    );

    let result = json!({
        "check_id": "config.semgrep.context-relay-no-python-runtime",
        "path": "input\\semgrep-target\\METADATA",
        "start": { "line": 1, "col": 1, "offset": 0 },
        "end": { "line": 1, "col": 7, "offset": 6 },
        "extra": {
            "message": "Native Semgrep packages must not contain Pysemgrep or a Python runtime.",
            "metadata": {},
            "severity": "ERROR",
            "fingerprint": "requires login",
            "lines": "requires login",
            "validation_state": "NO_VALIDATOR",
            "engine_kind": "OSS"
        }
    });
    let finding = serde_json::to_vec(&semgrep_report(
        vec![result.clone()],
        vec!["input/semgrep-target/METADATA"],
    ))
    .unwrap();
    assert_eq!(
        validate_semgrep_report(1, &finding, semgrep_warning(), &inputs)
            .unwrap()
            .0,
        RunDisposition::Findings(1)
    );

    let mut extra_field =
        semgrep_report(vec![result.clone()], vec!["input/semgrep-target/METADATA"]);
    extra_field
        .as_object_mut()
        .unwrap()
        .insert("fallback".into(), json!("python"));
    assert!(
        validate_semgrep_report(
            1,
            &serde_json::to_vec(&extra_field).unwrap(),
            semgrep_warning(),
            &inputs,
        )
        .is_err()
    );

    let duplicate = serde_json::to_vec(&semgrep_report(
        vec![result.clone()],
        vec![
            "input/semgrep-target/METADATA",
            "input/semgrep-target/METADATA",
        ],
    ))
    .unwrap();
    assert!(validate_semgrep_report(1, &duplicate, semgrep_warning(), &inputs).is_err());

    let mut source_bearing = result;
    source_bearing
        .get_mut("extra")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(
            "metavars".into(),
            json!({ "$X": { "abstract_content": "secret" } }),
        );
    let source_bearing = serde_json::to_vec(&semgrep_report(
        vec![source_bearing],
        vec!["input/semgrep-target/METADATA"],
    ))
    .unwrap();
    assert!(validate_semgrep_report(1, &source_bearing, semgrep_warning(), &inputs).is_err());
}

#[test]
fn semgrep_timing_binds_the_exact_rule_paths_and_input_sizes() {
    let inputs = vec![frame("input/semgrep-target/METADATA", b"hello world")];
    let valid = semgrep_report(vec![], vec!["input/semgrep-target/METADATA"]);
    assert!(
        validate_semgrep_report(
            0,
            &serde_json::to_vec(&valid).unwrap(),
            semgrep_warning(),
            &inputs,
        )
        .is_ok()
    );

    for poisoned in [
        ("rules", json!([])),
        ("rules", json!(["context-relay-no-python-runtime"])),
        ("profiling_times", json!([])),
        ("total_bytes", json!(10)),
        (
            "targets",
            json!([{
                "path": "input/semgrep-target/METADATA",
                "num_bytes": 10,
                "match_times": [0.0],
                "parse_times": [0.0],
                "run_time": 0.0
            }]),
        ),
        (
            "targets",
            json!([{
                "path": "input/semgrep-target/OTHER",
                "num_bytes": 11,
                "match_times": [0.0],
                "parse_times": [0.0],
                "run_time": 0.0
            }]),
        ),
        (
            "targets",
            json!([{
                "path": "input/semgrep-target/METADATA",
                "num_bytes": 11,
                "match_times": [],
                "parse_times": [0.0],
                "run_time": 0.0
            }]),
        ),
    ] {
        let mut report = valid.clone();
        report
            .get_mut("time")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(poisoned.0.into(), poisoned.1);
        assert!(
            validate_semgrep_report(
                0,
                &serde_json::to_vec(&report).unwrap(),
                semgrep_warning(),
                &inputs,
            )
            .is_err()
        );
    }
}

#[test]
fn semgrep_accepts_the_exact_native_clean_profile_shape() {
    let inputs = vec![frame(
        "input/semgrep-target/runtime-inventory.txt",
        b"osemgrep\n",
    )];
    let report = br#"{"version":"1.170.0","results":[],"errors":[],"paths":{"scanned":["input/semgrep-target/runtime-inventory.txt"]},"time":{"rules":["config.semgrep.context-relay-no-python-runtime"],"rules_parse_time":0.000034809112548828125,"profiling_times":{},"parsing_time":{"total_time":0.0,"per_file_time":{"mean":0.0,"std_dev":0.0},"very_slow_stats":{"time_ratio":0.0,"count_ratio":0.0},"very_slow_files":[]},"scanning_time":{"total_time":0.0002048015594482422,"per_file_time":{"mean":0.0002048015594482422,"std_dev":0.0},"very_slow_stats":{"time_ratio":0.0,"count_ratio":0.0},"very_slow_files":[]},"matching_time":{"total_time":0.0,"per_file_and_rule_time":{"mean":0.0,"std_dev":0.0},"very_slow_stats":{"time_ratio":0.0,"count_ratio":0.0},"very_slow_rules_on_files":[]},"tainting_time":{"total_time":0.0,"per_def_and_rule_time":{"mean":0.0,"std_dev":0.0},"very_slow_stats":{"time_ratio":0.0,"count_ratio":0.0},"very_slow_rules_on_defs":[]},"fixpoint_timeouts":[],"prefiltering":{"project_level_time":0.0,"file_level_time":0.0,"rules_with_project_prefilters_ratio":0.0,"rules_with_file_prefilters_ratio":1.0,"rules_selected_ratio":0.0,"rules_matched_ratio":0.0},"targets":[{"path":"input/semgrep-target/runtime-inventory.txt","num_bytes":9,"match_times":[0.0],"parse_times":[0.0],"run_time":0.0002048015594482422}],"total_bytes":9,"max_memory_bytes":86793536},"engine_requested":"OSS","skipped_rules":[],"profiling_results":[]}"#;

    assert_eq!(
        validate_semgrep_report(0, report, semgrep_warning(), &inputs)
            .unwrap()
            .0,
        RunDisposition::Clean
    );
}

#[cfg(feature = "ci-candidate-sidecar-smoke")]
#[test]
fn semgrep_candidate_diagnostics_classify_only_pre_json_rejections() {
    let inputs = vec![frame(
        "input/semgrep-target/runtime-inventory.txt",
        b"osemgrep\n",
    )];
    let report = serde_json::to_vec(&semgrep_report(
        vec![],
        vec!["input/semgrep-target/runtime-inventory.txt"],
    ))
    .unwrap();

    for (exit, stderr, stage) in [
        (2, semgrep_warning(), 0),
        (0, b"".as_slice(), 1),
        (0, b"unexpected\n".as_slice(), 2),
        (0, b"[clock][WARNING]: warning\n".as_slice(), 3),
        (0, b"[00.10][WARNING]: warning\n".as_slice(), 4),
    ] {
        assert_eq!(
            validate_semgrep_report(exit, &report, stderr, &inputs),
            Err(RunnerError::CiSemgrepValidation(stage))
        );
    }
}

#[test]
fn rulesync_outputs_match_the_exact_feature_semantic_manifest() {
    let command = SidecarCommand::RuleSyncGenerate {
        target: RuleSyncTarget::CodexCli,
        features: RuleSyncFeatures::new(&[
            RuleSyncFeature::Rules,
            RuleSyncFeature::Mcp,
            RuleSyncFeature::Skills,
        ])
        .unwrap(),
    };
    let inputs = vec![
        frame("input/.rulesync/rules/overview.md", b"# Rules\n"),
        frame("input/.rulesync/mcp.json", br#"{"mcpServers":{}}"#),
        frame(
            "input/.rulesync/skills/review/SKILL.md",
            b"---\nname: review\ndescription: review\n---\nReview.\n",
        ),
    ];
    let outputs = vec![
        frame("output/AGENTS.md", b"# Rules\n"),
        frame("output/.codex/config.toml", b"mcp_servers = {}\n"),
        frame(
            "output/.agents/skills/review/SKILL.md",
            b"---\nname: review\ndescription: review\n---\nReview.\n",
        ),
    ];
    assert!(validate_rulesync_outputs(&command, &inputs, &outputs).is_ok());

    let unexpected = vec![frame("output/.codex/poison.json", b"{}")];
    assert!(validate_rulesync_outputs(&command, &inputs, &unexpected).is_err());
}
