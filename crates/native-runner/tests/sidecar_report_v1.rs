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

fn semgrep_core_result(rule: &str, severity: &str, message: &str, end: u64) -> Value {
    json!({
        "check_id": rule,
        "path": "input/semgrep-target/METADATA",
        "start": { "line": 1, "col": 1, "offset": 0 },
        "end": { "line": 1, "col": end + 1, "offset": end },
        "extra": {
            "metavars": {},
            "engine_kind": "OSS",
            "is_ignored": false,
            "message": message,
            "metadata": {},
            "severity": severity,
            "validation_state": "NO_VALIDATOR"
        }
    })
}

fn semgrep_core_report(results: Vec<Value>) -> Value {
    let mut report = semgrep_report(results, vec!["input/semgrep-target/METADATA"]);
    report["rules_by_engine"] = json!([
        ["config.semgrep.context-relay-scan-canary", "OSS"],
        ["config.semgrep.context-relay-no-python-runtime", "OSS"]
    ]);
    report["interfile_languages_used"] = json!([]);
    report
}

#[test]
fn semgrep_core_accepts_exit_zero_with_empty_stderr_and_strips_the_canary() {
    let inputs = vec![frame("input/semgrep-target/METADATA", b"hello world")];
    let canary = semgrep_core_result(
        "config.semgrep.context-relay-scan-canary",
        "INFO",
        "Context Relay scan coverage canary.",
        1,
    );
    let finding = semgrep_core_result(
        "config.semgrep.context-relay-no-python-runtime",
        "ERROR",
        "Native Semgrep packages must not contain Pysemgrep or a Python runtime.",
        6,
    );

    let (clean, normalized) = validate_semgrep_report(
        0,
        &serde_json::to_vec(&semgrep_core_report(vec![canary.clone()])).unwrap(),
        b"",
        &inputs,
    )
    .unwrap();
    assert_eq!(clean, RunDisposition::Clean);
    assert!(
        serde_json::from_slice::<Value>(&normalized).unwrap()["results"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    assert_eq!(
        validate_semgrep_report(
            0,
            &serde_json::to_vec(&semgrep_core_report(vec![canary, finding])).unwrap(),
            b"",
            &inputs,
        )
        .unwrap()
        .0,
        RunDisposition::Findings(1)
    );
}

#[test]
fn semgrep_core_accepts_omitted_optional_rule_metadata() {
    let inputs = vec![frame("input/semgrep-target/METADATA", b"hello world")];
    let mut canary = semgrep_core_result(
        "config.semgrep.context-relay-scan-canary",
        "INFO",
        "Context Relay scan coverage canary.",
        1,
    );
    canary["extra"].as_object_mut().unwrap().remove("metadata");

    assert_eq!(
        validate_semgrep_report(
            0,
            &serde_json::to_vec(&semgrep_core_report(vec![canary])).unwrap(),
            b"",
            &inputs,
        )
        .unwrap()
        .0,
        RunDisposition::Clean
    );
}

#[test]
fn semgrep_core_accepts_and_strips_the_closed_regex_capture() {
    let inputs = vec![frame("input/semgrep-target/METADATA", b"python.exe\n")];
    let canary = semgrep_core_result(
        "config.semgrep.context-relay-scan-canary",
        "INFO",
        "Context Relay scan coverage canary.",
        1,
    );
    let mut finding = semgrep_core_result(
        "config.semgrep.context-relay-no-python-runtime",
        "ERROR",
        "Native Semgrep packages must not contain Pysemgrep or a Python runtime.",
        10,
    );
    finding["extra"]["metavars"] = json!({
        "$1": {
            "start": { "line": 1, "col": 1, "offset": 0 },
            "end": { "line": 1, "col": 11, "offset": 10 },
            "abstract_content": "python.exe"
        }
    });

    let (_, report) = validate_semgrep_report(
        0,
        &serde_json::to_vec(&semgrep_core_report(vec![canary, finding])).unwrap(),
        b"",
        &inputs,
    )
    .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&report).unwrap()["results"][0]["extra"]["metavars"],
        json!({})
    );
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
