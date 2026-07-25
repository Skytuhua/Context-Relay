use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use crate::{
    ContentFrame, RuleSyncFeature, RuleSyncTarget, RunDisposition, RunnerError, SidecarCommand,
    StagePath, command::rulesync_input_feature,
};

const GITLEAKS_KEYS: [&str; 18] = [
    "RuleID",
    "Description",
    "StartLine",
    "EndLine",
    "StartColumn",
    "EndColumn",
    "Match",
    "Secret",
    "File",
    "SymlinkFile",
    "Commit",
    "Entropy",
    "Author",
    "Email",
    "Date",
    "Message",
    "Tags",
    "Fingerprint",
];
const SEMGREP_KEYS: [&str; 8] = [
    "version",
    "results",
    "errors",
    "paths",
    "time",
    "engine_requested",
    "skipped_rules",
    "profiling_results",
];
const SEMGREP_WARNING: &str = "!!! You're using one or more options starting with '--x-'. These options are not part of the semgrep API. They will change or will be removed without notice !!! ";
const SEMGREP_RULE_ID: &str = "config.semgrep.context-relay-no-python-runtime";
const SEMGREP_BARE_RULE_ID: &str = "context-relay-no-python-runtime";
const SEMGREP_CANARY_RULE_ID: &str = "config.semgrep.context-relay-scan-canary";
const SEMGREP_BARE_CANARY_RULE_ID: &str = "context-relay-scan-canary";

pub fn validate_gitleaks_report(
    exit: i32,
    stdout: &[u8],
    stderr: &[u8],
    inputs: &[ContentFrame],
) -> Result<(RunDisposition, Vec<u8>), RunnerError> {
    if !matches!(exit, 0 | 10) {
        return invalid();
    }
    let expected_paths = inputs
        .iter()
        .map(|input| {
            input
                .path()
                .as_str()
                .strip_prefix("input/gitleaks-scan/")
                .filter(|path| !path.is_empty())
                .map(str::to_owned)
                .ok_or(RunnerError::InvalidToolOutput)
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected_bytes = inputs.iter().try_fold(0_u64, |total, input| {
        total
            .checked_add(input.bytes().len() as u64)
            .ok_or(RunnerError::LimitExceeded)
    })?;
    let mut findings = serde_json::from_slice::<Value>(stdout)
        .map_err(|_| RunnerError::InvalidToolOutput)?
        .as_array()
        .cloned()
        .ok_or(RunnerError::InvalidToolOutput)?;
    let mut fingerprints = BTreeSet::new();
    for finding in &mut findings {
        let object = finding
            .as_object_mut()
            .ok_or(RunnerError::InvalidToolOutput)?;
        if !exact_keys(object, &GITLEAKS_KEYS)
            || !nonempty_string(object, "Description")
            || !empty_strings(
                object,
                &[
                    "SymlinkFile",
                    "Commit",
                    "Author",
                    "Email",
                    "Date",
                    "Message",
                ],
            )
            || object.get("Secret").and_then(Value::as_str) != Some("REDACTED")
            || !object
                .get("Match")
                .and_then(Value::as_str)
                .is_some_and(|value| value.contains("REDACTED"))
            || !object
                .get("Entropy")
                .and_then(Value::as_f64)
                .is_some_and(|value| value.is_finite() && value >= 0.0)
            || !object
                .get("Tags")
                .and_then(Value::as_array)
                .is_some_and(|tags| tags.iter().all(Value::is_string))
        {
            return invalid();
        }
        let rule = object
            .get("RuleID")
            .and_then(Value::as_str)
            .filter(|value| {
                !value.is_empty()
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            })
            .map(str::to_owned)
            .ok_or(RunnerError::InvalidToolOutput)?;
        let reported_file = object
            .get("File")
            .and_then(Value::as_str)
            .filter(|value| !value.contains('\\'))
            .map(str::to_owned)
            .ok_or(RunnerError::InvalidToolOutput)?;
        let file = reported_file
            .strip_prefix("input/gitleaks-scan/")
            .unwrap_or(&reported_file);
        if !expected_paths.contains(file) {
            return invalid();
        }
        let start_line = positive_integer(object, "StartLine")?;
        let end_line = positive_integer(object, "EndLine")?;
        let start_column = positive_integer(object, "StartColumn")?;
        let end_column = positive_integer(object, "EndColumn")?;
        if (end_line, end_column) < (start_line, start_column) {
            return invalid();
        }
        let reported_fingerprint = format!("{reported_file}:{rule}:{start_line}");
        let canonical_fingerprint = format!("{file}:{rule}:{start_line}");
        if object.get("Fingerprint").and_then(Value::as_str) != Some(reported_fingerprint.as_str())
            || !fingerprints.insert(canonical_fingerprint.clone())
        {
            return invalid();
        }
        object.insert("File".to_owned(), Value::String(file.to_owned()));
        object.insert(
            "Fingerprint".to_owned(),
            Value::String(canonical_fingerprint),
        );
        object.remove("Secret");
        object.remove("Match");
    }
    let count = u32::try_from(findings.len()).map_err(|_| RunnerError::LimitExceeded)?;
    let disposition = match (exit, count) {
        (0, 0) => RunDisposition::Clean,
        (10, count) if count > 0 => RunDisposition::Findings(count),
        _ => return invalid(),
    };
    validate_gitleaks_diagnostics(stderr, expected_bytes, disposition)?;
    Ok((
        disposition,
        serde_json::to_vec(&findings).map_err(|_| RunnerError::InvalidToolOutput)?,
    ))
}

pub fn validate_semgrep_report(
    exit: i32,
    stdout: &[u8],
    stderr: &[u8],
    inputs: &[ContentFrame],
) -> Result<(RunDisposition, Vec<u8>), RunnerError> {
    if !matches!(exit, 0 | 1) || !valid_semgrep_warning(stderr) {
        return invalid();
    }
    let mut report: Value =
        serde_json::from_slice(stdout).map_err(|_| RunnerError::InvalidToolOutput)?;
    let object = report.as_object().ok_or(RunnerError::InvalidToolOutput)?;
    if !exact_keys(object, &SEMGREP_KEYS)
        || object.get("version").and_then(Value::as_str) != Some("1.170.0")
        || object.get("engine_requested").and_then(Value::as_str) != Some("OSS")
        || !empty_array(object.get("errors"))
        || !empty_array(object.get("skipped_rules"))
        || !empty_array(object.get("profiling_results"))
    {
        return invalid();
    }
    let expected = inputs
        .iter()
        .map(|input| input.path().as_str().to_owned())
        .collect::<BTreeSet<_>>();
    validate_semgrep_time(
        object
            .get("time")
            .and_then(Value::as_object)
            .ok_or(RunnerError::InvalidToolOutput)?,
        inputs,
    )?;
    let results = object
        .get("results")
        .and_then(Value::as_array)
        .ok_or(RunnerError::InvalidToolOutput)?;
    let mut identities = BTreeSet::new();
    let mut canaries = BTreeSet::new();
    let mut findings = Vec::new();
    for result in results {
        let result_object = result.as_object().ok_or(RunnerError::InvalidToolOutput)?;
        match validate_semgrep_result(result_object, &expected, &mut identities)? {
            SemgrepResultKind::Canary(path) => {
                if !canaries.insert(path) {
                    return invalid();
                }
            }
            SemgrepResultKind::Finding => findings.push(result.clone()),
        }
    }
    if !canaries.is_empty() && canaries != expected {
        return invalid();
    }
    let paths = object
        .get("paths")
        .and_then(Value::as_object)
        .ok_or(RunnerError::InvalidToolOutput)?;
    if !(exact_keys(paths, &["scanned"])
        || (exact_keys(paths, &["scanned", "skipped"]) && empty_array(paths.get("skipped"))))
    {
        return invalid();
    }
    let scanned_values = paths
        .get("scanned")
        .and_then(Value::as_array)
        .ok_or(RunnerError::InvalidToolOutput)?;
    let mut scanned = BTreeSet::new();
    for value in scanned_values {
        let path = scanner_path(value.as_str().ok_or(RunnerError::InvalidToolOutput)?)?;
        if !scanned.insert(path) {
            return invalid();
        }
    }
    let exact_scanned = scanned == expected && scanned_values.len() == expected.len();
    let canary_coverage = scanned.is_empty() && scanned_values.is_empty() && canaries == expected;
    if !exact_scanned && !canary_coverage {
        return invalid();
    }
    let count = u32::try_from(findings.len()).map_err(|_| RunnerError::LimitExceeded)?;
    let disposition = match (exit, count, canaries.is_empty()) {
        (0, 0, true) | (1, 0, false) => RunDisposition::Clean,
        (1, count, _) if count > 0 => RunDisposition::Findings(count),
        _ => return invalid(),
    };
    if !canaries.is_empty() {
        report["results"] = Value::Array(findings);
    }
    Ok((
        disposition,
        serde_json::to_vec(&report).map_err(|_| RunnerError::InvalidToolOutput)?,
    ))
}

pub fn classify_semgrep_invalid_output(
    exit: i32,
    stdout: &[u8],
    stderr: &[u8],
    inputs: &[ContentFrame],
) -> Option<&'static str> {
    if validate_semgrep_report(exit, stdout, stderr, inputs).is_ok() {
        return None;
    }
    if !matches!(exit, 0 | 1) {
        return Some("exit");
    }

    let canonical_warning = format!("[0.0][WARNING]: {SEMGREP_WARNING}\n");
    let report_is_valid =
        validate_semgrep_report(exit, stdout, canonical_warning.as_bytes(), inputs).is_ok();
    let crlf_warning = stderr
        .strip_suffix(b"\r\n")
        .map(|line| [line, b"\n"].concat())
        .is_some_and(|warning| valid_semgrep_warning(&warning));

    match (valid_semgrep_warning(stderr), crlf_warning, report_is_valid) {
        (true, _, false) => Some(semgrep_report_boundary(exit, stdout, inputs)),
        (false, true, true) => Some("stderr-crlf"),
        (false, true, false) => Some(match semgrep_report_boundary(exit, stdout, inputs) {
            "json" => "stderr-crlf-report-json",
            "envelope" => "stderr-crlf-report-envelope",
            "time" => "stderr-crlf-report-time",
            "paths" => "stderr-crlf-report-paths",
            "results" => "stderr-crlf-report-results",
            "disposition" => "stderr-crlf-report-disposition",
            _ => "stderr-crlf-and-report",
        }),
        (false, false, true) => Some("stderr"),
        (false, false, false) => Some("stderr-and-report"),
        (true, _, true) => None,
    }
}

fn semgrep_report_boundary(exit: i32, stdout: &[u8], inputs: &[ContentFrame]) -> &'static str {
    let Ok(report) = serde_json::from_slice::<Value>(stdout) else {
        return "json";
    };
    let Some(object) = report.as_object() else {
        return "json";
    };
    if !exact_keys(object, &SEMGREP_KEYS)
        || object.get("version").and_then(Value::as_str) != Some("1.170.0")
        || object.get("engine_requested").and_then(Value::as_str) != Some("OSS")
        || !empty_array(object.get("errors"))
        || !empty_array(object.get("skipped_rules"))
        || !empty_array(object.get("profiling_results"))
    {
        return "envelope";
    }
    let Some(time) = object.get("time").and_then(Value::as_object) else {
        return "time-shape";
    };
    if validate_semgrep_time(time, inputs).is_err() {
        return semgrep_time_boundary(time, inputs);
    }
    let expected = inputs
        .iter()
        .map(|input| input.path().as_str().to_owned())
        .collect::<BTreeSet<_>>();
    if let Some(boundary) = semgrep_paths_boundary(object, &expected) {
        return boundary;
    }
    let Some(results) = object.get("results").and_then(Value::as_array) else {
        return "results";
    };
    let mut identities = BTreeSet::new();
    if results.iter().any(|result| {
        result.as_object().is_none_or(|result| {
            validate_semgrep_result(result, &expected, &mut identities).is_err()
        })
    }) {
        return "results";
    }
    match (exit, results.len()) {
        (0, 0) | (1, 1..) => "valid",
        _ => "disposition",
    }
}

fn semgrep_paths_boundary(
    report: &Map<String, Value>,
    expected: &BTreeSet<String>,
) -> Option<&'static str> {
    let Some(paths) = report.get("paths").and_then(Value::as_object) else {
        return Some("paths-shape");
    };
    if !(exact_keys(paths, &["scanned"])
        || (exact_keys(paths, &["scanned", "skipped"]) && empty_array(paths.get("skipped"))))
    {
        return Some(if paths.contains_key("skipped") {
            "paths-skipped"
        } else {
            "paths-shape"
        });
    }
    let Some(scanned_values) = paths.get("scanned").and_then(Value::as_array) else {
        return Some("paths-array");
    };
    let scanned = scanned_values
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or(())
                .and_then(|path| scanner_path(path).map_err(|_| ()))
        })
        .collect::<Result<BTreeSet<_>, _>>();
    let Ok(scanned) = scanned else {
        return Some("paths-value");
    };
    if scanned_values.is_empty() {
        let target_count = report
            .get("time")
            .and_then(Value::as_object)
            .and_then(|time| time.get("targets"))
            .and_then(Value::as_array)
            .map(Vec::len);
        return Some(match target_count {
            Some(0) => "paths-empty-time-empty",
            Some(count) if count == expected.len() => "paths-empty-time-complete",
            _ => "paths-empty-time-other",
        });
    }
    if scanned_values.len() != expected.len() {
        return Some("paths-count");
    }
    (scanned != *expected).then_some("paths-set")
}

fn semgrep_time_boundary(time: &Map<String, Value>, inputs: &[ContentFrame]) -> &'static str {
    const KEYS: [&str; 12] = [
        "rules",
        "rules_parse_time",
        "profiling_times",
        "parsing_time",
        "scanning_time",
        "matching_time",
        "tainting_time",
        "fixpoint_timeouts",
        "prefiltering",
        "targets",
        "total_bytes",
        "max_memory_bytes",
    ];
    if !time.keys().all(|key| KEYS.contains(&key.as_str()))
        || ![
            "rules",
            "rules_parse_time",
            "profiling_times",
            "targets",
            "total_bytes",
        ]
        .iter()
        .all(|key| time.contains_key(*key))
    {
        return "time-shape";
    }
    match time.get("rules").and_then(Value::as_array) {
        Some(rules) if rules.len() > 1 => return "time-rules-multiple",
        Some(rules) if rules.is_empty() => {}
        Some(rules) if rules[0].as_str().is_none() => return "time-rules-non-string",
        Some(rules) if !valid_semgrep_rule_id(rules[0].as_str()) => {
            return "time-rules-other-one";
        }
        Some(_) => {}
        None => return "time-rules-non-array",
    }
    if !time
        .get("fixpoint_timeouts")
        .is_none_or(|value| empty_array(Some(value)))
    {
        return "time-fixpoints";
    }
    if !nonnegative_number(time.get("rules_parse_time")) {
        return "time-rules-parse";
    }
    if !time
        .get("max_memory_bytes")
        .is_none_or(|value| value.as_u64().is_some())
    {
        return "time-max-memory";
    }
    if !empty_object(time.get("profiling_times")) {
        return "time-profiling";
    }
    if validate_semgrep_targets(time, inputs).is_err() {
        return semgrep_targets_boundary(time, inputs);
    }
    for (key, average_key, slow_key, label) in [
        (
            "parsing_time",
            "per_file_time",
            "very_slow_files",
            "time-parsing",
        ),
        (
            "scanning_time",
            "per_file_time",
            "very_slow_files",
            "time-scanning",
        ),
        (
            "matching_time",
            "per_file_and_rule_time",
            "very_slow_rules_on_files",
            "time-matching",
        ),
        (
            "tainting_time",
            "per_def_and_rule_time",
            "very_slow_rules_on_defs",
            "time-tainting",
        ),
    ] {
        if time
            .get(key)
            .is_some_and(|value| validate_file_timing(Some(value), average_key, slow_key).is_err())
        {
            return label;
        }
    }
    "time-prefiltering"
}

fn semgrep_targets_boundary(time: &Map<String, Value>, inputs: &[ContentFrame]) -> &'static str {
    let expected = inputs
        .iter()
        .filter_map(|input| {
            u64::try_from(input.bytes().len())
                .ok()
                .map(|size| (input.path().as_str().to_owned(), size))
        })
        .collect::<BTreeMap<_, _>>();
    if expected.len() != inputs.len() {
        return "time-targets-inputs";
    }
    if time.get("total_bytes").and_then(Value::as_u64).is_none() {
        return "time-targets-total";
    }
    let Some(targets) = time.get("targets").and_then(Value::as_array) else {
        return "time-targets-array";
    };
    let rule_count = time
        .get("rules")
        .and_then(Value::as_array)
        .map_or(usize::MAX, Vec::len);
    let mut seen = BTreeSet::new();
    for target in targets {
        let Some(target) = target.as_object() else {
            return "time-targets-shape";
        };
        if !exact_keys(
            target,
            &[
                "path",
                "num_bytes",
                "match_times",
                "parse_times",
                "run_time",
            ],
        ) {
            return "time-targets-shape";
        }
        if !nonnegative_number(target.get("run_time")) {
            return "time-targets-run";
        }
        if !nonnegative_numbers(target.get("match_times"), rule_count)
            || !nonnegative_numbers(target.get("parse_times"), rule_count)
        {
            return "time-targets-timing";
        }
        let Some(path) = target
            .get("path")
            .and_then(Value::as_str)
            .and_then(|path| scanner_path(path).ok())
        else {
            return "time-targets-path";
        };
        let Some(expected_size) = expected.get(&path) else {
            return "time-targets-path";
        };
        if target.get("num_bytes").and_then(Value::as_u64) != Some(*expected_size) {
            return "time-targets-size";
        }
        if !seen.insert(path) {
            return "time-targets-duplicate";
        }
    }
    "time-targets-other"
}

pub fn classify_semgrep_exit_details(stdout: &[u8], stderr: &[u8]) -> (&'static str, String) {
    let report_kind = serde_json::from_slice::<Value>(stdout)
        .ok()
        .and_then(|report| report.get("errors")?.as_array().cloned())
        .map(|errors| {
            let has = |expected| {
                errors
                    .iter()
                    .any(|error| error.get("type").and_then(Value::as_str) == Some(expected))
            };
            if has("Timeout") || has("Timeout during interfile analysis") {
                "report-timeout"
            } else if has("Out of memory") || has("OOM during interfile analysis") {
                "report-out-of-memory"
            } else if has("Stack overflow") {
                "report-stack-overflow"
            } else if has("Fatal error") {
                "report-fatal"
            } else if errors.is_empty() {
                "report-no-errors"
            } else {
                "report-other-error"
            }
        })
        .unwrap_or("report-no-json");

    let stderr = std::str::from_utf8(stderr)
        .unwrap_or("")
        .to_ascii_lowercase();
    let exception_constructor = ["error: exception ", "exception: ", "executor pool job: "]
        .iter()
        .find_map(|marker| {
            let (_, tail) = stderr.split_once(marker)?;
            let constructor = &tail[..tail
                .find(|character: char| {
                    !character.is_ascii_alphanumeric() && !matches!(character, '_' | '.')
                })
                .unwrap_or(tail.len())];
            (!constructor.is_empty()
                && constructor.len() <= 64
                && constructor
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.')))
            .then_some(constructor)
        });
    let permission_denied = ["permission denied", "access is denied", "eacces"]
        .iter()
        .any(|needle| stderr.contains(needle));
    let stderr_kind = if permission_denied && stderr.contains("nul") {
        "stderr-permission-denied-nul"
    } else if permission_denied {
        "stderr-permission-denied"
    } else if ["no such file", "not found", "enoent"]
        .iter()
        .any(|needle| stderr.contains(needle))
    {
        "stderr-not-found"
    } else if ["invalid argument", "einval"]
        .iter()
        .any(|needle| stderr.contains(needle))
    {
        "stderr-invalid-argument"
    } else if stderr.contains("timeout") {
        "stderr-timeout"
    } else if stderr.contains("out of memory") {
        "stderr-out-of-memory"
    } else if stderr.contains("stack overflow") {
        "stderr-stack-overflow"
    } else if stderr.contains("exception unix.unix_error(unix.ebadf")
        || stderr.contains("unix_error: bad file descriptor")
    {
        "stderr-unix-ebadf"
    } else if stderr.contains("exception unix.unix_error(unix.epipe")
        || stderr.contains("unix_error: broken pipe")
    {
        "stderr-unix-epipe"
    } else if stderr.contains("exception unix.unix_error(unix.eio")
        || stderr.contains("unix_error: input/output error")
        || stderr.contains("unix_error: i/o error")
    {
        "stderr-unix-eio"
    } else if stderr.contains("exception unix.unix_error(unix.eintr")
        || stderr.contains("unix_error: interrupted system call")
    {
        "stderr-unix-eintr"
    } else if stderr.contains("exception unix.unix_error(unix.eagain")
        || stderr.contains("exception unix.unix_error(unix.ewouldblock")
        || stderr.contains("unix_error: resource temporarily unavailable")
        || stderr.contains("unix_error: operation would block")
    {
        "stderr-unix-retry"
    } else if stderr.contains("exception unix.unix_error(unix.enosys")
        || stderr.contains("unix_error: function not implemented")
    {
        "stderr-unix-enosys"
    } else if stderr.contains("exception unix.unix_error(unix.eunknownerr 5")
        || stderr.contains("unix_error: unknown error 5")
    {
        "stderr-unix-unknown-5"
    } else if stderr.contains("exception unix.unix_error(") || stderr.contains("unix_error:") {
        "stderr-unix-other"
    } else if stderr.contains("exception sys_error(") {
        "stderr-sys-error"
    } else if stderr.contains("exception end_of_file") {
        "stderr-end-of-file"
    } else if stderr.contains("exception not_found") {
        "stderr-not-found-exception"
    } else if stderr.contains("exception eio.cancel.cancelled") {
        "stderr-cancelled"
    } else if stderr.contains("exception exception.timeout")
        || stderr.contains("exception time_limit.timeout")
    {
        "stderr-timeout-exception"
    } else if let Some(constructor) = exception_constructor {
        return (report_kind, format!("stderr-exception-{constructor}"));
    } else if stderr.contains("exception") {
        "stderr-other-exception"
    } else if stderr.is_empty() {
        "stderr-empty"
    } else {
        "stderr-other"
    };
    (report_kind, stderr_kind.to_owned())
}

pub fn validate_rulesync_outputs(
    command: &SidecarCommand,
    inputs: &[ContentFrame],
    outputs: &[ContentFrame],
) -> Result<(), RunnerError> {
    let SidecarCommand::RuleSyncGenerate { target, features } = command else {
        return Err(RunnerError::InvalidCommand);
    };
    command.validate_inputs(inputs)?;
    let mut expected = BTreeSet::new();
    for input in inputs {
        let relative = input
            .path()
            .as_str()
            .strip_prefix("input/.rulesync/")
            .ok_or(RunnerError::InvalidToolOutput)?;
        match (target, rulesync_input_feature(relative)?) {
            (RuleSyncTarget::ClaudeCode, RuleSyncFeature::Rules) => {
                let child = relative
                    .strip_prefix("rules/")
                    .ok_or(RunnerError::InvalidToolOutput)?;
                if child == "overview.md" {
                    expected.insert("output/CLAUDE.md".to_owned());
                } else {
                    expected.insert(format!("output/.claude/rules/{child}"));
                }
            }
            (RuleSyncTarget::CodexCli, RuleSyncFeature::Rules) => {
                expected.insert("output/AGENTS.md".to_owned());
            }
            (RuleSyncTarget::ClaudeCode, RuleSyncFeature::Commands) => {
                expected.insert(format!(
                    "output/.claude/commands/{}",
                    relative
                        .strip_prefix("commands/")
                        .ok_or(RunnerError::InvalidToolOutput)?
                ));
            }
            (RuleSyncTarget::CodexCli, RuleSyncFeature::Commands) => {
                expected.insert(format!(
                    "output/.codex/prompts/{}",
                    relative
                        .strip_prefix("commands/")
                        .ok_or(RunnerError::InvalidToolOutput)?
                ));
            }
            (RuleSyncTarget::ClaudeCode, RuleSyncFeature::Subagents) => {
                expected.insert(format!(
                    "output/.claude/agents/{}",
                    relative
                        .strip_prefix("subagents/")
                        .ok_or(RunnerError::InvalidToolOutput)?
                ));
            }
            (RuleSyncTarget::CodexCli, RuleSyncFeature::Subagents) => {
                let source = relative
                    .strip_prefix("subagents/")
                    .ok_or(RunnerError::InvalidToolOutput)?;
                expected.insert(format!(
                    "output/.codex/agents/{}.toml",
                    source
                        .strip_suffix(".md")
                        .ok_or(RunnerError::InvalidToolOutput)?
                ));
            }
            (RuleSyncTarget::ClaudeCode, RuleSyncFeature::Skills) => {
                expected.insert(format!(
                    "output/.claude/skills/{}",
                    relative
                        .strip_prefix("skills/")
                        .ok_or(RunnerError::InvalidToolOutput)?
                ));
            }
            (RuleSyncTarget::CodexCli, RuleSyncFeature::Skills) => {
                expected.insert(format!(
                    "output/.agents/skills/{}",
                    relative
                        .strip_prefix("skills/")
                        .ok_or(RunnerError::InvalidToolOutput)?
                ));
            }
            (RuleSyncTarget::ClaudeCode, RuleSyncFeature::Mcp) => {
                expected.insert("output/.mcp.json".to_owned());
            }
            (RuleSyncTarget::CodexCli, RuleSyncFeature::Mcp) => {
                expected.insert("output/.codex/config.toml".to_owned());
            }
            (RuleSyncTarget::ClaudeCode, RuleSyncFeature::Hooks) => {
                expected.insert("output/.claude/settings.json".to_owned());
            }
            (RuleSyncTarget::CodexCli, RuleSyncFeature::Hooks) => {
                expected.insert("output/.codex/hooks.json".to_owned());
            }
            (
                RuleSyncTarget::ClaudeCode,
                RuleSyncFeature::Permissions | RuleSyncFeature::Ignore,
            ) => {
                expected.insert("output/.claude/settings.json".to_owned());
            }
            (RuleSyncTarget::CodexCli, RuleSyncFeature::Permissions) => {
                expected.insert("output/.codex/config.toml".to_owned());
                if has_nonempty_bash_permissions(input.bytes())? {
                    expected.insert("output/.codex/rules/rulesync.rules".to_owned());
                }
            }
            (_, RuleSyncFeature::Checks | RuleSyncFeature::Ignore) => {
                return Err(RunnerError::InvalidToolOutput);
            }
        }
    }
    let actual = outputs
        .iter()
        .map(|output| {
            if output.bytes().is_empty() || std::str::from_utf8(output.bytes()).is_err() {
                return Err(RunnerError::InvalidToolOutput);
            }
            let path = output.path().as_str();
            if path.ends_with(".json") {
                let value: Value = serde_json::from_slice(output.bytes())
                    .map_err(|_| RunnerError::InvalidToolOutput)?;
                if !value.is_object() {
                    return Err(RunnerError::InvalidToolOutput);
                }
            }
            Ok(path.to_owned())
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if actual != expected || outputs.len() != expected.len() || features.bits() == 0 {
        return invalid();
    }
    Ok(())
}

fn validate_gitleaks_diagnostics(
    stderr: &[u8],
    expected_bytes: u64,
    disposition: RunDisposition,
) -> Result<(), RunnerError> {
    let text = std::str::from_utf8(stderr).map_err(|_| RunnerError::InvalidToolOutput)?;
    if !text.ends_with('\n') || text.replace("\r\n", "\n").contains('\r') {
        return invalid();
    }
    let normalized = text.replace("\r\n", "\n");
    let lines = normalized
        .trim_end_matches('\n')
        .split('\n')
        .collect::<Vec<_>>();
    if lines.len() != 2 {
        return invalid();
    }
    let first = diagnostic_body(lines[0], "INF")?;
    let prefix = format!("scanned ~{expected_bytes} bytes (");
    let remainder = first
        .strip_prefix(&prefix)
        .and_then(|value| value.split_once(") in "))
        .ok_or(RunnerError::InvalidToolOutput)?;
    if !valid_human_size(remainder.0) || !valid_duration(remainder.1) {
        return invalid();
    }
    match disposition {
        RunDisposition::Clean if diagnostic_body(lines[1], "INF")? == "no leaks found" => Ok(()),
        RunDisposition::Findings(count)
            if diagnostic_body(lines[1], "WRN")? == format!("leaks found: {count}") =>
        {
            Ok(())
        }
        _ => invalid(),
    }
}

fn diagnostic_body<'a>(line: &'a str, level: &str) -> Result<&'a str, RunnerError> {
    let (timestamp, rest) = line.split_once(' ').ok_or(RunnerError::InvalidToolOutput)?;
    if !valid_timestamp(timestamp) {
        return invalid();
    }
    rest.strip_prefix(&format!("{level} "))
        .ok_or(RunnerError::InvalidToolOutput)
}

fn valid_timestamp(value: &str) -> bool {
    let (clock, suffix) = value.split_at(value.len().saturating_sub(2));
    if !matches!(suffix, "AM" | "PM") {
        return false;
    }
    let Some((hour, minute)) = clock.split_once(':') else {
        return false;
    };
    hour.parse::<u8>()
        .is_ok_and(|value| (1..=12).contains(&value))
        && minute.len() == 2
        && minute.parse::<u8>().is_ok_and(|value| value < 60)
}

fn valid_human_size(value: &str) -> bool {
    value.split_once(' ').is_some_and(|(number, unit)| {
        number
            .parse::<f64>()
            .is_ok_and(|value| value.is_finite() && value >= 0.0)
            && matches!(unit, "bytes" | "KB" | "MB" | "GB" | "TB")
    })
}

fn valid_duration(value: &str) -> bool {
    let boundary = value
        .find(|character: char| !character.is_ascii_digit() && character != '.')
        .unwrap_or(value.len());
    let (number, unit) = value.split_at(boundary);
    number
        .parse::<f64>()
        .is_ok_and(|value| value.is_finite() && value >= 0.0)
        && matches!(unit, "ns" | "us" | "µs" | "ms" | "s")
}

fn valid_semgrep_warning(stderr: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(stderr) else {
        return false;
    };
    let Some(line) = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
    else {
        return false;
    };
    if line.contains('\n') || line.contains('\r') {
        return false;
    }
    let Some(rest) = line.strip_prefix('[') else {
        return false;
    };
    let Some((timing, message)) = rest.split_once("][WARNING]: ") else {
        return false;
    };
    timing.matches('.').count() == 1
        && timing
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
        && message == SEMGREP_WARNING
}

enum SemgrepResultKind {
    Canary(String),
    Finding,
}

fn validate_semgrep_result(
    result: &Map<String, Value>,
    expected_paths: &BTreeSet<String>,
    identities: &mut BTreeSet<String>,
) -> Result<SemgrepResultKind, RunnerError> {
    if !exact_keys(result, &["check_id", "path", "start", "end", "extra"]) {
        return invalid();
    }
    let rule_id = result
        .get("check_id")
        .and_then(Value::as_str)
        .filter(|value| valid_semgrep_rule_id(Some(value)))
        .ok_or(RunnerError::InvalidToolOutput)?;
    let path = scanner_path(
        result
            .get("path")
            .and_then(Value::as_str)
            .ok_or(RunnerError::InvalidToolOutput)?,
    )?;
    if !expected_paths.contains(&path) {
        return invalid();
    }
    let start = semgrep_position(
        result
            .get("start")
            .and_then(Value::as_object)
            .ok_or(RunnerError::InvalidToolOutput)?,
    )?;
    let end = semgrep_position(
        result
            .get("end")
            .and_then(Value::as_object)
            .ok_or(RunnerError::InvalidToolOutput)?,
    )?;
    if end < start {
        return invalid();
    }
    let extra = result
        .get("extra")
        .and_then(Value::as_object)
        .ok_or(RunnerError::InvalidToolOutput)?;
    let is_canary = matches!(
        rule_id,
        SEMGREP_CANARY_RULE_ID | SEMGREP_BARE_CANARY_RULE_ID
    );
    if !exact_keys(
        extra,
        &[
            "message",
            "metadata",
            "severity",
            "fingerprint",
            "lines",
            "validation_state",
            "engine_kind",
        ],
    ) || extra.get("message").and_then(Value::as_str)
        != Some(if is_canary {
            "Context Relay scan coverage canary."
        } else {
            "Native Semgrep packages must not contain Pysemgrep or a Python runtime."
        })
        || !extra
            .get("metadata")
            .and_then(Value::as_object)
            .is_some_and(Map::is_empty)
        || extra.get("severity").and_then(Value::as_str)
            != Some(if is_canary { "INFO" } else { "ERROR" })
        || extra.get("fingerprint").and_then(Value::as_str) != Some("requires login")
        || extra.get("lines").and_then(Value::as_str) != Some("requires login")
        || extra.get("validation_state").and_then(Value::as_str) != Some("NO_VALIDATOR")
        || extra.get("engine_kind").and_then(Value::as_str) != Some("OSS")
    {
        return invalid();
    }
    if is_canary {
        return (start == (1, 1, 0) && end > start)
            .then_some(SemgrepResultKind::Canary(path))
            .ok_or(RunnerError::InvalidToolOutput);
    }
    let identity = format!(
        "{}:{path}:{}:{}:{}:{}:{}:{}",
        SEMGREP_RULE_ID, start.0, start.1, start.2, end.0, end.1, end.2
    );
    identities
        .insert(identity)
        .then_some(SemgrepResultKind::Finding)
        .ok_or(RunnerError::InvalidToolOutput)
}

fn semgrep_position(position: &Map<String, Value>) -> Result<(u64, u64, u64), RunnerError> {
    if !exact_keys(position, &["line", "col", "offset"]) {
        return invalid();
    }
    let line = positive_integer(position, "line")?;
    let column = positive_integer(position, "col")?;
    let offset = position
        .get("offset")
        .and_then(Value::as_u64)
        .ok_or(RunnerError::InvalidToolOutput)?;
    Ok((line, column, offset))
}

fn validate_semgrep_time(
    time: &Map<String, Value>,
    inputs: &[ContentFrame],
) -> Result<(), RunnerError> {
    const KEYS: [&str; 12] = [
        "rules",
        "rules_parse_time",
        "profiling_times",
        "parsing_time",
        "scanning_time",
        "matching_time",
        "tainting_time",
        "fixpoint_timeouts",
        "prefiltering",
        "targets",
        "total_bytes",
        "max_memory_bytes",
    ];
    if !time.keys().all(|key| KEYS.contains(&key.as_str()))
        || ![
            "rules",
            "rules_parse_time",
            "profiling_times",
            "targets",
            "total_bytes",
        ]
        .iter()
        .all(|key| time.contains_key(*key))
        || !time
            .get("rules")
            .and_then(Value::as_array)
            .is_some_and(|rules| {
                rules.len() <= 2
                    && rules
                        .iter()
                        .all(|rule| valid_semgrep_rule_id(rule.as_str()))
                    && rules
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<BTreeSet<_>>()
                        .len()
                        == rules.len()
            })
        || !time
            .get("fixpoint_timeouts")
            .is_none_or(|value| empty_array(Some(value)))
        || !nonnegative_number(time.get("rules_parse_time"))
        || !time
            .get("max_memory_bytes")
            .is_none_or(|value| value.as_u64().is_some())
        || !empty_object(time.get("profiling_times"))
    {
        return invalid();
    }
    validate_semgrep_targets(time, inputs)?;
    for (key, average_key, slow_key) in [
        ("parsing_time", "per_file_time", "very_slow_files"),
        ("scanning_time", "per_file_time", "very_slow_files"),
        (
            "matching_time",
            "per_file_and_rule_time",
            "very_slow_rules_on_files",
        ),
        (
            "tainting_time",
            "per_def_and_rule_time",
            "very_slow_rules_on_defs",
        ),
    ] {
        if let Some(value) = time.get(key) {
            validate_file_timing(Some(value), average_key, slow_key)?;
        }
    }
    if let Some(prefiltering) = time.get("prefiltering") {
        let prefiltering = prefiltering
            .as_object()
            .ok_or(RunnerError::InvalidToolOutput)?;
        if !exact_keys(
            prefiltering,
            &[
                "project_level_time",
                "file_level_time",
                "rules_with_project_prefilters_ratio",
                "rules_with_file_prefilters_ratio",
                "rules_selected_ratio",
                "rules_matched_ratio",
            ],
        ) || !prefiltering
            .values()
            .all(|value| nonnegative_number(Some(value)))
        {
            return invalid();
        }
    }
    Ok(())
}

fn validate_semgrep_targets(
    time: &Map<String, Value>,
    inputs: &[ContentFrame],
) -> Result<(), RunnerError> {
    let rule_count = time
        .get("rules")
        .and_then(Value::as_array)
        .ok_or(RunnerError::InvalidToolOutput)?
        .len();
    let expected = inputs
        .iter()
        .map(|input| {
            (
                input.path().as_str().to_owned(),
                u64::try_from(input.bytes().len()).map_err(|_| RunnerError::LimitExceeded),
            )
        })
        .map(|(path, size)| size.map(|size| (path, size)))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    if expected.len() != inputs.len() {
        return invalid();
    }
    if time.get("total_bytes").and_then(Value::as_u64).is_none() {
        return invalid();
    }
    let targets = time
        .get("targets")
        .and_then(Value::as_array)
        .ok_or(RunnerError::InvalidToolOutput)?;
    let mut seen = BTreeSet::new();
    for target in targets {
        let target = target.as_object().ok_or(RunnerError::InvalidToolOutput)?;
        if !exact_keys(
            target,
            &[
                "path",
                "num_bytes",
                "match_times",
                "parse_times",
                "run_time",
            ],
        ) || !nonnegative_number(target.get("run_time"))
            || !nonnegative_numbers(target.get("match_times"), rule_count)
            || !nonnegative_numbers(target.get("parse_times"), rule_count)
        {
            return invalid();
        }
        let path = scanner_path(
            target
                .get("path")
                .and_then(Value::as_str)
                .ok_or(RunnerError::InvalidToolOutput)?,
        )?;
        let Some(expected_size) = expected.get(&path) else {
            return invalid();
        };
        if target.get("num_bytes").and_then(Value::as_u64) != Some(*expected_size)
            || !seen.insert(path)
        {
            return invalid();
        }
    }
    Ok(())
}

fn nonnegative_numbers(value: Option<&Value>, expected_len: usize) -> bool {
    value.and_then(Value::as_array).is_some_and(|values| {
        (values.len() == expected_len || (expected_len == 0 && values.len() == 1))
            && values.iter().all(|value| nonnegative_number(Some(value)))
    })
}

fn validate_file_timing(
    value: Option<&Value>,
    average_key: &str,
    slow_key: &str,
) -> Result<(), RunnerError> {
    let object = value
        .and_then(Value::as_object)
        .ok_or(RunnerError::InvalidToolOutput)?;
    if !exact_keys(
        object,
        &["total_time", average_key, "very_slow_stats", slow_key],
    ) || !nonnegative_number(object.get("total_time"))
        || !empty_array(object.get(slow_key))
    {
        return invalid();
    }
    for key in [average_key, "very_slow_stats"] {
        let pair = object
            .get(key)
            .and_then(Value::as_object)
            .ok_or(RunnerError::InvalidToolOutput)?;
        let keys = if key == average_key {
            ["mean", "std_dev"]
        } else {
            ["time_ratio", "count_ratio"]
        };
        if !exact_keys(pair, &keys) || !pair.values().all(|value| nonnegative_number(Some(value))) {
            return invalid();
        }
    }
    Ok(())
}

fn scanner_path(value: &str) -> Result<String, RunnerError> {
    let normalized = value.replace('\\', "/");
    let path = normalized.strip_prefix("./").unwrap_or(&normalized);
    StagePath::try_from(path)
        .map(|path| path.as_str().to_owned())
        .map_err(|_| RunnerError::InvalidToolOutput)
}

fn valid_semgrep_rule_id(value: Option<&str>) -> bool {
    matches!(
        value,
        Some(
            SEMGREP_RULE_ID
                | SEMGREP_BARE_RULE_ID
                | SEMGREP_CANARY_RULE_ID
                | SEMGREP_BARE_CANARY_RULE_ID
        )
    )
}

fn has_nonempty_bash_permissions(bytes: &[u8]) -> Result<bool, RunnerError> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| RunnerError::InvalidToolOutput)?;
    Ok(value
        .get("permission")
        .and_then(|value| value.get("bash"))
        .and_then(Value::as_object)
        .is_some_and(|value| !value.is_empty()))
}

fn exact_keys(object: &Map<String, Value>, keys: &[&str]) -> bool {
    object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
}

fn empty_array(value: Option<&Value>) -> bool {
    value.and_then(Value::as_array).is_some_and(Vec::is_empty)
}

fn empty_object(value: Option<&Value>) -> bool {
    value.and_then(Value::as_object).is_some_and(Map::is_empty)
}

fn nonnegative_number(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_f64)
        .is_some_and(|value| value.is_finite() && value >= 0.0)
}

fn nonempty_string(object: &Map<String, Value>, key: &str) -> bool {
    object
        .get(key)
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty())
}

fn empty_strings(object: &Map<String, Value>, keys: &[&str]) -> bool {
    keys.iter()
        .all(|key| object.get(*key).and_then(Value::as_str) == Some(""))
}

fn positive_integer(object: &Map<String, Value>, key: &str) -> Result<u64, RunnerError> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .ok_or(RunnerError::InvalidToolOutput)
}

fn invalid<T>() -> Result<T, RunnerError> {
    Err(RunnerError::InvalidToolOutput)
}
