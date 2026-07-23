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
        return Err(semgrep_validation_error(0));
    }
    let report: Value = serde_json::from_slice(stdout).map_err(|_| semgrep_validation_error(1))?;
    let object = report
        .as_object()
        .ok_or_else(|| semgrep_validation_error(1))?;
    if !exact_keys(object, &SEMGREP_KEYS)
        || object.get("version").and_then(Value::as_str) != Some("1.170.0")
        || object.get("engine_requested").and_then(Value::as_str) != Some("OSS")
        || !empty_array(object.get("errors"))
        || !empty_array(object.get("skipped_rules"))
        || !empty_array(object.get("profiling_results"))
    {
        return Err(semgrep_validation_error(1));
    }
    let expected = inputs
        .iter()
        .map(|input| input.path().as_str().to_owned())
        .collect::<BTreeSet<_>>();
    validate_semgrep_time(
        object
            .get("time")
            .and_then(Value::as_object)
            .ok_or_else(|| semgrep_validation_error(2))?,
        inputs,
    )
    .map_err(|_| semgrep_validation_error(2))?;
    let paths = object
        .get("paths")
        .and_then(Value::as_object)
        .ok_or_else(|| semgrep_validation_error(3))?;
    if !(exact_keys(paths, &["scanned"])
        || (exact_keys(paths, &["scanned", "skipped"]) && empty_array(paths.get("skipped"))))
    {
        return Err(semgrep_validation_error(3));
    }
    let scanned_values = paths
        .get("scanned")
        .and_then(Value::as_array)
        .ok_or_else(|| semgrep_validation_error(3))?;
    let mut scanned = BTreeSet::new();
    for value in scanned_values {
        let path = scanner_path(value.as_str().ok_or_else(|| semgrep_validation_error(3))?)
            .map_err(|_| semgrep_validation_error(3))?;
        if !scanned.insert(path) {
            return Err(semgrep_validation_error(3));
        }
    }
    if scanned != expected || scanned_values.len() != expected.len() {
        return Err(semgrep_validation_error(3));
    }
    let results = object
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| semgrep_validation_error(4))?;
    let mut identities = BTreeSet::new();
    for result in results {
        validate_semgrep_result(
            result
                .as_object()
                .ok_or_else(|| semgrep_validation_error(4))?,
            &expected,
            &mut identities,
        )
        .map_err(|_| semgrep_validation_error(4))?;
    }
    let count = u32::try_from(results.len()).map_err(|_| semgrep_validation_error(4))?;
    let disposition = match (exit, count) {
        (0, 0) => RunDisposition::Clean,
        (1, count) if count > 0 => RunDisposition::Findings(count),
        _ => return Err(semgrep_validation_error(4)),
    };
    Ok((disposition, stdout.to_vec()))
}

const fn semgrep_validation_error(stage: u8) -> RunnerError {
    #[cfg(feature = "ci-candidate-sidecar-smoke")]
    {
        RunnerError::CiSemgrepValidation(stage)
    }
    #[cfg(not(feature = "ci-candidate-sidecar-smoke"))]
    {
        let _ = stage;
        RunnerError::InvalidToolOutput
    }
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
    let Some(line) = text.strip_suffix('\n') else {
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

fn validate_semgrep_result(
    result: &Map<String, Value>,
    expected_paths: &BTreeSet<String>,
    identities: &mut BTreeSet<String>,
) -> Result<(), RunnerError> {
    if !exact_keys(result, &["check_id", "path", "start", "end", "extra"])
        || result.get("check_id").and_then(Value::as_str) != Some(SEMGREP_RULE_ID)
    {
        return invalid();
    }
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
        != Some("Native Semgrep packages must not contain Pysemgrep or a Python runtime.")
        || !extra
            .get("metadata")
            .and_then(Value::as_object)
            .is_some_and(Map::is_empty)
        || extra.get("severity").and_then(Value::as_str) != Some("ERROR")
        || extra.get("fingerprint").and_then(Value::as_str) != Some("requires login")
        || extra.get("lines").and_then(Value::as_str) != Some("requires login")
        || extra.get("validation_state").and_then(Value::as_str) != Some("NO_VALIDATOR")
        || extra.get("engine_kind").and_then(Value::as_str) != Some("OSS")
    {
        return invalid();
    }
    let identity = format!(
        "{}:{path}:{}:{}:{}:{}:{}:{}",
        SEMGREP_RULE_ID, start.0, start.1, start.2, end.0, end.1, end.2
    );
    identities
        .insert(identity)
        .then_some(())
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
    if !exact_keys(
        time,
        &[
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
        ],
    ) || !time
        .get("rules")
        .and_then(Value::as_array)
        .is_some_and(|rules| rules.len() == 1 && rules[0].as_str() == Some(SEMGREP_RULE_ID))
        || !empty_array(time.get("fixpoint_timeouts"))
        || !nonnegative_number(time.get("rules_parse_time"))
        || !time
            .get("max_memory_bytes")
            .and_then(Value::as_u64)
            .is_some()
        || !empty_object(time.get("profiling_times"))
    {
        return invalid();
    }
    validate_semgrep_targets(time, inputs)?;
    validate_file_timing(time.get("parsing_time"), "per_file_time", "very_slow_files")?;
    validate_file_timing(
        time.get("scanning_time"),
        "per_file_time",
        "very_slow_files",
    )?;
    validate_file_timing(
        time.get("matching_time"),
        "per_file_and_rule_time",
        "very_slow_rules_on_files",
    )?;
    validate_file_timing(
        time.get("tainting_time"),
        "per_def_and_rule_time",
        "very_slow_rules_on_defs",
    )?;
    let prefiltering = time
        .get("prefiltering")
        .and_then(Value::as_object)
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
    Ok(())
}

fn validate_semgrep_targets(
    time: &Map<String, Value>,
    inputs: &[ContentFrame],
) -> Result<(), RunnerError> {
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
    let total_bytes = expected.values().try_fold(0_u64, |total, size| {
        total.checked_add(*size).ok_or(RunnerError::LimitExceeded)
    })?;
    if time.get("total_bytes").and_then(Value::as_u64) != Some(total_bytes) {
        return invalid();
    }
    let targets = time
        .get("targets")
        .and_then(Value::as_array)
        .ok_or(RunnerError::InvalidToolOutput)?;
    if targets.len() != expected.len() {
        return invalid();
    }
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
            || !one_nonnegative_number(target.get("match_times"))
            || !one_nonnegative_number(target.get("parse_times"))
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
    (seen.len() == expected.len())
        .then_some(())
        .ok_or(RunnerError::InvalidToolOutput)
}

fn one_nonnegative_number(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_array)
        .is_some_and(|values| values.len() == 1 && nonnegative_number(values.first()))
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
