use std::collections::BTreeMap;

use context_relay_protocol::{ClientError, MAX_MARKDOWN_BYTES};
use serde_yaml_ng::Value;

use super::invalid;

const MAX_CONFIG_BYTES: usize = 1024 * 1024;
const MAX_DEPTH: usize = 32;
const MAX_COLLECTION_ENTRIES: usize = 256;

#[derive(Clone, Debug)]
pub(super) struct ParsedHermesYaml {
    pub source: Vec<u8>,
    pub value: Value,
    pub patch_index: YamlPatchIndex,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct YamlSpan {
    pub start: usize,
    pub end: usize,
    pub indent: usize,
}

#[derive(Clone, Debug, Default)]
pub(super) struct YamlPatchIndex {
    pub paths: BTreeMap<Vec<String>, YamlSpan>,
}

#[derive(Clone, Debug)]
struct OpenKey {
    path: Vec<String>,
    indent: usize,
    start: usize,
    targeted: bool,
}

pub(super) fn parse_config(bytes: &[u8]) -> Result<ParsedHermesYaml, ClientError> {
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(invalid("Hermes config exceeds the size limit"));
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| invalid("Hermes config is not valid UTF-8"))?;
    scan_physical_lines(text)?;
    let value: Value =
        serde_yaml_ng::from_slice(bytes).map_err(|_| invalid("Hermes config is invalid"))?;
    if !matches!(value, Value::Mapping(_)) {
        return Err(invalid("Hermes config root is not a mapping"));
    }
    validate_value(&value, 0)?;
    let patch_index = build_patch_index(text, &value)?;
    Ok(ParsedHermesYaml {
        source: bytes.to_vec(),
        value,
        patch_index,
    })
}

pub(super) fn topology_supported(parsed: &ParsedHermesYaml) -> bool {
    let Value::Mapping(root) = &parsed.value else {
        return false;
    };
    for key in ["approvals", "command_allowlist", "mcp_servers", "hooks"] {
        if root.contains_key(Value::String(key.to_owned()))
            && !parsed.patch_index.paths.contains_key(&vec![key.to_owned()])
        {
            return false;
        }
    }
    if let Some(Value::Mapping(plugins)) = root.get(Value::String("plugins".to_owned())) {
        for key in ["enabled", "disabled"] {
            if plugins.contains_key(Value::String(key.to_owned()))
                && !parsed
                    .patch_index
                    .paths
                    .contains_key(&vec!["plugins".to_owned(), key.to_owned()])
            {
                return false;
            }
        }
    }
    true
}

pub(super) fn scan_text_secret(bytes: &[u8], safe_location: &str) -> Result<(), ClientError> {
    if bytes.len() > MAX_MARKDOWN_BYTES {
        return Err(path_error(safe_location, "exceeds the size limit"));
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| path_error(safe_location, "is not valid UTF-8"))?;
    let lower = text.to_ascii_lowercase();
    let secret_pattern = contains_structured_secret(text)
        || lower.contains("-----begin private key-----")
        || lower.contains("-----begin rsa private key-----")
        || lower.contains("-----begin openssh private key-----")
        || lower.contains("authorization: bearer ")
        || lower.contains("authorization: basic ")
        || contains_supported_token_prefix(text)
        || contains_url_user_info(text);
    if secret_pattern {
        return Err(path_error(safe_location, "contains secret-like text"));
    }
    Ok(())
}

fn contains_structured_secret(text: &str) -> bool {
    let mut parents = Vec::<(usize, String)>::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(value) = trimmed.strip_prefix('-').map(str::trim) {
            let path = parents
                .iter()
                .map(|(_, part)| part.clone())
                .collect::<Vec<_>>();
            if !value.is_empty() && credential_container(&path) {
                return true;
            }
            continue;
        }
        let Some((key, value)) = trimmed.split_once(':') else {
            continue;
        };
        let indent = line.len() - trimmed.len();
        while parents.last().is_some_and(|(parent, _)| *parent >= indent) {
            parents.pop();
        }
        let key = key.trim_matches(['"', '\'']).trim();
        let mut path = parents
            .iter()
            .map(|(_, part)| part.clone())
            .collect::<Vec<_>>();
        path.push(key.to_owned());
        if !value.trim().is_empty() && (secret_key(key) || credential_container(&path)) {
            return true;
        }
        parents.push((indent, key.to_owned()));
    }
    false
}

pub(super) fn secret_key(key: &str) -> bool {
    matches!(
        normalize_key(key).as_str(),
        "apikey"
            | "token"
            | "password"
            | "secret"
            | "authorization"
            | "cookie"
            | "clientkey"
            | "clientkeypassphrase"
            | "credential"
    )
}

pub(super) fn credential_container(path: &[String]) -> bool {
    path.iter().any(|part| {
        matches!(
            normalize_key(part).as_str(),
            "env"
                | "headers"
                | "httpheaders"
                | "credentials"
                | "channels"
                | "platforms"
                | "gatewayauth"
                | "pairing"
        )
    })
}

pub(super) fn secret_scalar(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("-----begin private key-----")
        || lower.starts_with("bearer ")
        || lower.starts_with("basic ")
        || contains_supported_token_prefix(value)
        || contains_url_user_info(value)
}

pub(super) fn environment_placeholder(value: &str) -> Option<&str> {
    let inner = value.strip_prefix("${")?.strip_suffix('}')?;
    let bytes = inner.as_bytes();
    if !(1..=128).contains(&bytes.len())
        || !(bytes[0] == b'_' || bytes[0].is_ascii_uppercase())
        || !bytes[1..]
            .iter()
            .all(|byte| *byte == b'_' || byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        return None;
    }
    Some(inner)
}

fn scan_physical_lines(text: &str) -> Result<(), ClientError> {
    let mut documents = 0usize;
    for (index, raw) in text.split_inclusive('\n').enumerate() {
        let line = raw.strip_suffix('\n').unwrap_or(raw);
        let line = line.strip_suffix('\r').unwrap_or(line);
        let indentation = line
            .as_bytes()
            .iter()
            .take_while(|byte| matches!(byte, b' ' | b'\t'))
            .copied()
            .collect::<Vec<_>>();
        if indentation.contains(&b'\t') {
            return Err(invalid("Hermes config uses tab indentation"));
        }
        let trimmed = line.trim_start();
        if trimmed.starts_with('%') {
            return Err(invalid("Hermes config directives are not supported"));
        }
        if trimmed == "---" {
            documents += 1;
            if documents > 1 || index != 0 {
                return Err(invalid("Hermes config contains multiple documents"));
            }
        }
        if trimmed == "..." {
            return Err(invalid(
                "Hermes config document terminators are not supported",
            ));
        }
    }
    Ok(())
}

fn validate_value(value: &Value, depth: usize) -> Result<(), ClientError> {
    if depth > MAX_DEPTH {
        return Err(invalid("Hermes config nesting exceeds the limit"));
    }
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
        Value::String(text) => {
            if text.len() > MAX_MARKDOWN_BYTES {
                Err(invalid("Hermes config scalar exceeds the size limit"))
            } else {
                Ok(())
            }
        }
        Value::Sequence(values) => {
            if values.len() > MAX_COLLECTION_ENTRIES {
                return Err(invalid("Hermes config collection exceeds the entry limit"));
            }
            for value in values {
                validate_value(value, depth + 1)?;
            }
            Ok(())
        }
        Value::Mapping(values) => {
            if values.len() > MAX_COLLECTION_ENTRIES {
                return Err(invalid("Hermes config collection exceeds the entry limit"));
            }
            for (key, value) in values {
                let Value::String(key) = key else {
                    return Err(invalid("Hermes config mapping key is not text"));
                };
                if key.len() > MAX_MARKDOWN_BYTES {
                    return Err(invalid("Hermes config key exceeds the size limit"));
                }
                validate_value(value, depth + 1)?;
            }
            Ok(())
        }
        Value::Tagged(_) => Err(invalid("Hermes config tags are not supported")),
    }
}

fn build_patch_index(text: &str, semantic: &Value) -> Result<YamlPatchIndex, ClientError> {
    let mut index = YamlPatchIndex::default();
    let mut open = Vec::<OpenKey>::new();
    let mut offset = 0usize;
    let mut prefix_start = None;

    for raw in text.split_inclusive('\n') {
        let line = raw.strip_suffix('\n').unwrap_or(raw);
        let line = line.strip_suffix('\r').unwrap_or(line);
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            prefix_start.get_or_insert(offset);
            offset += raw.len();
            continue;
        }
        let indent = line.len() - line.trim_start_matches(' ').len();
        let key = parse_block_key(line.trim_start());
        if let Some(key) = key {
            let end = prefix_start.take().unwrap_or(offset);
            close_at_or_above(&mut open, indent, end, &mut index);
            let mut path = open
                .iter()
                .map(|entry| entry.path.last().cloned().unwrap_or_default())
                .collect::<Vec<_>>();
            path.push(key.to_owned());
            let targeted = targeted_path(&path);
            let value_text = line
                .trim_start()
                .split_once(':')
                .map(|(_, value)| value.trim_start())
                .unwrap_or_default();
            if targeted
                && (value_text.starts_with('!')
                    || value_text.starts_with('&')
                    || value_text.starts_with('*')
                    || value_text.starts_with('[')
                    || value_text.starts_with('{')
                    || key == "<<")
            {
                return Err(invalid("Hermes reviewed config topology is ambiguous"));
            }
            open.push(OpenKey {
                path,
                indent,
                start: offset,
                targeted,
            });
        } else {
            let item = line
                .trim_start()
                .strip_prefix('-')
                .map(str::trim_start)
                .unwrap_or_else(|| line.trim_start());
            if open.last().is_some_and(|entry| entry.targeted)
                && matches!(
                    item.as_bytes().first(),
                    Some(b'!' | b'&' | b'*' | b'[' | b'{')
                )
            {
                return Err(invalid("Hermes reviewed config topology is ambiguous"));
            }
            prefix_start = None;
        }
        offset += raw.len();
    }
    close_at_or_above(&mut open, 0, text.len(), &mut index);
    for path in index.paths.keys() {
        if resolve_path(semantic, path).is_none() {
            return Err(invalid("Hermes config patch index is inconsistent"));
        }
    }
    Ok(index)
}

fn close_at_or_above(
    open: &mut Vec<OpenKey>,
    indent: usize,
    end: usize,
    index: &mut YamlPatchIndex,
) {
    while open.last().is_some_and(|entry| entry.indent >= indent) {
        let Some(entry) = open.pop() else {
            break;
        };
        if entry.targeted {
            index.paths.insert(
                entry.path,
                YamlSpan {
                    start: entry.start,
                    end,
                    indent: entry.indent,
                },
            );
        }
    }
}

fn parse_block_key(line: &str) -> Option<&str> {
    if line.starts_with('-') || line.starts_with('?') {
        return None;
    }
    let (key, _) = line.split_once(':')?;
    let key = key.trim();
    if key.is_empty()
        || key.starts_with('"')
        || key.starts_with('\'')
        || key.chars().any(char::is_control)
    {
        return None;
    }
    Some(key)
}

fn targeted_path(path: &[String]) -> bool {
    match path {
        [root, ..] if root == "approvals" || root == "command_allowlist" => true,
        [root, state, ..]
            if root == "plugins" && matches!(state.as_str(), "enabled" | "disabled") =>
        {
            true
        }
        [root, ..] if root == "mcp_servers" || root == "hooks" => true,
        _ => false,
    }
}

fn resolve_path<'a>(mut value: &'a Value, path: &[String]) -> Option<&'a Value> {
    for part in path {
        let Value::Mapping(mapping) = value else {
            return None;
        };
        value = mapping.get(Value::String(part.clone()))?;
    }
    Some(value)
}

fn normalize_key(key: &str) -> String {
    key.chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn contains_supported_token_prefix(value: &str) -> bool {
    value
        .split(|character: char| {
            character.is_ascii_whitespace() || matches!(character, '"' | '\'' | '=' | ':')
        })
        .any(|token| {
            token.starts_with("sk-proj-")
                || token.starts_with("sk-ant-")
                || (token.starts_with("sk-") && token.len() >= 12)
                || token.starts_with("ghp_")
                || token.starts_with("github_pat_")
                || token.starts_with("xoxb-")
                || token.starts_with("xoxp-")
                || token.starts_with("glpat-")
                || token.starts_with("npm_")
                || token.starts_with("hf_")
                || token.starts_with("pypi-AgEIcHlwaS5vcmc")
                || ((token.starts_with("AKIA") || token.starts_with("ASIA")) && token.len() >= 16)
                || token.starts_with("AIza")
        })
}

fn contains_url_user_info(value: &str) -> bool {
    value.split_ascii_whitespace().any(|candidate| {
        candidate.split_once("://").is_some_and(|(_, authority)| {
            authority
                .split(['/', '?', '#'])
                .next()
                .is_some_and(|authority| authority.contains('@'))
        })
    })
}

fn path_error(location: &str, reason: &str) -> ClientError {
    ClientError {
        code: context_relay_protocol::ErrorCode::InvalidRequest,
        message: format!("Hermes reviewed file {location} {reason}"),
        field_path: None,
        retryable: false,
    }
}
