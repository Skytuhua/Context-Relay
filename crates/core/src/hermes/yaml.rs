use std::collections::{BTreeMap, BTreeSet};

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
        if !parsed
            .patch_index
            .paths
            .contains_key(&vec!["plugins".to_owned()])
        {
            return false;
        }
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
        if let (Some(enabled), Some(disabled)) = (
            safe_plugin_names(plugins, "enabled"),
            safe_plugin_names(plugins, "disabled"),
        ) && (enabled.duplicate
            || disabled.duplicate
            || !enabled.names.is_disjoint(&disabled.names))
        {
            return false;
        }
    }
    if let Some(memory) = root.get(Value::String("memory".to_owned())) {
        let Some(memory) = memory.as_mapping() else {
            return false;
        };
        if !parsed
            .patch_index
            .paths
            .contains_key(&vec!["memory".to_owned()])
        {
            return false;
        }
        for key in ["memory_enabled", "user_profile_enabled"] {
            if memory.contains_key(Value::String(key.to_owned()))
                && !parsed
                    .patch_index
                    .paths
                    .contains_key(&vec!["memory".to_owned(), key.to_owned()])
            {
                return false;
            }
        }
    }
    true
}

struct SafePluginNames<'a> {
    names: BTreeSet<&'a str>,
    duplicate: bool,
}

fn safe_plugin_names<'a>(
    plugins: &'a serde_yaml_ng::Mapping,
    state: &str,
) -> Option<SafePluginNames<'a>> {
    let Some(value) = plugins.get(Value::String(state.to_owned())) else {
        return Some(SafePluginNames {
            names: BTreeSet::new(),
            duplicate: false,
        });
    };
    let values = value.as_sequence()?;
    if values.len() > MAX_COLLECTION_ENTRIES {
        return None;
    }
    let mut names = BTreeSet::new();
    let mut duplicate = false;
    for value in values {
        let name = value.as_str().filter(|name| safe_plugin_name(name))?;
        duplicate |= !names.insert(name);
    }
    Some(SafePluginNames { names, duplicate })
}

fn safe_plugin_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=128).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        && !matches!(name, "." | "..")
}

pub(super) fn patch_owned_paths(
    parsed: &ParsedHermesYaml,
    replacements: &BTreeMap<Vec<String>, Option<Value>>,
) -> Result<Vec<u8>, ClientError> {
    if !topology_supported(parsed) {
        return Err(invalid("Hermes reviewed config topology is unsupported"));
    }
    let line_ending = source_line_ending(&parsed.source)?;
    let mut expected = parsed.value.clone();
    let mut edits = Vec::<(usize, usize, Vec<u8>)>::new();
    let mut insertions = BTreeMap::<usize, Vec<(Vec<String>, Vec<u8>)>>::new();

    for (path, replacement) in replacements {
        if !owned_replacement_path(path) {
            return Err(invalid("Hermes config replacement path is not owned"));
        }
        if matches!(
            path.as_slice(),
            [root] if matches!(root.as_str(), "plugins" | "mcp_servers" | "hooks")
        ) && resolve_path(&parsed.value, path).is_some()
        {
            return Err(invalid(
                "Hermes config replacement would overwrite unowned children",
            ));
        }
        set_semantic_path(&mut expected, path, replacement.clone())?;
        if let Some(span) = parsed.patch_index.paths.get(path) {
            let bytes = replacement
                .as_ref()
                .map(|value| {
                    render_key_value(path.last().unwrap(), value, span.indent, line_ending)
                })
                .transpose()?
                .unwrap_or_default();
            edits.push((span.start, span.end, bytes));
            continue;
        }
        let Some(value) = replacement.as_ref() else {
            continue;
        };
        let parent = &path[..path.len() - 1];
        let (offset, indent) = if parent.is_empty() {
            (parsed.source.len(), 0)
        } else {
            let span = parsed
                .patch_index
                .paths
                .get(parent)
                .ok_or_else(|| invalid("Hermes config insertion parent is unavailable"))?;
            let parent_value = resolve_path(&parsed.value, parent)
                .ok_or_else(|| invalid("Hermes config insertion parent is unavailable"))?;
            if !matches!(parent_value, Value::Mapping(_)) {
                return Err(invalid("Hermes config insertion parent is not a mapping"));
            }
            (span.end, span.indent + 2)
        };
        let rendered = render_key_value(path.last().unwrap(), value, indent, line_ending)?;
        insertions
            .entry(offset)
            .or_default()
            .push((path.clone(), rendered));
    }

    for (offset, mut values) in insertions {
        values.sort_by(|left, right| left.0.cmp(&right.0));
        let mut bytes = Vec::new();
        if offset > 0 && !parsed.source[..offset].ends_with(line_ending.as_bytes()) {
            bytes.extend_from_slice(line_ending.as_bytes());
        }
        for (_, value) in values {
            bytes.extend_from_slice(&value);
        }
        edits.push((offset, offset, bytes));
    }
    edits.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| right.1.cmp(&left.1)));
    for window in edits.windows(2) {
        let later = &window[0];
        let earlier = &window[1];
        if earlier.1 > later.0 {
            return Err(invalid("Hermes config replacement spans overlap"));
        }
    }
    let mut rendered = parsed.source.clone();
    for (start, end, replacement) in edits {
        if start > end || end > rendered.len() {
            return Err(invalid("Hermes config replacement span is invalid"));
        }
        rendered.splice(start..end, replacement);
    }
    let reparsed = parse_config(&rendered)?;
    if !topology_supported(&reparsed) {
        return Err(invalid("Hermes rendered config topology is unsupported"));
    }
    if reparsed.value != expected {
        return Err(invalid(
            "Hermes rendered config changed an unowned semantic path",
        ));
    }
    if reparsed.value == parsed.value {
        Ok(parsed.source.clone())
    } else {
        Ok(rendered)
    }
}

fn source_line_ending(source: &[u8]) -> Result<&'static str, ClientError> {
    let mut saw_lf = false;
    let mut saw_crlf = false;
    for (index, byte) in source.iter().enumerate() {
        if *byte != b'\n' {
            continue;
        }
        if index > 0 && source[index - 1] == b'\r' {
            saw_crlf = true;
        } else {
            saw_lf = true;
        }
    }
    if saw_lf && saw_crlf {
        return Err(invalid("Hermes config mixes line-ending conventions"));
    }
    Ok(if saw_crlf { "\r\n" } else { "\n" })
}

fn owned_replacement_path(path: &[String]) -> bool {
    match path {
        [root] => matches!(
            root.as_str(),
            "approvals" | "command_allowlist" | "plugins" | "mcp_servers" | "hooks" | "memory"
        ),
        [root, _] if root == "approvals" || root == "mcp_servers" || root == "hooks" => true,
        [root, state] if root == "plugins" && matches!(state.as_str(), "enabled" | "disabled") => {
            true
        }
        [root, key]
            if root == "memory"
                && matches!(key.as_str(), "memory_enabled" | "user_profile_enabled") =>
        {
            true
        }
        _ => false,
    }
}

fn set_semantic_path(
    root: &mut Value,
    path: &[String],
    replacement: Option<Value>,
) -> Result<(), ClientError> {
    let (leaf, parent) = path
        .split_last()
        .ok_or_else(|| invalid("Hermes config replacement path is empty"))?;
    let mut value = root;
    for part in parent {
        let Value::Mapping(mapping) = value else {
            return Err(invalid("Hermes config replacement parent is not a mapping"));
        };
        value = mapping
            .get_mut(Value::String(part.clone()))
            .ok_or_else(|| invalid("Hermes config replacement parent is unavailable"))?;
    }
    let Value::Mapping(mapping) = value else {
        return Err(invalid("Hermes config replacement parent is not a mapping"));
    };
    if let Some(replacement) = replacement {
        mapping.insert(Value::String(leaf.clone()), replacement);
    } else {
        mapping.remove(Value::String(leaf.clone()));
    }
    Ok(())
}

fn render_key_value(
    key: &str,
    value: &Value,
    indent: usize,
    line_ending: &str,
) -> Result<Vec<u8>, ClientError> {
    let yaml = serde_yaml_ng::to_string(value)
        .map_err(|_| invalid("Hermes reviewed value cannot be rendered"))?;
    let yaml = yaml.strip_prefix("---\n").unwrap_or(&yaml);
    let yaml = yaml.strip_suffix('\n').unwrap_or(yaml);
    let prefix = " ".repeat(indent);
    let mut output = String::new();
    if !yaml.contains('\n') && !matches!(value, Value::Sequence(_) | Value::Mapping(_)) {
        output.push_str(&prefix);
        output.push_str(key);
        output.push_str(": ");
        output.push_str(yaml);
        output.push_str(line_ending);
    } else {
        output.push_str(&prefix);
        output.push_str(key);
        output.push(':');
        output.push_str(line_ending);
        for line in yaml.split('\n') {
            output.push_str(&prefix);
            output.push_str("  ");
            output.push_str(line);
            output.push_str(line_ending);
        }
    }
    Ok(output.into_bytes())
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
    let normalized = normalize_key(key);
    matches!(
        normalized.as_str(),
        "apikey"
            | "token"
            | "password"
            | "secret"
            | "authorization"
            | "cookie"
            | "clientkey"
            | "clientkeypassphrase"
            | "credential"
    ) || ["token", "secret", "password", "credential"]
        .iter()
        .any(|suffix| normalized.ends_with(suffix))
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
                | "oauth"
                | "oauth2"
                | "auth"
                | "authentication"
                | "authorization"
                | "authorizationcode"
                | "credential"
        )
    })
}

pub(super) fn secret_scalar(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    contains_private_key_header(&lower)
        || contains_authorization_header(&lower)
        || contains_authorization_scheme(&lower)
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
        [root, ..] if root == "memory" => true,
        [root] if root == "plugins" => true,
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
            !(character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
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

fn contains_private_key_header(value: &str) -> bool {
    let mut remaining = value;
    while let Some((_, after_begin)) = remaining.split_once("-----begin ") {
        let Some((label, after_header)) = after_begin.split_once("-----") else {
            return false;
        };
        let label = label.trim();
        if label == "private key"
            || label.ends_with(" private key")
            || label == "pgp private key block"
        {
            return true;
        }
        remaining = after_header;
    }
    false
}

fn contains_authorization_header(value: &str) -> bool {
    value.match_indices("authorization").any(|(start, _)| {
        let bytes = value.as_bytes();
        if !word_boundary(bytes, start, "authorization".len()) {
            return false;
        }
        let mut cursor = start + "authorization".len();
        while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        if !matches!(bytes.get(cursor), Some(b':' | b'=')) {
            return false;
        }
        cursor += 1;
        while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        cursor < bytes.len()
    })
}

fn contains_authorization_scheme(value: &str) -> bool {
    ["bearer", "basic"].iter().any(|scheme| {
        value.match_indices(scheme).any(|(start, _)| {
            let bytes = value.as_bytes();
            if !word_boundary(bytes, start, scheme.len()) {
                return false;
            }
            let mut cursor = start + scheme.len();
            if !bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
                return false;
            }
            while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
                cursor += 1;
            }
            cursor < bytes.len()
        })
    })
}

fn word_boundary(bytes: &[u8], start: usize, length: usize) -> bool {
    let identifier = |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-');
    start
        .checked_sub(1)
        .is_none_or(|index| !identifier(bytes[index]))
        && bytes
            .get(start + length)
            .is_none_or(|byte| !identifier(*byte))
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
