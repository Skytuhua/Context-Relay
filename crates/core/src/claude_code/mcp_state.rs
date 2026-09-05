//! Passive MCP inspection. Claude's `mcp list` and `mcp get` health-check
//! servers; neither command is suitable for preview or transaction readback.

use std::{collections::BTreeSet, fmt, fs, io::Read as _, path::Path};

use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Value};

use super::{
    BRIDGE_SERVER_NAME, BridgeDeclarationProbeError, CanonicalCliDeclaration, ClaudeCodeLayout,
    ClientError, canonical_cli_declaration, canonical_json, claude_file_identity,
    collect_mcp_names, invalid_request, metadata_is_link_or_reparse,
    open_executable_without_substitution,
};

const CONFIG_LIMIT: u64 = 1024 * 1024;

pub(super) struct McpConfiguration {
    user: Map<String, Value>,
    local: Map<String, Value>,
    project: Map<String, Value>,
}

impl McpConfiguration {
    pub(super) fn read(layout: &ClaudeCodeLayout) -> Result<Self, ClientError> {
        for settings in &layout.managed_settings_paths {
            let path = settings.with_file_name("managed-mcp.json");
            match fs::symlink_metadata(&path) {
                // This file replaces all user/local/project MCP declarations.
                // Enterprise configuration is outside this adapter's authority.
                Ok(_) => return Err(invalid_request("Claude Code managed MCP policy is active")),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    validate_config_path(&path, true).map_err(|_| {
                        invalid_request("Claude Code managed MCP policy cannot be inspected")
                    })?;
                }
                Err(_) => {
                    return Err(invalid_request(
                        "Claude Code managed MCP policy cannot be inspected",
                    ));
                }
            }
        }
        let state = read_object(&layout.state_path)?;
        let project = read_object(&layout.project_root.join(".mcp.json"))?;
        let local = project_entry(&state, &layout.project_root)?;
        Ok(Self {
            user: optional_object(state.get("mcpServers"))?,
            local: optional_object(local.and_then(|value| value.get("mcpServers")))?,
            project: optional_object(project.get("mcpServers"))?,
        })
    }

    pub(super) fn names(&self) -> Result<Vec<String>, ClientError> {
        let mut names = BTreeSet::new();
        for servers in [&self.user, &self.local, &self.project] {
            collect_mcp_names(Some(&Value::Object(servers.clone())), &mut names)?;
            if servers.values().any(|server| !server.is_object()) {
                return Err(invalid_request("Claude Code MCP declaration is invalid"));
            }
        }
        Ok(names.into_iter().collect())
    }

    pub(super) fn managed_declaration(
        &self,
    ) -> Result<Option<CanonicalCliDeclaration>, BridgeDeclarationProbeError> {
        // A project/local declaration can shadow the user declaration. It is
        // outside this transaction's authority, even if its body is identical.
        if self.local.contains_key(BRIDGE_SERVER_NAME)
            || self.project.contains_key(BRIDGE_SERVER_NAME)
        {
            return Err(BridgeDeclarationProbeError::Conflict);
        }
        self.user
            .get(BRIDGE_SERVER_NAME)
            .map(|server| {
                let body =
                    canonical_json(server).map_err(|_| BridgeDeclarationProbeError::Inspection)?;
                canonical_cli_declaration(&body).map_err(|_| BridgeDeclarationProbeError::Conflict)
            })
            .transpose()
    }
}

pub(super) fn project_entry<'a>(
    state: &'a Map<String, Value>,
    project: &Path,
) -> Result<Option<&'a Map<String, Value>>, ClientError> {
    let Some(projects) = state.get("projects") else {
        return Ok(None);
    };
    let projects = projects
        .as_object()
        .ok_or_else(|| invalid_request("Claude Code projects are invalid"))?;
    let key = project
        .to_str()
        .ok_or_else(|| invalid_request("Claude Code project path is not text"))?;
    let mut matches = projects
        .iter()
        .filter(|(candidate, _)| project_keys_match(candidate, key));
    let first = matches
        .next()
        .map(|(_, value)| {
            value
                .as_object()
                .ok_or_else(|| invalid_request("Claude Code project configuration is invalid"))
        })
        .transpose()?;
    if matches.next().is_some() {
        return Err(invalid_request(
            "Claude Code project configuration is ambiguous",
        ));
    }
    Ok(first)
}

fn project_keys_match(left: &str, right: &str) -> bool {
    #[cfg(windows)]
    {
        fn normalized(value: &str) -> String {
            let value = value.replace('\\', "/");
            if let Some(unc) = value.strip_prefix("//?/UNC/") {
                format!("//{unc}")
            } else {
                value.strip_prefix("//?/").unwrap_or(&value).to_owned()
            }
        }
        normalized(left).eq_ignore_ascii_case(&normalized(right))
    }
    #[cfg(not(windows))]
    {
        left == right
    }
}

fn optional_object(value: Option<&Value>) -> Result<Map<String, Value>, ClientError> {
    match value {
        None => Ok(Map::new()),
        Some(Value::Object(object)) => Ok(object.clone()),
        Some(_) => Err(invalid_request("Claude Code MCP configuration is invalid")),
    }
}

pub(super) fn validate_config_path(path: &Path, allow_missing: bool) -> std::io::Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(std::io::Error::other(
            "configuration path is not absolute and normalized",
        ));
    }
    for component in path.ancestors() {
        match fs::symlink_metadata(component) {
            Ok(metadata) if !metadata_is_link_or_reparse(&metadata) => {}
            Err(error) if allow_missing && error.kind() == std::io::ErrorKind::NotFound => {}
            _ => {
                return Err(std::io::Error::other(
                    "configuration path has unsafe topology",
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn read_object(path: &Path) -> Result<Map<String, Value>, ClientError> {
    let error = || invalid_request("Claude Code MCP configuration cannot be safely inspected");
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(failure) if failure.kind() == std::io::ErrorKind::NotFound => {
            // Missing configuration is allowed; a dangling link is not absence.
            validate_config_path(path, true).map_err(|_| error())?;
            return Ok(Map::new());
        }
        Err(_) => return Err(error()),
    };
    validate_config_path(path, false).map_err(|_| error())?;
    if !metadata.is_file()
        || metadata_is_link_or_reparse(&metadata)
        || metadata.len() > CONFIG_LIMIT
    {
        return Err(error());
    }
    let file = open_executable_without_substitution(path).map_err(|_| error())?;
    let metadata = file.metadata().map_err(|_| error())?;
    if !metadata.is_file()
        || metadata_is_link_or_reparse(&metadata)
        || metadata.len() > CONFIG_LIMIT
    {
        return Err(error());
    }
    let mut bytes = Vec::new();
    (&file)
        .take(CONFIG_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| error())?;
    if bytes.len() as u64 > CONFIG_LIMIT {
        return Err(error());
    }
    let current = open_executable_without_substitution(path).map_err(|_| error())?;
    validate_config_path(path, false).map_err(|_| error())?;
    if claude_file_identity(&file).map_err(|_| error())?
        != claude_file_identity(&current).map_err(|_| error())?
    {
        return Err(error());
    }
    let value = parse_unique_json(&bytes).map_err(|_| error())?;
    match value {
        Value::Object(object) => Ok(object),
        _ => Err(error()),
    }
}

pub(super) fn parse_unique_json(bytes: &[u8]) -> Result<Value, serde_json::Error> {
    serde_json::from_slice::<StrictValue>(bytes).map(|value| value.0)
}

// Value normally keeps the last duplicate key. Reject duplicates at every
// depth so malformed JSON cannot disguise a command, argument, scope or env.
struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictValue;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("JSON with unique object keys")
            }
            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(StrictValue(value.into()))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(StrictValue(value.into()))
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(StrictValue(value.into()))
            }
            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(value)
                    .map(|value| StrictValue(Value::Number(value)))
                    .ok_or_else(|| E::custom("invalid JSON number"))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(StrictValue(value.into()))
            }
            fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(StrictValue(value.into()))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(StrictValue(value)) = sequence.next_element()? {
                    values.push(value);
                }
                Ok(StrictValue(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut object: A) -> Result<Self::Value, A::Error> {
                let mut values = Map::new();
                while let Some((key, StrictValue(value))) =
                    object.next_entry::<String, StrictValue>()?
                {
                    if values.insert(key, value).is_some() {
                        return Err(de::Error::custom("duplicate JSON key"));
                    }
                }
                Ok(StrictValue(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(StrictVisitor)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn a_linked_configuration_parent_is_never_treated_as_safe_or_absent() {
        let root = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(root.path()).unwrap();
        let actual = root.join("actual");
        let linked = root.join("linked");
        std::os::unix::fs::symlink(&actual, &linked).unwrap();
        assert!(read_object(&linked.join(".claude.json")).is_err());
        fs::create_dir(&actual).unwrap();
        fs::write(actual.join(".claude.json"), b"{}").unwrap();
        assert!(read_object(&linked.join(".claude.json")).is_err());
        assert!(read_object(&actual.join(".claude.json")).is_ok());
    }
}
