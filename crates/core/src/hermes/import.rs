use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
    str::FromStr,
};

use context_relay_protocol::{
    ClientError, ComponentKind, ComponentRecord, DeviceId, ErrorCode, HarnessId,
    HybridLogicalClock, NativeScope, Provenance, RecordId, ScopeRef, Sha256Digest,
};
use serde::Serialize;
use serde_json::Value as JsonValue;
use serde_yaml_ng::Value as YamlValue;
use sha2::{Digest as _, Sha256};

use super::{
    HermesAdapter, HermesMemoryDocument, HermesMemoryKind, invalid, yaml, yaml::ParsedHermesYaml,
};

const MAX_TREE_DEPTH: usize = 8;
const MAX_TREE_ENTRIES: usize = 256;

pub(super) fn project_reviewed_config(
    parsed: &ParsedHermesYaml,
    profile: &str,
) -> Result<Vec<ComponentRecord>, ClientError> {
    let root = parsed
        .value
        .as_mapping()
        .ok_or_else(|| invalid("Hermes config root is not a mapping"))?;
    let mut components = Vec::new();

    if let Some(value) = get(root, "approvals") {
        if let Some(approvals) = value.as_mapping() {
            for (key, value) in approvals {
                let key = key
                    .as_str()
                    .ok_or_else(|| invalid("Hermes approval key is invalid"))?;
                let path = format!("approvals.{key}");
                let (fidelity, reason) = permission_mapping(&path)
                    .ok_or_else(|| invalid("Hermes permission path is invalid"))?;
                push_permission_component(
                    &mut components,
                    profile,
                    &path,
                    value,
                    fidelity,
                    reason,
                )?;
            }
        } else {
            let (fidelity, reason) = permission_mapping("approvals")
                .ok_or_else(|| invalid("Hermes permission path is invalid"))?;
            push_permission_component(
                &mut components,
                profile,
                "approvals",
                value,
                fidelity,
                reason,
            )?;
        }
    }

    if let Some(value) = get(root, "command_allowlist") {
        let (fidelity, reason) = permission_mapping("command_allowlist")
            .ok_or_else(|| invalid("Hermes permission path is invalid"))?;
        push_permission_component(
            &mut components,
            profile,
            "command_allowlist",
            value,
            fidelity,
            reason,
        )?;
    }

    if let Some(plugins) = get(root, "plugins").and_then(YamlValue::as_mapping) {
        for (state, enabled) in [("enabled", true), ("disabled", false)] {
            let Some(values) = get(plugins, state).and_then(YamlValue::as_sequence) else {
                continue;
            };
            for name in values {
                let name = name
                    .as_str()
                    .ok_or_else(|| invalid("Hermes plugin state name is invalid"))?;
                safe_name(name)?;
                let location = format!("config:plugins.{state}.{name}");
                let mut component = draft_component(
                    profile,
                    ComponentKind::Plugin,
                    name,
                    format!("{{\"enabled\":{enabled}}}"),
                    &location,
                    "json",
                    vec![("enabled".into(), enabled.to_string())],
                )?;
                component.archived = !enabled;
                components.push(component);
            }
        }
    }

    if let Some(servers) = get(root, "mcp_servers").and_then(YamlValue::as_mapping) {
        for (name, server) in servers {
            let name = name
                .as_str()
                .ok_or_else(|| invalid("Hermes MCP server name is invalid"))?;
            safe_name(name)?;
            let (reviewed, redacted, placeholders) = sanitize_mcp(server)?;
            let body = canonical_json(&reviewed)?;
            let enabled = reviewed
                .get("enabled")
                .and_then(JsonValue::as_bool)
                .unwrap_or(true);
            let mut extra = vec![("enabled".into(), enabled.to_string())];
            if redacted {
                extra.push(("redacted".into(), "true".into()));
                extra.push((
                    "secretReferenceNames".into(),
                    placeholders.into_iter().collect::<Vec<_>>().join(","),
                ));
            }
            let mut component = draft_component(
                profile,
                ComponentKind::McpServer,
                name,
                body,
                &format!("config:mcp_servers.{name}"),
                "json",
                extra,
            )?;
            component.archived = !enabled;
            components.push(component);
        }
    }

    if let Some(hooks) = get(root, "hooks").and_then(YamlValue::as_mapping) {
        for (name, hook) in hooks {
            let name = name
                .as_str()
                .ok_or_else(|| invalid("Hermes hook name is invalid"))?;
            safe_name(name)?;
            let mut placeholders = BTreeSet::new();
            collect_contextual_placeholders(hook, &mut placeholders)?;
            let (reviewed, redacted) = sanitize_general(hook, &mut vec!["hooks".to_owned()]);
            let reviewed =
                reviewed.ok_or_else(|| invalid("Hermes hook contains no reviewed values"))?;
            let body = canonical_json(&reviewed)?;
            let enabled = reviewed
                .get("enabled")
                .and_then(JsonValue::as_bool)
                .unwrap_or(true);
            let mut extra = vec![("enabled".into(), enabled.to_string())];
            if redacted {
                extra.push(("redacted".into(), "true".into()));
                if !placeholders.is_empty() {
                    extra.push((
                        "secretReferenceNames".into(),
                        placeholders.into_iter().collect::<Vec<_>>().join(","),
                    ));
                }
            }
            let mut component = draft_component(
                profile,
                ComponentKind::Hook,
                name,
                body,
                &format!("config:hooks.{name}"),
                "json",
                extra,
            )?;
            component.archived = !enabled;
            components.push(component);
        }
    }

    Ok(components)
}

pub(super) fn reviewed_config_projection(
    parsed: &ParsedHermesYaml,
    profile: &str,
) -> Result<JsonValue, ClientError> {
    let components = project_reviewed_config(parsed, profile)?;
    let mut root = BTreeMap::<String, JsonValue>::new();
    let mut approvals = BTreeMap::<String, JsonValue>::new();
    let mut plugins_enabled = BTreeSet::new();
    let mut plugins_disabled = BTreeSet::new();
    let mut mcp_servers = BTreeMap::<String, JsonValue>::new();
    let mut hooks = BTreeMap::<String, JsonValue>::new();

    for component in components {
        let location = component
            .metadata
            .iter()
            .find_map(|(key, value)| (key == "structuralLocation").then_some(value.as_str()))
            .ok_or_else(|| invalid("Hermes component location is missing"))?;
        match component.kind {
            ComponentKind::PermissionDeclaration => {
                let value: JsonValue = serde_json::from_str(&component.body_markdown)
                    .map_err(|_| invalid("Hermes reviewed permission is invalid"))?;
                if location == "config:approvals" {
                    root.insert("approvals".into(), value);
                } else if let Some(key) = location.strip_prefix("config:approvals.") {
                    safe_name(key)?;
                    approvals.insert(key.to_owned(), value);
                } else if location == "config:command_allowlist" {
                    root.insert("command_allowlist".into(), value);
                } else {
                    return Err(invalid("Hermes reviewed permission path is invalid"));
                }
            }
            ComponentKind::Plugin => {
                if location.starts_with("config:plugins.enabled.") {
                    plugins_enabled.insert(component.name);
                } else if location.starts_with("config:plugins.disabled.") {
                    plugins_disabled.insert(component.name);
                } else {
                    return Err(invalid("Hermes reviewed plugin path is invalid"));
                }
            }
            ComponentKind::McpServer => {
                mcp_servers.insert(
                    component.name,
                    serde_json::from_str(&component.body_markdown)
                        .map_err(|_| invalid("Hermes reviewed MCP declaration is invalid"))?,
                );
            }
            ComponentKind::Hook => {
                hooks.insert(
                    component.name,
                    serde_json::from_str(&component.body_markdown)
                        .map_err(|_| invalid("Hermes reviewed hook declaration is invalid"))?,
                );
            }
            _ => return Err(invalid("Hermes reviewed config component is invalid")),
        }
    }

    if !approvals.is_empty() {
        root.insert(
            "approvals".into(),
            serde_json::to_value(approvals)
                .map_err(|_| invalid("Hermes reviewed permission is invalid"))?,
        );
    }
    if !plugins_enabled.is_empty() || !plugins_disabled.is_empty() {
        let mut plugins = BTreeMap::<&str, Vec<String>>::new();
        if !plugins_disabled.is_empty() {
            plugins.insert("disabled", plugins_disabled.into_iter().collect::<Vec<_>>());
        }
        if !plugins_enabled.is_empty() {
            plugins.insert("enabled", plugins_enabled.into_iter().collect::<Vec<_>>());
        }
        root.insert(
            "plugins".into(),
            serde_json::to_value(plugins)
                .map_err(|_| invalid("Hermes reviewed plugin state is invalid"))?,
        );
    }
    if !mcp_servers.is_empty() {
        root.insert(
            "mcp_servers".into(),
            serde_json::to_value(mcp_servers)
                .map_err(|_| invalid("Hermes reviewed MCP declaration is invalid"))?,
        );
    }
    if !hooks.is_empty() {
        root.insert(
            "hooks".into(),
            serde_json::to_value(hooks)
                .map_err(|_| invalid("Hermes reviewed hook declaration is invalid"))?,
        );
    }
    serde_json::to_value(root).map_err(|_| invalid("Hermes reviewed config projection is invalid"))
}

pub(super) fn validation_config_projection(
    parsed: &ParsedHermesYaml,
    profile: &str,
) -> Result<JsonValue, ClientError> {
    let reviewed = reviewed_config_projection(parsed, profile)?;
    if !reviewed.is_object() {
        return Err(invalid("Hermes reviewed config projection is invalid"));
    }
    Ok(JsonValue::Object(Default::default()))
}

pub(super) fn permission_mapping(path: &str) -> Option<(&'static str, &'static str)> {
    match path {
        "approvals" => Some(("lossy", "confirmation_switch_not_portable")),
        "command_allowlist" => Some(("lossy", "permanent_allowlist_not_portable")),
        _ => {
            let key = path.strip_prefix("approvals.")?;
            if key.is_empty() || key.contains('.') {
                return None;
            }
            Some(match key {
                "mode" => ("lossy", "approval_mode_not_portable"),
                "deny" => ("lossy", "deny_pattern_not_portable"),
                "cron" => ("lossy", "cron_permission_not_portable"),
                "confirm" | "confirmation" | "require_confirmation" => {
                    ("lossy", "confirmation_switch_not_portable")
                }
                _ => ("exact", "native_equivalent"),
            })
        }
    }
}

fn push_permission_component(
    components: &mut Vec<ComponentRecord>,
    profile: &str,
    path: &str,
    value: &YamlValue,
    fidelity: &str,
    reason: &str,
) -> Result<(), ClientError> {
    let (reviewed, _) = sanitize_general(value, &mut path.split('.').map(str::to_owned).collect());
    let body = canonical_json(
        reviewed
            .as_ref()
            .ok_or_else(|| invalid("Hermes permission contains no reviewed values"))?,
    )?;
    components.push(draft_component(
        profile,
        ComponentKind::PermissionDeclaration,
        path,
        body,
        &format!("config:{path}"),
        "json",
        permission_metadata(profile, path, fidelity, reason),
    )?);
    Ok(())
}

impl HermesAdapter {
    pub(super) fn project_current_config(
        &self,
        parsed: &ParsedHermesYaml,
    ) -> Result<Vec<ComponentRecord>, ClientError> {
        let mut components = project_reviewed_config(parsed, &self.layout.profile.name)?;
        for component in &mut components {
            self.finish_component(component)?;
        }
        Ok(components)
    }

    pub(super) fn import_policy_conflicts(&self) -> Vec<String> {
        let Ok(bytes) = fs::read(self.layout.profile.hermes_home.join("config.yaml")) else {
            return Vec::new();
        };
        let Ok(parsed) = yaml::parse_config(&bytes) else {
            return Vec::new();
        };
        let Some(root) = parsed.value.as_mapping() else {
            return Vec::new();
        };
        let mut conflicts = BTreeSet::new();
        if let Some(approvals) = get(root, "approvals").and_then(YamlValue::as_mapping) {
            if get(approvals, "mode").is_some() {
                conflicts.insert("approval_mode_not_portable".to_owned());
            }
            if get(approvals, "deny").is_some() {
                conflicts.insert("deny_pattern_not_portable".to_owned());
            }
            if ["confirm", "confirmation", "require_confirmation"]
                .iter()
                .any(|key| get(approvals, key).is_some())
            {
                conflicts.insert("confirmation_switch_not_portable".to_owned());
            }
            if get(approvals, "cron").is_some() {
                conflicts.insert("cron_permission_not_portable".to_owned());
            }
        }
        if get(root, "command_allowlist").is_some() {
            conflicts.insert("permanent_allowlist_not_portable".to_owned());
        }
        conflicts.into_iter().collect()
    }

    pub(super) fn import_scope(
        &self,
        scope: ScopeRef,
        include_disabled: bool,
        components: &mut Vec<ComponentRecord>,
        digests: &mut BTreeSet<Sha256Digest>,
    ) -> Result<(), ClientError> {
        match scope {
            ScopeRef::Global => {
                let root = &self.layout.profile.hermes_home;
                let config_path = root.join("config.yaml");
                let bytes = read_required_reviewed_file(root, &config_path, "profile:config.yaml")?;
                let parsed = yaml::parse_config(&bytes)?;
                digests.insert(digest(&parsed.source));
                let projected = project_reviewed_config(&parsed, &self.layout.profile.name)?;
                let enabled_plugins = projected
                    .iter()
                    .filter(|component| {
                        component.kind == ComponentKind::Plugin
                            && !component.archived
                            && component
                                .metadata
                                .iter()
                                .find_map(|(key, value)| {
                                    (key == "structuralLocation").then_some(value.as_str())
                                })
                                .is_some_and(|location| {
                                    location.starts_with("config:plugins.enabled.")
                                })
                    })
                    .map(|component| component.name.clone())
                    .collect::<BTreeSet<_>>();
                let disabled_plugins = projected
                    .iter()
                    .filter(|component| {
                        component.kind == ComponentKind::Plugin
                            && component.archived
                            && component
                                .metadata
                                .iter()
                                .find_map(|(key, value)| {
                                    (key == "structuralLocation").then_some(value.as_str())
                                })
                                .is_some_and(|location| {
                                    location.starts_with("config:plugins.disabled.")
                                })
                    })
                    .map(|component| component.name.clone())
                    .collect::<BTreeSet<_>>();
                let disabled_hooks = projected
                    .iter()
                    .filter(|component| component.kind == ComponentKind::Hook && component.archived)
                    .map(|component| component.name.clone())
                    .collect::<BTreeSet<_>>();
                for mut component in projected {
                    if component.archived && !include_disabled {
                        continue;
                    }
                    self.finish_component(&mut component)?;
                    components.push(component);
                }
                self.import_profile_files(
                    include_disabled,
                    &enabled_plugins,
                    &disabled_plugins,
                    &disabled_hooks,
                    components,
                    digests,
                )?;
            }
            ScopeRef::Project { project_id } => {
                self.import_project_context(project_id, components, digests)?;
            }
        }
        Ok(())
    }

    pub(super) fn import_memory_documents(&self) -> Result<Vec<HermesMemoryDocument>, ClientError> {
        let root = &self.layout.profile.hermes_home;
        let mut documents = Vec::new();
        for (relative, kind) in [
            ("memories/MEMORY.md", HermesMemoryKind::Agent),
            ("memories/USER.md", HermesMemoryKind::User),
        ] {
            let path = root.join(relative);
            let Some(bytes) =
                read_optional_reviewed_file(root, &path, &format!("profile:{relative}"))?
            else {
                continue;
            };
            yaml::scan_text_secret(&bytes, &format!("profile:{relative}"))?;
            documents.push(HermesMemoryDocument {
                kind,
                body_markdown: String::from_utf8(bytes.clone())
                    .map_err(|_| invalid("Hermes memory is not valid UTF-8"))?,
                source_digest: digest(&bytes),
            });
        }
        Ok(documents)
    }

    fn import_profile_files(
        &self,
        include_disabled: bool,
        enabled_plugins: &BTreeSet<String>,
        disabled_plugins: &BTreeSet<String>,
        disabled_hooks: &BTreeSet<String>,
        components: &mut Vec<ComponentRecord>,
        digests: &mut BTreeSet<Sha256Digest>,
    ) -> Result<(), ClientError> {
        let root = &self.layout.profile.hermes_home;
        if let Some(bytes) =
            read_optional_reviewed_file(root, &root.join("SOUL.md"), "profile:SOUL.md")?
        {
            yaml::scan_text_secret(&bytes, "profile:SOUL.md")?;
            digests.insert(digest(&bytes));
            components.push(self.file_component(
                ScopeRef::Global,
                ComponentKind::Rule,
                "SOUL.md",
                String::from_utf8(bytes).map_err(|_| invalid("Hermes soul is not valid UTF-8"))?,
                "profile:SOUL.md",
                "markdown",
                vec![
                    ("contextRole".into(), "soul".into()),
                    ("precedenceIndex".into(), "0".into()),
                ],
            )?);
        }
        self.import_skills(components, digests)?;
        self.import_plugins(
            include_disabled,
            enabled_plugins,
            disabled_plugins,
            components,
            digests,
        )?;
        self.import_hooks(include_disabled, disabled_hooks, components, digests)
    }

    fn import_skills(
        &self,
        components: &mut Vec<ComponentRecord>,
        digests: &mut BTreeSet<Sha256Digest>,
    ) -> Result<(), ClientError> {
        let profile_root = &self.layout.profile.hermes_home;
        let skills_root = profile_root.join("skills");
        let Some(skills_root) =
            optional_real_directory(profile_root, &skills_root, "profile:skills")?
        else {
            return Ok(());
        };
        let mut files = Vec::new();
        let mut count = 0usize;
        collect_skill_files(&skills_root, &skills_root, 0, &mut count, &mut files)?;
        files.sort();
        for path in files {
            let relative = display_relative(
                path.strip_prefix(&skills_root)
                    .map_err(|_| invalid("Hermes skill escaped its allowlist"))?,
            )?;
            let location = format!("profile:skills/{relative}");
            let bytes = read_required_reviewed_file(&skills_root, &path, &location)?;
            yaml::scan_text_secret(&bytes, &location)?;
            let name = path
                .parent()
                .and_then(Path::file_name)
                .and_then(|name| name.to_str())
                .ok_or_else(|| invalid("Hermes skill name is invalid"))?;
            safe_name(name)?;
            digests.insert(digest(&bytes));
            components.push(self.file_component(
                ScopeRef::Global,
                ComponentKind::Skill,
                name,
                String::from_utf8(bytes).map_err(|_| invalid("Hermes skill is not valid UTF-8"))?,
                &location,
                "markdown",
                Vec::new(),
            )?);
        }
        Ok(())
    }

    fn import_plugins(
        &self,
        include_disabled: bool,
        enabled_plugins: &BTreeSet<String>,
        disabled_plugins: &BTreeSet<String>,
        components: &mut Vec<ComponentRecord>,
        digests: &mut BTreeSet<Sha256Digest>,
    ) -> Result<(), ClientError> {
        let profile_root = &self.layout.profile.hermes_home;
        let plugins_root = profile_root.join("plugins");
        let Some(plugins_root) =
            optional_real_directory(profile_root, &plugins_root, "profile:plugins")?
        else {
            return Ok(());
        };
        for directory in direct_safe_directories(&plugins_root, "profile:plugins")? {
            let name = directory
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| invalid("Hermes plugin name is invalid"))?;
            safe_name(name)?;
            let state = match (
                enabled_plugins.contains(name),
                disabled_plugins.contains(name),
            ) {
                (true, false) => "enabled",
                (false, true) => "disabled",
                (false, false) => "discovered",
                (true, true) => "ambiguous",
            };
            let active = state == "enabled";
            if !active && !include_disabled {
                continue;
            }
            let location = format!("profile:plugins/{name}/plugin.yaml");
            let Some(bytes) = read_optional_reviewed_file(
                &plugins_root,
                &directory.join("plugin.yaml"),
                &location,
            )?
            else {
                continue;
            };
            yaml::scan_text_secret(&bytes, &location)?;
            digests.insert(digest(&bytes));
            let body = reviewed_plugin_manifest(&bytes, name)?;
            let mut component = self.file_component(
                ScopeRef::Global,
                ComponentKind::Plugin,
                name,
                body,
                &location,
                "yaml",
                vec![
                    ("manifest".into(), "true".into()),
                    ("enabled".into(), active.to_string()),
                    ("pluginState".into(), state.into()),
                ],
            )?;
            component.archived = !active;
            components.push(component);
        }
        Ok(())
    }

    fn import_hooks(
        &self,
        include_disabled: bool,
        disabled_hooks: &BTreeSet<String>,
        components: &mut Vec<ComponentRecord>,
        digests: &mut BTreeSet<Sha256Digest>,
    ) -> Result<(), ClientError> {
        let profile_root = &self.layout.profile.hermes_home;
        let hooks_root = profile_root.join("hooks");
        let Some(hooks_root) = optional_real_directory(profile_root, &hooks_root, "profile:hooks")?
        else {
            return Ok(());
        };
        for directory in direct_safe_directories(&hooks_root, "profile:hooks")? {
            let name = directory
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| invalid("Hermes hook name is invalid"))?;
            safe_name(name)?;
            let disabled = disabled_hooks.contains(name);
            if disabled && !include_disabled {
                continue;
            }
            for (file, native_format, component_name) in [
                ("HOOK.yaml", "yaml", name.to_owned()),
                ("handler.py", "python", format!("{name}/handler.py")),
            ] {
                let location = format!("profile:hooks/{name}/{file}");
                let Some(bytes) =
                    read_optional_reviewed_file(&hooks_root, &directory.join(file), &location)?
                else {
                    continue;
                };
                yaml::scan_text_secret(&bytes, &location)?;
                digests.insert(digest(&bytes));
                let mut component = self.file_component(
                    ScopeRef::Global,
                    ComponentKind::Hook,
                    &component_name,
                    String::from_utf8(bytes)
                        .map_err(|_| invalid("Hermes hook file is not valid UTF-8"))?,
                    &location,
                    native_format,
                    vec![
                        ("gatewayHook".into(), "true".into()),
                        ("enabled".into(), (!disabled).to_string()),
                    ],
                )?;
                component.archived = disabled;
                components.push(component);
            }
        }
        Ok(())
    }

    fn import_project_context(
        &self,
        project_id: context_relay_protocol::ProjectId,
        components: &mut Vec<ComponentRecord>,
        digests: &mut BTreeSet<Sha256Digest>,
    ) -> Result<(), ClientError> {
        let mut directory = self.layout.working_directory.clone();
        loop {
            let preferred = directory.join(".hermes.md");
            let fallback = directory.join("HERMES.md");
            let selected = if reviewed_file_exists(&preferred)? {
                Some((preferred, ".hermes.md"))
            } else if reviewed_file_exists(&fallback)? {
                Some((fallback, "HERMES.md"))
            } else {
                None
            };
            if let Some((path, name)) = selected {
                let relative_directory = path
                    .parent()
                    .and_then(|parent| parent.strip_prefix(&self.layout.project_root).ok())
                    .ok_or_else(|| invalid("Hermes project context escaped its root"))?;
                let relative_directory = display_relative(relative_directory)?;
                let location = if relative_directory.is_empty() {
                    format!("project:{name}")
                } else {
                    format!("project:{relative_directory}/{name}")
                };
                let bytes =
                    read_required_reviewed_file(&self.layout.project_root, &path, &location)?;
                yaml::scan_text_secret(&bytes, &location)?;
                digests.insert(digest(&bytes));
                components.push(
                    self.file_component(
                        ScopeRef::Project { project_id },
                        ComponentKind::Instruction,
                        name,
                        String::from_utf8(bytes)
                            .map_err(|_| invalid("Hermes project context is not valid UTF-8"))?,
                        &location,
                        "markdown",
                        vec![
                            ("contextRole".into(), "project".into()),
                            ("precedenceIndex".into(), "1".into()),
                        ],
                    )?,
                );
                return Ok(());
            }
            if directory == self.layout.project_root {
                return Ok(());
            }
            directory = directory
                .parent()
                .filter(|parent| parent.starts_with(&self.layout.project_root))
                .ok_or_else(|| invalid("Hermes project context traversal is invalid"))?
                .to_path_buf();
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn file_component(
        &self,
        scope: ScopeRef,
        kind: ComponentKind,
        name: &str,
        body: String,
        location: &str,
        native_format: &str,
        extra: Vec<(String, String)>,
    ) -> Result<ComponentRecord, ClientError> {
        let mut component = draft_component(
            &self.layout.profile.name,
            kind,
            name,
            body,
            location,
            native_format,
            extra,
        )?;
        component.scope = scope;
        self.finish_component(&mut component)?;
        Ok(component)
    }

    fn finish_component(&self, component: &mut ComponentRecord) -> Result<(), ClientError> {
        let scope = match component.scope {
            ScopeRef::Global => "global".to_owned(),
            ScopeRef::Project { project_id } => format!("project:{project_id}"),
        };
        let location = component
            .metadata
            .iter()
            .find_map(|(key, value)| (key == "structuralLocation").then_some(value.as_str()))
            .ok_or_else(|| invalid("Hermes component location is missing"))?;
        component.id = stable_record_id(&format!(
            "{scope}|{:?}|{}|{}|{}",
            component.kind, self.layout.profile.name, location, component.name
        ))?;
        component.provenance = Provenance {
            origin_device: self.origin_device,
            harness: Some(HarnessId::Hermes),
            source: None,
            created_hlc: self.observed_hlc,
        };
        component
            .validate()
            .map_err(|_| invalid("Hermes component exceeds protocol limits"))
    }
}

fn sanitize_mcp(value: &YamlValue) -> Result<(JsonValue, bool, BTreeSet<String>), ClientError> {
    let mapping = value
        .as_mapping()
        .ok_or_else(|| invalid("Hermes MCP server declaration is invalid"))?;
    let mut object = BTreeMap::new();
    let mut redacted = false;
    let mut placeholders = BTreeSet::new();
    for (key, value) in mapping {
        let key = key
            .as_str()
            .ok_or_else(|| invalid("Hermes MCP server key is invalid"))?;
        if yaml::secret_key(key) || yaml::credential_container(&[key.to_owned()]) {
            redacted = true;
            collect_placeholders(value, &mut placeholders);
            continue;
        }
        if !matches!(
            key,
            "command"
                | "args"
                | "url"
                | "timeout"
                | "connect_timeout"
                | "idle_timeout_seconds"
                | "max_lifetime_seconds"
                | "enabled"
                | "supports_parallel_tool_calls"
                | "tools"
        ) {
            continue;
        }
        if credential_context_field(key, value) {
            redacted = true;
            collect_context_field_placeholders(key, value, &mut placeholders)?;
            continue;
        }
        if key == "tools" {
            let tools = value
                .as_mapping()
                .ok_or_else(|| invalid("Hermes MCP tools declaration is invalid"))?;
            let mut reviewed_tools = BTreeMap::new();
            for (tool_key, tool_value) in tools {
                let tool_key = tool_key
                    .as_str()
                    .ok_or_else(|| invalid("Hermes MCP tools key is invalid"))?;
                if !matches!(tool_key, "include" | "exclude" | "prompts" | "resources") {
                    continue;
                }
                collect_redacted_placeholders(
                    tool_value,
                    &mut vec!["tools".into(), tool_key.into()],
                    &mut placeholders,
                );
                let (reviewed, removed) =
                    sanitize_general(tool_value, &mut vec!["tools".into(), tool_key.into()]);
                redacted |= removed;
                if let Some(reviewed) = reviewed {
                    reviewed_tools.insert(tool_key.to_owned(), reviewed);
                }
            }
            object.insert(
                key.to_owned(),
                JsonValue::Object(reviewed_tools.into_iter().collect()),
            );
        } else {
            collect_redacted_placeholders(value, &mut vec![key.to_owned()], &mut placeholders);
            let (reviewed, removed) = sanitize_general(value, &mut vec![key.to_owned()]);
            redacted |= removed;
            if let Some(reviewed) = reviewed {
                object.insert(key.to_owned(), reviewed);
            }
        }
    }
    Ok((
        JsonValue::Object(object.into_iter().collect()),
        redacted,
        placeholders,
    ))
}

fn sanitize_general(value: &YamlValue, path: &mut Vec<String>) -> (Option<JsonValue>, bool) {
    match value {
        YamlValue::Null => (Some(JsonValue::Null), false),
        YamlValue::Bool(value) => (Some(JsonValue::Bool(*value)), false),
        YamlValue::Number(value) => {
            let json = serde_json::to_value(value).ok();
            (json, false)
        }
        YamlValue::String(value) => {
            if yaml::secret_scalar(value) {
                (None, true)
            } else {
                (Some(JsonValue::String(value.clone())), false)
            }
        }
        YamlValue::Sequence(values) => {
            let mut result = Vec::new();
            let mut redacted = false;
            for value in values {
                let (reviewed, removed) = sanitize_general(value, path);
                redacted |= removed;
                if let Some(reviewed) = reviewed {
                    result.push(reviewed);
                }
            }
            (Some(JsonValue::Array(result)), redacted)
        }
        YamlValue::Mapping(values) => {
            let mut result = BTreeMap::new();
            let mut redacted = false;
            for (key, value) in values {
                let Some(key) = key.as_str() else {
                    return (None, true);
                };
                path.push(key.to_owned());
                if yaml::secret_key(key) || yaml::credential_container(path) {
                    redacted = true;
                    path.pop();
                    continue;
                }
                if credential_context_field(key, value) {
                    redacted = true;
                    path.pop();
                    continue;
                }
                let (reviewed, removed) = sanitize_general(value, path);
                redacted |= removed;
                if let Some(reviewed) = reviewed {
                    result.insert(key.to_owned(), reviewed);
                }
                path.pop();
            }
            (
                Some(JsonValue::Object(result.into_iter().collect())),
                redacted,
            )
        }
        YamlValue::Tagged(_) => (None, true),
    }
}

#[derive(Serialize)]
struct ReviewedPluginManifest<'a> {
    name: &'a str,
    version: &'a YamlValue,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<&'a str>,
}

fn reviewed_plugin_manifest(bytes: &[u8], expected_name: &str) -> Result<String, ClientError> {
    let parsed = yaml::parse_config(bytes)?;
    let root = parsed
        .value
        .as_mapping()
        .ok_or_else(|| invalid("Hermes plugin manifest root is invalid"))?;
    let name = get(root, "name")
        .and_then(YamlValue::as_str)
        .filter(|name| *name == expected_name)
        .ok_or_else(|| invalid("Hermes plugin manifest name is invalid"))?;
    let version = get(root, "version")
        .filter(|version| match version {
            YamlValue::String(value) => !value.is_empty() && value.len() <= 128,
            YamlValue::Number(value) => value.to_string().len() <= 128,
            _ => false,
        })
        .ok_or_else(|| invalid("Hermes plugin manifest version is invalid"))?;
    let description = get(root, "description")
        .map(|value| {
            value
                .as_str()
                .filter(|description| description.len() <= 4096)
                .ok_or_else(|| invalid("Hermes plugin manifest description is invalid"))
        })
        .transpose()?;
    serde_yaml_ng::to_string(&ReviewedPluginManifest {
        name,
        version,
        description,
    })
    .map_err(|_| invalid("Hermes plugin manifest projection is invalid"))
}

fn credential_context_field(key: &str, value: &YamlValue) -> bool {
    match (key, value) {
        ("command", YamlValue::String(command)) => {
            credential_option_tokens(command.split_whitespace())
        }
        ("args", YamlValue::Sequence(arguments)) => {
            let Some(arguments) = arguments
                .iter()
                .map(YamlValue::as_str)
                .collect::<Option<Vec<_>>>()
            else {
                return true;
            };
            credential_option_tokens(arguments)
        }
        _ => false,
    }
}

fn credential_option_tokens<'a>(tokens: impl IntoIterator<Item = &'a str>) -> bool {
    let tokens = tokens
        .into_iter()
        .take(MAX_CREDENTIAL_ARGUMENTS + 1)
        .collect::<Vec<_>>();
    if tokens.len() > MAX_CREDENTIAL_ARGUMENTS
        || tokens
            .iter()
            .any(|token| token.len() > MAX_CREDENTIAL_ARGUMENT_BYTES)
    {
        return true;
    }
    for (index, token) in tokens.iter().enumerate() {
        let token = token.trim_matches(['\'', '"']);
        let Some(option) = token
            .strip_prefix("--")
            .or_else(|| token.strip_prefix('-'))
            .or_else(|| token.strip_prefix('/'))
        else {
            continue;
        };
        if let Some((name, value)) = option.split_once('=') {
            if credential_option_name(name) && !value.is_empty() {
                return true;
            }
        } else if credential_option_name(option) && tokens.get(index + 1).is_some() {
            return true;
        }
    }
    false
}

fn credential_option_name(name: &str) -> bool {
    let normalized = name
        .bytes()
        .filter(|byte| byte.is_ascii_alphanumeric())
        .map(|byte| byte.to_ascii_lowercase())
        .collect::<Vec<_>>();
    matches!(
        normalized.as_slice(),
        b"apikey"
            | b"token"
            | b"password"
            | b"secret"
            | b"credential"
            | b"cookie"
            | b"authorization"
            | b"clientkey"
    )
}

const MAX_CREDENTIAL_ARGUMENTS: usize = 128;
const MAX_CREDENTIAL_ARGUMENT_BYTES: usize = 4096;
const MAX_CONTEXTUAL_PLACEHOLDERS: usize = 128;

fn collect_contextual_placeholders(
    value: &YamlValue,
    names: &mut BTreeSet<String>,
) -> Result<(), ClientError> {
    match value {
        YamlValue::Sequence(values) => {
            for value in values {
                collect_contextual_placeholders(value, names)?;
            }
        }
        YamlValue::Mapping(values) => {
            for (key, value) in values {
                let Some(key) = key.as_str() else {
                    continue;
                };
                if credential_context_field(key, value) {
                    collect_context_field_placeholders(key, value, names)?;
                } else {
                    collect_contextual_placeholders(value, names)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn collect_context_field_placeholders(
    key: &str,
    value: &YamlValue,
    names: &mut BTreeSet<String>,
) -> Result<(), ClientError> {
    match (key, value) {
        ("command", YamlValue::String(command)) => {
            let tokens = command
                .split_whitespace()
                .take(MAX_CREDENTIAL_ARGUMENTS + 1)
                .collect::<Vec<_>>();
            if tokens.len() > MAX_CREDENTIAL_ARGUMENTS
                || tokens
                    .iter()
                    .any(|token| token.len() > MAX_CREDENTIAL_ARGUMENT_BYTES)
            {
                return Err(invalid(
                    "Hermes credential command exceeds the review limit",
                ));
            }
            for token in tokens {
                collect_embedded_placeholder_names(token, names)?;
            }
        }
        ("args", YamlValue::Sequence(arguments)) => {
            if arguments.len() > MAX_CREDENTIAL_ARGUMENTS {
                return Err(invalid(
                    "Hermes credential arguments exceed the review limit",
                ));
            }
            for argument in arguments {
                let argument = argument
                    .as_str()
                    .ok_or_else(|| invalid("Hermes credential argument is invalid"))?;
                if argument.len() > MAX_CREDENTIAL_ARGUMENT_BYTES {
                    return Err(invalid(
                        "Hermes credential argument exceeds the review limit",
                    ));
                }
                collect_embedded_placeholder_names(argument, names)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn collect_embedded_placeholder_names(
    value: &str,
    names: &mut BTreeSet<String>,
) -> Result<(), ClientError> {
    let bytes = value.as_bytes();
    let mut index = 0usize;
    while index + 3 < bytes.len() {
        if bytes[index] != b'$' || bytes[index + 1] != b'{' {
            index += 1;
            continue;
        }
        let name_start = index + 2;
        let search_end = bytes.len().min(name_start + 129);
        let Some(relative_end) = bytes[name_start..search_end]
            .iter()
            .position(|byte| *byte == b'}')
        else {
            index += 2;
            continue;
        };
        let name_end = name_start + relative_end;
        let name = &bytes[name_start..name_end];
        let valid = !name.is_empty()
            && (name[0] == b'_' || name[0].is_ascii_uppercase())
            && name[1..]
                .iter()
                .all(|byte| *byte == b'_' || byte.is_ascii_uppercase() || byte.is_ascii_digit());
        if valid {
            let name = std::str::from_utf8(name)
                .map_err(|_| invalid("Hermes placeholder name is invalid"))?;
            if !names.contains(name) && names.len() >= MAX_CONTEXTUAL_PLACEHOLDERS {
                return Err(invalid(
                    "Hermes placeholder metadata exceeds the review limit",
                ));
            }
            names.insert(name.to_owned());
        }
        index = name_end + 1;
    }
    Ok(())
}

fn collect_redacted_placeholders(
    value: &YamlValue,
    path: &mut Vec<String>,
    names: &mut BTreeSet<String>,
) {
    match value {
        YamlValue::Sequence(values) => {
            for value in values {
                collect_redacted_placeholders(value, path, names);
            }
        }
        YamlValue::Mapping(values) => {
            for (key, value) in values {
                let Some(key) = key.as_str() else {
                    continue;
                };
                path.push(key.to_owned());
                if yaml::secret_key(key) || yaml::credential_container(path) {
                    collect_placeholders(value, names);
                } else {
                    collect_redacted_placeholders(value, path, names);
                }
                path.pop();
            }
        }
        YamlValue::String(value) if yaml::secret_scalar(value) => {
            if let Some(name) = yaml::environment_placeholder(value) {
                names.insert(name.to_owned());
            }
        }
        _ => {}
    }
}

fn collect_placeholders(value: &YamlValue, names: &mut BTreeSet<String>) {
    match value {
        YamlValue::String(value) => {
            if let Some(name) = yaml::environment_placeholder(value) {
                names.insert(name.to_owned());
            }
        }
        YamlValue::Sequence(values) => {
            for value in values {
                collect_placeholders(value, names);
            }
        }
        YamlValue::Mapping(values) => {
            for value in values.values() {
                collect_placeholders(value, names);
            }
        }
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn draft_component(
    profile: &str,
    kind: ComponentKind,
    name: &str,
    body: String,
    location: &str,
    native_format: &str,
    mut extra: Vec<(String, String)>,
) -> Result<ComponentRecord, ClientError> {
    safe_name_or_file(name)?;
    let device = DeviceId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073982")
        .map_err(|_| invalid("Hermes component provenance cannot be derived"))?;
    let mut metadata = vec![
        ("profile".into(), profile.to_owned()),
        ("structuralLocation".into(), location.to_owned()),
        ("nativeFormat".into(), native_format.to_owned()),
    ];
    metadata.append(&mut extra);
    metadata.sort();
    let component = ComponentRecord {
        id: stable_record_id(&format!("draft|{profile}|{kind:?}|{location}|{name}"))?,
        scope: ScopeRef::Global,
        kind,
        name: name.to_owned(),
        body_markdown: body,
        metadata,
        provenance: Provenance {
            origin_device: device,
            harness: Some(HarnessId::Hermes),
            source: None,
            created_hlc: HybridLogicalClock::new(0, 0, device),
        },
        archived: false,
    };
    component
        .validate()
        .map_err(|_| invalid("Hermes component exceeds protocol limits"))?;
    Ok(component)
}

fn permission_metadata(
    _profile: &str,
    path: &str,
    fidelity: &str,
    reason: &str,
) -> Vec<(String, String)> {
    vec![
        ("nativePermissionPath".into(), path.to_owned()),
        ("mappingFidelity".into(), fidelity.to_owned()),
        ("mappingReason".into(), reason.to_owned()),
    ]
}

fn canonical_json(value: &JsonValue) -> Result<String, ClientError> {
    serde_json::to_string(value).map_err(|_| invalid("Hermes reviewed value is not representable"))
}

fn get<'a>(mapping: &'a serde_yaml_ng::Mapping, key: &str) -> Option<&'a serde_yaml_ng::Value> {
    mapping.get(YamlValue::String(key.to_owned()))
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest(Sha256::digest(bytes).into())
}

fn stable_record_id(key: &str) -> Result<RecordId, ClientError> {
    let mut bytes: [u8; 32] = Sha256::digest(key.as_bytes()).into();
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    RecordId::from_str(&format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    ))
    .map_err(|_| invalid("Hermes component identifier cannot be derived"))
}

fn read_required_reviewed_file(
    root: &Path,
    path: &Path,
    location: &str,
) -> Result<Vec<u8>, ClientError> {
    read_optional_reviewed_file(root, path, location)?
        .ok_or_else(|| path_error(location, "was not found"))
}

fn read_optional_reviewed_file(
    root: &Path,
    path: &Path,
    location: &str,
) -> Result<Option<Vec<u8>>, ClientError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(path_error(location, "cannot be inspected")),
    };
    if is_link_or_reparse_point(&metadata) || !metadata.is_file() {
        return Err(path_error(location, "is not a regular file"));
    }
    let canonical =
        fs::canonicalize(path).map_err(|_| path_error(location, "cannot be safely resolved"))?;
    if !canonical.starts_with(root) {
        return Err(path_error(location, "escaped its allowlist"));
    }
    let bytes = fs::read(&canonical).map_err(|_| path_error(location, "cannot be read"))?;
    if bytes.len() > context_relay_protocol::MAX_MARKDOWN_BYTES {
        return Err(path_error(location, "exceeds the size limit"));
    }
    Ok(Some(bytes))
}

fn optional_real_directory(
    root: &Path,
    path: &Path,
    location: &str,
) -> Result<Option<PathBuf>, ClientError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(path_error(location, "cannot be inspected")),
    };
    if is_link_or_reparse_point(&metadata) || !metadata.is_dir() {
        return Err(path_error(location, "is not a regular directory"));
    }
    let canonical =
        fs::canonicalize(path).map_err(|_| path_error(location, "cannot be safely resolved"))?;
    if !canonical.starts_with(root) {
        return Err(path_error(location, "escaped its allowlist"));
    }
    Ok(Some(canonical))
}

fn direct_safe_directories(root: &Path, location: &str) -> Result<Vec<PathBuf>, ClientError> {
    let mut directories = Vec::new();
    let mut count = 0usize;
    for entry in fs::read_dir(root).map_err(|_| path_error(location, "cannot be enumerated"))? {
        count += 1;
        if count > MAX_TREE_ENTRIES {
            return Err(path_error(location, "contains too many entries"));
        }
        let entry = entry.map_err(|_| path_error(location, "contains an unreadable entry"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| path_error(location, "contains an unsafe entry name"))?;
        safe_name(&name)?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|_| path_error(location, "contains an unreadable entry"))?;
        if is_link_or_reparse_point(&metadata) {
            return Err(path_error(location, "contains a linked entry"));
        }
        if !metadata.is_dir() {
            continue;
        }
        let canonical = fs::canonicalize(entry.path())
            .map_err(|_| path_error(location, "contains an unresolved entry"))?;
        if canonical.parent() != Some(root) {
            return Err(path_error(location, "contains an escaped entry"));
        }
        directories.push(canonical);
    }
    directories.sort();
    Ok(directories)
}

fn collect_skill_files(
    root: &Path,
    directory: &Path,
    depth: usize,
    count: &mut usize,
    files: &mut Vec<PathBuf>,
) -> Result<(), ClientError> {
    if depth > MAX_TREE_DEPTH {
        return Err(path_error("profile:skills", "exceeds the depth limit"));
    }
    for entry in
        fs::read_dir(directory).map_err(|_| path_error("profile:skills", "cannot be enumerated"))?
    {
        *count += 1;
        if *count > MAX_TREE_ENTRIES {
            return Err(path_error("profile:skills", "contains too many entries"));
        }
        let entry =
            entry.map_err(|_| path_error("profile:skills", "contains an unreadable entry"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| path_error("profile:skills", "contains an unsafe entry name"))?;
        if name != "SKILL.md" {
            safe_name(&name)?;
        }
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|_| path_error("profile:skills", "contains an unreadable entry"))?;
        if is_link_or_reparse_point(&metadata) {
            return Err(path_error("profile:skills", "contains a linked entry"));
        }
        if metadata.is_dir() {
            let canonical = fs::canonicalize(entry.path())
                .map_err(|_| path_error("profile:skills", "contains an unresolved entry"))?;
            if !canonical.starts_with(root) {
                return Err(path_error("profile:skills", "contains an escaped entry"));
            }
            collect_skill_files(root, &canonical, depth + 1, count, files)?;
        } else if metadata.is_file() && name == "SKILL.md" {
            files.push(entry.path());
        }
    }
    Ok(())
}

fn reviewed_file_exists(path: &Path) -> Result<bool, ClientError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if is_link_or_reparse_point(&metadata) => {
            Err(invalid("Hermes project context is linked"))
        }
        Ok(metadata) if metadata.is_file() => Ok(true),
        Ok(_) => Err(invalid("Hermes project context is not a regular file")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(invalid("Hermes project context cannot be inspected")),
    }
}

fn display_relative(path: &Path) -> Result<String, ClientError> {
    let mut parts = Vec::new();
    for component in path.components() {
        let Component::Normal(part) = component else {
            return Err(invalid("Hermes relative path is invalid"));
        };
        let part = part
            .to_str()
            .ok_or_else(|| invalid("Hermes relative path is not UTF-8"))?;
        if part.contains('/') || part.contains('\\') || part.chars().any(char::is_control) {
            return Err(invalid("Hermes relative path is unsafe"));
        }
        parts.push(part);
    }
    Ok(parts.join("/"))
}

fn safe_name(name: &str) -> Result<(), ClientError> {
    let bytes = name.as_bytes();
    if !(1..=128).contains(&bytes.len())
        || !(bytes[0].is_ascii_alphanumeric())
        || !bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        || name == "."
        || name == ".."
    {
        return Err(invalid("Hermes reviewed name is unsafe"));
    }
    Ok(())
}

fn safe_name_or_file(name: &str) -> Result<(), ClientError> {
    if name == ".hermes.md" {
        return Ok(());
    }
    if name.contains('/') {
        for part in name.split('/') {
            safe_name(part)?;
        }
        Ok(())
    } else {
        safe_name(name)
    }
}

fn is_link_or_reparse_point(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn path_error(location: &str, reason: &str) -> ClientError {
    ClientError {
        code: ErrorCode::InvalidRequest,
        message: format!("Hermes reviewed path {location} {reason}"),
        field_path: None,
        retryable: false,
    }
}

pub(super) fn validate_bound_scope(
    adapter: &HermesAdapter,
    native_scope: &NativeScope,
) -> Result<ScopeRef, ClientError> {
    match native_scope {
        NativeScope::Global => Ok(ScopeRef::Global),
        NativeScope::Project { project_id, root }
            if *project_id == adapter.project_id && *root == adapter.project_root_wire() =>
        {
            Ok(ScopeRef::Project {
                project_id: *project_id,
            })
        }
        NativeScope::Project { .. } => {
            Err(invalid("Hermes import requested an unconfigured project"))
        }
    }
}
