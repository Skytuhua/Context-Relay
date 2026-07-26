use std::{
    collections::BTreeSet,
    env, fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    str::FromStr,
    thread,
    time::{Duration, Instant},
};

use context_relay_native_runner::{NativeState, OsNativeFileSystem};
use context_relay_protocol::{
    ApplyReceipt, CapabilityLevel, ChangeClass, ClassifiedChanges, CliOperation, CliOperations,
    ClientError, ComponentKind, ComponentRecord, DesiredState, DeviceId, DiscoveredScopes,
    ErrorCode, HarnessAdapter, HarnessId, HybridLogicalClock, ImportRequest, ImportedState,
    InstallationMethod, NativePlatform, NativeScope, ProbeContext, ProbeReport, ProjectId,
    Provenance, RecordId, RenderedFile, RenderedState, ScopeRef, SemanticDiff, Sha256Digest,
    ValidationReport, WireNativeValue,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::native_transaction::{
    engine::{BoundaryError, FrozenOutput, NativeAdapter, RestrictedRun},
    model::{ApprovedMutation, MutationKind, NativeTransactionPlan, RestorableStateFingerprint},
};

const SUPPORTED_VERSIONS: [&str; 2] = ["2.1.214", "2.1.213"];
const CLI_TIMEOUT_MS: u32 = 30_000;
const CLI_OUTPUT_LIMIT: u64 = 64 * 1024;
const MANAGED_START: &str = "<!-- context-relay:start -->";
const MANAGED_END: &str = "<!-- context-relay:end -->";

#[derive(Clone, Debug)]
pub struct ClaudeCodeLayout {
    pub executable: PathBuf,
    pub version: String,
    pub installation_method: InstallationMethod,
    pub config_dir: PathBuf,
    pub state_path: PathBuf,
    pub project_root: PathBuf,
    pub managed_settings_paths: Vec<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct ClaudeCodeAdapter {
    layout: ClaudeCodeLayout,
    project_id: ProjectId,
    origin_device: DeviceId,
    observed_hlc: HybridLogicalClock,
    executable_hash: Sha256Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ClaudeCommand {
    Doctor,
    PluginList,
    McpList,
    McpGet(String),
}

impl ClaudeCommand {
    fn argv(&self) -> Vec<String> {
        match self {
            Self::Doctor => vec!["doctor".to_owned()],
            Self::PluginList => {
                vec!["plugin".to_owned(), "list".to_owned(), "--json".to_owned()]
            }
            Self::McpList => vec!["mcp".to_owned(), "list".to_owned()],
            Self::McpGet(name) => vec!["mcp".to_owned(), "get".to_owned(), name.clone()],
        }
    }
}

impl ClaudeCodeAdapter {
    pub fn discover(
        project_root: impl Into<PathBuf>,
        project_id: ProjectId,
        origin_device: DeviceId,
        observed_hlc: HybridLogicalClock,
    ) -> Result<Self, ClientError> {
        let project_root = project_root.into();
        let executable = find_executable().ok_or_else(|| {
            client_error(
                ErrorCode::NotFound,
                "Claude Code executable was not found",
                false,
            )
        })?;
        let executable_hash = digest_file(&executable)?;
        let output = run_bounded_command(&executable, &["--version"], executable_hash)?;
        let version =
            parse_version(std::str::from_utf8(&output).unwrap_or_default()).ok_or_else(|| {
                client_error(
                    ErrorCode::HarnessUnsupported,
                    "Claude Code returned an invalid version",
                    false,
                )
            })?;
        parse_doctor_output(&run_bounded_command(
            &executable,
            &["doctor"],
            executable_hash,
        )?)?;
        let home = home_dir().ok_or_else(|| {
            client_error(
                ErrorCode::NotFound,
                "The user configuration root was not found",
                false,
            )
        })?;
        let config_dir = env::var_os("CLAUDE_CONFIG_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".claude"));
        let state_path = if env::var_os("CLAUDE_CONFIG_DIR").is_some() {
            config_dir.join(".claude.json")
        } else {
            home.join(".claude.json")
        };
        Self::from_layout(
            ClaudeCodeLayout {
                installation_method: installation_method(&executable),
                executable,
                version,
                config_dir,
                state_path,
                project_root,
                managed_settings_paths: managed_settings_paths(),
            },
            project_id,
            origin_device,
            observed_hlc,
        )
    }

    pub fn from_layout(
        layout: ClaudeCodeLayout,
        project_id: ProjectId,
        origin_device: DeviceId,
        observed_hlc: HybridLogicalClock,
    ) -> Result<Self, ClientError> {
        if parse_version(&layout.version).as_deref() != Some(layout.version.as_str()) {
            return Err(client_error(
                ErrorCode::InvalidRequest,
                "Claude Code version is invalid",
                false,
            ));
        }
        let executable_hash = digest_file(&layout.executable)?;
        Ok(Self {
            layout,
            project_id,
            origin_device,
            observed_hlc,
            executable_hash,
        })
    }

    pub fn project_root_wire(&self) -> WireNativeValue {
        wire_path(&self.layout.project_root)
    }

    pub fn project_settings_path(&self) -> PathBuf {
        self.layout
            .project_root
            .join(".claude")
            .join("settings.json")
    }

    pub fn plan_native_settings(
        &self,
        desired: &DesiredState,
    ) -> Result<ApprovedMutation, ClientError> {
        self.require_apply_supported()?;
        desired
            .validate()
            .map_err(|_| invalid_request("Desired Claude Code state is invalid"))?;
        let path = self.project_settings_path();
        let bytes = self.render_settings(
            &path,
            desired,
            ScopeRef::Project {
                project_id: self.project_id,
            },
        )?;
        let snapshot = OsNativeFileSystem::new()
            .snapshot(&path)
            .map_err(|_| invalid_request("Claude Code settings cannot be safely inspected"))?;
        let NativeState::RegularFile { metadata, .. } = snapshot.state() else {
            return Err(invalid_request(
                "Claude Code mixed settings must already exist",
            ));
        };
        let intended = NativeState::regular_file(bytes, metadata.clone());
        Ok(ApprovedMutation {
            target: wire_path(&path),
            kind: MutationKind::Payload,
            content: intended
                .encode_v1()
                .map_err(|_| invalid_request("Claude Code settings are not representable"))?,
            expected: RestorableStateFingerprint(Sha256Digest(*snapshot.fingerprint())),
            intended: RestorableStateFingerprint(Sha256Digest(intended.fingerprint())),
        })
    }

    pub fn plan_native_file(
        &self,
        component: &ComponentRecord,
    ) -> Result<ApprovedMutation, ClientError> {
        self.require_apply_supported()?;
        component
            .validate()
            .map_err(|_| invalid_request("Claude Code file component is invalid"))?;
        if !matches!(
            component.kind,
            ComponentKind::Instruction | ComponentKind::Rule | ComponentKind::Skill
        ) {
            return Err(invalid_request("Claude Code file component is invalid"));
        }
        let path = component_path(self, component)?;
        let snapshot = OsNativeFileSystem::new()
            .snapshot(&path)
            .map_err(|_| invalid_request("Claude Code Markdown cannot be safely inspected"))?;
        let NativeState::RegularFile { bytes, metadata } = snapshot.state() else {
            return Err(invalid_request(
                "Claude Code Markdown must already exist before it is managed",
            ));
        };
        let intended = NativeState::regular_file(
            render_managed_markdown(bytes, &component.body_markdown, component.archived)?,
            metadata.clone(),
        );
        Ok(ApprovedMutation {
            target: wire_path(&path),
            kind: MutationKind::Payload,
            content: intended
                .encode_v1()
                .map_err(|_| invalid_request("Claude Code Markdown is not representable"))?,
            expected: RestorableStateFingerprint(Sha256Digest(*snapshot.fingerprint())),
            intended: RestorableStateFingerprint(Sha256Digest(intended.fingerprint())),
        })
    }

    fn capability(&self) -> CapabilityLevel {
        if SUPPORTED_VERSIONS.contains(&self.layout.version.as_str()) {
            CapabilityLevel::Full
        } else {
            CapabilityLevel::ImportOnly
        }
    }

    fn require_apply_supported(&self) -> Result<(), ClientError> {
        (self.capability() == CapabilityLevel::Full)
            .then_some(())
            .ok_or_else(|| {
                client_error(
                    ErrorCode::HarnessUnsupported,
                    "This Claude Code version is import-only",
                    false,
                )
            })
    }

    fn policy_conflicts(&self) -> Vec<String> {
        let mut conflicts = Vec::new();
        if self
            .layout
            .managed_settings_paths
            .iter()
            .any(|path| path.is_file())
        {
            conflicts.push("managed_settings_active".to_owned());
        }
        if !project_is_approved(&self.layout.state_path, &self.layout.project_root) {
            conflicts.push("project_unapproved".to_owned());
        }
        match project_mcp_approval_status(&self.layout.state_path, &self.layout.project_root) {
            Ok((true, false)) => conflicts.push("project_mcp_approvals_configured".to_owned()),
            Ok((true, true)) => {
                conflicts.push("project_mcp_approvals_configured".to_owned());
                conflicts.push("project_mcp_approval_conflict".to_owned());
            }
            Ok((false, _)) => {}
            Err(()) => conflicts.push("project_mcp_approvals_invalid".to_owned()),
        }
        conflicts
    }

    fn validation_commands(&self) -> Result<Vec<ClaudeCommand>, ClientError> {
        let path = self.layout.project_root.join(".mcp.json");
        let names = match read_optional_file(&path)? {
            Some(bytes) => {
                let value = parse_object(&bytes, "Claude Code MCP configuration is invalid")?;
                let mut names = match value.get("mcpServers") {
                    Some(servers) => servers
                        .as_object()
                        .ok_or_else(|| invalid_request("Claude Code MCP configuration is invalid"))?
                        .keys()
                        .cloned()
                        .collect::<Vec<_>>(),
                    None => Vec::new(),
                };
                for name in &names {
                    safe_name(name)?;
                }
                names.sort();
                names
            }
            None => Vec::new(),
        };
        Ok(validation_commands(names))
    }

    fn import_scope(
        &self,
        scope: ScopeRef,
        include_disabled: bool,
        components: &mut Vec<ComponentRecord>,
        digests: &mut BTreeSet<Sha256Digest>,
    ) -> Result<(), ClientError> {
        match scope {
            ScopeRef::Global => {
                self.import_markdown_tree(
                    &self.layout.config_dir,
                    ScopeRef::Global,
                    components,
                    digests,
                )?;
                self.import_settings(
                    &self.layout.config_dir.join("settings.json"),
                    ScopeRef::Global,
                    include_disabled,
                    components,
                    digests,
                )?;
                self.import_state_mcp(None, ScopeRef::Global, components, digests)?;
            }
            ScopeRef::Project { project_id } => {
                self.import_markdown_tree(
                    &self.layout.project_root,
                    ScopeRef::Project { project_id },
                    components,
                    digests,
                )?;
                self.import_settings(
                    &self.project_settings_path(),
                    ScopeRef::Project { project_id },
                    include_disabled,
                    components,
                    digests,
                )?;
                self.import_mcp_file(
                    &self.layout.project_root.join(".mcp.json"),
                    ScopeRef::Project { project_id },
                    components,
                    digests,
                )?;
                self.import_state_mcp(
                    Some(&self.layout.project_root),
                    ScopeRef::Project { project_id },
                    components,
                    digests,
                )?;
            }
        }
        Ok(())
    }

    fn import_markdown_tree(
        &self,
        root: &Path,
        scope: ScopeRef,
        components: &mut Vec<ComponentRecord>,
        digests: &mut BTreeSet<Sha256Digest>,
    ) -> Result<(), ClientError> {
        let instruction_paths = if matches!(scope, ScopeRef::Global) {
            vec![(root.join("CLAUDE.md"), "CLAUDE.md")]
        } else {
            vec![
                (root.join("CLAUDE.md"), "CLAUDE.md"),
                (root.join(".claude").join("CLAUDE.md"), ".claude/CLAUDE.md"),
            ]
        };
        for (path, location) in instruction_paths {
            self.import_markdown(
                &path,
                location,
                ComponentKind::Instruction,
                location,
                scope.clone(),
                components,
                digests,
            )?;
        }
        let claude_root = if matches!(scope, ScopeRef::Global) {
            root.to_path_buf()
        } else {
            root.join(".claude")
        };
        for (directory, kind) in [
            ("rules", ComponentKind::Rule),
            ("skills", ComponentKind::Skill),
        ] {
            let tree = claude_root.join(directory);
            for path in reviewed_markdown_files(&tree, kind)? {
                let relative = path
                    .strip_prefix(&tree)
                    .map_err(|_| invalid_request("Claude Code path escaped its allowlist"))?;
                let location = format!("{directory}/{}", display_relative(relative)?);
                let name = if kind == ComponentKind::Skill {
                    relative
                        .parent()
                        .and_then(Path::file_name)
                        .and_then(|name| name.to_str())
                        .ok_or_else(|| invalid_request("Claude Code skill name is invalid"))?
                        .to_owned()
                } else {
                    display_relative(relative)?
                };
                self.import_markdown(
                    &path,
                    &location,
                    kind,
                    &name,
                    scope.clone(),
                    components,
                    digests,
                )?;
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn import_markdown(
        &self,
        path: &Path,
        location: &str,
        kind: ComponentKind,
        name: &str,
        scope: ScopeRef,
        components: &mut Vec<ComponentRecord>,
        digests: &mut BTreeSet<Sha256Digest>,
    ) -> Result<(), ClientError> {
        let Some(bytes) = read_optional_file(path)? else {
            return Ok(());
        };
        let body = String::from_utf8(bytes.clone())
            .map_err(|_| invalid_request("Claude Code Markdown is not UTF-8"))?;
        digests.insert(digest(&bytes));
        components.push(self.component(scope, kind, name, body, location)?);
        Ok(())
    }

    fn import_settings(
        &self,
        path: &Path,
        scope: ScopeRef,
        include_disabled: bool,
        components: &mut Vec<ComponentRecord>,
        digests: &mut BTreeSet<Sha256Digest>,
    ) -> Result<(), ClientError> {
        let Some(bytes) = read_optional_file(path)? else {
            return Ok(());
        };
        let value = parse_object(&bytes, "Claude Code settings are invalid")?;
        digests.insert(digest(&bytes));
        for (key, kind) in [
            ("permissions", ComponentKind::PermissionDeclaration),
            ("hooks", ComponentKind::Hook),
        ] {
            if let Some(value) = value.get(key) {
                components.push(self.component(
                    scope.clone(),
                    kind,
                    key,
                    canonical_json(value)?,
                    &format!("settings.json#{key}"),
                )?);
            }
        }
        if let Some(plugins) = value.get("enabledPlugins").and_then(Value::as_object) {
            for (name, enabled) in plugins {
                let enabled = enabled
                    .as_bool()
                    .ok_or_else(|| invalid_request("Claude Code plugin state is invalid"))?;
                if enabled || include_disabled {
                    let mut component = self.component(
                        scope.clone(),
                        ComponentKind::Plugin,
                        name,
                        enabled.to_string(),
                        &format!("settings.json#enabledPlugins/{name}"),
                    )?;
                    component.archived = !enabled;
                    components.push(component);
                }
            }
        }
        Ok(())
    }

    fn import_mcp_file(
        &self,
        path: &Path,
        scope: ScopeRef,
        components: &mut Vec<ComponentRecord>,
        digests: &mut BTreeSet<Sha256Digest>,
    ) -> Result<(), ClientError> {
        let Some(bytes) = read_optional_file(path)? else {
            return Ok(());
        };
        let value = parse_object(&bytes, "Claude Code MCP configuration is invalid")?;
        digests.insert(digest(&bytes));
        self.import_mcp_map(
            value.get("mcpServers"),
            scope,
            ".mcp.json#mcpServers",
            components,
            digests,
        )
    }

    fn import_state_mcp(
        &self,
        project: Option<&Path>,
        scope: ScopeRef,
        components: &mut Vec<ComponentRecord>,
        digests: &mut BTreeSet<Sha256Digest>,
    ) -> Result<(), ClientError> {
        let Some(bytes) = read_optional_file(&self.layout.state_path)? else {
            return Ok(());
        };
        let value = parse_object(&bytes, "Claude Code state is invalid")?;
        let servers = if let Some(project) = project {
            value
                .get("projects")
                .and_then(Value::as_object)
                .and_then(|projects| projects.get(project.to_string_lossy().as_ref()))
                .and_then(Value::as_object)
                .and_then(|project| project.get("mcpServers"))
        } else {
            value.get("mcpServers")
        };
        self.import_mcp_map(
            servers,
            scope,
            ".claude.json#mcpServers",
            components,
            digests,
        )
    }

    fn import_mcp_map(
        &self,
        servers: Option<&Value>,
        scope: ScopeRef,
        location: &str,
        components: &mut Vec<ComponentRecord>,
        digests: &mut BTreeSet<Sha256Digest>,
    ) -> Result<(), ClientError> {
        let Some(servers) = servers else {
            return Ok(());
        };
        let servers = servers
            .as_object()
            .ok_or_else(|| invalid_request("Claude Code MCP configuration is invalid"))?;
        for (name, server) in servers {
            let redacted = redact_sensitive(server.clone());
            let body = canonical_json(&redacted)?;
            digests.insert(digest(body.as_bytes()));
            components.push(self.component(
                scope.clone(),
                ComponentKind::McpServer,
                name,
                body,
                &format!("{location}/{name}"),
            )?);
        }
        Ok(())
    }

    fn component(
        &self,
        scope: ScopeRef,
        kind: ComponentKind,
        name: &str,
        body_markdown: String,
        location: &str,
    ) -> Result<ComponentRecord, ClientError> {
        let scope_key = match scope {
            ScopeRef::Global => "global".to_owned(),
            ScopeRef::Project { project_id } => format!("project:{project_id}"),
        };
        let component = ComponentRecord {
            id: stable_record_id(&format!("{scope_key}|{kind:?}|{location}|{name}"))?,
            scope,
            kind,
            name: name.to_owned(),
            body_markdown,
            metadata: vec![("structuralLocation".to_owned(), location.to_owned())],
            provenance: Provenance {
                origin_device: self.origin_device,
                harness: Some(HarnessId::ClaudeCode),
                source: None,
                created_hlc: self.observed_hlc,
            },
            archived: false,
        };
        component
            .validate()
            .map_err(|_| invalid_request("Claude Code component exceeds protocol limits"))?;
        Ok(component)
    }

    fn render_settings(
        &self,
        path: &Path,
        desired: &DesiredState,
        scope: ScopeRef,
    ) -> Result<Vec<u8>, ClientError> {
        let existing = read_optional_file(path)?
            .ok_or_else(|| invalid_request("Claude Code mixed settings must already exist"))?;
        let mut settings = parse_object(&existing, "Claude Code settings are invalid")?;
        for component in desired
            .components
            .iter()
            .filter(|component| component.scope == scope)
        {
            let key = match component.kind {
                ComponentKind::PermissionDeclaration => "permissions",
                ComponentKind::Hook => "hooks",
                _ => continue,
            };
            if component.archived {
                settings.remove(key);
            } else {
                settings.insert(
                    key.to_owned(),
                    serde_json::from_str(&component.body_markdown).map_err(|_| {
                        invalid_request("Claude Code settings component is invalid")
                    })?,
                );
            }
        }
        serde_json::to_vec(&Value::Object(settings))
            .map_err(|_| invalid_request("Claude Code settings cannot be rendered"))
    }

    fn render_cli_operation(
        &self,
        component: &ComponentRecord,
    ) -> Result<Option<CliOperation>, ClientError> {
        let scope = cli_scope(&component.scope);
        let arguments = match component.kind {
            ComponentKind::Plugin => {
                safe_name(&component.name)?;
                if component.archived {
                    vec![
                        "plugin".to_owned(),
                        "uninstall".to_owned(),
                        component.name.clone(),
                        "--scope".to_owned(),
                        scope.to_owned(),
                        "--keep-data".to_owned(),
                    ]
                } else {
                    vec![
                        "plugin".to_owned(),
                        "install".to_owned(),
                        component.name.clone(),
                        "--scope".to_owned(),
                        scope.to_owned(),
                    ]
                }
            }
            ComponentKind::McpServer => {
                safe_name(&component.name)?;
                if component.archived {
                    vec![
                        "mcp".to_owned(),
                        "remove".to_owned(),
                        component.name.clone(),
                        "--scope".to_owned(),
                        scope.to_owned(),
                    ]
                } else {
                    let value: Value = serde_json::from_str(&component.body_markdown)
                        .map_err(|_| invalid_request("Claude Code MCP component is invalid"))?;
                    if contains_redaction(&value) {
                        return Err(invalid_request(
                            "Redacted Claude Code MCP configuration cannot be applied",
                        ));
                    }
                    vec![
                        "mcp".to_owned(),
                        "add-json".to_owned(),
                        component.name.clone(),
                        canonical_json(&value)?,
                        "--scope".to_owned(),
                        scope.to_owned(),
                    ]
                }
            }
            _ => return Ok(None),
        };
        Ok(Some(CliOperation {
            executable: wire_path(&self.layout.executable),
            arguments: arguments
                .into_iter()
                .map(|argument| wire_text(&argument))
                .collect(),
            timeout_ms: CLI_TIMEOUT_MS,
        }))
    }
}

impl HarnessAdapter for ClaudeCodeAdapter {
    fn probe(&self, context: &ProbeContext) -> Result<ProbeReport, ClientError> {
        context
            .validate()
            .map_err(|_| invalid_request("Claude Code probe context is invalid"))?;
        if context.harness != HarnessId::ClaudeCode {
            return Err(invalid_request(
                "Claude Code adapter received another harness",
            ));
        }
        Ok(ProbeReport {
            executable: Some(wire_path(&self.layout.executable)),
            executable_sha256: Some(self.executable_hash),
            harness_version: Some(self.layout.version.clone()),
            installation_method: self.layout.installation_method,
            config_roots: vec![
                wire_path(&self.layout.config_dir),
                wire_path(&self.layout.project_root),
            ],
            active_profile: context.requested_profile.clone(),
            policy_conflicts: self.policy_conflicts(),
            capability: self.capability(),
        })
    }

    fn discover_scopes(&self, report: &ProbeReport) -> Result<DiscoveredScopes, ClientError> {
        report
            .validate()
            .map_err(|_| invalid_request("Claude Code probe report is invalid"))?;
        Ok(DiscoveredScopes(vec![
            NativeScope::Global,
            NativeScope::Project {
                project_id: self.project_id,
                root: self.project_root_wire(),
            },
        ]))
    }

    fn import(&self, request: &ImportRequest) -> Result<ImportedState, ClientError> {
        request
            .validate()
            .map_err(|_| invalid_request("Claude Code import request is invalid"))?;
        let mut components = Vec::new();
        let mut digests = BTreeSet::new();
        let mut seen = BTreeSet::new();
        for scope in &request.scopes {
            let key = match scope {
                NativeScope::Global => "global".to_owned(),
                NativeScope::Project { project_id, root }
                    if *project_id == self.project_id && *root == self.project_root_wire() =>
                {
                    format!("project:{project_id}")
                }
                NativeScope::Project { .. } => {
                    return Err(invalid_request(
                        "Claude Code import requested an unconfigured project",
                    ));
                }
            };
            if !seen.insert(key) {
                return Err(invalid_request("Claude Code import repeated a scope"));
            }
            let scope = match scope {
                NativeScope::Global => ScopeRef::Global,
                NativeScope::Project { project_id, .. } => ScopeRef::Project {
                    project_id: *project_id,
                },
            };
            self.import_scope(
                scope,
                request.include_disabled,
                &mut components,
                &mut digests,
            )?;
        }
        components.sort_by_key(|component| component.id);
        Ok(ImportedState {
            components,
            source_digests: digests.into_iter().collect(),
        })
    }

    fn render(&self, desired: &DesiredState) -> Result<RenderedState, ClientError> {
        self.require_apply_supported()?;
        desired
            .validate()
            .map_err(|_| invalid_request("Desired Claude Code state is invalid"))?;
        let mut files = Vec::new();
        let mut cli_operations = Vec::new();
        let mut settings_scopes = Vec::new();
        for component in &desired.components {
            match component.kind {
                ComponentKind::Hook | ComponentKind::PermissionDeclaration => {
                    if !settings_scopes.contains(&component.scope) {
                        settings_scopes.push(component.scope.clone());
                    }
                }
                ComponentKind::Plugin | ComponentKind::McpServer => {
                    if let Some(operation) = self.render_cli_operation(component)? {
                        cli_operations.push(operation);
                    }
                }
                ComponentKind::Instruction | ComponentKind::Rule | ComponentKind::Skill => {
                    if component.archived {
                        continue;
                    }
                    let path = component_path(self, component)?;
                    let bytes = component.body_markdown.as_bytes();
                    files.push(RenderedFile {
                        path: wire_path(&path),
                        bytes_sha256: digest(bytes),
                        byte_length: bytes.len() as u64,
                    });
                }
            }
        }
        for scope in settings_scopes {
            let path = settings_path(self, &scope)?;
            let bytes = self.render_settings(&path, desired, scope)?;
            files.push(RenderedFile {
                path: wire_path(&path),
                bytes_sha256: digest(&bytes),
                byte_length: bytes.len() as u64,
            });
        }
        files.sort_by(|left, right| left.path.bytes.cmp(&right.path.bytes));
        Ok(RenderedState {
            files,
            cli_operations,
        })
    }

    fn classify(&self, diff: &SemanticDiff) -> Result<ClassifiedChanges, ClientError> {
        diff.validate()
            .map_err(|_| invalid_request("Claude Code semantic diff is invalid"))?;
        if !diff.conflicts.is_empty() {
            return Err(client_error(
                ErrorCode::Conflict,
                "Claude Code semantic diff has conflicts",
                false,
            ));
        }
        Ok(ClassifiedChanges(diff.changes.clone()))
    }

    fn plan_cli_ops(&self, changes: &ClassifiedChanges) -> Result<CliOperations, ClientError> {
        self.require_apply_supported()?;
        changes
            .validate()
            .map_err(|_| invalid_request("Claude Code changes are invalid"))?;
        let mut operations = Vec::new();
        for change in &changes.0 {
            let (kind, scope, name) = parse_change_target(&change.target)?;
            let component = ComponentRecord {
                id: stable_record_id(&change.target)?,
                scope,
                kind,
                name,
                body_markdown: change.summary.clone(),
                metadata: vec![],
                provenance: Provenance {
                    origin_device: self.origin_device,
                    harness: Some(HarnessId::ClaudeCode),
                    source: None,
                    created_hlc: self.observed_hlc,
                },
                archived: matches!(change.class, ChangeClass::Remove | ChangeClass::Disable),
            };
            if let Some(operation) = self.render_cli_operation(&component)? {
                operations.push(operation);
            }
        }
        Ok(CliOperations(operations))
    }

    fn validate_effective(&self, receipt: &ApplyReceipt) -> Result<ValidationReport, ClientError> {
        receipt
            .validate()
            .map_err(|_| invalid_request("Claude Code receipt is invalid"))?;
        self.require_apply_supported()?;
        let commands = self.validation_commands()?;
        let mut listed_mcp = BTreeSet::new();
        for command in commands {
            let argv = command.argv();
            let arguments = argv.iter().map(String::as_str).collect::<Vec<_>>();
            let output =
                run_bounded_command(&self.layout.executable, &arguments, self.executable_hash)?;
            match command {
                ClaudeCommand::Doctor => parse_doctor_output(&output)?,
                ClaudeCommand::PluginList => parse_plugin_list_output(&output)?,
                ClaudeCommand::McpList => listed_mcp = parse_mcp_list_output(&output)?,
                ClaudeCommand::McpGet(name) => {
                    if !listed_mcp.contains(&name) {
                        return Ok(ValidationReport {
                            valid: false,
                            findings: vec!["configured_mcp_server_missing".to_owned()],
                        });
                    }
                    parse_mcp_get_output(&output, &name)?;
                }
            }
        }
        Ok(ValidationReport {
            valid: true,
            findings: vec![],
        })
    }
}

impl NativeAdapter for ClaudeCodeAdapter {
    fn reprobe_live_state(&mut self, plan: &NativeTransactionPlan) -> Result<(), BoundaryError> {
        if self.capability() != CapabilityLevel::Full
            || plan.setup.harness != HarnessId::ClaudeCode
            || plan.setup.harness_version != self.layout.version
            || plan.setup.executable_path != wire_path(&self.layout.executable)
            || digest_file_boundary(&self.layout.executable)? != plan.setup.executable_hash
        {
            return Err(BoundaryError::new("Claude Code installation changed"));
        }
        Ok(())
    }

    fn compare_approved_digests(
        &mut self,
        plan: &NativeTransactionPlan,
    ) -> Result<(), BoundaryError> {
        for expected in &plan.setup.expected_native_digests {
            let path = decode_wire_path(&expected.target)?;
            let actual = if path.is_file() {
                Some(digest_file_boundary(&path)?)
            } else {
                None
            };
            if actual != expected.expected_digest {
                return Err(BoundaryError::new("Claude Code native state changed"));
            }
        }
        Ok(())
    }

    fn validate_staged_output(
        &mut self,
        plan: &NativeTransactionPlan,
        run: &RestrictedRun,
    ) -> Result<FrozenOutput, BoundaryError> {
        if run.staged_output_hash != plan.expected_semantic_output_hash
            || run.scanner_result_hash != plan.scanner_result_hash
        {
            return Err(BoundaryError::new("Claude Code staged output changed"));
        }
        Ok(FrozenOutput {
            staged_output_hash: run.staged_output_hash,
            scanner_result_hash: run.scanner_result_hash,
        })
    }

    fn validate_effective(
        &mut self,
        plan: &NativeTransactionPlan,
        receipt: &ApplyReceipt,
    ) -> Result<(), BoundaryError> {
        let intended = plan
            .mutations
            .iter()
            .map(|mutation| mutation.intended.0)
            .collect::<Vec<_>>();
        if receipt.plan_id != plan.setup.plan_id || receipt.resulting_digests != intended {
            return Err(BoundaryError::new(
                "Claude Code effective state differs from the plan",
            ));
        }
        Ok(())
    }
}

fn component_path(
    adapter: &ClaudeCodeAdapter,
    component: &ComponentRecord,
) -> Result<PathBuf, ClientError> {
    let root = match component.scope {
        ScopeRef::Global => adapter.layout.config_dir.clone(),
        ScopeRef::Project { project_id } if project_id == adapter.project_id => {
            adapter.layout.project_root.join(".claude")
        }
        ScopeRef::Project { .. } => {
            return Err(invalid_request(
                "Claude Code component names an unconfigured project",
            ));
        }
    };
    match component.kind {
        ComponentKind::Instruction => {
            if component.name == "CLAUDE.md" && matches!(component.scope, ScopeRef::Project { .. })
            {
                Ok(adapter.layout.project_root.join("CLAUDE.md"))
            } else if component.name == ".claude/CLAUDE.md" {
                Ok(adapter
                    .layout
                    .project_root
                    .join(".claude")
                    .join("CLAUDE.md"))
            } else if matches!(component.scope, ScopeRef::Global) {
                Ok(adapter.layout.config_dir.join("CLAUDE.md"))
            } else {
                Err(invalid_request(
                    "Claude Code instruction location is invalid",
                ))
            }
        }
        ComponentKind::Rule => {
            safe_relative_name(&component.name)?;
            Ok(root.join("rules").join(&component.name))
        }
        ComponentKind::Skill => {
            safe_name(&component.name)?;
            Ok(root.join("skills").join(&component.name).join("SKILL.md"))
        }
        _ => Err(invalid_request("Claude Code file component is invalid")),
    }
}

fn settings_path(adapter: &ClaudeCodeAdapter, scope: &ScopeRef) -> Result<PathBuf, ClientError> {
    match scope {
        ScopeRef::Global => Ok(adapter.layout.config_dir.join("settings.json")),
        ScopeRef::Project { project_id } if *project_id == adapter.project_id => {
            Ok(adapter.project_settings_path())
        }
        ScopeRef::Project { .. } => Err(invalid_request(
            "Claude Code settings name an unconfigured project",
        )),
    }
}

fn validation_commands(mcp_names: Vec<String>) -> Vec<ClaudeCommand> {
    let mut commands = vec![
        ClaudeCommand::Doctor,
        ClaudeCommand::PluginList,
        ClaudeCommand::McpList,
    ];
    commands.extend(mcp_names.into_iter().map(ClaudeCommand::McpGet));
    commands
}

fn run_bounded_command(
    executable: &Path,
    arguments: &[&str],
    expected_hash: Sha256Digest,
) -> Result<Vec<u8>, ClientError> {
    if digest_file(executable)? != expected_hash {
        return Err(client_error(
            ErrorCode::Conflict,
            "Claude Code executable changed",
            false,
        ));
    }
    let mut child = Command::new(executable)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| {
            client_error(
                ErrorCode::HarnessUnsupported,
                "Claude Code command failed",
                true,
            )
        })?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| invalid_request("Claude Code command output is unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| invalid_request("Claude Code command output is unavailable"))?;
    let stdout_thread = thread::spawn(move || read_capped(stdout));
    let stderr_thread = thread::spawn(move || read_capped(stderr));
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|_| {
            client_error(
                ErrorCode::HarnessUnsupported,
                "Claude Code command failed",
                true,
            )
        })? {
            break status;
        }
        if started.elapsed() >= Duration::from_millis(u64::from(CLI_TIMEOUT_MS)) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(client_error(
                ErrorCode::Timeout,
                "Claude Code command timed out",
                true,
            ));
        }
        thread::sleep(Duration::from_millis(10));
    };
    let stdout = stdout_thread
        .join()
        .map_err(|_| invalid_request("Claude Code command output is invalid"))?
        .map_err(|_| invalid_request("Claude Code command output is invalid"))?;
    let stderr = stderr_thread
        .join()
        .map_err(|_| invalid_request("Claude Code command output is invalid"))?
        .map_err(|_| invalid_request("Claude Code command output is invalid"))?;
    if !status.success() || !stderr.is_empty() {
        return Err(client_error(
            ErrorCode::HarnessUnsupported,
            "Claude Code command failed",
            false,
        ));
    }
    Ok(stdout)
}

fn read_capped(reader: impl Read) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(CLI_OUTPUT_LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > CLI_OUTPUT_LIMIT {
        return Err(std::io::Error::other("output limit exceeded"));
    }
    Ok(bytes)
}

fn bounded_utf8(bytes: &[u8]) -> Result<&str, ClientError> {
    if bytes.len() as u64 > CLI_OUTPUT_LIMIT {
        return Err(invalid_request("Claude Code command output is too large"));
    }
    std::str::from_utf8(bytes)
        .map_err(|_| invalid_request("Claude Code command output is not UTF-8"))
}

fn parse_doctor_output(bytes: &[u8]) -> Result<(), ClientError> {
    (bounded_utf8(bytes)?.trim() == "Claude Code diagnostics: OK")
        .then_some(())
        .ok_or_else(|| invalid_request("Claude Code doctor output is invalid"))
}

fn parse_plugin_list_output(bytes: &[u8]) -> Result<(), ClientError> {
    bounded_utf8(bytes)?;
    let plugins = serde_json::from_slice::<Value>(bytes)
        .ok()
        .and_then(|value| value.as_array().cloned())
        .filter(|plugins| plugins.len() <= 256)
        .ok_or_else(|| invalid_request("Claude Code plugin output is invalid"))?;
    for plugin in plugins {
        let plugin = plugin
            .as_object()
            .ok_or_else(|| invalid_request("Claude Code plugin output is invalid"))?;
        let allowed = ["id", "version", "enabled", "errors"];
        if plugin.keys().any(|key| !allowed.contains(&key.as_str()))
            || plugin.len() != allowed.len()
        {
            return Err(invalid_request("Claude Code plugin output is invalid"));
        }
        safe_name(
            plugin
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid_request("Claude Code plugin output is invalid"))?,
        )?;
        let version = plugin
            .get("version")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_request("Claude Code plugin output is invalid"))?;
        if version.is_empty()
            || version.len() > 128
            || !version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"+._-".contains(&byte))
            || plugin.get("enabled").and_then(Value::as_bool).is_none()
            || plugin
                .get("errors")
                .and_then(Value::as_array)
                .is_none_or(|errors| !errors.is_empty())
        {
            return Err(invalid_request("Claude Code plugin output is invalid"));
        }
    }
    Ok(())
}

fn parse_mcp_list_output(bytes: &[u8]) -> Result<BTreeSet<String>, ClientError> {
    let output = bounded_utf8(bytes)?;
    let mut names = BTreeSet::new();
    for line in output.lines() {
        let (name, detail) = line
            .split_once(": ")
            .ok_or_else(|| invalid_request("Claude Code MCP list output is invalid"))?;
        safe_name(name)?;
        let (endpoint, kind) = detail
            .rsplit_once(" (")
            .filter(|(_, kind)| kind.ends_with(')'))
            .ok_or_else(|| invalid_request("Claude Code MCP list output is invalid"))?;
        if endpoint.is_empty()
            || endpoint.len() > 2_048
            || endpoint.chars().any(char::is_control)
            || kind.len() < 2
            || kind.len() > 33
            || !kind[..kind.len() - 1]
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || !names.insert(name.to_owned())
        {
            return Err(invalid_request("Claude Code MCP list output is invalid"));
        }
    }
    Ok(names)
}

fn parse_mcp_get_output(bytes: &[u8], expected_name: &str) -> Result<(), ClientError> {
    bounded_utf8(bytes)?;
    let server = serde_json::from_slice::<Value>(bytes)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .ok_or_else(|| invalid_request("Claude Code MCP get output is invalid"))?;
    if server
        .keys()
        .any(|key| !["name", "type", "url"].contains(&key.as_str()))
        || server.len() != 3
        || server.get("name").and_then(Value::as_str) != Some(expected_name)
    {
        return Err(invalid_request("Claude Code MCP get output is invalid"));
    }
    safe_name(expected_name)?;
    for key in ["type", "url"] {
        let value = server
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_request("Claude Code MCP get output is invalid"))?;
        if value.is_empty() || value.len() > 2_048 || value.chars().any(char::is_control) {
            return Err(invalid_request("Claude Code MCP get output is invalid"));
        }
    }
    Ok(())
}

fn render_managed_markdown(
    existing: &[u8],
    body: &str,
    archived: bool,
) -> Result<Vec<u8>, ClientError> {
    let existing = std::str::from_utf8(existing)
        .map_err(|_| invalid_request("Claude Code Markdown is not UTF-8"))?;
    if body.contains(MANAGED_START) || body.contains(MANAGED_END) {
        return Err(invalid_request(
            "Claude Code managed Markdown contains reserved markers",
        ));
    }
    let starts = existing.match_indices(MANAGED_START).collect::<Vec<_>>();
    let ends = existing.match_indices(MANAGED_END).collect::<Vec<_>>();
    let rendered = match (starts.as_slice(), ends.as_slice()) {
        ([], []) if !archived => {
            let mut rendered = existing.to_owned();
            if !rendered.is_empty() && !rendered.ends_with('\n') {
                rendered.push('\n');
            }
            rendered.push_str(MANAGED_START);
            rendered.push('\n');
            rendered.push_str(body);
            if !body.ends_with('\n') {
                rendered.push('\n');
            }
            rendered.push_str(MANAGED_END);
            rendered.push('\n');
            rendered
        }
        ([(start, _)], [(end, _)]) if start < end => {
            let suffix = end + MANAGED_END.len();
            if archived {
                format!("{}{}", &existing[..*start], &existing[suffix..])
            } else {
                let mut rendered = existing[..start + MANAGED_START.len()].to_owned();
                rendered.push('\n');
                rendered.push_str(body);
                if !body.ends_with('\n') {
                    rendered.push('\n');
                }
                rendered.push_str(&existing[*end..]);
                rendered
            }
        }
        _ => {
            return Err(invalid_request(
                "Claude Code managed Markdown markers are malformed",
            ));
        }
    };
    if rendered.len() > 1024 * 1024 {
        return Err(invalid_request("Claude Code managed Markdown is too large"));
    }
    Ok(rendered.into_bytes())
}

fn reviewed_markdown_files(root: &Path, kind: ComponentKind) -> Result<Vec<PathBuf>, ClientError> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let metadata = fs::symlink_metadata(root)
        .map_err(|_| invalid_request("Claude Code configuration cannot be inspected"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid_request(
            "Claude Code configuration has unsafe topology",
        ));
    }
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)
            .map_err(|_| invalid_request("Claude Code configuration cannot be inspected"))?
        {
            let entry = entry
                .map_err(|_| invalid_request("Claude Code configuration cannot be inspected"))?;
            let metadata = entry
                .file_type()
                .map_err(|_| invalid_request("Claude Code configuration cannot be inspected"))?;
            if metadata.is_symlink() {
                return Err(invalid_request(
                    "Claude Code configuration has unsafe topology",
                ));
            }
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file()
                && match kind {
                    ComponentKind::Rule => entry.path().extension().is_some_and(|ext| ext == "md"),
                    ComponentKind::Skill => entry.file_name() == "SKILL.md",
                    _ => false,
                }
            {
                files.push(entry.path());
            }
        }
    }
    files.sort();
    Ok(files)
}

fn read_optional_file(path: &Path) -> Result<Option<Vec<u8>>, ClientError> {
    if !path.exists() {
        return Ok(None);
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| invalid_request("Claude Code configuration cannot be inspected"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 1024 * 1024 {
        return Err(invalid_request(
            "Claude Code configuration has unsafe topology or size",
        ));
    }
    fs::read(path)
        .map(Some)
        .map_err(|_| invalid_request("Claude Code configuration cannot be read"))
}

fn parse_object(bytes: &[u8], message: &'static str) -> Result<Map<String, Value>, ClientError> {
    serde_json::from_slice::<Value>(bytes)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .ok_or_else(|| invalid_request(message))
}

fn canonical_json(value: &Value) -> Result<String, ClientError> {
    serde_json::to_string(value)
        .map_err(|_| invalid_request("Claude Code configuration cannot be serialized"))
}

fn redact_sensitive(value: Value) -> Value {
    match value {
        Value::Object(values) => Value::Object(
            values
                .into_iter()
                .map(|(key, value)| {
                    let folded = key.to_ascii_lowercase().replace(['-', '_'], "");
                    let sensitive = [
                        "env",
                        "headers",
                        "oauth",
                        "token",
                        "secret",
                        "password",
                        "authorization",
                        "apikey",
                    ]
                    .iter()
                    .any(|name| folded.contains(name));
                    (
                        key,
                        if sensitive {
                            Value::String("<redacted>".to_owned())
                        } else {
                            redact_sensitive(value)
                        },
                    )
                })
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.into_iter().map(redact_sensitive).collect()),
        value => value,
    }
}

fn contains_redaction(value: &Value) -> bool {
    match value {
        Value::String(value) => value == "<redacted>",
        Value::Array(values) => values.iter().any(contains_redaction),
        Value::Object(values) => values.values().any(contains_redaction),
        _ => false,
    }
}

fn project_is_approved(state_path: &Path, project_root: &Path) -> bool {
    read_optional_file(state_path)
        .ok()
        .flatten()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|state| {
            state
                .get("projects")?
                .get(project_root.to_string_lossy().as_ref())?
                .get("hasTrustDialogAccepted")?
                .as_bool()
        })
        == Some(true)
}

fn project_mcp_approval_status(state_path: &Path, project_root: &Path) -> Result<(bool, bool), ()> {
    let Some(bytes) = read_optional_file(state_path).map_err(|_| ())? else {
        return Ok((false, false));
    };
    let state = serde_json::from_slice::<Value>(&bytes).map_err(|_| ())?;
    let Some(project) = state
        .get("projects")
        .and_then(Value::as_object)
        .and_then(|projects| projects.get(project_root.to_string_lossy().as_ref()))
        .and_then(Value::as_object)
    else {
        return Ok((false, false));
    };
    let configured = [
        "enableAllProjectMcpServers",
        "enabledMcpjsonServers",
        "disabledMcpjsonServers",
    ]
    .iter()
    .any(|key| project.contains_key(*key));
    if !configured {
        return Ok((false, false));
    }
    if project
        .get("enableAllProjectMcpServers")
        .is_some_and(|value| !value.is_boolean())
    {
        return Err(());
    }
    let enabled = approval_names(project.get("enabledMcpjsonServers"))?;
    let disabled = approval_names(project.get("disabledMcpjsonServers"))?;
    Ok((true, !enabled.is_disjoint(&disabled)))
}

fn approval_names(value: Option<&Value>) -> Result<BTreeSet<String>, ()> {
    let Some(value) = value else {
        return Ok(BTreeSet::new());
    };
    let values = value
        .as_array()
        .filter(|values| values.len() <= 256)
        .ok_or(())?;
    let mut names = BTreeSet::new();
    for value in values {
        let name = value.as_str().ok_or(())?;
        safe_name(name).map_err(|_| ())?;
        if !names.insert(name.to_owned()) {
            return Err(());
        }
    }
    Ok(names)
}

fn stable_record_id(key: &str) -> Result<RecordId, ClientError> {
    let mut bytes: [u8; 32] = Sha256::digest(key.as_bytes()).into();
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let id = format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    );
    RecordId::from_str(&id)
        .map_err(|_| invalid_request("Claude Code component identifier cannot be derived"))
}

fn parse_change_target(target: &str) -> Result<(ComponentKind, ScopeRef, String), ClientError> {
    let mut parts = target.splitn(4, ':');
    let kind = match parts.next() {
        Some("claude-plugin") => ComponentKind::Plugin,
        Some("claude-mcp") => ComponentKind::McpServer,
        _ => return Err(invalid_request("Claude Code CLI change target is invalid")),
    };
    let scope = match parts.next() {
        Some("global") => ScopeRef::Global,
        Some("project") => {
            let project = parts
                .next()
                .ok_or_else(|| invalid_request("Claude Code CLI change target is invalid"))?;
            ScopeRef::Project {
                project_id: ProjectId::from_str(project)
                    .map_err(|_| invalid_request("Claude Code CLI project is invalid"))?,
            }
        }
        _ => return Err(invalid_request("Claude Code CLI scope is invalid")),
    };
    let name = parts
        .next()
        .ok_or_else(|| invalid_request("Claude Code CLI component name is missing"))?
        .to_owned();
    Ok((kind, scope, name))
}

fn safe_name(name: &str) -> Result<(), ClientError> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.len() > 255
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"@._-".contains(&byte))
    {
        return Err(invalid_request("Claude Code component name is unsafe"));
    }
    Ok(())
}

fn safe_relative_name(name: &str) -> Result<(), ClientError> {
    if name.is_empty()
        || Path::new(name).is_absolute()
        || Path::new(name)
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
        || !name.ends_with(".md")
    {
        return Err(invalid_request("Claude Code relative path is unsafe"));
    }
    Ok(())
}

fn display_relative(path: &Path) -> Result<String, ClientError> {
    let value = path
        .to_str()
        .ok_or_else(|| invalid_request("Claude Code relative path is not Unicode"))?
        .replace('\\', "/");
    safe_relative_name(&value)?;
    Ok(value)
}

fn cli_scope(scope: &ScopeRef) -> &'static str {
    match scope {
        ScopeRef::Global => "user",
        ScopeRef::Project { .. } => "project",
    }
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest(Sha256::digest(bytes).into())
}

fn digest_file(path: &Path) -> Result<Sha256Digest, ClientError> {
    hash_file(path).map_err(|_| {
        client_error(
            ErrorCode::NotFound,
            "Claude Code executable is missing",
            false,
        )
    })
}

fn digest_file_boundary(path: &Path) -> Result<Sha256Digest, BoundaryError> {
    hash_file(path).map_err(|_| BoundaryError::new("Claude Code file cannot be read"))
}

fn hash_file(path: &Path) -> std::io::Result<Sha256Digest> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            return Ok(Sha256Digest(hasher.finalize().into()));
        }
        hasher.update(&buffer[..read]);
    }
}

fn parse_version(output: &str) -> Option<String> {
    let version = output.split_whitespace().next()?;
    let mut parts = version.split('.');
    let valid = (0..3).all(|_| {
        parts
            .next()
            .is_some_and(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    }) && parts.next().is_none();
    valid.then(|| version.to_owned())
}

fn find_executable() -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    let names: &[&str] = if cfg!(windows) {
        &["claude.exe", "claude.cmd"]
    } else {
        &["claude"]
    };
    env::split_paths(&path)
        .flat_map(|directory| names.iter().map(move |name| directory.join(name)))
        .find(|candidate| candidate.is_file())
}

fn installation_method(path: &Path) -> InstallationMethod {
    let folded = path.to_string_lossy().to_ascii_lowercase();
    if folded.contains("node_modules")
        || folded.contains("npm")
        || folded.contains("homebrew")
        || folded.contains("winget")
        || folded.contains("/opt/")
    {
        InstallationMethod::PackageManager
    } else {
        InstallationMethod::Manual
    }
}

fn home_dir() -> Option<PathBuf> {
    env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from)
}

fn managed_settings_paths() -> Vec<PathBuf> {
    if cfg!(windows) {
        env::var_os("ProgramFiles")
            .map(PathBuf::from)
            .into_iter()
            .map(|root| root.join("ClaudeCode").join("managed-settings.json"))
            .collect()
    } else if cfg!(target_os = "macos") {
        vec![PathBuf::from(
            "/Library/Application Support/ClaudeCode/managed-settings.json",
        )]
    } else {
        vec![PathBuf::from("/etc/claude-code/managed-settings.json")]
    }
}

fn wire_text(value: &str) -> WireNativeValue {
    let mut wire = wire_path(Path::new(value));
    wire.display = Some(value.to_owned());
    wire
}

#[cfg(windows)]
fn wire_path(path: &Path) -> WireNativeValue {
    use std::os::windows::ffi::OsStrExt as _;

    WireNativeValue {
        platform: NativePlatform::Windows,
        bytes: path
            .as_os_str()
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect(),
        display: path.to_str().map(str::to_owned),
    }
}

#[cfg(not(windows))]
fn wire_path(path: &Path) -> WireNativeValue {
    use std::os::unix::ffi::OsStrExt as _;

    WireNativeValue {
        platform: NativePlatform::Macos,
        bytes: path.as_os_str().as_bytes().to_vec(),
        display: path.to_str().map(str::to_owned),
    }
}

#[cfg(windows)]
fn decode_wire_path(value: &WireNativeValue) -> Result<PathBuf, BoundaryError> {
    use std::{ffi::OsString, os::windows::ffi::OsStringExt as _};

    if value.platform != NativePlatform::Windows || !value.bytes.len().is_multiple_of(2) {
        return Err(BoundaryError::new("Claude Code native path is invalid"));
    }
    Ok(PathBuf::from(OsString::from_wide(
        &value
            .bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>(),
    )))
}

#[cfg(not(windows))]
fn decode_wire_path(value: &WireNativeValue) -> Result<PathBuf, BoundaryError> {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt as _};

    if value.platform != NativePlatform::Macos || value.bytes.contains(&0) {
        return Err(BoundaryError::new("Claude Code native path is invalid"));
    }
    Ok(PathBuf::from(OsString::from_vec(value.bytes.clone())))
}

fn invalid_request(message: &'static str) -> ClientError {
    client_error(ErrorCode::InvalidRequest, message, false)
}

fn client_error(code: ErrorCode, message: &'static str, retryable: bool) -> ClientError {
    ClientError {
        code,
        message: message.to_owned(),
        field_path: None,
        retryable,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        digest_file, parse_doctor_output, parse_mcp_get_output, parse_mcp_list_output,
        parse_plugin_list_output, validation_commands,
    };
    use serde_json::Value;
    use std::fs;

    #[test]
    fn standalone_executable_hashing_is_not_limited_like_configuration() {
        let path = std::env::temp_dir().join(format!(
            "context-relay-claude-code-large-executable-{}",
            std::process::id()
        ));
        fs::write(&path, vec![0; 1024 * 1024 + 1]).unwrap();
        let result = digest_file(&path);
        let _ = fs::remove_file(path);
        assert!(result.is_ok());
    }

    #[test]
    fn validation_uses_only_reviewed_read_only_commands_and_bounded_outputs() {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/claude-code-2.1.214.json"))
                .unwrap();
        let commands = validation_commands(vec!["docs".to_owned()]);
        assert_eq!(
            commands
                .into_iter()
                .map(|command| command.argv())
                .collect::<Vec<_>>(),
            vec![
                vec!["doctor".to_owned()],
                vec!["plugin".to_owned(), "list".to_owned(), "--json".to_owned()],
                vec!["mcp".to_owned(), "list".to_owned()],
                vec!["mcp".to_owned(), "get".to_owned(), "docs".to_owned()],
            ]
        );
        parse_doctor_output(fixture["doctorOutput"].as_str().unwrap().as_bytes()).unwrap();
        parse_plugin_list_output(
            serde_json::to_vec(&fixture["pluginListJson"])
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        parse_mcp_list_output(fixture["mcpListOutput"].as_str().unwrap().as_bytes()).unwrap();
        parse_mcp_get_output(
            serde_json::to_vec(&fixture["mcpGetOutput"])
                .unwrap()
                .as_slice(),
            "docs",
        )
        .unwrap();
    }

    #[test]
    fn validation_rejects_unbounded_malformed_or_secret_output() {
        assert!(parse_doctor_output(&vec![b'x'; 65 * 1024]).is_err());
        assert!(parse_plugin_list_output(br#"[{"id":"ok","token":"secret"}]"#).is_err());
        assert!(parse_mcp_list_output(b"not a reviewed line").is_err());
        assert!(
            parse_mcp_get_output(
                br#"{"name":"docs","type":"http","url":"https://example.com","headers":{"Authorization":"secret"}}"#,
                "docs",
            )
            .is_err()
        );
    }
}
