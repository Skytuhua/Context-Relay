use std::{
    collections::BTreeSet,
    env, fs,
    io::{Read, Seek, SeekFrom},
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

mod mcp_state;
use mcp_state::McpConfiguration;
mod command_context;
use command_context::ClaudeCommandContext;

use crate::mcp::install::{
    BRIDGE_SERVER_NAME, is_canonical_bridge_body, is_managed_bridge_component,
};
use crate::native_memory::{
    NativeMemoryAdapter, NativeMemoryCapabilities, NativeMemoryDisable, NativeMemoryDocumentKind,
    has_managed_memory_hook_identity, is_primary_memory_instruction_component,
    merge_managed_memory_hooks,
};
use crate::native_transaction::{
    cli::{CliMutationOutcome, CliRestoreOutcome, NativeCliExecutor},
    engine::{BoundaryError, FrozenOutput, NativeAdapter, RestrictedRun},
    model::{
        ApprovedCliMutation, ApprovedMutation, CanonicalCliDeclaration, MutationKind,
        NativeTransactionPlan, RestorableStateFingerprint,
    },
};

const SUPPORTED_VERSIONS: [&str; 2] = ["2.1.214", "2.1.213"];
const CLI_TIMEOUT_MS: u32 = 30_000;
const CLI_OUTPUT_LIMIT: u64 = 64 * 1024;
// Bound the combined native MCP inventory independently of the adapter DTO limit.
const MAX_MCP_VALIDATION_NAMES: usize = 64;
const MANAGED_START: &str = "<!-- context-relay:start -->";
const MANAGED_END: &str = "<!-- context-relay:end -->";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BridgeDeclarationProbeError {
    Conflict,
    Inspection,
}

impl From<BridgeDeclarationProbeError> for BoundaryError {
    fn from(error: BridgeDeclarationProbeError) -> Self {
        BoundaryError::new(match error {
            BridgeDeclarationProbeError::Conflict => {
                "Claude Code prior MCP declaration is disabled or unmanaged"
            }
            BridgeDeclarationProbeError::Inspection => {
                "Claude Code managed bridge state cannot be safely inspected"
            }
        })
    }
}

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

pub trait ClaudeCodeCommandRunner {
    fn before_launch(&mut self, _arguments: &[String]) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn run(&mut self, command: VerifiedClaudeCommand<'_>) -> Result<Vec<u8>, BoundaryError>;
}

impl<F> ClaudeCodeCommandRunner for F
where
    F: FnMut(&[String]) -> Result<Vec<u8>, BoundaryError>,
{
    fn run(&mut self, command: VerifiedClaudeCommand<'_>) -> Result<Vec<u8>, BoundaryError> {
        self(command.arguments())
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ClaudeCodeProcessRunner;

impl ClaudeCodeCommandRunner for ClaudeCodeProcessRunner {
    fn run(&mut self, command: VerifiedClaudeCommand<'_>) -> Result<Vec<u8>, BoundaryError> {
        command.execute()
    }
}

pub struct ClaudeCodeCliExecutor<'a, O> {
    adapter: &'a ClaudeCodeAdapter,
    operation_runner: O,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ClaudeCommand {
    Doctor,
    PluginList,
}

impl ClaudeCommand {
    fn argv(&self) -> Vec<String> {
        match self {
            Self::Doctor => vec!["doctor".to_owned()],
            Self::PluginList => {
                vec!["plugin".to_owned(), "list".to_owned(), "--json".to_owned()]
            }
        }
    }
}

impl ClaudeCodeAdapter {
    pub fn project_id(&self) -> ProjectId {
        self.project_id
    }

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
        if env::var_os("CLAUDE_CODE_CUSTOM_OAUTH_URL").is_some_and(|value| !value.is_empty()) {
            return Err(client_error(
                ErrorCode::HarnessUnsupported,
                "Claude Code custom OAuth state is not supported",
                false,
            ));
        }
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
        let command_context = ClaudeCommandContext::new(&config_dir, &state_path, &project_root)?;
        let executable_hash = digest_file(&executable)?;
        let version = discover_version_with(|arguments| {
            run_bounded_command(&executable, arguments, executable_hash, &command_context)
        })?;
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

    fn command_context(&self) -> Result<ClaudeCommandContext, ClientError> {
        ClaudeCommandContext::new(
            &self.layout.config_dir,
            &self.layout.state_path,
            &self.layout.project_root,
        )
    }

    fn validate_cli_context(&self, mutation: &ApprovedCliMutation) -> Result<(), BoundaryError> {
        let context = self
            .command_context()
            .map_err(|_| BoundaryError::new("Claude Code configuration binding is invalid"))?;
        if mutation.execution_context.as_ref() != Some(&context.approval_binding()) {
            return Err(BoundaryError::new(
                "Claude Code command context differs from the approved setup; request a new preview",
            ));
        }
        context
            .validate()
            .map_err(|_| BoundaryError::new("Claude Code configuration binding changed"))
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
        self.plan_native_settings_for_scope(
            desired,
            ScopeRef::Project {
                project_id: self.project_id,
            },
        )
    }

    pub fn plan_native_global_settings(
        &self,
        desired: &DesiredState,
    ) -> Result<ApprovedMutation, ClientError> {
        self.plan_native_settings_for_scope(desired, ScopeRef::Global)
    }

    fn plan_native_settings_for_scope(
        &self,
        desired: &DesiredState,
        scope: ScopeRef,
    ) -> Result<ApprovedMutation, ClientError> {
        self.require_apply_supported()?;
        desired
            .validate()
            .map_err(|_| invalid_request("Desired Claude Code state is invalid"))?;
        let path = settings_path(self, &scope)?;
        let bytes = self.render_settings(&path, desired, scope)?;
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
        if is_primary_memory_instruction_component(HarnessId::ClaudeCode, component) {
            let (path, expected, _, intended) =
                self.primary_memory_instruction_projection(component)?;
            return Ok(ApprovedMutation {
                target: wire_path(&path),
                kind: MutationKind::Payload,
                content: intended
                    .encode_v1()
                    .map_err(|_| invalid_request("Claude Code Markdown is not representable"))?,
                expected: RestorableStateFingerprint(Sha256Digest(expected)),
                intended: RestorableStateFingerprint(Sha256Digest(intended.fingerprint())),
            });
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

    fn primary_memory_instruction_projection(
        &self,
        component: &ComponentRecord,
    ) -> Result<(PathBuf, [u8; 32], NativeState, NativeState), ClientError> {
        let path = component_path(self, component)?;
        let snapshot = OsNativeFileSystem::new()
            .snapshot(&path)
            .map_err(|_| invalid_request("Claude Code Markdown cannot be safely inspected"))?;
        let current = snapshot.state().clone();
        let intended = match snapshot.state() {
            NativeState::RegularFile { bytes, metadata } => NativeState::regular_file(
                render_managed_markdown(bytes, &component.body_markdown, component.archived)?,
                metadata.clone(),
            ),
            NativeState::Absent { .. } if component.archived => current.clone(),
            NativeState::Absent { .. } => {
                let template_path = path.with_file_name(".mcp.json");
                let template =
                    OsNativeFileSystem::new()
                        .snapshot(&template_path)
                        .map_err(|_| {
                            invalid_request(
                                "Claude Code primary instruction metadata template is unavailable",
                            )
                        })?;
                let NativeState::RegularFile { metadata, .. } = template.state() else {
                    return Err(invalid_request(
                        "Claude Code primary instruction needs an existing project-root metadata template",
                    ));
                };
                let metadata = metadata
                    .for_absent_sibling_creation(&current)
                    .map_err(|_| {
                        invalid_request(
                            "Claude Code primary instruction metadata template is not bound to the target parent",
                        )
                    })?;
                NativeState::regular_file(
                    render_managed_markdown(&[], &component.body_markdown, false)?,
                    metadata,
                )
            }
        };
        Ok((path, *snapshot.fingerprint(), current, intended))
    }

    pub fn plan_bridge_cli_mutation(
        &self,
        intended: &ComponentRecord,
    ) -> Result<ApprovedCliMutation, ClientError> {
        self.require_apply_supported()?;
        if !is_managed_bridge_component(HarnessId::ClaudeCode, intended) {
            return Err(invalid_request(
                "Claude Code CLI mutation requires the managed bridge",
            ));
        }
        self.command_context()?.validate()?;
        self.recheck_executable_client()?;
        let expected = self
            .probe_managed_declaration()
            .map_err(|error| match error {
                BridgeDeclarationProbeError::Conflict => client_error(
                    ErrorCode::Conflict,
                    "Claude Code managed bridge state cannot be safely inspected",
                    false,
                ),
                BridgeDeclarationProbeError::Inspection => {
                    invalid_request("Claude Code managed bridge state cannot be safely inspected")
                }
            })?;
        let intended_declaration = canonical_cli_declaration(&intended.body_markdown)?;
        Ok(ApprovedCliMutation {
            execution_context: Some(self.command_context()?.approval_binding()),
            stable_id: intended.id.to_string(),
            forward: vec![self.declaration_operation(Some(&intended_declaration))],
            rollback: vec![self.declaration_operation(expected.as_ref())],
            expected,
            intended: Some(intended_declaration),
        })
    }

    pub fn cli_executor(&self) -> ClaudeCodeCliExecutor<'_, ClaudeCodeProcessRunner> {
        self.cli_executor_with_runner(ClaudeCodeProcessRunner)
    }

    pub fn cli_executor_with_runner<O>(&self, operation_runner: O) -> ClaudeCodeCliExecutor<'_, O>
    where
        O: ClaudeCodeCommandRunner,
    {
        ClaudeCodeCliExecutor {
            adapter: self,
            operation_runner,
        }
    }

    fn recheck_executable_client(&self) -> Result<(), ClientError> {
        if digest_regular_non_link_file(&self.layout.executable)? != self.executable_hash {
            return Err(client_error(
                ErrorCode::Conflict,
                "Claude Code executable changed",
                false,
            ));
        }
        Ok(())
    }

    fn recheck_executable_boundary(&self) -> Result<(), BoundaryError> {
        if digest_regular_non_link_file_boundary(&self.layout.executable)? != self.executable_hash {
            return Err(BoundaryError::new("Claude Code executable changed"));
        }
        Ok(())
    }

    fn run_verified(
        &self,
        runner: &mut impl ClaudeCodeCommandRunner,
        arguments: &[String],
    ) -> Result<Vec<u8>, BoundaryError> {
        let context = self
            .command_context()
            .map_err(|_| BoundaryError::new("Claude Code configuration binding is invalid"))?;
        context
            .validate()
            .map_err(|_| BoundaryError::new("Claude Code configuration binding changed"))?;
        let executable =
            open_verified_claude_executable(&self.layout.executable, self.executable_hash)?;
        runner.before_launch(arguments)?;
        executable.revalidate_before_launch()?;
        let launch = executable
            .prepare_launch()
            .map_err(|_| BoundaryError::new("Claude Code executable cannot be safely prepared"))?;
        runner.run(VerifiedClaudeCommand {
            executable: &executable,
            launch,
            arguments,
            context,
        })
    }

    fn declaration_operation(&self, declaration: Option<&CanonicalCliDeclaration>) -> CliOperation {
        let arguments = match declaration {
            Some(declaration) => vec![
                "mcp".to_owned(),
                "add-json".to_owned(),
                BRIDGE_SERVER_NAME.to_owned(),
                declaration.canonical_body.clone(),
                "--scope".to_owned(),
                "user".to_owned(),
            ],
            None => vec![
                "mcp".to_owned(),
                "remove".to_owned(),
                BRIDGE_SERVER_NAME.to_owned(),
                "--scope".to_owned(),
                "user".to_owned(),
            ],
        };
        CliOperation {
            executable: wire_path(&self.layout.executable),
            arguments: arguments
                .into_iter()
                .map(|argument| wire_text(&argument))
                .collect(),
            timeout_ms: CLI_TIMEOUT_MS,
        }
    }

    fn probe_managed_declaration(
        &self,
    ) -> Result<Option<CanonicalCliDeclaration>, BridgeDeclarationProbeError> {
        self.command_context()
            .and_then(|context| context.validate())
            .map_err(|_| BridgeDeclarationProbeError::Inspection)?;
        McpConfiguration::read(&self.layout)
            .map_err(|_| BridgeDeclarationProbeError::Inspection)?
            .managed_declaration()
    }

    pub(crate) fn capability(&self) -> CapabilityLevel {
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
        self.imported_mcp_names()?;
        Ok(validation_commands())
    }

    fn imported_mcp_names(&self) -> Result<Vec<String>, ClientError> {
        McpConfiguration::read(&self.layout)?.names()
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
        let value = mcp_state::read_object(&self.layout.state_path)?;
        let servers = if let Some(project) = project {
            mcp_state::project_entry(&value, project)?.and_then(|project| project.get("mcpServers"))
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
            if component.kind == ComponentKind::Hook
                && has_managed_memory_hook_identity(HarnessId::ClaudeCode, component)
            {
                if settings.get(key).is_none() && component.archived {
                    continue;
                }
                let intended = merge_managed_memory_hooks(
                    HarnessId::ClaudeCode,
                    settings.get(key),
                    component,
                )?;
                settings.insert(key.to_owned(), intended);
            } else if component.archived {
                settings.remove(key);
            } else {
                let intended = serde_json::from_str(&component.body_markdown)
                    .map_err(|_| invalid_request("Claude Code settings component is invalid"))?;
                settings.insert(key.to_owned(), intended);
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

impl NativeMemoryAdapter for ClaudeCodeAdapter {
    fn native_memory_capabilities(&self) -> Result<NativeMemoryCapabilities, ClientError> {
        let path = self.project_settings_path();
        let supported = SUPPORTED_VERSIONS.contains(&self.layout.version.as_str());
        let snapshot = match OsNativeFileSystem::new().snapshot(&path) {
            Ok(snapshot) => Some(snapshot),
            Err(context_relay_native_runner::RunnerError::Io)
                if safely_missing_project_settings(&self.layout.project_root, &path) =>
            {
                None
            }
            Err(_) => {
                return Err(invalid_request(
                    "Claude Code memory settings cannot be safely inspected",
                ));
            }
        };
        let (project_settings, metadata) = match snapshot.as_ref().map(|snapshot| snapshot.state())
        {
            Some(NativeState::RegularFile { bytes, metadata }) => {
                let settings = match parse_object(bytes, "Claude Code settings are invalid") {
                    Ok(settings) => settings,
                    Err(_) => {
                        return Ok(NativeMemoryCapabilities {
                            disable: NativeMemoryDisable::Unavailable,
                            sources: vec![],
                        });
                    }
                };
                (Some(settings), Some(metadata.clone()))
            }
            Some(NativeState::Absent { .. }) | None => (None, None),
        };
        let (effective_settings, managed) =
            match self.effective_native_memory_settings(project_settings.as_ref()) {
                Ok(effective) => effective,
                Err(_) => {
                    return Ok(NativeMemoryCapabilities {
                        disable: NativeMemoryDisable::Unavailable,
                        sources: vec![],
                    });
                }
            };
        let Some(memory_root) = self.bound_native_memory_root(&effective_settings, supported)?
        else {
            return Ok(NativeMemoryCapabilities {
                disable: NativeMemoryDisable::Unavailable,
                sources: vec![],
            });
        };
        let sources = self.native_memory_sources(&memory_root)?;
        if !supported || managed {
            let capabilities = NativeMemoryCapabilities {
                disable: NativeMemoryDisable::WatchOnly,
                sources,
            };
            capabilities.validate()?;
            return Ok(capabilities);
        }
        let (mut settings, metadata, expected) = match (project_settings, metadata, snapshot) {
            (Some(settings), Some(metadata), Some(snapshot)) => {
                (settings, metadata, *snapshot.fingerprint())
            }
            (None, None, Some(snapshot))
                if matches!(snapshot.state(), NativeState::Absent { .. }) =>
            {
                let metadata = missing_project_settings_metadata(&path, snapshot.state())?;
                (Map::new(), metadata, *snapshot.fingerprint())
            }
            _ => {
                return Ok(NativeMemoryCapabilities {
                    disable: NativeMemoryDisable::WatchOnly,
                    sources,
                });
            }
        };
        let mutations = match settings.get("autoMemoryEnabled") {
            Some(Value::Bool(false)) => vec![],
            Some(Value::Bool(true)) | None => {
                settings.insert("autoMemoryEnabled".to_owned(), Value::Bool(false));
                let rendered = serde_json::to_vec(&Value::Object(settings)).map_err(|_| {
                    invalid_request("Claude Code memory settings cannot be rendered")
                })?;
                let intended = NativeState::regular_file(rendered, metadata);
                vec![ApprovedMutation {
                    target: wire_path(&path),
                    kind: MutationKind::Payload,
                    content: intended.encode_v1().map_err(|_| {
                        invalid_request("Claude Code memory settings are not representable")
                    })?,
                    expected: RestorableStateFingerprint(Sha256Digest(expected)),
                    intended: RestorableStateFingerprint(Sha256Digest(intended.fingerprint())),
                }]
            }
            Some(_) => {
                let capabilities = NativeMemoryCapabilities {
                    disable: NativeMemoryDisable::WatchOnly,
                    sources,
                };
                capabilities.validate()?;
                return Ok(capabilities);
            }
        };
        let capabilities = NativeMemoryCapabilities {
            disable: NativeMemoryDisable::Supported(mutations),
            sources,
        };
        capabilities.validate()?;
        Ok(capabilities)
    }
}

impl ClaudeCodeAdapter {
    fn bound_native_memory_root(
        &self,
        settings: &Map<String, Value>,
        supported: bool,
    ) -> Result<Option<PathBuf>, ClientError> {
        if let Some(value) = settings.get("autoMemoryDirectory") {
            let Some(value) = value.as_str() else {
                return Ok(None);
            };
            let configured = Path::new(value);
            if value.is_empty()
                || value.len() > 4_096
                || configured
                    .components()
                    .any(|component| matches!(component, std::path::Component::ParentDir))
            {
                return Ok(None);
            }
            let root = if configured.is_absolute() {
                configured.to_path_buf()
            } else {
                if configured.components().any(|component| {
                    matches!(
                        component,
                        std::path::Component::RootDir | std::path::Component::Prefix(_)
                    )
                }) {
                    return Ok(None);
                }
                self.layout.project_root.join(configured)
            };
            return safe_memory_directory_binding(&root);
        }
        if !supported {
            return Ok(None);
        }
        let canonical_project = match fs::canonicalize(&self.layout.project_root) {
            Ok(path) => path,
            Err(_) => return Ok(None),
        };
        let key = canonical_project
            .to_string_lossy()
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() || character == '-' {
                    character
                } else {
                    '-'
                }
            })
            .collect::<String>();
        if key.is_empty() || key.len() > 4_096 {
            return Ok(None);
        }
        safe_memory_directory_binding(
            &self
                .layout
                .config_dir
                .join("projects")
                .join(key)
                .join("memory"),
        )
    }

    fn native_memory_sources(
        &self,
        root: &Path,
    ) -> Result<Vec<crate::native_memory::NativeMemorySource>, ClientError> {
        const MAX_TOPIC_FILES: usize = 32;

        let mut sources = vec![crate::native_memory::native_memory_source(
            HarnessId::ClaudeCode,
            &self.layout.version,
            ScopeRef::Project {
                project_id: self.project_id,
            },
            NativeMemoryDocumentKind::Agent,
            wire_path(&root.join("MEMORY.md")),
        )?];
        let mut topics = Vec::new();
        if let Ok(entries) = fs::read_dir(root) {
            for entry in entries.take(MAX_TOPIC_FILES + 1) {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(_) => continue,
                };
                let file_type = match entry.file_type() {
                    Ok(file_type) => file_type,
                    Err(_) => continue,
                };
                if !file_type.is_file() || file_type.is_symlink() {
                    continue;
                }
                let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                let folded = name.to_ascii_lowercase();
                if name == "MEMORY.md"
                    || !name.ends_with(".md")
                    || name.len() > 128
                    || folded.contains("session")
                    || folded.contains("history")
                    || folded.contains("rollout")
                    || folded.contains("raw_memories")
                {
                    continue;
                }
                topics.push(entry.path());
            }
        }
        topics.sort();
        topics.truncate(MAX_TOPIC_FILES);
        for path in topics {
            sources.push(crate::native_memory::native_memory_source(
                HarnessId::ClaudeCode,
                &self.layout.version,
                ScopeRef::Project {
                    project_id: self.project_id,
                },
                NativeMemoryDocumentKind::Topic,
                wire_path(&path),
            )?);
        }
        Ok(sources)
    }

    fn effective_native_memory_settings(
        &self,
        project_settings: Option<&Map<String, Value>>,
    ) -> Result<(Map<String, Value>, bool), ()> {
        let mut effective = project_settings.cloned().unwrap_or_default();
        let mut managed = false;
        let mut managed_directory = None::<Value>;
        for path in &self.layout.managed_settings_paths {
            if !path.is_file() {
                continue;
            }
            let settings = read_optional_file(path)
                .ok()
                .flatten()
                .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                .and_then(|value| value.as_object().cloned())
                .ok_or(())?;
            managed |= settings.contains_key("autoMemoryEnabled")
                || settings.contains_key("autoMemoryDirectory");
            if let Some(directory) = settings.get("autoMemoryDirectory") {
                if managed_directory
                    .as_ref()
                    .is_some_and(|current| current != directory)
                {
                    return Err(());
                }
                managed_directory = Some(directory.clone());
            }
        }
        if let Some(directory) = managed_directory {
            effective.insert("autoMemoryDirectory".to_owned(), directory);
        }
        Ok((effective, managed))
    }
}

fn safely_missing_project_settings(project_root: &Path, settings_path: &Path) -> bool {
    let expected_parent = project_root.join(".claude");
    if settings_path.parent() != Some(expected_parent.as_path())
        || settings_path
            .file_name()
            .is_none_or(|name| name != "settings.json")
    {
        return false;
    }
    let Ok(project_metadata) = fs::symlink_metadata(project_root) else {
        return false;
    };
    if project_metadata.file_type().is_symlink() || !project_metadata.is_dir() {
        return false;
    }
    let Ok(canonical_project) = fs::canonicalize(project_root) else {
        return false;
    };
    if canonical_project != project_root {
        return false;
    }
    match fs::symlink_metadata(&expected_parent) {
        Err(error) => error.kind() == std::io::ErrorKind::NotFound,
        Ok(parent_metadata)
            if parent_metadata.is_dir() && !parent_metadata.file_type().is_symlink() =>
        {
            matches!(
                fs::symlink_metadata(settings_path),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound
            )
        }
        Ok(_) => false,
    }
}

fn missing_project_settings_metadata(
    settings_path: &Path,
    absent: &NativeState,
) -> Result<context_relay_native_runner::NativeMetadata, ClientError> {
    let parent = settings_path
        .parent()
        .ok_or_else(|| invalid_request("Claude Code memory settings parent is unavailable"))?;
    let mut siblings = fs::read_dir(parent)
        .map_err(|_| invalid_request("Claude Code memory settings parent cannot be inspected"))?
        .map(|entry| {
            entry.map(|entry| entry.path()).map_err(|_| {
                invalid_request("Claude Code memory settings parent cannot be inspected")
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    siblings.sort();
    for sibling in siblings {
        if sibling == settings_path {
            continue;
        }
        let metadata = fs::symlink_metadata(&sibling).map_err(|_| {
            invalid_request("Claude Code memory settings sibling cannot be inspected")
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            continue;
        }
        let snapshot = OsNativeFileSystem::new().snapshot(&sibling).map_err(|_| {
            invalid_request("Claude Code memory settings sibling cannot be safely inspected")
        })?;
        let NativeState::RegularFile { metadata, .. } = snapshot.state() else {
            continue;
        };
        return metadata.for_absent_sibling_creation(absent).map_err(|_| {
            invalid_request("Claude Code memory settings sibling is not bound to the target parent")
        });
    }
    Err(invalid_request(
        "Claude Code memory settings need an existing same-directory metadata template",
    ))
}

fn safe_memory_directory_binding(path: &Path) -> Result<Option<PathBuf>, ClientError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => Ok(None),
        Ok(_) => fs::canonicalize(path)
            .map(Some)
            .map_err(|_| invalid_request("Claude Code memory directory cannot be resolved")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Some(path.to_path_buf())),
        Err(_) => Ok(None),
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
                    if is_primary_memory_instruction_component(HarnessId::ClaudeCode, component) {
                        let (path, _, current, intended) =
                            self.primary_memory_instruction_projection(component)?;
                        if current.fingerprint() != intended.fingerprint()
                            && let NativeState::RegularFile { bytes, .. } = intended
                        {
                            files.push(RenderedFile {
                                path: wire_path(&path),
                                bytes_sha256: digest(&bytes),
                                byte_length: bytes.len() as u64,
                            });
                        }
                        continue;
                    }
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
        let context = self.command_context()?;
        self.validate_effective_with(receipt, |command| {
            let argv = command.argv();
            let arguments = argv.iter().map(String::as_str).collect::<Vec<_>>();
            run_bounded_command(
                &self.layout.executable,
                &arguments,
                self.executable_hash,
                &context,
            )
        })
    }
}

impl ClaudeCodeAdapter {
    fn validate_effective_with(
        &self,
        receipt: &ApplyReceipt,
        mut execute: impl FnMut(&ClaudeCommand) -> Result<Vec<u8>, ClientError>,
    ) -> Result<ValidationReport, ClientError> {
        receipt
            .validate()
            .map_err(|_| invalid_request("Claude Code receipt is invalid"))?;
        self.require_apply_supported()?;
        let commands = self.validation_commands()?;
        for command in commands {
            let output = execute(&command)?;
            match command {
                ClaudeCommand::Doctor => parse_doctor_output(&output)?,
                ClaudeCommand::PluginList => parse_plugin_list_output(&output)?,
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
        self.command_context()
            .and_then(|context| context.validate())
            .map_err(|_| BoundaryError::new("Claude Code configuration binding changed"))?;
        if self.capability() != CapabilityLevel::Full
            || plan.setup.harness != HarnessId::ClaudeCode
            || plan.setup.harness_version != self.layout.version
            || plan.setup.executable_path != wire_path(&self.layout.executable)
            || digest_file_boundary(&self.layout.executable)? != plan.setup.executable_hash
        {
            return Err(BoundaryError::new("Claude Code installation changed"));
        }
        for mutation in &plan.cli_mutations {
            self.validate_cli_context(mutation)?;
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

impl<O> NativeCliExecutor for ClaudeCodeCliExecutor<'_, O>
where
    O: ClaudeCodeCommandRunner,
{
    fn probe_cli_mutation(
        &mut self,
        mutation: &ApprovedCliMutation,
    ) -> Result<Option<Sha256Digest>, BoundaryError> {
        self.adapter.recheck_executable_boundary()?;
        self.validate_mutation(mutation)?;
        let live = self.adapter.probe_managed_declaration()?;
        Ok(declaration_fingerprint(live.as_ref()))
    }

    fn compare_cli_targets(
        &mut self,
        mutations: &[ApprovedCliMutation],
    ) -> Result<(), BoundaryError> {
        self.adapter.recheck_executable_boundary()?;
        for mutation in mutations {
            self.validate_mutation(mutation)?;
            let live = self.adapter.probe_managed_declaration()?;
            if declaration_fingerprint(live.as_ref())
                != declaration_fingerprint(mutation.expected.as_ref())
            {
                return Err(BoundaryError::new(
                    "Claude Code managed bridge declaration changed",
                ));
            }
        }
        Ok(())
    }

    fn apply_cli_mutation(
        &mut self,
        mutation: &ApprovedCliMutation,
    ) -> Result<CliMutationOutcome, BoundaryError> {
        self.adapter.recheck_executable_boundary()?;
        self.validate_mutation(mutation)?;
        let live = self.adapter.probe_managed_declaration()?;
        if declaration_fingerprint(live.as_ref())
            != declaration_fingerprint(mutation.expected.as_ref())
        {
            return Ok(CliMutationOutcome {
                resulting_fingerprint: declaration_fingerprint(live.as_ref()),
                command_error: None,
            });
        }
        let command_error = self.run_operations(&mutation.forward).err();
        let resulting = self.adapter.probe_managed_declaration()?;
        Ok(CliMutationOutcome {
            resulting_fingerprint: declaration_fingerprint(resulting.as_ref()),
            command_error,
        })
    }

    fn restore_cli_mutation_if_matches(
        &mut self,
        mutation: &ApprovedCliMutation,
    ) -> Result<CliRestoreOutcome, BoundaryError> {
        self.adapter.recheck_executable_boundary()?;
        self.validate_mutation(mutation)?;
        let live = self.adapter.probe_managed_declaration()?;
        if declaration_fingerprint(live.as_ref())
            != declaration_fingerprint(mutation.intended.as_ref())
        {
            return Ok(CliRestoreOutcome {
                restored: false,
                resulting_fingerprint: declaration_fingerprint(live.as_ref()),
            });
        }
        self.run_operations(&mutation.rollback)?;
        let resulting = self.adapter.probe_managed_declaration()?;
        Ok(CliRestoreOutcome {
            restored: declaration_fingerprint(resulting.as_ref())
                == declaration_fingerprint(mutation.expected.as_ref()),
            resulting_fingerprint: declaration_fingerprint(resulting.as_ref()),
        })
    }

    fn finish_committed_cli_mutations(
        &mut self,
        mutations: &[ApprovedCliMutation],
    ) -> Result<(), BoundaryError> {
        self.adapter.recheck_executable_boundary()?;
        for mutation in mutations {
            self.validate_mutation(mutation)?;
            let live = self.adapter.probe_managed_declaration()?;
            if declaration_fingerprint(live.as_ref())
                != declaration_fingerprint(mutation.intended.as_ref())
            {
                return Err(BoundaryError::new(
                    "Claude Code committed bridge declaration changed",
                ));
            }
        }
        Ok(())
    }
}

impl<O> ClaudeCodeCliExecutor<'_, O>
where
    O: ClaudeCodeCommandRunner,
{
    fn validate_mutation(&self, mutation: &ApprovedCliMutation) -> Result<(), BoundaryError> {
        self.adapter.validate_cli_context(mutation)?;
        if mutation.expected.is_none() && mutation.intended.is_none() {
            return Err(BoundaryError::new(
                "Claude Code CLI mutation has no declaration",
            ));
        }
        for declaration in [mutation.expected.as_ref(), mutation.intended.as_ref()]
            .into_iter()
            .flatten()
        {
            validate_cli_declaration(declaration)?;
        }
        let expected_forward = vec![
            self.adapter
                .declaration_operation(mutation.intended.as_ref()),
        ];
        let expected_rollback = vec![
            self.adapter
                .declaration_operation(mutation.expected.as_ref()),
        ];
        if mutation.forward != expected_forward || mutation.rollback != expected_rollback {
            return Err(BoundaryError::new(
                "Claude Code CLI operations differ from the approved declaration",
            ));
        }
        Ok(())
    }

    fn run_operations(&mut self, operations: &[CliOperation]) -> Result<(), BoundaryError> {
        for operation in operations {
            if operation.executable != wire_path(&self.adapter.layout.executable)
                || operation.timeout_ms != CLI_TIMEOUT_MS
            {
                return Err(BoundaryError::new(
                    "Claude Code CLI operation is not canonical",
                ));
            }
            let arguments = operation
                .arguments
                .iter()
                .map(|argument| {
                    argument
                        .display
                        .clone()
                        .ok_or_else(|| BoundaryError::new("Claude Code CLI argument is not text"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            self.adapter
                .run_verified(&mut self.operation_runner, &arguments)?;
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

fn validation_commands() -> Vec<ClaudeCommand> {
    vec![ClaudeCommand::Doctor, ClaudeCommand::PluginList]
}

fn collect_mcp_names(
    servers: Option<&Value>,
    names: &mut BTreeSet<String>,
) -> Result<(), ClientError> {
    let Some(servers) = servers else {
        return Ok(());
    };
    let servers = servers
        .as_object()
        .ok_or_else(|| invalid_request("Claude Code MCP configuration is invalid"))?;
    for name in servers.keys() {
        safe_name(name)?;
        if names.insert(name.clone()) && names.len() > MAX_MCP_VALIDATION_NAMES {
            return Err(invalid_request(
                "Claude Code MCP configuration has too many servers",
            ));
        }
    }
    Ok(())
}

fn run_bounded_command(
    executable: &Path,
    arguments: &[&str],
    expected_hash: Sha256Digest,
    context: &ClaudeCommandContext,
) -> Result<Vec<u8>, ClientError> {
    run_bounded_command_with_hook(executable, arguments, expected_hash, context, || {})
}

fn run_bounded_command_with_hook(
    executable: &Path,
    arguments: &[&str],
    expected_hash: Sha256Digest,
    context: &ClaudeCommandContext,
    before_spawn: impl FnOnce(),
) -> Result<Vec<u8>, ClientError> {
    let executable = open_verified_claude_executable(executable, expected_hash)
        .map_err(|_| client_error(ErrorCode::Conflict, "Claude Code executable changed", false))?;
    before_spawn();
    executable
        .revalidate_before_launch()
        .map_err(|_| client_error(ErrorCode::Conflict, "Claude Code executable changed", false))?;
    run_bounded_verified_command(&executable, arguments, context)
}

fn run_bounded_verified_command(
    executable: &VerifiedClaudeExecutable,
    arguments: &[&str],
    context: &ClaudeCommandContext,
) -> Result<Vec<u8>, ClientError> {
    executable
        .revalidate_before_launch()
        .map_err(|_| client_error(ErrorCode::Conflict, "Claude Code executable changed", false))?;
    let launch = executable.prepare_launch()?;
    run_prepared_claude_command(launch, &executable.source_path, arguments, context)
}

fn run_prepared_claude_command(
    launch: PreparedClaudeLaunch,
    original_path: &Path,
    arguments: &[&str],
    context: &ClaudeCommandContext,
) -> Result<Vec<u8>, ClientError> {
    #[cfg(windows)]
    if launch.source_path.as_path() != original_path {
        return Err(client_error(
            ErrorCode::Conflict,
            "Claude Code prepared executable identity changed",
            false,
        ));
    }
    launch.revalidate().map_err(|_| {
        client_error(
            ErrorCode::Conflict,
            "Claude Code prepared executable changed",
            false,
        )
    })?;
    let mut command = Command::new(launch.program());
    context.configure(&mut command, arguments)?;
    command
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;

        command.arg0(original_path);
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use std::os::unix::process::CommandExt as _;

        // SAFETY: the hook performs no work in the child. Its presence forces
        // fork/exec so the sealed, non-CLOEXEC memfd survives until execve
        // resolves its descriptor path.
        unsafe {
            command.pre_exec(|| Ok(()));
        }
    }
    let mut child = command.spawn().map_err(|_| {
        client_error(
            ErrorCode::HarnessUnsupported,
            "Claude Code command failed",
            true,
        )
    })?;
    launch.revalidate().map_err(|_| {
        let _ = child.kill();
        let _ = child.wait();
        client_error(
            ErrorCode::Conflict,
            "Claude Code prepared executable changed",
            false,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ClaudeFileIdentity {
    volume: u64,
    index: u64,
}

#[derive(Debug)]
struct VerifiedClaudeExecutable {
    source_path: PathBuf,
    file: fs::File,
    identity: ClaudeFileIdentity,
    expected_hash: Sha256Digest,
}

impl VerifiedClaudeExecutable {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn prepare_launch(&self) -> Result<PreparedClaudeLaunch, ClientError> {
        use std::{
            ffi::CString,
            os::fd::{AsRawFd as _, FromRawFd as _},
        };

        let name = CString::new("context-relay-claude")
            .map_err(|_| invalid_request("Claude Code executable staging failed"))?;
        // SAFETY: memfd_create receives a valid NUL-terminated name and returns
        // a newly owned descriptor on success.
        let descriptor = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_ALLOW_SEALING) };
        if descriptor < 0 {
            return Err(invalid_request("Claude Code executable staging failed"));
        }
        // SAFETY: the successful memfd_create result is a newly owned descriptor.
        let mut staged = unsafe { fs::File::from_raw_fd(descriptor) };
        // SAFETY: descriptor remains owned by `staged`.
        if unsafe { libc::fchmod(descriptor, 0o700) } < 0 {
            return Err(invalid_request("Claude Code executable staging failed"));
        }
        let mut source = self
            .file
            .try_clone()
            .map_err(|_| invalid_request("Claude Code executable staging failed"))?;
        source
            .seek(SeekFrom::Start(0))
            .map_err(|_| invalid_request("Claude Code executable staging failed"))?;
        std::io::copy(&mut source, &mut staged)
            .and_then(|_| staged.sync_all())
            .map_err(|_| invalid_request("Claude Code executable staging failed"))?;
        if hash_open_file(&staged).ok() != Some(self.expected_hash) {
            return Err(client_error(
                ErrorCode::Conflict,
                "Claude Code staged executable changed",
                false,
            ));
        }
        let seals =
            libc::F_SEAL_WRITE | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL;
        // SAFETY: descriptor remains owned by `staged`; fcntl mutates or reads
        // only the kernel seal state of that descriptor.
        if unsafe { libc::fcntl(descriptor, libc::F_ADD_SEALS, seals) } < 0
            || unsafe { libc::fcntl(descriptor, libc::F_GET_SEALS) } & seals != seals
        {
            return Err(invalid_request("Claude Code executable staging failed"));
        }
        let program = if Path::new("/proc/self/fd").is_dir() {
            PathBuf::from(format!("/proc/self/fd/{}", staged.as_raw_fd()))
        } else {
            PathBuf::from(format!("/dev/fd/{}", staged.as_raw_fd()))
        };
        Ok(PreparedClaudeLaunch {
            program,
            expected_hash: self.expected_hash,
            descriptor: staged,
        })
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn prepare_launch(&self) -> Result<PreparedClaudeLaunch, ClientError> {
        prepare_staged_claude_launch(self)
    }

    fn open(path: &Path) -> Result<Self, ClientError> {
        if !is_native_claude_executable_path(path, cfg!(windows)) {
            return Err(invalid_request(
                "Claude Code executable is not a native executable",
            ));
        }
        validate_executable_path_components(path)
            .map_err(|_| invalid_request("Claude Code executable topology is unsafe"))?;
        let metadata = fs::symlink_metadata(path).map_err(|_| {
            client_error(
                ErrorCode::NotFound,
                "Claude Code executable is missing",
                false,
            )
        })?;
        if !metadata.is_file() || metadata_is_link_or_reparse(&metadata) {
            return Err(invalid_request("Claude Code executable topology is unsafe"));
        }
        let file = open_executable_without_substitution(path)
            .map_err(|_| invalid_request("Claude Code executable cannot be safely opened"))?;
        let opened_metadata = file
            .metadata()
            .map_err(|_| invalid_request("Claude Code executable cannot be safely inspected"))?;
        if !opened_metadata.is_file() || metadata_is_link_or_reparse(&opened_metadata) {
            return Err(invalid_request("Claude Code executable topology is unsafe"));
        }
        #[cfg(windows)]
        if !windows_reader_is_native_pe(
            file.try_clone().map_err(|_| {
                invalid_request("Claude Code executable cannot be safely inspected")
            })?,
        )
        .map_err(|_| invalid_request("Claude Code executable cannot be safely inspected"))?
        {
            return Err(invalid_request(
                "Claude Code executable is not a native executable",
            ));
        }
        let identity = claude_file_identity(&file)
            .map_err(|_| invalid_request("Claude Code executable identity is unavailable"))?;
        let expected_hash = hash_open_file(&file)
            .map_err(|_| invalid_request("Claude Code executable cannot be read"))?;
        Ok(Self {
            source_path: path.to_path_buf(),
            file,
            identity,
            expected_hash,
        })
    }

    fn revalidate_before_launch(&self) -> Result<(), BoundaryError> {
        validate_executable_path_components(&self.source_path)
            .map_err(|_| BoundaryError::new("Claude Code executable topology is unsafe"))?;
        let held_identity = claude_file_identity(&self.file)
            .map_err(|_| BoundaryError::new("Claude Code executable identity is unavailable"))?;
        let held_hash = hash_open_file(&self.file)
            .map_err(|_| BoundaryError::new("Claude Code executable cannot be read"))?;
        let metadata = fs::symlink_metadata(&self.source_path)
            .map_err(|_| BoundaryError::new("Claude Code executable is missing"))?;
        if !metadata.is_file()
            || metadata_is_link_or_reparse(&metadata)
            || held_identity != self.identity
            || held_hash != self.expected_hash
        {
            return Err(BoundaryError::new("Claude Code executable changed"));
        }
        let reopened = open_executable_without_substitution(&self.source_path)
            .map_err(|_| BoundaryError::new("Claude Code executable is unsafe"))?;
        let reopened_identity = claude_file_identity(&reopened)
            .map_err(|_| BoundaryError::new("Claude Code executable identity is unavailable"))?;
        let reopened_hash = hash_open_file(&reopened)
            .map_err(|_| BoundaryError::new("Claude Code executable cannot be read"))?;
        if reopened_identity != self.identity || reopened_hash != self.expected_hash {
            return Err(BoundaryError::new("Claude Code executable changed"));
        }
        Ok(())
    }
}

struct PreparedClaudeLaunch {
    program: PathBuf,
    #[cfg(windows)]
    source_path: PathBuf,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    expected_hash: Sha256Digest,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    descriptor: fs::File,
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    _directory: tempfile::TempDir,
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    executable: VerifiedClaudeExecutable,
}

impl PreparedClaudeLaunch {
    fn program(&self) -> &Path {
        &self.program
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn revalidate(&self) -> Result<(), BoundaryError> {
        use std::os::fd::AsRawFd as _;

        let seals =
            libc::F_SEAL_WRITE | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL;
        // SAFETY: `descriptor` owns a valid memfd for the lifetime of `self`.
        let actual_seals = unsafe { libc::fcntl(self.descriptor.as_raw_fd(), libc::F_GET_SEALS) };
        let actual_hash = hash_open_file(&self.descriptor)
            .map_err(|_| BoundaryError::new("Claude Code prepared executable cannot be read"))?;
        if actual_seals < 0 || actual_seals & seals != seals || actual_hash != self.expected_hash {
            return Err(BoundaryError::new(
                "Claude Code prepared executable changed",
            ));
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn revalidate(&self) -> Result<(), BoundaryError> {
        self.executable.revalidate_before_launch()
    }
}

/// A non-forgeable Claude Code command capability bound to prepared bytes.
///
/// Runners can inspect the reviewed argument vector or consume the capability
/// to execute it, but cannot recover the mutable discovery pathname.
pub struct VerifiedClaudeCommand<'a> {
    executable: &'a VerifiedClaudeExecutable,
    launch: PreparedClaudeLaunch,
    arguments: &'a [String],
    context: ClaudeCommandContext,
}

impl VerifiedClaudeCommand<'_> {
    pub fn arguments(&self) -> &[String] {
        self.arguments
    }

    pub fn execute(self) -> Result<Vec<u8>, BoundaryError> {
        let arguments = self
            .arguments
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        run_prepared_claude_command(
            self.launch,
            &self.executable.source_path,
            &arguments,
            &self.context,
        )
        .map_err(|_| {
            BoundaryError::new("Claude Code command failed at the native transaction boundary")
        })
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn prepare_staged_claude_launch(
    executable: &VerifiedClaudeExecutable,
) -> Result<PreparedClaudeLaunch, ClientError> {
    use std::io::Write as _;
    #[cfg(unix)]
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    let mut builder = tempfile::Builder::new();
    builder.prefix("context-relay-claude-");
    #[cfg(unix)]
    builder.permissions(fs::Permissions::from_mode(0o700));
    let directory = builder.tempdir().map_err(|_| {
        client_error(
            ErrorCode::HarnessUnsupported,
            "Claude Code executable staging failed",
            true,
        )
    })?;
    let directory_metadata = fs::symlink_metadata(directory.path()).map_err(|_| {
        client_error(
            ErrorCode::HarnessUnsupported,
            "Claude Code executable staging failed",
            true,
        )
    })?;
    if !directory_metadata.is_dir() || metadata_is_link_or_reparse(&directory_metadata) || {
        #[cfg(unix)]
        {
            directory_metadata.permissions().mode() & 0o777 != 0o700
        }
        #[cfg(not(unix))]
        {
            false
        }
    } {
        return Err(client_error(
            ErrorCode::HarnessUnsupported,
            "Claude Code executable staging failed",
            false,
        ));
    }

    let path = directory.path().join(if cfg!(windows) {
        "claude.exe"
    } else {
        "claude"
    });
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o700);
    let mut staged_file = options.open(&path).map_err(|_| {
        client_error(
            ErrorCode::HarnessUnsupported,
            "Claude Code executable staging failed",
            true,
        )
    })?;
    let mut source = executable.file.try_clone().map_err(|_| {
        client_error(
            ErrorCode::HarnessUnsupported,
            "Claude Code executable staging failed",
            true,
        )
    })?;
    source.seek(SeekFrom::Start(0)).map_err(|_| {
        client_error(
            ErrorCode::HarnessUnsupported,
            "Claude Code executable staging failed",
            true,
        )
    })?;
    std::io::copy(&mut source, &mut staged_file)
        .and_then(|_| staged_file.flush())
        .and_then(|_| staged_file.sync_all())
        .map_err(|_| {
            client_error(
                ErrorCode::HarnessUnsupported,
                "Claude Code executable staging failed",
                true,
            )
        })?;
    drop(staged_file);
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).map_err(|_| {
        client_error(
            ErrorCode::HarnessUnsupported,
            "Claude Code executable staging failed",
            true,
        )
    })?;

    let staged = VerifiedClaudeExecutable::open(&path).map_err(|_| {
        client_error(
            ErrorCode::HarnessUnsupported,
            "Claude Code executable staging failed",
            false,
        )
    })?;
    let staged_metadata = fs::symlink_metadata(&path).map_err(|_| {
        client_error(
            ErrorCode::HarnessUnsupported,
            "Claude Code executable staging failed",
            false,
        )
    })?;
    if staged.expected_hash != executable.expected_hash
        || !staged_metadata.is_file()
        || metadata_is_link_or_reparse(&staged_metadata)
        || {
            #[cfg(unix)]
            {
                staged_metadata.permissions().mode() & 0o777 != 0o700
            }
            #[cfg(not(unix))]
            {
                false
            }
        }
    {
        return Err(client_error(
            ErrorCode::Conflict,
            "Claude Code staged executable changed",
            false,
        ));
    }
    staged.revalidate_before_launch().map_err(|_| {
        client_error(
            ErrorCode::Conflict,
            "Claude Code staged executable changed",
            false,
        )
    })?;
    Ok(PreparedClaudeLaunch {
        program: path,
        #[cfg(windows)]
        source_path: executable.source_path.clone(),
        _directory: directory,
        executable: staged,
    })
}

fn open_verified_claude_executable(
    path: &Path,
    expected_hash: Sha256Digest,
) -> Result<VerifiedClaudeExecutable, BoundaryError> {
    let executable = VerifiedClaudeExecutable::open(path).map_err(|error| {
        BoundaryError::new(format!(
            "Claude Code executable cannot be safely attested ({}): {error:?}",
            path.display()
        ))
    })?;
    if executable.expected_hash != expected_hash {
        return Err(BoundaryError::new("Claude Code executable changed"));
    }
    Ok(executable)
}

#[cfg(unix)]
fn open_executable_without_substitution(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(windows)]
fn open_executable_without_substitution(path: &Path) -> std::io::Result<fs::File> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ};

    fs::OpenOptions::new()
        .read(true)
        // Permit CreateProcess to read the image while denying concurrent
        // writers and rename/delete substitution until after spawn.
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
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

fn canonical_cli_declaration(body: &str) -> Result<CanonicalCliDeclaration, ClientError> {
    if !is_canonical_bridge_body(HarnessId::ClaudeCode, body, false) {
        return Err(invalid_request(
            "Claude Code declaration is not the managed bridge",
        ));
    }
    Ok(CanonicalCliDeclaration {
        harness: HarnessId::ClaudeCode,
        server_name: BRIDGE_SERVER_NAME.to_owned(),
        canonical_body: body.to_owned(),
        fingerprint: digest(body.as_bytes()),
    })
}

fn validate_cli_declaration(declaration: &CanonicalCliDeclaration) -> Result<(), BoundaryError> {
    if declaration.harness != HarnessId::ClaudeCode
        || declaration.server_name != BRIDGE_SERVER_NAME
        || declaration.fingerprint != digest(declaration.canonical_body.as_bytes())
        || !is_canonical_bridge_body(HarnessId::ClaudeCode, &declaration.canonical_body, false)
    {
        return Err(BoundaryError::new(
            "Claude Code CLI declaration is not canonical",
        ));
    }
    Ok(())
}

fn declaration_fingerprint(declaration: Option<&CanonicalCliDeclaration>) -> Option<Sha256Digest> {
    declaration.map(|declaration| declaration.fingerprint)
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
    let newline = if existing.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let normalized_body = body
        .replace("\r\n", "\n")
        .trim_end_matches('\n')
        .replace('\n', newline);
    let rendered = match (starts.as_slice(), ends.as_slice()) {
        ([], []) if !archived => {
            let mut rendered = existing.to_owned();
            if !rendered.is_empty() && !rendered.ends_with(newline) {
                rendered.push_str(newline);
            }
            rendered.push_str(MANAGED_START);
            rendered.push_str(newline);
            rendered.push_str(&normalized_body);
            rendered.push_str(newline);
            rendered.push_str(MANAGED_END);
            rendered.push_str(newline);
            rendered
        }
        ([(start, _)], [(end, _)]) if start < end => {
            let marker_end = end + MANAGED_END.len();
            let suffix = if existing[marker_end..].starts_with("\r\n") {
                marker_end + 2
            } else if existing[marker_end..].starts_with('\n') {
                marker_end + 1
            } else {
                marker_end
            };
            if archived {
                format!("{}{}", &existing[..*start], &existing[suffix..])
            } else {
                let mut rendered = existing[..start + MANAGED_START.len()].to_owned();
                rendered.push_str(newline);
                rendered.push_str(&normalized_body);
                rendered.push_str(newline);
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
    mcp_state::read_object(state_path).ok().and_then(|state| {
        mcp_state::project_entry(&state, project_root)
            .ok()??
            .get("hasTrustDialogAccepted")?
            .as_bool()
    }) == Some(true)
}

fn project_mcp_approval_status(state_path: &Path, project_root: &Path) -> Result<(bool, bool), ()> {
    let state = mcp_state::read_object(state_path).map_err(|_| ())?;
    let Some(project) = mcp_state::project_entry(&state, project_root).map_err(|_| ())? else {
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
    digest_regular_non_link_file(path)
}

fn digest_file_boundary(path: &Path) -> Result<Sha256Digest, BoundaryError> {
    digest_regular_non_link_file_boundary(path)
}

fn digest_regular_non_link_file(path: &Path) -> Result<Sha256Digest, ClientError> {
    // Digests are taken for every native target (config, settings, and the
    // executable alike), so this must not apply the executable-only policy
    // (`.exe` + PE image) that `VerifiedClaudeExecutable::open` enforces.
    // The safety requirements are the same subset that applies to any
    // regular file: no symlink, no reparse point, opened without
    // write/share substitution, then hashed.
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| invalid_request("Claude Code native file is missing"))?;
    if !metadata.is_file() || metadata_is_link_or_reparse(&metadata) {
        return Err(invalid_request(
            "Claude Code native file topology is unsafe",
        ));
    }
    let file = open_executable_without_substitution(path)
        .map_err(|_| invalid_request("Claude Code native file cannot be safely opened"))?;
    let opened = file
        .metadata()
        .map_err(|_| invalid_request("Claude Code native file cannot be safely inspected"))?;
    if !opened.is_file() || metadata_is_link_or_reparse(&opened) {
        return Err(invalid_request(
            "Claude Code native file topology is unsafe",
        ));
    }
    hash_open_file(&file).map_err(|_| invalid_request("Claude Code native file cannot be read"))
}

fn digest_regular_non_link_file_boundary(path: &Path) -> Result<Sha256Digest, BoundaryError> {
    digest_regular_non_link_file(path).map_err(|error| {
        BoundaryError::new(format!(
            "Claude Code executable cannot be safely attested ({}): {error:?}",
            path.display()
        ))
    })
}

fn hash_open_file(file: &fs::File) -> std::io::Result<Sha256Digest> {
    let mut file = file.try_clone()?;
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            file.seek(SeekFrom::Start(0))?;
            return Ok(Sha256Digest(hasher.finalize().into()));
        }
        hasher.update(&buffer[..read]);
    }
}

#[cfg(unix)]
fn claude_file_identity(file: &fs::File) -> std::io::Result<ClaudeFileIdentity> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file.metadata()?;
    Ok(ClaudeFileIdentity {
        volume: metadata.dev(),
        index: metadata.ino(),
    })
}

#[cfg(windows)]
fn claude_file_identity(file: &fs::File) -> std::io::Result<ClaudeFileIdentity> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle},
    };

    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `file` owns a valid handle and `information` is writable for
    // the exact structure expected by GetFileInformationByHandle.
    let succeeded = unsafe {
        GetFileInformationByHandle(
            file.as_raw_handle() as HANDLE,
            std::ptr::from_mut(&mut information),
        )
    };
    if succeeded == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(ClaudeFileIdentity {
        volume: u64::from(information.dwVolumeSerialNumber),
        index: (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow),
    })
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
    let names = executable_names(cfg!(windows));
    let from_path = env::var_os("PATH").and_then(|path| {
        env::split_paths(&path)
            .flat_map(|directory| names.iter().map(move |name| directory.join(name)))
            .find(|candidate| digest_regular_non_link_file(candidate).is_ok())
    });
    if from_path.is_some() {
        return from_path;
    }
    #[cfg(windows)]
    {
        if let Some(home) = env::var_os("USERPROFILE") {
            let native = PathBuf::from(home).join(".local/bin/claude.exe");
            if digest_regular_non_link_file(&native).is_ok() {
                return Some(native);
            }
        }
        let mut roots = Vec::new();
        if let Some(roaming) = env::var_os("APPDATA") {
            roots.push(PathBuf::from(roaming).join("Claude/claude-code"));
        }
        if let Some(local) = env::var_os("LOCALAPPDATA") {
            roots.push(
                PathBuf::from(local)
                    .join("Packages/Claude_pzs8sxrjxfjjc/LocalCache/Roaming/Claude/claude-code"),
            );
        }
        find_windows_bundled_claude(&roots)
    }
    #[cfg(not(windows))]
    None
}

#[cfg(windows)]
fn find_windows_bundled_claude(roots: &[PathBuf]) -> Option<PathBuf> {
    let mut candidates = Vec::new();
    for root in roots {
        let Ok(entries) = fs::read_dir(root) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(version) = name
                .split('.')
                .map(str::parse::<u32>)
                .collect::<Result<Vec<_>, _>>()
                .ok()
                .filter(|parts| {
                    parts.len() == 3
                        && parts
                            .iter()
                            .map(u32::to_string)
                            .collect::<Vec<_>>()
                            .join(".")
                            == name
                })
            else {
                continue;
            };
            let executable = entry.path().join("claude.exe");
            if validate_executable_path_components(&executable).is_ok() {
                candidates.push((version, executable));
            }
        }
    }
    candidates.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
    candidates.into_iter().map(|(_, path)| path).find(|path| {
        digest_regular_non_link_file(path).is_ok()
            && open_executable_without_substitution(path)
                .and_then(windows_reader_is_native_pe)
                .unwrap_or(false)
    })
}

fn discover_version_with(
    mut execute: impl FnMut(&[&str]) -> Result<Vec<u8>, ClientError>,
) -> Result<String, ClientError> {
    let output = execute(&["--version"])?;
    let version =
        parse_version(std::str::from_utf8(&output).unwrap_or_default()).ok_or_else(|| {
            client_error(
                ErrorCode::HarnessUnsupported,
                "Claude Code returned an invalid version",
                false,
            )
        })?;
    // An unqualified version can be reported as ImportOnly without running its
    // potentially interactive diagnostics. Full setup retains its existing gate.
    if SUPPORTED_VERSIONS.contains(&version.as_str()) {
        parse_doctor_output(&execute(&["doctor"])?)?;
    }
    Ok(version)
}

fn executable_names(windows: bool) -> &'static [&'static str] {
    if windows {
        &["claude.exe"]
    } else {
        &["claude"]
    }
}

fn is_native_claude_executable_path(path: &Path, windows: bool) -> bool {
    !windows
        || path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
}

#[cfg(any(windows, test))]
fn windows_reader_is_native_pe(mut reader: impl Read + Seek) -> Result<bool, std::io::Error> {
    let mut dos_header = [0_u8; 64];
    if let Err(error) = reader.read_exact(&mut dos_header) {
        return match error.kind() {
            std::io::ErrorKind::UnexpectedEof => Ok(false),
            _ => Err(error),
        };
    }
    if &dos_header[..2] != b"MZ" {
        return Ok(false);
    }
    let pe_offset = u32::from_le_bytes(
        dos_header[0x3c..0x40]
            .try_into()
            .expect("fixed DOS header range"),
    );
    reader.seek(SeekFrom::Start(u64::from(pe_offset)))?;
    let mut signature = [0_u8; 4];
    if let Err(error) = reader.read_exact(&mut signature) {
        return match error.kind() {
            std::io::ErrorKind::UnexpectedEof => Ok(false),
            _ => Err(error),
        };
    }
    Ok(signature == *b"PE\0\0")
}

fn metadata_is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;

        windows_attributes_are_reparse(metadata.file_attributes())
    }
    #[cfg(not(windows))]
    false
}

#[cfg(windows)]
fn validate_executable_path_components(path: &Path) -> std::io::Result<()> {
    use std::os::windows::fs::MetadataExt as _;

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()?.join(path)
    };
    let mut attributes = Vec::new();
    for component in absolute.ancestors() {
        if component.as_os_str().is_empty() {
            continue;
        }
        attributes.push(fs::symlink_metadata(component)?.file_attributes());
    }
    if !windows_path_component_attributes_are_safe(&attributes) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Claude Code executable path contains a reparse point",
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn validate_executable_path_components(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(any(windows, test))]
fn windows_attributes_are_reparse(attributes: u32) -> bool {
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

    attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(any(windows, test))]
fn windows_path_component_attributes_are_safe(attributes: &[u32]) -> bool {
    attributes
        .iter()
        .all(|attributes| !windows_attributes_are_reparse(*attributes))
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
    // `VerifiedClaudeExecutable::open` enforces the native-executable policy
    // on every platform: Windows additionally requires the `.exe` extension
    // and a PE image header. Fixtures therefore carry the platform suffix
    // and a minimal MZ/PE stub on Windows; other platforms keep the plain
    // placeholder bytes.
    fn fixture_executable_bytes() -> Vec<u8> {
        #[cfg(windows)]
        {
            let mut bytes = vec![0_u8; 0x44];
            bytes[0] = b'M';
            bytes[1] = b'Z';
            let pe_offset: u32 = 0x40;
            bytes[0x3c..0x40].copy_from_slice(&pe_offset.to_le_bytes());
            bytes[0x40..0x44].copy_from_slice(b"PE\0\0");
            bytes
        }
        #[cfg(not(windows))]
        {
            b"fixture executable".to_vec()
        }
    }

    use super::{
        ClaudeCodeAdapter, ClaudeCodeLayout, ClaudeCommand, MAX_MCP_VALIDATION_NAMES, digest_file,
        executable_names, is_native_claude_executable_path, parse_doctor_output,
        parse_plugin_list_output, validation_commands, windows_attributes_are_reparse,
        windows_path_component_attributes_are_safe, windows_reader_is_native_pe,
    };
    #[cfg(unix)]
    use super::{run_bounded_command, run_bounded_command_with_hook};
    use context_relay_protocol::{
        ApplyReceipt, DeviceId, ErrorCode, HybridLogicalClock, InstallationMethod, PlanId,
        ProjectId,
    };
    use serde_json::Value;
    use std::{fs, str::FromStr as _};

    #[cfg(windows)]
    #[test]
    fn bundled_claude_discovery_uses_numeric_release_directories_and_native_files() {
        let temp = std::env::temp_dir();
        let root = temp.join(format!(
            "relay-claude-discovery-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        for version in ["2.1.9", "2.1.202", "2.1.999-malicious", "02.1.999"] {
            let directory = root.join(version);
            fs::create_dir(&directory).unwrap();
            fs::write(directory.join("claude.exe"), fixture_executable_bytes()).unwrap();
        }
        // A greater version with a script or directory is not an executable candidate.
        fs::create_dir(root.join("3.0.0")).unwrap();
        fs::write(root.join("3.0.0/claude.cmd"), b"@echo unsafe").unwrap();
        fs::create_dir(root.join("4.0.0")).unwrap();
        fs::write(root.join("4.0.0/claude.exe"), b"not a native executable").unwrap();
        let result = super::find_windows_bundled_claude(std::slice::from_ref(&root));
        assert!(
            fs::canonicalize(&root)
                .unwrap()
                .starts_with(fs::canonicalize(&temp).unwrap())
        );
        fs::remove_dir_all(&root).unwrap();
        assert_eq!(result, Some(root.join("2.1.202/claude.exe")));
    }

    #[test]
    fn discovery_of_unqualified_claude_does_not_require_interactive_doctor() {
        let mut commands = Vec::new();
        let version = super::discover_version_with(|arguments| {
            commands.push(
                arguments
                    .iter()
                    .map(|item| item.to_string())
                    .collect::<Vec<_>>(),
            );
            if arguments == ["--version"] {
                Ok(b"2.1.202 (Claude Code)\n".to_vec())
            } else {
                Err(super::invalid_request("Doctor must not be executed"))
            }
        })
        .unwrap();
        assert_eq!(version, "2.1.202");
        assert_eq!(commands, vec![vec!["--version"]]);
    }

    #[test]
    fn discovery_of_supported_claude_still_requires_its_qualified_doctor_output() {
        let mut commands = Vec::new();
        let result = super::discover_version_with(|arguments| {
            commands.push(
                arguments
                    .iter()
                    .map(|item| item.to_string())
                    .collect::<Vec<_>>(),
            );
            Ok(if arguments == ["--version"] {
                b"2.1.214 (Claude Code)\n".to_vec()
            } else {
                b"unexpected output".to_vec()
            })
        });
        assert!(result.is_err());
        assert_eq!(commands, vec![vec!["--version"], vec!["doctor"]]);
    }

    #[test]
    fn windows_discovery_and_mutation_accept_only_native_claude_exe() {
        assert_eq!(executable_names(true), &["claude.exe"]);
        assert!(is_native_claude_executable_path(
            std::path::Path::new("claude.exe"),
            true
        ));
        for wrapper in ["claude.cmd", "claude.bat", "claude.ps1", "claude"] {
            assert!(
                !is_native_claude_executable_path(std::path::Path::new(wrapper), true),
                "accepted Windows wrapper {wrapper}"
            );
        }
        for wrapper in [
            b"#!/bin/sh\nexec node claude.js\n".as_slice(),
            b"@echo off\r\nnode claude.js\r\n".as_slice(),
        ] {
            assert!(
                !windows_reader_is_native_pe(std::io::Cursor::new(wrapper)).unwrap(),
                "accepted Windows script bytes"
            );
        }
        let mut native_pe = vec![0_u8; 68];
        native_pe[..2].copy_from_slice(b"MZ");
        native_pe[0x3c..0x40].copy_from_slice(&64_u32.to_le_bytes());
        native_pe[64..68].copy_from_slice(b"PE\0\0");
        assert!(windows_reader_is_native_pe(std::io::Cursor::new(native_pe)).unwrap());
    }

    #[test]
    fn windows_reparse_attribute_is_rejected_even_when_not_a_symlink() {
        assert!(windows_attributes_are_reparse(0x0000_0400));
        assert!(windows_attributes_are_reparse(0x0000_0420));
        assert!(!windows_attributes_are_reparse(0x0000_0020));
    }

    #[test]
    fn windows_reparse_attribute_is_rejected_on_every_path_component() {
        assert!(windows_path_component_attributes_are_safe(&[
            0x0000_0010,
            0x0000_0010,
            0x0000_0020,
        ]));
        assert!(!windows_path_component_attributes_are_safe(&[
            0x0000_0010,
            0x0000_0410,
            0x0000_0020,
        ]));
    }

    #[cfg(unix)]
    #[test]
    fn verified_execution_launches_attested_bytes() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let executable = root.path().join("claude");
        fs::write(&executable, b"#!/bin/sh\nprintf '%s\\n' \"$1\"\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let expected_hash = digest_file(&executable).unwrap();

        let physical = fs::canonicalize(root.path()).unwrap();
        let context = super::ClaudeCommandContext::new(
            &physical.join(".claude"),
            &physical.join(".claude.json"),
            &physical,
        )
        .unwrap();
        let output =
            run_bounded_command(&executable, &["attested"], expected_hash, &context).unwrap();

        assert_eq!(output, b"attested\n");
    }

    #[cfg(unix)]
    #[test]
    fn verified_execution_rejects_path_substitution_before_spawn() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let executable = root.path().join("claude");
        let attested_backup = root.path().join("attested-claude");
        let replacement = root.path().join("replacement-claude");
        fs::copy("/bin/echo", &executable).unwrap();
        fs::write(&replacement, b"#!/bin/sh\nprintf 'replacement\\n'\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o700)).unwrap();
        let expected_hash = digest_file(&executable).unwrap();

        let physical = fs::canonicalize(root.path()).unwrap();
        let context = super::ClaudeCommandContext::new(
            &physical.join(".claude"),
            &physical.join(".claude.json"),
            &physical,
        )
        .unwrap();
        let result = run_bounded_command_with_hook(
            &executable,
            &["attested"],
            expected_hash,
            &context,
            || {
                fs::rename(&executable, &attested_backup).unwrap();
                fs::rename(&replacement, &executable).unwrap();
            },
        );

        assert!(result.is_err());
    }

    #[test]
    fn standalone_executable_hashing_is_not_limited_like_configuration() {
        let mut bytes = fixture_executable_bytes();
        bytes.resize(1024 * 1024 + 1, 0);
        let path = std::env::temp_dir().join(format!(
            "context-relay-claude-code-large-executable-{}{}",
            std::process::id(),
            std::env::consts::EXE_SUFFIX,
        ));
        fs::write(&path, bytes).unwrap();
        let result = digest_file(&path);
        let _ = fs::remove_file(path);
        assert!(result.is_ok());
    }

    #[test]
    fn validation_uses_only_reviewed_read_only_commands_and_bounded_outputs() {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/claude-code-2.1.214.json"))
                .unwrap();
        let commands = validation_commands();
        assert_eq!(
            commands
                .into_iter()
                .map(|command| command.argv())
                .collect::<Vec<_>>(),
            vec![
                vec!["doctor".to_owned()],
                vec!["plugin".to_owned(), "list".to_owned(), "--json".to_owned()],
            ]
        );
        parse_doctor_output(fixture["doctorOutput"].as_str().unwrap().as_bytes()).unwrap();
        parse_plugin_list_output(
            serde_json::to_vec(&fixture["pluginListJson"])
                .unwrap()
                .as_slice(),
        )
        .unwrap();
    }

    #[test]
    fn validation_rejects_unbounded_malformed_or_secret_output() {
        assert!(parse_doctor_output(&vec![b'x'; 65 * 1024]).is_err());
        assert!(parse_plugin_list_output(br#"[{"id":"ok","token":"secret"}]"#).is_err());
    }

    #[test]
    fn effective_validation_includes_global_mcp_without_executing_configured_servers() {
        let root = tempfile::tempdir().unwrap();
        let physical_root = fs::canonicalize(root.path()).unwrap();
        let config_dir = physical_root.join("claude");
        let project_root = physical_root.join("project");
        fs::create_dir_all(&config_dir).unwrap();
        fs::create_dir_all(&project_root).unwrap();
        let sentinel = physical_root.join("configured-bridge-ran");
        let command = serde_json::to_string(&sentinel.to_string_lossy()).unwrap();
        let state_path = config_dir.join(".claude.json");
        fs::write(
            &state_path,
            format!(
                r#"{{"mcpServers":{{"context-relay":{{"type":"stdio","command":{command},"args":[]}}}}}}"#
            ),
        )
        .unwrap();
        fs::write(
            project_root.join(".mcp.json"),
            format!(
                r#"{{"mcpServers":{{"project-tools":{{"type":"stdio","command":{command},"args":[]}}}}}}"#
            ),
        )
        .unwrap();
        let executable = physical_root.join(format!("claude-bin{}", std::env::consts::EXE_SUFFIX));
        fs::write(&executable, fixture_executable_bytes()).unwrap();
        let device = DeviceId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073982").unwrap();
        let adapter = ClaudeCodeAdapter::from_layout(
            ClaudeCodeLayout {
                executable,
                version: "2.1.214".to_owned(),
                installation_method: InstallationMethod::Manual,
                config_dir,
                state_path,
                project_root,
                managed_settings_paths: vec![],
            },
            ProjectId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073981").unwrap(),
            device,
            HybridLogicalClock::new(1_900_000_000_000, 0, device),
        )
        .unwrap();
        let receipt = ApplyReceipt {
            plan_id: PlanId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073984").unwrap(),
            applied_hlc: HybridLogicalClock::new(1_900_000_000_001, 0, device),
            resulting_digests: vec![],
        };
        let mut commands = Vec::new();
        let report = adapter
            .validate_effective_with(&receipt, |command| {
                commands.push(command.argv());
                Ok(match command {
                    ClaudeCommand::Doctor => b"Claude Code diagnostics: OK\n".to_vec(),
                    ClaudeCommand::PluginList => b"[]".to_vec(),
                })
            })
            .unwrap();
        assert!(report.valid);
        assert_eq!(
            commands,
            vec![vec!["doctor"], vec!["plugin", "list", "--json"],]
        );
        assert!(!sentinel.exists());
    }

    struct McpSourceFixture {
        _root: tempfile::TempDir,
        adapter: ClaudeCodeAdapter,
        receipt: ApplyReceipt,
    }

    fn mcp_servers(indices: impl IntoIterator<Item = usize>) -> Value {
        Value::Object(
            indices
                .into_iter()
                .map(|index| {
                    (
                        format!("server-{index:04}"),
                        serde_json::json!({
                            "type": "stdio",
                            "command": "never-run",
                            "args": []
                        }),
                    )
                })
                .collect(),
        )
    }

    fn mcp_source_fixture(
        global: impl IntoIterator<Item = usize>,
        project_state: impl IntoIterator<Item = usize>,
        project_file: impl IntoIterator<Item = usize>,
    ) -> McpSourceFixture {
        let root = tempfile::tempdir().unwrap();
        let physical_root = fs::canonicalize(root.path()).unwrap();
        let config_dir = physical_root.join("claude");
        let project_root = physical_root.join("project");
        fs::create_dir_all(&config_dir).unwrap();
        fs::create_dir_all(&project_root).unwrap();
        let state_path = config_dir.join(".claude.json");
        let project_key = project_root.to_string_lossy().into_owned();
        fs::write(
            &state_path,
            serde_json::to_vec(&serde_json::json!({
                "mcpServers": mcp_servers(global),
                "projects": {
                    (project_key): {
                        "mcpServers": mcp_servers(project_state)
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            project_root.join(".mcp.json"),
            serde_json::to_vec(&serde_json::json!({
                "mcpServers": mcp_servers(project_file)
            }))
            .unwrap(),
        )
        .unwrap();
        let executable = physical_root.join(format!("claude-bin{}", std::env::consts::EXE_SUFFIX));
        fs::write(&executable, fixture_executable_bytes()).unwrap();
        let device = DeviceId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073982").unwrap();
        let adapter = ClaudeCodeAdapter::from_layout(
            ClaudeCodeLayout {
                executable,
                version: "2.1.214".to_owned(),
                installation_method: InstallationMethod::Manual,
                config_dir,
                state_path,
                project_root,
                managed_settings_paths: vec![],
            },
            ProjectId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073981").unwrap(),
            device,
            HybridLogicalClock::new(1_900_000_000_000, 0, device),
        )
        .unwrap();
        McpSourceFixture {
            _root: root,
            adapter,
            receipt: ApplyReceipt {
                plan_id: PlanId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073984").unwrap(),
                applied_hlc: HybridLogicalClock::new(1_900_000_000_001, 0, device),
                resulting_digests: vec![],
            },
        }
    }

    #[test]
    fn effective_validation_accepts_exactly_the_deduplicated_mcp_name_limit() {
        let half = MAX_MCP_VALIDATION_NAMES / 2;
        let quarter = MAX_MCP_VALIDATION_NAMES / 4;
        let fixture = mcp_source_fixture(
            0..half,
            quarter..quarter + half,
            half..MAX_MCP_VALIDATION_NAMES,
        );
        let names = (0..MAX_MCP_VALIDATION_NAMES)
            .map(|index| format!("server-{index:04}"))
            .collect::<Vec<_>>();
        let mut commands = Vec::new();
        let report = fixture
            .adapter
            .validate_effective_with(&fixture.receipt, |command| {
                commands.push(command.argv());
                Ok(match command {
                    ClaudeCommand::Doctor => b"Claude Code diagnostics: OK\n".to_vec(),
                    ClaudeCommand::PluginList => b"[]".to_vec(),
                })
            })
            .unwrap();

        assert!(report.valid);
        assert_eq!(commands.len(), 2);
        assert_eq!(fixture.adapter.imported_mcp_names().unwrap(), names);
    }

    #[test]
    fn effective_validation_rejects_the_sixty_fifth_unique_name_before_execution() {
        let half = MAX_MCP_VALIDATION_NAMES / 2;
        let quarter = MAX_MCP_VALIDATION_NAMES / 4;
        let fixture = mcp_source_fixture(
            0..half,
            quarter..quarter + half,
            half..=MAX_MCP_VALIDATION_NAMES,
        );
        let mut executions = 0;
        let error = fixture
            .adapter
            .validate_effective_with(&fixture.receipt, |_| {
                executions += 1;
                Ok(Vec::new())
            })
            .unwrap_err();

        assert_eq!(executions, 0);
        assert_eq!(error.code, ErrorCode::InvalidRequest);
        assert!(!error.retryable);
        assert_eq!(error.field_path, None);
    }
}
