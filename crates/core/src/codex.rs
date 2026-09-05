//! The deliberately small Codex 0.144.x integration surface.
//!
//! This module only reads configuration which is useful to relay.  In
//! particular it deliberately never walks `$CODEX_HOME`: auth, sessions,
//! history, sqlite state, logs, and approval records are not adapter input.

pub mod staged_mcp;

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    env, fs,
    io::{ErrorKind, Read, Seek, SeekFrom},
    path::{Component, Path, PathBuf},
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
use toml_edit::{DocumentMut, Item, Value as TomlValue};

use crate::mcp::install::{
    BRIDGE_SERVER_NAME, is_canonical_bridge_body, is_managed_bridge_component,
};
use crate::native_memory::{
    NativeMemoryAdapter, NativeMemoryCapabilities, NativeMemoryDisable, NativeMemoryDocumentKind,
    has_managed_memory_hook_identity, is_primary_memory_instruction_component,
    merge_managed_memory_hooks, native_memory_source,
};
use crate::native_transaction::{
    cli::{CliMutationOutcome, CliRestoreOutcome, NativeCliExecutor},
    engine::{BoundaryError, FrozenOutput, NativeAdapter, RestrictedRun},
    model::{
        ApprovedCliMutation, ApprovedMutation, CanonicalCliDeclaration, MutationKind,
        NativeTransactionPlan, RestorableStateFingerprint,
    },
};

const SUPPORTED_VERSIONS: [&str; 2] = ["0.144.1", "0.144.0"];
const CLI_TIMEOUT_MS: u32 = 30_000;
const CLI_OUTPUT_LIMIT: u64 = 64 * 1024;
const MANAGED_START: &str = "<!-- context-relay:start -->";
const MANAGED_END: &str = "<!-- context-relay:end -->";
const MANAGED_PERMISSION_KEYS: [&str; 5] = [
    "approval_policy",
    "approvals_reviewer",
    "sandbox_mode",
    "default_permissions",
    "permissions",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BridgeDeclarationProbeError {
    Conflict,
    Inspection,
}

impl From<BridgeDeclarationProbeError> for BoundaryError {
    fn from(error: BridgeDeclarationProbeError) -> Self {
        BoundaryError::new(match error {
            BridgeDeclarationProbeError::Conflict => {
                "Codex prior MCP declaration is disabled or unmanaged"
            }
            BridgeDeclarationProbeError::Inspection => {
                "Codex managed bridge state cannot be safely inspected"
            }
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodexExecutableKind {
    Native,
    Wrapper,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct CodexLayout {
    pub executable: PathBuf,
    pub executable_kind: CodexExecutableKind,
    pub version: String,
    pub installation_method: InstallationMethod,
    pub codex_home: PathBuf,
    pub user_skills_dir: PathBuf,
    pub project_root: PathBuf,
    pub working_directory: PathBuf,
    pub requirements_paths: Vec<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct CodexAdapter {
    layout: CodexLayout,
    project_id: ProjectId,
    origin_device: DeviceId,
    observed_hlc: HybridLogicalClock,
    executable_hash: Sha256Digest,
}

/// An opened, digest-bound Codex executable identity.
#[derive(Debug)]
struct VerifiedCodexExecutable {
    path: PathBuf,
    file: fs::File,
    identity: CodexFileIdentity,
    expected_hash: Sha256Digest,
    #[cfg(windows)]
    topology: Vec<CodexPathComponent>,
}

impl VerifiedCodexExecutable {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn prepare_launch(&self) -> Result<PreparedCodexLaunch, ClientError> {
        use std::{
            ffi::CString,
            os::fd::{AsRawFd as _, FromRawFd as _},
        };

        let name = CString::new("context-relay-codex")
            .map_err(|_| invalid("Codex executable staging failed"))?;
        let descriptor = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_ALLOW_SEALING) };
        if descriptor < 0 {
            return Err(invalid("Codex executable staging failed"));
        }
        let mut staged = unsafe { fs::File::from_raw_fd(descriptor) };
        if unsafe { libc::fchmod(descriptor, 0o700) } < 0 {
            return Err(invalid("Codex executable staging failed"));
        }
        let mut input = self
            .file
            .try_clone()
            .map_err(|_| invalid("Codex executable staging failed"))?;
        input
            .seek(SeekFrom::Start(0))
            .map_err(|_| invalid("Codex executable staging failed"))?;
        std::io::copy(&mut input, &mut staged)
            .map_err(|_| invalid("Codex executable staging failed"))?;
        staged
            .sync_all()
            .map_err(|_| invalid("Codex executable staging failed"))?;
        if hash_open_file(&staged).ok() != Some(self.expected_hash) {
            return Err(invalid("Codex executable staging verification failed"));
        }
        let seals =
            libc::F_SEAL_WRITE | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL;
        if unsafe { libc::fcntl(descriptor, libc::F_ADD_SEALS, seals) } < 0
            || unsafe { libc::fcntl(descriptor, libc::F_GET_SEALS) } & seals != seals
        {
            return Err(invalid("Codex executable staging failed"));
        }
        let program = if Path::new("/proc/self/fd").is_dir() {
            PathBuf::from(format!("/proc/self/fd/{descriptor}"))
        } else {
            PathBuf::from(format!("/dev/fd/{descriptor}"))
        };
        Ok(PreparedCodexLaunch {
            program,
            _descriptor: staged,
        })
    }

    #[cfg(windows)]
    fn prepare_launch(&self) -> Result<PreparedCodexLaunch, ClientError> {
        Ok(PreparedCodexLaunch {
            program: self.path.clone(),
        })
    }

    #[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
    fn prepare_launch(&self) -> Result<PreparedCodexLaunch, ClientError> {
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

        let staging = tempfile::Builder::new()
            .prefix("context-relay-codex-exec-")
            .tempdir()
            .map_err(|_| invalid("Codex executable staging failed"))?;
        fs::set_permissions(staging.path(), fs::Permissions::from_mode(0o700))
            .map_err(|_| invalid("Codex executable staging failed"))?;
        let program = staging.path().join("codex");
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&program)
            .map_err(|_| invalid("Codex executable staging failed"))?;
        let mut input = self
            .file
            .try_clone()
            .map_err(|_| invalid("Codex executable staging failed"))?;
        input
            .seek(SeekFrom::Start(0))
            .map_err(|_| invalid("Codex executable staging failed"))?;
        std::io::copy(&mut input, &mut output)
            .map_err(|_| invalid("Codex executable staging failed"))?;
        output
            .sync_all()
            .map_err(|_| invalid("Codex executable staging failed"))?;
        drop(output);
        let metadata = fs::symlink_metadata(&program)
            .map_err(|_| invalid("Codex executable staging failed"))?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.permissions().mode() & 0o777 != 0o700
            || hash_file(&program).ok() != Some(self.expected_hash)
        {
            return Err(invalid("Codex executable staging verification failed"));
        }
        Ok(PreparedCodexLaunch {
            program,
            _staging: staging,
        })
    }

    fn revalidate_before_launch(&self) -> Result<(), BoundaryError> {
        #[cfg(windows)]
        revalidate_codex_path_topology(&self.topology)?;
        let held_identity = codex_file_identity(&self.file)
            .map_err(|_| BoundaryError::new("Codex executable identity is unavailable"))?;
        let held_hash = hash_open_file(&self.file)
            .map_err(|_| BoundaryError::new("Codex executable cannot be read"))?;
        let metadata = fs::symlink_metadata(&self.path)
            .map_err(|_| BoundaryError::new("Codex executable is missing"))?;
        if !metadata.is_file()
            || is_link_or_reparse_point(&metadata)
            || held_identity != self.identity
            || held_hash != self.expected_hash
        {
            return Err(BoundaryError::new("Codex executable changed"));
        }
        let reopened = open_codex_executable(&self.path)
            .map_err(|_| BoundaryError::new("Codex executable is unsafe"))?;
        let reopened_identity = codex_file_identity(&reopened)
            .map_err(|_| BoundaryError::new("Codex executable identity is unavailable"))?;
        let reopened_hash = hash_open_file(&reopened)
            .map_err(|_| BoundaryError::new("Codex executable cannot be read"))?;
        if reopened_identity != self.identity || reopened_hash != self.expected_hash {
            return Err(BoundaryError::new("Codex executable changed"));
        }
        Ok(())
    }
}

struct PreparedCodexLaunch {
    program: PathBuf,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    _descriptor: fs::File,
    #[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
    _staging: tempfile::TempDir,
}

/// A non-forgeable command capability bound to verified executable bytes.
///
/// Runners can inspect argument boundaries or execute this capability, but
/// cannot recover the mutable pathname used during discovery.
pub struct VerifiedCodexCommand<'a> {
    executable: &'a VerifiedCodexExecutable,
    launch: PreparedCodexLaunch,
    arguments: &'a [String],
}

impl VerifiedCodexCommand<'_> {
    pub fn arguments(&self) -> &[String] {
        self.arguments
    }

    pub fn execute(self, working_directory: &Path) -> Result<Vec<u8>, BoundaryError> {
        let arguments = self
            .arguments
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        run_prepared_codex_command(
            self.launch,
            &self.executable.path,
            &arguments,
            working_directory,
        )
        .map_err(|_| BoundaryError::new("Codex command failed at the native transaction boundary"))
    }
}

pub trait CodexCommandRunner {
    fn before_launch(&mut self, _arguments: &[String]) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn run(&mut self, command: VerifiedCodexCommand<'_>) -> Result<Vec<u8>, BoundaryError>;
}

impl<F> CodexCommandRunner for F
where
    F: FnMut(&[String]) -> Result<Vec<u8>, BoundaryError>,
{
    fn run(&mut self, command: VerifiedCodexCommand<'_>) -> Result<Vec<u8>, BoundaryError> {
        self(command.arguments())
    }
}

#[derive(Clone, Debug)]
pub struct CodexProcessRunner {
    working_directory: PathBuf,
}

impl CodexCommandRunner for CodexProcessRunner {
    fn run(&mut self, command: VerifiedCodexCommand<'_>) -> Result<Vec<u8>, BoundaryError> {
        command.execute(&self.working_directory)
    }
}

pub struct CodexCliExecutor<'a, O, V> {
    adapter: &'a CodexAdapter,
    operation_runner: O,
    validation_runner: V,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CodexCommand {
    PluginList,
    McpList,
    McpGet(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CodexExecutableSnapshot {
    kind: CodexExecutableKind,
    digest: Sha256Digest,
}

impl CodexCommand {
    fn argv(&self) -> Vec<String> {
        match self {
            Self::PluginList => vec!["plugin".into(), "list".into(), "--json".into()],
            Self::McpList => vec!["mcp".into(), "list".into(), "--json".into()],
            Self::McpGet(name) => vec!["mcp".into(), "get".into(), name.clone(), "--json".into()],
        }
    }
}

impl CodexAdapter {
    pub fn project_id(&self) -> ProjectId {
        self.project_id
    }

    pub fn discover(
        project_root: impl Into<PathBuf>,
        working_directory: impl Into<PathBuf>,
        project_id: ProjectId,
        origin_device: DeviceId,
        observed_hlc: HybridLogicalClock,
    ) -> Result<Self, ClientError> {
        let project_root = project_root.into();
        let working_directory = working_directory.into();
        let home = home_dir().ok_or_else(|| not_found("Codex home was not found"))?;
        let codex_home = match env::var_os("CODEX_HOME") {
            Some(value) => {
                let value = PathBuf::from(value);
                if !value.is_dir() {
                    return Err(not_found("CODEX_HOME does not exist"));
                }
                value
            }
            None => home.join(".codex"),
        };
        let executable =
            find_executable(&home).ok_or_else(|| not_found("Codex executable was not found"))?;
        let installation_method = installation_method(&executable);
        #[cfg(windows)]
        let (executable, expected_standalone_version) = resolve_windows_standalone_candidate(
            &executable,
            &home,
            env::var_os("LOCALAPPDATA").as_deref().map(Path::new),
        )?;
        #[cfg(not(windows))]
        let expected_standalone_version: Option<String> = None;
        let (executable_snapshot, version) = discover_executable_version(
            &executable,
            &working_directory,
            expected_standalone_version.as_deref(),
        )?;
        Self::from_discovered_layout_after_version(
            CodexLayout {
                installation_method,
                executable,
                executable_kind: CodexExecutableKind::Unknown,
                version: String::new(),
                codex_home,
                user_skills_dir: home.join(".agents/skills"),
                project_root,
                working_directory,
                requirements_paths: requirements_paths(),
            },
            project_id,
            origin_device,
            observed_hlc,
            executable_snapshot,
            version,
            || {},
        )
    }

    pub fn from_layout(
        layout: CodexLayout,
        project_id: ProjectId,
        origin_device: DeviceId,
        observed_hlc: HybridLogicalClock,
    ) -> Result<Self, ClientError> {
        let executable_snapshot = snapshot_executable(&layout.executable)?;
        Self::from_attested_layout(
            layout,
            project_id,
            origin_device,
            observed_hlc,
            executable_snapshot,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_discovered_layout_after_version(
        mut layout: CodexLayout,
        project_id: ProjectId,
        origin_device: DeviceId,
        observed_hlc: HybridLogicalClock,
        executable_snapshot: CodexExecutableSnapshot,
        version: String,
        after_version: impl FnOnce(),
    ) -> Result<Self, ClientError> {
        layout.executable_kind = executable_snapshot.kind;
        layout.version = version;
        after_version();
        Self::from_attested_layout(
            layout,
            project_id,
            origin_device,
            observed_hlc,
            executable_snapshot,
        )
    }

    fn from_attested_layout(
        mut layout: CodexLayout,
        project_id: ProjectId,
        origin_device: DeviceId,
        observed_hlc: HybridLogicalClock,
        executable_snapshot: CodexExecutableSnapshot,
    ) -> Result<Self, ClientError> {
        if !valid_version(&layout.version) {
            return Err(invalid("Codex version is invalid"));
        }
        for path in [
            &layout.executable,
            &layout.codex_home,
            &layout.project_root,
            &layout.working_directory,
        ] {
            wire_path(path)
                .validate()
                .map_err(|_| invalid("Codex path is not representable"))?;
        }
        if !layout.executable.is_file()
            || !layout.codex_home.is_dir()
            || !layout.project_root.is_dir()
            || !layout.working_directory.is_dir()
        {
            return Err(not_found("Codex installation or project is missing"));
        }
        layout.executable = canonical_existing_path(&layout.executable)?;
        layout.codex_home = canonical_existing_directory(&layout.codex_home)?;
        layout.user_skills_dir = canonical_directory_or_absent_path(&layout.user_skills_dir)?;
        layout.project_root = canonical_existing_directory(&layout.project_root)?;
        layout.working_directory = canonical_existing_directory(&layout.working_directory)?;
        layout.requirements_paths = layout
            .requirements_paths
            .into_iter()
            .map(|path| canonical_file_or_absent_path(&path))
            .collect::<Result<_, _>>()?;
        if !layout.working_directory.starts_with(&layout.project_root) {
            return Err(invalid(
                "Codex working directory is outside the project root",
            ));
        }
        if snapshot_executable(&layout.executable)? != executable_snapshot {
            return Err(client_error(
                ErrorCode::Conflict,
                "Codex executable changed",
                false,
            ));
        }
        layout.executable_kind = executable_snapshot.kind;
        let executable_hash = executable_snapshot.digest;
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

    pub fn plan_bridge_cli_mutation(
        &self,
        intended: &ComponentRecord,
    ) -> Result<ApprovedCliMutation, ClientError> {
        self.plan_bridge_cli_mutation_with_runner(intended, self.process_runner())
    }

    pub fn plan_bridge_cli_mutation_with_runner(
        &self,
        intended: &ComponentRecord,
        mut validation_runner: impl CodexCommandRunner,
    ) -> Result<ApprovedCliMutation, ClientError> {
        self.require_apply_supported()?;
        if !is_managed_bridge_component(HarnessId::Codex, intended) {
            return Err(invalid("Codex CLI mutation requires the managed bridge"));
        }
        self.recheck_executable_client()?;
        let expected = self
            .probe_managed_declaration(&mut validation_runner)
            .map_err(|error| match error {
                BridgeDeclarationProbeError::Conflict => client_error(
                    ErrorCode::Conflict,
                    "Codex managed bridge state cannot be safely inspected",
                    false,
                ),
                BridgeDeclarationProbeError::Inspection => {
                    invalid("Codex managed bridge state cannot be safely inspected")
                }
            })?;
        let intended_declaration = canonical_cli_declaration(&intended.body_markdown)?;
        Ok(ApprovedCliMutation {
            execution_context: None,
            stable_id: intended.id.to_string(),
            forward: vec![self.declaration_operation(Some(&intended_declaration))?],
            rollback: vec![self.declaration_operation(expected.as_ref())?],
            expected,
            intended: Some(intended_declaration),
        })
    }

    pub fn cli_executor(&self) -> CodexCliExecutor<'_, CodexProcessRunner, CodexProcessRunner> {
        self.cli_executor_with_runners(self.process_runner(), self.process_runner())
    }

    pub fn cli_executor_with_runners<O, V>(
        &self,
        operation_runner: O,
        validation_runner: V,
    ) -> CodexCliExecutor<'_, O, V>
    where
        O: CodexCommandRunner,
        V: CodexCommandRunner,
    {
        CodexCliExecutor {
            adapter: self,
            operation_runner,
            validation_runner,
        }
    }

    fn process_runner(&self) -> CodexProcessRunner {
        CodexProcessRunner {
            working_directory: self.layout.working_directory.clone(),
        }
    }

    fn recheck_executable_client(&self) -> Result<(), ClientError> {
        open_verified_codex_executable(&self.layout.executable, self.executable_hash)
            .map_err(|_| client_error(ErrorCode::Conflict, "Codex executable changed", false))?;
        Ok(())
    }

    fn recheck_executable_boundary(&self) -> Result<(), BoundaryError> {
        if self.setup_capability() != CapabilityLevel::Full {
            return Err(BoundaryError::new("Codex setup is blocked"));
        }
        open_verified_codex_executable(&self.layout.executable, self.executable_hash)?;
        Ok(())
    }

    fn run_verified(
        &self,
        runner: &mut impl CodexCommandRunner,
        arguments: &[String],
    ) -> Result<Vec<u8>, BoundaryError> {
        self.run_verified_with_policy(runner, arguments, false)
    }

    fn run_authoritative(
        &self,
        runner: &mut impl CodexCommandRunner,
        arguments: &[String],
    ) -> Result<Vec<u8>, BoundaryError> {
        self.run_verified_with_policy(runner, arguments, true)
    }

    fn run_verified_with_policy(
        &self,
        runner: &mut impl CodexCommandRunner,
        arguments: &[String],
        authoritative: bool,
    ) -> Result<Vec<u8>, BoundaryError> {
        let executable =
            open_verified_codex_executable(&self.layout.executable, self.executable_hash)?;
        runner.before_launch(arguments)?;
        if authoritative && self.setup_capability() != CapabilityLevel::Full {
            return Err(BoundaryError::new("Codex setup is blocked"));
        }
        executable.revalidate_before_launch()?;
        let launch = executable
            .prepare_launch()
            .map_err(|_| BoundaryError::new("Codex executable cannot be safely prepared"))?;
        runner.run(VerifiedCodexCommand {
            executable: &executable,
            launch,
            arguments,
        })
    }

    fn declaration_operation(
        &self,
        declaration: Option<&CanonicalCliDeclaration>,
    ) -> Result<CliOperation, ClientError> {
        let arguments = match declaration {
            Some(declaration) => {
                let value: Value = serde_json::from_str(&declaration.canonical_body)
                    .map_err(|_| invalid("Codex managed bridge declaration is invalid"))?;
                render_mcp_add(BRIDGE_SERVER_NAME, &value)?
            }
            None => vec![
                "mcp".to_owned(),
                "remove".to_owned(),
                BRIDGE_SERVER_NAME.to_owned(),
            ],
        };
        Ok(CliOperation {
            executable: wire_path(&self.layout.executable),
            arguments: arguments
                .into_iter()
                .map(|argument| wire_text(&argument))
                .collect(),
            timeout_ms: CLI_TIMEOUT_MS,
        })
    }

    fn probe_managed_declaration(
        &self,
        validation_runner: &mut impl CodexCommandRunner,
    ) -> Result<Option<CanonicalCliDeclaration>, BridgeDeclarationProbeError> {
        let plugin_argv = CodexCommand::PluginList.argv();
        let plugin_output = self
            .run_verified(validation_runner, &plugin_argv)
            .map_err(|_| BridgeDeclarationProbeError::Inspection)?;
        parse_plugin_list_json(&plugin_output)
            .map_err(|_| BridgeDeclarationProbeError::Inspection)?;

        let list_argv = CodexCommand::McpList.argv();
        let listed = self
            .run_verified(validation_runner, &list_argv)
            .map_err(|_| BridgeDeclarationProbeError::Inspection)?;
        let states =
            parse_mcp_list_states(&listed).map_err(|_| BridgeDeclarationProbeError::Inspection)?;
        match states.get(BRIDGE_SERVER_NAME) {
            None => return Ok(None),
            Some(false) => {
                return Err(BridgeDeclarationProbeError::Conflict);
            }
            Some(true) => {}
        }

        let get_argv = CodexCommand::McpGet(BRIDGE_SERVER_NAME.to_owned()).argv();
        let output = self
            .run_verified(validation_runner, &get_argv)
            .map_err(|_| BridgeDeclarationProbeError::Inspection)?;
        parse_managed_mcp_get_json(&output)
    }
    pub fn project_config_path(&self) -> PathBuf {
        self.layout.project_root.join(".codex/config.toml")
    }

    pub fn plan_native_config(
        &self,
        desired: &DesiredState,
        scope: ScopeRef,
    ) -> Result<ApprovedMutation, ClientError> {
        let path = self.config_path(&scope)?;
        self.plan_native_config_path(desired, scope, path)
    }

    pub fn plan_native_config_at(
        &self,
        desired: &DesiredState,
        scope: ScopeRef,
        structural_location: &str,
    ) -> Result<ApprovedMutation, ClientError> {
        let (_, fragment) = split_structural_location(structural_location)?;
        if !MANAGED_PERMISSION_KEYS.contains(&fragment) && fragment != "hooks" {
            return Err(invalid("Codex config structural location is invalid"));
        }
        let path = self.config_path_from_location(&scope, structural_location, fragment)?;
        self.plan_native_config_path(desired, scope, path)
    }

    fn plan_native_config_path(
        &self,
        desired: &DesiredState,
        scope: ScopeRef,
        path: PathBuf,
    ) -> Result<ApprovedMutation, ClientError> {
        self.require_apply_supported()?;
        desired
            .validate()
            .map_err(|_| invalid("Desired Codex state is invalid"))?;
        if matches!(scope, ScopeRef::Project { .. }) && !self.project_is_trusted()? {
            return Err(unsupported(
                "Untrusted project configuration is import-only",
            ));
        }
        if matches!(scope, ScopeRef::Project { .. }) {
            self.validate_project_path(&path)?;
        }
        let snapshot = OsNativeFileSystem::new()
            .snapshot(&path)
            .map_err(|_| invalid("Codex config cannot be safely inspected"))?;
        let (bytes, metadata) = match snapshot.state() {
            NativeState::RegularFile { bytes, metadata } => {
                (bytes.as_slice(), Some(metadata.clone()))
            }
            NativeState::Absent { .. } => (&[][..], None),
        };
        let rendered = self.render_config(bytes, desired, &path)?;
        let intended = if metadata.is_none() && rendered.is_empty() {
            snapshot.state().clone()
        } else {
            let metadata = match metadata {
                Some(metadata) => metadata,
                None => OsNativeFileSystem::new()
                    .metadata_for_new_private_file(&path)
                    .map_err(|_| invalid("Codex config creation metadata is unavailable"))?,
            };
            NativeState::regular_file(rendered, metadata)
        };
        self.approved_file(&path, snapshot.fingerprint(), intended)
    }

    pub fn plan_native_markdown(
        &self,
        component: &ComponentRecord,
    ) -> Result<ApprovedMutation, ClientError> {
        self.require_apply_supported()?;
        ensure_reviewed_text(&component.body_markdown)?;
        if !matches!(
            component.kind,
            ComponentKind::Instruction | ComponentKind::Rule | ComponentKind::Skill
        ) {
            return Err(invalid("Codex Markdown component is invalid"));
        }
        if component.kind == ComponentKind::Rule
            && matches!(component.scope, ScopeRef::Project { .. })
            && !self.project_is_trusted()?
        {
            return Err(unsupported("Untrusted project rules are import-only"));
        }
        let path = self.markdown_path(component)?;
        if matches!(component.scope, ScopeRef::Project { .. }) {
            self.validate_project_path(&path)?;
        }
        if is_primary_memory_instruction_component(HarnessId::Codex, component) {
            let (path, expected, _, intended) =
                self.primary_memory_instruction_projection(component)?;
            return self.approved_file(&path, &expected, intended);
        }
        let snapshot = OsNativeFileSystem::new()
            .snapshot(&path)
            .map_err(|_| invalid("Codex Markdown cannot be safely inspected"))?;
        let NativeState::RegularFile { bytes, metadata } = snapshot.state() else {
            return Err(invalid("Codex Markdown must already exist"));
        };
        let intended = NativeState::regular_file(
            render_managed_markdown(bytes, &component.body_markdown, component.archived)?,
            metadata.clone(),
        );
        self.approved_file(&path, snapshot.fingerprint(), intended)
    }

    fn primary_memory_instruction_projection(
        &self,
        component: &ComponentRecord,
    ) -> Result<(PathBuf, [u8; 32], NativeState, NativeState), ClientError> {
        let standard = self.markdown_path(component)?;
        let override_path = standard.with_file_name("AGENTS.override.md");
        self.validate_project_path(&override_path)?;
        let path = if nonempty_file(&override_path)? {
            override_path
        } else {
            standard
        };
        self.validate_project_path(&path)?;
        let snapshot = OsNativeFileSystem::new()
            .snapshot(&path)
            .map_err(|_| invalid("Codex Markdown cannot be safely inspected"))?;
        let current = snapshot.state().clone();
        let intended = match snapshot.state() {
            NativeState::RegularFile { bytes, metadata } => NativeState::regular_file(
                render_managed_markdown(bytes, &component.body_markdown, component.archived)?,
                metadata.clone(),
            ),
            NativeState::Absent { .. } if component.archived => current.clone(),
            NativeState::Absent { .. } => {
                let metadata = OsNativeFileSystem::new()
                    .metadata_for_new_private_file(&path)
                    .map_err(|_| {
                        invalid("Codex primary instruction creation metadata is unavailable")
                    })?;
                NativeState::regular_file(
                    render_managed_markdown(&[], &component.body_markdown, false)?,
                    metadata,
                )
            }
        };
        Ok((path, *snapshot.fingerprint(), current, intended))
    }

    pub fn plan_native_hooks_json(
        &self,
        component: &ComponentRecord,
    ) -> Result<ApprovedMutation, ClientError> {
        self.require_apply_supported()?;
        ensure_reviewed_text(&component.body_markdown)?;
        if component.kind != ComponentKind::Hook {
            return Err(invalid("Codex hooks component is invalid"));
        }
        if matches!(component.scope, ScopeRef::Project { .. }) && !self.project_is_trusted()? {
            return Err(unsupported("Untrusted project hooks are import-only"));
        }
        let path = self.hooks_json_path(component)?;
        if matches!(component.scope, ScopeRef::Project { .. }) {
            self.validate_project_path(&path)?;
        }
        let snapshot = OsNativeFileSystem::new()
            .snapshot(&path)
            .map_err(|_| invalid("Codex hooks cannot be safely inspected"))?;
        let (existing, metadata) = match snapshot.state() {
            NativeState::RegularFile { bytes, metadata } => {
                (bytes.as_slice(), Some(metadata.clone()))
            }
            NativeState::Absent { .. } => (&[][..], None),
        };
        let mut object = if existing.is_empty() {
            Map::new()
        } else {
            parse_object(existing, "Codex hooks are invalid")?
        };
        if has_managed_memory_hook_identity(HarnessId::Codex, component) {
            if object.get("hooks").is_some() || !component.archived {
                let hooks =
                    merge_managed_memory_hooks(HarnessId::Codex, object.get("hooks"), component)?;
                object.insert("hooks".into(), hooks);
            }
        } else if component.archived {
            object.remove("hooks");
        } else {
            let hooks = serde_json::from_str(&component.body_markdown)
                .map_err(|_| invalid("Codex hooks component is invalid"))?;
            object.insert("hooks".into(), hooks);
        }
        let bytes = serde_json::to_vec(&Value::Object(object))
            .map_err(|_| invalid("Codex hooks cannot be rendered"))?;
        let intended = if metadata.is_none() && component.archived && bytes == b"{}" {
            snapshot.state().clone()
        } else {
            let metadata = match metadata {
                Some(metadata) => metadata,
                None => OsNativeFileSystem::new()
                    .metadata_for_new_private_file(&path)
                    .map_err(|_| invalid("Codex hooks creation metadata is unavailable"))?,
            };
            NativeState::regular_file(bytes, metadata)
        };
        self.approved_file(&path, snapshot.fingerprint(), intended)
    }

    fn approved_file(
        &self,
        path: &Path,
        expected: &[u8; 32],
        intended: NativeState,
    ) -> Result<ApprovedMutation, ClientError> {
        Ok(ApprovedMutation {
            target: wire_path(path),
            kind: MutationKind::Payload,
            content: intended
                .encode_v1()
                .map_err(|_| invalid("Codex native state is not representable"))?,
            expected: RestorableStateFingerprint(Sha256Digest(*expected)),
            intended: RestorableStateFingerprint(Sha256Digest(intended.fingerprint())),
        })
    }

    pub(crate) fn capability(&self) -> CapabilityLevel {
        if SUPPORTED_VERSIONS.contains(&self.layout.version.as_str())
            && self.layout.executable_kind == CodexExecutableKind::Native
        {
            CapabilityLevel::Full
        } else {
            CapabilityLevel::ImportOnly
        }
    }

    pub(crate) fn setup_capability(&self) -> CapabilityLevel {
        let base = self.capability();
        if base != CapabilityLevel::Full {
            return base;
        }
        if self.managed_requirements_active().unwrap_or(true)
            || self.project_is_trusted().ok() != Some(true)
        {
            CapabilityLevel::Blocked
        } else {
            CapabilityLevel::Full
        }
    }

    fn require_apply_supported(&self) -> Result<(), ClientError> {
        match self.setup_capability() {
            CapabilityLevel::Full => Ok(()),
            CapabilityLevel::Blocked => Err(unsupported("This Codex setup is blocked")),
            CapabilityLevel::ImportOnly | CapabilityLevel::Missing => {
                Err(unsupported("This Codex installation is import-only"))
            }
        }
    }

    fn policy_conflicts(&self) -> Result<Vec<String>, ClientError> {
        let mut conflicts = Vec::new();
        if nonempty_file(&self.layout.codex_home.join("AGENTS.override.md"))?
            && nonempty_file(&self.layout.codex_home.join("AGENTS.md"))?
        {
            conflicts.push("global_instructions_shadowed".into());
        }
        if self.managed_requirements_active()? {
            conflicts.push("managed_requirements_active".into());
        }
        if self.project_instruction_shadowed()? {
            conflicts.push("project_instructions_shadowed".into());
        }
        if !self.project_is_trusted()? {
            conflicts.push("project_untrusted".into());
        }
        conflicts.sort();
        conflicts.dedup();
        Ok(conflicts)
    }

    fn managed_requirements_active(&self) -> Result<bool, ClientError> {
        for path in &self.layout.requirements_paths {
            if read_optional_file(path)?.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn project_instruction_shadowed(&self) -> Result<bool, ClientError> {
        for directory in self.project_layers()? {
            if nonempty_file(&directory.join("AGENTS.override.md"))?
                && nonempty_file(&directory.join("AGENTS.md"))?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn project_is_trusted(&self) -> Result<bool, ClientError> {
        let Some(bytes) = read_optional_file(&self.layout.codex_home.join("config.toml"))? else {
            return Ok(false);
        };
        let document = bytes_to_document(&bytes)?;
        let root = self.layout.project_root.to_string_lossy();
        Ok(document
            .get("projects")
            .and_then(Item::as_table)
            .and_then(|projects| projects.get(root.as_ref()))
            .and_then(Item::as_table)
            .and_then(|project| project.get("trust_level"))
            .and_then(Item::as_str)
            == Some("trusted"))
    }

    fn config_path(&self, scope: &ScopeRef) -> Result<PathBuf, ClientError> {
        match scope {
            ScopeRef::Global => Ok(self.layout.codex_home.join("config.toml")),
            ScopeRef::Project { project_id } if *project_id == self.project_id => {
                Ok(self.project_config_path())
            }
            _ => Err(invalid("Codex scope is not configured")),
        }
    }

    fn config_path_from_location(
        &self,
        scope: &ScopeRef,
        location: &str,
        expected_fragment: &str,
    ) -> Result<PathBuf, ClientError> {
        let (path, fragment) = split_structural_location(location)?;
        if fragment != expected_fragment {
            return Err(invalid("Codex config structural location is invalid"));
        }
        match scope {
            ScopeRef::Global if path == "config.toml" => {
                Ok(self.layout.codex_home.join("config.toml"))
            }
            ScopeRef::Project { project_id } if *project_id == self.project_id => {
                for layer in self.project_layers()? {
                    let expected = format!(
                        "{}/.codex/config.toml",
                        display_project_location(&self.layout.project_root, &layer)?
                    );
                    if path == expected {
                        return Ok(layer.join(".codex/config.toml"));
                    }
                }
                Err(invalid("Codex project config location is inactive"))
            }
            _ => Err(invalid("Codex config structural location is invalid")),
        }
    }

    fn config_location_for_path(
        &self,
        path: &Path,
        scope: &ScopeRef,
    ) -> Result<String, ClientError> {
        match scope {
            ScopeRef::Global if path == self.layout.codex_home.join("config.toml") => {
                Ok("config.toml".into())
            }
            ScopeRef::Project { project_id } if *project_id == self.project_id => {
                for layer in self.project_layers()? {
                    if path == layer.join(".codex/config.toml") {
                        return Ok(format!(
                            "{}/.codex/config.toml",
                            display_project_location(&self.layout.project_root, &layer)?
                        ));
                    }
                }
                Err(invalid("Codex project config location is inactive"))
            }
            _ => Err(invalid("Codex config path is not configured")),
        }
    }

    fn config_component_path(
        &self,
        component: &ComponentRecord,
    ) -> Result<Option<PathBuf>, ClientError> {
        match component.kind {
            ComponentKind::PermissionDeclaration => {
                if !MANAGED_PERMISSION_KEYS.contains(&component.name.as_str()) {
                    return Err(invalid("Codex permission component is invalid"));
                }
                match structural_location(component)? {
                    Some(location) => self
                        .config_path_from_location(
                            &component.scope,
                            location,
                            component.name.as_str(),
                        )
                        .map(Some),
                    None => self.config_path(&component.scope).map(Some),
                }
            }
            ComponentKind::Hook => {
                let Some(location) = structural_location(component)? else {
                    return Ok(None);
                };
                let (path, fragment) = split_structural_location(location)?;
                if fragment == "hooks" && path.ends_with("config.toml") {
                    return self
                        .config_path_from_location(&component.scope, location, "hooks")
                        .map(Some);
                }
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    fn hooks_path(&self, scope: &ScopeRef) -> Result<PathBuf, ClientError> {
        match scope {
            ScopeRef::Global => Ok(self.layout.codex_home.join("hooks.json")),
            ScopeRef::Project { project_id } if *project_id == self.project_id => {
                Ok(self.layout.project_root.join(".codex/hooks.json"))
            }
            _ => Err(invalid("Codex scope is not configured")),
        }
    }

    fn hooks_json_path(&self, component: &ComponentRecord) -> Result<PathBuf, ClientError> {
        let Some(location) = structural_location(component)? else {
            return self.hooks_path(&component.scope);
        };
        let (path, fragment) = split_structural_location(location)?;
        if fragment != "hooks" {
            return Err(invalid("Codex hooks structural location is invalid"));
        }
        match component.scope {
            ScopeRef::Global if path == "hooks.json" => {
                Ok(self.layout.codex_home.join("hooks.json"))
            }
            ScopeRef::Project { project_id } if project_id == self.project_id => {
                for layer in self.project_layers()? {
                    let expected = format!(
                        "{}/.codex/hooks.json",
                        display_project_location(&self.layout.project_root, &layer)?
                    );
                    if path == expected {
                        return Ok(layer.join(".codex/hooks.json"));
                    }
                }
                Err(invalid("Codex project hooks location is inactive"))
            }
            _ => Err(invalid("Codex hooks structural location is invalid")),
        }
    }

    fn hooks_location_for_path(
        &self,
        path: &Path,
        scope: &ScopeRef,
    ) -> Result<String, ClientError> {
        match scope {
            ScopeRef::Global if path == self.layout.codex_home.join("hooks.json") => {
                Ok("hooks.json".into())
            }
            ScopeRef::Project { project_id } if *project_id == self.project_id => {
                for layer in self.project_layers()? {
                    if path == layer.join(".codex/hooks.json") {
                        return Ok(format!(
                            "{}/.codex/hooks.json",
                            display_project_location(&self.layout.project_root, &layer)?
                        ));
                    }
                }
                Err(invalid("Codex project hooks location is inactive"))
            }
            _ => Err(invalid("Codex hooks path is not configured")),
        }
    }

    fn markdown_path(&self, component: &ComponentRecord) -> Result<PathBuf, ClientError> {
        let location = structural_location(component)?;
        match (&component.scope, component.kind, location) {
            (ScopeRef::Global, ComponentKind::Instruction, None) => {
                safe_file_name(&component.name)?;
                Ok(self.layout.codex_home.join(&component.name))
            }
            (ScopeRef::Global, ComponentKind::Rule, None) => Ok(self
                .layout
                .codex_home
                .join("rules")
                .join(safe_rule_relative(&component.name)?)),
            (ScopeRef::Global, ComponentKind::Skill, None) => {
                safe_name(&component.name)?;
                Ok(self
                    .layout
                    .user_skills_dir
                    .join(&component.name)
                    .join("SKILL.md"))
            }
            (ScopeRef::Project { project_id }, ComponentKind::Instruction, None)
                if *project_id == self.project_id =>
            {
                safe_file_name(&component.name)?;
                Ok(self.layout.project_root.join(&component.name))
            }
            (ScopeRef::Project { project_id }, ComponentKind::Rule, None)
                if *project_id == self.project_id =>
            {
                Ok(self
                    .layout
                    .project_root
                    .join(".codex/rules")
                    .join(safe_rule_relative(&component.name)?))
            }
            (ScopeRef::Project { project_id }, ComponentKind::Skill, None)
                if *project_id == self.project_id =>
            {
                safe_name(&component.name)?;
                Ok(self
                    .layout
                    .project_root
                    .join(".agents/skills")
                    .join(&component.name)
                    .join("SKILL.md"))
            }
            (ScopeRef::Global, ComponentKind::Instruction, Some(location)) => {
                safe_file_name(location)?;
                if location != component.name {
                    return Err(invalid("Codex instruction location is inconsistent"));
                }
                Ok(self.layout.codex_home.join(location))
            }
            (ScopeRef::Global, ComponentKind::Rule, Some(location)) => {
                let relative = location
                    .strip_prefix("rules/")
                    .ok_or_else(|| invalid("Codex rule location is unsafe"))?;
                if relative != component.name {
                    return Err(invalid("Codex rule location is inconsistent"));
                }
                Ok(self
                    .layout
                    .codex_home
                    .join("rules")
                    .join(safe_rule_relative(relative)?))
            }
            (ScopeRef::Global, ComponentKind::Skill, Some(location)) => {
                safe_name(&component.name)?;
                if location != format!("user skills/{}/SKILL.md", component.name) {
                    return Err(invalid("Codex skill location is unsafe"));
                }
                Ok(self
                    .layout
                    .user_skills_dir
                    .join(&component.name)
                    .join("SKILL.md"))
            }
            (ScopeRef::Project { project_id }, kind, Some(location))
                if *project_id == self.project_id =>
            {
                for layer in self.project_layers()? {
                    let prefix = display_project_location(&self.layout.project_root, &layer)?;
                    match kind {
                        ComponentKind::Instruction => {
                            safe_file_name(&component.name)?;
                            if location == format!("{prefix}/{}", component.name) {
                                return Ok(layer.join(&component.name));
                            }
                        }
                        ComponentKind::Rule => {
                            let rule_prefix = format!("{prefix}/.codex/rules/");
                            if let Some(relative) = location.strip_prefix(&rule_prefix)
                                && relative == component.name
                            {
                                return Ok(layer
                                    .join(".codex/rules")
                                    .join(safe_rule_relative(relative)?));
                            }
                        }
                        ComponentKind::Skill => {
                            safe_name(&component.name)?;
                            if location
                                == format!("{prefix}/.agents/skills/{}/SKILL.md", component.name)
                            {
                                return Ok(layer
                                    .join(".agents/skills")
                                    .join(&component.name)
                                    .join("SKILL.md"));
                            }
                        }
                        _ => {}
                    }
                }
                Err(invalid("Codex project Markdown location is inactive"))
            }
            _ => Err(invalid("Codex Markdown location is unsafe")),
        }
    }

    fn render_config(
        &self,
        existing: &[u8],
        desired: &DesiredState,
        target: &Path,
    ) -> Result<Vec<u8>, ClientError> {
        let mut document = bytes_to_document(existing)?;
        for component in &desired.components {
            ensure_reviewed_text(&component.body_markdown)?;
            let Some(component_path) = self.config_component_path(component)? else {
                continue;
            };
            if component_path != target {
                continue;
            }
            let key = match component.kind {
                ComponentKind::PermissionDeclaration
                    if MANAGED_PERMISSION_KEYS.contains(&component.name.as_str()) =>
                {
                    component.name.as_str()
                }
                ComponentKind::PermissionDeclaration => {
                    return Err(invalid("Codex permission component is invalid"));
                }
                ComponentKind::Hook if component.name == "hooks" => "hooks",
                ComponentKind::Hook => {
                    return Err(invalid("Codex inline hooks component is invalid"));
                }
                _ => continue,
            };
            if component.archived {
                document.remove(key);
                continue;
            }
            document[key] = managed_toml_item(component, key)?;
        }
        Ok(document.to_string().into_bytes())
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
                self.import_instruction(
                    &self.layout.codex_home,
                    ScopeRef::Global,
                    0,
                    "",
                    components,
                    digests,
                )?;
                self.import_config(
                    &self.layout.codex_home.join("config.toml"),
                    ScopeRef::Global,
                    include_disabled,
                    components,
                    digests,
                )?;
                self.import_hooks(
                    &self.layout.codex_home.join("hooks.json"),
                    ScopeRef::Global,
                    components,
                    digests,
                )?;
                self.import_rules(
                    &self.layout.codex_home.join("rules"),
                    ScopeRef::Global,
                    "rules",
                    components,
                    digests,
                )?;
                self.import_skills(
                    &self.layout.user_skills_dir,
                    ScopeRef::Global,
                    "user skills",
                    components,
                    digests,
                )?;
            }
            ScopeRef::Project { project_id } => {
                for (index, directory) in self.project_layers()?.into_iter().enumerate() {
                    self.import_instruction(
                        &directory,
                        ScopeRef::Project { project_id },
                        index + 1,
                        &display_project_location(&self.layout.project_root, &directory)?,
                        components,
                        digests,
                    )?;
                    self.import_skills(
                        &directory.join(".agents/skills"),
                        ScopeRef::Project { project_id },
                        &format!(
                            "{}/.agents/skills",
                            display_project_location(&self.layout.project_root, &directory)?
                        ),
                        components,
                        digests,
                    )?;
                    if self.project_is_trusted()? {
                        self.import_config(
                            &directory.join(".codex/config.toml"),
                            ScopeRef::Project { project_id },
                            include_disabled,
                            components,
                            digests,
                        )?;
                        self.import_hooks(
                            &directory.join(".codex/hooks.json"),
                            ScopeRef::Project { project_id },
                            components,
                            digests,
                        )?;
                        self.import_rules(
                            &directory.join(".codex/rules"),
                            ScopeRef::Project { project_id },
                            &format!(
                                "{}/.codex/rules",
                                display_project_location(&self.layout.project_root, &directory)?
                            ),
                            components,
                            digests,
                        )?;
                    }
                }
            }
        };
        Ok(())
    }

    fn import_instruction(
        &self,
        root: &Path,
        scope: ScopeRef,
        precedence: usize,
        location_prefix: &str,
        components: &mut Vec<ComponentRecord>,
        digests: &mut BTreeSet<Sha256Digest>,
    ) -> Result<(), ClientError> {
        if matches!(&scope, ScopeRef::Project { .. }) {
            self.validate_project_path(root)?;
        }
        let override_path = root.join("AGENTS.override.md");
        let standard_path = root.join("AGENTS.md");
        let selected = if nonempty_file(&override_path)? {
            Some((override_path, "AGENTS.override.md".to_owned()))
        } else if nonempty_file(&standard_path)? {
            Some((standard_path, "AGENTS.md".to_owned()))
        } else if matches!(&scope, ScopeRef::Project { .. }) {
            let mut selected = None;
            for name in self.project_doc_fallback_filenames()? {
                let path = root.join(&name);
                if nonempty_file(&path)? {
                    selected = Some((path, name));
                    break;
                }
            }
            selected
        } else {
            None
        };
        if let Some((path, name)) = selected {
            let location = if location_prefix.is_empty() {
                name.to_owned()
            } else {
                format!("{location_prefix}/{name}")
            };
            self.import_markdown(
                &path,
                scope,
                ComponentKind::Instruction,
                &name,
                &location,
                Some(precedence),
                components,
                digests,
            )?;
        }
        Ok(())
    }

    fn project_doc_fallback_filenames(&self) -> Result<Vec<String>, ClientError> {
        let Some(bytes) = read_optional_file(&self.layout.codex_home.join("config.toml"))? else {
            return Ok(Vec::new());
        };
        let document = bytes_to_document(&bytes)?;
        let Some(item) = document.get("project_doc_fallback_filenames") else {
            return Ok(Vec::new());
        };
        let values = item
            .as_array()
            .ok_or_else(|| invalid("Codex fallback instruction names are invalid"))?;
        values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| invalid("Codex fallback instruction name is invalid"))
            })
            .map(|result| {
                result.and_then(|name| {
                    safe_file_name(&name)?;
                    Ok(name)
                })
            })
            .collect()
    }

    fn import_rules(
        &self,
        root: &Path,
        scope: ScopeRef,
        location: &str,
        components: &mut Vec<ComponentRecord>,
        digests: &mut BTreeSet<Sha256Digest>,
    ) -> Result<(), ClientError> {
        if matches!(&scope, ScopeRef::Project { .. }) {
            self.validate_project_path(root)?;
        }
        for path in reviewed_files(root, |path| {
            path.extension()
                .is_some_and(|extension| extension == "rules")
        })? {
            let name = display_relative(
                path.strip_prefix(root)
                    .map_err(|_| invalid("Codex rule escaped its root"))?,
            )?;
            self.import_markdown(
                &path,
                scope.clone(),
                ComponentKind::Rule,
                &name,
                &format!("{location}/{name}"),
                None,
                components,
                digests,
            )?;
        }
        Ok(())
    }

    fn import_skills(
        &self,
        root: &Path,
        scope: ScopeRef,
        location: &str,
        components: &mut Vec<ComponentRecord>,
        digests: &mut BTreeSet<Sha256Digest>,
    ) -> Result<(), ClientError> {
        if matches!(&scope, ScopeRef::Project { .. }) {
            self.validate_project_path(root)?;
        }
        for path in reviewed_skill_files(root)? {
            let name = path
                .parent()
                .and_then(Path::file_name)
                .and_then(|name| name.to_str())
                .ok_or_else(|| invalid("Codex skill name is invalid"))?;
            safe_name(name)?;
            self.import_markdown(
                &path,
                scope.clone(),
                ComponentKind::Skill,
                name,
                &format!("{location}/{name}/SKILL.md"),
                None,
                components,
                digests,
            )?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn import_markdown(
        &self,
        path: &Path,
        scope: ScopeRef,
        kind: ComponentKind,
        name: &str,
        location: &str,
        precedence: Option<usize>,
        components: &mut Vec<ComponentRecord>,
        digests: &mut BTreeSet<Sha256Digest>,
    ) -> Result<(), ClientError> {
        if matches!(&scope, ScopeRef::Project { .. }) {
            self.validate_project_path(path)?;
        }
        let Some(bytes) = read_optional_file(path)? else {
            return Ok(());
        };
        let body =
            String::from_utf8(bytes.clone()).map_err(|_| invalid("Codex Markdown is not UTF-8"))?;
        ensure_reviewed_text(&body)?;
        digests.insert(digest(&bytes));
        let mut component = self.component(scope, kind, name, body, location)?;
        if let Some(precedence) = precedence {
            component
                .metadata
                .push(("precedenceIndex".into(), precedence.to_string()));
        }
        components.push(component);
        Ok(())
    }

    fn import_config(
        &self,
        path: &Path,
        scope: ScopeRef,
        include_disabled: bool,
        components: &mut Vec<ComponentRecord>,
        digests: &mut BTreeSet<Sha256Digest>,
    ) -> Result<(), ClientError> {
        if matches!(&scope, ScopeRef::Project { .. }) {
            self.validate_project_path(path)?;
        }
        let Some(bytes) = read_optional_file(path)? else {
            return Ok(());
        };
        let document = bytes_to_document(&bytes)?;
        digests.insert(digest(&bytes));
        let location = format!("{}#", self.config_location_for_path(path, &scope)?);
        for key in MANAGED_PERMISSION_KEYS {
            if let Some(item) = document.get(key) {
                let mut component = self.component(
                    scope.clone(),
                    ComponentKind::PermissionDeclaration,
                    key,
                    synthetic_toml_item(key, item)?,
                    &format!("{location}{key}"),
                )?;
                ensure_reviewed_text(&component.body_markdown)?;
                component
                    .metadata
                    .push(("tomlItemKind".into(), toml_item_kind(item)?.into()));
                components.push(component);
            }
        }
        if let Some(hooks) = document.get("hooks") {
            let mut component = self.component(
                scope.clone(),
                ComponentKind::Hook,
                "hooks",
                synthetic_toml_item("hooks", hooks)?,
                &format!("{location}hooks"),
            )?;
            ensure_reviewed_text(&component.body_markdown)?;
            component
                .metadata
                .push(("tomlItemKind".into(), toml_item_kind(hooks)?.into()));
            components.push(component);
        }
        if let Some(plugins) = document.get("plugins").and_then(Item::as_table) {
            for (name, table) in plugins {
                safe_name(name)?;
                let enabled = table
                    .as_table()
                    .and_then(|table| table.get("enabled"))
                    .and_then(Item::as_bool)
                    .unwrap_or(true);
                if enabled || include_disabled {
                    let redacted = redact_plugin_sensitive(toml_item_json(table));
                    let mut component = self.component(
                        scope.clone(),
                        ComponentKind::Plugin,
                        name,
                        canonical_json(&redacted)?,
                        &format!("{location}plugins/{name}"),
                    )?;
                    component.archived = !enabled;
                    components.push(component);
                }
            }
        }
        if let Some(servers) = document.get("mcp_servers").and_then(Item::as_table) {
            for (name, table) in servers {
                safe_name(name)?;
                let value = toml_item_json(table);
                let redacted = redact_sensitive(value);
                let mut component = self.component(
                    scope.clone(),
                    ComponentKind::McpServer,
                    name,
                    canonical_json(&redacted)?,
                    &format!("{location}mcp_servers/{name}"),
                )?;
                if contains_redaction(&redacted) {
                    component.archived = false;
                }
                components.push(component);
            }
        }
        Ok(())
    }

    fn import_hooks(
        &self,
        path: &Path,
        scope: ScopeRef,
        components: &mut Vec<ComponentRecord>,
        digests: &mut BTreeSet<Sha256Digest>,
    ) -> Result<(), ClientError> {
        if matches!(&scope, ScopeRef::Project { .. }) {
            self.validate_project_path(path)?;
        }
        let Some(bytes) = read_optional_file(path)? else {
            return Ok(());
        };
        let object = parse_object(&bytes, "Codex hooks are invalid")?;
        digests.insert(digest(&bytes));
        if let Some(hooks) = object.get("hooks") {
            let location = format!("{}#hooks", self.hooks_location_for_path(path, &scope)?);
            let component = self.component(
                scope,
                ComponentKind::Hook,
                "hooks.json",
                canonical_json(hooks)?,
                &location,
            )?;
            ensure_reviewed_text(&component.body_markdown)?;
            components.push(component);
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
            metadata: vec![("structuralLocation".into(), location.to_owned())],
            provenance: Provenance {
                origin_device: self.origin_device,
                harness: Some(HarnessId::Codex),
                source: None,
                created_hlc: self.observed_hlc,
            },
            archived: false,
        };
        component
            .validate()
            .map_err(|_| invalid("Codex component exceeds protocol limits"))?;
        Ok(component)
    }

    fn project_layers(&self) -> Result<Vec<PathBuf>, ClientError> {
        let relative = self
            .layout
            .working_directory
            .strip_prefix(&self.layout.project_root)
            .map_err(|_| invalid("Codex working directory is outside the project root"))?;
        let mut layers = vec![self.layout.project_root.clone()];
        let mut current = self.layout.project_root.clone();
        self.validate_project_path(&current)?;
        for component in relative.components() {
            if let Component::Normal(name) = component {
                current.push(name);
                self.validate_project_path(&current)?;
                layers.push(current.clone());
            } else {
                return Err(invalid("Codex working directory is unsafe"));
            }
        }
        Ok(layers)
    }

    fn validate_project_path(&self, path: &Path) -> Result<(), ClientError> {
        let relative = path
            .strip_prefix(&self.layout.project_root)
            .map_err(|_| invalid("Codex project path escaped its root"))?;
        if relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(invalid("Codex project path is unsafe"));
        }
        let mut current = self.layout.project_root.clone();
        let root_metadata = fs::symlink_metadata(&current)
            .map_err(|_| invalid("Codex project path cannot be inspected"))?;
        if !root_metadata.is_dir() || project_metadata_is_link(&root_metadata) {
            return Err(invalid("Codex project path has unsafe topology"));
        }
        for component in relative.components() {
            let Component::Normal(name) = component else {
                return Err(invalid("Codex project path is unsafe"));
            };
            current.push(name);
            match fs::symlink_metadata(&current) {
                Ok(metadata) if project_metadata_is_link(&metadata) => {
                    return Err(invalid("Codex project path has unsafe topology"));
                }
                Ok(_) => {}
                Err(error) if error.kind() == ErrorKind::NotFound => break,
                Err(_) => return Err(invalid("Codex project path cannot be inspected")),
            }
        }
        Ok(())
    }
}

impl NativeMemoryAdapter for CodexAdapter {
    fn native_memory_capabilities(&self) -> Result<NativeMemoryCapabilities, ClientError> {
        let memory_root = self.layout.codex_home.join("memories");
        let sources = vec![
            native_memory_source(
                HarnessId::Codex,
                &self.layout.version,
                ScopeRef::Global,
                NativeMemoryDocumentKind::Agent,
                wire_path(&memory_root.join("MEMORY.md")),
            )?,
            native_memory_source(
                HarnessId::Codex,
                &self.layout.version,
                ScopeRef::Global,
                NativeMemoryDocumentKind::Summary,
                wire_path(&memory_root.join("memory_summary.md")),
            )?,
        ];
        match self.setup_capability() {
            CapabilityLevel::Blocked | CapabilityLevel::Missing => {
                let capabilities = NativeMemoryCapabilities {
                    disable: NativeMemoryDisable::Unavailable,
                    sources: vec![],
                };
                capabilities.validate()?;
                return Ok(capabilities);
            }
            CapabilityLevel::ImportOnly => {
                let capabilities = NativeMemoryCapabilities {
                    disable: NativeMemoryDisable::WatchOnly,
                    sources,
                };
                capabilities.validate()?;
                return Ok(capabilities);
            }
            CapabilityLevel::Full => {}
        }

        let watch_only = || NativeMemoryCapabilities {
            disable: NativeMemoryDisable::WatchOnly,
            sources: sources.clone(),
        };
        let mut mutations = Vec::new();
        let mut seen = HashSet::new();
        // Project layers override the global settings. Include their explicit
        // memory values in the same reviewed, reversible setup transaction.
        for (path, project_layer) in self.effective_config_paths()? {
            // CODEX_HOME may itself be the project's .codex directory. The
            // first occurrence is global and must set both inherited defaults.
            if !seen.insert(path.clone()) {
                continue;
            }
            if project_layer {
                self.validate_project_path(&path)?;
                match fs::symlink_metadata(&path) {
                    Err(error) if error.kind() == ErrorKind::NotFound => continue,
                    Err(_) => return Ok(watch_only()),
                    Ok(_) => {}
                }
            }
            let snapshot = match OsNativeFileSystem::new().snapshot(&path) {
                Ok(snapshot) => snapshot,
                Err(_) => return Ok(watch_only()),
            };
            if project_layer && matches!(snapshot.state(), NativeState::Absent { .. }) {
                continue;
            }
            let NativeState::RegularFile { bytes, metadata } = snapshot.state() else {
                return Ok(watch_only());
            };
            let mut document = match bytes_to_document(bytes) {
                Ok(document) => document,
                Err(_) => return Ok(watch_only()),
            };
            let changed = match staged_mcp::disable_memory_settings(&mut document, project_layer) {
                Ok(changed) => changed,
                Err(_) => return Ok(watch_only()),
            };
            if changed {
                let intended =
                    NativeState::regular_file(document.to_string().into_bytes(), metadata.clone());
                mutations.push(self.approved_file(&path, snapshot.fingerprint(), intended)?);
            }
        }
        let capabilities = NativeMemoryCapabilities {
            disable: NativeMemoryDisable::Supported(mutations),
            sources,
        };
        capabilities.validate()?;
        Ok(capabilities)
    }
}

impl HarnessAdapter for CodexAdapter {
    fn probe(&self, context: &ProbeContext) -> Result<ProbeReport, ClientError> {
        context
            .validate()
            .map_err(|_| invalid("Codex probe context is invalid"))?;
        if context.harness != HarnessId::Codex {
            return Err(invalid("Codex adapter received another harness"));
        }
        Ok(ProbeReport {
            executable: Some(wire_path(&self.layout.executable)),
            executable_sha256: Some(self.executable_hash),
            harness_version: Some(self.layout.version.clone()),
            installation_method: self.layout.installation_method,
            config_roots: vec![
                wire_path(&self.layout.codex_home),
                wire_path(&self.layout.user_skills_dir),
                wire_path(&self.layout.project_root),
            ],
            active_profile: context.requested_profile.clone(),
            policy_conflicts: self.policy_conflicts()?,
            capability: self.setup_capability(),
        })
    }

    fn discover_scopes(&self, report: &ProbeReport) -> Result<DiscoveredScopes, ClientError> {
        report
            .validate()
            .map_err(|_| invalid("Codex probe report is invalid"))?;
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
            .map_err(|_| invalid("Codex import request is invalid"))?;
        let mut components = Vec::new();
        let mut digests = BTreeSet::new();
        let mut seen = HashSet::new();
        for native_scope in &request.scopes {
            let scope = match native_scope {
                NativeScope::Global => ScopeRef::Global,
                NativeScope::Project { project_id, root }
                    if *project_id == self.project_id && *root == self.project_root_wire() =>
                {
                    ScopeRef::Project {
                        project_id: *project_id,
                    }
                }
                _ => return Err(invalid("Codex import requested an unconfigured project")),
            };
            let key = match &scope {
                ScopeRef::Global => "global".to_owned(),
                ScopeRef::Project { project_id } => format!("project:{project_id}"),
            };
            if !seen.insert(key) {
                return Err(invalid("Codex import repeated a scope"));
            }
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
            .map_err(|_| invalid("Desired Codex state is invalid"))?;
        let mut files = Vec::new();
        let mut cli_operations = Vec::new();
        let mut config_paths = BTreeSet::new();
        let mut hook_components = BTreeMap::new();
        for component in &desired.components {
            if matches!(component.scope, ScopeRef::Project { .. })
                && matches!(
                    component.kind,
                    ComponentKind::PermissionDeclaration
                        | ComponentKind::Hook
                        | ComponentKind::Rule
                )
                && !self.project_is_trusted()?
            {
                return Err(unsupported(
                    "Untrusted project Codex configuration is import-only",
                ));
            }
            match component.kind {
                ComponentKind::PermissionDeclaration => {
                    let path = self
                        .config_component_path(component)?
                        .ok_or_else(|| invalid("Codex permission target is invalid"))?;
                    if matches!(component.scope, ScopeRef::Project { .. }) {
                        self.validate_project_path(&path)?;
                    }
                    config_paths.insert(path);
                }
                ComponentKind::Hook => {
                    if let Some(path) = self.config_component_path(component)? {
                        if matches!(component.scope, ScopeRef::Project { .. }) {
                            self.validate_project_path(&path)?;
                        }
                        config_paths.insert(path);
                    } else {
                        let path = self.hooks_json_path(component)?;
                        if matches!(component.scope, ScopeRef::Project { .. }) {
                            self.validate_project_path(&path)?;
                        }
                        if hook_components.insert(path, component).is_some() {
                            return Err(invalid("Codex hooks target is repeated"));
                        }
                    }
                }
                ComponentKind::Instruction | ComponentKind::Rule | ComponentKind::Skill => {
                    if is_primary_memory_instruction_component(HarnessId::Codex, component) {
                        let (path, _, current, intended) =
                            self.primary_memory_instruction_projection(component)?;
                        if current.fingerprint() != intended.fingerprint()
                            && let NativeState::RegularFile { bytes, .. } = intended
                        {
                            files.push(rendered_file(path, &bytes));
                        }
                        continue;
                    }
                    let path = self.markdown_path(component)?;
                    if matches!(component.scope, ScopeRef::Project { .. }) {
                        self.validate_project_path(&path)?;
                    }
                    let existing =
                        read_required_regular(&path, "Codex Markdown must already exist")?;
                    let bytes = render_managed_markdown(
                        &existing,
                        &component.body_markdown,
                        component.archived,
                    )?;
                    files.push(rendered_file(path, &bytes));
                }
                ComponentKind::Plugin | ComponentKind::McpServer => {
                    if let Some(operation) = self.render_cli_operation(component)? {
                        cli_operations.push(operation);
                    }
                }
            }
        }
        for path in config_paths {
            let existing = read_optional_file(&path)?.unwrap_or_default();
            files.push(rendered_file(
                path.clone(),
                &self.render_config(&existing, desired, &path)?,
            ));
        }
        for (path, component) in hook_components {
            let existing = read_optional_file(&path)?.unwrap_or_default();
            let mut object = if existing.is_empty() {
                Map::new()
            } else {
                parse_object(&existing, "Codex hooks are invalid")?
            };
            if has_managed_memory_hook_identity(HarnessId::Codex, component) {
                if object.get("hooks").is_some() || !component.archived {
                    let hooks = merge_managed_memory_hooks(
                        HarnessId::Codex,
                        object.get("hooks"),
                        component,
                    )?;
                    object.insert("hooks".into(), hooks);
                }
            } else if component.archived {
                object.remove("hooks");
            } else {
                let hooks = serde_json::from_str(&component.body_markdown)
                    .map_err(|_| invalid("Codex hooks component is invalid"))?;
                object.insert("hooks".into(), hooks);
            }
            let bytes = serde_json::to_vec(&Value::Object(object))
                .map_err(|_| invalid("Codex hooks cannot be rendered"))?;
            files.push(rendered_file(path, &bytes));
        }
        files.sort_by(|left, right| left.path.bytes.cmp(&right.path.bytes));
        Ok(RenderedState {
            files,
            cli_operations,
        })
    }

    fn classify(&self, diff: &SemanticDiff) -> Result<ClassifiedChanges, ClientError> {
        diff.validate()
            .map_err(|_| invalid("Codex semantic diff is invalid"))?;
        if !diff.conflicts.is_empty() {
            return Err(client_error(
                ErrorCode::Conflict,
                "Codex semantic diff has conflicts",
                false,
            ));
        }
        Ok(ClassifiedChanges(diff.changes.clone()))
    }

    fn plan_cli_ops(&self, changes: &ClassifiedChanges) -> Result<CliOperations, ClientError> {
        self.require_apply_supported()?;
        changes
            .validate()
            .map_err(|_| invalid("Codex changes are invalid"))?;
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
                    harness: Some(HarnessId::Codex),
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
        self.validate_effective_with(receipt, |command| {
            let argv = command.argv();
            run_bounded_command(
                &self.layout.executable,
                &argv.iter().map(String::as_str).collect::<Vec<_>>(),
                self.executable_hash,
                &self.layout.working_directory,
            )
        })
    }
}

impl CodexAdapter {
    fn validate_effective_with(
        &self,
        receipt: &ApplyReceipt,
        mut execute: impl FnMut(&CodexCommand) -> Result<Vec<u8>, ClientError>,
    ) -> Result<ValidationReport, ClientError> {
        receipt
            .validate()
            .map_err(|_| invalid("Codex receipt is invalid"))?;
        self.require_apply_supported()?;
        let installed_plugins = parse_plugin_list_json(&execute(&CodexCommand::PluginList)?)?;
        if installed_plugins != self.imported_plugin_states()? {
            return Ok(ValidationReport {
                valid: false,
                findings: vec!["configured_plugin_state_mismatch".into()],
            });
        }
        let configured = parse_mcp_list_json(&execute(&CodexCommand::McpList)?)?;
        let expected = self.imported_mcp_declarations()?;
        let expected_names = expected.keys().cloned().collect::<BTreeSet<_>>();
        if configured != expected_names {
            return Ok(ValidationReport {
                valid: false,
                findings: vec!["configured_mcp_server_state_mismatch".into()],
            });
        }
        for (name, expected_declaration) in expected {
            let command = CodexCommand::McpGet(name.clone());
            let output = execute(&command)?;
            let actual_declaration = parse_mcp_get_json(&output, &name)?;
            if actual_declaration != expected_declaration {
                return Ok(ValidationReport {
                    valid: false,
                    findings: vec!["configured_mcp_server_declaration_mismatch".into()],
                });
            }
        }
        Ok(ValidationReport {
            valid: true,
            findings: vec![],
        })
    }
}

impl CodexAdapter {
    fn render_cli_operation(
        &self,
        component: &ComponentRecord,
    ) -> Result<Option<CliOperation>, ClientError> {
        if !matches!(component.scope, ScopeRef::Global) {
            return Err(unsupported("Project Codex CLI changes are import-only"));
        }
        let arguments = match component.kind {
            ComponentKind::Plugin => {
                safe_name(&component.name)?;
                if component.archived {
                    vec![
                        "plugin".into(),
                        "remove".into(),
                        component.name.clone(),
                        "--json".into(),
                    ]
                } else {
                    vec![
                        "plugin".into(),
                        "add".into(),
                        component.name.clone(),
                        "--json".into(),
                    ]
                }
            }
            ComponentKind::McpServer => {
                safe_name(&component.name)?;
                if component.archived {
                    vec!["mcp".into(), "remove".into(), component.name.clone()]
                } else {
                    let value: Value = serde_json::from_str(&component.body_markdown)
                        .map_err(|_| invalid("Codex MCP component is invalid"))?;
                    if contains_redaction(&value) {
                        return Err(invalid(
                            "Redacted Codex MCP configuration cannot be applied",
                        ));
                    }
                    render_mcp_add(&component.name, &value)?
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

    fn imported_plugin_states(&self) -> Result<BTreeMap<String, bool>, ClientError> {
        let mut states = BTreeMap::new();
        for (path, is_project) in self.effective_config_paths()? {
            if is_project {
                self.validate_project_path(&path)?;
            }
            let Some(bytes) = read_optional_file(&path)? else {
                continue;
            };
            let document = bytes_to_document(&bytes)?;
            if let Some(plugins) = document.get("plugins") {
                let plugins = plugins
                    .as_table()
                    .ok_or_else(|| invalid("Codex plugin configuration is invalid"))?;
                for (name, item) in plugins {
                    safe_name(name)?;
                    let table = item
                        .as_table()
                        .ok_or_else(|| invalid("Codex plugin configuration is invalid"))?;
                    let enabled = match table.get("enabled") {
                        Some(enabled) => enabled
                            .as_bool()
                            .ok_or_else(|| invalid("Codex plugin configuration is invalid"))?,
                        None => true,
                    };
                    if enabled {
                        states.insert(name.to_owned(), true);
                    } else {
                        states.remove(name);
                    }
                }
            }
        }
        Ok(states)
    }

    fn imported_mcp_declarations(&self) -> Result<BTreeMap<String, Value>, ClientError> {
        let mut declarations = BTreeMap::new();
        for (path, is_project) in self.effective_config_paths()? {
            if is_project {
                self.validate_project_path(&path)?;
            }
            let Some(bytes) = read_optional_file(&path)? else {
                continue;
            };
            let document = bytes_to_document(&bytes)?;
            if let Some(servers) = document.get("mcp_servers") {
                let servers = servers
                    .as_table()
                    .ok_or_else(|| invalid("Codex MCP configuration is invalid"))?;
                for (name, item) in servers {
                    safe_name(name)?;
                    let table = item
                        .as_table()
                        .ok_or_else(|| invalid("Codex MCP configuration is invalid"))?;
                    let enabled = match table.get("enabled") {
                        Some(enabled) => enabled
                            .as_bool()
                            .ok_or_else(|| invalid("Codex MCP configuration is invalid"))?,
                        None => true,
                    };
                    if enabled {
                        declarations.insert(name.to_owned(), normalize_config_mcp(table)?);
                    } else {
                        declarations.remove(name);
                    }
                }
            }
        }
        Ok(declarations)
    }

    fn effective_config_paths(&self) -> Result<Vec<(PathBuf, bool)>, ClientError> {
        let mut paths = vec![(self.layout.codex_home.join("config.toml"), false)];
        if self.project_is_trusted()? {
            paths.extend(
                self.project_layers()?
                    .into_iter()
                    .map(|layer| (layer.join(".codex/config.toml"), true)),
            );
        }
        Ok(paths)
    }

    fn verify_native_memory_plan_state(
        &self,
        plan: &NativeTransactionPlan,
        final_state: bool,
    ) -> Result<(), BoundaryError> {
        if plan.native_memory_registrations.is_empty() {
            return Ok(());
        }
        let capabilities = self
            .native_memory_capabilities()
            .map_err(|_| BoundaryError::new("Codex memory settings cannot be inspected"))?;
        if plan.native_memory_registrations.len() != capabilities.sources.len()
            || plan
                .native_memory_registrations
                .iter()
                .any(|registration| !capabilities.sources.contains(&registration.source))
        {
            return Err(BoundaryError::new("Codex native memory location changed"));
        }
        let NativeMemoryDisable::Supported(required) = capabilities.disable else {
            return Err(BoundaryError::new("Codex memory settings changed"));
        };
        for needed in required {
            // Reservation checks run between writes, including inverse writes.
            // Permit only the two exact reviewed states, in either direction.
            // Final validation permits enabled values only as an inverse result.
            let approved = plan.mutations.iter().any(|mutation| {
                mutation.target == needed.target
                    && mutation.kind == MutationKind::Payload
                    && ((!final_state
                        && mutation.expected == needed.expected
                        && mutation.intended == needed.intended)
                        || (mutation.expected == needed.intended
                            && mutation.intended == needed.expected))
            });
            if !approved {
                return Err(BoundaryError::new("Codex memory settings changed"));
            }
        }
        Ok(())
    }
}

impl NativeAdapter for CodexAdapter {
    fn reprobe_live_state(&mut self, plan: &NativeTransactionPlan) -> Result<(), BoundaryError> {
        let executable_matches =
            open_verified_codex_executable(&self.layout.executable, plan.setup.executable_hash)
                .is_ok();
        if self.setup_capability() != CapabilityLevel::Full
            || plan.setup.harness != HarnessId::Codex
            || plan.setup.harness_version != self.layout.version
            || plan.setup.executable_path != wire_path(&self.layout.executable)
            || !executable_matches
        {
            return Err(BoundaryError::new("Codex installation changed"));
        }
        self.verify_native_memory_plan_state(plan, false)
    }
    fn compare_approved_digests(
        &mut self,
        plan: &NativeTransactionPlan,
    ) -> Result<(), BoundaryError> {
        for expected in &plan.setup.expected_native_digests {
            let path = decode_wire_path(&expected.target)?;
            let actual = match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.is_file() && !is_link_or_reparse_point(&metadata) => {
                    Some(digest_file_boundary(&path)?)
                }
                Ok(_) => None,
                Err(error) if error.kind() == ErrorKind::NotFound => None,
                Err(_) => return Err(BoundaryError::new("Codex native state cannot be inspected")),
            };
            if actual != expected.expected_digest {
                return Err(BoundaryError::new("Codex native state changed"));
            }
        }
        Ok(())
    }
    fn verify_live_state_reservation(
        &mut self,
        plan: &NativeTransactionPlan,
    ) -> Result<(), BoundaryError> {
        self.reprobe_live_state(plan)
    }
    fn validate_staged_output(
        &mut self,
        plan: &NativeTransactionPlan,
        run: &RestrictedRun,
    ) -> Result<FrozenOutput, BoundaryError> {
        if run.staged_output_hash != plan.expected_semantic_output_hash
            || run.scanner_result_hash != plan.scanner_result_hash
        {
            return Err(BoundaryError::new("Codex staged output changed"));
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
                "Codex effective state differs from the plan",
            ));
        }
        self.verify_native_memory_plan_state(plan, true)
    }
}

impl<O, V> NativeCliExecutor for CodexCliExecutor<'_, O, V>
where
    O: CodexCommandRunner,
    V: CodexCommandRunner,
{
    fn probe_cli_mutation(
        &mut self,
        mutation: &ApprovedCliMutation,
    ) -> Result<Option<Sha256Digest>, BoundaryError> {
        self.adapter.recheck_executable_boundary()?;
        self.validate_mutation(mutation)?;
        let live = self
            .adapter
            .probe_managed_declaration(&mut self.validation_runner)?;
        Ok(declaration_fingerprint(live.as_ref()))
    }

    fn compare_cli_targets(
        &mut self,
        mutations: &[ApprovedCliMutation],
    ) -> Result<(), BoundaryError> {
        self.adapter.recheck_executable_boundary()?;
        for mutation in mutations {
            self.validate_mutation(mutation)?;
            let live = self
                .adapter
                .probe_managed_declaration(&mut self.validation_runner)?;
            if declaration_fingerprint(live.as_ref())
                != declaration_fingerprint(mutation.expected.as_ref())
            {
                return Err(BoundaryError::new(
                    "Codex managed bridge declaration changed",
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
        let live = self
            .adapter
            .probe_managed_declaration(&mut self.validation_runner)?;
        if declaration_fingerprint(live.as_ref())
            != declaration_fingerprint(mutation.expected.as_ref())
        {
            return Ok(CliMutationOutcome {
                resulting_fingerprint: declaration_fingerprint(live.as_ref()),
                command_error: None,
            });
        }
        let command_error = self.run_operations(&mutation.forward).err();
        let resulting = self
            .adapter
            .probe_managed_declaration(&mut self.validation_runner)?;
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
        let live = self
            .adapter
            .probe_managed_declaration(&mut self.validation_runner)?;
        if declaration_fingerprint(live.as_ref())
            != declaration_fingerprint(mutation.intended.as_ref())
        {
            return Ok(CliRestoreOutcome {
                restored: false,
                resulting_fingerprint: declaration_fingerprint(live.as_ref()),
            });
        }
        self.run_operations(&mutation.rollback)?;
        let resulting = self
            .adapter
            .probe_managed_declaration(&mut self.validation_runner)?;
        if declaration_fingerprint(resulting.as_ref())
            != declaration_fingerprint(mutation.expected.as_ref())
        {
            return Err(BoundaryError::new(
                "Codex managed bridge restore produced an unexpected declaration",
            ));
        }
        Ok(CliRestoreOutcome {
            restored: true,
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
            let live = self
                .adapter
                .probe_managed_declaration(&mut self.validation_runner)?;
            if declaration_fingerprint(live.as_ref())
                != declaration_fingerprint(mutation.intended.as_ref())
            {
                return Err(BoundaryError::new(
                    "Codex committed bridge declaration changed",
                ));
            }
        }
        Ok(())
    }
}

impl<O, V> CodexCliExecutor<'_, O, V>
where
    O: CodexCommandRunner,
    V: CodexCommandRunner,
{
    fn validate_mutation(&self, mutation: &ApprovedCliMutation) -> Result<(), BoundaryError> {
        if mutation.stable_id.is_empty()
            || (mutation.expected.is_none() && mutation.intended.is_none())
        {
            return Err(BoundaryError::new(
                "Codex CLI mutation has no managed declaration",
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
                .declaration_operation(mutation.intended.as_ref())
                .map_err(|_| BoundaryError::new("Codex intended declaration is invalid"))?,
        ];
        let expected_rollback = vec![
            self.adapter
                .declaration_operation(mutation.expected.as_ref())
                .map_err(|_| BoundaryError::new("Codex expected declaration is invalid"))?,
        ];
        if mutation.forward != expected_forward || mutation.rollback != expected_rollback {
            return Err(BoundaryError::new(
                "Codex CLI operations differ from the approved declaration",
            ));
        }
        Ok(())
    }

    fn run_operations(&mut self, operations: &[CliOperation]) -> Result<(), BoundaryError> {
        for operation in operations {
            if operation.executable != wire_path(&self.adapter.layout.executable)
                || operation.timeout_ms != CLI_TIMEOUT_MS
            {
                return Err(BoundaryError::new("Codex CLI operation is not canonical"));
            }
            let arguments = operation
                .arguments
                .iter()
                .map(|argument| {
                    argument
                        .display
                        .clone()
                        .ok_or_else(|| BoundaryError::new("Codex CLI argument is not text"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            self.adapter
                .run_authoritative(&mut self.operation_runner, &arguments)?;
        }
        Ok(())
    }
}

fn rendered_file(path: PathBuf, bytes: &[u8]) -> RenderedFile {
    RenderedFile {
        path: wire_path(&path),
        bytes_sha256: digest(bytes),
        byte_length: bytes.len() as u64,
    }
}

fn render_mcp_add(name: &str, value: &Value) -> Result<Vec<String>, ClientError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("Codex MCP component is invalid"))?;
    if object.contains_key("url") {
        if object
            .keys()
            .any(|key| !["url", "bearer_token_env_var"].contains(&key.as_str()))
            || contains_control(value)
            || contains_redaction(value)
            || value_contains_secret_like(value)
        {
            return Err(invalid("Codex MCP transport is unsupported"));
        }
        let url = object
            .get("url")
            .and_then(Value::as_str)
            .filter(|url| !url.is_empty())
            .ok_or_else(|| invalid("Codex MCP transport is unsupported"))?;
        let mut rendered = vec![
            "mcp".into(),
            "add".into(),
            name.into(),
            "--url".into(),
            url.into(),
        ];
        if let Some(token) = object.get("bearer_token_env_var") {
            let token = token
                .as_str()
                .filter(|token| !token.is_empty())
                .ok_or_else(|| invalid("Codex MCP transport is unsupported"))?;
            rendered.push("--bearer-token-env-var".into());
            rendered.push(token.into());
        }
        return Ok(rendered);
    }
    if object
        .keys()
        .any(|key| !["type", "command", "args", "env"].contains(&key.as_str()))
        || contains_control(value)
        || contains_redaction(value)
        || value_contains_secret_like(value)
    {
        return Err(invalid("Codex MCP transport is unsupported"));
    }
    if object
        .get("type")
        .is_some_and(|kind| kind.as_str() != Some("stdio"))
    {
        return Err(invalid("Codex MCP transport is unsupported"));
    }
    let command = object
        .get("command")
        .and_then(Value::as_str)
        .filter(|command| !command.is_empty())
        .ok_or_else(|| invalid("Codex MCP transport is unsupported"))?;
    let mut rendered = vec!["mcp".into(), "add".into(), name.into()];
    let empty_environment = Map::new();
    let environment = match object.get("env") {
        Some(environment) => environment
            .as_object()
            .ok_or_else(|| invalid("Codex MCP transport is unsupported"))?,
        None => &empty_environment,
    };
    let mut environment = environment.iter().collect::<Vec<_>>();
    environment.sort_by_key(|(key, _)| *key);
    for (key, value) in environment {
        let value = value
            .as_str()
            .ok_or_else(|| invalid("Codex MCP transport is unsupported"))?;
        if key.is_empty()
            || key.chars().any(char::is_control)
            || key.contains('=')
            || value == "<redacted>"
        {
            return Err(invalid(
                "Redacted Codex MCP configuration cannot be applied",
            ));
        }
        rendered.push("--env".into());
        rendered.push(format!("{key}={value}"));
    }
    rendered.push("--".into());
    rendered.push(command.into());
    if let Some(arguments) = object.get("args") {
        let arguments = arguments
            .as_array()
            .ok_or_else(|| invalid("Codex MCP transport is unsupported"))?;
        for argument in arguments {
            let argument = argument
                .as_str()
                .ok_or_else(|| invalid("Codex MCP transport is unsupported"))?;
            rendered.push(argument.into());
        }
    }
    Ok(rendered)
}

fn parse_plugin_list_json(bytes: &[u8]) -> Result<BTreeMap<String, bool>, ClientError> {
    if bytes.len() as u64 > CLI_OUTPUT_LIMIT {
        return Err(invalid("Codex plugin output is invalid"));
    }
    let object = serde_json::from_slice::<Value>(bytes)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .ok_or_else(|| invalid("Codex plugin output is invalid"))?;
    if object.len() != 2 || !object.contains_key("installed") || !object.contains_key("available") {
        return Err(invalid("Codex plugin output is invalid"));
    }
    let installed = object
        .get("installed")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("Codex plugin output is invalid"))?;
    let available = object
        .get("available")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("Codex plugin output is invalid"))?;
    if installed.len() + available.len() > 256 {
        return Err(invalid("Codex plugin output is invalid"));
    }
    let mut ids = BTreeSet::new();
    let mut installed_states = BTreeMap::new();
    for (plugin, expected_installed) in installed
        .iter()
        .map(|plugin| (plugin, true))
        .chain(available.iter().map(|plugin| (plugin, false)))
    {
        let plugin = plugin
            .as_object()
            .ok_or_else(|| invalid("Codex plugin output is invalid"))?;
        let allowed = [
            "pluginId",
            "name",
            "marketplaceName",
            "version",
            "installed",
            "enabled",
            "source",
            "installPolicy",
            "authPolicy",
        ];
        if plugin.len() != allowed.len()
            || plugin.keys().any(|key| !allowed.contains(&key.as_str()))
        {
            return Err(invalid("Codex plugin output is invalid"));
        }
        let id = plugin
            .get("pluginId")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("Codex plugin output is invalid"))?;
        safe_name(id)?;
        let string_field = |name| {
            plugin
                .get(name)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty() && !value.chars().any(char::is_control))
                .ok_or_else(|| invalid("Codex plugin output is invalid"))
        };
        safe_name(string_field("name")?)?;
        safe_name(string_field("marketplaceName")?)?;
        string_field("version")?;
        let install_policy = string_field("installPolicy")?;
        let auth_policy = string_field("authPolicy")?;
        let enabled = plugin
            .get("enabled")
            .and_then(Value::as_bool)
            .ok_or_else(|| invalid("Codex plugin output is invalid"))?;
        if !ids.insert(id)
            || plugin.get("installed").and_then(Value::as_bool) != Some(expected_installed)
            || install_policy != "AVAILABLE"
            || !["ON_USE", "ON_INSTALL"].contains(&auth_policy)
        {
            return Err(invalid("Codex plugin output is invalid"));
        }
        parse_plugin_source(
            plugin
                .get("source")
                .ok_or_else(|| invalid("Codex plugin output is invalid"))?,
        )?;
        if expected_installed {
            installed_states.insert(id.to_owned(), enabled);
        }
    }
    Ok(installed_states)
}

fn parse_mcp_list_json(bytes: &[u8]) -> Result<BTreeSet<String>, ClientError> {
    Ok(parse_mcp_list_states(bytes)?
        .into_iter()
        .filter_map(|(name, enabled)| enabled.then_some(name))
        .collect())
}

fn parse_mcp_list_states(bytes: &[u8]) -> Result<BTreeMap<String, bool>, ClientError> {
    if bytes.len() as u64 > CLI_OUTPUT_LIMIT {
        return Err(invalid("Codex MCP output is invalid"));
    }
    let servers = serde_json::from_slice::<Value>(bytes)
        .ok()
        .and_then(|value| value.as_array().cloned())
        .filter(|servers| servers.len() <= 256)
        .ok_or_else(|| invalid("Codex MCP output is invalid"))?;
    let mut states = BTreeMap::new();
    for server in &servers {
        let server = parse_mcp_server(server, McpOutputKind::List)?;
        if states.insert(server.name, server.enabled).is_some() {
            return Err(invalid("Codex MCP output is invalid"));
        }
    }
    Ok(states)
}

fn parse_mcp_get_json(bytes: &[u8], expected_name: &str) -> Result<Value, ClientError> {
    if bytes.len() as u64 > CLI_OUTPUT_LIMIT {
        return Err(invalid("Codex MCP output is invalid"));
    }
    let parsed = parse_mcp_server(
        &serde_json::from_slice::<Value>(bytes)
            .map_err(|_| invalid("Codex MCP output is invalid"))?,
        McpOutputKind::Get,
    )?;
    if parsed.name != expected_name || !parsed.enabled {
        return Err(invalid("Codex MCP output is invalid"));
    }
    Ok(parsed.declaration)
}

fn parse_managed_mcp_get_json(
    bytes: &[u8],
) -> Result<Option<CanonicalCliDeclaration>, BridgeDeclarationProbeError> {
    if bytes.len() as u64 > CLI_OUTPUT_LIMIT {
        return Err(BridgeDeclarationProbeError::Inspection);
    }
    let value = serde_json::from_slice::<Value>(bytes)
        .map_err(|_| BridgeDeclarationProbeError::Inspection)?;
    let parsed = parse_mcp_server(&value, McpOutputKind::Get)
        .map_err(|_| BridgeDeclarationProbeError::Inspection)?;
    let object = value
        .as_object()
        .ok_or(BridgeDeclarationProbeError::Inspection)?;
    if parsed.name != BRIDGE_SERVER_NAME {
        return Err(BridgeDeclarationProbeError::Inspection);
    }
    if !parsed.enabled
        || !object.get("disabled_reason").is_some_and(Value::is_null)
        || !object.get("enabled_tools").is_some_and(Value::is_null)
        || !object.get("disabled_tools").is_some_and(Value::is_null)
        || !object
            .get("startup_timeout_sec")
            .is_some_and(Value::is_null)
        || !object.get("tool_timeout_sec").is_some_and(Value::is_null)
    {
        return Err(BridgeDeclarationProbeError::Conflict);
    }
    let transport = object
        .get("transport")
        .and_then(Value::as_object)
        .ok_or(BridgeDeclarationProbeError::Inspection)?;
    if transport.get("type").and_then(Value::as_str) != Some("stdio")
        || !transport
            .get("env")
            .is_some_and(|env| env.is_null() || env.as_object().is_some_and(Map::is_empty))
        || !transport
            .get("env_vars")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
        || !transport.get("cwd").is_some_and(Value::is_null)
    {
        return Err(BridgeDeclarationProbeError::Conflict);
    }
    if transport.get("command").and_then(Value::as_str) == Some("<redacted>") {
        return Err(BridgeDeclarationProbeError::Inspection);
    }
    let body = serde_json::json!({
        "args": transport
            .get("args")
            .ok_or(BridgeDeclarationProbeError::Inspection)?,
        "command": transport
            .get("command")
            .ok_or(BridgeDeclarationProbeError::Inspection)?,
        "type": "stdio",
    });
    let canonical_body =
        serde_json::to_string(&body).map_err(|_| BridgeDeclarationProbeError::Inspection)?;
    canonical_cli_declaration(&canonical_body)
        .map(Some)
        .map_err(|_| BridgeDeclarationProbeError::Conflict)
}

#[derive(Clone, Copy)]
enum McpOutputKind {
    List,
    Get,
}

struct ParsedMcpServer {
    name: String,
    enabled: bool,
    declaration: Value,
}

fn parse_mcp_server(
    value: &Value,
    output_kind: McpOutputKind,
) -> Result<ParsedMcpServer, ClientError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("Codex MCP output is invalid"))?;
    let expected = match output_kind {
        McpOutputKind::List => [
            "name",
            "enabled",
            "disabled_reason",
            "transport",
            "startup_timeout_sec",
            "tool_timeout_sec",
            "auth_status",
        ]
        .as_slice(),
        McpOutputKind::Get => [
            "name",
            "enabled",
            "disabled_reason",
            "transport",
            "enabled_tools",
            "disabled_tools",
            "startup_timeout_sec",
            "tool_timeout_sec",
        ]
        .as_slice(),
    };
    if object.len() != expected.len() || object.keys().any(|key| !expected.contains(&key.as_str()))
    {
        return Err(invalid("Codex MCP output is invalid"));
    }
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("Codex MCP output is invalid"))?;
    safe_name(name)?;
    let enabled = object
        .get("enabled")
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid("Codex MCP output is invalid"))?;
    parse_nullable_string(
        object
            .get("disabled_reason")
            .ok_or_else(|| invalid("Codex MCP output is invalid"))?,
        false,
    )?;
    let transport = object
        .get("transport")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("Codex MCP output is invalid"))?;
    parse_mcp_transport(transport)?;
    parse_timeout(
        object
            .get("startup_timeout_sec")
            .ok_or_else(|| invalid("Codex MCP output is invalid"))?,
    )?;
    parse_timeout(
        object
            .get("tool_timeout_sec")
            .ok_or_else(|| invalid("Codex MCP output is invalid"))?,
    )?;
    match output_kind {
        McpOutputKind::List => {
            parse_required_string(
                object
                    .get("auth_status")
                    .ok_or_else(|| invalid("Codex MCP output is invalid"))?,
            )?;
        }
        McpOutputKind::Get => {
            parse_nullable_string_array(
                object
                    .get("enabled_tools")
                    .ok_or_else(|| invalid("Codex MCP output is invalid"))?,
            )?;
            parse_nullable_string_array(
                object
                    .get("disabled_tools")
                    .ok_or_else(|| invalid("Codex MCP output is invalid"))?,
            )?;
        }
    }
    let declaration = normalize_live_mcp(object)?;
    Ok(ParsedMcpServer {
        name: name.to_owned(),
        enabled,
        declaration,
    })
}

fn normalize_live_mcp(object: &Map<String, Value>) -> Result<Value, ClientError> {
    let mut declaration = Map::new();
    for key in [
        "transport",
        "enabled_tools",
        "disabled_tools",
        "startup_timeout_sec",
        "tool_timeout_sec",
    ] {
        if let Some(value) = object.get(key) {
            declaration.insert(key.into(), value.clone());
        }
    }
    if let Some(transport) = declaration
        .get_mut("transport")
        .and_then(Value::as_object_mut)
        && transport.get("type").and_then(Value::as_str) == Some("stdio")
        && transport.get("env").is_some_and(Value::is_null)
    {
        // Codex CLI emits null for an omitted stdio env table. Its effective
        // declaration is the same empty map produced by config normalization.
        transport.insert("env".into(), Value::Object(Map::new()));
    }
    Ok(redact_sensitive(Value::Object(declaration)))
}

fn normalize_config_mcp(table: &toml_edit::Table) -> Result<Value, ClientError> {
    let is_http = table.get("url").is_some();
    let transport_keys: &[&str] = if is_http {
        &[
            "type",
            "url",
            "bearer_token_env_var",
            "http_headers",
            "env_http_headers",
        ]
    } else {
        &["type", "command", "args", "env", "env_vars", "cwd"]
    };
    let common_keys = [
        "enabled",
        "enabled_tools",
        "disabled_tools",
        "startup_timeout_sec",
        "tool_timeout_sec",
    ];
    if table
        .iter()
        .any(|(key, _)| !transport_keys.contains(&key) && !common_keys.contains(&key))
    {
        return Err(invalid("Codex MCP configuration is invalid"));
    }

    let mut transport = Map::new();
    let kind = if is_http { "streamable_http" } else { "stdio" };
    match table.get("type").map(toml_item_json) {
        Some(Value::String(configured)) if configured == kind => {}
        None => {}
        _ => return Err(invalid("Codex MCP configuration is invalid")),
    }
    transport.insert("type".into(), Value::String(kind.into()));
    if is_http {
        insert_required_config_value(table, &mut transport, "url")?;
        insert_optional_config_value(table, &mut transport, "bearer_token_env_var", Value::Null);
        insert_optional_config_value(table, &mut transport, "http_headers", Value::Null);
        insert_optional_config_value(table, &mut transport, "env_http_headers", Value::Null);
    } else {
        insert_required_config_value(table, &mut transport, "command")?;
        insert_optional_config_value(table, &mut transport, "args", Value::Array(vec![]));
        insert_optional_config_value(table, &mut transport, "env", Value::Object(Map::new()));
        insert_optional_config_value(table, &mut transport, "env_vars", Value::Array(vec![]));
        insert_optional_config_value(table, &mut transport, "cwd", Value::Null);
    }
    parse_mcp_transport(&transport)?;

    let mut declaration = Map::new();
    declaration.insert("transport".into(), Value::Object(transport));
    for key in [
        "enabled_tools",
        "disabled_tools",
        "startup_timeout_sec",
        "tool_timeout_sec",
    ] {
        declaration.insert(
            key.into(),
            table.get(key).map(toml_item_json).unwrap_or(Value::Null),
        );
    }
    parse_nullable_string_array(&declaration["enabled_tools"])?;
    parse_nullable_string_array(&declaration["disabled_tools"])?;
    parse_timeout(&declaration["startup_timeout_sec"])?;
    parse_timeout(&declaration["tool_timeout_sec"])?;
    Ok(redact_sensitive(Value::Object(declaration)))
}

fn insert_required_config_value(
    table: &toml_edit::Table,
    target: &mut Map<String, Value>,
    key: &'static str,
) -> Result<(), ClientError> {
    let value = table
        .get(key)
        .map(toml_item_json)
        .ok_or_else(|| invalid("Codex MCP configuration is invalid"))?;
    target.insert(key.into(), value);
    Ok(())
}

fn insert_optional_config_value(
    table: &toml_edit::Table,
    target: &mut Map<String, Value>,
    key: &'static str,
    default: Value,
) {
    target.insert(
        key.into(),
        table.get(key).map(toml_item_json).unwrap_or(default),
    );
}

fn parse_plugin_source(value: &Value) -> Result<(), ClientError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("Codex plugin output is invalid"))?;
    let source = object
        .get("source")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("Codex plugin output is invalid"))?;
    let expected = match source {
        "git" => ["source", "url", "ref"].as_slice(),
        "local" => ["source", "path"].as_slice(),
        _ => return Err(invalid("Codex plugin output is invalid")),
    };
    if object.len() != expected.len() || object.keys().any(|key| !expected.contains(&key.as_str()))
    {
        return Err(invalid("Codex plugin output is invalid"));
    }
    for key in expected.iter().filter(|key| **key != "source") {
        let value = object
            .get(*key)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && !value.chars().any(char::is_control))
            .ok_or_else(|| invalid("Codex plugin output is invalid"))?;
        if value == "<redacted>" {
            return Err(invalid("Codex plugin output is invalid"));
        }
    }
    Ok(())
}

fn parse_mcp_transport(transport: &Map<String, Value>) -> Result<(), ClientError> {
    let kind = transport
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("Codex MCP output is invalid"))?;
    let expected = match kind {
        "streamable_http" => [
            "type",
            "url",
            "bearer_token_env_var",
            "http_headers",
            "env_http_headers",
        ]
        .as_slice(),
        "stdio" => ["type", "command", "args", "env", "env_vars", "cwd"].as_slice(),
        _ => return Err(invalid("Codex MCP output is invalid")),
    };
    if transport.len() != expected.len()
        || transport
            .keys()
            .any(|key| !expected.contains(&key.as_str()))
    {
        return Err(invalid("Codex MCP output is invalid"));
    }
    match kind {
        "streamable_http" => {
            parse_required_string(
                transport
                    .get("url")
                    .ok_or_else(|| invalid("Codex MCP output is invalid"))?,
            )?;
            parse_nullable_string(
                transport
                    .get("bearer_token_env_var")
                    .ok_or_else(|| invalid("Codex MCP output is invalid"))?,
                true,
            )?;
            parse_nullable_headers(
                transport
                    .get("http_headers")
                    .ok_or_else(|| invalid("Codex MCP output is invalid"))?,
            )?;
            parse_nullable_headers(
                transport
                    .get("env_http_headers")
                    .ok_or_else(|| invalid("Codex MCP output is invalid"))?,
            )?;
        }
        "stdio" => {
            parse_required_string(
                transport
                    .get("command")
                    .ok_or_else(|| invalid("Codex MCP output is invalid"))?,
            )?;
            parse_string_array(
                transport
                    .get("args")
                    .ok_or_else(|| invalid("Codex MCP output is invalid"))?,
                false,
            )?;
            let environment = transport
                .get("env")
                .ok_or_else(|| invalid("Codex MCP output is invalid"))?;
            if !environment.is_null() {
                parse_string_map(environment)?;
            }
            parse_string_array(
                transport
                    .get("env_vars")
                    .ok_or_else(|| invalid("Codex MCP output is invalid"))?,
                true,
            )?;
            parse_nullable_string(
                transport
                    .get("cwd")
                    .ok_or_else(|| invalid("Codex MCP output is invalid"))?,
                true,
            )?;
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn parse_required_string(value: &Value) -> Result<&str, ClientError> {
    value
        .as_str()
        .filter(|value| !value.is_empty() && !value.chars().any(char::is_control))
        .ok_or_else(|| invalid("Codex MCP output is invalid"))
}

fn parse_nullable_string(value: &Value, nonempty: bool) -> Result<(), ClientError> {
    if value.is_null() {
        return Ok(());
    }
    let value = value
        .as_str()
        .ok_or_else(|| invalid("Codex MCP output is invalid"))?;
    if value.chars().any(char::is_control) || (nonempty && value.is_empty()) {
        return Err(invalid("Codex MCP output is invalid"));
    }
    Ok(())
}

fn parse_string_array(value: &Value, nonempty: bool) -> Result<(), ClientError> {
    let values = value
        .as_array()
        .ok_or_else(|| invalid("Codex MCP output is invalid"))?;
    for value in values {
        let value = value
            .as_str()
            .ok_or_else(|| invalid("Codex MCP output is invalid"))?;
        if value.chars().any(char::is_control) || (nonempty && value.is_empty()) {
            return Err(invalid("Codex MCP output is invalid"));
        }
    }
    Ok(())
}

fn parse_nullable_string_array(value: &Value) -> Result<(), ClientError> {
    if value.is_null() {
        Ok(())
    } else {
        parse_string_array(value, false)
    }
}

fn parse_string_map(value: &Value) -> Result<(), ClientError> {
    let values = value
        .as_object()
        .ok_or_else(|| invalid("Codex MCP output is invalid"))?;
    for (key, value) in values {
        if key.is_empty() || key.chars().any(char::is_control) {
            return Err(invalid("Codex MCP output is invalid"));
        }
        let value = value
            .as_str()
            .ok_or_else(|| invalid("Codex MCP output is invalid"))?;
        if value.chars().any(char::is_control) {
            return Err(invalid("Codex MCP output is invalid"));
        }
    }
    Ok(())
}

fn parse_nullable_headers(value: &Value) -> Result<(), ClientError> {
    if value.is_null() {
        return Ok(());
    }
    let headers = value
        .as_object()
        .ok_or_else(|| invalid("Codex MCP output is invalid"))?;
    for (key, value) in headers {
        if key.is_empty() || key.chars().any(char::is_control) {
            return Err(invalid("Codex MCP output is invalid"));
        }
        parse_nullable_string(value, false)?;
    }
    Ok(())
}

fn parse_timeout(value: &Value) -> Result<(), ClientError> {
    if value.is_null() {
        return Ok(());
    }
    value
        .as_f64()
        .filter(|value| value.is_finite() && *value >= 0.0)
        .ok_or_else(|| invalid("Codex MCP output is invalid"))?;
    Ok(())
}

fn contains_control(value: &Value) -> bool {
    match value {
        Value::String(value) => value.chars().any(char::is_control),
        Value::Array(values) => values.iter().any(contains_control),
        Value::Object(values) => values.values().any(contains_control),
        _ => false,
    }
}

fn render_managed_markdown(
    existing: &[u8],
    body: &str,
    archived: bool,
) -> Result<Vec<u8>, ClientError> {
    let existing =
        std::str::from_utf8(existing).map_err(|_| invalid("Codex Markdown is not UTF-8"))?;
    if body.contains(MANAGED_START) || body.contains(MANAGED_END) {
        return Err(invalid("Codex managed Markdown contains reserved markers"));
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
            let mut output = existing.to_owned();
            if !output.is_empty() && !output.ends_with(newline) {
                output.push_str(newline);
            }
            output.push_str(MANAGED_START);
            output.push_str(newline);
            output.push_str(&normalized_body);
            output.push_str(newline);
            output.push_str(MANAGED_END);
            output.push_str(newline);
            output
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
                let mut output = existing[..start + MANAGED_START.len()].to_owned();
                output.push_str(newline);
                output.push_str(&normalized_body);
                output.push_str(newline);
                output.push_str(&existing[*end..]);
                output
            }
        }
        _ => return Err(invalid("Codex managed Markdown markers are malformed")),
    };
    (rendered.len() <= 1024 * 1024)
        .then_some(rendered.into_bytes())
        .ok_or_else(|| invalid("Codex managed Markdown is too large"))
}

fn reviewed_files(
    root: &Path,
    predicate: impl Fn(&Path) -> bool,
) -> Result<Vec<PathBuf>, ClientError> {
    let metadata = match fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(invalid("Codex configuration cannot be inspected")),
    };
    if !metadata.is_dir() || project_metadata_is_link(&metadata) {
        return Err(invalid("Codex configuration has unsafe topology"));
    }
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)
            .map_err(|_| invalid("Codex configuration cannot be inspected"))?
        {
            let entry = entry.map_err(|_| invalid("Codex configuration cannot be inspected"))?;
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|_| invalid("Codex configuration cannot be inspected"))?;
            if project_metadata_is_link(&metadata) {
                return Err(invalid("Codex configuration has unsafe topology"));
            }
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() && predicate(&entry.path()) {
                files.push(entry.path());
            }
        }
    }
    files.sort();
    Ok(files)
}

fn project_metadata_is_link(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;

        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn reviewed_skill_files(root: &Path) -> Result<Vec<PathBuf>, ClientError> {
    let metadata = match fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(invalid("Codex skills cannot be inspected")),
    };
    if !metadata.is_dir() || project_metadata_is_link(&metadata) {
        return Err(invalid("Codex skills have unsafe topology"));
    }
    let mut files = Vec::new();
    for entry in fs::read_dir(root).map_err(|_| invalid("Codex skills cannot be inspected"))? {
        let entry = entry.map_err(|_| invalid("Codex skills cannot be inspected"))?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|_| invalid("Codex skills cannot be inspected"))?;
        if project_metadata_is_link(&metadata) {
            return Err(invalid("Codex skills have unsafe topology"));
        }
        if !metadata.is_dir() {
            continue;
        }
        let skill = entry.path().join("SKILL.md");
        match fs::symlink_metadata(&skill) {
            Ok(metadata) if metadata.is_file() && !project_metadata_is_link(&metadata) => {
                files.push(skill);
            }
            Ok(_) => return Err(invalid("Codex skills have unsafe topology")),
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(_) => return Err(invalid("Codex skills cannot be inspected")),
        }
    }
    files.sort();
    Ok(files)
}

fn canonical_existing_path(path: &Path) -> Result<PathBuf, ClientError> {
    fs::canonicalize(path).map_err(|_| invalid("Codex path cannot be safely resolved"))
}

fn canonical_existing_directory(path: &Path) -> Result<PathBuf, ClientError> {
    let canonical = canonical_existing_path(path)?;
    canonical
        .is_dir()
        .then_some(canonical)
        .ok_or_else(|| invalid("Codex directory cannot be safely resolved"))
}

fn canonical_directory_or_absent_path(path: &Path) -> Result<PathBuf, ClientError> {
    if path.is_dir() {
        return canonical_existing_directory(path);
    }
    if path.exists()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(invalid("Codex directory cannot be safely resolved"));
    }

    let mut ancestor = path;
    let mut suffix = Vec::new();
    while !ancestor.exists() {
        let name = ancestor
            .file_name()
            .ok_or_else(|| invalid("Codex directory cannot be safely resolved"))?;
        suffix.push(name.to_owned());
        ancestor = ancestor
            .parent()
            .ok_or_else(|| invalid("Codex directory cannot be safely resolved"))?;
    }
    let mut canonical = canonical_existing_directory(ancestor)?;
    for component in suffix.into_iter().rev() {
        canonical.push(component);
    }
    Ok(canonical)
}

fn canonical_file_or_absent_path(path: &Path) -> Result<PathBuf, ClientError> {
    if path.exists() {
        let canonical = canonical_existing_path(path)?;
        return canonical
            .is_file()
            .then_some(canonical)
            .ok_or_else(|| invalid("Codex requirements path cannot be safely resolved"));
    }
    canonical_directory_or_absent_path(path)
}

fn read_optional_file(path: &Path) -> Result<Option<Vec<u8>>, ClientError> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("Codex configuration path has no parent"))?;
    if !parent.is_dir() {
        let mut current = parent;
        loop {
            match fs::symlink_metadata(current) {
                Ok(metadata) if metadata.is_dir() && !project_metadata_is_link(&metadata) => {
                    return Ok(None);
                }
                Ok(_) => {
                    return Err(invalid("Codex configuration has unsafe topology or state"));
                }
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    current = current.parent().ok_or_else(|| {
                        invalid("Codex configuration has unsafe topology or state")
                    })?;
                }
                Err(_) => {
                    return Err(invalid("Codex configuration has unsafe topology or state"));
                }
            }
        }
    }
    let snapshot = OsNativeFileSystem::new()
        .snapshot(path)
        .map_err(|_| invalid("Codex configuration has unsafe topology or state"))?;
    match snapshot.state() {
        NativeState::Absent { .. } => Ok(None),
        NativeState::RegularFile { bytes, .. } if bytes.len() <= 1024 * 1024 => {
            Ok(Some(bytes.clone()))
        }
        NativeState::RegularFile { .. } => {
            Err(invalid("Codex configuration has unsafe topology or size"))
        }
    }
}
fn read_required_regular(path: &Path, message: &'static str) -> Result<Vec<u8>, ClientError> {
    read_optional_file(path)?.ok_or_else(|| invalid(message))
}
fn nonempty_file(path: &Path) -> Result<bool, ClientError> {
    Ok(read_optional_file(path)?.is_some_and(|bytes| !bytes.is_empty()))
}
fn bytes_to_document(bytes: &[u8]) -> Result<DocumentMut, ClientError> {
    std::str::from_utf8(bytes)
        .map_err(|_| invalid("Codex TOML is not UTF-8"))?
        .parse::<DocumentMut>()
        .map_err(|_| invalid("Codex TOML is invalid"))
}
fn synthetic_toml_item(key: &str, item: &Item) -> Result<String, ClientError> {
    let mut document = DocumentMut::new();
    document[key] = item.clone();
    let rendered = document.to_string();
    (!rendered.is_empty())
        .then_some(rendered)
        .ok_or_else(|| invalid("Codex managed TOML item is invalid"))
}
fn toml_item_kind(item: &Item) -> Result<&'static str, ClientError> {
    match item {
        Item::Value(_) => Ok("value"),
        Item::Table(_) => Ok("table"),
        Item::ArrayOfTables(_) => Ok("array-of-tables"),
        Item::None => Err(invalid("Codex managed TOML item is invalid")),
    }
}
fn managed_toml_item(component: &ComponentRecord, key: &str) -> Result<Item, ClientError> {
    let Some(expected_kind) = metadata_value(component, "tomlItemKind")? else {
        let value = component
            .body_markdown
            .parse::<TomlValue>()
            .map_err(|_| invalid("Codex config component is invalid"))?;
        return Ok(Item::Value(value));
    };
    let document = component
        .body_markdown
        .parse::<DocumentMut>()
        .map_err(|_| invalid("Codex config component is invalid"))?;
    if document.iter().count() != 1 {
        return Err(invalid("Codex config component is invalid"));
    }
    let item = document
        .get(key)
        .cloned()
        .ok_or_else(|| invalid("Codex config component is invalid"))?;
    if toml_item_kind(&item)? != expected_kind {
        return Err(invalid("Codex config component kind changed"));
    }
    Ok(item)
}
fn metadata_value<'a>(
    component: &'a ComponentRecord,
    key: &str,
) -> Result<Option<&'a str>, ClientError> {
    let mut values = component
        .metadata
        .iter()
        .filter_map(|(candidate, value)| (candidate == key).then_some(value.as_str()));
    let first = values.next();
    if values.next().is_some() {
        return Err(invalid("Codex component metadata is ambiguous"));
    }
    Ok(first)
}
fn structural_location(component: &ComponentRecord) -> Result<Option<&str>, ClientError> {
    metadata_value(component, "structuralLocation")
}
fn split_structural_location(location: &str) -> Result<(&str, &str), ClientError> {
    if location.chars().any(char::is_control) {
        return Err(invalid("Codex structural location is unsafe"));
    }
    let (path, fragment) = location
        .split_once('#')
        .ok_or_else(|| invalid("Codex structural location is invalid"))?;
    if path.is_empty() || fragment.is_empty() || fragment.contains('#') {
        return Err(invalid("Codex structural location is invalid"));
    }
    Ok((path, fragment))
}
fn parse_object(bytes: &[u8], message: &'static str) -> Result<Map<String, Value>, ClientError> {
    serde_json::from_slice::<Value>(bytes)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .ok_or_else(|| invalid(message))
}
fn canonical_json(value: &Value) -> Result<String, ClientError> {
    serde_json::to_string(value).map_err(|_| invalid("Codex configuration cannot be serialized"))
}
fn toml_item_json(item: &Item) -> Value {
    match item {
        Item::None => Value::Null,
        Item::Value(value) => toml_value_json(value),
        Item::Table(table) => Value::Object(
            table
                .iter()
                .map(|(key, value)| (key.to_owned(), toml_item_json(value)))
                .collect(),
        ),
        Item::ArrayOfTables(tables) => Value::Array(
            tables
                .iter()
                .map(|table| {
                    Value::Object(
                        table
                            .iter()
                            .map(|(key, value)| (key.to_owned(), toml_item_json(value)))
                            .collect(),
                    )
                })
                .collect(),
        ),
    }
}

fn toml_value_json(value: &TomlValue) -> Value {
    match value {
        TomlValue::String(value) => Value::String(value.value().to_owned()),
        TomlValue::Integer(value) => Value::Number((*value.value()).into()),
        TomlValue::Float(value) => serde_json::Number::from_f64(*value.value())
            .map(Value::Number)
            .unwrap_or(Value::Null),
        TomlValue::Boolean(value) => Value::Bool(*value.value()),
        TomlValue::Datetime(value) => Value::String(value.value().to_string()),
        TomlValue::Array(values) => Value::Array(values.iter().map(toml_value_json).collect()),
        TomlValue::InlineTable(table) => Value::Object(
            table
                .iter()
                .map(|(key, value)| (key.to_owned(), toml_value_json(value)))
                .collect(),
        ),
    }
}
fn ensure_reviewed_text(text: &str) -> Result<(), ClientError> {
    if secret_like_text(text) {
        Err(invalid("Codex reviewed content contains secret-like text"))
    } else {
        Ok(())
    }
}
fn secret_like_text(text: &str) -> bool {
    crate::mcp::contains_secret_like(text) || contains_url_user_info(text)
}
fn contains_url_user_info(text: &str) -> bool {
    text.split_ascii_whitespace().any(|candidate| {
        candidate.split_once("://").is_some_and(|(_, rest)| {
            rest.split(['/', '?', '#'])
                .next()
                .is_some_and(|authority| authority.contains('@'))
        })
    })
}
fn value_contains_secret_like(value: &Value) -> bool {
    match value {
        Value::String(value) => secret_like_text(value),
        Value::Array(values) => values.iter().any(value_contains_secret_like),
        Value::Object(values) => values.values().any(value_contains_secret_like),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}
fn redact_sensitive(value: Value) -> Value {
    match value {
        Value::Object(values) => Value::Object(
            values
                .into_iter()
                .map(|(key, value)| {
                    (
                        key.clone(),
                        if sensitive_map(&key) {
                            redact_all_values(value)
                        } else if sensitive_key(&key) {
                            Value::String("<redacted>".into())
                        } else {
                            redact_sensitive(value)
                        },
                    )
                })
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.into_iter().map(redact_sensitive).collect()),
        Value::String(value) if secret_like_text(&value) => Value::String("<redacted>".into()),
        value => value,
    }
}
fn redact_plugin_sensitive(value: Value) -> Value {
    match value {
        Value::Object(values) => Value::Object(
            values
                .into_iter()
                .map(|(key, value)| {
                    let redacted = if sensitive_map(&key) {
                        redact_all_values(value)
                    } else if sensitive_key(&key) {
                        Value::String("<redacted>".into())
                    } else if plugin_public_key(&key) {
                        redact_sensitive(value)
                    } else {
                        match value {
                            Value::Object(_) | Value::Array(_) => redact_plugin_sensitive(value),
                            Value::Null => Value::Null,
                            _ => Value::String("<redacted>".into()),
                        }
                    };
                    (key, redacted)
                })
                .collect(),
        ),
        Value::Array(values) => {
            Value::Array(values.into_iter().map(redact_plugin_sensitive).collect())
        }
        Value::Null => Value::Null,
        Value::String(value) if secret_like_text(&value) => Value::String("<redacted>".into()),
        _ => Value::String("<redacted>".into()),
    }
}
fn plugin_public_key(key: &str) -> bool {
    let normalized = key
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect::<String>();
    matches!(
        normalized.as_str(),
        "description"
            | "enabled"
            | "endpoint"
            | "name"
            | "path"
            | "pluginid"
            | "ref"
            | "source"
            | "type"
            | "url"
            | "version"
    )
}
fn sensitive_key(key: &str) -> bool {
    let normalized = key
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect::<String>();
    [
        "apikey",
        "accesskey",
        "privatekey",
        "token",
        "secret",
        "auth",
        "password",
        "passphrase",
        "pwd",
        "authorization",
        "bearer",
        "cookie",
        "credential",
        "header",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
        || normalized == "key"
        || matches!(
            normalized.as_str(),
            "clientkey"
                | "encryptionkey"
                | "hmackey"
                | "serviceaccountkey"
                | "signingkey"
                | "sshkey"
        )
}
fn sensitive_map(key: &str) -> bool {
    let normalized = key
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect::<String>();
    matches!(normalized.as_str(), "env" | "environment")
        || normalized.ends_with("headers")
        || normalized.ends_with("headermap")
}
fn redact_all_values(value: Value) -> Value {
    match value {
        Value::Object(values) => Value::Object(
            values
                .into_iter()
                .map(|(key, value)| (key, redact_all_values(value)))
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.into_iter().map(redact_all_values).collect()),
        Value::Null => Value::Null,
        _ => Value::String("<redacted>".into()),
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
fn display_project_location(root: &Path, directory: &Path) -> Result<String, ClientError> {
    let relative = directory
        .strip_prefix(root)
        .map_err(|_| invalid("Codex project path escaped its root"))?;
    if relative.as_os_str().is_empty() {
        Ok("project".into())
    } else {
        Ok(format!("project/{}", display_relative(relative)?))
    }
}
fn display_relative(path: &Path) -> Result<String, ClientError> {
    let value = path
        .to_str()
        .ok_or_else(|| invalid("Codex relative path is not Unicode"))?
        .replace('\\', "/");
    if value.chars().any(char::is_control) {
        return Err(invalid("Codex relative path is unsafe"));
    }
    Ok(value)
}

fn parse_change_target(target: &str) -> Result<(ComponentKind, ScopeRef, String), ClientError> {
    let mut parts = target.splitn(3, '|');
    let kind = match parts.next() {
        Some("codex-plugin") => ComponentKind::Plugin,
        Some("codex-mcp") => ComponentKind::McpServer,
        _ => return Err(invalid("Codex CLI change target is invalid")),
    };
    let scope = match parts.next() {
        Some("global") => ScopeRef::Global,
        _ => return Err(unsupported("Project Codex CLI changes are import-only")),
    };
    let name = parts
        .next()
        .ok_or_else(|| invalid("Codex CLI component name is missing"))?
        .to_owned();
    safe_name(&name)?;
    Ok((kind, scope, name))
}
fn safe_name(name: &str) -> Result<(), ClientError> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.len() > 255
        || name.chars().any(char::is_control)
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"@._-".contains(&byte))
    {
        return Err(invalid("Codex component name is unsafe"));
    }
    Ok(())
}
fn safe_file_name(name: &str) -> Result<(), ClientError> {
    safe_name(name)?;
    if !name.ends_with(".md") {
        return Err(invalid("Codex instruction name is unsafe"));
    }
    Ok(())
}
fn safe_rule_relative(relative: &str) -> Result<PathBuf, ClientError> {
    let path = PathBuf::from(relative);
    if relative.is_empty()
        || relative.contains('\\')
        || relative.chars().any(char::is_control)
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || path.extension().and_then(|extension| extension.to_str()) != Some("rules")
    {
        return Err(invalid("Codex rule location is unsafe"));
    }
    Ok(path)
}
fn stable_record_id(key: &str) -> Result<RecordId, ClientError> {
    let mut bytes: [u8; 32] = Sha256::digest(key.as_bytes()).into();
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    RecordId::from_str(&format!("{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}", bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15])).map_err(|_| invalid("Codex component identifier cannot be derived"))
}
fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest(Sha256::digest(bytes).into())
}

fn canonical_cli_declaration(body: &str) -> Result<CanonicalCliDeclaration, ClientError> {
    let value: Value = serde_json::from_str(body)
        .map_err(|_| invalid("Codex managed bridge declaration is invalid"))?;
    if serde_json::to_string(&value).ok().as_deref() != Some(body)
        || !is_canonical_bridge_body(HarnessId::Codex, body, false)
    {
        return Err(invalid("Codex managed bridge declaration is invalid"));
    }
    Ok(CanonicalCliDeclaration {
        harness: HarnessId::Codex,
        server_name: BRIDGE_SERVER_NAME.to_owned(),
        canonical_body: body.to_owned(),
        fingerprint: digest(body.as_bytes()),
    })
}

fn validate_cli_declaration(declaration: &CanonicalCliDeclaration) -> Result<(), BoundaryError> {
    if declaration.harness != HarnessId::Codex
        || declaration.server_name != BRIDGE_SERVER_NAME
        || declaration.fingerprint != digest(declaration.canonical_body.as_bytes())
        || canonical_cli_declaration(&declaration.canonical_body).is_err()
    {
        return Err(BoundaryError::new(
            "Codex CLI declaration is not the managed bridge",
        ));
    }
    Ok(())
}

fn declaration_fingerprint(declaration: Option<&CanonicalCliDeclaration>) -> Option<Sha256Digest> {
    declaration.map(|declaration| declaration.fingerprint)
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CodexFileIdentity {
    device: u64,
    inode: u64,
    links: u64,
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CodexFileIdentity {
    volume: u32,
    index: u64,
    links: u32,
}

#[cfg(windows)]
#[derive(Debug)]
struct CodexPathComponent {
    path: PathBuf,
    file: fs::File,
    identity: CodexFileIdentity,
}

#[cfg(unix)]
fn codex_file_identity(file: &fs::File) -> std::io::Result<CodexFileIdentity> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file.metadata()?;
    Ok(CodexFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        links: metadata.nlink(),
    })
}

#[cfg(windows)]
fn codex_file_identity(file: &fs::File) -> std::io::Result<CodexFileIdentity> {
    let information = codex_file_information(file)?;
    Ok(CodexFileIdentity {
        volume: information.dwVolumeSerialNumber,
        index: (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow),
        links: information.nNumberOfLinks,
    })
}

#[cfg(windows)]
fn codex_file_information(
    file: &fs::File,
) -> std::io::Result<windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION> {
    use std::{mem::MaybeUninit, os::windows::io::AsRawHandle as _};

    use windows_sys::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle},
    };

    let mut information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    if unsafe {
        GetFileInformationByHandle(file.as_raw_handle() as HANDLE, information.as_mut_ptr())
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { information.assume_init() })
}

#[cfg(windows)]
fn open_codex_path_component(path: &Path) -> std::io::Result<CodexPathComponent> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
    };

    let file = fs::OpenOptions::new()
        .read(true)
        // Holding every directory handle without write/delete sharing prevents
        // an already-open or new actor from retargeting an intermediate path
        // component while CreateProcess resolves the executable pathname.
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let information = codex_file_information(&file)?;
    if information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(std::io::Error::other(
            "Codex executable path component is unsafe",
        ));
    }
    let identity = codex_file_identity(&file)?;
    Ok(CodexPathComponent {
        path: path.to_path_buf(),
        file,
        identity,
    })
}

#[cfg(windows)]
fn open_codex_path_topology(path: &Path) -> std::io::Result<Vec<CodexPathComponent>> {
    let mut ancestors = path
        .ancestors()
        .skip(1)
        .filter(|ancestor| !ancestor.as_os_str().is_empty())
        .collect::<Vec<_>>();
    ancestors.reverse();
    ancestors
        .into_iter()
        .map(open_codex_path_component)
        .collect()
}

#[cfg(windows)]
fn revalidate_codex_path_topology(topology: &[CodexPathComponent]) -> Result<(), BoundaryError> {
    for component in topology {
        let held_identity = codex_file_identity(&component.file)
            .map_err(|_| BoundaryError::new("Codex executable path topology is unavailable"))?;
        let reopened = open_codex_path_component(&component.path)
            .map_err(|_| BoundaryError::new("Codex executable path topology is unsafe"))?;
        if held_identity != component.identity || reopened.identity != component.identity {
            return Err(BoundaryError::new("Codex executable path topology changed"));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn open_codex_executable(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(windows)]
fn open_codex_executable(path: &Path) -> std::io::Result<fs::File> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ,
    };

    let file = fs::OpenOptions::new()
        .read(true)
        // CreateProcess may read the image, while write/delete/rename remain
        // denied until the verified handle is dropped after process creation.
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let attributes = codex_file_information(&file)?.dwFileAttributes;
    if attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0 {
        return Err(std::io::Error::other("Codex executable is unsafe"));
    }
    Ok(file)
}

fn hash_open_file(file: &fs::File) -> std::io::Result<Sha256Digest> {
    let mut file = file.try_clone()?;
    file.seek(SeekFrom::Start(0))?;
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

fn read_open_file(file: &fs::File) -> std::io::Result<Vec<u8>> {
    let mut file = file.try_clone()?;
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn open_verified_codex_executable(
    path: &Path,
    expected_hash: Sha256Digest,
) -> Result<VerifiedCodexExecutable, BoundaryError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| BoundaryError::new("Codex executable is missing"))?;
    if !metadata.is_file() || is_link_or_reparse_point(&metadata) {
        return Err(BoundaryError::new("Codex executable is unsafe"));
    }
    #[cfg(windows)]
    let topology = open_codex_path_topology(path)
        .map_err(|_| BoundaryError::new("Codex executable path topology is unsafe"))?;
    let file = open_codex_executable(path)
        .map_err(|_| BoundaryError::new("Codex executable cannot be safely opened"))?;
    let identity = codex_file_identity(&file)
        .map_err(|_| BoundaryError::new("Codex executable identity is unavailable"))?;
    let hash =
        hash_open_file(&file).map_err(|_| BoundaryError::new("Codex executable cannot be read"))?;
    let executable = VerifiedCodexExecutable {
        path: path.to_path_buf(),
        file,
        identity,
        expected_hash,
        #[cfg(windows)]
        topology,
    };
    if hash != expected_hash {
        return Err(BoundaryError::new("Codex executable changed"));
    }
    executable.revalidate_before_launch()?;
    Ok(executable)
}

fn snapshot_executable(path: &Path) -> Result<CodexExecutableSnapshot, ClientError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| not_found("Codex executable is missing"))?;
    if !metadata.is_file() || is_link_or_reparse_point(&metadata) {
        return Err(invalid("Codex executable is unsafe"));
    }
    let file =
        open_codex_executable(path).map_err(|_| invalid("Codex executable cannot be opened"))?;
    let bytes = read_open_file(&file).map_err(|_| not_found("Codex executable is missing"))?;
    let digest = digest(&bytes);
    let verified = open_verified_codex_executable(path, digest)
        .map_err(|_| invalid("Codex executable changed"))?;
    drop(verified);
    Ok(CodexExecutableSnapshot {
        kind: classify_executable_bytes(path, &bytes),
        digest,
    })
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

fn digest_file_boundary(path: &Path) -> Result<Sha256Digest, BoundaryError> {
    hash_file(path).map_err(|_| BoundaryError::new("Codex file cannot be read"))
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

fn discover_executable_version(
    executable: &Path,
    working_directory: &Path,
    expected_standalone_version: Option<&str>,
) -> Result<(CodexExecutableSnapshot, String), ClientError> {
    discover_executable_version_after_snapshot(
        executable,
        working_directory,
        expected_standalone_version,
        || {},
    )
}

fn discover_executable_version_after_snapshot(
    executable: &Path,
    working_directory: &Path,
    expected_standalone_version: Option<&str>,
    after_snapshot: impl FnOnce(),
) -> Result<(CodexExecutableSnapshot, String), ClientError> {
    let snapshot = snapshot_executable(executable)?;
    let version = if snapshot.kind == CodexExecutableKind::Native {
        after_snapshot();
        let output = run_bounded_command(
            executable,
            &["--version"],
            snapshot.digest,
            working_directory,
        )?;
        parse_version(std::str::from_utf8(&output).unwrap_or_default())
            .ok_or_else(|| unsupported("Codex returned an invalid version"))?
    } else {
        // Wrapper and unknown files remain import-only. Never execute an
        // unclassified candidate merely to obtain its version.
        "0.0.0".to_owned()
    };
    if expected_standalone_version.is_some_and(|expected| expected != version) {
        return Err(unsupported(
            "Codex standalone release version does not match",
        ));
    }
    if snapshot_executable(executable)? != snapshot {
        return Err(client_error(
            ErrorCode::Conflict,
            "Codex executable changed",
            false,
        ));
    }
    Ok((snapshot, version))
}

fn run_bounded_command(
    executable: &Path,
    arguments: &[&str],
    expected_hash: Sha256Digest,
    working_directory: &Path,
) -> Result<Vec<u8>, ClientError> {
    let executable = open_verified_codex_executable(executable, expected_hash)
        .map_err(|_| client_error(ErrorCode::Conflict, "Codex executable changed", false))?;
    run_bounded_verified_command(&executable, arguments, working_directory)
}

fn run_bounded_verified_command(
    executable: &VerifiedCodexExecutable,
    arguments: &[&str],
    working_directory: &Path,
) -> Result<Vec<u8>, ClientError> {
    run_bounded_verified_command_with_hook(executable, arguments, working_directory, || {})
}

fn run_bounded_verified_command_with_hook(
    executable: &VerifiedCodexExecutable,
    arguments: &[&str],
    working_directory: &Path,
    before_spawn: impl FnOnce(),
) -> Result<Vec<u8>, ClientError> {
    executable
        .revalidate_before_launch()
        .map_err(|_| client_error(ErrorCode::Conflict, "Codex executable changed", false))?;
    before_spawn();
    #[cfg(windows)]
    executable
        .revalidate_before_launch()
        .map_err(|_| client_error(ErrorCode::Conflict, "Codex executable changed", false))?;
    let launch = executable.prepare_launch()?;
    run_prepared_codex_command(launch, &executable.path, arguments, working_directory)
}

fn run_prepared_codex_command(
    launch: PreparedCodexLaunch,
    original_path: &Path,
    arguments: &[&str],
    working_directory: &Path,
) -> Result<Vec<u8>, ClientError> {
    #[cfg(windows)]
    if launch.program.as_path() != original_path {
        return Err(client_error(
            ErrorCode::Conflict,
            "Codex prepared executable identity changed",
            false,
        ));
    }
    let mut command = Command::new(&launch.program);
    command
        .args(arguments)
        .current_dir(working_directory)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use std::os::unix::process::CommandExt as _;

        command.arg0(original_path);
        // SAFETY: the hook performs no work in the child. Its presence forces
        // Rust's fork/exec path so the sealed, non-CLOEXEC memfd survives until
        // execve resolves `/proc/self/fd/N`.
        unsafe {
            command.pre_exec(|| Ok(()));
        }
    }
    #[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
    {
        use std::os::unix::process::CommandExt as _;

        command.arg0(original_path);
    }
    let mut child = command
        .spawn()
        .map_err(|_| unsupported("Codex command failed"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| invalid("Codex command output is unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| invalid("Codex command output is unavailable"))?;
    let stdout_thread = thread::spawn(move || read_capped(stdout));
    let stderr_thread = thread::spawn(move || read_capped(stderr));
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|_| unsupported("Codex command failed"))?
        {
            break status;
        }
        if started.elapsed() >= Duration::from_millis(u64::from(CLI_TIMEOUT_MS)) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(client_error(
                ErrorCode::Timeout,
                "Codex command timed out",
                true,
            ));
        }
        thread::sleep(Duration::from_millis(10));
    };
    let stdout = stdout_thread
        .join()
        .map_err(|_| invalid("Codex command output is invalid"))?
        .map_err(|_| invalid("Codex command output is invalid"))?;
    let stderr = stderr_thread
        .join()
        .map_err(|_| invalid("Codex command output is invalid"))?
        .map_err(|_| invalid("Codex command output is invalid"))?;
    if !status.success() || !stderr.is_empty() {
        return Err(unsupported("Codex command failed"));
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
fn valid_version(version: &str) -> bool {
    let mut parts = version.split('.');
    (0..3).all(|_| {
        parts
            .next()
            .is_some_and(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    }) && parts.next().is_none()
}
fn parse_version(output: &str) -> Option<String> {
    let mut parts = output.split_whitespace();
    let prefix = parts.next()?;
    let version = parts.next()?;
    if !["codex", "codex-cli"].contains(&prefix)
        || parts.next().is_some()
        || !valid_version(version)
    {
        return None;
    }
    Some(version.to_owned())
}
fn classify_executable_bytes(path: &Path, bytes: &[u8]) -> CodexExecutableKind {
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if ["cmd", "bat", "ps1"].contains(&extension.as_str()) {
        return CodexExecutableKind::Wrapper;
    }
    classify_executable_magic(bytes)
}
fn classify_executable_magic(bytes: &[u8]) -> CodexExecutableKind {
    if bytes.starts_with(b"#!") {
        CodexExecutableKind::Wrapper
    } else if bytes.starts_with(b"\x7fELF")
        || bytes.starts_with(b"MZ")
        || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xce])
        || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
        || bytes.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
        || bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
    {
        CodexExecutableKind::Native
    } else {
        CodexExecutableKind::Unknown
    }
}
fn find_executable(home: &Path) -> Option<PathBuf> {
    let mut candidates = env::var_os("PATH")
        .map(|path| {
            env::split_paths(&path)
                .map(|directory| directory.join(if cfg!(windows) { "codex.exe" } else { "codex" }))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    candidates.extend(platform_candidates(
        home,
        env::var_os("LOCALAPPDATA").as_deref().map(Path::new),
        cfg!(windows),
    ));
    candidates.into_iter().find(|candidate| candidate.is_file())
}

#[cfg(windows)]
fn resolve_windows_standalone_candidate(
    candidate: &Path,
    home: &Path,
    local_app_data: Option<&Path>,
) -> Result<(PathBuf, Option<String>), ClientError> {
    let unchanged = || Ok((candidate.to_path_buf(), None));
    let Some(candidate_path) = lexical_windows_disk_path(candidate) else {
        return unchanged();
    };
    let Some(home) = lexical_windows_disk_path(home) else {
        return unchanged();
    };
    let standalone = home.join(".codex/packages/standalone");
    let current = standalone.join("current");
    let current_bin = current.join("bin");
    let programs_bin = local_app_data
        .and_then(lexical_windows_disk_path)
        .map(|local| local.join("Programs/OpenAI/Codex/bin"));
    let is_programs_alias = programs_bin
        .as_ref()
        .is_some_and(|bin| candidate_path == bin.join("codex.exe"));
    if !is_programs_alias && candidate_path != current_bin.join("codex.exe") {
        return unchanged();
    }
    let alias = if is_programs_alias {
        programs_bin.as_ref().expect("recognized Programs alias")
    } else {
        &current
    };
    let metadata = fs::symlink_metadata(alias)
        .map_err(|_| invalid("Codex standalone alias is unavailable"))?;
    if !is_link_or_reparse_point(&metadata) {
        return unchanged();
    }

    // Resolve only the installer's two documented aliases. Never canonicalize
    // an arbitrary PATH entry or the expected releases root: that would hide
    // unapproved reparse points from the physical executable topology checks.
    let _alias_topology = open_codex_path_topology(alias)
        .map_err(|_| invalid("Codex standalone alias topology is unsafe"))?;
    let releases = standalone.join("releases");
    // The synthetic final component makes the topology include releases itself.
    let _release_topology = open_codex_path_topology(&releases.join("codex.exe"))
        .map_err(|_| invalid("Codex standalone release topology is unsafe"))?;
    let read_target = |path: &Path| {
        fs::read_link(path)
            .ok()
            .and_then(|target| lexical_windows_disk_path(&target))
            .ok_or_else(|| invalid("Codex standalone alias target is unsafe"))
    };
    if is_programs_alias && read_target(alias)? != current_bin {
        return Err(invalid("Codex standalone alias target is unexpected"));
    }
    let release = read_target(&current)?;
    let tail = release
        .strip_prefix(&releases)
        .map_err(|_| invalid("Codex standalone release is outside its root"))?;
    let mut components = tail.components();
    let Some(std::path::Component::Normal(directory)) = components.next() else {
        return Err(invalid("Codex standalone release path is invalid"));
    };
    if components.next().is_some() {
        return Err(invalid("Codex standalone release path is invalid"));
    }
    let target = match std::env::consts::ARCH {
        "x86_64" => "-x86_64-pc-windows-msvc",
        "aarch64" => "-aarch64-pc-windows-msvc",
        _ => return Err(unsupported("Codex standalone architecture is unsupported")),
    };
    let version = directory
        .to_str()
        .and_then(|directory| directory.strip_suffix(target))
        .filter(|version| valid_version(version))
        .ok_or_else(|| invalid("Codex standalone release directory is invalid"))?;
    let executable = release.join("bin/codex.exe");
    let _physical_topology = open_codex_path_topology(&executable)
        .map_err(|_| invalid("Codex standalone executable topology is unsafe"))?;
    // Persist this physical path. Retargeting either alias after this point
    // cannot change which release is snapshotted, probed, or later launched.
    Ok((executable, Some(version.to_owned())))
}

#[cfg(windows)]
fn lexical_windows_disk_path(path: &Path) -> Option<PathBuf> {
    use std::path::{Component, Prefix};

    let mut components = path.components();
    let Component::Prefix(prefix) = components.next()? else {
        return None;
    };
    let drive = match prefix.kind() {
        Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => drive,
        _ => return None,
    };
    if components.next()? != Component::RootDir {
        return None;
    }
    let mut normalized = PathBuf::from(format!("{}:\\", char::from(drive.to_ascii_uppercase())));
    for component in components {
        let Component::Normal(name) = component else {
            return None;
        };
        normalized.push(name);
    }
    Some(normalized)
}
fn platform_candidates(home: &Path, local_app_data: Option<&Path>, windows: bool) -> Vec<PathBuf> {
    if windows {
        let Some(local_app_data) = local_app_data else {
            return Vec::new();
        };
        vec![
            local_app_data.join("Programs/OpenAI/Codex/bin/codex.exe"),
            local_app_data.join("Programs/ChatGPT/resources/codex.exe"),
        ]
    } else {
        vec![
            PathBuf::from("/Applications/ChatGPT.app/Contents/Resources/codex"),
            home.join("Applications/ChatGPT.app/Contents/Resources/codex"),
            home.join(".local/bin/codex"),
        ]
    }
}
fn installation_method(path: &Path) -> InstallationMethod {
    let normalized = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let parts = normalized
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    let ends_with = |suffix: &[&str]| parts.ends_with(suffix);
    let contains_sequence = |sequence: &[&str]| {
        parts
            .windows(sequence.len())
            .any(|candidate| candidate == sequence)
    };

    if ends_with(&["chatgpt.app", "contents", "resources", "codex"])
        || ends_with(&["programs", "chatgpt", "resources", "codex.exe"])
    {
        InstallationMethod::Bundled
    } else if parts.contains(&"node_modules")
        || contains_sequence(&["homebrew", "cellar"])
        || contains_sequence(&["opt", "homebrew"])
        || contains_sequence(&["microsoft", "winget", "packages"])
    {
        InstallationMethod::PackageManager
    } else if ends_with(&[".local", "bin", "codex"])
        || ends_with(&["programs", "openai", "codex", "bin", "codex.exe"])
    {
        InstallationMethod::Manual
    } else {
        InstallationMethod::Unknown
    }
}
fn home_dir() -> Option<PathBuf> {
    env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from)
}
fn requirements_paths() -> Vec<PathBuf> {
    if cfg!(windows) {
        env::var_os("ProgramData")
            .map(PathBuf::from)
            .into_iter()
            .map(|root| root.join("OpenAI/Codex/requirements.toml"))
            .collect()
    } else {
        vec![PathBuf::from("/etc/codex/requirements.toml")]
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
        return Err(BoundaryError::new("Codex native path is invalid"));
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
        return Err(BoundaryError::new("Codex native path is invalid"));
    }
    Ok(PathBuf::from(OsString::from_vec(value.bytes.clone())))
}
fn invalid(message: &'static str) -> ClientError {
    client_error(ErrorCode::InvalidRequest, message, false)
}
fn not_found(message: &'static str) -> ClientError {
    client_error(ErrorCode::NotFound, message, false)
}
fn unsupported(message: &'static str) -> ClientError {
    client_error(ErrorCode::HarnessUnsupported, message, false)
}
fn client_error(code: ErrorCode, message: &'static str, retryable: bool) -> ClientError {
    ClientError {
        code,
        message: message.into(),
        field_path: None,
        retryable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static NEXT_EFFECTIVE_FIXTURE: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(0);

    #[cfg(unix)]
    #[test]
    fn verified_handle_execution_does_not_follow_a_late_path_replacement() {
        let root = fs::canonicalize(env::temp_dir()).unwrap().join(format!(
            "context-relay-codex-descriptor-{}-{}",
            std::process::id(),
            NEXT_EFFECTIVE_FIXTURE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let true_source = ["/usr/bin/true", "/bin/true"]
            .into_iter()
            .map(Path::new)
            .find(|path| path.is_file())
            .unwrap();
        let false_source = ["/usr/bin/false", "/bin/false"]
            .into_iter()
            .map(Path::new)
            .find(|path| path.is_file())
            .unwrap();
        let executable = root.join("codex");
        let replacement = root.join("replacement");
        let original = root.join("original");
        fs::copy(true_source, &executable).unwrap();
        fs::copy(false_source, &replacement).unwrap();
        let expected_hash = hash_file(&executable).unwrap();
        let verified = open_verified_codex_executable(&executable, expected_hash).unwrap();

        let result = run_bounded_verified_command_with_hook(&verified, &[], &root, || {
            fs::rename(&executable, &original).unwrap();
            fs::rename(&replacement, &executable).unwrap();
        });

        let _ = fs::remove_dir_all(&root);
        result.unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn verified_launch_rejects_in_place_mutation_after_final_check() {
        let root = fs::canonicalize(env::temp_dir()).unwrap().join(format!(
            "context-relay-codex-in-place-{}-{}",
            std::process::id(),
            NEXT_EFFECTIVE_FIXTURE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let true_source = ["/usr/bin/true", "/bin/true"]
            .into_iter()
            .map(Path::new)
            .find(|path| path.is_file())
            .unwrap();
        let false_source = ["/usr/bin/false", "/bin/false"]
            .into_iter()
            .map(Path::new)
            .find(|path| path.is_file())
            .unwrap();
        let executable = root.join("codex");
        fs::copy(true_source, &executable).unwrap();
        let expected_hash = hash_file(&executable).unwrap();
        let verified = open_verified_codex_executable(&executable, expected_hash).unwrap();

        let result = run_bounded_verified_command_with_hook(&verified, &[], &root, || {
            fs::copy(false_source, &executable).unwrap();
        });

        let _ = fs::remove_dir_all(&root);
        assert!(result.is_err());
    }

    #[cfg(windows)]
    #[test]
    fn verified_executable_rejects_reparse_point_in_parent_topology() {
        use std::os::windows::fs::symlink_dir;

        let root = env::temp_dir().join(format!(
            "context-relay-codex-reparse-{}-{}",
            std::process::id(),
            NEXT_EFFECTIVE_FIXTURE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let real_parent = root.join("real/bin");
        fs::create_dir_all(&real_parent).unwrap();
        let executable = real_parent.join("codex.exe");
        fs::write(&executable, b"fixture executable").unwrap();
        let linked_parent = root.join("linked");
        if symlink_dir(root.join("real"), &linked_parent).is_err() {
            let _ = fs::remove_dir_all(&root);
            return;
        }
        let linked_executable = linked_parent.join("bin/codex.exe");
        let expected_hash = hash_file(&executable).unwrap();

        assert!(
            open_verified_codex_executable(&linked_executable, expected_hash).is_err(),
            "an intermediate reparse point reached the executable launch boundary"
        );
        let _ = fs::remove_dir_all(&root);
    }

    struct EffectiveValidationFixture {
        root: PathBuf,
        adapter: CodexAdapter,
        global_config: PathBuf,
        root_config: PathBuf,
        nested_config: PathBuf,
        sentinel: PathBuf,
    }

    impl Drop for EffectiveValidationFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn effective_validation_fixture() -> EffectiveValidationFixture {
        let root = fs::canonicalize(env::temp_dir()).unwrap().join(format!(
            "context-relay-codex-effective-{}-{}",
            std::process::id(),
            NEXT_EFFECTIVE_FIXTURE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let codex_home = root.join("codex home");
        let user_skills_dir = root.join("home/.agents/skills");
        let project_root = root.join("project with spaces");
        let working_directory = project_root.join("service");
        for directory in [
            &codex_home,
            &user_skills_dir,
            &project_root,
            &working_directory,
        ] {
            fs::create_dir_all(directory).unwrap();
        }
        let executable = root.join("codex");
        fs::write(&executable, b"\x7fELFtest executable").unwrap();
        let sentinel = root.join("configured-stdio-ran");
        let quoted_project = serde_json::to_string(&project_root.to_string_lossy()).unwrap();
        let quoted_sentinel = serde_json::to_string(&sentinel.to_string_lossy()).unwrap();
        let global_config = codex_home.join("config.toml");
        fs::write(
            &global_config,
            format!(
                "[mcp_servers.docs]\ncommand = \"/usr/bin/touch\"\nargs = [{quoted_sentinel}]\n\n[mcp_servers.global_disabled]\nenabled = false\ncommand = \"/usr/bin/touch\"\nargs = [{quoted_sentinel}]\n\n[projects.{quoted_project}]\ntrust_level = \"trusted\"\n"
            ),
        )
        .unwrap();
        let root_config = project_root.join(".codex/config.toml");
        fs::create_dir_all(root_config.parent().unwrap()).unwrap();
        fs::write(
            &root_config,
            format!(
                "[mcp_servers.root]\ncommand = \"/usr/bin/touch\"\nargs = [{quoted_sentinel}]\n\n[mcp_servers.root_disabled]\nenabled = false\ncommand = \"/usr/bin/touch\"\nargs = [{quoted_sentinel}]\n"
            ),
        )
        .unwrap();
        let nested_config = working_directory.join(".codex/config.toml");
        fs::create_dir_all(nested_config.parent().unwrap()).unwrap();
        fs::write(
            &nested_config,
            format!(
                "[mcp_servers.nested]\ncommand = \"/usr/bin/touch\"\nargs = [{quoted_sentinel}]\n\n[mcp_servers.nested_disabled]\nenabled = false\ncommand = \"/usr/bin/touch\"\nargs = [{quoted_sentinel}]\n"
            ),
        )
        .unwrap();
        let project_id = ProjectId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073981").unwrap();
        let device_id = DeviceId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073982").unwrap();
        let adapter = CodexAdapter::from_layout(
            CodexLayout {
                executable,
                executable_kind: CodexExecutableKind::Unknown,
                version: "0.144.1".into(),
                installation_method: InstallationMethod::Manual,
                codex_home,
                user_skills_dir,
                project_root,
                working_directory,
                requirements_paths: vec![],
            },
            project_id,
            device_id,
            HybridLogicalClock::new(1_900_000_000_000, 0, device_id),
        )
        .unwrap();
        EffectiveValidationFixture {
            root,
            adapter,
            global_config,
            root_config,
            nested_config,
            sentinel,
        }
    }

    fn effective_validation_receipt() -> ApplyReceipt {
        ApplyReceipt {
            plan_id: context_relay_protocol::PlanId::from_str(
                "018f22e2-79b0-7cc8-98c4-dc0c0c073984",
            )
            .unwrap(),
            applied_hlc: HybridLogicalClock::new(
                1_900_000_000_001,
                0,
                DeviceId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073982").unwrap(),
            ),
            resulting_digests: vec![],
        }
    }

    fn effective_validation_output(
        fixture: &EffectiveValidationFixture,
        command: &CodexCommand,
        enabled_names: &[&str],
    ) -> Result<Vec<u8>, ClientError> {
        if matches!(command, CodexCommand::PluginList) {
            return Ok(br#"{"installed":[],"available":[]}"#.to_vec());
        }
        let declarations = fixture.adapter.imported_mcp_declarations()?;
        let live_server = |name: &str, list: bool| {
            let declaration = declarations.get(name);
            let transport = declaration
                .and_then(|value| value.get("transport"))
                .cloned()
                .unwrap_or_else(|| {
                    serde_json::json!({
                        "type": "stdio",
                        "command": "unexpected",
                        "args": [],
                        "env": {},
                        "env_vars": [],
                        "cwd": null
                    })
                });
            let mut server = serde_json::json!({
                "name": name,
                "enabled": true,
                "disabled_reason": null,
                "transport": transport,
                "startup_timeout_sec": declaration.and_then(|value| value.get("startup_timeout_sec")).cloned().unwrap_or(Value::Null),
                "tool_timeout_sec": declaration.and_then(|value| value.get("tool_timeout_sec")).cloned().unwrap_or(Value::Null)
            });
            if list {
                server["auth_status"] = Value::String("unsupported".into());
            } else {
                server["enabled_tools"] = declaration
                    .and_then(|value| value.get("enabled_tools"))
                    .cloned()
                    .unwrap_or(Value::Null);
                server["disabled_tools"] = declaration
                    .and_then(|value| value.get("disabled_tools"))
                    .cloned()
                    .unwrap_or(Value::Null);
            }
            server
        };
        Ok(match command {
            CodexCommand::PluginList => unreachable!(),
            CodexCommand::McpList => serde_json::to_vec(
                &enabled_names
                    .iter()
                    .map(|name| live_server(name, true))
                    .chain(std::iter::once(serde_json::json!({
                        "name": "listed-disabled",
                        "enabled": false,
                        "disabled_reason": "disabled by config",
                        "transport": {
                            "type": "stdio",
                            "command": "never-run",
                            "args": [],
                            "env": {},
                            "env_vars": [],
                            "cwd": null
                        },
                        "startup_timeout_sec": null,
                        "tool_timeout_sec": null,
                        "auth_status": "unsupported"
                    })))
                    .collect::<Vec<_>>(),
            )
            .unwrap(),
            CodexCommand::McpGet(name) => serde_json::to_vec(&live_server(name, false)).unwrap(),
        })
    }

    fn validate_with_frozen_outputs(
        fixture: &EffectiveValidationFixture,
        enabled_names: &[&str],
    ) -> (Result<ValidationReport, ClientError>, Vec<Vec<String>>) {
        let mut commands = Vec::new();
        let result =
            fixture
                .adapter
                .validate_effective_with(&effective_validation_receipt(), |command| {
                    commands.push(command.argv());
                    effective_validation_output(fixture, command, enabled_names)
                });
        (result, commands)
    }

    #[test]
    fn effective_validation_selects_trusted_layers_in_exact_cli_order_without_starting_stdio() {
        let fixture = effective_validation_fixture();
        let (trusted, commands) =
            validate_with_frozen_outputs(&fixture, &["docs", "nested", "root"]);
        assert!(trusted.unwrap().valid);
        assert_eq!(
            commands,
            vec![
                vec!["plugin", "list", "--json"],
                vec!["mcp", "list", "--json"],
                vec!["mcp", "get", "docs", "--json"],
                vec!["mcp", "get", "nested", "--json"],
                vec!["mcp", "get", "root", "--json"],
            ]
        );
        assert!(!fixture.sentinel.exists());

        let trusted_config = fs::read_to_string(&fixture.global_config).unwrap();
        fs::write(
            &fixture.global_config,
            trusted_config.replace("trust_level = \"trusted\"", "trust_level = \"untrusted\""),
        )
        .unwrap();
        let (untrusted, commands) = validate_with_frozen_outputs(&fixture, &["docs"]);
        assert_eq!(untrusted.unwrap_err().code, ErrorCode::HarnessUnsupported);
        assert!(commands.is_empty());

        fs::write(&fixture.global_config, trusted_config).unwrap();
        let (missing, commands) = validate_with_frozen_outputs(&fixture, &["docs", "root"]);
        let missing = missing.unwrap();
        assert!(!missing.valid);
        assert_eq!(
            missing.findings,
            vec!["configured_mcp_server_state_mismatch"]
        );
        assert_eq!(
            commands,
            vec![
                vec!["plugin", "list", "--json"],
                vec!["mcp", "list", "--json"],
            ]
        );
        assert!(!fixture.sentinel.exists());

        let quoted_project =
            serde_json::to_string(&fixture.adapter.layout.project_root.to_string_lossy()).unwrap();
        fs::write(
            &fixture.global_config,
            format!(
                "mcp_servers = \"not-a-table\"\n\n[projects.{quoted_project}]\ntrust_level = \"trusted\"\n"
            ),
        )
        .unwrap();
        assert!(validate_with_frozen_outputs(&fixture, &[]).0.is_err());
    }

    #[test]
    fn effective_validation_honors_same_name_shadowing_across_trusted_layers() {
        let fixture = effective_validation_fixture();
        fs::write(
            &fixture.global_config,
            format!(
                "{}\n[mcp_servers.shadowed]\ncommand = \"global-shadowed\"\n\n[mcp_servers.reenabled]\nenabled = false\ncommand = \"global-disabled\"\n",
                fs::read_to_string(&fixture.global_config).unwrap()
            ),
        )
        .unwrap();
        fs::write(
            &fixture.root_config,
            format!(
                "{}\n[mcp_servers.shadowed]\nenabled = true\ncommand = \"root-shadowed\"\n",
                fs::read_to_string(&fixture.root_config).unwrap()
            ),
        )
        .unwrap();
        fs::write(
            &fixture.nested_config,
            format!(
                "{}\n[mcp_servers.shadowed]\nenabled = false\ncommand = \"nested-disabled\"\n\n[mcp_servers.reenabled]\nenabled = true\ncommand = \"nested-reenabled\"\n",
                fs::read_to_string(&fixture.nested_config).unwrap()
            ),
        )
        .unwrap();

        let (report, commands) =
            validate_with_frozen_outputs(&fixture, &["docs", "nested", "reenabled", "root"]);
        assert!(report.unwrap().valid);
        assert_eq!(
            commands,
            vec![
                vec!["plugin", "list", "--json"],
                vec!["mcp", "list", "--json"],
                vec!["mcp", "get", "docs", "--json"],
                vec!["mcp", "get", "nested", "--json"],
                vec!["mcp", "get", "reenabled", "--json"],
                vec!["mcp", "get", "root", "--json"],
            ]
        );
        assert!(!fixture.sentinel.exists());
    }

    #[test]
    fn effective_validation_rejects_missing_plugins_extra_servers_and_mcp_body_drift() {
        let fixture = effective_validation_fixture();
        fs::write(
            &fixture.global_config,
            format!(
                "{}\n[plugins.\"formatter@team\"]\nenabled = true\n",
                fs::read_to_string(&fixture.global_config).unwrap()
            ),
        )
        .unwrap();
        let missing_plugin = validate_with_frozen_outputs(&fixture, &["docs", "nested", "root"])
            .0
            .unwrap();
        assert!(!missing_plugin.valid);
        assert_eq!(
            missing_plugin.findings,
            vec!["configured_plugin_state_mismatch"]
        );

        fs::write(
            &fixture.global_config,
            fs::read_to_string(&fixture.global_config)
                .unwrap()
                .replace("\n[plugins.\"formatter@team\"]\nenabled = true\n", ""),
        )
        .unwrap();
        let extra_server =
            validate_with_frozen_outputs(&fixture, &["docs", "nested", "root", "unexpected"])
                .0
                .unwrap();
        assert!(!extra_server.valid);
        assert_eq!(
            extra_server.findings,
            vec!["configured_mcp_server_state_mismatch"]
        );

        let drifted = fixture
            .adapter
            .validate_effective_with(&effective_validation_receipt(), |command| {
                let mut output =
                    effective_validation_output(&fixture, command, &["docs", "nested", "root"])?;
                if matches!(command, CodexCommand::McpGet(name) if name == "docs") {
                    let mut value: Value = serde_json::from_slice(&output).unwrap();
                    value["transport"]["command"] = Value::String("drifted-command".into());
                    output = serde_json::to_vec(&value).unwrap();
                }
                Ok(output)
            })
            .unwrap();
        assert!(!drifted.valid);
        assert_eq!(
            drifted.findings,
            vec!["configured_mcp_server_declaration_mismatch"]
        );
    }

    #[test]
    fn validation_commands_never_start_mcp_servers() {
        assert_eq!(
            [
                CodexCommand::PluginList,
                CodexCommand::McpList,
                CodexCommand::McpGet("docs".into())
            ]
            .into_iter()
            .map(|command| command.argv())
            .collect::<Vec<_>>(),
            vec![
                vec!["plugin", "list", "--json"],
                vec!["mcp", "list", "--json"],
                vec!["mcp", "get", "docs", "--json"]
            ]
        );
    }
    #[test]
    fn native_executable_magic_is_classified_without_executing_wrappers() {
        assert_eq!(
            classify_executable_magic(b"\x7fELF"),
            CodexExecutableKind::Native
        );
        assert_eq!(
            classify_executable_magic(b"#!/bin/sh"),
            CodexExecutableKind::Wrapper
        );
        assert_eq!(
            classify_executable_magic(b"text"),
            CodexExecutableKind::Unknown
        );
    }
    #[test]
    fn installation_method_uses_exact_distribution_path_shapes() {
        assert_eq!(
            installation_method(Path::new(
                "/Applications/ChatGPT.app/Contents/Resources/codex"
            )),
            InstallationMethod::Bundled
        );
        assert_eq!(
            installation_method(Path::new(
                r"C:\Users\person\AppData\Local\Programs\ChatGPT\resources\codex.exe"
            )),
            InstallationMethod::Bundled
        );
        assert_eq!(
            installation_method(Path::new("/opt/homebrew/Cellar/codex/0.144.1/bin/codex")),
            InstallationMethod::PackageManager
        );
        assert_eq!(
            installation_method(Path::new(
                "/usr/local/lib/node_modules/@openai/codex/bin/codex"
            )),
            InstallationMethod::PackageManager
        );
        assert_eq!(
            installation_method(Path::new("/Users/person/.local/bin/codex")),
            InstallationMethod::Manual
        );
        assert_eq!(
            installation_method(Path::new(
                r"C:\Users\person\AppData\Local\Programs\OpenAI\Codex\bin\codex.exe"
            )),
            InstallationMethod::Manual
        );
        assert_eq!(
            installation_method(Path::new("/custom/npm-backup/bin/codex")),
            InstallationMethod::Unknown
        );
        assert_eq!(
            installation_method(Path::new("/custom/tools/codex")),
            InstallationMethod::Unknown
        );
    }
    #[cfg(unix)]
    #[test]
    fn native_discovery_rejects_replacement_before_version_without_execution() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = fs::canonicalize(env::temp_dir()).unwrap().join(format!(
            "context-relay-codex-discovery-race-{}-{}",
            std::process::id(),
            NEXT_EFFECTIVE_FIXTURE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let executable = root.join("codex");
        let sentinel = root.join("wrapper-ran");
        fs::write(&executable, b"\x7fELFnative executable").unwrap();

        let result = discover_executable_version_after_snapshot(&executable, &root, None, || {
            fs::write(
                &executable,
                format!(
                    "#!/bin/sh\n/usr/bin/touch '{}'\nprintf 'codex 0.144.1\\n'\n",
                    sentinel.display()
                ),
            )
            .unwrap();
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        });
        let sentinel_exists = sentinel.exists();
        let _ = fs::remove_dir_all(root);
        assert!(matches!(
            result,
            Err(ClientError {
                code: ErrorCode::Conflict,
                ..
            })
        ));
        assert!(!sentinel_exists);
    }
    #[cfg(unix)]
    #[test]
    fn native_discovery_rejects_replacement_after_version_before_construction() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = fs::canonicalize(env::temp_dir()).unwrap().join(format!(
            "context-relay-codex-discovery-post-version-race-{}-{}",
            std::process::id(),
            NEXT_EFFECTIVE_FIXTURE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let codex_home = root.join("codex-home");
        let user_skills_dir = root.join("user-skills");
        let project_root = root.join("project");
        for directory in [&codex_home, &user_skills_dir, &project_root] {
            fs::create_dir_all(directory).unwrap();
        }
        let executable = root.join("codex");
        fs::copy("/usr/bin/true", &executable).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let attested = snapshot_executable(&executable).unwrap();
        assert_eq!(attested.kind, CodexExecutableKind::Native);
        let replacement = fs::read("/usr/bin/touch").unwrap();
        assert_eq!(
            classify_executable_bytes(&executable, &replacement),
            CodexExecutableKind::Native
        );
        let sentinel = project_root.join("plugin");
        let device_id = DeviceId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073982").unwrap();
        let result = CodexAdapter::from_discovered_layout_after_version(
            CodexLayout {
                executable: executable.clone(),
                executable_kind: CodexExecutableKind::Unknown,
                version: String::new(),
                installation_method: InstallationMethod::Manual,
                codex_home,
                user_skills_dir,
                project_root: project_root.clone(),
                working_directory: project_root,
                requirements_paths: vec![],
            },
            ProjectId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073981").unwrap(),
            device_id,
            HybridLogicalClock::new(1_900_000_000_000, 0, device_id),
            attested,
            "0.144.1".into(),
            || {
                fs::write(&executable, replacement).unwrap();
                fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
            },
        );
        if let Ok(adapter) = &result {
            let _ = adapter.validate_effective(&effective_validation_receipt());
        }
        let sentinel_exists = sentinel.exists();
        let _ = fs::remove_dir_all(root);
        assert!(matches!(
            result,
            Err(ClientError {
                code: ErrorCode::Conflict,
                ..
            })
        ));
        assert!(!sentinel_exists);
    }
    #[test]
    fn observed_stdio_null_environment_normalizes_to_no_overrides() {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/codex-0.144.6-mcp.json")).unwrap();
        let declaration = parse_mcp_get_json(
            &serde_json::to_vec(&fixture["mcpGetJson"]).unwrap(),
            "context-relay",
        )
        .unwrap();
        assert_eq!(declaration["transport"]["env"], serde_json::json!({}));
    }

    #[test]
    fn frozen_release_outputs_match_reviewed_json_contracts() {
        for source in [
            include_str!("../tests/fixtures/codex-0.144.0.json"),
            include_str!("../tests/fixtures/codex-0.144.1.json"),
        ] {
            let fixture: Value = serde_json::from_str(source).unwrap();
            parse_plugin_list_json(&serde_json::to_vec(&fixture["pluginListJson"]).unwrap())
                .unwrap();
            assert_eq!(
                parse_mcp_list_json(&serde_json::to_vec(&fixture["mcpListJson"]).unwrap()).unwrap(),
                BTreeSet::from(["docs".to_owned()])
            );
            parse_mcp_get_json(&serde_json::to_vec(&fixture["mcpGetJson"]).unwrap(), "docs")
                .unwrap();
        }
    }
    #[test]
    fn plugin_json_schema_rejects_wrong_types_membership_sources_and_unknown_fields() {
        let plugin = serde_json::json!({
            "pluginId": "formatter@team",
            "name": "formatter",
            "marketplaceName": "team",
            "version": "1.2.3",
            "installed": true,
            "enabled": true,
            "source": {
                "source": "git",
                "url": "https://example.com/team/plugins.git",
                "ref": "v1.2.3"
            },
            "installPolicy": "AVAILABLE",
            "authPolicy": "ON_USE"
        });
        let valid = |installed: Vec<Value>, available: Vec<Value>| {
            serde_json::to_vec(&serde_json::json!({
                "installed": installed,
                "available": available
            }))
            .unwrap()
        };
        let local = serde_json::json!({
            "pluginId": "local@team",
            "name": "local",
            "marketplaceName": "team",
            "version": "1.0.0",
            "installed": false,
            "enabled": false,
            "source": {"source": "local", "path": "/safe/plugin"},
            "installPolicy": "AVAILABLE",
            "authPolicy": "ON_INSTALL"
        });
        parse_plugin_list_json(&valid(vec![plugin.clone()], vec![local])).unwrap();

        let mut cases = Vec::new();
        let mut unknown = plugin.clone();
        unknown["control"] = Value::Bool(true);
        cases.push(valid(vec![unknown], vec![]));
        let mut wrong_name = plugin.clone();
        wrong_name["name"] = Value::Bool(true);
        cases.push(valid(vec![wrong_name], vec![]));
        let mut wrong_membership = plugin.clone();
        wrong_membership["installed"] = Value::Bool(false);
        cases.push(valid(vec![wrong_membership], vec![]));
        let mut wrong_source = plugin.clone();
        wrong_source["source"]["path"] = Value::String("/extra".into());
        cases.push(valid(vec![wrong_source], vec![]));
        cases.push(valid(vec![plugin.clone()], vec![plugin]));
        cases.push(br#"{"installed":[],"available":[],"unexpected":[]}"#.to_vec());
        for case in cases {
            assert!(parse_plugin_list_json(&case).is_err());
        }
    }
    #[test]
    fn mcp_list_and_get_schemas_reject_wrong_types_unknown_fields_and_disabled_entries() {
        let stdio_transport = serde_json::json!({
            "type": "stdio",
            "command": "local-server",
            "args": ["--safe"],
            "env": {"ALPHA": "first", "ZETA": "last"},
            "env_vars": ["INHERITED"],
            "cwd": null
        });
        let list_entry = serde_json::json!({
            "name": "local-tools",
            "enabled": true,
            "disabled_reason": null,
            "transport": stdio_transport,
            "startup_timeout_sec": 5.5,
            "tool_timeout_sec": 10,
            "auth_status": "unsupported"
        });
        let mut disabled = list_entry.clone();
        disabled["name"] = Value::String("disabled".into());
        disabled["enabled"] = Value::Bool(false);
        disabled["disabled_reason"] = Value::String("disabled by config".into());
        assert_eq!(
            parse_mcp_list_json(
                &serde_json::to_vec(&Value::Array(vec![list_entry.clone(), disabled.clone()]))
                    .unwrap()
            )
            .unwrap(),
            BTreeSet::from(["local-tools".to_owned()])
        );

        let mut get_entry = list_entry.clone();
        let object = get_entry.as_object_mut().unwrap();
        object.remove("auth_status");
        object.insert(
            "enabled_tools".into(),
            serde_json::json!(["read", "search"]),
        );
        object.insert("disabled_tools".into(), Value::Null);
        parse_mcp_get_json(&serde_json::to_vec(&get_entry).unwrap(), "local-tools").unwrap();

        let mut cases = Vec::new();
        let mut wrong_enabled = list_entry.clone();
        wrong_enabled["enabled"] = Value::String("true".into());
        cases.push(Value::Array(vec![wrong_enabled]));
        let mut unknown_server = list_entry.clone();
        unknown_server["unknown"] = Value::Bool(true);
        cases.push(Value::Array(vec![unknown_server]));
        let mut unknown_transport = list_entry.clone();
        unknown_transport["transport"]["unknown"] = Value::Bool(true);
        cases.push(Value::Array(vec![unknown_transport]));
        let mut wrong_env = list_entry.clone();
        wrong_env["transport"]["env"]["ALPHA"] = Value::Null;
        cases.push(Value::Array(vec![wrong_env]));
        let mut negative_timeout = list_entry.clone();
        negative_timeout["tool_timeout_sec"] = serde_json::json!(-1);
        cases.push(Value::Array(vec![negative_timeout]));
        cases.push(Value::Array(vec![list_entry.clone(), list_entry]));
        for case in cases {
            assert!(parse_mcp_list_json(&serde_json::to_vec(&case).unwrap()).is_err());
        }

        let mut wrong_get = get_entry.clone();
        wrong_get["enabled_tools"] = Value::String("read".into());
        assert!(
            parse_mcp_get_json(&serde_json::to_vec(&wrong_get).unwrap(), "local-tools").is_err()
        );
        let mut unknown_get = get_entry;
        unknown_get["auth_status"] = Value::String("unsupported".into());
        assert!(
            parse_mcp_get_json(&serde_json::to_vec(&unknown_get).unwrap(), "local-tools").is_err()
        );

        let http_list = serde_json::json!([{
            "name": "docs",
            "enabled": true,
            "disabled_reason": null,
            "transport": {
                "type": "streamable_http",
                "url": "https://example.com/mcp",
                "bearer_token_env_var": null,
                "http_headers": {"X-Literal": "value", "X-None": null},
                "env_http_headers": {"Authorization": "DOCS_TOKEN"}
            },
            "startup_timeout_sec": null,
            "tool_timeout_sec": 1,
            "auth_status": "bearer_token"
        }]);
        assert_eq!(
            parse_mcp_list_json(&serde_json::to_vec(&http_list).unwrap()).unwrap(),
            BTreeSet::from(["docs".to_owned()])
        );
        let mut wrong_http_header = http_list.clone();
        wrong_http_header[0]["transport"]["http_headers"]["X-Literal"] = serde_json::json!(true);
        assert!(parse_mcp_list_json(&serde_json::to_vec(&wrong_http_header).unwrap()).is_err());
        let mut unknown_http = http_list;
        unknown_http[0]["transport"]["cwd"] = Value::Null;
        assert!(parse_mcp_list_json(&serde_json::to_vec(&unknown_http).unwrap()).is_err());

        let mut http_get = serde_json::json!({
            "name": "docs",
            "enabled": true,
            "disabled_reason": null,
            "transport": {
                "type": "streamable_http",
                "url": "https://example.com/mcp",
                "bearer_token_env_var": "DOCS_TOKEN",
                "http_headers": null,
                "env_http_headers": null
            },
            "enabled_tools": null,
            "disabled_tools": ["write"],
            "startup_timeout_sec": null,
            "tool_timeout_sec": null
        });
        parse_mcp_get_json(&serde_json::to_vec(&http_get).unwrap(), "docs").unwrap();
        http_get["transport"]["bearer_token_env_var"] = serde_json::json!(false);
        assert!(parse_mcp_get_json(&serde_json::to_vec(&http_get).unwrap(), "docs").is_err());
    }
    #[test]
    fn cli_json_parsers_reject_outputs_over_the_size_and_entry_limits() {
        let oversized = vec![b' '; (CLI_OUTPUT_LIMIT + 1) as usize];
        assert!(parse_plugin_list_json(&oversized).is_err());
        assert!(parse_mcp_list_json(&oversized).is_err());
        assert!(parse_mcp_get_json(&oversized, "docs").is_err());

        let plugins: Vec<Value> = (0..257)
            .map(|index| {
                serde_json::json!({
                    "pluginId": format!("p{index}"),
                    "name": format!("p{index}"),
                    "marketplaceName": "team",
                    "version": "1",
                    "installed": true,
                    "enabled": true,
                    "source": {"source": "local", "path": "/safe/plugin"},
                    "installPolicy": "AVAILABLE",
                    "authPolicy": "ON_USE"
                })
            })
            .collect();
        let plugin_bytes = serde_json::to_vec(&serde_json::json!({
            "installed": plugins,
            "available": []
        }))
        .unwrap();
        assert!(plugin_bytes.len() as u64 <= CLI_OUTPUT_LIMIT);
        assert!(parse_plugin_list_json(&plugin_bytes).is_err());

        let servers: Vec<Value> = (0..257)
            .map(|index| {
                serde_json::json!({
                    "name": format!("m{index}"),
                    "enabled": true,
                    "disabled_reason": null,
                    "transport": {
                        "type": "stdio",
                        "command": "server",
                        "args": [],
                        "env": {},
                        "env_vars": [],
                        "cwd": null
                    },
                    "startup_timeout_sec": null,
                    "tool_timeout_sec": null,
                    "auth_status": "unsupported"
                })
            })
            .collect();
        let server_bytes = serde_json::to_vec(&Value::Array(servers)).unwrap();
        assert!(server_bytes.len() as u64 <= CLI_OUTPUT_LIMIT);
        assert!(parse_mcp_list_json(&server_bytes).is_err());
    }
    #[test]
    fn platform_candidates_are_isolated_by_native_platform() {
        let macos = platform_candidates(
            Path::new("/Users/test"),
            Some(Path::new("C:/Users/test/AppData/Local")),
            false,
        );
        assert_eq!(
            macos,
            vec![
                PathBuf::from("/Applications/ChatGPT.app/Contents/Resources/codex"),
                PathBuf::from("/Users/test/Applications/ChatGPT.app/Contents/Resources/codex"),
                PathBuf::from("/Users/test/.local/bin/codex"),
            ]
        );
        let windows = platform_candidates(
            Path::new("/Users/test"),
            Some(Path::new("C:/Users/test/AppData/Local")),
            true,
        );
        assert_eq!(
            windows,
            vec![
                PathBuf::from("C:/Users/test/AppData/Local/Programs/OpenAI/Codex/bin/codex.exe"),
                PathBuf::from("C:/Users/test/AppData/Local/Programs/ChatGPT/resources/codex.exe")
            ]
        );
    }
}

#[cfg(all(test, windows))]
mod standalone_discovery_tests {
    use super::*;
    use std::{os::windows::process::CommandExt, sync::OnceLock};
    use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

    const TARGET: &str = if cfg!(target_arch = "aarch64") {
        "aarch64-pc-windows-msvc"
    } else {
        "x86_64-pc-windows-msvc"
    };

    struct Standalone {
        _root: tempfile::TempDir,
        home: PathBuf,
        local: PathBuf,
        releases: PathBuf,
        current: PathBuf,
        alias: PathBuf,
        original: PathBuf,
        replacement: PathBuf,
    }

    fn native_probe() -> &'static [u8] {
        static BYTES: OnceLock<Vec<u8>> = OnceLock::new();
        BYTES.get_or_init(|| {
            let build = tempfile::tempdir().unwrap();
            let binary = build.path().join("probe.exe");
            let output = Command::new(env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
                .arg("--edition=2024")
                .arg(
                    Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("tests/fixtures/codex-native-discovery-probe.rs"),
                )
                .arg("-o")
                .arg(&binary)
                .creation_flags(CREATE_NO_WINDOW)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "native fixture failed to build: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            fs::read(binary).unwrap()
        })
    }

    fn junction(link: &Path, target: &Path) {
        let output = Command::new("cmd")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(link.to_str().unwrap().replace('/', "\\"))
            .arg(target.to_str().unwrap().replace('/', "\\"))
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "mandatory junction fixture failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    impl Standalone {
        fn new() -> Self {
            let root = tempfile::Builder::new()
                .prefix("context-relay-standalone-")
                .tempdir()
                .unwrap();
            let home = root.path().join("home");
            let local = home.join("AppData/Local");
            let base = home.join(".codex/packages/standalone");
            let releases = base.join("releases");
            let release = |version: &str| {
                let bin = releases.join(format!("{version}-{TARGET}")).join("bin");
                fs::create_dir_all(&bin).unwrap();
                fs::write(bin.join("codex.exe"), native_probe()).unwrap();
                fs::write(bin.join("version.txt"), version).unwrap();
                bin.join("codex.exe")
            };
            let original = release("0.144.1");
            let replacement = release("0.144.0");
            let current = base.join("current");
            junction(&current, original.parent().unwrap().parent().unwrap());
            let alias_bin = local.join("Programs/OpenAI/Codex/bin");
            fs::create_dir_all(alias_bin.parent().unwrap()).unwrap();
            junction(&alias_bin, &current.join("bin"));
            Self {
                _root: root,
                home,
                local,
                releases,
                current,
                alias: alias_bin.join("codex.exe"),
                original,
                replacement,
            }
        }

        fn resolve(&self) -> Result<(PathBuf, Option<String>), ClientError> {
            resolve_windows_standalone_candidate(&self.alias, &self.home, Some(&self.local))
        }

        fn retarget(&self, release: &Path) {
            fs::remove_dir(&self.current).unwrap();
            junction(&self.current, release);
        }

        fn adapter(
            &self,
            physical: PathBuf,
            snapshot: CodexExecutableSnapshot,
            version: String,
        ) -> CodexAdapter {
            let device_id = DeviceId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073982").unwrap();
            CodexAdapter::from_discovered_layout_after_version(
                CodexLayout {
                    executable: physical,
                    executable_kind: CodexExecutableKind::Unknown,
                    version: String::new(),
                    installation_method: InstallationMethod::Manual,
                    codex_home: self.home.join(".codex"),
                    user_skills_dir: self.home.join(".agents/skills"),
                    project_root: self.home.clone(),
                    working_directory: self.home.clone(),
                    requirements_paths: vec![],
                },
                ProjectId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073981").unwrap(),
                device_id,
                HybridLogicalClock::new(1_900_000_000_000, 0, device_id),
                snapshot,
                version,
                || {},
            )
            .unwrap()
        }
    }

    #[test]
    fn standalone_alias_is_resolved_before_version_and_later_retargets_cannot_redirect_probe() {
        for retarget_after_snapshot in [false, true] {
            let fixture = Standalone::new();
            let (physical, expected_version) = fixture.resolve().unwrap();
            assert_eq!(physical, fixture.original);
            assert_eq!(expected_version.as_deref(), Some("0.144.1"));
            let replacement_release = fixture.replacement.parent().unwrap().parent().unwrap();
            if !retarget_after_snapshot {
                fixture.retarget(replacement_release);
            }
            let (snapshot, version) = discover_executable_version_after_snapshot(
                &physical,
                &fixture.home,
                expected_version.as_deref(),
                || {
                    if retarget_after_snapshot {
                        fixture.retarget(replacement_release);
                    }
                },
            )
            .unwrap();
            assert_eq!(version, "0.144.1");
            assert!(physical.with_file_name("invoked").exists());
            assert!(!fixture.replacement.with_file_name("invoked").exists());
            let output =
                run_bounded_command(&physical, &["--version"], snapshot.digest, &fixture.home)
                    .unwrap();
            assert_eq!(output, b"codex-cli 0.144.1\n");
            assert!(!fixture.replacement.with_file_name("invoked").exists());
        }
    }

    #[test]
    fn standalone_resolution_rejects_outside_root_wrong_shape_target_and_nested_junctions() {
        for mode in [
            "outside",
            "shape",
            "target",
            "nested",
            "root-link",
            "programs-target",
        ] {
            let fixture = Standalone::new();
            match mode {
                "outside" => fixture.retarget(fixture._root.path()),
                "shape" => fixture.retarget(fixture.original.parent().unwrap()),
                "target" => {
                    let wrong = fixture.releases.join("0.144.1-wrong-target");
                    fs::create_dir(&wrong).unwrap();
                    fixture.retarget(&wrong);
                }
                "nested" => {
                    let bin = fixture.original.parent().unwrap();
                    let moved = bin.with_file_name("moved-bin");
                    fs::rename(bin, &moved).unwrap();
                    junction(bin, &moved);
                }
                "root-link" => {
                    let moved = fixture.releases.with_file_name("moved-releases");
                    fs::rename(&fixture.releases, &moved).unwrap();
                    junction(&fixture.releases, &moved);
                }
                "programs-target" => {
                    let alias_bin = fixture.alias.parent().unwrap();
                    fs::remove_dir(alias_bin).unwrap();
                    junction(alias_bin, fixture.replacement.parent().unwrap());
                }
                _ => unreachable!(),
            }
            assert!(fixture.resolve().is_err(), "accepted {mode}");
            assert!(!fixture.replacement.with_file_name("invoked").exists());
        }
    }

    #[test]
    fn standalone_resolution_never_canonicalizes_an_arbitrary_path_alias() {
        let fixture = Standalone::new();
        let arbitrary = fixture._root.path().join("custom-bin");
        junction(&arbitrary, fixture.original.parent().unwrap());
        let candidate = arbitrary.join("codex.exe");
        let (path, expected_version) =
            resolve_windows_standalone_candidate(&candidate, &fixture.home, Some(&fixture.local))
                .unwrap();
        assert_eq!(path, candidate);
        assert!(expected_version.is_none());
        assert!(snapshot_executable(&path).is_err());
    }

    #[test]
    fn standalone_current_alias_is_bound_to_the_expected_physical_release() {
        let fixture = Standalone::new();
        let (physical, expected_version) = resolve_windows_standalone_candidate(
            &fixture.current.join("bin/codex.exe"),
            &fixture.home,
            None,
        )
        .unwrap();
        assert_eq!(physical, fixture.original);
        assert_eq!(expected_version.as_deref(), Some("0.144.1"));
        let (_, version) =
            discover_executable_version(&physical, &fixture.home, expected_version.as_deref())
                .unwrap();
        assert_eq!(version, "0.144.1");
        assert!(!fixture.replacement.with_file_name("invoked").exists());
    }

    #[test]
    fn constructed_standalone_adapter_stays_bound_after_alias_retargets() {
        let fixture = Standalone::new();
        let (physical, expected_version) = fixture.resolve().unwrap();
        let (snapshot, version) =
            discover_executable_version(&physical, &fixture.home, expected_version.as_deref())
                .unwrap();
        let adapter = fixture.adapter(physical, snapshot, version);
        fixture.retarget(fixture.replacement.parent().unwrap().parent().unwrap());
        let output = run_bounded_command(
            &adapter.layout.executable,
            &["--version"],
            adapter.executable_hash,
            &fixture.home,
        )
        .unwrap();
        assert_eq!(output, b"codex-cli 0.144.1\n");
        assert!(!fixture.replacement.with_file_name("invoked").exists());
    }

    #[test]
    fn constructed_standalone_adapter_rejects_changed_binary_and_reparse_ancestor() {
        for replace_ancestor in [false, true] {
            let fixture = Standalone::new();
            let (physical, expected_version) = fixture.resolve().unwrap();
            let (snapshot, version) =
                discover_executable_version(&physical, &fixture.home, expected_version.as_deref())
                    .unwrap();
            let adapter = fixture.adapter(physical, snapshot, version);
            if replace_ancestor {
                let bin = fixture.original.parent().unwrap();
                fs::rename(bin, bin.with_file_name("retired-bin")).unwrap();
                junction(bin, fixture.replacement.parent().unwrap());
            } else {
                let mut replacement = native_probe().to_vec();
                replacement.extend_from_slice(b"changed executable digest");
                fs::write(&fixture.original, replacement).unwrap();
            }
            assert!(
                run_bounded_command(
                    &adapter.layout.executable,
                    &["--version"],
                    adapter.executable_hash,
                    &fixture.home
                )
                .is_err()
            );
            assert!(!fixture.replacement.with_file_name("invoked").exists());
        }
    }

    #[test]
    fn standalone_release_directory_must_match_the_native_version() {
        let fixture = Standalone::new();
        fs::write(fixture.original.with_file_name("version.txt"), "0.144.0").unwrap();
        let result = discover_executable_version(&fixture.original, &fixture.home, Some("0.144.1"));
        assert!(result.is_err());
    }
}
