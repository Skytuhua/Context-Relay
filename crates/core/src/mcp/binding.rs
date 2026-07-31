use std::{
    cmp::Ordering,
    fs,
    path::{Path, PathBuf},
};

use context_relay_protocol::{
    ClientError, ErrorCode, HarnessAccessPolicy, HarnessId, McpBinding, McpScopeSelector,
    NativePlatform, ProjectId, ProjectIdentity, ScopeRef, WireNativeValue,
};

use crate::{search::AllowedSearchScope, vault::Vault};

const SCOPE_DENIED_MESSAGE: &str = "The calling harness is not allowed to access this scope";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedMcpBinding {
    pub harness: HarnessId,
    pub active_project: Option<ProjectIdentity>,
    pub policy: HarnessAccessPolicy,
    pub access: McpAccess,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpAccess {
    global_read: bool,
    project_read: Option<ProjectId>,
    global_write: bool,
    project_write: Option<ProjectId>,
}

impl McpAccess {
    fn resolve(policy: &HarnessAccessPolicy, active_project: Option<ProjectId>) -> Self {
        let global_read =
            AllowedSearchScope::resolve(Some(McpScopeSelector::Global), policy, active_project)
                .is_ok();
        let project_read = AllowedSearchScope::resolve(
            Some(McpScopeSelector::ActiveProject),
            policy,
            active_project,
        )
        .is_ok()
        .then_some(active_project)
        .flatten();

        let global_write = global_read
            && matches!(
                policy,
                HarnessAccessPolicy::Default | HarnessAccessPolicy::GlobalOnly { read_only: false }
            );
        let project_write = project_read.filter(|_| {
            matches!(
                policy,
                HarnessAccessPolicy::Default
                    | HarnessAccessPolicy::ActiveProjectOnly { read_only: false }
                    | HarnessAccessPolicy::SelectedProject {
                        read_only: false,
                        ..
                    }
            )
        });

        Self {
            global_read,
            project_read,
            global_write,
            project_write,
        }
    }

    pub fn read_scope(&self, requested: McpScopeSelector) -> Result<ScopeRef, ClientError> {
        self.scope(requested, false).ok_or_else(scope_denied)
    }

    pub fn write_scope(&self, requested: McpScopeSelector) -> Result<ScopeRef, ClientError> {
        self.scope(requested, true).ok_or_else(scope_denied)
    }

    pub fn require_tasks(&self, write: bool) -> Result<ProjectId, ClientError> {
        if write {
            self.project_write
        } else {
            self.project_read
        }
        .ok_or_else(scope_denied)
    }

    pub fn allows_record_scope(&self, scope: &ScopeRef, write: bool) -> bool {
        let requested = match scope {
            ScopeRef::Global => McpScopeSelector::Global,
            ScopeRef::Project { .. } => McpScopeSelector::ActiveProject,
        };
        self.scope(requested, write)
            .is_some_and(|allowed| allowed == *scope)
    }

    fn scope(&self, requested: McpScopeSelector, write: bool) -> Option<ScopeRef> {
        match (requested, write) {
            (McpScopeSelector::Global, false) if self.global_read => Some(ScopeRef::Global),
            (McpScopeSelector::Global, true) if self.global_write => Some(ScopeRef::Global),
            (McpScopeSelector::ActiveProject, false) => self
                .project_read
                .map(|project_id| ScopeRef::Project { project_id }),
            (McpScopeSelector::ActiveProject, true) => self
                .project_write
                .map(|project_id| ScopeRef::Project { project_id }),
            _ => None,
        }
    }
}

pub fn resolve_binding(
    vault: &Vault,
    binding: &McpBinding,
) -> Result<ResolvedMcpBinding, ClientError> {
    let working_directory =
        canonical_directory(&binding.working_directory).map_err(|_| invalid_binding())?;
    let working_ancestors =
        CanonicalAncestors::new(&working_directory).map_err(|_| invalid_binding())?;
    let projects = vault.projects().map_err(|_| vault_error())?;

    let mut best: Option<(usize, ProjectIdentity)> = None;
    let mut ambiguous = false;
    for project in projects {
        let Some(root) = vault
            .path(&project.project_id.to_string())
            .map_err(|_| vault_error())?
        else {
            continue;
        };
        let Some((specificity, project)) = registered_match(&working_ancestors, root, project)
        else {
            continue;
        };
        match best.as_ref().map(|(length, _)| specificity.cmp(length)) {
            None | Some(Ordering::Greater) => {
                best = Some((specificity, project));
                ambiguous = false;
            }
            Some(Ordering::Equal) => {
                if best
                    .as_ref()
                    .is_some_and(|(_, current)| current.project_id != project.project_id)
                {
                    ambiguous = true;
                }
            }
            Some(Ordering::Less) => {}
        }
    }
    if ambiguous {
        return Err(scope_denied());
    }

    let active_project = best.map(|(_, project)| project);
    let policy = vault
        .access_policy(binding.harness)
        .map_err(|_| vault_error())?;
    if let HarnessAccessPolicy::SelectedProject { project_id, .. } = &policy
        && active_project.as_ref().map(|project| project.project_id) != Some(*project_id)
    {
        return Err(scope_denied());
    }
    let access = McpAccess::resolve(
        &policy,
        active_project.as_ref().map(|project| project.project_id),
    );

    Ok(ResolvedMcpBinding {
        harness: binding.harness,
        active_project,
        policy,
        access,
    })
}

fn registered_match(
    working_ancestors: &CanonicalAncestors,
    root: WireNativeValue,
    project: ProjectIdentity,
) -> Option<(usize, ProjectIdentity)> {
    let root = canonical_directory(&root).ok()?;
    root.parent()?;
    working_ancestors
        .specificity(&root)
        .map(|specificity| (specificity, project))
}

fn canonical_directory(value: &WireNativeValue) -> Result<PathBuf, ()> {
    let path = decode_native_path(value)?;
    if !path.is_absolute() {
        return Err(());
    }
    let canonical = fs::canonicalize(path).map_err(|_| ())?;
    fs::metadata(&canonical)
        .map_err(|_| ())?
        .is_dir()
        .then_some(canonical)
        .ok_or(())
}

fn decode_native_path(value: &WireNativeValue) -> Result<PathBuf, ()> {
    #[cfg(windows)]
    {
        use std::{ffi::OsString, os::windows::ffi::OsStringExt};

        if value.platform != NativePlatform::Windows || !value.bytes.len().is_multiple_of(2) {
            return Err(());
        }
        let units = value
            .bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        if units.contains(&0) {
            return Err(());
        }
        Ok(PathBuf::from(OsString::from_wide(&units)))
    }
    #[cfg(target_os = "macos")]
    {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};

        if value.platform != NativePlatform::Macos || value.bytes.contains(&0) {
            return Err(());
        }
        Ok(PathBuf::from(OsString::from_vec(value.bytes.clone())))
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = value;
        Err(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CanonicalAncestor {
    identity: DirectoryIdentity,
    specificity: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CanonicalAncestors(Vec<CanonicalAncestor>);

impl CanonicalAncestors {
    fn new(working_directory: &Path) -> Result<Self, ()> {
        let ancestors = working_directory.ancestors().collect::<Vec<_>>();
        let count = ancestors.len();
        let mut identities = Vec::with_capacity(count);
        for (index, ancestor) in ancestors.into_iter().enumerate() {
            match directory_identity(ancestor) {
                Ok(identity) => identities.push(CanonicalAncestor {
                    identity,
                    specificity: count - index,
                }),
                Err(()) if index == 0 => return Err(()),
                Err(()) => {}
            }
        }
        Ok(Self(identities))
    }

    fn specificity(&self, root: &Path) -> Option<usize> {
        let identity = directory_identity(root).ok()?;
        self.0
            .iter()
            .find(|ancestor| ancestor.identity == identity)
            .map(|ancestor| ancestor.specificity)
    }
}

#[cfg(not(windows))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct DirectoryIdentity(PathBuf);

#[cfg(not(windows))]
fn directory_identity(path: &Path) -> Result<DirectoryIdentity, ()> {
    Ok(DirectoryIdentity(path.to_path_buf()))
}

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct DirectoryIdentity {
    volume_serial_number: u64,
    file_id: [u8; 16],
}

#[cfg(windows)]
fn directory_identity(path: &Path) -> Result<DirectoryIdentity, ()> {
    use std::{
        fs::OpenOptions,
        mem::size_of,
        os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    };
    use windows_sys::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx,
        },
    };

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .map_err(|_| ())?;
    let mut information = FILE_ID_INFO::default();
    // SAFETY: `file` owns a valid open directory handle and `information` is a
    // correctly sized writable `FILE_ID_INFO` buffer for the duration of the call.
    let succeeded = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as HANDLE,
            FileIdInfo,
            std::ptr::from_mut(&mut information).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    };
    if succeeded == 0 {
        return Err(());
    }
    Ok(DirectoryIdentity {
        volume_serial_number: information.VolumeSerialNumber,
        file_id: information.FileId.Identifier,
    })
}

fn scope_denied() -> ClientError {
    ClientError {
        code: ErrorCode::ScopeDenied,
        message: SCOPE_DENIED_MESSAGE.to_owned(),
        field_path: None,
        retryable: false,
    }
}

fn invalid_binding() -> ClientError {
    ClientError {
        code: ErrorCode::InvalidRequest,
        message: "The MCP harness binding is invalid".to_owned(),
        field_path: None,
        retryable: false,
    }
}

fn vault_error() -> ClientError {
    ClientError {
        code: ErrorCode::Internal,
        message: "The local vault operation failed".to_owned(),
        field_path: None,
        retryable: false,
    }
}
