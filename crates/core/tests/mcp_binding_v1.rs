#![cfg(any(windows, target_os = "macos"))]

mod support;

use std::{
    fs,
    path::{Path, PathBuf},
};

use context_relay_core::{
    mcp::binding::{ResolvedMcpBinding, resolve_binding, resolve_hook_binding},
    vault::Vault,
};
use context_relay_protocol::{
    ClientError, ErrorCode, HarnessAccessPolicy, HarnessId, McpBinding, McpScopeSelector,
    NativePlatform, ProjectId, ProjectIdentity, ScopeRef, WireNativeValue,
};
use tempfile::{TempDir, tempdir};

use support::{ID_7, ID_8, MemoryKeyStore, TempVault};

const CREDENTIAL: &str = "mcp-binding-v1";
const DENIED_MESSAGE: &str = "The calling harness is not allowed to access this scope";

struct Fixture {
    _database: TempVault,
    _keys: MemoryKeyStore,
    roots: TempDir,
    vault: Vault,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let database = TempVault::new(name);
        let keys = MemoryKeyStore::default();
        let vault = Vault::open(database.path(), CREDENTIAL, &keys).unwrap();
        Self {
            _database: database,
            _keys: keys,
            roots: tempdir().unwrap(),
            vault,
        }
    }

    fn root(&self, name: &str) -> PathBuf {
        self.roots.path().join(name)
    }

    fn register(&mut self, project: &ProjectIdentity, root: &Path) {
        self.vault.put_project(project).unwrap();
        self.vault
            .put_path(&project.project_id.to_string(), &wire_path(root))
            .unwrap();
    }

    fn set_policy(&mut self, policy: HarnessAccessPolicy) {
        self.vault
            .set_access_policy(HarnessId::Codex, &policy)
            .unwrap();
    }

    fn resolve(&self, working_directory: &Path) -> Result<ResolvedMcpBinding, ClientError> {
        resolve_binding(
            &self.vault,
            &McpBinding {
                harness: HarnessId::Codex,
                working_directory: wire_path(working_directory),
            },
        )
    }

    fn resolve_hook(&self, working_directory: &Path) -> Result<ResolvedMcpBinding, ClientError> {
        resolve_hook_binding(
            &self.vault,
            &McpBinding {
                harness: HarnessId::Codex,
                working_directory: wire_path(working_directory),
            },
        )
    }
}

fn project(id: &str, name: &str) -> ProjectIdentity {
    ProjectIdentity {
        project_id: id.parse::<ProjectId>().unwrap(),
        github_repository_id: None,
        git_remote_fingerprint: None,
        monorepo_subdirectory: None,
        name: name.to_owned(),
    }
}

fn project_a() -> ProjectIdentity {
    project(ID_7, "Alpha")
}

fn project_b() -> ProjectIdentity {
    project(ID_8, "Beta")
}

fn project_scope(project_id: ProjectId) -> ScopeRef {
    ScopeRef::Project { project_id }
}

fn assert_denied(error: ClientError) {
    assert_eq!(error.code, ErrorCode::ScopeDenied);
    assert_eq!(error.message, DENIED_MESSAGE);
    assert_eq!(error.field_path, None);
    assert!(!error.retryable);
}

fn assert_scope(result: Result<ScopeRef, ClientError>, expected: Option<ScopeRef>, label: &str) {
    match expected {
        Some(expected) => assert_eq!(result.unwrap(), expected, "{label}"),
        None => assert_denied(result.expect_err(label)),
    }
}

#[test]
fn longest_registered_root_resolves_without_accepting_a_project_id() {
    let mut fixture = Fixture::new("mcp-longest-root");
    let repo = fixture.root("repo");
    let package = repo.join("packages/app");
    fs::create_dir_all(&package).unwrap();

    fixture.register(&project_a(), &repo);
    fixture.register(&project_b(), &package);

    let resolved = fixture.resolve(&package).unwrap();
    assert_eq!(resolved.harness, HarnessId::Codex);
    assert_eq!(
        resolved
            .active_project
            .as_ref()
            .map(|project| project.project_id),
        Some(project_b().project_id)
    );
    assert_eq!(resolved.policy, HarnessAccessPolicy::Default);
}

#[test]
fn no_matching_project_resolves_global_only_under_the_default_policy() {
    let fixture = Fixture::new("mcp-no-project");
    let working_directory = fixture.root("unregistered");
    fs::create_dir_all(&working_directory).unwrap();

    let resolved = fixture.resolve(&working_directory).unwrap();
    assert_eq!(resolved.active_project, None);
    assert_eq!(
        resolved
            .access
            .read_scope(McpScopeSelector::Global)
            .unwrap(),
        ScopeRef::Global
    );
    assert_eq!(
        resolved
            .access
            .write_scope(McpScopeSelector::Global)
            .unwrap(),
        ScopeRef::Global
    );
    assert_denied(
        resolved
            .access
            .read_scope(McpScopeSelector::ActiveProject)
            .unwrap_err(),
    );
    assert_denied(resolved.access.require_tasks(false).unwrap_err());
    assert!(
        resolved
            .access
            .allows_record_scope(&ScopeRef::Global, false)
    );
    assert!(
        !resolved
            .access
            .allows_record_scope(&project_scope(project_a().project_id), false)
    );
}

#[test]
fn unusable_registered_roots_are_ignored_without_rewriting_them() {
    let mut fixture = Fixture::new("mcp-missing-root");
    let missing = fixture.root("missing");
    fs::create_dir_all(&missing).unwrap();
    fixture.register(&project_a(), &missing);
    fs::remove_dir(&missing).unwrap();
    let working_directory = fixture.root("working");
    fs::create_dir_all(&working_directory).unwrap();

    let resolved = fixture.resolve(&working_directory).unwrap();
    assert_eq!(resolved.active_project, None);
    assert_eq!(
        fixture
            .vault
            .path(&project_a().project_id.to_string())
            .unwrap(),
        Some(wire_path(&missing))
    );
}

#[test]
fn equal_specificity_for_different_projects_fails_closed() {
    let mut fixture = Fixture::new("mcp-ambiguous-root");
    let repo = fixture.root("repo");
    fs::create_dir_all(&repo).unwrap();
    fixture.register(&project_a(), &repo);
    fixture.register(&project_b(), &repo);

    assert_denied(fixture.resolve(&repo).unwrap_err());
}

#[cfg(windows)]
#[test]
fn linguistic_casefold_siblings_never_share_project_identity() {
    let mut fixture = Fixture::new("mcp-linguistic-siblings");
    let sharp_s = fixture.root("Straße");
    let double_s = fixture.root("STRASSE");
    fs::create_dir_all(&sharp_s).unwrap();
    match fs::create_dir(&double_s) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return,
        Err(error) => panic!("could not create linguistic sibling: {error}"),
    }
    fixture.register(&project_a(), &sharp_s);

    let resolved = fixture.resolve(&double_s).unwrap();
    assert_eq!(resolved.active_project, None);
}

#[test]
fn selected_project_must_be_the_canonical_active_project() {
    let mut fixture = Fixture::new("mcp-selected-project");
    let repo_a = fixture.root("alpha");
    let repo_b = fixture.root("beta");
    let unmatched = fixture.root("unmatched");
    fs::create_dir_all(&repo_a).unwrap();
    fs::create_dir_all(&repo_b).unwrap();
    fs::create_dir_all(&unmatched).unwrap();
    fixture.register(&project_a(), &repo_a);
    fixture.register(&project_b(), &repo_b);
    fixture.set_policy(HarnessAccessPolicy::SelectedProject {
        project_id: project_a().project_id,
        read_only: false,
    });

    assert_denied(fixture.resolve(&repo_b).unwrap_err());
    assert_denied(fixture.resolve(&unmatched).unwrap_err());
}

#[test]
fn hook_binding_acknowledges_no_match_but_rejects_wrong_selected_or_ambiguous_projects() {
    let mut fixture = Fixture::new("hook-selected-project");
    let repo_a = fixture.root("alpha");
    let repo_b = fixture.root("beta");
    let unmatched = fixture.root("unmatched");
    fs::create_dir_all(&repo_a).unwrap();
    fs::create_dir_all(&repo_b).unwrap();
    fs::create_dir_all(&unmatched).unwrap();
    fixture.register(&project_a(), &repo_a);
    fixture.register(&project_b(), &repo_b);
    fixture.set_policy(HarnessAccessPolicy::SelectedProject {
        project_id: project_a().project_id,
        read_only: false,
    });

    assert_eq!(
        fixture.resolve_hook(&unmatched).unwrap().active_project,
        None
    );
    assert_denied(fixture.resolve_hook(&repo_b).unwrap_err());

    fixture.register(
        &project("018f22e2-79b0-7cc8-98c4-dc0c0c073986", "ambiguous alpha"),
        &repo_a,
    );
    assert_denied(fixture.resolve_hook(&repo_a).unwrap_err());
}

#[test]
fn every_harness_policy_applies_the_complete_read_write_and_task_matrix() {
    struct Case {
        label: &'static str,
        policy: HarnessAccessPolicy,
        global_read: bool,
        project_read: bool,
        global_write: bool,
        project_write: bool,
        task_read: bool,
        task_write: bool,
    }

    let project_id = project_a().project_id;
    let cases = [
        Case {
            label: "default",
            policy: HarnessAccessPolicy::Default,
            global_read: true,
            project_read: true,
            global_write: true,
            project_write: true,
            task_read: true,
            task_write: true,
        },
        Case {
            label: "read_only",
            policy: HarnessAccessPolicy::ReadOnly,
            global_read: true,
            project_read: true,
            global_write: false,
            project_write: false,
            task_read: true,
            task_write: false,
        },
        Case {
            label: "active_project_only",
            policy: HarnessAccessPolicy::ActiveProjectOnly { read_only: false },
            global_read: false,
            project_read: true,
            global_write: false,
            project_write: true,
            task_read: true,
            task_write: true,
        },
        Case {
            label: "active_project_only_read_only",
            policy: HarnessAccessPolicy::ActiveProjectOnly { read_only: true },
            global_read: false,
            project_read: true,
            global_write: false,
            project_write: false,
            task_read: true,
            task_write: false,
        },
        Case {
            label: "global_only",
            policy: HarnessAccessPolicy::GlobalOnly { read_only: false },
            global_read: true,
            project_read: false,
            global_write: true,
            project_write: false,
            task_read: false,
            task_write: false,
        },
        Case {
            label: "global_only_read_only",
            policy: HarnessAccessPolicy::GlobalOnly { read_only: true },
            global_read: true,
            project_read: false,
            global_write: false,
            project_write: false,
            task_read: false,
            task_write: false,
        },
        Case {
            label: "selected_project",
            policy: HarnessAccessPolicy::SelectedProject {
                project_id,
                read_only: false,
            },
            global_read: false,
            project_read: true,
            global_write: false,
            project_write: true,
            task_read: true,
            task_write: true,
        },
        Case {
            label: "selected_project_read_only",
            policy: HarnessAccessPolicy::SelectedProject {
                project_id,
                read_only: true,
            },
            global_read: false,
            project_read: true,
            global_write: false,
            project_write: false,
            task_read: true,
            task_write: false,
        },
        Case {
            label: "disabled",
            policy: HarnessAccessPolicy::Disabled,
            global_read: false,
            project_read: false,
            global_write: false,
            project_write: false,
            task_read: false,
            task_write: false,
        },
    ];

    for case in cases {
        let mut fixture = Fixture::new(case.label);
        let repo = fixture.root("repo");
        fs::create_dir_all(&repo).unwrap();
        fixture.register(&project_a(), &repo);
        fixture.set_policy(case.policy.clone());
        let resolved = fixture.resolve(&repo).unwrap();

        assert_scope(
            resolved.access.read_scope(McpScopeSelector::Global),
            case.global_read.then_some(ScopeRef::Global),
            case.label,
        );
        assert_scope(
            resolved.access.read_scope(McpScopeSelector::ActiveProject),
            case.project_read.then_some(project_scope(project_id)),
            case.label,
        );
        assert_scope(
            resolved.access.write_scope(McpScopeSelector::Global),
            case.global_write.then_some(ScopeRef::Global),
            case.label,
        );
        assert_scope(
            resolved.access.write_scope(McpScopeSelector::ActiveProject),
            case.project_write.then_some(project_scope(project_id)),
            case.label,
        );
        match case.task_read {
            true => assert_eq!(
                resolved.access.require_tasks(false).unwrap(),
                project_id,
                "{}",
                case.label
            ),
            false => assert_denied(resolved.access.require_tasks(false).expect_err(case.label)),
        }
        match case.task_write {
            true => assert_eq!(
                resolved.access.require_tasks(true).unwrap(),
                project_id,
                "{}",
                case.label
            ),
            false => assert_denied(resolved.access.require_tasks(true).expect_err(case.label)),
        }
        assert_eq!(
            resolved
                .access
                .allows_record_scope(&ScopeRef::Global, false),
            case.global_read,
            "{}",
            case.label
        );
        assert_eq!(
            resolved
                .access
                .allows_record_scope(&project_scope(project_id), true),
            case.project_write,
            "{}",
            case.label
        );
        assert!(
            !resolved
                .access
                .allows_record_scope(&project_scope(project_b().project_id), false),
            "{}",
            case.label
        );
    }
}

#[cfg(windows)]
#[test]
fn windows_case_variants_resolve_the_same_directory_identity() {
    let mut fixture = Fixture::new("mcp-windows-case-variant");
    let registered = fixture.root("Repo");
    fs::create_dir_all(&registered).unwrap();
    fixture.register(&project_a(), &registered);
    let alternate_case = fixture.root("repo");

    let resolved = fixture.resolve(&alternate_case).unwrap();
    assert_eq!(
        resolved.active_project.unwrap().project_id,
        project_a().project_id
    );
}

#[cfg(windows)]
#[test]
fn windows_case_sensitive_siblings_use_distinct_file_identities_when_supported() {
    let mut fixture = Fixture::new("mcp-windows-case-sensitive-siblings");
    match enable_case_sensitive_directory(fixture.roots.path()).unwrap() {
        CaseSensitivityEnable::Enabled => {}
        CaseSensitivityEnable::Unsupported(code) => {
            eprintln!("case-sensitive directories are unsupported ({code})");
            return;
        }
    }
    let upper = fixture.root("Case");
    let lower = fixture.root("case");
    fs::create_dir(&upper).unwrap();
    fs::create_dir(&lower).unwrap();
    fixture.register(&project_a(), &upper);

    let resolved = fixture.resolve(&lower).unwrap();
    assert_eq!(resolved.active_project, None);
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CaseSensitivityEnable {
    Enabled,
    Unsupported(u32),
}

#[cfg(windows)]
fn enable_case_sensitive_directory(path: &Path) -> std::io::Result<CaseSensitivityEnable> {
    use std::{
        fs::OpenOptions,
        mem::size_of,
        os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    };
    use windows_sys::Win32::{
        Foundation::{ERROR_INVALID_FUNCTION, ERROR_NOT_SUPPORTED, HANDLE},
        Storage::FileSystem::{
            FILE_CASE_SENSITIVE_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE,
            FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, FileCaseSensitiveInfo,
            SetFileInformationByHandle,
        },
    };

    // This SDK version exposes the structure and information class but not the
    // documented flag constant.
    const FILE_CASE_SENSITIVE_INFO_FLAG_ENABLE: u32 = 1;

    let directory = OpenOptions::new()
        .write(true)
        .access_mode(FILE_WRITE_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    let information = FILE_CASE_SENSITIVE_INFO {
        Flags: FILE_CASE_SENSITIVE_INFO_FLAG_ENABLE,
    };
    // SAFETY: `directory` is a valid directory handle opened for attribute
    // writes and `information` is a correctly sized immutable input buffer.
    let succeeded = unsafe {
        SetFileInformationByHandle(
            directory.as_raw_handle() as HANDLE,
            FileCaseSensitiveInfo,
            std::ptr::from_ref(&information).cast(),
            size_of::<FILE_CASE_SENSITIVE_INFO>() as u32,
        )
    };
    if succeeded != 0 {
        return Ok(CaseSensitivityEnable::Enabled);
    }

    let error = std::io::Error::last_os_error();
    match error.raw_os_error().map(|code| code as u32) {
        Some(code @ (ERROR_NOT_SUPPORTED | ERROR_INVALID_FUNCTION)) => {
            Ok(CaseSensitivityEnable::Unsupported(code))
        }
        _ => Err(error),
    }
}

#[cfg(target_os = "macos")]
#[test]
fn native_path_bytes_are_authoritative_and_display_is_ignored() {
    let mut fixture = Fixture::new("mcp-native-bytes");
    let repo = fixture.roots.path().join("repo-臺");
    fs::create_dir_all(&repo).unwrap();
    fixture.register(&project_a(), &repo);
    let mut binding = McpBinding {
        harness: HarnessId::Codex,
        working_directory: wire_path(&repo),
    };
    binding.working_directory.display = Some("/not/the/native/path".to_owned());

    let resolved = resolve_binding(&fixture.vault, &binding).unwrap();
    assert_eq!(
        resolved.active_project.unwrap().project_id,
        project_a().project_id
    );
}

#[cfg(target_os = "macos")]
fn wire_path(path: &Path) -> WireNativeValue {
    use std::os::unix::ffi::OsStrExt;

    WireNativeValue {
        platform: NativePlatform::Macos,
        bytes: path.as_os_str().as_bytes().to_vec(),
        display: path.to_str().map(str::to_owned),
    }
}

#[cfg(windows)]
fn wire_path(path: &Path) -> WireNativeValue {
    use std::os::windows::ffi::OsStrExt;

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
