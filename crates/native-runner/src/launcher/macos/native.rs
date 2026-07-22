use std::{
    collections::BTreeSet,
    ffi::{CStr, CString, OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{Cursor, ErrorKind, Read, Write},
    mem::MaybeUninit,
    os::fd::{AsRawFd, FromRawFd, IntoRawFd},
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        process::CommandExt,
    },
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    ptr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use plist::Value;
use sha2::{Digest, Sha256};

use super::{
    model::{
        GenerationId, GenerationState, MacCodeIdentity, MacCommand, MacCommandPaths,
        MacPolicyError, MacRootIdentity,
    },
    policy::{
        EntitlementSubject, EntitlementValue, GenerationJournal, GenerationLease,
        GenerationProcess, MachOInspection, ProcessOutcome, SignedGeneration,
        validate_macho_closure,
    },
};
use crate::macos_spawn::{
    MacChild, MacProcessGuardian, capture_code_identity, spawn_suspended_verified,
};

const HELPER_NAME: &str = "context-relay-native-helper";
const MAX_PROTOCOL_BYTES: usize = 68 * 1024 * 1024;
const MAX_STDERR_BYTES: usize = 4 * 1024 * 1024;
const MAX_CODESIGN_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_TEMPLATE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_MATERIALS: usize = 64;
const MAX_RUNTIME: Duration = Duration::from_secs(35);
const MAX_CLEANUP_DEPTH: usize = 64;
const MAX_CLEANUP_ENTRIES: usize = 100_000;
const INFO_PLIST: &[u8] = include_bytes!("../../../resources/macos/Info.plist");
const HELPER_ENTITLEMENTS: &[u8] =
    include_bytes!("../../../resources/macos/helper.entitlements.plist");

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacSourceMaterial {
    relative_path: String,
    source: PathBuf,
    size: u64,
    sha256: [u8; 32],
}

impl MacSourceMaterial {
    pub fn new(
        relative_path: impl Into<String>,
        source: PathBuf,
        size: u64,
        sha256: [u8; 32],
    ) -> Result<Self, MacPolicyError> {
        let relative_path = relative_path.into();
        validate_relative_path(&relative_path)?;
        if !source.is_absolute() || size == 0 || size > MAX_TEMPLATE_BYTES {
            return Err(MacPolicyError::InvalidConfiguration);
        }
        Ok(Self {
            relative_path,
            source,
            size,
            sha256,
        })
    }
}

#[derive(Clone, Debug)]
pub struct MacGenerationSpec {
    id: GenerationId,
    private_root: PathBuf,
    helper_template: PathBuf,
    helper_sha256: [u8; 32],
    materials: Vec<MacSourceMaterial>,
    input: Vec<u8>,
    timeout: Duration,
}

impl MacGenerationSpec {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: GenerationId,
        private_root: PathBuf,
        helper_template: PathBuf,
        helper_sha256: [u8; 32],
        materials: Vec<MacSourceMaterial>,
        input: Vec<u8>,
        timeout: Duration,
    ) -> Result<Self, MacPolicyError> {
        if !private_root.is_absolute()
            || !helper_template.is_absolute()
            || materials.len() > MAX_MATERIALS
            || input.is_empty()
            || input.len() > MAX_PROTOCOL_BYTES
            || timeout.is_zero()
            || timeout > MAX_RUNTIME
        {
            return Err(MacPolicyError::InvalidConfiguration);
        }
        let mut paths = BTreeSet::new();
        if materials
            .iter()
            .any(|material| !paths.insert(material.relative_path.as_str()))
        {
            return Err(MacPolicyError::InvalidConfiguration);
        }
        Ok(Self {
            id,
            private_root,
            helper_template,
            helper_sha256,
            materials,
            input,
            timeout,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeMachOInspection {
    pub relative_path: String,
    pub subject: EntitlementSubject,
    pub entitlements: Vec<(String, EntitlementValue)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacRecoveryOutcome {
    Committed,
    Restored,
    Conflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacRecoveryCleanup {
    Cleaned,
    Conflict,
}

#[derive(Clone, Copy, Debug)]
pub struct MacRecoveryIdentity<'a> {
    generation_id: &'a str,
    bundle_id: &'a str,
    guardian_pgid: Option<i32>,
    bundle_root: Option<&'a MacRootIdentity>,
    container_root: Option<&'a MacRootIdentity>,
}

impl<'a> MacRecoveryIdentity<'a> {
    pub const fn new(
        generation_id: &'a str,
        bundle_id: &'a str,
        guardian_pgid: Option<i32>,
        bundle_root: Option<&'a MacRootIdentity>,
        container_root: Option<&'a MacRootIdentity>,
    ) -> Self {
        Self {
            generation_id,
            bundle_id,
            guardian_pgid,
            bundle_root,
            container_root,
        }
    }
}

#[derive(Debug)]
struct HeldDirectory {
    file: File,
    device: u64,
    inode: u64,
    mode: u32,
    identity: MacRootIdentity,
}

#[derive(Debug)]
struct HeldCleanupNode {
    file: File,
    device: u64,
    inode: u64,
    mode: u32,
    links: u64,
}

impl HeldCleanupNode {
    fn open_at(
        parent: &File,
        name: &CStr,
        observed: &libc::stat,
    ) -> Result<Option<Self>, MacPolicyError> {
        let kind = observed.st_mode & libc::S_IFMT;
        if !matches!(kind, libc::S_IFDIR | libc::S_IFREG | libc::S_IFLNK)
            || kind != libc::S_IFDIR && observed.st_nlink != 1
        {
            return Err(MacPolicyError::IdentityMismatch);
        }
        repair_named_metadata(parent, name, observed)?;
        let repaired = stat_named(parent, name)?.ok_or(MacPolicyError::IdentityMismatch)?;
        if !same_stat_identity(observed, &repaired) {
            return Err(MacPolicyError::IdentityMismatch);
        }
        let flags = if kind == libc::S_IFDIR {
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC
        } else if kind == libc::S_IFLNK {
            libc::O_RDONLY | libc::O_SYMLINK | libc::O_CLOEXEC
        } else {
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC
        };
        let descriptor = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
        if descriptor == -1 {
            return match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::ENOENT) => Ok(None),
                _ => Err(MacPolicyError::IdentityMismatch),
            };
        }
        let file = unsafe { File::from_raw_fd(descriptor) };
        let metadata = file.metadata().map_err(|_| MacPolicyError::BundleIo)?;
        let node = Self {
            file,
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            links: metadata.nlink(),
        };
        if node.device != repaired.st_dev as u64
            || node.inode != repaired.st_ino
            || node.mode & libc::S_IFMT as u32 != u32::from(kind)
        {
            return Err(MacPolicyError::IdentityMismatch);
        }
        Ok(Some(node))
    }

    const fn directory(&self) -> bool {
        self.mode & libc::S_IFMT as u32 == libc::S_IFDIR as u32
    }

    const fn symlink(&self) -> bool {
        self.mode & libc::S_IFMT as u32 == libc::S_IFLNK as u32
    }

    fn still_named_by(&self, parent: &File, name: &CStr) -> Result<bool, MacPolicyError> {
        let Some(current) = stat_named(parent, name)? else {
            return Ok(false);
        };
        Ok(self.device == current.st_dev as u64
            && self.inode == current.st_ino
            && self.mode & libc::S_IFMT as u32 == u32::from(current.st_mode & libc::S_IFMT))
    }
}

fn repair_named_metadata(
    parent: &File,
    name: &CStr,
    observed: &libc::stat,
) -> Result<(), MacPolicyError> {
    let current = stat_named(parent, name)?.ok_or(MacPolicyError::IdentityMismatch)?;
    if !same_stat_identity(observed, &current) {
        return Err(MacPolicyError::IdentityMismatch);
    }
    let mut attributes = libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: libc::ATTR_CMN_FLAGS,
        volattr: 0,
        dirattr: 0,
        fileattr: 0,
        forkattr: 0,
    };
    let mut flags = 0_u32;
    if unsafe {
        libc::setattrlistat(
            parent.as_raw_fd(),
            name.as_ptr(),
            (&raw mut attributes).cast(),
            (&raw mut flags).cast(),
            std::mem::size_of_val(&flags),
            libc::FSOPT_NOFOLLOW,
        )
    } != 0
    {
        return Err(MacPolicyError::IdentityMismatch);
    }
    let kind = observed.st_mode & libc::S_IFMT;
    if kind != libc::S_IFLNK {
        let mode = if kind == libc::S_IFDIR { 0o700 } else { 0o600 };
        if unsafe {
            libc::fchmodat(
                parent.as_raw_fd(),
                name.as_ptr(),
                mode,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(MacPolicyError::IdentityMismatch);
        }
    }
    Ok(())
}

fn same_stat_identity(left: &libc::stat, right: &libc::stat) -> bool {
    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && left.st_gen == right.st_gen
        && left.st_birthtime == right.st_birthtime
        && left.st_birthtime_nsec == right.st_birthtime_nsec
        && left.st_mode & libc::S_IFMT == right.st_mode & libc::S_IFMT
}

impl HeldDirectory {
    fn open_at(parent: &File, name: &CStr) -> Result<Option<Self>, MacPolicyError> {
        let descriptor = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor == -1 {
            return match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::ENOENT) => Ok(None),
                _ => Err(MacPolicyError::BundleIo),
            };
        }
        let file = unsafe { File::from_raw_fd(descriptor) };
        let metadata = file.metadata().map_err(|_| MacPolicyError::BundleIo)?;
        if !metadata.file_type().is_dir() {
            return Err(MacPolicyError::BundleIo);
        }
        Ok(Some(Self {
            identity: root_identity(&file)?,
            file,
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
        }))
    }

    fn still_named_by(&self, parent: &File, name: &CStr) -> Result<bool, MacPolicyError> {
        let current = Self::open_at(parent, name)?;
        Ok(current
            .is_some_and(|current| current.device == self.device && current.inode == self.inode))
    }
}

#[derive(Debug)]
struct CleanupTree {
    parent: File,
    name: CString,
    directory: HeldDirectory,
}

impl CleanupTree {
    fn capture(parent: File, name: CString) -> Result<Self, MacPolicyError> {
        let directory = HeldDirectory::open_at(&parent, &name)?.ok_or(MacPolicyError::BundleIo)?;
        Ok(Self {
            parent,
            name,
            directory,
        })
    }

    fn preflight(&self) -> Result<(), MacPolicyError> {
        let mut entries = 0;
        preflight_held_tree(
            &self.parent,
            &self.name,
            &self.directory,
            self.directory.device,
            0,
            &mut entries,
        )
    }

    fn remove_preflighted(self) -> Result<(), MacPolicyError> {
        remove_held_tree(&self.parent, &self.name, &self.directory)
    }

    fn remove(self) -> Result<(), MacPolicyError> {
        self.preflight()?;
        self.remove_preflighted()
    }

    fn capture_matching(
        parent: File,
        name: CString,
        expected: &MacRootIdentity,
        allowed_modes: &[u32],
    ) -> Result<Option<Self>, MacPolicyError> {
        let Some(observed) = stat_named(&parent, &name)? else {
            return Ok(None);
        };
        if observed.st_mode & libc::S_IFMT != libc::S_IFDIR
            || &identity_from_stat(&observed)? != expected
        {
            return Err(MacPolicyError::IdentityMismatch);
        }
        repair_named_metadata(&parent, &name, &observed)?;
        let repaired = stat_named(&parent, &name)?.ok_or(MacPolicyError::IdentityMismatch)?;
        if !same_stat_identity(&observed, &repaired)
            || !allowed_root_mode(u32::from(repaired.st_mode), allowed_modes)
        {
            return Err(MacPolicyError::IdentityMismatch);
        }
        let Some(directory) = HeldDirectory::open_at(&parent, &name)? else {
            return Ok(None);
        };
        if &identity_from_stat(&repaired)? != expected
            || &directory.identity != expected
            || !allowed_root_mode(directory.mode, allowed_modes)
        {
            return Err(MacPolicyError::IdentityMismatch);
        }
        Ok(Some(Self {
            parent,
            name,
            directory,
        }))
    }

    fn identity(&self) -> Result<MacRootIdentity, MacPolicyError> {
        root_identity(&self.directory.file)
    }
}

fn allowed_root_mode(mode: u32, allowed_modes: &[u32]) -> bool {
    allowed_modes.contains(&(mode & 0o7777))
}

fn root_identity(file: &File) -> Result<MacRootIdentity, MacPolicyError> {
    let mut stat = MaybeUninit::<libc::stat>::zeroed();
    if unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(MacPolicyError::BundleIo);
    }
    let stat = unsafe { stat.assume_init() };
    identity_from_stat(&stat)
}

fn identity_from_stat(stat: &libc::stat) -> Result<MacRootIdentity, MacPolicyError> {
    MacRootIdentity::new(
        stat.st_dev as u64,
        stat.st_ino,
        stat.st_gen,
        stat.st_birthtime,
        u32::try_from(stat.st_birthtime_nsec).map_err(|_| MacPolicyError::IdentityMismatch)?,
        u32::from(stat.st_mode),
    )
    .map_err(|_| MacPolicyError::IdentityMismatch)
}

pub fn cleanup_recovered_generation(
    private_root: &Path,
    identity: &MacRecoveryIdentity<'_>,
    state: GenerationState,
    _outcome: MacRecoveryOutcome,
) -> Result<MacRecoveryCleanup, MacPolicyError> {
    if !matches!(state, GenerationState::Retired | GenerationState::Poisoned) {
        return Err(MacPolicyError::InvalidTransition);
    }
    let parsed = GenerationId::parse(identity.bundle_id)?;
    let suffix = parsed
        .as_str()
        .rsplit_once('.')
        .map(|(_, suffix)| suffix)
        .ok_or(MacPolicyError::InvalidGenerationId)?;
    if suffix != identity.generation_id {
        return Err(MacPolicyError::InvalidGenerationId);
    }
    if !recovered_group_is_absent(identity.guardian_pgid)? {
        return Ok(MacRecoveryCleanup::Conflict);
    }
    let (Some(bundle_identity), Some(container_identity)) =
        (identity.bundle_root, identity.container_root)
    else {
        return Ok(MacRecoveryCleanup::Conflict);
    };
    if identity.guardian_pgid.is_none() {
        return Ok(MacRecoveryCleanup::Conflict);
    }
    let root = match validate_private_root(private_root) {
        Ok(root) => root,
        Err(_) => return Ok(MacRecoveryCleanup::Conflict),
    };
    let bundle_parent = match open_absolute_directory(&root) {
        Ok(parent) => parent,
        Err(_) => return Ok(MacRecoveryCleanup::Conflict),
    };
    let bundle_name = c_name(&format!("{}.app", parsed.as_str()))?;
    let container_parent = match open_user_containers_directory() {
        Ok(parent) => parent,
        Err(_) => return Ok(MacRecoveryCleanup::Conflict),
    };
    let container_name = c_name(parsed.as_str())?;

    let bundle = match CleanupTree::capture_matching(
        bundle_parent,
        bundle_name,
        bundle_identity,
        &[0o500, 0o700],
    ) {
        Ok(Some(bundle)) => bundle,
        Ok(None) | Err(MacPolicyError::IdentityMismatch | MacPolicyError::BundleIo) => {
            return Ok(MacRecoveryCleanup::Conflict);
        }
        Err(error) => return Err(error),
    };
    let container = match CleanupTree::capture_matching(
        container_parent,
        container_name,
        container_identity,
        &[0o700],
    ) {
        Ok(Some(container)) => container,
        Ok(None) | Err(MacPolicyError::IdentityMismatch | MacPolicyError::BundleIo) => {
            return Ok(MacRecoveryCleanup::Conflict);
        }
        Err(error) => return Err(error),
    };
    if container.preflight().is_err() || bundle.preflight().is_err() {
        return Ok(MacRecoveryCleanup::Conflict);
    }
    if container.remove_preflighted().is_err() {
        return Ok(MacRecoveryCleanup::Conflict);
    }
    if bundle.remove_preflighted().is_err() {
        return Ok(MacRecoveryCleanup::Conflict);
    }
    Ok(MacRecoveryCleanup::Cleaned)
}

fn recovered_group_is_absent(pgid: Option<i32>) -> Result<bool, MacPolicyError> {
    let Some(pgid) = pgid else {
        return Ok(true);
    };
    if pgid <= 0 {
        return Ok(false);
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if unsafe { libc::kill(-pgid, 0) } != 0 {
            match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::ESRCH) => return Ok(true),
                Some(libc::EPERM) => {}
                _ => return Ok(false),
            }
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        thread::sleep(Duration::from_millis(5));
    }
}

pub struct PreparedGeneration {
    signed: SignedGeneration,
    inspections: Vec<NativeMachOInspection>,
    process: MacGenerationProcess,
}

impl PreparedGeneration {
    pub fn signed_generation(&self) -> &SignedGeneration {
        &self.signed
    }

    pub fn inspections(&self) -> &[NativeMachOInspection] {
        &self.inspections
    }

    pub fn bundle_path(&self) -> &Path {
        &self.process.bundle
    }

    pub fn into_process(self) -> MacGenerationProcess {
        self.process
    }
}

pub fn prepare_generation<J: GenerationJournal>(
    spec: MacGenerationSpec,
    journal: &J,
) -> Result<PreparedGeneration, MacPolicyError> {
    let private_root = validate_private_root(&spec.private_root)?;
    journal.reserve(&spec.id)?;
    let mut lease = GenerationLease::new(spec.id.clone());
    let mut guardian = None;
    let mut bundle_cleanup = None;
    let mut bundle_bound = false;
    let mut stage = "guardian start";

    let prepared = (|| {
        let guardian_directory = open_absolute_directory(&private_root)?;
        let guardian_name = c_name(&format!(".guardian-{}.lease", spec.id.as_str()))?;
        guardian = Some(MacProcessGuardian::start(
            &guardian_directory,
            &guardian_name,
        )?);
        let guardian_ref = guardian.as_mut().ok_or(MacPolicyError::InvalidTransition)?;
        stage = "guardian bind";
        journal.bind_guardian(&spec.id, guardian_ref.pgid())?;
        stage = "helper template verification";
        verify_template(&spec.helper_template, spec.helper_sha256, guardian_ref)?;

        stage = "bundle layout";
        let bundle = private_root.join(format!("{}.app", spec.id.as_str()));
        fs::create_dir(&bundle).map_err(|_| MacPolicyError::BundleIo)?;
        let bundle_name = c_name(&format!("{}.app", spec.id.as_str()))?;
        bundle_cleanup = Some(CleanupTree::capture(
            open_absolute_directory(&private_root)?,
            bundle_name,
        )?);
        let bundle_identity = bundle_cleanup
            .as_ref()
            .ok_or(MacPolicyError::BundleIo)?
            .identity()?;
        journal.bind_bundle_root(&spec.id, &bundle_identity)?;
        bundle_bound = true;
        let bundle_root = &bundle_cleanup
            .as_ref()
            .ok_or(MacPolicyError::BundleIo)?
            .directory
            .file;
        if unsafe { libc::fchmod(bundle_root.as_raw_fd(), 0o700) } != 0 {
            return Err(MacPolicyError::BundleIo);
        }
        let contents = bundle.join("Contents");
        let macos = contents.join("MacOS");
        let helpers_root = contents.join("Helpers");
        let helpers = helpers_root.join("runtime");
        let resources = contents.join("Resources");
        for directory in [&contents, &macos, &helpers_root, &helpers, &resources] {
            create_private_directory(directory)?;
        }

        let helper = macos.join(HELPER_NAME);
        copy_verified(&spec.helper_template, &helper, None, spec.helper_sha256)?;
        if !is_macho(&helper)? {
            return Err(MacPolicyError::InvalidMachOClosure);
        }
        write_info_plist(&contents.join("Info.plist"), &spec.id)?;
        let entitlements = resources.join("helper.entitlements.plist");
        write_new(&entitlements, HELPER_ENTITLEMENTS)?;

        stage = "sidecar material preparation";
        let mut sidecar_machos = Vec::new();
        for material in &spec.materials {
            let destination = helpers.join(&material.relative_path);
            if let Some(parent) = destination.parent() {
                create_private_ancestors(&helpers, parent)?;
            }
            copy_verified(
                &material.source,
                &destination,
                Some(material.size),
                material.sha256,
            )?;
            if is_macho(&destination)? {
                sidecar_machos.push(destination);
            }
        }
        sidecar_machos.sort_by(|left, right| {
            right
                .components()
                .count()
                .cmp(&left.components().count())
                .then_with(|| left.cmp(right))
        });

        for path in &sidecar_machos {
            run_codesign(&MacCommand::sign_sidecar(path_text(path)?)?, guardian_ref)?;
            run_codesign(&MacCommand::verify_path(path_text(path)?)?, guardian_ref)?;
            let values = read_entitlements(path, guardian_ref)?;
            if !values.is_empty() {
                return Err(MacPolicyError::InvalidEntitlements);
            }
            fs::set_permissions(path, fs::Permissions::from_mode(0o500))
                .map_err(|_| MacPolicyError::BundleIo)?;
        }

        stage = "generation signing";
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o500))
            .map_err(|_| MacPolicyError::BundleIo)?;
        let command_paths = MacCommandPaths::new(
            path_text(&bundle)?,
            path_text(&helper)?,
            path_text(&entitlements)?,
        )?;
        run_codesign(
            &MacCommand::sign_generation(&command_paths, &spec.id),
            guardian_ref,
        )?;
        run_codesign(&MacCommand::verify_strict(&command_paths), guardian_ref)?;
        verify_identity_and_runtime(&command_paths, &spec.id, guardian_ref)?;

        stage = "Mach-O closure validation";
        let mut actual_machos = enumerate_machos(&bundle)?;
        actual_machos.sort();
        let helper_relative = relative_text(&bundle, &helper)?;
        let expected = actual_machos.iter().map(String::as_str).collect::<Vec<_>>();
        let mut policy_inspections = Vec::with_capacity(actual_machos.len());
        let mut inspections = Vec::with_capacity(actual_machos.len());
        for relative in &actual_machos {
            let path = bundle.join(relative);
            run_codesign(&MacCommand::verify_path(path_text(&path)?)?, guardian_ref)?;
            let entitlements = if relative == &helper_relative {
                read_entitlements_command(
                    &MacCommand::display_entitlements(&command_paths),
                    guardian_ref,
                )?
            } else {
                read_entitlements(&path, guardian_ref)?
            };
            let subject = if relative == &helper_relative {
                EntitlementSubject::Helper
            } else {
                EntitlementSubject::Sidecar
            };
            policy_inspections.push(MachOInspection {
                relative_path: relative.clone(),
                signed: true,
                entitlements: entitlements.clone(),
            });
            inspections.push(NativeMachOInspection {
                relative_path: relative.clone(),
                subject,
                entitlements,
            });
        }
        validate_macho_closure(&helper_relative, &expected, &policy_inspections)?;
        stage = "bundle freeze";
        freeze_tree(&bundle)?;
        let signed_sha256 = generation_digest(&bundle)?;
        stage = "container preflight";
        let container_parent = open_user_containers_directory()?;
        let container_name = c_name(spec.id.as_str())?;
        if HeldDirectory::open_at(&container_parent, &container_name)?.is_some() {
            return Err(MacPolicyError::InvalidTransition);
        }
        stage = "helper code identity";
        let helper_file = open_verified_executable(&helper)?;
        let helper_code_identity = capture_code_identity(&helper_file, &helper)?;
        let signed = SignedGeneration::new(spec.id.clone(), signed_sha256, bundle_identity);
        stage = "journal finalize";
        journal.finalize(&signed)?;

        Ok(PreparedGeneration {
            signed,
            inspections,
            process: MacGenerationProcess::new(
                bundle,
                helper,
                helper_file,
                helper_code_identity,
                spec.input,
                spec.timeout,
                bundle_cleanup.take().ok_or(MacPolicyError::BundleIo)?,
                container_parent,
                container_name,
                guardian.take().ok_or(MacPolicyError::ProcessFailed)?,
            ),
        })
    })();

    match prepared {
        Ok(prepared) => Ok(prepared),
        Err(original) => {
            #[cfg(debug_assertions)]
            eprintln!("macOS generation preparation failed at {stage}: {original:?}");
            let poison = journal.transition(
                &spec.id,
                GenerationState::Prepared,
                GenerationState::Poisoned,
            );
            if poison.is_ok() {
                let _ = lease.poison();
            }
            let termination = if let Some(guardian) = guardian.as_mut() {
                let pgid = guardian.pgid();
                guardian
                    .kill_group_and_reap()
                    .and_then(|()| wait_for_process_group_exit(pgid))
            } else {
                Ok(())
            };
            let cleanup = if poison.is_ok() && termination.is_ok() && bundle_bound {
                bundle_cleanup
                    .take()
                    .ok_or(MacPolicyError::BundleIo)?
                    .remove()
            } else {
                Ok(())
            };
            poison?;
            termination?;
            cleanup?;
            Err(original)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacProcessOutput {
    exit_code: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl MacProcessOutput {
    pub const fn exit_code(&self) -> i32 {
        self.exit_code
    }

    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }
}

pub struct MacGenerationProcess {
    bundle: PathBuf,
    helper: PathBuf,
    _helper_file: File,
    helper_code_identity: MacCodeIdentity,
    bundle_cleanup: Option<CleanupTree>,
    container_parent: Option<File>,
    container_name: CString,
    container_directory: Option<HeldDirectory>,
    container_bound: bool,
    input: Option<Vec<u8>>,
    timeout: Duration,
    child: Option<MacChild>,
    guardian: Option<MacProcessGuardian>,
    pgid: Option<libc::pid_t>,
    writer: Option<JoinHandle<Result<(), MacPolicyError>>>,
    stdout: Option<JoinHandle<Result<Vec<u8>, MacPolicyError>>>,
    stderr: Option<JoinHandle<Result<Vec<u8>, MacPolicyError>>>,
    spawn_attempted: bool,
    resumed: bool,
    io_started: bool,
    io_cancelled: Arc<AtomicBool>,
    finished: bool,
    cleaned: bool,
}

impl MacGenerationProcess {
    #[allow(clippy::too_many_arguments)]
    fn new(
        bundle: PathBuf,
        helper: PathBuf,
        helper_file: File,
        helper_code_identity: MacCodeIdentity,
        input: Vec<u8>,
        timeout: Duration,
        bundle_cleanup: CleanupTree,
        container_parent: File,
        container_name: CString,
        guardian: MacProcessGuardian,
    ) -> Self {
        let pgid = guardian.pgid();
        Self {
            bundle,
            helper,
            _helper_file: helper_file,
            helper_code_identity,
            bundle_cleanup: Some(bundle_cleanup),
            container_parent: Some(container_parent),
            container_name,
            container_directory: None,
            container_bound: false,
            input: Some(input),
            timeout,
            child: None,
            guardian: Some(guardian),
            pgid: Some(pgid),
            writer: None,
            stdout: None,
            stderr: None,
            spawn_attempted: false,
            resumed: false,
            io_started: false,
            io_cancelled: Arc::new(AtomicBool::new(false)),
            finished: false,
            cleaned: false,
        }
    }

    fn capture_container(&mut self) -> Result<MacRootIdentity, MacPolicyError> {
        let parent = self
            .container_parent
            .as_ref()
            .ok_or(MacPolicyError::InvalidTransition)?;
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(directory) = HeldDirectory::open_at(parent, &self.container_name)? {
                let identity = directory.identity.clone();
                self.container_directory = Some(directory);
                return Ok(identity);
            }
            if Instant::now() >= deadline {
                return Err(MacPolicyError::BundleIo);
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn start_io(&mut self) -> Result<(), MacPolicyError> {
        let child = self.child.as_mut().ok_or(MacPolicyError::ProcessFailed)?;
        let mut stdin = child.take_stdin().ok_or(MacPolicyError::ProtocolIo)?;
        let stdout = child.take_stdout().ok_or(MacPolicyError::ProtocolIo)?;
        let stderr = child.take_stderr().ok_or(MacPolicyError::ProtocolIo)?;
        let input = self.input.take().ok_or(MacPolicyError::ProtocolIo)?;
        for file in [&stdin, &stdout, &stderr] {
            set_nonblocking(file)?;
        }
        let stdout_cancelled = Arc::clone(&self.io_cancelled);
        self.stdout = Some(thread::spawn(move || {
            drain_bounded_cancellable(stdout, MAX_PROTOCOL_BYTES, &stdout_cancelled)
        }));
        let stderr_cancelled = Arc::clone(&self.io_cancelled);
        self.stderr = Some(thread::spawn(move || {
            drain_bounded_cancellable(stderr, MAX_STDERR_BYTES, &stderr_cancelled)
        }));
        let writer_cancelled = Arc::clone(&self.io_cancelled);
        self.writer = Some(thread::spawn(move || {
            write_all_cancellable(&mut stdin, &input, &writer_cancelled)
        }));
        self.io_started = true;
        Ok(())
    }

    fn collect_io(&mut self) -> Result<(Vec<u8>, Vec<u8>), MacPolicyError> {
        join(self.writer.take())??;
        let stdout = join(self.stdout.take())??;
        let stderr = join(self.stderr.take())??;
        Ok((stdout, stderr))
    }
}

impl GenerationProcess for MacGenerationProcess {
    type Output = MacProcessOutput;

    fn spawn_suspended(&mut self) -> Result<MacRootIdentity, MacPolicyError> {
        if self.spawn_attempted {
            #[cfg(debug_assertions)]
            eprintln!("macOS suspended spawn preflight failed: repeated attempt");
            return Err(MacPolicyError::InvalidTransition);
        }
        self.spawn_attempted = true;
        let Some(container_parent) = self.container_parent.as_ref() else {
            #[cfg(debug_assertions)]
            eprintln!("macOS suspended spawn preflight failed: missing container parent");
            return Err(MacPolicyError::InvalidTransition);
        };
        match HeldDirectory::open_at(container_parent, &self.container_name) {
            Ok(None) => {}
            Ok(Some(_)) => {
                #[cfg(debug_assertions)]
                eprintln!("macOS suspended spawn preflight failed: container already exists");
                return Err(MacPolicyError::InvalidTransition);
            }
            Err(error) => {
                #[cfg(debug_assertions)]
                eprintln!("macOS suspended spawn preflight failed: container lookup: {error:?}");
                return Err(error);
            }
        }
        let runtime = self.bundle.join("Contents/Helpers/runtime");
        let environment = [
            (OsStr::new("LANG"), OsStr::new("C")),
            (OsStr::new("LC_ALL"), OsStr::new("C")),
            (OsStr::new("PATH"), runtime.as_os_str()),
        ];
        let guardian = self
            .guardian
            .as_mut()
            .ok_or(MacPolicyError::InvalidTransition)?;
        let pgid = guardian.pgid();
        let child = spawn_suspended_verified(
            &self.helper,
            &[],
            &environment,
            None,
            Some(pgid),
            &self.helper_code_identity,
        )
        .inspect_err(|_error| {
            #[cfg(debug_assertions)]
            eprintln!("macOS suspended spawn verification failed: {_error:?}");
        })?;
        guardian.ensure_alive().inspect_err(|_error| {
            #[cfg(debug_assertions)]
            eprintln!("macOS spawn guardian check failed: {_error:?}");
        })?;
        self.child = Some(child);
        self.child
            .as_mut()
            .ok_or(MacPolicyError::ProcessFailed)?
            .resume()?;
        let container_identity = self.capture_container().inspect_err(|_error| {
            #[cfg(debug_assertions)]
            eprintln!("macOS suspended container capture failed: {_error:?}");
        })?;
        self.child
            .as_mut()
            .ok_or(MacPolicyError::ProcessFailed)?
            .suspend_and_verify(&self.helper_code_identity)
            .inspect_err(|_error| {
                #[cfg(debug_assertions)]
                eprintln!("macOS container bootstrap suspension failed: {_error:?}");
            })?;
        self.guardian
            .as_mut()
            .ok_or(MacPolicyError::InvalidTransition)?
            .ensure_alive()
            .inspect_err(|_error| {
                #[cfg(debug_assertions)]
                eprintln!("macOS container bootstrap guardian check failed: {_error:?}");
            })?;
        Ok(container_identity)
    }

    fn confirm_container_bound(&mut self) {
        self.container_bound = self.container_directory.is_some();
    }

    fn resume_and_send_input(&mut self) -> Result<(), MacPolicyError> {
        if self.resumed || self.finished || self.container_directory.is_none() {
            return Err(MacPolicyError::InvalidTransition);
        }
        self.guardian
            .as_mut()
            .ok_or(MacPolicyError::ProcessFailed)?
            .ensure_alive()?;
        self.child
            .as_mut()
            .ok_or(MacPolicyError::ProcessFailed)?
            .resume()?;
        self.resumed = true;
        self.start_io()
    }

    fn wait(&mut self) -> ProcessOutcome<Self::Output> {
        if !self.resumed {
            return ProcessOutcome::Abnormal(MacPolicyError::InvalidTransition);
        }
        let started = Instant::now();
        let succeeded = loop {
            let Some(child_pid) = self.child.as_ref().map(MacChild::pid) else {
                return ProcessOutcome::Abnormal(MacPolicyError::ProcessFailed);
            };
            match child_exit_succeeded(child_pid) {
                Ok(Some(succeeded)) => break succeeded,
                Ok(None) if started.elapsed() < self.timeout => {
                    thread::sleep(Duration::from_millis(5));
                }
                Ok(None) => return ProcessOutcome::Abnormal(MacPolicyError::ProcessTimedOut),
                Err(error) => return ProcessOutcome::Abnormal(error),
            }
        };
        let (stdout, stderr) = match self.finish_original_group() {
            Ok(output) => output,
            Err(error) => return ProcessOutcome::Abnormal(error),
        };
        if succeeded {
            ProcessOutcome::Completed(MacProcessOutput {
                exit_code: 0,
                stdout,
                stderr,
            })
        } else {
            ProcessOutcome::Abnormal(MacPolicyError::ProcessFailed)
        }
    }

    fn terminate_original_group(&mut self) -> Result<(), MacPolicyError> {
        self.finish_original_group().map(|_| ())
    }

    fn cleanup_terminal(&mut self) -> Result<(), MacPolicyError> {
        if !self.finished {
            return Err(MacPolicyError::InvalidTransition);
        }
        if self.cleaned {
            return Ok(());
        }
        let container_parent = self
            .container_parent
            .as_ref()
            .ok_or(MacPolicyError::InvalidTransition)?;
        if self.container_bound {
            let container = self
                .container_directory
                .as_ref()
                .ok_or(MacPolicyError::InvalidTransition)?;
            let mut entries = 0;
            preflight_held_tree(
                container_parent,
                &self.container_name,
                container,
                container.device,
                0,
                &mut entries,
            )?;
        }
        self.bundle_cleanup
            .as_ref()
            .ok_or(MacPolicyError::InvalidTransition)?
            .preflight()?;

        let container_parent = self
            .container_parent
            .take()
            .ok_or(MacPolicyError::InvalidTransition)?;
        let container = self.container_directory.take();
        if self.container_bound
            && let Some(container) = container
        {
            remove_held_tree(&container_parent, &self.container_name, &container)?;
        }
        self.bundle_cleanup
            .take()
            .ok_or(MacPolicyError::InvalidTransition)?
            .remove_preflighted()?;
        self.cleaned = true;
        Ok(())
    }
}

impl Drop for MacGenerationProcess {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.terminate_original_group();
        }
    }
}

impl MacGenerationProcess {
    fn finish_original_group(&mut self) -> Result<(Vec<u8>, Vec<u8>), MacPolicyError> {
        if self.finished {
            return Ok((Vec::new(), Vec::new()));
        }
        let Some(pgid) = self.pgid else {
            if self.child.is_some() {
                return Err(MacPolicyError::ProcessFailed);
            }
            self.finished = true;
            return Ok((Vec::new(), Vec::new()));
        };
        let group_result = self
            .guardian
            .as_mut()
            .ok_or(MacPolicyError::ProcessFailed)?
            .kill_group_and_reap();
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.io_cancelled.store(true, Ordering::Release);
        let output = if self.io_started {
            self.collect_io()
        } else {
            if let Some(child) = self.child.as_mut() {
                child.take_stdin();
                child.take_stdout();
                child.take_stderr();
            }
            self.input.take();
            Ok((Vec::new(), Vec::new()))
        };
        let group_result = group_result.and_then(|()| wait_for_process_group_exit(pgid));
        if group_result.is_ok() {
            self.finished = true;
        }
        group_result?;
        output
    }
}

fn child_exit_succeeded(pgid: libc::pid_t) -> Result<Option<bool>, MacPolicyError> {
    let mut info = MaybeUninit::<libc::siginfo_t>::zeroed();
    // WNOWAIT keeps the group leader as the exact PID anchor until SIGKILL is sent.
    if unsafe {
        libc::waitid(
            libc::P_PID,
            u32::try_from(pgid).map_err(|_| MacPolicyError::ProcessFailed)?,
            info.as_mut_ptr(),
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    } != 0
    {
        return Err(MacPolicyError::ProcessFailed);
    }
    let info = unsafe { info.assume_init() };
    if info.si_pid == 0 {
        return Ok(None);
    }
    if info.si_pid != pgid {
        return Err(MacPolicyError::ProcessFailed);
    }
    Ok(Some(
        info.si_code == libc::CLD_EXITED && info.si_status == 0,
    ))
}

fn wait_for_process_group_exit(pgid: libc::pid_t) -> Result<(), MacPolicyError> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if unsafe { libc::kill(-pgid, 0) } != 0 {
            match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::ESRCH) => return Ok(()),
                Some(libc::EPERM) => {}
                _ => return Err(MacPolicyError::ProcessFailed),
            }
        }
        if Instant::now() >= deadline {
            return Err(MacPolicyError::ProcessFailed);
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn verify_template(
    path: &Path,
    expected_sha256: [u8; 32],
    guardian: &mut MacProcessGuardian,
) -> Result<(), MacPolicyError> {
    copy_digest(path, None, None, expected_sha256).map(|_| ())?;
    if !is_macho(path)? {
        return Err(MacPolicyError::TemplateMismatch);
    }
    run_codesign(&MacCommand::verify_path(path_text(path)?)?, guardian)?;
    let entitlements = read_entitlements(path, guardian)?;
    if entitlements
        != [(
            "com.apple.security.app-sandbox".into(),
            EntitlementValue::Boolean(true),
        )]
    {
        return Err(MacPolicyError::InvalidEntitlements);
    }
    Ok(())
}

fn validate_private_root(path: &Path) -> Result<PathBuf, MacPolicyError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| MacPolicyError::InvalidConfiguration)?;
    if !metadata.file_type().is_dir() || metadata.mode() & 0o077 != 0 {
        return Err(MacPolicyError::InvalidConfiguration);
    }
    let canonical = fs::canonicalize(path).map_err(|_| MacPolicyError::InvalidConfiguration)?;
    if canonical != path {
        return Err(MacPolicyError::InvalidConfiguration);
    }
    path_text(&canonical)?;
    Ok(canonical)
}

fn c_name(value: &str) -> Result<CString, MacPolicyError> {
    if value.is_empty() || value.contains('/') {
        return Err(MacPolicyError::InvalidGenerationId);
    }
    CString::new(value.as_bytes()).map_err(|_| MacPolicyError::InvalidGenerationId)
}

fn account_home() -> Result<PathBuf, MacPolicyError> {
    let mut record = MaybeUninit::<libc::passwd>::uninit();
    let mut result = ptr::null_mut();
    let requested = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let size = if requested > 0 {
        usize::try_from(requested).unwrap_or(16 * 1024)
    } else {
        16 * 1024
    }
    .clamp(16 * 1024, 1024 * 1024);
    let mut buffer = vec![0_u8; size];
    let status = unsafe {
        libc::getpwuid_r(
            libc::geteuid(),
            record.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 || result.is_null() {
        return Err(MacPolicyError::InvalidConfiguration);
    }
    let home = unsafe { CStr::from_ptr((*result).pw_dir) };
    let path = PathBuf::from(OsString::from_vec(home.to_bytes().to_vec()));
    if !path.is_absolute() {
        return Err(MacPolicyError::InvalidConfiguration);
    }
    Ok(path)
}

fn open_user_containers_directory() -> Result<File, MacPolicyError> {
    open_absolute_directory(&account_home()?.join("Library/Containers"))
}

fn open_absolute_directory(path: &Path) -> Result<File, MacPolicyError> {
    if !path.is_absolute() {
        return Err(MacPolicyError::InvalidConfiguration);
    }
    let root = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if root == -1 {
        return Err(MacPolicyError::BundleIo);
    }
    let mut directory = unsafe { File::from_raw_fd(root) };
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                let name = CString::new(name.as_bytes()).map_err(|_| MacPolicyError::BundleIo)?;
                directory = HeldDirectory::open_at(&directory, &name)?
                    .ok_or(MacPolicyError::BundleIo)?
                    .file;
            }
            _ => return Err(MacPolicyError::InvalidConfiguration),
        }
    }
    Ok(directory)
}

fn remove_held_tree(
    parent: &File,
    name: &CStr,
    directory: &HeldDirectory,
) -> Result<(), MacPolicyError> {
    let mut entries = 0;
    remove_held_tree_inner(parent, name, directory, directory.device, 0, &mut entries)
}

fn preflight_held_tree(
    parent: &File,
    name: &CStr,
    directory: &HeldDirectory,
    tree_device: u64,
    depth: usize,
    entries: &mut usize,
) -> Result<(), MacPolicyError> {
    if directory.device != tree_device || !directory.still_named_by(parent, name)? {
        return Err(MacPolicyError::IdentityMismatch);
    }
    preflight_directory_contents(&directory.file, tree_device, depth, entries)?;
    if !directory.still_named_by(parent, name)? {
        return Err(MacPolicyError::IdentityMismatch);
    }
    Ok(())
}

fn preflight_directory_contents(
    directory: &File,
    tree_device: u64,
    depth: usize,
    entries: &mut usize,
) -> Result<(), MacPolicyError> {
    let metadata = directory.metadata().map_err(|_| MacPolicyError::BundleIo)?;
    if depth > MAX_CLEANUP_DEPTH
        || metadata.dev() != tree_device
        || !metadata.file_type().is_dir()
        || unsafe { libc::fchflags(directory.as_raw_fd(), 0) } != 0
        || unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } != 0
    {
        return Err(MacPolicyError::IdentityMismatch);
    }
    for name in read_directory_names(directory, entries)? {
        let Some(observed) = stat_named(directory, &name)? else {
            continue;
        };
        if observed.st_dev as u64 != tree_device {
            return Err(MacPolicyError::IdentityMismatch);
        }
        let Some(child) = HeldCleanupNode::open_at(directory, &name, &observed)? else {
            return Err(MacPolicyError::IdentityMismatch);
        };
        if child.device != tree_device || (!child.directory() && child.links != 1) {
            return Err(MacPolicyError::IdentityMismatch);
        }
        if child.directory() {
            if !child.still_named_by(directory, &name)? {
                return Err(MacPolicyError::IdentityMismatch);
            }
            let held = HeldDirectory {
                identity: root_identity(&child.file)?,
                file: child.file,
                device: child.device,
                inode: child.inode,
                mode: child.mode,
            };
            preflight_held_tree(directory, &name, &held, tree_device, depth + 1, entries)?;
        } else if !child.still_named_by(directory, &name)? {
            return Err(MacPolicyError::IdentityMismatch);
        }
    }
    Ok(())
}

fn remove_held_tree_inner(
    parent: &File,
    name: &CStr,
    directory: &HeldDirectory,
    tree_device: u64,
    depth: usize,
    entries: &mut usize,
) -> Result<(), MacPolicyError> {
    if directory.device != tree_device || !directory.still_named_by(parent, name)? {
        return Err(MacPolicyError::BundleIo);
    }
    remove_directory_contents(&directory.file, tree_device, depth, entries)?;
    if !directory.still_named_by(parent, name)? {
        return Err(MacPolicyError::BundleIo);
    }
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(MacPolicyError::BundleIo);
    }
    sync_directory(parent)
}

fn remove_directory_contents(
    directory: &File,
    tree_device: u64,
    depth: usize,
    entries: &mut usize,
) -> Result<(), MacPolicyError> {
    let metadata = directory.metadata().map_err(|_| MacPolicyError::BundleIo)?;
    if depth > MAX_CLEANUP_DEPTH
        || metadata.dev() != tree_device
        || !metadata.file_type().is_dir()
        || unsafe { libc::fchflags(directory.as_raw_fd(), 0) } != 0
        || unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } != 0
    {
        return Err(MacPolicyError::BundleIo);
    }
    for name in read_directory_names(directory, entries)? {
        let Some(observed) = stat_named(directory, &name)? else {
            continue;
        };
        if observed.st_dev as u64 != tree_device {
            return Err(MacPolicyError::BundleIo);
        }
        let Some(child) = HeldCleanupNode::open_at(directory, &name, &observed)? else {
            continue;
        };
        if child.device != tree_device || (!child.directory() && child.links != 1) {
            return Err(MacPolicyError::BundleIo);
        }
        if unsafe { libc::fchflags(child.file.as_raw_fd(), 0) } != 0 {
            return Err(MacPolicyError::BundleIo);
        }
        if child.directory() {
            if unsafe { libc::fchmod(child.file.as_raw_fd(), 0o700) } != 0
                || !child.still_named_by(directory, &name)?
            {
                return Err(MacPolicyError::BundleIo);
            }
            let held = HeldDirectory {
                identity: root_identity(&child.file)?,
                file: child.file,
                device: child.device,
                inode: child.inode,
                mode: child.mode,
            };
            remove_held_tree_inner(directory, &name, &held, tree_device, depth + 1, entries)?;
        } else {
            if !child.symlink() && unsafe { libc::fchmod(child.file.as_raw_fd(), 0o600) } != 0 {
                return Err(MacPolicyError::BundleIo);
            }
            if !child.still_named_by(directory, &name)? {
                return Err(MacPolicyError::BundleIo);
            }
            if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0
                && std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT)
            {
                return Err(MacPolicyError::BundleIo);
            }
        }
    }
    sync_directory(directory)
}

fn stat_named(parent: &File, name: &CStr) -> Result<Option<libc::stat>, MacPolicyError> {
    let mut metadata = MaybeUninit::<libc::stat>::zeroed();
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0
    {
        return Ok(Some(unsafe { metadata.assume_init() }));
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ENOENT) => Ok(None),
        _ => Err(MacPolicyError::BundleIo),
    }
}

struct DirectoryStream(*mut libc::DIR);

impl Drop for DirectoryStream {
    fn drop(&mut self) {
        unsafe {
            libc::closedir(self.0);
        }
    }
}

fn read_directory_names(
    directory: &File,
    entries: &mut usize,
) -> Result<Vec<CString>, MacPolicyError> {
    let held = directory.metadata().map_err(|_| MacPolicyError::BundleIo)?;
    let reopened = HeldDirectory::open_at(directory, c".")?.ok_or(MacPolicyError::BundleIo)?;
    if reopened.device != held.dev() || reopened.inode != held.ino() {
        return Err(MacPolicyError::BundleIo);
    }
    let reopened = reopened.file.into_raw_fd();
    let stream = unsafe { libc::fdopendir(reopened) };
    if stream.is_null() {
        unsafe {
            libc::close(reopened);
        }
        return Err(MacPolicyError::BundleIo);
    }
    let stream = DirectoryStream(stream);
    let mut names = Vec::new();
    loop {
        unsafe {
            *libc::__error() = 0;
        }
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            if unsafe { *libc::__error() } == 0 {
                break;
            }
            return Err(MacPolicyError::BundleIo);
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        *entries = entries.checked_add(1).ok_or(MacPolicyError::BundleIo)?;
        if *entries > MAX_CLEANUP_ENTRIES {
            return Err(MacPolicyError::BundleIo);
        }
        names.push(name.to_owned());
    }
    Ok(names)
}

fn sync_directory(directory: &File) -> Result<(), MacPolicyError> {
    if unsafe { libc::fsync(directory.as_raw_fd()) } == 0
        || std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL)
    {
        Ok(())
    } else {
        Err(MacPolicyError::BundleIo)
    }
}

fn create_private_directory(path: &Path) -> Result<(), MacPolicyError> {
    fs::create_dir(path).map_err(|_| MacPolicyError::BundleIo)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| MacPolicyError::BundleIo)
}

fn create_private_ancestors(base: &Path, target: &Path) -> Result<(), MacPolicyError> {
    let relative = target
        .strip_prefix(base)
        .map_err(|_| MacPolicyError::InvalidConfiguration)?;
    let mut current = base.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(MacPolicyError::InvalidConfiguration);
        };
        current.push(component);
        match fs::create_dir(&current) {
            Ok(()) => fs::set_permissions(&current, fs::Permissions::from_mode(0o700))
                .map_err(|_| MacPolicyError::BundleIo)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let metadata =
                    fs::symlink_metadata(&current).map_err(|_| MacPolicyError::BundleIo)?;
                if !metadata.file_type().is_dir() {
                    return Err(MacPolicyError::BundleIo);
                }
            }
            Err(_) => return Err(MacPolicyError::BundleIo),
        }
    }
    Ok(())
}

fn write_info_plist(path: &Path, id: &GenerationId) -> Result<(), MacPolicyError> {
    const PLACEHOLDER: &str = "__CONTEXT_RELAY_GENERATION_ID__";
    let template = std::str::from_utf8(INFO_PLIST).map_err(|_| MacPolicyError::BundleIo)?;
    if template.matches(PLACEHOLDER).count() != 1 {
        return Err(MacPolicyError::BundleIo);
    }
    write_new(path, template.replace(PLACEHOLDER, id.as_str()).as_bytes())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), MacPolicyError> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options.open(path).map_err(|_| MacPolicyError::BundleIo)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| MacPolicyError::BundleIo)
}

fn copy_verified(
    source: &Path,
    destination: &Path,
    expected_size: Option<u64>,
    expected_sha256: [u8; 32],
) -> Result<(), MacPolicyError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let source_file = options
        .open(source)
        .map_err(|_| MacPolicyError::TemplateMismatch)?;
    copy_digest(
        source,
        Some(source_file),
        Some(destination),
        expected_sha256,
    )?;
    if expected_size
        .is_some_and(|size| !fs::metadata(destination).is_ok_and(|metadata| metadata.len() == size))
    {
        return Err(MacPolicyError::TemplateMismatch);
    }
    Ok(())
}

fn open_verified_executable(path: &Path) -> Result<File, MacPolicyError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .map_err(|_| MacPolicyError::IdentityMismatch)?;
    let metadata = file
        .metadata()
        .map_err(|_| MacPolicyError::IdentityMismatch)?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return Err(MacPolicyError::IdentityMismatch);
    }
    Ok(file)
}

fn copy_digest(
    source_path: &Path,
    source: Option<File>,
    destination: Option<&Path>,
    expected_sha256: [u8; 32],
) -> Result<[u8; 32], MacPolicyError> {
    let mut source = match source {
        Some(file) => file,
        None => {
            let mut options = OpenOptions::new();
            options
                .read(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
            options
                .open(source_path)
                .map_err(|_| MacPolicyError::TemplateMismatch)?
        }
    };
    let metadata = source
        .metadata()
        .map_err(|_| MacPolicyError::TemplateMismatch)?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > MAX_TEMPLATE_BYTES
    {
        return Err(MacPolicyError::TemplateMismatch);
    }
    let mut destination = destination
        .map(|path| {
            let mut options = OpenOptions::new();
            options
                .write(true)
                .create_new(true)
                .mode(0o700)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
            options.open(path).map_err(|_| MacPolicyError::BundleIo)
        })
        .transpose()?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = source
            .read(&mut buffer)
            .map_err(|_| MacPolicyError::TemplateMismatch)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        if let Some(file) = destination.as_mut() {
            file.write_all(&buffer[..count])
                .map_err(|_| MacPolicyError::BundleIo)?;
        }
    }
    if let Some(file) = destination.as_mut() {
        file.sync_all().map_err(|_| MacPolicyError::BundleIo)?;
    }
    let digest: [u8; 32] = hasher.finalize().into();
    if digest != expected_sha256 {
        return Err(MacPolicyError::TemplateMismatch);
    }
    Ok(digest)
}

fn run_codesign(
    command: &MacCommand,
    guardian: &mut MacProcessGuardian,
) -> Result<Vec<u8>, MacPolicyError> {
    guardian.ensure_alive()?;
    let mut process = Command::new(command.program());
    process
        .args(command.arguments())
        .env_clear()
        .stdin(Stdio::null())
        .process_group(guardian.pgid());
    let output = process
        .output()
        .map_err(|_| MacPolicyError::CodeSignFailed)?;
    guardian.ensure_alive()?;
    if !output.status.success()
        || output.stdout.len() > MAX_CODESIGN_OUTPUT_BYTES
        || output.stderr.len() > MAX_CODESIGN_OUTPUT_BYTES
    {
        return Err(MacPolicyError::CodeSignFailed);
    }
    let mut bytes = output.stdout;
    bytes.extend_from_slice(&output.stderr);
    Ok(bytes)
}

fn read_entitlements(
    path: &Path,
    guardian: &mut MacProcessGuardian,
) -> Result<Vec<(String, EntitlementValue)>, MacPolicyError> {
    let command = MacCommand::display_path_entitlements(path_text(path)?)?;
    read_entitlements_command(&command, guardian)
}

fn read_entitlements_command(
    command: &MacCommand,
    guardian: &mut MacProcessGuardian,
) -> Result<Vec<(String, EntitlementValue)>, MacPolicyError> {
    let output = run_codesign(command, guardian)?;
    let Some(start) = find_bytes(&output, b"<?xml") else {
        return Ok(Vec::new());
    };
    let end_marker = b"</plist>";
    let end = find_bytes(&output[start..], end_marker)
        .map(|index| start + index + end_marker.len())
        .ok_or(MacPolicyError::InvalidEntitlements)?;
    let value = Value::from_reader_xml(Cursor::new(&output[start..end]))
        .map_err(|_| MacPolicyError::InvalidEntitlements)?;
    let dictionary = value
        .into_dictionary()
        .ok_or(MacPolicyError::InvalidEntitlements)?;
    let mut entries = dictionary
        .into_iter()
        .map(|(key, value)| {
            let value = match value {
                Value::Boolean(value) => EntitlementValue::Boolean(value),
                _ => EntitlementValue::Other,
            };
            (key, value)
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(entries)
}

fn verify_identity_and_runtime(
    paths: &MacCommandPaths,
    id: &GenerationId,
    guardian: &mut MacProcessGuardian,
) -> Result<(), MacPolicyError> {
    let output = run_codesign(&MacCommand::display_identity(paths), guardian)?;
    let output = std::str::from_utf8(&output).map_err(|_| MacPolicyError::IdentityMismatch)?;
    let expected = format!("Identifier={}", id.as_str());
    if output
        .lines()
        .filter(|line| line.trim() == expected)
        .count()
        != 1
        || !output
            .lines()
            .any(|line| line.contains("CodeDirectory") && line.contains("runtime"))
    {
        return Err(MacPolicyError::IdentityMismatch);
    }
    Ok(())
}

fn enumerate_machos(root: &Path) -> Result<Vec<String>, MacPolicyError> {
    let mut files = enumerate_files(root)?;
    files.retain(|relative| is_macho(&root.join(relative)).unwrap_or(false));
    Ok(files)
}

fn enumerate_files(root: &Path) -> Result<Vec<String>, MacPolicyError> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).map_err(|_| MacPolicyError::BundleIo)? {
            let entry = entry.map_err(|_| MacPolicyError::BundleIo)?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|_| MacPolicyError::BundleIo)?;
            if metadata.file_type().is_dir() {
                pending.push(path);
            } else if metadata.file_type().is_file() && metadata.nlink() == 1 {
                files.push(relative_text(root, &path)?);
            } else {
                return Err(MacPolicyError::InvalidMachOClosure);
            }
        }
    }
    files.sort();
    Ok(files)
}

fn generation_digest(root: &Path) -> Result<[u8; 32], MacPolicyError> {
    let mut hasher = Sha256::new();
    hasher.update(b"context-relay/macos-signed-generation/v1\0");
    for relative in enumerate_files(root)? {
        let bytes = fs::read(root.join(&relative)).map_err(|_| MacPolicyError::BundleIo)?;
        hasher.update((relative.len() as u64).to_be_bytes());
        hasher.update(relative.as_bytes());
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(Sha256::digest(&bytes));
    }
    Ok(hasher.finalize().into())
}

fn freeze_tree(root: &Path) -> Result<(), MacPolicyError> {
    for relative in enumerate_files(root)? {
        let path = root.join(relative);
        let mode = if is_macho(&path)? { 0o500 } else { 0o400 };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|_| MacPolicyError::BundleIo)?;
    }
    let mut directories = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        directories.push(directory.clone());
        for entry in fs::read_dir(directory).map_err(|_| MacPolicyError::BundleIo)? {
            let path = entry.map_err(|_| MacPolicyError::BundleIo)?.path();
            if fs::symlink_metadata(&path)
                .map_err(|_| MacPolicyError::BundleIo)?
                .file_type()
                .is_dir()
            {
                pending.push(path);
            }
        }
    }
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in directories {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o500))
            .map_err(|_| MacPolicyError::BundleIo)?;
    }
    Ok(())
}

fn is_macho(path: &Path) -> Result<bool, MacPolicyError> {
    let mut file = File::open(path).map_err(|_| MacPolicyError::BundleIo)?;
    let mut magic = [0_u8; 4];
    if file.read_exact(&mut magic).is_err() {
        return Ok(false);
    }
    Ok(matches!(
        magic,
        [0xfe, 0xed, 0xfa, 0xce]
            | [0xce, 0xfa, 0xed, 0xfe]
            | [0xfe, 0xed, 0xfa, 0xcf]
            | [0xcf, 0xfa, 0xed, 0xfe]
            | [0xca, 0xfe, 0xba, 0xbe]
            | [0xbe, 0xba, 0xfe, 0xca]
            | [0xca, 0xfe, 0xba, 0xbf]
            | [0xbf, 0xba, 0xfe, 0xca]
    ))
}

fn set_nonblocking(file: &File) -> Result<(), MacPolicyError> {
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags == -1
        || unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1
    {
        return Err(MacPolicyError::ProtocolIo);
    }
    Ok(())
}

fn drain_bounded_cancellable(
    mut reader: File,
    limit: usize,
    cancelled: &AtomicBool,
) -> Result<Vec<u8>, MacPolicyError> {
    let mut output = Vec::new();
    let mut overflow = false;
    let mut buffer = [0_u8; 8192];
    let mut cancellation_drain = None;
    loop {
        if cancellation_drain.is_none() && cancelled.load(Ordering::Acquire) {
            cancellation_drain = Some(pipe_available(&reader)?);
        }
        let read_limit = cancellation_drain
            .map(|remaining| remaining.min(buffer.len()))
            .unwrap_or(buffer.len());
        if read_limit == 0 {
            break;
        }
        let count = match reader.read(&mut buffer[..read_limit]) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                if cancelled.load(Ordering::Acquire) {
                    break;
                }
                thread::sleep(Duration::from_millis(1));
                continue;
            }
            Err(_) => return Err(MacPolicyError::ProtocolIo),
        };
        if output.len().saturating_add(count) <= limit {
            output.extend_from_slice(&buffer[..count]);
        } else {
            overflow = true;
        }
        if let Some(remaining) = cancellation_drain.as_mut() {
            *remaining -= count;
        }
    }
    if overflow {
        Err(MacPolicyError::ProtocolLimitExceeded)
    } else {
        Ok(output)
    }
}

fn pipe_available(file: &File) -> Result<usize, MacPolicyError> {
    let mut available = 0_i32;
    if unsafe { libc::ioctl(file.as_raw_fd(), libc::FIONREAD, &mut available) } == -1 {
        return Err(MacPolicyError::ProtocolIo);
    }
    usize::try_from(available).map_err(|_| MacPolicyError::ProtocolIo)
}

fn write_all_cancellable(
    writer: &mut File,
    input: &[u8],
    cancelled: &AtomicBool,
) -> Result<(), MacPolicyError> {
    let mut offset = 0;
    while offset < input.len() {
        if cancelled.load(Ordering::Acquire) {
            return Err(MacPolicyError::ProtocolIo);
        }
        match writer.write(&input[offset..]) {
            Ok(0) => return Err(MacPolicyError::ProtocolIo),
            Ok(count) => offset += count,
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(_) => return Err(MacPolicyError::ProtocolIo),
        }
    }
    writer.flush().map_err(|_| MacPolicyError::ProtocolIo)
}

fn join<T>(handle: Option<JoinHandle<T>>) -> Result<T, MacPolicyError> {
    handle
        .ok_or(MacPolicyError::ProtocolIo)?
        .join()
        .map_err(|_| MacPolicyError::ProtocolIo)
}

fn validate_relative_path(path: &str) -> Result<(), MacPolicyError> {
    let path = Path::new(path);
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(MacPolicyError::InvalidConfiguration);
    }
    Ok(())
}

fn path_text(path: &Path) -> Result<&str, MacPolicyError> {
    let text = path.to_str().ok_or(MacPolicyError::InvalidConfiguration)?;
    if !text.starts_with('/') || text.contains(['\0', '\n', '\r']) {
        return Err(MacPolicyError::InvalidConfiguration);
    }
    Ok(text)
}

fn relative_text(root: &Path, path: &Path) -> Result<String, MacPolicyError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| MacPolicyError::InvalidConfiguration)?;
    relative
        .to_str()
        .map(|value| value.replace('\\', "/"))
        .ok_or(MacPolicyError::InvalidConfiguration)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
