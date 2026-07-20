use std::path::Path;

use sha2::{Digest, Sha256};

use crate::{RunnerError, RuntimeTarget, StagePath, validate_path_set};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

const MAX_FILES: usize = 64;
const MAX_FILE_BYTES: usize = 268_435_456;
const MAX_TOTAL_BYTES: usize = 768 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HydrationFile {
    path: StagePath,
    bytes: Vec<u8>,
    executable: bool,
}

impl HydrationFile {
    pub fn new(
        path: StagePath,
        bytes: Vec<u8>,
        expected_sha256: [u8; 32],
        executable: bool,
    ) -> Result<Self, RunnerError> {
        if bytes.len() > MAX_FILE_BYTES || Sha256::digest(&bytes).as_slice() != expected_sha256 {
            return Err(RunnerError::DigestMismatch);
        }
        Ok(Self {
            path,
            bytes,
            executable,
        })
    }

    pub fn path(&self) -> &StagePath {
        &self.path
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub const fn executable(&self) -> bool {
        self.executable
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HydrationOutcome {
    Installed,
    AlreadyExists,
}

pub fn install_hydrated_closure(
    workspace: &Path,
    target: &str,
    manifest_digest: [u8; 32],
    nonce: [u8; 16],
    files: Vec<HydrationFile>,
) -> Result<HydrationOutcome, RunnerError> {
    if !workspace.is_absolute() || files.is_empty() || files.len() > MAX_FILES {
        return Err(RunnerError::InvalidPath);
    }
    let policy = match target {
        "windows-x86_64" => RuntimeTarget::WindowsX86_64,
        "macos-aarch64" | "macos-x86_64" => RuntimeTarget::MacosArm64,
        _ => return Err(RunnerError::UnsupportedTarget),
    };
    let paths = files
        .iter()
        .map(|file| file.path.clone())
        .collect::<Vec<_>>();
    validate_path_set(policy, &paths)?;
    for (index, path) in paths.iter().enumerate() {
        if paths.iter().enumerate().any(|(other_index, other)| {
            index != other_index
                && other
                    .as_str()
                    .strip_prefix(path.as_str())
                    .is_some_and(|suffix| suffix.starts_with('/'))
        }) {
            return Err(RunnerError::PathCollision);
        }
    }
    let total = files.iter().try_fold(0_usize, |total, file| {
        total
            .checked_add(file.bytes.len())
            .ok_or(RunnerError::LimitExceeded)
    })?;
    if total > MAX_TOTAL_BYTES {
        return Err(RunnerError::LimitExceeded);
    }
    install_platform(
        workspace,
        target,
        &hex(&manifest_digest),
        &format!(".context-relay-hydrate-{}.partial", hex(&nonce)),
        &files,
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(any(windows, target_os = "macos"))]
fn install_platform(
    workspace: &Path,
    target: &str,
    manifest: &str,
    partial: &str,
    files: &[HydrationFile],
) -> Result<HydrationOutcome, RunnerError> {
    #[cfg(windows)]
    return windows::install(workspace, target, manifest, partial, files);
    #[cfg(target_os = "macos")]
    return macos::install(workspace, target, manifest, partial, files);
}

#[cfg(not(any(windows, target_os = "macos")))]
fn install_platform(
    _workspace: &Path,
    _target: &str,
    _manifest: &str,
    _partial: &str,
    _files: &[HydrationFile],
) -> Result<HydrationOutcome, RunnerError> {
    Err(RunnerError::UnsupportedTarget)
}

#[cfg(test)]
type TestHook = Box<dyn FnOnce() -> Result<(), RunnerError> + Send>;
#[cfg(test)]
static AFTER_PARENT_BIND_TEST_HOOK: std::sync::Mutex<Option<TestHook>> =
    std::sync::Mutex::new(None);
#[cfg(test)]
static AFTER_PARTIAL_CREATE_TEST_HOOK: std::sync::Mutex<Option<TestHook>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
fn set_after_parent_bind_test_hook(
    hook: impl FnOnce() -> Result<(), RunnerError> + Send + 'static,
) {
    *AFTER_PARENT_BIND_TEST_HOOK.lock().expect("test hook lock") = Some(Box::new(hook));
}

#[cfg(test)]
fn set_after_partial_create_test_hook(
    hook: impl FnOnce() -> Result<(), RunnerError> + Send + 'static,
) {
    *AFTER_PARTIAL_CREATE_TEST_HOOK
        .lock()
        .expect("test hook lock") = Some(Box::new(hook));
}

#[cfg(test)]
fn run_after_parent_bind_test_hook() -> Result<(), RunnerError> {
    if let Some(hook) = AFTER_PARENT_BIND_TEST_HOOK
        .lock()
        .expect("test hook lock")
        .take()
    {
        hook()?;
    }
    Ok(())
}

#[cfg(test)]
fn run_after_partial_create_test_hook() -> Result<(), RunnerError> {
    if let Some(hook) = AFTER_PARTIAL_CREATE_TEST_HOOK
        .lock()
        .expect("test hook lock")
        .take()
    {
        hook()?;
    }
    Ok(())
}

#[cfg(all(test, any(windows, target_os = "macos")))]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use sha2::{Digest, Sha256};

    use super::{
        HydrationFile, HydrationOutcome, install_hydrated_closure, set_after_parent_bind_test_hook,
        set_after_partial_create_test_hook,
    };
    use crate::{RunnerError, StagePath};

    const TARGET: &str = if cfg!(windows) {
        "windows-x86_64"
    } else {
        "macos-aarch64"
    };
    static TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn guarded_hydration_installs_once_and_never_replaces_an_existing_cache() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let workspace = scratch("ordinary");
        let manifest = [0x11; 32];
        let original = file("fixture/fixture.exe", b"original", true);

        assert_eq!(
            install_hydrated_closure(&workspace, TARGET, manifest, [0x22; 16], vec![original],)
                .unwrap(),
            HydrationOutcome::Installed,
        );
        let installed = cache(&workspace, manifest).join("fixture/fixture.exe");
        assert_eq!(fs::read(&installed).unwrap(), b"original");

        assert_eq!(
            install_hydrated_closure(
                &workspace,
                TARGET,
                manifest,
                [0x33; 16],
                vec![file("fixture/fixture.exe", b"replacement", true)],
            )
            .unwrap(),
            HydrationOutcome::AlreadyExists,
        );
        assert_eq!(fs::read(installed).unwrap(), b"original");
        assert_no_partial(&workspace, manifest);
        fs::remove_dir_all(workspace).unwrap();
    }

    #[test]
    fn ancestor_swap_at_the_bound_handle_cannot_touch_the_external_tree() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let workspace = scratch("ancestor-swap");
        let outside = scratch("ancestor-swap-outside");
        let canary = outside.join("canary");
        fs::write(&canary, b"outside").unwrap();
        let target = workspace.join("target");
        let moved = workspace.join("target-moved");
        let hook_target = target.clone();
        let hook_moved = moved.clone();
        let hook_outside = outside.clone();
        set_after_parent_bind_test_hook(move || {
            swap_ancestor(&hook_target, &hook_moved, &hook_outside)?;
            Ok(())
        });

        let result = install_hydrated_closure(
            &workspace,
            TARGET,
            [0x44; 32],
            [0x55; 16],
            vec![file("fixture/fixture.exe", b"payload", true)],
        );
        if cfg!(windows) {
            assert_eq!(result.unwrap(), HydrationOutcome::Installed);
        } else {
            assert!(matches!(result, Err(RunnerError::ConcurrentChange)));
        }
        assert_eq!(fs::read(&canary).unwrap(), b"outside");
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 1);
        cleanup_swap(&workspace, &target, &moved);
        fs::remove_dir_all(workspace).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[test]
    fn failed_hydration_cleans_only_its_held_partial_after_an_ancestor_swap() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let workspace = scratch("cleanup-swap");
        let outside = scratch("cleanup-swap-outside");
        let canary = outside.join("canary");
        fs::write(&canary, b"outside").unwrap();
        let target = workspace.join("target");
        let moved = workspace.join("target-moved");
        let hook_target = target.clone();
        let hook_moved = moved.clone();
        let hook_outside = outside.clone();
        set_after_partial_create_test_hook(move || {
            swap_ancestor(&hook_target, &hook_moved, &hook_outside)?;
            Err(RunnerError::Io)
        });

        assert!(matches!(
            install_hydrated_closure(
                &workspace,
                TARGET,
                [0x66; 32],
                [0x77; 16],
                vec![file("fixture/fixture.exe", b"payload", true)],
            ),
            Err(RunnerError::Io)
        ));
        assert_eq!(fs::read(&canary).unwrap(), b"outside");
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 1);
        let held_parent = if moved.exists() {
            moved.join("sidecars").join(TARGET)
        } else {
            target.join("sidecars").join(TARGET)
        };
        assert!(fs::read_dir(held_parent).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("partial")
        }));
        cleanup_swap(&workspace, &target, &moved);
        fs::remove_dir_all(workspace).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    fn file(path: &str, bytes: &[u8], executable: bool) -> HydrationFile {
        HydrationFile::new(
            StagePath::try_from(path).unwrap(),
            bytes.to_vec(),
            Sha256::digest(bytes).into(),
            executable,
        )
        .unwrap()
    }

    fn cache(workspace: &Path, manifest: [u8; 32]) -> PathBuf {
        workspace
            .join("target/sidecars")
            .join(TARGET)
            .join(hex(&manifest))
    }

    fn assert_no_partial(workspace: &Path, manifest: [u8; 32]) {
        let parent = cache(workspace, manifest).parent().unwrap().to_path_buf();
        assert!(fs::read_dir(parent).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("partial")
        }));
    }

    #[cfg(target_os = "macos")]
    fn swap_ancestor(target: &Path, moved: &Path, outside: &Path) -> Result<(), RunnerError> {
        fs::rename(target, moved).map_err(|_| RunnerError::Io)?;
        std::os::unix::fs::symlink(outside, target).map_err(|_| RunnerError::Io)
    }

    #[cfg(windows)]
    fn swap_ancestor(target: &Path, moved: &Path, _outside: &Path) -> Result<(), RunnerError> {
        assert!(
            fs::rename(target, moved).is_err(),
            "held handle allowed ancestor rename"
        );
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn cleanup_swap(_workspace: &Path, target: &Path, moved: &Path) {
        if moved.exists() {
            fs::remove_file(target).unwrap();
            fs::rename(moved, target).unwrap();
        }
    }

    #[cfg(windows)]
    fn cleanup_swap(_workspace: &Path, _target: &Path, _moved: &Path) {}

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn scratch(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "context-relay-hydration-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        fs::create_dir(&path).unwrap();
        path
    }
}
