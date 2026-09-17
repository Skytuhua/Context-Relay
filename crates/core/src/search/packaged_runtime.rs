use std::{
    fs::{File, OpenOptions},
    io::Read,
    os::windows::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    },
    path::{Path, PathBuf},
    sync::Mutex,
};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use windows_sys::Win32::{
    Foundation::{FreeLibrary, HMODULE},
    Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE,
        GetFinalPathNameByHandleW,
    },
    System::LibraryLoader::{
        GetModuleFileNameW, GetModuleHandleW, GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32,
        LoadLibraryExW,
    },
};

use super::{ModelArtifact, ModelError};

static ORIGIN: Mutex<Option<RuntimeOrigin>> = Mutex::new(None);

enum RuntimeOrigin {
    Ambient,
    Packaged(PackagedRuntime),
}

struct PackagedRuntime {
    root: PathBuf,
    configured: bool,
    // These process-lifetime guards prevent replacement of verified native code
    // and its canonical directory chain after checking and while ORT uses it.
    _files: Vec<File>,
    _directories: Vec<File>,
    _libraries: Vec<LoadedLibrary>,
}

struct LoadedLibrary(usize);

impl Drop for LoadedLibrary {
    fn drop(&mut self) {
        // Each wrapper owns exactly one successful LoadLibraryExW reference.
        unsafe {
            FreeLibrary(self.0 as HMODULE);
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuntimeManifest {
    schema_version: u32,
    runtime: String,
    version: String,
    target: String,
    visual_cpp_version: String,
    artifacts: Vec<ModelArtifact>,
}

pub(super) fn initialize_ambient() -> Result<(), ModelError> {
    let mut origin = ORIGIN
        .lock()
        .map_err(|_| ModelError::RuntimeInitialization)?;
    match origin.as_ref() {
        Some(RuntimeOrigin::Packaged(runtime)) if !runtime.configured => {
            return Err(ModelError::RuntimeInitialization);
        }
        Some(_) => return Ok(()),
        None => {}
    }
    ort::init().with_telemetry(false).commit();
    *origin = Some(RuntimeOrigin::Ambient);
    Ok(())
}

pub(super) fn initialize_packaged(directory: &Path) -> Result<(), ModelError> {
    let root = directory
        .canonicalize()
        .map_err(|_| ModelError::RuntimeInitialization)?;
    let mut origin = ORIGIN
        .lock()
        .map_err(|_| ModelError::RuntimeInitialization)?;
    if let Some(existing) = origin.as_ref() {
        return match existing {
            RuntimeOrigin::Packaged(runtime) if runtime.root == root && runtime.configured => {
                Ok(())
            }
            _ => Err(ModelError::RuntimeInitialization),
        };
    }
    let manifest: RuntimeManifest = serde_json::from_str(include_str!(
        "../../models/onnxruntime-win-x64-1.24.2/manifest.json"
    ))
    .map_err(|_| ModelError::InvalidManifest)?;
    if manifest.schema_version != 1
        || manifest.runtime != "onnxruntime"
        || manifest.version != "1.24.2"
        || manifest.target != "x86_64-pc-windows-msvc"
        || manifest.visual_cpp_version != "14.44.35211.0"
    {
        return Err(ModelError::InvalidManifest);
    }
    let (directories, files) = pin_artifacts(&root, &manifest.artifacts, || {}, || {})?;
    let dlls: Vec<_> = manifest
        .artifacts
        .iter()
        .filter(|a| a.file.ends_with(".dll"))
        .collect();
    // A prior ambient load cannot be silently treated as the packaged runtime.
    // Production Windows companions use static CRT; native model tests must too.
    for artifact in &dlls {
        let name = wide(Path::new(&artifact.file));
        if !unsafe { GetModuleHandleW(name.as_ptr()) }.is_null() {
            return Err(ModelError::RuntimeInitialization);
        }
    }
    let mut libraries = Vec::new();
    for artifact in dlls {
        let path = root.join(&artifact.file);
        let name = wide(&path);
        // Load the manifest's C++ prerequisites first. Subsequent imports use
        // those loaded modules or System32, never PATH or an unlisted sibling.
        let handle = unsafe {
            LoadLibraryExW(
                name.as_ptr(),
                std::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if handle.is_null() {
            return Err(ModelError::RuntimeInitialization);
        }
        let library = LoadedLibrary(handle as usize);
        if loaded_path(handle)? != path {
            return Err(ModelError::RuntimeInitialization);
        }
        libraries.push(library);
    }
    let configured = configure_packaged_ort(
        &root.join("onnxruntime.dll"),
        libraries.last().ok_or(ModelError::InvalidManifest)?.0 as HMODULE,
    )
    .unwrap_or(false);
    // ORT retains its DLL globally. Keep the matching guards even if configuring
    // its environment was refused; do not leave a native library unpinned.
    *origin = Some(RuntimeOrigin::Packaged(PackagedRuntime {
        root,
        configured,
        _files: files,
        _directories: directories,
        _libraries: libraries,
    }));
    if configured {
        Ok(())
    } else {
        Err(ModelError::RuntimeInitialization)
    }
}

fn configure_packaged_ort(path: &Path, module: HMODULE) -> Result<bool, ModelError> {
    // init_from alone can silently retain an earlier differently named library.
    // Attest the actual API table before creating any environment or session.
    let export = unsafe { GetProcAddress(module, c"OrtGetApiBase".as_ptr().cast()) }
        .ok_or(ModelError::RuntimeInitialization)?;
    let get_base: unsafe extern "C" fn() -> *const ort::sys::OrtApiBase =
        unsafe { std::mem::transmute(export) };
    let base = unsafe { get_base().as_ref() }.ok_or(ModelError::RuntimeInitialization)?;
    let expected = unsafe { (base.GetApi)(ort::sys::ORT_API_VERSION) };
    if expected.is_null() {
        return Err(ModelError::RuntimeInitialization);
    }
    let builder = ort::init_from(path).map_err(|_| ModelError::RuntimeInitialization)?;
    if !std::ptr::eq(ort::api(), expected) {
        return Err(ModelError::RuntimeInitialization);
    }
    Ok(builder.with_telemetry(false).commit())
}

fn pin_directories(root: &Path) -> Result<Vec<File>, ModelError> {
    let mut directories = Vec::new();
    for path in root.ancestors().collect::<Vec<_>>().into_iter().rev() {
        let directory = OpenOptions::new()
            .access_mode(FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|_| ModelError::RuntimeInitialization)?;
        let metadata = directory
            .metadata()
            .map_err(|_| ModelError::RuntimeInitialization)?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(ModelError::RuntimeInitialization);
        }
        directories.push(directory);
    }
    Ok(directories)
}

fn pin_artifacts(
    root: &Path,
    artifacts: &[ModelArtifact],
    after_directories: impl FnOnce(),
    after_files: impl FnOnce(),
) -> Result<(Vec<File>, Vec<File>), ModelError> {
    let directories = pin_directories(root)?;
    after_directories();
    let files = artifacts
        .iter()
        .map(|artifact| verify_file(root, artifact))
        .collect::<Result<Vec<_>, _>>()?;
    after_files();
    // Normalized handle paths attest the physical objects, not the spelling used
    // to open them. A transient junction leaves file guards at its target even
    // if it is removed before this check. Never re-resolve the expected paths.
    for (directory, expected) in directories
        .iter()
        .zip(root.ancestors().collect::<Vec<_>>().into_iter().rev())
    {
        let metadata = directory
            .metadata()
            .map_err(|_| ModelError::RuntimeInitialization)?;
        if !metadata.is_dir()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || final_handle_path(directory)? != expected
        {
            return Err(ModelError::RuntimeInitialization);
        }
    }
    for (file, artifact) in files.iter().zip(artifacts) {
        if final_handle_path(file)? != root.join(&artifact.file) {
            return Err(ModelError::RuntimeInitialization);
        }
    }
    Ok((directories, files))
}

fn final_handle_path(file: &File) -> Result<PathBuf, ModelError> {
    use std::os::windows::ffi::OsStringExt;
    let mut buffer = vec![0_u16; 32_768];
    // Zero requests FILE_NAME_NORMALIZED and VOLUME_NAME_DOS.
    let length = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            0,
        )
    } as usize;
    if length == 0 || length >= buffer.len() {
        return Err(ModelError::RuntimeInitialization);
    }
    Ok(PathBuf::from(std::ffi::OsString::from_wide(
        &buffer[..length],
    )))
}

fn verify_file(root: &Path, artifact: &ModelArtifact) -> Result<File, ModelError> {
    if Path::new(&artifact.file).components().count() != 1
        || !matches!(
            Path::new(&artifact.file).components().next(),
            Some(std::path::Component::Normal(_))
        )
        || !super::lowercase_hex(&artifact.sha256, 64)
    {
        return Err(ModelError::InvalidManifest);
    }
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(root.join(&artifact.file))
        .map_err(|_| ModelError::MissingArtifact(artifact.file.clone()))?;
    let metadata = file
        .metadata()
        .map_err(|_| ModelError::MissingArtifact(artifact.file.clone()))?;
    if !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || metadata.len() != artifact.bytes
    {
        return Err(ModelError::SizeMismatch(artifact.file.clone()));
    }
    let mut input = (&file).take(artifact.bytes.saturating_add(1));
    let mut hasher = Sha256::new();
    let mut count = 0;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let bytes = input
            .read(&mut buffer)
            .map_err(|_| ModelError::HashMismatch(artifact.file.clone()))?;
        if bytes == 0 {
            break;
        }
        count += bytes as u64;
        hasher.update(&buffer[..bytes]);
    }
    if count != artifact.bytes || format!("{:x}", hasher.finalize()) != artifact.sha256 {
        return Err(ModelError::HashMismatch(artifact.file.clone()));
    }
    Ok(file)
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

fn loaded_path(handle: HMODULE) -> Result<PathBuf, ModelError> {
    use std::os::windows::ffi::OsStringExt;
    let mut buffer = vec![0_u16; 32_768];
    let length =
        unsafe { GetModuleFileNameW(handle, buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if length == 0 || length >= buffer.len() {
        return Err(ModelError::RuntimeInitialization);
    }
    PathBuf::from(std::ffi::OsString::from_wide(&buffer[..length]))
        .canonicalize()
        .map_err(|_| ModelError::RuntimeInitialization)
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::IO::DeviceIoControl;

    #[test]
    fn empty_guarded_directory_cannot_be_renamed_or_deleted() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("runtime");
        std::fs::create_dir(&root).unwrap();
        let guards = pin_directories(&root.canonicalize().unwrap()).unwrap();
        assert!(std::fs::rename(&root, scratch.path().join("moved")).is_err());
        assert!(std::fs::remove_dir(&root).is_err());
        drop(guards);
    }

    #[test]
    #[allow(
        clippy::assertions_on_constants,
        reason = "ignored qualification must compile for ordinary non-static test builds"
    )]
    #[ignore = "requires explicit runtime assets and static CRT; owns a disposable child process"]
    fn ort_api_attestation_rejects_an_already_selected_renamed_library() {
        use std::io::Seek;
        use std::os::windows::process::CommandExt;
        assert!(cfg!(target_feature = "crt-static"));
        let Some(root) = std::env::var_os("CONTEXT_RELAY_ORT_ATTESTATION_CHILD") else {
            let root = tempfile::tempdir().unwrap();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--ignored", "--exact", "search::packaged_runtime::tests::ort_api_attestation_rejects_an_already_selected_renamed_library", "--nocapture"])
                .env("CONTEXT_RELAY_ORT_ATTESTATION_CHILD", root.path())
                .creation_flags(0x0800_0000).output().unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            root.close().unwrap();
            return;
        };
        let root = PathBuf::from(root);
        let source = PathBuf::from(std::env::var_os("CONTEXT_RELAY_RUNTIME_DIR").unwrap());
        let manifest: RuntimeManifest = serde_json::from_str(include_str!(
            "../../models/onnxruntime-win-x64-1.24.2/manifest.json"
        ))
        .unwrap();
        for artifact in &manifest.artifacts {
            let mut source = verify_file(&source, artifact).unwrap();
            source.rewind().unwrap();
            let mut output = File::create(root.join(&artifact.file)).unwrap();
            std::io::copy(&mut source, &mut output).unwrap();
        }
        let renamed = root.join("renamed-onnxruntime.dll");
        std::fs::copy(root.join("onnxruntime.dll"), &renamed).unwrap();
        let mut libraries = Vec::new();
        for artifact in manifest
            .artifacts
            .iter()
            .filter(|artifact| artifact.file.ends_with(".dll"))
        {
            let path = if artifact.file == "onnxruntime.dll" {
                renamed.clone()
            } else {
                root.join(&artifact.file)
            };
            let handle = unsafe {
                LoadLibraryExW(
                    wide(&path).as_ptr(),
                    std::ptr::null_mut(),
                    LOAD_LIBRARY_SEARCH_SYSTEM32,
                )
            };
            assert!(
                !handle.is_null(),
                "native fixture: {}",
                std::io::Error::last_os_error()
            );
            libraries.push(LoadedLibrary(handle as usize));
        }
        let _uncommitted = ort::init_from(&renamed).unwrap();
        let packaged = root.join("onnxruntime.dll");
        let handle = unsafe {
            LoadLibraryExW(
                wide(&packaged).as_ptr(),
                std::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        assert!(!handle.is_null());
        libraries.push(LoadedLibrary(handle as usize));
        assert!(
            configure_packaged_ort(&packaged, handle).is_err(),
            "ORT retained a different API table"
        );
    }

    // Install a junction on an existing empty directory, while the loader still
    // holds its original directory handle. No shell or normal profile is used.
    fn redirect_empty_directory(path: &Path, target: &Path) -> File {
        let target = target.canonicalize().unwrap();
        let substitute = target.to_string_lossy().replacen(r"\\?\", r"\??\", 1);
        let name: Vec<u16> = substitute.encode_utf16().chain([0, 0]).collect();
        let length = ((name.len() - 2) * 2) as u16;
        let mut data = Vec::new();
        data.extend_from_slice(&0xa000_0003_u32.to_le_bytes());
        data.extend_from_slice(&(8 + name.len() as u16 * 2).to_le_bytes());
        data.extend_from_slice(&0_u16.to_le_bytes());
        for field in [0, length, length + 2, 0] {
            data.extend_from_slice(&field.to_le_bytes());
        }
        for character in name {
            data.extend_from_slice(&character.to_le_bytes());
        }
        let directory = OpenOptions::new()
            .access_mode(windows_sys::Win32::Storage::FileSystem::FILE_WRITE_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .unwrap();
        let mut returned = 0;
        let result = unsafe {
            DeviceIoControl(
                directory.as_raw_handle(),
                0x0009_00a4,
                data.as_ptr().cast(),
                data.len() as u32,
                std::ptr::null_mut(),
                0,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(
            result,
            0,
            "junction fixture: {}",
            std::io::Error::last_os_error()
        );
        directory
    }

    #[test]
    fn artifact_acquisition_rejects_directory_redirected_after_initial_check() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("runtime");
        let target = scratch.path().join("replacement");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("fixture.dll"), b"verified bytes").unwrap();
        let artifacts = [ModelArtifact {
            file: "fixture.dll".into(),
            bytes: 14,
            sha256: format!("{:x}", Sha256::digest(b"verified bytes")),
        }];
        let result = pin_artifacts(
            &root.canonicalize().unwrap(),
            &artifacts,
            || {
                redirect_empty_directory(&root, &target);
            },
            || {},
        );
        let rejected = result.is_err();
        drop(result);
        // Remove only the junction itself before TempDir cleans its own files.
        std::fs::remove_dir(&root).unwrap();
        assert!(
            rejected,
            "a redirected directory reached the native-load boundary"
        );
    }

    #[test]
    fn artifact_acquisition_rejects_redirect_then_restore_before_final_check() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("runtime");
        let target = scratch.path().join("replacement");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("fixture.dll"), b"verified bytes").unwrap();
        let artifacts = [ModelArtifact {
            file: "fixture.dll".into(),
            bytes: 14,
            sha256: format!("{:x}", Sha256::digest(b"verified bytes")),
        }];
        let attacker = std::cell::RefCell::new(None);
        let result = pin_artifacts(
            &root.canonicalize().unwrap(),
            &artifacts,
            || {
                *attacker.borrow_mut() = Some(redirect_empty_directory(&root, &target));
            },
            || {
                let attacker = attacker.borrow();
                let directory = attacker.as_ref().unwrap();
                let data = 0xa000_0003_u64.to_le_bytes();
                let mut returned = 0;
                let result = unsafe {
                    DeviceIoControl(
                        directory.as_raw_handle(),
                        0x0009_00ac,
                        data.as_ptr().cast(),
                        data.len() as u32,
                        std::ptr::null_mut(),
                        0,
                        &mut returned,
                        std::ptr::null_mut(),
                    )
                };
                assert_ne!(
                    result,
                    0,
                    "remove junction: {}",
                    std::io::Error::last_os_error()
                );
                std::fs::write(root.join("fixture.dll"), b"unverified DLL").unwrap();
            },
        );
        assert!(
            result.is_err(),
            "verified files were detached from the native-load directory"
        );
    }
}
