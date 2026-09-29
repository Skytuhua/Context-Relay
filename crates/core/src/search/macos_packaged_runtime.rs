use super::{ModelError, lowercase_hex};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BuildTrust {
    signed_runtime_sha256: String,
    signed_runtime_bytes: u64,
    library_constraint_sha256: String,
}

impl BuildTrust {
    fn parse(value: Option<&str>) -> Result<Self, ModelError> {
        let trust: Self = serde_json::from_str(value.ok_or(ModelError::RuntimeInitialization)?)
            .map_err(|_| ModelError::RuntimeInitialization)?;
        if !lowercase_hex(&trust.signed_runtime_sha256, 64)
            || !lowercase_hex(&trust.library_constraint_sha256, 64)
            || !(1..=256 * 1024 * 1024).contains(&trust.signed_runtime_bytes)
        {
            return Err(ModelError::RuntimeInitialization);
        }
        Ok(trust)
    }
}

#[cfg(target_os = "macos")]
pub(super) use native::{initialize_ambient, initialize_packaged};

#[cfg(target_os = "macos")]
mod native {
    use super::{BuildTrust, ModelError};
    use crate::search::ModelArtifact;
    use sha2::{Digest, Sha256};
    use std::{
        ffi::CString,
        fs::{File, OpenOptions},
        io::Read,
        os::unix::{ffi::OsStrExt, fs::OpenOptionsExt},
        path::{Path, PathBuf},
        sync::Mutex,
    };

    const LIBRARY: &str = "libonnxruntime.1.24.2.dylib";
    static ORIGIN: Mutex<Option<RuntimeOrigin>> = Mutex::new(None);

    enum RuntimeOrigin {
        Ambient,
        Packaged {
            root: PathBuf,
            configured: bool,
            library: LoadedLibrary,
        },
    }

    struct LoadedLibrary(usize);
    impl Drop for LoadedLibrary {
        fn drop(&mut self) {
            unsafe {
                libc::dlclose(self.0 as *mut libc::c_void);
            }
        }
    }

    pub(crate) fn initialize_ambient() -> Result<(), ModelError> {
        let mut origin = ORIGIN
            .lock()
            .map_err(|_| ModelError::RuntimeInitialization)?;
        match origin.as_ref() {
            Some(RuntimeOrigin::Packaged {
                configured: false, ..
            }) => {
                return Err(ModelError::RuntimeInitialization);
            }
            Some(_) => return Ok(()),
            None => {}
        }
        ort::init().with_telemetry(false).commit();
        *origin = Some(RuntimeOrigin::Ambient);
        Ok(())
    }

    pub(crate) fn initialize_packaged(directory: &Path) -> Result<(), ModelError> {
        // Cargo embeds this only after packaging signs and pins the final dylib.
        // Runtime environment variables and unsigned upstream pins cannot opt in.
        let trust = BuildTrust::parse(option_env!("CONTEXT_RELAY_MACOS_RUNTIME"))?;
        let mut expected = [0; 32];
        for (index, byte) in expected.iter_mut().enumerate() {
            *byte = u8::from_str_radix(
                &trust.library_constraint_sha256[index * 2..index * 2 + 2],
                16,
            )
            .map_err(|_| ModelError::RuntimeInitialization)?;
        }
        let root = directory
            .canonicalize()
            .map_err(|_| ModelError::RuntimeInitialization)?;
        let mut origin = ORIGIN
            .lock()
            .map_err(|_| ModelError::RuntimeInitialization)?;
        if let Some(existing) = origin.as_ref() {
            return match existing {
                RuntimeOrigin::Packaged {
                    root: existing_root,
                    configured: true,
                    ..
                } if existing_root == &root => Ok(()),
                _ => Err(ModelError::RuntimeInitialization),
            };
        }
        // POSIX file descriptors cannot prevent mutation. The verified running
        // process's kernel-enforced constraint protects code identity at dlopen.
        context_relay_native_runner::verify_current_library_constraint(&expected)
            .map_err(|_| ModelError::RuntimeInitialization)?;
        let manifest: serde_json::Value = serde_json::from_str(include_str!(
            "../../models/onnxruntime-osx-arm64-1.24.2/manifest.json"
        ))
        .map_err(|_| ModelError::InvalidManifest)?;
        let mut artifacts: Vec<ModelArtifact> =
            serde_json::from_value(manifest["artifacts"].clone())
                .map_err(|_| ModelError::InvalidManifest)?;
        let runtime = artifacts.first_mut().ok_or(ModelError::InvalidManifest)?;
        if runtime.file != LIBRARY {
            return Err(ModelError::InvalidManifest);
        }
        runtime.bytes = trust.signed_runtime_bytes;
        runtime.sha256 = trust.signed_runtime_sha256;
        let _files = artifacts
            .iter()
            .map(|artifact| verify_artifact(&root, artifact))
            .collect::<Result<Vec<_>, _>>()?;
        let path = root.join(LIBRARY);
        let name = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| ModelError::RuntimeInitialization)?;
        let module = unsafe {
            libc::dlopen(
                name.as_ptr(),
                libc::RTLD_NOW | libc::RTLD_LOCAL | libc::RTLD_FIRST,
            )
        };
        if module.is_null() {
            return Err(ModelError::RuntimeInitialization);
        }
        // ORT can retain its API globally even when later configuration fails.
        // Retain the module and refuse ambient fallback on every subsequent error.
        *origin = Some(RuntimeOrigin::Packaged {
            root,
            configured: false,
            library: LoadedLibrary(module as usize),
        });
        let Some(RuntimeOrigin::Packaged {
            configured,
            library,
            ..
        }) = origin.as_mut()
        else {
            unreachable!()
        };
        *configured = configure(&path, library).unwrap_or(false);
        if *configured {
            Ok(())
        } else {
            Err(ModelError::RuntimeInitialization)
        }
    }

    fn verify_artifact(root: &Path, artifact: &ModelArtifact) -> Result<File, ModelError> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(root.join(&artifact.file))
            .map_err(|_| ModelError::MissingArtifact(artifact.file.clone()))?;
        let metadata = file
            .metadata()
            .map_err(|_| ModelError::MissingArtifact(artifact.file.clone()))?;
        if !metadata.is_file() || metadata.len() != artifact.bytes {
            return Err(ModelError::SizeMismatch(artifact.file.clone()));
        }
        let mut hash = Sha256::new();
        let mut count = 0;
        let mut buffer = [0; 64 * 1024];
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|_| ModelError::HashMismatch(artifact.file.clone()))?;
            if read == 0 {
                break;
            }
            count += read as u64;
            if count > artifact.bytes {
                return Err(ModelError::SizeMismatch(artifact.file.clone()));
            }
            hash.update(&buffer[..read]);
        }
        if count != artifact.bytes {
            return Err(ModelError::SizeMismatch(artifact.file.clone()));
        }
        if format!("{:x}", hash.finalize()) != artifact.sha256 {
            return Err(ModelError::HashMismatch(artifact.file.clone()));
        }
        Ok(file)
    }

    fn configure(path: &Path, library: &LoadedLibrary) -> Result<bool, ModelError> {
        let export =
            unsafe { libc::dlsym(library.0 as *mut libc::c_void, c"OrtGetApiBase".as_ptr()) };
        if export.is_null() {
            return Err(ModelError::RuntimeInitialization);
        }
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
    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn runtime_files_reject_tampering_links_and_nonregular_inputs() {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join(LIBRARY);
            let bytes = b"verified runtime fixture";
            let artifact = ModelArtifact {
                file: LIBRARY.into(),
                bytes: bytes.len() as u64,
                sha256: format!("{:x}", Sha256::digest(bytes)),
            };
            std::fs::write(&path, bytes).unwrap();
            verify_artifact(directory.path(), &artifact).unwrap();
            std::fs::write(&path, vec![0; bytes.len()]).unwrap();
            assert!(matches!(
                verify_artifact(directory.path(), &artifact),
                Err(ModelError::HashMismatch(_))
            ));
            std::fs::write(&path, b"short").unwrap();
            assert!(matches!(
                verify_artifact(directory.path(), &artifact),
                Err(ModelError::SizeMismatch(_))
            ));
            std::fs::remove_file(&path).unwrap();
            assert!(verify_artifact(directory.path(), &artifact).is_err());
            let source = directory.path().join("source");
            std::fs::write(&source, bytes).unwrap();
            std::os::unix::fs::symlink(&source, &path).unwrap();
            assert!(verify_artifact(directory.path(), &artifact).is_err());
            std::fs::remove_file(&path).unwrap();
            let fifo = CString::new(path.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
            assert!(verify_artifact(directory.path(), &artifact).is_err());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_runtime_requires_complete_bounded_build_trust() {
        let valid = serde_json::json!({
            "signedRuntimeSha256": "ab".repeat(32),
            "signedRuntimeBytes": 35_361_512,
            "libraryConstraintSha256": "cd".repeat(32),
        });
        let parsed = BuildTrust::parse(Some(&valid.to_string())).unwrap();
        assert_eq!(parsed.signed_runtime_bytes, 35_361_512);
        assert_eq!(parsed.signed_runtime_sha256, "ab".repeat(32));
        assert_eq!(parsed.library_constraint_sha256, "cd".repeat(32));
        assert!(BuildTrust::parse(None).is_err());
        for input in ["", "{}", "null", "[]", "not json"] {
            assert!(BuildTrust::parse(Some(input)).is_err());
        }
        for (field, value) in [
            ("signedRuntimeSha256", serde_json::json!("AB".repeat(32))),
            ("signedRuntimeSha256", serde_json::json!("ab".repeat(31))),
            (
                "libraryConstraintSha256",
                serde_json::json!("zz".repeat(32)),
            ),
            ("libraryConstraintSha256", serde_json::json!("")),
            ("signedRuntimeBytes", serde_json::json!(0)),
            ("signedRuntimeBytes", serde_json::json!(268_435_457_u64)),
            ("signedRuntimeBytes", serde_json::json!(-1)),
            ("unexpected", serde_json::json!(true)),
        ] {
            let mut invalid = valid.clone();
            invalid[field] = value;
            assert!(
                BuildTrust::parse(Some(&invalid.to_string())).is_err(),
                "{field}"
            );
        }
        for field in [
            "signedRuntimeSha256",
            "signedRuntimeBytes",
            "libraryConstraintSha256",
        ] {
            let mut invalid = valid.clone();
            invalid.as_object_mut().unwrap().remove(field);
            assert!(BuildTrust::parse(Some(&invalid.to_string())).is_err());
        }
    }
}
