//! Persisted runtime identity for future sealed setup and recovery.

pub use super::RetainedRuntimeReference;
use super::{
    CapturedRuntime, Inventory, MAX_DEPTH, MAX_ENTRIES, MAX_FILE_BYTES, RuntimeFile,
    RuntimeManifest, children, invalid, inventory_stage_with, manifest_bytes_identity, read_file,
    real_path, stage_path,
};
use context_relay_native_runner::{
    OsNativeFileSystem, PinnedNativeDirectory, RuntimeTarget, validate_path_set,
};
use context_relay_protocol::{ClientError, Sha256Digest};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    os::windows::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
};

const MAX_MANIFEST_BYTES: usize = 48 * 1024 * 1024;
const MANIFEST_NAME: &str = "manifest.json";

#[derive(Debug)]
pub struct RetainedRuntime {
    pin: PinnedNativeDirectory,
    container_pin: PinnedNativeDirectory,
    root: PathBuf,
    manifest: RuntimeManifest,
    reference: RetainedRuntimeReference,
}

impl CapturedRuntime {
    /// Publishes a durable copy identified by its manifest hash. Files are not permanently
    /// locked: execution must reverify and hold its own locks later.
    pub fn retain(self) -> Result<RetainedRuntime, ClientError> {
        self.retain_with_directory_sync(|path| {
            OsNativeFileSystem::new()
                .synchronize_directory(path)
                .map_err(|_| invalid())
        })
    }

    fn retain_with_directory_sync(
        self,
        mut synchronize: impl FnMut(&Path) -> Result<(), ClientError>,
    ) -> Result<RetainedRuntime, ClientError> {
        self.pin.verify_private().map_err(|_| invalid())?;
        self.container_pin.verify_private().map_err(|_| invalid())?;
        validate_manifest(&self.manifest)?;
        let container = self.root.parent().ok_or_else(invalid)?;
        require_entries(container, &["payload"])?;
        require_entries(self._directory.path(), &["runtime"])?;
        verify_payload(&self.pin, &self.root, &self.manifest, true)?;
        // Children before parents so every new directory entry reaches its
        // durability barrier before the manifest is published.
        for directory in self.manifest.directories.iter().rev() {
            self.pin
                .synchronize_relative_directory(&stage_path(directory)?)
                .map_err(|_| invalid())?;
        }
        self.pin.synchronize().map_err(|_| invalid())?;
        let bytes = serde_json::to_vec(&self.manifest).map_err(|_| invalid())?;
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(invalid());
        }
        let mut output = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(1)
            .custom_flags(0x0020_0000)
            .open(container.join(MANIFEST_NAME))
            .map_err(|_| invalid())?;
        output.write_all(&bytes).map_err(|_| invalid())?;
        output.sync_all().map_err(|_| invalid())?;
        drop(output);
        self.container_pin.synchronize().map_err(|_| invalid())?;
        synchronize(self._directory.path())?;
        synchronize(self._directory.path().parent().ok_or_else(invalid)?)?;
        let reference = RetainedRuntimeReference {
            schema_version: 1,
            storage_key: self
                ._directory
                .path()
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(invalid)?
                .into(),
            manifest_identity: self.identity,
        };
        validate_reference(&reference)?;
        let retained_manifest = read_manifest(container, &self.container_pin, &reference)?;
        if retained_manifest != self.manifest {
            return Err(invalid());
        }
        let CapturedRuntime {
            pin,
            container_pin,
            _directory,
            root,
            manifest,
            ..
        } = self;
        let _ = _directory.keep();
        Ok(RetainedRuntime {
            pin,
            container_pin,
            root,
            manifest,
            reference,
        })
    }
}

impl RetainedRuntime {
    pub fn open(store: &Path, reference: &RetainedRuntimeReference) -> Result<Self, ClientError> {
        validate_reference(reference)?;
        let store = real_path(store, true)?;
        let holder = store.join(&reference.storage_key);
        let container = holder.join("runtime");
        let root = container.join("payload");
        let filesystem = OsNativeFileSystem::new();
        let container_pin = filesystem
            .open_private_directory(&container)
            .map_err(|_| invalid())?;
        let pin = filesystem
            .open_private_directory(&root)
            .map_err(|_| invalid())?;
        require_entries(&holder, &["runtime"])?;
        let manifest = read_manifest(&container, &container_pin, reference)?;
        verify_payload(&pin, &root, &manifest, false)?;
        Ok(Self {
            pin,
            container_pin,
            root,
            manifest,
            reference: reference.clone(),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn manifest(&self) -> &RuntimeManifest {
        &self.manifest
    }
    pub fn reference(&self) -> &RetainedRuntimeReference {
        &self.reference
    }
    pub fn identity(&self) -> Sha256Digest {
        self.reference.manifest_identity
    }

    pub fn verify(&self) -> Result<(), ClientError> {
        self.pin.verify_private().map_err(|_| invalid())?;
        self.container_pin.verify_private().map_err(|_| invalid())?;
        let container = self.root.parent().ok_or_else(invalid)?;
        require_entries(container.parent().ok_or_else(invalid)?, &["runtime"])?;
        let manifest = read_manifest(
            self.root.parent().ok_or_else(invalid)?,
            &self.container_pin,
            &self.reference,
        )?;
        if manifest != self.manifest {
            return Err(invalid());
        }
        verify_payload(&self.pin, &self.root, &self.manifest, false)
    }
}

fn validate_reference(reference: &RetainedRuntimeReference) -> Result<(), ClientError> {
    reference.validate()
}

fn require_entries(path: &Path, expected: &[&str]) -> Result<(), ClientError> {
    let observed = children(path)?
        .into_iter()
        .map(|(name, _)| name)
        .collect::<Vec<_>>();
    if observed
        .iter()
        .map(String::as_str)
        .ne(expected.iter().copied())
    {
        return Err(invalid());
    }
    Ok(())
}

fn read_manifest(
    container: &Path,
    pin: &PinnedNativeDirectory,
    reference: &RetainedRuntimeReference,
) -> Result<RuntimeManifest, ClientError> {
    require_entries(container, &[MANIFEST_NAME, "payload"])?;
    let mut bytes = Vec::new();
    let observed = read_file(&container.join(MANIFEST_NAME), MANIFEST_NAME, |chunk| {
        if bytes.len().saturating_add(chunk.len()) > MAX_MANIFEST_BYTES {
            return Err(invalid());
        }
        bytes.extend_from_slice(chunk);
        Ok(())
    })?;
    let (size, hash) = pin
        .hash_regular_file(
            &stage_path(MANIFEST_NAME)?,
            MAX_MANIFEST_BYTES as u64,
            false,
        )
        .map_err(|_| invalid())?;
    if size != observed.size
        || Sha256Digest(hash) != observed.sha256
        || manifest_bytes_identity(&bytes) != reference.manifest_identity
    {
        return Err(invalid());
    }
    let manifest: RuntimeManifest = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    validate_manifest(&manifest)?;
    if serde_json::to_vec(&manifest).map_err(|_| invalid())? != bytes {
        return Err(invalid());
    }
    Ok(manifest)
}

fn validate_manifest(manifest: &RuntimeManifest) -> Result<(), ClientError> {
    if manifest.schema_version != 1
        || manifest.projection != "hermes-python-source-first-v1"
        || manifest.source_roots.is_empty()
        || manifest.source_roots.len() > 128
        || manifest
            .files
            .len()
            .saturating_add(manifest.directories.len())
            > MAX_ENTRIES
        || manifest
            .directories
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || manifest
            .files
            .windows(2)
            .any(|pair| pair[0].path >= pair[1].path)
    {
        return Err(invalid());
    }
    let mut inventory = Inventory::default();
    let mut siblings: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for path in manifest
        .directories
        .iter()
        .map(String::as_str)
        .chain(manifest.files.iter().map(|file| file.path.as_str()))
    {
        stage_path(path)?;
        if path.split('/').count() > MAX_DEPTH + 1 {
            return Err(invalid());
        }
        let (parent, name) = path.rsplit_once('/').unwrap_or(("", path));
        siblings.entry(parent).or_default().push(name.to_owned());
    }
    for names in siblings.values() {
        if names.iter().all(|name| name.is_ascii()) {
            let mut aliases = BTreeSet::new();
            if names
                .iter()
                .any(|name| !aliases.insert(name.to_ascii_uppercase()))
            {
                return Err(invalid());
            }
        } else {
            validate_path_set(
                RuntimeTarget::WindowsX86_64,
                &names
                    .iter()
                    .map(|name| stage_path(name))
                    .collect::<Result<Vec<_>, _>>()?,
            )
            .map_err(|_| invalid())?;
        }
    }
    for path in &manifest.directories {
        inventory.directory(path)?;
    }
    for file in &manifest.files {
        inventory.file(file.clone())?;
    }
    if inventory
        .directories
        .into_iter()
        .ne(manifest.directories.iter().cloned())
    {
        return Err(invalid());
    }
    Ok(())
}

fn verify_payload(
    pin: &PinnedNativeDirectory,
    root: &Path,
    manifest: &RuntimeManifest,
    synchronize: bool,
) -> Result<(), ClientError> {
    for directory in &manifest.directories {
        pin.verify_relative_directory(&stage_path(directory)?)
            .map_err(|_| invalid())?;
    }
    let observed = inventory_stage_with(root, &mut |_, relative| {
        let (size, hash) = pin
            .hash_regular_file(&stage_path(relative)?, MAX_FILE_BYTES, synchronize)
            .map_err(|_| invalid())?;
        Ok(RuntimeFile {
            path: relative.into(),
            size,
            sha256: Sha256Digest(hash),
        })
    })?;
    if observed.directories != manifest.directories || observed.files != manifest.files {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hermes::python_runtime::{CapturedRuntime, RuntimeSource, capture_inputs};
    use std::{fs, path::PathBuf};

    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf, CapturedRuntime) {
        let temp = tempfile::tempdir().unwrap();
        let store = fs::canonicalize(temp.path()).unwrap();
        let source = store.join("source");
        fs::create_dir(&source).unwrap();
        fs::create_dir(source.join("empty")).unwrap();
        fs::write(source.join("module.py"), b"VALUE = 'approved'\n").unwrap();
        let captured = capture_inputs(
            &store,
            vec![RuntimeSource {
                source: source.clone(),
                destination: "source".into(),
            }],
        )
        .unwrap();
        (temp, store, source, captured)
    }

    #[test]
    fn fresh_reopen_uses_retained_bytes_after_source_removal() {
        let (_temp, store, source, captured) = fixture();
        let identity = captured.identity();
        let retained = captured.retain().unwrap();
        let reference: RetainedRuntimeReference =
            serde_json::from_slice(&serde_json::to_vec(retained.reference()).unwrap()).unwrap();
        let root = retained.root().to_owned();
        assert_eq!(retained.identity(), identity);
        drop(retained);
        fs::remove_dir_all(&source).unwrap();
        let reopened = RetainedRuntime::open(&store, &reference).unwrap();
        assert_eq!(reopened.root(), root);
        assert_eq!(reopened.identity(), identity);
        assert_eq!(
            fs::read(root.join("source/module.py")).unwrap(),
            b"VALUE = 'approved'\n"
        );
        reopened.verify().unwrap();
    }

    #[test]
    fn reopening_rejects_payload_manifest_and_reference_changes() {
        let (_temp, store, _source, captured) = fixture();
        let retained = captured.retain().unwrap();
        let reference = retained.reference().clone();
        let root = retained.root().to_owned();
        drop(retained);
        fs::write(root.join("source/module.py"), b"changed").unwrap();
        assert!(RetainedRuntime::open(&store, &reference).is_err());
        fs::write(root.join("source/module.py"), b"VALUE = 'approved'\n").unwrap();
        RetainedRuntime::open(&store, &reference).unwrap();
        fs::write(root.join("source/extra.py"), b"unexpected").unwrap();
        assert!(RetainedRuntime::open(&store, &reference).is_err());
        fs::remove_file(root.join("source/extra.py")).unwrap();
        let manifest = root.parent().unwrap().join("manifest.json");
        let original = fs::read(&manifest).unwrap();
        fs::write(&manifest, b"{}").unwrap();
        assert!(RetainedRuntime::open(&store, &reference).is_err());
        fs::write(&manifest, original).unwrap();
        for key in ["../outside", "C:/outside", "nested/path", "", "unrelated"] {
            let mut changed = reference.clone();
            changed.storage_key = key.into();
            assert!(RetainedRuntime::open(&store, &changed).is_err());
        }
        let mut changed = reference.clone();
        changed.manifest_identity.0[0] ^= 1;
        assert!(RetainedRuntime::open(&store, &changed).is_err());
        fs::remove_file(manifest).unwrap();
        assert!(RetainedRuntime::open(&store, &reference).is_err());
    }

    #[test]
    fn fresh_reopen_rejects_public_descendants_and_manifest() {
        use std::{os::windows::process::CommandExt as _, process::Command};
        for relative in [
            "payload/source/module.py",
            "payload/source/empty",
            "manifest.json",
        ] {
            let (_temp, store, _source, captured) = fixture();
            let retained = captured.retain().unwrap();
            let reference = retained.reference().clone();
            let target = retained.root().parent().unwrap().join(relative);
            drop(retained);
            assert!(
                Command::new("icacls")
                    .arg(&target)
                    .args(["/grant", "*S-1-1-0:R"])
                    .creation_flags(0x0800_0000)
                    .output()
                    .unwrap()
                    .status
                    .success()
            );
            assert!(
                RetainedRuntime::open(&store, &reference).is_err(),
                "accepted public {relative}"
            );
        }
    }

    #[test]
    fn fresh_reopen_rejects_weakened_privacy_and_directory_substitution() {
        use std::{os::windows::process::CommandExt as _, process::Command};
        let (_temp, store, _source, captured) = fixture();
        let retained = captured.retain().unwrap();
        let reference = retained.reference().clone();
        let root = retained.root().to_owned();
        drop(retained);
        let empty = root.join("source/empty");
        let outside = store.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("canary.py"), b"outside").unwrap();
        fs::remove_dir(&empty).unwrap();
        assert!(
            Command::new("cmd.exe")
                .args(["/d", "/c", "mklink", "/J"])
                .arg(&empty)
                .arg(&outside)
                .creation_flags(0x0800_0000)
                .output()
                .unwrap()
                .status
                .success()
        );
        assert!(RetainedRuntime::open(&store, &reference).is_err());
        fs::remove_dir(&empty).unwrap();
        fs::create_dir(&empty).unwrap();
        RetainedRuntime::open(&store, &reference).unwrap();
        assert!(
            Command::new("icacls")
                .arg(&root)
                .args(["/grant", "*S-1-1-0:(OI)(CI)R"])
                .creation_flags(0x0800_0000)
                .output()
                .unwrap()
                .status
                .success()
        );
        assert!(RetainedRuntime::open(&store, &reference).is_err());
        assert_eq!(fs::read(outside.join("canary.py")).unwrap(), b"outside");
    }

    #[test]
    fn interrupted_directory_flush_never_publishes_a_reference() {
        for fail_at in [1, 2] {
            let (_temp, _store, source, captured) = fixture();
            let holder = captured
                .root()
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .to_owned();
            let mut calls = 0;
            let result = captured.retain_with_directory_sync(|path| {
                calls += 1;
                assert!(holder.join("runtime/manifest.json").is_file());
                if calls == fail_at {
                    Err(invalid())
                } else {
                    OsNativeFileSystem::new()
                        .synchronize_directory(path)
                        .map_err(|_| invalid())
                }
            });
            assert!(result.is_err());
            assert_eq!(calls, fail_at);
            assert!(!holder.exists());
            assert_eq!(
                fs::read(source.join("module.py")).unwrap(),
                b"VALUE = 'approved'\n"
            );
        }
    }

    #[test]
    fn oversized_manifest_and_missing_empty_directory_are_rejected() {
        let (_temp, store, _source, captured) = fixture();
        let retained = captured.retain().unwrap();
        let reference = retained.reference().clone();
        let root = retained.root().to_owned();
        drop(retained);
        fs::remove_dir(root.join("source/empty")).unwrap();
        assert!(RetainedRuntime::open(&store, &reference).is_err());
        fs::create_dir(root.join("source/empty")).unwrap();
        RetainedRuntime::open(&store, &reference).unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(root.parent().unwrap().join(MANIFEST_NAME))
            .unwrap()
            .set_len(MAX_MANIFEST_BYTES as u64 + 1)
            .unwrap();
        assert!(RetainedRuntime::open(&store, &reference).is_err());
    }

    #[test]
    fn manifest_validation_rejects_schema_paths_aliases_and_missing_parents() {
        let (_temp, _store, _source, captured) = fixture();
        let original = captured.manifest().clone();
        validate_manifest(&original).unwrap();
        let mut changed = original.clone();
        changed.schema_version += 1;
        assert!(validate_manifest(&changed).is_err());
        for path in [
            "../outside.py",
            "C:/outside.py",
            "source/module.py:stream",
            "source/MODULE.py",
        ] {
            let mut changed = original.clone();
            let mut file = changed.files[0].clone();
            file.path = path.into();
            changed.files.push(file);
            changed.files.sort_by(|a, b| a.path.cmp(&b.path));
            assert!(validate_manifest(&changed).is_err(), "accepted {path}");
        }
        let mut changed = original;
        changed.directories.retain(|path| path != "source");
        assert!(validate_manifest(&changed).is_err());
    }

    #[test]
    fn failed_publication_retains_nothing_and_preserves_source() {
        let (_temp, _store, source, captured) = fixture();
        let root = captured.root().to_owned();
        fs::write(
            root.parent().unwrap().join("manifest.json"),
            b"unexpected prior manifest",
        )
        .unwrap();
        assert!(captured.retain().is_err());
        assert!(!root.exists());
        assert_eq!(
            fs::read(source.join("module.py")).unwrap(),
            b"VALUE = 'approved'\n"
        );
    }
}
