//! Retained local runtime bytes. A capture is identity, not launch permission.

mod literals;
#[cfg(windows)]
mod management;
#[cfg(all(test, windows))]
pub(super) use management::tests::{
    management_test_guard, prepared_runtime_fixture, runtime_fixture,
};
mod preparation;
mod projection;
use preparation::Control;
pub use preparation::{PreparationPhase, PreparationProgress};
#[cfg(windows)]
pub mod retained;

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

use context_relay_native_runner::StagePath;
use context_relay_protocol::{ClientError, Sha256Digest};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::python_installation::{file_identity, is_link, open_without_substitution, real_path};

const MAX_ENTRIES: usize = 32_768;
const MAX_DEPTH: usize = 32;
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 1024 * 1024 * 1024;

/// Persisted identity, not permission to execute. Reopening also verifies bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetainedRuntimeReference {
    schema_version: u32,
    storage_key: String,
    manifest_identity: Sha256Digest,
}

impl RetainedRuntimeReference {
    pub(crate) fn validate(&self) -> Result<(), ClientError> {
        let suffix = self
            .storage_key
            .strip_prefix("context-relay-hermes-runtime-")
            .ok_or_else(invalid)?;
        if self.schema_version != 1
            || !(6..=64).contains(&suffix.len())
            || !suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
        {
            return Err(invalid());
        }
        stage_path(&self.storage_key)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeFile {
    pub path: String,
    pub size: u64,
    pub sha256: Sha256Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeManifest {
    pub schema_version: u32,
    pub projection: String,
    pub source_roots: Vec<RuntimeSource>,
    pub directories: Vec<String>,
    pub files: Vec<RuntimeFile>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeSource {
    pub source: PathBuf,
    pub destination: String,
}

#[derive(Debug)]
pub struct CapturedRuntime {
    // Drop the handles before TempDir removes its owned tree.
    #[cfg(windows)]
    pin: context_relay_native_runner::PinnedNativeDirectory,
    #[cfg(windows)]
    container_pin: context_relay_native_runner::PinnedNativeDirectory,
    _directory: tempfile::TempDir,
    root: PathBuf,
    manifest: RuntimeManifest,
    identity: Sha256Digest,
}

impl CapturedRuntime {
    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn manifest(&self) -> &RuntimeManifest {
        &self.manifest
    }
    pub fn identity(&self) -> Sha256Digest {
        self.identity
    }
    pub fn verify(&self) -> Result<(), ClientError> {
        self.verify_controlled(&Control::new(&AtomicBool::new(false), &mut |_| {}))
    }
    fn verify_controlled(&self, control: &Control<'_>) -> Result<(), ClientError> {
        control.phase(PreparationPhase::CheckingCopy)?;
        #[cfg(windows)]
        self.pin.verify_path().map_err(|_| invalid())?;
        let observed = inventory_stage_controlled(
            self.root(),
            &mut |source, relative| {
                let file = read_file(source, relative, |bytes| control.bytes(bytes.len() as u64))?;
                control.file()?;
                Ok(file)
            },
            control,
        )?;
        if observed.directories != self.manifest.directories
            || observed.files != self.manifest.files
            || manifest_identity(&self.manifest)? != self.identity
        {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Capture the selected installed runtime without running its launcher or Python.
/// The returned bytes still need sealed approval and contained command qualification.
pub fn capture(executable: &Path, parent: &Path) -> Result<CapturedRuntime, ClientError> {
    capture_with_progress(executable, parent, &AtomicBool::new(false), |_| {})
}

/// Passive preparation with cooperative cancellation and phase-local counts.
/// The callback runs synchronously and should only record/coalesce progress.
pub fn capture_with_progress(
    executable: &Path,
    parent: &Path,
    cancelled: &AtomicBool,
    mut report: impl FnMut(PreparationProgress),
) -> Result<CapturedRuntime, ClientError> {
    let control = Control::new(cancelled, &mut report);
    control.phase(PreparationPhase::Inspecting)?;
    let installation = super::python_installation::inspect(executable)?.ok_or_else(invalid)?;
    control.check()?;
    let mut projection = projection::build_controlled(&installation, &control)?;
    control.check()?;
    projection.roots.push(SourceRoot {
        source: real_path(executable, false)?,
        destination: "metadata/hermes-launcher.exe".into(),
    });
    for (index, observation) in installation.metadata.iter().enumerate() {
        control.check()?;
        if !projection
            .roots
            .iter()
            .any(|root| observation.path.starts_with(&root.source))
        {
            projection.roots.push(SourceRoot {
                source: observation.path.clone(),
                destination: format!("metadata/observation-{index}"),
            });
        }
    }
    let mut captured = capture_inputs_controlled(parent, projection.roots, &control)?;
    verify_metadata_observations(&captured.manifest, &installation.metadata)?;
    for control in projection.controls {
        if !captured.manifest.files.contains(&control) {
            return Err(invalid());
        }
    }
    control.check()?;
    if super::python_installation::inspect(executable)?.as_ref() != Some(&installation) {
        return Err(invalid());
    }
    let mut expected = Inventory::default();
    for directory in &captured.manifest.directories {
        control.check()?;
        expected.directory(directory)?;
    }
    for file in &captured.manifest.files {
        control.check()?;
        expected.file(file.clone())?;
    }
    for (path, bytes) in projection.generated {
        control.check()?;
        stage_path(&path)?;
        if bytes.len() as u64 > MAX_FILE_BYTES {
            return Err(invalid());
        }
        expected.file(RuntimeFile {
            path: path.clone(),
            size: bytes.len() as u64,
            sha256: Sha256Digest(Sha256::digest(&bytes).into()),
        })?;
        let destination = captured.root().join(&path);
        fs::create_dir_all(destination.parent().ok_or_else(invalid)?).map_err(|_| invalid())?;
        real_path(destination.parent().ok_or_else(invalid)?, true)?;
        super::write_private_file(&destination, &bytes)?;
    }
    captured.manifest.directories = expected.directories.into_iter().collect();
    captured.manifest.files = expected.files.into_values().collect();
    captured.identity = manifest_identity(&captured.manifest)?;
    captured.verify_controlled(&control)?;
    Ok(captured)
}

type SourceRoot = RuntimeSource;

fn verify_metadata_observations(
    manifest: &RuntimeManifest,
    observations: &[super::python_installation::MetadataObservation],
) -> Result<(), ClientError> {
    for observation in observations {
        let root = manifest
            .source_roots
            .iter()
            .find(|root| observation.path.starts_with(&root.source))
            .ok_or_else(invalid)?;
        let suffix = observation
            .path
            .strip_prefix(&root.source)
            .map_err(|_| invalid())?;
        let mut destination = root.destination.clone();
        for part in suffix.components() {
            let std::path::Component::Normal(name) = part else {
                return Err(invalid());
            };
            destination.push('/');
            destination.push_str(name.to_str().ok_or_else(invalid)?);
        }
        stage_path(&destination)?;
        if !manifest
            .files
            .iter()
            .any(|file| file.path == destination && file.sha256 == observation.sha256)
        {
            return Err(invalid());
        }
    }
    Ok(())
}

#[cfg(test)]
fn capture_inputs(parent: &Path, roots: Vec<SourceRoot>) -> Result<CapturedRuntime, ClientError> {
    capture_inputs_controlled(
        parent,
        roots,
        &Control::new(&AtomicBool::new(false), &mut |_| {}),
    )
}

#[cfg(all(test, windows))]
pub(super) fn inert_prepared_fixture(
    launcher: &[u8],
) -> (tempfile::TempDir, retained::PreparedRuntime) {
    let store = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(store.path()).unwrap();
    let source = root.join("source");
    fs::create_dir(&source).unwrap();
    let mut roots = vec![];
    for (name, destination, bytes) in [
        (
            "python",
            "python/python.exe",
            b"inert: must never execute".as_slice(),
        ),
        (
            "bootstrap",
            "bootstrap.py",
            b"raise RuntimeError('must never execute')".as_slice(),
        ),
        ("launcher", "metadata/hermes-launcher.exe", launcher),
    ] {
        let path = source.join(name);
        fs::write(&path, bytes).unwrap();
        roots.push(RuntimeSource {
            source: path,
            destination: destination.into(),
        });
    }
    let prepared = capture_inputs(&root, roots)
        .unwrap()
        .prepare_owned_with_progress(&AtomicBool::new(false), |_| {})
        .unwrap();
    (store, prepared)
}

fn capture_inputs_controlled(
    parent: &Path,
    mut roots: Vec<SourceRoot>,
    control: &Control<'_>,
) -> Result<CapturedRuntime, ClientError> {
    control.phase(PreparationPhase::Copying)?;
    let parent = real_path(parent, true)?;
    if roots.is_empty() || roots.len() > 128 {
        return Err(invalid());
    }
    roots.sort_by(|left, right| left.destination.cmp(&right.destination));
    for pair in roots.windows(2) {
        if pair[1].destination == pair[0].destination
            || pair[1]
                .destination
                .starts_with(&(pair[0].destination.clone() + "/"))
        {
            return Err(invalid());
        }
    }
    for root in &mut roots {
        control.check()?;
        stage_path(&root.destination)?;
        let metadata = fs::symlink_metadata(&root.source).map_err(|_| invalid())?;
        root.source = real_path(&root.source, metadata.is_dir())?;
        if metadata.is_dir() && parent.starts_with(&root.source) {
            return Err(invalid());
        }
    }
    let mut builder = tempfile::Builder::new();
    builder.prefix("context-relay-hermes-runtime-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        builder.permissions(fs::Permissions::from_mode(0o700));
    }
    let directory = builder.tempdir_in(&parent).map_err(|_| invalid())?;
    let container = directory.path().join("runtime");
    let root_path = container.join("payload");
    #[cfg(windows)]
    let container_pin = context_relay_native_runner::OsNativeFileSystem::new()
        .create_private_directory(&container)
        .map_err(|_| invalid())?;
    #[cfg(windows)]
    let pin = context_relay_native_runner::OsNativeFileSystem::new()
        .create_private_directory(&root_path)
        .map_err(|_| invalid())?;
    #[cfg(not(windows))]
    {
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        builder.create(&container).map_err(|_| invalid())?;
        builder.create(&root_path).map_err(|_| invalid())?;
    }
    #[cfg(test)]
    let started = std::time::Instant::now();
    let mut inventory = Inventory::default();
    for root in &roots {
        capture_node(
            &root.source,
            &root.destination,
            &root_path,
            &mut inventory,
            0,
            control,
        )?;
    }
    #[cfg(test)]
    if inventory.files.len() > 1000 {
        eprintln!("Runtime copy: {:?}", started.elapsed());
    }
    // A fresh complete source inventory catches additions/deletions during copy,
    // including files that did not exist when their parent was first visited.
    let mut current = Inventory::default();
    control.phase(PreparationPhase::CheckingSource)?;
    for root in &roots {
        inspect_node(
            &root.source,
            &root.destination,
            &mut current,
            0,
            true,
            control,
        )?;
    }
    if current != inventory {
        return Err(invalid());
    }
    #[cfg(test)]
    if inventory.files.len() > 1000 {
        eprintln!("Runtime copy + source recheck: {:?}", started.elapsed());
    }
    let manifest = RuntimeManifest {
        schema_version: 1,
        projection: "hermes-python-source-first-v1".into(),
        source_roots: roots,
        directories: inventory.directories.into_iter().collect(),
        files: inventory.files.into_values().collect(),
    };
    let identity = manifest_identity(&manifest)?;
    let captured = CapturedRuntime {
        #[cfg(windows)]
        pin,
        #[cfg(windows)]
        container_pin,
        _directory: directory,
        root: root_path,
        manifest,
        identity,
    };
    Ok(captured)
}

fn invalid() -> ClientError {
    super::invalid("Hermes Python runtime could not be captured consistently")
}

#[derive(Default, Debug, Eq, PartialEq)]
struct Inventory {
    directories: BTreeSet<String>,
    files: BTreeMap<String, RuntimeFile>,
    total: u64,
}

impl Inventory {
    fn parents(&mut self, path: &str) -> Result<(), ClientError> {
        let mut prefix = String::new();
        let parts: Vec<_> = path.split('/').collect();
        for part in &parts[..parts.len().saturating_sub(1)] {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(part);
            self.directory(&prefix)?;
        }
        Ok(())
    }
    fn directory(&mut self, path: &str) -> Result<(), ClientError> {
        stage_path(path)?;
        if self.files.contains_key(path) {
            return Err(invalid());
        }
        self.directories.insert(path.to_owned());
        self.check_limit()
    }
    fn file(&mut self, file: RuntimeFile) -> Result<(), ClientError> {
        self.parents(&file.path)?;
        if file.size > MAX_FILE_BYTES
            || self.directories.contains(&file.path)
            || self.files.contains_key(&file.path)
        {
            return Err(invalid());
        }
        self.total = self.total.checked_add(file.size).ok_or_else(invalid)?;
        if self.total > MAX_TOTAL_BYTES {
            return Err(invalid());
        }
        self.files.insert(file.path.clone(), file);
        self.check_limit()
    }
    fn check_limit(&self) -> Result<(), ClientError> {
        if self.files.len() + self.directories.len() > MAX_ENTRIES {
            return Err(invalid());
        }
        Ok(())
    }
}

fn stage_path(path: &str) -> Result<StagePath, ClientError> {
    StagePath::try_from(path).map_err(|_| invalid())
}

fn manifest_identity(manifest: &RuntimeManifest) -> Result<Sha256Digest, ClientError> {
    let bytes = serde_json::to_vec(manifest).map_err(|_| invalid())?;
    Ok(manifest_bytes_identity(&bytes))
}

fn manifest_bytes_identity(bytes: &[u8]) -> Sha256Digest {
    let mut hash = Sha256::new();
    hash.update(b"context-relay/hermes-python-runtime/v1\0");
    hash.update(bytes);
    Sha256Digest(hash.finalize().into())
}

fn omitted_source(path: &Path) -> Result<bool, ClientError> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(invalid)?;
    if name.eq_ignore_ascii_case("__pycache__") {
        // Python does not import orphaned PEP 3147 cache files from this directory.
        real_path(path, true)?;
        return Ok(true);
    }
    if name.to_ascii_lowercase().ends_with(".pyc") || name.to_ascii_lowercase().ends_with(".pyo") {
        // Legacy bytecode beside modules can be importable without source. Such
        // installations cannot be represented by this source-first projection.
        real_path(path, false)?;
        real_path(&path.with_extension("py"), false)?;
        return Ok(true);
    }
    Ok(false)
}

fn validate_source_destination(relative: &str) -> Result<(), ClientError> {
    if let Some(path) = relative.strip_prefix("source/") {
        projection::safe_pattern(path)?;
    }
    Ok(())
}

fn reject_private_name(path: &Path) -> Result<(), ClientError> {
    if path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            matches!(
                name.to_ascii_lowercase().as_str(),
                ".env" | ".envrc" | ".git" | "auth.json" | "credentials.json"
            )
        })
    {
        return Err(invalid());
    }
    Ok(())
}

fn children_controlled(
    path: &Path,
    control: &Control<'_>,
) -> Result<Vec<(String, PathBuf)>, ClientError> {
    control.check()?;
    real_path(path, true)?;
    let mut entries = Vec::new();
    for entry in fs::read_dir(path).map_err(|_| invalid())? {
        control.check()?;
        if entries.len() >= MAX_ENTRIES {
            return Err(invalid());
        }
        let entry = entry.map_err(|_| invalid())?;
        let name = entry.file_name().into_string().map_err(|_| invalid())?;
        stage_path(&name)?;
        entries.push((name, entry.path()));
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    control.check()?;
    // ASCII NFKC is unchanged and ordinal case equivalence is exactly ASCII
    // uppercase. Avoid quadratic comparisons in large package directories.
    if entries.iter().all(|(name, _)| name.is_ascii()) {
        let mut aliases = BTreeSet::new();
        for (name, _) in &entries {
            control.check()?;
            if !aliases.insert(name.to_ascii_uppercase()) {
                return Err(invalid());
            }
        }
        return Ok(entries);
    }
    control.check_paths(
        &entries
            .iter()
            .map(|(name, _)| stage_path(name))
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    Ok(entries)
}

fn capture_node(
    source: &Path,
    relative: &str,
    stage: &Path,
    inventory: &mut Inventory,
    depth: usize,
    control: &Control<'_>,
) -> Result<(), ClientError> {
    control.check()?;
    if depth > MAX_DEPTH {
        return Err(invalid());
    }
    validate_source_destination(relative)?;
    if omitted_source(source)? {
        return Ok(());
    }
    reject_private_name(source)?;
    let metadata = fs::symlink_metadata(source).map_err(|_| invalid())?;
    real_path(source, metadata.is_dir())?;
    if metadata.is_dir() {
        inventory.parents(relative)?;
        inventory.directory(relative)?;
        fs::create_dir_all(stage.join(relative)).map_err(|_| invalid())?;
        for (name, path) in children_controlled(source, control)? {
            capture_node(
                &path,
                &format!("{relative}/{name}"),
                stage,
                inventory,
                depth + 1,
                control,
            )?;
        }
    } else {
        inventory.parents(relative)?;
        let destination = stage.join(relative);
        fs::create_dir_all(destination.parent().ok_or_else(invalid)?).map_err(|_| invalid())?;
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&destination)
            .map_err(|_| invalid())?;
        let remaining = MAX_TOTAL_BYTES
            .checked_sub(inventory.total)
            .ok_or_else(invalid)?;
        let mut copied = 0u64;
        let file = read_file(source, relative, |bytes| {
            control.check()?;
            copied += bytes.len() as u64;
            if copied > remaining {
                return Err(invalid());
            }
            output.write_all(bytes).map_err(|_| invalid())?;
            control.bytes(bytes.len() as u64)
        })?;
        // This temporary capture has no durable approval. Verify readable bytes
        // after copying; a future durable promotion must flush before sealing.
        inventory.file(file)?;
        control.file()?;
    }
    Ok(())
}

fn inspect_node(
    source: &Path,
    relative: &str,
    inventory: &mut Inventory,
    depth: usize,
    source_policy: bool,
    control: &Control<'_>,
) -> Result<(), ClientError> {
    inspect_node_with(
        source,
        relative,
        inventory,
        depth,
        source_policy,
        &mut |source, relative| {
            let file = read_file(source, relative, |bytes| control.bytes(bytes.len() as u64))?;
            control.file()?;
            Ok(file)
        },
        control,
    )
}

fn inspect_node_with(
    source: &Path,
    relative: &str,
    inventory: &mut Inventory,
    depth: usize,
    source_policy: bool,
    reader: &mut impl FnMut(&Path, &str) -> Result<RuntimeFile, ClientError>,
    control: &Control<'_>,
) -> Result<(), ClientError> {
    control.check()?;
    if depth > MAX_DEPTH {
        return Err(invalid());
    }
    validate_source_destination(relative)?;
    if source_policy && omitted_source(source)? {
        return Ok(());
    }
    reject_private_name(source)?;
    let metadata = fs::symlink_metadata(source).map_err(|_| invalid())?;
    real_path(source, metadata.is_dir())?;
    if metadata.is_dir() {
        inventory.parents(relative)?;
        inventory.directory(relative)?;
        for (name, path) in children_controlled(source, control)? {
            inspect_node_with(
                &path,
                &format!("{relative}/{name}"),
                inventory,
                depth + 1,
                source_policy,
                reader,
                control,
            )?;
        }
    } else {
        inventory.file(reader(source, relative)?)?;
    }
    Ok(())
}

fn inventory_stage_controlled(
    stage: &Path,
    reader: &mut impl FnMut(&Path, &str) -> Result<RuntimeFile, ClientError>,
    control: &Control<'_>,
) -> Result<RuntimeManifest, ClientError> {
    control.check()?;
    let mut inventory = Inventory::default();
    for (name, path) in children_controlled(stage, control)? {
        inspect_node_with(&path, &name, &mut inventory, 0, false, reader, control)?;
    }
    Ok(RuntimeManifest {
        schema_version: 1,
        projection: String::new(),
        source_roots: Vec::new(),
        directories: inventory.directories.into_iter().collect(),
        files: inventory.files.into_values().collect(),
    })
}

fn read_file(
    source: &Path,
    relative: &str,
    mut consume: impl FnMut(&[u8]) -> Result<(), ClientError>,
) -> Result<RuntimeFile, ClientError> {
    stage_path(relative)?;
    let source = real_path(source, false)?;
    let mut input = open_without_substitution(&source).map_err(|_| invalid())?;
    let before = input.metadata().map_err(|_| invalid())?;
    if !before.is_file() || is_link(&before) || before.len() > MAX_FILE_BYTES {
        return Err(invalid());
    }
    real_path(&source, false)?;
    let mut size = 0u64;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = input.read(&mut buffer).map_err(|_| invalid())?;
        if count == 0 {
            break;
        }
        size += count as u64;
        if size > MAX_FILE_BYTES {
            return Err(invalid());
        }
        hash.update(&buffer[..count]);
        consume(&buffer[..count])?;
    }
    let current = open_without_substitution(&source).map_err(|_| invalid())?;
    real_path(&source, false)?;
    let after = input.metadata().map_err(|_| invalid())?;
    if size != before.len()
        || after.len() != before.len()
        || after.modified().map_err(|_| invalid())? != before.modified().map_err(|_| invalid())?
        || file_identity(&input).map_err(|_| invalid())?
            != file_identity(&current).map_err(|_| invalid())?
    {
        return Err(invalid());
    }
    Ok(RuntimeFile {
        path: relative.to_owned(),
        size,
        sha256: Sha256Digest(hash.finalize().into()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn retained_bytes_survive_source_changes_and_verify_exact_inventory() {
        let temp = tempfile::tempdir().unwrap();
        let parent = fs::canonicalize(temp.path()).unwrap();
        let source = parent.join("source");
        fs::create_dir(&source).unwrap();
        fs::create_dir(source.join("empty")).unwrap();
        fs::write(source.join("module.py"), b"VALUE = 'original'\n").unwrap();
        let captured = capture_inputs(
            &parent,
            vec![SourceRoot {
                source: source.clone(),
                destination: "source".into(),
            }],
        )
        .unwrap();
        captured.verify().unwrap();
        fs::write(source.join("module.py"), b"VALUE = 'changed'\n").unwrap();
        assert_eq!(
            fs::read(captured.root().join("source/module.py")).unwrap(),
            b"VALUE = 'original'\n"
        );
        captured.verify().unwrap();
        fs::write(captured.root().join("source/extra.py"), b"unexpected").unwrap();
        assert!(captured.verify().is_err());
        fs::remove_file(captured.root().join("source/extra.py")).unwrap();
        fs::remove_dir(captured.root().join("source/empty")).unwrap();
        assert!(captured.verify().is_err());
    }

    #[test]
    fn capture_identity_is_deterministic_and_detects_changed_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let parent = fs::canonicalize(temp.path()).unwrap();
        let source = parent.join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("module.py"), b"original").unwrap();
        let capture = || {
            capture_inputs(
                &parent,
                vec![SourceRoot {
                    source: source.clone(),
                    destination: "source".into(),
                }],
            )
            .unwrap()
        };
        let first = capture();
        let second = capture();
        assert_eq!(first.identity(), second.identity());
        fs::write(first.root().join("source/module.py"), b"tampered").unwrap();
        assert!(first.verify().is_err());
        second.verify().unwrap();
    }

    #[test]
    fn capture_rejects_oversized_files_deep_trees_and_unicode_aliases() {
        let temp = tempfile::tempdir().unwrap();
        let parent = fs::canonicalize(temp.path()).unwrap();
        let source = parent.join("source");
        fs::create_dir(&source).unwrap();
        let capture = || {
            capture_inputs(
                &parent,
                vec![SourceRoot {
                    source: source.clone(),
                    destination: "source".into(),
                }],
            )
        };
        let large = fs::File::create(source.join("large.bin")).unwrap();
        large.set_len(MAX_FILE_BYTES + 1).unwrap();
        drop(large);
        assert!(capture().is_err());
        fs::remove_file(source.join("large.bin")).unwrap();
        fs::write(source.join("A.py"), b"one").unwrap();
        fs::write(source.join("Ａ.py"), b"two").unwrap();
        assert!(capture().is_err());
        fs::remove_file(source.join("Ａ.py")).unwrap();
        let mut nested = source.clone();
        for _ in 0..=MAX_DEPTH {
            nested.push("d");
            fs::create_dir(&nested).unwrap();
        }
        assert!(capture().is_err());
    }

    #[cfg(windows)]
    #[test]
    fn capture_and_recheck_reject_junctions_without_reading_outside_tree() {
        use std::{os::windows::process::CommandExt as _, process::Command};
        let temp = tempfile::tempdir().unwrap();
        let parent = fs::canonicalize(temp.path()).unwrap();
        let source = parent.join("source");
        let outside = parent.join("outside");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("canary.py"), b"outside").unwrap();
        let junction = |path: &Path| {
            assert!(
                Command::new("cmd.exe")
                    .args(["/d", "/c", "mklink", "/J"])
                    .arg(path)
                    .arg(&outside)
                    .creation_flags(0x0800_0000)
                    .output()
                    .unwrap()
                    .status
                    .success()
            );
        };
        let capture = || {
            capture_inputs(
                &parent,
                vec![SourceRoot {
                    source: source.clone(),
                    destination: "source".into(),
                }],
            )
        };
        let link = source.join("linked");
        junction(&link);
        assert!(capture().is_err());
        fs::remove_dir(&link).unwrap();
        let captured = capture().unwrap();
        let staged_link = captured.root().join("source/linked");
        junction(&staged_link);
        assert!(captured.verify().is_err());
        fs::remove_dir(&staged_link).unwrap();
        captured.verify().unwrap();
        assert_eq!(fs::read(outside.join("canary.py")).unwrap(), b"outside");
    }

    #[test]
    fn source_first_capture_rejects_sourceless_bytecode() {
        let temp = tempfile::tempdir().unwrap();
        let parent = fs::canonicalize(temp.path()).unwrap();
        let source = parent.join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("only.pyc"), b"sourceless module").unwrap();
        let capture = || {
            capture_inputs(
                &parent,
                vec![SourceRoot {
                    source: source.clone(),
                    destination: "source".into(),
                }],
            )
        };
        assert!(capture().is_err());
        fs::write(source.join("only.py"), b"VALUE = 'source'").unwrap();
        let captured = capture().unwrap();
        assert!(!captured.root().join("source/only.pyc").exists());
        captured.verify().unwrap();
        fs::write(captured.root().join("source/only.pyc"), b"injected").unwrap();
        assert!(captured.verify().is_err());
    }

    #[test]
    fn retained_metadata_must_match_original_discovery_even_if_live_bytes_revert() {
        let temp = tempfile::tempdir().unwrap();
        let parent = fs::canonicalize(temp.path()).unwrap();
        let source = parent.join("metadata");
        fs::create_dir(&source).unwrap();
        let path = source.join("METADATA");
        fs::write(&path, b"version A").unwrap();
        let original = super::super::python_installation::MetadataObservation {
            path: path.clone(),
            sha256: Sha256Digest(Sha256::digest(b"version A").into()),
        };
        fs::write(&path, b"version B").unwrap();
        let captured = capture_inputs(
            &parent,
            vec![SourceRoot {
                source: source.clone(),
                destination: "packages/dist-info".into(),
            }],
        )
        .unwrap();
        fs::write(&path, b"version A").unwrap();
        assert!(
            verify_metadata_observations(captured.manifest(), std::slice::from_ref(&original))
                .is_err()
        );
        let captured = capture_inputs(
            &parent,
            vec![SourceRoot {
                source: path,
                destination: "metadata/observation-0".into(),
            }],
        )
        .unwrap();
        verify_metadata_observations(captured.manifest(), &[original]).unwrap();
    }

    #[test]
    fn source_roots_cannot_capture_excluded_checkout_trees() {
        let temp = tempfile::tempdir().unwrap();
        let parent = fs::canonicalize(temp.path()).unwrap();
        for name in ["venv", "node_modules", ".venv", "VENV"] {
            let source = parent.join(name);
            fs::create_dir_all(&source).unwrap();
            fs::write(source.join("canary"), b"must not capture").unwrap();
            assert!(
                capture_inputs(
                    &parent,
                    vec![SourceRoot {
                        source,
                        destination: format!("source/{name}")
                    }]
                )
                .is_err()
            );
        }
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "opt-in retained Hermes management checks; requires an explicit installation path"]
    fn installed_retained_management_checks_use_owned_runtime_and_isolated_home() {
        use context_relay_native_runner::{
            OsNativeFileSystem,
            windows_management::{HermesManagementCommand, run_hermes_python},
        };
        use std::{sync::atomic::AtomicBool, time::Instant};
        let executable = std::env::var_os("CONTEXT_RELAY_HERMES_METADATA_EXE")
            .expect("select a Hermes installation explicitly");
        let temp = tempfile::tempdir().unwrap();
        let parent = fs::canonicalize(temp.path()).unwrap();
        let started = Instant::now();
        println!("Capturing selected runtime for owned management checks");
        let captured = capture(Path::new(&executable), &parent).unwrap();
        let retained = captured.retain().unwrap();
        let reference = retained.reference().clone();
        drop(retained);
        let locked = retained::RetainedRuntime::open(&parent, &reference)
            .unwrap()
            .lock()
            .unwrap();
        println!(
            "Reopened and locked {} runtime files at {:?}",
            locked.manifest().files.len(),
            started.elapsed()
        );
        let root = locked.root().to_owned();
        let home = parent.join("management-home");
        let home_pin = OsNativeFileSystem::new()
            .create_private_directory(&home)
            .unwrap();
        fs::write(home.join("config.yaml"), b"{}\n").unwrap();
        let mut owner = (locked, home_pin, temp);
        for (command, marker) in [
            (HermesManagementCommand::Version, "0.17.0"),
            (HermesManagementCommand::ConfigCheck, "Configuration Status"),
        ] {
            println!(
                "Starting {command:?} with isolated synthetic home at {:?}",
                started.elapsed()
            );
            let (output, returned) =
                run_hermes_python(&root, &home, command, owner, &AtomicBool::new(false)).unwrap();
            owner = returned;
            let stdout = String::from_utf8(output.stdout).unwrap();
            let stderr = String::from_utf8(output.stderr).unwrap();
            println!(
                "{command:?} exit={} stdout={stdout} stderr={stderr}",
                output.exit_code
            );
            assert_eq!(output.exit_code, 0);
            assert!(stdout.contains(marker));
            owner.0.verify().unwrap();
        }
        println!(
            "Both retained Hermes management commands completed; inventory verified at {:?}",
            started.elapsed()
        );
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "opt-in capture and isolated copied-CPython probe; requires an explicit Hermes path"]
    fn installed_runtime_capture_has_only_staged_python_paths() {
        use process_wrap::std::{ChildWrapper, CommandWrap, CreationFlags, JobObject};
        use std::{
            process::{Command, Stdio},
            thread,
            time::{Duration, Instant},
        };
        struct OwnedChild(Box<dyn ChildWrapper>);
        impl Drop for OwnedChild {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let executable = std::env::var_os("CONTEXT_RELAY_HERMES_METADATA_EXE")
            .expect("select a Hermes installation explicitly");
        let temp = tempfile::tempdir().unwrap();
        let parent = fs::canonicalize(temp.path()).unwrap();
        println!("Capturing the selected installation without running it");
        let started = Instant::now();
        let captured = capture(Path::new(&executable), &parent).unwrap();
        println!(
            "Captured {} files / {} directories / {} bytes in {:?}",
            captured.manifest.files.len(),
            captured.manifest.directories.len(),
            captured
                .manifest
                .files
                .iter()
                .map(|file| file.size)
                .sum::<u64>(),
            started.elapsed()
        );
        let retained = captured.retain().unwrap();
        let reference =
            serde_json::from_slice(&serde_json::to_vec(retained.reference()).unwrap()).unwrap();
        drop(retained);
        println!(
            "Retained runtime flushed; reopening from serialized identity at {:?}",
            started.elapsed()
        );
        let captured = retained::RetainedRuntime::open(&parent, &reference).unwrap();
        println!(
            "Fresh retained-runtime verification passed at {:?}",
            started.elapsed()
        );
        let home = parent.join("probe-home");
        fs::create_dir(&home).unwrap();
        fs::write(
            home.join("sitecustomize.py"),
            format!(
                "from pathlib import Path\nPath({:?}).write_text('executed')\n",
                home.join("canary")
            ),
        )
        .unwrap();
        let output = parent.join("stdout.txt");
        let errors = parent.join("stderr.txt");
        let mut command = Command::new(captured.root().join("python/python.exe"));
        command
            .args(["-I", "-S", "-B"])
            .arg(captured.root().join("bootstrap.py"))
            .arg("path-probe")
            .current_dir(&home)
            .env_clear()
            .env("HOME", &home)
            .env("HERMES_HOME", &home)
            .env("USERPROFILE", &home)
            .env("APPDATA", &home)
            .env("LOCALAPPDATA", &home)
            .env("PYTHONPATH", &home)
            .env("PYTHONHOME", &home)
            .env("PATH", super::super::minimal_system_path())
            .stdin(Stdio::null())
            .stdout(fs::File::create(&output).unwrap())
            .stderr(fs::File::create(&errors).unwrap());
        if let Some(system_root) = std::env::var_os("SystemRoot") {
            command.env("SystemRoot", system_root);
        }
        let mut wrapped = CommandWrap::from(command);
        let mut flags = CreationFlags(Default::default());
        flags.0.0 = 0x0800_0000;
        wrapped.wrap(flags).wrap(JobObject);
        let mut child = OwnedChild(wrapped.spawn().unwrap());
        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            assert!(
                started.elapsed() < Duration::from_secs(15),
                "copied Python probe timed out"
            );
            thread::sleep(Duration::from_millis(20));
        };
        assert!(
            status.success(),
            "copied Python failed: {}",
            fs::read_to_string(&errors).unwrap()
        );
        assert!(fs::metadata(&output).unwrap().len() <= 64 * 1024);
        assert_eq!(fs::metadata(&errors).unwrap().len(), 0);
        let report: serde_json::Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
        assert_eq!(report["isolated"], 1);
        assert_eq!(report["noSite"], 1);
        assert_eq!(report["siteLoaded"], false);
        for path in report["paths"].as_array().unwrap() {
            assert!(
                fs::canonicalize(path.as_str().unwrap())
                    .unwrap()
                    .starts_with(captured.root())
            );
        }
        assert!(!home.join("canary").exists());
        captured.verify().unwrap();
        println!("Copied CPython path probe passed; no Hermes command was invoked");
    }
}
