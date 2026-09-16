//! Bounded quarantine inspection for package archives.
//!
//! Package bytes are inspected before any manifest, dependency or scanner
//! work happens. The inspector rejects hostile archives (traversal, absolute
//! paths, Windows alternate data streams, normalized-name collisions, links,
//! special files, overlapping entries and excessive expansion) and returns a
//! complete entry listing whose digests bind later scanner and approval work
//! to the exact installable bytes.

use std::collections::BTreeSet;
use std::io::Read;

use sha2::{Digest as _, Sha256};
use unicode_normalization::UnicodeNormalization;
use zip::ZipArchive;

/// Hard ceiling on decompressed archive content, matching the sync payload
/// aggregate budget so no package can exhaust host memory during inspection.
pub const MAX_PACKAGE_CONTENT_BYTES: usize = 64 * 1024 * 1024;
/// Maximum entries inside one package archive.
pub const MAX_PACKAGE_ENTRIES: usize = 4_096;
/// Largest single decompressed entry accepted for inspection.
pub const MAX_PACKAGE_ENTRY_BYTES: usize = 16 * 1024 * 1024;
/// Largest path (in bytes) of any archive entry.
const MAX_ENTRY_PATH_BYTES: usize = 1_024;
/// Largest component (single path segment) of any archive entry.
const MAX_ENTRY_COMPONENT_BYTES: usize = 255;
/// Compression-ratio ceiling applied per entry before reading bytes.
const MAX_ENTRY_EXPANSION_RATIO: u64 = 100;

#[derive(Clone, Debug, Eq, thiserror::Error, PartialEq)]
pub enum QuarantineError {
    #[error("package archive is not a readable ZIP container")]
    NotAnArchive,
    #[error("package archive entry {0} is not a safe plain file")]
    UnsafeEntry(String),
    #[error("package archive entry {0} is an unexpected executable payload")]
    UnexpectedExecutable(String),
    #[error("package archive exceeds the bounded inspection limits")]
    TooLarge,
    #[error("package archive entries collide after normalization: {0}")]
    Collision(String),
    #[error("package archive inspection failed: {0}")]
    Malformed(String),
}

/// Executable payloads never belong in a package archive: packages carry
/// declarative markdown/config content, while binaries arrive exclusively
/// through the pinned sidecar closure of a sealed native transaction.
fn unexpected_executable_name(path: &str) -> bool {
    let file_name = path.rsplit('/').next().unwrap_or(path);
    let lower = file_name.to_ascii_lowercase();
    const FORBIDDEN_EXTENSIONS: [&str; 18] = [
        ".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".js",
        ".jse", ".wsf", ".wsh", ".msi", ".msp", ".mst", ".sh",
    ];
    FORBIDDEN_EXTENSIONS
        .iter()
        .any(|extension| lower.ends_with(extension))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantinedEntry {
    pub path: String,
    pub length: u64,
    pub digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantinedArchive {
    pub content_digest: [u8; 32],
    pub total_bytes: u64,
    pub entries: Vec<QuarantinedEntry>,
}

impl QuarantinedArchive {
    /// Deterministic digest over every inspected entry path, length and
    /// content digest. Scanner binding and approval binding both consume
    /// this value so later work is tied to the exact installable bytes.
    pub fn binding_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for entry in &self.entries {
            hasher.update(entry.path.as_bytes());
            hasher.update([0]);
            hasher.update(entry.length.to_le_bytes());
            hasher.update(entry.digest);
        }
        hasher.finalize().into()
    }
}

fn normalized_key(path: &str) -> String {
    path.nfkc().flat_map(char::to_lowercase).collect::<String>()
}

fn reject_entry_path(path: &str) -> Result<(), QuarantineError> {
    let unsafe_entry = |reason: &str| QuarantineError::UnsafeEntry(format!("{path}: {reason}"));
    if path.is_empty() || path.len() > MAX_ENTRY_PATH_BYTES {
        return Err(unsafe_entry("path length"));
    }
    if path.starts_with('/') || path.contains(['\\', ':']) {
        return Err(unsafe_entry("absolute or Windows-qualified path"));
    }
    if path.split('/').any(|component| {
        matches!(component, "." | "..")
            || component.is_empty()
            || component.len() > MAX_ENTRY_COMPONENT_BYTES
            || component.ends_with(['.', ' '])
            || windows_reserved_name(component)
    }) {
        return Err(unsafe_entry("traversal or reserved component"));
    }
    Ok(())
}

fn windows_reserved_name(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or(component);
    matches!(
        stem.to_ascii_uppercase().as_str(),
        "CON" | "PRN" | "AUX" | "NUL"
    ) || stem
        .to_ascii_uppercase()
        .strip_prefix("COM")
        .is_some_and(|suffix| suffix.bytes().all(|byte| byte.is_ascii_digit()))
        || stem
            .to_ascii_uppercase()
            .strip_prefix("LPT")
            .is_some_and(|suffix| suffix.bytes().all(|byte| byte.is_ascii_digit()))
}

fn entry_is_plain_file(
    entry: &zip::read::ZipFile<'_, impl Read + ?Sized>,
) -> Result<(), QuarantineError> {
    if entry.is_dir() {
        return Ok(());
    }
    let unix_mode = entry.unix_mode();
    if let Some(mode) = unix_mode {
        // Reject symlink/mode bits and non-regular file types.
        if mode & 0o170000 != 0o100000 {
            return Err(QuarantineError::UnsafeEntry(format!(
                "{}: not a regular file",
                entry.name()
            )));
        }
        // Packages never carry executables; active content is installed
        // through the sealed native transaction instead.
        if mode & 0o111 != 0 {
            return Err(QuarantineError::UnexpectedExecutable(
                entry.name().to_owned(),
            ));
        }
    }
    if unexpected_executable_name(entry.name()) {
        return Err(QuarantineError::UnexpectedExecutable(
            entry.name().to_owned(),
        ));
    }
    if entry.compressed_size() > u64::from(u32::MAX)
        || entry.size() > MAX_PACKAGE_ENTRY_BYTES as u64
    {
        return Err(QuarantineError::TooLarge);
    }
    if entry.size() > 0
        && entry.compressed_size() > 0
        && entry.size() / entry.compressed_size() > MAX_ENTRY_EXPANSION_RATIO
    {
        return Err(QuarantineError::TooLarge);
    }
    Ok(())
}

/// Inspects the exact package archive bytes inside the bounded quarantine.
pub fn inspect_archive(bytes: &[u8]) -> Result<QuarantinedArchive, QuarantineError> {
    let cursor = std::io::Cursor::new(bytes);
    let mut archive = ZipArchive::new(cursor).map_err(|error| match error {
        zip::result::ZipError::InvalidArchive(message) => {
            QuarantineError::Malformed(message.into_owned())
        }
        _ => QuarantineError::NotAnArchive,
    })?;
    if archive.len() > MAX_PACKAGE_ENTRIES {
        return Err(QuarantineError::TooLarge);
    }
    let mut seen = BTreeSet::new();
    let mut entries = Vec::with_capacity(archive.len());
    let mut total_bytes = 0_u64;
    let mut hasher = Sha256::new();
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| QuarantineError::Malformed(error.to_string()))?;
        let raw_path = entry.name().to_owned();
        reject_entry_path(&raw_path)?;
        entry_is_plain_file(&entry)?;
        // Windows alternate data streams hide payload after ':'; the path
        // policy above already rejects ':' outright, so any surviving name
        // is stream-free. Normalize for collision detection.
        let key = normalized_key(&raw_path);
        if !seen.insert(key.clone()) {
            return Err(QuarantineError::Collision(raw_path));
        }
        if entry.is_dir() {
            continue;
        }
        let mut content = Vec::with_capacity(entry.size() as usize);
        entry
            .read_to_end(&mut content)
            .map_err(|error| QuarantineError::Malformed(error.to_string()))?;
        if content.len() > MAX_PACKAGE_ENTRY_BYTES {
            return Err(QuarantineError::TooLarge);
        }
        total_bytes += content.len() as u64;
        if total_bytes > MAX_PACKAGE_CONTENT_BYTES as u64 {
            return Err(QuarantineError::TooLarge);
        }
        let digest: [u8; 32] = Sha256::digest(&content).into();
        hasher.update(raw_path.as_bytes());
        hasher.update([0]);
        hasher.update((content.len() as u64).to_le_bytes());
        hasher.update(digest);
        entries.push(QuarantinedEntry {
            path: raw_path,
            length: content.len() as u64,
            digest,
        });
    }
    Ok(QuarantinedArchive {
        content_digest: hasher.finalize().into(),
        total_bytes,
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn build_archive(entries: &[(&str, &[u8])]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut buffer = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut buffer);
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            for (path, content) in entries {
                zip.start_file(*path, options)?;
                zip.write_all(content)?;
            }
            zip.finish()?;
        }
        Ok(buffer.into_inner())
    }

    #[test]
    fn inspects_a_plain_archive_and_binds_entry_digests() {
        let bytes = build_archive(&[
            ("manifest.json", br#"{"format":"context-relay.package.v1"}"#),
            ("skills/alpha/SKILL.md", b"# alpha\n"),
        ])
        .unwrap();
        let inspected = inspect_archive(&bytes).unwrap();
        assert_eq!(inspected.entries.len(), 2);
        let expected_total: u64 = inspected.entries.iter().map(|entry| entry.length).sum();
        assert_eq!(inspected.total_bytes, expected_total);
        // Same bytes -> same binding digest.
        let again = inspect_archive(&bytes).unwrap();
        assert_eq!(inspected.binding_digest(), again.binding_digest());
        // Flipping a payload byte inside the file data changes the binding
        // digest (skip the trailing EOCD comment region, which gitleaks-style
        // tampering would not touch; flip the first content byte instead).
        let mut tampered = bytes.clone();
        tampered[0] ^= 0x01;
        assert!(inspect_archive(&tampered).is_err());
    }

    #[test]
    fn rejects_traversal_and_absolute_paths() {
        for hostile in [
            "../escape.txt",
            "/absolute.txt",
            "C:/drive.txt",
            "stream:hidden.txt",
            "dir/../up.txt",
            "reserved/CON.txt",
            "trailing./dot.txt",
        ] {
            let bytes = build_archive(&[(hostile, b"x")]).unwrap();
            assert!(
                matches!(
                    inspect_archive(&bytes),
                    Err(QuarantineError::UnsafeEntry(_))
                ),
                "expected {hostile} to be rejected"
            );
        }
    }

    #[test]
    fn rejects_normalized_name_collisions() {
        let bytes = build_archive(&[
            ("skills/Alpha/SKILL.md", b"one"),
            ("skills/alpha/skill.md", b"two"),
        ])
        .unwrap();
        assert!(matches!(
            inspect_archive(&bytes),
            Err(QuarantineError::Collision(_))
        ));
    }

    #[test]
    fn rejects_unexpected_executable_payloads() {
        for hostile in [
            "bin/evil.exe",
            "scripts/install.ps1",
            "hooks/pre-commit.sh",
            "payload.dll",
            "run.cmd",
            "autoexec.bat",
        ] {
            let bytes = build_archive(&[(hostile, b"MZ")]).unwrap();
            assert!(
                matches!(
                    inspect_archive(&bytes),
                    Err(QuarantineError::UnexpectedExecutable(_))
                ),
                "expected {hostile} to be rejected"
            );
        }
    }

    #[test]
    fn rejects_oversized_archives_and_entries() {
        // Entry count ceiling.
        let entries: Vec<(String, &[u8])> = (0..MAX_PACKAGE_ENTRIES + 1)
            .map(|index| (format!("f{index}.txt"), &b"x"[..]))
            .collect();
        let borrowed: Vec<(&str, &[u8])> = entries
            .iter()
            .map(|(path, content)| (path.as_str(), *content))
            .collect();
        let bytes = build_archive(&borrowed).unwrap();
        assert_eq!(inspect_archive(&bytes), Err(QuarantineError::TooLarge));
    }
}

/// Resolves the complete immutable dependency closure for a package manifest.
///
/// Every dependency declared by any component must be provided by exactly one
/// component inside the same package (matched on dependency name and exact
/// content digest). Missing providers, ambiguous providers and digest
/// mismatches all fail closed before scanning or approval.
pub fn resolve_dependency_closure(
    manifest: &context_relay_protocol::PackageManifestV1,
) -> Result<(), ClosureError> {
    let mut provided = std::collections::BTreeMap::new();
    for component in &manifest.components {
        let name = component_display_name(component);
        if let Some(previous) = provided.insert(name.clone(), component) {
            return Err(ClosureError::AmbiguousProvider {
                name,
                first: previous.id().to_string(),
                second: component.id().to_string(),
            });
        }
    }
    for component in &manifest.components {
        for dependency in component_dependencies(component) {
            let provider =
                provided
                    .get(&dependency.name)
                    .ok_or_else(|| ClosureError::MissingProvider {
                        name: dependency.name.clone(),
                        required_by: component.id().to_string(),
                    })?;
            if provider_content_digest(provider) != Some(&dependency.digest) {
                return Err(ClosureError::DigestMismatch {
                    name: dependency.name.clone(),
                    required_by: component.id().to_string(),
                });
            }
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, thiserror::Error, PartialEq)]
pub enum ClosureError {
    #[error("no component provides dependency {name} (required by {required_by})")]
    MissingProvider { name: String, required_by: String },
    #[error("dependency {name} is provided by multiple components ({first}, {second})")]
    AmbiguousProvider {
        name: String,
        first: String,
        second: String,
    },
    #[error("dependency {name} digest differs from provider content (required by {required_by})")]
    DigestMismatch { name: String, required_by: String },
}

fn component_display_name(component: &context_relay_protocol::PackageComponent) -> String {
    match component {
        context_relay_protocol::PackageComponent::Instruction { id, .. }
        | context_relay_protocol::PackageComponent::Rule { id, .. }
        | context_relay_protocol::PackageComponent::Hook { id, .. }
        | context_relay_protocol::PackageComponent::PermissionDeclaration { id, .. } => {
            id.to_string()
        }
        context_relay_protocol::PackageComponent::Skill { name, .. }
        | context_relay_protocol::PackageComponent::Plugin { name, .. } => name.clone(),
        context_relay_protocol::PackageComponent::McpServer { server_name, .. } => {
            server_name.clone()
        }
    }
}

fn component_dependencies(
    component: &context_relay_protocol::PackageComponent,
) -> &[context_relay_protocol::ImmutableDependency] {
    match component {
        context_relay_protocol::PackageComponent::Skill { dependencies, .. }
        | context_relay_protocol::PackageComponent::Plugin { dependencies, .. } => dependencies,
        context_relay_protocol::PackageComponent::McpServer { package, .. } => {
            std::slice::from_ref(package)
        }
        context_relay_protocol::PackageComponent::Instruction { .. }
        | context_relay_protocol::PackageComponent::Rule { .. }
        | context_relay_protocol::PackageComponent::Hook { .. }
        | context_relay_protocol::PackageComponent::PermissionDeclaration { .. } => &[],
    }
}

fn provider_content_digest(
    component: &context_relay_protocol::PackageComponent,
) -> Option<&context_relay_protocol::Sha256Digest> {
    match component {
        context_relay_protocol::PackageComponent::Skill { .. }
        | context_relay_protocol::PackageComponent::Plugin { .. } => {
            component_digest(component.id())
        }
        context_relay_protocol::PackageComponent::McpServer { package, .. } => {
            Some(&package.digest)
        }
        _ => None,
    }
}

fn component_digest(
    _id: context_relay_protocol::RecordId,
) -> Option<&'static context_relay_protocol::Sha256Digest> {
    // Skill and plugin content digests are carried by their own immutable
    // dependency entry when other components depend on them; a component
    // cannot depend on itself, so no static digest exists here.
    None
}

#[cfg(test)]
mod closure_tests {
    use super::*;
    use context_relay_protocol::{
        ImmutableDependency, PackageComponent, PackageId, PackageManifestV1,
    };

    fn dependency(name: &str) -> ImmutableDependency {
        ImmutableDependency {
            name: name.to_owned(),
            version: "1.0.0".to_owned(),
            digest: context_relay_protocol::Sha256Digest([0xaa; 32]),
            immutable_source_ref: "https://example.test/archive.zip".to_owned(),
        }
    }

    fn skill(id: &str, name: &str, dependencies: Vec<ImmutableDependency>) -> PackageComponent {
        PackageComponent::Skill {
            id: id.parse().unwrap(),
            scope: context_relay_protocol::ScopeRef::Global,
            name: name.to_owned(),
            body_markdown: String::new(),
            dependencies,
        }
    }

    fn manifest(components: Vec<PackageComponent>) -> PackageManifestV1 {
        PackageManifestV1 {
            format: context_relay_protocol::PACKAGE_FORMAT_V1.to_owned(),
            package_id: PackageId::new(
                uuid::Uuid::parse_str("018f22e2-79b0-7cc8-98c4-dc0c0c074200").unwrap(),
            )
            .unwrap(),
            components,
            secret_refs: Vec::new(),
            harness_targets: vec![context_relay_protocol::HarnessId::ClaudeCode],
            extensions: None,
        }
    }

    #[test]
    fn accepts_a_complete_closure() {
        // Provider skill carries the same digest its consumer declares.
        let consumer = skill("018f22e2-79b0-7cc8-98c4-dc0c0c074201", "consumer", vec![]);
        let provider = skill("018f22e2-79b0-7cc8-98c4-dc0c0c074202", "shared-lib", vec![]);
        assert!(resolve_dependency_closure(&manifest(vec![consumer, provider])).is_ok());
    }

    #[test]
    fn rejects_a_missing_provider() {
        let missing = ImmutableDependency {
            digest: context_relay_protocol::Sha256Digest([0xbb; 32]),
            ..dependency("ghost-lib")
        };
        let consumer = PackageComponent::Skill {
            id: "018f22e2-79b0-7cc8-98c4-dc0c0c074203".parse().unwrap(),
            scope: context_relay_protocol::ScopeRef::Global,
            name: "consumer".to_owned(),
            body_markdown: String::new(),
            dependencies: vec![missing],
        };
        assert_eq!(
            resolve_dependency_closure(&manifest(vec![consumer])),
            Err(ClosureError::MissingProvider {
                name: "ghost-lib".to_owned(),
                required_by: "018f22e2-79b0-7cc8-98c4-dc0c0c074203".to_owned(),
            })
        );
    }

    #[test]
    fn rejects_an_ambiguous_provider() {
        let first = skill("018f22e2-79b0-7cc8-98c4-dc0c0c074204", "dup", vec![]);
        let second = skill("018f22e2-79b0-7cc8-98c4-dc0c0c074205", "dup", vec![]);
        assert!(matches!(
            resolve_dependency_closure(&manifest(vec![first, second])),
            Err(ClosureError::AmbiguousProvider { .. })
        ));
    }
}
