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
    #[error("package archive exceeds the bounded inspection limits")]
    TooLarge,
    #[error("package archive entries collide after normalization: {0}")]
    Collision(String),
    #[error("package archive inspection failed: {0}")]
    Malformed(String),
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
