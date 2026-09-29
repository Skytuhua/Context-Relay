use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use context_relay_protocol::ClientError;

use super::{HermesProfile, invalid, not_found};

pub(super) fn enumerate_profiles(default_root: &Path) -> Result<Vec<HermesProfile>, ClientError> {
    let default_root =
        canonical_real_directory(default_root, "Hermes default profile was not found")?;
    let mut profiles = vec![HermesProfile {
        name: super::DEFAULT_PROFILE.to_owned(),
        hermes_home: default_root.clone(),
    }];
    let profiles_root = default_root.join("profiles");
    if !profiles_root.exists() {
        return Ok(profiles);
    }
    let metadata = fs::symlink_metadata(&profiles_root)
        .map_err(|_| not_found("Hermes profiles root was not found"))?;
    if is_link_or_reparse_point(&metadata) || !metadata.is_dir() {
        return Ok(profiles);
    }
    let profiles_root = fs::canonicalize(&profiles_root)
        .map_err(|_| invalid("Hermes profiles root cannot be safely resolved"))?;
    let mut candidates = BTreeMap::<String, Vec<(String, PathBuf)>>::new();
    for entry in
        fs::read_dir(&profiles_root).map_err(|_| invalid("Hermes profiles cannot be enumerated"))?
    {
        let entry = entry.map_err(|_| invalid("Hermes profile entry cannot be inspected"))?;
        let source_name = match entry.file_name().into_string() {
            Ok(name) => name,
            Err(_) => continue,
        };
        let normalized = ascii_lowercase(&source_name);
        if !valid_profile_name(&normalized) {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|_| invalid("Hermes profile entry cannot be inspected"))?;
        if is_link_or_reparse_point(&metadata) || !metadata.is_dir() {
            continue;
        }
        let candidate = fs::canonicalize(entry.path())
            .map_err(|_| invalid("Hermes profile cannot be safely resolved"))?;
        if candidate.parent() != Some(profiles_root.as_path()) {
            continue;
        }
        candidates
            .entry(normalized)
            .or_default()
            .push((source_name, candidate));
    }
    let mut roots = BTreeSet::new();
    for (name, entries) in candidates {
        let spellings = entries
            .iter()
            .map(|(spelling, _)| spelling)
            .collect::<BTreeSet<_>>();
        if spellings.len() != 1 || !valid_profile_name(entries[0].0.as_str()) {
            continue;
        }
        let home = entries[0].1.clone();
        if !roots.insert(home.clone()) {
            continue;
        }
        profiles.push(HermesProfile {
            name,
            hermes_home: home,
        });
    }
    profiles.sort_by(
        |left, right| match (left.name.as_str(), right.name.as_str()) {
            (super::DEFAULT_PROFILE, super::DEFAULT_PROFILE) => std::cmp::Ordering::Equal,
            (super::DEFAULT_PROFILE, _) => std::cmp::Ordering::Less,
            (_, super::DEFAULT_PROFILE) => std::cmp::Ordering::Greater,
            _ => left.name.cmp(&right.name),
        },
    );
    Ok(profiles)
}

pub(super) fn select_profile(
    default_root: &Path,
    requested: &str,
) -> Result<HermesProfile, ClientError> {
    let requested = ascii_lowercase(requested);
    enumerate_profiles(default_root)?
        .into_iter()
        .find(|profile| profile.name == requested)
        .ok_or_else(|| not_found("Hermes profile was not found"))
}

pub(super) fn validate_profile_binding(
    default_root: &Path,
    selected: &HermesProfile,
) -> Result<(), ClientError> {
    let expected = select_profile(default_root, &selected.name)?;
    let selected_home = fs::canonicalize(&selected.hermes_home)
        .map_err(|_| not_found("Hermes selected profile was not found"))?;
    if selected.name != expected.name || selected_home != expected.hermes_home {
        return Err(invalid("Hermes profile binding is invalid"));
    }
    Ok(())
}

pub(super) fn canonical_real_directory(
    path: &Path,
    missing: &'static str,
) -> Result<PathBuf, ClientError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| not_found(missing))?;
    if is_link_or_reparse_point(&metadata) || !metadata.is_dir() {
        return Err(not_found(missing));
    }
    fs::canonicalize(path).map_err(|_| invalid("Hermes profile root cannot be safely resolved"))
}

fn is_link_or_reparse_point(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;

        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn ascii_lowercase(value: &str) -> String {
    value
        .bytes()
        .map(|byte| byte.to_ascii_lowercase() as char)
        .collect()
}

fn valid_profile_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    if !(1..=64).contains(&bytes.len()) {
        return false;
    }
    (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes[1..].iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}
