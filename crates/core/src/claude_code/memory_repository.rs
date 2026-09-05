//! Passive repository selection for Claude's default memory directory.

use std::{
    fs,
    path::{Path, PathBuf},
};

use super::{mcp_state, memory_path, metadata_is_link_or_reparse};

pub(super) fn default_root(project: &Path) -> Option<PathBuf> {
    mcp_state::validate_config_path(project, false).ok()?;
    let project = native_realpath(project)?;
    if !project.is_dir() {
        return None;
    }
    for root in project.ancestors() {
        let marker = root.join(".git");
        match fs::symlink_metadata(&marker) {
            Ok(metadata) if metadata_is_link_or_reparse(&metadata) => return None,
            Ok(metadata) if metadata.is_dir() => return Some(root.to_owned()),
            Ok(metadata) if metadata.is_file() => return worktree_root(root).ok(),
            Ok(_) => return None,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                mcp_state::validate_config_path(&marker, true).ok()?;
            }
            Err(_) => return None,
        }
    }
    Some(project)
}

fn worktree_root(root: &Path) -> Result<PathBuf, ()> {
    let fallback = || Ok(root.to_owned());
    let Some(marker) = read_text(&root.join(".git"))? else {
        return fallback();
    };
    let Some(pointer) = marker.strip_prefix("gitdir:") else {
        return fallback();
    };
    let gitdir = resolve(trim(pointer), root)?;
    let Some(common) = read_text(&gitdir.join("commondir"))? else {
        return fallback();
    };
    let common = resolve(&common, &gitdir)?;
    // Submodules and arbitrary gitdir files keep their own repository root.
    if gitdir.parent() != Some(common.join("worktrees").as_path()) {
        return fallback();
    }
    let Some(backlink) = read_text(&gitdir.join("gitdir"))? else {
        return fallback();
    };
    let backlink = resolve(&backlink, &gitdir)?;
    mcp_state::validate_config_path(&backlink, true).map_err(|_| ())?;
    let Some(backlink) = native_realpath(&backlink) else {
        return fallback();
    };
    if backlink != root.join(".git") {
        return fallback();
    }
    let selected = if common.file_name().is_some_and(|name| name == ".git") {
        common.parent().ok_or(())?.to_owned()
    } else {
        common
    };
    mcp_state::validate_config_path(&selected, false).map_err(|_| ())?;
    if !selected.is_dir() {
        return Err(());
    }
    Ok(selected)
}

fn native_realpath(path: &Path) -> Option<PathBuf> {
    let path = fs::canonicalize(path).ok()?;
    // The native helper uses ordinary Windows paths. Retain its case-sensitive
    // lexical comparisons when metadata mixes absolute and relative pointers.
    #[cfg(windows)]
    {
        let native = ordinary_canonical_path(&path)?;
        // Removing a verbatim prefix must not redirect trailing-dot/space
        // components or another extended spelling to an ordinary-path alias.
        (fs::canonicalize(&native).ok()? == path).then_some(native)
    }
    #[cfg(not(windows))]
    Some(path)
}

#[cfg(windows)]
fn ordinary_canonical_path(path: &Path) -> Option<PathBuf> {
    use std::path::{Component, Prefix};
    if !path.is_absolute() {
        return None;
    }
    let Component::Prefix(prefix) = path.components().next()? else {
        return None;
    };
    match prefix.kind() {
        Prefix::VerbatimDisk(_) => Some(PathBuf::from(path.to_str()?.strip_prefix(r"\\?\")?)),
        Prefix::VerbatimUNC(_, _) => Some(PathBuf::from(format!(
            r"\\{}",
            path.to_str()?.strip_prefix(r"\\?\UNC\")?
        ))),
        Prefix::Disk(_) | Prefix::UNC(_, _) => Some(path.to_owned()),
        _ => None,
    }
}

fn read_text(path: &Path) -> Result<Option<String>, ()> {
    mcp_state::read_bytes(path)
        .map_err(|_| ())
        .map(|bytes| bytes.map(|bytes| trim(&String::from_utf8_lossy(&bytes)).to_owned()))
}

fn trim(value: &str) -> &str {
    // JavaScript trim includes BOM, but excludes Unicode NEL (U+0085).
    value.trim_matches(|character: char| {
        character == '\u{feff}' || (character.is_whitespace() && character != '\u{85}')
    })
}

fn resolve(value: &str, base: &Path) -> Result<PathBuf, ()> {
    if value.len() > 4096
        || value.contains('\0')
        || value.starts_with(r"\\")
        || value.starts_with("//")
    {
        // Network/device pointers need separate qualification. Do not guess
        // another root when a native worktree may use an unsupported binding.
        return Err(());
    }
    let path = Path::new(value);
    #[cfg(windows)]
    if path.has_root() && !path.is_absolute() {
        return memory_path::bind_current_drive(memory_path::normalize(path), base).ok_or(());
    }
    #[cfg(windows)]
    if !path.is_absolute()
        && matches!(
            path.components().next(),
            Some(std::path::Component::Prefix(_))
        )
    {
        return Err(());
    }
    Ok(memory_path::normalize(&base.join(path)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::collections::BTreeMap;

    #[derive(Deserialize)]
    struct Fixture {
        cases: Vec<Case>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Case {
        platform: String,
        name: String,
        project: String,
        dirs: Vec<String>,
        files: BTreeMap<String, String>,
        expected_root: String,
    }

    #[test]
    fn repository_bindings_match_pinned_native_helper_vectors() {
        let fixture: Fixture = serde_json::from_str(include_str!(
            "../../tests/fixtures/claude-code-2.1.202-memory-repositories.json"
        ))
        .unwrap();
        for case in fixture.cases {
            if (case.platform == "windows") != cfg!(windows) {
                continue;
            }
            let temp = tempfile::tempdir().unwrap();
            let root = fs::canonicalize(temp.path()).unwrap();
            let ordinary_root = root.to_str().unwrap().trim_start_matches(r"\\?\");
            for directory in case.dirs {
                fs::create_dir_all(root.join(directory)).unwrap();
            }
            for (name, text) in case.files {
                let file = root.join(name);
                fs::create_dir_all(file.parent().unwrap()).unwrap();
                fs::write(file, text.replace("$ROOT", ordinary_root)).unwrap();
            }
            // The native helper returns ordinary Windows paths, whereas the
            // synthetic filesystem root uses Rust's canonical verbatim prefix.
            let ordinary = |path: PathBuf| {
                path.to_str()
                    .unwrap()
                    .trim_start_matches(r"\\?\")
                    .to_owned()
            };
            assert_eq!(
                default_root(&root.join(case.project)).map(ordinary),
                Some(ordinary(root.join(case.expected_root))),
                "{}",
                case.name
            );
        }
    }

    #[test]
    fn unsafe_or_oversized_git_marker_never_guesses_a_root() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        fs::write(root.join(".git"), vec![b'x'; 1024 * 1024 + 1]).unwrap();
        assert_eq!(default_root(&root), None);
        fs::write(
            root.join(".git"),
            b"gitdir: //unqualified-host/repository\n",
        )
        .unwrap();
        assert_eq!(default_root(&root), None);
    }

    #[cfg(windows)]
    #[test]
    fn native_paths_only_convert_qualified_absolute_drive_and_unc_prefixes() {
        assert_eq!(
            ordinary_canonical_path(Path::new(r"\\?\C:\repo")),
            Some(PathBuf::from(r"C:\repo"))
        );
        assert_eq!(
            ordinary_canonical_path(Path::new(r"\\?\UNC\server\share\repo")),
            Some(PathBuf::from(r"\\server\share\repo"))
        );
        for path in [
            r"\\?\Volume{123}\repo",
            r"\\.\device\repo",
            r"C:repo",
            "repo",
        ] {
            assert_eq!(ordinary_canonical_path(Path::new(path)), None, "{path}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn native_path_conversion_rejects_trailing_component_aliases() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        fs::create_dir(root.join("project")).unwrap();
        assert!(native_realpath(&root.join("project")).is_some());
        for name in ["project.", "project "] {
            let path = root.join(name);
            fs::create_dir(&path).unwrap();
            assert_eq!(native_realpath(&path), None);
        }
    }

    #[cfg(unix)]
    #[test]
    fn linked_git_marker_or_metadata_is_not_followed() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let project = root.join("project");
        let external = root.join("external");
        fs::create_dir(&project).unwrap();
        fs::create_dir_all(external.join("worktrees/topic")).unwrap();
        symlink(&external, project.join(".git")).unwrap();
        assert_eq!(default_root(&project), None);
        fs::remove_file(project.join(".git")).unwrap();
        fs::write(
            project.join(".git"),
            b"gitdir: ../external/worktrees/topic\n",
        )
        .unwrap();
        fs::write(root.join("common.txt"), b"../..\n").unwrap();
        symlink(
            root.join("common.txt"),
            external.join("worktrees/topic/commondir"),
        )
        .unwrap();
        assert_eq!(default_root(&project), None);
    }
}
