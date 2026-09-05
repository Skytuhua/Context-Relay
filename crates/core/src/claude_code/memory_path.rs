use std::path::{Component, Path, PathBuf};

use unicode_normalization::UnicodeNormalization as _;

/// Match the pinned harness's configured-directory string rules before binding
/// the result to the filesystem. An ignored value falls back to its default.
pub(super) fn configured_directory(value: &str, home: &Path) -> Option<PathBuf> {
    if value.is_empty() {
        return None;
    }
    let expanded;
    let value = if let Some(suffix) = value
        .strip_prefix("~/")
        .or_else(|| value.strip_prefix("~\\"))
    {
        let normalized = normalize(Path::new(suffix));
        let child = normalized.to_str()?;
        if matches!(child, "." | "..") || child.starts_with("../") || child.starts_with("..\\") {
            return None;
        }
        let home = home.to_str()?;
        // Node's path.join concatenates a rooted suffix; Path::join replaces
        // the home in that case, which would select a different directory.
        expanded = format!("{home}{}{suffix}", std::path::MAIN_SEPARATOR);
        &expanded
    } else {
        value
    };
    let normalized = normalize(Path::new(value));
    let text = normalized.to_str()?.trim_end_matches(['/', '\\']);
    let path = Path::new(text);
    if !path.has_root()
        || text.encode_utf16().count() < 3
        || text.starts_with(r"\\")
        || text.starts_with("//")
        || text.contains('\0')
        || (text.len() == 2 && text.as_bytes()[1] == b':')
    {
        return None;
    }
    // Native strings end in a separator, but a filesystem binding must not:
    // lstat/symlink_metadata can follow a directory symlink with a trailing '/'.
    Some(PathBuf::from(text.nfc().collect::<String>()))
}

fn normalize(path: &Path) -> PathBuf {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(components.last(), Some(Component::Normal(_))) {
                    components.pop();
                } else if !path.has_root() {
                    components.push(component);
                }
            }
            _ => components.push(component),
        }
    }
    // Append component bytes rather than PathBuf::push: an interior "D:"
    // segment must not be reinterpreted as a replacement drive prefix.
    let mut result = std::ffi::OsString::new();
    let mut separator = false;
    for component in components {
        if separator {
            result.push(std::path::MAIN_SEPARATOR_STR);
        }
        result.push(component.as_os_str());
        separator = matches!(component, Component::Normal(_) | Component::ParentDir);
    }
    if result.is_empty() {
        PathBuf::from(".")
    } else {
        PathBuf::from(result)
    }
}

pub(super) fn bind_current_drive(path: PathBuf, project: &Path) -> Option<PathBuf> {
    if path.is_absolute() {
        return Some(path);
    }
    #[cfg(windows)]
    if path.has_root() {
        use std::path::Prefix;
        if let Some(Component::Prefix(prefix)) = project.components().next()
            && let Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) = prefix.kind()
        {
            return Some(PathBuf::from(format!(
                "{}:{}",
                char::from(drive),
                path.to_str()?
            )));
        }
    }
    #[cfg(not(windows))]
    let _ = project;
    None
}

pub(super) fn directory_key(path: &Path) -> Option<String> {
    let input = path.to_str()?;
    if input.is_empty() || input.len() > 4096 {
        return None;
    }
    #[cfg(windows)]
    {
        // Rust canonicalization adds a verbatim prefix. The CLI's ordinary
        // working-directory path does not include that filesystem prefix.
        let input = if let Some(unc) = input.strip_prefix(r"\\?\UNC\") {
            format!(r"\\{unc}")
        } else if let Some(drive) = input.strip_prefix(r"\\?\") {
            if drive.as_bytes().get(1) != Some(&b':') {
                return None;
            }
            drive.to_owned()
        } else {
            input.to_owned()
        };
        Some(encode_key(&input))
    }
    #[cfg(not(windows))]
    Some(encode_key(input))
}

fn encode_key(input: &str) -> String {
    // The native JavaScript replacement and length limit operate on UTF-16
    // units. A supplementary character contributes two hyphens.
    let mut key = input
        .encode_utf16()
        .map(|unit| {
            if matches!(unit, 48..=57 | 65..=90 | 97..=122) {
                char::from(unit as u8)
            } else {
                '-'
            }
        })
        .collect::<String>();
    if key.len() > 200 {
        key.truncate(200);
        let hash = input.encode_utf16().fold(0_i32, |hash, unit| {
            hash.wrapping_mul(31).wrapping_add(i32::from(unit))
        });
        key.push('-');
        key.push_str(&base36(hash.unsigned_abs()));
    }
    key
}

fn base36(mut number: u32) -> String {
    if number == 0 {
        return "0".to_owned();
    }
    let mut digits = Vec::new();
    while number != 0 {
        let digit = number % 36;
        digits.push(char::from(if digit < 10 {
            b'0' + digit as u8
        } else {
            b'a' + (digit - 10) as u8
        }));
        number /= 36;
    }
    digits.into_iter().rev().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Fixture {
        cases: Vec<KeyCase>,
    }

    #[derive(Deserialize)]
    struct KeyCase {
        input: String,
        key: String,
    }

    #[derive(Deserialize)]
    struct DirectoryFixture {
        cases: Vec<PlatformCases>,
    }

    #[derive(Deserialize)]
    struct PlatformCases {
        platform: String,
        home: String,
        cases: Vec<DirectoryCase>,
    }

    #[derive(Deserialize)]
    struct DirectoryCase {
        input: String,
        directory: Option<String>,
    }

    #[test]
    fn configured_directories_match_the_pinned_cli_string_helper() {
        let fixture: DirectoryFixture = serde_json::from_str(include_str!(
            "../../tests/fixtures/claude-code-2.1.202-memory-directories.json"
        ))
        .unwrap();
        let platform = if cfg!(windows) { "windows" } else { "macos" };
        let vectors = fixture
            .cases
            .into_iter()
            .filter(|case| case.platform == platform)
            .collect::<Vec<_>>();
        assert!(!vectors.is_empty());
        for vectors in vectors {
            for case in vectors.cases {
                assert_eq!(
                    configured_directory(&case.input, Path::new(&vectors.home)),
                    case.directory.map(PathBuf::from),
                    "{} under {}",
                    case.input,
                    vectors.home
                );
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn rooted_configured_directories_use_the_selected_projects_drive() {
        assert_eq!(
            bind_current_drive(PathBuf::from(r"\memory"), Path::new(r"\\?\D:\project")),
            Some(PathBuf::from(r"D:\memory"))
        );
        assert_eq!(
            bind_current_drive(
                PathBuf::from(r"\memory"),
                Path::new(r"\\server\share\project")
            ),
            None
        );
    }

    #[test]
    fn project_keys_match_the_pinned_cli_string_helpers() {
        let fixture: Fixture = serde_json::from_str(include_str!(
            "../../tests/fixtures/claude-code-2.1.202-memory-keys.json"
        ))
        .unwrap();
        for case in fixture.cases {
            assert_eq!(encode_key(&case.input), case.key, "{}", case.input);
        }
    }

    #[cfg(windows)]
    #[test]
    fn canonical_windows_paths_use_the_cli_drive_spelling() {
        assert_eq!(
            directory_key(Path::new(r"\\?\C:\Work\project with spaces")),
            Some("C--Work-project-with-spaces".to_owned())
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_paths_are_not_replaced_with_a_different_project_identity() {
        use std::os::unix::ffi::OsStrExt;
        let path = Path::new(std::ffi::OsStr::from_bytes(b"/tmp/project-\xff"));
        assert_eq!(directory_key(path), None);
    }
}
