use std::path::Path;

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
