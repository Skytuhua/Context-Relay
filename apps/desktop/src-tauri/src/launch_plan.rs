// Hermes' installed hermes_cli/profiles.py uses this identifier grammar.
pub fn profile_args(profile: Option<&str>) -> Result<Vec<String>, &'static str> {
    let profile = profile.ok_or("Choose a Hermes profile before opening it.")?;
    if profile.is_empty()
        || profile.len() > 64
        || !profile
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
        || !profile.as_bytes()[0].is_ascii_alphanumeric()
    {
        return Err("Choose a valid installed Hermes profile.");
    }
    Ok(vec!["--profile".into(), profile.into()])
}

pub fn copy_command(
    executable: &str,
    root: &str,
    args: &[String],
    windows: bool,
) -> Result<String, &'static str> {
    let quote = |text: &str| -> Result<String, &'static str> {
        if text.chars().any(char::is_control) {
            return Err("This path cannot be safely copied as a terminal command.");
        }
        Ok(format!(
            "'{}'",
            if windows {
                text.replace('\'', "''")
            } else {
                text.replace('\'', "'\"'\"'")
            }
        ))
    };
    let mut command = if windows {
        format!(
            "& {{ Set-Location -LiteralPath {} -ErrorAction Stop; & {}",
            quote(root)?,
            quote(executable)?
        )
    } else {
        format!("cd -- {} && {}", quote(root)?, quote(executable)?)
    };
    for arg in args {
        command.push(' ');
        command.push_str(&quote(arg)?);
    }
    if windows {
        command.push_str(" }");
    }
    Ok(command)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hermes_profile_is_explicit_and_cannot_be_an_option_or_path() {
        assert_eq!(
            profile_args(Some("default")).unwrap(),
            ["--profile", "default"]
        );
        assert_eq!(
            profile_args(Some("work-2")).unwrap(),
            ["--profile", "work-2"]
        );
        for value in [
            None,
            Some(""),
            Some("../work"),
            Some("--help"),
            Some("a;whoami"),
            Some("Work"),
        ] {
            assert!(profile_args(value).is_err());
        }
    }

    #[test]
    fn copied_powershell_treats_metacharacters_as_literal_data() {
        let command = copy_command(
            "C:\\tools\\it's $x.exe",
            "C:\\a;$(whoami)",
            &["--profile".into(), "default".into()],
            true,
        )
        .unwrap();
        assert_eq!(
            command,
            "& { Set-Location -LiteralPath 'C:\\a;$(whoami)' -ErrorAction Stop; & 'C:\\tools\\it''s $x.exe' '--profile' 'default' }"
        );
        assert!(copy_command("tool\n.exe", "root", &[], true).is_err());
    }

    #[test]
    fn copied_posix_command_quotes_each_argument() {
        assert_eq!(
            copy_command("/tools/it's", "/a;$x", &[], false).unwrap(),
            "cd -- '/a;$x' && '/tools/it'\"'\"'s'"
        );
    }
}
