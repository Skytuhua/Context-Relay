use std::collections::BTreeSet;

use unicode_normalization::UnicodeNormalization;

use crate::{RunnerError, RuntimeTarget};

const MAX_STAGE_PATH_BYTES: usize = 1_024;
const MAX_COMPONENT_BYTES: usize = 255;
const MAX_COMPONENTS: usize = 64;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StagePath(String);

impl StagePath {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for StagePath {
    type Error = RunnerError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.is_empty()
            || value.len() > MAX_STAGE_PATH_BYTES
            || value.starts_with('/')
            || value.contains(['\\', ':'])
            || value.chars().any(char::is_control)
        {
            return Err(RunnerError::InvalidPath);
        }

        let components = value.split('/').collect::<Vec<_>>();
        if components.len() > MAX_COMPONENTS
            || components.iter().any(|component| {
                component.is_empty()
                    || matches!(*component, "." | "..")
                    || component.len() > MAX_COMPONENT_BYTES
                    || component.ends_with(['.', ' '])
                    || windows_reserved_name(component)
            })
        {
            return Err(RunnerError::InvalidPath);
        }

        Ok(Self(value.to_owned()))
    }
}

impl TryFrom<String> for StagePath {
    type Error = RunnerError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

pub fn validate_path_set(target: RuntimeTarget, paths: &[StagePath]) -> Result<(), RunnerError> {
    match target {
        RuntimeTarget::WindowsX86_64 => {
            let mut aliases: Vec<String> = Vec::new();
            for path in paths {
                let alias = path.as_str().nfkc().collect::<String>();
                if aliases.iter().any(|existing| {
                    windows_ordinal_ignore_case_eq(existing, &alias).unwrap_or(true)
                }) {
                    return Err(RunnerError::PathCollision);
                }
                aliases.push(alias);
            }
        }
        RuntimeTarget::MacosArm64 => {
            let mut aliases = BTreeSet::new();
            for path in paths {
                let alias = path
                    .as_str()
                    .nfd()
                    .flat_map(char::to_lowercase)
                    .collect::<String>();
                if !aliases.insert(alias) {
                    return Err(RunnerError::PathCollision);
                }
            }
        }
    }
    Ok(())
}

pub fn windows_ordinal_ignore_case_eq(left: &str, right: &str) -> Result<bool, RunnerError> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};

        let left = left.encode_utf16().collect::<Vec<_>>();
        let right = right.encode_utf16().collect::<Vec<_>>();
        let left_len = i32::try_from(left.len()).map_err(|_| RunnerError::InvalidPath)?;
        let right_len = i32::try_from(right.len()).map_err(|_| RunnerError::InvalidPath)?;
        let result =
            unsafe { CompareStringOrdinal(left.as_ptr(), left_len, right.as_ptr(), right_len, 1) };
        if result == 0 {
            return Err(RunnerError::InvalidPath);
        }
        Ok(result == CSTR_EQUAL)
    }
    #[cfg(not(windows))]
    {
        Ok(simple_windows_uppercase(left) == simple_windows_uppercase(right))
    }
}

#[cfg(not(windows))]
fn simple_windows_uppercase(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            let mut uppercase = character.to_uppercase();
            let first = uppercase.next().unwrap_or(character);
            if uppercase.next().is_none() {
                first
            } else if character == 'ß' {
                'ẞ'
            } else {
                character
            }
        })
        .collect()
}

fn windows_reserved_name(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or_default();
    let name = stem.nfkc().collect::<String>().to_ascii_uppercase();
    if matches!(
        name.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$"
    ) {
        return true;
    }

    for prefix in ["COM", "LPT"] {
        if let Some(suffix) = name.strip_prefix(prefix)
            && matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
        {
            return true;
        }
    }
    false
}
