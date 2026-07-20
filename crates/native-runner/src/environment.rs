use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
};

use crate::{RunnerError, RuntimeTarget, StageDirectory, StageLayout};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestrictedEnvironment {
    values: BTreeMap<OsString, OsString>,
}

impl RestrictedEnvironment {
    pub fn for_stage(stage: &StageLayout, _target: RuntimeTarget) -> Result<Self, RunnerError> {
        let home = stage.path(StageDirectory::Home).into_os_string();
        let config = stage.path(StageDirectory::Config).into_os_string();
        let data = stage.path(StageDirectory::Data).into_os_string();
        let cache = stage.path(StageDirectory::Cache).into_os_string();
        let temp = stage.path(StageDirectory::Temp).into_os_string();
        let runtime = stage.path(StageDirectory::Runtime).into_os_string();
        let mut values = BTreeMap::new();
        for (key, value) in [
            ("HOME", home.clone()),
            ("USERPROFILE", home),
            ("APPDATA", data.clone()),
            ("LOCALAPPDATA", data.clone()),
            ("XDG_CONFIG_HOME", config),
            ("XDG_DATA_HOME", data),
            ("XDG_CACHE_HOME", cache),
            ("TMP", temp.clone()),
            ("TEMP", temp.clone()),
            ("TMPDIR", temp),
            ("PATH", runtime),
            ("LANG", OsString::from("C.UTF-8")),
            ("LC_ALL", OsString::from("C.UTF-8")),
        ] {
            values.insert(OsString::from(key), value);
        }
        #[cfg(windows)]
        if matches!(_target, RuntimeTarget::WindowsX86_64) {
            values.insert(
                OsString::from("SYSTEMROOT"),
                windows_directory().ok_or(RunnerError::InvalidEnvironment)?,
            );
        }
        Ok(Self { values })
    }

    pub fn get(&self, key: &str) -> Option<&OsStr> {
        self.values.get(OsStr::new(key)).map(OsString::as_os_str)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&OsStr, &OsStr)> {
        self.values
            .iter()
            .map(|(key, value)| (key.as_os_str(), value.as_os_str()))
    }
}

#[cfg(windows)]
pub(crate) fn windows_directory() -> Option<OsString> {
    use std::os::windows::ffi::OsStringExt;

    use windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW;

    let mut buffer = vec![0_u16; 260];
    loop {
        let length = unsafe { GetWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
        if length == 0 {
            return None;
        }
        let length = length as usize;
        if length < buffer.len() {
            buffer.truncate(length);
            let directory = OsString::from_wide(&buffer);
            return std::path::Path::new(&directory)
                .is_absolute()
                .then_some(directory);
        }
        let capacity = length
            .checked_add(1)
            .filter(|capacity| *capacity <= 32_768)?;
        buffer.resize(capacity, 0);
    }
}
