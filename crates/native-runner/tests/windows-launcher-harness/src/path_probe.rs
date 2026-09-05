//! Read-only path-resolution diagnostics for the isolated Windows launcher tests.

use serde_json::{Value, json};
use std::{
    fs,
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    path::Path,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_NAME_OPENED, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, GetFinalPathNameByHandleW, VOLUME_NAME_DOS,
    VOLUME_NAME_GUID, VOLUME_NAME_NONE, VOLUME_NAME_NT,
};

fn path_result(result: std::io::Result<std::path::PathBuf>) -> Value {
    match result {
        Ok(path) => json!({"path":path}),
        Err(error) => json!({"error":error.raw_os_error()}),
    }
}

pub fn inspect(path: &Path) -> Value {
    let mut result = json!({
        "enumeration":fs::read_dir(path).is_ok(),
        "canonical":path_result(fs::canonicalize(path)),
        "queries":{},
    });
    let handle = match fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
    {
        Ok(handle) => handle,
        Err(error) => {
            result["openError"] = json!(error.raw_os_error());
            return result;
        }
    };
    for (name, volume) in [
        ("dos", VOLUME_NAME_DOS),
        ("guid", VOLUME_NAME_GUID),
        ("nt", VOLUME_NAME_NT),
        ("none", VOLUME_NAME_NONE),
    ] {
        for (form, flags) in [
            ("normalized", volume),
            ("opened", volume | FILE_NAME_OPENED),
        ] {
            let mut buffer = vec![0_u16; 32_768];
            // SAFETY: the file handle is live and the output buffer has the advertised size.
            let length = unsafe {
                GetFinalPathNameByHandleW(
                    handle.as_raw_handle(),
                    buffer.as_mut_ptr(),
                    buffer.len() as u32,
                    flags,
                )
            };
            let value = if length == 0 {
                json!({"error":std::io::Error::last_os_error().raw_os_error()})
            } else if length as usize >= buffer.len() {
                json!({"tooLong":true})
            } else {
                json!({"path":String::from_utf16(&buffer[..length as usize]).unwrap()})
            };
            if name == "nt"
                && form == "normalized"
                && let Some(nt_path) = value["path"].as_str()
            {
                let win32 = std::path::PathBuf::from(format!(r"\\?\GLOBALROOT{nt_path}"));
                result["ntInput"] = json!({"enumeration":fs::read_dir(&win32).is_ok(),"canonical":path_result(fs::canonicalize(&win32))});
            }
            result["queries"][format!("{name}-{form}")] = value;
        }
    }
    result
}
