use std::path::PathBuf;

use context_relay_local_ipc::Client;
use context_relay_protocol::{
    ClientError, ClientRole, ErrorCode, HarnessId, HarnessLaunchInfo, HarnessParams, LocalRequest,
    LocalResult, NativePlatform, WireNativeValue,
};
use tauri::State;

use crate::{LocalClientState, launch_plan, new_request_id};

fn error(message: &str) -> ClientError {
    ClientError {
        code: ErrorCode::InvalidRequest,
        message: message.into(),
        field_path: None,
        retryable: false,
    }
}

fn native_path(value: &WireNativeValue) -> Result<PathBuf, ClientError> {
    value
        .validate()
        .map_err(|_| error("The discovered path is invalid. Refresh the harness connection."))?;
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        if value.platform != NativePlatform::Windows {
            return Err(error("The discovered path belongs to another platform."));
        }
        let units: Vec<u16> = value
            .bytes
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        if units.contains(&0) {
            return Err(error("The discovered path is invalid."));
        }
        Ok(PathBuf::from(std::ffi::OsString::from_wide(&units)))
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::ffi::OsStringExt;
        if value.platform != NativePlatform::Macos || value.bytes.contains(&0) {
            return Err(error("The discovered path is invalid for this platform."));
        }
        Ok(PathBuf::from(std::ffi::OsString::from_vec(
            value.bytes.clone(),
        )))
    }
}

#[derive(Debug)]
struct LaunchPlan {
    executable: PathBuf,
    root: PathBuf,
    args: Vec<String>,
}

fn validated_plan(
    selection: &HarnessParams,
    info: HarnessLaunchInfo,
) -> Result<LaunchPlan, ClientError> {
    if selection.project_id.is_none() || info.selection != *selection {
        return Err(error(
            "Choose a registered project and refresh its harness connection.",
        ));
    }
    let args = match selection.harness {
        HarnessId::Hermes => {
            launch_plan::profile_args(selection.hermes_profile.as_deref()).map_err(error)?
        }
        _ if selection.hermes_profile.is_none() => Vec::new(),
        _ => return Err(error("This harness does not accept a Hermes profile.")),
    };
    let executable = native_path(&info.executable)?;
    let root = native_path(&info.project_root)?;
    if !executable.is_absolute() || !root.is_absolute() || !executable.is_file() || !root.is_dir() {
        return Err(error(
            "The harness or project folder moved. Refresh the connection before opening it.",
        ));
    }
    let executable = executable
        .canonicalize()
        .map_err(|_| error("The installed harness could not be resolved."))?;
    let root = root
        .canonicalize()
        .map_err(|_| error("The project folder could not be resolved."))?;
    // Never pass .cmd/.bat through CreateProcess: those require shell parsing.
    #[cfg(windows)]
    if !executable
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
    {
        return Err(error(
            "Install the harness's native executable using its installation guide, then refresh the connection.",
        ));
    }
    Ok(LaunchPlan {
        executable,
        root,
        args,
    })
}

async fn resolve(
    selection: HarnessParams,
    state: &LocalClientState,
) -> Result<LaunchPlan, ClientError> {
    let request = LocalRequest::HarnessLaunchInfo(selection.clone());
    request
        .validate()
        .map_err(|_| error("Choose a valid harness, profile and project."))?;
    match state
        .call_with(
            ClientRole::Desktop,
            new_request_id(),
            request,
            Client::connect,
        )
        .await?
    {
        LocalResult::HarnessLaunchInfo { info } => validated_plan(&selection, info),
        _ => Err(error(
            "Update Context Relay and its local service before opening a harness.",
        )),
    }
}

#[tauri::command]
pub async fn open_harness(
    selection: HarnessParams,
    state: State<'_, LocalClientState>,
) -> Result<(), ClientError> {
    let plan = resolve(selection, &state).await?;
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // This command is called only by the user's Open button. The visible console
        // hosts the harness's own sign-in/trust prompts; no input is automated.
        let mut child = std::process::Command::new(&plan.executable)
            .args(&plan.args)
            .current_dir(&plan.root)
            .creation_flags(0x00000010)
            .spawn()
            .map_err(|_| {
                error("The harness terminal could not open. Try its copied command in PowerShell.")
            })?;
        std::thread::spawn(move || {
            let _ = child.wait();
        });
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = plan;
        Err(error(
            "Use Copy command and paste it into Terminal to open this harness.",
        ))
    }
}

#[tauri::command]
pub async fn harness_copy_command(
    selection: HarnessParams,
    state: State<'_, LocalClientState>,
) -> Result<String, ClientError> {
    let plan = resolve(selection, &state).await?;
    let executable = plan
        .executable
        .to_str()
        .ok_or_else(|| error("The executable path cannot be copied as text."))?;
    let root = plan
        .root
        .to_str()
        .ok_or_else(|| error("The project path cannot be copied as text."))?;
    launch_plan::copy_command(executable, root, &plan.args, cfg!(windows)).map_err(error)
}

fn guide(harness: HarnessId) -> &'static str {
    // Official installation pages verified 2026-09-07. No URL is accepted from JS.
    match harness {
        HarnessId::Codex => "https://developers.openai.com/codex/cli/",
        HarnessId::ClaudeCode => "https://code.claude.com/docs/en/quickstart",
        HarnessId::Hermes => "https://hermes-agent.nousresearch.com/docs/",
    }
}

#[tauri::command]
pub fn open_harness_guide(harness: HarnessId) -> Result<(), ClientError> {
    let url = guide(harness);
    #[cfg(windows)]
    {
        #[link(name = "shell32")]
        unsafe extern "system" {
            fn ShellExecuteW(
                window: *mut std::ffi::c_void,
                operation: *const u16,
                file: *const u16,
                parameters: *const u16,
                directory: *const u16,
                show: i32,
            ) -> isize;
        }
        let url: Vec<u16> = url.encode_utf16().chain(Some(0)).collect();
        let operation: Vec<u16> = "open".encode_utf16().chain(Some(0)).collect();
        // Both strings are fixed, NUL-terminated values and remain live for the call.
        let result = unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                operation.as_ptr(),
                url.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,
            )
        };
        if result <= 32 {
            return Err(error(
                "The installation guide could not open in your browser.",
            ));
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let mut child = std::process::Command::new("/usr/bin/open")
            .arg(url)
            .spawn()
            .map_err(|_| error("The installation guide could not open in your browser."))?;
        std::thread::spawn(move || {
            let _ = child.wait();
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire(path: &std::path::Path) -> WireNativeValue {
        #[cfg(windows)]
        let bytes = {
            use std::os::windows::ffi::OsStrExt;
            path.as_os_str()
                .encode_wide()
                .flat_map(u16::to_le_bytes)
                .collect()
        };
        #[cfg(not(windows))]
        let bytes = {
            use std::os::unix::ffi::OsStrExt;
            path.as_os_str().as_bytes().to_vec()
        };
        WireNativeValue {
            platform: if cfg!(windows) {
                NativePlatform::Windows
            } else {
                NativePlatform::Macos
            },
            bytes,
            display: None,
        }
    }

    #[test]
    fn launch_plan_requires_the_same_registered_binding_and_existing_paths() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("harness.exe");
        std::fs::write(&executable, []).unwrap();
        let selection = HarnessParams {
            harness: HarnessId::Codex,
            project_id: Some("018f22e2-79b0-7cc8-98c4-dc0c0c075001".parse().unwrap()),
            hermes_profile: None,
        };
        let info = HarnessLaunchInfo {
            selection: selection.clone(),
            executable: wire(&executable),
            project_root: wire(directory.path()),
        };
        let plan = validated_plan(&selection, info.clone()).unwrap();
        assert_eq!(plan.executable, executable.canonicalize().unwrap());
        assert_eq!(plan.root, directory.path().canonicalize().unwrap());
        assert!(plan.args.is_empty());

        let mut wrong = info.clone();
        wrong.selection.harness = HarnessId::ClaudeCode;
        assert!(validated_plan(&selection, wrong).is_err());
        let mut unregistered = selection.clone();
        unregistered.project_id = None;
        assert!(validated_plan(&unregistered, info.clone()).is_err());
        let mut missing_root = info.clone();
        missing_root.project_root = wire(&directory.path().join("missing"));
        assert!(validated_plan(&selection, missing_root).is_err());
        let mut spoofed_display = info.clone();
        spoofed_display.executable.display = Some("C:\\different.exe".into());
        assert_eq!(
            validated_plan(&selection, spoofed_display)
                .unwrap()
                .executable,
            plan.executable
        );
        std::fs::remove_file(&executable).unwrap();
        assert!(validated_plan(&selection, info).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn launch_rejects_shell_scripts_even_when_discovered() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("harness.cmd");
        std::fs::write(&executable, []).unwrap();
        let selection = HarnessParams {
            harness: HarnessId::ClaudeCode,
            project_id: Some("018f22e2-79b0-7cc8-98c4-dc0c0c075001".parse().unwrap()),
            hermes_profile: None,
        };
        let info = HarnessLaunchInfo {
            selection: selection.clone(),
            executable: wire(&executable),
            project_root: wire(directory.path()),
        };
        assert!(validated_plan(&selection, info).is_err());
    }
}
