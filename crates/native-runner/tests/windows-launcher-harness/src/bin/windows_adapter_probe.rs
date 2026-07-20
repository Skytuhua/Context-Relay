#![cfg(windows)]

use std::{
    env, fs,
    io::Write,
    net::{SocketAddr, TcpStream},
    process::{Command, ExitCode, Stdio},
    time::Duration,
};

use context_relay_native_runner::{
    ContentFrame, FailureCode, RunDisposition, RunLimits, RunRequest, RunResponse, RunStats,
    StagePath, read_helper_request, write_run_response_for,
};
use sha2::{Digest, Sha256};
use windows_sys::Win32::{
    Foundation::{GetHandleInformation, HANDLE_FLAG_INHERIT},
    System::Console::{GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE},
};

fn main() -> ExitCode {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    if arguments
        .next()
        .is_some_and(|value| value == "--descendant")
    {
        std::thread::sleep(Duration::from_secs(60));
        return ExitCode::SUCCESS;
    }
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    if arguments
        .first()
        .is_some_and(|value| value == "--sidecar-child")
    {
        return ExitCode::SUCCESS;
    }

    if exact_environment().is_err() {
        return ExitCode::from(2);
    }
    let request = match read_helper_request(&mut std::io::stdin().lock()) {
        Ok(request) => request,
        Err(_) => return ExitCode::from(2),
    };
    if verify_closure(&request).is_err() {
        return ExitCode::from(2);
    }
    let Some(input) = request.request().inputs().first() else {
        return ExitCode::from(2);
    };
    let Ok(instructions) = std::str::from_utf8(input.bytes()) else {
        return ExitCode::from(2);
    };
    let mut lines = instructions.lines();
    let Some(denied_path) = lines.next().and_then(|line| line.strip_prefix("DENY=")) else {
        return ExitCode::from(2);
    };
    let Some(address) = lines
        .next()
        .and_then(|line| line.strip_prefix("CONNECT="))
        .and_then(|value| value.parse::<SocketAddr>().ok())
    else {
        return ExitCode::from(2);
    };
    let Some(mode) = lines.next().and_then(|line| line.strip_prefix("MODE=")) else {
        return ExitCode::from(2);
    };
    if lines.next().is_some()
        || fs::read(denied_path).is_ok()
        || TcpStream::connect_timeout(&address, Duration::from_millis(500)).is_ok()
    {
        return ExitCode::from(2);
    }

    let mut response = RunResponse::failed(FailureCode::InvalidOutput);
    if mode == "NO_PROTOCOL_HANDLE_LEAK" {
        let handles = unsafe {
            [
                GetStdHandle(STD_INPUT_HANDLE),
                GetStdHandle(STD_OUTPUT_HANDLE),
                GetStdHandle(STD_ERROR_HANDLE),
            ]
        };
        if context_relay_native_runner::windows::seal_protocol_handles_before_sidecar().is_err()
            || handles.iter().any(|handle| {
                let mut flags = 0;
                (unsafe { GetHandleInformation(*handle, &mut flags) }) == 0
                    || flags & HANDLE_FLAG_INHERIT != 0
            })
        {
            response = RunResponse::failed(FailureCode::ClosureMismatch);
        } else if !Command::new(env::current_exe().unwrap())
            .arg("--sidecar-child")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
        {
            response = RunResponse::failed(FailureCode::LimitExceeded);
        }
    }

    let mut stdout = std::io::stdout().lock();
    match mode {
        "BOUND" | "NO_PROTOCOL_HANDLE_LEAK" => {
            write_run_response_for(&mut stdout, request.request(), &response)
        }
        "BOUND_LARGE" => write_run_response_for(
            &mut stdout,
            request.request(),
            &RunResponse::completed(
                RunDisposition::Generated,
                vec![
                    ContentFrame::new(
                        StagePath::try_from("output/probe.md").unwrap(),
                        vec![b'x'; 5 * 1024 * 1024],
                    )
                    .unwrap(),
                ],
                RunStats::new(1, 1, 1),
                RunLimits::for_command(request.request().command()),
            )
            .unwrap(),
        ),
        "WRONG_BINDING" => wrong_binding(&mut stdout, request.request(), &response),
        "STDERR" => {
            let _ = std::io::stderr().lock().write_all(b"unexpected");
            write_run_response_for(&mut stdout, request.request(), &response)
        }
        "TRAILING" => {
            write_run_response_for(&mut stdout, request.request(), &response).and_then(|()| {
                stdout
                    .write_all(&[0])
                    .map_err(|_| context_relay_native_runner::RunnerError::Io)
            })
        }
        "TIMEOUT" => {
            if std::process::Command::new(env::current_exe().unwrap())
                .arg("--descendant")
                .spawn()
                .is_err()
            {
                return ExitCode::from(2);
            }
            std::thread::sleep(Duration::from_secs(60));
            Ok(())
        }
        _ => return ExitCode::from(2),
    }
    .map_or(ExitCode::from(2), |()| ExitCode::SUCCESS)
}

fn wrong_binding(
    stdout: &mut impl Write,
    request: &RunRequest,
    response: &RunResponse,
) -> Result<(), context_relay_native_runner::RunnerError> {
    let mut nonce = *request.nonce();
    nonce[0] ^= 1;
    let wrong = RunRequest::new(
        nonce,
        *request.expected_closure_sha256(),
        request.command().clone(),
        request.inputs().to_vec(),
    )?;
    write_run_response_for(stdout, &wrong, response)
}

fn exact_environment() -> Result<(), ()> {
    const EXPECTED: [&str; 14] = [
        "APPDATA",
        "HOME",
        "LANG",
        "LC_ALL",
        "LOCALAPPDATA",
        "PATH",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "USERPROFILE",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
    ];
    let mut keys = env::vars_os()
        .map(|(key, _)| key.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    keys.sort_unstable();
    if keys == EXPECTED { Ok(()) } else { Err(()) }
}

fn verify_closure(request: &context_relay_native_runner::HelperRunRequest) -> Result<(), ()> {
    let root = env::current_exe()
        .map_err(|_| ())?
        .parent()
        .ok_or(())?
        .join("runtime");
    for material in request.closure() {
        let path = root.join(material.path().as_str());
        let bytes = fs::read(&path).map_err(|_| ())?;
        if bytes.len() as u64 != material.size()
            || Sha256::digest(&bytes).as_slice() != material.sha256()
            || fs::OpenOptions::new().write(true).open(path).is_ok()
        {
            return Err(());
        }
    }
    Ok(())
}
