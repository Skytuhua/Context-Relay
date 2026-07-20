#[cfg(target_os = "macos")]
use std::{
    io::Write,
    process::{Command, Stdio},
    time::Duration,
};

#[cfg(target_os = "macos")]
use context_relay_native_runner::{
    ContentFrame, FailureCode, RunDisposition, RunLimits, RunRequest, RunResponse, RunStats,
    StagePath, read_helper_request, write_run_response_for,
};

#[cfg(target_os = "macos")]
fn main() {
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--ordinary-child")) {
        loop {
            std::thread::sleep(Duration::from_secs(60));
        }
    }
    let helper = read_helper_request(&mut std::io::stdin().lock()).unwrap();
    let request = helper.request();
    let mode = std::str::from_utf8(request.inputs()[0].bytes()).unwrap();
    let response = if mode == "GUARDIAN_GROUP_CHILD" {
        let child = Command::new(std::env::current_exe().unwrap())
            .arg("--ordinary-child")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = i32::try_from(child.id()).unwrap();
        let pgid = unsafe { libc::getpgid(pid) };
        std::mem::forget(child);
        let proof = format!("CHILD_PID={pid}\nCHILD_PGID={pgid}\n").into_bytes();
        RunResponse::completed(
            RunDisposition::Generated,
            vec![
                ContentFrame::new(
                    StagePath::try_from("output/.claude/rules/probe.md").unwrap(),
                    proof.clone(),
                )
                .unwrap(),
            ],
            RunStats::new(1, u64::try_from(proof.len()).unwrap(), 1),
            RunLimits::for_command(request.command()),
        )
        .unwrap()
    } else {
        RunResponse::failed(FailureCode::InvalidOutput)
    };
    let mut stdout = std::io::stdout().lock();
    match mode {
        "WRONG_BINDING" => {
            let wrong = RunRequest::new(
                [0x99; 16],
                *request.expected_closure_sha256(),
                request.command().clone(),
                request.inputs().to_vec(),
            )
            .unwrap();
            write_run_response_for(&mut stdout, &wrong, &response).unwrap();
        }
        "TRAILING" => {
            write_run_response_for(&mut stdout, request, &response).unwrap();
            stdout.write_all(&[0]).unwrap();
        }
        "STDERR" => {
            write_run_response_for(&mut stdout, request, &response).unwrap();
            std::io::stderr().lock().write_all(b"unexpected").unwrap();
        }
        "MALFORMED" => {
            let mut frame = Vec::new();
            write_run_response_for(&mut frame, request, &response).unwrap();
            frame.pop().unwrap();
            stdout.write_all(&frame).unwrap();
        }
        _ => write_run_response_for(&mut stdout, request, &response).unwrap(),
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {}
