use std::{
    io::Write,
    process::{Command, Stdio},
};

use context_relay_native_runner::{
    ClosureMaterial, ContentFrame, FailureCode, HelperRunRequest, RunRequest, RunResponse,
    SidecarCommand, StagePath, closure_material_digest, read_run_response_for,
    write_helper_request,
};
use sha2::{Digest, Sha256};

fn helper() -> String {
    env!("CARGO_BIN_EXE_context-relay-native-helper").to_owned()
}

#[test]
fn helper_has_no_cli_argument_surface() {
    let status = Command::new(helper())
        .arg("powershell.exe")
        .arg("-Command")
        .arg("whoami")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(!status.success());
}

#[test]
fn helper_accepts_one_bounded_closed_frame_and_fails_closed_on_missing_closure() {
    let material = ClosureMaterial::new(
        StagePath::try_from("bin/gitleaks.exe").unwrap(),
        1,
        Sha256::digest([]).into(),
        true,
    )
    .unwrap();
    let request = RunRequest::new(
        [7; 16],
        closure_material_digest(std::slice::from_ref(&material)).unwrap(),
        SidecarCommand::GitleaksScanPackage,
        vec![
            ContentFrame::new(
                StagePath::try_from("input/gitleaks-scan/payload/rules.md").unwrap(),
                b"safe\n".to_vec(),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let helper_request = HelperRunRequest::new(request.clone(), vec![material]).unwrap();
    let mut wire = Vec::new();
    write_helper_request(&mut wire, &helper_request).unwrap();

    let mut child = Command::new(helper())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&wire).unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(output.status.success(), "stderr={:?}", output.stderr);
    assert!(output.stderr.is_empty());
    assert_eq!(
        read_run_response_for(&mut output.stdout.as_slice(), &request).unwrap(),
        RunResponse::failed(FailureCode::ClosureMismatch)
    );
}
