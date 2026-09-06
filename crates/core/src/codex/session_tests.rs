//! Opt-in lifecycle qualification in fresh homes, with an inert hook and local model.

use std::{
    env, fs,
    os::windows::process::CommandExt as _,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

use context_relay_protocol::HarnessId;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

#[test]
#[ignore = "requires explicitly selected Codex 0.144.6, Node and rustc; local model only"]
fn pinned_codex_sessions_require_exact_hook_trust_and_deliver_generated_commands() {
    const SHA256: &str = "4b76ded066d0239115ca97473d010c92072bc5c5550a45dd7cbebe1e9eb956a7";
    let executable = PathBuf::from(
        env::var_os("CONTEXT_RELAY_TEST_CODEX_EXE").expect("explicit Codex executable"),
    );
    let node = PathBuf::from(
        env::var_os("CONTEXT_RELAY_TEST_NODE_EXE").expect("explicit Node executable"),
    );
    assert_eq!(
        format!("{:x}", Sha256::digest(fs::read(&executable).unwrap())),
        SHA256
    );
    let temp = tempfile::tempdir().unwrap();
    let physical = fs::canonicalize(temp.path()).unwrap();
    assert!(
        matches!(physical.components().next(), Some(std::path::Component::Prefix(prefix))
            if matches!(prefix.kind(), std::path::Prefix::VerbatimDisk(_))),
        "The opt-in fixture requires a temporary directory on a local Windows drive"
    );
    let root = PathBuf::from(physical.to_str().unwrap().strip_prefix(r"\\?\").unwrap());
    assert!(root.is_absolute());
    assert_eq!(fs::canonicalize(&root).unwrap(), physical);
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let capture = root.join("capture.exe");
    let compiled = Command::new("rustc")
        .arg(fixtures.join("claude-hook-capture.rs"))
        .args(["--crate-name", "hook_capture", "-o"])
        .arg(&capture)
        .creation_flags(0x0800_0000)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let mut cases = vec![];
    for name in [
        "plain",
        "space 測試 O'Brien $HOME",
        "symbols & % ! ^ [literal]",
        "smart O‘Brien O’Brien O‚Brien O‛Brien",
    ] {
        let case = root.join(name);
        let home = case.join("home");
        let project = case.join("project");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir(&project).unwrap();
        let bridge = case.join("inert bridge.exe");
        fs::copy(&capture, &bridge).unwrap();
        let hook = crate::native_memory::managed_memory_hooks(
            HarnessId::Codex,
            &super::wire_path(&fs::canonicalize(&bridge).unwrap()),
        )
        .unwrap()
        .remove(0);
        let hooks: Value = serde_json::from_str(&hook.body_markdown).unwrap();
        cases.push(json!({"name":name,"root":case,"home":home,"project":project,"hooks":hooks}));
    }
    let manifest = root.join("manifest.json");
    fs::write(
        &manifest,
        serde_json::to_vec(&json!({
            "executable":executable,"sha256":SHA256,"cases":cases
        }))
        .unwrap(),
    )
    .unwrap();
    let stdout = root.join("stdout");
    let stderr = root.join("stderr");
    let mut command = Command::new(node);
    command.env_clear();
    for name in ["SystemRoot", "WINDIR"] {
        if let Some(value) = env::var_os(name) {
            command.env(name, value);
        }
    }
    command
        .arg(fixtures.join("codex-local-session.mjs"))
        .arg(manifest)
        .current_dir(&root)
        .stdin(Stdio::piped())
        .stdout(fs::File::create(&stdout).unwrap())
        .stderr(fs::File::create(&stderr).unwrap());
    let result =
        crate::test_windows_process::run_in_owned_job(&mut command, Duration::from_secs(150));
    assert!(
        result.is_ok_and(|status| status.success()),
        "stdout: {}\nstderr: {}",
        fs::read_to_string(stdout).unwrap(),
        fs::read_to_string(stderr).unwrap()
    );
    println!("{}", fs::read_to_string(root.join("stdout")).unwrap());
}
