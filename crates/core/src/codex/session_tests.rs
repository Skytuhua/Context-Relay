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

#[test]
#[ignore = "requires explicitly selected Codex 0.144.6 and Node; readback in fresh homes only"]
fn pinned_codex_project_trust_matches_adapter_lookup() {
    use super::{CodexAdapter, CodexExecutableKind, CodexLayout};
    use context_relay_protocol::{DeviceId, HybridLogicalClock, InstallationMethod, ProjectId};

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
        if matches!(prefix.kind(), std::path::Prefix::VerbatimDisk(_)))
    );
    let root = PathBuf::from(physical.to_str().unwrap().strip_prefix(r"\\?\").unwrap());
    assert_eq!(fs::canonicalize(&root).unwrap(), physical);
    let mut cases = Vec::new();
    for name in [
        "lowercase",
        "uppercase",
        "normalized-untrusted",
        "normalized-trusted",
        "lexical-untrusted",
        "lexical-trusted",
        "verbatim-only",
        "verbatim-request",
        "verbatim-shadowed",
        "unset-lowercase",
        "unicode-alias",
        "nested-inherit",
        "nested-untrusted",
        "nested-explicit-trusted",
    ] {
        let case = root.join(name);
        let home = case.join("home");
        let project = case.join("Project Ä 測試");
        let cwd = if name.starts_with("nested-") {
            project.join("service")
        } else {
            project.clone()
        };
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(cwd.join(".codex")).unwrap();
        fs::create_dir(project.join(".git")).unwrap();
        let ordinary = project.to_str().unwrap();
        let lower = ordinary.to_ascii_lowercase();
        let upper = ordinary.to_ascii_uppercase();
        let verbatim = fs::canonicalize(&project)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let entries = match name {
            "lowercase" => vec![(lower, Some("trusted"))],
            "uppercase" => vec![(upper, Some("trusted"))],
            "normalized-untrusted" => vec![(upper, Some("trusted")), (lower, Some("untrusted"))],
            "normalized-trusted" => vec![(upper, Some("untrusted")), (lower, Some("trusted"))],
            "lexical-untrusted" => vec![
                (ordinary.to_owned(), Some("trusted")),
                (upper, Some("untrusted")),
            ],
            "lexical-trusted" => vec![
                (ordinary.to_owned(), Some("untrusted")),
                (upper, Some("trusted")),
            ],
            "verbatim-only" | "verbatim-request" => vec![(verbatim.clone(), Some("trusted"))],
            "verbatim-shadowed" => vec![
                (verbatim.clone(), Some("trusted")),
                (lower, Some("untrusted")),
            ],
            "unset-lowercase" => vec![(lower, None), (upper, Some("trusted"))],
            "unicode-alias" => vec![(lower.replace('Ä', "ä"), Some("trusted"))],
            "nested-inherit" => vec![(lower, Some("trusted"))],
            "nested-untrusted" => vec![
                (lower, Some("trusted")),
                (
                    cwd.to_str().unwrap().to_ascii_lowercase(),
                    Some("untrusted"),
                ),
            ],
            "nested-explicit-trusted" => vec![
                (lower, Some("untrusted")),
                (cwd.to_str().unwrap().to_ascii_lowercase(), Some("trusted")),
            ],
            _ => unreachable!(),
        };
        let mut config = String::from(
            "[features]\nhooks = true\nshell_snapshot = false\n[memories]\ngenerate_memories = false\nuse_memories = false\n",
        );
        for (key, trust) in entries {
            config.push_str(&format!(
                "\n[projects.{}]\n",
                serde_json::to_string(&key).unwrap()
            ));
            if let Some(trust) = trust {
                config.push_str(&format!("trust_level = {trust:?}\n"));
            }
        }
        fs::write(home.join("config.toml"), config).unwrap();
        fs::write(cwd.join(".codex/hooks.json"), r#"{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"context-relay-inert-fixture-command"}]}]}}"#).unwrap();
        let requested_cwd = if name == "verbatim-request" {
            PathBuf::from(verbatim)
        } else {
            cwd
        };
        cases.push(json!({"name":name,"home":home,"project":project,"cwd":requested_cwd}));
    }
    let results_path = root.join("results.json");
    let manifest = root.join("manifest.json");
    fs::write(
        &manifest,
        serde_json::to_vec(
            &json!({"executable":executable,"sha256":SHA256,"cases":cases,"results":results_path}),
        )
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
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/codex-project-trust.mjs"))
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
        fs::read_to_string(&stdout).unwrap(),
        fs::read_to_string(stderr).unwrap()
    );
    println!("{}", fs::read_to_string(stdout).unwrap());
    let results: Vec<Value> = serde_json::from_slice(&fs::read(results_path).unwrap()).unwrap();
    assert_eq!(results.len(), cases.len());
    let project_id: ProjectId = "018f22e2-79b0-7cc8-98c4-dc0c0c073981".parse().unwrap();
    let device: DeviceId = "018f22e2-79b0-7cc8-98c4-dc0c0c073982".parse().unwrap();
    for (entry, result) in cases.iter().zip(results) {
        assert_eq!(entry["name"], result["name"]);
        let project = PathBuf::from(entry["project"].as_str().unwrap());
        let cwd = PathBuf::from(entry["cwd"].as_str().unwrap());
        let home = PathBuf::from(entry["home"].as_str().unwrap());
        let adapter = CodexAdapter::from_layout(
            CodexLayout {
                executable: executable.clone(),
                executable_kind: CodexExecutableKind::Native,
                version: "0.144.6".into(),
                installation_method: InstallationMethod::Manual,
                codex_home: home.clone(),
                user_home: home.clone(),
                user_skills_dir: home.join("skills"),
                project_root: project.clone(),
                working_directory: cwd.clone(),
                requirements_paths: vec![],
            },
            project_id,
            device,
            HybridLogicalClock::new(0, 0, device),
        )
        .unwrap();
        let selected_config = fs::canonicalize(cwd).unwrap().join(".codex/config.toml");
        assert_eq!(
            adapter
                .effective_config_paths()
                .unwrap()
                .iter()
                .any(|(path, _)| *path == selected_config),
            result["trusted"].as_bool().unwrap(),
            "{}",
            entry["name"]
        );
        if entry["name"] == "nested-untrusted" || entry["name"] == "nested-explicit-trusted" {
            assert!(!adapter.project_is_trusted().unwrap());
        }
    }
}
