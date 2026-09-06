use super::super::{CodexExecutableKind, CodexLayout, wire_path};
use super::*;
use context_relay_protocol::{
    DeviceId, HarnessId, HybridLogicalClock, InstallationMethod, ProjectId,
};
use sha2::{Digest as _, Sha256};
use std::{env, path::PathBuf};

#[test]
#[ignore = "requires explicitly selected Codex 0.144.6; disposable profiles only"]
fn pinned_codex_reads_native_hook_trust_without_executing_hooks() {
    const HASH: &str = "4b76ded066d0239115ca97473d010c92072bc5c5550a45dd7cbebe1e9eb956a7";
    let executable = PathBuf::from(
        env::var_os("CONTEXT_RELAY_TEST_CODEX_EXE").expect("explicit Codex executable"),
    );
    if env::var_os("CONTEXT_RELAY_HOOK_READBACK_CHILD").is_none() {
        let outer = tempfile::tempdir().unwrap();
        let canary = super::tests::compile_probe(outer.path());
        let scratch = outer.path().join("scratch");
        let ambient = outer.path().join("unrelated ambient profile");
        fs::create_dir(&scratch).unwrap();
        fs::create_dir(&ambient).unwrap();
        let original = b"# This profile must not be read or changed\n";
        fs::write(ambient.join("config.toml"), original).unwrap();
        let stdout = outer.path().join("stdout");
        let stderr = outer.path().join("stderr");
        let mut child = Command::new(env::current_exe().unwrap());
        child.env_clear();
        for key in ["SystemRoot", "WINDIR"] {
            if let Some(value) = env::var_os(key) {
                child.env(key, value);
            }
        }
        child.args(["--exact", "codex::hook_readback::native_tests::pinned_codex_reads_native_hook_trust_without_executing_hooks", "--ignored", "--nocapture"])
            .env("CONTEXT_RELAY_HOOK_READBACK_CHILD", "1")
            .env("CONTEXT_RELAY_TEST_CODEX_EXE", executable)
            .env("CONTEXT_RELAY_TEST_HOOK_EXE", canary)
            .env("CODEX_HOME", &ambient).env("HOME", &ambient).env("USERPROFILE", &ambient)
            .env("TEMP", &scratch).env("TMP", &scratch)
            .current_dir(outer.path()).stdin(Stdio::piped())
            .stdout(fs::File::create(&stdout).unwrap()).stderr(fs::File::create(&stderr).unwrap());
        let result =
            crate::test_windows_process::run_in_owned_job(&mut child, Duration::from_secs(100));
        assert!(
            result.is_ok_and(|status| status.success()),
            "stdout: {}\nstderr: {}",
            fs::read_to_string(&stdout).unwrap(),
            fs::read_to_string(stderr).unwrap()
        );
        assert_eq!(fs::read(ambient.join("config.toml")).unwrap(), original);
        println!("{}", fs::read_to_string(stdout).unwrap());
        return;
    }
    let mut gate = String::new();
    std::io::stdin().read_to_string(&mut gate).unwrap();
    assert_eq!(gate, "run");
    assert_eq!(
        format!("{:x}", Sha256::digest(fs::read(&executable).unwrap())),
        HASH
    );
    let temp = tempfile::tempdir_in(env::current_dir().unwrap()).unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let home = root.join("user home 專案");
    let config = root.join("custom profile O'Brien & [literal]");
    let project = root.join("project 專案");
    for path in [&home, &config, &project] {
        fs::create_dir(path).unwrap();
    }
    let device: DeviceId = "018f22e2-79b0-7cc8-98c4-dc0c0c073982".parse().unwrap();
    let adapter = CodexAdapter::from_layout(
        CodexLayout {
            executable: executable.clone(),
            executable_kind: CodexExecutableKind::Native,
            version: "0.144.6".into(),
            installation_method: InstallationMethod::Manual,
            codex_home: config.clone(),
            user_home: home.clone(),
            user_skills_dir: home.join(".agents/skills"),
            project_root: project.clone(),
            working_directory: project.clone(),
            requirements_paths: vec![],
        },
        "018f22e2-79b0-7cc8-98c4-dc0c0c073981"
            .parse::<ProjectId>()
            .unwrap(),
        device,
        HybridLogicalClock::new(1, 0, device),
    )
    .unwrap();
    // A fixture-owned marker executable makes any hook invocation observable.
    let bridge = root.join("must never execute.exe");
    fs::copy(env::var_os("CONTEXT_RELAY_TEST_HOOK_EXE").unwrap(), &bridge).unwrap();
    let component =
        crate::native_memory::managed_memory_hooks(HarnessId::Codex, &wire_path(&bridge))
            .unwrap()
            .remove(0);
    let hooks: Value = serde_json::from_str(&component.body_markdown).unwrap();
    let hook_path = config.join("hooks.json");
    fs::write(
        &hook_path,
        serde_json::to_vec(&json!({"hooks":hooks})).unwrap(),
    )
    .unwrap();
    let base = format!(
        "[projects.{}]\ntrust_level = \"trusted\"\n",
        serde_json::to_string(
            &dunce::simplified(&project)
                .to_string_lossy()
                .to_ascii_lowercase()
        )
        .unwrap()
    );
    let config_path = config.join("config.toml");
    fs::write(&config_path, &base).unwrap();
    let mut wrapper = adapter.clone();
    wrapper.layout.executable_kind = CodexExecutableKind::Wrapper;
    assert!(wrapper.read_native_hooks().is_err());
    let initial = adapter.read_native_hooks().unwrap();
    // Even this empty profile is changed by app-server startup. This probe
    // must remain test-only until those non-RPC effects can be contained.
    assert!(config.join(".personality_migration").is_file());
    assert_eq!(initial.len(), 2);
    assert!(
        initial
            .iter()
            .all(|hook| hook.trust_status == "untrusted" && hook.enabled && !hook.is_managed)
    );
    let mut trusted = base.clone();
    for hook in &initial {
        assert_eq!(fs::canonicalize(&hook.source_path).unwrap(), hook_path);
        assert!(
            hook.command
                .as_ref()
                .unwrap()
                .contains("must never execute.exe")
        );
        trusted.push_str(&format!(
            "\n[hooks.state.{}]\ntrusted_hash = {}\n",
            serde_json::to_string(&hook.key).unwrap(),
            serde_json::to_string(&hook.current_hash).unwrap()
        ));
    }
    for phase in ["trusted", "disabled", "modified"] {
        let current = if phase == "disabled" {
            format!("{trusted}\n[features]\nhooks = false\n")
        } else {
            trusted.clone()
        };
        fs::write(&config_path, &current).unwrap();
        if phase == "modified" {
            let mut changed = hooks.clone();
            for event in ["SessionStart", "Stop"] {
                changed[event][0]["hooks"][0]["statusMessage"] =
                    json!("Changed disposable definition");
            }
            fs::write(
                &hook_path,
                serde_json::to_vec(&json!({"hooks":changed})).unwrap(),
            )
            .unwrap();
        }
        let before_hooks = fs::read(&hook_path).unwrap();
        let result = adapter.read_native_hooks().unwrap();
        assert_eq!(result.len(), if phase == "disabled" { 0 } else { 2 });
        assert!(result.iter().all(|hook| hook.trust_status == phase));
        assert_eq!(fs::read_to_string(&config_path).unwrap(), current);
        assert_eq!(fs::read(&hook_path).unwrap(), before_hooks);
        println!("{phase}: {} hooks", result.len());
        assert!(
            !root.join("hook-executed").exists(),
            "hook listing executed a hook"
        );
    }
    assert!(!home.join(".codex").exists());
    assert_eq!(
        format!("{:x}", Sha256::digest(fs::read(executable).unwrap())),
        HASH
    );
}
