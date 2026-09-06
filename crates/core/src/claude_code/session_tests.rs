//! Opt-in qualification against an exact installed executable and local model stub.

use std::os::windows::process::CommandExt as _;
use std::{
    collections::BTreeMap,
    env, fs,
    os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

use windows_sys::Win32::{
    Foundation::{ERROR_INVALID_PARAMETER, GetLastError, WAIT_OBJECT_0},
    System::Threading::{OpenProcess, WaitForSingleObject},
};

use crate::test_windows_process::run_in_owned_job;
use context_relay_protocol::HarnessId;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use super::{command_context::ClaudeCommandContext, memory_path, memory_repository, wire_path};

#[test]
#[ignore = "requires explicitly selected pinned Claude, Node and rustc; uses only a local model stub"]
fn pinned_claude_sessions_use_effective_memory_and_deliver_generated_lifecycle_hooks() {
    let executable = PathBuf::from(
        env::var_os("CONTEXT_RELAY_TEST_CLAUDE_EXE").expect("explicit Claude executable"),
    );
    let expected = env::var("CONTEXT_RELAY_TEST_CLAUDE_SHA256").expect("explicit Claude digest");
    let node = PathBuf::from(
        env::var_os("CONTEXT_RELAY_TEST_NODE_EXE").expect("explicit Node executable"),
    );
    assert_eq!(
        format!("{:x}", Sha256::digest(fs::read(&executable).unwrap())),
        expected
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
    verify_fixture_descendant_cleanup(&node, &root);
    let bridge = root.join("capture.exe");
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let compiled = Command::new("rustc")
        .arg(fixtures.join("claude-hook-capture.rs"))
        .args(["--crate-name", "hook_capture", "-o"])
        .arg(&bridge)
        .creation_flags(0x0800_0000)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let marker = "CONTEXT_RELAY_SYNTHETIC_MEMORY_4E9A";
    let decoy = "CONTEXT_RELAY_WRONG_FOLDER_7B36";
    let mut cases = vec![];
    for name in [
        "enabled",
        "project-disabled",
        "local-enabled",
        "local-disabled",
        "environment-force-enabled",
        "environment-disabled",
        "settings-flag",
        "user-source-only",
        "repository-subfolder",
        "linked-worktree",
        "custom-configuration",
        "user-env-force-enabled",
        "user-env-disabled",
        "project-env-disabled",
        "local-env-force-enabled",
        "local-env-disabled",
        "user-env-lowercase-force-enabled",
        "local-env-mixed-case-disabled",
        "user-env-conflicting-aliases",
        "user-env-lowercase-project-disabled",
    ] {
        let case = root.join(name);
        let home = case.join("home");
        let config = home.join(if name == "custom-configuration" {
            "custom configuration"
        } else {
            ".claude"
        });
        let mut project = case.join("project");
        if name == "repository-subfolder" || name == "linked-worktree" {
            project = project.join("nested");
        }
        fs::create_dir_all(&config).unwrap();
        fs::create_dir_all(project.join(".claude")).unwrap();
        let copied_bridge = case.join("bridge $HOME O'Brien 專案.exe");
        fs::copy(&bridge, &copied_bridge).unwrap();
        let hook = crate::native_memory::managed_memory_hooks(
            HarnessId::ClaudeCode,
            &wire_path(&fs::canonicalize(&copied_bridge).unwrap()),
        )
        .unwrap()
        .remove(0);
        let hooks: Value = serde_json::from_str(&hook.body_markdown).unwrap();
        let enabled = !matches!(
            name,
            "project-disabled"
                | "local-disabled"
                | "environment-disabled"
                | "user-env-disabled"
                | "project-env-disabled"
                | "local-env-disabled"
                | "local-env-mixed-case-disabled"
                | "user-env-lowercase-project-disabled"
        );
        let mut user =
            json!({"hooks":hooks,"autoMemoryEnabled":true,"autoMemoryDirectory":"~/memory"});
        let mut project_settings = json!({});
        let mut extra_arguments: Vec<String> = vec![];
        let mut memory = home.join("memory");
        if matches!(
            name,
            "project-disabled"
                | "local-enabled"
                | "local-disabled"
                | "settings-flag"
                | "user-source-only"
        ) {
            project_settings["autoMemoryEnabled"] = json!(false);
        }
        if matches!(name, "local-enabled" | "local-disabled") {
            fs::write(
                project.join(".claude/settings.local.json"),
                serde_json::to_vec(&json!({"autoMemoryEnabled":name=="local-enabled"})).unwrap(),
            )
            .unwrap();
        }
        if name == "environment-force-enabled" {
            user["autoMemoryEnabled"] = json!(false);
        }
        if name == "user-env-force-enabled" {
            user["autoMemoryEnabled"] = json!(false);
            user["env"] = json!({"CLAUDE_CODE_DISABLE_AUTO_MEMORY":"false"});
        }
        if name == "user-env-lowercase-force-enabled" {
            user["autoMemoryEnabled"] = json!(false);
            user["env"] = json!({"claude_code_disable_auto_memory":"false"});
        }
        if name == "user-env-conflicting-aliases" {
            user["autoMemoryEnabled"] = json!(false);
            user["env"] = json!({"CLAUDE_CODE_DISABLE_AUTO_MEMORY":"true","claude_code_disable_auto_memory":"false"});
        }
        if name == "user-env-lowercase-project-disabled" {
            user["autoMemoryEnabled"] = json!(false);
            user["env"] = json!({"claude_code_disable_auto_memory":"false"});
            project_settings["env"] = json!({"CLAUDE_CODE_DISABLE_AUTO_MEMORY":"true"});
        }
        if name == "local-env-mixed-case-disabled" {
            user["env"] = json!({"CLAUDE_CODE_DISABLE_AUTO_MEMORY":"false"});
            fs::write(project.join(".claude/settings.local.json"), serde_json::to_vec(&json!({"autoMemoryEnabled":false,"env":{"Claude_Code_Disable_Auto_Memory":"true"}})).unwrap()).unwrap();
        }
        if name == "user-env-disabled"
            || name == "project-env-disabled"
            || name == "local-env-force-enabled"
        {
            user["env"] = json!({"CLAUDE_CODE_DISABLE_AUTO_MEMORY":"true"});
        }
        if name == "project-env-disabled" {
            user["env"] = json!({"CLAUDE_CODE_DISABLE_AUTO_MEMORY":"false"});
            project_settings["env"] = json!({"CLAUDE_CODE_DISABLE_AUTO_MEMORY":"true"});
        }
        if name == "local-env-force-enabled" {
            fs::write(project.join(".claude/settings.local.json"), serde_json::to_vec(&json!({"autoMemoryEnabled":false,"env":{"CLAUDE_CODE_DISABLE_AUTO_MEMORY":"false"}})).unwrap()).unwrap();
        }
        if name == "local-env-disabled" {
            user["env"] = json!({"CLAUDE_CODE_DISABLE_AUTO_MEMORY":"false"});
            fs::write(project.join(".claude/settings.local.json"), serde_json::to_vec(&json!({"autoMemoryEnabled":false,"env":{"CLAUDE_CODE_DISABLE_AUTO_MEMORY":"true"}})).unwrap()).unwrap();
        }
        if name == "settings-flag" {
            extra_arguments = vec!["--settings".into(), r#"{"autoMemoryEnabled":true}"#.into()];
        }
        if name == "user-source-only" {
            extra_arguments = vec!["--setting-sources".into(), "user".into()];
        }
        if name == "repository-subfolder" {
            fs::create_dir(case.join("project/.git")).unwrap();
        }
        if name == "linked-worktree" {
            let gitdir = case.join("main/.git/worktrees/topic");
            fs::create_dir_all(&gitdir).unwrap();
            fs::write(
                case.join("project/.git"),
                b"gitdir: ../main/.git/worktrees/topic\n",
            )
            .unwrap();
            fs::write(gitdir.join("commondir"), b"../..\n").unwrap();
            fs::write(gitdir.join("gitdir"), b"../../../../project/.git\n").unwrap();
        }
        if matches!(name, "repository-subfolder" | "linked-worktree") {
            user.as_object_mut().unwrap().remove("autoMemoryDirectory");
            let repository = memory_repository::default_root(&project).unwrap();
            memory = config
                .join("projects")
                .join(memory_path::directory_key(&repository).unwrap())
                .join("memory");
            let wrong = config
                .join("projects")
                .join(memory_path::directory_key(&project).unwrap())
                .join("memory");
            fs::create_dir_all(&wrong).unwrap();
            fs::write(wrong.join("MEMORY.md"), decoy).unwrap();
        }
        fs::create_dir_all(&memory).unwrap();
        fs::write(memory.join("MEMORY.md"), marker).unwrap();
        fs::write(
            config.join("settings.json"),
            serde_json::to_vec(&user).unwrap(),
        )
        .unwrap();
        fs::write(
            project.join(".claude/settings.json"),
            serde_json::to_vec(&project_settings).unwrap(),
        )
        .unwrap();
        let state = if name == "custom-configuration" {
            config.join(".claude.json")
        } else {
            home.join(".claude.json")
        };
        let context = ClaudeCommandContext::new(&config, &state, &project, &home).unwrap();
        let mut command = Command::new(&executable);
        context.configure(&mut command, &[]).unwrap();
        let mut environment = command
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_str().unwrap().to_owned(),
                    value.unwrap().to_str().unwrap().to_owned(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        environment.insert("TEMP".into(), case.to_str().unwrap().into());
        environment.insert("TMP".into(), case.to_str().unwrap().into());
        if name == "environment-force-enabled" {
            environment.insert("CLAUDE_CODE_DISABLE_AUTO_MEMORY".into(), "false".into());
        }
        if name == "environment-disabled" {
            environment.insert("CLAUDE_CODE_DISABLE_AUTO_MEMORY".into(), "true".into());
        }
        cases.push(json!({"name":name,"root":case,"project":project,"environment":environment,"arguments":extra_arguments,"markers":{marker:enabled,decoy:false}}));
    }
    let manifest = root.join("manifest.json");
    let result = root.join("results.json");
    fs::write(&manifest,serde_json::to_vec(&json!({"executable":executable,"sha256":expected,"version":"2.1.202","cases":cases,"result":result})).unwrap()).unwrap();
    let stdout_path = root.join("stdout.log");
    let stderr_path = root.join("stderr.log");
    let mut command = Command::new(&node);
    command
        .arg("--unhandled-rejections=strict")
        .arg(fixtures.join("claude-local-session.mjs"))
        .arg(&manifest)
        .stdin(Stdio::piped())
        .stdout(fs::File::create(&stdout_path).unwrap())
        .stderr(fs::File::create(&stderr_path).unwrap())
        .creation_flags(0x0800_0000);
    let status = run_in_owned_job(
        &mut command,
        Duration::from_secs(40 * cases.len() as u64 + 60),
    )
    .expect("Local harness sessions must finish within their deadline");
    println!("{}", fs::read_to_string(&stdout_path).unwrap());
    assert!(
        status.success(),
        "{}",
        fs::read_to_string(&stderr_path).unwrap()
    );
    let results: Value = serde_json::from_slice(&fs::read(&result).unwrap()).unwrap();
    assert_eq!(results["results"].as_array().unwrap().len(), cases.len());
    for (case, result) in cases.iter().zip(results["results"].as_array().unwrap()) {
        assert_eq!(result["passed"], true, "{}", case["name"]);
        for event in ["start", "stop"] {
            assert_eq!(
                fs::canonicalize(result[event]["cwd"].as_str().unwrap()).unwrap(),
                fs::canonicalize(case["project"].as_str().unwrap()).unwrap()
            );
        }
    }
}

fn verify_fixture_descendant_cleanup(node: &Path, root: &Path) {
    for mode in ["exit", "timeout"] {
        let pid_path = root.join(format!("{mode}-child.pid"));
        let mut command = Command::new(node);
        command
            .args([
                "--eval",
                r#"
            const fs = require('fs');
            if (fs.readFileSync(0, 'utf8') !== 'run') process.exit(2);
            const child = require('child_process').spawn(process.execPath,
                ['-e', 'setInterval(() => {}, 1000)'], {windowsHide:true, stdio:'ignore'});
            fs.writeFileSync(process.argv[1], String(child.pid));
            if (process.argv[2] === 'exit') process.exit(0);
            setInterval(() => {}, 1000);
        "#,
            ])
            .arg(&pid_path)
            .arg(mode)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let outcome = run_in_owned_job(&mut command, Duration::from_secs(2));
        if mode == "exit" {
            assert!(outcome.unwrap().success());
        } else {
            assert!(outcome.is_err());
        }
        let pid: u32 = fs::read_to_string(&pid_path).unwrap().parse().unwrap();
        // SAFETY: open only a synchronization handle to our recorded synthetic child.
        let raw = unsafe { OpenProcess(0x0010_0000, 0, pid) };
        if raw.is_null() {
            // SAFETY: reads this thread's preceding Win32 call error.
            assert_eq!(unsafe { GetLastError() }, ERROR_INVALID_PARAMETER);
        } else {
            // SAFETY: OpenProcess returned a new non-null owned handle.
            let child = unsafe { OwnedHandle::from_raw_handle(raw) };
            // SAFETY: the synchronization handle is live; waiting does not mutate it.
            assert_eq!(
                unsafe { WaitForSingleObject(child.as_raw_handle(), 5000) },
                WAIT_OBJECT_0
            );
        }
    }
    println!("Owned fixture descendants terminate after normal exit and timeout");
}
