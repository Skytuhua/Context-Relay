#![cfg(windows)]

use std::{
    collections::BTreeMap,
    env, fs,
    io::{Read as _, Seek as _},
    os::windows::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

use context_relay_local_ipc::{RuntimeConfig, ServerHelloV1, connect, read_json};
use context_relay_protocol::PROTOCOL_VERSION;
use serde_json::json;
use sha2::{Digest as _, Sha256};

#[path = "../../core/src/test_windows_process.rs"]
#[allow(dead_code)] // This fixture uses the output-limited entry point only.
mod windows_process;

// This deliberately does not share the disposable daemon/write fixture: the
// production bridge must retain the real Windows profile and credential store.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires explicit installed bridge/hash, pinned Codex, Node and an already-running unlocked service"]
async fn actual_codex_reads_installed_service_status_without_workspace_changes() {
    const CODEX_SHA256: &str = "4b76ded066d0239115ca97473d010c92072bc5c5550a45dd7cbebe1e9eb956a7";
    let codex = explicit_path("CONTEXT_RELAY_TEST_CODEX_EXE");
    let node = explicit_path("CONTEXT_RELAY_TEST_NODE_EXE");
    let installed = explicit_path("CONTEXT_RELAY_TEST_INSTALLED_MCP_EXE");
    let expected = env::var("CONTEXT_RELAY_TEST_INSTALLED_MCP_SHA256").unwrap();
    assert!(expected.len() == 64 && expected.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(
        fs::canonicalize(&installed).unwrap(),
        fs::canonicalize(
            explicit_path("LOCALAPPDATA").join("Context Relay/context-relay-context-mcp.exe")
        )
        .unwrap()
    );
    // Hold read-only handles that deny replacement/write for the whole session.
    let _codex_pin = pin_executable(&codex, CODEX_SHA256);
    let _installed_pin = pin_executable(&installed, &expected);
    let before = service_hello().await;
    let real_home = explicit_path("USERPROFILE");
    let real_codex_home =
        env::var_os("CODEX_HOME").map_or_else(|| real_home.join(".codex"), PathBuf::from);
    let canaries: Vec<_> = ["config.toml", "hooks.json", ".personality_migration"]
        .map(|name| real_codex_home.join(name))
        .into_iter()
        .map(|path| {
            let hash = optional_hash(&path);
            (path, hash)
        })
        .collect();
    let mut bridge_env = BTreeMap::new();
    for name in [
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "PROGRAMDATA",
        "TEMP",
        "TMP",
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "XDG_DATA_HOME",
    ] {
        let fallback = match name {
            "XDG_CONFIG_HOME" => real_home.join(".config"),
            "XDG_CACHE_HOME" => real_home.join(".cache"),
            "XDG_DATA_HOME" => real_home.join(".local/share"),
            _ => real_home.clone(),
        };
        bridge_env.insert(name, env::var_os(name).map_or(fallback, PathBuf::from));
    }
    let temp = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(temp.path())
        .unwrap()
        .join("Installed harness 測試 O’Brien & [literal]");
    fs::create_dir(&root).unwrap();
    let project = root.join("project");
    let home = root.join("home");
    fs::create_dir(&project).unwrap();
    fs::create_dir(&home).unwrap();
    // No sibling daemon: a disappearing service must fail, never be started in
    // the test's kill-on-close job (the ordinary service is not test-owned).
    let bridge = root.join("context-relay-context-mcp.exe");
    fs::copy(&installed, &bridge).unwrap();
    let _bridge_pin = pin_executable(&bridge, &expected);
    assert!(!root.join("context-relay-contextd.exe").exists());
    let manifest = root.join("manifest.json");
    fs::write(
        &manifest,
        serde_json::to_vec(&json!({
            "executable": codex, "sha256": CODEX_SHA256,
            "bridge": bridge, "bridgeSha256": expected, "bridgeEnv": bridge_env,
            "root": root, "project": project, "home": home, "protocol": PROTOCOL_VERSION,
        }))
        .unwrap(),
    )
    .unwrap();
    let stdout = root.join("stdout");
    let stderr = root.join("stderr");
    let mut command = Command::new(node);
    command.env_clear();
    for name in ["SystemRoot", "WINDIR"] {
        command.env(name, env::var_os(name).unwrap());
    }
    command
        .arg(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/installed-codex-status.mjs"),
        )
        .arg(manifest)
        .current_dir(&root)
        .stdin(Stdio::piped())
        .stdout(fs::File::create(&stdout).unwrap())
        .stderr(fs::File::create(&stderr).unwrap());
    let out = stdout.clone();
    let err = stderr.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        windows_process::run_in_owned_job_with_output_limit(
            &mut command,
            Duration::from_secs(150),
            &[&out, &err],
            1024 * 1024,
        )
    })
    .await;
    // Verify these even when the contained harness failed.
    assert_eq!(
        service_hello().await.daemon_instance_nonce,
        before.daemon_instance_nonce
    );
    for (path, hash) in canaries {
        assert_eq!(
            optional_hash(&path),
            hash,
            "ordinary Codex configuration changed"
        );
    }
    assert!(
        matches!(outcome, Ok(Ok(status)) if status.success()),
        "stdout: {}\nstderr: {}",
        fs::read_to_string(&stdout).unwrap(),
        fs::read_to_string(&stderr).unwrap()
    );
    println!("{}", fs::read_to_string(stdout).unwrap());
    // Release the copied executable before tempfile removes the owned fixture.
    drop(_bridge_pin);
}

fn explicit_path(name: &str) -> PathBuf {
    PathBuf::from(env::var_os(name).expect(name))
}

fn pin_executable(path: &Path, expected: &str) -> fs::File {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(path)
        .unwrap();
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let length = file.read(&mut buffer).unwrap();
        if length == 0 {
            break;
        }
        hash.update(&buffer[..length]);
    }
    assert_eq!(format!("{:x}", hash.finalize()), expected);
    file.rewind().unwrap();
    file
}

fn optional_hash(path: &Path) -> Option<String> {
    match fs::read(path) {
        Ok(bytes) => Some(format!("{:x}", Sha256::digest(bytes))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => panic!("cannot check configuration canary: {error}"),
    }
}

async fn service_hello() -> ServerHelloV1 {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut stream = connect(&RuntimeConfig::production())
            .await
            .expect("service must already be running");
        let hello: ServerHelloV1 = read_json(&mut stream).await.unwrap();
        assert_eq!(hello.protocol, PROTOCOL_VERSION);
        hello
    })
    .await
    .expect("service greeting timed out")
}
