#[cfg(target_os = "macos")]
use std::{
    collections::BTreeMap,
    env,
    ffi::{CStr, CString},
    fs,
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    ptr,
    time::Duration,
};

#[cfg(target_os = "macos")]
const PROBE_PORTS: [u16; 8] = [42831, 43197, 43921, 44777, 45263, 46183, 47221, 48731];
#[cfg(target_os = "macos")]
const OUTSIDE_CLOSURE_CANARY: &str = ".context-relay-outside-closure-canary";
#[cfg(target_os = "macos")]
#[allow(clippy::zombie_processes)] // The launcher under test must kill this inherited group child.
fn main() {
    if env::args().nth(1).as_deref() == Some("--ordinary-child") {
        loop {
            std::thread::sleep(Duration::from_secs(60));
        }
    }

    let argv = env::args().skip(1).collect::<Vec<_>>();
    let argv_exact = argv
        == [
            "generate",
            "--targets",
            "claudecode",
            "--features",
            "rules",
            "--output-roots",
            "output",
            "--config",
            "rulesync.jsonc",
            "--input-root",
            "input",
            "--silent",
        ];
    let root = env::current_dir().unwrap();
    let mode = fs::read_to_string(root.join("input/.rulesync/rules/probe.md")).unwrap();
    if mode == "ESCAPE_HANG" {
        let session = unsafe { libc::setsid() };
        let session_errno = if session <= 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            0
        };
        let pid = unsafe { libc::getpid() };
        let pgid = unsafe { libc::getpgrp() };
        let home_write = fs::write(
            PathBuf::from(env::var_os("HOME").unwrap()).join("ordinary-child.pid"),
            format!("{pid}\n{pgid}\n"),
        )
        .is_ok();
        if session <= 0 || !home_write {
            let output_path = root.join("output/.claude/rules/probe.md");
            fs::create_dir_all(output_path.parent().unwrap()).unwrap();
            fs::write(
                output_path,
                format!(
                    "ESCAPE_SETSID={session}\nESCAPE_ERRNO={session_errno}\nESCAPE_HOME_WRITE={}\n",
                    u8::from(home_write)
                ),
            )
            .unwrap();
            return;
        }
        loop {
            std::thread::sleep(Duration::from_secs(60));
        }
    }
    if mode == "HANG" {
        let child = Command::new(env::current_exe().unwrap())
            .arg("--ordinary-child")
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = i32::try_from(child.id()).unwrap();
        let pgid = unsafe { libc::getpgid(pid) };
        assert!(pgid > 0);
        assert_eq!(pgid, unsafe { libc::getpgrp() });
        fs::write(
            PathBuf::from(env::var_os("HOME").unwrap()).join("ordinary-child.pid"),
            format!("{pid}\n{pgid}\n"),
        )
        .unwrap();
        loop {
            std::thread::sleep(Duration::from_secs(60));
        }
    }
    let creation_probe = (mode == "PROCESS_CREATION_DENIED").then(probe_process_creation);
    assert!(matches!(
        mode.as_str(),
        "SUCCESS" | "PROCESS_CREATION_DENIED"
    ));

    let environment_exact = env::vars_os().collect::<BTreeMap<_, _>>() == expected_env(&root);
    let home = PathBuf::from(env::var_os("HOME").unwrap());
    let fake_home_write = fs::write(home.join("proof"), b"ok").is_ok();
    let real_home_denied =
        fs::read(account_home().join(".context-relay-macos-adapter-canary")).is_err();
    let loopback_denied = PROBE_PORTS.iter().all(|port| {
        TcpStream::connect_timeout(
            &SocketAddr::from(([127, 0, 0, 1], *port)),
            Duration::from_millis(100),
        )
        .is_err()
    });
    let closure_denied = matches!(
        fs::read(outside_closure_canary()),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied
    );
    let proof = format!(
        "ARGV_EXACT={}\nENV_EXACT={}\nFAKE_HOME_WRITE={}\nREAL_HOME_DENIED={}\nLOOPBACK_DENIED={}\nCLOSURE_DENIED={}\n",
        u8::from(argv_exact),
        u8::from(environment_exact),
        u8::from(fake_home_write),
        u8::from(real_home_denied),
        u8::from(loopback_denied),
        u8::from(closure_denied),
    );
    let output_path = root.join("output/.claude/rules/probe.md");
    fs::create_dir_all(output_path.parent().unwrap()).unwrap();
    let output = creation_probe.map_or(proof.clone(), |creation_probe| {
        format!("{proof}{creation_probe}")
    });
    fs::write(output_path, output).unwrap();
}

#[cfg(target_os = "macos")]
fn probe_process_creation() -> String {
    let sidecar_pid = unsafe { libc::getpid() };
    let fork_result = unsafe { libc::fork() };
    let (fork_denied, fork_child_pid) = if fork_result == -1 {
        (
            std::io::Error::last_os_error().raw_os_error() == Some(libc::EAGAIN),
            0,
        )
    } else if fork_result == 0 {
        unsafe {
            libc::setsid();
        }
        loop {
            std::thread::sleep(Duration::from_secs(60));
        }
    } else {
        unsafe {
            libc::kill(fork_result, libc::SIGKILL);
            libc::waitpid(fork_result, ptr::null_mut(), 0);
        }
        (false, fork_result)
    };

    let program = env::current_exe().unwrap();
    let program = CString::new(program.as_os_str().as_encoded_bytes()).unwrap();
    let argument = CString::new("--ordinary-child").unwrap();
    let mut argv = [
        program.as_ptr().cast_mut(),
        argument.as_ptr().cast_mut(),
        ptr::null_mut(),
    ];
    let mut environment = [ptr::null_mut()];
    let mut spawn_child_pid = 0;
    let spawn_status = unsafe {
        libc::posix_spawn(
            &mut spawn_child_pid,
            program.as_ptr(),
            ptr::null(),
            ptr::null(),
            argv.as_mut_ptr(),
            environment.as_mut_ptr(),
        )
    };
    let spawn_denied = spawn_status == libc::EAGAIN;
    if spawn_status == 0 {
        unsafe {
            libc::kill(spawn_child_pid, libc::SIGKILL);
            libc::waitpid(spawn_child_pid, ptr::null_mut(), 0);
        }
    }
    format!(
        "SIDECAR_PID={sidecar_pid}\nFORK_DENIED={}\nFORK_CHILD_PID={fork_child_pid}\nPOSIX_SPAWN_DENIED={}\nPOSIX_SPAWN_CHILD_PID={spawn_child_pid}\n",
        u8::from(fork_denied),
        u8::from(spawn_denied),
    )
}

#[cfg(target_os = "macos")]
fn expected_env(root: &Path) -> BTreeMap<std::ffi::OsString, std::ffi::OsString> {
    let home = root.join("home").into_os_string();
    let data = root.join("data").into_os_string();
    let temp = root.join("temp").into_os_string();
    [
        ("HOME", home.clone()),
        ("USERPROFILE", home),
        ("APPDATA", data.clone()),
        ("LOCALAPPDATA", data.clone()),
        ("XDG_CONFIG_HOME", root.join("config").into_os_string()),
        ("XDG_DATA_HOME", data),
        ("XDG_CACHE_HOME", root.join("cache").into_os_string()),
        ("TMP", temp.clone()),
        ("TEMP", temp.clone()),
        ("TMPDIR", temp),
        ("PATH", root.join("runtime").into_os_string()),
        ("LANG", "C.UTF-8".into()),
        ("LC_ALL", "C.UTF-8".into()),
    ]
    .into_iter()
    .map(|(key, value)| (key.into(), value))
    .collect()
}

#[cfg(target_os = "macos")]
fn outside_closure_canary() -> PathBuf {
    let mut path = env::current_exe().unwrap();
    for component in ["rulesync", "bin", "runtime", "Helpers", "Contents"] {
        assert_eq!(
            path.file_name().and_then(|value| value.to_str()),
            Some(component)
        );
        assert!(path.pop());
    }
    assert_eq!(
        path.extension().and_then(|value| value.to_str()),
        Some("app")
    );
    assert!(path.pop());
    assert_eq!(
        path.file_name().and_then(|value| value.to_str()),
        Some("private")
    );
    assert!(path.pop());
    path.join(OUTSIDE_CLOSURE_CANARY)
}

#[cfg(target_os = "macos")]
fn account_home() -> PathBuf {
    let passwd = unsafe { libc::getpwuid(libc::getuid()) };
    assert!(!passwd.is_null());
    PathBuf::from(
        unsafe { CStr::from_ptr((*passwd).pw_dir) }
            .to_str()
            .unwrap(),
    )
}

#[cfg(not(target_os = "macos"))]
fn main() {}
