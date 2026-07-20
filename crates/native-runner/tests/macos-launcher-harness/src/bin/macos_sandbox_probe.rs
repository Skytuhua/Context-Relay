#[cfg(target_os = "macos")]
use std::{
    env, fs,
    io::{self, Read},
    net::{SocketAddr, TcpStream},
    os::{fd::RawFd, unix::process::CommandExt},
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};

#[cfg(target_os = "macos")]
use objc2_foundation::NSHomeDirectory;

#[cfg(target_os = "macos")]
#[allow(clippy::zombie_processes)] // Fixtures intentionally outlive or are killed with the helper.
fn main() {
    match env::args().nth(1).as_deref() {
        Some("--child") => return child(),
        Some("--detached") => return detached(),
        Some("--sleep") => loop {
            std::thread::sleep(Duration::from_secs(60));
        },
        Some("--hold-stdio") => {
            std::thread::sleep(Duration::from_secs(3));
            return;
        }
        _ => {}
    }

    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    match field_optional(&input, "MODE") {
        Some("WRITE") => {
            let home = NSHomeDirectory().to_string();
            fs::write(Path::new(&home).join(field(&input, "RELATIVE")), b"later").unwrap();
            println!("WROTE=1");
        }
        Some("DETACH") => {
            let mut command = Command::new(bundled_child());
            command
                .args([
                    "--detached",
                    field(&input, "TARGET"),
                    field(&input, "MARKER"),
                ])
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            unsafe {
                command.pre_exec(|| {
                    if libc::setsid() == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            command.spawn().unwrap();
            println!("DETACHED=1");
        }
        Some("DETACH_STDIO") => {
            let mut command = Command::new(bundled_child());
            command.arg("--hold-stdio").env_clear();
            unsafe {
                command.pre_exec(|| {
                    if libc::setsid() == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            command.spawn().unwrap();
            println!("DETACHED_STDIO=1");
        }
        Some("HANG") => {
            Command::new(bundled_child())
                .arg("--sleep")
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            loop {
                std::thread::sleep(Duration::from_secs(60));
            }
        }
        _ => check_isolation(&input),
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {}

#[cfg(target_os = "macos")]
fn check_isolation(input: &str) {
    let canary = field(input, "CANARY");
    let address = field(input, "ADDRESS").parse::<SocketAddr>().unwrap();
    let inherited_fd = field(input, "FD").parse::<RawFd>().unwrap();
    let real_home_denied = fs::read(canary).is_err();
    let loopback_denied = TcpStream::connect_timeout(&address, Duration::from_secs(1)).is_err();
    let fd_denied = unsafe { libc::fcntl(inherited_fd, libc::F_GETFD) } == -1;
    let env_denied = [
        "AWS_SECRET_ACCESS_KEY",
        "GITHUB_TOKEN",
        "HTTP_PROXY",
        "SSH_AUTH_SOCK",
    ]
    .iter()
    .all(|name| env::var_os(name).is_none());
    let home = NSHomeDirectory().to_string();
    let stage = Path::new(&home).join("context-relay-stage");
    fs::create_dir_all(&stage).unwrap();
    let fake_home_write = fs::write(stage.join("proof"), b"ok").is_ok();
    let child_denied = Command::new(bundled_child())
        .args(["--child", canary, &address.to_string()])
        .env_clear()
        .status()
        .is_ok_and(|status| status.success());
    for (name, value) in [
        ("REAL_HOME_DENIED", real_home_denied),
        ("LOOPBACK_DENIED", loopback_denied),
        ("FD_DENIED", fd_denied),
        ("ENV_DENIED", env_denied),
        ("FAKE_HOME_WRITE", fake_home_write),
        ("CHILD_DENIED", child_denied),
    ] {
        println!("{name}={}", u8::from(value));
    }
}

#[cfg(target_os = "macos")]
fn child() {
    let mut args = env::args().skip(2);
    let canary = args.next().unwrap();
    let address = args.next().unwrap().parse::<SocketAddr>().unwrap();
    let denied = fs::read(canary).is_err()
        && TcpStream::connect_timeout(&address, Duration::from_secs(1)).is_err();
    std::process::exit(i32::from(!denied));
}

#[cfg(target_os = "macos")]
fn detached() {
    let mut args = env::args().skip(2);
    let target = args.next().unwrap();
    let marker = args.next().unwrap();
    std::thread::sleep(Duration::from_secs(2));
    fs::write(
        marker,
        if fs::read(target).is_err() {
            b"DENIED"
        } else {
            b"LEAKED"
        },
    )
    .unwrap();
}

#[cfg(target_os = "macos")]
fn bundled_child() -> std::path::PathBuf {
    env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("Helpers/runtime/probe-child")
}

#[cfg(target_os = "macos")]
fn field<'a>(input: &'a str, name: &str) -> &'a str {
    field_optional(input, name).unwrap()
}

#[cfg(target_os = "macos")]
fn field_optional<'a>(input: &'a str, name: &str) -> Option<&'a str> {
    input.lines().find_map(|line| {
        line.strip_prefix(name)
            .and_then(|rest| rest.strip_prefix('='))
    })
}
