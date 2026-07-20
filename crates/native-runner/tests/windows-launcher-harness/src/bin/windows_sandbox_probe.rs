#![cfg(windows)]

use std::{
    env,
    ffi::OsString,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    os::windows::ffi::OsStringExt,
    path::PathBuf,
    time::Duration,
};
use windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW;

fn main() {
    assert_restricted_environment();
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(b"READY\n").unwrap();
    stdout.flush().unwrap();

    let mut request = String::new();
    std::io::stdin().read_to_string(&mut request).unwrap();
    let mut lines = request.lines();
    if lines.next() == Some("RUNTIME-SEAL") {
        assert_eq!(lines.next(), None);
        let runtime = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .join("runtime");
        let nested = runtime.join("nested");
        assert!(
            std::fs::OpenOptions::new()
                .write(true)
                .open(nested.join("pinned.dll"))
                .is_err()
        );
        assert!(
            std::fs::OpenOptions::new()
                .write(true)
                .open(nested.join("inherited.dll"))
                .is_err()
        );
        assert!(
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(runtime.join("root-attacker.dll"))
                .is_err()
        );
        assert!(
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(nested.join("attacker.dll"))
                .is_err()
        );
        writeln!(stdout, "RUNTIME-SEALED").unwrap();
        return;
    }
    let mut lines = request.lines();
    let denied_path = lines.next().unwrap().strip_prefix("DENY=").unwrap();
    let address: SocketAddr = lines
        .next()
        .unwrap()
        .strip_prefix("CONNECT=")
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(lines.next(), Some("PING"));
    assert_eq!(lines.next(), None);
    assert!(std::fs::read(denied_path).is_err());
    assert!(TcpStream::connect_timeout(&address, Duration::from_millis(500)).is_err());

    writeln!(stdout, "INPUT-OK").unwrap();
    writeln!(std::io::stderr().lock(), "PROBE-ERR").unwrap();
}

fn assert_restricted_environment() {
    const EXPECTED_KEYS: [&str; 14] = [
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
    let mut keys: Vec<_> = env::vars_os()
        .map(|(key, _)| key.to_string_lossy().into_owned())
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, EXPECTED_KEYS);

    let home = PathBuf::from(env::var_os("HOME").unwrap());
    let stage = home.parent().unwrap();
    assert_eq!(home, stage.join("home"));
    assert_eq!(env::var_os("USERPROFILE").unwrap(), home);
    assert_eq!(env::var_os("APPDATA").unwrap(), stage.join("data"));
    let local_app_data = PathBuf::from(env::var_os("LOCALAPPDATA").unwrap());
    assert!(local_app_data.starts_with(stage.join("data")));
    assert!(local_app_data.is_dir());
    assert_eq!(
        env::var_os("XDG_CONFIG_HOME").unwrap(),
        stage.join("config")
    );
    assert_eq!(env::var_os("XDG_DATA_HOME").unwrap(), stage.join("data"));
    assert_eq!(env::var_os("XDG_CACHE_HOME").unwrap(), stage.join("cache"));
    let effective_temp = local_app_data.join("Temp");
    assert_eq!(env::var_os("TEMP").unwrap(), effective_temp);
    assert_eq!(env::var_os("TMP").unwrap(), effective_temp);
    assert!(effective_temp.is_dir());
    assert_eq!(env::var_os("TMPDIR").unwrap(), stage.join("temp"));
    assert_eq!(env::var_os("PATH").unwrap(), stage.join("runtime"));
    assert_eq!(env::var("LANG").unwrap(), "C.UTF-8");
    assert_eq!(env::var("LC_ALL").unwrap(), "C.UTF-8");
    let mut buffer = vec![0_u16; 32_768];
    let length = unsafe { GetWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    assert!(length > 0 && (length as usize) < buffer.len());
    buffer.truncate(length as usize);
    assert_eq!(
        env::var_os("SYSTEMROOT"),
        Some(OsString::from_wide(&buffer))
    );
}
