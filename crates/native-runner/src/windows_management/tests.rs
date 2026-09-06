use super::*;
use std::{fs, sync::Arc};

static SERIAL: Mutex<()> = Mutex::new(());
const CHILD_MODE: &str = "CONTEXT_RELAY_MANAGEMENT_CHILD_MODE";

struct Owner(Arc<AtomicBool>);
impl Drop for Owner {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

fn fixture(mode: &str) -> ProcessSpec {
    ProcessSpec {
        executable: std::env::current_exe().unwrap(),
        args: vec![
            "--exact".into(),
            "windows_management::tests::management_child_fixture".into(),
            "--nocapture".into(),
        ],
        directory: std::env::current_dir().unwrap(),
        environment: vec![(CHILD_MODE.into(), mode.into())],
    }
}

fn limits() -> Limits {
    Limits {
        runtime: Duration::from_secs(5),
        cleanup: Duration::from_secs(3),
        output: 64 * 1024,
    }
}

#[test]
fn management_child_fixture() {
    let Ok(mode) = std::env::var(CHILD_MODE) else {
        return;
    };
    match mode.as_str() {
        "echo" => {
            println!("Hermes fixture: 專案 🚀");
            eprintln!("diagnostic");
        }
        "empty-write" | "empty-then-flood" => {
            use windows_sys::Win32::{
                Storage::FileSystem::WriteFile,
                System::Console::{GetStdHandle, STD_OUTPUT_HANDLE},
            };
            thread::sleep(Duration::from_millis(60));
            let mut written = 0;
            assert_ne!(
                unsafe {
                    WriteFile(
                        GetStdHandle(STD_OUTPUT_HANDLE),
                        [0u8].as_ptr(),
                        0,
                        &mut written,
                        null_mut(),
                    )
                },
                0
            );
            thread::sleep(Duration::from_millis(60));
            if mode == "empty-write" {
                println!("after-empty-write");
            } else {
                use std::io::Write as _;
                let mut stdout = std::io::stdout().lock();
                loop {
                    stdout.write_all(&[b'x'; 4096]).unwrap();
                }
            }
        }
        "flood" => {
            use std::io::Write as _;
            let mut stdout = std::io::stdout().lock();
            loop {
                stdout.write_all(&[b'x'; 4096]).unwrap();
            }
        }
        "wait" => loop {
            thread::sleep(Duration::from_secs(1));
        },
        "parent-pipes" | "parent-closed-pipes" => {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap());
            child
                .args([
                    "--exact",
                    "windows_management::tests::management_child_fixture",
                    "--nocapture",
                ])
                .env_clear()
                .env(CHILD_MODE, "wait");
            if mode == "parent-closed-pipes" {
                child
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null());
            }
            let child = child.spawn().unwrap();
            println!("descendant={}", child.id());
            std::process::exit(0);
        }
        _ => panic!("unexpected fixture mode"),
    }
}

#[test]
fn management_captures_both_streams_and_returns_runtime_owner() {
    let _serial = SERIAL.lock().unwrap();
    let released = Arc::new(AtomicBool::new(false));
    let (output, owner) = run_process(
        fixture("echo"),
        Owner(released.clone()),
        &AtomicBool::new(false),
        limits(),
        Faults::default(),
    )
    .unwrap();
    assert_eq!(output.exit_code, 0);
    assert!(String::from_utf8_lossy(&output.stdout).contains("專案 🚀"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("diagnostic"));
    assert!(!released.load(Ordering::SeqCst));
    drop(owner);
    assert!(released.load(Ordering::SeqCst));
}

#[test]
fn management_bounds_flood_timeout_and_cancellation() {
    let _serial = SERIAL.lock().unwrap();
    for (mode, expected) in [
        ("flood", ManagementError::OutputLimit),
        ("wait", ManagementError::Timeout),
    ] {
        let released = Arc::new(AtomicBool::new(false));
        let mut bound = limits();
        if mode == "wait" {
            bound.runtime = Duration::from_millis(250);
        }
        let started = Instant::now();
        let result = run_process(
            fixture(mode),
            Owner(released.clone()),
            &AtomicBool::new(false),
            bound,
            Faults::default(),
        );
        assert_eq!(result.err(), Some(expected));
        assert!(released.load(Ordering::SeqCst));
        assert!(started.elapsed() < Duration::from_secs(9));
    }
    let cancelled = Arc::new(AtomicBool::new(false));
    let signal = cancelled.clone();
    let thread = thread::spawn(move || {
        thread::sleep(Duration::from_millis(100));
        signal.store(true, Ordering::SeqCst);
    });
    let released = Arc::new(AtomicBool::new(false));
    let result = run_process(
        fixture("wait"),
        Owner(released.clone()),
        &cancelled,
        limits(),
        Faults::default(),
    );
    thread.join().unwrap();
    assert_eq!(result.err(), Some(ManagementError::Cancelled));
    assert!(released.load(Ordering::SeqCst));
}

#[test]
fn management_stops_descendants_with_open_or_closed_pipes() {
    let _serial = SERIAL.lock().unwrap();
    for mode in ["parent-pipes", "parent-closed-pipes"] {
        let (output, ()) = run_process(
            fixture(mode),
            (),
            &AtomicBool::new(false),
            limits(),
            Faults::default(),
        )
        .unwrap();
        let text = String::from_utf8_lossy(&output.stdout);
        let pid: u32 = text
            .lines()
            .find_map(|line| line.strip_prefix("descendant="))
            .expect("child PID")
            .parse()
            .unwrap();
        let process = unsafe {
            windows_sys::Win32::System::Threading::OpenProcess(
                windows_sys::Win32::System::Threading::PROCESS_SYNCHRONIZE,
                0,
                pid,
            )
        };
        if let Ok(process) = owned(process) {
            assert_eq!(
                unsafe { WaitForSingleObject(raw(&process), 0) },
                WAIT_OBJECT_0
            );
        }
    }
}

#[test]
fn management_launch_failures_and_uncertain_cleanup_preserve_ownership() {
    let _serial = SERIAL.lock().unwrap();
    for faults in [
        Faults {
            assignment: true,
            ..Faults::default()
        },
        Faults {
            resume: true,
            ..Faults::default()
        },
    ] {
        let released = Arc::new(AtomicBool::new(false));
        let result = run_process(
            fixture("wait"),
            Owner(released.clone()),
            &AtomicBool::new(false),
            limits(),
            faults,
        );
        assert_eq!(result.err(), Some(ManagementError::Launch));
        assert!(released.load(Ordering::SeqCst));
    }
    let released = Arc::new(AtomicBool::new(false));
    let mut bound = limits();
    bound.runtime = Duration::from_millis(100);
    bound.cleanup = Duration::from_millis(100);
    let result = run_process(
        fixture("wait"),
        Owner(released.clone()),
        &AtomicBool::new(false),
        bound,
        Faults {
            cleanup: true,
            ..Faults::default()
        },
    );
    assert_eq!(result.err(), Some(ManagementError::CleanupPending));
    assert!(!released.load(Ordering::SeqCst));
    let mut slot = PROCESS.lock().unwrap();
    slot.as_mut().unwrap().faults.cleanup = false;
    assert!(slot.as_mut().unwrap().cleanup(false, limits()).is_ok());
    slot.take();
    assert!(released.load(Ordering::SeqCst));
}

#[test]
fn settings_readback_returns_owner_only_after_descendants_stop() {
    use std::os::windows::process::CommandExt as _;
    let _serial = SERIAL.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    fs::create_dir(root.join("python")).unwrap();
    let source = root.join("readback_fixture.rs");
    fs::write(
        &source,
        r#"
use std::{env, process::{Command, Stdio}, thread, time::Duration};
fn main() {
    let args = env::args().collect::<Vec<_>>();
    if args.get(1).is_some_and(|v| v == "--child") {
        loop { thread::sleep(Duration::from_secs(1)); }
    }
    assert_eq!(&args[1..5], ["-I", "-S", "-B", "-c"]);
    assert!(args[5].contains("load_config_readonly"));
    let child = Command::new(env::current_exe().unwrap()).arg("--child")
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    println!("{}", child.id());
}
"#,
    )
    .unwrap();
    let compilation = std::process::Command::new("rustc")
        .args(["--edition=2024", "--crate-name", "readback_fixture"])
        .arg(source)
        .arg("-o")
        .arg(root.join("python/python.exe"))
        .creation_flags(0x0800_0000)
        .output()
        .unwrap();
    assert!(
        compilation.status.success(),
        "{}",
        String::from_utf8_lossy(&compilation.stderr)
    );
    let released = Arc::new(AtomicBool::new(false));
    let (output, owner) = read_hermes_settings_for_qualification(
        &root,
        &root,
        Owner(released.clone()),
        &AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(output.exit_code, 0);
    assert!(!released.load(Ordering::SeqCst));
    let pid = String::from_utf8(output.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let process = unsafe {
        windows_sys::Win32::System::Threading::OpenProcess(
            windows_sys::Win32::System::Threading::PROCESS_SYNCHRONIZE,
            0,
            pid,
        )
    };
    if let Ok(process) = owned(process) {
        assert_eq!(
            unsafe { WaitForSingleObject(raw(&process), 0) },
            WAIT_OBJECT_0
        );
    }
    drop(owner);
    assert!(released.load(Ordering::SeqCst));
}

#[test]
fn management_retains_real_file_locks_until_cleanup_can_be_proved() {
    let _serial = SERIAL.lock().unwrap();
    let mut random = [0u8; 16];
    OsRng.try_fill_bytes(&mut random).unwrap();
    let suffix = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let root = std::env::temp_dir().join(format!("context-relay-management-lease-{suffix}"));
    fs::create_dir(&root).unwrap();
    let runtime = root.join("runtime");
    let pin = crate::OsNativeFileSystem::new()
        .create_private_directory(&runtime)
        .unwrap();
    let path = runtime.join("module.py");
    fs::write(&path, b"approved").unwrap();
    let (lease, _, _) = pin
        .lock_regular_file(&crate::StagePath::try_from("module.py").unwrap(), 100)
        .unwrap();
    let mut bound = limits();
    bound.runtime = Duration::from_millis(100);
    bound.cleanup = Duration::from_millis(50);
    let result = run_process(
        fixture("wait"),
        (lease, pin),
        &AtomicBool::new(false),
        bound,
        Faults {
            cleanup: true,
            ..Faults::default()
        },
    );
    assert_eq!(result.err(), Some(ManagementError::CleanupPending));
    assert!(fs::write(&path, b"changed").is_err());
    assert!(fs::remove_file(&path).is_err());
    assert!(fs::rename(&runtime, root.join("moved")).is_err());
    // A second request must not run past an unproved cleanup state.
    assert_eq!(
        run_process(
            fixture("echo"),
            (),
            &AtomicBool::new(false),
            bound,
            Faults::default()
        )
        .err(),
        Some(ManagementError::CleanupPending)
    );
    PROCESS.lock().unwrap().as_mut().unwrap().faults.cleanup = false;
    let (output, ()) = run_process(
        fixture("echo"),
        (),
        &AtomicBool::new(false),
        limits(),
        Faults::default(),
    )
    .unwrap();
    assert_eq!(output.exit_code, 0);
    fs::write(&path, b"released").unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn management_reports_output_limit_reached_during_final_drain() {
    let _serial = SERIAL.lock().unwrap();
    // The child can exit after writing more than one output read but before
    // collect sees the process exit. Cleanup must preserve any output error.
    let mut bound = limits();
    bound.output = 8;
    let result = run_process(
        fixture("echo"),
        (),
        &AtomicBool::new(false),
        bound,
        Faults {
            defer_output: true,
            ..Faults::default()
        },
    );
    assert_eq!(result.err(), Some(ManagementError::OutputLimit));
}

#[test]
fn management_unwind_keeps_the_owner_until_a_later_reap() {
    let _serial = SERIAL.lock().unwrap();
    let released = Arc::new(AtomicBool::new(false));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_process(
            fixture("wait"),
            Owner(released.clone()),
            &AtomicBool::new(false),
            limits(),
            Faults {
                unwind: true,
                ..Faults::default()
            },
        )
    }));
    assert!(result.is_err());
    assert!(PROCESS.is_poisoned());
    assert!(!released.load(Ordering::SeqCst));
    let (output, ()) = run_process(
        fixture("echo"),
        (),
        &AtomicBool::new(false),
        limits(),
        Faults::default(),
    )
    .unwrap();
    assert_eq!(output.exit_code, 0);
    assert!(!PROCESS.is_poisoned());
    assert!(released.load(Ordering::SeqCst));
}

#[test]
fn management_keeps_reading_after_a_zero_byte_pipe_write() {
    let _serial = SERIAL.lock().unwrap();
    let (output, ()) = run_process(
        fixture("empty-write"),
        (),
        &AtomicBool::new(false),
        limits(),
        Faults::default(),
    )
    .unwrap();
    assert!(String::from_utf8_lossy(&output.stdout).contains("after-empty-write"));
    assert_eq!(
        run_process(
            fixture("empty-then-flood"),
            (),
            &AtomicBool::new(false),
            limits(),
            Faults::default()
        )
        .err(),
        Some(ManagementError::OutputLimit)
    );
}

#[test]
fn management_zero_byte_completion_keeps_pipe_open_and_cap_active() {
    let (mut pipe, _writer) = OutputPipe::new().unwrap();
    pipe.complete_read(0, 3, true).unwrap();
    assert!(!pipe.finished);
    pipe.buffer[..3].copy_from_slice(b"end");
    pipe.complete_read(3, 3, true).unwrap();
    assert_eq!(pipe.output, b"end");
    assert_eq!(
        pipe.complete_read(1, 3, true),
        Err(ManagementError::OutputLimit)
    );
}
