#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{CStr, CString},
    fs,
    io::Write,
    net::TcpListener,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{PermissionsExt, symlink},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use context_relay_native_runner::macos::{
    GenerationId, GenerationJournal, GenerationState, MacOsSandboxLauncher, MacPolicyError,
    MacRecoveryCleanup, MacRecoveryIdentity, MacRecoveryOutcome, MacRootIdentity, SignedGeneration,
    cleanup_recovered_generation,
};
use context_relay_native_runner::{
    ContentFrame, FailureCode, RuleSyncFeature, RuleSyncFeatures, RuleSyncTarget, RunDisposition,
    RunRequest, RunResponse, RuntimeTarget, SandboxLauncher, SidecarCommand, SidecarId, StagePath,
    parse_sidecar_manifest, verify_closure,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const REQUEST_NONCE: [u8; 16] = [0x42; 16];
const REAL_HOME_CANARY: &str = ".context-relay-macos-adapter-canary";
const OUTSIDE_CLOSURE_CANARY: &str = ".context-relay-outside-closure-canary";
const REAL_SIDECAR_MANIFEST_ROOT: &str = "CONTEXT_RELAY_REAL_SIDECAR_MANIFEST_ROOT";
const CI_CANDIDATE_DOCUMENT: &str = "CONTEXT_RELAY_CI_CANDIDATE_DOCUMENT";
const EXPECTED_PROOF: &[u8] =
    b"ARGV_EXACT=1\nENV_EXACT=1\nFAKE_HOME_WRITE=1\nREAL_HOME_DENIED=1\nLOOPBACK_DENIED=1\nCLOSURE_DENIED=1\n";
static NATIVE_TEST_LOCK: Mutex<()> = Mutex::new(());

fn native_test_lock() -> std::sync::MutexGuard<'static, ()> {
    NATIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn unwrap_run(
    result: Result<RunResponse, context_relay_native_runner::RunnerError>,
    journal: &TestJournal,
) -> RunResponse {
    result.unwrap_or_else(|error| panic!("{error:?}; lifecycle={:?}", journal.events()))
}

fn set_immutable(path: &Path, symlink: bool) {
    let encoded = CString::new(path.as_os_str().as_bytes()).unwrap();
    let flags = libc::O_RDONLY
        | libc::O_CLOEXEC
        | if symlink {
            libc::O_SYMLINK
        } else {
            libc::O_NOFOLLOW
        };
    let descriptor = unsafe { libc::open(encoded.as_ptr(), flags) };
    assert!(descriptor >= 0, "failed to open {}", path.display());
    let file = unsafe { fs::File::from_raw_fd(descriptor) };
    assert_eq!(
        unsafe { libc::fchflags(file.as_raw_fd(), libc::UF_IMMUTABLE) },
        0
    );
}

fn clear_immutable_tree(path: &Path) {
    let _ = Command::new("/usr/bin/chflags")
        .args(["-R", "nouchg"])
        .arg(path)
        .status();
    let _ = Command::new("/bin/chmod")
        .args(["-R", "u+rwx"])
        .arg(path)
        .status();
}

fn root_identity(path: &Path) -> MacRootIdentity {
    let file = fs::File::open(path).unwrap();
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    assert_eq!(
        unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) },
        0
    );
    let stat = unsafe { stat.assume_init() };
    MacRootIdentity::new(
        stat.st_dev as u64,
        stat.st_ino,
        stat.st_gen,
        stat.st_birthtime,
        u32::try_from(stat.st_birthtime_nsec).unwrap(),
        u32::from(stat.st_mode),
    )
    .unwrap()
}

#[test]
fn production_adapter_runs_one_bound_response_in_a_single_use_container() {
    let _serial = native_test_lock();
    let fixture = Fixture::new(Helper::Production);
    let journal = TestJournal::default();
    let launcher = fixture.launcher(journal.clone());

    let response = unwrap_run(
        launcher.run(&fixture.closure, &fixture.request("SUCCESS")),
        &journal,
    );
    let RunResponse::Completed {
        disposition,
        outputs,
        ..
    } = &response
    else {
        panic!("production helper did not return its uniquely bound response: {response:?}");
    };
    assert_eq!(*disposition, RunDisposition::Generated);
    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0].path().as_str(), "output/.claude/rules/probe.md");
    assert_eq!(outputs[0].bytes(), EXPECTED_PROOF);
    assert!(matches!(
        fixture.listener.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
    assert_eq!(
        journal.events(),
        [
            GenerationState::Prepared,
            GenerationState::Active,
            GenerationState::Retired,
        ]
    );
    assert_generation_cleaned(&fixture.private_root, &journal);
}

#[test]
fn recovered_generation_cleanup_clears_immutable_app_and_container_trees() {
    let _serial = native_test_lock();
    let parent = case_sensitive_apfs_root();
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = parent.join(format!(
        "macos-immutable-cleanup-{}-{suffix}",
        std::process::id()
    ));
    let private_root = root.join("private");
    fs::create_dir_all(&private_root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&private_root, fs::Permissions::from_mode(0o700)).unwrap();

    let id = GenerationId::from_nonce(suffix.to_le_bytes());
    let generation_id = id.as_str().rsplit_once('.').unwrap().1;
    let app = private_root.join(format!("{}.app", id.as_str()));
    let container = account_home().join("Library/Containers").join(id.as_str());
    let outside = root.join("outside-canary");
    fs::write(&outside, b"outside\n").unwrap();

    for tree in [&app, &container] {
        let nested = tree.join("nested");
        let file = nested.join("payload");
        let link = nested.join("outside-link");
        fs::create_dir_all(&nested).unwrap();
        fs::write(&file, b"payload\n").unwrap();
        symlink(&outside, &link).unwrap();
        set_immutable(&file, false);
        set_immutable(&link, true);
        set_immutable(&nested, false);
        set_immutable(tree, false);
    }
    let bundle_identity = root_identity(&app);
    let container_identity = root_identity(&container);

    let result = cleanup_recovered_generation(
        &private_root,
        &MacRecoveryIdentity::new(
            generation_id,
            id.as_str(),
            Some(i32::MAX),
            Some(&bundle_identity),
            Some(&container_identity),
        ),
        GenerationState::Poisoned,
        MacRecoveryOutcome::Conflict,
    );
    if result.is_err() {
        clear_immutable_tree(&app);
        clear_immutable_tree(&container);
        let _ = fs::remove_dir_all(&app);
        let _ = fs::remove_dir_all(&container);
    }
    assert_eq!(result, Ok(MacRecoveryCleanup::Cleaned));
    assert!(!app.exists());
    assert!(!container.exists());
    assert_eq!(fs::read(&outside).unwrap(), b"outside\n");
    cleanup_recovered_generation(
        &private_root,
        &MacRecoveryIdentity::new(
            generation_id,
            id.as_str(),
            Some(i32::MAX),
            Some(&bundle_identity),
            Some(&container_identity),
        ),
        GenerationState::Poisoned,
        MacRecoveryOutcome::Conflict,
    )
    .unwrap();

    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn valid_response_kills_closed_stdio_descendant_before_retiring() {
    let _serial = native_test_lock();
    let fixture = Fixture::new(Helper::ProtocolFault);
    let journal = TestJournal::default();
    let launcher = fixture.launcher(journal.clone());

    let RunResponse::Completed { outputs, .. } = unwrap_run(
        launcher.run(&fixture.closure, &fixture.request("GUARDIAN_GROUP_CHILD")),
        &journal,
    ) else {
        panic!("fixture did not return its valid response");
    };
    assert_eq!(outputs.len(), 1);
    let identity = std::str::from_utf8(outputs[0].bytes()).unwrap();
    let pid = parse_fixture_process(identity, "CHILD_PID=");
    let pgid = parse_fixture_process(identity, "CHILD_PGID=");
    assert_eq!(
        journal.events(),
        [
            GenerationState::Prepared,
            GenerationState::Active,
            GenerationState::Retired,
        ]
    );
    assert_group_gone(pid, pgid, "valid response");
    assert_generation_cleaned(&fixture.private_root, &journal);
}

#[test]
fn production_sidecar_cannot_fork_or_posix_spawn_descendants() {
    let _serial = native_test_lock();
    let fixture = Fixture::new(Helper::Production);
    let journal = TestJournal::default();
    let launcher = fixture.launcher(journal.clone());

    let response = unwrap_run(
        launcher.run(
            &fixture.closure,
            &fixture.request("PROCESS_CREATION_DENIED"),
        ),
        &journal,
    );
    let RunResponse::Completed { outputs, .. } = &response else {
        panic!("process-creation probe did not return a valid response: {response:?}");
    };
    let proof = std::str::from_utf8(outputs[0].bytes()).unwrap();
    assert!(proof.starts_with(std::str::from_utf8(EXPECTED_PROOF).unwrap()));
    assert!(proof.contains("FORK_DENIED=1\n"));
    assert!(proof.contains("POSIX_SPAWN_DENIED=1\n"));
    assert_eq!(parse_fixture_process(proof, "FORK_CHILD_PID="), 0);
    assert_eq!(parse_fixture_process(proof, "POSIX_SPAWN_CHILD_PID="), 0);
    let sidecar_pid = parse_fixture_process(proof, "SIDECAR_PID=");
    assert!(!process_exists(sidecar_pid));
    assert_generation_cleaned(&fixture.private_root, &journal);
}

#[test]
fn production_adapter_poisoned_unbound_trailing_or_stderr_helper_output() {
    let _serial = native_test_lock();
    for mode in ["WRONG_BINDING", "TRAILING", "STDERR"] {
        let fixture = Fixture::new(Helper::ProtocolFault);
        let journal = TestJournal::default();
        let launcher = fixture.launcher(journal.clone());

        assert_eq!(
            unwrap_run(
                launcher.run(&fixture.closure, &fixture.request(mode)),
                &journal,
            ),
            RunResponse::failed(FailureCode::ToolFailed),
            "mode {mode}"
        );
        assert_generation_cleaned(&fixture.private_root, &journal);
        assert_eq!(
            journal.events(),
            [
                GenerationState::Prepared,
                GenerationState::Active,
                GenerationState::Poisoned,
            ],
            "mode {mode}"
        );
    }
}

#[test]
fn production_adapter_poisoned_malformed_bound_helper_frame() {
    let _serial = native_test_lock();
    let fixture = Fixture::new(Helper::ProtocolFault);
    let journal = TestJournal::default();
    let launcher = fixture.launcher(journal.clone());

    assert_eq!(
        unwrap_run(
            launcher.run(&fixture.closure, &fixture.request("MALFORMED")),
            &journal,
        ),
        RunResponse::failed(FailureCode::ToolFailed)
    );
    assert_eq!(
        journal.events(),
        [
            GenerationState::Prepared,
            GenerationState::Active,
            GenerationState::Poisoned,
        ]
    );
    assert_generation_cleaned(&fixture.private_root, &journal);
}

#[test]
fn production_helper_exact_kills_a_sidecar_that_escapes_the_original_group() {
    let _serial = native_test_lock();
    let fixture = Fixture::new(Helper::Production);
    let journal = TestJournal::default();
    let launcher = fixture.launcher(journal.clone());
    let started = Instant::now();

    let request = fixture.request("ESCAPE_HANG");
    let (response, pid, pgid) = std::thread::scope(|scope| {
        let closure = &fixture.closure;
        let run = scope.spawn(move || launcher.run(closure, &request).unwrap());
        let deadline = Instant::now() + Duration::from_secs(10);
        let (pid, pgid) = loop {
            if let Some(identity) = recorded_group(&journal) {
                break identity;
            }
            if run.is_finished() {
                let response = run.join().unwrap();
                panic!("fixture exited before recording its child process group: {response:?}");
            }
            assert!(
                Instant::now() < deadline,
                "fixture did not record its child process group"
            );
            std::thread::sleep(Duration::from_millis(5));
        };
        (run.join().unwrap(), pid, pgid)
    });
    assert_eq!(response, RunResponse::failed(FailureCode::TimedOut));
    assert!(started.elapsed() >= Duration::from_secs(29));
    assert!(started.elapsed() < Duration::from_secs(40));
    assert_eq!(
        journal.events(),
        [
            GenerationState::Prepared,
            GenerationState::Active,
            GenerationState::Poisoned,
        ]
    );

    assert_group_gone(pid, pgid, "timeout");
    assert_generation_cleaned(&fixture.private_root, &journal);
}

#[test]
#[ignore = "requires exact hydrated sidecars and native arm64 App Sandbox"]
fn real_sidecar_rulesync_generates_only_the_validated_output() {
    let _serial = native_test_lock();
    let fixture = RealFixture::new(SidecarId::RuleSync);
    let request = fixture.request(
        [0x51; 16],
        SidecarCommand::RuleSyncGenerate {
            target: RuleSyncTarget::ClaudeCode,
            features: RuleSyncFeatures::new(&[RuleSyncFeature::Rules]).unwrap(),
        },
        vec![frame(
            "input/.rulesync/rules/overview.md",
            b"---\nroot: true\n---\n\n# Shared instructions\n\nKeep changes minimal.\n",
        )],
    );

    let response = fixture.run(&request);
    let RunResponse::Completed {
        disposition,
        outputs,
        ..
    } = response
    else {
        panic!("real RuleSync did not return a completed response: {response:?}");
    };
    assert_eq!(disposition, RunDisposition::Generated);
    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0].path().as_str(), "output/CLAUDE.md");
    assert!(!outputs[0].bytes().is_empty());
    assert!(std::str::from_utf8(outputs[0].bytes()).is_ok());
    fixture.assert_complete_lifecycles(1);
}

#[test]
#[ignore = "requires exact hydrated sidecars and native arm64 App Sandbox"]
fn real_sidecar_rulesync_rejects_malformed_frontmatter_and_cleans_up() {
    let _serial = native_test_lock();
    let fixture = RealFixture::new(SidecarId::RuleSync);
    let request = fixture.request(
        [0x52; 16],
        SidecarCommand::RuleSyncGenerate {
            target: RuleSyncTarget::ClaudeCode,
            features: RuleSyncFeatures::new(&[RuleSyncFeature::Rules]).unwrap(),
        },
        vec![frame(
            "input/.rulesync/rules/overview.md",
            b"---\nroot: [\n---\n\n# Invalid instructions\n",
        )],
    );

    assert_eq!(
        fixture.run(&request),
        RunResponse::Failed(FailureCode::InvalidOutput)
    );
    fixture.assert_complete_lifecycles(1);
}

#[test]
#[ignore = "requires exact hydrated sidecars and native arm64 App Sandbox"]
fn real_sidecar_gitleaks_clean_and_finding_ignore_attacker_gitleaksignore() {
    let _serial = native_test_lock();
    let fixture = RealFixture::new(SidecarId::Gitleaks);
    let clean = fixture.request(
        [0x61; 16],
        SidecarCommand::GitleaksScanPackage,
        vec![frame(
            "input/gitleaks-scan/payload/main.rs",
            b"fn main() {}\n",
        )],
    );
    let clean_response = fixture.run(&clean);
    let RunResponse::Completed {
        disposition,
        outputs,
        ..
    } = clean_response
    else {
        panic!("real Gitleaks clean scan did not complete: {clean_response:?}");
    };
    assert_eq!(disposition, RunDisposition::Clean);
    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0].path().as_str(), "reports/gitleaks.json");
    assert_eq!(outputs[0].bytes(), b"[]");

    let finding = fixture.request(
        [0x62; 16],
        SidecarCommand::GitleaksScanPackage,
        vec![
            frame(
                "input/gitleaks-scan/payload/.gitleaksignore",
                b"payload/secret.txt:aws-access-token:1\n",
            ),
            frame(
                "input/gitleaks-scan/payload/secret.txt",
                b"credential = AKIAQWERTYUIOPASDFGH\n",
            ),
        ],
    );
    let finding_response = fixture.run(&finding);
    let RunResponse::Completed {
        disposition,
        outputs,
        ..
    } = finding_response
    else {
        panic!("real Gitleaks findings scan did not complete: {finding_response:?}");
    };
    assert_eq!(disposition, RunDisposition::Findings(1));
    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0].path().as_str(), "reports/gitleaks.json");
    let report: Value = serde_json::from_slice(outputs[0].bytes()).unwrap();
    let findings = report.as_array().unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["RuleID"], "aws-access-token");
    assert_eq!(findings[0]["File"], "payload/secret.txt");
    assert!(findings[0].get("Secret").is_none());
    assert!(findings[0].get("Match").is_none());
    fixture.assert_complete_lifecycles(2);
}

#[test]
#[ignore = "requires exact hydrated sidecars and native arm64 App Sandbox"]
fn real_sidecar_semgrep_clean_and_finding_use_the_closed_policy() {
    let _serial = native_test_lock();
    let fixture = RealFixture::new(SidecarId::Osemgrep);
    let clean = fixture.request(
        [0x71; 16],
        SidecarCommand::OsemgrepScanPackage,
        vec![frame(
            "input/semgrep-target/runtime-inventory.txt",
            b"osemgrep\n",
        )],
    );
    let clean_response = fixture.run(&clean);
    let RunResponse::Completed {
        disposition,
        outputs,
        ..
    } = clean_response
    else {
        panic!(
            "real Semgrep clean scan did not complete: {clean_response:?}; direct diagnostic: {}",
            fixture.diagnose_semgrep(b"osemgrep\n")
        );
    };
    assert_eq!(disposition, RunDisposition::Clean);
    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0].path().as_str(), "reports/semgrep.json");

    let finding = fixture.request(
        [0x72; 16],
        SidecarCommand::OsemgrepScanPackage,
        vec![frame(
            "input/semgrep-target/runtime-inventory.txt",
            b"python.exe\n",
        )],
    );
    let finding_response = fixture.run(&finding);
    let RunResponse::Completed {
        disposition,
        outputs,
        ..
    } = finding_response
    else {
        panic!(
            "real Semgrep finding scan did not complete: {finding_response:?}; direct diagnostic: {}",
            fixture.diagnose_semgrep(b"python.exe\n")
        );
    };
    assert_eq!(disposition, RunDisposition::Findings(1));
    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0].path().as_str(), "reports/semgrep.json");
    fixture.assert_complete_lifecycles(2);
}

#[derive(Clone, Copy)]
enum Helper {
    Production,
    ProtocolFault,
}

struct RealFixture {
    root: PathBuf,
    private_root: PathBuf,
    helper: PathBuf,
    closure: context_relay_native_runner::VerifiedClosure,
    journal: TestJournal,
}

impl RealFixture {
    fn new(sidecar: SidecarId) -> Self {
        assert_eq!(architecture(), "arm64");
        let parent = case_sensitive_apfs_root();
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = parent.join(format!(
            "macos-real-sidecar-{}-{suffix}",
            std::process::id()
        ));
        let private_root = root.join("private");
        fs::create_dir_all(&private_root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&private_root, fs::Permissions::from_mode(0o700)).unwrap();
        let workspace = workspace_root();
        let manifest_workspace = real_manifest_workspace(&workspace)
            .unwrap_or_else(|error| panic!("{REAL_SIDECAR_MANIFEST_ROOT}: {error}"));
        let hydrated = std::env::var_os("CONTEXT_RELAY_REAL_SIDECAR_ROOT")
            .map(PathBuf::from)
            .expect("CONTEXT_RELAY_REAL_SIDECAR_ROOT must name the verified hydration root");
        assert!(hydrated.is_absolute(), "hydration root must be absolute");
        assert_eq!(
            fs::canonicalize(&hydrated).unwrap(),
            hydrated,
            "hydration root must be canonical"
        );
        let manifest = parse_sidecar_manifest(
            &fs::read(manifest_workspace.join("third_party/sidecars/manifest.v1.json")).unwrap(),
        )
        .unwrap();
        let closure = verify_real_sidecar_closure(
            &manifest,
            &manifest_workspace,
            &hydrated.join(sidecar.stable_name()),
            RuntimeTarget::MacosArm64,
            sidecar,
        );
        assert_eq!(
            closure.version(),
            match sidecar {
                SidecarId::RuleSync => "14.0.1",
                SidecarId::Gitleaks => "8.30.1",
                SidecarId::Osemgrep => "1.170.0",
            }
        );

        let helper = root.join("context-relay-native-helper");
        fs::copy(env!("CARGO_BIN_EXE_context-relay-native-helper"), &helper).unwrap();
        sign_helper(&helper);
        Self {
            root,
            private_root,
            helper,
            closure,
            journal: TestJournal::default(),
        }
    }

    fn request(
        &self,
        nonce: [u8; 16],
        command: SidecarCommand,
        inputs: Vec<ContentFrame>,
    ) -> RunRequest {
        RunRequest::new(nonce, *self.closure.closure_sha256(), command, inputs).unwrap()
    }

    fn run(&self, request: &RunRequest) -> RunResponse {
        let launcher = MacOsSandboxLauncher::new(
            self.private_root.clone(),
            self.helper.clone(),
            digest(&self.helper),
            self.journal.clone(),
        )
        .unwrap();
        launcher
            .run(&self.closure, request)
            .unwrap_or_else(|error| panic!("{error:?}; lifecycle={:?}", self.journal.events()))
    }

    fn diagnose_semgrep(&self, input: &[u8]) -> String {
        assert_eq!(self.closure.sidecar(), SidecarId::Osemgrep);
        let root = self.root.join("semgrep-direct-diagnostic");
        let config = root.join("config/semgrep/package.yml");
        let target = root.join("input/semgrep-target/runtime-inventory.txt");
        fs::create_dir_all(config.parent().unwrap()).unwrap();
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::copy(
            workspace_root().join("third_party/sidecars/policies/semgrep-package.yml"),
            &config,
        )
        .unwrap();
        fs::write(&target, input).unwrap();
        for directory in ["home", "data", "cache", "temp", "runtime"] {
            fs::create_dir_all(root.join(directory)).unwrap();
        }
        let executable = self
            .closure
            .root()
            .join(self.closure.executable().path().as_str());
        let argv = SidecarCommand::OsemgrepScanPackage.argv();
        let mut command = Command::new(executable);
        command
            .args(argv.iter().skip(1))
            .current_dir(&root)
            .env_clear()
            .env("HOME", root.join("home"))
            .env("USERPROFILE", root.join("home"))
            .env("APPDATA", root.join("data"))
            .env("LOCALAPPDATA", root.join("data"))
            .env("XDG_CONFIG_HOME", root.join("config"))
            .env("XDG_DATA_HOME", root.join("data"))
            .env("XDG_CACHE_HOME", root.join("cache"))
            .env("TMP", root.join("temp"))
            .env("TEMP", root.join("temp"))
            .env("TMPDIR", root.join("temp"))
            .env("PATH", root.join("runtime"))
            .env("LANG", "C.UTF-8")
            .env("LC_ALL", "C.UTF-8");
        unsafe {
            command.pre_exec(|| {
                let no_children = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::setrlimit(libc::RLIMIT_NPROC, &no_children) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let output = command.output().unwrap();
        format!(
            "status={:?}, stdout={}, stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    }

    fn assert_complete_lifecycles(&self, count: usize) {
        let events = self.journal.events();
        assert_eq!(events.len(), count * 3);
        for lifecycle in events.chunks_exact(3) {
            assert_eq!(
                lifecycle,
                [
                    GenerationState::Prepared,
                    GenerationState::Active,
                    GenerationState::Retired,
                ]
            );
        }
    }
}

fn verify_real_sidecar_closure(
    manifest: &context_relay_native_runner::SidecarManifest,
    workspace: &Path,
    hydrated: &Path,
    target: RuntimeTarget,
    sidecar: SidecarId,
) -> context_relay_native_runner::VerifiedClosure {
    if sidecar == SidecarId::Osemgrep
        && let Some(document_path) = std::env::var_os(CI_CANDIDATE_DOCUMENT)
    {
        #[cfg(feature = "ci-candidate-sidecar-smoke")]
        {
            return context_relay_native_runner::verify_ci_candidate_closure(
                &fs::read(PathBuf::from(document_path)).unwrap(),
                manifest,
                workspace,
                hydrated,
                target,
                sidecar,
            )
            .unwrap();
        }
        #[cfg(not(feature = "ci-candidate-sidecar-smoke"))]
        {
            drop(document_path);
            panic!("{CI_CANDIDATE_DOCUMENT} requires the explicit CI candidate test feature");
        }
    }
    verify_closure(manifest, workspace, hydrated, target, sidecar).unwrap()
}

impl Drop for RealFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct Fixture {
    root: PathBuf,
    private_root: PathBuf,
    helper: PathBuf,
    closure: context_relay_native_runner::VerifiedClosure,
    canary: PathBuf,
    listener: TcpListener,
}

impl Fixture {
    fn new(helper_kind: Helper) -> Self {
        assert_eq!(architecture(), "arm64");
        let parent = case_sensitive_apfs_root();
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = parent.join(format!("macos-adapter-{}-{suffix}", std::process::id()));
        let private_root = root.join("private");
        let hydrated = root.join("hydrated");
        fs::create_dir_all(&private_root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&private_root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(root.join(OUTSIDE_CLOSURE_CANARY), b"outside closure").unwrap();

        let helper = root.join("helper-template");
        let helper_binary = match helper_kind {
            Helper::Production => env!("CARGO_BIN_EXE_context-relay-native-helper"),
            Helper::ProtocolFault => env!("CARGO_BIN_EXE_macos_adapter_bad_helper"),
        };
        fs::copy(helper_binary, &helper).unwrap();
        sign_helper(&helper);

        let sidecar_path = "bin/rulesync";
        let sidecar = hydrated.join(sidecar_path);
        fs::create_dir_all(sidecar.parent().unwrap()).unwrap();
        fs::copy(env!("CARGO_BIN_EXE_macos_adapter_sidecar"), &sidecar).unwrap();
        fs::set_permissions(&sidecar, fs::Permissions::from_mode(0o700)).unwrap();
        sign_empty(&sidecar);
        let source_path = "third_party/sidecars/rulesync/source-lock.v1.json";
        let license_path = "third_party/sidecars/licenses/rulesync-MIT.txt";
        let source = b"source lock\n";
        let license = b"MIT license\n";
        write(&root.join(source_path), source);
        write(&root.join(license_path), license);
        let sidecar_bytes = fs::read(&sidecar).unwrap();
        let argv = [
            "rulesync",
            "generate",
            "--targets",
            "<closed-target>",
            "--features",
            "<closed-features>",
            "--output-roots",
            "output",
            "--config",
            "rulesync.jsonc",
            "--input-root",
            "input",
            "--silent",
        ];
        let manifest = json!({
            "schemaVersion": 1,
            "digestFormat": "sha256-nul-argv-v1",
            "allowedReleaseHosts": ["github.com"],
            "tools": [{
                "id": "rulesync",
                "version": "14.0.1",
                "source": {
                    "repository": "https://github.com/dyoshikawa/rulesync",
                    "revision": "a".repeat(40),
                    "tree": "b".repeat(40),
                    "materialPath": source_path,
                    "materialSha256": sha256(source),
                },
                "license": { "spdx": "MIT", "path": license_path, "sha256": sha256(license) },
                "relinking": null,
                "materials": [],
                "commandTemplate": {
                    "id": "rulesync-generate-v1",
                    "argv": argv,
                    "sha256": sha256(argv.join("\0").as_bytes()),
                },
                "targets": [{
                    "target": "windows-x86_64",
                    "enabled": false,
                    "disabledReason": "fixture-disabled",
                    "reproducibleBuilds": 0,
                    "correspondingSourceComplete": false,
                    "download": null,
                    "executable": null,
                    "closure": [],
                }, {
                    "target": "macos-aarch64",
                    "enabled": true,
                    "disabledReason": null,
                    "reproducibleBuilds": 1,
                    "correspondingSourceComplete": true,
                    "download": {
                        "url": "https://github.com/dyoshikawa/rulesync/releases/download/v14.0.1/rulesync",
                        "format": "raw",
                        "size": sidecar_bytes.len(),
                        "sha256": sha256(&sidecar_bytes),
                        "entries": [{ "path": sidecar_path, "type": "file", "size": sidecar_bytes.len() }],
                        "extractPath": sidecar_path,
                    },
                    "executable": { "path": sidecar_path, "size": sidecar_bytes.len(), "sha256": sha256(&sidecar_bytes) },
                    "closure": [{ "path": sidecar_path, "size": sidecar_bytes.len(), "sha256": sha256(&sidecar_bytes), "executable": true }],
                }],
            }],
        });
        let manifest = parse_sidecar_manifest(&serde_json::to_vec(&manifest).unwrap()).unwrap();
        let closure = verify_closure(
            &manifest,
            &root,
            &hydrated,
            RuntimeTarget::MacosArm64,
            SidecarId::RuleSync,
        )
        .unwrap();
        let canary = account_home().join(REAL_HOME_CANARY);
        let listener = bind_probe_listener();
        listener.set_nonblocking(true).unwrap();
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&canary)
            .unwrap()
            .write_all(b"real home canary")
            .unwrap();
        Self {
            root,
            private_root,
            helper,
            closure,
            canary,
            listener,
        }
    }

    fn launcher(&self, journal: TestJournal) -> MacOsSandboxLauncher<TestJournal> {
        MacOsSandboxLauncher::new(
            self.private_root.clone(),
            self.helper.clone(),
            digest(&self.helper),
            journal,
        )
        .unwrap()
    }

    fn request(&self, mode: &str) -> RunRequest {
        RunRequest::new(
            REQUEST_NONCE,
            *self.closure.closure_sha256(),
            SidecarCommand::RuleSyncGenerate {
                target: RuleSyncTarget::ClaudeCode,
                features: RuleSyncFeatures::new(&[RuleSyncFeature::Rules]).unwrap(),
            },
            vec![
                ContentFrame::new(
                    StagePath::try_from("input/.rulesync/rules/probe.md").unwrap(),
                    mode.as_bytes().to_vec(),
                )
                .unwrap(),
            ],
        )
        .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.canary);
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[derive(Clone, Default)]
struct TestJournal(Arc<Mutex<JournalState>>);

#[derive(Default)]
struct JournalState {
    seen: BTreeSet<GenerationId>,
    states: BTreeMap<GenerationId, GenerationState>,
    events: Vec<GenerationState>,
    last_id: Option<GenerationId>,
}

impl TestJournal {
    fn events(&self) -> Vec<GenerationState> {
        self.0.lock().unwrap().events.clone()
    }

    fn last_id(&self) -> GenerationId {
        self.0.lock().unwrap().last_id.clone().unwrap()
    }

    fn try_last_id(&self) -> Option<GenerationId> {
        self.0.lock().unwrap().last_id.clone()
    }
}

impl GenerationJournal for TestJournal {
    fn reserve(&self, id: &GenerationId) -> Result<(), MacPolicyError> {
        let mut state = self.0.lock().unwrap();
        if !state.seen.insert(id.clone()) {
            return Err(MacPolicyError::InvalidTransition);
        }
        state.states.insert(id.clone(), GenerationState::Prepared);
        state.last_id = Some(id.clone());
        state.events.push(GenerationState::Prepared);
        Ok(())
    }

    fn bind_guardian(&self, id: &GenerationId, pgid: i32) -> Result<(), MacPolicyError> {
        if pgid <= 0 || self.0.lock().unwrap().states.get(id) != Some(&GenerationState::Prepared) {
            return Err(MacPolicyError::InvalidTransition);
        }
        Ok(())
    }

    fn bind_bundle_root(
        &self,
        id: &GenerationId,
        _bundle: &MacRootIdentity,
    ) -> Result<(), MacPolicyError> {
        if self.0.lock().unwrap().states.get(id) != Some(&GenerationState::Prepared) {
            return Err(MacPolicyError::InvalidTransition);
        }
        Ok(())
    }

    fn finalize(&self, generation: &SignedGeneration) -> Result<(), MacPolicyError> {
        if self.0.lock().unwrap().states.get(generation.id()) != Some(&GenerationState::Prepared) {
            return Err(MacPolicyError::InvalidTransition);
        }
        Ok(())
    }

    fn bind_container_root(
        &self,
        id: &GenerationId,
        _container: &MacRootIdentity,
    ) -> Result<(), MacPolicyError> {
        if self.0.lock().unwrap().states.get(id) != Some(&GenerationState::Prepared) {
            return Err(MacPolicyError::InvalidTransition);
        }
        Ok(())
    }

    fn transition(
        &self,
        id: &GenerationId,
        from: GenerationState,
        to: GenerationState,
    ) -> Result<(), MacPolicyError> {
        let mut state = self.0.lock().unwrap();
        if state.states.get(id) != Some(&from) {
            return Err(MacPolicyError::InvalidTransition);
        }
        state.states.insert(id.clone(), to);
        state.events.push(to);
        Ok(())
    }

    fn poison_interrupted_after_restart(&self) -> Result<(), MacPolicyError> {
        let mut state = self.0.lock().unwrap();
        for generation in state.states.values_mut() {
            if matches!(
                *generation,
                GenerationState::Prepared | GenerationState::Active
            ) {
                *generation = GenerationState::Poisoned;
            }
        }
        Ok(())
    }
}

fn case_sensitive_apfs_root() -> PathBuf {
    let root = PathBuf::from(
        std::env::var_os("CONTEXT_RELAY_CASE_SENSITIVE_APFS_ROOT")
            .expect("native CI must mount and declare a case-sensitive APFS root"),
    );
    let canonical = fs::canonicalize(&root).unwrap();
    assert_eq!(root, canonical);
    let path = CString::new(root.to_str().unwrap()).unwrap();
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    assert_eq!(unsafe { libc::statfs(path.as_ptr(), stat.as_mut_ptr()) }, 0);
    let stat = unsafe { stat.assume_init() };
    let filesystem = unsafe { CStr::from_ptr(stat.f_fstypename.as_ptr()) }
        .to_str()
        .unwrap();
    assert_eq!(filesystem, "apfs");
    let lower = root.join(format!("case-check-{}", std::process::id()));
    let upper = root.join(format!("CASE-CHECK-{}", std::process::id()));
    fs::write(&lower, b"lower").unwrap();
    fs::write(&upper, b"upper").unwrap();
    assert_eq!(fs::read(&lower).unwrap(), b"lower");
    assert_eq!(fs::read(&upper).unwrap(), b"upper");
    fs::remove_file(lower).unwrap();
    fs::remove_file(upper).unwrap();
    root
}

fn bind_probe_listener() -> TcpListener {
    [42831, 43197, 43921, 44777, 45263, 46183, 47221, 48731]
        .into_iter()
        .find_map(|port| TcpListener::bind(("127.0.0.1", port)).ok())
        .expect("one closed fixture loopback port must be available")
}

fn sign_helper(path: &Path) {
    let entitlements = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../resources/macos/helper.entitlements.plist");
    let status = Command::new("/usr/bin/codesign")
        .args([
            "--force",
            "--sign",
            "-",
            "--options",
            "runtime",
            "--timestamp=none",
            "--entitlements",
        ])
        .arg(entitlements)
        .arg(path)
        .status()
        .unwrap();
    assert!(status.success());
}

fn sign_empty(path: &Path) {
    let status = Command::new("/usr/bin/codesign")
        .args([
            "--force",
            "--sign",
            "-",
            "--options",
            "runtime",
            "--timestamp=none",
        ])
        .arg(path)
        .status()
        .unwrap();
    assert!(status.success());
}

fn account_home() -> PathBuf {
    let passwd = unsafe { libc::getpwuid(libc::getuid()) };
    assert!(!passwd.is_null());
    PathBuf::from(
        unsafe { CStr::from_ptr((*passwd).pw_dir) }
            .to_str()
            .unwrap(),
    )
}

fn container_data(id: &GenerationId) -> PathBuf {
    account_home()
        .join("Library/Containers")
        .join(id.as_str())
        .join("Data")
}

fn architecture() -> String {
    String::from_utf8(
        Command::new("/usr/bin/uname")
            .arg("-m")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_owned()
}

fn process_exists(pid: i32) -> bool {
    unsafe { libc::kill(pid, 0) == 0 }
}

fn process_group_exists(pgid: i32) -> bool {
    unsafe { libc::kill(-pgid, 0) == 0 }
}

fn recorded_group(journal: &TestJournal) -> Option<(i32, i32)> {
    let id = journal.try_last_id()?;
    let pid_file = container_data(&id)
        .join(hex_nonce(REQUEST_NONCE))
        .join("home/ordinary-child.pid");
    let values = fs::read_to_string(pid_file)
        .ok()?
        .lines()
        .map(str::parse::<i32>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    let [pid, pgid] = values.as_slice() else {
        return None;
    };
    Some((*pid, *pgid))
}

fn assert_generation_cleaned(private_root: &Path, journal: &TestJournal) {
    let id = journal.last_id();
    assert!(!private_root.join(format!("{}.app", id.as_str())).exists());
    assert!(!container_data(&id).parent().unwrap().exists());
}

fn parse_fixture_process(output: &str, prefix: &str) -> i32 {
    output
        .lines()
        .find_map(|line| line.strip_prefix(prefix))
        .unwrap()
        .parse()
        .unwrap()
}

fn assert_group_gone(pid: i32, pgid: i32, outcome: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while (process_exists(pid) || process_group_exists(pgid)) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(
        !process_exists(pid),
        "ordinary child {pid} survived {outcome}"
    );
    assert!(
        !process_group_exists(pgid),
        "generation process group {pgid} survived {outcome}"
    );
}

fn write(path: &Path, bytes: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

fn frame(path: &str, bytes: &[u8]) -> ContentFrame {
    ContentFrame::new(StagePath::try_from(path).unwrap(), bytes.to_vec()).unwrap()
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../..")
        .canonicalize()
        .unwrap()
}

fn real_manifest_workspace(committed: &Path) -> Result<PathBuf, String> {
    let Some(root) = std::env::var_os(REAL_SIDECAR_MANIFEST_ROOT) else {
        return Ok(committed.to_owned());
    };
    validate_manifest_workspace(&PathBuf::from(root))
}

fn validate_manifest_workspace(root: &Path) -> Result<PathBuf, String> {
    let rendered = root.as_os_str().to_string_lossy();
    if !root.is_absolute()
        || rendered.split('/').any(|part| part == "." || part == "..")
        || root.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err("override must be an absolute normalized path".to_owned());
    }
    let canonical = fs::canonicalize(root).map_err(|_| "override root is missing".to_owned())?;
    if canonical != root {
        return Err("override root must already be canonical".to_owned());
    }
    let manifest = canonical.join("third_party/sidecars/manifest.v1.json");
    if fs::canonicalize(&manifest).ok().as_deref() != Some(manifest.as_path()) {
        return Err("manifest is missing or linked outside the canonical override root".to_owned());
    }
    Ok(canonical)
}

#[test]
fn real_manifest_workspace_rejects_missing_and_noncanonical_overrides() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!(
            "context-relay-manifest-root-{}-{suffix}",
            std::process::id()
        ));
    assert!(validate_manifest_workspace(&root).is_err());
    fs::create_dir_all(root.join("third_party/sidecars")).unwrap();
    fs::write(root.join("third_party/sidecars/manifest.v1.json"), b"{}").unwrap();
    assert!(validate_manifest_workspace(&root).is_ok());
    assert!(validate_manifest_workspace(&root.join(".")).is_err());
    fs::remove_dir_all(root).unwrap();
}

fn digest(path: &Path) -> [u8; 32] {
    Sha256::digest(fs::read(path).unwrap()).into()
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn hex_nonce(nonce: [u8; 16]) -> String {
    nonce
        .into_iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
