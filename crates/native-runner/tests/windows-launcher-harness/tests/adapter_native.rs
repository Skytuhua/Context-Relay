#![cfg(windows)]

use std::{
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use context_relay_native_runner::windows::{
    LaunchError, ProfileIdentity, ProfileJournal, ProfileMoniker,
};
use context_relay_native_runner::{
    ContentFrame, FailureCode, RunDisposition, RunRequest, RunResponse, RunnerError, RuntimeTarget,
    SidecarCommand, SidecarId, StagePath, WindowsSandboxLauncher, parse_sidecar_manifest,
    verify_closure,
};
use serde_json::json;
use sha2::{Digest, Sha256};

#[test]
fn production_adapter_runs_bound_protocol_inside_denied_appcontainer() {
    let fixture = Fixture::new();
    let journal = TestJournal::default();
    let launcher = launcher(journal.clone(), &fixture.root);

    assert_eq!(
        run_durable(
            &launcher,
            &journal,
            &fixture.closure,
            &fixture.request("BOUND"),
        )
        .unwrap(),
        RunResponse::failed(FailureCode::InvalidOutput)
    );
    assert!(matches!(
        fixture.listener.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
    assert_eq!(
        journal.events(),
        ["reserve", "created", "cleanup", "deleted"]
    );
    assert_profile_was_deleted(journal.identity());
}

#[test]
fn profile_cleanup_waits_for_a_durable_outer_result() {
    use context_relay_native_runner::windows::{CreateProfileOutcome, ProfileApi, Win32ProfileApi};

    let fixture = Fixture::new();
    let journal = TestJournal::default();
    let launcher = launcher(journal.clone(), &fixture.root);
    let request = fixture.request("BOUND");
    let lease = launcher.prepare_profile(*request.nonce()).unwrap();
    assert_eq!(
        lease.identity().moniker(),
        &ProfileMoniker::from_nonce(*request.nonce())
    );

    assert_eq!(
        launcher
            .run_prepared(&lease, &fixture.closure, &request)
            .unwrap(),
        RunResponse::failed(FailureCode::InvalidOutput)
    );
    assert_eq!(journal.events(), ["reserve", "created"]);
    let mut profiles = Win32ProfileApi::new();
    assert_eq!(
        profiles.create_profile(lease.identity()).unwrap(),
        CreateProfileOutcome::AlreadyExists
    );

    journal.mark_result_durable();
    launcher.cleanup_after_durable_outcome(&lease).unwrap();
    assert_eq!(
        journal.events(),
        ["reserve", "created", "cleanup", "deleted"]
    );
    assert_eq!(
        launcher.cleanup_after_durable_outcome(&lease),
        Err(RunnerError::SidecarUnavailable)
    );
    assert_eq!(
        profiles.create_profile(lease.identity()).unwrap(),
        CreateProfileOutcome::Created
    );
    assert_eq!(
        launcher.run_prepared(&lease, &fixture.closure, &request),
        Err(RunnerError::SidecarUnavailable)
    );
    profiles.delete_profile(lease.identity()).unwrap();
}

#[test]
fn production_adapter_rejects_unbound_trailing_or_stderr_output() {
    for mode in ["WRONG_BINDING", "TRAILING", "STDERR"] {
        let fixture = Fixture::new();
        let journal = TestJournal::default();
        let launcher = launcher(journal.clone(), &fixture.root);

        assert_eq!(
            run_durable(
                &launcher,
                &journal,
                &fixture.closure,
                &fixture.request(mode),
            )
            .unwrap(),
            RunResponse::failed(FailureCode::ToolFailed),
            "mode {mode}"
        );
        assert_eq!(journal.events().last(), Some(&"deleted"));
    }
}

#[test]
fn helper_protocol_handles_are_not_reinherited_by_a_sidecar_child() {
    let fixture = Fixture::new();
    let journal = TestJournal::default();
    let launcher = launcher(journal.clone(), &fixture.root);

    assert_eq!(
        run_durable(
            &launcher,
            &journal,
            &fixture.closure,
            &fixture.request("NO_PROTOCOL_HANDLE_LEAK"),
        )
        .unwrap(),
        RunResponse::failed(FailureCode::InvalidOutput)
    );
    assert_eq!(journal.events().last(), Some(&"deleted"));
}

#[test]
fn production_adapter_accepts_a_valid_response_above_four_mibibytes() {
    let fixture = Fixture::new();
    let journal = TestJournal::default();
    let launcher = launcher(journal.clone(), &fixture.root);

    let response = run_durable(
        &launcher,
        &journal,
        &fixture.closure,
        &fixture.request("BOUND_LARGE"),
    )
    .unwrap();
    let RunResponse::Completed {
        disposition,
        outputs,
        ..
    } = response
    else {
        panic!("valid bounded response was rejected");
    };
    assert_eq!(disposition, RunDisposition::Generated);
    assert_eq!(outputs[0].bytes().len(), 5 * 1024 * 1024);
}

#[test]
fn production_adapter_rejects_command_mismatch_before_profile_creation() {
    let fixture = Fixture::new();
    let journal = TestJournal::default();
    let launcher = launcher(journal.clone(), &fixture.root);
    let request = RunRequest::new(
        [0x91; 16],
        *fixture.closure.closure_sha256(),
        SidecarCommand::GitleaksScanPackage,
        vec![
            ContentFrame::new(
                StagePath::try_from("input/gitleaks-scan/payload/main.rs").unwrap(),
                b"fn main() {}".to_vec(),
            )
            .unwrap(),
        ],
    )
    .unwrap();

    assert_eq!(
        launcher.validate_request(&fixture.closure, &request),
        Err(RunnerError::ClosureMismatch)
    );
    assert!(journal.events().is_empty());
}

#[test]
fn timeout_terminates_the_job_before_profile_cleanup() {
    let fixture = Fixture::new();
    let journal = TestJournal::default();
    let launcher = launcher(journal.clone(), &fixture.root);
    let started = Instant::now();

    assert_eq!(
        run_durable(
            &launcher,
            &journal,
            &fixture.closure,
            &fixture.request("TIMEOUT"),
        )
        .unwrap(),
        RunResponse::failed(FailureCode::TimedOut)
    );
    assert!(started.elapsed() >= Duration::from_secs(29));
    assert!(started.elapsed() < Duration::from_secs(40));
    assert_eq!(journal.events().last(), Some(&"deleted"));
}

fn launcher(journal: TestJournal, root: &Path) -> WindowsSandboxLauncher<TestJournal> {
    let helper = root.join("helper-template.exe");
    fs::copy(
        PathBuf::from(env!("CARGO_BIN_EXE_windows_adapter_probe")),
        &helper,
    )
    .unwrap();
    let digest = Sha256::digest(fs::read(&helper).unwrap()).into();
    WindowsSandboxLauncher::new(helper, digest, journal).unwrap()
}

fn run_durable(
    launcher: &WindowsSandboxLauncher<TestJournal>,
    journal: &TestJournal,
    closure: &context_relay_native_runner::VerifiedClosure,
    request: &RunRequest,
) -> Result<RunResponse, RunnerError> {
    launcher.validate_request(closure, request)?;
    let lease = launcher.prepare_profile(*request.nonce())?;
    let result = launcher.run_prepared(&lease, closure, request);
    journal.mark_result_durable();
    launcher.cleanup_after_durable_outcome(&lease)?;
    result
}

fn assert_profile_was_deleted(identity: ProfileIdentity) {
    use context_relay_native_runner::windows::{CreateProfileOutcome, ProfileApi, Win32ProfileApi};
    let mut api = Win32ProfileApi::new();
    assert_eq!(
        api.create_profile(&identity).unwrap(),
        CreateProfileOutcome::Created
    );
    api.delete_profile(&identity).unwrap();
}

#[derive(Clone, Default)]
struct TestJournal(Arc<Mutex<JournalState>>);

#[derive(Default)]
struct JournalState {
    events: Vec<&'static str>,
    identity: Option<ProfileIdentity>,
    result_durable: bool,
}

impl TestJournal {
    fn events(&self) -> Vec<&'static str> {
        self.0.lock().unwrap().events.clone()
    }

    fn identity(&self) -> ProfileIdentity {
        self.0.lock().unwrap().identity.clone().unwrap()
    }

    fn record(&self, event: &'static str, identity: &ProfileIdentity) {
        let mut state = self.0.lock().unwrap();
        state.events.push(event);
        state.identity = Some(identity.clone());
    }

    fn mark_result_durable(&self) {
        self.0.lock().unwrap().result_durable = true;
    }
}

impl ProfileJournal for TestJournal {
    fn reserve(&mut self, identity: &ProfileIdentity) -> Result<(), LaunchError> {
        self.record("reserve", identity);
        Ok(())
    }

    fn mark_created(&mut self, identity: &ProfileIdentity) -> Result<(), LaunchError> {
        self.record("created", identity);
        Ok(())
    }

    fn attest_created(&mut self, identity: &ProfileIdentity) -> Result<(), LaunchError> {
        let state = self.0.lock().unwrap();
        if state.events.last() == Some(&"created") && state.identity.as_ref() == Some(identity) {
            Ok(())
        } else {
            Err(LaunchError::JournalFailure)
        }
    }

    fn mark_cleanup_pending(&mut self, identity: &ProfileIdentity) -> Result<(), LaunchError> {
        if !self.0.lock().unwrap().result_durable {
            return Err(LaunchError::JournalFailure);
        }
        self.record("cleanup", identity);
        Ok(())
    }

    fn mark_deleted(&mut self, identity: &ProfileIdentity) -> Result<(), LaunchError> {
        self.record("deleted", identity);
        Ok(())
    }
}

struct Fixture {
    root: PathBuf,
    closure: context_relay_native_runner::VerifiedClosure,
    denied_path: PathBuf,
    listener: TcpListener,
    nonce: [u8; 16],
}

impl Fixture {
    fn new() -> Self {
        let root = unique_temp_path();
        let nonce = Sha256::digest(root.as_os_str().as_encoded_bytes())[..16]
            .try_into()
            .unwrap();
        let hydrated = root.join("hydrated");
        let source_path = "third_party/sidecars/rulesync/source-lock.v1.json";
        let license_path = "third_party/sidecars/licenses/rulesync-MIT.txt";
        let executable_path = "bin/rulesync.exe";
        let source = b"source lock\n";
        let license = b"MIT license\n";
        let executable = b"closed runtime fixture";
        write(&root.join(source_path), source);
        write(&root.join(license_path), license);
        write(&hydrated.join(executable_path), executable);
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
                    "enabled": true,
                    "disabledReason": null,
                    "reproducibleBuilds": 1,
                    "correspondingSourceComplete": true,
                    "download": {
                        "url": "https://github.com/dyoshikawa/rulesync/releases/download/v14.0.1/rulesync.exe",
                        "format": "raw",
                        "size": executable.len(),
                        "sha256": sha256(executable),
                        "entries": [{ "path": executable_path, "type": "file", "size": executable.len() }],
                        "extractPath": executable_path,
                    },
                    "executable": { "path": executable_path, "size": executable.len(), "sha256": sha256(executable) },
                    "closure": [{ "path": executable_path, "size": executable.len(), "sha256": sha256(executable), "executable": true }],
                }, {
                    "target": "macos-aarch64",
                    "enabled": false,
                    "disabledReason": "fixture-disabled",
                    "reproducibleBuilds": 0,
                    "correspondingSourceComplete": false,
                    "download": null,
                    "executable": null,
                    "closure": [],
                }],
            }],
        });
        let manifest = parse_sidecar_manifest(&serde_json::to_vec(&manifest).unwrap()).unwrap();
        let closure = verify_closure(
            &manifest,
            &root,
            &hydrated,
            RuntimeTarget::WindowsX86_64,
            SidecarId::RuleSync,
        )
        .unwrap();
        let denied_path = std::env::var_os("USERPROFILE")
            .map(PathBuf::from)
            .unwrap()
            .join(format!(
                ".context-relay-adapter-canary-{}",
                std::process::id()
            ));
        fs::write(&denied_path, b"real-home-canary").unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        Self {
            root,
            closure,
            denied_path,
            listener,
            nonce,
        }
    }

    fn request(&self, mode: &str) -> RunRequest {
        let instructions = format!(
            "DENY={}\nCONNECT={}\nMODE={mode}\n",
            self.denied_path.display(),
            self.listener.local_addr().unwrap()
        );
        let features = context_relay_native_runner::RuleSyncFeatures::new(&[
            context_relay_native_runner::RuleSyncFeature::Rules,
        ])
        .unwrap();
        RunRequest::new(
            self.nonce,
            *self.closure.closure_sha256(),
            SidecarCommand::RuleSyncGenerate {
                target: context_relay_native_runner::RuleSyncTarget::ClaudeCode,
                features,
            },
            vec![
                ContentFrame::new(
                    StagePath::try_from("input/.rulesync/rules/probe.md").unwrap(),
                    instructions.into_bytes(),
                )
                .unwrap(),
            ],
        )
        .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.denied_path);
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn write(path: &Path, bytes: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn unique_temp_path() -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "context-relay-adapter-{}-{now}",
        std::process::id()
    ))
}
