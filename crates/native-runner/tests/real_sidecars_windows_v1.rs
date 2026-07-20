#![cfg(windows)]

use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use context_relay_native_runner::windows::{
    CreateProfileOutcome, LaunchError, ProfileApi, ProfileIdentity, ProfileJournal, Win32ProfileApi,
};
use context_relay_native_runner::{
    ContentFrame, FailureCode, RuleSyncFeature, RuleSyncFeatures, RuleSyncTarget, RunDisposition,
    RunRequest, RunResponse, RunnerError, RuntimeTarget, SidecarCommand, SidecarId, StagePath,
    VerifiedClosure, WindowsSandboxLauncher, parse_sidecar_manifest, verify_closure,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

const REAL_SIDECAR_ROOT: &str = "CONTEXT_RELAY_REAL_SIDECAR_ROOT";
const REAL_SIDECAR_MANIFEST_ROOT: &str = "CONTEXT_RELAY_REAL_SIDECAR_MANIFEST_ROOT";
const CI_CANDIDATE_DOCUMENT: &str = "CONTEXT_RELAY_CI_CANDIDATE_DOCUMENT";

#[test]
#[ignore = "requires exact hydrated sidecars and a native Windows AppContainer"]
fn real_rulesync_generates_only_the_validated_output_inside_appcontainer() {
    let fixture = RealFixture::new(SidecarId::RuleSync);
    let command = SidecarCommand::RuleSyncGenerate {
        target: RuleSyncTarget::ClaudeCode,
        features: RuleSyncFeatures::new(&[RuleSyncFeature::Rules]).unwrap(),
    };
    let request = fixture.request(
        [0x51; 16],
        command,
        vec![frame(
            "input/.rulesync/rules/overview.md",
            b"---\nroot: true\n---\n\n# Shared instructions\n\nKeep changes minimal.\n".to_vec(),
        )],
    );

    let response = fixture
        .run(&request)
        .unwrap_or_else(|error| panic!("{error:?}; lifecycle={:?}", fixture.journal.events()));
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
    fixture.assert_complete_lifecycle();
}

#[test]
#[ignore = "requires exact hydrated sidecars and a native Windows AppContainer"]
fn real_rulesync_rejects_malformed_frontmatter_and_cleans_up() {
    let fixture = RealFixture::new(SidecarId::RuleSync);
    let command = SidecarCommand::RuleSyncGenerate {
        target: RuleSyncTarget::ClaudeCode,
        features: RuleSyncFeatures::new(&[RuleSyncFeature::Rules]).unwrap(),
    };
    let request = fixture.request(
        [0x52; 16],
        command,
        vec![frame(
            "input/.rulesync/rules/overview.md",
            b"---\nroot: [\n---\n\n# Invalid instructions\n".to_vec(),
        )],
    );

    let response = fixture
        .run(&request)
        .unwrap_or_else(|error| panic!("{error:?}; lifecycle={:?}", fixture.journal.events()));
    assert_eq!(response, RunResponse::Failed(FailureCode::InvalidOutput));
    fixture.assert_complete_lifecycle();
}

#[test]
#[ignore = "requires exact hydrated sidecars and a native Windows AppContainer"]
fn real_gitleaks_distinguishes_clean_and_findings_and_ignores_attacker_ignore_file() {
    let fixture = RealFixture::new(SidecarId::Gitleaks);
    let clean = fixture.request(
        [0x61; 16],
        SidecarCommand::GitleaksScanPackage,
        vec![frame(
            "input/gitleaks-scan/payload/main.rs",
            b"fn main() {}\n".to_vec(),
        )],
    );
    let clean_response = fixture
        .run(&clean)
        .unwrap_or_else(|error| panic!("{error:?}; lifecycle={:?}", fixture.journal.events()));
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
                b"payload/secret.txt:aws-access-token:1\n".to_vec(),
            ),
            frame(
                "input/gitleaks-scan/payload/secret.txt",
                b"credential = AKIAQWERTYUIOPASDFGH\n".to_vec(),
            ),
        ],
    );
    let finding_response = fixture.run(&finding).unwrap();
    let RunResponse::Completed {
        disposition,
        outputs,
        ..
    } = finding_response
    else {
        panic!("real Gitleaks findings scan did not complete: {finding_response:?}");
    };
    assert_eq!(disposition, RunDisposition::Findings(1));
    let report: Value = serde_json::from_slice(outputs[0].bytes()).unwrap();
    let findings = report.as_array().unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["RuleID"], "aws-access-token");
    assert_eq!(findings[0]["File"], "payload/secret.txt");
    assert!(findings[0].get("Secret").is_none());
    assert!(findings[0].get("Match").is_none());
    fixture.assert_complete_lifecycle();
}

#[test]
#[ignore = "requires exact hydrated sidecars and a native Windows AppContainer"]
fn real_semgrep_clean_and_finding_use_the_closed_policy() {
    let fixture = RealFixture::new(SidecarId::Osemgrep);
    let clean = fixture.request(
        [0x71; 16],
        SidecarCommand::OsemgrepScanPackage,
        vec![frame(
            "input/semgrep-target/runtime-inventory.txt",
            b"osemgrep\n".to_vec(),
        )],
    );
    let RunResponse::Completed {
        disposition,
        outputs,
        ..
    } = fixture.run(&clean).unwrap()
    else {
        panic!("real Semgrep clean scan did not complete");
    };
    assert_eq!(disposition, RunDisposition::Clean);
    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0].path().as_str(), "reports/semgrep.json");

    let finding = fixture.request(
        [0x72; 16],
        SidecarCommand::OsemgrepScanPackage,
        vec![frame(
            "input/semgrep-target/runtime-inventory.txt",
            b"python.exe\n".to_vec(),
        )],
    );
    let RunResponse::Completed {
        disposition,
        outputs,
        ..
    } = fixture.run(&finding).unwrap()
    else {
        panic!("real Semgrep finding scan did not complete");
    };
    assert_eq!(disposition, RunDisposition::Findings(1));
    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0].path().as_str(), "reports/semgrep.json");
    fixture.assert_complete_lifecycle();
}

struct RealFixture {
    temp_root: PathBuf,
    helper: PathBuf,
    closure: VerifiedClosure,
    journal: TestJournal,
}

impl RealFixture {
    fn new(sidecar: SidecarId) -> Self {
        let workspace = workspace_root();
        let manifest_workspace = real_manifest_workspace(&workspace)
            .unwrap_or_else(|error| panic!("{REAL_SIDECAR_MANIFEST_ROOT}: {error}"));
        let hydrated = std::env::var_os(REAL_SIDECAR_ROOT)
            .map(PathBuf::from)
            .unwrap_or_else(|| panic!("{REAL_SIDECAR_ROOT} must name the verified hydration root"));
        assert!(hydrated.is_absolute(), "hydration root must be absolute");
        let manifest = parse_sidecar_manifest(
            &fs::read(manifest_workspace.join("third_party/sidecars/manifest.v1.json")).unwrap(),
        )
        .unwrap();
        let closure = verify_real_sidecar_closure(
            &manifest,
            &manifest_workspace,
            &hydrated.join(sidecar.stable_name()),
            RuntimeTarget::WindowsX86_64,
            sidecar,
        );
        let helper_source = PathBuf::from(env!("CARGO_BIN_EXE_context-relay-native-helper"));
        assert!(helper_source.is_absolute());
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_root = std::env::temp_dir().join(format!(
            "context-relay-real-sidecar-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&temp_root).unwrap();
        let helper = temp_root.join("context-relay-native-helper.exe");
        fs::copy(helper_source, &helper).unwrap();
        Self {
            temp_root,
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

    fn launcher(&self) -> WindowsSandboxLauncher<TestJournal> {
        let digest = Sha256::digest(fs::read(&self.helper).unwrap()).into();
        WindowsSandboxLauncher::new(self.helper.clone(), digest, self.journal.clone()).unwrap()
    }

    fn run(&self, request: &RunRequest) -> Result<RunResponse, RunnerError> {
        let launcher = self.launcher();
        launcher.validate_request(&self.closure, request)?;
        let lease = launcher.prepare_profile(*request.nonce())?;
        let result = launcher.run_prepared(&lease, &self.closure, request);
        self.journal.mark_result_durable();
        launcher.cleanup_after_durable_outcome(&lease)?;
        assert_profile_was_deleted(lease.identity());
        result
    }

    fn assert_complete_lifecycle(&self) {
        let events = self.journal.events();
        assert!(!events.is_empty());
        assert_eq!(events.len() % 4, 0);
        for lifecycle in events.chunks_exact(4) {
            assert_eq!(lifecycle, ["reserve", "created", "cleanup", "deleted"]);
        }
    }
}

fn verify_real_sidecar_closure(
    manifest: &context_relay_native_runner::SidecarManifest,
    workspace: &Path,
    hydrated: &Path,
    target: RuntimeTarget,
    sidecar: SidecarId,
) -> VerifiedClosure {
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
        let _ = fs::remove_dir_all(&self.temp_root);
    }
}

fn frame(path: &str, bytes: Vec<u8>) -> ContentFrame {
    ContentFrame::new(StagePath::try_from(path).unwrap(), bytes).unwrap()
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
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
        || rendered
            .split(['/', '\\'])
            .any(|part| part == "." || part == "..")
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
    let canonical_text = canonical.to_string_lossy();
    let comparable = if let Some(path) = canonical_text.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{path}")
    } else {
        canonical_text
            .strip_prefix(r"\\?\")
            .unwrap_or(&canonical_text)
            .to_owned()
    };
    if !root
        .as_os_str()
        .to_string_lossy()
        .eq_ignore_ascii_case(&comparable)
    {
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
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "context-relay-manifest-root-{}-{unique}",
        std::process::id()
    ));
    assert!(validate_manifest_workspace(&root).is_err());
    fs::create_dir_all(root.join("third_party/sidecars")).unwrap();
    fs::write(root.join("third_party/sidecars/manifest.v1.json"), b"{}").unwrap();
    assert!(validate_manifest_workspace(&root).is_ok());
    assert!(validate_manifest_workspace(&root.join(".")).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[derive(Clone, Default)]
struct TestJournal(Arc<Mutex<TestJournalState>>);

#[derive(Default)]
struct TestJournalState {
    events: Vec<&'static str>,
    identity: Option<ProfileIdentity>,
    result_durable: bool,
}

impl TestJournal {
    fn record(&self, event: &'static str) {
        self.0.lock().unwrap().events.push(event);
    }

    fn events(&self) -> Vec<&'static str> {
        self.0.lock().unwrap().events.clone()
    }

    fn mark_result_durable(&self) {
        self.0.lock().unwrap().result_durable = true;
    }
}

impl ProfileJournal for TestJournal {
    fn reserve(&mut self, identity: &ProfileIdentity) -> Result<(), LaunchError> {
        let mut state = self.0.lock().unwrap();
        state.result_durable = false;
        state.identity = Some(identity.clone());
        drop(state);
        self.record("reserve");
        Ok(())
    }

    fn mark_created(&mut self, _identity: &ProfileIdentity) -> Result<(), LaunchError> {
        self.record("created");
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

    fn mark_cleanup_pending(&mut self, _identity: &ProfileIdentity) -> Result<(), LaunchError> {
        if !self.0.lock().unwrap().result_durable {
            return Err(LaunchError::JournalFailure);
        }
        self.record("cleanup");
        Ok(())
    }

    fn mark_deleted(&mut self, _identity: &ProfileIdentity) -> Result<(), LaunchError> {
        self.record("deleted");
        Ok(())
    }
}

fn assert_profile_was_deleted(identity: &ProfileIdentity) {
    let mut api = Win32ProfileApi::new();
    assert_eq!(
        api.create_profile(identity).unwrap(),
        CreateProfileOutcome::Created
    );
    api.delete_profile(identity).unwrap();
}
