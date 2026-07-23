#![cfg(feature = "ci-candidate-sidecar-smoke")]

use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use context_relay_native_runner::{
    RuntimeTarget, SidecarId, parse_sidecar_manifest, verify_ci_candidate_closure, verify_closure,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const CANDIDATE_DOMAIN: &[u8] = b"context-relay/ci-candidate-sidecar-smoke/v1\0";

#[test]
fn pending_semgrep_candidate_is_test_only_and_exactly_bound() {
    let workspace = workspace_root();
    let manifest_bytes = current_material_manifest(&workspace);
    let manifest = parse_sidecar_manifest(&manifest_bytes).unwrap();
    let source_lock =
        fs::read(workspace.join("third_party/sidecars/semgrep/source-lock.v1.json")).unwrap();
    let bundle_evidence =
        fs::read(workspace.join("third_party/sidecars/semgrep/bundle-evidence.v1.json")).unwrap();
    let executable = b"candidate osemgrep fixture\n";
    let executable_sha256 = hex_hash(executable);
    let document = json!({
        "schemaVersion": 1,
        "purpose": "ci-native-sidecar-smoke-only",
        "publishable": false,
        "enabled": false,
        "target": "windows-x86_64",
        "sidecar": "semgrep",
        "version": "1.170.0",
        "productionManifestSha256": hex_hash(&manifest_bytes),
        "sourceLockSha256": hex_hash(&source_lock),
        "bundleEvidenceSha256": hex_hash(&bundle_evidence),
        "bundleEvidenceStatus": "source_bundle_v1_native_builds_pending",
        "archive": {
            "format": "tar.gz",
            "size": 1234,
            "sha256": "1111111111111111111111111111111111111111111111111111111111111111",
            "entries": [{ "path": "osemgrep.exe", "type": "file", "size": executable.len() }],
            "extractPath": "osemgrep.exe"
        },
        "executable": {
            "path": "osemgrep.exe",
            "size": executable.len(),
            "sha256": executable_sha256
        },
        "closure": [{
            "path": "osemgrep.exe",
            "size": executable.len(),
            "sha256": executable_sha256,
            "executable": true
        }]
    });
    let bytes = serde_json::to_vec_pretty(&document).unwrap();
    let fixture = CandidateFixture::new(&bytes, executable);

    assert!(
        verify_closure(
            &manifest,
            &workspace,
            &fixture.hydrated_root,
            RuntimeTarget::WindowsX86_64,
            SidecarId::Osemgrep,
        )
        .is_err(),
        "the production verifier must keep rejecting the pending target"
    );
    let verified = verify_ci_candidate_closure(
        &bytes,
        &manifest,
        &workspace,
        &fixture.hydrated_root,
        RuntimeTarget::WindowsX86_64,
        SidecarId::Osemgrep,
    )
    .unwrap();
    assert_eq!(verified.sidecar(), SidecarId::Osemgrep);
    assert_eq!(verified.version(), "1.170.0");
    assert_eq!(verified.executable().path().as_str(), "osemgrep.exe");

    for field in ["enabled", "publishable"] {
        let mut rejected = document.clone();
        rejected[field] = Value::Bool(true);
        let rejected_bytes = serde_json::to_vec_pretty(&rejected).unwrap();
        assert!(
            verify_ci_candidate_closure(
                &rejected_bytes,
                &manifest,
                &workspace,
                &fixture.hydrated_root,
                RuntimeTarget::WindowsX86_64,
                SidecarId::Osemgrep,
            )
            .is_err(),
            "candidate field {field} must never be accepted as true"
        );
    }

    let wrong_root = fixture.root.join("0".repeat(64)).join("semgrep");
    fs::create_dir_all(&wrong_root).unwrap();
    fs::write(wrong_root.join("osemgrep.exe"), executable).unwrap();
    assert!(
        verify_ci_candidate_closure(
            &bytes,
            &manifest,
            &workspace,
            &wrong_root,
            RuntimeTarget::WindowsX86_64,
            SidecarId::Osemgrep,
        )
        .is_err(),
        "the domain-separated candidate digest must name the cache generation"
    );

    fs::write(fixture.hydrated_root.join("osemgrep.exe"), b"tampered").unwrap();
    assert!(
        verify_ci_candidate_closure(
            &bytes,
            &manifest,
            &workspace,
            &fixture.hydrated_root,
            RuntimeTarget::WindowsX86_64,
            SidecarId::Osemgrep,
        )
        .is_err(),
        "the candidate verifier must bind the exact hydrated closure"
    );
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn hex_hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn current_material_manifest(workspace: &Path) -> Vec<u8> {
    let mut manifest: Value = serde_json::from_slice(
        &fs::read(workspace.join("third_party/sidecars/manifest.v1.json")).unwrap(),
    )
    .unwrap();
    let semgrep = manifest["tools"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|tool| tool["id"] == "semgrep")
        .unwrap();
    for material in semgrep["materials"].as_array_mut().unwrap() {
        let path = material["path"].as_str().unwrap();
        material["sha256"] = Value::String(hex_hash(&fs::read(workspace.join(path)).unwrap()));
    }
    serde_json::to_vec_pretty(&manifest).unwrap()
}

struct CandidateFixture {
    root: PathBuf,
    hydrated_root: PathBuf,
}

impl CandidateFixture {
    fn new(document: &[u8], executable: &[u8]) -> Self {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "context-relay-candidate-manifest-{}-{suffix}",
            std::process::id()
        ));
        let digest = Sha256::new()
            .chain_update(CANDIDATE_DOMAIN)
            .chain_update(document)
            .finalize();
        let hydrated_root = root.join(format!("{digest:x}")).join("semgrep");
        fs::create_dir_all(&hydrated_root).unwrap();
        fs::write(hydrated_root.join("osemgrep.exe"), executable).unwrap();
        Self {
            root,
            hydrated_root,
        }
    }
}

impl Drop for CandidateFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
