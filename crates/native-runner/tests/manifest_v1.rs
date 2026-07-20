use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use context_relay_native_runner::{
    RuntimeTarget, SidecarId, parse_sidecar_manifest, verify_closure,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[test]
fn committed_manifest_matches_the_strict_rust_schema() {
    parse_sidecar_manifest(include_bytes!(
        "../../../third_party/sidecars/manifest.v1.json"
    ))
    .unwrap();
}

#[test]
fn strict_manifest_verifies_materials_and_exact_hydrated_closure() {
    let fixture = Fixture::new();
    let manifest = parse_sidecar_manifest(&fixture.bytes()).unwrap();
    let closure = verify_closure(
        &manifest,
        &fixture.root,
        &fixture.hydrated,
        RuntimeTarget::WindowsX86_64,
        SidecarId::RuleSync,
    )
    .unwrap();
    assert_eq!(closure.sidecar(), SidecarId::RuleSync);
    assert_eq!(closure.target(), RuntimeTarget::WindowsX86_64);
    assert_eq!(closure.version(), "14.0.1");
    assert_eq!(closure.materials().len(), 1);
    assert_eq!(closure.executable().path().as_str(), "bin/rulesync.exe");

    fs::write(fixture.hydrated.join("bin/rulesync.exe"), b"changed").unwrap();
    assert!(
        verify_closure(
            &manifest,
            &fixture.root,
            &fixture.hydrated,
            RuntimeTarget::WindowsX86_64,
            SidecarId::RuleSync,
        )
        .is_err()
    );
}

#[test]
fn manifest_rejects_unknown_duplicate_and_mismatched_fields() {
    let fixture = Fixture::new();

    let mut unknown = fixture.manifest.clone();
    unknown["unknown"] = json!(true);
    assert!(parse_sidecar_manifest(&serde_json::to_vec(&unknown).unwrap()).is_err());

    let mut nested_unknown = fixture.manifest.clone();
    nested_unknown["tools"][0]["commandTemplate"]["shell"] = json!("pwsh");
    assert!(parse_sidecar_manifest(&serde_json::to_vec(&nested_unknown).unwrap()).is_err());

    let mut duplicate_tools = fixture.manifest.clone();
    let tool = duplicate_tools["tools"][0].clone();
    duplicate_tools["tools"].as_array_mut().unwrap().push(tool);
    assert!(parse_sidecar_manifest(&serde_json::to_vec(&duplicate_tools).unwrap()).is_err());

    let mut duplicate_target = fixture.manifest.clone();
    let target = duplicate_target["tools"][0]["targets"][0].clone();
    duplicate_target["tools"][0]["targets"]
        .as_array_mut()
        .unwrap()
        .push(target);
    assert!(parse_sidecar_manifest(&serde_json::to_vec(&duplicate_target).unwrap()).is_err());

    let mut bad_command_digest = fixture.manifest.clone();
    bad_command_digest["tools"][0]["commandTemplate"]["sha256"] = json!("00".repeat(32));
    assert!(parse_sidecar_manifest(&serde_json::to_vec(&bad_command_digest).unwrap()).is_err());

    let mut arbitrary_command = fixture.manifest.clone();
    let argv = ["pwsh", "-Command", "Get-ChildItem Env:"];
    arbitrary_command["tools"][0]["commandTemplate"]["argv"] = json!(argv);
    arbitrary_command["tools"][0]["commandTemplate"]["sha256"] =
        json!(sha256(argv.join("\0").as_bytes()));
    assert!(parse_sidecar_manifest(&serde_json::to_vec(&arbitrary_command).unwrap()).is_err());

    let mut abbreviated_hash = fixture.manifest.clone();
    abbreviated_hash["tools"][0]["targets"][0]["executable"]["sha256"] = json!("abcd");
    assert!(parse_sidecar_manifest(&serde_json::to_vec(&abbreviated_hash).unwrap()).is_err());

    let mut disabled_with_material = fixture.manifest.clone();
    disabled_with_material["tools"][0]["targets"][0]["enabled"] = json!(false);
    disabled_with_material["tools"][0]["targets"][0]["disabledReason"] = json!("disabled");
    assert!(parse_sidecar_manifest(&serde_json::to_vec(&disabled_with_material).unwrap()).is_err());
}

#[test]
fn closure_verification_rejects_missing_material_extra_files_and_disabled_targets() {
    let fixture = Fixture::new();
    let manifest = parse_sidecar_manifest(&fixture.bytes()).unwrap();
    assert!(
        verify_closure(
            &manifest,
            &fixture.root,
            &fixture.hydrated,
            RuntimeTarget::MacosArm64,
            SidecarId::RuleSync,
        )
        .is_err()
    );

    fs::write(fixture.hydrated.join("unexpected"), b"extra").unwrap();
    assert!(
        verify_closure(
            &manifest,
            &fixture.root,
            &fixture.hydrated,
            RuntimeTarget::WindowsX86_64,
            SidecarId::RuleSync,
        )
        .is_err()
    );
    fs::remove_file(fixture.hydrated.join("unexpected")).unwrap();

    fs::remove_file(
        fixture
            .root
            .join("third_party/sidecars/rulesync/source-lock.v1.json"),
    )
    .unwrap();
    assert!(
        verify_closure(
            &manifest,
            &fixture.root,
            &fixture.hydrated,
            RuntimeTarget::WindowsX86_64,
            SidecarId::RuleSync,
        )
        .is_err()
    );
}

#[test]
fn closure_verification_rejects_hardlinked_material() {
    let fixture = Fixture::new();
    let manifest = parse_sidecar_manifest(&fixture.bytes()).unwrap();
    fs::hard_link(
        fixture.hydrated.join("bin/rulesync.exe"),
        fixture.root.join("outside-hardlink.exe"),
    )
    .unwrap();

    assert!(
        verify_closure(
            &manifest,
            &fixture.root,
            &fixture.hydrated,
            RuntimeTarget::WindowsX86_64,
            SidecarId::RuleSync,
        )
        .is_err()
    );
}

#[test]
fn enabled_semgrep_rejects_an_internally_incomplete_source_lock() {
    let mut fixture = Fixture::new();
    let source_path = "third_party/sidecars/rulesync/source-lock.v1.json";
    let source_lock = serde_json::to_vec(&json!({
        "sourceRevision": "a".repeat(40),
        "sourceTree": "b".repeat(40),
        "completeCorrespondingSource": false,
        "recursiveInventoryComplete": false,
        "opam": {
            "resolvedSourceArchives": [],
            "resolvedSourceArchivesComplete": false
        },
        "targetStatus": [{
            "distributionTarget": "windows-x86_64",
            "enabled": false
        }],
        "missingMaterial": ["resolved sources"]
    }))
    .unwrap();
    fs::write(fixture.root.join(source_path), &source_lock).unwrap();

    let argv = [
        "osemgrep",
        "scan",
        "--experimental",
        "--oss-only",
        "--metrics=off",
        "--disable-version-check",
        "--strict",
        "--error",
        "--json",
        "--quiet",
        "--no-git-ignore",
        "--x-ignore-semgrepignore-files",
        "--jobs=1",
        "--timeout=30",
        "--timeout-threshold=1",
        "--max-target-bytes=8388608",
        "--config",
        "<staged-rule>",
        "<staged-target>",
    ];
    let relinking_path = "third_party/sidecars/semgrep/RELINKING.md";
    let relinking = b"replacement instructions";
    write(&fixture.root.join(relinking_path), relinking);
    let generator_path = "scripts/semgrep-source-bundle.mjs";
    let generator = b"export const fixture = true;\n";
    write(&fixture.root.join(generator_path), generator);
    let evidence_path = "third_party/sidecars/semgrep/bundle-evidence.v1.json";
    let evidence = semgrep_bundle_evidence(
        &sha256(&source_lock),
        &sha256(generator),
        "complete_corresponding_source",
    );
    write(&fixture.root.join(evidence_path), &evidence);
    let tool = &mut fixture.manifest["tools"][0];
    tool["id"] = json!("semgrep");
    tool["version"] = json!("1.170.0");
    tool["source"]["materialSha256"] = json!(sha256(&source_lock));
    tool["license"]["spdx"] = json!("LGPL-2.1-or-later");
    tool["relinking"] = json!({
        "path": relinking_path,
        "sha256": sha256(relinking)
    });
    tool["materials"] = json!([{
        "role": "source-bundle-generator",
        "path": generator_path,
        "sha256": sha256(generator)
    }, {
        "role": "source-bundle-evidence",
        "path": evidence_path,
        "sha256": sha256(&evidence)
    }]);
    tool["commandTemplate"] = json!({
        "id": "osemgrep-scan-v1",
        "argv": argv,
        "sha256": sha256(argv.join("\0").as_bytes())
    });
    tool["targets"][0]["reproducibleBuilds"] = json!(2);
    tool["targets"][0]["correspondingSourceComplete"] = json!(true);

    let manifest = parse_sidecar_manifest(&fixture.bytes()).unwrap();
    assert!(
        verify_closure(
            &manifest,
            &fixture.root,
            &fixture.hydrated,
            RuntimeTarget::WindowsX86_64,
            SidecarId::Osemgrep,
        )
        .is_err()
    );

    let valid_inventory = json!({
        "sourceRevision": "a".repeat(40),
        "sourceTree": "b".repeat(40),
        "completeCorrespondingSource": true,
        "recursiveInventoryComplete": true,
        "opam": {
            "resolvedSourceArchives": [{
                "package": "dependency",
                "version": "1.0",
                "targets": ["windows-x86_64"],
                "opamPath": "packages/dependency/dependency.1.0/opam",
                "opamSha256": "a".repeat(64),
                "licenses": ["MIT"],
                "source": {
                    "checksums": [{
                        "algorithm": "sha256",
                        "digest": "b".repeat(64)
                    }],
                    "mirrors": [],
                    "supplementalChecksums": [],
                    "url": "https://example.invalid/dependency.tbz"
                },
                "extraSources": []
            }],
            "resolvedSourceArchivesComplete": true
        },
        "targetStatus": [{
            "distributionTarget": "windows-x86_64",
            "enabled": true
        }],
        "licenseMaterials": semgrep_license_materials(),
        "missingMaterial": []
    });
    let (valid_inventory, native_evidence, native_materials) = seal_native_evidence(
        &fixture.root,
        valid_inventory,
        &fixture.manifest["tools"][0]["targets"][0],
    );
    fs::write(fixture.root.join(source_path), &valid_inventory).unwrap();
    fixture.manifest["tools"][0]["source"]["materialSha256"] = json!(sha256(&valid_inventory));
    let evidence = semgrep_bundle_evidence(
        &sha256(&valid_inventory),
        &sha256(generator),
        "complete_corresponding_source",
    );
    fs::write(fixture.root.join(evidence_path), &evidence).unwrap();
    fixture.manifest["tools"][0]["materials"][1]["sha256"] = json!(sha256(&evidence));
    fixture.manifest["tools"][0]["materials"]
        .as_array_mut()
        .unwrap()
        .extend(native_materials);
    let manifest = parse_sidecar_manifest(&fixture.bytes()).unwrap();
    verify_closure(
        &manifest,
        &fixture.root,
        &fixture.hydrated,
        RuntimeTarget::WindowsX86_64,
        SidecarId::Osemgrep,
    )
    .unwrap();

    let mut incomplete_native: Value = serde_json::from_slice(&native_evidence).unwrap();
    incomplete_native["status"] = json!("pending");
    let incomplete_native = serde_json::to_vec(&incomplete_native).unwrap();
    let native_path = "third_party/sidecars/semgrep/native-build-evidence.v1.json";
    fs::write(fixture.root.join(native_path), &incomplete_native).unwrap();
    fixture.manifest["tools"][0]["materials"][2]["sha256"] = json!(sha256(&incomplete_native));
    let manifest = parse_sidecar_manifest(&fixture.bytes()).unwrap();
    assert!(
        verify_closure(
            &manifest,
            &fixture.root,
            &fixture.hydrated,
            RuntimeTarget::WindowsX86_64,
            SidecarId::Osemgrep,
        )
        .is_err()
    );
    fs::write(fixture.root.join(native_path), &native_evidence).unwrap();
    fixture.manifest["tools"][0]["materials"][2]["sha256"] = json!(sha256(&native_evidence));

    let pending_evidence = semgrep_bundle_evidence(
        &sha256(&valid_inventory),
        &sha256(generator),
        "source_bundle_reproducible_native_builds_pending",
    );
    fs::write(fixture.root.join(evidence_path), &pending_evidence).unwrap();
    fixture.manifest["tools"][0]["materials"][1]["sha256"] = json!(sha256(&pending_evidence));
    let manifest = parse_sidecar_manifest(&fixture.bytes()).unwrap();
    assert!(
        verify_closure(
            &manifest,
            &fixture.root,
            &fixture.hydrated,
            RuntimeTarget::WindowsX86_64,
            SidecarId::Osemgrep,
        )
        .is_err()
    );

    let malformed_inventory = serde_json::to_vec(&json!({
        "sourceRevision": "a".repeat(40),
        "sourceTree": "b".repeat(40),
        "completeCorrespondingSource": true,
        "recursiveInventoryComplete": true,
        "opam": {
            "resolvedSourceArchives": [{ "package": "dependency" }],
            "resolvedSourceArchivesComplete": true
        },
        "targetStatus": [{
            "distributionTarget": "windows-x86_64",
            "enabled": true
        }],
        "licenseMaterials": semgrep_license_materials(),
        "missingMaterial": []
    }))
    .unwrap();
    fs::write(fixture.root.join(source_path), &malformed_inventory).unwrap();
    fixture.manifest["tools"][0]["source"]["materialSha256"] = json!(sha256(&malformed_inventory));
    let evidence = semgrep_bundle_evidence(
        &sha256(&malformed_inventory),
        &sha256(generator),
        "complete_corresponding_source",
    );
    fs::write(fixture.root.join(evidence_path), &evidence).unwrap();
    fixture.manifest["tools"][0]["materials"][1]["sha256"] = json!(sha256(&evidence));
    let manifest = parse_sidecar_manifest(&fixture.bytes()).unwrap();
    assert!(
        verify_closure(
            &manifest,
            &fixture.root,
            &fixture.hydrated,
            RuntimeTarget::WindowsX86_64,
            SidecarId::Osemgrep,
        )
        .is_err()
    );
}

#[cfg(unix)]
#[test]
fn closure_verification_rejects_wrong_executable_mode() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::new();
    let executable = fixture.hydrated.join("bin/rulesync.exe");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o600)).unwrap();
    let manifest = parse_sidecar_manifest(&fixture.bytes()).unwrap();

    assert!(
        verify_closure(
            &manifest,
            &fixture.root,
            &fixture.hydrated,
            RuntimeTarget::WindowsX86_64,
            SidecarId::RuleSync,
        )
        .is_err()
    );
}

struct Fixture {
    root: PathBuf,
    hydrated: PathBuf,
    manifest: Value,
}

impl Fixture {
    fn new() -> Self {
        let root = unique_temp_path();
        let hydrated = root.join("hydrated");
        let source_path = "third_party/sidecars/rulesync/source-lock.v1.json";
        let license_path = "third_party/sidecars/licenses/rulesync-MIT.txt";
        let executable_path = "bin/rulesync.exe";
        let source = b"source lock\n";
        let license = b"MIT license\n";
        let executable = b"pinned executable";
        write(&root.join(source_path), source);
        write(&root.join(license_path), license);
        write(&hydrated.join(executable_path), executable);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                hydrated.join(executable_path),
                fs::Permissions::from_mode(0o700),
            )
            .unwrap();
        }

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
                "license": {
                    "spdx": "MIT",
                    "path": license_path,
                    "sha256": sha256(license),
                },
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
                        "entries": [{
                            "path": executable_path,
                            "type": "file",
                            "size": executable.len(),
                        }],
                        "extractPath": executable_path,
                    },
                    "executable": {
                        "path": executable_path,
                        "size": executable.len(),
                        "sha256": sha256(executable),
                    },
                    "closure": [{
                        "path": executable_path,
                        "size": executable.len(),
                        "sha256": sha256(executable),
                        "executable": true,
                    }],
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
        Self {
            root,
            hydrated,
            manifest,
        }
    }

    fn bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.manifest).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
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

fn semgrep_bundle_evidence(
    source_lock_sha256: &str,
    generator_sha256: &str,
    status: &str,
) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schemaVersion": 1,
        "format": "context-relay-semgrep-source-v1",
        "sourceLockSha256": source_lock_sha256,
        "bundleGeneratorSha256": generator_sha256,
        "independentBuilds": 2,
        "byteIdentical": true,
        "status": status,
        "sourceAssetUrl": "https://github.com/Skytuhua/Context-Relay/releases/download/sidecars-semgrep-1.170.0-source.1/semgrep-1.170.0-corresponding-source.tar",
        "bundle": {
            "sha256": "c".repeat(64),
            "size": 1_149_545_984_u64,
            "payloadEntries": 39_539,
            "recordedLinks": 85
        }
    }))
    .unwrap()
}

fn seal_native_evidence(
    root: &Path,
    mut lock: Value,
    target: &Value,
) -> (Vec<u8>, Vec<u8>, Vec<Value>) {
    let support = [
        (
            "native-ci-provenance",
            "third_party/sidecars/semgrep/native-ci-provenance.v1.json",
            b"provenance\n".as_slice(),
        ),
        (
            "native-release-finalizer",
            "scripts/finalize-semgrep-native-release.mjs",
            b"finalizer\n".as_slice(),
        ),
        (
            "source-bundle-reseal",
            "scripts/reseal-semgrep-source-bundle.mjs",
            b"reseal\n".as_slice(),
        ),
    ];
    let support_refs = support
        .iter()
        .map(|(_, path, bytes)| {
            write(&root.join(path), bytes);
            json!({ "path": path, "sha256": sha256(bytes) })
        })
        .collect::<Vec<_>>();
    let support_materials = support
        .iter()
        .map(|(role, path, bytes)| json!({ "role": role, "path": path, "sha256": sha256(bytes) }))
        .collect::<Vec<_>>();
    let commit = "1".repeat(40);
    let archive = &target["download"];
    let builders = ["a", "b"]
        .iter()
        .enumerate()
        .map(|(index, slot)| {
            json!({
                "target": "windows-x86_64",
                "build": format!("build-{slot}"),
                "artifactName": format!("task9-semgrep-windows-build-{slot}-{commit}-42-1"),
                "identitySha256": if index == 0 { "5".repeat(64) } else { "6".repeat(64) },
                "identitySize": 256,
                "checkRunId": 100 + index,
                "jobDefinition": "native-semgrep-windows-x64-builders",
                "jobIndex": index,
                "jobTotal": 2,
                "runnerName": format!("runner-{slot}"),
                "runnerOs": "Windows",
                "runnerArch": "X64"
            })
        })
        .collect::<Vec<_>>();
    let evidence = json!({
        "schemaVersion": 1,
        "status": "native_builds_and_sandbox_smokes_verified",
        "bootstrapSource": {
            "sourceLockSha256": "2".repeat(64),
            "sourceRevision": lock["sourceRevision"],
            "sourceTree": lock["sourceTree"],
            "bundleEvidenceSha256": "3".repeat(64),
            "bundle": {
                "sha256": "4".repeat(64),
                "size": 1024,
                "payloadEntries": 2,
                "recordedLinks": 0
            }
        },
        "ci": {
            "commit": commit,
            "runId": "42",
            "runAttempt": 1,
            "workflowRef": "example/project/.github/workflows/ci.yml@refs/heads/main",
            "workflowSha": commit
        },
        "provenanceSha256": support_refs[0]["sha256"],
        "builders": builders,
        "smokes": [{
            "target": "windows-x86_64",
            "checkRunId": 102,
            "jobDefinition": "native-isolation-windows-x64",
            "sandboxMechanism": "windows-appcontainer",
            "sha256": "7".repeat(64),
            "size": 256
        }],
        "targets": [{
            "target": "windows-x86_64",
            "runtimeArchive": {
                "name": "rulesync.exe",
                "size": archive["size"],
                "sha256": archive["sha256"]
            },
            "evidenceArchive": { "name": "evidence.tar.gz", "size": 512, "sha256": "8".repeat(64) },
            "runtimeClosure": { "size": 256, "sha256": "9".repeat(64) },
            "manifests": {
                "build-a.MANIFEST.sha256": { "size": 128, "sha256": "a".repeat(64) },
                "build-b.MANIFEST.sha256": { "size": 128, "sha256": "a".repeat(64) },
                "build-a-evidence.MANIFEST.sha256": { "size": 128, "sha256": "b".repeat(64) },
                "build-b-evidence.MANIFEST.sha256": { "size": 128, "sha256": "b".repeat(64) }
            },
            "offlineEvidence": [
                { "build": "build-a", "size": 128, "sha256": "c".repeat(64) },
                { "build": "build-b", "size": 128, "sha256": "c".repeat(64) }
            ]
        }],
        "windowsBuilder": {
            "evidence": { "size": 256, "sha256": "d".repeat(64) },
            "schema": { "size": 256, "sha256": "e".repeat(64) },
            "toolchain": { "size": 256, "sha256": "f".repeat(64) }
        },
        "support": support_refs
    });
    let evidence_bytes = serde_json::to_vec(&evidence).unwrap();
    let evidence_path = "third_party/sidecars/semgrep/native-build-evidence.v1.json";
    write(&root.join(evidence_path), &evidence_bytes);
    lock["toolchains"] = json!([{
        "distributionTarget": "windows-x86_64",
        "status": "native_builds_verified",
        "builderEvidence": {
            "schemaSha256": evidence["windowsBuilder"]["schema"]["sha256"],
            "sha256": evidence["windowsBuilder"]["evidence"]["sha256"],
            "status": "verified_native_capture"
        }
    }]);
    lock["nativeBuildEvidence"] = json!({
        "path": evidence_path,
        "sha256": sha256(&evidence_bytes),
        "support": evidence["support"]
    });
    let mut materials = vec![json!({
        "role": "native-build-evidence",
        "path": evidence_path,
        "sha256": sha256(&evidence_bytes)
    })];
    materials.extend(support_materials);
    (
        serde_json::to_vec(&lock).unwrap(),
        evidence_bytes,
        materials,
    )
}

fn semgrep_license_materials() -> Value {
    let mut materials = Vec::new();
    for source in [
        "memtrace",
        "obackward",
        "ocaml-compiler",
        "ocaml-opentelemetry",
        "ocaml-tree-sitter-core",
        "pcre2-ocaml",
        "pyro-caml",
        "semgrep",
        "semgrep-interfaces",
        "testo",
        "tree-sitter-runtime",
    ] {
        let path = match source {
            "semgrep" => "sources/semgrep/LICENSE".to_owned(),
            "tree-sitter-runtime" => "support/tree-sitter-LICENSE".to_owned(),
            _ => format!("pins/{source}/LICENSE"),
        };
        materials.push(json!({
            "source": source,
            "kind": "license",
            "spdx": "MIT",
            "path": path,
            "sha256": "f".repeat(64)
        }));
        if source == "semgrep-interfaces" {
            materials.push(json!({
                "source": source,
                "kind": "notice",
                "spdx": "MIT",
                "path": "pins/semgrep-interfaces/NOTICE",
                "sha256": "e".repeat(64)
            }));
        }
    }
    Value::Array(materials)
}

fn unique_temp_path() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "context-relay-native-manifest-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}
