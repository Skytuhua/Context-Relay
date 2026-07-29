use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
};

use context_relay_core::hermes::{
    HermesAdapter, HermesExecutableKind, HermesLayout, HermesProfile,
};
use context_relay_protocol::{
    CapabilityLevel, DeviceId, ErrorCode, HarnessAdapter, HarnessId, HybridLogicalClock,
    InstallationMethod, ProbeContext, ProjectId,
};
use serde_json::{Map, Value};

const PROJECT_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073981";
const DEVICE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073982";
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct Fixture {
    root: PathBuf,
    adapter: HermesAdapter,
    layout: HermesLayout,
    project_id: ProjectId,
    default_home: PathBuf,
    profiles_root: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn fixture(source: &str) -> Fixture {
    let source: Value = serde_json::from_str(source).unwrap();
    let root = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!(
            "context-relay-hermes-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
    let default_home = root.join("hermes home");
    let profiles_root = default_home.join("profiles");
    let project_root = root.join("project with spaces");
    let working_directory = project_root.join("service");
    let profile = source["profile"].as_object().unwrap();
    let files = profile["files"].as_object().unwrap();
    materialize_profile(&default_home, profile, files);
    materialize_profile(&profiles_root.join("coder"), profile, files);
    materialize_profile(&profiles_root.join("writer"), profile, files);
    materialize(&project_root, source["project"].as_object().unwrap());
    fs::create_dir_all(&working_directory).unwrap();

    // Snapshot the operational canaries before removing them from this general fixture.
    for profile_root in [
        &default_home,
        &profiles_root.join("coder"),
        &profiles_root.join("writer"),
    ] {
        assert!(profile_root.join("gateway.pid").is_file());
        assert!(profile_root.join("gateway_state.json").is_file());
        fs::remove_file(profile_root.join("gateway.pid")).unwrap();
        fs::remove_file(profile_root.join("gateway_state.json")).unwrap();
    }

    let executable = root.join("hermes");
    fs::write(&executable, b"\x7fELFfixture hermes executable").unwrap();
    let project_id = ProjectId::from_str(PROJECT_ID).unwrap();
    let device_id = DeviceId::from_str(DEVICE_ID).unwrap();
    let layout = HermesLayout {
        executable,
        executable_kind: HermesExecutableKind::Native,
        version: source["version"].as_str().unwrap().to_owned(),
        installation_method: InstallationMethod::PackageManager,
        default_hermes_home: default_home.clone(),
        profile: HermesProfile {
            name: "coder".to_owned(),
            hermes_home: profiles_root.join("coder"),
        },
        project_root,
        working_directory,
    };
    let adapter = HermesAdapter::from_layout(
        layout.clone(),
        project_id,
        device_id,
        HybridLogicalClock::new(1_900_000_000_000, 0, device_id),
    )
    .unwrap();
    Fixture {
        root,
        adapter,
        layout,
        project_id,
        default_home,
        profiles_root,
    }
}

fn materialize_profile(root: &Path, profile: &Map<String, Value>, files: &Map<String, Value>) {
    materialize(root, files);
    fs::write(
        root.join("config.yaml"),
        profile["configYaml"].as_str().unwrap(),
    )
    .unwrap();
}

fn materialize(root: &Path, files: &Map<String, Value>) {
    for (relative, body) in files {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, body.as_str().unwrap()).unwrap();
    }
}

fn profile_layout(
    fixture: &Fixture,
    name: &str,
    version: &str,
    kind: HermesExecutableKind,
) -> HermesLayout {
    HermesLayout {
        executable: fixture.layout.executable.clone(),
        executable_kind: kind,
        version: version.to_owned(),
        installation_method: fixture.layout.installation_method,
        default_hermes_home: fixture.default_home.clone(),
        profile: HermesProfile {
            name: name.to_owned(),
            hermes_home: if name == "default" {
                fixture.default_home.clone()
            } else {
                fixture.profiles_root.join(name)
            },
        },
        project_root: fixture.layout.project_root.clone(),
        working_directory: fixture.layout.working_directory.clone(),
    }
}

fn probe(
    adapter: &HermesAdapter,
    requested_profile: Option<&str>,
) -> context_relay_protocol::ProbeReport {
    adapter
        .probe(&ProbeContext {
            harness: HarnessId::Hermes,
            requested_profile: requested_profile.map(str::to_owned),
        })
        .unwrap()
}

#[test]
fn supported_release_fixtures_bind_one_named_profile() {
    for source in [
        include_str!("fixtures/hermes-0.18.2.json"),
        include_str!("fixtures/hermes-0.18.1.json"),
    ] {
        let fixture = fixture(source);
        let report = probe(&fixture.adapter, Some("coder"));
        assert_eq!(report.capability, CapabilityLevel::Full);
        assert_eq!(report.active_profile.as_deref(), Some("coder"));
        assert_eq!(
            report.config_roots,
            vec![
                fixture.adapter.profile_home_wire(),
                fixture.adapter.project_root_wire()
            ]
        );
    }
}

#[test]
fn default_and_named_profiles_are_distinct_explicit_targets() {
    let _env = ENV_LOCK.lock().unwrap();
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let discovered = HermesAdapter::discover_profiles(&fixture.default_home).unwrap();
    assert_eq!(
        discovered
            .iter()
            .map(|profile| profile.name.as_str())
            .collect::<Vec<_>>(),
        vec!["default", "coder", "writer"]
    );
    assert_ne!(discovered[0].hermes_home, discovered[1].hermes_home);
    assert_ne!(discovered[1].hermes_home, discovered[2].hermes_home);
    assert_ne!(discovered[0].hermes_home, discovered[2].hermes_home);
    for profile in discovered {
        let adapter = HermesAdapter::from_layout(
            profile_layout(
                &fixture,
                &profile.name,
                &fixture.layout.version,
                HermesExecutableKind::Native,
            ),
            fixture.project_id,
            DeviceId::from_str(DEVICE_ID).unwrap(),
            HybridLogicalClock::new(1_900_000_000_000, 0, DeviceId::from_str(DEVICE_ID).unwrap()),
        )
        .unwrap();
        assert_eq!(
            adapter.profile_home_wire().display.as_deref(),
            profile.hermes_home.to_str()
        );
    }
}

#[test]
fn unknown_profile_is_rejected_without_fallback_or_creation() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let default_before = fs::read(fixture.default_home.join("config.yaml")).unwrap();
    let coder_before = fs::read(fixture.profiles_root.join("coder/config.yaml")).unwrap();
    let error = HermesAdapter::from_layout(
        profile_layout(
            &fixture,
            "missing",
            &fixture.layout.version,
            HermesExecutableKind::Native,
        ),
        fixture.project_id,
        DeviceId::from_str(DEVICE_ID).unwrap(),
        HybridLogicalClock::new(1_900_000_000_000, 0, DeviceId::from_str(DEVICE_ID).unwrap()),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::NotFound);
    assert!(!fixture.profiles_root.join("missing").exists());
    assert_eq!(
        fs::read(fixture.default_home.join("config.yaml")).unwrap(),
        default_before
    );
    assert_eq!(
        fs::read(fixture.profiles_root.join("coder/config.yaml")).unwrap(),
        coder_before
    );
}

#[test]
fn invalid_nested_symlinked_and_case_colliding_profiles_are_ignored() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    for name in [
        "-invalid",
        "UPPER",
        "too.long.profile",
        "a".repeat(65).as_str(),
    ] {
        fs::create_dir_all(fixture.profiles_root.join(name)).unwrap();
    }
    fs::create_dir_all(fixture.profiles_root.join("coder/child")).unwrap();
    fs::create_dir_all(fixture.profiles_root.join("Coder")).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        &fixture.profiles_root.join("writer"),
        fixture.profiles_root.join("linked"),
    )
    .unwrap();
    #[cfg(windows)]
    let _ = std::os::windows::fs::symlink_dir(
        &fixture.profiles_root.join("writer"),
        fixture.profiles_root.join("linked"),
    );
    let discovered = HermesAdapter::discover_profiles(&fixture.default_home).unwrap();
    let has_distinct_case_collision = fs::read_dir(&fixture.profiles_root)
        .unwrap()
        .filter_map(Result::ok)
        .any(|entry| entry.file_name() == "Coder");
    assert_eq!(
        discovered
            .iter()
            .map(|profile| profile.name.as_str())
            .collect::<Vec<_>>(),
        if has_distinct_case_collision {
            vec!["default", "writer"]
        } else {
            vec!["default", "coder", "writer"]
        }
    );
}

#[test]
fn adapter_cannot_be_redirected_after_construction() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let default_canary = fixture.default_home.join("do-not-read");
    let writer_canary = fixture.profiles_root.join("writer/do-not-read");
    fs::write(&default_canary, "default canary").unwrap();
    fs::write(&writer_canary, "writer canary").unwrap();
    for requested in ["writer", "default"] {
        let error = fixture
            .adapter
            .probe(&ProbeContext {
                harness: HarnessId::Hermes,
                requested_profile: Some(requested.to_owned()),
            })
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidRequest);
    }
    assert_eq!(
        fs::read_to_string(default_canary).unwrap(),
        "default canary"
    );
    assert_eq!(fs::read_to_string(writer_canary).unwrap(), "writer canary");
}

#[test]
fn working_directory_must_stay_inside_project_root() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let mut outside = fixture.layout.clone();
    outside.working_directory = fixture.root.clone();
    assert_eq!(
        HermesAdapter::from_layout(
            outside,
            fixture.project_id,
            DeviceId::from_str(DEVICE_ID).unwrap(),
            HybridLogicalClock::new(1_900_000_000_000, 0, DeviceId::from_str(DEVICE_ID).unwrap()),
        )
        .unwrap_err()
        .code,
        ErrorCode::InvalidRequest
    );
    let mut unresolved = fixture.layout.clone();
    unresolved.project_root = fixture.root.join("does-not-exist");
    assert_eq!(
        HermesAdapter::from_layout(
            unresolved,
            fixture.project_id,
            DeviceId::from_str(DEVICE_ID).unwrap(),
            HybridLogicalClock::new(1_900_000_000_000, 0, DeviceId::from_str(DEVICE_ID).unwrap()),
        )
        .unwrap_err()
        .code,
        ErrorCode::NotFound
    );
}

#[test]
fn unknown_versions_and_wrappers_are_import_only() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let mut variants = vec![
        ("9.9.9", HermesExecutableKind::Native, "hermes"),
        ("0.18.2", HermesExecutableKind::Wrapper, "hermes-script"),
        ("0.18.2", HermesExecutableKind::Wrapper, "hermes.cmd"),
        ("0.18.2", HermesExecutableKind::Wrapper, "hermes.bat"),
        ("0.18.2", HermesExecutableKind::Wrapper, "hermes.ps1"),
    ];
    for (version, kind, executable_name) in variants.drain(..) {
        let mut layout = profile_layout(&fixture, "coder", version, kind);
        layout.executable = fixture.root.join(executable_name);
        fs::write(
            &layout.executable,
            if executable_name == "hermes-script" {
                &b"#!/bin/sh\necho 0.18.2\n"[..]
            } else {
                &b"wrapper"[..]
            },
        )
        .unwrap();
        let adapter = HermesAdapter::from_layout(
            layout,
            fixture.project_id,
            DeviceId::from_str(DEVICE_ID).unwrap(),
            HybridLogicalClock::new(1_900_000_000_000, 0, DeviceId::from_str(DEVICE_ID).unwrap()),
        )
        .unwrap();
        assert_eq!(
            probe(&adapter, Some("coder")).capability,
            CapabilityLevel::ImportOnly
        );
        assert_eq!(
            adapter
                .render(&context_relay_protocol::DesiredState {
                    components: vec![],
                    scopes: vec![]
                })
                .unwrap_err()
                .code,
            ErrorCode::HarnessUnsupported
        );
    }
}

#[test]
fn from_layout_reclassifies_wrapper_bytes_claimed_as_native() {
    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let mut layout = profile_layout(
        &fixture,
        "coder",
        &fixture.layout.version,
        HermesExecutableKind::Native,
    );
    layout.executable = fixture.root.join("claimed-native-wrapper");
    fs::write(&layout.executable, b"#!/bin/sh\necho 0.18.2\n").unwrap();

    let adapter = HermesAdapter::from_layout(
        layout,
        fixture.project_id,
        DeviceId::from_str(DEVICE_ID).unwrap(),
        HybridLogicalClock::new(1_900_000_000_000, 0, DeviceId::from_str(DEVICE_ID).unwrap()),
    )
    .unwrap();

    assert_eq!(
        probe(&adapter, Some("coder")).capability,
        CapabilityLevel::ImportOnly
    );
}

#[cfg(windows)]
#[test]
fn windows_junction_profile_paths_are_rejected() {
    fn junction(link: &Path, target: &Path) {
        let status = std::process::Command::new("cmd")
            .arg("/C")
            .arg(format!(
                "mklink /J \"{}\" \"{}\"",
                link.display(),
                target.display()
            ))
            .status()
            .unwrap();
        assert!(status.success());
    }

    let fixture = fixture(include_str!("fixtures/hermes-0.18.2.json"));
    let default_junction = fixture.root.join("default-junction");
    junction(&default_junction, &fixture.default_home);
    assert_eq!(
        HermesAdapter::discover_profiles(&default_junction)
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
    fs::remove_dir(&default_junction).unwrap();

    let profiles_target = fixture.root.join("profiles-target");
    fs::rename(&fixture.profiles_root, &profiles_target).unwrap();
    junction(&fixture.profiles_root, &profiles_target);
    assert_eq!(
        HermesAdapter::discover_profiles(&fixture.default_home)
            .unwrap()
            .iter()
            .map(|profile| profile.name.as_str())
            .collect::<Vec<_>>(),
        vec!["default"]
    );
    fs::remove_dir(&fixture.profiles_root).unwrap();
    fs::rename(&profiles_target, &fixture.profiles_root).unwrap();

    let candidate_junction = fixture.profiles_root.join("fake");
    junction(&candidate_junction, &fixture.profiles_root.join("writer"));
    assert_eq!(
        HermesAdapter::discover_profiles(&fixture.default_home)
            .unwrap()
            .iter()
            .map(|profile| profile.name.as_str())
            .collect::<Vec<_>>(),
        vec!["default", "coder", "writer"]
    );
}
