use std::path::Path;
#[cfg(windows)]
use std::{ffi::OsString, os::windows::ffi::OsStringExt};

use context_relay_native_runner::{
    RestrictedEnvironment, RuleSyncFeature, RuleSyncFeatures, RuleSyncTarget, RuntimeTarget,
    SidecarCommand, SidecarId, StageDirectory, StageLayout, StagePath, WorkingDirectory,
    validate_path_set,
};

fn path(value: &str) -> StagePath {
    StagePath::try_from(value).expect("valid stage path")
}

#[test]
fn stage_paths_accept_only_unambiguous_relative_names() {
    assert_eq!(
        path("input/.rulesync/rules/main.md").as_str(),
        "input/.rulesync/rules/main.md"
    );

    for invalid in [
        "",
        "/absolute",
        "C:relative",
        "C:\\absolute",
        "\\\\server\\share",
        "\\\\?\\C:\\device",
        "input//file",
        "input/./file",
        "input/../file",
        "input\\file",
        "input/file:stream",
        "input/trailing. ",
        "input/trailing.",
        "input/control\u{001f}",
        "input/control\u{0085}",
        "input/CON",
        "input/con.txt",
        "input/COM1.json",
        "input/COM\u{00b9}",
        "input/LPT\u{00b2}",
        "input/LPT\u{00b3}.txt",
        "input/\u{ff23}\u{ff2f}\u{ff2e}",
    ] {
        assert!(
            StagePath::try_from(invalid).is_err(),
            "accepted {invalid:?}"
        );
    }

    let long_component = format!("input/{}", "a".repeat(256));
    assert!(StagePath::try_from(long_component.as_str()).is_err());
    let long = (0..20)
        .map(|_| "a".repeat(60))
        .collect::<Vec<_>>()
        .join("/");
    assert!(StagePath::try_from(long.as_str()).is_err());
}

#[test]
fn path_sets_reject_platform_aliases() {
    assert!(
        validate_path_set(
            RuntimeTarget::WindowsX86_64,
            &[path("input/Rules.md"), path("input/rules.md")],
        )
        .is_err()
    );
    assert!(
        validate_path_set(
            RuntimeTarget::MacosArm64,
            &[path("input/caf\u{00e9}.md"), path("input/cafe\u{0301}.md")],
        )
        .is_err()
    );
    assert!(
        validate_path_set(
            RuntimeTarget::WindowsX86_64,
            &[path("input/a.md"), path("input/b.md")],
        )
        .is_ok()
    );
    #[cfg(windows)]
    assert_eq!(
        validate_path_set(
            RuntimeTarget::WindowsX86_64,
            &[path("input/Σ.md"), path("input/σ.md")],
        ),
        Err(context_relay_native_runner::RunnerError::PathCollision)
    );
}

#[test]
fn closed_commands_emit_only_the_frozen_argument_arrays() {
    let features = RuleSyncFeatures::new(&[
        RuleSyncFeature::Skills,
        RuleSyncFeature::Rules,
        RuleSyncFeature::Mcp,
    ])
    .unwrap();
    let rulesync = SidecarCommand::RuleSyncGenerate {
        target: RuleSyncTarget::ClaudeCode,
        features,
    };
    assert_eq!(
        rulesync.argv(),
        [
            "rulesync",
            "generate",
            "--targets",
            "claudecode",
            "--features",
            "rules,mcp,skills",
            "--output-roots",
            "output",
            "--config",
            "rulesync.jsonc",
            "--input-root",
            "input",
            "--silent",
        ]
    );
    assert_eq!(rulesync.working_directory(), WorkingDirectory::StageRoot);
    assert_eq!(rulesync.sidecar(), SidecarId::RuleSync);

    assert_eq!(
        SidecarCommand::GitleaksScanPackage.argv(),
        [
            "gitleaks",
            "--no-banner",
            "--no-color",
            "--log-level=info",
            "--redact=100",
            "--exit-code=10",
            "--report-format=json",
            "--report-path=-",
            "--config",
            "config/gitleaks.toml",
            "--gitleaks-ignore-path",
            "config/gitleaks.empty-ignore",
            "--ignore-gitleaks-allow",
            "--max-target-megabytes=0",
            "--max-archive-depth=0",
            "--max-decode-depth=1",
            "--timeout=30",
            "--diagnostics=",
            "dir",
            "--follow-symlinks=false",
            "input/gitleaks-scan",
        ]
    );
    assert_eq!(
        SidecarCommand::GitleaksScanPackage.sidecar(),
        SidecarId::Gitleaks
    );
    assert_eq!(
        SidecarCommand::OsemgrepScanPackage.argv(),
        [
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
            "config/semgrep/package.yml",
            "input/semgrep-target",
        ]
    );
    assert_eq!(
        SidecarCommand::OsemgrepScanPackage.sidecar(),
        SidecarId::Osemgrep
    );

    for command in [
        rulesync,
        SidecarCommand::GitleaksScanPackage,
        SidecarCommand::OsemgrepScanPackage,
    ] {
        assert!(
            command
                .argv()
                .iter()
                .all(|argument| !argument.starts_with('@'))
        );
    }
    assert!(RuleSyncFeatures::new(&[]).is_err());
    assert!(RuleSyncFeatures::new(&[RuleSyncFeature::Rules, RuleSyncFeature::Rules]).is_err());
}

#[test]
fn rulesync_accepts_only_canonical_config_and_enabled_curated_inputs() {
    let without_skills = SidecarCommand::RuleSyncGenerate {
        target: RuleSyncTarget::CodexCli,
        features: RuleSyncFeatures::new(&[RuleSyncFeature::Rules]).unwrap(),
    };
    assert!(
        without_skills
            .validate_input(&path("input/.rulesync/rules/base.md"), b"safe")
            .is_ok()
    );
    for (input, bytes) in [
        ("input/rulesync.jsonc", b"{}\n".as_slice()),
        ("rulesync.jsonc", b"{}\n".as_slice()),
        ("input/rulesync.local.jsonc", b"{}\n".as_slice()),
        ("input/rulesync.jsonc", br#"{"targets":["*"]}"#.as_slice()),
        (
            "input/.rulesync/skills/unapproved/SKILL.md",
            b"safe".as_slice(),
        ),
    ] {
        assert!(
            without_skills.validate_input(&path(input), bytes).is_err(),
            "accepted {input}"
        );
    }

    let fixed_files = SidecarCommand::RuleSyncGenerate {
        target: RuleSyncTarget::ClaudeCode,
        features: RuleSyncFeatures::new(&[
            RuleSyncFeature::Ignore,
            RuleSyncFeature::Mcp,
            RuleSyncFeature::Hooks,
            RuleSyncFeature::Permissions,
        ])
        .unwrap(),
    };
    for allowed in [
        "input/.rulesync/.aiignore",
        "input/.rulesync/mcp.json",
        "input/.rulesync/hooks.json",
        "input/.rulesync/permissions.json",
    ] {
        assert!(
            fixed_files.validate_input(&path(allowed), b"{}").is_ok(),
            "rejected canonical fixed input {allowed}"
        );
    }
    for rejected in [
        "input/.rulesync/ignore/value",
        "input/.rulesync/mcp/value",
        "input/.rulesync/mcp.jsonc",
        "input/.rulesync/hooks/value",
        "input/.rulesync/permissions/value",
        "input/.rulesync/checks/value.md",
    ] {
        assert!(
            fixed_files.validate_input(&path(rejected), b"{}").is_err(),
            "accepted noncanonical input {rejected}"
        );
    }

    let invalid_codex = SidecarCommand::RuleSyncGenerate {
        target: RuleSyncTarget::CodexCli,
        features: RuleSyncFeatures::new(&[RuleSyncFeature::Ignore]).unwrap(),
    };
    assert!(invalid_codex.validate().is_err());
    let invalid_checks = SidecarCommand::RuleSyncGenerate {
        target: RuleSyncTarget::ClaudeCode,
        features: RuleSyncFeatures::new(&[RuleSyncFeature::Checks]).unwrap(),
    };
    assert!(invalid_checks.validate().is_err());

    let with_skills = SidecarCommand::RuleSyncGenerate {
        target: RuleSyncTarget::CodexCli,
        features: RuleSyncFeatures::new(&[RuleSyncFeature::Skills]).unwrap(),
    };
    assert!(
        with_skills
            .validate_input(&path("input/.rulesync/skills/approved/SKILL.md"), b"safe")
            .is_ok()
    );
    assert!(
        with_skills
            .validate_input(
                &path("input/.rulesync/skills/.curated/unapproved/SKILL.md"),
                b"safe",
            )
            .is_err()
    );
    for alias in [".CURATED", ".CuRaTeD", ".ＣＵＲＡＴＥＤ"] {
        let candidate = format!("input/.rulesync/skills/{alias}/unapproved/SKILL.md");
        assert!(
            with_skills
                .validate_input(&path(&candidate), b"safe")
                .is_err(),
            "accepted curated alias {alias}"
        );
    }

    assert!(
        without_skills
            .validate_rulesync_exit(0, b"", b"", true)
            .is_ok()
    );
    assert!(
        without_skills
            .validate_rulesync_exit(0, b"noise", b"", true)
            .is_err()
    );
    assert!(
        without_skills
            .validate_rulesync_exit(0, b"", b"warning", true)
            .is_err()
    );
    assert!(
        without_skills
            .validate_rulesync_exit(0, b"", b"", false)
            .is_err()
    );
    assert!(
        without_skills
            .validate_rulesync_exit(1, b"", b"", true)
            .is_err()
    );
}

#[test]
fn stage_environment_is_built_only_from_private_roots() {
    let root = std::env::temp_dir().join("context-relay-portable-stage-v1");
    let layout = StageLayout::new(root.clone()).unwrap();
    for directory in [
        StageDirectory::Input,
        StageDirectory::Output,
        StageDirectory::Home,
        StageDirectory::Config,
        StageDirectory::Data,
        StageDirectory::Cache,
        StageDirectory::Temp,
        StageDirectory::Runtime,
        StageDirectory::Reports,
    ] {
        assert!(layout.path(directory).starts_with(&root));
    }

    let environment =
        RestrictedEnvironment::for_stage(&layout, RuntimeTarget::WindowsX86_64).unwrap();
    for denied in [
        "AWS_SECRET_ACCESS_KEY",
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "GITHUB_TOKEN",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "GIT_CONFIG_GLOBAL",
        "SSH_AUTH_SOCK",
        "NODE_OPTIONS",
        "PYTHONPATH",
        "DYLD_INSERT_LIBRARIES",
        "LD_PRELOAD",
        "CONTEXT_RELAY_TOKEN",
    ] {
        assert!(environment.get(denied).is_none(), "inherited {denied}");
    }
    for key in [
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
        "TMP",
        "TEMP",
        "TMPDIR",
        "PATH",
    ] {
        let value = environment.get(key).expect("required private root");
        assert!(Path::new(value).starts_with(&root), "{key} escaped stage");
    }
    assert_eq!(environment.get("LANG").unwrap(), "C.UTF-8");
    assert_eq!(environment.get("LC_ALL").unwrap(), "C.UTF-8");
}

#[cfg(windows)]
#[test]
fn windows_stage_environment_adds_only_the_api_derived_system_root() {
    use windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW;

    let root = std::env::temp_dir().join("context-relay-windows-environment-v1");
    let layout = StageLayout::new(root).unwrap();
    let environment =
        RestrictedEnvironment::for_stage(&layout, RuntimeTarget::WindowsX86_64).unwrap();
    let mut keys = environment
        .iter()
        .map(|(key, _)| key.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
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
        ]
    );

    let mut buffer = vec![0_u16; 32_768];
    let length = unsafe { GetWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    assert!(length > 0 && (length as usize) < buffer.len());
    buffer.truncate(length as usize);
    assert_eq!(
        environment.get("SYSTEMROOT"),
        Some(OsString::from_wide(&buffer).as_os_str())
    );
}
