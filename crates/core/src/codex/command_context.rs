use std::{env, fs, path::PathBuf, process::Command};

use super::{ClientError, CodexLayout, invalid, wire_path};
use crate::native_transaction::CliExecutionContext;

/// The selected profile and project travel with the verified executable.
#[derive(Clone, Debug)]
pub(super) struct CodexCommandContext {
    codex_home: PathBuf,
    user_home: PathBuf,
    project_root: PathBuf,
    pub(super) working_directory: PathBuf,
}

impl CodexCommandContext {
    pub(super) fn new(layout: &CodexLayout) -> Result<Self, ClientError> {
        let context = Self {
            codex_home: layout.codex_home.clone(),
            user_home: layout.user_home.clone(),
            project_root: layout.project_root.clone(),
            working_directory: layout.working_directory.clone(),
        };
        context.validate()?;
        Ok(context)
    }

    pub(super) fn validate(&self) -> Result<(), ClientError> {
        let error = || invalid("Codex configuration binding changed or is unsafe");
        for path in [
            &self.codex_home,
            &self.user_home,
            &self.project_root,
            &self.working_directory,
        ] {
            if !path.is_absolute()
                || path.to_str().is_none()
                || !path.is_dir()
                || fs::canonicalize(path).map_err(|_| error())? != *path
            {
                return Err(error());
            }
        }
        if !self.working_directory.starts_with(&self.project_root) {
            return Err(error());
        }
        Ok(())
    }

    pub(super) fn approval_binding(&self) -> CliExecutionContext {
        CliExecutionContext::CodexV1 {
            codex_home: wire_path(&self.codex_home),
            user_home: wire_path(&self.user_home),
            project_root: wire_path(&self.project_root),
            working_directory: wire_path(&self.working_directory),
        }
    }

    pub(super) fn configure(&self, command: &mut Command) -> Result<(), ClientError> {
        self.validate()?;
        command
            .env_clear()
            .current_dir(&self.working_directory)
            .env("CODEX_HOME", &self.codex_home)
            .env("HOME", &self.user_home)
            .env("USERPROFILE", &self.user_home)
            .env("APPDATA", self.user_home.join("AppData/Roaming"))
            .env("LOCALAPPDATA", self.user_home.join("AppData/Local"))
            .env("TEMP", env::temp_dir())
            .env("TMP", env::temp_dir())
            .env("TERM", "dumb")
            .env("NO_COLOR", "1");
        #[cfg(windows)]
        {
            use std::{os::windows::process::CommandExt as _, path::Path};
            let system = env::var_os("SystemRoot")
                .filter(|value| Path::new(value).is_absolute())
                .ok_or_else(|| invalid("Codex command environment is unavailable"))?;
            command
                .env("SystemRoot", &system)
                .env("WINDIR", &system)
                .env("PATH", Path::new(&system).join("System32"))
                .creation_flags(0x0800_0000);
        }
        #[cfg(not(windows))]
        command.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    #[test]
    fn echo_context() {
        if env::var_os("CONTEXT_RELAY_CODEX_CONTEXT_PROBE").is_none() {
            return;
        }
        println!(
            "CONTEXT_PROBE={}",
            json!({
                "home": env::var_os("HOME"), "profile": env::var_os("USERPROFILE"),
                "config": env::var_os("CODEX_HOME"), "cwd": env::current_dir().unwrap(),
                "ambient": env::var_os("INHERITED_CANARY"), "preload": env::var_os("NODE_OPTIONS"),
                "configOverride": env::var_os("XDG_CONFIG_HOME"),
            })
        );
    }

    #[test]
    fn subprocess_context_discards_ambient_configuration_and_preloads() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let context = CodexCommandContext {
            codex_home: root.join("custom config 專案"),
            user_home: root.join("home"),
            project_root: root.join("project"),
            working_directory: root.join("project/service"),
        };
        for path in [
            &context.codex_home,
            &context.user_home,
            &context.working_directory,
        ] {
            fs::create_dir_all(path).unwrap();
        }
        let mut command = Command::new(env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "codex::command_context::tests::echo_context",
                "--nocapture",
            ])
            .env("CODEX_HOME", root.join("wrong"))
            .env("INHERITED_CANARY", "must-not-survive")
            .env("XDG_CONFIG_HOME", root.join("other"))
            .env("NODE_OPTIONS", "--require wrong-preload.js");
        context.configure(&mut command).unwrap();
        command.env("CONTEXT_RELAY_CODEX_CONTEXT_PROBE", "1");
        let output = command.output().unwrap();
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        let actual: Value = serde_json::from_str(
            text.lines()
                .find_map(|line| line.strip_prefix("CONTEXT_PROBE="))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            actual["home"],
            serde_json::to_value(context.user_home.as_os_str()).unwrap()
        );
        assert_eq!(actual["profile"], actual["home"]);
        assert_eq!(
            actual["config"],
            serde_json::to_value(context.codex_home.as_os_str()).unwrap()
        );
        assert_eq!(
            fs::canonicalize(actual["cwd"].as_str().unwrap()).unwrap(),
            context.working_directory
        );
        for key in ["ambient", "preload", "configOverride"] {
            assert_eq!(actual[key], Value::Null);
        }
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "requires explicitly selected Codex 0.144.6; writes only disposable profiles"]
    fn pinned_codex_cli_reads_and_writes_only_the_selected_profile() {
        use super::super::{CodexAdapter, CodexExecutableKind};
        use context_relay_protocol::{DeviceId, HybridLogicalClock, InstallationMethod, ProjectId};
        use sha2::{Digest as _, Sha256};

        const HASH: &str = "4b76ded066d0239115ca97473d010c92072bc5c5550a45dd7cbebe1e9eb956a7";
        let executable = PathBuf::from(
            env::var_os("CONTEXT_RELAY_TEST_CODEX_EXE").expect("explicit Codex executable"),
        );
        if env::var_os("CONTEXT_RELAY_CODEX_CONTEXT_CHILD").is_none() {
            use std::{process::Stdio, time::Duration};
            let outer = tempfile::tempdir().unwrap();
            let ambient = outer.path().join("ambient profile");
            fs::create_dir(&ambient).unwrap();
            let scratch = outer.path().join("scratch");
            fs::create_dir(&scratch).unwrap();
            let original = b"[mcp_servers.ambient]\ncommand = 'must-not-be-used'\n";
            fs::write(ambient.join("config.toml"), original).unwrap();
            let stdout = outer.path().join("stdout");
            let stderr = outer.path().join("stderr");
            let mut child = Command::new(env::current_exe().unwrap());
            child.env_clear();
            for key in ["SystemRoot", "WINDIR"] {
                if let Some(value) = env::var_os(key) {
                    child.env(key, value);
                }
            }
            child.args(["--exact", "codex::command_context::tests::pinned_codex_cli_reads_and_writes_only_the_selected_profile", "--ignored", "--nocapture"])
                .env("CONTEXT_RELAY_CODEX_CONTEXT_CHILD", "1")
                .env("CONTEXT_RELAY_TEST_CODEX_EXE", &executable)
                .env("CODEX_HOME", &ambient).env("HOME", &ambient).env("USERPROFILE", &ambient)
                .env("TEMP", &scratch).env("TMP", &scratch)
                .current_dir(outer.path()).stdin(Stdio::piped())
                .stdout(fs::File::create(&stdout).unwrap()).stderr(fs::File::create(&stderr).unwrap());
            let result =
                crate::test_windows_process::run_in_owned_job(&mut child, Duration::from_secs(90));
            assert!(
                result.is_ok_and(|status| status.success()),
                "stdout: {}\nstderr: {}",
                fs::read_to_string(&stdout).unwrap(),
                fs::read_to_string(stderr).unwrap()
            );
            assert_eq!(fs::read(ambient.join("config.toml")).unwrap(), original);
            println!("{}", fs::read_to_string(stdout).unwrap());
            return;
        }
        use std::io::Read as _;
        let mut gate = String::new();
        std::io::stdin().read_to_string(&mut gate).unwrap();
        assert_eq!(gate, "run");
        assert_eq!(
            format!("{:x}", Sha256::digest(fs::read(&executable).unwrap())),
            HASH
        );
        // Codex refuses PATH helper aliases inside its process TEMP. Keep the
        // disposable profiles beside the isolated scratch directory.
        let temp = tempfile::tempdir_in(env::current_dir().unwrap()).unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let peer = root.join("other profile");
        fs::create_dir(&peer).unwrap();
        let peer_config = b"# Another profile must remain unchanged\n[mcp_servers.other]\ncommand = 'inert-other'\n";
        fs::write(peer.join("config.toml"), peer_config).unwrap();
        for custom in [false, true] {
            let home = root.join(if custom {
                "custom home 專案"
            } else {
                "default home"
            });
            let config = if custom {
                root.join("separate config O'Brien & [literal]")
            } else {
                home.join(".codex")
            };
            let project = root.join(if custom {
                "custom project"
            } else {
                "default project"
            });
            for path in [&home, &config, &project] {
                fs::create_dir_all(path).unwrap();
            }
            fs::write(
                config.join("config.toml"),
                "# Preserve unrelated settings\n[mcp_servers.keep]\ncommand = 'inert-keep'\n",
            )
            .unwrap();
            let device: DeviceId = "018f22e2-79b0-7cc8-98c4-dc0c0c073982".parse().unwrap();
            let adapter = CodexAdapter::from_layout(
                CodexLayout {
                    executable: executable.clone(),
                    executable_kind: CodexExecutableKind::Native,
                    version: "0.144.6".into(),
                    installation_method: InstallationMethod::Manual,
                    codex_home: config.clone(),
                    user_home: home.clone(),
                    user_skills_dir: home.join(".agents/skills"),
                    project_root: project.clone(),
                    working_directory: project,
                    requirements_paths: vec![],
                },
                "018f22e2-79b0-7cc8-98c4-dc0c0c073981"
                    .parse::<ProjectId>()
                    .unwrap(),
                device,
                HybridLogicalClock::new(1_900_000_000_000, 0, device),
            )
            .unwrap();
            let run = |args: &[&str]| {
                adapter
                    .run_verified(
                        &mut adapter.process_runner(),
                        &args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>(),
                    )
                    .unwrap()
            };
            let initial: Value = serde_json::from_slice(&run(&["mcp", "list", "--json"])).unwrap();
            assert_eq!(initial.as_array().unwrap().len(), 1);
            assert_eq!(initial[0]["name"], "keep");
            run(&["mcp", "add", "context-relay-test", "--", "inert-selected"]);
            let actual: Value =
                serde_json::from_slice(&run(&["mcp", "get", "context-relay-test", "--json"]))
                    .unwrap();
            assert_eq!(actual["transport"]["command"], "inert-selected");
            let saved = fs::read_to_string(config.join("config.toml")).unwrap();
            assert!(saved.contains("[mcp_servers.context-relay-test]"));
            let saved: toml_edit::DocumentMut = saved.parse().unwrap();
            assert_eq!(
                saved["mcp_servers"]["keep"]["command"].as_str(),
                Some("inert-keep")
            );
            run(&["mcp", "remove", "context-relay-test"]);
            let final_state: Value =
                serde_json::from_slice(&run(&["mcp", "list", "--json"])).unwrap();
            assert_eq!(final_state, initial);
            assert_eq!(fs::read(peer.join("config.toml")).unwrap(), peer_config);
            if custom {
                assert!(!home.join(".codex/config.toml").exists());
            }
        }
        assert_eq!(
            format!("{:x}", Sha256::digest(fs::read(executable).unwrap())),
            HASH
        );
    }
}
