use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

use super::{ClientError, invalid_request};
use unicode_normalization::UnicodeNormalization as _;

#[derive(Clone, Debug)]
pub(super) struct ClaudeCommandContext {
    config_dir: PathBuf,
    state_path: PathBuf,
    project_root: PathBuf,
    home: PathBuf,
    overridden: bool,
}

impl ClaudeCommandContext {
    pub(super) fn new(
        config_dir: &Path,
        state_path: &Path,
        project_root: &Path,
    ) -> Result<Self, ClientError> {
        let error = || invalid_request("Claude Code configuration and state paths do not agree");
        if [config_dir, state_path, project_root]
            .into_iter()
            .any(|path| !path.is_absolute() || path.to_str().is_none())
        {
            return Err(error());
        }
        // Claude normalizes its configuration directory before reading files.
        // Reject a spelling that would make its reads disagree with ours.
        if config_dir
            .to_str()
            .is_some_and(|value| value.nfc().ne(value.chars()))
        {
            return Err(error());
        }
        let home = state_path.parent().ok_or_else(error)?;
        let overridden = state_path == config_dir.join(".claude.json");
        if !overridden
            && (config_dir != home.join(".claude") || state_path != home.join(".claude.json"))
        {
            return Err(error());
        }
        Ok(Self {
            config_dir: config_dir.to_owned(),
            state_path: state_path.to_owned(),
            project_root: project_root.to_owned(),
            home: home.to_owned(),
            overridden,
        })
    }

    pub(super) fn validate(&self) -> Result<(), ClientError> {
        let error = || invalid_request("Claude Code configuration binding changed or is unsafe");
        for path in [&self.config_dir, &self.state_path, &self.project_root] {
            super::mcp_state::validate_config_path(path, true).map_err(|_| error())?;
        }
        if !self.project_root.is_dir() {
            return Err(error());
        }
        // The installed CLI gives this legacy file precedence over .claude.json.
        // Do not let its appearance redirect an already selected state target.
        match fs::symlink_metadata(self.config_dir.join(".config.json")) {
            Err(failure) if failure.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err(error()),
        }
        Ok(())
    }

    pub(super) fn approval_binding(&self) -> crate::native_transaction::CliExecutionContext {
        crate::native_transaction::CliExecutionContext::ClaudeCodeV1 {
            config_dir: super::wire_path(&self.config_dir),
            state_path: super::wire_path(&self.state_path),
            project_root: super::wire_path(&self.project_root),
        }
    }

    pub(super) fn configure(
        &self,
        command: &mut Command,
        arguments: &[&str],
    ) -> Result<(), ClientError> {
        // Version discovery does not load or mutate configuration. It can still
        // report an import-only installation with an unsupported legacy state.
        if arguments != ["--version"] {
            self.validate()?;
        }
        command
            .env_clear()
            .current_dir(&self.project_root)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("APPDATA", self.home.join("AppData/Roaming"))
            .env("LOCALAPPDATA", self.home.join("AppData/Local"))
            .env("TEMP", env::temp_dir())
            .env("TMP", env::temp_dir())
            .env("TERM", "dumb")
            .env("NO_COLOR", "1")
            .env("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1")
            .env("DISABLE_AUTOUPDATER", "1");
        if self.overridden {
            command.env("CLAUDE_CONFIG_DIR", &self.config_dir);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt as _;
            let error = || invalid_request("Claude Code command environment is unavailable");
            let system = env::var_os("SystemRoot")
                .filter(|value| Path::new(value).is_absolute())
                .ok_or_else(error)?;
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
    use std::fs;

    #[test]
    fn context_child() {
        if std::env::var_os("CONTEXT_RELAY_CONTEXT_PROBE").is_none() {
            return;
        }
        println!(
            "CONTEXT_PROBE={}",
            json!({
                "cwd": std::env::current_dir().unwrap(),
                "home": std::env::var_os("HOME"),
                "profile": std::env::var_os("USERPROFILE"),
                "config": std::env::var_os("CLAUDE_CONFIG_DIR"),
                "ambient": std::env::var_os("INHERITED_CANARY"),
                "preload": std::env::var_os("NODE_OPTIONS"),
            })
        );
    }

    #[test]
    fn commands_use_the_selected_configuration_and_project_without_ambient_overrides() {
        let root = tempfile::tempdir().unwrap();
        let root_path = fs::canonicalize(root.path()).unwrap();
        for overridden in [false, true] {
            let home = root_path.join(if overridden { "override" } else { "home" });
            let config = if overridden {
                home.clone()
            } else {
                home.join(".claude")
            };
            let state = home.join(".claude.json");
            let project = root_path.join("selected project 專案");
            fs::create_dir_all(&config).unwrap();
            fs::create_dir_all(&project).unwrap();
            let context = ClaudeCommandContext::new(&config, &state, &project).unwrap();
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "claude_code::command_context::tests::context_child",
                    "--nocapture",
                ])
                .current_dir(&root_path)
                .env("CLAUDE_CONFIG_DIR", root_path.join("wrong-config"))
                .env("INHERITED_CANARY", "must-not-survive")
                .env("NODE_OPTIONS", "--require wrong-preload.js");
            context.configure(&mut command, &[]).unwrap();
            command.env("CONTEXT_RELAY_CONTEXT_PROBE", "1");
            let output = command.output().unwrap();
            assert!(output.status.success());
            let text = String::from_utf8(output.stdout).unwrap();
            let value: Value = serde_json::from_str(
                text.lines()
                    .find_map(|line| line.strip_prefix("CONTEXT_PROBE="))
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                fs::canonicalize(Path::new(value["cwd"].as_str().unwrap())).unwrap(),
                project
            );
            // OsString's JSON representation is platform-specific; compare to
            // independently selected fixture paths, not a context getter.
            assert_eq!(
                value["home"],
                serde_json::to_value(home.as_os_str()).unwrap()
            );
            assert_eq!(
                value["profile"],
                serde_json::to_value(home.as_os_str()).unwrap()
            );
            assert_eq!(
                value["config"],
                if overridden {
                    serde_json::to_value(config.as_os_str()).unwrap()
                } else {
                    Value::Null
                }
            );
            assert_eq!(value["ambient"], Value::Null);
            assert_eq!(value["preload"], Value::Null);
        }
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "requires an explicitly selected, digest-pinned installed Claude CLI"]
    fn pinned_claude_cli_uses_selected_configuration_and_validates_installed_plugin() {
        use sha2::{Digest as _, Sha256};
        let executable = PathBuf::from(
            env::var_os("CONTEXT_RELAY_TEST_CLAUDE_EXE").expect("explicit Claude executable"),
        );
        let expected =
            env::var("CONTEXT_RELAY_TEST_CLAUDE_SHA256").expect("explicit Claude digest");
        let actual = Sha256::digest(fs::read(&executable).unwrap());
        assert_eq!(format!("{actual:x}"), expected);
        let hash = super::super::digest_file(&executable).unwrap();
        let root = tempfile::tempdir().unwrap();
        let physical = fs::canonicalize(root.path()).unwrap();
        let server = format!("context-relay-qualification-{}", std::process::id());
        for overridden in [false, true] {
            let home = physical.join(if overridden { "override" } else { "home" });
            let config = if overridden {
                home.clone()
            } else {
                home.join(".claude")
            };
            let state = home.join(".claude.json");
            let project = physical.join(if overridden {
                "override project 專案"
            } else {
                "default project 專案"
            });
            fs::create_dir_all(&config).unwrap();
            fs::create_dir_all(&project).unwrap();
            let context = ClaudeCommandContext::new(&config, &state, &project).unwrap();
            let body = json!({"type":"stdio", "command": physical.join("inert-missing-bridge.exe"), "args":["--harness","claude-code"]});
            let encoded = serde_json::to_string(&body).unwrap();
            super::super::run_bounded_command(
                &executable,
                &["mcp", "add-json", &server, &encoded, "--scope", "local"],
                hash,
                &context,
            )
            .unwrap();
            let saved: Value = serde_json::from_slice(
                &fs::read(&state).expect("CLI must write inside the selected temporary home"),
            )
            .unwrap();
            let key = project
                .to_str()
                .unwrap()
                .strip_prefix(r"\\?\")
                .unwrap()
                .replace('\\', "/");
            assert_eq!(saved["projects"][&key]["mcpServers"][&server], body);
            super::super::run_bounded_command(
                &executable,
                &["mcp", "remove", &server, "--scope", "local"],
                hash,
                &context,
            )
            .unwrap();
            let saved: Value = serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
            assert!(saved["projects"][&key]["mcpServers"].get(&server).is_none());
            let marketplace = home.join("local-fixture-marketplace");
            let plugin = marketplace.join("plugins/relay-probe");
            fs::create_dir_all(marketplace.join(".claude-plugin")).unwrap();
            fs::create_dir_all(plugin.join(".claude-plugin")).unwrap();
            fs::create_dir_all(plugin.join("skills/probe")).unwrap();
            fs::write(marketplace.join(".claude-plugin/marketplace.json"), serde_json::to_vec(&json!({
                "name":"relay-qualification", "owner":{"name":"Local test fixture"},
                "plugins":[{"name":"relay-probe", "source":"./plugins/relay-probe", "description":"Static qualification fixture"}]
            })).unwrap()).unwrap();
            fs::write(plugin.join(".claude-plugin/plugin.json"), br#"{"name":"relay-probe","version":"1.0.0","description":"Static qualification fixture"}"#).unwrap();
            fs::write(
                plugin.join("skills/probe/SKILL.md"),
                "---\ndescription: Static qualification fixture\n---\nThis is a test note.\n",
            )
            .unwrap();
            let version_output =
                super::super::run_bounded_command(&executable, &["--version"], hash, &context)
                    .unwrap();
            assert_eq!(
                super::super::parse_version_output(&version_output).unwrap(),
                "2.1.202"
            );
            // Claude's marketplace parser rejects a Windows verbatim prefix
            // even though it names the same physical local directory.
            let marketplace_argument = marketplace.to_str().unwrap().strip_prefix(r"\\?\").unwrap();
            for arguments in [
                vec![
                    "plugin",
                    "marketplace",
                    "add",
                    marketplace_argument,
                    "--scope",
                    "user",
                ],
                vec![
                    "plugin",
                    "install",
                    "relay-probe@relay-qualification",
                    "--scope",
                    "user",
                ],
            ] {
                super::super::run_bounded_command(&executable, &arguments, hash, &context).unwrap();
            }
            let output = super::super::run_bounded_command(
                &executable,
                &["plugin", "list", "--json"],
                hash,
                &context,
            )
            .unwrap();
            super::super::parse_plugin_list_output(&output).unwrap();
            let plugins: Value = serde_json::from_slice(&output).unwrap();
            assert_eq!(plugins.as_array().unwrap().len(), 1);
            assert_eq!(plugins[0]["id"], "relay-probe@relay-qualification");
            println!(
                "Qualified {} configuration and installed-plugin validation with the real pinned CLI",
                if overridden { "override" } else { "default" }
            );
        }
    }

    #[test]
    fn commands_reject_an_unrepresentable_configuration_binding() {
        let root = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(root.path()).unwrap();
        let config = root.join("custom");
        let state = root.join("elsewhere/.claude.json");
        assert!(ClaudeCommandContext::new(&config, &state, &root).is_err());
    }

    #[test]
    fn commands_reject_configuration_paths_the_cli_would_normalize() {
        let root = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(root.path()).unwrap();
        let config = root.join("cafe\u{301}");
        assert!(ClaudeCommandContext::new(&config, &config.join(".claude.json"), &root).is_err());
    }

    #[test]
    fn commands_recheck_legacy_state_precedence_before_launch() {
        let root = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(root.path()).unwrap();
        let config = root.join(".claude");
        fs::create_dir(&config).unwrap();
        let context =
            ClaudeCommandContext::new(&config, &root.join(".claude.json"), &root).unwrap();
        fs::write(config.join(".config.json"), b"{}").unwrap();
        let mut command = Command::new("must-not-run");
        assert!(
            context
                .configure(&mut command, &["mcp", "add-json"])
                .is_err()
        );
    }
}
