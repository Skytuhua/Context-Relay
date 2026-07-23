use crate::{RunnerError, SidecarId, StagePath};
use unicode_normalization::UnicodeNormalization;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleSyncTarget {
    ClaudeCode,
    CodexCli,
}

impl RuleSyncTarget {
    pub(crate) const fn argument(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claudecode",
            Self::CodexCli => "codexcli",
        }
    }

    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::ClaudeCode => 0,
            Self::CodexCli => 1,
        }
    }

    pub(crate) const fn from_code(value: u8) -> Result<Self, RunnerError> {
        match value {
            0 => Ok(Self::ClaudeCode),
            1 => Ok(Self::CodexCli),
            _ => Err(RunnerError::InvalidFrame),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleSyncFeature {
    Rules,
    Ignore,
    Mcp,
    Subagents,
    Commands,
    Skills,
    Hooks,
    Permissions,
    Checks,
}

impl RuleSyncFeature {
    const ALL: [Self; 9] = [
        Self::Rules,
        Self::Ignore,
        Self::Mcp,
        Self::Subagents,
        Self::Commands,
        Self::Skills,
        Self::Hooks,
        Self::Permissions,
        Self::Checks,
    ];

    const fn bit(self) -> u16 {
        1 << self as u8
    }

    const fn argument(self) -> &'static str {
        match self {
            Self::Rules => "rules",
            Self::Ignore => "ignore",
            Self::Mcp => "mcp",
            Self::Subagents => "subagents",
            Self::Commands => "commands",
            Self::Skills => "skills",
            Self::Hooks => "hooks",
            Self::Permissions => "permissions",
            Self::Checks => "checks",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuleSyncFeatures(u16);

impl RuleSyncFeatures {
    pub fn new(features: &[RuleSyncFeature]) -> Result<Self, RunnerError> {
        let mut bits = 0_u16;
        for feature in features {
            let bit = feature.bit();
            if bits & bit != 0 {
                return Err(RunnerError::InvalidCommand);
            }
            bits |= bit;
        }
        (bits != 0)
            .then_some(Self(bits))
            .ok_or(RunnerError::InvalidCommand)
    }

    pub(crate) const fn contains(self, feature: RuleSyncFeature) -> bool {
        self.0 & feature.bit() != 0
    }

    fn argument(self) -> String {
        RuleSyncFeature::ALL
            .into_iter()
            .filter(|feature| self.contains(*feature))
            .map(RuleSyncFeature::argument)
            .collect::<Vec<_>>()
            .join(",")
    }

    pub(crate) const fn bits(self) -> u16 {
        self.0
    }

    pub(crate) const fn from_bits(bits: u16) -> Result<Self, RunnerError> {
        const VALID_BITS: u16 = (1 << 9) - 1;
        if bits == 0 || bits & !VALID_BITS != 0 {
            return Err(RunnerError::InvalidFrame);
        }
        Ok(Self(bits))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkingDirectory {
    StageRoot,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SidecarCommand {
    RuleSyncGenerate {
        target: RuleSyncTarget,
        features: RuleSyncFeatures,
    },
    GitleaksScanPackage,
    OsemgrepScanPackage,
}

impl SidecarCommand {
    pub fn validate(&self) -> Result<(), RunnerError> {
        match self {
            Self::RuleSyncGenerate { target, features } => {
                if features.contains(RuleSyncFeature::Checks)
                    || (*target == RuleSyncTarget::CodexCli
                        && features.contains(RuleSyncFeature::Ignore))
                {
                    return Err(RunnerError::InvalidCommand);
                }
                Ok(())
            }
            Self::GitleaksScanPackage | Self::OsemgrepScanPackage => Ok(()),
        }
    }

    pub const fn sidecar(&self) -> SidecarId {
        match self {
            Self::RuleSyncGenerate { .. } => SidecarId::RuleSync,
            Self::GitleaksScanPackage => SidecarId::Gitleaks,
            Self::OsemgrepScanPackage => SidecarId::Osemgrep,
        }
    }

    pub const fn template_id(&self) -> &'static str {
        match self {
            Self::RuleSyncGenerate { .. } => "rulesync-generate-v1",
            Self::GitleaksScanPackage => "gitleaks-dir-v1",
            Self::OsemgrepScanPackage => "osemgrep-scan-v1",
        }
    }

    pub fn normalized_arguments(&self) -> Vec<String> {
        let mut argv = self.argv();
        argv.remove(0);
        argv
    }

    pub fn argv(&self) -> Vec<String> {
        match self {
            Self::RuleSyncGenerate { target, features } => [
                "rulesync".to_owned(),
                "generate".to_owned(),
                "--targets".to_owned(),
                target.argument().to_owned(),
                "--features".to_owned(),
                features.argument(),
                "--output-roots".to_owned(),
                "output".to_owned(),
                "--config".to_owned(),
                "rulesync.jsonc".to_owned(),
                "--input-root".to_owned(),
                "input".to_owned(),
                "--silent".to_owned(),
            ]
            .into(),
            Self::GitleaksScanPackage => [
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
            .map(str::to_owned)
            .into(),
            Self::OsemgrepScanPackage => [
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
                "--time",
                "--x-parmap",
                "--jobs=1",
                "--timeout=30",
                "--timeout-threshold=1",
                "--max-target-bytes=8388608",
                "--config",
                "config/semgrep/package.yml",
                "input/semgrep-target",
            ]
            .map(str::to_owned)
            .into(),
        }
    }

    pub const fn working_directory(&self) -> WorkingDirectory {
        WorkingDirectory::StageRoot
    }

    pub fn validate_input(&self, path: &StagePath, bytes: &[u8]) -> Result<(), RunnerError> {
        match self {
            Self::RuleSyncGenerate { features, .. } => {
                let relative = path
                    .as_str()
                    .strip_prefix("input/.rulesync/")
                    .ok_or(RunnerError::InvalidCommand)?;
                if relative.split('/').any(|component| {
                    component
                        .nfkc()
                        .flat_map(char::to_lowercase)
                        .eq(".curated".chars())
                }) {
                    return Err(RunnerError::InvalidCommand);
                }
                let feature = rulesync_input_feature(relative)?;
                if !features.contains(feature)
                    || bytes.is_empty()
                    || std::str::from_utf8(bytes).is_err()
                {
                    return Err(RunnerError::InvalidCommand);
                }
                if matches!(
                    feature,
                    RuleSyncFeature::Mcp | RuleSyncFeature::Hooks | RuleSyncFeature::Permissions
                ) && !serde_json::from_slice::<serde_json::Value>(bytes)
                    .ok()
                    .and_then(|value| value.as_object().map(|_| ()))
                    .is_some()
                {
                    return Err(RunnerError::InvalidCommand);
                }
                Ok(())
            }
            Self::GitleaksScanPackage => path
                .as_str()
                .strip_prefix("input/gitleaks-scan/payload/")
                .filter(|relative| !relative.is_empty())
                .map(|_| ())
                .ok_or(RunnerError::InvalidCommand),
            Self::OsemgrepScanPackage => path
                .as_str()
                .strip_prefix("input/semgrep-target/")
                .filter(|relative| !relative.is_empty())
                .map(|_| ())
                .ok_or(RunnerError::InvalidCommand),
        }
    }

    pub fn validate_inputs(&self, inputs: &[crate::ContentFrame]) -> Result<(), RunnerError> {
        self.validate()?;
        if let Self::RuleSyncGenerate { features, .. } = self {
            let present = inputs.iter().try_fold(0_u16, |bits, input| {
                let relative = input
                    .path()
                    .as_str()
                    .strip_prefix("input/.rulesync/")
                    .ok_or(RunnerError::InvalidCommand)?;
                Ok::<_, RunnerError>(bits | rulesync_input_feature(relative)?.bit())
            })?;
            if RuleSyncFeature::ALL
                .into_iter()
                .any(|feature| features.contains(feature) != (present & feature.bit() != 0))
            {
                return Err(RunnerError::InvalidCommand);
            }
        }
        Ok(())
    }

    pub fn validate_rulesync_exit(
        &self,
        exit_code: i32,
        stdout: &[u8],
        stderr: &[u8],
        output_complete: bool,
    ) -> Result<(), RunnerError> {
        matches!(self, Self::RuleSyncGenerate { .. })
            .then_some(())
            .filter(|_| exit_code == 0 && stdout.is_empty() && stderr.is_empty() && output_complete)
            .ok_or(RunnerError::InvalidToolOutput)
    }
}

pub(crate) fn rulesync_input_feature(relative: &str) -> Result<RuleSyncFeature, RunnerError> {
    match relative {
        ".aiignore" => Ok(RuleSyncFeature::Ignore),
        "mcp.json" => Ok(RuleSyncFeature::Mcp),
        "hooks.json" => Ok(RuleSyncFeature::Hooks),
        "permissions.json" => Ok(RuleSyncFeature::Permissions),
        _ => {
            let (directory, child) = relative
                .split_once('/')
                .filter(|(_, child)| !child.is_empty())
                .ok_or(RunnerError::InvalidCommand)?;
            let feature = match directory {
                "rules" if child.ends_with(".md") => RuleSyncFeature::Rules,
                "subagents" if child.ends_with(".md") => RuleSyncFeature::Subagents,
                "commands" if child.ends_with(".md") => RuleSyncFeature::Commands,
                "skills" if child.contains('/') => RuleSyncFeature::Skills,
                _ => return Err(RunnerError::InvalidCommand),
            };
            Ok(feature)
        }
    }
}
