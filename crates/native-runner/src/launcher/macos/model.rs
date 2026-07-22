use std::fmt;

const BUNDLE_PREFIX: &str = "com.contextrelay.native-runner.";

pub use crate::MacRootIdentity;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GenerationId(String);

impl GenerationId {
    pub fn from_nonce(nonce: [u8; 16]) -> Self {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut value = String::with_capacity(BUNDLE_PREFIX.len() + 32);
        value.push_str(BUNDLE_PREFIX);
        for byte in nonce {
            value.push(char::from(HEX[usize::from(byte >> 4)]));
            value.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        Self(value)
    }

    pub fn parse(value: &str) -> Result<Self, MacPolicyError> {
        let suffix = value
            .strip_prefix(BUNDLE_PREFIX)
            .ok_or(MacPolicyError::InvalidGenerationId)?;
        if suffix.len() != 32
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(MacPolicyError::InvalidGenerationId);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerationState {
    Prepared,
    Active,
    Retired,
    Poisoned,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacCodeIdentity(Vec<u8>);

impl MacCodeIdentity {
    pub fn new(bytes: Vec<u8>) -> Result<Self, MacPolicyError> {
        if bytes.is_empty() || bytes.len() > 64 {
            return Err(MacPolicyError::IdentityMismatch);
        }
        Ok(Self(bytes))
    }

    pub fn matches(&self, actual: &[u8]) -> bool {
        self.0 == actual
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacCommandPaths {
    bundle: String,
    helper: String,
    entitlements: String,
}

impl MacCommandPaths {
    pub fn new(
        bundle: impl Into<String>,
        helper: impl Into<String>,
        entitlements: impl Into<String>,
    ) -> Result<Self, MacPolicyError> {
        let paths = Self {
            bundle: bundle.into(),
            helper: helper.into(),
            entitlements: entitlements.into(),
        };
        for path in [&paths.bundle, &paths.helper, &paths.entitlements] {
            validate_private_absolute_path(path)?;
        }
        if !paths.helper.starts_with(&(paths.bundle.clone() + "/")) {
            return Err(MacPolicyError::PathOutsideBundle);
        }
        Ok(paths)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacCommand {
    arguments: Vec<String>,
}

impl MacCommand {
    pub fn sign_generation(paths: &MacCommandPaths, generation: &GenerationId) -> Self {
        Self {
            arguments: vec![
                "--force".into(),
                "--sign".into(),
                "-".into(),
                "--options".into(),
                "runtime".into(),
                "--timestamp=none".into(),
                "--identifier".into(),
                generation.as_str().into(),
                "--entitlements".into(),
                paths.entitlements.clone(),
                paths.bundle.clone(),
            ],
        }
    }

    pub fn sign_sidecar(path: &str, entitlements: &str) -> Result<Self, MacPolicyError> {
        validate_private_absolute_path(path)?;
        validate_private_absolute_path(entitlements)?;
        Ok(Self {
            arguments: vec![
                "--force".into(),
                "--sign".into(),
                "-".into(),
                "--options".into(),
                "runtime".into(),
                "--timestamp=none".into(),
                "--entitlements".into(),
                entitlements.into(),
                path.into(),
            ],
        })
    }

    pub fn verify_strict(paths: &MacCommandPaths) -> Self {
        Self {
            arguments: vec![
                "--verify".into(),
                "--strict".into(),
                "--verbose=4".into(),
                paths.bundle.clone(),
            ],
        }
    }

    pub fn display_entitlements(paths: &MacCommandPaths) -> Self {
        Self {
            arguments: vec![
                "--display".into(),
                "--entitlements".into(),
                ":-".into(),
                "--xml".into(),
                paths.helper.clone(),
            ],
        }
    }

    pub fn display_identity(paths: &MacCommandPaths) -> Self {
        Self {
            arguments: vec![
                "--display".into(),
                "--verbose=4".into(),
                paths.helper.clone(),
            ],
        }
    }

    pub fn verify_path(path: &str) -> Result<Self, MacPolicyError> {
        validate_private_absolute_path(path)?;
        Ok(Self {
            arguments: vec![
                "--verify".into(),
                "--strict".into(),
                "--verbose=4".into(),
                path.into(),
            ],
        })
    }

    pub fn display_path_entitlements(path: &str) -> Result<Self, MacPolicyError> {
        validate_private_absolute_path(path)?;
        Ok(Self {
            arguments: vec![
                "--display".into(),
                "--entitlements".into(),
                ":-".into(),
                "--xml".into(),
                path.into(),
            ],
        })
    }

    pub const fn program(&self) -> &'static str {
        "/usr/bin/codesign"
    }

    pub fn arguments(&self) -> Vec<&str> {
        self.arguments.iter().map(String::as_str).collect()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacPolicyError {
    InvalidGenerationId,
    InvalidPath,
    PathOutsideBundle,
    InvalidTransition,
    InvalidEntitlements,
    InvalidMachOClosure,
    InvalidConfiguration,
    JournalFailure,
    TemplateMismatch,
    BundleIo,
    CodeSignFailed,
    IdentityMismatch,
    ProtocolIo,
    ProtocolLimitExceeded,
    ProcessFailed,
    ProcessTimedOut,
}

impl fmt::Display for MacPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for MacPolicyError {}

fn validate_private_absolute_path(path: &str) -> Result<(), MacPolicyError> {
    if !path.starts_with('/')
        || path.contains('\0')
        || path.contains('\n')
        || path.contains('\r')
        || path
            .split('/')
            .any(|component| matches!(component, "." | ".."))
        || path.ends_with('/')
    {
        return Err(MacPolicyError::InvalidPath);
    }
    Ok(())
}
