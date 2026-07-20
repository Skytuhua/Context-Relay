#[path = "../../../src/macos_identity.rs"]
pub mod macos_identity;
pub use macos_identity::MacRootIdentity;

#[path = "../../../src/launcher/macos/model.rs"]
pub mod model;
#[path = "../../../src/launcher/macos/policy.rs"]
pub mod policy;

#[cfg(target_os = "macos")]
pub mod macos {
    pub use crate::model::{MacCodeIdentity, MacPolicyError};
}

#[cfg(target_os = "macos")]
#[path = "../../../src/macos_spawn.rs"]
pub mod macos_spawn;

#[cfg(target_os = "macos")]
#[path = "../../../src/launcher/macos/native.rs"]
pub mod native;
