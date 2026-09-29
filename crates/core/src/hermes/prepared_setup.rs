//! Passive setup planning with ownership of the exact captured Python runtime.
use super::{HermesAdapter, conflict, python_runtime::retained::PreparedRuntime};
use crate::{
    native_transaction::InstalledRuntimeBinding,
    setup::{BridgeInstallService, BridgeLocator, RegisteredProject},
    vault::Vault,
};
use context_relay_protocol::{CapabilityLevel, ClientError, SetupPlan};

/// This object can only produce a preview. Its private adapter has no runtime
/// execution authority, and unused copies retain automatic cleanup ownership.
#[derive(Debug)]
pub struct PreparedHermesSetup {
    adapter: HermesAdapter,
    runtime: PreparedRuntime,
}

impl HermesAdapter {
    pub fn into_setup_preview(
        mut self,
        runtime: PreparedRuntime,
    ) -> Result<PreparedHermesSetup, ClientError> {
        self.revalidate_bound_installation()?;
        if self.retained_runtime.is_some()
            || self.preview_runtime.is_some()
            || self.layout.version != "0.17.0"
            || !runtime.manifest().files.iter().any(|file| {
                file.path == "metadata/hermes-launcher.exe" && file.sha256 == self.executable_hash
            })
        {
            return Err(conflict(
                "Hermes prepared runtime does not match this installation",
            ));
        }
        self.preview_runtime = Some(Box::new(InstalledRuntimeBinding::HermesPythonV1 {
            runtime: runtime.reference().clone(),
        }));
        if self.capability() != CapabilityLevel::Full {
            return Err(conflict(
                "Hermes configuration cannot be prepared for setup",
            ));
        }
        Ok(PreparedHermesSetup {
            adapter: self,
            runtime,
        })
    }
}

impl PreparedHermesSetup {
    /// Does not launch either the copied runtime or the ordinary installation.
    /// If the vault's commit acknowledgement fails, the now-durable copy stays:
    /// deleting it could invalidate a plan that actually committed.
    pub fn preview(
        self,
        vault: &mut Vault,
        locator: impl BridgeLocator,
        project: &RegisteredProject,
        now_ms: u64,
    ) -> Result<SetupPlan, ClientError> {
        let Self { adapter, runtime } = self;
        adapter.revalidate_bound_installation()?;
        let device = adapter.origin_device;
        let clock = adapter.observed_hlc;
        BridgeInstallService::new(vault, adapter, locator, device, clock).preview_before_persist(
            Some(project),
            now_ms,
            move || {
                let _ = runtime.persist();
            },
        )
    }
}
