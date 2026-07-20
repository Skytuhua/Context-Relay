#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use context_relay_native_runner::macos::{
    GenerationId, GenerationJournal, GenerationState, MacOsSandboxLauncher, MacPolicyError,
    SignedGeneration,
};

#[test]
fn production_launcher_is_available_only_with_a_durable_generation_journal() {
    fn accepts_launcher<J: GenerationJournal>(_: &MacOsSandboxLauncher<J>) {}
    let _ = accepts_launcher::<CompileJournal>;
}

struct CompileJournal;

impl GenerationJournal for CompileJournal {
    fn reserve(&self, _id: &GenerationId) -> Result<(), MacPolicyError> {
        Ok(())
    }

    fn bind_guardian(&self, _id: &GenerationId, _pgid: i32) -> Result<(), MacPolicyError> {
        Ok(())
    }

    fn bind_bundle_root(
        &self,
        _id: &GenerationId,
        _bundle: &context_relay_native_runner::macos::MacRootIdentity,
    ) -> Result<(), MacPolicyError> {
        Ok(())
    }

    fn finalize(&self, _generation: &SignedGeneration) -> Result<(), MacPolicyError> {
        Ok(())
    }

    fn bind_container_root(
        &self,
        _id: &GenerationId,
        _container: &context_relay_native_runner::macos::MacRootIdentity,
    ) -> Result<(), MacPolicyError> {
        Ok(())
    }

    fn transition(
        &self,
        _id: &GenerationId,
        _from: GenerationState,
        _to: GenerationState,
    ) -> Result<(), MacPolicyError> {
        Ok(())
    }

    fn poison_interrupted_after_restart(&self) -> Result<(), MacPolicyError> {
        Ok(())
    }
}
