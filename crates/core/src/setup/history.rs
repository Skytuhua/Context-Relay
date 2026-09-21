use super::*;
use context_relay_protocol::{
    HarnessSetupRecord, HarnessSetupState, HarnessSetupSummary, HarnessSetupsPage,
};

fn state(value: SetupPlanLifecycle) -> HarnessSetupState {
    match value {
        SetupPlanLifecycle::Previewed => HarnessSetupState::Previewed,
        SetupPlanLifecycle::Applying => HarnessSetupState::Applying,
        SetupPlanLifecycle::Applied => HarnessSetupState::Applied,
        SetupPlanLifecycle::ApplyRestored => HarnessSetupState::ApplyRestored,
        SetupPlanLifecycle::RollingBack => HarnessSetupState::RollingBack,
        SetupPlanLifecycle::RolledBack => HarnessSetupState::RolledBack,
        SetupPlanLifecycle::RollbackRestored => HarnessSetupState::RollbackRestored,
        SetupPlanLifecycle::Conflict => HarnessSetupState::Conflict,
        SetupPlanLifecycle::Expired => HarnessSetupState::Expired,
    }
}

/// Loads only an approved original settings plan. Never executes or resumes it.
pub fn harness_setup(vault: &Vault, plan_id: &PlanId) -> Result<HarnessSetupRecord, ClientError> {
    let stored = vault
        .setup_plan(plan_id)
        .map_err(|_| invalid("Setup cannot be loaded"))?
        .ok_or_else(|| invalid("Setup does not exist"))?;
    let opened = validated_original_plan(&stored, plan_id)?;
    let record = HarnessSetupRecord {
        plan: opened.plan.setup,
        state: state(stored.lifecycle),
        created_at: stored.created_ms,
    };
    record
        .validate()
        .map_err(|_| invalid("This plan is not a harness settings setup"))?;
    Ok(record)
}

/// Pagination advances across excluded purposes and inverse plans, including empty pages.
pub fn harness_setups(
    vault: &Vault,
    after: Option<&PlanId>,
) -> Result<HarnessSetupsPage, ClientError> {
    let ids = vault
        .setup_plan_ids_after(after)
        .map_err(|_| invalid("Setup history cannot be loaded"))?;
    let next_after = (ids.len() > 50).then(|| ids[49]);
    let mut setups = Vec::new();
    for id in ids.into_iter().take(50) {
        let stored = vault
            .setup_plan(&id)
            .map_err(|_| invalid("Setup cannot be loaded"))?
            .ok_or_else(|| invalid("Setup does not exist"))?;
        let opened = open_plan(&stored.payload)
            .map_err(|_| invalid("Setup history contains an invalid plan"))?;
        if opened.rollback_of_plan_id.is_some()
            || opened.plan.setup.rulesync_version != "bridge-preview-v1"
        {
            continue;
        }
        let opened = validated_original_plan(&stored, &id)?;
        let plan = opened.plan.setup;
        setups.push(HarnessSetupSummary {
            plan_id: id,
            harness: plan.harness,
            harness_profile: plan.harness_profile,
            target_scopes: plan
                .target_scopes
                .into_iter()
                .map(|scope| match scope {
                    NativeScope::Global => ScopeRef::Global,
                    NativeScope::Project { project_id, .. } => ScopeRef::Project { project_id },
                })
                .collect(),
            state: state(stored.lifecycle),
            created_at: stored.created_ms,
            expires_at: stored.expires_ms,
        });
    }
    let page = HarnessSetupsPage { setups, next_after };
    page.validate()
        .map_err(|_| invalid("Setup history is invalid"))?;
    Ok(page)
}
