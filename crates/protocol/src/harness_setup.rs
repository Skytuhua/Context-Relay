//! Setup attempts are observations; persisted plan state is the durable result.
use crate::{
    ClientError, HarnessId, MAX_TITLE_BYTES, PlanId, ScopeRef, SetupPlan, ValidationError,
    required_text,
};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum HarnessExecutionAction {
    Apply,
    Rollback,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct HarnessExecutionParams {
    pub plan_id: PlanId,
    pub action: HarnessExecutionAction,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum HarnessExecutionPhase {
    Queued,
    Running,
    Finished,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct HarnessExecutionStatus {
    pub plan_id: PlanId,
    pub action: HarnessExecutionAction,
    pub phase: HarnessExecutionPhase,
    #[serde(deserialize_with = "crate::required_nullable")]
    pub error: Option<ClientError>,
}
impl HarnessExecutionStatus {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if let Some(error) = &self.error {
            if self.phase != HarnessExecutionPhase::Finished {
                return Err(ValidationError::Invalid("harnessExecution.error"));
            }
            required_text(&error.message, "harnessExecution.error", MAX_TITLE_BYTES)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum HarnessSetupState {
    Previewed,
    Applying,
    Applied,
    ApplyRestored,
    RollingBack,
    RolledBack,
    RollbackRestored,
    Conflict,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct HarnessSetupRecord {
    pub plan: SetupPlan,
    pub state: HarnessSetupState,
    #[serde(with = "crate::decimal_u64")]
    #[ts(type = "string")]
    pub created_at: u64,
}
impl HarnessSetupRecord {
    pub fn validate(&self) -> Result<(), ValidationError> {
        self.plan.validate()?;
        if self.plan.rulesync_version != "bridge-preview-v1" {
            return Err(ValidationError::Invalid("harnessSetup.plan"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct HarnessSetupSummary {
    pub plan_id: PlanId,
    pub harness: HarnessId,
    #[serde(deserialize_with = "crate::required_nullable")]
    pub harness_profile: Option<String>,
    pub target_scopes: Vec<ScopeRef>,
    pub state: HarnessSetupState,
    #[serde(with = "crate::decimal_u64")]
    #[ts(type = "string")]
    pub created_at: u64,
    #[serde(with = "crate::decimal_u64")]
    #[ts(type = "string")]
    pub expires_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct HarnessSetupsParams {
    #[serde(deserialize_with = "crate::required_nullable")]
    pub after: Option<PlanId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct HarnessSetupsPage {
    pub setups: Vec<HarnessSetupSummary>,
    #[serde(deserialize_with = "crate::required_nullable")]
    pub next_after: Option<PlanId>,
}
impl HarnessSetupsPage {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.setups.len() > 50 {
            return Err(ValidationError::Invalid("harnessSetups"));
        }
        for setup in &self.setups {
            if let Some(profile) = &setup.harness_profile {
                required_text(profile, "harnessSetups.profile", MAX_TITLE_BYTES)?;
            }
            if (setup.harness == HarnessId::Hermes) != setup.harness_profile.is_some()
                || setup.target_scopes.is_empty()
                || setup.target_scopes.len() > crate::MAX_ADAPTER_COLLECTION_ITEMS
            {
                return Err(ValidationError::Invalid("harnessSetups.selection"));
            }
        }
        Ok(())
    }
}
