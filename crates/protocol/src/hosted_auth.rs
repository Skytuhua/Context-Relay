use crate::OperationId;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct HostedAuthStartParams {
    pub operation_id: OperationId,
    pub expected_generation: OperationId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct HostedAuthGenerationParams {
    pub generation: OperationId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum HostedAuthFailure {
    Unavailable,
    Denied,
    Expired,
    CredentialStore,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(
    tag = "phase",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[ts(
    tag = "phase",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum HostedAuthState {
    Disabled {},
    SignedOut {
        #[serde(deserialize_with = "crate::required_nullable")]
        remote_revoked: Option<bool>,
    },
    SigningIn {},
    Restoring {},
    Connected {},
    SigningOut {},
    Failed {
        reason: HostedAuthFailure,
    },
}

/// Desktop control state only: never carries hosted tokens, callback codes or verifier.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct HostedAuthStatus {
    pub generation: OperationId,
    pub state: HostedAuthState,
}
