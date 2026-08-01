use std::collections::BTreeSet;

use context_relay_native_runner::MacRootIdentity;
use context_relay_protocol::{ApplyReceipt, HarnessId, PlanId, Sha256Digest, WireNativeValue};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::native_memory::{NativeMemoryLedger, NativeMemoryRegistration};
use crate::native_transaction::{
    MutationKind, NativeApplyReceipt, NativeObjectToken, NativeReceiptEntry, OwnershipChange,
    RestorableStateFingerprint, TransactionStep,
};

use super::{
    BeforeImagePolicy, Vault, VaultError, from_json, put_native_memory_ledger, sha256_key,
    sqlite_u64, to_i64, to_json,
};

pub use crate::native_transaction::MutationWalState as NativeWalState;

const MAX_BEFORE_IMAGE_BATCH: usize = 4_096;
const MAX_NATIVE_PLAN_BYTES: usize = 16 * 1024 * 1024;
const MAX_CLI_DECLARATION_BYTES: usize = 1024 * 1024;
const MAX_CLI_OPERATIONS_BYTES: usize = 1024 * 1024;
const MAX_CLI_WAL_ROWS: u32 = 1_024;
const WINDOWS_MONIKER_PREFIX: &str = "context-relay.native.";
const MACOS_BUNDLE_PREFIX: &str = "com.contextrelay.native-runner.";
const MACOS_CONTAINER_DOMAIN: &[u8] = b"context-relay/macos-container/v1\0";

#[derive(Clone, Copy, Debug)]
pub struct BeforeImageWrite<'a> {
    pub id: &'a str,
    pub plan_id: Option<&'a PlanId>,
    pub payload: &'a [u8],
    pub created_ms: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct NativePlanWrite<'a> {
    pub plan_id: &'a PlanId,
    pub approval_hash: &'a Sha256Digest,
    pub payload: &'a [u8],
    pub created_ms: u64,
    pub expires_ms: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct SetupPlanWrite<'a> {
    pub plan_id: &'a PlanId,
    pub schema_version: u32,
    pub approval_version: u32,
    pub approval_hash: &'a Sha256Digest,
    pub payload: &'a [u8],
    pub created_ms: u64,
    pub expires_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupPlanLifecycle {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupPlanAction {
    Apply,
    Rollback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupPlanClaim {
    Claimed,
    Replay,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetupPlanRecord {
    pub plan_id: PlanId,
    pub schema_version: u32,
    pub approval_version: u32,
    pub approval_hash: Sha256Digest,
    pub payload: Vec<u8>,
    pub created_ms: u64,
    pub expires_ms: u64,
    pub lifecycle: SetupPlanLifecycle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeCliWalState {
    Prepared,
    Applied,
    RestorePrepared,
    Restored,
    Conflict,
}

#[derive(Clone, Copy, Debug)]
pub struct NativeCliWalWrite<'a> {
    pub sequence: u32,
    pub stable_id: &'a str,
    pub harness: HarnessId,
    pub server_name: &'a str,
    pub expected_declaration: Option<&'a [u8]>,
    pub expected_fingerprint: Option<&'a Sha256Digest>,
    pub intended_declaration: Option<&'a [u8]>,
    pub intended_fingerprint: Option<&'a Sha256Digest>,
    pub forward_operations: &'a [u8],
    pub rollback_operations: &'a [u8],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeCliWalRecord {
    pub sequence: u32,
    pub stable_id: String,
    pub harness: HarnessId,
    pub server_name: String,
    pub expected_declaration: Option<Vec<u8>>,
    pub expected_fingerprint: Option<Sha256Digest>,
    pub intended_declaration: Option<Vec<u8>>,
    pub intended_fingerprint: Option<Sha256Digest>,
    pub forward_operations: Vec<u8>,
    pub rollback_operations: Vec<u8>,
    pub state: NativeCliWalState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacGenerationState {
    Prepared,
    Active,
    Retired,
    Poisoned,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MacGenerationSubstate {
    Reserved,
    GuardianBound,
    BundleBound,
    Finalized,
    ContainerBound,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeSandboxIdentity {
    Windows {
        moniker: String,
        sid: Vec<u8>,
    },
    Macos {
        generation_id: String,
        bundle_id: String,
        container: Vec<u8>,
        guardian_pgid: Option<i32>,
        bundle_root: Option<Vec<u8>>,
        signed_digest: Option<Sha256Digest>,
        container_root: Option<Vec<u8>>,
        substate: MacGenerationSubstate,
        state: MacGenerationState,
    },
}

impl NativeSandboxIdentity {
    pub fn reserved_macos(generation_id: String, bundle_id: String, container: Vec<u8>) -> Self {
        Self::Macos {
            generation_id,
            bundle_id,
            container,
            guardian_pgid: None,
            bundle_root: None,
            signed_digest: None,
            container_root: None,
            substate: MacGenerationSubstate::Reserved,
            state: MacGenerationState::Prepared,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeTransactionStatus {
    Pending,
    Committed,
    Restoring,
    Restored,
    Conflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeSandboxCleanupState {
    Pending,
    Cleaned,
    Conflict,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeTransactionSnapshot {
    pub transaction_id: String,
    pub plan_id: PlanId,
    pub status: NativeTransactionStatus,
    pub sandbox_cleanup_state: NativeSandboxCleanupState,
    pub current_step: u8,
    pub entered_step: u8,
    pub identity: NativeSandboxIdentity,
}

#[derive(Clone, Copy, Debug)]
pub struct NativeWalWrite<'a> {
    pub target_sequence: u32,
    pub target: &'a WireNativeValue,
    pub object_token: &'a NativeObjectToken,
    pub before_image_id: &'a str,
    pub operation_kind: MutationKind,
    pub expected: &'a RestorableStateFingerprint,
    pub intended_applied: &'a RestorableStateFingerprint,
    pub intended_restored: &'a RestorableStateFingerprint,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeWalRecord {
    pub target_sequence: u32,
    pub target: WireNativeValue,
    pub object_token: NativeObjectToken,
    pub applied_object_token: Option<NativeObjectToken>,
    pub restored_object_token: Option<NativeObjectToken>,
    pub absence_rebind: Option<NativeWalAbsenceRebind>,
    pub before_image_id: String,
    pub operation_kind: MutationKind,
    pub expected: RestorableStateFingerprint,
    pub intended_applied: RestorableStateFingerprint,
    pub intended_restored: RestorableStateFingerprint,
    pub state: NativeWalState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeWalAbsenceRebind {
    pub target_sequence: u32,
    pub old_token: NativeObjectToken,
    pub new_token: NativeObjectToken,
}

#[derive(Debug)]
struct RawNativeTransaction {
    transaction_id: String,
    plan_id: String,
    status: String,
    sandbox_cleanup_state: String,
    current_step: i64,
    entered_step: i64,
    platform: String,
    windows_moniker: Option<String>,
    windows_sid: Option<Vec<u8>>,
    mac_generation_id: Option<String>,
    mac_bundle_id: Option<String>,
    mac_container: Option<Vec<u8>>,
    mac_guardian_pgid: Option<i64>,
    mac_bundle_root: Option<Vec<u8>>,
    mac_signed_digest: Option<Vec<u8>>,
    mac_container_root: Option<Vec<u8>>,
    mac_generation_substate: Option<String>,
    mac_generation_state: Option<String>,
}

#[derive(Debug)]
struct RawWalRecord {
    target_sequence: i64,
    target_json: Vec<u8>,
    object_volume: Vec<u8>,
    object_id: Vec<u8>,
    object_topology: Vec<u8>,
    applied_object_volume: Option<Vec<u8>>,
    applied_object_id: Option<Vec<u8>>,
    applied_object_topology: Option<Vec<u8>>,
    restored_object_volume: Option<Vec<u8>>,
    restored_object_id: Option<Vec<u8>>,
    restored_object_topology: Option<Vec<u8>>,
    absence_rebind_target_sequence: Option<i64>,
    absence_rebind_old_volume: Option<Vec<u8>>,
    absence_rebind_old_id: Option<Vec<u8>>,
    absence_rebind_old_topology: Option<Vec<u8>>,
    absence_rebind_new_volume: Option<Vec<u8>>,
    absence_rebind_new_id: Option<Vec<u8>>,
    absence_rebind_new_topology: Option<Vec<u8>>,
    before_image_id: String,
    operation_kind: String,
    expected: Vec<u8>,
    intended_applied: Vec<u8>,
    intended_restored: Vec<u8>,
    state: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeReceiptPayload {
    schema_version: u32,
    targets: Vec<NativeReceiptPayloadEntry>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeReceiptPayloadEntry {
    target: WireNativeValue,
    fingerprint: Sha256Digest,
}

impl Vault {
    pub fn put_before_images_batch(
        &mut self,
        images: &[BeforeImageWrite<'_>],
        policy: BeforeImagePolicy,
    ) -> Result<(), VaultError> {
        if images.is_empty() {
            return Ok(());
        }
        if images.len() > MAX_BEFORE_IMAGE_BATCH {
            return Err(VaultError::Validation(
                "before-image batch is too large".to_owned(),
            ));
        }

        let created_ms = images[0].created_ms;
        let mut ids = BTreeSet::new();
        let mut payload_bytes = 0_u64;
        for image in images {
            if image.id.trim().is_empty() {
                return Err(VaultError::Validation(
                    "before-image id cannot be empty".to_owned(),
                ));
            }
            if !ids.insert(image.id.to_owned()) {
                return Err(VaultError::Validation(
                    "before-image batch contains duplicate ids".to_owned(),
                ));
            }
            if image.created_ms != created_ms {
                return Err(VaultError::Validation(
                    "before-image batch timestamps must match".to_owned(),
                ));
            }
            let bytes =
                u64::try_from(image.payload.len()).map_err(|_| VaultError::BudgetExceeded)?;
            payload_bytes = payload_bytes
                .checked_add(bytes)
                .ok_or(VaultError::BudgetExceeded)?;
        }
        if payload_bytes > policy.max_bytes {
            return Err(VaultError::BudgetExceeded);
        }

        let transaction = self.connection.transaction()?;
        let current_bytes = sqlite_u64(
            transaction.query_row(
                "SELECT coalesce(sum(length(payload)), 0) FROM before_images",
                [],
                |row| row.get::<_, i64>(0),
            )?,
            "before-image byte total",
        )?;
        let mut replaced_bytes = 0_u64;
        for id in &ids {
            let bytes = transaction
                .query_row(
                    "SELECT length(payload) FROM before_images WHERE id = ?1",
                    [id],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?;
            if let Some(bytes) = bytes {
                replaced_bytes = replaced_bytes
                    .checked_add(sqlite_u64(bytes, "before-image length")?)
                    .ok_or(VaultError::BudgetExceeded)?;
            }
        }
        let mut required = current_bytes
            .saturating_sub(replaced_bytes)
            .checked_add(payload_bytes)
            .ok_or(VaultError::BudgetExceeded)?;

        if required > policy.max_bytes {
            let cutoff = created_ms.saturating_sub(policy.retention_ms);
            let candidates = {
                let mut statement = transaction.prepare(
                    "SELECT before_images.id, before_images.plan_id,
                            length(before_images.payload)
                     FROM before_images
                     JOIN receipts ON receipts.plan_id = before_images.plan_id
                     WHERE receipts.successful = 1
                       AND receipts.resolved = 1
                       AND receipts.applied_ms < ?1
                       AND NOT EXISTS (
                           SELECT 1 FROM native_receipts
                           WHERE native_receipts.plan_id = before_images.plan_id
                       )
                     ORDER BY receipts.applied_ms, before_images.created_ms, before_images.id",
                )?;
                statement
                    .query_map([to_i64(cutoff)?], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    })?
                    .collect::<Result<Vec<_>, _>>()?
            };
            for (candidate_id, candidate_plan, bytes) in candidates {
                if required <= policy.max_bytes {
                    break;
                }
                if ids.contains(&candidate_id) {
                    continue;
                }
                let bytes = sqlite_u64(bytes, "before-image length")?;
                transaction.execute("DELETE FROM before_images WHERE id = ?1", [&candidate_id])?;
                required = required.saturating_sub(bytes);
                transaction.execute(
                    "DELETE FROM receipts
                     WHERE plan_id = ?1
                       AND NOT EXISTS (
                           SELECT 1 FROM before_images WHERE plan_id = ?1
                       )",
                    [&candidate_plan],
                )?;
            }
        }
        if required > policy.max_bytes {
            return Err(VaultError::BudgetExceeded);
        }

        for image in images {
            transaction.execute(
                "INSERT INTO before_images(id, plan_id, created_ms, payload)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(id) DO UPDATE SET plan_id = excluded.plan_id,
                    created_ms = excluded.created_ms, payload = excluded.payload",
                params![
                    image.id,
                    image.plan_id.map(ToString::to_string),
                    to_i64(image.created_ms)?,
                    image.payload,
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }
}

fn validate_identity(identity: &NativeSandboxIdentity) -> Result<(), VaultError> {
    match identity {
        NativeSandboxIdentity::Windows { moniker, sid } => {
            let suffix = moniker.strip_prefix(WINDOWS_MONIKER_PREFIX);
            if !suffix.is_some_and(valid_lower_hex_32) || !valid_appcontainer_sid(sid) {
                return Err(VaultError::Validation(
                    "Windows sandbox identity is not canonical".to_owned(),
                ));
            }
        }
        NativeSandboxIdentity::Macos {
            generation_id,
            bundle_id,
            container,
            guardian_pgid,
            bundle_root,
            signed_digest,
            container_root,
            substate,
            state,
        } => {
            let expected_bundle = format!("{MACOS_BUNDLE_PREFIX}{generation_id}");
            let mut expected_container = MACOS_CONTAINER_DOMAIN.to_vec();
            expected_container.extend_from_slice(expected_bundle.as_bytes());
            if !valid_lower_hex_32(generation_id)
                || bundle_id != &expected_bundle
                || container != &expected_container
            {
                return Err(VaultError::Validation(
                    "macOS sandbox generation identity is not canonical".to_owned(),
                ));
            }
            if guardian_pgid.is_some_and(|pgid| pgid <= 0)
                || bundle_root
                    .as_deref()
                    .is_some_and(|root| MacRootIdentity::decode(root).is_err())
                || container_root
                    .as_deref()
                    .is_some_and(|root| MacRootIdentity::decode(root).is_err())
            {
                return Err(VaultError::Validation(
                    "macOS lifecycle identity is invalid".to_owned(),
                ));
            }
            let fields_match_substate = match substate {
                MacGenerationSubstate::Reserved => {
                    guardian_pgid.is_none()
                        && bundle_root.is_none()
                        && signed_digest.is_none()
                        && container_root.is_none()
                }
                MacGenerationSubstate::GuardianBound => {
                    guardian_pgid.is_some()
                        && bundle_root.is_none()
                        && signed_digest.is_none()
                        && container_root.is_none()
                }
                MacGenerationSubstate::BundleBound => {
                    guardian_pgid.is_some()
                        && bundle_root.is_some()
                        && signed_digest.is_none()
                        && container_root.is_none()
                }
                MacGenerationSubstate::Finalized => {
                    guardian_pgid.is_some()
                        && bundle_root.is_some()
                        && signed_digest.is_some()
                        && container_root.is_none()
                }
                MacGenerationSubstate::ContainerBound => {
                    guardian_pgid.is_some()
                        && bundle_root.is_some()
                        && signed_digest.is_some()
                        && container_root.is_some()
                }
            };
            if !fields_match_substate
                || matches!(
                    state,
                    MacGenerationState::Active | MacGenerationState::Retired
                ) && *substate != MacGenerationSubstate::ContainerBound
            {
                return Err(VaultError::Validation(
                    "macOS lifecycle substate is inconsistent".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn valid_lower_hex_32(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_appcontainer_sid(bytes: &[u8]) -> bool {
    let Ok(value) = std::str::from_utf8(bytes) else {
        return false;
    };
    let Some(rest) = value.strip_prefix("S-1-15-2-") else {
        return false;
    };
    let parts = rest.split('-').collect::<Vec<_>>();
    parts.len() == 7
        && parts.iter().all(|part| {
            part.parse::<u32>()
                .is_ok_and(|number| number.to_string() == *part)
        })
}

struct IdentityColumns<'a> {
    platform: &'static str,
    windows_moniker: Option<&'a str>,
    windows_sid: Option<&'a [u8]>,
    mac_generation_id: Option<&'a str>,
    mac_bundle_id: Option<&'a str>,
    mac_container: Option<&'a [u8]>,
    mac_guardian_pgid: Option<i32>,
    mac_bundle_root: Option<&'a [u8]>,
    mac_signed_digest: Option<&'a [u8]>,
    mac_container_root: Option<&'a [u8]>,
    mac_generation_substate: Option<&'static str>,
    mac_generation_state: Option<&'static str>,
}

fn identity_columns(identity: &NativeSandboxIdentity) -> IdentityColumns<'_> {
    match identity {
        NativeSandboxIdentity::Windows { moniker, sid } => IdentityColumns {
            platform: "windows",
            windows_moniker: Some(moniker),
            windows_sid: Some(sid),
            mac_generation_id: None,
            mac_bundle_id: None,
            mac_container: None,
            mac_guardian_pgid: None,
            mac_bundle_root: None,
            mac_signed_digest: None,
            mac_container_root: None,
            mac_generation_substate: None,
            mac_generation_state: None,
        },
        NativeSandboxIdentity::Macos {
            generation_id,
            bundle_id,
            container,
            guardian_pgid,
            bundle_root,
            signed_digest,
            container_root,
            substate,
            state,
        } => IdentityColumns {
            platform: "macos",
            windows_moniker: None,
            windows_sid: None,
            mac_generation_id: Some(generation_id),
            mac_bundle_id: Some(bundle_id),
            mac_container: Some(container),
            mac_guardian_pgid: *guardian_pgid,
            mac_bundle_root: bundle_root.as_deref(),
            mac_signed_digest: signed_digest.as_ref().map(|digest| digest.0.as_slice()),
            mac_container_root: container_root.as_deref(),
            mac_generation_substate: Some(mac_substate_name(*substate)),
            mac_generation_state: Some(mac_state_name(*state)),
        },
    }
}

fn load_native_transaction(
    connection: &Connection,
    transaction_id: &str,
) -> Result<Option<NativeTransactionSnapshot>, VaultError> {
    let raw = connection
        .query_row(
            "SELECT transaction_id, plan_id, status, sandbox_cleanup_state,
                    current_step, entered_step, platform,
                    windows_moniker, windows_sid, mac_generation_id, mac_bundle_id,
                    mac_container, mac_guardian_pgid, mac_bundle_root, mac_signed_digest,
                    mac_container_root, mac_generation_substate, mac_generation_state
             FROM native_transactions WHERE transaction_id = ?1",
            [transaction_id],
            |row| {
                Ok(RawNativeTransaction {
                    transaction_id: row.get(0)?,
                    plan_id: row.get(1)?,
                    status: row.get(2)?,
                    sandbox_cleanup_state: row.get(3)?,
                    current_step: row.get(4)?,
                    entered_step: row.get(5)?,
                    platform: row.get(6)?,
                    windows_moniker: row.get(7)?,
                    windows_sid: row.get(8)?,
                    mac_generation_id: row.get(9)?,
                    mac_bundle_id: row.get(10)?,
                    mac_container: row.get(11)?,
                    mac_guardian_pgid: row.get(12)?,
                    mac_bundle_root: row.get(13)?,
                    mac_signed_digest: row.get(14)?,
                    mac_container_root: row.get(15)?,
                    mac_generation_substate: row.get(16)?,
                    mac_generation_state: row.get(17)?,
                })
            },
        )
        .optional()?;
    raw.map(decode_native_transaction).transpose()
}

fn decode_native_transaction(
    raw: RawNativeTransaction,
) -> Result<NativeTransactionSnapshot, VaultError> {
    let status = parse_transaction_status(&raw.status)?;
    let sandbox_cleanup_state = parse_sandbox_cleanup_state(&raw.sandbox_cleanup_state)?;
    let current_step = u8::try_from(raw.current_step)
        .map_err(|_| VaultError::Validation("native transaction step is outside u8".to_owned()))?;
    let entered_step = u8::try_from(raw.entered_step).map_err(|_| {
        VaultError::Validation("entered native transaction step is outside u8".to_owned())
    })?;
    let plan_id = raw
        .plan_id
        .parse::<PlanId>()
        .map_err(|_| VaultError::Validation("native transaction plan id is invalid".to_owned()))?;
    let identity = match (
        raw.platform.as_str(),
        raw.windows_moniker,
        raw.windows_sid,
        raw.mac_generation_id,
        raw.mac_bundle_id,
        raw.mac_container,
        raw.mac_guardian_pgid,
        raw.mac_bundle_root,
        raw.mac_signed_digest,
        raw.mac_container_root,
        raw.mac_generation_substate,
        raw.mac_generation_state,
    ) {
        (
            "windows",
            Some(moniker),
            Some(sid),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ) => NativeSandboxIdentity::Windows { moniker, sid },
        (
            "macos",
            None,
            None,
            Some(generation_id),
            Some(bundle_id),
            Some(container),
            guardian_pgid,
            bundle_root,
            signed_digest,
            container_root,
            Some(substate),
            Some(state),
        ) => NativeSandboxIdentity::Macos {
            generation_id,
            bundle_id,
            container,
            guardian_pgid: guardian_pgid
                .map(i32::try_from)
                .transpose()
                .map_err(|_| VaultError::Validation("macOS guardian PGID is invalid".to_owned()))?,
            bundle_root,
            signed_digest: signed_digest
                .map(|bytes| {
                    bytes.try_into().map(Sha256Digest).map_err(|_| {
                        VaultError::Validation("macOS signed digest is invalid".to_owned())
                    })
                })
                .transpose()?,
            container_root,
            substate: parse_mac_substate(&substate)?,
            state: parse_mac_state(&state)?,
        },
        _ => {
            return Err(VaultError::Validation(
                "native transaction sandbox identity is inconsistent".to_owned(),
            ));
        }
    };
    validate_identity(&identity)?;
    Ok(NativeTransactionSnapshot {
        transaction_id: raw.transaction_id,
        plan_id,
        status,
        sandbox_cleanup_state,
        current_step,
        entered_step,
        identity,
    })
}

fn parse_transaction_status(value: &str) -> Result<NativeTransactionStatus, VaultError> {
    match value {
        "pending" => Ok(NativeTransactionStatus::Pending),
        "committed" => Ok(NativeTransactionStatus::Committed),
        "restoring" => Ok(NativeTransactionStatus::Restoring),
        "restored" => Ok(NativeTransactionStatus::Restored),
        "conflict" => Ok(NativeTransactionStatus::Conflict),
        _ => Err(VaultError::Validation(
            "native transaction status is invalid".to_owned(),
        )),
    }
}

fn sandbox_cleanup_state_name(state: NativeSandboxCleanupState) -> &'static str {
    match state {
        NativeSandboxCleanupState::Pending => "pending",
        NativeSandboxCleanupState::Cleaned => "cleaned",
        NativeSandboxCleanupState::Conflict => "conflict",
    }
}

fn parse_sandbox_cleanup_state(value: &str) -> Result<NativeSandboxCleanupState, VaultError> {
    match value {
        "pending" => Ok(NativeSandboxCleanupState::Pending),
        "cleaned" => Ok(NativeSandboxCleanupState::Cleaned),
        "conflict" => Ok(NativeSandboxCleanupState::Conflict),
        _ => Err(VaultError::Validation(
            "native sandbox cleanup state is invalid".to_owned(),
        )),
    }
}

fn mac_state_name(state: MacGenerationState) -> &'static str {
    match state {
        MacGenerationState::Prepared => "prepared",
        MacGenerationState::Active => "active",
        MacGenerationState::Retired => "retired",
        MacGenerationState::Poisoned => "poisoned",
    }
}

fn parse_mac_state(value: &str) -> Result<MacGenerationState, VaultError> {
    match value {
        "prepared" => Ok(MacGenerationState::Prepared),
        "active" => Ok(MacGenerationState::Active),
        "retired" => Ok(MacGenerationState::Retired),
        "poisoned" => Ok(MacGenerationState::Poisoned),
        _ => Err(VaultError::Validation(
            "macOS generation state is invalid".to_owned(),
        )),
    }
}

fn mac_substate_name(substate: MacGenerationSubstate) -> &'static str {
    match substate {
        MacGenerationSubstate::Reserved => "reserved",
        MacGenerationSubstate::GuardianBound => "guardian_bound",
        MacGenerationSubstate::BundleBound => "bundle_bound",
        MacGenerationSubstate::Finalized => "finalized",
        MacGenerationSubstate::ContainerBound => "container_bound",
    }
}

fn parse_mac_substate(value: &str) -> Result<MacGenerationSubstate, VaultError> {
    match value {
        "reserved" => Ok(MacGenerationSubstate::Reserved),
        "guardian_bound" => Ok(MacGenerationSubstate::GuardianBound),
        "bundle_bound" => Ok(MacGenerationSubstate::BundleBound),
        "finalized" => Ok(MacGenerationSubstate::Finalized),
        "container_bound" => Ok(MacGenerationSubstate::ContainerBound),
        _ => Err(VaultError::Validation(
            "macOS generation substate is invalid".to_owned(),
        )),
    }
}

fn mutation_kind_name(kind: MutationKind) -> &'static str {
    match kind {
        MutationKind::Payload => "payload",
        MutationKind::ExecutableDisabled => "executable_disabled",
        MutationKind::ActivationReference => "activation_reference",
    }
}

fn parse_mutation_kind(value: &str) -> Result<MutationKind, VaultError> {
    match value {
        "payload" => Ok(MutationKind::Payload),
        "executable_disabled" => Ok(MutationKind::ExecutableDisabled),
        "activation_reference" => Ok(MutationKind::ActivationReference),
        _ => Err(VaultError::Validation(
            "native WAL mutation kind is invalid".to_owned(),
        )),
    }
}

fn wal_state_name(state: NativeWalState) -> &'static str {
    match state {
        NativeWalState::Prepared => "prepared",
        NativeWalState::Applied => "applied",
        NativeWalState::RestorePrepared => "restore_prepared",
        NativeWalState::Restored => "restored",
        NativeWalState::Conflict => "conflict",
    }
}

fn parse_wal_state(value: &str) -> Result<NativeWalState, VaultError> {
    match value {
        "prepared" => Ok(NativeWalState::Prepared),
        "applied" => Ok(NativeWalState::Applied),
        "restore_prepared" => Ok(NativeWalState::RestorePrepared),
        "restored" => Ok(NativeWalState::Restored),
        "conflict" => Ok(NativeWalState::Conflict),
        _ => Err(VaultError::Validation(
            "native WAL state is invalid".to_owned(),
        )),
    }
}

fn raw_wal_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawWalRecord> {
    Ok(RawWalRecord {
        target_sequence: row.get(0)?,
        target_json: row.get(1)?,
        object_volume: row.get(2)?,
        object_id: row.get(3)?,
        object_topology: row.get(4)?,
        applied_object_volume: row.get(5)?,
        applied_object_id: row.get(6)?,
        applied_object_topology: row.get(7)?,
        restored_object_volume: row.get(8)?,
        restored_object_id: row.get(9)?,
        restored_object_topology: row.get(10)?,
        absence_rebind_target_sequence: row.get(11)?,
        absence_rebind_old_volume: row.get(12)?,
        absence_rebind_old_id: row.get(13)?,
        absence_rebind_old_topology: row.get(14)?,
        absence_rebind_new_volume: row.get(15)?,
        absence_rebind_new_id: row.get(16)?,
        absence_rebind_new_topology: row.get(17)?,
        before_image_id: row.get(18)?,
        operation_kind: row.get(19)?,
        expected: row.get(20)?,
        intended_applied: row.get(21)?,
        intended_restored: row.get(22)?,
        state: row.get(23)?,
    })
}

fn load_native_wal_record(
    connection: &Connection,
    transaction_id: &str,
    target_sequence: u32,
) -> Result<Option<NativeWalRecord>, VaultError> {
    let raw = connection
        .query_row(
            "SELECT target_sequence, target_json, object_volume, object_id, object_topology,
                    applied_object_volume, applied_object_id, applied_object_topology,
                    restored_object_volume, restored_object_id, restored_object_topology,
                    absence_rebind_target_sequence,
                    absence_rebind_old_volume, absence_rebind_old_id, absence_rebind_old_topology,
                    absence_rebind_new_volume, absence_rebind_new_id, absence_rebind_new_topology,
                    before_image_id, operation_kind, expected_fingerprint,
                    intended_applied_fingerprint, intended_restored_fingerprint, state
             FROM native_mutation_wal
             WHERE transaction_id = ?1 AND target_sequence = ?2",
            params![transaction_id, i64::from(target_sequence)],
            raw_wal_record,
        )
        .optional()?;
    raw.map(decode_wal_record).transpose()
}

fn load_native_wal(
    connection: &Connection,
    transaction_id: &str,
) -> Result<Vec<NativeWalRecord>, VaultError> {
    let mut statement = connection.prepare(
        "SELECT target_sequence, target_json, object_volume, object_id, object_topology,
                applied_object_volume, applied_object_id, applied_object_topology,
                restored_object_volume, restored_object_id, restored_object_topology,
                absence_rebind_target_sequence,
                absence_rebind_old_volume, absence_rebind_old_id, absence_rebind_old_topology,
                absence_rebind_new_volume, absence_rebind_new_id, absence_rebind_new_topology,
                before_image_id, operation_kind, expected_fingerprint,
                intended_applied_fingerprint, intended_restored_fingerprint, state
         FROM native_mutation_wal
         WHERE transaction_id = ?1
         ORDER BY target_sequence",
    )?;
    let raw = statement
        .query_map([transaction_id], raw_wal_record)?
        .collect::<Result<Vec<_>, _>>()?;
    raw.into_iter().map(decode_wal_record).collect()
}

fn decode_wal_record(raw: RawWalRecord) -> Result<NativeWalRecord, VaultError> {
    let target_sequence = u32::try_from(raw.target_sequence).map_err(|_| {
        VaultError::Validation("native WAL target sequence is outside u32".to_owned())
    })?;
    let target = from_json::<WireNativeValue>(&raw.target_json)?;
    target
        .validate()
        .map_err(|error| VaultError::Validation(error.to_string()))?;
    if raw.object_volume.is_empty() || raw.object_id.is_empty() || raw.object_topology.is_empty() {
        return Err(VaultError::Validation(
            "native WAL object token is incomplete".to_owned(),
        ));
    }
    let applied_object_token = match (
        raw.applied_object_volume,
        raw.applied_object_id,
        raw.applied_object_topology,
    ) {
        (None, None, None) => None,
        (Some(volume), Some(object), Some(topology))
            if !volume.is_empty() && !object.is_empty() && !topology.is_empty() =>
        {
            Some(NativeObjectToken {
                volume,
                object,
                topology,
            })
        }
        _ => {
            return Err(VaultError::Validation(
                "native WAL applied object token is incomplete".to_owned(),
            ));
        }
    };
    let restored_object_token = match (
        raw.restored_object_volume,
        raw.restored_object_id,
        raw.restored_object_topology,
    ) {
        (None, None, None) => None,
        (Some(volume), Some(object), Some(topology))
            if !volume.is_empty() && !object.is_empty() && !topology.is_empty() =>
        {
            Some(NativeObjectToken {
                volume,
                object,
                topology,
            })
        }
        _ => {
            return Err(VaultError::Validation(
                "native WAL restored object token is incomplete".to_owned(),
            ));
        }
    };
    let absence_rebind = match (
        raw.absence_rebind_target_sequence,
        raw.absence_rebind_old_volume,
        raw.absence_rebind_old_id,
        raw.absence_rebind_old_topology,
        raw.absence_rebind_new_volume,
        raw.absence_rebind_new_id,
        raw.absence_rebind_new_topology,
    ) {
        (None, None, None, None, None, None, None) => None,
        (
            Some(sequence),
            Some(old_volume),
            Some(old_object),
            Some(old_topology),
            Some(new_volume),
            Some(new_object),
            Some(new_topology),
        ) if !old_volume.is_empty()
            && !old_object.is_empty()
            && !old_topology.is_empty()
            && !new_volume.is_empty()
            && !new_object.is_empty()
            && !new_topology.is_empty() =>
        {
            let rebind_target_sequence = u32::try_from(sequence).map_err(|_| {
                VaultError::Validation(
                    "native WAL absence rebind sequence is outside u32".to_owned(),
                )
            })?;
            let old_token = NativeObjectToken {
                volume: old_volume,
                object: old_object,
                topology: old_topology,
            };
            let new_token = NativeObjectToken {
                volume: new_volume,
                object: new_object,
                topology: new_topology,
            };
            if rebind_target_sequence >= target_sequence
                || !old_token.is_absence_generation()
                || !new_token.is_absence_generation()
                || !new_token.has_same_parent_binding(&old_token)
            {
                return Err(VaultError::Validation(
                    "native WAL absence rebind is invalid".to_owned(),
                ));
            }
            Some(NativeWalAbsenceRebind {
                target_sequence: rebind_target_sequence,
                old_token,
                new_token,
            })
        }
        _ => {
            return Err(VaultError::Validation(
                "native WAL absence rebind is incomplete".to_owned(),
            ));
        }
    };
    let expected = decode_fingerprint(raw.expected)?;
    let intended_applied = decode_fingerprint(raw.intended_applied)?;
    let intended_restored = decode_fingerprint(raw.intended_restored)?;
    let state = parse_wal_state(&raw.state)?;
    if matches!(
        state,
        NativeWalState::Applied | NativeWalState::RestorePrepared
    ) && expected != intended_applied
        && applied_object_token.is_none()
    {
        return Err(VaultError::Validation(
            "written native WAL state is missing applied object provenance".to_owned(),
        ));
    }
    if state == NativeWalState::Restored
        && expected != intended_applied
        && restored_object_token.is_none()
    {
        return Err(VaultError::Validation(
            "restored native WAL state is missing restored object provenance".to_owned(),
        ));
    }
    if matches!(state, NativeWalState::Prepared | NativeWalState::Applied)
        && restored_object_token.is_some()
    {
        return Err(VaultError::Validation(
            "native WAL has restored provenance before restore preparation".to_owned(),
        ));
    }
    if absence_rebind.is_some()
        && !matches!(
            state,
            NativeWalState::RestorePrepared | NativeWalState::Restored | NativeWalState::Conflict
        )
    {
        return Err(VaultError::Validation(
            "native WAL absence rebind is attached to an invalid state".to_owned(),
        ));
    }
    Ok(NativeWalRecord {
        target_sequence,
        target,
        object_token: NativeObjectToken {
            volume: raw.object_volume,
            object: raw.object_id,
            topology: raw.object_topology,
        },
        applied_object_token,
        restored_object_token,
        absence_rebind,
        before_image_id: raw.before_image_id,
        operation_kind: parse_mutation_kind(&raw.operation_kind)?,
        expected,
        intended_applied,
        intended_restored,
        state,
    })
}

fn decode_fingerprint(bytes: Vec<u8>) -> Result<RestorableStateFingerprint, VaultError> {
    let digest = bytes.try_into().map_err(|_| {
        VaultError::Validation("native fingerprint is not exactly 32 bytes".to_owned())
    })?;
    Ok(RestorableStateFingerprint(Sha256Digest(digest)))
}

fn wal_write_matches(existing: &NativeWalRecord, write: &NativeWalWrite<'_>) -> bool {
    existing.target_sequence == write.target_sequence
        && existing.target == *write.target
        && existing.object_token == *write.object_token
        && existing.before_image_id == write.before_image_id
        && existing.operation_kind == write.operation_kind
        && existing.expected == *write.expected
        && existing.intended_applied == *write.intended_applied
        && existing.intended_restored == *write.intended_restored
}

fn load_native_receipt(
    connection: &Connection,
    plan_id: &PlanId,
) -> Result<Option<NativeApplyReceipt>, VaultError> {
    let row = connection
        .query_row(
            "SELECT native_receipts.target_count, native_receipts.payload_json,
                    receipts.payload_json
             FROM native_receipts
             JOIN receipts ON receipts.plan_id = native_receipts.plan_id
             WHERE native_receipts.plan_id = ?1",
            [plan_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .optional()?;
    let Some((target_count, native_json, legacy_json)) = row else {
        return Ok(None);
    };
    let payload = from_json::<NativeReceiptPayload>(&native_json)?;
    if payload.schema_version != 1
        || target_count < 0
        || usize::try_from(target_count).ok() != Some(payload.targets.len())
    {
        return Err(VaultError::Validation(
            "native receipt metadata is inconsistent".to_owned(),
        ));
    }
    let legacy = from_json::<ApplyReceipt>(&legacy_json)?;
    legacy
        .validate()
        .map_err(|error| VaultError::Validation(error.to_string()))?;
    if legacy.plan_id != *plan_id || legacy.resulting_digests.len() != payload.targets.len() {
        return Err(VaultError::Validation(
            "native receipt legacy metadata is inconsistent".to_owned(),
        ));
    }
    let mut seen = BTreeSet::new();
    let mut targets = Vec::with_capacity(payload.targets.len());
    for (index, entry) in payload.targets.into_iter().enumerate() {
        entry
            .target
            .validate()
            .map_err(|error| VaultError::Validation(error.to_string()))?;
        if legacy.resulting_digests[index] != entry.fingerprint
            || !seen.insert(to_json(&entry.target)?)
        {
            return Err(VaultError::Validation(
                "native receipt target metadata is inconsistent".to_owned(),
            ));
        }
        targets.push(NativeReceiptEntry {
            target: entry.target,
            fingerprint: RestorableStateFingerprint(entry.fingerprint),
        });
    }
    Ok(Some(NativeApplyReceipt { legacy, targets }))
}

fn load_native_ownership(
    connection: &Connection,
    stable_id: &str,
) -> Result<Option<OwnershipChange>, VaultError> {
    let row = connection
        .query_row(
            "SELECT structural_location, semantic_digest, native_digest
             FROM native_ownership WHERE stable_id = ?1",
            [stable_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .optional()?;
    row.map(|(structural_location, semantic_digest, native_digest)| {
        Ok(OwnershipChange {
            stable_id: stable_id.to_owned(),
            structural_location,
            semantic_digest: decode_digest(semantic_digest, "semantic")?,
            native_digest: decode_digest(native_digest, "native")?,
        })
    })
    .transpose()
}

fn ownership_matches(
    transaction: &Transaction<'_>,
    transaction_id: &str,
    ownership: &[OwnershipChange],
) -> Result<bool, VaultError> {
    let count = transaction.query_row(
        "SELECT count(*) FROM native_ownership WHERE transaction_id = ?1",
        [transaction_id],
        |row| row.get::<_, i64>(0),
    )?;
    if usize::try_from(count).ok() != Some(ownership.len()) {
        return Ok(false);
    }
    for expected in ownership {
        let stored = transaction
            .query_row(
                "SELECT transaction_id, structural_location, semantic_digest, native_digest
                 FROM native_ownership WHERE stable_id = ?1",
                [&expected.stable_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some((owner, location, semantic, native)) = stored else {
            return Ok(false);
        };
        if owner != transaction_id
            || location != expected.structural_location
            || semantic.as_slice() != expected.semantic_digest.0
            || native.as_slice() != expected.native_digest.0
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn decode_digest(bytes: Vec<u8>, field: &'static str) -> Result<Sha256Digest, VaultError> {
    let digest = bytes.try_into().map_err(|_| {
        VaultError::Validation(format!(
            "native ownership {field} digest is not exactly 32 bytes"
        ))
    })?;
    Ok(Sha256Digest(digest))
}

fn decode_cli_digest(bytes: Vec<u8>, field: &'static str) -> Result<Sha256Digest, VaultError> {
    let digest = bytes.try_into().map_err(|_| {
        VaultError::Validation(format!("{field} fingerprint is not exactly 32 bytes"))
    })?;
    Ok(Sha256Digest(digest))
}

fn cli_harness_name(harness: HarnessId) -> Result<&'static str, VaultError> {
    match harness {
        HarnessId::ClaudeCode => Ok("claude_code"),
        HarnessId::Codex => Ok("codex"),
        HarnessId::Hermes => Err(VaultError::Validation(
            "native CLI WAL does not support Hermes".to_owned(),
        )),
    }
}

fn parse_cli_harness(value: &str) -> Result<HarnessId, VaultError> {
    match value {
        "claude_code" => Ok(HarnessId::ClaudeCode),
        "codex" => Ok(HarnessId::Codex),
        _ => Err(VaultError::Validation(
            "native CLI WAL harness is invalid".to_owned(),
        )),
    }
}

const fn cli_wal_state_name(state: NativeCliWalState) -> &'static str {
    match state {
        NativeCliWalState::Prepared => "prepared",
        NativeCliWalState::Applied => "applied",
        NativeCliWalState::RestorePrepared => "restore_prepared",
        NativeCliWalState::Restored => "restored",
        NativeCliWalState::Conflict => "conflict",
    }
}

fn parse_cli_wal_state(value: &str) -> Result<NativeCliWalState, VaultError> {
    match value {
        "prepared" => Ok(NativeCliWalState::Prepared),
        "applied" => Ok(NativeCliWalState::Applied),
        "restore_prepared" => Ok(NativeCliWalState::RestorePrepared),
        "restored" => Ok(NativeCliWalState::Restored),
        "conflict" => Ok(NativeCliWalState::Conflict),
        _ => Err(VaultError::Validation(
            "native CLI WAL state is invalid".to_owned(),
        )),
    }
}

fn validate_cli_declaration(
    declaration: Option<&[u8]>,
    fingerprint: Option<&Sha256Digest>,
    field: &'static str,
) -> Result<(), VaultError> {
    match (declaration, fingerprint) {
        (None, None) => Ok(()),
        (Some(bytes), Some(expected))
            if !bytes.is_empty() && bytes.len() <= MAX_CLI_DECLARATION_BYTES =>
        {
            std::str::from_utf8(bytes).map_err(|_| {
                VaultError::Validation(format!("native CLI WAL {field} declaration is not UTF-8"))
            })?;
            let actual = Sha256Digest(Sha256::digest(bytes).into());
            if actual != *expected {
                return Err(VaultError::Validation(format!(
                    "native CLI WAL {field} declaration fingerprint does not match"
                )));
            }
            Ok(())
        }
        (Some(_), Some(_)) => Err(VaultError::Validation(format!(
            "native CLI WAL {field} declaration length is invalid"
        ))),
        _ => Err(VaultError::Validation(format!(
            "native CLI WAL {field} declaration and fingerprint must be paired"
        ))),
    }
}

fn validate_native_cli_wal_write(write: &NativeCliWalWrite<'_>) -> Result<(), VaultError> {
    if write.sequence >= MAX_CLI_WAL_ROWS {
        return Err(VaultError::Validation(
            "native CLI WAL sequence exceeds its bound".to_owned(),
        ));
    }
    if write.stable_id.trim().is_empty() || write.stable_id.len() > 512 {
        return Err(VaultError::Validation(
            "native CLI WAL stable id length is invalid".to_owned(),
        ));
    }
    cli_harness_name(write.harness)?;
    if write.server_name != "context-relay" {
        return Err(VaultError::Validation(
            "native CLI WAL supports only the context-relay server".to_owned(),
        ));
    }
    validate_cli_declaration(
        write.expected_declaration,
        write.expected_fingerprint,
        "expected",
    )?;
    validate_cli_declaration(
        write.intended_declaration,
        write.intended_fingerprint,
        "intended",
    )?;
    if write.expected_declaration.is_none() && write.intended_declaration.is_none() {
        return Err(VaultError::Validation(
            "native CLI WAL mutation cannot preserve absence".to_owned(),
        ));
    }
    if write.forward_operations.is_empty()
        || write.forward_operations.len() > MAX_CLI_OPERATIONS_BYTES
        || write.rollback_operations.is_empty()
        || write.rollback_operations.len() > MAX_CLI_OPERATIONS_BYTES
    {
        return Err(VaultError::Validation(
            "native CLI WAL operation payload length is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn load_native_cli_wal_record(
    connection: &Connection,
    transaction_id: &str,
    sequence: u32,
) -> Result<Option<NativeCliWalRecord>, VaultError> {
    let raw = connection
        .query_row(
            "SELECT sequence, stable_id, harness, server_name,
                    expected_declaration, expected_fingerprint,
                    intended_declaration, intended_fingerprint,
                    forward_operations, rollback_operations, state
             FROM native_cli_wal
             WHERE transaction_id = ?1 AND sequence = ?2",
            params![transaction_id, i64::from(sequence)],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                    row.get::<_, Option<Vec<u8>>>(6)?,
                    row.get::<_, Option<Vec<u8>>>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                    row.get::<_, String>(10)?,
                ))
            },
        )
        .optional()?;
    raw.map(
        |(
            sequence,
            stable_id,
            harness,
            server_name,
            expected_declaration,
            expected_fingerprint,
            intended_declaration,
            intended_fingerprint,
            forward_operations,
            rollback_operations,
            state,
        )| {
            let expected_fingerprint = expected_fingerprint
                .map(|bytes| decode_cli_digest(bytes, "native CLI WAL expected"))
                .transpose()?;
            let intended_fingerprint = intended_fingerprint
                .map(|bytes| decode_cli_digest(bytes, "native CLI WAL intended"))
                .transpose()?;
            let record = NativeCliWalRecord {
                sequence: u32::try_from(sequence).map_err(|_| {
                    VaultError::Validation("native CLI WAL sequence is outside u32".to_owned())
                })?,
                stable_id,
                harness: parse_cli_harness(&harness)?,
                server_name,
                expected_declaration,
                expected_fingerprint,
                intended_declaration,
                intended_fingerprint,
                forward_operations,
                rollback_operations,
                state: parse_cli_wal_state(&state)?,
            };
            validate_native_cli_wal_record(&record)?;
            Ok(record)
        },
    )
    .transpose()
}

fn load_native_cli_wal(
    connection: &Connection,
    transaction_id: &str,
) -> Result<Vec<NativeCliWalRecord>, VaultError> {
    let sequences = {
        let mut statement = connection.prepare(
            "SELECT sequence FROM native_cli_wal
             WHERE transaction_id = ?1 ORDER BY sequence",
        )?;
        statement
            .query_map([transaction_id], |row| row.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?
    };
    sequences
        .into_iter()
        .map(|sequence| {
            let sequence = u32::try_from(sequence).map_err(|_| {
                VaultError::Validation("native CLI WAL sequence is outside u32".to_owned())
            })?;
            load_native_cli_wal_record(connection, transaction_id, sequence)?.ok_or_else(|| {
                VaultError::Validation("native CLI WAL row disappeared during query".to_owned())
            })
        })
        .collect()
}

fn validate_native_cli_wal_record(record: &NativeCliWalRecord) -> Result<(), VaultError> {
    let write = NativeCliWalWrite {
        sequence: record.sequence,
        stable_id: &record.stable_id,
        harness: record.harness,
        server_name: &record.server_name,
        expected_declaration: record.expected_declaration.as_deref(),
        expected_fingerprint: record.expected_fingerprint.as_ref(),
        intended_declaration: record.intended_declaration.as_deref(),
        intended_fingerprint: record.intended_fingerprint.as_ref(),
        forward_operations: &record.forward_operations,
        rollback_operations: &record.rollback_operations,
    };
    validate_native_cli_wal_write(&write)
}

fn cli_wal_write_matches(record: &NativeCliWalRecord, write: &NativeCliWalWrite<'_>) -> bool {
    record.sequence == write.sequence
        && record.stable_id == write.stable_id
        && record.harness == write.harness
        && record.server_name == write.server_name
        && record.expected_declaration.as_deref() == write.expected_declaration
        && record.expected_fingerprint.as_ref() == write.expected_fingerprint
        && record.intended_declaration.as_deref() == write.intended_declaration
        && record.intended_fingerprint.as_ref() == write.intended_fingerprint
        && record.forward_operations == write.forward_operations
        && record.rollback_operations == write.rollback_operations
}

impl Vault {
    pub fn commit_native_success(
        &mut self,
        transaction_id: &str,
        receipt: &NativeApplyReceipt,
        ownership: &[OwnershipChange],
    ) -> Result<(), VaultError> {
        receipt
            .legacy
            .validate()
            .map_err(|error| VaultError::Validation(error.to_string()))?;
        if receipt.legacy.resulting_digests.len() != receipt.targets.len() {
            return Err(VaultError::Validation(
                "legacy and native receipt target counts differ".to_owned(),
            ));
        }
        let mut receipt_targets = BTreeSet::new();
        for (index, target) in receipt.targets.iter().enumerate() {
            target
                .target
                .validate()
                .map_err(|error| VaultError::Validation(error.to_string()))?;
            if receipt.legacy.resulting_digests[index] != target.fingerprint.0 {
                return Err(VaultError::Validation(
                    "legacy and native receipt fingerprints differ".to_owned(),
                ));
            }
            if !receipt_targets.insert(to_json(&target.target)?) {
                return Err(VaultError::Validation(
                    "native receipt contains duplicate targets".to_owned(),
                ));
            }
        }
        let mut stable_ids = BTreeSet::new();
        let mut locations = BTreeSet::new();
        for change in ownership {
            if change.stable_id.trim().is_empty() || change.structural_location.trim().is_empty() {
                return Err(VaultError::Validation(
                    "native ownership identity cannot be empty".to_owned(),
                ));
            }
            if !stable_ids.insert(change.stable_id.as_str())
                || !locations.insert(change.structural_location.as_str())
            {
                return Err(VaultError::Validation(
                    "native ownership changes must be unique".to_owned(),
                ));
            }
        }

        let transaction = self.connection.transaction()?;
        let snapshot = load_native_transaction(&transaction, transaction_id)?.ok_or_else(|| {
            VaultError::Validation("native transaction does not exist".to_owned())
        })?;
        if snapshot.plan_id != receipt.legacy.plan_id {
            return Err(VaultError::Validation(
                "native receipt plan does not match its transaction".to_owned(),
            ));
        }
        if snapshot.status == NativeTransactionStatus::Committed {
            let stored = load_native_receipt(&transaction, &snapshot.plan_id)?;
            if stored.as_ref() == Some(receipt)
                && ownership_matches(&transaction, transaction_id, ownership)?
            {
                transaction.commit()?;
                return Ok(());
            }
            return Err(VaultError::Validation(
                "committed native transaction cannot be changed".to_owned(),
            ));
        }
        if snapshot.status != NativeTransactionStatus::Pending {
            return Err(VaultError::Validation(
                "native transaction is not pending".to_owned(),
            ));
        }
        if snapshot.current_step != TransactionStep::ValidateEffectiveConfiguration as u8
            || snapshot.entered_step != TransactionStep::CommitOwnershipAndReceipt as u8
        {
            return Err(VaultError::Validation(
                "native commit step was not durably entered".to_owned(),
            ));
        }

        let wal = load_native_wal(&transaction, transaction_id)?;
        if wal.len() != receipt.targets.len() {
            return Err(VaultError::Validation(
                "native receipt does not cover every WAL target".to_owned(),
            ));
        }
        for (record, target) in wal.iter().zip(&receipt.targets) {
            if record.state != NativeWalState::Applied
                || record.target != target.target
                || record.intended_applied != target.fingerprint
            {
                return Err(VaultError::Validation(
                    "native receipt does not match the applied WAL".to_owned(),
                ));
            }
        }

        let native_payload = NativeReceiptPayload {
            schema_version: 1,
            targets: receipt
                .targets
                .iter()
                .map(|entry| NativeReceiptPayloadEntry {
                    target: entry.target.clone(),
                    fingerprint: entry.fingerprint.0,
                })
                .collect(),
        };
        let plan_id = snapshot.plan_id.to_string();
        let applied_ms = to_i64(receipt.legacy.applied_hlc.physical_ms)?;
        transaction.execute(
            "INSERT INTO receipts(plan_id, successful, resolved, applied_ms, payload_json)
             VALUES (?1, 1, 1, ?2, ?3)",
            params![plan_id, applied_ms, to_json(&receipt.legacy)?],
        )?;
        transaction.execute(
            "INSERT INTO native_receipts(plan_id, transaction_id, target_count, payload_json)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                plan_id,
                transaction_id,
                i64::try_from(receipt.targets.len()).map_err(|_| {
                    VaultError::Validation("native receipt target count exceeds i64".to_owned())
                })?,
                to_json(&native_payload)?,
            ],
        )?;
        for change in ownership {
            transaction.execute(
                "INSERT INTO native_ownership(
                     stable_id, transaction_id, structural_location, semantic_digest, native_digest
                 ) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(stable_id) DO UPDATE SET
                    transaction_id = excluded.transaction_id,
                    structural_location = excluded.structural_location,
                    semantic_digest = excluded.semantic_digest,
                    native_digest = excluded.native_digest",
                params![
                    change.stable_id,
                    transaction_id,
                    change.structural_location,
                    change.semantic_digest.0.as_slice(),
                    change.native_digest.0.as_slice(),
                ],
            )?;
        }
        let changed = transaction.execute(
            "UPDATE native_transactions
             SET status = 'committed', current_step = 19, entered_step = 19,
                 updated_ms = ?2, committed_ms = ?2
             WHERE transaction_id = ?1 AND status = 'pending'
               AND current_step = 18 AND entered_step = 19",
            params![transaction_id, applied_ms],
        )?;
        if changed != 1 {
            return Err(VaultError::Validation(
                "native transaction status changed concurrently".to_owned(),
            ));
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn native_receipt(
        &self,
        plan_id: &PlanId,
    ) -> Result<Option<NativeApplyReceipt>, VaultError> {
        load_native_receipt(&self.connection, plan_id)
    }

    pub fn native_ownership(&self, stable_id: &str) -> Result<Option<OwnershipChange>, VaultError> {
        load_native_ownership(&self.connection, stable_id)
    }
}

impl Vault {
    pub fn prepare_native_wal(
        &mut self,
        transaction_id: &str,
        write: &NativeWalWrite<'_>,
    ) -> Result<(), VaultError> {
        write
            .target
            .validate()
            .map_err(|error| VaultError::Validation(error.to_string()))?;
        if write.before_image_id.trim().is_empty() {
            return Err(VaultError::Validation(
                "native WAL before-image id cannot be empty".to_owned(),
            ));
        }
        if write.object_token.volume.is_empty()
            || write.object_token.object.is_empty()
            || write.object_token.topology.is_empty()
        {
            return Err(VaultError::Validation(
                "native WAL object token is incomplete".to_owned(),
            ));
        }

        let target_json = to_json(write.target)?;
        let transaction = self.connection.transaction()?;
        let snapshot = load_native_transaction(&transaction, transaction_id)?.ok_or_else(|| {
            VaultError::Validation("native transaction does not exist".to_owned())
        })?;
        if snapshot.status != NativeTransactionStatus::Pending {
            return Err(VaultError::Validation(
                "native WAL can only be prepared for a pending transaction".to_owned(),
            ));
        }
        let before_plan = transaction
            .query_row(
                "SELECT plan_id FROM before_images WHERE id = ?1",
                [write.before_image_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?;
        let expected_plan_id = snapshot.plan_id.to_string();
        if before_plan.as_ref().and_then(|value| value.as_deref())
            != Some(expected_plan_id.as_str())
        {
            return Err(VaultError::Validation(
                "native WAL before image does not belong to its plan".to_owned(),
            ));
        }

        if let Some(existing) =
            load_native_wal_record(&transaction, transaction_id, write.target_sequence)?
        {
            if wal_write_matches(&existing, write) {
                transaction.commit()?;
                return Ok(());
            }
            return Err(VaultError::Validation(
                "native WAL target sequence is immutable".to_owned(),
            ));
        }

        let next_sequence = transaction.query_row(
            "SELECT count(*) FROM native_mutation_wal WHERE transaction_id = ?1",
            [transaction_id],
            |row| row.get::<_, i64>(0),
        )?;
        if i64::from(write.target_sequence) != next_sequence {
            return Err(VaultError::Validation(
                "native WAL target sequence must be contiguous".to_owned(),
            ));
        }
        let duplicate_target = load_native_wal(&transaction, transaction_id)?
            .iter()
            .any(|record| same_native_target(&record.target, write.target));
        if duplicate_target {
            return Err(VaultError::Validation(
                "native WAL target cannot appear more than once".to_owned(),
            ));
        }

        transaction.execute(
            "INSERT INTO native_mutation_wal(
                 transaction_id, target_sequence, target_json, object_volume, object_id,
                 object_topology, before_image_id, operation_kind, expected_fingerprint,
                 intended_applied_fingerprint, intended_restored_fingerprint, state
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'prepared')",
            params![
                transaction_id,
                i64::from(write.target_sequence),
                target_json,
                write.object_token.volume,
                write.object_token.object,
                write.object_token.topology,
                write.before_image_id,
                mutation_kind_name(write.operation_kind),
                write.expected.0.0.as_slice(),
                write.intended_applied.0.0.as_slice(),
                write.intended_restored.0.0.as_slice(),
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn transition_native_wal(
        &mut self,
        transaction_id: &str,
        target_sequence: u32,
        next: NativeWalState,
    ) -> Result<(), VaultError> {
        let transaction = self.connection.transaction()?;
        let existing = load_native_wal_record(&transaction, transaction_id, target_sequence)?
            .ok_or_else(|| VaultError::Validation("native WAL entry does not exist".to_owned()))?;
        if existing.state == next {
            transaction.commit()?;
            return Ok(());
        }
        if existing.state == NativeWalState::Prepared
            && next == NativeWalState::Applied
            && existing.expected != existing.intended_applied
            && existing.applied_object_token.is_none()
        {
            return Err(VaultError::Validation(
                "written native WAL must persist applied provenance atomically".to_owned(),
            ));
        }
        if existing.state == NativeWalState::Prepared
            && next == NativeWalState::RestorePrepared
            && existing.applied_object_token.is_none()
        {
            return Err(VaultError::Validation(
                "prepared native WAL cannot restore without a durable candidate".to_owned(),
            ));
        }
        if existing.state == NativeWalState::RestorePrepared
            && next == NativeWalState::Restored
            && existing.expected != existing.intended_applied
            && existing.restored_object_token.is_none()
        {
            return Err(VaultError::Validation(
                "restored native WAL must persist restored provenance first".to_owned(),
            ));
        }
        let allowed = matches!(
            (existing.state, next),
            (NativeWalState::Prepared, NativeWalState::Applied)
                | (NativeWalState::Prepared, NativeWalState::RestorePrepared)
                | (NativeWalState::Prepared, NativeWalState::Restored)
                | (NativeWalState::Prepared, NativeWalState::Conflict)
                | (NativeWalState::Applied, NativeWalState::RestorePrepared)
                | (NativeWalState::Applied, NativeWalState::Conflict)
                | (NativeWalState::RestorePrepared, NativeWalState::Restored)
                | (NativeWalState::RestorePrepared, NativeWalState::Conflict)
        );
        if !allowed {
            return Err(VaultError::Validation(
                "native WAL state transition is not monotonic".to_owned(),
            ));
        }
        let changed = transaction.execute(
            "UPDATE native_mutation_wal SET state = ?3
             WHERE transaction_id = ?1 AND target_sequence = ?2 AND state = ?4",
            params![
                transaction_id,
                i64::from(target_sequence),
                wal_state_name(next),
                wal_state_name(existing.state),
            ],
        )?;
        if changed != 1 {
            return Err(VaultError::Validation(
                "native WAL state changed concurrently".to_owned(),
            ));
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn record_native_wal_candidate(
        &mut self,
        transaction_id: &str,
        target_sequence: u32,
        object_token: &NativeObjectToken,
    ) -> Result<(), VaultError> {
        if object_token.volume.is_empty()
            || object_token.object.is_empty()
            || object_token.topology.is_empty()
        {
            return Err(VaultError::Validation(
                "native WAL candidate object token is empty".to_owned(),
            ));
        }
        let transaction = self.connection.transaction()?;
        let existing = load_native_wal_record(&transaction, transaction_id, target_sequence)?
            .ok_or_else(|| VaultError::Validation("native WAL entry does not exist".to_owned()))?;
        if existing.state != NativeWalState::Prepared {
            return Err(VaultError::Validation(
                "native WAL candidate can only be recorded while prepared".to_owned(),
            ));
        }
        if existing.expected == existing.intended_applied {
            return Err(VaultError::Validation(
                "unchanged native WAL cannot have an install candidate".to_owned(),
            ));
        }
        if let Some(existing_token) = existing.applied_object_token.as_ref() {
            if existing_token != object_token {
                return Err(VaultError::Validation(
                    "native WAL candidate object token is immutable".to_owned(),
                ));
            }
            transaction.commit()?;
            return Ok(());
        }
        let changed = transaction.execute(
            "UPDATE native_mutation_wal
             SET applied_object_volume = ?3, applied_object_id = ?4,
                 applied_object_topology = ?5
             WHERE transaction_id = ?1 AND target_sequence = ?2
               AND state = 'prepared' AND applied_object_volume IS NULL
               AND applied_object_id IS NULL AND applied_object_topology IS NULL",
            params![
                transaction_id,
                i64::from(target_sequence),
                object_token.volume,
                object_token.object,
                object_token.topology,
            ],
        )?;
        if changed != 1 {
            return Err(VaultError::Validation(
                "native WAL candidate changed concurrently".to_owned(),
            ));
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn transition_native_wal_with_applied_object_token(
        &mut self,
        transaction_id: &str,
        target_sequence: u32,
        next: NativeWalState,
        object_token: &NativeObjectToken,
    ) -> Result<(), VaultError> {
        if object_token.volume.is_empty()
            || object_token.object.is_empty()
            || object_token.topology.is_empty()
        {
            return Err(VaultError::Validation(
                "native WAL object token is empty".to_owned(),
            ));
        }
        let transaction = self.connection.transaction()?;
        let existing = load_native_wal_record(&transaction, transaction_id, target_sequence)?
            .ok_or_else(|| VaultError::Validation("native WAL entry does not exist".to_owned()))?;
        if existing
            .applied_object_token
            .as_ref()
            .is_some_and(|existing_token| existing_token != object_token)
        {
            return Err(VaultError::Validation(
                "native WAL applied object token is immutable".to_owned(),
            ));
        }
        if existing.state == next {
            if existing.applied_object_token.as_ref() != Some(object_token) {
                return Err(VaultError::Validation(
                    "native WAL applied object token changed after transition".to_owned(),
                ));
            }
            transaction.commit()?;
            return Ok(());
        }
        let allowed = matches!(
            (existing.state, next),
            (NativeWalState::Prepared, NativeWalState::Applied)
                | (NativeWalState::Prepared, NativeWalState::Conflict)
        );
        if !allowed {
            return Err(VaultError::Validation(
                "native WAL token transition is not monotonic".to_owned(),
            ));
        }
        let changed = transaction.execute(
            "UPDATE native_mutation_wal
             SET applied_object_volume = ?3, applied_object_id = ?4,
                 applied_object_topology = ?5, state = ?6
             WHERE transaction_id = ?1 AND target_sequence = ?2 AND state = ?7",
            params![
                transaction_id,
                i64::from(target_sequence),
                object_token.volume,
                object_token.object,
                object_token.topology,
                wal_state_name(next),
                wal_state_name(existing.state),
            ],
        )?;
        if changed != 1 {
            return Err(VaultError::Validation(
                "native WAL state changed concurrently".to_owned(),
            ));
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn record_native_wal_restored_candidate(
        &mut self,
        transaction_id: &str,
        target_sequence: u32,
        object_token: &NativeObjectToken,
    ) -> Result<(), VaultError> {
        if object_token.volume.is_empty()
            || object_token.object.is_empty()
            || object_token.topology.is_empty()
        {
            return Err(VaultError::Validation(
                "native WAL restored candidate object token is empty".to_owned(),
            ));
        }
        let transaction = self.connection.transaction()?;
        let existing = load_native_wal_record(&transaction, transaction_id, target_sequence)?
            .ok_or_else(|| VaultError::Validation("native WAL entry does not exist".to_owned()))?;
        if existing.state != NativeWalState::RestorePrepared {
            return Err(VaultError::Validation(
                "restored candidate requires restore-prepared WAL state".to_owned(),
            ));
        }
        if existing.expected == existing.intended_applied {
            return Err(VaultError::Validation(
                "unchanged native WAL cannot have a restored candidate".to_owned(),
            ));
        }
        if let Some(existing_token) = existing.restored_object_token.as_ref() {
            if existing_token != object_token {
                return Err(VaultError::Validation(
                    "native WAL restored candidate object token is immutable".to_owned(),
                ));
            }
            transaction.commit()?;
            return Ok(());
        }
        let changed = transaction.execute(
            "UPDATE native_mutation_wal
             SET restored_object_volume = ?3, restored_object_id = ?4,
                 restored_object_topology = ?5
             WHERE transaction_id = ?1 AND target_sequence = ?2
               AND state = 'restore_prepared' AND restored_object_volume IS NULL
               AND restored_object_id IS NULL AND restored_object_topology IS NULL",
            params![
                transaction_id,
                i64::from(target_sequence),
                object_token.volume,
                object_token.object,
                object_token.topology,
            ],
        )?;
        if changed != 1 {
            return Err(VaultError::Validation(
                "native WAL restored candidate changed concurrently".to_owned(),
            ));
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn checkpoint_native_wal_absence_rebind(
        &mut self,
        transaction_id: &str,
        target_sequence: u32,
        later_sequence: u32,
        expected_old_token: &NativeObjectToken,
        new_token: &NativeObjectToken,
    ) -> Result<(), VaultError> {
        let transaction = self.connection.transaction()?;
        let snapshot = load_native_transaction(&transaction, transaction_id)?.ok_or_else(|| {
            VaultError::Validation("native transaction does not exist".to_owned())
        })?;
        if snapshot.status != NativeTransactionStatus::Restoring {
            return Err(VaultError::Validation(
                "native WAL absence rebind requires restoring status".to_owned(),
            ));
        }
        let records = load_native_wal(&transaction, transaction_id)?;
        let (existing, later) = validate_absence_rebind_edge(
            &records,
            target_sequence,
            later_sequence,
            expected_old_token,
            new_token,
        )?;
        if later.state != NativeWalState::RestorePrepared {
            return Err(VaultError::Validation(
                "native WAL absence checkpoint requires restore-prepared later target".to_owned(),
            ));
        }
        let applied_token = existing.applied_object_token.as_ref().ok_or_else(|| {
            VaultError::Validation("native WAL absence rebind is missing applied token".to_owned())
        })?;
        if applied_token != expected_old_token && applied_token != new_token {
            return Err(VaultError::Validation(
                "native WAL absence checkpoint lost its exact old-token provenance".to_owned(),
            ));
        }
        if let Some(checkpoint) = later.absence_rebind.as_ref() {
            if checkpoint.target_sequence != target_sequence
                || checkpoint.old_token != *expected_old_token
                || checkpoint.new_token != *new_token
            {
                return Err(VaultError::Validation(
                    "native WAL absence checkpoint is immutable".to_owned(),
                ));
            }
            transaction.commit()?;
            return Ok(());
        }
        let changed = transaction.execute(
            "UPDATE native_mutation_wal
             SET absence_rebind_target_sequence = ?3,
                 absence_rebind_old_volume = ?4, absence_rebind_old_id = ?5,
                 absence_rebind_old_topology = ?6,
                 absence_rebind_new_volume = ?7, absence_rebind_new_id = ?8,
                 absence_rebind_new_topology = ?9
             WHERE transaction_id = ?1 AND target_sequence = ?2
               AND state = 'restore_prepared'
               AND absence_rebind_target_sequence IS NULL
               AND absence_rebind_old_volume IS NULL
               AND absence_rebind_old_id IS NULL
               AND absence_rebind_old_topology IS NULL
               AND absence_rebind_new_volume IS NULL
               AND absence_rebind_new_id IS NULL
               AND absence_rebind_new_topology IS NULL",
            params![
                transaction_id,
                i64::from(later_sequence),
                i64::from(target_sequence),
                expected_old_token.volume,
                expected_old_token.object,
                expected_old_token.topology,
                new_token.volume,
                new_token.object,
                new_token.topology,
            ],
        )?;
        if changed != 1 {
            return Err(VaultError::Validation(
                "native WAL absence checkpoint changed concurrently".to_owned(),
            ));
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn rebind_native_wal_applied_absence(
        &mut self,
        transaction_id: &str,
        target_sequence: u32,
        later_sequence: u32,
        expected_old_token: &NativeObjectToken,
        new_token: &NativeObjectToken,
    ) -> Result<(), VaultError> {
        let transaction = self.connection.transaction()?;
        let snapshot = load_native_transaction(&transaction, transaction_id)?.ok_or_else(|| {
            VaultError::Validation("native transaction does not exist".to_owned())
        })?;
        if snapshot.status != NativeTransactionStatus::Restoring {
            return Err(VaultError::Validation(
                "native WAL absence rebind requires restoring status".to_owned(),
            ));
        }
        let records = load_native_wal(&transaction, transaction_id)?;
        let (existing, later) = validate_absence_rebind_edge(
            &records,
            target_sequence,
            later_sequence,
            expected_old_token,
            new_token,
        )?;
        let checkpoint = later.absence_rebind.as_ref().ok_or_else(|| {
            VaultError::Validation(
                "native WAL absence rebind requires a durable checkpoint".to_owned(),
            )
        })?;
        if checkpoint.target_sequence != target_sequence
            || checkpoint.old_token != *expected_old_token
            || checkpoint.new_token != *new_token
        {
            return Err(VaultError::Validation(
                "native WAL absence rebind does not match its durable checkpoint".to_owned(),
            ));
        }
        let applied_token = existing.applied_object_token.as_ref().ok_or_else(|| {
            VaultError::Validation("native WAL absence rebind is missing applied token".to_owned())
        })?;
        if applied_token == new_token {
            transaction.commit()?;
            return Ok(());
        }
        if applied_token != expected_old_token {
            return Err(VaultError::Validation(
                "native WAL absence rebind lost its exact old-token CAS".to_owned(),
            ));
        }
        let changed = transaction.execute(
            "UPDATE native_mutation_wal
             SET applied_object_volume = ?3, applied_object_id = ?4,
                 applied_object_topology = ?5
             WHERE transaction_id = ?1 AND target_sequence = ?2
               AND state = 'restore_prepared'
               AND applied_object_volume = ?6 AND applied_object_id = ?7
               AND applied_object_topology = ?8",
            params![
                transaction_id,
                i64::from(target_sequence),
                new_token.volume,
                new_token.object,
                new_token.topology,
                expected_old_token.volume,
                expected_old_token.object,
                expected_old_token.topology,
            ],
        )?;
        if changed != 1 {
            return Err(VaultError::Validation(
                "native WAL absence rebind changed concurrently".to_owned(),
            ));
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn native_wal(&self, transaction_id: &str) -> Result<Vec<NativeWalRecord>, VaultError> {
        load_native_wal(&self.connection, transaction_id)
    }
}

fn validate_absence_rebind_edge<'a>(
    records: &'a [NativeWalRecord],
    target_sequence: u32,
    later_sequence: u32,
    expected_old_token: &NativeObjectToken,
    new_token: &NativeObjectToken,
) -> Result<(&'a NativeWalRecord, &'a NativeWalRecord), VaultError> {
    if later_sequence <= target_sequence {
        return Err(VaultError::Validation(
            "native WAL absence rebind requires a descending restore edge".to_owned(),
        ));
    }
    if !expected_old_token.is_absence_generation()
        || !new_token.is_absence_generation()
        || !new_token.has_same_parent_binding(expected_old_token)
    {
        return Err(VaultError::Validation(
            "native WAL absence rebind token is not a matching parent generation".to_owned(),
        ));
    }
    let existing = records
        .iter()
        .find(|record| record.target_sequence == target_sequence)
        .ok_or_else(|| VaultError::Validation("native WAL entry does not exist".to_owned()))?;
    let later = records
        .iter()
        .find(|record| record.target_sequence == later_sequence)
        .ok_or_else(|| {
            VaultError::Validation("later native WAL restore entry does not exist".to_owned())
        })?;
    if existing.state != NativeWalState::RestorePrepared {
        return Err(VaultError::Validation(
            "native WAL absence rebind requires restore-prepared target".to_owned(),
        ));
    }
    if !matches!(
        later.state,
        NativeWalState::RestorePrepared | NativeWalState::Restored
    ) {
        return Err(VaultError::Validation(
            "native WAL absence rebind requires a proven later restore".to_owned(),
        ));
    }
    let restored_token = later.restored_object_token.as_ref().ok_or_else(|| {
        VaultError::Validation(
            "native WAL absence rebind requires later restored provenance".to_owned(),
        )
    })?;
    if !existing
        .object_token
        .has_same_parent_binding(expected_old_token)
        || !later
            .object_token
            .has_same_parent_binding(expected_old_token)
        || !restored_token.has_same_parent_binding(expected_old_token)
    {
        return Err(VaultError::Validation(
            "native WAL absence rebind crossed parent bindings".to_owned(),
        ));
    }
    let nearest_later = records
        .iter()
        .filter(|record| {
            record.target_sequence > target_sequence
                && record.applied_object_token.is_some()
                && record
                    .object_token
                    .has_same_parent_binding(&existing.object_token)
        })
        .map(|record| record.target_sequence)
        .min();
    if nearest_later != Some(later_sequence) {
        return Err(VaultError::Validation(
            "native WAL absence rebind skipped a later same-parent mutation".to_owned(),
        ));
    }
    Ok((existing, later))
}

fn validate_setup_plan_write(plan: &SetupPlanWrite<'_>) -> Result<(), VaultError> {
    if plan.schema_version == 0 || plan.approval_version == 0 {
        return Err(VaultError::Validation(
            "setup plan envelope versions must be positive".to_owned(),
        ));
    }
    if plan.payload.is_empty() || plan.payload.len() > MAX_NATIVE_PLAN_BYTES {
        return Err(VaultError::Validation(
            "setup plan payload length is invalid".to_owned(),
        ));
    }
    if plan.expires_ms < plan.created_ms {
        return Err(VaultError::Validation(
            "setup plan expires before it was created".to_owned(),
        ));
    }
    Ok(())
}

fn canonical_native_memory_registrations(
    registrations: &[NativeMemoryRegistration],
) -> Result<(Vec<NativeMemoryRegistration>, Vec<u8>), VaultError> {
    let mut registrations = registrations.to_vec();
    registrations.sort_by_key(|registration| registration.source.id);
    let mut unique = BTreeSet::new();
    for registration in &registrations {
        registration
            .source
            .validate()
            .map_err(|error| VaultError::Validation(error.to_string()))?;
        if !unique.insert(registration.source.id) {
            return Err(VaultError::Validation(
                "native memory source is registered more than once".to_owned(),
            ));
        }
    }
    let canonical = to_json(&registrations)?;
    Ok((registrations, canonical))
}

fn load_setup_native_memory_binding(
    connection: &Connection,
    plan_id: &PlanId,
) -> Result<Option<Vec<NativeMemoryRegistration>>, VaultError> {
    let Some(payload) = connection
        .query_row(
            "SELECT payload_json FROM setup_native_memory_bindings WHERE plan_id = ?1",
            [plan_id.to_string()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?
    else {
        return Ok(None);
    };
    let decoded = from_json::<Vec<NativeMemoryRegistration>>(&payload)?;
    let (registrations, canonical) = canonical_native_memory_registrations(&decoded)?;
    if canonical != payload {
        return Err(VaultError::Validation(
            "native memory registration binding is not canonical".to_owned(),
        ));
    }
    Ok(Some(registrations))
}

const fn setup_plan_lifecycle_name(state: SetupPlanLifecycle) -> &'static str {
    match state {
        SetupPlanLifecycle::Previewed => "previewed",
        SetupPlanLifecycle::Applying => "applying",
        SetupPlanLifecycle::Applied => "applied",
        SetupPlanLifecycle::ApplyRestored => "apply_restored",
        SetupPlanLifecycle::RollingBack => "rolling_back",
        SetupPlanLifecycle::RolledBack => "rolled_back",
        SetupPlanLifecycle::RollbackRestored => "rollback_restored",
        SetupPlanLifecycle::Conflict => "conflict",
        SetupPlanLifecycle::Expired => "expired",
    }
}

fn parse_setup_plan_lifecycle(value: &str) -> Result<SetupPlanLifecycle, VaultError> {
    match value {
        "previewed" => Ok(SetupPlanLifecycle::Previewed),
        "applying" => Ok(SetupPlanLifecycle::Applying),
        "applied" => Ok(SetupPlanLifecycle::Applied),
        "apply_restored" => Ok(SetupPlanLifecycle::ApplyRestored),
        "rolling_back" => Ok(SetupPlanLifecycle::RollingBack),
        "rolled_back" => Ok(SetupPlanLifecycle::RolledBack),
        "rollback_restored" => Ok(SetupPlanLifecycle::RollbackRestored),
        "conflict" => Ok(SetupPlanLifecycle::Conflict),
        "expired" => Ok(SetupPlanLifecycle::Expired),
        _ => Err(VaultError::Validation(
            "setup plan lifecycle is invalid".to_owned(),
        )),
    }
}

fn load_setup_plan(
    connection: &Connection,
    plan_id: &PlanId,
) -> Result<Option<SetupPlanRecord>, VaultError> {
    let raw = connection
        .query_row(
            "SELECT lifecycle.schema_version, lifecycle.approval_version,
                    plans.approval_hash, plans.payload, plans.created_ms, plans.expires_ms,
                    lifecycle.state
             FROM setup_plan_lifecycle AS lifecycle
             JOIN native_plans AS plans USING(plan_id)
             WHERE lifecycle.plan_id = ?1",
            [plan_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .optional()?;
    let Some((schema, approval, hash, payload, created, expires, lifecycle)) = raw else {
        return Ok(None);
    };
    Ok(Some(SetupPlanRecord {
        plan_id: *plan_id,
        schema_version: u32::try_from(schema).map_err(|_| {
            VaultError::Validation("setup plan schema version is outside u32".to_owned())
        })?,
        approval_version: u32::try_from(approval).map_err(|_| {
            VaultError::Validation("setup plan approval version is outside u32".to_owned())
        })?,
        approval_hash: decode_cli_digest(hash, "setup plan approval")?,
        payload,
        created_ms: sqlite_u64(created, "setup plan created timestamp")?,
        expires_ms: sqlite_u64(expires, "setup plan expiry timestamp")?,
        lifecycle: parse_setup_plan_lifecycle(&lifecycle)?,
    }))
}

impl Vault {
    pub fn prepare_native_cli_wal(
        &mut self,
        transaction_id: &str,
        write: &NativeCliWalWrite<'_>,
    ) -> Result<(), VaultError> {
        if transaction_id.trim().is_empty() {
            return Err(VaultError::Validation(
                "native CLI WAL transaction id cannot be empty".to_owned(),
            ));
        }
        validate_native_cli_wal_write(write)?;
        let transaction = self.connection.transaction()?;
        let snapshot = load_native_transaction(&transaction, transaction_id)?.ok_or_else(|| {
            VaultError::Validation("native transaction does not exist".to_owned())
        })?;
        if snapshot.status != NativeTransactionStatus::Pending {
            return Err(VaultError::Validation(
                "native CLI WAL can only be prepared for a pending transaction".to_owned(),
            ));
        }
        if let Some(existing) =
            load_native_cli_wal_record(&transaction, transaction_id, write.sequence)?
        {
            if cli_wal_write_matches(&existing, write) {
                transaction.commit()?;
                return Ok(());
            }
            return Err(VaultError::Validation(
                "native CLI WAL sequence is immutable".to_owned(),
            ));
        }
        let existing = load_native_cli_wal(&transaction, transaction_id)?;
        if usize::try_from(write.sequence).ok() != Some(existing.len()) {
            return Err(VaultError::Validation(
                "native CLI WAL sequence must be contiguous".to_owned(),
            ));
        }
        if existing.iter().any(|record| {
            record.stable_id == write.stable_id
                || (record.harness == write.harness && record.server_name == write.server_name)
        }) {
            return Err(VaultError::Validation(
                "native CLI WAL target cannot appear more than once".to_owned(),
            ));
        }
        let expected_fingerprint = write
            .expected_fingerprint
            .map(|fingerprint| fingerprint.0.as_slice());
        let intended_fingerprint = write
            .intended_fingerprint
            .map(|fingerprint| fingerprint.0.as_slice());
        transaction.execute(
            "INSERT INTO native_cli_wal(
                 transaction_id, sequence, stable_id, harness, server_name,
                 expected_declaration, expected_fingerprint,
                 intended_declaration, intended_fingerprint,
                 forward_operations, rollback_operations, state
             ) VALUES (
                 ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'prepared'
             )",
            params![
                transaction_id,
                i64::from(write.sequence),
                write.stable_id,
                cli_harness_name(write.harness)?,
                write.server_name,
                write.expected_declaration,
                expected_fingerprint,
                write.intended_declaration,
                intended_fingerprint,
                write.forward_operations,
                write.rollback_operations,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn transition_native_cli_wal(
        &mut self,
        transaction_id: &str,
        sequence: u32,
        next: NativeCliWalState,
    ) -> Result<(), VaultError> {
        let transaction = self.connection.transaction()?;
        let existing = load_native_cli_wal_record(&transaction, transaction_id, sequence)?
            .ok_or_else(|| {
                VaultError::Validation("native CLI WAL row does not exist".to_owned())
            })?;
        if existing.state == next {
            transaction.commit()?;
            return Ok(());
        }
        let allowed = matches!(
            (existing.state, next),
            (NativeCliWalState::Prepared, NativeCliWalState::Applied)
                | (NativeCliWalState::Prepared, NativeCliWalState::Conflict)
                | (
                    NativeCliWalState::Applied,
                    NativeCliWalState::RestorePrepared | NativeCliWalState::Conflict
                )
                | (
                    NativeCliWalState::RestorePrepared,
                    NativeCliWalState::Restored | NativeCliWalState::Conflict
                )
        );
        if !allowed {
            return Err(VaultError::Validation(
                "native CLI WAL state transition is not monotonic".to_owned(),
            ));
        }
        let changed = transaction.execute(
            "UPDATE native_cli_wal SET state = ?3
             WHERE transaction_id = ?1 AND sequence = ?2 AND state = ?4",
            params![
                transaction_id,
                i64::from(sequence),
                cli_wal_state_name(next),
                cli_wal_state_name(existing.state),
            ],
        )?;
        if changed != 1 {
            return Err(VaultError::Validation(
                "native CLI WAL state changed concurrently".to_owned(),
            ));
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn native_cli_wal(
        &self,
        transaction_id: &str,
    ) -> Result<Vec<NativeCliWalRecord>, VaultError> {
        if transaction_id.trim().is_empty() {
            return Err(VaultError::Validation(
                "native CLI WAL transaction id cannot be empty".to_owned(),
            ));
        }
        load_native_cli_wal(&self.connection, transaction_id)
    }

    pub fn native_plan_payload_for_recovery(
        &self,
        transaction_id: &str,
    ) -> Result<Vec<u8>, VaultError> {
        if transaction_id.trim().is_empty() {
            return Err(VaultError::Validation(
                "native recovery transaction id cannot be empty".to_owned(),
            ));
        }
        self.connection
            .query_row(
                "SELECT plans.payload
                 FROM native_transactions AS transactions
                 JOIN native_plans AS plans USING(plan_id)
                 WHERE transactions.transaction_id = ?1",
                [transaction_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(|| {
                VaultError::Validation(
                    "native recovery transaction or sealed plan is missing".to_owned(),
                )
            })
    }

    pub fn finish_committed_native_cli_cleanup(
        &mut self,
        transaction_id: &str,
    ) -> Result<(), VaultError> {
        let transaction = self.connection.transaction()?;
        let snapshot = load_native_transaction(&transaction, transaction_id)?.ok_or_else(|| {
            VaultError::Validation("native transaction does not exist".to_owned())
        })?;
        if snapshot.status != NativeTransactionStatus::Committed || snapshot.current_step != 19 {
            return Err(VaultError::Validation(
                "native CLI cleanup requires a durable committed transaction".to_owned(),
            ));
        }
        let unfinished = transaction.query_row(
            "SELECT count(*) FROM native_cli_wal
             WHERE transaction_id = ?1 AND state != 'applied'",
            [transaction_id],
            |row| row.get::<_, i64>(0),
        )?;
        if unfinished != 0 {
            return Err(VaultError::Validation(
                "committed native CLI cleanup requires applied WAL rows".to_owned(),
            ));
        }
        transaction.execute(
            "DELETE FROM native_cli_wal WHERE transaction_id = ?1",
            [transaction_id],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn put_setup_plan(&mut self, plan: SetupPlanWrite<'_>) -> Result<(), VaultError> {
        validate_setup_plan_write(&plan)?;
        let plan_id = plan.plan_id.to_string();
        let created_ms = to_i64(plan.created_ms)?;
        let expires_ms = to_i64(plan.expires_ms)?;
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO native_plans(
                 plan_id, approval_hash, payload, created_ms, expires_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(plan_id) DO NOTHING",
            params![
                plan_id,
                plan.approval_hash.0.as_slice(),
                plan.payload,
                created_ms,
                expires_ms,
            ],
        )?;
        let stored = transaction.query_row(
            "SELECT approval_hash, payload, created_ms, expires_ms
             FROM native_plans WHERE plan_id = ?1",
            [&plan_id],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )?;
        if stored
            != (
                plan.approval_hash.0.to_vec(),
                plan.payload.to_vec(),
                created_ms,
                expires_ms,
            )
        {
            return Err(VaultError::Validation(
                "setup plan id was reused with different canonical bytes".to_owned(),
            ));
        }
        transaction.execute(
            "INSERT INTO setup_plan_lifecycle(
                 plan_id, schema_version, approval_version, state, updated_ms
             ) VALUES (?1, ?2, ?3, 'previewed', ?4)
             ON CONFLICT(plan_id) DO NOTHING",
            params![
                plan_id,
                i64::from(plan.schema_version),
                i64::from(plan.approval_version),
                created_ms,
            ],
        )?;
        let versions = transaction.query_row(
            "SELECT schema_version, approval_version
             FROM setup_plan_lifecycle WHERE plan_id = ?1",
            [&plan_id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )?;
        if versions
            != (
                i64::from(plan.schema_version),
                i64::from(plan.approval_version),
            )
        {
            return Err(VaultError::Validation(
                "setup plan id was reused with different envelope versions".to_owned(),
            ));
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn setup_plan(&self, plan_id: &PlanId) -> Result<Option<SetupPlanRecord>, VaultError> {
        load_setup_plan(&self.connection, plan_id)
    }

    pub fn incomplete_setup_plans(&self) -> Result<Vec<SetupPlanRecord>, VaultError> {
        let plan_ids = {
            let mut statement = self.connection.prepare(
                "SELECT plan_id FROM setup_plan_lifecycle
                 WHERE state IN ('applying', 'rolling_back')
                 ORDER BY updated_ms, plan_id",
            )?;
            statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        plan_ids
            .into_iter()
            .map(|plan_id| {
                let plan_id = plan_id.parse::<PlanId>().map_err(|_| {
                    VaultError::Validation("setup plan identifier is invalid".to_owned())
                })?;
                load_setup_plan(&self.connection, &plan_id)?.ok_or_else(|| {
                    VaultError::Validation(
                        "incomplete setup plan disappeared during query".to_owned(),
                    )
                })
            })
            .collect()
    }

    pub fn claim_setup_plan(
        &mut self,
        plan_id: &PlanId,
        action: SetupPlanAction,
        now_ms: u64,
    ) -> Result<SetupPlanClaim, VaultError> {
        let now_ms = to_i64(now_ms)?;
        let transaction = self.connection.transaction()?;
        let stored = transaction
            .query_row(
                "SELECT lifecycle.state, plans.expires_ms
                 FROM setup_plan_lifecycle AS lifecycle
                 JOIN native_plans AS plans USING(plan_id)
                 WHERE lifecycle.plan_id = ?1",
                [plan_id.to_string()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?
            .ok_or_else(|| VaultError::Validation("setup plan does not exist".to_owned()))?;
        let current = parse_setup_plan_lifecycle(&stored.0)?;
        let (expected, claimed, replay) = match action {
            SetupPlanAction::Apply => (
                SetupPlanLifecycle::Previewed,
                SetupPlanLifecycle::Applying,
                SetupPlanLifecycle::Applied,
            ),
            SetupPlanAction::Rollback => (
                SetupPlanLifecycle::Applied,
                SetupPlanLifecycle::RollingBack,
                SetupPlanLifecycle::RolledBack,
            ),
        };
        if current == replay {
            transaction.commit()?;
            return Ok(SetupPlanClaim::Replay);
        }
        if action == SetupPlanAction::Apply
            && current == SetupPlanLifecycle::Previewed
            && now_ms >= stored.1
        {
            let changed = transaction.execute(
                "UPDATE setup_plan_lifecycle SET state = 'expired', updated_ms = ?2
                 WHERE plan_id = ?1 AND state = 'previewed'",
                params![plan_id.to_string(), now_ms],
            )?;
            if changed != 1 {
                return Err(VaultError::Validation(
                    "setup plan lifecycle changed concurrently".to_owned(),
                ));
            }
            transaction.commit()?;
            return Err(VaultError::Validation("setup plan has expired".to_owned()));
        }
        if current != expected {
            return Err(VaultError::Validation(format!(
                "setup plan cannot be claimed from {}",
                setup_plan_lifecycle_name(current)
            )));
        }
        let changed = transaction.execute(
            "UPDATE setup_plan_lifecycle SET state = ?2, updated_ms = ?3
             WHERE plan_id = ?1 AND state = ?4",
            params![
                plan_id.to_string(),
                setup_plan_lifecycle_name(claimed),
                now_ms,
                setup_plan_lifecycle_name(expected),
            ],
        )?;
        if changed != 1 {
            return Err(VaultError::Validation(
                "setup plan lifecycle changed concurrently".to_owned(),
            ));
        }
        transaction.commit()?;
        Ok(SetupPlanClaim::Claimed)
    }

    pub fn finish_setup_plan(
        &mut self,
        plan_id: &PlanId,
        next: SetupPlanLifecycle,
    ) -> Result<(), VaultError> {
        if next == SetupPlanLifecycle::Applied
            && self
                .setup_plan_native_memory_registrations(plan_id)?
                .is_none()
        {
            self.bind_setup_plan_native_memory(plan_id, &[])?;
        }
        self.finish_setup_plan_from_native_memory_binding(plan_id, next)
    }

    /// Persists the exact native-memory descriptor and intended-digest set for
    /// a claimed setup apply. Call this after deriving the registrations from
    /// the opened sealed plan and before beginning native execution.
    pub fn bind_setup_plan_native_memory(
        &mut self,
        plan_id: &PlanId,
        registrations: &[NativeMemoryRegistration],
    ) -> Result<(), VaultError> {
        let (_, canonical) = canonical_native_memory_registrations(registrations)?;
        let transaction = self.connection.transaction()?;
        let current = transaction
            .query_row(
                "SELECT state FROM setup_plan_lifecycle WHERE plan_id = ?1",
                [plan_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| VaultError::Validation("setup plan does not exist".to_owned()))
            .and_then(|value| parse_setup_plan_lifecycle(&value))?;
        if !matches!(
            current,
            SetupPlanLifecycle::Applying | SetupPlanLifecycle::Applied
        ) {
            return Err(VaultError::Validation(
                "native memory registrations require a claimed setup apply".to_owned(),
            ));
        }
        let stored = transaction
            .query_row(
                "SELECT payload_json FROM setup_native_memory_bindings WHERE plan_id = ?1",
                [plan_id.to_string()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        match stored {
            Some(stored) if stored != canonical => {
                return Err(VaultError::Validation(
                    "native memory registration binding changed during setup replay".to_owned(),
                ));
            }
            Some(_) => {}
            None if current == SetupPlanLifecycle::Applying => {
                transaction.execute(
                    "INSERT INTO setup_native_memory_bindings(plan_id, payload_json)
                     VALUES (?1, ?2)",
                    params![plan_id.to_string(), canonical],
                )?;
            }
            None => {
                return Err(VaultError::Validation(
                    "applied setup plan has no native memory registration binding".to_owned(),
                ));
            }
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn setup_plan_native_memory_registrations(
        &self,
        plan_id: &PlanId,
    ) -> Result<Option<Vec<NativeMemoryRegistration>>, VaultError> {
        load_setup_native_memory_binding(&self.connection, plan_id)
    }

    /// Finishes a successful setup apply and publishes the exact memory-source
    /// descriptors and intended file digests in the same SQLite transaction.
    /// Task-level composition derives these registrations only from the opened
    /// sealed plan; the watcher cannot register paths by itself.
    pub fn finish_setup_plan_with_native_memory(
        &mut self,
        plan_id: &PlanId,
        next: SetupPlanLifecycle,
        registrations: &[NativeMemoryRegistration],
    ) -> Result<(), VaultError> {
        if !registrations.is_empty() && next != SetupPlanLifecycle::Applied {
            return Err(VaultError::Validation(
                "native memory sources require a successful setup apply".to_owned(),
            ));
        }
        if next == SetupPlanLifecycle::Applied {
            self.bind_setup_plan_native_memory(plan_id, registrations)?;
        }
        self.finish_setup_plan_from_native_memory_binding(plan_id, next)
    }

    fn finish_setup_plan_from_native_memory_binding(
        &mut self,
        plan_id: &PlanId,
        next: SetupPlanLifecycle,
    ) -> Result<(), VaultError> {
        let transaction = self.connection.transaction()?;
        let current = transaction
            .query_row(
                "SELECT state FROM setup_plan_lifecycle WHERE plan_id = ?1",
                [plan_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| VaultError::Validation("setup plan does not exist".to_owned()))
            .and_then(|value| parse_setup_plan_lifecycle(&value))?;
        let registrations = if next == SetupPlanLifecycle::Applied {
            load_setup_native_memory_binding(&transaction, plan_id)?.ok_or_else(|| {
                VaultError::Validation(
                    "setup apply has no native memory registration binding".to_owned(),
                )
            })?
        } else {
            Vec::new()
        };
        if current != next {
            let allowed = matches!(
                (current, next),
                (
                    SetupPlanLifecycle::Applying,
                    SetupPlanLifecycle::Applied
                        | SetupPlanLifecycle::ApplyRestored
                        | SetupPlanLifecycle::Conflict
                ) | (
                    SetupPlanLifecycle::RollingBack,
                    SetupPlanLifecycle::RolledBack
                        | SetupPlanLifecycle::RollbackRestored
                        | SetupPlanLifecycle::Conflict
                )
            );
            if !allowed {
                return Err(VaultError::Validation(
                    "setup plan lifecycle finish is invalid".to_owned(),
                ));
            }
            let changed = transaction.execute(
                "UPDATE setup_plan_lifecycle SET state = ?2
                 WHERE plan_id = ?1 AND state = ?3",
                params![
                    plan_id.to_string(),
                    setup_plan_lifecycle_name(next),
                    setup_plan_lifecycle_name(current),
                ],
            )?;
            if changed != 1 {
                return Err(VaultError::Validation(
                    "setup plan lifecycle changed concurrently".to_owned(),
                ));
            }
        }
        for registration in &registrations {
            let existing = transaction
                .query_row(
                    "SELECT payload_json FROM native_memory_sources WHERE source_id = ?1",
                    [sha256_key(&registration.source.id.0)],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()?
                .map(|payload| from_json::<NativeMemoryLedger>(&payload))
                .transpose()?;
            let setup_created = existing.is_none();
            let mut ledger = existing
                .unwrap_or_else(|| NativeMemoryLedger::for_source(registration.source.clone()));
            if ledger.source.as_ref() != Some(&registration.source) {
                return Err(VaultError::Validation(
                    "native memory source metadata changed after preview".to_owned(),
                ));
            }
            if current == next && ledger.last_applied_digest != registration.last_applied_digest {
                return Err(VaultError::Validation(
                    "native memory applied digest changed during setup replay".to_owned(),
                ));
            }
            ledger.last_applied_digest = registration.last_applied_digest;
            let canonical = to_json(&ledger)?;
            put_native_memory_ledger(&transaction, &ledger, &canonical)?;
            let source_id = sha256_key(&registration.source.id.0);
            if setup_created {
                transaction.execute(
                    "INSERT INTO setup_native_memory_managed_sources(source_id)
                     VALUES (?1) ON CONFLICT(source_id) DO NOTHING",
                    [&source_id],
                )?;
            }
            transaction.execute(
                "INSERT INTO setup_native_memory_source_refs(plan_id, source_id)
                 VALUES (?1, ?2) ON CONFLICT(plan_id, source_id) DO NOTHING",
                params![plan_id.to_string(), source_id],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Atomically persists a freshly sealed inverse plan, claims that inverse
    /// for apply, and claims the original public plan for rollback.
    pub fn claim_setup_plan_rollback(
        &mut self,
        original_plan_id: &PlanId,
        inverse: SetupPlanWrite<'_>,
        now_ms: u64,
    ) -> Result<SetupPlanClaim, VaultError> {
        validate_setup_plan_write(&inverse)?;
        if original_plan_id == inverse.plan_id {
            return Err(VaultError::Validation(
                "rollback inverse plan id must differ from the original".to_owned(),
            ));
        }
        let now_ms = to_i64(now_ms)?;
        let inverse_created_ms = to_i64(inverse.created_ms)?;
        let inverse_expires_ms = to_i64(inverse.expires_ms)?;
        let original_id = original_plan_id.to_string();
        let inverse_id = inverse.plan_id.to_string();
        let transaction = self.connection.transaction()?;
        let current = transaction
            .query_row(
                "SELECT state FROM setup_plan_lifecycle WHERE plan_id = ?1",
                [&original_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| VaultError::Validation("setup plan does not exist".to_owned()))
            .and_then(|value| parse_setup_plan_lifecycle(&value))?;
        if current == SetupPlanLifecycle::RolledBack {
            transaction.commit()?;
            return Ok(SetupPlanClaim::Replay);
        }
        if current != SetupPlanLifecycle::Applied {
            return Err(VaultError::Validation(format!(
                "setup plan cannot be claimed from {}",
                setup_plan_lifecycle_name(current)
            )));
        }

        transaction.execute(
            "INSERT INTO native_plans(
                 plan_id, approval_hash, payload, created_ms, expires_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(plan_id) DO NOTHING",
            params![
                inverse_id,
                inverse.approval_hash.0.as_slice(),
                inverse.payload,
                inverse_created_ms,
                inverse_expires_ms,
            ],
        )?;
        let stored = transaction.query_row(
            "SELECT approval_hash, payload, created_ms, expires_ms
             FROM native_plans WHERE plan_id = ?1",
            [&inverse_id],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )?;
        if stored
            != (
                inverse.approval_hash.0.to_vec(),
                inverse.payload.to_vec(),
                inverse_created_ms,
                inverse_expires_ms,
            )
        {
            return Err(VaultError::Validation(
                "rollback inverse plan id was reused with different canonical bytes".to_owned(),
            ));
        }
        transaction.execute(
            "INSERT INTO setup_plan_lifecycle(
                 plan_id, schema_version, approval_version, state, updated_ms
             ) VALUES (?1, ?2, ?3, 'applying', ?4)
             ON CONFLICT(plan_id) DO NOTHING",
            params![
                inverse_id,
                i64::from(inverse.schema_version),
                i64::from(inverse.approval_version),
                now_ms,
            ],
        )?;
        let inverse_binding = transaction.query_row(
            "SELECT schema_version, approval_version, state
             FROM setup_plan_lifecycle WHERE plan_id = ?1",
            [&inverse_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )?;
        if inverse_binding
            != (
                i64::from(inverse.schema_version),
                i64::from(inverse.approval_version),
                "applying".to_owned(),
            )
        {
            return Err(VaultError::Validation(
                "rollback inverse lifecycle binding differs".to_owned(),
            ));
        }
        let changed = transaction.execute(
            "UPDATE setup_plan_lifecycle SET state = 'rolling_back', updated_ms = ?2
             WHERE plan_id = ?1 AND state = 'applied'",
            params![original_id, now_ms],
        )?;
        if changed != 1 {
            return Err(VaultError::Validation(
                "setup plan lifecycle changed concurrently".to_owned(),
            ));
        }
        transaction.commit()?;
        Ok(SetupPlanClaim::Claimed)
    }

    /// Atomically records the terminal outcome for an original rollback and
    /// its internal inverse apply transaction.
    pub fn finish_setup_plan_rollback(
        &mut self,
        original_plan_id: &PlanId,
        inverse_plan_id: &PlanId,
        original_next: SetupPlanLifecycle,
        inverse_next: SetupPlanLifecycle,
    ) -> Result<(), VaultError> {
        let allowed = matches!(
            (original_next, inverse_next),
            (SetupPlanLifecycle::RolledBack, SetupPlanLifecycle::Applied)
                | (
                    SetupPlanLifecycle::RollbackRestored,
                    SetupPlanLifecycle::ApplyRestored
                )
                | (SetupPlanLifecycle::Conflict, SetupPlanLifecycle::Conflict)
        );
        if !allowed || original_plan_id == inverse_plan_id {
            return Err(VaultError::Validation(
                "setup rollback terminal lifecycle pair is invalid".to_owned(),
            ));
        }
        let transaction = self.connection.transaction()?;
        let changed_inverse = transaction.execute(
            "UPDATE setup_plan_lifecycle SET state = ?2
             WHERE plan_id = ?1 AND state = 'applying'",
            params![
                inverse_plan_id.to_string(),
                setup_plan_lifecycle_name(inverse_next),
            ],
        )?;
        let changed_original = transaction.execute(
            "UPDATE setup_plan_lifecycle SET state = ?2
             WHERE plan_id = ?1 AND state = 'rolling_back'",
            params![
                original_plan_id.to_string(),
                setup_plan_lifecycle_name(original_next),
            ],
        )?;
        if changed_inverse != 1 || changed_original != 1 {
            return Err(VaultError::Validation(
                "setup rollback lifecycle changed concurrently".to_owned(),
            ));
        }
        if original_next == SetupPlanLifecycle::RolledBack {
            let source_ids = {
                let mut statement = transaction.prepare(
                    "SELECT source_id FROM setup_native_memory_source_refs
                     WHERE plan_id = ?1 ORDER BY source_id",
                )?;
                statement
                    .query_map([original_plan_id.to_string()], |row| {
                        row.get::<_, String>(0)
                    })?
                    .collect::<Result<Vec<_>, _>>()?
            };
            transaction.execute(
                "DELETE FROM setup_native_memory_source_refs WHERE plan_id = ?1",
                [original_plan_id.to_string()],
            )?;
            for source_id in source_ids {
                transaction.execute(
                    "DELETE FROM native_memory_sources
                     WHERE source_id = ?1
                       AND EXISTS (
                           SELECT 1 FROM setup_native_memory_managed_sources managed
                           WHERE managed.source_id = native_memory_sources.source_id
                       )
                       AND NOT EXISTS (
                           SELECT 1 FROM setup_native_memory_source_refs refs
                           WHERE refs.source_id = native_memory_sources.source_id
                       )",
                    [source_id],
                )?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn begin_native_transaction(
        &mut self,
        transaction_id: &str,
        plan: NativePlanWrite<'_>,
        identity: NativeSandboxIdentity,
    ) -> Result<(), VaultError> {
        if transaction_id.trim().is_empty() {
            return Err(VaultError::Validation(
                "native transaction id cannot be empty".to_owned(),
            ));
        }
        if plan.payload.is_empty() || plan.payload.len() > MAX_NATIVE_PLAN_BYTES {
            return Err(VaultError::Validation(
                "native plan payload length is invalid".to_owned(),
            ));
        }
        if plan.expires_ms < plan.created_ms {
            return Err(VaultError::Validation(
                "native plan expires before it was created".to_owned(),
            ));
        }
        validate_identity(&identity)?;

        let plan_id = plan.plan_id.to_string();
        let created_ms = to_i64(plan.created_ms)?;
        let expires_ms = to_i64(plan.expires_ms)?;
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO native_plans(
                 plan_id, approval_hash, payload, created_ms, expires_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(plan_id) DO NOTHING",
            params![
                plan_id,
                plan.approval_hash.0.as_slice(),
                plan.payload,
                created_ms,
                expires_ms,
            ],
        )?;
        let stored_plan = transaction.query_row(
            "SELECT approval_hash, payload, created_ms, expires_ms
             FROM native_plans WHERE plan_id = ?1",
            [&plan_id],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )?;
        if stored_plan
            != (
                plan.approval_hash.0.to_vec(),
                plan.payload.to_vec(),
                created_ms,
                expires_ms,
            )
        {
            return Err(VaultError::Validation(
                "native plan id was reused with different content".to_owned(),
            ));
        }
        let lifecycle = transaction
            .query_row(
                "SELECT state FROM setup_plan_lifecycle WHERE plan_id = ?1",
                [&plan_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .map(|state| parse_setup_plan_lifecycle(&state))
            .transpose()?;
        if lifecycle.is_some_and(|state| {
            !matches!(
                state,
                SetupPlanLifecycle::Applying | SetupPlanLifecycle::RollingBack
            )
        }) {
            return Err(VaultError::Validation(
                "persisted setup plan must be claimed before native transaction begin".to_owned(),
            ));
        }

        if let Some(existing) = load_native_transaction(&transaction, transaction_id)? {
            if existing.plan_id == *plan.plan_id
                && existing.status == NativeTransactionStatus::Pending
                && existing.current_step == 0
                && existing.entered_step == 0
                && existing.identity == identity
            {
                transaction.commit()?;
                return Ok(());
            }
            return Err(VaultError::Validation(
                "native transaction id was reused with different content".to_owned(),
            ));
        }
        let bound_transaction = transaction
            .query_row(
                "SELECT transaction_id FROM native_transactions WHERE plan_id = ?1",
                [&plan_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if bound_transaction.is_some() {
            return Err(VaultError::Validation(
                "native plan is already bound to another transaction".to_owned(),
            ));
        }

        let columns = identity_columns(&identity);
        transaction.execute(
            "INSERT INTO native_transactions(
                 transaction_id, plan_id, status, current_step, entered_step, created_ms, updated_ms,
                 platform, windows_moniker, windows_sid, mac_generation_id, mac_bundle_id,
                 mac_container, mac_guardian_pgid, mac_bundle_root, mac_signed_digest,
                 mac_container_root, mac_generation_substate, mac_generation_state
             ) VALUES (
                 ?1, ?2, 'pending', 0, 0, ?3, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                 ?11, ?12, ?13, ?14, ?15
             )",
            params![
                transaction_id,
                plan_id,
                created_ms,
                columns.platform,
                columns.windows_moniker,
                columns.windows_sid,
                columns.mac_generation_id,
                columns.mac_bundle_id,
                columns.mac_container,
                columns.mac_guardian_pgid,
                columns.mac_bundle_root,
                columns.mac_signed_digest,
                columns.mac_container_root,
                columns.mac_generation_substate,
                columns.mac_generation_state,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn enter_native_step(
        &mut self,
        transaction_id: &str,
        step: TransactionStep,
    ) -> Result<(), VaultError> {
        let step = step as u8;
        let transaction = self.connection.transaction()?;
        let snapshot = load_native_transaction(&transaction, transaction_id)?.ok_or_else(|| {
            VaultError::Validation("native transaction does not exist".to_owned())
        })?;
        if snapshot.entered_step == step
            && matches!(snapshot.current_step, current if current == step || current + 1 == step)
        {
            transaction.commit()?;
            return Ok(());
        }
        let valid_status = snapshot.status == NativeTransactionStatus::Pending
            || (step == TransactionStep::RestoreMatchingAppliedTargets as u8
                && matches!(
                    snapshot.status,
                    NativeTransactionStatus::Committed
                        | NativeTransactionStatus::Restored
                        | NativeTransactionStatus::Conflict
                ));
        let valid_order = step == TransactionStep::RestoreMatchingAppliedTargets as u8
            || (snapshot.entered_step == snapshot.current_step
                && snapshot.current_step + 1 == step);
        if !valid_status || !valid_order {
            return Err(VaultError::Validation(
                "native transaction step cannot be entered out of order".to_owned(),
            ));
        }
        let changed = transaction.execute(
            "UPDATE native_transactions SET entered_step = ?2
             WHERE transaction_id = ?1 AND entered_step = ?3 AND current_step = ?4",
            params![
                transaction_id,
                i64::from(step),
                i64::from(snapshot.entered_step),
                i64::from(snapshot.current_step),
            ],
        )?;
        if changed != 1 {
            return Err(VaultError::Validation(
                "native transaction step changed concurrently".to_owned(),
            ));
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn complete_native_step(
        &mut self,
        transaction_id: &str,
        step: TransactionStep,
    ) -> Result<(), VaultError> {
        let step = step as u8;
        if step >= TransactionStep::CommitOwnershipAndReceipt as u8 {
            return Err(VaultError::Validation(
                "terminal native steps require their atomic finalizer".to_owned(),
            ));
        }
        let transaction = self.connection.transaction()?;
        let snapshot = load_native_transaction(&transaction, transaction_id)?.ok_or_else(|| {
            VaultError::Validation("native transaction does not exist".to_owned())
        })?;
        if snapshot.status != NativeTransactionStatus::Pending {
            return Err(VaultError::Validation(
                "only pending native transactions can complete a forward step".to_owned(),
            ));
        }
        if snapshot.current_step == step && snapshot.entered_step == step {
            transaction.commit()?;
            return Ok(());
        }
        if snapshot.current_step + 1 != step || snapshot.entered_step != step {
            return Err(VaultError::Validation(
                "native transaction step was not durably entered".to_owned(),
            ));
        }
        let changed = transaction.execute(
            "UPDATE native_transactions SET current_step = ?2
             WHERE transaction_id = ?1 AND current_step = ?3 AND entered_step = ?2
               AND status = 'pending'",
            params![transaction_id, i64::from(step), i64::from(step - 1)],
        )?;
        if changed != 1 {
            return Err(VaultError::Validation(
                "native transaction step changed concurrently".to_owned(),
            ));
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn native_transaction(
        &self,
        transaction_id: &str,
    ) -> Result<Option<NativeTransactionSnapshot>, VaultError> {
        load_native_transaction(&self.connection, transaction_id)
    }

    pub fn pending_native_transactions(
        &self,
    ) -> Result<Vec<NativeTransactionSnapshot>, VaultError> {
        let transaction_ids = {
            let mut statement = self.connection.prepare(
                "SELECT transaction_id FROM native_transactions
                 WHERE status = 'pending'
                 ORDER BY created_ms, transaction_id",
            )?;
            statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        transaction_ids
            .into_iter()
            .map(|transaction_id| {
                load_native_transaction(&self.connection, &transaction_id)?.ok_or_else(|| {
                    VaultError::Validation(
                        "pending native transaction disappeared during query".to_owned(),
                    )
                })
            })
            .collect()
    }

    pub fn recoverable_native_transactions(
        &self,
    ) -> Result<Vec<NativeTransactionSnapshot>, VaultError> {
        let transaction_ids = {
            let mut statement = self.connection.prepare(
                "SELECT transaction_id FROM native_transactions
                 WHERE status IN ('pending', 'restoring')
                    OR (status IN ('committed', 'restored', 'conflict') AND current_step < 20)
                    OR (platform = 'macos' AND mac_generation_state IN ('prepared', 'active'))
                 ORDER BY created_ms, transaction_id",
            )?;
            statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        transaction_ids
            .into_iter()
            .map(|transaction_id| {
                load_native_transaction(&self.connection, &transaction_id)?.ok_or_else(|| {
                    VaultError::Validation(
                        "recoverable native transaction disappeared during query".to_owned(),
                    )
                })
            })
            .collect()
    }

    pub fn native_before_image(&self, id: &str) -> Result<Vec<u8>, VaultError> {
        self.connection
            .query_row(
                "SELECT payload FROM before_images WHERE id = ?1",
                [id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(|| VaultError::Validation("native before-image is missing".to_owned()))
    }

    pub fn begin_native_recovery(&mut self, transaction_id: &str) -> Result<(), VaultError> {
        let transaction = self.connection.transaction()?;
        let snapshot = load_native_transaction(&transaction, transaction_id)?.ok_or_else(|| {
            VaultError::Validation("native transaction does not exist".to_owned())
        })?;
        match snapshot.status {
            NativeTransactionStatus::Pending => {
                let changed = transaction.execute(
                    "UPDATE native_transactions SET status = 'restoring'
                     WHERE transaction_id = ?1 AND status = 'pending'",
                    [transaction_id],
                )?;
                if changed != 1 {
                    return Err(VaultError::Validation(
                        "native transaction status changed concurrently".to_owned(),
                    ));
                }
            }
            NativeTransactionStatus::Restoring => {}
            _ => {
                return Err(VaultError::Validation(
                    "native transaction is not recoverable before commit".to_owned(),
                ));
            }
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn poison_interrupted_macos_generation(
        &mut self,
        transaction_id: &str,
    ) -> Result<(), VaultError> {
        let transaction = self.connection.transaction()?;
        let snapshot = load_native_transaction(&transaction, transaction_id)?.ok_or_else(|| {
            VaultError::Validation("native transaction does not exist".to_owned())
        })?;
        if matches!(
            snapshot.identity,
            NativeSandboxIdentity::Macos {
                state: MacGenerationState::Prepared | MacGenerationState::Active,
                ..
            }
        ) {
            let changed = transaction.execute(
                "UPDATE native_transactions SET mac_generation_state = 'poisoned'
                 WHERE transaction_id = ?1 AND mac_generation_state IN ('prepared', 'active')",
                [transaction_id],
            )?;
            if changed != 1 {
                return Err(VaultError::Validation(
                    "macOS generation state changed concurrently".to_owned(),
                ));
            }
        }
        transaction.commit()?;
        Ok(())
    }

    #[deprecated(note = "use poison_interrupted_macos_generation")]
    pub fn poison_active_macos_generation(
        &mut self,
        transaction_id: &str,
    ) -> Result<(), VaultError> {
        self.poison_interrupted_macos_generation(transaction_id)
    }

    pub fn finish_native_recovery(
        &mut self,
        transaction_id: &str,
        conflict: bool,
    ) -> Result<(), VaultError> {
        self.finish_native_recovery_with_cli_no_write(transaction_id, conflict, &[])
    }

    pub fn finish_native_recovery_with_cli_no_write(
        &mut self,
        transaction_id: &str,
        conflict: bool,
        prepared_cli_no_write: &[u32],
    ) -> Result<(), VaultError> {
        let transaction = self.connection.transaction()?;
        let snapshot = load_native_transaction(&transaction, transaction_id)?.ok_or_else(|| {
            VaultError::Validation("native transaction does not exist".to_owned())
        })?;
        let desired = if conflict {
            NativeTransactionStatus::Conflict
        } else {
            NativeTransactionStatus::Restored
        };
        if snapshot.status == desired && snapshot.current_step == 19 && snapshot.entered_step == 19
        {
            transaction.commit()?;
            return Ok(());
        }
        if snapshot.status != NativeTransactionStatus::Restoring {
            return Err(VaultError::Validation(
                "native transaction is not restoring".to_owned(),
            ));
        }
        let unfinished_native = transaction.query_row(
            "SELECT count(*) FROM native_mutation_wal
             WHERE transaction_id = ?1 AND state NOT IN ('restored', 'conflict')",
            [transaction_id],
            |row| row.get::<_, i64>(0),
        )?;
        let native_conflicts = transaction.query_row(
            "SELECT count(*) FROM native_mutation_wal
             WHERE transaction_id = ?1 AND state = 'conflict'",
            [transaction_id],
            |row| row.get::<_, i64>(0),
        )?;
        let cli_records = load_native_cli_wal(&transaction, transaction_id)?;
        let prepared = cli_records
            .iter()
            .filter(|record| record.state == NativeCliWalState::Prepared)
            .map(|record| record.sequence)
            .collect::<BTreeSet<_>>();
        let approved_no_write = prepared_cli_no_write
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if prepared != approved_no_write {
            return Err(VaultError::Validation(
                "native recovery prepared CLI no-write disposition does not match its WAL"
                    .to_owned(),
            ));
        }
        let unfinished_cli = cli_records
            .iter()
            .filter(|record| {
                matches!(
                    record.state,
                    NativeCliWalState::Applied | NativeCliWalState::RestorePrepared
                )
            })
            .count();
        let cli_conflicts = cli_records
            .iter()
            .filter(|record| record.state == NativeCliWalState::Conflict)
            .count();
        let has_conflict = native_conflicts != 0 || cli_conflicts != 0;
        if unfinished_native != 0 || unfinished_cli != 0 || has_conflict != conflict {
            return Err(VaultError::Validation(
                "native recovery outcome does not match its WAL".to_owned(),
            ));
        }
        let changed = transaction.execute(
            "UPDATE native_transactions SET status = ?2, current_step = 19, entered_step = 19
             WHERE transaction_id = ?1 AND status = 'restoring'",
            params![
                transaction_id,
                if conflict { "conflict" } else { "restored" },
            ],
        )?;
        if changed != 1 {
            return Err(VaultError::Validation(
                "native transaction status changed concurrently".to_owned(),
            ));
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn finish_native_cleanup(&mut self, transaction_id: &str) -> Result<(), VaultError> {
        let transaction = self.connection.transaction()?;
        let snapshot = load_native_transaction(&transaction, transaction_id)?.ok_or_else(|| {
            VaultError::Validation("native transaction does not exist".to_owned())
        })?;
        if !matches!(snapshot.current_step, 19 | 20)
            || !matches!(
                snapshot.status,
                NativeTransactionStatus::Committed
                    | NativeTransactionStatus::Restored
                    | NativeTransactionStatus::Conflict
            )
        {
            return Err(VaultError::Validation(
                "native cleanup requires a durable terminal outcome".to_owned(),
            ));
        }

        if snapshot.current_step == 20 {
            if snapshot.sandbox_cleanup_state == NativeSandboxCleanupState::Pending {
                return Err(VaultError::Validation(
                    "finished native cleanup is missing its durable disposition".to_owned(),
                ));
            }
            transaction.commit()?;
            return Ok(());
        }
        let cleanup_state = match snapshot.sandbox_cleanup_state {
            NativeSandboxCleanupState::Pending => NativeSandboxCleanupState::Cleaned,
            NativeSandboxCleanupState::Conflict => NativeSandboxCleanupState::Conflict,
            NativeSandboxCleanupState::Cleaned => {
                return Err(VaultError::Validation(
                    "native cleanup was marked cleaned before it finished".to_owned(),
                ));
            }
        };

        if snapshot.status == NativeTransactionStatus::Committed {
            transaction.execute(
                "DELETE FROM native_cli_wal WHERE transaction_id = ?1",
                [transaction_id],
            )?;
        } else if snapshot.status == NativeTransactionStatus::Restored {
            transaction.execute(
                "DELETE FROM native_cli_wal
                 WHERE transaction_id = ?1 AND state = 'restored'",
                [transaction_id],
            )?;
        }
        if matches!(
            snapshot.status,
            NativeTransactionStatus::Committed | NativeTransactionStatus::Restored
        ) {
            transaction.execute(
                "DELETE FROM native_mutation_wal WHERE transaction_id = ?1",
                [transaction_id],
            )?;
            transaction.execute(
                "DELETE FROM before_images WHERE plan_id = ?1",
                [snapshot.plan_id.to_string()],
            )?;
        }

        let changed = transaction.execute(
            "UPDATE native_transactions
             SET sandbox_cleanup_state = ?2, current_step = 20, entered_step = 20
             WHERE transaction_id = ?1 AND current_step = 19 AND entered_step IN (19, 20)
               AND sandbox_cleanup_state = ?3",
            params![
                transaction_id,
                sandbox_cleanup_state_name(cleanup_state),
                sandbox_cleanup_state_name(snapshot.sandbox_cleanup_state),
            ],
        )?;
        if changed != 1 {
            return Err(VaultError::Validation(
                "native cleanup state changed concurrently".to_owned(),
            ));
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn mark_native_cleanup_conflict(&mut self, transaction_id: &str) -> Result<(), VaultError> {
        let transaction = self.connection.transaction()?;
        let snapshot = load_native_transaction(&transaction, transaction_id)?.ok_or_else(|| {
            VaultError::Validation("native transaction does not exist".to_owned())
        })?;
        if snapshot.sandbox_cleanup_state == NativeSandboxCleanupState::Conflict
            && matches!(snapshot.current_step, 19 | 20)
        {
            transaction.commit()?;
            return Ok(());
        }
        if snapshot.current_step != 19
            || !matches!(snapshot.entered_step, 19 | 20)
            || !matches!(
                snapshot.status,
                NativeTransactionStatus::Committed
                    | NativeTransactionStatus::Restored
                    | NativeTransactionStatus::Conflict
            )
        {
            return Err(VaultError::Validation(
                "native cleanup conflict requires a durable terminal outcome".to_owned(),
            ));
        }
        let changed = transaction.execute(
            "UPDATE native_transactions
             SET sandbox_cleanup_state = 'conflict'
             WHERE transaction_id = ?1 AND status IN ('committed', 'restored', 'conflict')
               AND current_step = 19 AND entered_step IN (19, 20)
               AND sandbox_cleanup_state = 'pending'",
            [transaction_id],
        )?;
        if changed != 1 {
            return Err(VaultError::Validation(
                "native cleanup conflict changed concurrently".to_owned(),
            ));
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn bind_macos_guardian(
        &mut self,
        transaction_id: &str,
        guardian_pgid: i32,
    ) -> Result<(), VaultError> {
        if guardian_pgid <= 0 {
            return Err(VaultError::Validation(
                "macOS guardian PGID is invalid".to_owned(),
            ));
        }
        let transaction = self.connection.transaction()?;
        let snapshot = load_native_transaction(&transaction, transaction_id)?.ok_or_else(|| {
            VaultError::Validation("native transaction does not exist".to_owned())
        })?;
        let NativeSandboxIdentity::Macos {
            guardian_pgid: stored,
            substate,
            state,
            ..
        } = snapshot.identity
        else {
            return Err(VaultError::Validation(
                "native transaction is not a macOS generation".to_owned(),
            ));
        };
        if substate >= MacGenerationSubstate::GuardianBound {
            if stored == Some(guardian_pgid) {
                transaction.commit()?;
                return Ok(());
            }
            return Err(VaultError::Validation(
                "macOS guardian PGID changed".to_owned(),
            ));
        }
        if snapshot.status != NativeTransactionStatus::Pending
            || state != MacGenerationState::Prepared
            || substate != MacGenerationSubstate::Reserved
        {
            return Err(VaultError::Validation(
                "macOS guardian cannot be bound in this state".to_owned(),
            ));
        }
        let changed = transaction.execute(
            "UPDATE native_transactions
             SET mac_guardian_pgid = ?2, mac_generation_substate = 'guardian_bound'
             WHERE transaction_id = ?1 AND mac_generation_state = 'prepared'
               AND mac_generation_substate = 'reserved' AND mac_guardian_pgid IS NULL",
            params![transaction_id, guardian_pgid],
        )?;
        if changed != 1 {
            return Err(VaultError::Validation(
                "macOS guardian binding changed concurrently".to_owned(),
            ));
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn bind_macos_bundle_root(
        &mut self,
        transaction_id: &str,
        bundle_root: &[u8],
    ) -> Result<(), VaultError> {
        MacRootIdentity::decode(bundle_root).map_err(|_| {
            VaultError::Validation("macOS bundle root identity is invalid".to_owned())
        })?;
        let transaction = self.connection.transaction()?;
        let snapshot = load_native_transaction(&transaction, transaction_id)?.ok_or_else(|| {
            VaultError::Validation("native transaction does not exist".to_owned())
        })?;
        let NativeSandboxIdentity::Macos {
            bundle_root: stored,
            substate,
            state,
            ..
        } = snapshot.identity
        else {
            return Err(VaultError::Validation(
                "native transaction is not a macOS generation".to_owned(),
            ));
        };
        if substate >= MacGenerationSubstate::BundleBound {
            if stored.as_deref() == Some(bundle_root) {
                transaction.commit()?;
                return Ok(());
            }
            return Err(VaultError::Validation(
                "macOS bundle root identity changed".to_owned(),
            ));
        }
        if snapshot.status != NativeTransactionStatus::Pending
            || state != MacGenerationState::Prepared
            || substate != MacGenerationSubstate::GuardianBound
        {
            return Err(VaultError::Validation(
                "macOS bundle root cannot be bound in this state".to_owned(),
            ));
        }
        let changed = transaction.execute(
            "UPDATE native_transactions
             SET mac_bundle_root = ?2, mac_generation_substate = 'bundle_bound'
             WHERE transaction_id = ?1 AND mac_generation_state = 'prepared'
               AND mac_generation_substate = 'guardian_bound' AND mac_bundle_root IS NULL",
            params![transaction_id, bundle_root],
        )?;
        if changed != 1 {
            return Err(VaultError::Validation(
                "macOS bundle root binding changed concurrently".to_owned(),
            ));
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn finalize_macos_generation(
        &mut self,
        transaction_id: &str,
        signed_digest: &Sha256Digest,
    ) -> Result<(), VaultError> {
        let transaction = self.connection.transaction()?;
        let snapshot = load_native_transaction(&transaction, transaction_id)?.ok_or_else(|| {
            VaultError::Validation("native transaction does not exist".to_owned())
        })?;
        let NativeSandboxIdentity::Macos {
            signed_digest: stored,
            substate,
            state,
            ..
        } = snapshot.identity
        else {
            return Err(VaultError::Validation(
                "native transaction is not a macOS generation".to_owned(),
            ));
        };
        if substate >= MacGenerationSubstate::Finalized {
            if stored.as_ref() == Some(signed_digest) {
                transaction.commit()?;
                return Ok(());
            }
            return Err(VaultError::Validation(
                "macOS signed generation digest changed".to_owned(),
            ));
        }
        if snapshot.status != NativeTransactionStatus::Pending
            || state != MacGenerationState::Prepared
            || substate != MacGenerationSubstate::BundleBound
        {
            return Err(VaultError::Validation(
                "macOS generation cannot be finalized in this state".to_owned(),
            ));
        }
        let changed = transaction.execute(
            "UPDATE native_transactions
             SET mac_signed_digest = ?2, mac_generation_substate = 'finalized'
             WHERE transaction_id = ?1 AND mac_generation_state = 'prepared'
               AND mac_generation_substate = 'bundle_bound' AND mac_signed_digest IS NULL",
            params![transaction_id, signed_digest.0.as_slice()],
        )?;
        if changed != 1 {
            return Err(VaultError::Validation(
                "macOS generation finalization changed concurrently".to_owned(),
            ));
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn bind_macos_container_root(
        &mut self,
        transaction_id: &str,
        container_root: &[u8],
    ) -> Result<(), VaultError> {
        MacRootIdentity::decode(container_root).map_err(|_| {
            VaultError::Validation("macOS container root identity is invalid".to_owned())
        })?;
        let transaction = self.connection.transaction()?;
        let snapshot = load_native_transaction(&transaction, transaction_id)?.ok_or_else(|| {
            VaultError::Validation("native transaction does not exist".to_owned())
        })?;
        let NativeSandboxIdentity::Macos {
            container_root: stored,
            substate,
            state,
            ..
        } = snapshot.identity
        else {
            return Err(VaultError::Validation(
                "native transaction is not a macOS generation".to_owned(),
            ));
        };
        if substate >= MacGenerationSubstate::ContainerBound {
            if stored.as_deref() == Some(container_root) {
                transaction.commit()?;
                return Ok(());
            }
            return Err(VaultError::Validation(
                "macOS container root identity changed".to_owned(),
            ));
        }
        if snapshot.status != NativeTransactionStatus::Pending
            || state != MacGenerationState::Prepared
            || substate != MacGenerationSubstate::Finalized
        {
            return Err(VaultError::Validation(
                "macOS container root cannot be bound in this state".to_owned(),
            ));
        }
        let changed = transaction.execute(
            "UPDATE native_transactions
             SET mac_container_root = ?2, mac_generation_substate = 'container_bound'
             WHERE transaction_id = ?1 AND mac_generation_state = 'prepared'
               AND mac_generation_substate = 'finalized' AND mac_container_root IS NULL",
            params![transaction_id, container_root],
        )?;
        if changed != 1 {
            return Err(VaultError::Validation(
                "macOS container root binding changed concurrently".to_owned(),
            ));
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn transition_macos_generation(
        &mut self,
        transaction_id: &str,
        next: MacGenerationState,
    ) -> Result<(), VaultError> {
        let transaction = self.connection.transaction()?;
        let snapshot = load_native_transaction(&transaction, transaction_id)?.ok_or_else(|| {
            VaultError::Validation("native transaction does not exist".to_owned())
        })?;
        let NativeSandboxIdentity::Macos {
            state, substate, ..
        } = snapshot.identity
        else {
            return Err(VaultError::Validation(
                "native transaction is not a macOS generation".to_owned(),
            ));
        };
        if matches!(
            next,
            MacGenerationState::Active | MacGenerationState::Retired
        ) && snapshot.status != NativeTransactionStatus::Pending
        {
            return Err(VaultError::Validation(
                "live macOS generation transitions require a pending transaction".to_owned(),
            ));
        }
        if state == next {
            transaction.commit()?;
            return Ok(());
        }
        let allowed = matches!(
            (state, next),
            (MacGenerationState::Prepared, MacGenerationState::Active)
                | (MacGenerationState::Prepared, MacGenerationState::Poisoned)
                | (MacGenerationState::Active, MacGenerationState::Retired)
                | (MacGenerationState::Active, MacGenerationState::Poisoned)
        );
        if !allowed
            || next == MacGenerationState::Active
                && substate != MacGenerationSubstate::ContainerBound
        {
            return Err(VaultError::Validation(
                "macOS generation state transition is not monotonic".to_owned(),
            ));
        }
        let changed = transaction.execute(
            "UPDATE native_transactions
             SET mac_generation_state = ?2
             WHERE transaction_id = ?1 AND mac_generation_state = ?3",
            params![transaction_id, mac_state_name(next), mac_state_name(state)],
        )?;
        if changed != 1 {
            return Err(VaultError::Validation(
                "macOS generation state changed concurrently".to_owned(),
            ));
        }
        transaction.commit()?;
        Ok(())
    }
}

fn same_native_target(left: &WireNativeValue, right: &WireNativeValue) -> bool {
    left.platform == right.platform && left.bytes == right.bytes
}
