use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::{Arc, Mutex, MutexGuard},
};

use context_relay_protocol::{
    AccountId, DeviceCertificateId, DeviceId, RecoveryRestoreId, Sha256Digest,
};
use sha2::{Digest, Sha256};

use crate::{
    devices::{
        recovery_crypto::decode_recovery_enrollment_record_v1,
        recovery_restore_crypto::{decode_recovery_device_claim_v1, verify_recovery_device_claim},
        recovery_restore_transport::{
            RecoveryRestoreProjection, RecoveryRestoreReceipt, RecoveryRestoreTransport,
            RecoveryRootSnapshot,
        },
        recovery_transport::{
            RecoveryEnrollmentReceipt, RecoveryEnrollmentTransport, RecoveryRootStatus,
            RecoveryTransportError,
        },
    },
    sync::SyncScope,
};

#[derive(Clone)]
pub struct InMemoryRecoveryEnrollmentProvider {
    shared: Arc<SharedProvider>,
}

struct SharedProvider {
    state: Mutex<ProviderState>,
}

#[derive(Default)]
struct ProviderState {
    accepted: BTreeMap<AccountId, AcceptedEnrollment>,
    fail_next: usize,
    forged_status: Option<RecoveryRootStatus>,
    forged_receipt: Option<RecoveryEnrollmentReceipt>,
    forged_restore_snapshot: Option<RecoveryRootSnapshot>,
    forged_restore_receipt: Option<RecoveryRestoreReceipt>,
    forged_restore_projection: Option<RecoveryRestoreProjection>,
    omit_next_restore_claim: bool,
}

struct AcceptedEnrollment {
    canonical_record: Vec<u8>,
    receipt: RecoveryEnrollmentReceipt,
    recovery_generation: u64,
    restores: BTreeMap<RecoveryRestoreId, AcceptedRestore>,
    device_ids: BTreeSet<DeviceId>,
    certificate_ids: BTreeSet<DeviceCertificateId>,
}

struct AcceptedRestore {
    canonical_claim: Vec<u8>,
    receipt: RecoveryRestoreReceipt,
}

#[derive(Clone)]
pub struct InMemoryRecoveryEnrollmentTransport {
    shared: Arc<SharedProvider>,
    scope: SyncScope,
}

#[derive(Clone)]
pub struct InMemoryRecoveryRestoreTransport {
    shared: Arc<SharedProvider>,
    scope: SyncScope,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryEnrollmentCapture {
    pub account_id: AccountId,
    pub workspace_id: context_relay_protocol::WorkspaceId,
    pub enrollment_id: context_relay_protocol::RecoveryEnrollmentId,
    pub recovery_root_id: context_relay_protocol::RecoveryRootId,
    pub genesis_certificate_id: context_relay_protocol::DeviceCertificateId,
    pub canonical_record_sha256: Sha256Digest,
    pub canonical_record_len: usize,
    pub registered_at_ms: u64,
    pub recovery_generation: u64,
    pub restore_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryRestoreCapture {
    pub account_id: AccountId,
    pub workspace_id: context_relay_protocol::WorkspaceId,
    pub restore_id: RecoveryRestoreId,
    pub enrollment_id: context_relay_protocol::RecoveryEnrollmentId,
    pub recovery_root_id: context_relay_protocol::RecoveryRootId,
    pub certificate_id: DeviceCertificateId,
    pub device_id: DeviceId,
    pub canonical_record_sha256: Sha256Digest,
    pub canonical_claim_sha256: Sha256Digest,
    pub canonical_claim_len: usize,
    pub accepted_generation: u64,
    pub accepted_at_ms: u64,
}

impl InMemoryRecoveryEnrollmentProvider {
    pub fn new() -> Self {
        Self {
            shared: Arc::new(SharedProvider {
                state: Mutex::new(ProviderState::default()),
            }),
        }
    }

    pub fn transport(&self, scope: SyncScope) -> InMemoryRecoveryEnrollmentTransport {
        InMemoryRecoveryEnrollmentTransport {
            shared: Arc::clone(&self.shared),
            scope,
        }
    }

    pub fn restore_transport(&self, scope: SyncScope) -> InMemoryRecoveryRestoreTransport {
        InMemoryRecoveryRestoreTransport {
            shared: Arc::clone(&self.shared),
            scope,
        }
    }

    #[doc(hidden)]
    pub fn test_fail_next(&self, count: usize) {
        if let Ok(mut state) = self.shared.state.lock() {
            state.fail_next = state.fail_next.saturating_add(count);
        }
    }

    #[doc(hidden)]
    pub fn test_forge_next_status(&self, status: RecoveryRootStatus) {
        if let Ok(mut state) = self.shared.state.lock() {
            state.forged_status = Some(status);
        }
    }

    #[doc(hidden)]
    pub fn test_forge_next_receipt(&self, receipt: RecoveryEnrollmentReceipt) {
        if let Ok(mut state) = self.shared.state.lock() {
            state.forged_receipt = Some(receipt);
        }
    }

    #[doc(hidden)]
    pub fn test_forge_next_restore_snapshot(&self, snapshot: RecoveryRootSnapshot) {
        if let Ok(mut state) = self.shared.state.lock() {
            state.forged_restore_snapshot = Some(snapshot);
        }
    }

    #[doc(hidden)]
    pub fn test_forge_next_restore_receipt(&self, receipt: RecoveryRestoreReceipt) {
        if let Ok(mut state) = self.shared.state.lock() {
            state.forged_restore_receipt = Some(receipt);
        }
    }

    #[doc(hidden)]
    pub fn test_forge_next_restore_projection(&self, projection: RecoveryRestoreProjection) {
        if let Ok(mut state) = self.shared.state.lock() {
            state.forged_restore_projection = Some(projection);
        }
    }

    #[doc(hidden)]
    pub fn test_omit_next_restore_claim(&self) {
        if let Ok(mut state) = self.shared.state.lock() {
            state.omit_next_restore_claim = true;
        }
    }

    #[doc(hidden)]
    pub fn test_set_recovery_generation(&self, account_id: AccountId, generation: u64) {
        if let Ok(mut state) = self.shared.state.lock()
            && let Some(accepted) = state.accepted.get_mut(&account_id)
        {
            accepted.recovery_generation = generation;
        }
    }

    #[doc(hidden)]
    pub fn test_delete_account(&self, account_id: AccountId) {
        if let Ok(mut state) = self.shared.state.lock() {
            state.accepted.remove(&account_id);
        }
    }

    #[doc(hidden)]
    pub fn test_safe_captures(&self) -> Vec<RecoveryEnrollmentCapture> {
        let Ok(state) = self.shared.state.lock() else {
            return Vec::new();
        };
        state
            .accepted
            .values()
            .map(|accepted| RecoveryEnrollmentCapture {
                account_id: accepted.receipt.account_id,
                workspace_id: accepted.receipt.workspace_id,
                enrollment_id: accepted.receipt.enrollment_id,
                recovery_root_id: accepted.receipt.recovery_root_id,
                genesis_certificate_id: accepted.receipt.genesis_certificate_id,
                canonical_record_sha256: accepted.receipt.canonical_record_sha256,
                canonical_record_len: accepted.canonical_record.len(),
                registered_at_ms: accepted.receipt.registered_at_ms,
                recovery_generation: accepted.recovery_generation,
                restore_count: accepted.restores.len(),
            })
            .collect()
    }

    #[doc(hidden)]
    pub fn test_safe_restore_captures(&self) -> Vec<RecoveryRestoreCapture> {
        let Ok(state) = self.shared.state.lock() else {
            return Vec::new();
        };
        state
            .accepted
            .values()
            .flat_map(|accepted| {
                accepted.restores.values().filter_map(|restore| {
                    let claim = decode_recovery_device_claim_v1(&restore.canonical_claim).ok()?;
                    Some(RecoveryRestoreCapture {
                        account_id: restore.receipt.account_id,
                        workspace_id: restore.receipt.workspace_id,
                        restore_id: restore.receipt.restore_id,
                        enrollment_id: restore.receipt.enrollment_id,
                        recovery_root_id: restore.receipt.recovery_root_id,
                        certificate_id: restore.receipt.certificate_id,
                        device_id: claim.certificate.device_id,
                        canonical_record_sha256: restore.receipt.canonical_record_sha256,
                        canonical_claim_sha256: restore.receipt.canonical_claim_sha256,
                        canonical_claim_len: restore.canonical_claim.len(),
                        accepted_generation: restore.receipt.accepted_generation,
                        accepted_at_ms: restore.receipt.accepted_at_ms,
                    })
                })
            })
            .collect()
    }
}

impl Default for InMemoryRecoveryEnrollmentProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl RecoveryEnrollmentTransport for InMemoryRecoveryEnrollmentTransport {
    fn scope(&self) -> SyncScope {
        self.scope
    }

    fn root_status(&self) -> Result<Option<RecoveryRootStatus>, RecoveryTransportError> {
        let mut state = lock(&self.shared)?;
        maybe_fail(&mut state)?;
        if let Some(forged) = state.forged_status.take() {
            return Ok(Some(forged));
        }
        let Some(accepted) = state.accepted.get(&self.scope.account_id) else {
            return Ok(None);
        };
        if accepted.receipt.workspace_id != self.scope.workspace_id {
            return Err(RecoveryTransportError::Conflict);
        }
        Ok(Some(accepted.receipt.clone().into_status()))
    }

    fn register(
        &self,
        canonical_record: &[u8],
        now_ms: u64,
    ) -> Result<RecoveryEnrollmentReceipt, RecoveryTransportError> {
        let record = decode_recovery_enrollment_record_v1(canonical_record)
            .map_err(|_| RecoveryTransportError::Invalid)?;
        if record.account_id != self.scope.account_id
            || record.workspace_id != self.scope.workspace_id
        {
            return Err(RecoveryTransportError::Unauthorized);
        }
        let canonical_record_sha256 = Sha256Digest(Sha256::digest(canonical_record).into());
        let receipt = RecoveryEnrollmentReceipt {
            enrollment_id: record.enrollment_id,
            recovery_root_id: record.recovery_root_id,
            account_id: record.account_id,
            workspace_id: record.workspace_id,
            genesis_certificate_id: record.genesis_certificate_id,
            canonical_record_sha256,
            registered_at_ms: now_ms,
        };

        let mut state = lock(&self.shared)?;
        maybe_fail(&mut state)?;
        if let Some(accepted) = state.accepted.get(&self.scope.account_id) {
            if accepted.receipt.workspace_id != self.scope.workspace_id
                || accepted.canonical_record != canonical_record
            {
                return Err(RecoveryTransportError::Conflict);
            }
            let exact = accepted.receipt.clone();
            return Ok(state.forged_receipt.take().unwrap_or(exact));
        }

        state.accepted.insert(
            self.scope.account_id,
            AcceptedEnrollment {
                canonical_record: canonical_record.to_vec(),
                receipt: receipt.clone(),
                recovery_generation: 0,
                restores: BTreeMap::new(),
                device_ids: BTreeSet::from([record.genesis_certificate.device_id]),
                certificate_ids: BTreeSet::from([record.genesis_certificate_id]),
            },
        );
        Ok(state.forged_receipt.take().unwrap_or(receipt))
    }
}

impl RecoveryRestoreTransport for InMemoryRecoveryRestoreTransport {
    fn scope(&self) -> SyncScope {
        self.scope
    }

    fn root_snapshot(&self) -> Result<Option<RecoveryRootSnapshot>, RecoveryTransportError> {
        let mut state = lock(&self.shared)?;
        maybe_fail(&mut state)?;
        if let Some(forged) = state.forged_restore_snapshot.take() {
            return Ok(Some(forged));
        }
        let Some(accepted) = state.accepted.get(&self.scope.account_id) else {
            return Ok(None);
        };
        if accepted.receipt.workspace_id != self.scope.workspace_id {
            return Err(RecoveryTransportError::Conflict);
        }
        Ok(Some(RecoveryRootSnapshot {
            scope: self.scope,
            canonical_record: accepted.canonical_record.clone(),
            canonical_record_sha256: accepted.receipt.canonical_record_sha256,
            registered_at_ms: accepted.receipt.registered_at_ms,
            recovery_generation: accepted.recovery_generation,
        }))
    }

    fn submit_restore(
        &self,
        canonical_claim: &[u8],
        now_ms: u64,
    ) -> Result<RecoveryRestoreReceipt, RecoveryTransportError> {
        let claim = decode_recovery_device_claim_v1(canonical_claim)
            .map_err(|_| RecoveryTransportError::Invalid)?;
        if claim.account_id != self.scope.account_id
            || claim.workspace_id != self.scope.workspace_id
        {
            return Err(RecoveryTransportError::Unauthorized);
        }
        let canonical_claim_sha256 = Sha256Digest(Sha256::digest(canonical_claim).into());
        let mut state = lock(&self.shared)?;
        maybe_fail(&mut state)?;
        let receipt = {
            let accepted = state
                .accepted
                .get_mut(&self.scope.account_id)
                .ok_or(RecoveryTransportError::Invalid)?;
            if accepted.receipt.workspace_id != self.scope.workspace_id {
                return Err(RecoveryTransportError::Conflict);
            }
            if let Some(existing) = accepted.restores.get(&claim.restore_id) {
                if existing.canonical_claim != canonical_claim {
                    return Err(RecoveryTransportError::Conflict);
                }
                existing.receipt.clone()
            } else {
                let record = decode_recovery_enrollment_record_v1(&accepted.canonical_record)
                    .map_err(|_| RecoveryTransportError::Conflict)?;
                verify_recovery_device_claim(&record, &claim)
                    .map_err(|_| RecoveryTransportError::Invalid)?;
                if claim.expected_recovery_generation != accepted.recovery_generation
                    || accepted.recovery_generation >= i64::MAX as u64
                    || accepted.device_ids.contains(&claim.certificate.device_id)
                    || accepted.certificate_ids.contains(&claim.certificate_id)
                {
                    return Err(RecoveryTransportError::Conflict);
                }
                let next_generation = accepted
                    .recovery_generation
                    .checked_add(1)
                    .filter(|generation| *generation <= i64::MAX as u64)
                    .ok_or(RecoveryTransportError::Conflict)?;
                let receipt = RecoveryRestoreReceipt {
                    restore_id: claim.restore_id,
                    enrollment_id: claim.enrollment_id,
                    recovery_root_id: claim.recovery_root_id,
                    account_id: claim.account_id,
                    workspace_id: claim.workspace_id,
                    certificate_id: claim.certificate_id,
                    canonical_record_sha256: claim.canonical_record_sha256,
                    canonical_claim_sha256,
                    accepted_generation: next_generation,
                    accepted_at_ms: now_ms,
                };
                accepted.device_ids.insert(claim.certificate.device_id);
                accepted.certificate_ids.insert(claim.certificate_id);
                accepted.restores.insert(
                    claim.restore_id,
                    AcceptedRestore {
                        canonical_claim: canonical_claim.to_vec(),
                        receipt: receipt.clone(),
                    },
                );
                accepted.recovery_generation = next_generation;
                receipt
            }
        };
        Ok(state.forged_restore_receipt.take().unwrap_or(receipt))
    }

    fn restore_claim(
        &self,
        restore_id: RecoveryRestoreId,
    ) -> Result<Option<RecoveryRestoreProjection>, RecoveryTransportError> {
        let mut state = lock(&self.shared)?;
        maybe_fail(&mut state)?;
        if let Some(forged) = state.forged_restore_projection.take() {
            return Ok(Some(forged));
        }
        if state.omit_next_restore_claim {
            state.omit_next_restore_claim = false;
            return Ok(None);
        }
        let Some(accepted) = state.accepted.get(&self.scope.account_id) else {
            return Ok(None);
        };
        if accepted.receipt.workspace_id != self.scope.workspace_id {
            return Err(RecoveryTransportError::Conflict);
        }
        Ok(accepted
            .restores
            .get(&restore_id)
            .map(|restore| RecoveryRestoreProjection {
                canonical_claim: restore.canonical_claim.clone(),
                receipt: restore.receipt.clone(),
            }))
    }
}

fn lock(shared: &SharedProvider) -> Result<MutexGuard<'_, ProviderState>, RecoveryTransportError> {
    shared
        .state
        .lock()
        .map_err(|_| RecoveryTransportError::Transient)
}

fn maybe_fail(state: &mut ProviderState) -> Result<(), RecoveryTransportError> {
    if state.fail_next == 0 {
        return Ok(());
    }
    state.fail_next -= 1;
    Err(RecoveryTransportError::Transient)
}

impl fmt::Debug for InMemoryRecoveryEnrollmentProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InMemoryRecoveryEnrollmentProvider([REDACTED])")
    }
}

impl fmt::Debug for InMemoryRecoveryEnrollmentTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InMemoryRecoveryEnrollmentTransport")
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for InMemoryRecoveryRestoreTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InMemoryRecoveryRestoreTransport")
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}
