mod support;
use context_relay_core::{
    crypto::{DeviceKeys, RecoveryPhrase},
    devices::{
        recovery_crypto::decode_recovery_enrollment_record_v1,
        recovery_restore::{
            RecoveryRestoreCoordinator, RecoveryRestoreIdentity, RecoveryRestoreOutcome,
        },
        recovery_restore_transport::*,
        recovery_transport::RecoveryTransportError,
    },
    sync::SyncScope,
    vault::Vault,
};
use context_relay_protocol::{NativePlatform, RecoveryRestoreId, Sha256Digest};
use sha2::{Digest, Sha256};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU8, Ordering},
};

#[derive(Clone)]
struct CheckingTransport {
    snapshot: RecoveryRootSnapshot,
    submitted: Arc<Mutex<Vec<Vec<u8>>>>,
    endpoint: context_relay_core::devices::membership_crypto::MembershipEndpoint,
    objects: Vec<Vec<u8>>,
    stage: Arc<AtomicU8>,
}
impl RecoveryRestoreTransport for CheckingTransport {
    fn scope(&self) -> SyncScope {
        self.snapshot.scope
    }
    fn root_snapshot(&self) -> Result<Option<RecoveryRootSnapshot>, RecoveryTransportError> {
        Ok(Some(self.snapshot.clone()))
    }
    fn membership_endpoint(
        &self,
    ) -> Result<
        context_relay_core::devices::membership_crypto::MembershipEndpoint,
        RecoveryTransportError,
    > {
        Ok(self.endpoint)
    }
    fn membership_event(
        &self,
        address: Sha256Digest,
    ) -> Result<
        Option<context_relay_core::devices::membership_transport::MembershipEventObject>,
        RecoveryTransportError,
    > {
        if self.stage.load(Ordering::SeqCst) >= 3
            && let Some(canonical) = self.submitted.lock().unwrap().last()
        {
            let object=context_relay_core::devices::membership_transport::MembershipEventObject::from_evidence(&context_relay_core::devices::membership_crypto::MembershipHistoryEvent::RecoveryAdd{canonical_claim:canonical}).unwrap();
            if object.endpoints().unwrap().1 == address {
                return Ok(Some(object));
            }
        }
        Ok(self.objects.iter().map(|bytes|context_relay_core::devices::membership_transport::MembershipEventObject::from_canonical_bytes(bytes).unwrap()).find(|object|object.endpoints().unwrap().1==address))
    }
    fn submit_restore(
        &self,
        canonical: &[u8],
        _: u64,
    ) -> Result<RecoveryRestoreReceipt, RecoveryTransportError> {
        assert_eq!(
            &canonical[..3],
            &[0xb0, 0, 2],
            "new recovery must submit an explicit root-authorized V2 membership claim"
        );
        let claim=context_relay_core::devices::recovery_restore_crypto::v2::decode_recovery_device_claim_v2(canonical).unwrap();
        assert_eq!(claim.previous_state_sha256, self.endpoint.state_sha256);
        assert_eq!((claim.certificate.control_epoch, claim.key_epoch), (2, 2));
        self.submitted.lock().unwrap().push(canonical.to_vec());
        if self.stage.load(Ordering::SeqCst) == 0 {
            return Err(RecoveryTransportError::Transient);
        }
        Ok(receipt(canonical))
    }
    fn restore_claim(
        &self,
        _: RecoveryRestoreId,
    ) -> Result<Option<RecoveryRestoreProjection>, RecoveryTransportError> {
        if self.stage.load(Ordering::SeqCst) < 2 {
            return Ok(None);
        }
        Ok(self
            .submitted
            .lock()
            .unwrap()
            .last()
            .map(|canonical| RecoveryRestoreProjection {
                canonical_claim: canonical.clone(),
                receipt: receipt(canonical),
            }))
    }
}
fn receipt(canonical: &[u8]) -> RecoveryRestoreReceipt {
    let c =
        context_relay_core::devices::recovery_restore_crypto::v2::decode_recovery_device_claim_v2(
            canonical,
        )
        .unwrap();
    RecoveryRestoreReceipt {
        restore_id: c.restore_id,
        enrollment_id: c.enrollment_id,
        recovery_root_id: c.recovery_root_id,
        account_id: c.account_id,
        workspace_id: c.workspace_id,
        certificate_id: c.certificate_id,
        canonical_record_sha256: c.canonical_record_sha256,
        canonical_claim_sha256: Sha256Digest(Sha256::digest(canonical).into()),
        accepted_generation: c.expected_recovery_generation + 1,
        accepted_at_ms: 2,
    }
}
fn decode(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}
#[test]
fn native_recovery_prepares_v2_and_retries_exact_rotated_claim_after_restart_without_phrase() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/hosted-recovery-claim-v2.json")).unwrap();
    let canonical = decode(fixture["canonicalRecord"].as_str().unwrap());
    let record = decode_recovery_enrollment_record_v1(&canonical).unwrap();
    let transport = CheckingTransport {
        snapshot: RecoveryRootSnapshot {
            scope: SyncScope {
                account_id: record.account_id,
                workspace_id: record.workspace_id,
            },
            canonical_record_sha256: Sha256Digest(Sha256::digest(&canonical).into()),
            canonical_record: canonical,
            registered_at_ms: 1,
            recovery_generation: 0,
        },
        submitted: Arc::default(),
        endpoint: context_relay_core::devices::membership_crypto::MembershipEndpoint {
            state_sha256: Sha256Digest(
                decode(fixture["parentStateSha256"].as_str().unwrap())
                    .try_into()
                    .unwrap(),
            ),
            control_epoch: 2,
            key_epoch: 2,
        },
        stage: Arc::default(),
        objects: fixture["parentObjects"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| decode(v.as_str().unwrap()))
            .collect(),
    };
    let coordinator = RecoveryRestoreCoordinator::new(transport.clone());
    let path = support::TempVault::new("recovery-coordinator-v2");
    let store = support::MemoryKeyStore::default();
    let keys = DeviceKeys::from_seeds_for_test([31; 32], [32; 32]);
    let identity = RecoveryRestoreIdentity {
        device_id: "018f22e2-79b0-7cc8-98c4-dc0c0c073917".parse().unwrap(),
        device_name: "Recovered".into(),
        platform: NativePlatform::Windows,
        keys: &keys,
    };
    let mut vault = Vault::open(path.path(), "restore-coordinator-v2", &store).unwrap();
    let phrase = RecoveryPhrase::from_entropy_for_test([7; 32])
        .unwrap()
        .to_words();
    assert!(matches!(
        coordinator.recover(&mut vault, phrase, &identity).unwrap(),
        RecoveryRestoreOutcome::Submitting { .. }
    ));
    assert!(vault.prepared_recovery_v2(&keys).unwrap().is_some());
    drop(vault);
    let mut vault = Vault::open(path.path(), "restore-coordinator-v2", &store).unwrap();
    assert!(matches!(
        coordinator.resume_prepared(&mut vault, &identity).unwrap(),
        RecoveryRestoreOutcome::Submitting { .. }
    ));
    {
        let submitted = transport.submitted.lock().unwrap();
        assert_eq!(submitted.len(), 2);
        assert_eq!(submitted[0], submitted[1]);
    }
    for stage in [1, 2] {
        transport.stage.store(stage, Ordering::SeqCst);
        assert!(matches!(
            coordinator.resume_prepared(&mut vault, &identity).unwrap(),
            RecoveryRestoreOutcome::Submitting { .. }
        ));
        assert!(
            vault
                .recovery_membership_admission(&keys)
                .unwrap()
                .is_none(),
            "receipt or projection without exact publication must not admit"
        );
        assert!(vault.trusted_sync_material(&keys).is_err());
        drop(vault);
        vault = Vault::open(path.path(), "restore-coordinator-v2", &store).unwrap();
    }
    transport.stage.store(3, Ordering::SeqCst);
    let raw = rusqlite::Connection::open(path.path()).unwrap();
    let database_key = store.key("restore-coordinator-v2");
    unsafe {
        assert_eq!(
            rusqlite::ffi::sqlite3_key(raw.handle(), database_key.as_ptr().cast(), 32),
            0
        );
    }
    raw.execute_batch("CREATE TRIGGER reject_recovery_admission BEFORE INSERT ON recovery_v2_admission BEGIN SELECT RAISE(ABORT,'forced admission failure'); END;").unwrap();
    assert!(coordinator.resume_prepared(&mut vault, &identity).is_err());
    for table in [
        "accepted_membership",
        "membership_events",
        "membership_epoch_secrets",
        "recovery_v2_admission",
        "membership_current_activation",
    ] {
        assert_eq!(
            raw.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0,
            "atomic admission rollback: {table}"
        );
    }
    assert!(vault.prepared_recovery_v2(&keys).unwrap().is_some());
    raw.execute_batch("DROP TRIGGER reject_recovery_admission")
        .unwrap();
    drop(raw);
    drop(vault);
    vault = Vault::open(path.path(), "restore-coordinator-v2", &store).unwrap();
    assert!(
        vault
            .recovery_membership_admission(&keys)
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        coordinator.resume_prepared(&mut vault, &identity).unwrap(),
        RecoveryRestoreOutcome::RestoringHistory { .. }
    ));
    let admitted = vault.recovery_membership_admission(&keys).unwrap().unwrap();
    assert_eq!((admitted.control_epoch, admitted.key_epoch), (2, 2));
    assert!(
        vault.trusted_sync_material(&keys).is_err(),
        "admission is not current write activation"
    );
    drop(vault);
    vault = Vault::open(path.path(), "restore-coordinator-v2", &store).unwrap();
    assert_eq!(
        vault.recovery_membership_admission(&keys).unwrap(),
        Some(admitted)
    );
    assert!(vault.trusted_sync_material(&keys).is_err());
    let prepared = vault.prepared_recovery_v2(&keys).unwrap().unwrap();
    let ack = receipt(&prepared.canonical_claim);
    let projection = RecoveryRestoreProjection {
        canonical_claim: prepared.canonical_claim.clone(),
        receipt: ack.clone(),
    };
    let object = transport
        .membership_event(admitted.state_sha256)
        .unwrap()
        .unwrap();
    assert_eq!(
        vault
            .accept_recovery_membership(&ack, &projection, &object, &keys)
            .unwrap(),
        context_relay_core::vault::CommitDisposition::ExactReplay
    );
    assert!(vault.trusted_sync_material(&keys).is_err());
    let calls = transport.submitted.lock().unwrap().len();
    assert!(matches!(
        coordinator.resume_prepared(&mut vault, &identity).unwrap(),
        RecoveryRestoreOutcome::RestoringHistory { .. }
    ));
    assert_eq!(transport.submitted.lock().unwrap().len(), calls);
    let wrong = DeviceKeys::from_seeds_for_test([41; 32], [42; 32]);
    assert!(vault.recovery_membership_admission(&wrong).is_err());
    // A destroyed/revoked historical author can supply a candidate at its original epoch.
    let mut checkpoint = support::checkpoint();
    checkpoint.account_id = record.account_id;
    checkpoint.workspace_id = record.workspace_id;
    checkpoint.creator_device = record.genesis_certificate.device_id;
    checkpoint.created_hlc.node = checkpoint.creator_device;
    checkpoint.state_hash = context_relay_core::sync::StateSummaryV1 { entries: vec![] }
        .state_hash()
        .unwrap();
    let former = DeviceKeys::from_seeds_for_test([1; 32], [2; 32]);
    former.sign_checkpoint(&mut checkpoint).unwrap();
    drop(former);
    let checkpoint = context_relay_protocol::encode_checkpoint_v1(&checkpoint).unwrap();
    let budget = context_relay_core::vault::HistoricalReconstructionBudget {
        transfer: context_relay_core::vault::HistoricalTransferBudget {
            history: context_relay_core::devices::membership_crypto::MembershipHistoryBudget {
                max_events: 4096,
                max_bytes: 64 * 1024 * 1024,
            },
            max_pages: 4096,
            max_bytes: 64 * 1024 * 1024,
        },
        max_operations: 100000,
        max_operation_bytes: 64 * 1024 * 1024,
        max_dependencies: 1000000,
    };
    let mut bad_checkpoint = checkpoint.clone();
    let last = bad_checkpoint.len() - 1;
    bad_checkpoint[last] ^= 1;
    assert!(
        vault
            .select_recovery_history(admitted, &bad_checkpoint, &keys, budget)
            .is_err()
    );
    assert!(
        vault
            .select_recovery_history(admitted, &vec![0; 1024 * 1024 + 1], &keys, budget)
            .is_err()
    );
    assert!(
        vault
            .select_recovery_history(
                context_relay_core::devices::membership_crypto::MembershipEndpoint {
                    state_sha256: Sha256Digest([99; 32]),
                    ..admitted
                },
                &checkpoint,
                &keys,
                budget
            )
            .is_err()
    );
    assert!(
        vault
            .recovery_history_selection(&keys, budget)
            .unwrap()
            .is_none()
    );
    let raw = rusqlite::Connection::open(path.path()).unwrap();
    unsafe {
        assert_eq!(
            rusqlite::ffi::sqlite3_key(raw.handle(), database_key.as_ptr().cast(), 32),
            0
        );
    }
    raw.execute_batch("CREATE TRIGGER reject_recovery_selection BEFORE INSERT ON recovery_history_selection BEGIN SELECT RAISE(ABORT,'forced selection failure'); END;").unwrap();
    assert!(
        vault
            .select_recovery_history(admitted, &checkpoint, &keys, budget)
            .is_err()
    );
    assert_eq!(
        raw.query_row("SELECT count(*) FROM recovery_history_targets", [], |r| r
            .get::<_, i64>(
            0
        ))
        .unwrap(),
        0
    );
    raw.execute_batch("DROP TRIGGER reject_recovery_selection")
        .unwrap();
    drop(raw);
    let embeddings = |_, _: &context_relay_protocol::RecordMutationV1| Ok(None);
    let mut initial_bad = context_relay_protocol::decode_checkpoint_v1(&checkpoint).unwrap();
    initial_bad.state_hash = Sha256Digest([98; 32]);
    DeviceKeys::from_seeds_for_test([1; 32], [2; 32])
        .sign_checkpoint(&mut initial_bad)
        .unwrap();
    let initial_bad = context_relay_protocol::encode_checkpoint_v1(&initial_bad).unwrap();
    let bad_selection = vault
        .select_recovery_history(admitted, &initial_bad, &keys, budget)
        .unwrap();
    assert!(
        vault
            .reconstruct_recovery_history(bad_selection, &[], &keys, budget, &embeddings)
            .is_err()
    );
    let selected = vault
        .select_recovery_history(admitted, &checkpoint, &keys, budget)
        .unwrap();

    let target = selected.canonical_bytes();
    assert_eq!(target.len(), 307);
    let mut expected = b"context-relay/recovery-history-target/v1\0".to_vec();
    expected.extend(1u16.to_be_bytes());
    expected.extend(prepared.claim.restore_id.as_bytes());
    expected.extend(record.account_id.as_bytes());
    expected.extend(record.workspace_id.as_bytes());
    expected.extend(prepared.claim.canonical_record_sha256.0);
    expected.extend(Sha256::digest(&prepared.canonical_claim));
    expected.extend(admitted.state_sha256.0);
    expected.extend(admitted.state_sha256.0);
    expected.extend(admitted.control_epoch.to_be_bytes());
    expected.extend(admitted.key_epoch.to_be_bytes());
    expected.extend(identity.device_id.as_bytes());
    let mut decoder = minicbor::Decoder::new(&prepared.canonical_claim);
    assert_eq!(decoder.map().unwrap(), Some(16));
    for key in 0..9 {
        assert_eq!(decoder.u8().unwrap(), key);
        decoder.skip().unwrap();
    }
    assert_eq!(decoder.u8().unwrap(), 9);
    let start = decoder.position();
    decoder.skip().unwrap();
    expected.extend(Sha256::digest(
        &prepared.canonical_claim[start..decoder.position()],
    ));
    expected.extend(Sha256::digest(&checkpoint));
    assert_eq!(target, expected);
    assert_eq!(
        vault
            .select_recovery_history(admitted, &checkpoint, &keys, budget)
            .unwrap(),
        selected
    );
    let raw = rusqlite::Connection::open(path.path()).unwrap();
    unsafe {
        assert_eq!(
            rusqlite::ffi::sqlite3_key(raw.handle(), database_key.as_ptr().cast(), 32),
            0
        );
    }
    let total=raw.query_row("SELECT sum(length(target_sha256)+length(target)+length(checkpoint)+length(selection_signature)) FROM recovery_history_targets",[],|r|r.get::<_,i64>(0)).unwrap();
    drop(raw);
    let mut at_capacity = budget;
    at_capacity.transfer.max_bytes = total as usize;
    assert_eq!(
        vault
            .select_recovery_history(admitted, &checkpoint, &keys, at_capacity)
            .unwrap(),
        selected,
        "exact retry remains possible at byte cap"
    );
    let mut excess = context_relay_protocol::decode_checkpoint_v1(&checkpoint).unwrap();
    excess.state_hash = Sha256Digest([97; 32]);
    DeviceKeys::from_seeds_for_test([1; 32], [2; 32])
        .sign_checkpoint(&mut excess)
        .unwrap();
    assert!(matches!(
        vault.select_recovery_history(
            admitted,
            &context_relay_protocol::encode_checkpoint_v1(&excess).unwrap(),
            &keys,
            at_capacity
        ),
        Err(context_relay_core::vault::VaultError::BudgetExceeded)
    ));

    assert_eq!(selected.authorizing_endpoint(), admitted);
    assert_eq!(
        selected.checkpoint_sha256(),
        Sha256Digest(Sha256::digest(&checkpoint).into())
    );
    assert_eq!(
        vault.recovery_history_selection(&keys, budget).unwrap(),
        Some(selected)
    );
    assert!(
        vault.trusted_sync_material(&keys).is_err(),
        "selection is not installation or activation"
    );
    drop(vault);
    vault = Vault::open(path.path(), "restore-coordinator-v2", &store).unwrap();
    assert_eq!(
        vault.recovery_history_selection(&keys, budget).unwrap(),
        Some(selected)
    );
    assert!(
        !vault
            .recovery_history_is_installed(selected, &keys, budget)
            .unwrap()
    );
    let proof = vault
        .reconstruct_recovery_history(selected, &[], &keys, budget, &embeddings)
        .unwrap()
        .unwrap();
    assert!(
        !vault
            .recovery_history_is_installed(selected, &keys, budget)
            .unwrap()
    );
    assert!(vault.trusted_sync_material(&keys).is_err());
    drop(vault);
    vault = Vault::open(path.path(), "restore-coordinator-v2", &store).unwrap();
    assert!(
        !vault
            .recovery_history_is_installed(selected, &keys, budget)
            .unwrap()
    );
    let raw = rusqlite::Connection::open(path.path()).unwrap();
    unsafe {
        assert_eq!(
            rusqlite::ffi::sqlite3_key(raw.handle(), database_key.as_ptr().cast(), 32),
            0
        );
    }
    let total=raw.query_row("SELECT sum(length(target_sha256)+length(target)+length(checkpoint)+length(selection_signature)+COALESCE(length(prefixes),0)+COALESCE(length(reconstructed_signature),0)+COALESCE(length(installed_signature),0)) FROM recovery_history_targets",[],|r|r.get::<_,i64>(0)).unwrap();
    drop(raw);
    let mut installation_cap = budget;
    installation_cap.transfer.max_bytes = total as usize;
    assert!(
        matches!(
            vault.install_recovery_history(&proof, &keys, installation_cap, &embeddings),
            Err(context_relay_core::vault::VaultError::BudgetExceeded)
        ),
        "stage1 receipt must fit atomically"
    );
    assert!(
        !vault
            .recovery_history_is_installed(selected, &keys, budget)
            .unwrap()
    );
    assert!(vault.trusted_sync_material(&keys).is_err());
    drop(vault);
    vault = Vault::open(path.path(), "restore-coordinator-v2", &store).unwrap();
    assert!(
        !vault
            .recovery_history_is_installed(selected, &keys, budget)
            .unwrap()
    );
    assert!(
        vault
            .install_recovery_history(&proof, &keys, budget, &embeddings)
            .unwrap()
    );
    assert!(
        vault
            .recovery_history_is_installed(selected, &keys, budget)
            .unwrap()
    );
    drop(vault);
    vault = Vault::open(path.path(), "restore-coordinator-v2", &store).unwrap();
    assert!(
        vault
            .recovery_history_is_installed(selected, &keys, budget)
            .unwrap()
    );
    use context_relay_core::sync::{
        OperationBuildRequest, OperationBuilder, StateSummaryEntryV1, StateSummaryV1, SyncIdentity,
    };
    use context_relay_protocol::{
        DeviceSequence, HybridLogicalClock, ProjectIdentity, RecordKind, RecordMutationV1,
    };
    let project_id = "018f22e2-79b0-7cc8-98c4-dc0c0c073951".parse().unwrap();
    let mutation = RecordMutationV1::UpsertProject(ProjectIdentity {
        project_id,
        name: "Recovered historical project".into(),
        github_repository_id: None,
        git_remote_fingerprint: None,
        monorepo_subdirectory: None,
    });
    let author_id = "018f22e2-79b0-7cc8-98c4-dc0c0c073904".parse().unwrap();
    let author = DeviceKeys::from_seeds_for_test([3; 32], [4; 32]);
    let content = context_relay_core::crypto::ContentKey::from_bytes([22; 32]);
    let parent_object=context_relay_core::devices::membership_transport::MembershipEventObject::from_canonical_bytes(&transport.objects[0]).unwrap();
    let operation = OperationBuilder::new(SyncIdentity {
        membership_endpoint: Some(
            context_relay_core::devices::membership_crypto::MembershipEndpoint {
                state_sha256: parent_object.endpoints().unwrap().1,
                control_epoch: 1,
                key_epoch: 1,
            },
        ),
        account_id: record.account_id,
        workspace_id: record.workspace_id,
        device_id: author_id,
        control_epoch: 1,
        key_epoch: 1,
        device_keys: &author,
        content_key: &content,
    })
    .build(OperationBuildRequest {
        operation_id: "018f22e2-79b0-7cc8-98c4-dc0c0c073952".parse().unwrap(),
        project_id: Some(project_id),
        mutation: &mutation,
        causal_frontier: vec![],
        previous: None,
        blob_refs: vec![],
        created_hlc: HybridLogicalClock::new(1001, 0, author_id),
    })
    .unwrap();
    drop(author);
    drop(content);
    let mut next = context_relay_protocol::decode_checkpoint_v1(&checkpoint).unwrap();
    next.causal_frontier = vec![DeviceSequence {
        device_id: author_id,
        sequence: 1,
    }];
    next.state_hash = StateSummaryV1 {
        entries: vec![StateSummaryEntryV1 {
            record_id: mutation.record_id(),
            record_kind: RecordKind::Project,
            head_hashes: vec![operation.canonical_hash],
            tombstoned: false,
            conflicted: false,
        }],
    }
    .state_hash()
    .unwrap();
    let former = DeviceKeys::from_seeds_for_test([1; 32], [2; 32]);
    former.sign_checkpoint(&mut next).unwrap();
    let next_bytes = context_relay_protocol::encode_checkpoint_v1(&next).unwrap();
    assert!(
        vault
            .select_recovery_history(admitted, &next_bytes, &keys, budget)
            .is_err(),
        "a reconstructed old target requires proof of extension"
    );
    vault
        .stage_historical_operations(
            admitted,
            identity.device_id,
            std::slice::from_ref(&operation.canonical_bytes),
            &keys,
            budget,
        )
        .unwrap();
    let mut false_state = next.clone();
    false_state.state_hash = Sha256Digest([99; 32]);
    former.sign_checkpoint(&mut false_state).unwrap();
    drop(former);
    let false_bytes = context_relay_protocol::encode_checkpoint_v1(&false_state).unwrap();
    let false_target = vault
        .select_recovery_history(admitted, &false_bytes, &keys, budget)
        .unwrap();
    assert!(
        vault
            .reconstruct_recovery_history(false_target, &[], &keys, budget, &embeddings)
            .is_err(),
        "checkpoint signature does not prove claimed state"
    );
    assert!(vault.projects().unwrap().is_empty());
    let next_target = vault
        .select_recovery_history(admitted, &next_bytes, &keys, budget)
        .unwrap();
    let raw = rusqlite::Connection::open(path.path()).unwrap();
    unsafe {
        assert_eq!(
            rusqlite::ffi::sqlite3_key(raw.handle(), database_key.as_ptr().cast(), 32),
            0
        );
    }
    raw.execute_batch("DELETE FROM historical_operation_evidence")
        .unwrap();
    drop(raw);
    assert!(
        vault
            .reconstruct_recovery_history(next_target, &[], &keys, budget, &embeddings)
            .unwrap()
            .is_none()
    );
    assert!(
        !vault
            .recovery_history_is_installed(next_target, &keys, budget)
            .unwrap()
    );
    drop(vault);
    vault = Vault::open(path.path(), "restore-coordinator-v2", &store).unwrap();
    let proof = vault
        .reconstruct_recovery_history(
            next_target,
            std::slice::from_ref(&operation.canonical_bytes),
            &keys,
            budget,
            &embeddings,
        )
        .unwrap()
        .unwrap();
    let raw = rusqlite::Connection::open(path.path()).unwrap();
    unsafe {
        assert_eq!(
            rusqlite::ffi::sqlite3_key(raw.handle(), database_key.as_ptr().cast(), 32),
            0
        );
    }
    raw.execute_batch("CREATE TRIGGER reject_recovery_install BEFORE UPDATE OF installed_signature ON recovery_history_targets BEGIN SELECT RAISE(ABORT,'forced install failure'); END;").unwrap();
    assert!(
        vault
            .install_recovery_history(&proof, &keys, budget, &embeddings)
            .is_err()
    );
    assert!(vault.projects().unwrap().is_empty());
    assert!(
        !vault
            .recovery_history_is_installed(next_target, &keys, budget)
            .unwrap()
    );
    raw.execute_batch("DROP TRIGGER reject_recovery_install")
        .unwrap();
    drop(raw);
    assert!(
        vault
            .install_recovery_history(&proof, &keys, budget, &embeddings)
            .unwrap()
    );
    assert_eq!(
        vault.projects().unwrap()[0].name,
        "Recovered historical project"
    );
    drop(vault);
    vault = Vault::open(path.path(), "restore-coordinator-v2", &store).unwrap();
    assert!(
        vault
            .recovery_history_is_installed(next_target, &keys, budget)
            .unwrap()
    );
    assert!(
        vault
            .select_recovery_history(admitted, &checkpoint, &keys, budget)
            .is_err(),
        "installed target must not regress"
    );
    let incomplete = vault
        .select_recovery_history(admitted, &false_bytes, &keys, budget)
        .unwrap();
    assert!(
        vault
            .select_recovery_history(admitted, &checkpoint, &keys, budget)
            .is_err(),
        "A reconstructed -> B incomplete must not permit C below A"
    );
    assert_eq!(
        vault.recovery_history_selection(&keys, budget).unwrap(),
        Some(incomplete)
    );
    let old_hash = Sha256Digest(Sha256::digest(selected.canonical_bytes()).into());
    for clear in ["reconstructed_signature", "prefixes"] {
        drop(vault);
        let raw = rusqlite::Connection::open(path.path()).unwrap();
        unsafe {
            assert_eq!(
                rusqlite::ffi::sqlite3_key(raw.handle(), database_key.as_ptr().cast(), 32),
                0
            );
        }
        let saved=raw.query_row("SELECT prefixes,reconstructed_signature FROM recovery_history_targets WHERE target_sha256=?1",[old_hash.0.as_slice()],|r|Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,Vec<u8>>(1)?))).unwrap();
        raw.pragma_update(None, "ignore_check_constraints", true)
            .unwrap();
        raw.execute(
            &format!("UPDATE recovery_history_targets SET {clear}=NULL WHERE target_sha256=?1"),
            [old_hash.0.as_slice()],
        )
        .unwrap();
        drop(raw);
        vault = Vault::open(path.path(), "restore-coordinator-v2", &store).unwrap();
        assert!(
            vault
                .select_recovery_history(admitted, &next_bytes, &keys, budget)
                .is_err(),
            "inconsistent old empty receipt cannot disappear across restart: {clear}"
        );
        drop(vault);
        let raw = rusqlite::Connection::open(path.path()).unwrap();
        unsafe {
            assert_eq!(
                rusqlite::ffi::sqlite3_key(raw.handle(), database_key.as_ptr().cast(), 32),
                0
            );
        }
        raw.execute("UPDATE recovery_history_targets SET prefixes=?1,reconstructed_signature=?2 WHERE target_sha256=?3",rusqlite::params![saved.0,saved.1,old_hash.0.as_slice()]).unwrap();
        drop(raw);
        vault = Vault::open(path.path(), "restore-coordinator-v2", &store).unwrap();
    }
    assert_eq!(
        vault
            .select_recovery_history(admitted, &next_bytes, &keys, budget)
            .unwrap(),
        next_target
    );
    assert_eq!(
        vault.projects().unwrap()[0].name,
        "Recovered historical project"
    );
    drop(vault);
    let raw = rusqlite::Connection::open(path.path()).unwrap();
    unsafe {
        assert_eq!(
            rusqlite::ffi::sqlite3_key(raw.handle(), database_key.as_ptr().cast(), 32),
            0
        );
    }
    let receipt_count = raw
        .query_row(
            "SELECT count(*) FROM recovery_history_targets WHERE installed_signature IS NOT NULL",
            [],
            |r| r.get::<_, i64>(0),
        )
        .unwrap();
    raw.execute("DELETE FROM recovery_history_selection", [])
        .unwrap();
    drop(raw);
    vault = Vault::open(path.path(), "restore-coordinator-v2", &store).unwrap();
    assert!(
        vault
            .select_recovery_history(admitted, &checkpoint, &keys, budget)
            .is_err(),
        "a missing selector cannot erase the authenticated reconstruction floor"
    );
    assert_eq!(
        vault
            .select_recovery_history(admitted, &next_bytes, &keys, budget)
            .unwrap(),
        next_target
    );
    assert!(
        vault
            .recovery_history_is_installed(next_target, &keys, budget)
            .unwrap()
    );
    let raw = rusqlite::Connection::open(path.path()).unwrap();
    unsafe {
        assert_eq!(
            rusqlite::ffi::sqlite3_key(raw.handle(), database_key.as_ptr().cast(), 32),
            0
        );
    }
    assert_eq!(
        raw.query_row(
            "SELECT count(*) FROM recovery_history_targets WHERE installed_signature IS NOT NULL",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        receipt_count
    );
    assert_eq!(
        vault.projects().unwrap()[0].name,
        "Recovered historical project"
    );
}
