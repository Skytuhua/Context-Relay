mod support;
use context_relay_core::{
    crypto::DeviceKeys,
    devices::{
        membership_crypto::MembershipHistoryBudget,
        membership_transport::MembershipEventObject,
        recovery_restore_crypto::v2::decode_recovery_device_claim_v2,
        recovery_restore_transport::{RecoveryRestoreProjection, RecoveryRestoreReceipt},
    },
    vault::{HistoricalReconstructionBudget, HistoricalTransferBudget, Vault},
};
use context_relay_protocol::{RecoveryHistoryProgress, RecoveryRestoreStatus, Sha256Digest};
use sha2::{Digest, Sha256};
fn decode(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|n| u8::from_str_radix(&value[n..n + 2], 16).unwrap())
        .collect()
}
fn budget() -> HistoricalReconstructionBudget {
    HistoricalReconstructionBudget {
        transfer: HistoricalTransferBudget {
            history: MembershipHistoryBudget {
                max_events: 4096,
                max_bytes: 64 * 1024 * 1024,
            },
            max_pages: 4096,
            max_bytes: 64 * 1024 * 1024,
        },
        max_operations: 100000,
        max_operation_bytes: 64 * 1024 * 1024,
        max_dependencies: 1000000,
    }
}

#[test]
fn authenticated_candidate_is_read_only_and_missing_keys_are_distinct_from_current_authority() {
    history_selection_fixture(false);
}

#[test]
fn original_session_cancellation_rolls_back_history_transactions() {
    history_selection_fixture(true);
}

fn history_selection_fixture(check_authorization: bool) {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/hosted-recovery-claim-v2.json")).unwrap();
    let record = decode(fixture["canonicalRecord"].as_str().unwrap());
    let canonical = decode(fixture["canonicalClaim"].as_str().unwrap());
    let claim = decode_recovery_device_claim_v2(&canonical).unwrap();
    let objects = fixture["parentObjects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| MembershipEventObject::from_canonical_bytes(&decode(v.as_str().unwrap())).unwrap())
        .collect::<Vec<_>>();
    let path = support::TempVault::new("history-selection");
    let store = support::MemoryKeyStore::default();
    let keys = DeviceKeys::from_seeds_for_test([31; 32], [32; 32]);
    let mut vault = Vault::open(path.path(), "history-selection", &store).unwrap();
    vault
        .prepare_recovery_v2(&record, &canonical, &objects, &[], &keys)
        .unwrap();
    let receipt = RecoveryRestoreReceipt {
        restore_id: claim.restore_id,
        enrollment_id: claim.enrollment_id,
        recovery_root_id: claim.recovery_root_id,
        account_id: claim.account_id,
        workspace_id: claim.workspace_id,
        certificate_id: claim.certificate_id,
        canonical_record_sha256: claim.canonical_record_sha256,
        canonical_claim_sha256: Sha256Digest(Sha256::digest(&canonical).into()),
        accepted_generation: 1,
        accepted_at_ms: 2,
    };
    let publication = MembershipEventObject::from_evidence(
        &context_relay_core::devices::membership_crypto::MembershipHistoryEvent::RecoveryAdd {
            canonical_claim: &canonical,
        },
    )
    .unwrap();
    vault
        .accept_recovery_membership(
            &receipt,
            &RecoveryRestoreProjection {
                canonical_claim: canonical,
                receipt: receipt.clone(),
            },
            &publication,
            &keys,
        )
        .unwrap();
    let endpoint = vault.recovery_membership_admission(&keys).unwrap().unwrap();
    assert!(matches!(
        vault.recovery_history_status(&keys, budget()).unwrap(),
        RecoveryRestoreStatus::RestoringHistory {
            history: RecoveryHistoryProgress::Unselected {},
            ..
        }
    ));
    let root =
        context_relay_core::devices::recovery_crypto::decode_recovery_enrollment_record_v1(&record)
            .unwrap();
    let former = DeviceKeys::from_seeds_for_test([1; 32], [2; 32]);
    let history_author = DeviceKeys::from_seeds_for_test([3; 32], [4; 32]);
    let history_author_id = "018f22e2-79b0-7cc8-98c4-dc0c0c073904".parse().unwrap();
    use context_relay_core::sync::{
        OperationBuildRequest, OperationBuilder, OperationChainHead, SyncIdentity,
    };
    use context_relay_protocol::{
        DeviceSequence, HybridLogicalClock, ProjectIdentity, RecordMutationV1,
    };
    let recovery_keys = context_relay_core::crypto::RecoveryKeys::derive(
        &context_relay_core::crypto::RecoveryPhrase::from_entropy_for_test([7; 32]).unwrap(),
    )
    .unwrap();
    let original =
        context_relay_core::devices::recovery_crypto::open_recovery_metadata(&root, &recovery_keys)
            .unwrap();
    let content = context_relay_core::crypto::ContentKey::from_bytes(*original.active_epoch_key());
    let builder = OperationBuilder::new(SyncIdentity {
        membership_endpoint: None,
        account_id: claim.account_id,
        workspace_id: claim.workspace_id,
        device_id: history_author_id,
        control_epoch: 1,
        key_epoch: 1,
        device_keys: &history_author,
        content_key: &content,
    });
    let mut operations = Vec::new();
    let mut previous = None;
    let mut summaries = Vec::new();
    for n in 1..=4 {
        let project_id = format!("018f22e2-79b0-7cc8-98c4-dc0c0c0738{n:02}")
            .parse()
            .unwrap();
        let mutation = RecordMutationV1::UpsertProject(ProjectIdentity {
            project_id,
            name: format!("Recovered project {n}"),
            github_repository_id: None,
            git_remote_fingerprint: None,
            monorepo_subdirectory: None,
        });
        let mutation = if check_authorization {
            let mut memory = support::memory(
                &project_id.to_string(),
                context_relay_protocol::ScopeRef::Project { project_id },
                "Canceled history",
                "History resolver cancellation",
            );
            memory.provenance.origin_device = history_author_id;
            memory.provenance.created_hlc = HybridLogicalClock::new(1000 + n, 0, history_author_id);
            memory.created_hlc = memory.provenance.created_hlc;
            memory.updated_hlc = memory.created_hlc;
            RecordMutationV1::UpsertMemory(memory)
        } else {
            mutation
        };
        let operation = builder
            .build(OperationBuildRequest {
                operation_id: format!("018f22e2-79b0-7cc8-98c4-dc0c0c0737{n:02}")
                    .parse()
                    .unwrap(),
                project_id: Some(project_id),
                mutation: &mutation,
                causal_frontier: if n == 1 {
                    vec![]
                } else {
                    vec![DeviceSequence {
                        device_id: history_author_id,
                        sequence: n - 1,
                    }]
                },
                previous,
                blob_refs: vec![],
                created_hlc: HybridLogicalClock::new(1000 + n, 0, history_author_id),
            })
            .unwrap();
        previous = Some(OperationChainHead {
            sequence: n,
            canonical_hash: operation.canonical_hash,
        });
        if n <= 2 {
            summaries.push(context_relay_core::sync::StateSummaryEntryV1 {
                record_id: mutation.record_id(),
                record_kind: mutation.record_kind(),
                head_hashes: vec![operation.canonical_hash],
                tombstoned: false,
                conflicted: false,
            });
        }
        operations.push(operation);
    }
    let mut checkpoint = support::checkpoint();
    checkpoint.account_id = claim.account_id;
    checkpoint.workspace_id = claim.workspace_id;
    checkpoint.creator_device = root.genesis_certificate.device_id;
    checkpoint.created_hlc.node = checkpoint.creator_device;
    checkpoint.causal_frontier = vec![DeviceSequence {
        device_id: history_author_id,
        sequence: 2,
    }];
    checkpoint.state_hash = context_relay_core::sync::StateSummaryV1 { entries: summaries }
        .state_hash()
        .unwrap();
    former.sign_checkpoint(&mut checkpoint).unwrap();
    let bytes = context_relay_protocol::encode_checkpoint_v1(&checkpoint).unwrap();
    let hash = Sha256Digest(Sha256::digest(&bytes).into());
    if check_authorization {
        use context_relay_core::{auth::LoginCancellation, vault::VaultError};
        let selected = vault
            .select_recovery_history(endpoint, &bytes, &keys, budget())
            .unwrap();
        let before = vault.test_plaintext_cells().unwrap();
        let mut replacement = checkpoint.clone();
        replacement.created_hlc.logical += 1;
        former.sign_checkpoint(&mut replacement).unwrap();
        let replacement = context_relay_protocol::encode_checkpoint_v1(&replacement).unwrap();
        for next in [&replacement, &bytes] {
            let checks = std::cell::Cell::new(0);
            let cancellation = LoginCancellation::default();
            let result =
                vault.select_recovery_history_authorized(endpoint, next, &keys, budget(), || {
                    checks.set(checks.get() + 1);
                    cancellation.cancel();
                    if cancellation.is_canceled() {
                        Err(VaultError::OperationConflict)
                    } else {
                        Ok(())
                    }
                });
            assert!(
                result.is_err(),
                "canceled replacement/exact retry must be denied at final authorization"
            );
            assert_eq!(checks.get(), 1);
            assert_eq!(vault.test_plaintext_cells().unwrap(), before);
            drop(vault);
            vault = Vault::open(path.path(), "history-selection", &store).unwrap();
            assert_eq!(vault.test_plaintext_cells().unwrap(), before);
            assert_eq!(
                vault.recovery_history_selection(&keys, budget()).unwrap(),
                Some(selected)
            );
        }
        let checks = std::cell::Cell::new(0);
        assert!(
            vault
                .select_recovery_history_authorized(endpoint, &[0], &keys, budget(), || {
                    checks.set(checks.get() + 1);
                    Ok(())
                })
                .is_err()
        );
        assert_eq!(
            checks.get(),
            0,
            "integrity failure must not be recast as cancellation"
        );
        vault
            .unlock_recovery_history(
                selected,
                context_relay_core::crypto::RecoveryPhrase::from_entropy_for_test([7; 32])
                    .unwrap()
                    .to_words(),
                &keys,
                budget(),
                || Ok(()),
            )
            .unwrap();
        let pages = operations[..2]
            .iter()
            .map(|op| op.canonical_bytes.clone())
            .collect::<Vec<_>>();
        vault
            .stage_historical_operations(
                endpoint,
                claim.certificate.device_id,
                &pages,
                &keys,
                budget(),
            )
            .unwrap();
        let before = vault.test_plaintext_cells().unwrap();
        let cancellation = LoginCancellation::default();
        let resolved = std::cell::Cell::new(0);
        let embeddings = |_: context_relay_protocol::OperationId,
                          _: &context_relay_protocol::RecordMutationV1| {
            resolved.set(resolved.get() + 1);
            cancellation.cancel();
            Ok(Some(support::basis(0)))
        };
        let checks = std::cell::Cell::new(0);
        let authorize = || {
            checks.set(checks.get() + 1);
            assert!(
                resolved.get() > 0,
                "cancellation occurs during real reconstruction"
            );
            if cancellation.is_canceled() {
                Err(VaultError::OperationConflict)
            } else {
                Ok(())
            }
        };
        assert!(
            vault
                .reconstruct_recovery_history_authorized(
                    selected,
                    &[],
                    &keys,
                    budget(),
                    &embeddings,
                    authorize
                )
                .is_err()
        );
        assert_eq!(checks.get(), 1);
        drop(vault);
        vault = Vault::open(path.path(), "history-selection", &store).unwrap();
        assert_eq!(
            vault.test_plaintext_cells().unwrap(),
            before,
            "only authenticated staged pages remain; no reconstruction receipt commits"
        );
        let embeddings =
            |_: context_relay_protocol::OperationId,
             _: &context_relay_protocol::RecordMutationV1| Ok(Some(support::basis(0)));
        let proof = vault
            .reconstruct_recovery_history(selected, &[], &keys, budget(), &embeddings)
            .unwrap()
            .unwrap();
        let before = vault.test_plaintext_cells().unwrap();
        let cancellation = LoginCancellation::default();
        let resolved = std::cell::Cell::new(0);
        let cancel_embeddings =
            |_: context_relay_protocol::OperationId,
             _: &context_relay_protocol::RecordMutationV1| {
                resolved.set(resolved.get() + 1);
                cancellation.cancel();
                Ok(Some(support::basis(0)))
            };
        let checks = std::cell::Cell::new(0);
        assert!(
            vault
                .install_recovery_history_authorized(
                    &proof,
                    &keys,
                    budget(),
                    &cancel_embeddings,
                    || {
                        checks.set(checks.get() + 1);
                        assert!(resolved.get() > 0);
                        if cancellation.is_canceled() {
                            Err(VaultError::OperationConflict)
                        } else {
                            Ok(())
                        }
                    }
                )
                .is_err()
        );
        assert_eq!(checks.get(), 1);
        assert_eq!(
            vault.test_plaintext_cells().unwrap(),
            before,
            "records, heads, installed receipt and activation roll back together"
        );
        assert!(vault.trusted_sync_material(&keys).is_err());
        drop(vault);
        vault = Vault::open(path.path(), "history-selection", &store).unwrap();
        assert_eq!(vault.test_plaintext_cells().unwrap(), before);
        assert!(
            vault
                .install_recovery_history(&proof, &keys, budget(), &embeddings)
                .unwrap()
        );
        cancellation.cancel();
        let committed = vault.test_plaintext_cells().unwrap();
        drop(vault);
        vault = Vault::open(path.path(), "history-selection", &store).unwrap();
        assert_eq!(
            vault.test_plaintext_cells().unwrap(),
            committed,
            "later cancellation does not undo an authorized committed installation"
        );
        assert!(matches!(
            vault.recovery_history_status(&keys, budget()).unwrap(),
            RecoveryRestoreStatus::Complete { .. }
        ));
        return;
    }
    let candidate = vault
        .recovery_history_candidate(
            claim.restore_id,
            endpoint.state_sha256,
            &bytes,
            hash,
            &keys,
            budget(),
        )
        .unwrap();
    assert_eq!(candidate.author_device_id, checkpoint.creator_device);
    let mut oversized = checkpoint.clone();
    oversized.causal_frontier = vec![context_relay_protocol::DeviceSequence {
        device_id: checkpoint.creator_device,
        sequence: 100001,
    }];
    former.sign_checkpoint(&mut oversized).unwrap();
    let oversized = context_relay_protocol::encode_checkpoint_v1(&oversized).unwrap();
    assert!(matches!(
        vault
            .recovery_history_candidate(
                claim.restore_id,
                endpoint.state_sha256,
                &oversized,
                Sha256Digest(Sha256::digest(&oversized).into()),
                &keys,
                budget()
            )
            .unwrap()
            .extent,
        context_relay_protocol::RecoveryHistoryExtent::Unsupported {}
    ));
    let mut overflow = checkpoint.clone();
    overflow.causal_frontier = vec![
        context_relay_protocol::DeviceSequence {
            device_id: support::ID_1.parse().unwrap(),
            sequence: u64::MAX,
        },
        context_relay_protocol::DeviceSequence {
            device_id: support::ID_2.parse().unwrap(),
            sequence: 1,
        },
    ];
    former.sign_checkpoint(&mut overflow).unwrap();
    let overflow = context_relay_protocol::encode_checkpoint_v1(&overflow).unwrap();
    assert!(matches!(
        vault
            .recovery_history_candidate(
                claim.restore_id,
                endpoint.state_sha256,
                &overflow,
                Sha256Digest(Sha256::digest(&overflow).into()),
                &keys,
                budget()
            )
            .unwrap()
            .extent,
        context_relay_protocol::RecoveryHistoryExtent::Unsupported {}
    ));

    assert!(
        vault
            .recovery_history_selection(&keys, budget())
            .unwrap()
            .is_none()
    );
    assert!(
        vault
            .recovery_history_candidate(
                claim.restore_id,
                Sha256Digest([9; 32]),
                &bytes,
                hash,
                &keys,
                budget()
            )
            .is_err()
    );
    assert!(
        vault
            .recovery_history_candidate(
                claim.restore_id,
                endpoint.state_sha256,
                &bytes,
                Sha256Digest([9; 32]),
                &keys,
                budget()
            )
            .is_err()
    );
    vault
        .select_recovery_history(endpoint, &bytes, &keys, budget())
        .unwrap();
    assert!(matches!(
        vault.recovery_history_status(&keys, budget()).unwrap(),
        RecoveryRestoreStatus::RestoringHistory {
            history: RecoveryHistoryProgress::HistoricalKeysNeeded { .. },
            ..
        }
    ));
    assert!(vault.trusted_sync_material(&keys).is_err());
    drop(vault);
    let mut vault = Vault::open(path.path(), "history-selection", &store).unwrap();
    assert!(matches!(
        vault.recovery_history_status(&keys, budget()).unwrap(),
        RecoveryRestoreStatus::RestoringHistory {
            history: RecoveryHistoryProgress::HistoricalKeysNeeded { .. },
            ..
        }
    ));
    let selected = vault
        .recovery_history_selection(&keys, budget())
        .unwrap()
        .unwrap();
    let raw = rusqlite::Connection::open(path.path()).unwrap();
    let database_key = store.key("history-selection");
    unsafe {
        assert_eq!(
            rusqlite::ffi::sqlite3_key(raw.handle(), database_key.as_ptr().cast(), 32),
            0
        );
    }
    raw.execute_batch("CREATE TEMP TABLE saved_current AS SELECT * FROM membership_epoch_secrets WHERE independent_current=1; DELETE FROM membership_epoch_secrets WHERE independent_current=1").unwrap();
    assert!(matches!(
        vault.recovery_history_status(&keys, budget()).unwrap(),
        RecoveryRestoreStatus::RestoringHistory {
            history: RecoveryHistoryProgress::CurrentMaterialUnavailable { .. },
            ..
        }
    ));
    assert!(
        vault
            .unlock_recovery_history(
                selected,
                context_relay_core::crypto::RecoveryPhrase::from_entropy_for_test([7; 32])
                    .unwrap()
                    .to_words(),
                &keys,
                budget(),
                || Ok(())
            )
            .is_err(),
        "root repair cannot replace missing independent current material"
    );
    raw.execute_batch("INSERT INTO membership_epoch_secrets SELECT * FROM saved_current")
        .unwrap();

    let phrase = || {
        context_relay_core::crypto::RecoveryPhrase::from_entropy_for_test([7; 32])
            .unwrap()
            .to_words()
    };
    let authorization_checks = std::cell::Cell::new(0);
    assert!(
        vault
            .unlock_recovery_history(selected, phrase(), &keys, budget(), || {
                authorization_checks.set(authorization_checks.get() + 1);
                if authorization_checks.get() == 1 {
                    Ok(())
                } else {
                    Err(context_relay_core::vault::VaultError::OperationConflict)
                }
            })
            .is_err()
    );
    assert_eq!(
        authorization_checks.get(),
        2,
        "cancel injected after receipt insert, before commit"
    );
    assert_eq!(
        raw.query_row(
            "SELECT count(*) FROM recovery_v2_supplemental_history_keys",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0,
        "cancellation rolls back supplemental receipt"
    );
    assert!(matches!(
        vault.recovery_history_status(&keys, budget()).unwrap(),
        RecoveryRestoreStatus::RestoringHistory {
            history: RecoveryHistoryProgress::HistoricalKeysNeeded { .. },
            ..
        }
    ));
    vault
        .unlock_recovery_history(selected, phrase(), &keys, budget(), || Ok(()))
        .unwrap();
    let retained=raw.query_row("SELECT canonical_envelope,signature FROM recovery_v2_supplemental_history_keys WHERE key_epoch=1",[],|r|Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,Vec<u8>>(1)?))).unwrap();
    vault
        .unlock_recovery_history(selected, phrase(), &keys, budget(), || Ok(()))
        .unwrap();
    assert_eq!(raw.query_row("SELECT canonical_envelope,signature FROM recovery_v2_supplemental_history_keys WHERE key_epoch=1",[],|r|Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,Vec<u8>>(1)?))).unwrap(),retained,"exact retry retains original ciphertext and signature");

    assert!(
        vault
            .prepared_recovery_v2(&keys)
            .unwrap()
            .unwrap()
            .history_keys
            .is_empty(),
        "original inventory is immutable"
    );
    assert!(
        vault.trusted_sync_material(&keys).is_err(),
        "unlock never activates current writes"
    );
    assert!(matches!(
        vault.recovery_history_status(&keys, budget()).unwrap(),
        RecoveryRestoreStatus::RestoringHistory {
            history: RecoveryHistoryProgress::Incomplete { .. },
            ..
        }
    ));
    drop(vault);
    let mut vault = Vault::open(path.path(), "history-selection", &store).unwrap();
    assert!(matches!(
        vault.recovery_history_status(&keys, budget()).unwrap(),
        RecoveryRestoreStatus::RestoringHistory {
            history: RecoveryHistoryProgress::Incomplete { .. },
            ..
        }
    ));
    let embeddings = |_: context_relay_protocol::OperationId,
                      _: &context_relay_protocol::RecordMutationV1| Ok(None);
    let proof = vault
        .reconstruct_recovery_history(
            selected,
            &operations[..2]
                .iter()
                .map(|op| op.canonical_bytes.clone())
                .collect::<Vec<_>>(),
            &keys,
            budget(),
            &embeddings,
        )
        .unwrap()
        .unwrap();
    assert!(
        vault
            .install_recovery_history(&proof, &keys, budget(), &embeddings)
            .unwrap()
    );
    drop(vault);
    let mut vault = Vault::open(path.path(), "history-selection", &store).unwrap();
    assert!(matches!(
        vault.recovery_history_status(&keys, budget()).unwrap(),
        RecoveryRestoreStatus::Complete { .. }
    ));
    let raw = rusqlite::Connection::open(path.path()).unwrap();
    let database_key = store.key("history-selection");
    unsafe {
        assert_eq!(
            rusqlite::ffi::sqlite3_key(raw.handle(), database_key.as_ptr().cast(), 32),
            0
        );
    }
    raw.execute_batch("CREATE TEMP TABLE saved_local AS SELECT * FROM operations; CREATE TEMP TABLE saved_local_meta AS SELECT * FROM sync_operation_meta; CREATE TEMP TABLE saved_local_heads AS SELECT * FROM sync_record_heads; CREATE TEMP TABLE saved_verified AS SELECT * FROM historical_verified_operations; DELETE FROM operations WHERE id=(SELECT id FROM saved_local ORDER BY id LIMIT 1)").unwrap();
    assert!(
        vault.recovery_history_status(&keys, budget()).is_err(),
        "signed verified evidence alone cannot replace a missing installed local row"
    );
    raw.execute_batch("INSERT INTO operations SELECT * FROM saved_local WHERE id NOT IN (SELECT id FROM operations); INSERT INTO sync_operation_meta SELECT * FROM saved_local_meta WHERE operation_id NOT IN (SELECT operation_id FROM sync_operation_meta); INSERT INTO sync_record_heads SELECT * FROM saved_local_heads WHERE operation_id NOT IN (SELECT operation_id FROM sync_record_heads); DELETE FROM historical_verified_operations WHERE device_sequence='1'").unwrap();
    assert!(
        !matches!(
            vault.recovery_history_status(&keys, budget()),
            Ok(RecoveryRestoreStatus::Complete { .. })
        ),
        "missing signed dependency prefix cannot remain complete"
    );
    raw.execute_batch("INSERT INTO historical_verified_operations SELECT * FROM saved_verified WHERE operation_id NOT IN (SELECT operation_id FROM historical_verified_operations)").unwrap();
    assert!(
        matches!(
            vault.recovery_history_status(&keys, budget()).unwrap(),
            RecoveryRestoreStatus::Complete { .. }
        ),
        "restoring local rows, dependent metadata/heads and signed prefix restores the valid fixture"
    );
    raw.execute_batch("CREATE TEMP TABLE saved_targets AS SELECT * FROM recovery_history_targets; UPDATE recovery_history_targets SET installed_signature=zeroblob(64)").unwrap();
    assert!(
        vault.recovery_history_status(&keys, budget()).is_err(),
        "modified installed receipt fails closed"
    );
    raw.execute_batch("UPDATE recovery_history_targets SET installed_signature=NULL")
        .unwrap();
    assert!(
        !matches!(
            vault.recovery_history_status(&keys, budget()),
            Ok(RecoveryRestoreStatus::Complete { .. })
        ),
        "missing receipt cannot prove completion"
    );
    raw.execute_batch("UPDATE recovery_history_targets SET installed_signature=(SELECT installed_signature FROM saved_targets)").unwrap();
    raw.execute_batch("CREATE TEMP TABLE saved_repair AS SELECT * FROM recovery_v2_supplemental_history_keys; UPDATE recovery_v2_supplemental_history_keys SET signature=zeroblob(64)").unwrap();
    assert!(
        vault.recovery_history_status(&keys, budget()).is_err(),
        "corrupt retained root provenance cannot be repaired by status"
    );
    raw.execute_batch("DELETE FROM recovery_v2_supplemental_history_keys; INSERT INTO recovery_v2_supplemental_history_keys SELECT * FROM saved_repair").unwrap();
    raw.execute_batch("CREATE TEMP TABLE saved_admission AS SELECT * FROM recovery_v2_admission; DELETE FROM recovery_v2_admission").unwrap();
    assert!(
        vault.recovery_history_status(&keys, budget()).is_err(),
        "missing original admission receipt fails closed"
    );
    raw.execute_batch("INSERT INTO recovery_v2_admission SELECT * FROM saved_admission; UPDATE recovery_v2_admission SET signature=zeroblob(64)").unwrap();
    assert!(
        vault.recovery_history_status(&keys, budget()).is_err(),
        "modified original admission receipt fails closed"
    );
    raw.execute_batch("DELETE FROM recovery_v2_admission; INSERT INTO recovery_v2_admission SELECT * FROM saved_admission").unwrap();
    assert!(
        matches!(
            vault.recovery_history_status(&keys, budget()).unwrap(),
            RecoveryRestoreStatus::Complete { .. }
        ),
        "all deliberate receipt corruptions are restored before membership extension"
    );
    use context_relay_core::devices::{
        crypto::{SignedPairingRequest, control_v2::*},
        membership_crypto::{
            DeviceMembershipAddStatementV1, MembershipEndpoint, MembershipHistoryEvent,
        },
        revocation_crypto::{DeviceRevocationStatementV1, RevocationTransitionV1},
    };
    use context_relay_protocol::NativePlatform;
    let newcomer = DeviceKeys::from_seeds_for_test([41; 32], [42; 32]);
    let newcomer_id = "018f22e2-79b0-7cc8-98c4-dc0c0c073996".parse().unwrap();
    let request = SignedPairingRequest::build(
        "018f22e2-79b0-7cc8-98c4-dc0c0c073996".parse().unwrap(),
        newcomer_id,
        "Next desktop",
        NativePlatform::Windows,
        &newcomer,
    )
    .unwrap();
    let history = vault
        .accepted_membership_history(budget().transfer.history)
        .unwrap()
        .unwrap();
    let material = vault
        .staged_membership_epoch(
            endpoint,
            claim.certificate.device_id,
            endpoint.key_epoch,
            true,
            &keys,
            budget().transfer.history,
        )
        .unwrap()
        .unwrap();
    let built = build_pairing_approval_v2(
        &request,
        &history.pairing_parent(claim.certificate.device_id).unwrap(),
        claim.certificate.device_id,
        &keys,
        "018f22e2-79b0-7cc8-98c4-dc0c0c073996".parse().unwrap(),
        "Recovered",
        NativePlatform::Windows,
        &material,
    )
    .unwrap();
    let fork = build_pairing_approval_v2(
        &request,
        &history.pairing_parent(claim.certificate.device_id).unwrap(),
        claim.certificate.device_id,
        &keys,
        "018f22e2-79b0-7cc8-98c4-dc0c0c073996".parse().unwrap(),
        "Recovered",
        NativePlatform::Windows,
        &material,
    )
    .unwrap();
    let fork_payload = encode_pairing_approved_payload_v2(&fork.payload).unwrap();
    let fork_statement =
        DeviceMembershipAddStatementV1::from_approved_payload_v2(&fork_payload).unwrap();
    let fork_signature = fork_statement.sign(&claim.certificate, &keys).unwrap();
    let fork_endpoint = MembershipEndpoint {
        state_sha256: fork_statement.control_state_sha256(fork_signature).unwrap(),
        ..endpoint
    };
    let payload = encode_pairing_approved_payload_v2(&built.payload).unwrap();
    let add = DeviceMembershipAddStatementV1::from_approved_payload_v2(&payload).unwrap();
    let signature = add.sign(&claim.certificate, &keys).unwrap();
    let added = MembershipEndpoint {
        state_sha256: add.control_state_sha256(signature).unwrap(),
        ..endpoint
    };
    let statement = add.signing_preimage().unwrap();
    let event = || MembershipHistoryEvent::PairingAdd {
        statement: &statement,
        signature,
        request: &request,
        approved_payload: &payload,
    };
    assert!(
        vault
            .accept_membership_extension(
                MembershipEndpoint {
                    state_sha256: Sha256Digest([3; 32]),
                    ..endpoint
                },
                added,
                &[event()],
                budget().transfer.history
            )
            .is_err(),
        "gap rejected"
    );
    vault
        .accept_membership_extension(endpoint, added, &[event()], budget().transfer.history)
        .unwrap();
    assert!(
        vault
            .accept_membership_extension(
                endpoint,
                fork_endpoint,
                &[MembershipHistoryEvent::PairingAdd {
                    statement: &fork_statement.signing_preimage().unwrap(),
                    signature: fork_signature,
                    request: &request,
                    approved_payload: &fork_payload
                }],
                budget().transfer.history
            )
            .is_err(),
        "a valid competing fork cannot replace accepted history"
    );
    drop(vault);
    let mut vault = Vault::open(path.path(), "history-selection", &store).unwrap();
    assert!(
        matches!(
            vault.recovery_history_status(&keys, budget()).unwrap(),
            RecoveryRestoreStatus::Complete { .. }
        ),
        "same-epoch ADD preserves historical completion"
    );
    assert!(
        vault
            .install_recovery_history(&proof, &keys, budget(), &embeddings)
            .is_err(),
        "old proof cannot install at a new endpoint"
    );
    let history = vault
        .accepted_membership_history(budget().transfer.history)
        .unwrap()
        .unwrap();
    let (revoked, transition, signature) = RevocationTransitionV1::build(
        DeviceRevocationStatementV1 {
            schema_version: 1,
            revocation_id: "018f22e2-79b0-7cc8-98c4-dc0c0c073997".parse().unwrap(),
            account_id: claim.account_id,
            workspace_id: claim.workspace_id,
            issuer_device_id: claim.certificate.device_id,
            target_device_id: history_author_id,
            control_epoch: added.control_epoch,
            key_epoch: added.key_epoch,
            cutoff_sequence: 3,
            cutoff_hash: operations[2].canonical_hash,
            transition_sha256: Sha256Digest([1; 32]),
        },
        &keys,
        &history.state(),
    )
    .unwrap();
    let rotated = MembershipEndpoint {
        state_sha256: revoked.control_state_sha256(signature).unwrap(),
        control_epoch: added.control_epoch + 1,
        key_epoch: added.key_epoch + 1,
    };
    vault
        .accept_membership_extension(
            added,
            rotated,
            &[MembershipHistoryEvent::Revocation {
                statement: &revoked.signing_preimage().unwrap(),
                signature,
                transition: &transition.canonical_bytes().unwrap(),
            }],
            budget().transfer.history,
        )
        .unwrap();
    drop(vault);
    let vault = Vault::open(path.path(), "history-selection", &store).unwrap();
    assert!(
        matches!(
            vault.recovery_history_status(&keys, budget()).unwrap(),
            RecoveryRestoreStatus::Complete { .. }
        ),
        "rotation preserves historical completion without new write authority"
    );
    // A valid signature cannot smuggle a conflicting terminal or post-cutoff retained row.
    let mut wrong_terminal = operations[2].operation.clone();
    wrong_terminal.created_hlc.logical += 1;
    history_author
        .sign_sync_operation(&mut wrong_terminal)
        .unwrap();
    for (operation, label) in [
        (&wrong_terminal, "wrong terminal hash"),
        (&operations[3].operation, "post-cutoff row"),
    ] {
        let canonical = context_relay_protocol::encode_sync_operation_v1(operation).unwrap();
        raw.execute(
            "INSERT INTO operations(id,record_id,payload_json) VALUES(?1,?2,?3)",
            rusqlite::params![
                operation.operation_id.to_string(),
                operation.record_id.to_string(),
                serde_json::to_vec(operation).unwrap()
            ],
        )
        .unwrap();
        raw.execute("INSERT INTO sync_operation_meta(operation_id,account_id,workspace_id,device_id,device_sequence,canonical_sha256,direction,state) VALUES(?1,?2,?3,?4,?5,?6,'incoming','applied')",rusqlite::params![operation.operation_id.to_string(),claim.account_id.to_string(),claim.workspace_id.to_string(),operation.device_id.to_string(),operation.device_sequence.to_string(),Sha256::digest(&canonical).as_slice()]).unwrap();
        assert!(
            vault.recovery_history_status(&keys, budget()).is_err(),
            "{label}"
        );
        raw.execute(
            "DELETE FROM sync_operation_meta WHERE operation_id=?1",
            [operation.operation_id.to_string()],
        )
        .unwrap();
        raw.execute(
            "DELETE FROM operations WHERE id=?1",
            [operation.operation_id.to_string()],
        )
        .unwrap();
    }
    assert!(matches!(
        vault.recovery_history_status(&keys, budget()).unwrap(),
        RecoveryRestoreStatus::Complete { .. }
    ));
    assert!(
        vault.trusted_sync_material(&keys).is_err(),
        "completion never activates rotated material"
    );
}

#[test]
fn orphan_supplemental_receipts_cannot_be_treated_as_fresh_recovery() {
    let path = support::TempVault::new("history-orphan");
    let store = support::MemoryKeyStore::default();
    let keys = DeviceKeys::from_seeds_for_test([31; 32], [32; 32]);
    let vault = Vault::open(path.path(), "history-orphan", &store).unwrap();
    let raw = rusqlite::Connection::open(path.path()).unwrap();
    let database_key = store.key("history-orphan");
    unsafe {
        assert_eq!(
            rusqlite::ffi::sqlite3_key(raw.handle(), database_key.as_ptr().cast(), 32),
            0
        );
    }
    raw.execute_batch("INSERT INTO recovery_v2_supplemental_history_keys VALUES(1,zeroblob(32),x'00',zeroblob(64))").unwrap();
    assert!(vault.prepared_recovery_v2(&keys).is_err());
    drop(vault);
    let vault = Vault::open(path.path(), "history-orphan", &store).unwrap();
    assert!(vault.prepared_recovery_v2(&keys).is_err());
    assert!(vault.recovery_history_status(&keys, budget()).is_err());
}
