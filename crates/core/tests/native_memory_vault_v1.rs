mod support;

use context_relay_core::{
    native_memory::{
        NativeMemoryDocumentKind, NativeMemoryLedger, NativeMemoryLimits,
        NativeMemoryObservationKind, NativeMemoryRegistration, NativeMemorySnapshot,
        NativeMemorySource, NativeMemorySourceId, ReadyNativeMemory, extract_managed_markdown,
    },
    service::OfflineWorkspace,
    vault::{
        LATEST_SCHEMA_VERSION, SetupPlanAction, SetupPlanLifecycle, SetupPlanWrite, Vault,
        VaultError,
    },
};
use context_relay_protocol::{
    CandidateReviewParams, CandidateState, ErrorCode, HarnessId, MemoryOrigin, NativePlatform,
    PlanId, ScopeRef, Sha256Digest, WireNativeValue,
};
use rusqlite::{Connection, params};
use sha2::{Digest as _, Sha256};

use support::{ID_1, ID_7, MemoryKeyStore, TempVault};

const CREDENTIAL: &str = "native-memory-vault-tests";

fn open_keyed(path: &std::path::Path, key: &[u8; 32]) -> Connection {
    let connection = Connection::open(path).unwrap();
    // SAFETY: the connection owns the handle, the key remains valid for the call,
    // and this is the first SQLite operation after open.
    let result = unsafe {
        rusqlite::ffi::sqlite3_key(
            connection.handle(),
            key.as_ptr().cast(),
            key.len().try_into().unwrap(),
        )
    };
    assert_eq!(result, rusqlite::ffi::SQLITE_OK);
    connection
        .query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
        .unwrap();
    connection
}

fn source(scope: ScopeRef, harness: HarnessId, suffix: &str) -> NativeMemorySource {
    source_with_version(scope, harness, "test-1.0.0", suffix)
}

fn source_with_version(
    scope: ScopeRef,
    harness: HarnessId,
    adapter_version: &str,
    suffix: &str,
) -> NativeMemorySource {
    NativeMemorySource::new(
        harness,
        adapter_version,
        scope,
        NativeMemoryDocumentKind::Agent,
        WireNativeValue {
            platform: NativePlatform::Macos,
            bytes: format!("/tmp/context-relay/{suffix}.md").into_bytes(),
            display: Some(format!("/tmp/context-relay/{suffix}.md")),
        },
        NativeMemoryLimits {
            max_bytes: 4_096,
            max_characters: 4_096,
        },
        true,
    )
    .unwrap()
}

fn windows_source_with_units(
    scope: ScopeRef,
    adapter_version: &str,
    units: &[u16],
) -> NativeMemorySource {
    NativeMemorySource::new(
        HarnessId::ClaudeCode,
        adapter_version,
        scope,
        NativeMemoryDocumentKind::Agent,
        WireNativeValue {
            platform: NativePlatform::Windows,
            bytes: units.iter().flat_map(|unit| unit.to_le_bytes()).collect(),
            display: None,
        },
        NativeMemoryLimits {
            max_bytes: 4_096,
            max_characters: 4_096,
        },
        true,
    )
    .unwrap()
}

fn windows_source(scope: ScopeRef, adapter_version: &str, path: &str) -> NativeMemorySource {
    windows_source_with_units(
        scope,
        adapter_version,
        &path.encode_utf16().collect::<Vec<_>>(),
    )
}

fn ledger(source: NativeMemorySource, byte: u8) -> NativeMemoryLedger {
    let mut ledger = NativeMemoryLedger::for_source(source);
    ledger.last_observed_digest = Some(Sha256Digest([byte; 32]));
    ledger.last_unmanaged_digest = Some(Sha256Digest([byte + 1; 32]));
    ledger.last_imported_digest = Some(Sha256Digest([byte + 2; 32]));
    ledger.last_applied_digest = Some(Sha256Digest([byte + 3; 32]));
    ledger.last_applied_managed_digest = Some(Sha256Digest([byte + 4; 32]));
    ledger.initial_preview_complete = true;
    ledger
}

fn hex(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

fn source_hex(id: NativeMemorySourceId) -> String {
    id.0.0.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn legacy_source_id(source: &NativeMemorySource) -> NativeMemorySourceId {
    let mut hasher = Sha256::new();
    for field in [
        b"context-relay.native-memory-source.v1".as_slice(),
        b"codex",
        b"test-1.0.0",
        b"global",
        b"",
        b"agent",
        b"macos",
        source.path.bytes.as_slice(),
    ] {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    NativeMemorySourceId(Sha256Digest(hasher.finalize().into()))
}

#[test]
fn legacy_v1_ledger_reopens_and_reconciles_without_weakening_current_identity_validation() {
    let path = TempVault::new("native-memory-legacy-v1-reopen");
    let keys = MemoryKeyStore::default();
    let mut descriptor = source(ScopeRef::Global, HarnessId::Codex, "legacy-v1-reopen");
    descriptor.id = legacy_source_id(&descriptor);
    assert!(descriptor.validate().is_err());
    let ledger = NativeMemoryLedger::for_source(descriptor.clone());
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault.put_native_memory_candidate(&ledger, None).unwrap();
    drop(vault);

    let mut reopened = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(
        reopened
            .native_memory_ledger(&descriptor.id)
            .unwrap()
            .unwrap()
            .source,
        Some(descriptor.clone())
    );
    let candidate = OfflineWorkspace::new(&mut reopened, ID_7.parse().unwrap())
        .reconcile_native_memory(ReadyNativeMemory {
            source: descriptor,
            snapshot: NativeMemorySnapshot::Regular(b"legacy fact\n".to_vec()),
            kind: NativeMemoryObservationKind::InitialPreview,
        })
        .unwrap();
    assert!(candidate.is_some());
}

#[test]
fn migration_v9_through_latest_preserves_prior_rows_and_enforces_scope_shape() {
    let path = TempVault::new("native-memory-migration-v9");
    let keys = MemoryKeyStore::default();
    let key = [31; 32];
    keys.insert(CREDENTIAL, key);

    let raw = open_keyed(path.path(), &key);
    raw.execute_batch(include_str!("../migrations/0001_vault.sql"))
        .unwrap();
    raw.execute_batch(include_str!("../migrations/0002_before_image_plans.sql"))
        .unwrap();
    raw.execute_batch(include_str!("../migrations/0003_native_transactions.sql"))
        .unwrap();
    raw.execute_batch(include_str!("../migrations/0004_offline_workspace.sql"))
        .unwrap();
    raw.execute_batch(include_str!(
        "../migrations/0005_local_operation_bindings.sql"
    ))
    .unwrap();
    raw.execute_batch(include_str!(
        "../migrations/0006_local_operation_results.sql"
    ))
    .unwrap();
    raw.execute_batch(include_str!(
        "../migrations/0007_task_operation_bindings.sql"
    ))
    .unwrap();
    raw.execute_batch(include_str!(
        "../migrations/0008_task_transitions_and_handoff_queries.sql"
    ))
    .unwrap();
    raw.execute_batch(include_str!(
        "../migrations/0009_setup_cli_transactions.sql"
    ))
    .unwrap();
    raw.execute(
        "INSERT INTO projects(id, payload_json) VALUES (?1, ?2)",
        params![ID_7, br#"{"preserved":true}"#.as_slice()],
    )
    .unwrap();
    raw.execute(
        "INSERT INTO native_plans(plan_id, approval_hash, payload, created_ms, expires_ms)
         VALUES (?1, ?2, ?3, 10, 20)",
        params![ID_1, [61_u8; 32].as_slice(), b"legacy-applied-plan"],
    )
    .unwrap();
    raw.execute(
        "INSERT INTO setup_plan_lifecycle(
             plan_id, schema_version, approval_version, state, updated_ms
         ) VALUES (?1, 1, 2, 'applied', 11)",
        [ID_1],
    )
    .unwrap();
    raw.pragma_update(None, "user_version", 9).unwrap();
    drop(raw);

    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(vault.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
    let legacy_plan_id = ID_1.parse::<PlanId>().unwrap();
    assert_eq!(
        vault
            .setup_plan_native_memory_registrations(&legacy_plan_id)
            .unwrap(),
        Some(Vec::new())
    );
    assert!(matches!(
        vault.finish_setup_plan_with_native_memory(
            &legacy_plan_id,
            SetupPlanLifecycle::Applied,
            &[NativeMemoryRegistration {
                source: source(ScopeRef::Global, HarnessId::Codex, "legacy-replay"),
                last_applied_digest: Some(Sha256Digest([62; 32])),
            }],
        ),
        Err(VaultError::Validation(_))
    ));
    drop(vault);

    let raw = open_keyed(path.path(), &key);
    assert_eq!(
        raw.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'native_memory_sources'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap(),
        1
    );
    assert_eq!(
        raw.query_row(
            "SELECT count(*) FROM projects WHERE id = ?1",
            [ID_7],
            |row| { row.get::<_, i64>(0) }
        )
        .unwrap(),
        1
    );
    let payload = br#"{}"#;
    assert!(
        raw.execute(
            "INSERT INTO native_memory_sources(
                 source_id, harness, scope_kind, project_id, document_kind,
                 initial_preview_complete, payload_json
             ) VALUES (?1, 'codex', 'global', ?2, 'agent', 0, ?3)",
            params![hex(1), ID_7, payload.as_slice()],
        )
        .is_err()
    );
    assert!(
        raw.execute(
            "INSERT INTO native_memory_sources(
                 source_id, harness, scope_kind, project_id, document_kind,
                 initial_preview_complete, payload_json
             ) VALUES (?1, 'codex', 'project', NULL, 'agent', 0, ?2)",
            params![hex(2), payload.as_slice()],
        )
        .is_err()
    );
}

#[test]
fn ledger_round_trips_global_and_project_metadata() {
    let path = TempVault::new("native-memory-ledger-round-trip");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let global = ledger(source(ScopeRef::Global, HarnessId::Codex, "global"), 10);
    let project = ledger(
        source(
            ScopeRef::Project {
                project_id: ID_7.parse().unwrap(),
            },
            HarnessId::ClaudeCode,
            "project",
        ),
        20,
    );

    vault.put_native_memory_candidate(&global, None).unwrap();
    vault.put_native_memory_candidate(&project, None).unwrap();

    assert_eq!(
        vault.native_memory_ledger(&global.source_id).unwrap(),
        Some(global)
    );
    assert_eq!(
        vault.native_memory_ledger(&project.source_id).unwrap(),
        Some(project)
    );
    assert_eq!(
        vault
            .native_memory_ledger(&NativeMemorySourceId(Sha256Digest([99; 32])))
            .unwrap(),
        None
    );
}

#[test]
fn malformed_ledger_payload_is_rejected() {
    let path = TempVault::new("native-memory-ledger-malformed");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let stored = ledger(source(ScopeRef::Global, HarnessId::Hermes, "malformed"), 30);
    vault.put_native_memory_candidate(&stored, None).unwrap();
    drop(vault);

    let key = keys.key(CREDENTIAL);
    let raw = open_keyed(path.path(), &key);
    raw.execute(
        "UPDATE native_memory_sources SET payload_json = ?2 WHERE source_id = ?1",
        params![
            source_hex(stored.source_id),
            br#"{"unknown":true}"#.as_slice()
        ],
    )
    .unwrap();
    drop(raw);

    let vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert!(matches!(
        vault.native_memory_ledger(&stored.source_id),
        Err(VaultError::Serialization(_)) | Err(VaultError::Validation(_))
    ));
}

fn ready(source: NativeMemorySource, body: &str) -> ReadyNativeMemory {
    ReadyNativeMemory {
        source,
        snapshot: NativeMemorySnapshot::Regular(body.as_bytes().to_vec()),
        kind: NativeMemoryObservationKind::InitialPreview,
    }
}

fn ready_live(source: NativeMemorySource, body: &str) -> ReadyNativeMemory {
    ReadyNativeMemory {
        source,
        snapshot: NativeMemorySnapshot::Regular(body.as_bytes().to_vec()),
        kind: NativeMemoryObservationKind::LiveEdit,
    }
}

#[test]
fn successful_setup_apply_atomically_registers_descriptor_and_applied_digest() {
    let path = TempVault::new("native-memory-applied-registration");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let plan_id = ID_1.parse::<PlanId>().unwrap();
    let approval_hash = Sha256Digest([41; 32]);
    vault
        .put_setup_plan(SetupPlanWrite {
            plan_id: &plan_id,
            schema_version: 1,
            approval_version: 2,
            approval_hash: &approval_hash,
            payload: b"sealed-native-memory-plan",
            created_ms: 10,
            expires_ms: 20,
        })
        .unwrap();
    vault
        .claim_setup_plan(&plan_id, SetupPlanAction::Apply, 11)
        .unwrap();
    let descriptor = source(ScopeRef::Global, HarnessId::Codex, "applied");
    let applied = Sha256Digest([42; 32]);

    vault
        .finish_setup_plan_with_native_memory(
            &plan_id,
            SetupPlanLifecycle::Applied,
            &[NativeMemoryRegistration {
                source: descriptor.clone(),
                last_applied_digest: Some(applied),
            }],
        )
        .unwrap();
    let stored = vault.native_memory_ledger(&descriptor.id).unwrap().unwrap();
    assert_eq!(stored.source, Some(descriptor.clone()));
    assert_eq!(stored.last_applied_digest, Some(applied));
    assert_eq!(
        vault.setup_plan(&plan_id).unwrap().unwrap().lifecycle,
        SetupPlanLifecycle::Applied
    );

    vault
        .finish_setup_plan_with_native_memory(
            &plan_id,
            SetupPlanLifecycle::Applied,
            &[NativeMemoryRegistration {
                source: descriptor.clone(),
                last_applied_digest: Some(applied),
            }],
        )
        .unwrap();

    assert!(matches!(
        vault.finish_setup_plan_with_native_memory(&plan_id, SetupPlanLifecycle::Applied, &[],),
        Err(VaultError::Validation(_))
    ));

    let added = source(ScopeRef::Global, HarnessId::ClaudeCode, "added-on-replay");
    assert!(matches!(
        vault.finish_setup_plan_with_native_memory(
            &plan_id,
            SetupPlanLifecycle::Applied,
            &[
                NativeMemoryRegistration {
                    source: descriptor.clone(),
                    last_applied_digest: Some(applied),
                },
                NativeMemoryRegistration {
                    source: added,
                    last_applied_digest: None,
                },
            ],
        ),
        Err(VaultError::Validation(_))
    ));

    assert!(matches!(
        vault.finish_setup_plan_with_native_memory(
            &plan_id,
            SetupPlanLifecycle::Applied,
            &[NativeMemoryRegistration {
                source: descriptor.clone(),
                last_applied_digest: Some(Sha256Digest([99; 32])),
            }],
        ),
        Err(VaultError::Validation(_))
    ));
    assert_eq!(
        vault
            .native_memory_ledger(&descriptor.id)
            .unwrap()
            .unwrap()
            .last_applied_digest,
        Some(applied)
    );
}

#[test]
fn invalid_registration_cannot_publish_an_applied_lifecycle() {
    let path = TempVault::new("native-memory-registration-rollback");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let plan_id = ID_1.parse::<PlanId>().unwrap();
    let approval_hash = Sha256Digest([43; 32]);
    vault
        .put_setup_plan(SetupPlanWrite {
            plan_id: &plan_id,
            schema_version: 1,
            approval_version: 2,
            approval_hash: &approval_hash,
            payload: b"sealed-invalid-registration-plan",
            created_ms: 10,
            expires_ms: 20,
        })
        .unwrap();
    vault
        .claim_setup_plan(&plan_id, SetupPlanAction::Apply, 11)
        .unwrap();
    let mut invalid = source(ScopeRef::Global, HarnessId::Codex, "invalid");
    invalid.adapter_version = "changed-after-source-id".to_owned();

    assert!(matches!(
        vault.finish_setup_plan_with_native_memory(
            &plan_id,
            SetupPlanLifecycle::Applied,
            &[NativeMemoryRegistration {
                source: invalid,
                last_applied_digest: Some(Sha256Digest([44; 32])),
            }],
        ),
        Err(VaultError::Validation(_))
    ));
    assert_eq!(
        vault.setup_plan(&plan_id).unwrap().unwrap().lifecycle,
        SetupPlanLifecycle::Applying
    );
    assert!(vault.native_memory_ledgers().unwrap().is_empty());
}

fn apply_registered_source(
    vault: &mut Vault,
    plan_id: &str,
    registration: &NativeMemoryRegistration,
    marker: u8,
) {
    let plan_id = plan_id.parse::<PlanId>().unwrap();
    let approval_hash = Sha256Digest([marker; 32]);
    let payload = vec![marker; 8];
    vault
        .put_setup_plan(SetupPlanWrite {
            plan_id: &plan_id,
            schema_version: 2,
            approval_version: 2,
            approval_hash: &approval_hash,
            payload: &payload,
            created_ms: 10,
            expires_ms: 100,
        })
        .unwrap();
    vault
        .claim_setup_plan(&plan_id, SetupPlanAction::Apply, 11)
        .unwrap();
    vault
        .finish_setup_plan_with_native_memory(
            &plan_id,
            SetupPlanLifecycle::Applied,
            std::slice::from_ref(registration),
        )
        .unwrap();
}

fn rollback_registered_source(vault: &mut Vault, original_id: &str, inverse_id: &str, marker: u8) {
    let original_id = original_id.parse::<PlanId>().unwrap();
    let inverse_id = inverse_id.parse::<PlanId>().unwrap();
    let approval_hash = Sha256Digest([marker; 32]);
    let payload = vec![marker; 8];
    vault
        .claim_setup_plan_rollback(
            &original_id,
            SetupPlanWrite {
                plan_id: &inverse_id,
                schema_version: 2,
                approval_version: 2,
                approval_hash: &approval_hash,
                payload: &payload,
                created_ms: 20,
                expires_ms: 100,
            },
            21,
        )
        .unwrap();
    vault
        .finish_setup_plan_rollback(
            &original_id,
            &inverse_id,
            SetupPlanLifecycle::RolledBack,
            SetupPlanLifecycle::Applied,
        )
        .unwrap();
}

#[test]
fn rollback_unregisters_only_the_last_plan_owned_native_memory_source() {
    const PLAN_A: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073983";
    const PLAN_B: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073984";
    const ROLLBACK_A: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073985";
    const ROLLBACK_B: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073986";
    let path = TempVault::new("native-memory-shared-setup-ownership");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let descriptor = source(ScopeRef::Global, HarnessId::Codex, "shared-owner");
    let registration = NativeMemoryRegistration {
        source: descriptor.clone(),
        last_applied_digest: None,
    };

    apply_registered_source(&mut vault, PLAN_A, &registration, 51);
    apply_registered_source(&mut vault, PLAN_B, &registration, 52);
    rollback_registered_source(&mut vault, PLAN_A, ROLLBACK_A, 53);
    assert!(
        vault
            .native_memory_ledger(&descriptor.id)
            .unwrap()
            .is_some()
    );

    rollback_registered_source(&mut vault, PLAN_B, ROLLBACK_B, 54);
    assert!(
        vault
            .native_memory_ledger(&descriptor.id)
            .unwrap()
            .is_none()
    );
}

#[test]
fn adapter_upgrade_supersedes_one_active_source_and_rolls_back_with_ledger_continuity() {
    const ORIGINAL: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074001";
    const UPGRADE: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074002";
    const ROLLBACK: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074003";
    let path = TempVault::new("native-memory-adapter-upgrade");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let original = source_with_version(
        ScopeRef::Project {
            project_id: ID_7.parse().unwrap(),
        },
        HarnessId::ClaudeCode,
        "claude-1.0.0",
        "same-project-memory",
    );
    let upgraded = source_with_version(
        original.scope.clone(),
        HarnessId::ClaudeCode,
        "claude-2.0.0",
        "same-project-memory",
    );
    assert_ne!(original.id, upgraded.id);

    apply_registered_source(
        &mut vault,
        ORIGINAL,
        &NativeMemoryRegistration {
            source: original.clone(),
            last_applied_digest: None,
        },
        81,
    );
    let continuity = ledger(original.clone(), 82);
    vault
        .put_native_memory_candidate(&continuity, None)
        .unwrap();

    apply_registered_source(
        &mut vault,
        UPGRADE,
        &NativeMemoryRegistration {
            source: upgraded.clone(),
            last_applied_digest: None,
        },
        83,
    );

    let active = vault.native_memory_ledgers().unwrap();
    assert_eq!(active.len(), 1);
    let upgraded_ledger = &active[0];
    assert_eq!(upgraded_ledger.source.as_ref(), Some(&upgraded));
    assert_eq!(
        upgraded_ledger.last_observed_digest,
        continuity.last_observed_digest
    );
    assert_eq!(
        upgraded_ledger.last_unmanaged_digest,
        continuity.last_unmanaged_digest
    );
    assert_eq!(
        upgraded_ledger.last_imported_digest,
        continuity.last_imported_digest
    );
    assert_eq!(
        upgraded_ledger.last_applied_digest,
        continuity.last_applied_digest
    );
    assert_eq!(
        upgraded_ledger.last_applied_managed_digest,
        continuity.last_applied_managed_digest
    );
    assert!(upgraded_ledger.initial_preview_complete);
    assert_eq!(
        vault
            .native_memory_ledger(&original.id)
            .unwrap()
            .unwrap()
            .last_observed_digest,
        continuity.last_observed_digest
    );

    rollback_registered_source(&mut vault, UPGRADE, ROLLBACK, 84);

    assert!(vault.native_memory_ledger(&upgraded.id).unwrap().is_none());
    assert_eq!(
        vault.native_memory_ledgers().unwrap(),
        vec![continuity.clone()]
    );
}

#[test]
fn different_projects_cannot_claim_the_same_logical_native_path() {
    const FIRST_PLAN: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074004";
    const SECOND_PLAN: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074005";
    const OTHER_PROJECT: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074006";
    let path = TempVault::new("native-memory-cross-project-path-collision");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();

    // Claude's lossy project-key projection can map distinct project roots to
    // this same file. The vault boundary must reject the second logical owner.
    let first = source_with_version(
        ScopeRef::Project {
            project_id: ID_7.parse().unwrap(),
        },
        HarnessId::ClaudeCode,
        "claude-1.0.0",
        "lossy-project-key-memory",
    );
    let second = source_with_version(
        ScopeRef::Project {
            project_id: OTHER_PROJECT.parse().unwrap(),
        },
        HarnessId::ClaudeCode,
        "claude-1.0.0",
        "lossy-project-key-memory",
    );
    assert_eq!(first.path, second.path);
    assert_ne!(first.id, second.id);
    apply_registered_source(
        &mut vault,
        FIRST_PLAN,
        &NativeMemoryRegistration {
            source: first.clone(),
            last_applied_digest: None,
        },
        85,
    );

    let second_plan = SECOND_PLAN.parse::<PlanId>().unwrap();
    let approval_hash = Sha256Digest([86; 32]);
    vault
        .put_setup_plan(SetupPlanWrite {
            plan_id: &second_plan,
            schema_version: 2,
            approval_version: 2,
            approval_hash: &approval_hash,
            payload: b"second-project-collision",
            created_ms: 10,
            expires_ms: 100,
        })
        .unwrap();
    vault
        .claim_setup_plan(&second_plan, SetupPlanAction::Apply, 11)
        .unwrap();

    assert!(matches!(
        vault.finish_setup_plan_with_native_memory(
            &second_plan,
            SetupPlanLifecycle::Applied,
            &[NativeMemoryRegistration {
                source: second.clone(),
                last_applied_digest: None,
            }],
        ),
        Err(VaultError::Validation(message))
            if message.contains("native path") && message.contains("different logical source")
    ));
    assert_eq!(
        vault.setup_plan(&second_plan).unwrap().unwrap().lifecycle,
        SetupPlanLifecycle::Applying
    );
    assert!(vault.native_memory_ledger(&second.id).unwrap().is_none());
    assert_eq!(
        vault.native_memory_ledgers().unwrap(),
        vec![NativeMemoryLedger::for_source(first)]
    );
}

#[test]
fn superseded_setup_cannot_roll_back_before_its_active_successor() {
    const ORIGINAL: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074007";
    const UPGRADE: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074008";
    const BLOCKED_ROLLBACK: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074009";
    const UPGRADE_ROLLBACK: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074010";
    const ORIGINAL_ROLLBACK: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074011";
    let path = TempVault::new("native-memory-superseded-rollback-order");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let original = source_with_version(
        ScopeRef::Global,
        HarnessId::Codex,
        "codex-1.0.0",
        "rollback-order",
    );
    let upgraded = source_with_version(
        ScopeRef::Global,
        HarnessId::Codex,
        "codex-2.0.0",
        "rollback-order",
    );
    apply_registered_source(
        &mut vault,
        ORIGINAL,
        &NativeMemoryRegistration {
            source: original.clone(),
            last_applied_digest: None,
        },
        87,
    );
    apply_registered_source(
        &mut vault,
        UPGRADE,
        &NativeMemoryRegistration {
            source: upgraded,
            last_applied_digest: None,
        },
        88,
    );

    let original_plan = ORIGINAL.parse::<PlanId>().unwrap();
    let blocked_inverse = BLOCKED_ROLLBACK.parse::<PlanId>().unwrap();
    let approval_hash = Sha256Digest([89; 32]);
    assert!(matches!(
        vault.claim_setup_plan_rollback(
            &original_plan,
            SetupPlanWrite {
                plan_id: &blocked_inverse,
                schema_version: 2,
                approval_version: 2,
                approval_hash: &approval_hash,
                payload: b"blocked-out-of-order-rollback",
                created_ms: 20,
                expires_ms: 100,
            },
            21,
        ),
        Err(VaultError::Validation(message)) if message.contains("active successor")
    ));
    assert_eq!(
        vault.setup_plan(&original_plan).unwrap().unwrap().lifecycle,
        SetupPlanLifecycle::Applied
    );
    assert!(vault.setup_plan(&blocked_inverse).unwrap().is_none());

    rollback_registered_source(&mut vault, UPGRADE, UPGRADE_ROLLBACK, 90);
    rollback_registered_source(&mut vault, ORIGINAL, ORIGINAL_ROLLBACK, 91);
    assert!(vault.native_memory_ledger(&original.id).unwrap().is_none());
}

#[test]
fn windows_case_and_extended_prefix_aliases_cannot_cross_project_ownership() {
    const FIRST_PLANS: [&str; 2] = [
        "018f22e2-79b0-7cc8-98c4-dc0c0c074012",
        "018f22e2-79b0-7cc8-98c4-dc0c0c074013",
    ];
    const SECOND_PLANS: [&str; 2] = [
        "018f22e2-79b0-7cc8-98c4-dc0c0c074014",
        "018f22e2-79b0-7cc8-98c4-dc0c0c074015",
    ];
    const OTHER_PROJECT: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074016";
    let aliases = [r"c:\memory\memory.md", r"\\?\C:\Memory\MEMORY.md"];

    for (index, alias) in aliases.into_iter().enumerate() {
        let path = TempVault::new(&format!("native-memory-windows-alias-{index}"));
        let keys = MemoryKeyStore::default();
        let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
        let first = windows_source(
            ScopeRef::Project {
                project_id: ID_7.parse().unwrap(),
            },
            "claude-1.0.0",
            r"C:\Memory\MEMORY.md",
        );
        let alias = windows_source(
            ScopeRef::Project {
                project_id: OTHER_PROJECT.parse().unwrap(),
            },
            "claude-1.0.0",
            alias,
        );
        apply_registered_source(
            &mut vault,
            FIRST_PLANS[index],
            &NativeMemoryRegistration {
                source: first,
                last_applied_digest: None,
            },
            92 + index as u8,
        );

        let second_plan = SECOND_PLANS[index].parse::<PlanId>().unwrap();
        let approval_hash = Sha256Digest([94 + index as u8; 32]);
        vault
            .put_setup_plan(SetupPlanWrite {
                plan_id: &second_plan,
                schema_version: 2,
                approval_version: 2,
                approval_hash: &approval_hash,
                payload: b"windows-native-path-alias",
                created_ms: 10,
                expires_ms: 100,
            })
            .unwrap();
        vault
            .claim_setup_plan(&second_plan, SetupPlanAction::Apply, 11)
            .unwrap();
        assert!(matches!(
            vault.finish_setup_plan_with_native_memory(
                &second_plan,
                SetupPlanLifecycle::Applied,
                &[NativeMemoryRegistration {
                    source: alias,
                    last_applied_digest: None,
                }],
            ),
            Err(VaultError::Validation(message))
                if message.contains("native path") && message.contains("different logical source")
        ));
    }
}

#[test]
fn windows_alias_spelling_preserves_same_project_supersession_and_exact_rollback() {
    const ORIGINAL: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074017";
    const UPGRADE: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074018";
    const ROLLBACK: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074019";
    let path = TempVault::new("native-memory-windows-alias-upgrade");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let scope = ScopeRef::Project {
        project_id: ID_7.parse().unwrap(),
    };
    let original = windows_source(scope.clone(), "claude-1.0.0", r"C:\Memory\MEMORY.md");
    let upgraded = windows_source(scope, "claude-2.0.0", r"\\?\c:\memory\memory.md");
    apply_registered_source(
        &mut vault,
        ORIGINAL,
        &NativeMemoryRegistration {
            source: original.clone(),
            last_applied_digest: None,
        },
        96,
    );
    let continuity = ledger(original.clone(), 97);
    vault
        .put_native_memory_candidate(&continuity, None)
        .unwrap();
    apply_registered_source(
        &mut vault,
        UPGRADE,
        &NativeMemoryRegistration {
            source: upgraded.clone(),
            last_applied_digest: None,
        },
        98,
    );
    assert_eq!(vault.native_memory_ledgers().unwrap().len(), 1);
    assert_eq!(
        vault.native_memory_ledgers().unwrap()[0].source.as_ref(),
        Some(&upgraded)
    );

    rollback_registered_source(&mut vault, UPGRADE, ROLLBACK, 99);
    assert_eq!(vault.native_memory_ledgers().unwrap(), vec![continuity]);
}

#[test]
fn opaque_windows_wtf16_registers_and_does_not_block_an_unrelated_source() {
    const OPAQUE_PLAN: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074020";
    const UNRELATED_PLAN: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074021";
    const OTHER_PROJECT: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074022";
    let path = TempVault::new("native-memory-opaque-wtf16-registration");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let mut units = r"C:\Memory\".encode_utf16().collect::<Vec<_>>();
    units.push(0xd800);
    units.extend(".md".encode_utf16());
    let opaque = windows_source_with_units(
        ScopeRef::Project {
            project_id: ID_7.parse().unwrap(),
        },
        "claude-1.0.0",
        &units,
    );
    let unrelated = windows_source(
        ScopeRef::Project {
            project_id: OTHER_PROJECT.parse().unwrap(),
        },
        "claude-1.0.0",
        r"D:\Other\MEMORY.md",
    );

    apply_registered_source(
        &mut vault,
        OPAQUE_PLAN,
        &NativeMemoryRegistration {
            source: opaque.clone(),
            last_applied_digest: None,
        },
        100,
    );
    apply_registered_source(
        &mut vault,
        UNRELATED_PLAN,
        &NativeMemoryRegistration {
            source: unrelated.clone(),
            last_applied_digest: None,
        },
        101,
    );

    let active = vault.native_memory_ledgers().unwrap();
    assert_eq!(active.len(), 2);
    assert!(
        active
            .iter()
            .any(|ledger| ledger.source.as_ref() == Some(&opaque))
    );
    assert!(
        active
            .iter()
            .any(|ledger| ledger.source.as_ref() == Some(&unrelated))
    );
}

#[test]
fn exact_opaque_windows_wtf16_supersedes_and_rolls_back_losslessly() {
    const ORIGINAL: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074023";
    const UPGRADE: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074024";
    const ROLLBACK: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074025";
    let path = TempVault::new("native-memory-opaque-wtf16-upgrade");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let mut units = r"C:\Memory\".encode_utf16().collect::<Vec<_>>();
    units.push(0xd800);
    units.extend(".md".encode_utf16());
    let scope = ScopeRef::Project {
        project_id: ID_7.parse().unwrap(),
    };
    let original = windows_source_with_units(scope.clone(), "claude-1.0.0", &units);
    let upgraded = windows_source_with_units(scope, "claude-2.0.0", &units);
    apply_registered_source(
        &mut vault,
        ORIGINAL,
        &NativeMemoryRegistration {
            source: original.clone(),
            last_applied_digest: None,
        },
        102,
    );
    let continuity = ledger(original.clone(), 103);
    vault
        .put_native_memory_candidate(&continuity, None)
        .unwrap();

    apply_registered_source(
        &mut vault,
        UPGRADE,
        &NativeMemoryRegistration {
            source: upgraded.clone(),
            last_applied_digest: None,
        },
        104,
    );
    let active = vault.native_memory_ledgers().unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].source.as_ref(), Some(&upgraded));
    assert_eq!(
        active[0].last_observed_digest,
        continuity.last_observed_digest
    );

    rollback_registered_source(&mut vault, UPGRADE, ROLLBACK, 105);
    assert_eq!(vault.native_memory_ledgers().unwrap(), vec![continuity]);
}

#[test]
fn plausible_non_ascii_windows_case_alias_is_denied_across_projects() {
    const FIRST_PLAN: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074026";
    const SECOND_PLAN: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074027";
    const OTHER_PROJECT: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074028";
    let path = TempVault::new("native-memory-windows-unicode-case-alias");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let first = windows_source(
        ScopeRef::Project {
            project_id: ID_7.parse().unwrap(),
        },
        "claude-1.0.0",
        r"C:\Memory\RÉSUMÉ.md",
    );
    let alias = windows_source(
        ScopeRef::Project {
            project_id: OTHER_PROJECT.parse().unwrap(),
        },
        "claude-1.0.0",
        r"c:\memory\résumé.md",
    );
    apply_registered_source(
        &mut vault,
        FIRST_PLAN,
        &NativeMemoryRegistration {
            source: first,
            last_applied_digest: None,
        },
        106,
    );
    let second_plan = SECOND_PLAN.parse::<PlanId>().unwrap();
    let approval_hash = Sha256Digest([107; 32]);
    vault
        .put_setup_plan(SetupPlanWrite {
            plan_id: &second_plan,
            schema_version: 2,
            approval_version: 2,
            approval_hash: &approval_hash,
            payload: b"unicode-case-alias",
            created_ms: 10,
            expires_ms: 100,
        })
        .unwrap();
    vault
        .claim_setup_plan(&second_plan, SetupPlanAction::Apply, 11)
        .unwrap();

    assert!(matches!(
        vault.finish_setup_plan_with_native_memory(
            &second_plan,
            SetupPlanLifecycle::Applied,
            &[NativeMemoryRegistration {
                source: alias,
                last_applied_digest: None,
            }],
        ),
        Err(VaultError::Validation(message))
            if message.contains("ambiguous Windows native path case")
    ));
    assert_eq!(vault.native_memory_ledgers().unwrap().len(), 1);
}

#[test]
fn exact_non_ascii_windows_path_supersedes_and_rolls_back() {
    const ORIGINAL: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074029";
    const UPGRADE: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074030";
    const ROLLBACK: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074031";
    let path = TempVault::new("native-memory-windows-exact-unicode-upgrade");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let scope = ScopeRef::Project {
        project_id: ID_7.parse().unwrap(),
    };
    let original = windows_source(scope.clone(), "claude-1.0.0", r"C:\Memory\Résumé.md");
    let upgraded = windows_source(scope, "claude-2.0.0", r"C:\Memory\Résumé.md");
    apply_registered_source(
        &mut vault,
        ORIGINAL,
        &NativeMemoryRegistration {
            source: original.clone(),
            last_applied_digest: None,
        },
        108,
    );
    let continuity = ledger(original.clone(), 109);
    vault
        .put_native_memory_candidate(&continuity, None)
        .unwrap();
    apply_registered_source(
        &mut vault,
        UPGRADE,
        &NativeMemoryRegistration {
            source: upgraded.clone(),
            last_applied_digest: None,
        },
        110,
    );
    assert_eq!(vault.native_memory_ledgers().unwrap().len(), 1);
    assert_eq!(
        vault.native_memory_ledgers().unwrap()[0].source.as_ref(),
        Some(&upgraded)
    );

    rollback_registered_source(&mut vault, UPGRADE, ROLLBACK, 111);
    assert_eq!(vault.native_memory_ledgers().unwrap(), vec![continuity]);
}

#[test]
fn extended_trailing_dot_path_remains_distinct_across_projects() {
    const ORDINARY_PLAN: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074032";
    const EXTENDED_PLAN: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074033";
    const OTHER_PROJECT: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074034";
    let path = TempVault::new("native-memory-windows-extended-trailing-cross-project");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let ordinary = windows_source(
        ScopeRef::Project {
            project_id: ID_7.parse().unwrap(),
        },
        "claude-1.0.0",
        r"C:\Memory\memory.md",
    );
    let extended = windows_source(
        ScopeRef::Project {
            project_id: OTHER_PROJECT.parse().unwrap(),
        },
        "claude-1.0.0",
        r"\\?\C:\Memory\memory.md.",
    );

    apply_registered_source(
        &mut vault,
        ORDINARY_PLAN,
        &NativeMemoryRegistration {
            source: ordinary,
            last_applied_digest: None,
        },
        112,
    );
    apply_registered_source(
        &mut vault,
        EXTENDED_PLAN,
        &NativeMemoryRegistration {
            source: extended,
            last_applied_digest: None,
        },
        113,
    );
    assert_eq!(vault.native_memory_ledgers().unwrap().len(), 2);
}

#[test]
fn extended_trailing_space_path_does_not_supersede_same_project_ordinary_path() {
    const ORDINARY_PLAN: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074035";
    const EXTENDED_PLAN: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074036";
    let path = TempVault::new("native-memory-windows-extended-trailing-same-project");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let scope = ScopeRef::Project {
        project_id: ID_7.parse().unwrap(),
    };
    let ordinary = windows_source(scope.clone(), "claude-1.0.0", r"C:\Memory\memory.md");
    let extended = windows_source(scope, "claude-2.0.0", r"\\?\C:\Memory\memory.md ");

    apply_registered_source(
        &mut vault,
        ORDINARY_PLAN,
        &NativeMemoryRegistration {
            source: ordinary,
            last_applied_digest: None,
        },
        114,
    );
    apply_registered_source(
        &mut vault,
        EXTENDED_PLAN,
        &NativeMemoryRegistration {
            source: extended,
            last_applied_digest: None,
        },
        115,
    );
    assert_eq!(vault.native_memory_ledgers().unwrap().len(), 2);
}

#[test]
fn setup_none_and_terminal_replays_preserve_the_newest_export_digest() {
    const FIRST_EXPORT: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073993";
    const ORDINARY_SETUP: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073994";
    const NEWER_EXPORT: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073995";
    let path = TempVault::new("native-memory-export-digest-preservation");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let descriptor = source(ScopeRef::Global, HarnessId::Hermes, "shared-export-source");
    let first_digest = Sha256Digest([71; 32]);
    let newer_digest = Sha256Digest([72; 32]);
    let first_export = NativeMemoryRegistration {
        source: descriptor.clone(),
        last_applied_digest: Some(first_digest),
    };
    let ordinary_setup = NativeMemoryRegistration {
        source: descriptor.clone(),
        last_applied_digest: None,
    };
    let newer_export = NativeMemoryRegistration {
        source: descriptor.clone(),
        last_applied_digest: Some(newer_digest),
    };

    apply_registered_source(&mut vault, FIRST_EXPORT, &first_export, 71);
    apply_registered_source(&mut vault, ORDINARY_SETUP, &ordinary_setup, 72);
    assert_eq!(
        vault
            .native_memory_ledger(&descriptor.id)
            .unwrap()
            .unwrap()
            .last_applied_digest,
        Some(first_digest)
    );

    apply_registered_source(&mut vault, NEWER_EXPORT, &newer_export, 73);
    vault
        .finish_setup_plan_with_native_memory(
            &ORDINARY_SETUP.parse().unwrap(),
            SetupPlanLifecycle::Applied,
            std::slice::from_ref(&ordinary_setup),
        )
        .unwrap();
    vault
        .finish_setup_plan_with_native_memory(
            &FIRST_EXPORT.parse().unwrap(),
            SetupPlanLifecycle::Applied,
            std::slice::from_ref(&first_export),
        )
        .unwrap();
    assert_eq!(
        vault
            .native_memory_ledger(&descriptor.id)
            .unwrap()
            .unwrap()
            .last_applied_digest,
        Some(newer_digest)
    );
}

#[test]
fn rollback_unregisters_a_setup_source_without_deleting_its_reviewed_candidate() {
    const PLAN: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073991";
    const ROLLBACK: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073992";
    let path = TempVault::new("native-memory-setup-candidate-ownership");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let descriptor = source(ScopeRef::Global, HarnessId::Codex, "reviewed-setup-owner");
    let registration = NativeMemoryRegistration {
        source: descriptor.clone(),
        last_applied_digest: None,
    };
    apply_registered_source(&mut vault, PLAN, &registration, 55);
    let candidate = OfflineWorkspace::new(&mut vault, ID_7.parse().unwrap())
        .reconcile_native_memory(ready(descriptor.clone(), "reviewed native fact"))
        .unwrap()
        .unwrap();
    let reviewed = OfflineWorkspace::new(&mut vault, ID_7.parse().unwrap())
        .review_candidate(CandidateReviewParams {
            candidate_id: candidate.id,
            accepted: false,
            operation_id: ID_1.parse().unwrap(),
        })
        .unwrap();

    rollback_registered_source(&mut vault, PLAN, ROLLBACK, 56);

    assert!(
        vault
            .native_memory_ledger(&descriptor.id)
            .unwrap()
            .is_none()
    );
    assert_eq!(vault.candidate(&candidate.id).unwrap(), Some(reviewed));
}

#[test]
fn rollback_preserves_a_preexisting_native_memory_source_and_candidate_state() {
    const PLAN: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073987";
    const ROLLBACK: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073988";
    let path = TempVault::new("native-memory-preexisting-setup-ownership");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let descriptor = source(ScopeRef::Global, HarnessId::Codex, "preexisting-owner");
    let mut preexisting = NativeMemoryLedger::for_source(descriptor.clone());
    preexisting.last_unmanaged_digest = Some(Sha256Digest([61; 32]));
    preexisting.initial_preview_complete = true;
    vault
        .put_native_memory_candidate(&preexisting, None)
        .unwrap();
    let registration = NativeMemoryRegistration {
        source: descriptor.clone(),
        last_applied_digest: None,
    };

    apply_registered_source(&mut vault, PLAN, &registration, 62);
    rollback_registered_source(&mut vault, PLAN, ROLLBACK, 63);

    let preserved = vault.native_memory_ledger(&descriptor.id).unwrap().unwrap();
    assert_eq!(
        preserved.last_unmanaged_digest,
        Some(Sha256Digest([61; 32]))
    );
    assert!(preserved.initial_preview_complete);
}

#[test]
fn native_candidates_are_deterministic_bound_and_atomically_replayed() {
    let project_id = ID_7.parse().unwrap();
    let source = source(
        ScopeRef::Project { project_id },
        HarnessId::ClaudeCode,
        "atomic",
    );
    let fixture_a = TempVault::new("native-memory-atomic-a");
    let keys_a = MemoryKeyStore::default();
    let mut vault_a = Vault::open(fixture_a.path(), CREDENTIAL, &keys_a).unwrap();
    let initial = {
        let mut service = OfflineWorkspace::new(&mut vault_a, ID_7.parse().unwrap());
        service
            .reconcile_native_memory(ready(source.clone(), "Native fact\n"))
            .unwrap()
            .unwrap()
    };

    assert_eq!(initial.state, CandidateState::Pending);
    assert_eq!(initial.source_harness, HarnessId::ClaudeCode);
    assert_eq!(
        initial.proposed_memory.scope,
        ScopeRef::Project { project_id }
    );
    assert_eq!(initial.proposed_memory.origin, MemoryOrigin::NativeImport);
    assert_eq!(initial.proposed_memory.body_markdown, "Native fact\n");
    assert_eq!(
        initial.proposed_memory.tags,
        vec!["native-import", "claude-code"]
    );
    assert_eq!(initial.evidence_summary, "initial native-memory preview");
    assert_eq!(
        initial.id.to_string(),
        initial.proposed_memory.id.to_string()
    );
    assert_eq!(
        initial.id.to_string(),
        initial.proposed_memory.revision.to_string()
    );
    let imported_digest = extract_managed_markdown(b"Native fact\n")
        .unwrap()
        .unmanaged_digest;
    let stored = vault_a.native_memory_ledger(&source.id).unwrap().unwrap();
    assert_eq!(stored.last_imported_digest, Some(imported_digest));
    assert!(stored.initial_preview_complete);

    {
        let mut service = OfflineWorkspace::new(&mut vault_a, ID_7.parse().unwrap());
        assert_eq!(
            service
                .reconcile_native_memory(ready_live(source.clone(), "Native fact\n"))
                .unwrap(),
            None
        );
        assert_eq!(service.candidates(Some(project_id)).unwrap().len(), 1);
    }

    let fixture_b = TempVault::new("native-memory-atomic-b");
    let keys_b = MemoryKeyStore::default();
    let mut vault_b = Vault::open(fixture_b.path(), CREDENTIAL, &keys_b).unwrap();
    let deterministic = OfflineWorkspace::new(&mut vault_b, ID_7.parse().unwrap())
        .reconcile_native_memory(ready(source.clone(), "Native fact\n"))
        .unwrap()
        .unwrap();
    assert_eq!(deterministic.id, initial.id);

    let mut service = OfflineWorkspace::new(&mut vault_a, ID_7.parse().unwrap());
    let live = service
        .reconcile_native_memory(ready_live(source.clone(), "Native fact changed\n"))
        .unwrap()
        .unwrap();
    assert_ne!(live.id, initial.id);
    assert_eq!(live.evidence_summary, "native-memory edit");
    assert_eq!(service.candidates(Some(project_id)).unwrap().len(), 2);
}

#[test]
fn persistence_rejects_evidence_from_the_wrong_reconciliation_phase() {
    let source = source(ScopeRef::Global, HarnessId::Codex, "phase-evidence");
    let producer_path = TempVault::new("native-memory-phase-producer");
    let producer_keys = MemoryKeyStore::default();
    let mut producer = Vault::open(producer_path.path(), CREDENTIAL, &producer_keys).unwrap();
    let initial_candidate = OfflineWorkspace::new(&mut producer, ID_7.parse().unwrap())
        .reconcile_native_memory(ready(source.clone(), "initial candidate"))
        .unwrap()
        .unwrap();
    let ledger = producer.native_memory_ledger(&source.id).unwrap().unwrap();
    let mut candidate = initial_candidate.clone();
    candidate.evidence_summary = "native-memory edit".to_owned();

    let target_path = TempVault::new("native-memory-phase-target");
    let target_keys = MemoryKeyStore::default();
    let mut target = Vault::open(target_path.path(), CREDENTIAL, &target_keys).unwrap();

    assert!(matches!(
        target.put_native_memory_candidate(&ledger, Some(&candidate)),
        Err(VaultError::Validation(_))
    ));
    assert_eq!(target.native_memory_ledger(&source.id).unwrap(), None);
    assert!(target.candidates(None).unwrap().is_empty());

    target
        .put_native_memory_candidate(&ledger, Some(&initial_candidate))
        .unwrap();
    let mut live_candidate = OfflineWorkspace::new(&mut producer, ID_7.parse().unwrap())
        .reconcile_native_memory(ready_live(source.clone(), "live candidate"))
        .unwrap()
        .unwrap();
    let live_ledger = producer.native_memory_ledger(&source.id).unwrap().unwrap();
    live_candidate.evidence_summary = "initial native-memory preview".to_owned();

    assert!(matches!(
        target.put_native_memory_candidate(&live_ledger, Some(&live_candidate)),
        Err(VaultError::Validation(_))
    ));
    assert_eq!(
        target.native_memory_ledger(&source.id).unwrap(),
        Some(ledger)
    );
    assert_eq!(target.candidates(None).unwrap(), vec![initial_candidate]);
}

#[test]
fn direct_candidate_persistence_replay_is_idempotent() {
    let source = source(ScopeRef::Global, HarnessId::Hermes, "direct-replay");
    let producer_path = TempVault::new("native-memory-replay-producer");
    let producer_keys = MemoryKeyStore::default();
    let mut producer = Vault::open(producer_path.path(), CREDENTIAL, &producer_keys).unwrap();
    let candidate = OfflineWorkspace::new(&mut producer, ID_7.parse().unwrap())
        .reconcile_native_memory(ready(source.clone(), "candidate replay"))
        .unwrap()
        .unwrap();
    let ledger = producer.native_memory_ledger(&source.id).unwrap().unwrap();

    let target_path = TempVault::new("native-memory-replay-target");
    let target_keys = MemoryKeyStore::default();
    let mut target = Vault::open(target_path.path(), CREDENTIAL, &target_keys).unwrap();
    target
        .put_native_memory_candidate(&ledger, Some(&candidate))
        .unwrap();
    target
        .put_native_memory_candidate(&ledger, Some(&candidate))
        .unwrap();

    assert_eq!(target.candidates(None).unwrap(), vec![candidate]);
    assert_eq!(
        target.native_memory_ledger(&source.id).unwrap(),
        Some(ledger)
    );
}

#[test]
fn reverting_to_seen_content_advances_the_ledger_without_rewriting_the_candidate() {
    for reviewed_state in [
        CandidateState::Pending,
        CandidateState::Accepted,
        CandidateState::Rejected,
    ] {
        let suffix = match reviewed_state {
            CandidateState::Pending => "pending",
            CandidateState::Accepted => "accepted",
            CandidateState::Rejected => "rejected",
        };
        let source = source(
            ScopeRef::Global,
            HarnessId::Codex,
            &format!("revert-{suffix}"),
        );
        let path = TempVault::new(&format!("native-memory-revert-{suffix}"));
        let keys = MemoryKeyStore::default();
        let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
        let initial = OfflineWorkspace::new(&mut vault, ID_7.parse().unwrap())
            .reconcile_native_memory(ready(source.clone(), "content A"))
            .unwrap()
            .unwrap();
        let preserved = if reviewed_state == CandidateState::Pending {
            initial.clone()
        } else {
            OfflineWorkspace::new(&mut vault, ID_7.parse().unwrap())
                .review_candidate(CandidateReviewParams {
                    candidate_id: initial.id,
                    accepted: reviewed_state == CandidateState::Accepted,
                    operation_id: ID_7.parse().unwrap(),
                })
                .unwrap()
        };

        let live = OfflineWorkspace::new(&mut vault, ID_7.parse().unwrap())
            .reconcile_native_memory(ready_live(source.clone(), "content B"))
            .unwrap()
            .unwrap();
        assert_ne!(live.id, initial.id);

        let reverted = OfflineWorkspace::new(&mut vault, ID_7.parse().unwrap())
            .reconcile_native_memory(ready_live(source.clone(), "content A"))
            .unwrap();

        assert_eq!(reverted, None);
        assert_eq!(vault.candidate(&initial.id).unwrap(), Some(preserved));
        assert_eq!(vault.candidates(None).unwrap().len(), 2);
        let ledger = vault.native_memory_ledger(&source.id).unwrap().unwrap();
        assert_eq!(
            ledger.last_imported_digest,
            Some(
                extract_managed_markdown(b"content A")
                    .unwrap()
                    .unmanaged_digest
            )
        );
        assert_eq!(
            vault.memory(&initial.proposed_memory.id).unwrap().is_some(),
            reviewed_state == CandidateState::Accepted
        );
    }
}

#[test]
fn seen_candidate_dedup_rejects_every_immutable_field_mismatch() {
    let source = source(ScopeRef::Global, HarnessId::Codex, "immutable-dedup");
    let producer_path = TempVault::new("native-memory-immutable-producer");
    let producer_keys = MemoryKeyStore::default();
    let mut producer = Vault::open(producer_path.path(), CREDENTIAL, &producer_keys).unwrap();
    let initial = OfflineWorkspace::new(&mut producer, ID_7.parse().unwrap())
        .reconcile_native_memory(ready(source.clone(), "content A"))
        .unwrap()
        .unwrap();
    let initial_ledger = producer.native_memory_ledger(&source.id).unwrap().unwrap();
    OfflineWorkspace::new(&mut producer, ID_7.parse().unwrap())
        .reconcile_native_memory(ready_live(source.clone(), "content B"))
        .unwrap()
        .unwrap();
    assert_eq!(
        OfflineWorkspace::new(&mut producer, ID_7.parse().unwrap())
            .reconcile_native_memory(ready_live(source.clone(), "content A"))
            .unwrap(),
        None
    );
    let revert_ledger = producer.native_memory_ledger(&source.id).unwrap().unwrap();
    let mut incoming = initial.clone();
    incoming.evidence_summary = "native-memory edit".to_owned();

    for field in [
        "identity", "content", "scope", "harness", "title", "tags", "origin",
    ] {
        let path = TempVault::new(&format!("native-memory-immutable-{field}"));
        let keys = MemoryKeyStore::default();
        let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
        vault
            .put_native_memory_candidate(&initial_ledger, Some(&initial))
            .unwrap();
        let mut corrupted = initial.clone();
        match field {
            "identity" => corrupted.proposed_memory.id = ID_7.parse().unwrap(),
            "content" => corrupted.proposed_memory.body_markdown = "altered".to_owned(),
            "scope" => {
                corrupted.proposed_memory.scope = ScopeRef::Project {
                    project_id: ID_7.parse().unwrap(),
                };
            }
            "harness" => corrupted.source_harness = HarnessId::Hermes,
            "title" => corrupted.proposed_memory.title = "Altered title".to_owned(),
            "tags" => corrupted.proposed_memory.tags = vec!["altered".to_owned()],
            "origin" => corrupted.proposed_memory.origin = MemoryOrigin::Explicit,
            _ => unreachable!(),
        }
        vault.put_candidate(&corrupted).unwrap();

        assert!(matches!(
            vault.put_native_memory_candidate(&revert_ledger, Some(&incoming)),
            Err(VaultError::OperationConflict)
        ));
        assert_eq!(
            vault.native_memory_ledger(&source.id).unwrap(),
            Some(initial_ledger.clone()),
            "{field}"
        );
    }
}

#[test]
fn candidate_conflict_rolls_back_the_ledger_advance() {
    let source = source(ScopeRef::Global, HarnessId::Codex, "rollback");
    let path = TempVault::new("native-memory-candidate-conflict");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let first = OfflineWorkspace::new(&mut vault, ID_7.parse().unwrap())
        .reconcile_native_memory(ready(source.clone(), "Original native body"))
        .unwrap()
        .unwrap();
    let before = vault.native_memory_ledger(&source.id).unwrap().unwrap();
    let mut altered = first;
    altered.proposed_memory.body_markdown = "Altered bytes under the same identity".to_owned();
    let mut attempted = before.clone();
    attempted.last_observed_digest = Some(Sha256Digest([77; 32]));

    assert!(matches!(
        vault.put_native_memory_candidate(&attempted, Some(&altered)),
        Err(VaultError::OperationConflict)
    ));
    assert_eq!(
        vault.native_memory_ledger(&source.id).unwrap(),
        Some(before)
    );
}

#[test]
fn invalid_ready_source_is_rejected_without_persisting_state() {
    let mut source = source(ScopeRef::Global, HarnessId::Hermes, "invalid-ready");
    let original_id = source.id;
    source.id = NativeMemorySourceId(Sha256Digest([88; 32]));
    let path = TempVault::new("native-memory-invalid-ready");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let error = OfflineWorkspace::new(&mut vault, ID_7.parse().unwrap())
        .reconcile_native_memory(ready(source, "body"))
        .unwrap_err();

    assert_eq!(error.code, ErrorCode::InvalidRequest);
    assert_eq!(vault.native_memory_ledger(&original_id).unwrap(), None);
}
