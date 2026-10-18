use super::*;
use crate::{
    native_transaction::{MutationKind, RestorableStateFingerprint},
    vault::{DatabaseKeyStore, NativeSandboxCleanupState, NativeTransactionStatus},
};
use context_relay_protocol::{HarnessId, NativePlatform, Sha256Digest, WireNativeValue};
use rusqlite::Connection;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

const CREDENTIAL: &str = "journal-compensation-resume";
const TRANSACTION: &str = "compensation-resume";
const PLAN: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073981";
const KEY: [u8; 32] = [0x31; 32];

struct TestKeyStore;
impl DatabaseKeyStore for TestKeyStore {
    fn load_key(&self, credential: &str) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
        assert_eq!(credential, CREDENTIAL);
        Ok(Some(Zeroizing::new(KEY.to_vec())))
    }

    fn store_key(&self, _: &str, _: &[u8]) -> Result<(), VaultError> {
        panic!("the fixture key is already present")
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    lock_root: PathBuf,
    database: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let lock_root = fs::canonicalize(directory.path()).unwrap();
        let fixture = Self {
            database: lock_root.join("vault.db"),
            lock_root,
            _directory: directory,
        };
        fixture
            .open()
            .begin_native_transaction(
                TRANSACTION,
                NativePlanWrite {
                    plan_id: &PLAN.parse().unwrap(),
                    approval_hash: &Sha256Digest([8; 32]),
                    payload: b"encrypted compensation fixture",
                    created_ms: 10,
                    expires_ms: 20,
                },
                identity(),
            )
            .unwrap();
        fixture
    }

    fn open(&self) -> Vault {
        Vault::open(&self.database, CREDENTIAL, &TestKeyStore).unwrap()
    }

    fn journal<'a>(&self, vault: &'a mut Vault) -> VaultNativeJournal<'a> {
        let mut journal = VaultNativeJournal::new(
            vault,
            &self.lock_root,
            TRANSACTION,
            identity(),
            b"encrypted compensation fixture".to_vec(),
            10,
            BeforeImagePolicy::new(1024, 100),
        );
        // The fixture already contains the durable transaction. Acquire the
        // real lock without attempting to begin a second forward transaction.
        journal.profile_lock = Some(ProfileTransactionLock::acquire(&self.lock_root).unwrap());
        journal
    }

    fn execute_sql(&self, sql: &str) {
        let connection = Connection::open(&self.database).unwrap();
        // SAFETY: keying is the first operation on this owned SQLite handle;
        // the fixed fixture key lives throughout the synchronous call.
        let keyed = unsafe {
            rusqlite::ffi::sqlite3_key(
                connection.handle(),
                KEY.as_ptr().cast(),
                KEY.len().try_into().unwrap(),
            )
        };
        assert_eq!(keyed, rusqlite::ffi::SQLITE_OK);
        connection.execute_batch(sql).unwrap();
    }
}

fn identity() -> NativeSandboxIdentity {
    NativeSandboxIdentity::Windows {
        moniker: "context-relay.native.0123456789abcdef0123456789abcdef".into(),
        sid:
            b"S-1-15-2-3872518810-2985098273-1912316193-2655983105-1250049442-371239648-1157085541"
                .to_vec(),
    }
}

fn assert_finished(vault: &Vault, status: NativeTransactionStatus) {
    let transaction = vault.native_transaction(TRANSACTION).unwrap().unwrap();
    assert_eq!(transaction.status, status);
    assert_eq!(transaction.current_step, 20);
    assert_eq!(transaction.entered_step, 20);
    assert_eq!(
        transaction.sandbox_cleanup_state,
        NativeSandboxCleanupState::Cleaned
    );
}

#[test]
fn a_partially_applied_compensation_resumes_from_its_own_midpoint() {
    let fixture = Fixture::new();
    let mut vault = fixture.open();
    let plan = PLAN.parse().unwrap();
    for sequence in 0..2_u32 {
        let before = format!("before-{sequence}");
        vault
            .put_before_images_batch(
                &[BeforeImageWrite {
                    id: &before,
                    plan_id: Some(&plan),
                    payload: b"before image",
                    created_ms: 10,
                }],
                BeforeImagePolicy::new(1024, 100),
            )
            .unwrap();
        let path = format!(r"C:\vault\{before}");
        let target = WireNativeValue {
            platform: NativePlatform::Windows,
            bytes: path.encode_utf16().flat_map(u16::to_le_bytes).collect(),
            display: Some(path),
        };
        let token = NativeObjectToken {
            volume: vec![1],
            object: sequence.to_le_bytes().to_vec(),
            topology: vec![2],
        };
        vault
            .prepare_native_wal(
                TRANSACTION,
                &NativeWalWrite {
                    target_sequence: sequence,
                    target: &target,
                    object_token: &token,
                    before_image_id: &before,
                    operation_kind: MutationKind::Payload,
                    expected: &RestorableStateFingerprint(Sha256Digest([1; 32])),
                    intended_applied: &RestorableStateFingerprint(Sha256Digest([2; 32])),
                    intended_restored: &RestorableStateFingerprint(Sha256Digest([1; 32])),
                },
            )
            .unwrap();
        vault
            .transition_native_wal_with_applied_object_token(
                TRANSACTION,
                sequence,
                NativeWalState::Applied,
                &token,
            )
            .unwrap();
        // Filesystem compensation has supplied its durable restored candidate;
        // this test interrupts the journal finalizer between its row commits.
        vault
            .transition_native_wal(TRANSACTION, sequence, NativeWalState::RestorePrepared)
            .unwrap();
        vault
            .record_native_wal_restored_candidate(TRANSACTION, sequence, &token)
            .unwrap();
    }
    fixture.execute_sql(
        "CREATE TRIGGER interrupt_compensation BEFORE UPDATE OF state ON native_mutation_wal
         WHEN NEW.target_sequence = 1 AND NEW.state = 'restored'
         BEGIN SELECT RAISE(ABORT, 'injected compensation interruption'); END;",
    );
    {
        let mut journal = fixture.journal(&mut vault);
        let error = journal.finish_compensated(&[]).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("injected compensation interruption")
        );
        assert!(journal.profile_lock.is_some());
    }
    drop(vault);

    fixture.execute_sql("DROP TRIGGER interrupt_compensation;");
    let mut reopened = fixture.open();
    let interrupted = reopened.native_wal(TRANSACTION).unwrap();
    assert_eq!(interrupted.len(), 2);
    assert_eq!(interrupted[0].state, NativeWalState::Restored);
    assert_eq!(interrupted[1].state, NativeWalState::RestorePrepared);
    assert_eq!(
        reopened
            .native_transaction(TRANSACTION)
            .unwrap()
            .unwrap()
            .status,
        NativeTransactionStatus::Restoring
    );
    {
        let mut journal = fixture.journal(&mut reopened);
        journal.finish_compensated(&[]).unwrap();
        assert!(journal.profile_lock.is_none());
    }
    assert_finished(&reopened, NativeTransactionStatus::Restored);
    assert!(reopened.native_wal(TRANSACTION).unwrap().is_empty());
    assert_eq!(reopened.before_image_bytes().unwrap(), 0);
    drop(reopened);
    assert_finished(&fixture.open(), NativeTransactionStatus::Restored);
}

#[test]
fn a_partially_applied_cli_compensation_resumes_from_its_own_midpoint() {
    let fixture = Fixture::new();
    let mut vault = fixture.open();
    let expected = br#"{"command":"/old","args":[]}"#;
    let intended = br#"{"command":"/new","args":["--harness","codex"]}"#;
    let expected_fingerprint = Sha256Digest(Sha256::digest(expected).into());
    let intended_fingerprint = Sha256Digest(Sha256::digest(intended).into());
    for (sequence, harness, stable_id) in [
        (0, HarnessId::Codex, "018f22e2-79b0-7cc8-98c4-dc0c0c073982"),
        (
            1,
            HarnessId::ClaudeCode,
            "018f22e2-79b0-7cc8-98c4-dc0c0c073983",
        ),
    ] {
        vault
            .prepare_native_cli_wal(
                TRANSACTION,
                &NativeCliWalWrite {
                    sequence,
                    stable_id,
                    harness,
                    server_name: "context-relay",
                    expected_declaration: Some(expected),
                    expected_fingerprint: Some(&expected_fingerprint),
                    intended_declaration: Some(intended),
                    intended_fingerprint: Some(&intended_fingerprint),
                    forward_operations: br#"[{"op":"add","exact":true}]"#,
                    rollback_operations: br#"[{"op":"restore","exact":true}]"#,
                },
            )
            .unwrap();
        vault
            .transition_native_cli_wal(TRANSACTION, sequence, NativeCliWalState::Applied)
            .unwrap();
    }
    fixture.execute_sql(
        "CREATE TRIGGER interrupt_compensation BEFORE UPDATE OF state ON native_cli_wal
         WHEN NEW.sequence = 1 AND NEW.state = 'conflict'
         BEGIN SELECT RAISE(ABORT, 'injected compensation interruption'); END;",
    );
    {
        let mut journal = fixture.journal(&mut vault);
        let error = journal.finish_compensated(&[]).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("injected compensation interruption")
        );
        assert!(journal.profile_lock.is_some());
    }
    drop(vault);

    fixture.execute_sql("DROP TRIGGER interrupt_compensation;");
    let mut reopened = fixture.open();
    let interrupted = reopened.native_cli_wal(TRANSACTION).unwrap();
    assert_eq!(interrupted.len(), 2);
    assert_eq!(interrupted[0].state, NativeCliWalState::Conflict);
    assert_eq!(interrupted[1].state, NativeCliWalState::Applied);
    {
        let mut journal = fixture.journal(&mut reopened);
        let error = journal.finish_compensated(&[]).unwrap_err();
        assert_eq!(
            error.to_string(),
            "native CLI compensation encountered live divergence"
        );
        assert!(journal.profile_lock.is_none());
    }
    assert_finished(&reopened, NativeTransactionStatus::Conflict);
    let conflicts = reopened.native_cli_wal(TRANSACTION).unwrap();
    assert_eq!(conflicts.len(), 2);
    assert!(
        conflicts
            .iter()
            .all(|row| row.state == NativeCliWalState::Conflict)
    );
    drop(reopened);
    let reopened = fixture.open();
    assert_finished(&reopened, NativeTransactionStatus::Conflict);
    assert_eq!(reopened.native_cli_wal(TRANSACTION).unwrap(), conflicts);
}
