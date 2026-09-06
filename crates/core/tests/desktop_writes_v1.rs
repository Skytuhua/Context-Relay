mod support;

use context_relay_core::vault::{Vault, VaultError};
use context_relay_protocol::{DesktopWrite, MemoryCreateParams, MemoryKind, ScopeRef};
use support::{ID_1, MemoryKeyStore, TempVault};

#[test]
fn quota_rejects_new_writes_without_eviction_and_paging_survives_removal() {
    let path = TempVault::new("desktop-write-capacity");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), "journal", &keys).unwrap();
    let mut first = None;
    for index in 0..256 {
        let DesktopWrite::MemoryCreate(mut p) = write() else {
            unreachable!()
        };
        p.operation_id = format!("018f22e2-79b0-7cc8-98c4-{index:012x}")
            .parse()
            .unwrap();
        let pending = DesktopWrite::MemoryCreate(p);
        first.get_or_insert_with(|| pending.clone());
        vault.prepare_desktop_write(&pending).unwrap();
    }
    assert!(matches!(
        vault.prepare_desktop_write(&write()),
        Err(VaultError::BudgetExceeded)
    ));
    vault
        .prepare_desktop_write(first.as_ref().unwrap())
        .unwrap();
    let page = vault.desktop_writes(None).unwrap();
    assert_eq!(page.writes.len(), 50);
    let cursor = page.next_cursor.unwrap();
    for entry in page.writes {
        vault.forget_desktop_write(entry.operation_id).unwrap();
    }
    let next = vault.desktop_writes(Some(cursor)).unwrap();
    assert_eq!(next.writes.len(), 50);
    assert!(
        next.writes[0]
            .operation_id
            .to_string()
            .ends_with("000000000032")
    );
    vault.prepare_desktop_write(&write()).unwrap();
}

#[test]
fn recovered_request_replays_a_committed_save_after_vault_restart() {
    use context_relay_core::service::OfflineWorkspace;
    let path = TempVault::new("desktop-write-replay");
    let keys = MemoryKeyStore::default();
    let pending = write();
    let original = {
        let mut vault = Vault::open(path.path(), "journal", &keys).unwrap();
        vault.prepare_desktop_write(&pending).unwrap();
        let DesktopWrite::MemoryCreate(params) = pending.clone() else {
            unreachable!()
        };
        OfflineWorkspace::new(&mut vault, support::ID_9.parse().unwrap())
            .create_memory(params)
            .unwrap()
    };
    let mut vault = Vault::open(path.path(), "journal", &keys).unwrap();
    let recovered = vault
        .desktop_write(pending.operation_id())
        .unwrap()
        .unwrap();
    let DesktopWrite::MemoryCreate(params) = recovered else {
        unreachable!()
    };
    let replay = OfflineWorkspace::new(&mut vault, support::ID_9.parse().unwrap())
        .create_memory(params)
        .unwrap();
    assert_eq!(replay, original);
    assert_eq!(vault.memories(None, true).unwrap().len(), 1);
    vault.forget_desktop_write(pending.operation_id()).unwrap();
    assert_eq!(vault.memories(None, true).unwrap(), vec![original]);
}

fn write() -> DesktopWrite {
    DesktopWrite::MemoryCreate(MemoryCreateParams {
        operation_id: ID_1.parse().unwrap(),
        scope: ScopeRef::Global,
        kind: MemoryKind::Note,
        title: "Recovery secret title".into(),
        body_markdown: "Recovery secret body".into(),
        tags: vec![],
    })
}

#[test]
fn byte_quota_preserves_existing_large_requests_without_eviction() {
    let path = TempVault::new("desktop-write-byte-capacity");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), "journal", &keys).unwrap();
    let mut count = 0;
    let mut first = None;
    for index in 0..65 {
        let DesktopWrite::MemoryCreate(mut params) = write() else {
            unreachable!()
        };
        params.operation_id = format!("018f22e2-79b0-7cc8-98c4-{index:012x}")
            .parse()
            .unwrap();
        params.body_markdown = "x".repeat(context_relay_protocol::MAX_MARKDOWN_BYTES);
        let pending = DesktopWrite::MemoryCreate(params);
        first.get_or_insert_with(|| pending.clone());
        match vault.prepare_desktop_write(&pending) {
            Ok(()) => count += 1,
            Err(VaultError::BudgetExceeded) => break,
            Err(error) => panic!("{error}"),
        }
    }
    assert_eq!(count, 63);
    vault
        .prepare_desktop_write(first.as_ref().unwrap())
        .unwrap();
    let page = vault.desktop_writes(None).unwrap();
    assert_eq!(page.writes.len(), 50);
    assert_eq!(
        vault.desktop_writes(page.next_cursor).unwrap().writes.len(),
        13
    );
}

#[test]
fn prepared_write_survives_encrypted_reopen_without_creating_a_record() {
    let path = TempVault::new("desktop-write-reopen");
    let keys = MemoryKeyStore::default();
    let pending = write();
    {
        let mut vault = Vault::open(path.path(), "journal", &keys).unwrap();
        vault.prepare_desktop_write(&pending).unwrap();
        vault.prepare_desktop_write(&pending).unwrap();
        assert!(vault.memories(None, true).unwrap().is_empty());
    }
    let bytes = std::fs::read(path.path()).unwrap();
    assert!(
        !bytes
            .windows(21)
            .any(|value| value == b"Recovery secret title")
    );
    let mut vault = Vault::open(path.path(), "journal", &keys).unwrap();
    assert_eq!(
        vault.desktop_write(pending.operation_id()).unwrap(),
        Some(pending.clone())
    );
    let page = vault.desktop_writes(None).unwrap();
    assert_eq!(page.writes.len(), 1);
    assert_eq!(page.writes[0].operation_id, pending.operation_id());
    assert!(page.next_cursor.is_none());
    vault.forget_desktop_write(pending.operation_id()).unwrap();
    vault.forget_desktop_write(pending.operation_id()).unwrap();
    assert!(vault.desktop_writes(None).unwrap().writes.is_empty());
}

#[test]
fn prepare_rejects_changed_identity_and_invalid_input_without_replacing_original() {
    let path = TempVault::new("desktop-write-binding");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), "journal", &keys).unwrap();
    let original = write();
    vault.prepare_desktop_write(&original).unwrap();
    let DesktopWrite::MemoryCreate(mut changed) = original.clone() else {
        unreachable!()
    };
    changed.title = "Different intent".into();
    assert!(matches!(
        vault.prepare_desktop_write(&DesktopWrite::MemoryCreate(changed.clone())),
        Err(VaultError::OperationConflict)
    ));
    changed.body_markdown.clear();
    assert!(
        vault
            .prepare_desktop_write(&DesktopWrite::MemoryCreate(changed))
            .is_err()
    );
    assert_eq!(
        vault.desktop_write(original.operation_id()).unwrap(),
        Some(original)
    );
}
