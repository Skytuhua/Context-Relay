//! Private read bridge for already committed representatives; never incoming admission.
use super::*;

const LIVE_READ_BUDGET: HistoricalReconstructionBudget = HistoricalReconstructionBudget {
    transfer: HistoricalTransferBudget {
        history: CURRENT_BUDGET,
        max_pages: 4096,
        max_bytes: CURRENT_BUDGET.max_bytes,
    },
    max_operations: 100_000,
    max_operation_bytes: CURRENT_BUDGET.max_bytes,
    max_dependencies: 1_000_000,
};

/// Opaque cycle-local read material. Only the vault can construct or use this capability.
/// Ordinary `TrustedSyncMaterial::content_key` remains restricted to the current epoch.
pub struct HistoricalReadMaterial {
    endpoint: MembershipEndpoint,
    scope: crate::sync::SyncScope,
    device: DeviceId,
    keys: BTreeMap<u32, ContentKey>,
}

pub(in crate::vault) fn read_material(
    c: &Connection,
    expected: MembershipEndpoint,
    keys: &DeviceKeys,
) -> Result<HistoricalReadMaterial, VaultError> {
    let tx = c.unchecked_transaction()?;
    let stored = load(&tx, CURRENT_BUDGET)?.ok_or_else(invalid)?;
    let history = stored.verify(CURRENT_BUDGET)?;
    let device = history
        .state()
        .active_devices
        .values()
        .find(|certificate| {
            certificate.signing_public_key == keys.signing_public_key()
                && certificate.wrapping_public_key == keys.wrapping_public_key()
        })
        .ok_or_else(invalid)?
        .device_id;
    material::endpoint_check(&stored, expected, device, keys, CURRENT_BUDGET)?;
    let count:i64=tx.query_row("SELECT count(DISTINCT key_epoch) FROM membership_epoch_secrets WHERE device_id=?1 AND key_epoch<?2",params![device.to_string(),expected.key_epoch],|r|r.get(0))?;
    if count < 0
        || count > i64::from(expected.key_epoch)
        || count > CURRENT_BUDGET.max_events as i64 + 1
    {
        return Err(VaultError::BudgetExceeded);
    }
    let epochs=tx.prepare("SELECT DISTINCT key_epoch FROM membership_epoch_secrets WHERE device_id=?1 AND key_epoch<?2 ORDER BY key_epoch")?
        .query_map(params![device.to_string(),expected.key_epoch],|r|r.get::<_,u32>(0))?
        .collect::<Result<Vec<_>,_>>()?;
    let mut available = BTreeMap::new();
    // Missing history does not block ordinary current authority. Known seals are authenticated.
    for epoch in epochs {
        if let Some(bundle) =
            material::load_secret(&tx, &stored, device, epoch, false, keys, CURRENT_BUDGET)?
        {
            available.insert(epoch, ContentKey::from_bytes(*bundle.active_epoch_key()));
        }
    }
    tx.commit()?;
    Ok(HistoricalReadMaterial {
        endpoint: expected,
        scope: stored.scope,
        device,
        keys: available,
    })
}

impl HistoricalReadMaterial {
    pub(in crate::vault) fn rehydrate(
        &self,
        c: &Connection,
        operation: &SyncOperationV1,
    ) -> Result<RecordMutationV1, VaultError> {
        let stored = load(c, CURRENT_BUDGET)?.ok_or_else(invalid)?;
        let history = stored.verify(CURRENT_BUDGET)?;
        if stored.endpoint != self.endpoint
            || stored.scope != self.scope
            || operation.account_id != self.scope.account_id
            || operation.workspace_id != self.scope.workspace_id
            || operation.key_epoch >= self.endpoint.key_epoch
            || activation::active_device(c, &stored, &history)? != Some(self.device)
        {
            return Err(invalid());
        }
        self.keys.get(&operation.key_epoch).ok_or_else(invalid)?;
        authenticate_local_operation(c, &stored, self.device, operation, true)?;
        decrypt(operation, &self.keys)
    }
}

// Bound stored JSON before the merge primitive can load an existing representative.
// This counts raw rows for allocation only; they never become authenticated provenance.
pub(super) fn ensure_live_bounds(c: &Connection) -> Result<(), VaultError> {
    let budget = LIVE_READ_BUDGET;
    let (count,bytes):(i64,i64)=c.query_row("SELECT count(*),COALESCE(sum(n),0) FROM (SELECT length(o.payload_json)+length(o.id)+length(o.record_id)+COALESCE(length(m.device_id)+length(m.device_sequence)+length(m.canonical_sha256)+length(m.direction)+length(m.state),0) AS n FROM operations o LEFT JOIN sync_operation_meta m ON m.operation_id=o.id UNION ALL SELECT length(canonical) FROM historical_verified_operations)",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
    if count < 0
        || bytes < 0
        || count > budget.max_operations as i64
        || bytes > budget.max_operation_bytes as i64
    {
        return Err(VaultError::BudgetExceeded);
    }
    Ok(())
}

// Installation privately opens current material before reaching this validator; it need not
// already be activated. Current readers separately enforce their exact activation stamp.
pub(super) fn authenticate_local_operation(
    c: &Connection,
    stored: &Stored,
    device: DeviceId,
    operation: &SyncOperationV1,
    representative: bool,
) -> Result<(), VaultError> {
    let budget = LIVE_READ_BUDGET;
    ensure_live_bounds(c)?;
    let mut entries = Evidence::new();
    let mut local = BTreeSet::new();
    let mut ids = BTreeMap::new();
    let mut dependencies = 0usize;
    let mut q=c.prepare("SELECT o.id,o.record_id,o.payload_json,m.device_id,m.device_sequence,m.canonical_sha256,m.direction,m.state FROM operations o JOIN sync_operation_meta m ON m.operation_id=o.id WHERE m.account_id=?1 AND m.workspace_id=?2")?;
    let mut rows = q.query(params![
        stored.scope.account_id.to_string(),
        stored.scope.workspace_id.to_string()
    ])?;
    while let Some(row) = rows.next()? {
        let op: SyncOperationV1 = crate::vault::from_json(&row.get::<_, Vec<u8>>(2)?)?;
        let entry = decode_entry(&checked(encode_sync_operation_v1(&op))?)?;
        let direction: String = row.get(6)?;
        let state: String = row.get(7)?;
        if row.get::<_, String>(0)? != op.operation_id.to_string()
            || row.get::<_, String>(1)? != op.record_id.to_string()
            || row.get::<_, String>(3)? != op.device_id.to_string()
            || row.get::<_, String>(4)? != op.device_sequence.to_string()
            || row.get::<_, Vec<u8>>(5)? != entry.hash.0
            || op.account_id != stored.scope.account_id
            || op.workspace_id != stored.scope.workspace_id
            || !matches!(
                (direction.as_str(), state.as_str()),
                ("incoming", "applied") | ("outgoing", "queued")
            )
        {
            return Err(invalid());
        }
        local.insert((op.device_id, op.device_sequence));
        insert(&mut entries, &mut ids, &mut dependencies, entry, budget)?;
    }
    let mut q=c.prepare("SELECT CASE WHEN length(operation_id)=36 THEN operation_id END,CASE WHEN length(device_id)=36 THEN device_id END,CASE WHEN length(device_sequence) BETWEEN 1 AND 20 THEN device_sequence END,canonical FROM historical_verified_operations")?;
    let mut rows = q.query([])?;
    while let Some(row) = rows.next()? {
        let entry = decode_entry(&row.get::<_, Vec<u8>>(3)?)?;
        if row.get::<_, String>(0)? != entry.operation.operation_id.to_string()
            || row.get::<_, String>(1)? != entry.operation.device_id.to_string()
            || row.get::<_, String>(2)? != entry.operation.device_sequence.to_string()
        {
            return Err(invalid());
        }
        insert(&mut entries, &mut ids, &mut dependencies, entry, budget)?;
    }
    let evidence = authenticate(stored, entries, budget)?;
    if !saved_prefixes(c, stored, &evidence, device, budget)? {
        return Err(invalid());
    }
    let entry = evidence
        .entries
        .get(&(operation.device_id, operation.device_sequence))
        .ok_or_else(invalid)?;
    if !local.contains(&(operation.device_id, operation.device_sequence))
        || entry.bytes != checked(encode_sync_operation_v1(operation))?
    {
        return Err(invalid());
    }
    let mut frontier = Vec::new();
    let mut q=c.prepare("SELECT CASE WHEN length(device_id)=36 THEN device_id END,CASE WHEN length(device_sequence) BETWEEN 1 AND 20 THEN device_sequence END,CASE WHEN length(canonical_sha256)=32 THEN canonical_sha256 END FROM sync_device_heads WHERE workspace_id=?1 ORDER BY device_id")?;
    let mut rows = q.query([stored.scope.workspace_id.to_string()])?;
    while let Some(row) = rows.next()? {
        let device: DeviceId = row.get::<_, String>(0)?.parse().map_err(|_| invalid())?;
        let seq: u64 = row.get::<_, String>(1)?.parse().map_err(|_| invalid())?;
        let hash: Vec<u8> = row.get(2)?;
        if !local.contains(&(device, seq))
            || evidence
                .entries
                .get(&(device, seq))
                .is_none_or(|e| hash != e.hash.0)
        {
            return Err(invalid());
        }
        frontier.push(DeviceSequence {
            device_id: device,
            sequence: seq,
        });
    }
    if frontier
        .iter()
        .find(|h| h.device_id == operation.device_id)
        .is_none_or(|h| h.sequence < operation.device_sequence)
    {
        return Err(invalid());
    }
    let verified = verified_ranges(&evidence, &frontier, budget)?.ok_or_else(invalid)?;
    let mut represented = false;
    let mut q = c.prepare("SELECT CASE WHEN length(h.operation_id)=36 THEN h.operation_id END,CASE WHEN length(h.canonical_sha256)=32 THEN h.canonical_sha256 END,CASE WHEN length(h.record_kind)<=32 THEN h.record_kind END,CASE WHEN length(h.mutation_kind)<=32 THEN h.mutation_kind END,CASE WHEN length(m.device_id)=36 THEN m.device_id END,CASE WHEN length(m.device_sequence) BETWEEN 1 AND 20 THEN m.device_sequence END FROM sync_record_heads h JOIN sync_record_owners o ON o.record_id=h.record_id LEFT JOIN sync_operation_meta m ON m.operation_id=h.operation_id WHERE h.workspace_id=?1 AND h.record_id=?2 AND o.account_id=?3 AND o.workspace_id=?1 AND o.binding_state='verified'")?;
    let mut rows = q.query(params![
        stored.scope.workspace_id.to_string(),
        operation.record_id.to_string(),
        stored.scope.account_id.to_string()
    ])?;
    let mut head_count = 0usize;
    while let Some(row) = rows.next()? {
        head_count += 1;
        if head_count > budget.max_operations {
            return Err(VaultError::BudgetExceeded);
        }
        let head_device: DeviceId = row.get::<_, String>(4)?.parse().map_err(|_| invalid())?;
        let head_sequence: u64 = row.get::<_, String>(5)?.parse().map_err(|_| invalid())?;
        let head = evidence
            .entries
            .get(&(head_device, head_sequence))
            .ok_or_else(invalid)?;
        // A signature and higher sequence alone do not prove a stored head's chain.
        // Representation may use only the already verified local device/causal closure.
        if verified
            .get(&head_device)
            .is_none_or(|end| head_sequence > *end)
            || !local.contains(&(head_device, head_sequence))
            || head.operation.operation_id.to_string() != row.get::<_, String>(0)?
            || head.hash.0 != row.get::<_, Vec<u8>>(1)?.as_slice()
            || head.operation.record_id != operation.record_id
            || head.operation.record_kind != operation.record_kind
            || crate::vault::sync::record_kind_name(head.operation.record_kind)
                != row.get::<_, String>(2)?
            || crate::vault::sync::mutation_kind_name(head.operation.mutation_kind)
                != row.get::<_, String>(3)?
        {
            return Err(invalid());
        }
        represented |= if representative {
            head.bytes == entry.bytes
        } else {
            matches!(
                crate::sync::compare_operations(&head.operation, operation),
                crate::sync::CausalOrder::After | crate::sync::CausalOrder::Equal
            )
        };
    }
    if !represented {
        return Err(invalid());
    }
    Ok(())
}

fn insert(
    entries: &mut Evidence,
    ids: &mut BTreeMap<context_relay_protocol::OperationId, Sha256Digest>,
    dependencies: &mut usize,
    entry: Entry,
    budget: HistoricalReconstructionBudget,
) -> Result<(), VaultError> {
    let index = (entry.operation.device_id, entry.operation.device_sequence);
    if let Some(old) = entries.get(&index) {
        return if old.bytes == entry.bytes {
            Ok(())
        } else {
            Err(invalid())
        };
    }
    if ids
        .insert(entry.operation.operation_id, entry.hash)
        .is_some()
    {
        return Err(invalid());
    }
    *dependencies = dependencies
        .checked_add(entry.operation.causal_frontier.len())
        .ok_or(VaultError::BudgetExceeded)?;
    if *dependencies > budget.max_dependencies {
        return Err(VaultError::BudgetExceeded);
    }
    entries.insert(index, entry);
    Ok(())
}
