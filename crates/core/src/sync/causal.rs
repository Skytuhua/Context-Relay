use std::ops::RangeInclusive;

use context_relay_protocol::{DeviceId, SyncOperationV1};

use crate::vault::StoredDeviceHead;

use super::SyncError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CausalOrder {
    Before,
    Equal,
    After,
    Concurrent,
}

pub fn compare_operations(left: &SyncOperationV1, right: &SyncOperationV1) -> CausalOrder {
    if left.device_id == right.device_id {
        return left.device_sequence.cmp(&right.device_sequence).into();
    }

    let left_knows_right = known_sequence(left, right.device_id) >= right.device_sequence;
    let right_knows_left = known_sequence(right, left.device_id) >= left.device_sequence;
    match (left_knows_right, right_knows_left) {
        (true, false) => CausalOrder::After,
        (false, true) => CausalOrder::Before,
        (true, true) => CausalOrder::Equal,
        (false, false) => CausalOrder::Concurrent,
    }
}

pub fn missing_range(
    known: Option<StoredDeviceHead>,
    incoming: &SyncOperationV1,
) -> Result<Option<RangeInclusive<u64>>, SyncError> {
    if incoming.device_sequence == 0 {
        return Err(SyncError::InvalidChain);
    }
    let expected = match known {
        Some(head) => head
            .sequence
            .checked_add(1)
            .ok_or(SyncError::SequenceExhausted)?,
        None => 1,
    };
    if incoming.device_sequence < expected {
        return Err(SyncError::SequenceConflict);
    }
    if incoming.device_sequence == expected {
        return Ok(None);
    }
    let end = incoming
        .device_sequence
        .checked_sub(1)
        .ok_or(SyncError::InvalidChain)?;
    Ok(Some(expected..=end))
}

fn known_sequence(operation: &SyncOperationV1, device: DeviceId) -> u64 {
    operation
        .causal_frontier
        .iter()
        .filter(|entry| entry.device_id == device)
        .map(|entry| entry.sequence)
        .max()
        .unwrap_or(0)
}

impl From<std::cmp::Ordering> for CausalOrder {
    fn from(value: std::cmp::Ordering) -> Self {
        match value {
            std::cmp::Ordering::Less => Self::Before,
            std::cmp::Ordering::Equal => Self::Equal,
            std::cmp::Ordering::Greater => Self::After,
        }
    }
}
