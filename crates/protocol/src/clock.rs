use crate::{ClockError, DeviceId};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

pub mod decimal_u64 {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};
    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let text = String::deserialize(deserializer)?;
        let value: u64 = text.parse().map_err(D::Error::custom)?;
        if value.to_string() != text {
            return Err(D::Error::custom("noncanonical decimal u64"));
        }
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct HybridLogicalClock {
    #[serde(with = "decimal_u64")]
    #[ts(type = "DecimalU64")]
    pub physical_ms: u64,
    pub logical: u32,
    pub node: DeviceId,
}

impl HybridLogicalClock {
    pub const fn new(physical_ms: u64, logical: u32, node: DeviceId) -> Self {
        Self {
            physical_ms,
            logical,
            node,
        }
    }
    pub fn tick(self, now_ms: u64) -> Result<Self, ClockError> {
        let physical_ms = self.physical_ms.max(now_ms);
        let logical = if physical_ms == self.physical_ms {
            self.logical
                .checked_add(1)
                .ok_or(ClockError::ClockExhausted)?
        } else {
            0
        };
        Ok(Self {
            physical_ms,
            logical,
            node: self.node,
        })
    }
    pub fn observe(self, remote: &Self, now_ms: u64) -> Result<Self, ClockError> {
        let physical_ms = now_ms.max(self.physical_ms).max(remote.physical_ms);
        let logical = if physical_ms == self.physical_ms && physical_ms == remote.physical_ms {
            self.logical.max(remote.logical).checked_add(1)
        } else if physical_ms == self.physical_ms {
            self.logical.checked_add(1)
        } else if physical_ms == remote.physical_ms {
            remote.logical.checked_add(1)
        } else {
            Some(0)
        }
        .ok_or(ClockError::ClockExhausted)?;
        Ok(Self {
            physical_ms,
            logical,
            node: self.node,
        })
    }
}
