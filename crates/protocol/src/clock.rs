use crate::{ClockError, DeviceId};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

pub const DECIMAL_U64_SCHEMA_PATTERN: &str = "^(?:0|[1-9][0-9]{0,18}|1[0-7][0-9]{18}|18[0-3][0-9]{17}|184[0-3][0-9]{16}|1844[0-5][0-9]{15}|18446[0-6][0-9]{14}|184467[0-3][0-9]{13}|1844674[0-3][0-9]{12}|184467440[0-6][0-9]{10}|1844674407[0-2][0-9]{9}|18446744073[0-6][0-9]{8}|1844674407370[0-8][0-9]{6}|18446744073709[0-4][0-9]{5}|184467440737095[0-4][0-9]{4}|18446744073709550[0-9]{3}|18446744073709551[0-5][0-9]{2}|1844674407370955160[0-9]|1844674407370955161[0-5])$";

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
