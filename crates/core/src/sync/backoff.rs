use std::{error::Error, fmt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackoffPolicy {
    pub base_ms: u64,
    pub cap_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidBackoffPolicy;

impl fmt::Display for InvalidBackoffPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("backoff durations must be nonzero")
    }
}

impl Error for InvalidBackoffPolicy {}

impl BackoffPolicy {
    pub const DEFAULT: Self = Self {
        base_ms: 1_000,
        cap_ms: 60_000,
    };

    pub const fn validate(&self) -> Result<(), InvalidBackoffPolicy> {
        if self.base_ms == 0 || self.cap_ms == 0 {
            Err(InvalidBackoffPolicy)
        } else {
            Ok(())
        }
    }

    pub fn next_delay(&self, attempt: u32, random_u64: u64) -> u64 {
        if self.validate().is_err() {
            return 0;
        }
        let exponential = if attempt >= u64::BITS {
            u64::MAX
        } else {
            self.base_ms.saturating_mul(1_u64 << attempt)
        };
        let bound = self.cap_ms.min(exponential);
        if bound == u64::MAX {
            random_u64
        } else {
            random_u64 % (bound + 1)
        }
    }
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}
