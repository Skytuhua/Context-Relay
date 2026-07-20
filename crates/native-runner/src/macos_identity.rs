use std::fmt;

const DOMAIN: &[u8] = b"context-relay/macos-root/v2\0";
const PAYLOAD_BYTES: usize = 36;
const FILE_TYPE_MASK: u32 = 0o170000;
const DIRECTORY_TYPE: u32 = 0o040000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MacRootIdentityError;

impl fmt::Display for MacRootIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid macOS root identity")
    }
}

impl std::error::Error for MacRootIdentityError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacRootIdentity {
    device: u64,
    inode: u64,
    generation: u32,
    birthtime_seconds: i64,
    birthtime_nanoseconds: u32,
    file_type: u32,
}

impl MacRootIdentity {
    pub fn new(
        device: u64,
        inode: u64,
        generation: u32,
        birthtime_seconds: i64,
        birthtime_nanoseconds: u32,
        mode: u32,
    ) -> Result<Self, MacRootIdentityError> {
        if device == 0
            || inode == 0
            || birthtime_nanoseconds >= 1_000_000_000
            || mode & FILE_TYPE_MASK != DIRECTORY_TYPE
        {
            return Err(MacRootIdentityError);
        }
        Ok(Self {
            device,
            inode,
            generation,
            birthtime_seconds,
            birthtime_nanoseconds,
            file_type: mode & FILE_TYPE_MASK,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(DOMAIN.len() + PAYLOAD_BYTES);
        bytes.extend_from_slice(DOMAIN);
        bytes.extend_from_slice(&self.device.to_be_bytes());
        bytes.extend_from_slice(&self.inode.to_be_bytes());
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.extend_from_slice(&self.birthtime_seconds.to_be_bytes());
        bytes.extend_from_slice(&self.birthtime_nanoseconds.to_be_bytes());
        bytes.extend_from_slice(&self.file_type.to_be_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, MacRootIdentityError> {
        let payload = bytes
            .strip_prefix(DOMAIN)
            .filter(|payload| payload.len() == PAYLOAD_BYTES)
            .ok_or(MacRootIdentityError)?;
        Self::new(
            u64::from_be_bytes(payload[0..8].try_into().unwrap()),
            u64::from_be_bytes(payload[8..16].try_into().unwrap()),
            u32::from_be_bytes(payload[16..20].try_into().unwrap()),
            i64::from_be_bytes(payload[20..28].try_into().unwrap()),
            u32::from_be_bytes(payload[28..32].try_into().unwrap()),
            u32::from_be_bytes(payload[32..36].try_into().unwrap()),
        )
    }
}
