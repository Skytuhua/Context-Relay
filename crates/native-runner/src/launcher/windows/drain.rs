use std::io::Read;

use super::LaunchError;

pub fn drain_bounded<R: Read>(reader: R, limit: usize) -> Result<Vec<u8>, LaunchError> {
    let capture = limit.checked_add(1).ok_or(LaunchError::PipeLimitExceeded)?;
    let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
    reader
        .take(capture as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| LaunchError::PipeIo)?;
    if bytes.len() > limit {
        return Err(LaunchError::PipeLimitExceeded);
    }
    Ok(bytes)
}
