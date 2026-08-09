use context_relay_protocol::Sha256Digest;
use sha2::{Digest as _, Sha256};

use super::NativeMemoryError;

pub const MANAGED_START: &str = "<!-- context-relay:start -->";
pub const MANAGED_END: &str = "<!-- context-relay:end -->";
const MANAGED_PREFIX: &str = "<!-- context-relay:";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedMarkdown {
    pub managed_body: Option<Vec<u8>>,
    pub unmanaged_body: Vec<u8>,
    pub full_digest: Sha256Digest,
    pub unmanaged_digest: Sha256Digest,
}

pub fn extract_managed_markdown(bytes: &[u8]) -> Result<ManagedMarkdown, NativeMemoryError> {
    let text = std::str::from_utf8(bytes).map_err(|_| NativeMemoryError::InvalidUtf8)?;
    let starts = text.match_indices(MANAGED_START).collect::<Vec<_>>();
    let ends = text.match_indices(MANAGED_END).collect::<Vec<_>>();
    if text.matches(MANAGED_PREFIX).count() != starts.len() + ends.len() {
        return Err(NativeMemoryError::MalformedManagedFence);
    }

    let (managed_body, unmanaged_body) = match (starts.as_slice(), ends.as_slice()) {
        ([], []) => (None, bytes.to_vec()),
        ([(start, _)], [(end, _)]) if start < end => {
            let body_start = marker_line_end(bytes, *start, MANAGED_START.len(), false)?;
            let fence_end = marker_line_end(bytes, *end, MANAGED_END.len(), true)?;
            if !is_line_start(bytes, *start) || !is_line_start(bytes, *end) {
                return Err(NativeMemoryError::MalformedManagedFence);
            }

            let mut unmanaged = Vec::with_capacity(bytes.len() - (fence_end - start));
            unmanaged.extend_from_slice(&bytes[..*start]);
            unmanaged.extend_from_slice(&bytes[fence_end..]);
            (Some(bytes[body_start..*end].to_vec()), unmanaged)
        }
        _ => return Err(NativeMemoryError::MalformedManagedFence),
    };

    Ok(ManagedMarkdown {
        managed_body,
        full_digest: digest(bytes),
        unmanaged_digest: digest(normalize_final_newline(&unmanaged_body)),
        unmanaged_body,
    })
}

fn is_line_start(bytes: &[u8], index: usize) -> bool {
    index == 0 || bytes[index - 1] == b'\n'
}

fn marker_line_end(
    bytes: &[u8],
    marker_start: usize,
    marker_len: usize,
    allow_eof: bool,
) -> Result<usize, NativeMemoryError> {
    let marker_end = marker_start + marker_len;
    match bytes.get(marker_end..) {
        Some(rest) if rest.starts_with(b"\r\n") => Ok(marker_end + 2),
        Some(rest) if rest.starts_with(b"\n") => Ok(marker_end + 1),
        Some([]) if allow_eof => Ok(marker_end),
        _ => Err(NativeMemoryError::MalformedManagedFence),
    }
}

fn normalize_final_newline(bytes: &[u8]) -> &[u8] {
    if let Some(without_lf) = bytes.strip_suffix(b"\n") {
        without_lf.strip_suffix(b"\r").unwrap_or(without_lf)
    } else {
        bytes
    }
}

pub(crate) fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest(Sha256::digest(bytes).into())
}
