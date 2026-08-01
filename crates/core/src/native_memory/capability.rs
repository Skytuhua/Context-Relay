use std::collections::BTreeSet;

use context_relay_protocol::{
    ClientError, ErrorCode, HarnessId, MAX_MARKDOWN_BYTES, NativePlatform, ScopeRef,
    WireNativeValue,
};

use crate::native_transaction::model::ApprovedMutation;

use super::{
    NativeMemoryDocumentKind, NativeMemoryLimits, NativeMemorySource, NativeMemorySourceId,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeMemoryCapabilities {
    pub disable: NativeMemoryDisable,
    pub sources: Vec<NativeMemorySource>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeMemoryDisable {
    Supported(Vec<ApprovedMutation>),
    WatchOnly,
    Unavailable,
}

pub trait NativeMemoryAdapter {
    fn native_memory_capabilities(&self) -> Result<NativeMemoryCapabilities, ClientError>;
}

impl NativeMemoryCapabilities {
    pub fn validate(&self) -> Result<(), ClientError> {
        if matches!(self.disable, NativeMemoryDisable::Unavailable) && !self.sources.is_empty() {
            return Err(invalid("Unavailable native memory cannot declare sources"));
        }
        let mut ids = BTreeSet::<NativeMemorySourceId>::new();
        let mut paths = BTreeSet::<(u8, Vec<u8>)>::new();
        for source in &self.sources {
            validate_source_descriptor(source)?;
            if !ids.insert(source.id)
                || !paths.insert((source.path.platform as u8, source.path.bytes.clone()))
            {
                return Err(invalid("Native memory source is repeated"));
            }
            reject_forbidden_source_path(&source.path)?;
        }
        Ok(())
    }
}

pub(crate) fn validate_source_descriptor(source: &NativeMemorySource) -> Result<(), ClientError> {
    source
        .validate()
        .map_err(|_| invalid("Native memory source is invalid"))?;
    reject_forbidden_source_path(&source.path)
}

pub(crate) fn source(
    harness: HarnessId,
    adapter_version: &str,
    scope: ScopeRef,
    document_kind: NativeMemoryDocumentKind,
    path: WireNativeValue,
) -> Result<NativeMemorySource, ClientError> {
    NativeMemorySource::new(
        harness,
        adapter_version,
        scope,
        document_kind,
        path,
        NativeMemoryLimits {
            max_bytes: MAX_MARKDOWN_BYTES,
            max_characters: MAX_MARKDOWN_BYTES,
        },
        true,
    )
    .map_err(|_| invalid("Native memory source is invalid"))
}

fn reject_forbidden_source_path(path: &WireNativeValue) -> Result<(), ClientError> {
    let authoritative = match path.platform {
        NativePlatform::Macos => std::str::from_utf8(&path.bytes)
            .map(str::to_owned)
            .map_err(|_| invalid("Native memory source path is not UTF-8"))?,
        NativePlatform::Windows => {
            if !path.bytes.len().is_multiple_of(2) {
                return Err(invalid("Native memory source path is invalid UTF-16"));
            }
            let units = path
                .bytes
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect::<Vec<_>>();
            String::from_utf16(&units)
                .map_err(|_| invalid("Native memory source path is invalid UTF-16"))?
        }
    };
    let normalized = authoritative.replace('\\', "/").to_ascii_lowercase();
    let components = normalized
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    if components.iter().any(|component| {
        *component == ".."
            || matches!(*component, "sessions" | "session" | "history")
            || component.contains("rollout")
            || component.contains("raw_memories")
    }) || components.last().is_some_and(|name| {
        matches!(
            name.rsplit_once('.').map(|(_, extension)| extension),
            Some("db" | "sqlite" | "sqlite3")
        )
    }) {
        return Err(invalid("Native memory source path is forbidden"));
    }
    Ok(())
}

fn invalid(message: &'static str) -> ClientError {
    ClientError {
        code: ErrorCode::InvalidRequest,
        message: message.to_owned(),
        field_path: None,
        retryable: false,
    }
}

#[cfg(test)]
mod tests {
    use context_relay_protocol::{NativePlatform, WireNativeValue};

    use super::reject_forbidden_source_path;

    #[test]
    fn forbidden_source_check_uses_authoritative_path_bytes_not_display_text() {
        let path = WireNativeValue {
            platform: NativePlatform::Macos,
            bytes: b"/tmp/sessions/session.md".to_vec(),
            display: Some("/tmp/MEMORY.md".to_owned()),
        };
        assert!(reject_forbidden_source_path(&path).is_err());
    }
}
