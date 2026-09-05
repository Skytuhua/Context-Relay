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
    let forbidden = match path.platform {
        NativePlatform::Macos => {
            let authoritative = std::str::from_utf8(&path.bytes)
                .map_err(|_| invalid("Native memory source path is not UTF-8"))?;
            let normalized = authoritative.replace('\\', "/").to_ascii_lowercase();
            let components = normalized
                .split('/')
                .filter(|component| !component.is_empty())
                .collect::<Vec<_>>();
            components.iter().any(|component| {
                *component == ".."
                    || matches!(*component, "sessions" | "session" | "history")
                    || component.contains("rollout")
                    || component.contains("raw_memories")
            }) || components.last().is_some_and(|name| {
                matches!(
                    name.rsplit_once('.').map(|(_, extension)| extension),
                    Some("db" | "sqlite" | "sqlite3")
                )
            })
        }
        NativePlatform::Windows => {
            if !path.bytes.len().is_multiple_of(2) {
                return Err(invalid("Native memory source path is invalid UTF-16"));
            }
            let units = path
                .bytes
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect::<Vec<_>>();
            windows_path_is_forbidden(&units)
        }
    };
    if forbidden {
        return Err(invalid("Native memory source path is forbidden"));
    }
    Ok(())
}

fn windows_path_is_forbidden(units: &[u16]) -> bool {
    let mut last = None;
    for component in units
        .split(|unit| *unit == u16::from(b'/') || *unit == u16::from(b'\\'))
        .filter(|component| !component.is_empty())
    {
        if utf16_ascii_eq(component, b"..")
            || utf16_ascii_eq(component, b"sessions")
            || utf16_ascii_eq(component, b"session")
            || utf16_ascii_eq(component, b"history")
            || utf16_ascii_contains(component, b"rollout")
            || utf16_ascii_contains(component, b"raw_memories")
        {
            return true;
        }
        last = Some(component);
    }
    last.and_then(|name| {
        name.iter()
            .rposition(|unit| *unit == b'.' as u16)
            .map(|dot| &name[dot + 1..])
    })
    .is_some_and(|extension| {
        utf16_ascii_eq(extension, b"db")
            || utf16_ascii_eq(extension, b"sqlite")
            || utf16_ascii_eq(extension, b"sqlite3")
    })
}

fn utf16_ascii_contains(units: &[u16], needle: &[u8]) -> bool {
    units
        .windows(needle.len())
        .any(|candidate| utf16_ascii_eq(candidate, needle))
}

fn utf16_ascii_eq(units: &[u16], expected: &[u8]) -> bool {
    units.len() == expected.len()
        && units.iter().zip(expected).all(|(unit, expected)| {
            u8::try_from(*unit).is_ok_and(|unit| unit.eq_ignore_ascii_case(expected))
        })
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
    use context_relay_protocol::{HarnessId, NativePlatform, ScopeRef, WireNativeValue};

    use super::{
        NativeMemoryCapabilities, NativeMemoryDisable, NativeMemoryDocumentKind,
        NativeMemoryLimits, NativeMemorySource, reject_forbidden_source_path,
    };

    fn windows_capabilities(units: &[u16], display: Option<&str>) -> NativeMemoryCapabilities {
        let source = NativeMemorySource::new(
            HarnessId::Codex,
            "0.144.1",
            ScopeRef::Global,
            NativeMemoryDocumentKind::Agent,
            WireNativeValue {
                platform: NativePlatform::Windows,
                bytes: units.iter().copied().flat_map(u16::to_le_bytes).collect(),
                display: display.map(str::to_owned),
            },
            NativeMemoryLimits {
                max_bytes: 32,
                max_characters: 32,
            },
            true,
        )
        .unwrap();
        NativeMemoryCapabilities {
            disable: NativeMemoryDisable::WatchOnly,
            sources: vec![source],
        }
    }

    #[test]
    fn forbidden_source_check_uses_authoritative_path_bytes_not_display_text() {
        let path = WireNativeValue {
            platform: NativePlatform::Macos,
            bytes: b"/tmp/sessions/session.md".to_vec(),
            display: Some("/tmp/MEMORY.md".to_owned()),
        };
        assert!(reject_forbidden_source_path(&path).is_err());
    }

    #[test]
    fn windows_capabilities_accept_an_opaque_wtf16_source_path() {
        let mut units = r"C:\workspace\".encode_utf16().collect::<Vec<_>>();
        units.extend([0xd800, b'.' as u16, b'm' as u16, b'd' as u16]);

        windows_capabilities(&units, None).validate().unwrap();
    }

    #[test]
    fn windows_capabilities_filter_authoritative_bytes_not_display_text() {
        let units = r"C:\workspace\MEMORY.md".encode_utf16().collect::<Vec<_>>();

        windows_capabilities(&units, Some(r"C:\sessions\history.sqlite"))
            .validate()
            .unwrap();
    }

    #[test]
    fn windows_capabilities_reject_every_forbidden_ascii_path_pattern() {
        for path in [
            r"C:\workspace\..\memory.md",
            r"C:/workspace/SESSIONS/memory.md",
            r"C:\workspace\Session\memory.md",
            r"C:\workspace\history\memory.md",
            r"C:\workspace\preROLLOUTpost.md",
            r"C:\workspace\RAW_MEMORIES.md",
            r"C:\workspace\memory.DB",
            r"C:\workspace\memory.Sqlite",
            r"C:\workspace\memory.SQLITE3",
        ] {
            let units = path.encode_utf16().collect::<Vec<_>>();
            assert!(
                windows_capabilities(&units, Some(r"C:\workspace\MEMORY.md"))
                    .validate()
                    .is_err(),
                "forbidden source path was accepted: {path}"
            );
        }
    }
}
