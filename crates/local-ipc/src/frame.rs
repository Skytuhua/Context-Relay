use std::{fmt, ops::Deref};

use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::{Zeroize, Zeroizing};

use crate::{IpcError, MAX_IPC_FRAME_BYTES};

pub(crate) struct ZeroizingJsonFrame(Zeroizing<Vec<u8>>);

impl ZeroizingJsonFrame {
    pub(crate) fn from_frame(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

impl Deref for ZeroizingJsonFrame {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

impl Zeroize for ZeroizingJsonFrame {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for ZeroizingJsonFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ZeroizingJsonFrame([REDACTED])")
    }
}

pub(crate) fn encode_json_frame<T: Serialize>(value: &T) -> Result<ZeroizingJsonFrame, IpcError> {
    let mut payload = Zeroizing::new(Vec::new());
    serde_json::to_writer(&mut *payload, value).map_err(|_| IpcError::InvalidFrame)?;
    Ok(ZeroizingJsonFrame(payload))
}

pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>, IpcError> {
    let mut prefix = [0_u8; 4];
    reader
        .read_exact(&mut prefix)
        .await
        .map_err(|_| IpcError::Io)?;

    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 {
        return Err(IpcError::InvalidFrame);
    }
    if length > MAX_IPC_FRAME_BYTES {
        return Err(IpcError::FrameTooLarge);
    }

    let mut payload = vec![0_u8; length];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|_| IpcError::Io)?;
    Ok(payload)
}

pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> Result<(), IpcError> {
    if payload.is_empty() {
        return Err(IpcError::InvalidFrame);
    }
    if payload.len() > MAX_IPC_FRAME_BYTES {
        return Err(IpcError::FrameTooLarge);
    }

    writer
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await
        .map_err(|_| IpcError::Io)?;
    writer.write_all(payload).await.map_err(|_| IpcError::Io)
}

pub async fn read_json<R, T>(reader: &mut R) -> Result<T, IpcError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let payload = ZeroizingJsonFrame::from_frame(read_frame(reader).await?);
    serde_json::from_slice(&payload).map_err(|_| IpcError::InvalidFrame)
}

pub async fn write_json<W, T>(writer: &mut W, value: &T) -> Result<(), IpcError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let payload = encode_json_frame(value)?;
    write_frame(writer, &payload).await
}

#[cfg(test)]
mod tests {
    use serde::Serialize;
    use zeroize::Zeroize;

    use super::encode_json_frame;

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct SensitiveRecoveryFrame<'a> {
        recovery_phrase_words: &'a str,
        confirmation_word: &'a str,
    }

    #[test]
    fn recovery_json_frames_are_live_only_inside_a_redacted_zeroizing_owner() {
        let phrase =
            "abandon ability able about above absent absorb abstract absurd abuse access accident";
        let confirmation = "accident";
        let mut frame = encode_json_frame(&SensitiveRecoveryFrame {
            recovery_phrase_words: phrase,
            confirmation_word: confirmation,
        })
        .unwrap();

        assert!(
            frame
                .windows(phrase.len())
                .any(|window| window == phrase.as_bytes())
        );
        assert!(
            frame
                .windows(confirmation.len())
                .any(|window| window == confirmation.as_bytes())
        );
        assert!(!format!("{frame:?}").contains(phrase));
        assert!(!format!("{frame:?}").contains(confirmation));

        frame.zeroize();
        assert!(frame.is_empty());
    }
}
