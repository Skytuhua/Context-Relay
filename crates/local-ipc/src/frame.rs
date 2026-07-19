use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{IpcError, MAX_IPC_FRAME_BYTES};

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
    serde_json::from_slice(&read_frame(reader).await?).map_err(|_| IpcError::InvalidFrame)
}

pub async fn write_json<W, T>(writer: &mut W, value: &T) -> Result<(), IpcError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let payload = serde_json::to_vec(value).map_err(|_| IpcError::InvalidFrame)?;
    write_frame(writer, &payload).await
}
