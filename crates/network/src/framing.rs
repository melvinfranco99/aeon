use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::message::NetMessage;

/// Maximum accepted message size (16 MiB), to bound memory use against a
/// malicious or buggy peer sending a bogus huge length prefix.
const MAX_MESSAGE_BYTES: u32 = 16 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum FramingError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] Box<bincode::ErrorKind>),
    #[error("message of {0} bytes exceeds the maximum of {MAX_MESSAGE_BYTES}")]
    TooLarge(u32),
}

/// Writes a message as a 4-byte little-endian length prefix followed by its
/// bincode encoding.
pub async fn write_message<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    msg: &NetMessage,
) -> Result<(), FramingError> {
    let bytes = bincode::serialize(msg)?;
    let len = bytes.len() as u32;
    writer.write_all(&len.to_le_bytes()).await?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

/// Reads one length-prefixed message. Returns `Ok(None)` on clean EOF.
pub async fn read_message<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<Option<NetMessage>, FramingError> {
    let mut len_bytes = [0u8; 4];
    match reader.read_exact(&mut len_bytes).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_le_bytes(len_bytes);
    if len > MAX_MESSAGE_BYTES {
        return Err(FramingError::TooLarge(len));
    }
    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf).await?;
    let msg = bincode::deserialize(&buf)?;
    Ok(Some(msg))
}
