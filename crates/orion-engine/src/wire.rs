//! Engine / UI channel frames: one JSON object per line, size-bounded.
//!
//! Same shape as `tools/helios-astra-helper/src/session.rs`, but async.
//! A line over its limit is refused without being read to the end.

use std::io;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::command::{EngineCommand, EngineReply};
use orion_core::events::ClientEvent;

/// Protocol version: a UI whose version differs is refused at `Hello`.
pub const PROTOCOL_VERSION: u16 = 1;

/// Maximum size of a frame, newline excluded.
pub mod limits {
    pub const HELLO_BYTES: usize = 1024;
    pub const REQUEST_BYTES: usize = 1024 * 1024;
    pub const REPLY_BYTES: usize = 1024 * 1024;
    pub const EVENT_BYTES: usize = 64 * 1024;
}

/// First frame from the UI: it presents the token the engine handed it.
#[derive(Serialize, Deserialize)]
pub struct Hello {
    pub protocol_version: u16,
    /// Secret: this type does not implement `Debug`, so it is never printed.
    pub token: String,
}

/// Frames sent by the UI.
#[derive(Serialize, Deserialize)]
#[serde(tag = "frame", rename_all = "snake_case")]
pub enum ClientFrame {
    Hello(Hello),
    /// Boxed: a profile draft makes the command far larger than a hello.
    Request {
        id: u64,
        command: Box<EngineCommand>,
    },
}

/// Frames sent by the engine: the reply to a request, or a pushed event.
#[derive(Serialize, Deserialize)]
#[serde(tag = "frame", rename_all = "snake_case")]
pub enum EngineFrame {
    /// Boxed: a configuration view makes a reply far larger than an event.
    Reply {
        id: u64,
        result: Result<Box<EngineReply>, String>,
    },
    Event(ClientEvent),
}

/// Channel failure. Any error closes the connection: there is no resuming
/// in the middle of a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// The frame exceeds the limit set by the caller.
    TooLarge { limit: usize },
    /// Line that is not a valid frame, or stream closed in the middle of a line.
    Malformed,
    /// I/O error, reduced to its kind.
    Io(io::ErrorKind),
}

impl From<io::Error> for WireError {
    fn from(error: io::Error) -> Self {
        WireError::Io(error.kind())
    }
}

/// Reads one frame. `Ok(None)` is a clean end of stream, before any byte.
pub async fn read_frame<R, T>(reader: &mut R, limit: usize) -> Result<Option<T>, WireError>
where
    R: AsyncBufRead + Unpin,
    T: DeserializeOwned,
{
    let mut line = Vec::new();
    // One byte more than the limit, newline included: a frame at the limit
    // passes, and the first byte beyond it is refused without being buffered.
    let mut window = AsyncReadExt::take(&mut *reader, limit as u64 + 1);
    let read = window.read_until(b'\n', &mut line).await?;
    if read == 0 {
        return Ok(None);
    }
    let terminated = line.last() == Some(&b'\n');
    if terminated {
        line.pop();
    }
    if line.len() > limit {
        return Err(WireError::TooLarge { limit });
    }
    if !terminated {
        return Err(WireError::Malformed);
    }
    serde_json::from_slice(&line)
        .map(Some)
        .map_err(|_| WireError::Malformed)
}

/// Writes one frame followed by a newline, refusing a frame over `limit`:
/// nothing is written in that case.
pub async fn write_frame<W, T>(writer: &mut W, frame: &T, limit: usize) -> Result<(), WireError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let mut bytes = serde_json::to_vec(frame).map_err(|_| WireError::Malformed)?;
    if bytes.len() > limit {
        return Err(WireError::TooLarge { limit });
    }
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests;
