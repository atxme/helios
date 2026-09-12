//! The wire, and only the wire.
//!
//! Framing is one JSON object per line, as protocol 1 had it — a newline is a
//! delimiter no JSON value can contain, and the alternative, a length prefix,
//! buys nothing here and loses the ability to read a capture by eye.
//!
//! What changed is that the ceiling is no longer one number. A hello is a
//! token, a command is a locator, and a status may carry a campaign manifest
//! naming every target of a fleet rotation: three sizes two orders of
//! magnitude apart, and a single ceiling either refused the largest or let the
//! unauthenticated smallest grow to match it. Each direction therefore reads
//! and writes against the ceiling of what it is actually carrying
//! ([`aether::certificates::operator_session::limits`]).

use std::io::{BufRead, Write};

use aether::certificates::operator_session::{
    limits, OperatorCommand, OperatorHello, OperatorStatus,
};

#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("canal opérateur : {0}")]
    Io(#[from] std::io::Error),
    #[error("message opérateur illisible : {0}")]
    Malformed(String),
    #[error("message opérateur de {size} octets, au-delà du plafond de {ceiling}")]
    TooLarge { size: usize, ceiling: usize },
    #[error("le canal opérateur s'est fermé au milieu d'un message")]
    Truncated,
}

/// Writes one framed value, refusing anything over `ceiling`.
///
/// The check is on the encoded bytes rather than on the value: a manifest that
/// grew past what the reader will accept must fail here, on the side that can
/// still say which message it was, and not as a truncated read on the other.
pub fn write_frame<W: Write, T: serde::Serialize>(
    writer: &mut W,
    value: &T,
    ceiling: usize,
) -> Result<(), WireError> {
    let mut bytes = serde_json::to_vec(value).map_err(|e| WireError::Malformed(e.to_string()))?;
    if bytes.len() > ceiling {
        return Err(WireError::TooLarge {
            size: bytes.len(),
            ceiling,
        });
    }
    bytes.push(b'\n');
    writer.write_all(&bytes)?;
    writer.flush()?;
    Ok(())
}

/// Reads one framed value, refusing anything over `ceiling`.
///
/// `Ok(None)` is a clean close before any byte of a message. A close *inside*
/// one is [`WireError::Truncated`] and never an empty read: the difference is
/// between a peer that finished and a peer that died, and treating the second
/// as the first is how a half-run ceremony looks like a completed one.
pub fn read_frame<R: BufRead, T: serde::de::DeserializeOwned>(
    reader: &mut R,
    ceiling: usize,
) -> Result<Option<T>, WireError> {
    let mut bytes = Vec::new();
    // One byte past the ceiling, so a frame exactly at it is accepted and the
    // first byte over it is refused without buffering the rest.
    // Reborrowed and named: `take` is defined on both `Read` and `Iterator`,
    // and letting inference pick would move the reader out from under the
    // caller.
    let mut limited: std::io::Take<&mut R> = std::io::Read::take(&mut *reader, ceiling as u64 + 1);
    let read = limited.read_until(b'\n', &mut bytes)?;
    if read == 0 {
        return Ok(None);
    }
    match bytes.last() {
        Some(b'\n') => {
            bytes.pop();
        }
        // No delimiter and we stopped: either the peer went away mid-message,
        // or it is still sending one that is already too long. Both are fatal,
        // and the ceiling is the more useful of the two to name.
        _ if bytes.len() > ceiling => {
            return Err(WireError::TooLarge {
                size: bytes.len(),
                ceiling,
            })
        }
        _ => return Err(WireError::Truncated),
    }
    if bytes.len() > ceiling {
        return Err(WireError::TooLarge {
            size: bytes.len(),
            ceiling,
        });
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|e| WireError::Malformed(e.to_string()))
}

pub fn write_hello<W: Write>(writer: &mut W, hello: &OperatorHello) -> Result<(), WireError> {
    write_frame(writer, hello, limits::HELLO_BYTES)
}

pub fn write_status<W: Write>(writer: &mut W, status: &OperatorStatus) -> Result<(), WireError> {
    write_frame(writer, status, limits::STATUS_BYTES)
}

pub fn read_command<R: BufRead>(reader: &mut R) -> Result<Option<OperatorCommand>, WireError> {
    read_frame(reader, limits::COMMAND_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::certificates::encoding::Id16;
    use aether::certificates::operator_session::{
        GestureState, KeyPurpose, OperationKind, OperatorCommand, RemoteState, StepCommand,
        PROTOCOL_VERSION,
    };

    fn session() -> Id16 {
        Id16::new([5; 16]).expect("id")
    }

    fn status() -> OperatorStatus {
        OperatorStatus::new(
            session(),
            1,
            OperationKind::RecoverIdentity,
            RemoteState::AwaitingOperator,
            GestureState::AwaitingKey {
                index: 1,
                of: 1,
                purpose: KeyPurpose::OpenVault,
            },
        )
    }

    #[test]
    fn a_frame_survives_the_round_trip() {
        let mut buffer = Vec::new();
        write_status(&mut buffer, &status()).expect("written");
        let mut reader = std::io::BufReader::new(buffer.as_slice());
        let read: OperatorStatus = read_frame(&mut reader, limits::STATUS_BYTES)
            .expect("read")
            .expect("present");
        assert_eq!(read, status());
    }

    #[test]
    fn a_hello_carries_the_version_it_speaks() {
        let hello = OperatorHello {
            protocol_version: PROTOCOL_VERSION,
            session_id: session(),
            token: "t".repeat(64),
        };
        let mut buffer = Vec::new();
        write_hello(&mut buffer, &hello).expect("written");
        let mut reader = std::io::BufReader::new(buffer.as_slice());
        let read: OperatorHello = read_frame(&mut reader, limits::HELLO_BYTES)
            .expect("read")
            .expect("present");
        assert_eq!(read, hello);
    }

    #[test]
    fn a_clean_close_is_not_an_error() {
        let mut reader = std::io::BufReader::new(&b""[..]);
        let read: Option<OperatorCommand> = read_command(&mut reader).expect("clean");
        assert!(read.is_none());
    }

    /// The distinction the caller cannot make for itself: a peer that finished
    /// and a peer that died look the same at the socket, and only the missing
    /// delimiter tells them apart.
    #[test]
    fn a_close_inside_a_message_is_not_a_clean_close() {
        let mut reader = std::io::BufReader::new(&br#"{"command":"cancel""#[..]);
        assert!(matches!(
            read_command(&mut reader),
            Err(WireError::Truncated)
        ));
    }

    /// The unauthenticated frame must not be able to grow to the size of the
    /// authenticated one just by holding the socket open.
    #[test]
    fn a_flood_is_refused_at_the_ceiling_of_what_it_claims_to_be() {
        let flood = vec![b'x'; limits::COMMAND_BYTES * 2];
        let mut reader = std::io::BufReader::new(flood.as_slice());
        assert!(matches!(
            read_command(&mut reader),
            Err(WireError::TooLarge { .. })
        ));
    }

    /// A ceiling on the way out too: the side that can still name the message
    /// is the one that must refuse it.
    #[test]
    fn an_oversized_write_is_refused_before_it_reaches_the_socket() {
        let hello = OperatorHello {
            protocol_version: PROTOCOL_VERSION,
            session_id: session(),
            token: "t".repeat(limits::HELLO_BYTES * 2),
        };
        let mut buffer = Vec::new();
        assert!(matches!(
            write_hello(&mut buffer, &hello),
            Err(WireError::TooLarge { .. })
        ));
        assert!(buffer.is_empty(), "nothing partial reaches the peer");
    }

    #[test]
    fn a_command_that_is_not_one_is_refused_rather_than_defaulted() {
        let mut reader = std::io::BufReader::new(&b"{\"command\":\"exec\"}\n"[..]);
        assert!(matches!(
            read_command(&mut reader),
            Err(WireError::Malformed(_))
        ));
    }

    #[test]
    fn commands_are_read_in_order_from_one_stream() {
        let mut buffer = Vec::new();
        write_frame(
            &mut buffer,
            &OperatorCommand::Continue(StepCommand { revision: 1 }),
            limits::COMMAND_BYTES,
        )
        .expect("first");
        write_frame(
            &mut buffer,
            &OperatorCommand::Cancel(StepCommand { revision: 2 }),
            limits::COMMAND_BYTES,
        )
        .expect("second");
        let mut reader = std::io::BufReader::new(buffer.as_slice());
        assert_eq!(
            read_command(&mut reader).expect("one"),
            Some(OperatorCommand::Continue(StepCommand { revision: 1 }))
        );
        assert_eq!(
            read_command(&mut reader).expect("two"),
            Some(OperatorCommand::Cancel(StepCommand { revision: 2 }))
        );
        assert_eq!(read_command(&mut reader).expect("end"), None);
    }
}
