use aether::key_negotiation::{
    AuthenticatedKeyNegotiationCommit, AuthenticatedKeyNegotiationConfirmation,
    AuthenticatedKeyNegotiationRequest, AuthenticatedKeyNegotiationResponse,
    KeyNegotiationChallenge, MAX_KEY_NEGOTIATION_MESSAGE_BYTES,
};
use quinn::{RecvStream, SendStream};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::error::{PublicError, TransportError};

/// What a client sends.
///
/// Tagged, and the tag set is now exactly one transaction: challenge,
/// request, confirmation. The v5 `release` used to be the port's second entry
/// point; it moved into the WireGuard tunnel (spec §7.5), so the historic tag
/// no longer decodes and the frame is refused as a protocol error before any
/// handler runs — which is what a withdrawn message should look like on the
/// wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ClientMessage {
    ChallengeRequest {
        protocol_version: u16,
    },
    Request {
        request: Box<AuthenticatedKeyNegotiationRequest>,
    },
    Confirmation {
        confirmation: AuthenticatedKeyNegotiationConfirmation,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ServerMessage {
    Challenge {
        challenge: KeyNegotiationChallenge,
    },
    Response {
        response: Box<AuthenticatedKeyNegotiationResponse>,
    },
    Committed {
        commit: AuthenticatedKeyNegotiationCommit,
    },
    Error {
        error: PublicError,
    },
}
pub(crate) async fn write_frame<T: Serialize>(
    send: &mut SendStream,
    message: &T,
) -> Result<(), TransportError> {
    let bytes =
        serde_json::to_vec(message).map_err(|error| TransportError::Protocol(error.to_string()))?;
    if bytes.len() > MAX_KEY_NEGOTIATION_MESSAGE_BYTES {
        return Err(TransportError::MessageTooLarge);
    }
    send.write_all(&(bytes.len() as u32).to_be_bytes())
        .await
        .map_err(TransportError::Write)?;
    send.write_all(&bytes)
        .await
        .map_err(TransportError::Write)?;
    // Frame sizes are the practical half of an MTU problem: the PQ material is
    // what makes these messages tens of datagrams long, and a run that stops
    // after the first frame is a path that will not carry the second.
    tracing::info!(
        message = short_type_name::<T>(),
        bytes = bytes.len(),
        "quic: frame sent"
    );
    Ok(())
}

/// Message type without its module path, for a log line.
fn short_type_name<T: ?Sized>() -> &'static str {
    let full = std::any::type_name::<T>();
    full.rsplit("::").next().unwrap_or(full)
}

pub(crate) async fn read_frame<T: DeserializeOwned>(
    recv: &mut RecvStream,
) -> Result<T, TransportError> {
    let mut length = [0u8; 4];
    recv.read_exact(&mut length)
        .await
        .map_err(TransportError::Read)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_KEY_NEGOTIATION_MESSAGE_BYTES {
        return Err(TransportError::MessageTooLarge);
    }
    let mut bytes = vec![0u8; length];
    recv.read_exact(&mut bytes)
        .await
        .map_err(TransportError::Read)?;
    tracing::info!(
        message = short_type_name::<T>(),
        bytes = length,
        "quic: frame received"
    );
    serde_json::from_slice(&bytes).map_err(|error| TransportError::Protocol(error.to_string()))
}
