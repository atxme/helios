use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

use aether::key_negotiation::{
    AuthenticatedKeyNegotiationCommit, AuthenticatedKeyNegotiationConfirmation,
    AuthenticatedKeyNegotiationRequest, KeyNegotiationChallenge, KEY_NEGOTIATION_VERSION,
    SERVER_CHALLENGE_LEN,
};
use quinn::{Connection, Endpoint, RecvStream, SendStream};

use crate::{
    endpoint::{CHALLENGE_TIMEOUT, CONNECT_TIMEOUT, RESPONSE_TIMEOUT},
    framing::{read_frame, write_frame, ClientMessage, ServerMessage},
    identity::peer_certificate_sha256,
    TransportError,
};

/// Active client session. Confirmation consumes it to prevent duplicate commit.
pub struct ClientSession {
    _endpoint: Endpoint,
    connection: Connection,
    send: SendStream,
    recv: RecvStream,
    transaction_id: [u8; 16],
    server_challenge: [u8; SERVER_CHALLENGE_LEN],
}

impl ClientSession {
    /// Sends the confirmation and reads the commit, then hangs up.
    pub async fn confirm(
        mut self,
        confirmation: AuthenticatedKeyNegotiationConfirmation,
    ) -> Result<AuthenticatedKeyNegotiationCommit, TransportError> {
        if confirmation.confirmation.protocol_version != KEY_NEGOTIATION_VERSION
            || confirmation.confirmation.transaction_id != self.transaction_id
            || confirmation.confirmation.server_challenge != self.server_challenge
        {
            return Err(TransportError::Protocol(
                "client confirmation does not match the active transaction".into(),
            ));
        }
        write_frame(
            &mut self.send,
            &ClientMessage::Confirmation { confirmation },
        )
        .await?;
        self.send.finish().map_err(TransportError::ClosedStream)?;
        let committed = tokio::time::timeout(
            Duration::from_secs(5),
            read_frame::<ServerMessage>(&mut self.recv),
        )
        .await
        .map_err(|_| TransportError::CommitTimeout)??;
        let commit = match committed {
            ServerMessage::Committed { commit }
                if commit.transaction_id == self.transaction_id
                    && commit.server_challenge == self.server_challenge =>
            {
                commit
            }
            ServerMessage::Error { error } => return Err(TransportError::Rejected(error)),
            _ => {
                return Err(TransportError::Protocol(
                    "server returned an invalid commit acknowledgment".into(),
                ))
            }
        };
        self.connection.close(0u32.into(), b"negotiation committed");
        Ok(commit)
    }
}

async fn open_with_challenge(
    endpoint: &Endpoint,
    remote: SocketAddr,
    server_name: &str,
) -> Result<(Connection, SendStream, RecvStream, KeyNegotiationChallenge), TransportError> {
    let started = Instant::now();
    tracing::info!(
        %remote,
        %server_name,
        local = ?endpoint.local_addr().ok(),
        timeout_s = CONNECT_TIMEOUT.as_secs(),
        "quic: opening the key-negotiation connection"
    );
    let connecting = endpoint
        .connect(remote, server_name)
        .map_err(TransportError::Connect)?;
    let connection = match tokio::time::timeout(CONNECT_TIMEOUT, connecting).await {
        Err(_) => {
            tracing::warn!(
                %remote,
                %server_name,
                udp_port = remote.port(),
                timeout_s = CONNECT_TIMEOUT.as_secs(),
                "quic: no handshake answer — unreachable port, or this UDP port not forwarded to the gateway"
            );
            return Err(TransportError::ConnectTimeout(
                remote,
                CONNECT_TIMEOUT.as_secs(),
            ));
        }
        Ok(Err(error)) => {
            tracing::warn!(
                %remote,
                %server_name,
                elapsed_ms = started.elapsed().as_millis(),
                error = %error,
                detail = ?error,
                "quic: handshake refused"
            );
            return Err(TransportError::Connection(error));
        }
        Ok(Ok(connection)) => connection,
    };
    tracing::info!(
        %remote,
        %server_name,
        elapsed_ms = started.elapsed().as_millis(),
        rtt_ms = connection.rtt().as_millis(),
        gateway_certificate_sha256 = %peer_certificate_sha256(&connection)
            .unwrap_or_else(|_| "absente".into()),
        "quic: handshake complete, gateway certificate accepted"
    );

    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(TransportError::Connection)?;
    write_frame(
        &mut send,
        &ClientMessage::ChallengeRequest {
            protocol_version: KEY_NEGOTIATION_VERSION,
        },
    )
    .await?;
    let challenge =
        match tokio::time::timeout(CHALLENGE_TIMEOUT, read_frame::<ServerMessage>(&mut recv))
            .await
            .map_err(|_| TransportError::ResponseTimeout(CHALLENGE_TIMEOUT.as_secs()))??
        {
            ServerMessage::Challenge { challenge } => challenge,
            ServerMessage::Error { error } => return Err(TransportError::Rejected(error)),
            _ => {
                return Err(TransportError::Protocol(
                    "gateway answered a challenge request with something else".into(),
                ))
            }
        };
    Ok((connection, send, recv, challenge))
}

/// Asks the gateway for a challenge and checks the identity it announces.
pub async fn request_challenge(
    endpoint: &Endpoint,
    remote: SocketAddr,
    server_name: &str,
    expected_gateway_wg_public_key: &str,
) -> Result<PendingChallenge, TransportError> {
    let (connection, send, recv, challenge) =
        open_with_challenge(endpoint, remote, server_name).await?;
    challenge
        .validate_against(expected_gateway_wg_public_key, server_name)
        .map_err(|error| {
            tracing::warn!(
                %remote,
                announced_wg_public_key = %challenge.gateway_wg_public_key,
                announced_server_name = %challenge.server_name,
                expected_wg_public_key = %expected_gateway_wg_public_key,
                expected_server_name = %server_name,
                "quic: the gateway announces an identity the profile does not pin"
            );
            TransportError::Protocol(error.to_string())
        })?;
    Ok(PendingChallenge {
        connection,
        send,
        recv,
        challenge,
    })
}

/// A challenge in hand, on a connection ready to carry one transaction.
pub struct PendingChallenge {
    pub(crate) connection: Connection,
    pub(crate) send: SendStream,
    pub(crate) recv: RecvStream,
    pub(crate) challenge: KeyNegotiationChallenge,
}

impl PendingChallenge {
    pub fn server_challenge(&self) -> [u8; SERVER_CHALLENGE_LEN] {
        self.challenge.server_challenge
    }
}

/// Sends the signed request on the connection that issued its challenge.
pub async fn negotiate(
    endpoint: &Endpoint,
    pending: PendingChallenge,
    request: &AuthenticatedKeyNegotiationRequest,
) -> Result<
    (
        aether::key_negotiation::AuthenticatedKeyNegotiationResponse,
        ClientSession,
    ),
    TransportError,
> {
    request
        .request
        .validate()
        .map_err(|error| TransportError::Protocol(error.to_string()))?;
    if request.request.server_challenge != pending.challenge.server_challenge {
        return Err(TransportError::Protocol(
            "request does not carry the challenge issued on this connection".into(),
        ));
    }
    let PendingChallenge {
        connection,
        mut send,
        mut recv,
        challenge,
    } = pending;

    write_frame(
        &mut send,
        &ClientMessage::Request {
            request: Box::new(request.clone()),
        },
    )
    .await?;
    let answer = match tokio::time::timeout(
        RESPONSE_TIMEOUT,
        read_frame::<ServerMessage>(&mut recv),
    )
    .await
    {
        Err(_) => {
            tracing::warn!(
                timeout_s = RESPONSE_TIMEOUT.as_secs(),
                rtt_ms = connection.rtt().as_millis(),
                "quic: connection established but no negotiation answer"
            );
            return Err(TransportError::ResponseTimeout(RESPONSE_TIMEOUT.as_secs()));
        }
        Ok(answer) => answer?,
    };
    match answer {
        ServerMessage::Response { response } => Ok((
            *response,
            ClientSession {
                _endpoint: endpoint.clone(),
                connection,
                send,
                recv,
                transaction_id: request.request.transaction_id,
                server_challenge: challenge.server_challenge,
            },
        )),
        ServerMessage::Error { error } => Err(TransportError::Rejected(error)),
        _ => Err(TransportError::Protocol(
            "server answered a negotiation request out of order".into(),
        )),
    }
}
