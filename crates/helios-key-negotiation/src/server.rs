use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use aether::key_negotiation::{
    commitments_match, derive_negotiated_psk, static_psk_commitment,
    AuthenticatedKeyNegotiationCommit, AuthenticatedKeyNegotiationConfirmation,
    AuthenticatedKeyNegotiationRequest, KeyNegotiationChallenge, KeyNegotiationRequest,
    KeyNegotiationResponse, ProtectionMode, KEY_NEGOTIATION_VERSION, SERVER_CHALLENGE_LEN,
};
use aether::pq::{Kem, MlKem1024Kem};
use aether::SecretString;
use async_trait::async_trait;
use quinn::{Connection, Endpoint, SendStream};

use crate::{
    framing::{read_frame, write_frame, ClientMessage, ServerMessage},
    identity::peer_certificate_sha256,
    rate_limit::{rate_bucket, RateLimiter},
    transaction::{Deadline, RollbackGuard},
    PublicError, TransportError, CHALLENGE_VALIDITY, MAX_ACTIVE_NEGOTIATIONS,
    MAX_CONNECTION_LIFETIME, MAX_HANDSHAKES_PER_SOURCE, MAX_NEGOTIATIONS_PER_IDENTITY,
};

/// Secret configuration prepared for the WireGuard peer.
#[derive(Debug)]
pub struct PreparedKeyMaterial {
    pub response: KeyNegotiationResponse,
    pub psk: Option<SecretString>,
}

/// Applies the mode selected by Orion and derives the candidate peer secret.
pub fn prepare_key_material(
    request: &KeyNegotiationRequest,
    gateway_wg_public_key: &str,
    gateway_nonce: [u8; 16],
    static_psk: Option<&str>,
    confirmation_timeout: Duration,
) -> Result<PreparedKeyMaterial, PublicError> {
    use base64::Engine as _;

    request.validate().map_err(|_| PublicError::Protocol)?;
    aether::wg::validate_key(gateway_wg_public_key).map_err(|_| PublicError::Protocol)?;
    let timeout_secs = u32::try_from(confirmation_timeout.as_secs())
        .ok()
        .filter(|seconds| *seconds > 0)
        .ok_or(PublicError::Protocol)?;

    let mut response = KeyNegotiationResponse {
        protocol_version: KEY_NEGOTIATION_VERSION,
        transaction_id: request.transaction_id,
        server_challenge: request.server_challenge,
        selected_mode: request.mode,
        gateway_wg_public_key: gateway_wg_public_key.to_string(),
        client_wg_public_key: request.client_wg_public_key.clone(),
        gateway_nonce,
        kem_ciphertext: None,
        confirmation_timeout_secs: timeout_secs,
        psk_lifetime_secs: match request.mode {
            ProtectionMode::StaticPsk => 0,
            _ => aether::key_negotiation::NEGOTIATED_PSK_LIFETIME_SECS,
        },
    };

    let psk = match request.mode {
        ProtectionMode::Classic => return Err(PublicError::Rejected),
        ProtectionMode::StaticPsk => {
            let configured = static_psk.ok_or(PublicError::Rejected)?;
            let presented = request
                .static_psk_commitment
                .as_deref()
                .ok_or(PublicError::Protocol)?;
            let expected = static_psk_commitment(
                configured,
                &request.transaction_id,
                &request.client_nonce,
                &request.server_challenge,
                &request.client_wg_public_key,
                gateway_wg_public_key,
            )
            .map_err(|_| PublicError::Rejected)?;
            if !commitments_match(&expected, presented) {
                return Err(PublicError::Rejected);
            }
            Some(SecretString::new(configured.to_string()))
        }
        ProtectionMode::MlKem => {
            let public_key = request
                .kem_public_key
                .as_deref()
                .ok_or(PublicError::Protocol)?;
            let (ciphertext, shared_secret) =
                MlKem1024Kem::encapsulate(public_key).map_err(|_| PublicError::Protocol)?;
            response.kem_ciphertext = Some(ciphertext);
            let psk = derive_negotiated_psk(&shared_secret, request, &response)
                .map_err(|_| PublicError::Protocol)?;
            Some(SecretString::new(
                base64::engine::general_purpose::STANDARD.encode(psk.as_slice()),
            ))
        }
    };

    Ok(PreparedKeyMaterial { response, psk })
}

/// Result of preparing a peer slot. Rollback remains possible until confirm.
pub struct PreparedNegotiation {
    pub response: aether::key_negotiation::AuthenticatedKeyNegotiationResponse,
    pub confirmation_timeout: Duration,
}

/// What the gateway announces in a challenge, before anyone is authenticated.
#[derive(Debug, Clone)]
pub struct GatewayIdentity {
    pub wg_public_key: String,
    pub server_name: String,
}

#[async_trait]
pub trait NegotiationHandler: Send + Sync + 'static {
    fn announced_identity(&self) -> GatewayIdentity;

    async fn resolve_admitted_peer(&self, certificate_sha256: &str) -> Option<String>;

    async fn prepare(
        &self,
        certificate_sha256: String,
        request: AuthenticatedKeyNegotiationRequest,
    ) -> Result<PreparedNegotiation, PublicError>;

    async fn confirm(
        &self,
        confirmation: AuthenticatedKeyNegotiationConfirmation,
    ) -> Result<AuthenticatedKeyNegotiationCommit, PublicError>;

    async fn rollback(&self, transaction_id: [u8; 16], client_wg_public_key: &str);
}

pub async fn serve(endpoint: Endpoint, handler: Arc<dyn NegotiationHandler>) {
    let capacity = Arc::new(tokio::sync::Semaphore::new(MAX_ACTIVE_NEGOTIATIONS));
    let limiter = Arc::new(std::sync::Mutex::new(RateLimiter::new(
        MAX_HANDSHAKES_PER_SOURCE,
    )));
    let per_identity = Arc::new(std::sync::Mutex::new(RateLimiter::new(
        MAX_NEGOTIATIONS_PER_IDENTITY,
    )));

    while let Some(incoming) = endpoint.accept().await {
        if !incoming.remote_address_validated() {
            let remote = incoming.remote_address();
            if incoming.retry().is_err() {
                tracing::info!(%remote, "quic: retry refused for an already-validated peer");
            }
            continue;
        }

        let source = incoming.remote_address().ip();
        let admitted = limiter
            .lock()
            .map(|mut limiter| limiter.admit(rate_bucket(source), Instant::now()))
            .unwrap_or(false);
        if !admitted {
            tracing::warn!(%source, "key-negotiation handshake rate exceeded for this address");
            incoming.refuse();
            continue;
        }

        let permit = match Arc::clone(&capacity).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                incoming.refuse();
                continue;
            }
        };
        let handler = Arc::clone(&handler);
        let per_identity = Arc::clone(&per_identity);
        tokio::spawn(async move {
            let remote = incoming.remote_address();
            let served = tokio::time::timeout(
                MAX_CONNECTION_LIFETIME,
                handle_connection(incoming, handler, permit, per_identity),
            )
            .await
            .unwrap_or_else(|_| Err(TransportError::Protocol(absolute_lifetime_reached())));
            if let Err(error) = served {
                tracing::warn!(
                    %remote,
                    error = %error,
                    detail = ?error,
                    "quic: key-negotiation connection rejected"
                );
            }
        });
    }
}

fn absolute_lifetime_reached() -> String {
    format!(
        "connection exceeded its {} s absolute lifetime",
        MAX_CONNECTION_LIFETIME.as_secs()
    )
}

async fn handle_connection(
    incoming: quinn::Incoming,
    handler: Arc<dyn NegotiationHandler>,
    permit: tokio::sync::OwnedSemaphorePermit,
    per_identity: Arc<std::sync::Mutex<RateLimiter<String>>>,
) -> Result<(), TransportError> {
    let started = Instant::now();
    let deadline = Deadline::starting_now();
    let remote = incoming.remote_address();
    let connection = incoming.await.map_err(TransportError::Connection)?;
    let fingerprint = peer_certificate_sha256(&connection)?;
    let Some(admitted_peer) = handler.resolve_admitted_peer(&fingerprint).await else {
        tracing::warn!(
            %remote,
            client_certificate_sha256 = %fingerprint,
            "quic: certificate signed by the client CA but not admitted for any peer"
        );
        connection.close(0u32.into(), b"rejected");
        return Err(TransportError::Protocol(
            "client certificate is not admitted for any peer".into(),
        ));
    };
    let within_budget = per_identity
        .lock()
        .map(|mut limiter| limiter.admit(fingerprint.clone(), Instant::now()))
        .unwrap_or(false);
    if !within_budget {
        tracing::warn!(
            %remote,
            client_certificate_sha256 = %fingerprint,
            "key-negotiation rate exceeded for this admitted identity"
        );
        connection.close(0u32.into(), b"rate");
        return Err(TransportError::Protocol(
            "negotiation rate exceeded for this identity".into(),
        ));
    }
    tracing::info!(
        %remote,
        elapsed_ms = started.elapsed().as_millis(),
        rtt_ms = connection.rtt().as_millis(),
        client_certificate_sha256 = %fingerprint,
        "quic: client handshake accepted"
    );
    let (mut send, mut recv) = connection
        .accept_bi()
        .await
        .map_err(TransportError::Connection)?;

    let mut issued_challenge: Option<[u8; SERVER_CHALLENGE_LEN]> = None;
    let mut challenge_requests = 0u32;
    let challenge_deadline = Instant::now() + CHALLENGE_VALIDITY;

    let request = loop {
        let frame =
            tokio::time::timeout(deadline.remaining(), read_frame::<ClientMessage>(&mut recv))
                .await
                .map_err(|_| TransportError::Protocol(absolute_lifetime_reached()))??;
        match frame {
            ClientMessage::ChallengeRequest { protocol_version } => {
                if challenge_requests > 0 {
                    write_frame(
                        &mut send,
                        &ServerMessage::Error {
                            error: PublicError::Protocol,
                        },
                    )
                    .await?;
                    return Err(TransportError::Protocol(
                        "a connection may request only one challenge".into(),
                    ));
                }
                challenge_requests += 1;
                if protocol_version != KEY_NEGOTIATION_VERSION {
                    write_frame(
                        &mut send,
                        &ServerMessage::Error {
                            error: PublicError::Protocol,
                        },
                    )
                    .await?;
                    return Err(TransportError::Protocol(format!(
                        "unsupported protocol version {protocol_version}"
                    )));
                }
                let challenge = random_challenge()?;
                issued_challenge = Some(challenge);
                let identity = handler.announced_identity();
                write_frame(
                    &mut send,
                    &ServerMessage::Challenge {
                        challenge: KeyNegotiationChallenge {
                            protocol_version: KEY_NEGOTIATION_VERSION,
                            server_challenge: challenge,
                            gateway_wg_public_key: identity.wg_public_key,
                            server_name: identity.server_name,
                            expires_in_secs: CHALLENGE_VALIDITY.as_secs() as u32,
                        },
                    },
                )
                .await?;
            }
            ClientMessage::Request { request } => {
                if let Err(error) = consume_challenge(
                    &mut issued_challenge,
                    challenge_deadline,
                    request.request.server_challenge,
                ) {
                    write_frame(&mut send, &ServerMessage::Error { error }).await?;
                    return Ok(());
                }
                break *request;
            }
            ClientMessage::Confirmation { .. } => {
                write_frame(
                    &mut send,
                    &ServerMessage::Error {
                        error: PublicError::Protocol,
                    },
                )
                .await?;
                return Err(TransportError::Protocol(
                    "confirmation received before any negotiation".into(),
                ));
            }
        }
    };

    if request.request.validate().is_err() {
        write_frame(
            &mut send,
            &ServerMessage::Error {
                error: PublicError::Protocol,
            },
        )
        .await?;
        drain_then_close(&connection, &mut send, "malformed negotiation request").await;
        return Ok(());
    }
    if request.request.client_wg_public_key != admitted_peer {
        write_frame(
            &mut send,
            &ServerMessage::Error {
                error: PublicError::Rejected,
            },
        )
        .await?;
        drain_then_close(
            &connection,
            &mut send,
            "certificate and WireGuard identities differ",
        )
        .await;
        return Ok(());
    }

    let transaction_id = request.request.transaction_id;
    let server_challenge = request.request.server_challenge;
    let mut guard = RollbackGuard::arm(
        Arc::clone(&handler),
        transaction_id,
        request.request.client_wg_public_key.clone(),
    );
    let prepared = match handler.prepare(fingerprint, request).await {
        Ok(prepared) => prepared,
        Err(error) => {
            guard.roll_back().await;
            write_frame(&mut send, &ServerMessage::Error { error }).await?;
            drain_then_close(&connection, &mut send, "negotiation rejected").await;
            return Ok(());
        }
    };
    if let Err(error) = write_frame(
        &mut send,
        &ServerMessage::Response {
            response: Box::new(prepared.response),
        },
    )
    .await
    {
        guard.roll_back().await;
        return Err(error);
    }

    let confirmation = tokio::time::timeout(
        deadline.clamp(prepared.confirmation_timeout),
        read_frame::<ClientMessage>(&mut recv),
    )
    .await;
    let message = match confirmation {
        Ok(Ok(ClientMessage::Confirmation { confirmation }))
            if confirmation.confirmation.protocol_version == KEY_NEGOTIATION_VERSION
                && confirmation.confirmation.transaction_id == transaction_id
                && confirmation.confirmation.server_challenge == server_challenge =>
        {
            confirmation
        }
        _ => {
            guard.roll_back().await;
            return Ok(());
        }
    };

    let commit = match handler.confirm(message).await {
        Ok(commit) => commit,
        Err(error) => {
            guard.roll_back().await;
            write_frame(
                &mut send,
                &ServerMessage::Error {
                    error: error.clone(),
                },
            )
            .await?;
            return Err(TransportError::Protocol(error.to_string()));
        }
    };
    guard.disarm();

    if let Err(error) = write_frame(&mut send, &ServerMessage::Committed { commit }).await {
        tracing::warn!(
            %remote,
            transaction = %hex::encode(transaction_id),
            error = %error,
            "commit could not be sent; the slot stays armed and the client will renegotiate — this is not a rollback"
        );
        return Err(error);
    }

    drain_then_close(&connection, &mut send, "negotiation committed").await;
    drop(permit);
    Ok(())
}

async fn drain_then_close(connection: &Connection, send: &mut SendStream, reason: &'static str) {
    if let Err(error) = send.finish() {
        tracing::debug!(%error, "stream already closed by the peer");
    }
    match tokio::time::timeout(crate::endpoint::COMMIT_DELIVERY_TIMEOUT, send.stopped()).await {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => tracing::debug!(%error, "peer reset the stream before acknowledging it"),
        Err(_) => tracing::warn!(
            timeout_s = crate::endpoint::COMMIT_DELIVERY_TIMEOUT.as_secs(),
            "peer never acknowledged the final frame"
        ),
    }
    connection.close(0u32.into(), reason.as_bytes());
}

fn consume_challenge(
    issued: &mut Option<[u8; SERVER_CHALLENGE_LEN]>,
    deadline: Instant,
    presented: [u8; SERVER_CHALLENGE_LEN],
) -> Result<(), PublicError> {
    let Some(expected) = issued.take() else {
        tracing::warn!("key negotiation: request without a live challenge on this connection");
        return Err(PublicError::Rejected);
    };
    if Instant::now() > deadline {
        tracing::warn!("key negotiation: challenge expired before it was used");
        return Err(PublicError::Rejected);
    }
    if expected != presented {
        tracing::warn!("key negotiation: request carries a challenge this connection never issued");
        return Err(PublicError::Rejected);
    }
    Ok(())
}

fn random_challenge() -> Result<[u8; SERVER_CHALLENGE_LEN], TransportError> {
    let mut challenge = [0u8; SERVER_CHALLENGE_LEN];
    aether::random::fill_public(&mut challenge).map_err(|error| {
        TransportError::Protocol(format!("the approved DRBG produced no challenge: {error}"))
    })?;
    Ok(challenge)
}
