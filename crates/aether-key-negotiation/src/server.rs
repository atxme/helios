use std::{
    net::{IpAddr, SocketAddr},
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
    error::{PublicError, TransportError},
    framing::{read_frame, write_frame, ClientMessage, ServerMessage},
    identity::peer_certificate_sha256,
    rate_limit::{rate_bucket, RateLimiter},
    transaction::{Deadline, RollbackGuard},
    CHALLENGE_VALIDITY, MAX_ACTIVE_NEGOTIATIONS, MAX_CONNECTION_LIFETIME,
    MAX_HANDSHAKES_PER_SOURCE, MAX_NEGOTIATIONS_PER_IDENTITY,
};

/// Secret configuration prepared for the WireGuard peer.
///
/// Since `classic` stopped being a negotiable mode, every negotiation that
/// gets this far produces a key: `psk` is always `Some` here. The `Option`
/// remains because the data-plane call it feeds also uses `None` to *clear* a
/// slot, which is a different operation reached by a different path.
#[derive(Debug)]
pub struct PreparedKeyMaterial {
    pub response: KeyNegotiationResponse,
    pub psk: Option<SecretString>,
}

/// Applies the mode selected by Orion and derives the candidate peer secret.
///
/// The caller still owns transaction serialization, data-plane installation
/// and rollback. This function performs no I/O and is safe to exercise with
/// adversarial inputs.
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
        // `static_psk` never expires: the value belongs to both peers'
        // configuration, not to this transaction.
        psk_lifetime_secs: match request.mode {
            ProtectionMode::StaticPsk => 0,
            _ => aether::key_negotiation::NEGOTIATED_PSK_LIFETIME_SECS,
        },
    };

    let psk = match request.mode {
        ProtectionMode::StaticPsk => {
            // `Rejected`, not a mode-specific code: whether the peer has no
            // static PSK configured, or has one that does not match, is
            // exactly the sort of state the public boundary must not reveal.
            let configured = static_psk.ok_or(PublicError::Rejected)?;
            let presented = request
                .static_psk_commitment
                .as_deref()
                .ok_or(PublicError::Protocol)?;
            // Recomputed for this transaction, so the comparison proves
            // possession *now* rather than matching a stable identifier an
            // observer could have harvested from an earlier negotiation.
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
///
/// Public by construction: both values are already in every client profile.
/// Announcing them lets a client detect a wrong or substituted endpoint
/// before spending an ML-DSA-87 signature on it.
#[derive(Debug, Clone)]
pub struct GatewayIdentity {
    pub wg_public_key: String,
    pub server_name: String,
}

#[async_trait]
pub trait NegotiationHandler: Send + Sync + 'static {
    /// Identity to put in a challenge. Must be what the gateway actually
    /// serves, not what its configuration file says it should serve.
    fn announced_identity(&self) -> GatewayIdentity;

    /// The one admitted peer this TLS certificate belongs to, if any.
    ///
    /// Called as soon as mTLS names the peer and **before** a challenge is
    /// issued (spec §4.4, §7.3): an unknown fingerprint must not cost the
    /// gateway a CSPRNG read and a frame, and an admitted identity must not
    /// get to choose which peer it probes. The WireGuard key in the request
    /// is then checked against this answer — it is never itself a lookup key
    /// into the peer table.
    ///
    /// `source` is the canonical address the connection comes from. A source
    /// that is a tunnel VIP lets the implementation require that the VIP and
    /// the certificate name the same peer (in-tunnel PSK renewal).
    async fn resolve_admitted_peer(
        &self,
        certificate_sha256: &str,
        source: IpAddr,
    ) -> Option<String>;

    async fn prepare(
        &self,
        certificate_sha256: String,
        source: IpAddr,
        request: AuthenticatedKeyNegotiationRequest,
    ) -> Result<PreparedNegotiation, PublicError>;

    async fn confirm(
        &self,
        confirmation: AuthenticatedKeyNegotiationConfirmation,
    ) -> Result<AuthenticatedKeyNegotiationCommit, PublicError>;

    /// Undoes a transaction that never reached its commit.
    ///
    /// Only callable **before** the commit is signed. After that point there
    /// is no rollback: see the ordering in `heliosd::key_negotiation`.
    ///
    /// The peer's WireGuard key is passed alongside the identifier because
    /// this must also undo a `prepare` that was **destroyed part-way
    /// through** and therefore never recorded its transaction. The
    /// implementation matches on the identifier the slot itself carries, so
    /// a call naming a transaction that no longer owns the slot is a no-op.
    async fn rollback(&self, transaction_id: [u8; 16], client_wg_public_key: &str);
}
/// Serves connections until the endpoint is closed.
/// Serves the public negotiation port.
///
/// # Cost before authentication
///
/// Everything this port does — TLS 1.3, ML-DSA-65 verification, ML-KEM
/// encapsulation — is expensive, and all of it happens before the gateway
/// knows whether the peer is legitimate. That asymmetry is the DoS: a few
/// spoofed packets buy an attacker a lot of gateway CPU.
///
/// Two bounds, in the order that matters:
///
/// 1. **Address validation (QUIC Retry).** An `Incoming` whose address is not
///    yet validated is answered with a Retry packet, which costs a token and
///    no state. The peer must echo the token from that same address, so a
///    spoofed source never reaches the TLS handshake at all.
/// 2. **Per-source rate limit.** Validation proves the address is real, not
///    that it is friendly. Beyond [`MAX_HANDSHAKES_PER_SOURCE`] per window,
///    further handshakes from that address are refused.
///
/// [`MAX_ACTIVE_NEGOTIATIONS`] then bounds concurrency for what gets through.
pub async fn serve(endpoint: Endpoint, handler: Arc<dyn NegotiationHandler>) {
    let capacity = Arc::new(tokio::sync::Semaphore::new(MAX_ACTIVE_NEGOTIATIONS));
    let limiter = Arc::new(std::sync::Mutex::new(RateLimiter::new(
        MAX_HANDSHAKES_PER_SOURCE,
    )));
    // Counted once mTLS has named a peer, which is a different question from
    // the address budget above. A holder of one admitted certificate roaming
    // across addresses — or simply behind a large provider — would otherwise
    // face no limit at all, and every negotiation it opens costs the gateway
    // an ML-DSA-87 verification and an ML-KEM encapsulation.
    let per_identity = Arc::new(std::sync::Mutex::new(RateLimiter::new(
        MAX_NEGOTIATIONS_PER_IDENTITY,
    )));

    while let Some(incoming) = endpoint.accept().await {
        // Before any allocation or cryptography: prove the address is real.
        //
        // The Retry token itself is quinn's, bound to the address exactly as
        // this socket reports it. Issuing and checking both happen on the one
        // dual-stack socket, so an IPv4 client is `::ffff:a.b.c.d` on both
        // sides of that comparison and nothing here has to translate it.
        if !incoming.remote_address_validated() {
            let remote = canonical_remote(incoming.remote_address());
            if incoming.retry().is_err() {
                tracing::info!(%remote, "quic: retry refused for an already-validated peer");
            }
            continue;
        }

        let source = canonical_remote(incoming.remote_address()).ip();
        let admitted = limiter
            .lock()
            .map(|mut limiter| {
                limiter.admit(source_bucket(incoming.remote_address()), Instant::now())
            })
            // A poisoned lock must not open the port wide: refuse instead.
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
            let remote = canonical_remote(incoming.remote_address());
            // The absolute ceiling. `handle_connection` bounds each phase it
            // waits on, but the sum of well-behaved phases is not itself
            // bounded — this is what makes it so.
            let served = tokio::time::timeout(
                MAX_CONNECTION_LIFETIME,
                handle_connection(incoming, handler, permit, per_identity),
            )
            .await
            .unwrap_or_else(|_| Err(TransportError::Protocol(absolute_lifetime_reached())));
            if let Err(error) = served {
                // `aborted by peer` means the **client** hung up, and the text
                // that follows is its own error crossing the wire. Naming the
                // direction stops an operator reading a client-side refusal as
                // a gateway fault.
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
/// The peer's address as every consumer on this port must read it.
///
/// The dual-stack listener reports an IPv4 client as `::ffff:a.b.c.d`. The
/// budget bucket canonicalizes on its own ([`rate_bucket`]); this keeps the
/// journal on the same form, so the address a refusal names is the one an
/// operator would look for — and the one the bucket counted.
fn canonical_remote(remote: SocketAddr) -> SocketAddr {
    SocketAddr::new(aether::net::canonical_source(remote.ip()), remote.port())
}

/// The per-source budget a connection from `remote` is charged to, taking
/// `remote` exactly as the listening socket reports it.
pub(crate) fn source_bucket(remote: SocketAddr) -> std::net::IpAddr {
    rate_bucket(canonical_remote(remote).ip())
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
    let remote = canonical_remote(incoming.remote_address());
    let connection = incoming.await.map_err(TransportError::Connection)?;
    let fingerprint = peer_certificate_sha256(&connection)?;
    // Resolved before anything is spent on this connection (spec §4.4, §7.3).
    // Two properties come out of doing it here rather than at `prepare`: an
    // unknown fingerprint never costs a challenge, and an admitted identity
    // is bound to **its** peer from this point on — the WireGuard key in the
    // request is checked against this answer instead of being a lookup key of
    // its own, so one admitted client cannot aim a negotiation at another.
    let Some(admitted_peer) = handler
        .resolve_admitted_peer(&fingerprint, remote.ip())
        .await
    else {
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
    // Now that mTLS has named an *admitted* peer, charge it. A per-address
    // budget does not bound a single admitted identity that roams.
    let within_budget = per_identity
        .lock()
        .map(|mut limiter| limiter.admit(fingerprint.clone(), Instant::now()))
        // A poisoned lock must not open the port wide: refuse instead.
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
    // The fingerprint is what `heliosd peer add` was given: printing it here
    // makes an admission mismatch a comparison rather than a deduction.
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

    // The challenge lives here — in this task's stack, for this connection —
    // and nowhere else. That is the whole anti-replay design of v5, and it is
    // why it needed no global table, no persistence and no counter: an
    // `Option` owned by a single task is consumed exactly once by
    // construction, so two requests bearing the same challenge cannot both be
    // accepted even in principle. The 128-connection ceiling already bounds
    // how many can exist.
    let mut issued_challenge: Option<[u8; SERVER_CHALLENGE_LEN]> = None;
    let mut challenge_requests = 0u32;
    let challenge_deadline = Instant::now() + CHALLENGE_VALIDITY;

    let request = loop {
        // Nothing before the request has a phase timeout of its own: the
        // challenge round-trip is short and the client sets the pace. What it
        // must not do is outlast the connection, so the read is bounded by
        // what is left of the absolute lifetime and expires as an error
        // rather than as a destroyed task.
        let frame =
            tokio::time::timeout(deadline.remaining(), read_frame::<ClientMessage>(&mut recv))
                .await
                .map_err(|_| TransportError::Protocol(absolute_lifetime_reached()))??;
        match frame {
            ClientMessage::ChallengeRequest { protocol_version } => {
                // Exactly one per connection. Each costs a CSPRNG read and a
                // frame, and answering an unbounded stream of them is free
                // work for an attacker who never intends to negotiate. The
                // previous code merely replaced the live challenge, which
                // bounded how many were *valid* at once but not how many the
                // gateway would produce.
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
        // The error frame is the public answer. Finish the stream and wait
        // for the peer to take it before closing the connection; dropping it
        // immediately makes Quinn report `connection lost` instead of the
        // actual protocol refusal.
        drain_then_close(&connection, &mut send, "malformed negotiation request").await;
        return Ok(());
    }
    // The request may only speak for the peer mTLS already bound it to.
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
    // Armed before `prepare`, not after it. `prepare` reserves the peer's
    // slot and poses the candidate on the data plane before it returns, so
    // the interval it occupies is one where an abandoned connection has
    // something to undo.
    let mut guard = RollbackGuard::arm(
        Arc::clone(&handler),
        transaction_id,
        request.request.client_wg_public_key.clone(),
    );
    let prepared = match handler.prepare(fingerprint, remote.ip(), request).await {
        Ok(prepared) => prepared,
        Err(error) => {
            guard.roll_back().await;
            write_frame(&mut send, &ServerMessage::Error { error }).await?;
            // The error is the final application frame, just like a commit.
            // Returning immediately drops the stream before the peer has read
            // it; Quinn then reports a connection loss and hides the public
            // `rejected` result that was actually sent.
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

    // Clamped to whatever is left of the absolute lifetime. The confirmation
    // wait is the long one — up to 45 s — so it is the phase that would
    // otherwise run past the 90 s ceiling and have the connection destroyed
    // under it. Bounding it here means the deadline is reached on an ordinary
    // code path, with the rollback the ceiling itself cannot perform.
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
        // Timed out, unreadable, or not the transaction we are holding.
        _ => {
            guard.roll_back().await;
            return Ok(());
        }
    };

    // Point of no return. `confirm` persists the floor and signs the commit,
    // in that order; once it returns Ok there is no rollback, and none of the
    // failures below may reach for one. A commit that cannot be delivered
    // leaves the slot armed on this side and the client renegotiates — which
    // converges — whereas restoring the slot behind a signed commit would put
    // a valid, verifiable commit in a client's hands against a gateway that
    // had undone everything. That was the v4 behaviour, and it is the double
    // semantics v5 exists to remove.
    //
    // Disarmed only *after* `confirm` returns `Ok`: if the task is destroyed
    // during `confirm` itself the candidate must still come back, and if
    // `confirm` succeeded there is nothing left that may be undone.
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

    // Closed, not kept. The connection carried a transaction and that
    // transaction is over; nothing about the tunnel depends on it any more.
    // Liveness is read from the data plane by both ends.
    //
    // The drain is not politeness: closing a QUIC connection discards data
    // the peer has not read, so hanging up straight after the write loses the
    // commit on a fast local path. A lost commit is survivable — the client
    // renegotiates — but losing it *every* time would make the nominal case
    // the degraded one.
    drain_then_close(&connection, &mut send, "negotiation committed").await;
    drop(permit);
    Ok(())
}

/// Finishes a stream, waits for the peer to have taken it, then hangs up.
///
/// Failures are logged and swallowed: this runs after the point of no return,
/// where there is nothing left to undo and nothing useful to return.
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

/// Checks a presented challenge against the one this connection issued, and
/// spends it.
///
/// `Option::take` is the atomic consumption the specification asks for: the
/// value is owned by one task, so a second request carrying the same
/// challenge finds `None`. No lock is involved because there is nothing to
/// share.
///
/// Every failure is [`PublicError::Rejected`] — absent, expired, mismatched
/// and already-spent are indistinguishable on the wire, and the caller
/// journals which one it was.
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
