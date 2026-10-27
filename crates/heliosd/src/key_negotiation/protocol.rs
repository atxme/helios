//! The negotiation protocol served on the public endpoint, and the in-tunnel
//! release that ends a committed transaction.

use super::*;

#[async_trait::async_trait]
impl NegotiationHandler for GatewayHandler {
    fn announced_identity(&self) -> GatewayIdentity {
        // What is actually served, read from the loaded identity rather than
        // from the configuration file: after a rotation the daemon has not
        // restarted for, those two disagree, and the client must be told the
        // truth so it can name the discrepancy.
        GatewayIdentity {
            wg_public_key: self.gateway_public_key.clone(),
            server_name: self.gateway_pq_certificate.subject.clone(),
        }
    }

    async fn resolve_admitted_peer(
        &self,
        certificate_sha256: &str,
        source: std::net::IpAddr,
    ) -> Option<String> {
        let resolved = self.certificate_peer(certificate_sha256).await?;
        match origin::classify(&*self.network.read().await, source) {
            origin::Origin::Public => Some(resolved),
            origin::Origin::Tunnel { peer_public_key } if peer_public_key == resolved => {
                Some(resolved)
            }
            origin::Origin::Tunnel { peer_public_key } => {
                tracing::warn!(
                    %source,
                    vip_owner = %peer_public_key,
                    certificate_peer = %resolved,
                    "key negotiation refused: an in-tunnel source belongs to another peer than \
                     the presented certificate"
                );
                None
            }
        }
    }

    async fn prepare(
        &self,
        certificate_sha256: String,
        source: std::net::IpAddr,
        authenticated: AuthenticatedKeyNegotiationRequest,
    ) -> Result<PreparedNegotiation, PublicError> {
        let request = &authenticated.request;
        // The gateway used to refuse in silence: the client received a code,
        // the operator saw nothing at all, and the two halves of the same
        // failure could not be put side by side. Every refusal below now says
        // which peer, which transaction and — above all — why.
        let transaction = hex_prefix(&request.transaction_id);
        let peer_key = request.client_wg_public_key.clone();
        request.validate().map_err(|_| {
            tracing::warn!(%transaction, peer = %peer_key, "key negotiation refused: malformed request");
            PublicError::Protocol
        })?;
        // Checked before the peer table is even consulted: an authentic
        // request meant for another gateway must not reach a slot here. In a
        // shared infrastructure two gateways trust the same operator CA, so
        // without this the transcript is portable between them.
        request
            .assert_addressed_to(
                &self.gateway_public_key,
                &self.gateway_pq_certificate.subject,
                &self.served_certificate_fingerprint,
            )
            .map_err(|_| {
                tracing::warn!(
                    %transaction,
                    peer = %peer_key,
                    named_gateway = %request.gateway_wg_public_key,
                    named_server = %request.server_name,
                    served_gateway = %self.gateway_public_key,
                    served_server = %self.gateway_pq_certificate.subject,
                    "key negotiation refused: this request names another gateway"
                );
                PublicError::Rejected
            })?;
        let now = unix_time_now().map_err(|_| PublicError::Protocol)?;
        // The registry knows about leaves issued after admission; the pins in
        // `network.toml` only ever describe the generation a peer was admitted
        // with. Consulting the registry first is what keeps a renewed client
        // able to negotiate at all.
        let registered = self.registered_identity(&certificate_sha256, now).await;
        let (address, previous_psk, pq_fingerprint, minimum_mode) = {
            let network = self.network.read().await;
            // Found by the **TLS fingerprint**, never by the key the request
            // carries (spec §7.3). Searching on the request's field and then
            // comparing the fingerprint refuses the same messages, but it
            // makes a client-chosen value the index into the peer table; a
            // single missing comparison anywhere downstream would then let an
            // admitted identity aim a negotiation at another peer.
            //
            // The registry path obeys the same rule: the WireGuard key it
            // returns is *gateway state* derived from the fingerprint mTLS
            // proved, and the request's own field is still only ever compared
            // against it below. What §7.3 forbids is indexing the table with a
            // value the caller chose, and nothing here does.
            let peer = match &registered {
                Some(identity) => network
                    .peers
                    .iter()
                    .find(|peer| peer.public_key == identity.wg_public_key),
                None => network.peers.iter().find(|peer| {
                    peer.key_negotiation_certificate_sha256.as_deref()
                        == Some(certificate_sha256.as_str())
                }),
            }
            .ok_or_else(|| {
                tracing::warn!(
                    %transaction,
                    peer = %peer_key,
                    presented = %certificate_sha256,
                    registered = registered.is_some(),
                    "key negotiation refused: this client certificate is not admitted"
                );
                PublicError::Rejected
            })?;
            if peer.public_key != request.client_wg_public_key {
                tracing::warn!(
                    %transaction,
                    peer = %peer.name,
                    named = %request.client_wg_public_key,
                    admitted = %peer.public_key,
                    "key negotiation refused: the request names a WireGuard key other than the \
                     one this certificate is admitted for"
                );
                return Err(PublicError::Rejected);
            }
            let pq_fingerprint = match &registered {
                Some(identity) => identity.pq_certificate_fingerprint.to_hex(),
                None => peer
                    .key_negotiation_pq_certificate_sha256
                    .clone()
                    .ok_or(PublicError::Rejected)?,
            };
            (
                peer.address.clone(),
                peer.preshared_key
                    .as_ref()
                    .map(aether::SecretString::duplicate),
                pq_fingerprint,
                peer.minimum_key_negotiation_mode,
            )
        };
        // A peer without a floor is a plain WireGuard peer, which never
        // negotiates: it is refused like a mode below its floor.
        if !minimum_mode.is_some_and(|floor| request.mode.satisfies(floor)) {
            tracing::warn!(
                %transaction,
                peer = %peer_key,
                requested = ?request.mode,
                floor = ?minimum_mode,
                "key negotiation refused: mode below this peer's floor"
            );
            // `Rejected`, not a dedicated code. v4 answered `downgrade` here,
            // which let anyone read a peer's security floor off the public
            // port by trying one mode after another.
            return Err(PublicError::Rejected);
        }
        let in_tunnel = matches!(
            origin::classify(&*self.network.read().await, source),
            origin::Origin::Tunnel { .. }
        );
        // Every issuer the domain admits, and exactly one acceptable
        // fingerprint — the partner of the TLS half already proved. The
        // fingerprint decides before any signature is verified, so a caller
        // presenting a leaf this gateway never issued costs a hash.
        let issuers = self.client_leaf_issuers(now).await;
        let issuer_refs: Vec<&[u8]> = issuers.iter().map(Vec::as_slice).collect();
        authenticated
            .verify_against(&issuer_refs, &[pq_fingerprint.as_str()], now)
            .map_err(|error| {
                tracing::warn!(
                    %transaction,
                    peer = %peer_key,
                    %error,
                    "key negotiation refused: ML-DSA-87 authentication failed \
                     (signature, PQ certificate, or a clock too far off)"
                );
                PublicError::Rejected
            })?;
        let baseline_static_psk = self
            .static_psks
            .read()
            .await
            .get(&request.client_wg_public_key)
            .map(SecretString::duplicate);
        // Recomputed against this transaction's context, so a match proves
        // possession now rather than agreeing with a stable identifier.
        let current_matches_static_request = request
            .static_psk_commitment
            .as_deref()
            .zip(previous_psk.as_ref().map(SecretString::expose))
            .is_some_and(|(presented, current)| {
                aether::key_negotiation::static_psk_commitment(
                    current,
                    &request.transaction_id,
                    &request.client_nonce,
                    &request.server_challenge,
                    &request.client_wg_public_key,
                    &self.gateway_public_key,
                )
                .is_ok_and(|expected| {
                    aether::key_negotiation::commitments_match(&expected, presented)
                })
            });
        let configured_static_psk = if current_matches_static_request {
            previous_psk.as_ref().map(SecretString::expose)
        } else {
            baseline_static_psk.as_ref().map(SecretString::expose)
        };

        let generation = {
            let mut state = self.transactions.lock().await;
            // The peer was admitted when it was looked up above; a reload may
            // have removed it since. Settled under this lock, a removal wins
            // over the reservation rather than racing it.
            self.settle_admission(&mut state, &request.client_wg_public_key)
                .await?;
            if matches!(
                state.slot(&request.client_wg_public_key).state,
                SlotState::Revoked
            ) {
                tracing::warn!(
                    %transaction,
                    peer = %peer_key,
                    "key negotiation refused: this peer was removed from admission meanwhile"
                );
                return Err(PublicError::Rejected);
            }
            if state.replay_set.contains(&request.transaction_id) {
                tracing::warn!(
                    %transaction,
                    peer = %peer_key,
                    "key negotiation refused: transaction identifier already seen (replay)"
                );
                return Err(PublicError::Rejected);
            }
            // `prepare` reserves one generation and its eventual commit or
            // rollback consumes another. Refuse before reserving the peer or
            // recording the replay identifier if both transitions cannot be
            // represented.
            let Some(reserved_generation) = state
                .slot(&request.client_wg_public_key)
                .generation
                .checked_add(1)
            else {
                tracing::error!(
                    %transaction,
                    peer = %peer_key,
                    "key negotiation refused: peer generation is exhausted"
                );
                return Err(PublicError::Internal);
            };
            if reserved_generation.checked_add(1).is_none() {
                tracing::error!(
                    %transaction,
                    peer = %peer_key,
                    "key negotiation refused: peer generation has no terminal transition available"
                );
                return Err(PublicError::Internal);
            }
            if !state.peers.insert(request.client_wg_public_key.clone()) {
                // The case that leaves a client stuck without either end
                // saying so: a previous session died without closing, its
                // transaction still holds the peer, and every new attempt is
                // refused until that one is released.
                tracing::warn!(
                    %transaction,
                    peer = %peer_key,
                    "key negotiation refused: a transaction is already in flight for this peer — \
                     the previous session has not been released yet"
                );
                return Err(PublicError::Rejected);
            }
            if let Some(until) = state.slot(&request.client_wg_public_key).resting_until {
                if std::time::Instant::now() < until {
                    state.peers.remove(&request.client_wg_public_key);
                    tracing::warn!(
                        %transaction,
                        peer = %peer_key,
                        "key negotiation refused: this peer is in the rest period a rolled-back \
                         candidate armed"
                    );
                    return Err(PublicError::Rejected);
                }
            }
            if in_tunnel
                && !origin::tunnel_renewal_allowed(
                    request.mode,
                    &state.slot(&request.client_wg_public_key).state,
                )
            {
                state.peers.remove(&request.client_wg_public_key);
                tracing::warn!(
                    %transaction,
                    peer = %peer_key,
                    mode = ?request.mode,
                    "key negotiation refused: through the tunnel, only a committed ml_kem slot \
                     may be renewed"
                );
                return Err(PublicError::Rejected);
            }
            state.replay_set.insert(request.transaction_id);
            state.replay_order.push_back(request.transaction_id);
            while state.replay_order.len() > MAX_REPLAY_IDENTIFIERS {
                if let Some(expired) = state.replay_order.pop_front() {
                    state.replay_set.remove(&expired);
                }
            }
            // Reserved, not merely observed. Incrementing the generation and
            // claiming the slot happen under the **same** lock that reserved
            // the peer, so from here on every other actor — a delayed
            // `release`, the reclaimer, a rollback from an earlier
            // transaction — sees a generation it does not hold and a slot it
            // does not own, and is a no-op instead of a write.
            //
            // Reading the generation without taking it, as this did before,
            // left a window in which those actors still matched: they cleared
            // the data plane under a candidate that then committed.
            let slot = state.slot(&request.client_wg_public_key);
            slot.generation = reserved_generation;
            slot.resting_until = None;
            let previous_state = std::mem::replace(&mut slot.state, SlotState::Empty);
            slot.state = SlotState::Preparing {
                transaction_id: request.transaction_id,
                previous: Box::new(previous_state),
                address: address.clone(),
                previous_psk: previous_psk.as_ref().map(SecretString::duplicate),
                install_attempted: false,
            };
            slot.generation
        };

        // Read **before** the candidate is posed, because the commit compares
        // against it. Reading it after would let the very handshake the
        // attacker is trying to skip count as the proof.
        let handshake_before_install =
            match self.observe_handshake(&request.client_wg_public_key).await {
                Ok(observed) => observed,
                Err(error) => {
                    tracing::warn!(
                        %transaction,
                        peer = %peer_key,
                        "key negotiation refused: the data plane could not be read before posing \
                         the candidate PSK, so no commit could be proven afterwards"
                    );
                    self.abandon(request.transaction_id, &request.client_wg_public_key)
                        .await;
                    return Err(error);
                }
            };

        let gateway_nonce = match random_nonce() {
            Ok(nonce) => nonce,
            Err(_) => {
                self.abandon(request.transaction_id, &request.client_wg_public_key)
                    .await;
                return Err(PublicError::Protocol);
            }
        };
        let material = match prepare_key_material(
            request,
            &self.gateway_public_key,
            gateway_nonce,
            configured_static_psk,
            DEFAULT_CONFIRMATION_TIMEOUT,
        ) {
            Ok(material) => material,
            Err(error) => {
                tracing::warn!(
                    %transaction,
                    peer = %peer_key,
                    ?error,
                    "key negotiation refused: preparing the key material failed"
                );
                self.abandon(request.transaction_id, &request.client_wg_public_key)
                    .await;
                return Err(error);
            }
        };

        let response = match authenticate_response(
            material.response,
            self.gateway_pq_certificate.clone(),
            self.gateway_pq_private_key.as_slice(),
        ) {
            Ok(response) => response,
            Err(_) => {
                self.abandon(request.transaction_id, &request.client_wg_public_key)
                    .await;
                return Err(PublicError::Protocol);
            }
        };

        let transaction_record = Transaction {
            public_key: request.client_wg_public_key.clone(),
            address: address.clone(),
            client_pq_public_key: authenticated.certificate.ml_dsa_87_public_key.clone(),
            mode: request.mode,
            server_challenge: request.server_challenge,
            generation,
            handshake_before_install,
        };
        if let Err(error) = self
            .install_candidate(
                request.transaction_id,
                &request.client_wg_public_key,
                generation,
                address.clone(),
                material.psk,
                transaction_record,
            )
            .await
        {
            // Posed **before** answering, always: a client that received a PSK
            // the data plane refused would handshake with nobody.
            tracing::warn!(
                %transaction,
                peer = %peer_key,
                ?error,
                "key negotiation refused: installing the PSK on the data plane failed"
            );
            self.abandon(request.transaction_id, &request.client_wg_public_key)
                .await;
            return Err(error);
        }
        tracing::info!(
            %transaction,
            peer = %peer_key,
            mode = ?request.mode,
            confirmation_timeout_s = DEFAULT_CONFIRMATION_TIMEOUT.as_secs(),
            "key negotiation prepared: PSK installed, awaiting the client's confirmation"
        );
        if request.mode == ProtectionMode::StaticPsk && current_matches_static_request {
            if let Some(static_psk) = previous_psk.as_ref().map(SecretString::duplicate) {
                self.static_psks
                    .write()
                    .await
                    .insert(request.client_wg_public_key.clone(), static_psk);
            }
        }

        Ok(PreparedNegotiation {
            response,
            confirmation_timeout: DEFAULT_CONFIRMATION_TIMEOUT,
        })
    }

    /// Point of no return.
    ///
    /// The order below is normative (spec §11.2): verify the signature,
    /// **prove a WireGuard handshake**, persist the floor, sign, and only
    /// then record what the slot now holds. Persisting the floor before
    /// signing is deliberate — a floor that rises for a session the client
    /// never saw committed is still correct, because the peer just proved a
    /// WireGuard handshake at that level, whereas a floor lost to a crash
    /// between signing and writing is a security property gone. Of the two
    /// possible mistakes, one is not a mistake.
    ///
    /// Once this returns `Ok`, no caller may roll back. A commit that cannot
    /// be delivered leaves the slot armed and the client renegotiates, which
    /// converges; undoing it would hand a client a valid commit against a
    /// gateway that had restored the previous state.
    async fn confirm(
        &self,
        confirmation: AuthenticatedKeyNegotiationConfirmation,
    ) -> Result<AuthenticatedKeyNegotiationCommit, PublicError> {
        let transaction_id = confirmation.confirmation.transaction_id;
        let (client_pq_public_key, public_key, mode, server_challenge, before, generation) = self
            .transactions
            .lock()
            .await
            .active
            .get(&transaction_id)
            .map(|transaction| {
                (
                    transaction.client_pq_public_key.clone(),
                    transaction.public_key.clone(),
                    transaction.mode,
                    transaction.server_challenge,
                    transaction.handshake_before_install,
                    transaction.generation,
                )
            })
            .ok_or(PublicError::Rejected)?;
        if confirmation.confirmation.server_challenge != server_challenge {
            tracing::warn!(
                transaction = %hex_prefix(&transaction_id),
                peer = %public_key,
                "confirmation refused: it carries another transaction's challenge"
            );
            return Err(PublicError::Rejected);
        }
        confirmation
            .verify(&client_pq_public_key)
            .map_err(|_| PublicError::Rejected)?;

        // The gateway's own proof, and the only one that involves the peer's
        // **WireGuard** private key.
        //
        // Everything verified above proves possession of the client's TLS and
        // ML-DSA-87 identities. Those are two keys; the tunnel rests on a
        // third. An attacker who stole a client's negotiation identity but
        // not its WireGuard key could, without this check, present a
        // well-formed confirmation and have the gateway commit a PSK of their
        // choosing into that peer's slot — which cuts the genuine client off,
        // since a slot filled on one side only fails every handshake.
        //
        // The client is told to confirm *after* it observes a handshake, so
        // by the time this runs the data plane has the evidence. Comparing
        // raw observations rather than clocks keeps the check independent of
        // system time: only the backend's own notion of "later" matters.
        let after = self.observe_handshake(&public_key).await?;
        let handshake_proven = match (before, after) {
            (_, None) => false,
            (None, Some(_)) => true,
            (Some(before), Some(after)) => after > before,
        };
        if !handshake_proven {
            tracing::warn!(
                transaction = %hex_prefix(&transaction_id),
                peer = %public_key,
                "confirmation refused: no WireGuard handshake observed since the candidate PSK \
                 was posed, so the confirming party has not proven it holds the peer's WireGuard \
                 private key"
            );
            return Err(PublicError::Rejected);
        }

        // Compare-and-swap before anything durable happens. The candidate
        // this confirmation speaks for must still be the one the slot holds:
        // if the generation has moved, or the slot is no longer `preparing`
        // for this transaction, then the PSK about to be committed is not the
        // PSK on the data plane, and signing a commit for it would hand the
        // client a receipt for a secret the gateway does not have.
        {
            let mut state = self.transactions.lock().await;
            // A peer removed since the candidate was posed is revoked here,
            // which moves the generation: the check below then refuses.
            self.settle_admission(&mut state, &public_key).await?;
            let slot = state.slot(&public_key);
            let still_ours = slot.generation == generation
                && matches!(
                    &slot.state,
                    SlotState::Preparing { transaction_id: owner, .. } if *owner == transaction_id
                );
            if !still_ours {
                tracing::warn!(
                    transaction = %hex_prefix(&transaction_id),
                    peer = %public_key,
                    reserved = generation,
                    current = slot.generation,
                    "confirmation refused: this peer's slot moved on since the candidate was posed"
                );
                return Err(PublicError::Rejected);
            }
            if slot.generation.checked_add(1).is_none() {
                tracing::error!(
                    transaction = %hex_prefix(&transaction_id),
                    peer = %public_key,
                    "confirmation refused: peer generation is exhausted"
                );
                return Err(PublicError::Internal);
            }
        }

        self.raise_security_floor(&public_key, mode).await?;
        let commit = authenticate_commit(
            server_challenge,
            transaction_id,
            self.gateway_pq_private_key.as_slice(),
        )
        .map_err(|_| PublicError::Internal)?;

        // Past this line the transaction is irreversible: its rollback data
        // is dropped rather than moved to a second map.
        //
        // Dropping the reservation and recording what the slot now holds are
        // one locked step. Two steps left a window between them in which the
        // next request could reserve the freed peer and pose its own
        // candidate, only for this transaction's tail to overwrite the slot
        // record with its own — describing a PSK the data plane no longer
        // carried.
        let (transaction, committed_generation) = {
            let mut state = self.transactions.lock().await;
            // Checked again at the point of no return: a removal between the
            // check above and this lock must not end in a signed commit.
            self.settle_admission(&mut state, &public_key).await?;
            if !state.active.contains_key(&transaction_id) {
                return Err(PublicError::Internal);
            }
            let slot = state.slot(&public_key);
            if slot.generation != generation {
                return Err(PublicError::Internal);
            }
            let Some(next_generation) = slot.generation.checked_add(1) else {
                tracing::error!(
                    transaction = %hex_prefix(&transaction_id),
                    peer = %public_key,
                    "confirmation refused: peer generation is exhausted"
                );
                return Err(PublicError::Internal);
            };
            let transaction = state
                .active
                .remove(&transaction_id)
                .ok_or(PublicError::Internal)?;
            state.peers.remove(&transaction.public_key);
            let slot = state.slot(&transaction.public_key);
            // Two committed states, because the two modes leave two different
            // things in the slot. `ml_kem` leaves a fresh secret this
            // transaction owns, expires and may release. `static_psk` leaves
            // the value the operator configured on both peers: the
            // transaction proved possession of it and ends, but the secret
            // was there before and stays after, owned by nobody.
            slot.state = match mode {
                ProtectionMode::StaticPsk => SlotState::ConfiguredStatic,
                _ => SlotState::Committed(InstalledPsk {
                    transaction_id,
                    public_key: transaction.public_key.clone(),
                    address: transaction.address.clone(),
                    installed_at: std::time::Instant::now(),
                    bytes_baseline: None,
                }),
            };
            slot.generation = next_generation;
            (transaction, next_generation)
        };
        tracing::info!(
            transaction = %hex_prefix(&transaction_id),
            peer = %transaction.public_key,
            mode = ?mode,
            generation = committed_generation,
            "key negotiation committed: the floor is persisted and the slot is final"
        );
        Ok(commit)
    }

    async fn rollback(&self, transaction_id: [u8; 16], client_wg_public_key: &str) {
        tracing::info!(
            transaction = %hex_prefix(&transaction_id),
            peer = %client_wg_public_key,
            "key negotiation rolled back: the peer's previous PSK slot is restored"
        );
        // Ownership-guarded: if anything has touched this peer's slot since
        // the transaction reserved it, the restore is a no-op rather than a
        // write that would undo a newer negotiation.
        self.abandon(transaction_id, client_wg_public_key).await;
    }
}

/// Explicit teardown, arriving **inside the WireGuard tunnel**.
///
/// The gateway learns the caller's identity from the source VIP, which
/// `helios_api::auth::require_peer` has already resolved against the peer
/// table; this only ever *compares* the keys the body carries. So a release
/// engages the peer's WireGuard key — proved by the packet having crossed the
/// tunnel at all — on top of its ML-DSA-87 identity.
///
/// Idempotent and deliberately uninformative: cleared, already empty, owned by
/// another transaction, still `preparing` and holding a configured static PSK
/// are one and the same answer. Telling them apart would be an oracle on a
/// peer's state.
#[async_trait::async_trait]
impl helios_api::key_negotiation::PskReleaseHandler for GatewayHandler {
    async fn release(
        &self,
        caller_wg_public_key: &str,
        authenticated: AuthenticatedPskRelease,
    ) -> Result<(), PskReleaseRefusal> {
        let release = &authenticated.release;
        if release.protocol_version != KEY_NEGOTIATION_VERSION {
            return Err(PskReleaseRefusal::Protocol);
        }
        // The body's own copy of the client key is checked against the one the
        // transport proved, never used to find a peer. A negotiation identity
        // stolen from one client therefore cannot aim a release at another.
        if release.client_wg_public_key != caller_wg_public_key {
            tracing::warn!(
                peer = %caller_wg_public_key,
                "release refused: the body names another peer than the source VIP"
            );
            return Err(PskReleaseRefusal::Rejected);
        }
        if release.gateway_wg_public_key != self.gateway_public_key {
            tracing::warn!(
                peer = %caller_wg_public_key,
                "release refused: it names another gateway"
            );
            return Err(PskReleaseRefusal::Rejected);
        }
        let now = unix_time_now().map_err(|_| PskReleaseRefusal::Internal)?;
        // Same reason as the negotiation port: `network.toml` describes the
        // generation a peer was admitted with, and a renewed client presents
        // something else. A refusal here is not fatal — the 300 s reclaim is
        // the net — but it turns an explicit, immediate teardown into five
        // minutes of a PSK nobody holds, and the log would name an
        // authentication failure rather than a stale pin.
        //
        // Unlike the negotiation this is the **union** of the acceptable
        // generations, and correctly so: no TLS half was presented here, so
        // there is no pair to mix. The proof of identity is the tunnel itself,
        // which `require_peer` resolved from the source VIP.
        let mut fingerprints = self
            .registered_pq_fingerprints(caller_wg_public_key, now)
            .await;
        if fingerprints.is_empty() {
            let network = self.network.read().await;
            let peer = network
                .peers
                .iter()
                .find(|peer| peer.public_key == caller_wg_public_key)
                .ok_or(PskReleaseRefusal::Rejected)?;
            fingerprints.push(
                peer.key_negotiation_pq_certificate_sha256
                    .clone()
                    .ok_or(PskReleaseRefusal::Rejected)?,
            );
        }
        let issuers = self.client_leaf_issuers(now).await;
        let issuer_refs: Vec<&[u8]> = issuers.iter().map(Vec::as_slice).collect();
        let acceptable: Vec<&str> = fingerprints.iter().map(String::as_str).collect();
        authenticated
            .verify_against(&issuer_refs, &acceptable, now)
            .map_err(|error| {
                tracing::warn!(
                    peer = %caller_wg_public_key,
                    %error,
                    "release refused: authentication failed"
                );
                PskReleaseRefusal::Rejected
            })?;

        // Classification and action share one lock inside
        // `release_owned_slot`. If confirmation wins that lock first this
        // clears the PSK it just committed; if the release wins, the slot is
        // not committed yet and nothing is touched.
        match self
            .release_owned_slot(release.installed_transaction_id, caller_wg_public_key)
            .await
        {
            Ok(true) => {
                tracing::info!(
                    peer = %caller_wg_public_key,
                    transaction = %hex_prefix(&release.installed_transaction_id),
                    "signed release accepted: clearing the PSK slot"
                );
                Ok(())
            }
            Ok(false) => {
                tracing::info!(
                    peer = %caller_wg_public_key,
                    "release does not name the committed transaction that owns this peer's \
                     slot; answering without touching anything"
                );
                Ok(())
            }
            Err(error) => {
                tracing::warn!(
                    peer = %caller_wg_public_key,
                    ?error,
                    "could not apply the signed release to the PSK slot"
                );
                Err(PskReleaseRefusal::Internal)
            }
        }
    }
}

fn random_nonce() -> Result<[u8; 16]> {
    let mut nonce = [0u8; 16];
    aether::random::fill_public(&mut nonce)
        .map_err(|error| anyhow::anyhow!("the approved DRBG refused: {error}"))?;
    Ok(nonce)
}

impl GatewayHandler {
    /// The peer a certificate fingerprint is admitted for, ignoring where the
    /// connection comes from.
    async fn certificate_peer(&self, certificate_sha256: &str) -> Option<String> {
        // The registry first: it is the only place that knows about a leaf
        // issued after admission. The pins are the answer for a gateway with
        // no trust domain, and for a peer that has never renewed.
        if let Ok(now) = unix_time_now() {
            if let Some(identity) = self.registered_identity(certificate_sha256, now).await {
                return Some(identity.wg_public_key);
            }
        }
        self.network
            .read()
            .await
            .peers
            .iter()
            .find(|peer| {
                peer.key_negotiation_certificate_sha256.as_deref() == Some(certificate_sha256)
            })
            .map(|peer| peer.public_key.clone())
    }
}
