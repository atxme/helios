//! Production of the in-tunnel trust transactions — spec §8.1.1 and the
//! amendment of 22 August 2026 (§0.6).
//!
//! # The two problems this closes
//!
//! Transport was defined long before production was possible, and two
//! requirements stood in the way. Astra cannot reconstruct Orion's complete
//! local trust state, so it could not compute the `base_state_fingerprint` a
//! transaction is bound to; and its online half never holds `CA-PQ`, so it
//! could not sign the manifest the specification asked `CA-PQ` to sign. §0.6
//! settles both without weakening the anti-rollback:
//!
//! - the fingerprint stays the hash of Orion's **whole** local state, and
//!   travels inside the client's signed request. This module treats it as an
//!   opaque compare-and-swap token: it copies it into the manifest and never
//!   needs a preimage. The receiver recomputes it on its live state at commit,
//!   so anything that moved in between invalidates the transaction rather than
//!   applying a decision taken about a state that no longer exists;
//! - the manifest is signed by the **service key**. It authorizes attribution
//!   to a peer, the base state, the order and the atomic grouping — and no
//!   trust mutation whatsoever. Every object inside keeps the signature its own
//!   state machine demands, `CA-PQ` included. A compromised service key can
//!   therefore delay, omit or reorder a delivery, which was already inside its
//!   blast radius; it cannot fabricate a transition object.
//!
//! # Why nothing here decides what is true
//!
//! The gateway decided the peer is behind, from counters it holds. This module
//! answers a narrower question: which signed objects does this authority hold
//! that the peer's own epochs say it lacks? Where the two disagree the answer
//! is «nothing to distribute» — never an invented object, never a transaction
//! that would fail at the receiver after a full fragment cycle.
//!
//! # A transition reaches a peer only before it comes into force
//!
//! §8.1.1 refuses a transaction past its earliest activation, so an anchor
//! transition is distributable during `[not_before, activation_at)` and not
//! one second later — installing something that should already be in force as
//! if it were still ahead is exactly what that rule exists to stop. The
//! preparation delay of the rotation is therefore the window every peer has to
//! come back in, and `astra-signer rotate-ca-pq --prepare-days` is where it is
//! chosen. A peer that stays away longer is repaired by an operator, not by a
//! late delivery.
//!
//! # Limite connue : certaines transitions restent sans producteur
//!
//! [`AstraIssuerAuthorization`], the `CA-PQ` transition of §9.1 and emergency
//! revocations are what this authority holds. `CA-TLS` transitions are refused at the registry
//! rather than stored — it pins the epoch of that anchor without pinning the
//! anchor itself, so it could only check such an object against a value the
//! object carried. Gateway identity transitions have no producer. Pinning
//! `ca_tls_fingerprint` at `init-trust-domain` is what unblocks the first.

use std::sync::Arc;

use aether::certificates::{
    transport::{
        signing::{build_transaction, TransactionPlan},
        AuthenticatedTrustUpdateRequest, TrustUpdateChunk, TrustUpdateObject,
        TrustUpdateTransactionManifest, MAX_TRUST_UPDATE_RESPONSE_BYTES,
    },
    CertificateError,
};
use helios_api::internal::RelayedTrustUpdatePreparation;

use crate::service::AstraService;

/// How long a prepared transaction may be collected.
///
/// Ten minutes: several fragment round trips on a slow link, and far short of
/// the activation of anything it can carry. The manifest also refuses itself
/// past the earliest activation among its objects, so this is a ceiling on
/// collection, never a licence to apply something late.
pub const TRANSACTION_LIFETIME_SECS: u64 = 600;

/// Bytes one fragment's objects may occupy.
///
/// The manifest travels with **every** fragment, so the budget is the response
/// cap minus room for it. Half is deliberately coarse: a manifest is bounded
/// by 64 objects of fixed-width entries, nowhere near 32 KiB, and a tight
/// computation here would be a second place to keep the cap correct.
pub const CHUNK_BUDGET_BYTES: usize = MAX_TRUST_UPDATE_RESPONSE_BYTES / 2;

#[derive(Debug, thiserror::Error)]
pub enum PrepareError {
    #[error("the relayed request names a peer other than the one the gateway resolved")]
    CallerMismatch,
    #[error("the peer snapshot describes another identity")]
    PeerMismatch,
    #[error("the client request is refused: {0}")]
    Request(CertificateError),
    #[error("this authority holds no delegated issuer")]
    NoIssuer,
    #[error("the authority could not build this transaction: {0}")]
    Internal(CertificateError),
}

impl PrepareError {
    /// The bounded class the gateway — and through it the client — learns.
    pub fn refusal(&self) -> helios_api::certificates::TrustUpdateRefusal {
        use helios_api::certificates::TrustUpdateRefusal as Refusal;
        match self {
            Self::Internal(_) => Refusal::Internal,
            Self::NoIssuer => Refusal::Unavailable,
            _ => Refusal::Rejected,
        }
    }
}

/// Builds the transaction one lagging peer is missing, or nothing.
///
/// Everything is checked before a single object is selected: the gateway's
/// resolution matches the request's own copy, the snapshot describes the same
/// peer, and the request's signature verifies under the **active PQ leaf the
/// gateway holds** — not under a key the request carried. The last one is what
/// stops a gateway from relaying a request it wrote itself.
pub async fn prepare(
    service: &Arc<AstraService>,
    relayed: &RelayedTrustUpdatePreparation,
    now_unix: u64,
) -> Result<Option<(TrustUpdateTransactionManifest, Vec<TrustUpdateChunk>)>, PrepareError> {
    let caller = relayed.caller_wg_public_key;
    if relayed.request.request.client_wg_public_key != caller {
        return Err(PrepareError::CallerMismatch);
    }
    // The snapshot must describe the identity the gateway resolved, and its
    // leaf must be the one the snapshot's own active generation names. Both
    // are cheap, and both turn a disagreement between the two registries into
    // a refusal rather than a signature checked against the wrong key.
    let active = aether::certificates::gateway::pq_certificate_fingerprint(
        &relayed.peer.active_pq_certificate,
    )
    .map_err(PrepareError::Request)?;
    if !active.matches(&relayed.peer.state.active.pq_certificate_fingerprint) {
        return Err(PrepareError::PeerMismatch);
    }

    let (trust_domain_id, gateway_key, service_epoch, objects) = {
        let registry = service.registry.lock().await;
        let state = registry.state();

        // Both authorities that may have issued this leaf: the anchor, and the
        // delegated issuer an ordinary renewal chains to. Read from this
        // authority's registry, never from the request.
        let mut issuers = vec![&state.ca_public_key];
        if let Some(issuer) = &state.issuer {
            issuers.push(&issuer.authorization.pq_issuer_public_key);
        }
        // The active generation always; the next one only from its activation
        // — the same window the gateway applies, recomputed here rather than
        // relayed as a verdict somebody else reached.
        let mut acceptable = vec![relayed.peer.state.active.pq_certificate_fingerprint];
        if let (Some(next), Some(activation_at)) =
            (&relayed.peer.state.next, relayed.peer.state.activation_at)
        {
            if now_unix >= activation_at {
                acceptable.push(next.pq_certificate_fingerprint);
            }
        }
        relayed
            .request
            .verify(
                &issuers,
                &state.trust_domain_id,
                &state.gateway_wg_public_key,
                &caller,
                &acceptable,
                now_unix,
            )
            .map_err(PrepareError::Request)?;

        (
            state.trust_domain_id,
            state.gateway_wg_public_key,
            state.astra_service_key_epoch,
            select_objects(state, &relayed.request, now_unix),
        )
    };

    if objects.is_empty() {
        tracing::info!(
            peer = %caller,
            "preparation: this authority holds nothing this peer is missing"
        );
        return Ok(None);
    }

    // The earliest activation among the objects, which the manifest refuses
    // itself past. Read from the objects rather than chosen: a value picked
    // here could outlive an object that is already in force.
    let minimum_activation_at = objects
        .iter()
        .filter_map(activation_of)
        .min()
        .unwrap_or(u64::MAX);
    let expires_at = now_unix
        .checked_add(TRANSACTION_LIFETIME_SECS)
        .ok_or(PrepareError::Internal(CertificateError::ArithmeticOverflow))?;
    if now_unix >= minimum_activation_at {
        // Every object this authority could send is already in force. Saying
        // nothing beats emitting a transaction the receiver refuses on the
        // rule that exists to stop late application.
        tracing::warn!(
            peer = %caller,
            "preparation: every object this peer lacks is already past its activation"
        );
        return Ok(None);
    }

    let plan = TransactionPlan {
        transaction_id: crate::renewal::fresh_id().map_err(PrepareError::Internal)?,
        trust_domain_id,
        gateway_wg_public_key: gateway_key,
        client_wg_public_key: caller,
        // The opaque token, copied. Its preimage is Orion's business.
        base_state_fingerprint: relayed.request.request.base_state_fingerprint,
        created_at: now_unix,
        expires_at,
        minimum_activation_at,
        authority_epoch: service_epoch,
        authority_private_key: &service.service_private_key,
    };
    let built =
        build_transaction(objects, &plan, CHUNK_BUDGET_BYTES).map_err(PrepareError::Internal)?;
    tracing::info!(
        peer = %caller,
        objects = built.0.objects.len(),
        chunks = built.1.len(),
        "preparation: transaction built and bound to the caller's base state"
    );
    Ok(Some(built))
}

/// Which stored objects this peer's own epochs say it lacks.
fn select_objects(
    state: &crate::registry::AstraState,
    request: &AuthenticatedTrustUpdateRequest,
    now_unix: u64,
) -> Vec<TrustUpdateObject> {
    let mut objects = Vec::new();
    // Anchor transitions first, and by the receiver's own epoch. An operator
    // campaign produced them; this authority only decides who is behind, and
    // «behind» is a comparison the client itself signed.
    for stored in &state.transitions {
        if let TrustUpdateObject::CaTransition(transition) = &stored.object {
            let in_force_later = now_unix < transition.window.activation_at;
            let names_the_peers_anchor = request.request.ca_epoch == transition.current_ca_epoch;
            if in_force_later && names_the_peers_anchor {
                objects.push(stored.object.clone());
            }
        }
    }
    // Revocation counters are independent from certificate generations and
    // are not carried by `TrustUpdateRequest`. While a revocation's own
    // signed validity remains, offer it unconditionally; receivers deduplicate
    // its tombstone, while a client that missed it gets another chance to
    // learn the decision.
    for stored in &state.transitions {
        if let TrustUpdateObject::CertificateRevocation(revocation) = &stored.object {
            let still_relevant = revocation
                .revoked_tls_not_after
                .into_iter()
                .chain(revocation.revoked_pq_not_after)
                .any(|not_after| now_unix < not_after);
            if still_relevant {
                objects.push(stored.object.clone());
            }
        }
    }
    // The client TLS anchor, on the receiver's own epoch. Before
    // `activation_at` only: §8.1.1 refuses a transaction past its first
    // activation, and installing as future what should already be in force is
    // exactly what that rule forbids.
    for stored in &state.transitions {
        if let TrustUpdateObject::ClientTlsCaTransition(transition) = &stored.object {
            let in_force_later = now_unix < transition.window.activation_at;
            let names_the_peers_anchor =
                request.request.ca_tls_epoch == transition.current_ca_tls_epoch;
            if in_force_later && names_the_peers_anchor {
                objects.push(stored.object.clone());
            }
        }
    }
    // The gateway identity, and only once §11.1 step 6 has let it leave. A
    // client is offered the decision that moves it from the state it signed:
    // its own decision epoch, and the leaf it says it is pinning. A client on
    // another state would be handed a transition its own `install_transition`
    // refuses, costing it a full poll cycle to discover.
    for stored in &state.transitions {
        if !stored.published {
            continue;
        }
        match &stored.object {
            TrustUpdateObject::GatewayIdentityTransition(transition) => {
                let follows_the_clients_decision = request
                    .request
                    .gateway_decision_epoch
                    .checked_add(1)
                    .is_some_and(|next| next == transition.gateway_identity_epoch);
                let names_the_clients_leaf = request
                    .request
                    .active_gateway_certificate_fingerprint
                    .matches(&transition.active_gateway_certificate_fingerprint);
                if follows_the_clients_decision
                    && names_the_clients_leaf
                    && now_unix < transition.window.not_after
                {
                    objects.push(stored.object.clone());
                }
            }
            // The tombstone goes to the clients that hold the transition it
            // cancels — they are the ones whose decision epoch already *is*
            // that epoch, and the only ones whose `apply_abort` can act on it.
            //
            // Limite connue : un client qui n'a jamais reçu la transition
            // reste à l'époque précédente et refusera correctement le saut
            // vers la suivante (§6.3), sans pouvoir récupérer ce tombstone
            // ici. Lui servir un avortement qu'il ne peut pas appliquer ferait
            // échouer toute la transaction plutôt qu'une partie.
            TrustUpdateObject::GatewayTransitionAbort(abort) => {
                if request.request.gateway_decision_epoch == abort.gateway_identity_epoch {
                    objects.push(stored.object.clone());
                }
            }
            _ => {}
        }
    }
    // The delegation. A client whose `issuer_epoch` is behind cannot build the
    // chain of a delegated leaf at all: it holds the anchor and sees a leaf
    // signed by an intermediate it has never been told about.
    if let Some(issuer) = &state.issuer {
        if issuer.is_usable(now_unix) && request.request.issuer_epoch < issuer.issuer_epoch {
            objects.push(TrustUpdateObject::AstraIssuerAuthorization(Box::new(
                issuer.authorization.clone(),
            )));
        }
    }
    objects
}

/// When an object comes into force, for the objects that carry a window.
///
/// `None` for the ones that apply on receipt — a delegation is usable from its
/// `not_before`, which is in the past by the time it is distributed, and it is
/// not something the receiver may install «too late».
fn activation_of(object: &TrustUpdateObject) -> Option<u64> {
    match object {
        TrustUpdateObject::CaTransition(transition) => Some(transition.window.activation_at),
        TrustUpdateObject::ClientTlsCaTransition(transition) => {
            Some(transition.window.activation_at)
        }
        TrustUpdateObject::AstraServiceKeyTransition(transition) => {
            Some(transition.window.activation_at)
        }
        TrustUpdateObject::GatewayIdentityTransition(transition) => {
            Some(transition.window.activation_at)
        }
        TrustUpdateObject::ClientCertificateStageAuthorization(authorization) => {
            Some(authorization.window.activation_at)
        }
        TrustUpdateObject::ClientCertificateRotationGrant(grant) => {
            Some(grant.window.activation_at)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::certificates::authority::CaTransition;
    use aether::certificates::encoding::{
        generate_ml_dsa_87_keypair, Fingerprint, Id16, MlDsa87Signature, TrustDomainId,
        WireGuardKey,
    };
    use aether::certificates::transport::TrustUpdateRequest;
    use aether::certificates::window::TransitionWindow;
    use aether::certificates::{
        approval::AstraPolicyPin, CERTIFICATE_FORMAT_VERSION, CERTIFICATE_PROTOCOL_VERSION,
    };
    use aether::key_negotiation::{PqCertificate, PqCertificateRole, PQ_CERTIFICATE_VERSION};

    /// A state holding one signed anchor transition, and nothing else.
    ///
    /// The signatures are real: `select_objects` never checks one — the
    /// registry did that when it accepted the object — but building the
    /// fixture the honest way is what keeps this test from passing on an
    /// object the real path would have refused.
    fn state_with_transition(current_ca_epoch: u64) -> crate::registry::AstraState {
        let (ca_private, ca_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let (next_private, next_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let (_, service) = generate_ml_dsa_87_keypair().expect("keygen");
        let trust_domain_id = TrustDomainId::new([1; 16]).expect("domain");
        let transition = CaTransition {
            format_version: CERTIFICATE_FORMAT_VERSION,
            trust_domain_id,
            current_ca_epoch,
            next_ca_epoch: current_ca_epoch + 1,
            current_ca_fingerprint: ca_public.authority_fingerprint(),
            next_ca_fingerprint: next_public.authority_fingerprint(),
            next_ca_public_key: next_public,
            window: TransitionWindow::new(1_000, 90_000, 200_000).expect("window"),
            current_ca_signature: MlDsa87Signature::placeholder(),
            next_ca_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&ca_private, &next_private)
        .expect("signing");

        crate::registry::AstraState {
            trust_domain_id,
            gateway_wg_public_key: WireGuardKey::from_bytes([1; 32]),
            server_name: "gateway.example".into(),
            authority_url: "https://astra.example".into(),
            webauthn_rp_id: "astra.example".into(),
            astra_policy_fingerprint: AstraPolicyPin::new(Fingerprint::of(b"policy"))
                .expect("policy pin"),
            credential_registry_epoch: 1,
            ca_epoch: current_ca_epoch,
            ca_public_key: ca_public,
            ca_tls_epoch: 1,
            ca_tls_fingerprint: Some(Fingerprint::of(b"client tls ca")),
            ca_tls_rotation: None,
            astra_service_key_epoch: 1,
            astra_service_public_key: service,
            issuer: None,
            transitions: vec![crate::registry::StoredTransition {
                campaign_id: Id16::new([7; 16]).expect("id"),
                accepted_at: 2_000,
                object: TrustUpdateObject::CaTransition(Box::new(transition)),
                published: true,
                credential_registry: None,
            }],
            peers: Default::default(),
            status_epochs: Default::default(),
            audit: Default::default(),
        }
    }

    fn request(ca_epoch: u64) -> AuthenticatedTrustUpdateRequest {
        AuthenticatedTrustUpdateRequest {
            request: TrustUpdateRequest {
                protocol_version: CERTIFICATE_PROTOCOL_VERSION,
                request_id: Id16::new([3; 16]).expect("id"),
                trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
                gateway_wg_public_key: WireGuardKey::from_bytes([1; 32]),
                client_wg_public_key: WireGuardKey::from_bytes([2; 32]),
                ca_epoch,
                ca_tls_epoch: 1,
                astra_service_key_epoch: 1,
                issuer_epoch: 0,
                active_gateway_identity_epoch: 1,
                gateway_decision_epoch: 1,
                client_identity_generation: 4,
                active_gateway_tls_certificate_fingerprint: Fingerprint::of(b"gateway tls"),
                active_gateway_certificate_fingerprint: Fingerprint::of(b"gateway pq"),
                active_client_tls_certificate_fingerprint: Fingerprint::of(b"client tls"),
                active_client_pq_certificate_fingerprint: Fingerprint::of(b"client pq"),
                client_pq_certificate_fingerprint: Fingerprint::of(b"client pq"),
                base_state_fingerprint: Fingerprint::of(b"local state"),
            },
            certificate: PqCertificate {
                version: PQ_CERTIFICATE_VERSION,
                serial: [1; 16],
                subject: "orion".into(),
                issuer: "CA-PQ".into(),
                role: PqCertificateRole::Client,
                wireguard_public_key: WireGuardKey::from_bytes([2; 32]).to_base64(),
                ml_dsa_87_public_key: String::new(),
                not_before_unix: 0,
                not_after_unix: 100_000,
                ml_dsa_87_signature: String::new(),
            },
            ml_dsa_87_signature: MlDsa87Signature::placeholder(),
        }
    }

    fn state_with_revocation() -> crate::registry::AstraState {
        use aether::certificates::revocation::{
            EmergencyCertificateRevocation, RevocationReason, RevocationScope,
        };

        let mut state = state_with_transition(1);
        let (ca_private, ca_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let revocation = EmergencyCertificateRevocation {
            format_version: CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: state.trust_domain_id,
            ca_epoch: 1,
            scope: RevocationScope::Client,
            identity_key: WireGuardKey::from_bytes([9; 32]),
            server_name: None,
            revocation_epoch: 1,
            revoked_tls_fingerprint: Some(Fingerprint::of(b"withdrawn tls")),
            revoked_tls_not_after: Some(50_000),
            revoked_pq_fingerprint: Some(Fingerprint::of(b"withdrawn pq")),
            revoked_pq_not_after: Some(60_000),
            effective_at: 2_000,
            reason: RevocationReason::KeyCompromise,
            replacement_transition_fingerprint: None,
            ca_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&ca_private)
        .expect("signing");
        state.ca_public_key = ca_public;
        state.transitions = vec![crate::registry::StoredTransition {
            campaign_id: Id16::new([8; 16]).expect("id"),
            accepted_at: 2_000,
            object: TrustUpdateObject::CertificateRevocation(Box::new(revocation)),
            published: true,
            credential_registry: None,
        }];
        state
    }

    /// A peer still on the outgoing anchor is exactly who a transition is for.
    #[test]
    fn a_peer_behind_on_the_anchor_is_offered_the_transition() {
        let state = state_with_transition(1);
        let selected = select_objects(&state, &request(1), 2_000);
        assert_eq!(selected.len(), 1);
        assert!(matches!(selected[0], TrustUpdateObject::CaTransition(_)));
    }

    /// A peer that already moved must not be sent a transition it applied: it
    /// would be a transaction refused after a whole fragment cycle.
    #[test]
    fn a_peer_already_on_the_successor_is_offered_nothing() {
        let state = state_with_transition(1);
        assert!(select_objects(&state, &request(2), 2_000).is_empty());
    }

    /// §8.1.1 refuses a transaction past its earliest activation, so offering
    /// one then would be building something the receiver must reject. The
    /// preparation delay is the window every peer has to come back in.
    #[test]
    fn past_the_activation_the_transition_is_no_longer_offered() {
        let state = state_with_transition(1);
        assert_eq!(select_objects(&state, &request(1), 89_999).len(), 1);
        assert!(select_objects(&state, &request(1), 90_000).is_empty());
    }

    /// The gateway decision the client's own request says it is behind on.
    fn state_with_gateway_transition(published: bool) -> crate::registry::AstraState {
        use aether::certificates::authority::RotationReason;
        use aether::certificates::gateway::GatewayIdentityTransition;

        let mut state = state_with_transition(1);
        let transition = GatewayIdentityTransition {
            format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            ca_epoch: 1,
            gateway_identity_epoch: 2,
            gateway_wg_public_key: WireGuardKey::from_bytes([1; 32]),
            server_name: "gateway.example".into(),
            active_gateway_tls_certificate_fingerprint: Fingerprint::of(b"gateway tls"),
            next_gateway_tls_certificate: None,
            active_gateway_certificate_fingerprint: Fingerprint::of(b"gateway pq"),
            next_gateway_certificate: None,
            window: aether::certificates::window::TransitionWindow::new(1_000, 90_000, 150_000)
                .expect("window"),
            reason: RotationReason::Scheduled,
            ca_signature: MlDsa87Signature::placeholder(),
        };
        state.transitions = vec![crate::registry::StoredTransition {
            campaign_id: Id16::new([9; 16]).expect("id"),
            accepted_at: 2_000,
            object: TrustUpdateObject::GatewayIdentityTransition(Box::new(transition)),
            published,
            credential_registry: None,
        }];
        state
    }

    /// §6.3 orders it: nothing leaves before the authority has persisted the
    /// publication, and until then an abort is still legitimate.
    #[test]
    fn an_unpublished_gateway_transition_is_offered_to_nobody() {
        let state = state_with_gateway_transition(false);
        assert!(select_objects(&state, &request(1), 2_000).is_empty());
    }

    #[test]
    fn a_published_gateway_transition_reaches_the_client_it_moves() {
        let state = state_with_gateway_transition(true);
        let selected = select_objects(&state, &request(1), 2_000);
        assert!(selected
            .iter()
            .any(|object| matches!(object, TrustUpdateObject::GatewayIdentityTransition(_))));

        // Past `not_after` the decision is spent: the successor is active and
        // the outgoing leaf is gone.
        assert!(!select_objects(&state, &request(1), 150_000)
            .iter()
            .any(|object| matches!(object, TrustUpdateObject::GatewayIdentityTransition(_))));
    }

    /// A client pinning another gateway leaf would refuse this decision after
    /// collecting every fragment of it.
    #[test]
    fn a_client_on_another_gateway_leaf_is_offered_no_transition() {
        let state = state_with_gateway_transition(true);
        let mut elsewhere = request(1);
        elsewhere.request.active_gateway_certificate_fingerprint =
            Fingerprint::of(b"another gateway leaf");
        assert!(!select_objects(&state, &elsewhere, 2_000)
            .iter()
            .any(|object| matches!(object, TrustUpdateObject::GatewayIdentityTransition(_))));
    }

    fn state_with_client_tls_ca_rotation() -> crate::registry::AstraState {
        use aether::certificates::authority::ClientTlsCaTransition;

        let (ca_private, ca_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let mut state = state_with_transition(1);
        state.ca_public_key = ca_public;
        let active = Fingerprint::of(b"client tls ca");
        let transition = ClientTlsCaTransition {
            format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            ca_epoch: 1,
            current_ca_tls_epoch: 1,
            next_ca_tls_epoch: 2,
            active_client_tls_ca_fingerprint: active,
            next_client_tls_ca_certificate: aether::certificates::test_x509::client_material(
                "successor",
            )
            .authority,
            window: aether::certificates::window::TransitionWindow::new(1_000, 90_000, 150_000)
                .expect("window"),
            ca_pq_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&ca_private)
        .expect("sign");
        state.transitions = vec![crate::registry::StoredTransition {
            campaign_id: Id16::new([6; 16]).expect("id"),
            accepted_at: 2_000,
            object: TrustUpdateObject::ClientTlsCaTransition(Box::new(transition)),
            published: true,
            credential_registry: None,
        }];
        state
    }

    /// The client anchor follows the receiver's own epoch, like the `CA-PQ`
    /// one, and stops being offered once it is in force.
    #[test]
    fn a_peer_behind_on_the_client_tls_anchor_is_offered_its_rotation() {
        let state = state_with_client_tls_ca_rotation();
        let selected = select_objects(&state, &request(1), 2_000);
        assert!(selected
            .iter()
            .any(|object| matches!(object, TrustUpdateObject::ClientTlsCaTransition(_))));

        // Already on the successor: nothing to hand over.
        let mut ahead = request(1);
        ahead.request.ca_tls_epoch = 2;
        assert!(select_objects(&state, &ahead, 2_000).is_empty());
        // Past the activation, §8.1.1 refuses the transaction anyway.
        assert!(select_objects(&state, &request(1), 90_000).is_empty());
    }

    #[test]
    fn a_revocation_is_offered_until_its_last_signed_expiry() {
        let state = state_with_revocation();
        let selected = select_objects(&state, &request(1), 59_999);
        assert_eq!(selected.len(), 1);
        assert!(matches!(
            selected[0],
            TrustUpdateObject::CertificateRevocation(_)
        ));
        assert!(select_objects(&state, &request(1), 60_000).is_empty());
    }
}
