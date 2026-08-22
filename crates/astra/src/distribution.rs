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
//! # Limite connue : le seul objet distribuable aujourd'hui est la délégation
//!
//! [`AstraIssuerAuthorization`] is the only transition object this authority
//! stores. CA transitions, gateway identity transitions and revocations are
//! signed by `CA-PQ` in the operator companion, and §0.6 gives them a home —
//! the companion returns them **once**, bound to a campaign, and Astra
//! persists them — but nothing writes that store yet. Until it does, a peer
//! behind only on an anchor still receives nothing, and the gateway still says
//! so out loud instead of answering «up to date».

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
