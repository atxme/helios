//! Read-only certificate views: the trust domain, a client's enrolment
//! material, peers and pending stages.

use super::*;

/// What a client needs in order to renew its own identity (spec §19).
///
/// Everything here is public: anchors, epochs and URLs. It is what an Orion
/// profile has to carry so that `certificate_renewal` can seed a trust store
/// without asking the network for it — a seed fetched at renewal time would be
/// a seed an attacker chooses.
///
/// Read from the gateway's registry rather than typed by an operator: eleven
/// values copied by hand between two shells is eleven places to paste the
/// wrong one, and the failure surfaces months later at 80 % of a leaf's life.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustEnrolmentView {
    pub trust_domain_id: String,
    pub ca_epoch: u64,
    pub ca_pq_public_key: String,
    pub ca_tls_epoch: u64,
    pub client_tls_ca_der: String,
    /// Generation the named peer's identity is at, right now.
    pub client_generation: u64,
    /// Epoch of the gateway leaf this domain serves, and the highest decision
    /// accepted about it (spec §13.1: both are `1` on a fresh installation).
    ///
    /// Carried because nothing else can teach them to a client. A trust store
    /// seeded at `0` while the registry sits at `1` is permanently *behind* on
    /// [`crate::certificates::TrustUpdateHandler::trust_update`]'s comparison,
    /// with no transition able to close the gap — an identity transition only
    /// moves a client from the decision it already holds to the next one, and
    /// there is no transition to epoch 1. The gateway would answer `503` to
    /// every poll, for the life of the profile.
    pub active_gateway_identity_epoch: u64,
    pub gateway_decision_epoch: u64,
    pub astra_authority_url: String,
    pub webauthn_rp_id: String,
    pub astra_policy_fingerprint: String,
    pub credential_registry_epoch: u64,
    /// The operator credentials of the domain, as `CA-PQ` signed them.
    ///
    /// Public: a binding carries a credential identifier and a public key, and
    /// the consumer is what authenticates it — Orion under the `CA-PQ` of its
    /// own profile, never under this gateway's word.
    ///
    /// Carried by the enrolment rather than fetched, because the one moment a
    /// client needs them is the one where it has no tunnel: recovering an
    /// expired identity (§7.5) names the credential that will approve it, and
    /// a client that learned that list over the tunnel it no longer has would
    /// have no list at all.
    #[serde(default)]
    pub astra_credential_bindings: Vec<aether::certificates::approval::AstraCredentialBinding>,
    pub astra_service_key_epoch: u64,
    pub astra_service_public_key: String,
}

/// The domain as an operator reads it — `GET /api/certificates`.
///
/// # Why the console gets its own read
///
/// Every other view of the registry answers a *client's* question, and is
/// therefore shaped by what that client may learn: the §19 enrolment block
/// covers one peer, and a trust update tells its caller about its own
/// identity and nothing else. An operator's question is the opposite one —
/// *what is the state of the whole domain* — and there is no client-facing
/// route that could answer it without becoming an oracle on other peers.
///
/// Everything here is public: anchors, epochs, fingerprints and expiry dates.
/// No private key, no PSK, no capability token, and no certificate body — a
/// console shows what an operator acts on, and nobody acts on a DER blob.
///
/// # Why one read and not one per peer
///
/// The peers are rendered next to the epochs they were issued under. Reading
/// them separately would let a screen pair a generation taken at one instant
/// with an anchor taken at another, and the pairs that never existed together
/// are exactly the ones an operator would investigate.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateDomainView {
    pub trust_domain_id: String,
    pub server_name: String,
    /// Unix instant this snapshot was taken, on the gateway's clock.
    ///
    /// Sent rather than assumed: the browser's clock is the operator's, and a
    /// workstation minutes off would draw the renewal ladder at the wrong rung
    /// for every leaf on the screen.
    pub now_unix: u64,
    pub ca_epoch: u64,
    /// SHA-256 of the `CA-PQ` anchor's public key, lowercase hex.
    pub ca_pq_fingerprint: String,
    /// A successor anchor is installed and waiting for its activation.
    pub ca_transition_pending: bool,
    pub ca_activation_at: Option<u64>,
    /// When the outgoing anchor is retired and `ca_epoch` finally moves.
    pub ca_retire_active_at: Option<u64>,
    /// The incoming anchor, for the operator to compare with the companion —
    /// §9.1 makes that comparison the check, not the signature alone.
    pub next_ca_fingerprint: Option<String>,
    pub client_tls_ca_epoch: u64,
    /// The client TLS anchor in service, lowercase hex. With the next one, what
    /// tells a resuming rotation that the gateway holds it, or has promoted it.
    pub client_tls_ca_fingerprint: String,
    pub next_client_tls_ca_fingerprint: Option<String>,
    pub client_tls_ca_transition_pending: bool,
    pub gateway_identity_epoch: u64,
    pub gateway_tls_fingerprint: String,
    pub gateway_pq_fingerprint: String,
    pub gateway_transition_pending: bool,
    pub gateway_activation_at: Option<u64>,
    /// End of the overlap: when the incoming leaf is promoted and the outgoing
    /// one is destroyed.
    pub gateway_retire_active_at: Option<u64>,
    /// Whether the staged transition has been distributed (spec §6.3). Past
    /// this point no abort is accepted and only the bounded rollback remains.
    pub gateway_transition_published: bool,
    /// End of a service rollback in force, absent when none is (spec §4.4).
    pub gateway_rollback_expires_at: Option<u64>,
    /// Why the daemon must be restarted, when the registry has moved past the
    /// leaf this process serves.
    ///
    /// The served identity is unsealed once and held for the life of the
    /// process, so every scheduled switch is a restart — including the expiry
    /// of a bounded rollback, which no clock in this daemon acts on. Absent
    /// means the leaf in service is still the one a fresh start would choose.
    pub gateway_restart_due: Option<String>,
    pub astra_authority_url: String,
    pub astra_service_key_epoch: u64,
    pub astra_policy_fingerprint: String,
    pub webauthn_rp_id: String,
    pub credential_registry_epoch: u64,
    /// Operator credentials the domain holds. Two is the floor a vault opens
    /// under, and an approval nobody can answer is what one leaves behind.
    pub credential_bindings: usize,
    /// The delegated issuer, absent until `astra issuer install` has run.
    pub issuer: Option<IssuerView>,
    pub peers: Vec<PeerCertificateView>,
}

/// The bounded delegation an ordinary renewal is issued under (spec §3.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerView {
    pub issuer_epoch: u64,
    pub lifecycle: aether::certificates::state::IssuerLifecycle,
    pub not_before: u64,
    pub not_after: u64,
    /// Whether it may sign **now** — which the lifecycle alone does not say:
    /// an `active` delegation past its `not_after` signs nothing.
    pub usable: bool,
}

/// One admitted peer's identity, as the registry holds it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerCertificateView {
    pub name: String,
    pub wg_public_key: String,
    pub generation: u64,
    pub not_before: u64,
    pub not_after: u64,
    /// Where the active leaf sits on the 80 / 90 / 95 % ladder of spec §4.3.
    pub phase: aether::certificates::window::ValidityPhase,
    pub revoked: bool,
    /// A candidate generation under lease, and how far it has got.
    pub pending: Option<PendingStageView>,
    /// A committed successor waiting for its activation instant.
    pub next_generation: Option<u64>,
    pub activation_at: Option<u64>,
    /// Fragments of a signed transaction still queued for this peer.
    ///
    /// Non-zero means the peer is behind and has not finished collecting what
    /// would bring it forward — the one state where `trust-update` is doing
    /// something rather than answering "you are current".
    pub distribution_chunks_pending: u16,
}

/// A candidate generation between staging and commit (spec §3.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingStageView {
    pub generation: u64,
    pub state: aether::certificates::state::PendingStageState,
    pub stage_expires_at: u64,
}

/// `GET /api/certificates`, on the admin surface.
///
/// `404` when the gateway has no trust domain, for the same reason
/// [`trust_enrolment`] answers `404`: an empty registry and an absent one are
/// different facts, and a console handed an empty list would draw a domain
/// with no clients rather than a gateway that was never initialised.
pub async fn domain(State(s): State<AppState>) -> Response {
    let Some(handler) = s.trust_update.as_ref() else {
        return (
            StatusCode::NOT_FOUND,
            "this gateway has no trust domain — run `heliosd init-trust-domain`",
        )
            .into_response();
    };
    match handler.domain().await {
        Ok(view) => (StatusCode::OK, Json(view)).into_response(),
        Err(refusal) => refusal.status().into_response(),
    }
}

/// `GET /api/key-negotiation/trust-enrolment/{public_key}`, on the admin
/// surface.
///
/// `404` and not an empty body, for the same reason `/api/key-negotiation`
/// answers `404`: a tool handed `null` would have to guess between "no trust
/// domain on this gateway", "this peer is not admitted" and "read failure",
/// and would emit a profile that cannot renew without saying so.
pub async fn trust_enrolment(
    State(s): State<AppState>,
    axum::extract::Path(public_key): axum::extract::Path<String>,
) -> Response {
    let Some(handler) = s.trust_update.as_ref() else {
        return (
            StatusCode::NOT_FOUND,
            "this gateway has no trust domain — run `heliosd init-trust-domain`",
        )
            .into_response();
    };
    match handler.trust_enrolment(public_key.trim()).await {
        Ok(view) => (StatusCode::OK, Json(view)).into_response(),
        Err(TrustUpdateRefusal::Rejected) => (
            StatusCode::NOT_FOUND,
            "no such admitted peer in the certificate registry",
        )
            .into_response(),
        Err(refusal) => refusal.status().into_response(),
    }
}
