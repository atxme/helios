//! Peer admission and revocation.

use super::*;

/// An authorized WireGuard peer, as exposed to the UI.
///
/// The public key is public by nature; the PSK is never exposed, only its
/// presence is published.
///
/// The last four fields are the **runtime**, and they answer the question the
/// console is actually opened for: is this client connected right now. They
/// come from the data plane, not from the configuration, so they are absent
/// whenever the interface is down or the peer has never been seen — which is
/// why they are optional rather than zeroed. A peer showing `rx_bytes: 0`
/// because nothing was observed, and a peer showing `rx_bytes: 0` because it
/// really transferred nothing, are not the same fact.
#[derive(Serialize, Clone)]
pub struct PeerSummary {
    pub name: String,
    pub public_key: String,
    pub address: String,
    /// IPv6 VIP, `…/128`, when the peer has one; `null` otherwise. The same
    /// text form as [`NetworkPeerView::address_v6`], carried here so the
    /// console shows it on the row it already polls instead of joining a
    /// second request on the public key.
    pub address_v6: Option<String>,
    pub post_quantum: bool,
    pub admin: bool,
    /// `null` for a plain WireGuard peer, which has no negotiation floor.
    pub minimum_key_negotiation_mode: Option<ProtectionMode>,
    /// Seconds since the last successful handshake. `None` = never handshaked,
    /// or the data plane has not been observed since the interface came up.
    pub last_handshake_age_seconds: Option<u64>,
    /// The peer's current endpoint. It roams, so this value changes.
    pub endpoint: Option<String>,
    /// Bytes counted by the data plane, `None` when it was not observed.
    pub rx_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
}

impl PeerSummary {
    /// The configured half, with no runtime attached.
    ///
    /// Used as-is by admission and revocation: a peer that was just admitted
    /// has, by construction, never handshaked, and one that was just revoked
    /// no longer has a runtime worth reporting.
    pub(super) fn from_config(peer: &WgPeer) -> Self {
        Self {
            name: peer.name.clone(),
            public_key: peer.public_key.clone(),
            address: peer.address.clone(),
            address_v6: peer.address_v6.map(aether::net::format_vip_v6),
            post_quantum: peer.preshared_key.is_some(),
            admin: peer.admin,
            minimum_key_negotiation_mode: peer.minimum_key_negotiation_mode,
            last_handshake_age_seconds: None,
            endpoint: None,
            rx_bytes: None,
            tx_bytes: None,
        }
    }

    /// Attaches what the data plane last reported for this peer.
    pub(super) fn with_runtime(mut self, observed: &PeerStatus, now: SystemTime) -> Self {
        self.last_handshake_age_seconds = observed.last_handshake.and_then(|at| {
            // A handshake dated in the future means the clocks disagree, not
            // that the peer is fresh: reporting a negative age as a huge
            // unsigned number would show the peer as long dead.
            now.duration_since(at).ok().map(|age| age.as_secs())
        });
        self.endpoint = observed.endpoint.clone();
        self.rx_bytes = Some(observed.rx_bytes);
        self.tx_bytes = Some(observed.tx_bytes);
        self
    }
}

#[derive(Deserialize)]
pub struct PeerAdmitRequest {
    /// Friendly name, unique on the gateway.
    pub name: String,
    /// Client's Curve25519 public key, in base64.
    pub public_key: String,
    /// Authorizes this peer to mutate the control plane and updates.
    #[serde(default)]
    pub admin: bool,
    /// SHA-256 fingerprint of the client's key-negotiation leaf certificate.
    #[serde(default)]
    pub key_negotiation_certificate_sha256: Option<String>,
    /// SHA-256 fingerprint of the ML-DSA-65 application certificate.
    #[serde(default)]
    pub key_negotiation_pq_certificate_sha256: Option<String>,
    /// Persistent anti-downgrade floor.
    #[serde(default)]
    pub minimum_key_negotiation_mode: Option<ProtectionMode>,
    /// The client's TLS leaf itself, DER in base64.
    ///
    /// The fingerprints above are what `network.toml` pins; these two are what
    /// the certificate registry records, and it needs the objects rather than
    /// their digests — it verifies signatures made by them (spec §13.1). They
    /// are optional so a gateway without a trust domain keeps admitting peers
    /// exactly as before; supplied, they must agree with the fingerprints.
    #[serde(default)]
    pub key_negotiation_certificate: Option<String>,
    /// The client's ML-DSA-87 leaf, its JSON document in base64.
    #[serde(default)]
    pub key_negotiation_pq_certificate: Option<String>,
}

#[derive(Deserialize)]
pub struct PeerRevokeRequest {
    pub name: String,
}

/// Admits a peer and assigns it its VIP (ADR-004 §4).
///
/// # Why a dedicated route rather than a `POST /api/network`
///
/// `GET /api/network` returns a knowingly redacted view: no private key, no
/// PSK. A tool that read back this view, added a peer to it, and reposted it
/// would overwrite the configuration **without the other peers' PSKs**. But a
/// PSK slot filled on only one side makes every handshake of the affected
/// peer fail, with no recovery channel: the operator would cut themselves off
/// from their fleet while thinking they were adding a client. The mutation
/// must therefore be targeted and performed here, where the complete
/// configuration is known.
pub async fn peer_admit(
    State(s): State<AppState>,
    Json(body): Json<PeerAdmitRequest>,
) -> Result<Json<PeerSummary>, (StatusCode, String)> {
    let mut updated = s.network.read().await.duplicate();
    // The collision view takes the live WireGuard table as well as the
    // declared peers (`ADRESSAGE-IPV6.md` §3 bis.2, rule 2). This is the
    // snapshot the orchestrator republishes, not a fresh read of the backend:
    // it lags by at most one poll, and what it could miss — a peer added
    // since — is in the declared table anyway.
    let live_snapshot = s.peer_runtime.read().await.clone();
    let live: Vec<helios_provisioning::LivePeer<'_>> = live_snapshot
        .iter()
        .map(|peer| helios_provisioning::LivePeer {
            public_key: &peer.public_key,
            allowed_ips: &peer.allowed_ips,
        })
        .collect();
    // `ml_kem` unconditionally. The v4 default fell back to a plain WireGuard
    // peer when no PQ certificate was supplied, which quietly produced peers
    // whose first handshake was unprotected; the admission layer now refuses such a peer
    // outright, and naming the floor here makes the refusal say why.
    let minimum_mode = body
        .minimum_key_negotiation_mode
        .unwrap_or(ProtectionMode::MlKem);
    let admission = helios_provisioning::admit_with_key_negotiation(
        &mut updated,
        &live,
        &body.name,
        &body.public_key,
        body.admin,
        body.key_negotiation_certificate_sha256.as_deref(),
        body.key_negotiation_pq_certificate_sha256.as_deref(),
        minimum_mode,
    )
    .map_err(admission_status)?;
    let peer = &admission.peer;

    // The certificate registry **before** the configuration is written: a peer
    // in `network.toml` with no registry row is a client that connects and can
    // never renew, and nothing later says so. The reverse — a row for a peer
    // whose admission then failed to persist — is caught by the next
    // admission, which is idempotent for an unchanged peer.
    //
    // A readmission registers nothing: the peer's generation was recorded
    // when it was first admitted, and recording it again would replace
    // whatever renewal state the registry has kept since.
    if admission.outcome == AdmissionOutcome::Admitted {
        register_first_generation(&s, &body, peer).await?;
    }

    let summary = updated
        .peers
        .iter()
        .find(|declared| declared.name == peer.name)
        .map_or_else(|| PeerSummary::from_config(peer), PeerSummary::from_config);
    if admission.changed_config() {
        apply_network(&s, updated).await?;
    }

    tracing::info!(
        peer = %peer.name,
        vip = %peer.address,
        admin = peer.admin,
        outcome = ?admission.outcome,
        "peer admitted"
    );
    Ok(Json(summary))
}

/// Hands the peer's first generation to the certificate registry.
///
/// Three outcomes, and they are deliberately different: no trust domain means
/// nothing to record and the admission stands; a trust domain with no
/// certificates supplied is an admission that will not be able to renew, and
/// it is refused rather than left to be discovered later; anything else is the
/// registry's own answer.
async fn register_first_generation(
    s: &AppState,
    body: &PeerAdmitRequest,
    peer: &aether::WgPeer,
) -> Result<(), (StatusCode, String)> {
    use base64::Engine as _;

    let Some(handler) = s.trust_update.as_ref() else {
        return Ok(());
    };
    let decoder = base64::engine::general_purpose::STANDARD;
    let (Some(tls), Some(pq)) = (
        body.key_negotiation_certificate.as_deref(),
        body.key_negotiation_pq_certificate.as_deref(),
    ) else {
        return Err((
            StatusCode::BAD_REQUEST,
            "this gateway holds a trust domain, so admission also takes the client's two              certificates — the registry records the leaves themselves, not their digests.              `helios enroll` sends them; a caller that cannot must admit on a gateway              without a trust domain."
                .to_string(),
        ));
    };
    let tls = decoder
        .decode(tls.trim())
        .ok()
        .and_then(|der| DerCertificate::new(der).ok())
        .ok_or((
            StatusCode::BAD_REQUEST,
            "the client TLS certificate is not base64 DER".to_string(),
        ))?;
    let pq: PqCertificate = decoder
        .decode(pq.trim())
        .ok()
        .and_then(|json| serde_json::from_slice(&json).ok())
        .ok_or((
            StatusCode::BAD_REQUEST,
            "the client PQ certificate is not a base64 JSON document".to_string(),
        ))?;

    // Both halves of the same identity, checked against what admission just
    // pinned. Recording a leaf the peer table does not name would give the
    // gateway two answers about which certificate belongs to this peer.
    let declared_tls = peer
        .key_negotiation_certificate_sha256
        .as_deref()
        .unwrap_or_default();
    let declared_pq = peer
        .key_negotiation_pq_certificate_sha256
        .as_deref()
        .unwrap_or_default();
    if tls.fingerprint().to_hex() != declared_tls {
        return Err((
            StatusCode::BAD_REQUEST,
            "the TLS certificate does not hash to the fingerprint this admission pins".to_string(),
        ));
    }
    let pq_fingerprint =
        aether::certificates::gateway::pq_certificate_fingerprint(&pq).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "the PQ certificate cannot be canonically encoded".to_string(),
            )
        })?;
    if pq_fingerprint.to_hex() != declared_pq {
        return Err((
            StatusCode::BAD_REQUEST,
            "the PQ certificate does not hash to the fingerprint this admission pins".to_string(),
        ));
    }

    handler
        .admit_peer(&peer.name, &peer.public_key, tls, Box::new(pq))
        .await
        .map_err(|refusal| {
            (
                refusal.status(),
                "the certificate registry refused this peer's first generation".to_string(),
            )
        })
}

/// Removes a peer from admission.
///
/// This is not a cryptographic revocation: the peer drops at its next
/// handshake attempt, there is no revocation list (ADR-004).
pub async fn peer_revoke(
    State(s): State<AppState>,
    Json(body): Json<PeerRevokeRequest>,
) -> Result<Json<PeerSummary>, (StatusCode, String)> {
    let mut updated = s.network.read().await.duplicate();
    let peer = helios_provisioning::revoke(&mut updated, &body.name).map_err(admission_status)?;
    apply_network(&s, updated).await?;

    tracing::warn!(peer = %peer.name, "peer removed from admission");
    Ok(Json(PeerSummary::from_config(&peer)))
}

/// Translates an admission refusal into an HTTP code: each cause has its
/// own, so the caller can tell an input error from a state conflict.
fn admission_status(error: helios_provisioning::AdmissionError) -> (StatusCode, String) {
    use helios_provisioning::AdmissionError as E;
    let code = match &error {
        E::EmptyName
        | E::Key(_)
        | E::CertificateFingerprint
        // Both are refusals of an admission the caller can fix by supplying
        // what v5 requires — a PQ identity, and the `ml_kem` floor.
        | E::MissingNegotiationIdentity
        | E::FloorBelowMlKem(_) => StatusCode::BAD_REQUEST,
        E::NameTaken(_) | E::KeyTaken(_) | E::ReadmissionDiffers(_) => StatusCode::CONFLICT,
        E::Unknown(_) => StatusCode::NOT_FOUND,
        E::Ipam(_) => StatusCode::INSUFFICIENT_STORAGE,
        // The peer table holds an address the gateway cannot read: its
        // configuration is at fault, not the request.
        E::UndeclaredAddress { .. } => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (code, error.to_string())
}
