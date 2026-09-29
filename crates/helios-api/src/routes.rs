use std::time::SystemTime;

use aether::{
    certificates::encoding::DerCertificate,
    key_negotiation::{PqCertificate, ProtectionMode},
    NetworkConfig, OrchestratorCmd, SecretString, WgPeer,
};
use axum::{extract::State, http::StatusCode, Json};
use helios_firewall::ruleset;
use helios_wireguard::PeerStatus;
use serde::{Deserialize, Serialize};

use crate::certificates::TrustUpdateRefusalStatus;
use crate::AppState;

#[derive(Serialize)]
pub struct StatusResponse {
    pub state: String,
    pub version: &'static str,
    /// Uplinks, in order of preference. Several when the gateway has a cable
    /// and a radio: the firewall permits them all, the kernel picks.
    pub wan_ifaces: Vec<String>,
    pub lan_ifaces: Vec<String>,
    pub wg_peers: Vec<String>,
    pub allow_ssh_from: Vec<String>,
    /// Out-of-band administration interfaces, so an operator can see the way
    /// back in without reading `network.toml` on the gateway.
    pub admin_ifaces: Vec<String>,
    pub peers: Vec<PeerSummary>,
    pub wg_iface: String,
    pub wg_listen_port: Option<u16>,
    /// Public UDP port of the pre-WireGuard key negotiation, `None` when the
    /// gateway doesn't run the service. Exposed next to `wg_listen_port`
    /// because the two are redirected together on the box: a UI that only
    /// showed one would hide half of what has to be opened.
    pub key_negotiation_port: Option<u16>,
    pub dry_run: bool,
    pub split_tunnel_cidrs: Vec<String>,
    pub mss_clamp: Option<u16>,
    pub captive_portal_gateway: Option<String>,
    /// Age beyond which a handshake no longer proves a peer is there.
    ///
    /// Published rather than left for the console to hardcode: this is the
    /// same threshold the orchestrator uses to decide whether the kill-switch
    /// lifts, and an interface applying its own would eventually report a
    /// client as connected after the firewall had already cut it.
    pub handshake_stale_after_seconds: u64,
}

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
    pub post_quantum: bool,
    pub admin: bool,
    pub minimum_key_negotiation_mode: ProtectionMode,
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
    fn from_config(peer: &WgPeer) -> Self {
        Self {
            name: peer.name.clone(),
            public_key: peer.public_key.clone(),
            address: peer.address.clone(),
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
    fn with_runtime(mut self, observed: &PeerStatus, now: SystemTime) -> Self {
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

/// Public view of the network configuration.
///
/// It is deliberately distinct from [`NetworkConfig`]: a serialization
/// regression therefore cannot reintroduce the WireGuard private key or the
/// PSKs into `GET /api/network`.
#[derive(Serialize)]
pub struct NetworkConfigView {
    pub wan_ifaces: Vec<String>,
    pub lan_ifaces: Vec<String>,
    pub allow_ssh_from: Vec<String>,
    /// Exposed for the same reason as [`Self::allow_dhcp_on_wan`], and the
    /// cost of omitting it is higher: a view that dropped it would erase the
    /// out-of-band administration path on the first config reload from the
    /// UI, and the gateway would become unreachable at the next restart of
    /// `heliosd` — precisely the failure this field exists to prevent.
    pub admin_ifaces: Vec<String>,
    /// Deliberately exposed: it isn't a secret, and a view that omitted it
    /// would drop the field back to `false` on the first config reload from
    /// the UI — the gateway would lose its lease hours later, with nothing
    /// tying the failure to the setting.
    pub allow_dhcp_on_wan: bool,
    /// Exposed for the same reason as `allow_dhcp_on_wan`: a view that
    /// omitted it would reset it to `false` on the first reload from the UI.
    pub allow_client_internet: bool,
    pub admin_iface: Option<String>,
    pub split_tunnel_cidrs: Vec<String>,
    pub wg_iface: String,
    pub wg_private_key_configured: bool,
    /// Gateway's WireGuard public key — public by nature, it's the
    /// `peer_public_key` value of client profiles. `None` as long as no
    /// identity is resolved. Deriving it here spares the operator from
    /// having to copy it out of the terminal where they ran
    /// `heliosd init-identity`.
    pub wg_public_key: Option<String>,
    pub wg_address: String,
    pub wg_listen_port: u16,
    pub key_negotiation_port: Option<u16>,
    pub peers: Vec<NetworkPeerView>,
    pub static_peer_addrs: Vec<String>,
    pub escrow_public_key: Option<String>,
}

#[derive(Serialize)]
pub struct NetworkPeerView {
    pub name: String,
    pub public_key: String,
    pub address: String,
    pub preshared_key_configured: bool,
    pub key_negotiation_certificate_sha256: Option<String>,
    pub key_negotiation_pq_certificate_sha256: Option<String>,
    pub minimum_key_negotiation_mode: ProtectionMode,
    pub admin: bool,
}

impl From<&NetworkConfig> for NetworkConfigView {
    fn from(config: &NetworkConfig) -> Self {
        Self {
            wan_ifaces: config.wan_ifaces.clone(),
            lan_ifaces: config.lan_ifaces.clone(),
            allow_ssh_from: config.allow_ssh_from.clone(),
            admin_ifaces: config.admin_ifaces.clone(),
            allow_dhcp_on_wan: config.allow_dhcp_on_wan,
            allow_client_internet: config.allow_client_internet,
            admin_iface: config.admin_iface.clone(),
            split_tunnel_cidrs: config.split_tunnel_cidrs.clone(),
            wg_iface: config.wg_iface.clone(),
            wg_private_key_configured: !config.wg_private_key.is_empty(),
            // The **public** half is what this view publishes; the private
            // one is exposed only to derive it and never reaches the JSON.
            wg_public_key: aether::wg::public_from_private(config.wg_private_key.expose()).ok(),
            wg_address: config.wg_address.clone(),
            wg_listen_port: config.wg_listen_port,
            key_negotiation_port: config.key_negotiation_port,
            peers: config
                .peers
                .iter()
                .map(|peer| NetworkPeerView {
                    name: peer.name.clone(),
                    public_key: peer.public_key.clone(),
                    address: peer.address.clone(),
                    preshared_key_configured: peer.preshared_key.is_some(),
                    key_negotiation_certificate_sha256: peer
                        .key_negotiation_certificate_sha256
                        .clone(),
                    key_negotiation_pq_certificate_sha256: peer
                        .key_negotiation_pq_certificate_sha256
                        .clone(),
                    minimum_key_negotiation_mode: peer.minimum_key_negotiation_mode,
                    admin: peer.admin,
                })
                .collect(),
            static_peer_addrs: config.static_peer_addrs.clone(),
            escrow_public_key: config.escrow_public_key.clone(),
        }
    }
}

#[derive(Serialize)]
pub struct CmdResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl CmdResponse {
    fn ok() -> Self {
        Self {
            ok: true,
            error: None,
        }
    }
    fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(msg.into()),
        }
    }
}

#[derive(Serialize)]
pub struct FirewallRulesResponse {
    pub rules: String,
    pub default_verdict: String,
    pub dry_run: bool,
}

#[derive(Deserialize)]
pub struct ApplyRulesRequest {
    pub rules: String,
}

#[derive(Deserialize)]
pub struct SplitTunnelRequest {
    pub cidrs: Vec<String>,
}

#[derive(Deserialize)]
pub struct GatewayKeyRequest {
    /// New Curve25519 private key for the gateway, in base64.
    ///
    /// A [`SecretString`] rather than a `String`: the key arrives here from
    /// the wire, and this is the first type that holds it. Deserializing
    /// straight into the secret is what ADR-006 §5 asks for — parsing into a
    /// bare `String` first would leave a copy no `Drop` ever clears.
    pub private_key: SecretString,
}

/// Replaces the gateway's WireGuard private key and reseals it.
///
/// **Reachable only through the tunnel**: like this entire API, the firewall
/// restricts it to `admin_iface`. An identity rotation must never be
/// attempted from the Internet.
///
/// The TPM sealing secret never transits through this crate: this only
/// validates the shape and forwards it to the orchestrator, sole holder of
/// the secret. Here we reject early what is manifestly invalid, so an absurd
/// key never travels all the way to the TPM.
pub async fn gateway_key_set(
    State(s): State<AppState>,
    Json(body): Json<GatewayKeyRequest>,
) -> Result<Json<CmdResponse>, (StatusCode, String)> {
    use base64::Engine as _;

    let key = body.private_key.expose().trim();
    let raw = base64::engine::general_purpose::STANDARD
        .decode(key)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("undecodable key: {e}")))?;
    if raw.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "key of {} bytes instead of 32 — this is not a Curve25519 key",
                raw.len()
            ),
        ));
    }

    let ok = s
        .cmd_tx
        .send(OrchestratorCmd::UpdateGatewayKey(key.into()))
        .await
        .is_ok();
    Ok(Json(if ok {
        CmdResponse::ok()
    } else {
        CmdResponse::err("orchestrator unreachable")
    }))
}

pub async fn status(State(s): State<AppState>) -> Json<StatusResponse> {
    let state = s.tunnel_state.read().await;
    let policy = s.policy.read().await;
    let network = s.network.read().await;

    // The runtime is matched to the configuration by public key, never by
    // name: a peer can be renamed in `network.toml` while the data plane keeps
    // serving the same key, and matching on the name would silently attach one
    // client's traffic figures to another's row.
    let observed = s.peer_runtime.read().await;
    let now = SystemTime::now();
    let peers: Vec<PeerSummary> = network
        .peers
        .iter()
        .map(|p| {
            let summary = PeerSummary::from_config(p);
            match observed.iter().find(|o| o.public_key_b64() == p.public_key) {
                Some(status) => summary.with_runtime(status, now),
                None => summary,
            }
        })
        .collect();
    drop(observed);

    Json(StatusResponse {
        state: state.as_str().to_string(),
        version: env!("CARGO_PKG_VERSION"),
        wan_ifaces: network.wan_ifaces.clone(),
        lan_ifaces: network.lan_ifaces.clone(),
        wg_peers: network.wg_peers(),
        allow_ssh_from: network.allow_ssh_from.clone(),
        admin_ifaces: network.admin_ifaces.clone(),
        peers,
        wg_iface: network.wg_iface.clone(),
        wg_listen_port: policy.wg_listen_port,
        key_negotiation_port: network.key_negotiation_port,
        dry_run: s.dry_run,
        split_tunnel_cidrs: policy.split_tunnel_cidrs.clone(),
        mss_clamp: policy.mss_clamp,
        captive_portal_gateway: policy.captive_portal_gateway.clone(),
        handshake_stale_after_seconds: helios_wireguard::HANDSHAKE_STALE_AFTER_SECS,
    })
}

/// Public key-negotiation material, as an Orion profile pins it.
///
/// Distinct from the WireGuard identity: this one authenticates the
/// *negotiation*, not the tunnel. Everything here is a certificate — nothing
/// in this view is secret, and the sealed private halves cannot reach it.
#[derive(Serialize)]
pub struct KeyNegotiationView {
    pub port: Option<u16>,
    /// Name the gateway certificate authenticates, read from the PQ
    /// certificate's subject rather than reconfigured: the two could not
    /// disagree without the pinning failing anyway.
    pub server_name: String,
    /// DER gateway certificate, base64 — Orion's `gateway_ca_der`.
    pub gateway_ca_der: String,
    /// JSON ML-DSA-65 gateway certificate, base64 — Orion's
    /// `gateway_pq_certificate`.
    pub gateway_pq_certificate: String,
    /// Fingerprint the operator compares with what Orion displays.
    pub pq_certificate_sha256: String,
    /// WireGuard public key this certificate is bound to. A profile pinning
    /// it against another peer key is refused by Orion at import.
    pub wireguard_public_key: String,
}

/// Publishes the negotiation certificates, or explains their absence.
///
/// `404` rather than an empty body: a tool that received `null` would have to
/// guess between "feature absent", "not initialized yet" and "read failure",
/// and would end up emitting a profile whose pinning could never succeed.
pub async fn key_negotiation_get(
    State(s): State<AppState>,
) -> Result<Json<KeyNegotiationView>, (StatusCode, String)> {
    use base64::Engine as _;

    let material = s.key_negotiation.as_ref().ok_or((
        StatusCode::NOT_FOUND,
        "this gateway runs no key-negotiation service — build heliosd with the \
         `key-negotiation` feature, then run `heliosd init-key-negotiation`"
            .to_string(),
    ))?;
    let certificate: aether::key_negotiation::PqCertificate =
        serde_json::from_slice(&material.pq_certificate_json).map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "the gateway PQ certificate on disk is unreadable".to_string(),
            )
        })?;
    let fingerprint = certificate.fingerprint().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "the gateway PQ certificate cannot be fingerprinted".to_string(),
        )
    })?;
    let encoder = base64::engine::general_purpose::STANDARD;
    Ok(Json(KeyNegotiationView {
        port: s.network.read().await.key_negotiation_port,
        server_name: certificate.subject.clone(),
        gateway_ca_der: encoder.encode(&material.certificate_der),
        gateway_pq_certificate: encoder.encode(&material.pq_certificate_json),
        pq_certificate_sha256: fingerprint,
        wireguard_public_key: certificate.wireguard_public_key,
    }))
}

/// Returns the current network configuration without any secret.
pub async fn network_get(State(s): State<AppState>) -> Json<NetworkConfigView> {
    let network = s.network.read().await;
    Json(NetworkConfigView::from(&*network))
}

/// Hot-reloads the network configuration (JSON).
/// Persists to disk and sends `LoadNetworkConfig` to the orchestrator.
pub async fn network_set(
    State(s): State<AppState>,
    Json(mut new_config): Json<NetworkConfig>,
) -> Result<Json<CmdResponse>, (StatusCode, String)> {
    // `GET /api/network` exposes neither the private key nor the PSKs: a
    // configuration read back and reposted by the UI therefore necessarily
    // comes back without them. Reusing them from the current configuration
    // avoids a plain LAN interface change erasing the identity resolved from
    // the sealed vault and every negotiated PSK — the gateway would stay up,
    // then every handshake would fail with nothing tying the failure to the
    // setting that caused it.
    new_config.adopt_runtime_secrets_from(&*s.network.read().await);
    apply_network(&s, new_config).await?;
    Ok(Json(CmdResponse::ok()))
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
    // `ml_kem` unconditionally. The v4 default fell back to `classic` when no
    // PQ certificate was supplied, which quietly produced peers whose first
    // handshake was unprotected; the admission layer now refuses such a peer
    // outright, and naming the floor here makes the refusal say why.
    let minimum_mode = body
        .minimum_key_negotiation_mode
        .unwrap_or(ProtectionMode::MlKem);
    let peer = helios_provisioning::admit_with_key_negotiation(
        &mut updated,
        &body.name,
        &body.public_key,
        body.admin,
        body.key_negotiation_certificate_sha256.as_deref(),
        body.key_negotiation_pq_certificate_sha256.as_deref(),
        minimum_mode,
    )
    .map_err(admission_status)?;

    // The certificate registry **before** the configuration is written: a peer
    // in `network.toml` with no registry row is a client that connects and can
    // never renew, and nothing later says so. The reverse — a row for a peer
    // whose admission then failed to persist — is caught by the next
    // admission, which is idempotent for an unchanged peer.
    register_first_generation(&s, &body, &peer).await?;

    apply_network(&s, updated).await?;

    tracing::info!(peer = %peer.name, vip = %peer.address, admin = peer.admin, "peer admitted");
    Ok(Json(PeerSummary::from_config(&peer)))
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
            "this gateway holds a trust domain, so admission also takes the client's two              certificates — the registry records the leaves themselves, not their digests.              `helios-ctl enroll` sends them; a caller that cannot must admit on a gateway              without a trust domain."
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

/// Persists a mutated configuration then forwards it to the orchestrator.
///
/// [`aether::NetworkConfig::save_redacted`] owns the production projection and
/// excludes every runtime secret. Dry-run uses the one explicit exception: its
/// disposable WireGuard identity has no TPM vault, so it stays in
/// `network.toml`; peer PSKs remain excluded in both modes.
///
/// The dry-run exception is explicit and cannot otherwise be worked around:
/// without a TPM, the vault doesn't exist and `network.toml` is the **only**
/// place where the gateway's identity can live. Erasing it would make a
/// `--dev` daemon lose its identity on the first peer addition, with no
/// message tying the failure to the admission that caused it.
///
/// The orchestrator, meanwhile, receives the complete configuration: it is
/// the one that brings up the interface and installs the peers.
async fn apply_network(
    s: &AppState,
    updated: aether::NetworkConfig,
) -> Result<(), (StatusCode, String)> {
    let persisted = if s.dry_run {
        updated.save_for_development()
    } else {
        updated.save_redacted()
    };
    persisted.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    s.cmd_tx
        .send(OrchestratorCmd::LoadNetworkConfig(Box::new(updated)))
        .await
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "orchestrator unreachable".to_string(),
            )
        })
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
        E::NameTaken(_) | E::KeyTaken(_) => StatusCode::CONFLICT,
        E::Unknown(_) => StatusCode::NOT_FOUND,
        E::Ipam(_) => StatusCode::INSUFFICIENT_STORAGE,
    };
    (code, error.to_string())
}

pub async fn tunnel_start(State(s): State<AppState>) -> Json<CmdResponse> {
    let ok = s.cmd_tx.send(OrchestratorCmd::Connect).await.is_ok();
    Json(if ok {
        CmdResponse::ok()
    } else {
        CmdResponse::err("orchestrator unreachable")
    })
}

pub async fn tunnel_stop(State(s): State<AppState>) -> Json<CmdResponse> {
    let ok = s.cmd_tx.send(OrchestratorCmd::Disconnect).await.is_ok();
    Json(if ok {
        CmdResponse::ok()
    } else {
        CmdResponse::err("orchestrator unreachable")
    })
}

pub async fn firewall_rules_get(
    State(s): State<AppState>,
) -> Result<Json<FirewallRulesResponse>, (StatusCode, String)> {
    let state = *s.tunnel_state.read().await;
    let policy = s.policy.read().await;
    let rs = ruleset::render(&policy, state)
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;

    let verdict_str = match rs.default_verdict {
        ruleset::Verdict::Drop => "drop",
        ruleset::Verdict::Accept => "accept",
    };

    // Rendered faithfully to what the Netlink backend actually applies:
    // three hooked chains, each with its default policy.
    let mut lines = vec!["table inet helios {".to_string()];
    for kind in [
        ruleset::ChainKind::Input,
        ruleset::ChainKind::Forward,
        ruleset::ChainKind::Output,
    ] {
        let name = kind.as_str();
        lines.push(format!("  chain {name} {{"));
        lines.push(format!(
            "    type filter hook {name} priority filter; policy {verdict_str};"
        ));
        for rule in rs.chain(kind) {
            match &rule.note {
                Some(note) => lines.push(format!("    {rule}  # {note}")),
                None => lines.push(format!("    {rule}")),
            }
        }
        lines.push("  }".to_string());
    }
    if !rs.masquerade_out.is_empty() {
        lines.push("  chain postrouting {".to_string());
        lines.push("    type nat hook postrouting priority srcnat;".to_string());
        for out in &rs.masquerade_out {
            lines.push(format!(
                "    oifname \"{out}\" masquerade  # tunnel clients' Internet egress"
            ));
        }
        lines.push("  }".to_string());
    }
    if let Some(mss) = rs.mss_clamp {
        lines.push(format!(
            "  # MSS clamping requested ({mss}) — not applied by the Netlink backend"
        ));
    }
    lines.push("}".to_string());

    Ok(Json(FirewallRulesResponse {
        rules: lines.join("\n"),
        default_verdict: verdict_str.to_string(),
        dry_run: s.dry_run,
    }))
}

pub async fn firewall_rules_apply(
    State(s): State<AppState>,
    Json(body): Json<ApplyRulesRequest>,
) -> Json<CmdResponse> {
    let ok = s
        .cmd_tx
        .send(OrchestratorCmd::ApplyFirewallRules(body.rules))
        .await
        .is_ok();
    Json(if ok {
        CmdResponse::ok()
    } else {
        CmdResponse::err("orchestrator unreachable")
    })
}

pub async fn captive_portal_release(State(s): State<AppState>) -> Json<CmdResponse> {
    let ok = s
        .cmd_tx
        .send(OrchestratorCmd::AcknowledgeCaptivePortal)
        .await
        .is_ok();
    Json(if ok {
        CmdResponse::ok()
    } else {
        CmdResponse::err("orchestrator unreachable")
    })
}

pub async fn split_tunnel_set(
    State(s): State<AppState>,
    Json(body): Json<SplitTunnelRequest>,
) -> Json<CmdResponse> {
    let ok = s
        .cmd_tx
        .send(OrchestratorCmd::SetSplitTunnel(body.cidrs))
        .await
        .is_ok();
    Json(if ok {
        CmdResponse::ok()
    } else {
        CmdResponse::err("orchestrator unreachable")
    })
}

/// Publisher trust anchor, as compiled into **this** binary (ADR-002).
///
/// Everything here is a compile-time constant, not runtime state: that is
/// precisely the ADR's point — the trust root doesn't get hot-reconfigured,
/// it gets replaced by a firmware update. The UI displays it so an operator
/// can verify *which* keyring the deployed binary actually carries.
#[derive(Serialize)]
pub struct TrustResponse {
    /// Algorithms for which a valid signature is required — never "at least one".
    pub required_algs: Vec<&'static str>,
    /// Recognized publisher key epochs.
    pub publisher_keys: Vec<PublisherKeySummary>,
    /// `true` = development keyring. Forbidden in release by the build script.
    pub development_keys: bool,
    /// Domain separation of the reseal ticket, and its format version.
    pub reseal_domain: String,
    pub reseal_format_version: u32,
}

/// One epoch of the publisher keyring. Public keys are not exposed in full:
/// the UI has no use for them, a fingerprint is enough to compare them.
#[derive(Serialize)]
pub struct PublisherKeySummary {
    pub key_epoch: u32,
    pub fingerprint: String,
}

pub async fn trust() -> Json<TrustResponse> {
    use aether::sig::{ArtifactPayload as _, ResealPayload};

    Json(TrustResponse {
        required_algs: aether::sig::REQUIRED_ALGS
            .iter()
            .map(|alg| alg.as_str())
            .collect(),
        publisher_keys: aether::sig::PUBLISHER_KEYS
            .iter()
            .map(|keys| PublisherKeySummary {
                key_epoch: keys.key_epoch,
                fingerprint: keys.fingerprint(),
            })
            .collect(),
        development_keys: aether::sig::USING_DEVELOPMENT_PUBLISHER_KEYS,
        reseal_domain: String::from_utf8_lossy(ResealPayload::DOMAIN).into_owned(),
        reseal_format_version: ResealPayload::FORMAT_VERSION,
    })
}

#[cfg(test)]
mod tests;
