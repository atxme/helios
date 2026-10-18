//! What the gateway is and holds: status, served negotiation material, trust.

use super::*;

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
    /// What the last bring-up did with the IPv6 tunnel prefix:
    /// `"not_configured"`, `"installed"`, or `{"unavailable": {"reason": …}}`
    /// when the gateway runs IPv4-only in the degraded state of
    /// `ADRESSAGE-IPV6.md` §6.2. Observed on the data plane, like the peers'
    /// runtime, not read from the configuration.
    pub ipv6: Ipv6TunnelStatus,
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
        version: s.daemon_version,
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
        ipv6: s.ipv6.read().await.clone(),
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
