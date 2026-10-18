//! The network configuration view, its replacement and the gateway WireGuard key.

use super::*;

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
    /// IPv6 tunnel prefix, `fdXX:XXXX:XXXX::1/64`, when the gateway has one.
    /// Public configuration (`ADRESSAGE-IPV6.md` §5.1); `null` otherwise.
    pub wg_address_v6: Option<String>,
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
    /// IPv6 VIP, `…/128`, when the peer has one; `null` otherwise.
    pub address_v6: Option<String>,
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
            wg_address_v6: config.wg_address_v6.map(|prefix| prefix.to_string()),
            wg_listen_port: config.wg_listen_port,
            key_negotiation_port: config.key_negotiation_port,
            peers: config
                .peers
                .iter()
                .map(|peer| NetworkPeerView {
                    name: peer.name.clone(),
                    public_key: peer.public_key.clone(),
                    address: peer.address.clone(),
                    address_v6: peer.address_v6.map(aether::net::format_vip_v6),
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

/// Returns the current network configuration without any secret.
pub async fn network_get(State(s): State<AppState>) -> Json<NetworkConfigView> {
    let network = s.network.read().await;
    Json(NetworkConfigView::from(&*network))
}

/// Hot-reloads the network configuration (JSON).
/// Persists to disk and sends `LoadNetworkConfig` to the orchestrator.
///
/// A body whose `wg_address_v6` differs from the running one is refused with
/// `409 Conflict` and nothing is written: the tunnel prefix is applied at
/// startup only, so it is changed in `network.toml` followed by a restart. A
/// body whose firewall policy does not compile — an invalid split-tunnel CIDR
/// or SSH source — is refused with `400 Bad Request`, also before any write.
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
    {
        let running = s.network.read().await;
        new_config.adopt_runtime_secrets_from(&running);
        // Refused before anything is written. The orchestrator would not
        // apply such a change anyway, and persisting it here would answer
        // "ok" for a change that is not in force — or, from a body that
        // simply lacks the key, silently drop the tunnel prefix from
        // `network.toml` for the next start (`ADRESSAGE-IPV6.md` §2.5, §5.4).
        new_config
            .check_hot_reload(&running)
            .map_err(|refusal| (StatusCode::CONFLICT, refusal.to_string()))?;
    }
    // Same reasoning for an address the ruleset compiler refuses — a
    // split-tunnel CIDR, an SSH source: the orchestrator keeps the running
    // configuration, so writing this one would answer "ok" for a change that
    // is not in force, and leave it in the file for the next start.
    ruleset::check_policy(&new_config.firewall_policy()).map_err(|error| {
        (
            StatusCode::BAD_REQUEST,
            format!("network configuration refused: {error}"),
        )
    })?;
    apply_network(&s, new_config).await?;
    Ok(Json(CmdResponse::ok()))
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
pub(super) async fn apply_network(
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
